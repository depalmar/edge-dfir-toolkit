"""Analyzer: run detection packs over a case and score the result.

Three outcomes per detection - hit, no-hit, not-evaluated - and the third is
reported as loudly as the first. A device is never called clean; the best
verdict is NO-INDICATORS-FOUND, and it always ships with its evidence gaps.
"""
from __future__ import annotations

import html as _html
import re
from dataclasses import asdict
from urllib.parse import quote as _quote
from pathlib import Path
from typing import Any

import yaml

from . import __version__
from .checks import REGISTRY, Hit, excerpt
from .evidence import EvidenceView, Source, dump_json, glob_regex, iter_lines, parse_ts
from .util import REPO_ROOT, utcnow

PACK_DIR = REPO_ROOT / "artifacts" / "packs"
TIERS = ("possible", "likely", "confirmed")
MAX_HITS_KEPT = 50


# --------------------------------------------------------------------------- packs
def load_packs(pack_dir: Path = PACK_DIR) -> list[dict[str, Any]]:
    packs = []
    for p in sorted(pack_dir.glob("*.yml")):
        pack = yaml.safe_load(p.read_text(encoding="utf-8"))
        pack["_file"] = str(p.relative_to(REPO_ROOT))
        packs.append(pack)
    return packs


def packs_for(platform_id: str | None, packs: list[dict[str, Any]], all_packs: bool) -> list[dict[str, Any]]:
    if all_packs or not platform_id:
        return packs
    return [p for p in packs if platform_id in p.get("platforms", [])]


# --------------------------------------------------------------------------- engines
def _flags(det: dict[str, Any]) -> int:
    return re.I if "ignorecase" in det.get("flags", []) else 0


def run_log_regex(view: EvidenceView, det: dict[str, Any]) -> tuple[bool, list[Hit]]:
    srcs = view.sources(det["sources"])
    if not srcs:
        return False, []
    rx = re.compile(det["pattern"].encode(), _flags(det))
    excl = [re.compile(x.encode(), _flags(det)) for x in det.get("exclude", [])]
    hits = []
    for src in srcs:
        for n, raw in iter_lines(src):
            if rx.search(raw) and not any(x.search(raw) for x in excl):
                ts, tzk = parse_ts(raw.decode("latin-1"))
                hits.append(Hit(src.label(), det["title"], line=n, ts=ts, tz_known=tzk, excerpt=excerpt(raw)))
    return True, hits


def run_path_exists(view: EvidenceView, det: dict[str, Any]) -> tuple[bool, list[Hit]]:
    scope = [glob_regex(g.lstrip("/")) for g in det.get("scope", [])]
    files = view.all_files()

    def bare(s: Source) -> str:
        ref = s.ref.lstrip("/")
        return ref.split("]/", 1)[1] if ref.startswith("[") and "]/" in ref else ref

    if scope and not any(r.match(bare(f)) for f in files for r in scope):
        return False, []
    if not scope and not files:
        return False, []
    hits = [Hit(s.label(), f"{det['title']}: {s.ref}") for s in view.files(det["paths"])]
    return True, hits


def run_yara(view: EvidenceView, det: dict[str, Any]) -> tuple[bool, list[Hit]]:
    srcs = view.sources(det["sources"])
    if not srcs:
        return False, []
    try:
        import yara  # type: ignore
    except ImportError:
        return False, []
    rules = yara.compile(filepath=str(REPO_ROOT / det["rule"]))
    hits = []
    for src in srcs:
        for m in rules.match(str(src.local), timeout=60):
            hits.append(Hit(src.label(), f"YARA {m.rule}", extra={"rule": m.rule, "tags": list(m.tags)}))
    return True, hits


def run_check(view: EvidenceView, det: dict[str, Any], ctx: dict[str, Any]) -> tuple[bool, list[Hit]]:
    fn = REGISTRY[det["check"]]
    return fn(view, det, **ctx) if det["check"] == "hash_baseline" else fn(view, det)


ENGINES = {"log_regex": run_log_regex, "path_exists": run_path_exists, "yara": run_yara}


# --------------------------------------------------------------------------- scoring
def verdict(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_tier: dict[str, list[dict[str, Any]]] = {t: [] for t in TIERS}
    for r in results:
        for h in r["hits"]:
            by_tier[h["tier"]].append(r)
    classes_possible = {r["evidence_class"] for r in by_tier["possible"]}
    classes_likely = {r["evidence_class"] for r in by_tier["likely"]}
    if by_tier["confirmed"]:
        level = "COMPROMISED"
        why = "confirmed indicator: " + ", ".join(sorted({r["id"] for r in by_tier["confirmed"]}))
    elif len(classes_likely) >= 2:
        # Independent likely indicators in different evidence classes (a web shell
        # on disk AND a shell holding a socket, say) corroborate each other.
        level = "COMPROMISED"
        why = "likely indicators corroborated across evidence classes (" + ", ".join(sorted(classes_likely)) + \
              "): " + ", ".join(sorted({r["id"] for r in by_tier["likely"]}))
    elif by_tier["likely"]:
        level = "LIKELY-COMPROMISED"
        why = "likely indicator: " + ", ".join(sorted({r["id"] for r in by_tier["likely"]}))
    elif len(classes_possible) >= 2:
        level = "LIKELY-COMPROMISED"
        why = "possible indicators corroborated across evidence classes: " + ", ".join(sorted(classes_possible))
    elif by_tier["possible"]:
        level = "SUSPICIOUS"
        ids = ", ".join(sorted({r["id"] for r in by_tier["possible"]}))
        if classes_possible == {"offbox-logs"}:
            # Only the off-box checks fired: say what was seen, not "an attempt".
            fired = {r["id"] for r in by_tier["possible"]}
            seen = []
            if fired & {"offbox-gone-from-box", "offbox-never-forwarded"}:
                seen.append("the SIEM's copy of the device's syslog and the logs on the box disagree "
                            "(lines deleted locally, or never forwarded)")
            if "offbox-silent-while-active" in fired:
                seen.append("forwarding went quiet while another source shows the device active")
            why = "possible indicator: " + "; ".join(seen) + " (each finding lists the benign causes): " + ids
        else:
            why = "possible indicator (often exploitation attempted, success not shown): " + ids
    else:
        level = "NO-INDICATORS-FOUND"
        why = "no detection fired. This is not a finding that the device is clean; read the evidence gaps."
    return {"level": level, "rationale": why}


def _needs(det: dict[str, Any], view: EvidenceView) -> tuple[str, str]:
    """What a detection that was not evaluated needed, from its own sources, and how to close it."""
    src = det.get("sources") or {}
    steps = {s["step_id"]: s for s in view.manifest.get("steps", [])}
    parts, close = [], []
    for sid in src.get("steps") or []:
        s = steps.get(sid)
        if s is None:
            parts.append(f"step {sid}, which this case does not hold")
            close.append("collect it, or ingest the same output from an export")
        elif s["status"] != "ok":
            parts.append(f"step {sid} (`{s.get('cmd')}`), which was {s['status']}")
            close.append("re-run the step, or record why it cannot run")
        else:
            parts.append(f"step {sid} (`{s.get('cmd')}`), whose output it could not read")
            close.append("check the output against the profile's expected format")
    globs = src.get("files") or []
    if globs:
        if det["type"] == "yara":
            parts.append("a file to scan: a recovered binary or an ingested image"
                         + ("" if globs == ["**"] else f" matching {', '.join(globs)}"))
            close.append("ingest the recovered files or a disk image with edgetriage ingest")
        else:
            parts.append(f"a file matching {', '.join(globs)}")
            close.append("ingest an export or image that holds it")
    if not parts:
        return ("evidence its coded check could not find; its notes say what it reads",
                "Collect or ingest the evidence this detection reads.")
    uniq = list(dict.fromkeys(close))
    return "needs " + ", or ".join(parts), (uniq[0][0].upper() + uniq[0][1:] + "".join("; or " + c for c in uniq[1:]) + ".")


IMPACT_FLAG = {"vendor-bundle": "--allow-bundle", "break-glass": "--break-glass"}


def _class_close(cls: str, m: dict[str, Any]) -> str:
    """How to fill a missing evidence class: the profile's own steps for it (and the flag each
    needs), or an ingest that declares the class."""
    from .profiles import TIER_CLASS, get_profile
    ran = {s["step_id"]: s.get("status") for s in m.get("steps", [])}
    try:
        steps = [s for s in get_profile(m["profile"]).steps if cls in s.classes] if m.get("profile") else []
    except Exception:   # an unknown or renamed profile: fall back to the ingest route
        steps = []
    ingest = f"ingest an export or the vendor tool's output with edgetriage ingest <case> --label <name> --bundle <file> --evidence-class {cls}"
    if not steps:
        lead = f"No step in the {m['profile']} plan provides {cls} evidence, so " if m.get("profile") else ""
        return (lead + ingest + ".") if lead else ingest[0].upper() + ingest[1:] + "."
    named = "; ".join(f"{s.id}" + (f" (needs {IMPACT_FLAG[s.impact]})" if s.impact in IMPACT_FLAG else "")
                      + (f", which was {ran[s.id]}" if s.id in ran else ", not run") for s in steps)
    return f"The {m['profile']} plan's {cls} steps: {named}. Run them, or {ingest}."


def evidence_gaps(view: EvidenceView, results: list[dict[str, Any]],
                  window_start: str | None) -> list[dict[str, str]]:
    gaps: list[dict[str, str]] = []
    m = view.manifest
    covered = view.covered_classes()
    for cls in m.get("expected_evidence", []):
        if cls not in covered:
            gaps.append({"kind": "missing-evidence-class", "detail": f"no {cls} evidence in the case",
                         "close": _class_close(cls, m)})
    for s in m.get("steps", []):
        if s["status"] == "pending-manual":
            gaps.append({"kind": "manual-step-pending", "detail": f"{s['step_id']}: {s['purpose']}"})
        elif s["status"] in ("unavailable", "error", "refused"):
            gaps.append({"kind": "step-failed", "detail": f"{s['step_id']} ({s['status']}): {s.get('error')}"})
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}   # detections that need the same thing are one gap
    for r in results:
        if r["status"] == "not-evaluated":
            groups.setdefault((r.get("needs") or "required evidence not in case", r.get("close") or ""), []).append(r)
    for (need, close), rs in groups.items():
        g = {"kind": "detection-not-evaluated",
             "detail": f"{', '.join(r['id'] for r in rs)} ({', '.join(dict.fromkeys(r['pack'] for r in rs))}): {need}"}
        if close:
            g["close"] = close
        gaps.append(g)
    pf = m.get("preflight", {})
    if pf.get("rebooted_since_incident") == "yes":
        gaps.append({"kind": "volatile-lost", "detail": "device rebooted since the incident: memory-only implants and memory-disk files are gone"})
    if pf.get("patched_since_incident") == "yes":
        gaps.append({"kind": "upgraded", "detail": "device upgraded since the incident: pre-upgrade logs and files may be inaccessible"})
    if window_start:
        earliest = None
        for src in view.files(["**/*.log*", "**/*log"]):
            for _, raw in iter_lines(src, limit_bytes=8 * 1024 * 1024):
                ts, _ = parse_ts(raw.decode("latin-1"))
                if ts:
                    earliest = ts if earliest is None or ts < earliest else earliest
                    break
        if earliest is None:
            gaps.append({"kind": "log-retention",
                         "detail": f"no on-box log line with a dated timestamp was found, so nothing on the box is known to reach back "
                                   f"to the window start {window_start}; use off-box copies"})
        elif earliest[:19] > window_start[:19]:
            gaps.append({"kind": "log-retention",
                         "detail": f"the earliest on-box log line, {earliest}, is after the window start {window_start}; use off-box copies"})
    gaps.append({"kind": "standing", "detail": "on-box evidence on a compromised appliance may be tampered with; corroborate with off-box telemetry (SIEM, NetFlow, IdP, AD)"})
    pv = m.get("profile_validation")   # absent in cases collected before 0.8.0
    if pv is not None and not pv.get("validated_on"):
        gaps.append({"kind": "unvalidated-profile",
                     "detail": "the collection profile has not been run against a real device or vendor virtual edition; "
                               "a command that failed or returned an unexpected format shows as 'not evaluated', so read "
                               "the step statuses in manifest.json before relying on any absence"})
    return gaps


# --------------------------------------------------------------------------- main
def analyze(case_root: Path, *, platform_id: str | None = None, all_packs: bool = False,
            baseline: dict[str, str] | None = None, window_start: str | None = None,
            pack_dir: Path = PACK_DIR, forwarded: list[Path] | None = None,
            forwarded_local: list[str] | None = None, activity: list[Path] | None = None,
            activity_match: list[str] | None = None, activity_field: str | None = None) -> dict[str, Any]:
    """forwarded: the device's syslog as the SIEM received it. When given, the off-box
    checks run beside the packs (see offbox.py). activity: another source's record of what
    the device did, against which the forwarded stream's gaps are tested."""
    view = EvidenceView(case_root)
    platform_id = platform_id or view.manifest.get("platform_id")
    packs = packs_for(platform_id, load_packs(pack_dir), all_packs)
    ctx = {"baseline": baseline}
    results = []
    for pack in packs:
        for det in pack.get("detect", []):
            if det["type"] == "check":
                evaluated, hits = run_check(view, det, ctx)
            else:
                evaluated, hits = ENGINES[det["type"]](view, det)
            tiered = []
            for h in hits:
                d = asdict(h)
                d["tier"] = h.extra.get("tier", det["tier"])
                tiered.append(d)
            row = {
                "pack": pack["id"], "pack_name": pack["name"], "cves": pack.get("cves", []),
                "pack_confidence": pack.get("confidence"), "pack_unverified": bool(pack.get("unverified")),
                "id": det["id"], "title": det["title"], "type": det["type"], "tier": det["tier"],
                "evidence_class": det["evidence_class"], "attack": det.get("attack", []),
                "status": "not-evaluated" if not evaluated else ("hit" if hits else "no-hit"),
                "hit_count": len(hits), "hits": tiered[:MAX_HITS_KEPT],
                "notes": det.get("notes"),
            }
            if not evaluated:   # say what it needed and how to get it, not "required evidence not in case"
                row["needs"], row["close"] = _needs(det, view)
            results.append(row)
    off, off_rows = None, []
    if forwarded:
        from . import offbox
        off = offbox.compare(view, [Path(p) for p in forwarded], forwarded_local, window_start,
                             activity=[Path(p) for p in activity] if activity else None,
                             activity_match=activity_match, activity_field=activity_field)
        off_rows = offbox.results(off)
        for key in ("gone_from_box", "never_forwarded", "silent_while_active"):   # the hits live in detections, once
            off[key] = {k: v for k, v in off[key].items() if k != "hits"} | {"runs": len(off[key]["hits"])}
    gaps = evidence_gaps(view, results, window_start)
    at = next((i for i, g in enumerate(gaps) if g["kind"] == "standing"), len(gaps))
    for r in off_rows:
        if r["status"] == "not-evaluated":
            kind = "offbox-activity-missing" if r["id"] == "offbox-silent-while-active" else "offbox-not-compared"
            gaps.insert(at, {"kind": kind, "detail": f"{r['id']}: {r['reason']}"})
            at += 1
    out = {
        "case_id": view.manifest["case_id"],
        "platform_id": platform_id,
        "analyzed_utc": utcnow(),
        "tool_version": __version__,
        "packs_applied": [p["id"] for p in packs],
        "baseline_supplied": baseline is not None,
        "window_start": window_start,
        "verdict": verdict(results + off_rows),
        "detections": results + off_rows,
        "evidence_gaps": gaps,
    }
    ms = Path(case_root) / "manifest.sha256"
    out["manifest_sha256"] = ms.read_text().split()[0] if ms.is_file() else None
    if off is not None:
        out["offbox"] = off
    dump_json(Path(case_root) / "findings.json", out)
    (Path(case_root) / "report.md").write_text(render_report(out, view.manifest), encoding="utf-8")
    (Path(case_root) / "report.html").write_text(render_html(out, view.manifest), encoding="utf-8")
    return out


def _prov(r: dict[str, Any]) -> str:
    """How far to trust the detection itself: its pack's confidence, and unverified when it is."""
    c = r.get("pack_confidence")
    return (f"pack confidence {c}" + (", unverified" if r.get("pack_unverified") else "")) if c else ""


def render_report(f: dict[str, Any], m: dict[str, Any]) -> str:
    """report.md, in the order the guide reads a report: the verdict and what to do next, the
    evidence gaps, then the findings."""
    v = f["verdict"]
    hit = [r for r in f["detections"] if r["status"] == "hit"]
    ne = [r for r in f["detections"] if r["status"] == "not-evaluated"]
    clean = [r for r in f["detections"] if r["status"] == "no-hit"]
    cat = _catalog_entry(f.get("platform_id"))
    steps = {s["step_id"]: s for s in m.get("steps", [])}
    items, donot = next_steps(v["level"], cat)
    stem = cat.get("response")
    L = [
        f"# Edge triage report - {f['case_id']}",
        "",
        f"**Verdict: {v['level']}**  ",
        f"{v['rationale']}",
        "",
        "| | |", "|---|---|",
        f"| Platform | {cat['name'] + ' (' + str(f['platform_id']) + ')' if cat.get('name') else f['platform_id']} |",
        f"| Profile | {m.get('profile') or NO_PROFILE} |",
        f"| Target | {(m.get('target') or {}).get('host', 'n/a')} |",
        f"| Collected | {_collected(m)} |",
        f"| Analyzed | {_hms(f['analyzed_utc'])} UTC (edgetriage {f['tool_version']}) |",
        f"| Packs | {', '.join(f['packs_applied']) or 'none'} |",
        f"| Detections | {len(hit)} hit, {len(clean)} no hit, {len(ne)} not evaluated |",
    ]
    if f.get("manifest_sha256"):
        L.append(f"| Case manifest | sha256 {f['manifest_sha256']} |")
    L += ["", "## What to do next", ""] + [f"- {x}" for x in items]
    if stem:
        L.append(f"- The {cat.get('name', 'platform')} playbook, read with this verdict: {SITE_URL}#response/{_quote(str(stem))}?verdict={_quote(v['level'])}")
    if donot:
        L += ["", f"From the playbook, do not:"] + [f"- **{d['action']}.** {d['because']}" for d in donot]
    L += ["", "## Evidence gaps", "", "What this analysis could not see. Read these before the findings.", ""]
    for g in f["evidence_gaps"]:
        L.append(f"- **{g['kind']}** - {g['detail']}")
        close = g.get("close") or GAP_CLOSE.get(g["kind"])
        if close:
            L.append(f"  Close it: {close}")
    L += ["", "## Findings", ""]
    if not hit:
        L.append("No detection fired. That is not a finding that the device is clean: read the evidence gaps above.")
    for r in sorted(hit, key=lambda r: -max(TIERS.index(h["tier"]) for h in r["hits"])):
        top = max((h["tier"] for h in r["hits"]), key=TIERS.index)
        meta = " - ".join(x for x in [r["pack"] + (f" ({_prov(r)})" if _prov(r) else ""), " ".join(r["cves"]),
                                       f"{r['hit_count']} hit(s), evidence class {r['evidence_class']}"] if x)
        L += [f"### [{top.upper()}] {r['title']}", f"`{r['id']}` - {meta}", ""]
        for h in r["hits"][:10]:
            ts = f" - {h['ts']}{'' if h.get('tz_known') else ' (device-local)'}" if h.get("ts") else ""
            detail = f" - {h['detail']}" if h.get("detail") and h["detail"] != r["title"] else ""
            L.append(f"- {_where(h, steps)}{ts}{detail}")
            if h.get("excerpt"):
                L.append(f"  `{h['excerpt'][:200]}`")
        if r.get("notes"):
            L += ["", f"> {r['notes'].strip()}"]
        L.append("")
    if f.get("offbox"):
        L += offbox_markdown(f["offbox"])
    return "\n".join(L) + "\n"


def _dur(seconds: int) -> str:
    h, rem = divmod(int(seconds), 3600)
    if h:
        return f"{h} h {rem // 60} min" if rem // 60 else f"{h} h"
    return f"{rem // 60} min"


def offbox_rows(o: dict[str, Any]) -> list[tuple[str, str]]:
    """The off-box comparison as (label, value) pairs, shared by report.md and report.html."""
    rows = [("Forwarded copy", "; ".join(f"{Path(x['path']).name} ({x['format']}, {x['lines']} lines, sha256 {x['sha256'][:16]})"
                                         for x in o["forwarded"]) or "none")]
    rows.append(("Local logs", "; ".join(f"{x['source']} ({x['lines']} lines, {x['shared']} shared"
                                         f"{'' if x['comparable'] else ', not comparable'})" for x in o["local"]) or "none found"))
    if o.get("span"):
        rows.append(("Compared span", f"{o.get('shared', 0)} shared lines, {o['span']['from'] or 'line ' + str(o['span']['first_line'])}"
                                      f" to {o['span']['to'] or 'line ' + str(o['span']['last_line'])}"))
    if o.get("before_box"):
        b = o["before_box"]
        rows.append(("Older than the box", f"{b['lines']} forwarded lines ({b['from']} to {b['to']}) come before the oldest line "
                                           "still on the box. Rotation explains that unless the local log should reach further back."))
    for key, label in (("gone_from_box", "Gone from the box"), ("never_forwarded", "Never forwarded")):
        p = o[key]
        val = f"{p['runs']} run(s) found" if p["status"] == "evaluated" else "not evaluated"
        rows.append((label, val + (f" - {p['reason']}" if p.get("reason") else "")))
    acts = o.get("activity") or []
    if acts:
        match = f", matching {' or '.join(o['activity_match'])}" if o.get("activity_match") else ""
        rows.append(("Activity sources", "; ".join(
            f"{a['file']} ({a['format']}, {a['events']} timed event(s) of {a['records']} record(s){match}, "
            f"{a['from'] or '-'} to {a['to'] or '-'}, sha256 {a['sha256'][:16]})" for a in acts)))
    if o.get("gaps"):
        rows.append(("Stream gaps", "; ".join(f"{_dur(g['seconds'])} after {g['from']}{' (in the window)' if g['in_window'] else ''}"
                                              f"{_gap_activity(g) if acts else ''}" for g in o["gaps"]) + "."
                     + (" A gap with the device active elsewhere appears under Findings (EDGE-HUNT-0009)." if acts else
                        " Listed, not scored: pass --activity a record of what the device did in those hours, from a "
                        "source it does not control - sign-ins through it (IdP, RADIUS), sessions from it on the next "
                        "firewall, flows to or from it - to test them (EDGE-HUNT-0009).")))
    elif o.get("gap_floor_seconds"):
        rows.append(("Stream gaps", f"none of {_dur(o['gap_floor_seconds'])} or more"))
    return rows


def _gap_activity(g: dict[str, Any]) -> str:
    """What the activity exports say about one gap."""
    from .offbox import ACTIVE_MIN
    if "activity" not in g:
        return ": not placed (no year in the forwarded copy's times)"
    busy = [x for x in g["activity"] if x["events"]]
    if sum(x["events"] for x in busy) >= ACTIVE_MIN:
        return ": active: " + ", ".join(f"{x['events']} event(s) in {x['file']}" for x in busy)
    covering = [x["file"] for x in g["activity"] if x["covers"]]
    if covering:
        return f": quiet in {' and '.join(covering)} too"
    return f": {' and '.join(x['file'] for x in g['activity'])} do not span it"


def offbox_markdown(o: dict[str, Any]) -> list[str]:
    L = ["## Off-box comparison", "",
         "The device's syslog as the SIEM received it, lined up by message, in order, with the logs left on the box "
         "(EDGE-HUNT-0027). Runs on one side only appear under Findings as possible indicators.", "",
         "| | |", "|---|---|"]
    L += [f"| {k} | {v.replace('|', '/')} |" for k, v in offbox_rows(o)]
    return L + [""]


# --------------------------------------------------------------------------- report.html
# The same findings as report.md, laid out verdict first. One self-contained
# file: no script, no font, no request, and no link except back to the published
# toolkit. Every value is escaped - excerpts, sources, paths and gap details come
# from a compromised device and are attacker-influenced data. Like report.md it
# stays in the case folder and is never published.
SITE_URL = "https://depalmar.github.io/edge-dfir-toolkit/"
CLASS_ORDER = ["identity", "memory", "process", "sessions", "integrity", "config",
               "auth-logs", "web-logs", "system-logs", "filesystem", "persistence", "offbox-logs"]
GAP_CLOSE = {
    "missing-evidence-class": "Ingest the off-box copy for the window: edgetriage ingest <case> --label <name> --bundle <file>.",
    "detection-not-evaluated": "Collect or ingest the evidence this detection reads.",
    "manual-step-pending": "Run it by hand and record the outcome, or record why not. Break-glass steps run last, after preservation.",
    "step-failed": "Re-run the step or record the error; check the profile's prompt and pager.",
    "volatile-lost": "Memory-only evidence is gone; rely on off-box telemetry for the window.",
    "upgraded": "Ask the vendor about pre-upgrade logs; use off-box copies.",
    "log-retention": "Pull the off-box syslog from the window start to the earliest on-box line.",
    "standing": "Corroborate with off-box sources for the same hours: IdP or RADIUS sign-ins, the next firewall's "
                "sessions for the device's addresses, and flows where you have them.",
    "unvalidated-profile": "Read the step statuses in manifest.json before relying on any absence.",
    "offbox-not-compared": "Export the device's syslog from the SIEM for the same hours as raw lines, or as JSON or CSV with a "
                           "Message field, and pass it with --forwarded; point --forwarded-local at the local log it should match.",
    "offbox-activity-missing": "Export what the device did across the gap hours from a source it does not control - IdP or "
                               "RADIUS sign-ins through it, sessions from its inside address on the next firewall, flows to "
                               "or from it - and pass it with --activity; --activity-match keeps only records naming the device.",
}
_LIGHT = ("--bg:#fbfbfa;--panel:#fff;--panel-2:#fbfbfa;--ink:#1c1b19;--ink-2:#3d3a35;--muted:#6b6862;--faint:#a09b90;"
          "--line:#e4e1db;--line-soft:#f0ede8;--accent:#5e3a24;--accent-soft:#f2e9e2;--on-accent:#fff;--crit:#a12b2b;"
          "--high:#b4611c;--med:#8a7320;--low:#5c7a4a;--alert-bg:#fdf6f2;--code-bg:#f6f4f0")
_DARK = ("--bg:#1e1c1a;--panel:#2a2825;--panel-2:#312e2a;--ink:#f4f1ec;--ink-2:#ddd8d0;--muted:#bab4aa;--faint:#928b81;"
         "--line:#5d5851;--line-soft:#403d38;--accent:#ddc4b0;--accent-soft:#3b2c22;--on-accent:#1a1310;--crit:#f28c85;"
         "--high:#eaa965;--med:#d9c364;--low:#a6d18c;--alert-bg:#33261f;--code-bg:#312e2a")
REPORT_CSS = ":root{" + _LIGHT + """;color-scheme:light dark;
  --sans:system-ui,"Segoe UI",-apple-system,BlinkMacSystemFont,Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,"Cascadia Mono","SF Mono",SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
  --fs-xs:12px;--fs-sm:13px;--fs-base:14.5px;--fs-md:16px;--fs-lg:20px}
@media screen and (prefers-color-scheme:dark){:root{""" + _DARK + """}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:var(--fs-base)/1.55 var(--sans)}
a{color:var(--accent)}
code{font-family:var(--mono)}
.wrap{max-width:1180px;margin:0 auto;padding:20px 28px 48px}
.top{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding-bottom:12px;border-bottom:1px solid var(--line);margin-bottom:18px}
.dot{width:9px;height:9px;border-radius:50%;background:var(--accent)}
.top b{font-size:var(--fs-md)}.top code{font-size:var(--fs-sm);color:var(--ink-2)}
.top .pr{margin-left:auto;font-size:var(--fs-xs);color:var(--muted)}
h2{font-size:var(--fs-md);margin:26px 0 8px}
.muted{color:var(--muted)}.small{font-size:var(--fs-xs)}
.row1{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-start}
.vcard{flex:1 1 380px;background:var(--alert-bg);border:1px solid color-mix(in srgb,var(--crit) 35%,var(--line));border-radius:14px;padding:16px 18px}
.lbl{font-size:var(--fs-xs);letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:6px}
.vbig{display:inline-block;font-size:var(--fs-md);font-weight:700;letter-spacing:.02em;border-radius:7px;padding:4px 12px;border:1px solid currentColor}
.v-compromised{color:var(--on-accent);background:var(--crit);border-color:var(--crit)}
.v-likely-compromised{color:var(--high)}.v-suspicious{color:var(--med)}.v-no-indicators-found{color:var(--muted)}
.rat{font-size:var(--fs-md);margin:10px 0 6px;overflow-wrap:anywhere}
.sbar{display:flex;gap:2px;height:20px;border-radius:5px;overflow:hidden;margin-top:12px;background:var(--line-soft)}
.s-hit{background:var(--crit)}.s-no-hit{background:color-mix(in srgb,var(--muted) 45%,var(--panel))}.s-not-evaluated{background:var(--med)}
.cap{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;font-size:var(--fs-xs);color:var(--muted);margin-top:4px}
.meta{flex:1 1 320px;display:grid;grid-template-columns:auto 1fr;gap:6px 14px;margin:0;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px 16px;font-size:var(--fs-sm)}
.meta dt{color:var(--muted)}.meta dd{margin:0;overflow-wrap:anywhere}
.note{font-size:var(--fs-sm);color:var(--ink-2);margin:0 0 8px}
.vg{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:6px 14px}
.vgr{display:grid;grid-template-columns:120px repeat(3,minmax(0,1fr));gap:8px;align-items:start;padding:8px 6px;border-top:1px solid var(--line-soft)}
.vgr.h{border-top:0;font-size:var(--fs-xs);color:var(--muted);font-weight:600}
.vgr.lk{background:color-mix(in srgb,var(--high) 7%,transparent)}
.vgr .cls{font-size:var(--fs-sm)}
.cell{display:flex;flex-wrap:wrap;gap:4px}
.pill{font-family:var(--mono);font-size:11px;border-radius:20px;padding:1px 7px;border:1px solid var(--line);color:var(--muted);overflow-wrap:anywhere}
.pill.nh{text-decoration:line-through;text-decoration-color:var(--faint)}
.pill.ne{border-style:dashed;border-color:var(--med);color:var(--med)}
.pill.hit{color:var(--on-accent);font-weight:600}
.pill.hit.t-possible{background:var(--med);border-color:var(--med)}.pill.hit.t-likely{background:var(--high);border-color:var(--high)}
.pill.hit.t-confirmed{background:var(--crit);border-color:var(--crit)}
.gaps{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(340px,100%),1fr));gap:10px}
.gap{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px;font-size:var(--fs-sm)}
.gap p{margin:6px 0 0;overflow-wrap:anywhere}
.kind{font-family:var(--mono);font-size:11px;border:1px solid currentColor;border-radius:20px;padding:1px 7px;color:var(--high)}
.kind.std{color:var(--muted)}.close{color:var(--low);font-weight:600}
.find{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin:10px 0}
.next{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--accent);border-radius:12px;padding:4px 18px 12px;margin:18px 0 6px}
.next h2{margin:12px 0 6px}.next ul{margin:4px 0 8px;padding-left:20px}.next li{margin:3px 0}.dnh{margin:10px 0 2px;font-weight:600;font-size:var(--fs-sm)}
.dn li{font-size:var(--fs-sm)}.prov{font-size:var(--fs-xs);color:var(--muted)}.prov.unv{color:var(--high)}.hitl .w code{font-size:var(--fs-xs)}
.fh{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:flex-start}
.fid{font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted)}.ft{font-size:var(--fs-md);font-weight:600;margin:2px 0}
.badge{display:inline-block;font-size:var(--fs-xs);font-weight:600;border-radius:20px;padding:1px 8px;border:1px solid currentColor}
.tier-possible{color:var(--med)}.tier-likely{color:var(--high)}.tier-confirmed{color:var(--on-accent);background:var(--crit);border-color:var(--crit)}
.hitl{margin:10px 0 0;font-size:var(--fs-sm);overflow-wrap:anywhere}.hitl .w{color:var(--ink-2)}
pre{background:var(--code-bg);border:1px solid var(--line-soft);border-radius:8px;padding:8px 10px;margin:4px 0 0;font-size:var(--fs-xs);white-space:pre-wrap;word-break:break-all}
.strip{display:flex;gap:3px;flex-wrap:wrap}
.strip div{flex:1 0 18px;display:flex;flex-direction:column;align-items:center;gap:2px;min-width:18px}
.strip span{display:block;width:100%;height:22px;border-radius:4px}
.strip i{font-style:normal;font-family:var(--mono);font-size:10px;color:var(--muted)}
.st-ok{background:var(--low)}.st-pending-manual{background:var(--med)}.st-error{background:var(--crit)}
.st-off{background:var(--line);border:1px dashed var(--muted)}
.acts{margin-top:22px;padding-top:14px;border-top:1px solid var(--line);font-size:var(--fs-sm)}
@media (max-width:640px){.wrap{padding:16px}.vgr{grid-template-columns:90px repeat(3,minmax(0,1fr))}}
"""


def _catalog_entry(platform_id: str | None) -> dict[str, Any]:
    for p in sorted((REPO_ROOT / "artifacts" / "catalog").glob("*.yml")):
        d = yaml.safe_load(p.read_text()) or {}
        if d.get("id") == platform_id:
            return d
    return {}


def _where(h: dict[str, Any], steps: dict[str, dict[str, Any]]) -> str:
    """Where a hit came from, in words a responder can re-check: the command and the line."""
    src, line = str(h.get("source", "")), h.get("line")
    if src.startswith("step:"):
        s = steps.get(src[5:], {})
        what = f"`{s['cmd']}` (step {src[5:]})" if s.get("cmd") else f"step {src[5:]}"
    else:
        what = src
    return what + (f", line {line}" if line else "")


def _playbook(stem: str | None) -> dict[str, Any]:
    p = REPO_ROOT / "artifacts" / "response" / f"{stem}.yml"
    return (yaml.safe_load(p.read_text()) or {}) if stem and p.is_file() else {}


def next_steps(level: str, cat: dict[str, Any], top: int = 3) -> tuple[list[str], list[dict[str, str]]]:
    """What to do next, by verdict, with the platform playbook's own do-not list quoted (the
    playbook is a sourced record; the report adds no advice of its own beyond the guide's)."""
    pb = _playbook(cat.get("response"))
    name = cat.get("name") or "this platform"
    if level in ("COMPROMISED", "LIKELY-COMPROMISED"):
        items = ["Preserve before you act: the case folder may be the only copy of what the device held. Do not reboot, upgrade or "
                 "factory-reset it until the playbook's preservation steps are done.",
                 f"Follow the {name} response playbook in its order: preserve, contain, rotate, eradicate, recover, verify.",
                 "Treat the credentials the device held as exposed"
                 + (": " + "; ".join(c["what"] for c in (pb.get("credential_exposure") or [])[:top]) + "." if pb.get("credential_exposure") else ".")]
    elif level == "SUSPICIOUS":
        items = ["Find the second signal before you escalate: a hit in a different evidence class is what raises the verdict, "
                 "and the off-box hunts are where most second signals come from.",
                 "Close the evidence gaps listed here first; several of them are where a second signal would be.",
                 "Do not reboot or upgrade the device while the question is open."]
    else:
        items = ["Close the evidence gaps listed here before closing the case. This verdict means no indicators in the evidence "
                 "available; it is not a finding that the device is clean.",
                 "Pull the off-box copies the gaps name (SIEM syslog, sign-ins, the next firewall's sessions) and run the platform's hunts."]
    return items, (pb.get("do_not") or [])[:top]


def _hms(ts: str | None) -> str:
    return (ts or "").replace("T", " ").rstrip("Z").split(".")[0]


NO_PROFILE = "none (exports ingested, no live collection)"


def _collected(m: dict[str, Any]) -> str:
    """When the live collection ran; an ingest-only case (Ivanti, SonicWall) says it had none."""
    start, end = m.get("collection_start_utc"), m.get("collection_end_utc")
    if start and end:
        return f"{_hms(start)} to {_hms(end)[11:]} UTC"
    return f"from {_hms(start)} UTC, no end recorded" if start else "no live collection"


def render_html(f: dict[str, Any], m: dict[str, Any]) -> str:
    """report.html: verdict first, then how it was reached, the evidence gaps,
    the findings with their escaped excerpts, the collection and what to do next."""
    esc = _html.escape
    v, dets, gaps = f["verdict"], f["detections"], f["evidence_gaps"]
    level = v["level"]
    cat = _catalog_entry(f.get("platform_id"))
    words = {"hit": "hit", "no-hit": "no hit", "not-evaluated": "not evaluated"}
    st = {k: sum(1 for r in dets if r["status"] == k) for k in words}
    sbar = "".join(f'<span class="s-{k}" style="flex:{n}" title="{n} {words[k]}"></span>' for k, n in st.items() if n)
    summary = " · ".join(f"{n} {words[k]}" for k, n in st.items())

    def top_tier(r: dict[str, Any]) -> str:
        if r["status"] == "hit" and r["hits"]:
            return max((h["tier"] for h in r["hits"]), key=TIERS.index)
        return r["tier"]

    pv = m.get("profile_validation")
    pf = m.get("preflight") or {}
    rows = [("Platform", f'{cat["name"]} ({f.get("platform_id")})' if cat.get("name") else str(f.get("platform_id"))),
            ("Profile", str(m.get("profile") or NO_PROFILE) + (", not yet run on a real device" if pv is not None and not pv.get("validated_on") else "")),
            ("Target", str((m.get("target") or {}).get("host", "n/a"))),
            ("Collected", _collected(m)),
            ("Analyzed", f'{_hms(f["analyzed_utc"])} UTC, edgetriage {f["tool_version"]}'),
            ("Packs", ", ".join(f["packs_applied"]) or "none"),
            ("Preflight", f'rebooted: {pf.get("rebooted_since_incident", "unknown")} · upgraded: {pf.get("patched_since_incident", "unknown")}')]
    if m.get("clock_skew"):
        rows.append(("Clock", str(m["clock_skew"])))
    if f.get("manifest_sha256"):
        rows.append(("Case manifest", "sha256 " + f["manifest_sha256"]))
    meta = "".join(f"<dt>{esc(k)}</dt><dd>{esc(val)}</dd>" for k, val in rows)
    steps_by = {s["step_id"]: s for s in (m.get("steps") or [])}
    items, donot = next_steps(level, cat)

    classes = sorted({r["evidence_class"] for r in dets}, key=lambda c: CLASS_ORDER.index(c) if c in CLASS_ORDER else 99)
    grid = ['<div class="vgr h"><span>Evidence class</span><span>possible</span><span>likely</span><span>confirmed</span></div>']
    for c in classes:
        rs = [r for r in dets if r["evidence_class"] == c]
        cells = []
        for t in TIERS:
            pills = []
            for r in rs:
                if top_tier(r) != t:
                    continue
                cls = {"hit": f"hit t-{t}", "not-evaluated": "ne", "no-hit": "nh"}[r["status"]]
                pills.append(f'<span class="pill {cls}" title="{esc(r["title"])}: {words[r["status"]]}">{esc(r["id"])}</span>')
            cells.append(f'<div class="cell">{"".join(pills)}</div>')
        tint = " lk" if any(r["status"] == "hit" and top_tier(r) == "likely" for r in rs) else ""
        grid.append(f'<div class="vgr{tint}"><span class="cls">{esc(c)}</span>{"".join(cells)}</div>')

    gap_html = "".join(
        f'<div class="gap"><span class="kind{" std" if g["kind"] in ("standing", "unvalidated-profile") else ""}">{esc(g["kind"])}</span>'
        f'<p>{re.sub(r"`([^`]+)`", r"<code>\1</code>", esc(str(g["detail"])))}</p>'
        + (f'<p><span class="close">Close it:</span> {esc(g.get("close") or GAP_CLOSE[g["kind"]])}</p>' if g.get("close") or g["kind"] in GAP_CLOSE else "")
        + "</div>" for g in gaps)

    finds = []
    for r in sorted((r for r in dets if r["status"] == "hit"), key=lambda r: -TIERS.index(top_tier(r))):
        t = top_tier(r)
        hits = []
        for h in r["hits"][:10]:
            where = re.sub(r"`([^`]+)`", r"<code>\1</code>", esc(_where(h, steps_by)))   # the command, as a literal
            when = (" · " + esc(str(h["ts"]).replace("T", " ") + ("" if h.get("tz_known") else " (device-local)"))) if h.get("ts") else ""
            hits.append(f'<div class="hitl"><span class="w">{where}{when}</span>'
                        + (f'<div>{esc(str(h["detail"]))}</div>' if h.get("detail") and h["detail"] != r["title"] else "")
                        + (f'<pre><code>{esc(str(h["excerpt"]))}</code></pre>' if h.get("excerpt") else "") + "</div>")
        n = r["hit_count"]
        cves = " ".join(f'<a href="{SITE_URL}#cves/{_quote(c)}">{esc(c)}</a>' for c in r["cves"])
        prov = f' <span class="prov{" unv" if r.get("pack_unverified") or r.get("pack_confidence") == "low" else ""}">{esc(_prov(r))}</span>' if _prov(r) else ""
        meta_line = " · ".join(x for x in [esc(r["pack"]) + prov, cves, esc(r["evidence_class"]), f'{n} hit{"" if n == 1 else "s"}'] if x)
        finds.append(f'<article class="find"><div class="fh"><div><div class="fid">{esc(r["id"])}</div><div class="ft">{esc(r["title"])}</div>'
                     f'<div class="small muted">{meta_line}</div></div><div><span class="badge tier-{t}">{t}</span> '
                     + (f'<a href="{SITE_URL}#hunts/{_quote(r["hunt"])}">Hunt record &#8594;</a>' if r.get("hunt") else
                        f'<a href="{SITE_URL}#detections/{_quote(r["id"])}">Detection record &#8594;</a>')
                     + f'</div></div>{"".join(hits)}'
                     + (f'<p class="note">{esc(r["notes"].strip())}</p>' if r.get("notes") else "") + "</article>")
    if not finds:
        finds.append('<p class="note">No detection fired. That is not a finding that the device is clean: read the evidence gaps above.</p>')
    offbox_html = ""
    if f.get("offbox"):
        offbox_html = ('<h2>Off-box comparison</h2><p class="note">The device\'s syslog as the SIEM received it, lined up by '
                       'message, in order, with the logs left on the box. Runs on one side only appear under Findings as possible '
                       f'indicators. <a href="{SITE_URL}#hunts/EDGE-HUNT-0027">EDGE-HUNT-0027 &#8594;</a></p><dl class="meta">'
                       + "".join(f"<dt>{esc(k)}</dt><dd>{esc(val)}</dd>" for k, val in offbox_rows(f["offbox"])) + "</dl>")

    steps = m.get("steps") or []
    sclass = {"ok": "st-ok", "pending-manual": "st-pending-manual", "error": "st-error"}
    strip = []
    for s in steps:
        at = f' at {_hms(s.get("started_utc"))[11:]}' if s.get("started_utc") else ""
        strip.append(f'<div title="{esc(str(s.get("tier", "")))} {esc(str(s.get("step_id", "")))}: {esc(str(s.get("status", "")))}{esc(at)}">'
                     f'<span class="{sclass.get(s.get("status"), "st-off")}"></span><i>{esc(str(s.get("tier", "")))}</i></div>')
    times = [s[k] for s in steps for k in ("started_utc", "ended_utc") if s.get(k)]
    strip_cap = (f"{len(steps)} steps in order of volatility, {_hms(min(times))[11:]} to {_hms(max(times))[11:]} UTC."
                 if times else f"{len(steps)} steps in order of volatility.")
    stem = cat.get("response")
    respond = (f'<li><a href="{SITE_URL}#response/{_quote(str(stem))}?verdict={_quote(level)}">The {esc(cat.get("name", "platform"))} playbook, '
               f'read with the {esc(level)} lens &#8594;</a></li>' if stem else "")
    nexts = ('<section class="next"><h2>What to do next</h2><ul>' + "".join(f"<li>{esc(x)}</li>" for x in items) + respond + "</ul>"
             + (f'<p class="dnh">From the playbook, do not:</p><ul class="dn">' + "".join(
                 f'<li><b>{esc(d["action"])}.</b> {esc(d["because"])}</li>' for d in donot) + "</ul>" if donot else "") + "</section>")
    n_packs = len(f["packs_applied"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Edge triage report - {esc(f["case_id"])}</title><meta name="color-scheme" content="light dark">
<style>{REPORT_CSS}</style></head>
<body><main class="wrap">
<header class="top"><span class="dot"></span><b>Edge triage report</b><code>{esc(f["case_id"])}</code><span class="pr">Print or save as PDF from the browser (Ctrl+P or Cmd+P)</span></header>
<div class="row1"><section class="vcard" aria-label="Verdict"><div class="lbl">Verdict</div>
<span class="vbig v-{level.lower()}">{esc(level)}</span><p class="rat">{esc(v["rationale"])}</p>
<p class="small muted">Computed deterministically from the hits below. The {len(gaps)} evidence gaps say what this analysis could not see; read them before acting on the verdict.</p>
<div class="sbar" role="img" aria-label="{esc(summary)}">{sbar}</div>
<div class="cap"><span>{len(dets)} detections from {n_packs} pack{"" if n_packs == 1 else "s"}</span><span>{esc(summary)}</span></div></section>
<dl class="meta">{meta}</dl></div>
{nexts}
<h2>How the verdict was reached</h2>
<p class="note">Each detection sits in its evidence class and tier. Likely hits in two different classes corroborate each other; repeated hits in one class would not.</p>
<div class="vg">{"".join(grid)}</div>
<p class="small muted">filled: hit · dashed: not evaluated, a gap · struck: ran, no hit · tinted row: a class with a likely hit</p>
<h2>Evidence gaps - what this analysis could not see</h2>
<div class="gaps">{gap_html}</div>
<h2>Findings</h2>
{"".join(finds)}
{offbox_html}
<h2>Collection</h2>
<div class="strip" role="img" aria-label="{esc(strip_cap)}">{"".join(strip)}</div>
<p class="small muted">{esc(strip_cap)} Green ran; dashed did not run; olive waits for a person; red failed. Hover a block for the step.</p>
<p class="acts">findings.json and report.md sit beside this file; <code>edgetriage timeline</code> and <code>edgetriage brief</code> add timeline.jsonl and llm_brief.md to the same case folder.</p>
</main></body></html>
"""
