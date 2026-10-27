"""Analyzer: run detection packs over a case and score the result.

Three outcomes per detection - hit, no-hit, not-evaluated - and the third is
reported as loudly as the first. A device is never called clean; the best
verdict is NO-INDICATORS-FOUND, and it always ships with its evidence gaps.
"""
from __future__ import annotations

import re
from dataclasses import asdict
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
        why = "possible indicator (often exploitation attempted, success not shown): " + \
              ", ".join(sorted({r["id"] for r in by_tier["possible"]}))
    else:
        level = "NO-INDICATORS-FOUND"
        why = "no detection fired. This is not a finding that the device is clean; read the evidence gaps."
    return {"level": level, "rationale": why}


def evidence_gaps(view: EvidenceView, results: list[dict[str, Any]],
                  window_start: str | None) -> list[dict[str, str]]:
    gaps: list[dict[str, str]] = []
    m = view.manifest
    covered = view.covered_classes()
    for cls in m.get("expected_evidence", []):
        if cls not in covered:
            gaps.append({"kind": "missing-evidence-class", "detail": f"no {cls} evidence in the case"})
    for s in m.get("steps", []):
        if s["status"] == "pending-manual":
            gaps.append({"kind": "manual-step-pending", "detail": f"{s['step_id']}: {s['purpose']}"})
        elif s["status"] in ("unavailable", "error", "refused"):
            gaps.append({"kind": "step-failed", "detail": f"{s['step_id']} ({s['status']}): {s.get('error')}"})
    for r in results:
        if r["status"] == "not-evaluated":
            gaps.append({"kind": "detection-not-evaluated",
                         "detail": f"{r['id']} ({r['pack']}): required evidence not in case"})
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
        if earliest is None or earliest[:19] > window_start[:19]:
            gaps.append({"kind": "log-retention",
                         "detail": f"earliest on-box log line {earliest or 'n/a'} is after the window start {window_start}; use off-box copies"})
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
            pack_dir: Path = PACK_DIR) -> dict[str, Any]:
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
            results.append({
                "pack": pack["id"], "pack_name": pack["name"], "cves": pack.get("cves", []),
                "id": det["id"], "title": det["title"], "type": det["type"], "tier": det["tier"],
                "evidence_class": det["evidence_class"], "attack": det.get("attack", []),
                "status": "not-evaluated" if not evaluated else ("hit" if hits else "no-hit"),
                "hit_count": len(hits), "hits": tiered[:MAX_HITS_KEPT],
                "notes": det.get("notes"),
            })
    out = {
        "case_id": view.manifest["case_id"],
        "platform_id": platform_id,
        "analyzed_utc": utcnow(),
        "tool_version": __version__,
        "packs_applied": [p["id"] for p in packs],
        "baseline_supplied": baseline is not None,
        "window_start": window_start,
        "verdict": verdict(results),
        "detections": results,
        "evidence_gaps": evidence_gaps(view, results, window_start),
    }
    dump_json(Path(case_root) / "findings.json", out)
    (Path(case_root) / "report.md").write_text(render_report(out, view.manifest), encoding="utf-8")
    return out


def render_report(f: dict[str, Any], m: dict[str, Any]) -> str:
    v = f["verdict"]
    hit = [r for r in f["detections"] if r["status"] == "hit"]
    ne = [r for r in f["detections"] if r["status"] == "not-evaluated"]
    clean = [r for r in f["detections"] if r["status"] == "no-hit"]
    L = [
        f"# Edge triage report - {f['case_id']}",
        "",
        f"**Verdict: {v['level']}**  ",
        f"{v['rationale']}",
        "",
        "| | |", "|---|---|",
        f"| Platform | {f['platform_id']} |",
        f"| Profile | {m.get('profile')} |",
        f"| Target | {m.get('target', {}).get('host', 'n/a')} |",
        f"| Collected | {m.get('collection_start_utc', 'n/a')} -> {m.get('collection_end_utc', 'n/a')} |",
        f"| Analyzed | {f['analyzed_utc']} (edgetriage {f['tool_version']}) |",
        f"| Packs | {', '.join(f['packs_applied']) or 'none'} |",
        f"| Detections | {len(hit)} hit, {len(clean)} no hit, {len(ne)} not evaluated |",
        "",
        "## Findings",
        "",
    ]
    if not hit:
        L.append("No detection fired.")
    for r in sorted(hit, key=lambda r: -max(TIERS.index(h["tier"]) for h in r["hits"])):
        top = max((h["tier"] for h in r["hits"]), key=TIERS.index)
        L += [f"### [{top.upper()}] {r['title']}",
              f"`{r['id']}` - {r['pack']} {' '.join(r['cves'])} - {r['hit_count']} hit(s), evidence class {r['evidence_class']}",
              ""]
        for h in r["hits"][:10]:
            where = f"{h['source']}" + (f":{h['line']}" if h.get("line") else "")
            ts = f" ts={h['ts']}{'' if h.get('tz_known') else ' (device-local)'}" if h.get("ts") else ""
            L.append(f"- {where}{ts} - {h['detail']}")
            if h.get("excerpt"):
                L.append(f"  `{h['excerpt'][:200]}`")
        if r.get("notes"):
            L += ["", f"> {r['notes'].strip()}"]
        L.append("")
    L += ["## Evidence gaps", "", "What this analysis could not see. Read before acting on the verdict.", ""]
    for g in f["evidence_gaps"]:
        L.append(f"- **{g['kind']}** - {g['detail']}")
    L += ["", "## Detections not evaluated", ""]
    L += [f"- `{r['id']}` - {r['title']}" for r in ne] or ["None."]
    L.append("")
    return "\n".join(L)
