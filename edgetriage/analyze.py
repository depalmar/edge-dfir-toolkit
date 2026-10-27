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
    (Path(case_root) / "report.html").write_text(render_html(out, view.manifest), encoding="utf-8")
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


# --------------------------------------------------------------------------- report.html
# The same findings as report.md, laid out verdict first. One self-contained
# file: no script, no font, no request, and no link except back to the published
# toolkit. Every value is escaped - excerpts, sources, paths and gap details come
# from a compromised device and are attacker-influenced data. Like report.md it
# stays in the case folder and is never published.
SITE_URL = "https://depalmar.github.io/edge-dfir-toolkit/"
CLASS_ORDER = ["identity", "memory", "process", "sessions", "integrity", "config",
               "auth-logs", "web-logs", "system-logs", "filesystem", "persistence"]
GAP_CLOSE = {
    "missing-evidence-class": "Ingest the off-box copy for the window: edgetriage ingest <case> --label <name> --bundle <file>.",
    "detection-not-evaluated": "Collect or ingest the evidence this detection reads.",
    "manual-step-pending": "Run it by hand and record the outcome, or record why not. Break-glass steps run last, after preservation.",
    "step-failed": "Re-run the step or record the error; check the profile's prompt and pager.",
    "volatile-lost": "Memory-only evidence is gone; rely on off-box telemetry for the window.",
    "upgraded": "Ask the vendor about pre-upgrade logs; use off-box copies.",
    "log-retention": "Pull the off-box syslog from the window start to the earliest on-box line.",
    "standing": "Corroborate with NetFlow for the management interface and IdP logons for the same hours.",
    "unvalidated-profile": "Read the step statuses in manifest.json before relying on any absence.",
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
.s-hit{background:var(--crit)}.s-no-hit{background:var(--low)}.s-not-evaluated{background:var(--med)}
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


def _hms(ts: str | None) -> str:
    return (ts or "").replace("T", " ").rstrip("Z").split(".")[0]


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
            ("Profile", str(m.get("profile")) + (", not yet run on a real device" if pv is not None and not pv.get("validated_on") else "")),
            ("Target", str((m.get("target") or {}).get("host", "n/a"))),
            ("Collected", f'{_hms(m.get("collection_start_utc"))} to {_hms(m.get("collection_end_utc"))[11:]} UTC'),
            ("Analyzed", f'{_hms(f["analyzed_utc"])} UTC, edgetriage {f["tool_version"]}'),
            ("Packs", ", ".join(f["packs_applied"]) or "none"),
            ("Preflight", f'rebooted: {pf.get("rebooted_since_incident", "unknown")} · upgraded: {pf.get("patched_since_incident", "unknown")}')]
    if m.get("clock_skew"):
        rows.append(("Clock", str(m["clock_skew"])))
    meta = "".join(f"<dt>{esc(k)}</dt><dd>{esc(val)}</dd>" for k, val in rows)

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
        f'<p>{esc(str(g["detail"]))}</p>'
        + (f'<p><span class="close">Close it:</span> {esc(GAP_CLOSE[g["kind"]])}</p>' if g["kind"] in GAP_CLOSE else "")
        + "</div>" for g in gaps)

    finds = []
    for r in sorted((r for r in dets if r["status"] == "hit"), key=lambda r: -TIERS.index(top_tier(r))):
        t = top_tier(r)
        hits = []
        for h in r["hits"][:10]:
            where = str(h.get("source", "")) + (f':{h["line"]}' if h.get("line") else "")
            when = (str(h["ts"]).replace("T", " ") + ("" if h.get("tz_known") else " (device-local)")) if h.get("ts") else "no timestamp"
            hits.append(f'<div class="hitl"><span class="w">{esc(where)} · {esc(when)}</span>'
                        + (f'<div>{esc(str(h["detail"]))}</div>' if h.get("detail") else "")
                        + (f'<pre><code>{esc(str(h["excerpt"]))}</code></pre>' if h.get("excerpt") else "") + "</div>")
        n = r["hit_count"]
        meta_line = " · ".join(esc(x) for x in [r["pack"], " ".join(r["cves"]), r["evidence_class"], f'{n} hit{"" if n == 1 else "s"}'] if x)
        finds.append(f'<article class="find"><div class="fh"><div><div class="fid">{esc(r["id"])}</div><div class="ft">{esc(r["title"])}</div>'
                     f'<div class="small muted">{meta_line}</div></div><div><span class="badge tier-{t}">{t}</span> '
                     f'<a href="{SITE_URL}#detections/{_quote(r["id"])}">Detection record &#8594;</a></div></div>{"".join(hits)}'
                     + (f'<p class="note">{esc(r["notes"].strip())}</p>' if r.get("notes") else "") + "</article>")
    if not finds:
        finds.append('<p class="note">No detection fired. That is not a finding that the device is clean: read the evidence gaps above.</p>')

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
    respond = (f'<a href="{SITE_URL}#response/{_quote(str(stem))}?verdict={_quote(level)}">Respond: playbook with the {esc(level)} lens &#8594;</a><br>'
               if stem else "")
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
<h2>How the verdict was reached</h2>
<p class="note">Each detection sits in its evidence class and tier. Likely hits in two different classes corroborate each other; repeated hits in one class would not.</p>
<div class="vg">{"".join(grid)}</div>
<p class="small muted">filled: hit · dashed: not evaluated, a gap · struck: ran, no hit · tinted row: a class with a likely hit</p>
<h2>Evidence gaps - what this analysis could not see</h2>
<div class="gaps">{gap_html}</div>
<h2>Findings</h2>
{"".join(finds)}
<h2>Collection</h2>
<div class="strip" role="img" aria-label="{esc(strip_cap)}">{"".join(strip)}</div>
<p class="small muted">{esc(strip_cap)} Green ran; dashed did not run; olive waits for a person; red failed. Hover a block for the step.</p>
<p class="acts">{respond}findings.json and report.md sit beside this file; <code>edgetriage timeline</code> and <code>edgetriage brief</code> add timeline.jsonl and llm_brief.md to the same case folder.</p>
</main></body></html>
"""
