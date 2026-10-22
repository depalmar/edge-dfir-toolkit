"""edge-triage command line.

  edge-triage profiles
  edge-triage plan     --profile panos [--allow-bundle] [--break-glass]
  edge-triage collect  --profile panos --host 192.0.2.10 --user ir-ro --case-id IR-1 ...
  edge-triage ingest   <case> --label tsf --bundle tsf.tgz [--platform EDGE-0001]
  edge-triage analyze  <case> [--baseline b.json] [--window-start 2026-10-01T00:00:00]
  edge-triage timeline <case>
  edge-triage brief    <case>
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from . import __version__
from .analyze import analyze
from .checks.generic import load_baseline
from .collect import CollectionRefused, collect, plan
from .custody import Case
from .profiles import ProfileError, available_profiles, get_profile, load_profile
from .report_extras import build_brief, build_timeline
from .transport import ReplayTransport, SSHTransport, TransportError


def _vars(pairs: list[str] | None) -> dict[str, str]:
    out = {}
    for p in pairs or []:
        if "=" not in p:
            raise SystemExit(f"--var expects name=value, got {p!r}")
        k, v = p.split("=", 1)
        out[k] = v
    return out


def cmd_profiles(_a) -> int:
    for name, path in available_profiles().items():
        p = load_profile(path)
        print(f"{name:<12} {p.platform_id}  {p.display}  ({len(p.steps)} steps)")
    return 0


def cmd_plan(a) -> int:
    prof = get_profile(a.profile)
    print(f"# {prof.display} - order of volatility\n")
    for s, skip in plan(prof, a.allow_bundle, a.break_glass, _vars(a.var)):
        what = s.cmd or s.list_cmd or "(manual)"
        flag = f"  [SKIP: {skip}]" if skip else ""
        unv = "  [unverified]" if s.unverified else ""
        print(f"{s.tier:>2}  {s.impact:<13} {s.id:<24} {what}{flag}{unv}")
    held = [s for s in prof.steps if s not in prof.ordered(a.allow_bundle, a.break_glass)]
    if held:
        print(f"\n{len(held)} step(s) withheld; enable with --allow-bundle / --break-glass:")
        for s in held:
            print(f"    {s.impact:<13} {s.id}")
    return 0


def cmd_collect(a) -> int:
    prof = get_profile(a.profile)
    if a.replay:
        transport = ReplayTransport(Path(a.replay))
        target = {"host": a.host or "replay", "replay_dir": str(a.replay)}
    else:
        if not (a.host and a.user):
            raise SystemExit("--host and --user are required (or --replay DIR)")
        password = os.environ.get(a.password_env) if a.password_env else None
        if password is None and not a.key:
            password = getpass.getpass(f"password for {a.user}@{a.host}: ")
        transport = SSHTransport(a.host, a.user, password=password, key_filename=a.key, port=a.port,
                                 prompt=prof.prompt, pager=prof.pager, hostkey_sha256=a.hostkey_sha256)
        target = {"host": a.host, "port": a.port, "user": a.user}

    def confirm(msg: str) -> bool:
        if a.yes:
            return True
        print(msg, file=sys.stderr)
        return input("Type BREAK-GLASS to continue: ").strip() == "BREAK-GLASS"

    case = Case(Path(a.output) / a.case_id)
    try:
        m = collect(prof, transport, case, case_id=a.case_id, operator=a.operator, target=target,
                    preflight={"rebooted_since_incident": a.rebooted, "patched_since_incident": a.patched,
                               "notes": a.notes or ""},
                    variables=_vars(a.var), allow_bundle=a.allow_bundle, break_glass=a.break_glass,
                    confirm=confirm)
    except (CollectionRefused, TransportError, ProfileError) as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2
    print(f"[+] case {a.case_id} -> {case.root}")
    print("    " + ", ".join(f"{k}={v}" for k, v in sorted(m["summary"].items())))
    pending = [s["step_id"] for s in m["steps"] if s["status"] == "pending-manual"]
    if pending:
        print(f"    manual steps pending: {', '.join(pending)} (see manifest.json for instructions)")
    return 0


def cmd_ingest(a) -> int:
    case = Case(Path(a.case))
    if case.exists():
        m = case.load()
    else:
        if not a.platform:
            raise SystemExit("new case: --platform EDGE-XXXX is required")
        m = Case.new_manifest(case.root.name, a.operator, a.platform, None)
        m["expected_evidence"] = []
    if a.platform and m.get("platform_id") and a.platform != m["platform_id"]:
        raise SystemExit(f"case platform is {m['platform_id']}, not {a.platform}")
    rec = case.ingest(Path(a.bundle), a.label, extract=not a.no_extract, evidence_classes=a.evidence_class)
    m["ingested"].append(rec)
    digest = case.save(m)
    print(f"[+] ingested {rec['source_name']} sha256={rec['sha256']} verified={rec['copy_verified']}")
    if rec["extract_rejected"]:
        print(f"    {len(rec['extract_rejected'])} archive member(s) refused (recorded in manifest):")
        for r in rec["extract_rejected"][:10]:
            print(f"      {r}")
    print(f"    manifest sha256={digest}")
    return 0


def cmd_analyze(a) -> int:
    baseline = load_baseline(a.baseline) if a.baseline else None
    out = analyze(Path(a.case), platform_id=a.platform, all_packs=a.all_packs,
                  baseline=baseline, window_start=a.window_start)
    v = out["verdict"]
    print(f"VERDICT: {v['level']}\n  {v['rationale']}")
    for r in out["detections"]:
        if r["status"] == "hit":
            print(f"  [hit] {r['id']} x{r['hit_count']}")
    ne = sum(1 for r in out["detections"] if r["status"] == "not-evaluated")
    print(f"  {ne} detection(s) not evaluated, {len(out['evidence_gaps'])} evidence gap(s)")
    print(f"  report: {Path(a.case) / 'report.md'}")
    return 0


def cmd_timeline(a) -> int:
    rows = build_timeline(Path(a.case))
    print(f"[+] {len(rows)} timeline rows -> timeline.jsonl, timeline.csv")
    return 0


def cmd_brief(a) -> int:
    print(f"[+] {build_brief(Path(a.case))}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="edge-triage", description="Forensic triage for edge devices.")
    ap.add_argument("--version", action="version", version=f"edgetriage {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("profiles", help="list collection profiles").set_defaults(fn=cmd_profiles)

    p = sub.add_parser("plan", help="show what a profile will run, in order")
    p.add_argument("--profile", required=True)
    p.add_argument("--allow-bundle", action="store_true")
    p.add_argument("--break-glass", action="store_true")
    p.add_argument("--var", action="append", metavar="NAME=VALUE")
    p.set_defaults(fn=cmd_plan)

    c = sub.add_parser("collect", help="collect from a device (or a replay directory)")
    c.add_argument("--profile", required=True)
    c.add_argument("--case-id", required=True)
    c.add_argument("--output", default="./cases")
    c.add_argument("--operator")
    c.add_argument("--host")
    c.add_argument("--port", type=int, default=22)
    c.add_argument("--user")
    c.add_argument("--key", help="SSH private key file")
    c.add_argument("--password-env", help="read the password from this environment variable")
    c.add_argument("--hostkey-sha256", help="pin the device host key (SHA256:...) instead of known_hosts")
    c.add_argument("--replay", help="serve recorded outputs from this directory instead of SSH")
    c.add_argument("--var", action="append", metavar="NAME=VALUE")
    c.add_argument("--allow-bundle", action="store_true", help="permit vendor diagnostic bundles (writes a temp file on the device)")
    c.add_argument("--break-glass", action="store_true", help="include break-glass steps (core dumps, imaging); runs last")
    c.add_argument("--yes", action="store_true", help="skip the break-glass confirmation prompt")
    c.add_argument("--rebooted", choices=["yes", "no", "unknown"], default="unknown",
                   help="has the device rebooted since the suspected incident?")
    c.add_argument("--patched", choices=["yes", "no", "unknown"], default="unknown",
                   help="has the device been upgraded since the suspected incident?")
    c.add_argument("--notes")
    c.set_defaults(fn=cmd_collect)

    i = sub.add_parser("ingest", help="add a vendor bundle, export or image-triage output to a case")
    i.add_argument("case")
    i.add_argument("--bundle", required=True)
    i.add_argument("--label", required=True)
    i.add_argument("--platform", help="platform id, required when the case does not exist yet")
    i.add_argument("--operator")
    i.add_argument("--evidence-class", action="append",
                   help="what this proves, e.g. memory, web-logs, filesystem (repeatable)")
    i.add_argument("--no-extract", action="store_true")
    i.set_defaults(fn=cmd_ingest)

    z = sub.add_parser("analyze", help="run detection packs and score the case")
    z.add_argument("case")
    z.add_argument("--platform")
    z.add_argument("--all-packs", action="store_true")
    z.add_argument("--baseline", help="JSON {path: sha256} from a known-good device of the same build")
    z.add_argument("--window-start", help="ISO time the suspected exploitation window opens")
    z.set_defaults(fn=cmd_analyze)

    t = sub.add_parser("timeline", help="write timeline.jsonl / timeline.csv from findings")
    t.add_argument("case")
    t.set_defaults(fn=cmd_timeline)

    b = sub.add_parser("brief", help="write an LLM brief with cited, hashed records")
    b.add_argument("case")
    b.set_defaults(fn=cmd_brief)
    return ap


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        return a.fn(a)
    except ProfileError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
