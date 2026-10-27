#!/usr/bin/env python3
"""advisory_watch.py - what has been exploited that the repository does not cover yet.

Compares CISA's Known Exploited Vulnerabilities catalog with the detection
packs and the triage ledger in artifacts/watch/kev-watch.yml, and (with
--upstream) re-hashes the publisher files behind the indicator sets.

It never edits the repository. It reports; a person reads the primary
sources, then either adds a pack or indicator set, or records a decision in
the ledger, and the validator gates the result. The weekly workflow posts the
report to an issue.

    python artifacts/scripts/advisory_watch.py                 # fetch KEV, report
    python artifacts/scripts/advisory_watch.py --kev kev.json  # offline
    python artifacts/scripts/advisory_watch.py --upstream      # also re-hash indicator files
    python artifacts/scripts/advisory_watch.py --draft         # ledger stubs for new entries
    python artifacts/scripts/advisory_watch.py --dates         # the kev_added block, from the feed

`kev_added` in the ledger holds CISA's dateAdded for every KEV entry on a
watched platform since `since`. The site flags records whose file was last
changed before their platform's newest entry. When the feed and the block
differ, the report says so and --dates prints the replacement; a person
pastes it, as with every other ledger change.

Exit status: 0 nothing new, 10 something needs triage or the dates are out of step, 1 error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WATCH = ROOT / "artifacts" / "watch" / "kev-watch.yml"
NEEDS_TRIAGE = 10


def load_watch(path: Path = WATCH) -> dict:
    return yaml.safe_load(path.read_text())


def pack_cves(root: Path = ROOT) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for p in sorted((root / "artifacts" / "packs").glob("*.yml")):
        d = yaml.safe_load(p.read_text())
        for c in d.get("cves", []):
            out.setdefault(c, []).append(d["id"])
    return out


def ioc_files(root: Path = ROOT) -> dict[str, str]:
    out = {}
    for p in sorted((root / "artifacts" / "intel" / "iocs").glob("*.yml")):
        d = yaml.safe_load(p.read_text())
        if d.get("file_url"):
            out[d["id"]] = d["file_url"]
    return out


def fetch(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "edge-dfir-toolkit advisory_watch"})
    with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 - https URLs from the repo
        return r.read()


def platform_of(entry: dict, platforms: dict) -> str | None:
    vendor, product = entry.get("vendorProject", ""), entry.get("product", "")
    for pid, rule in platforms.items():
        if re.search(rule["vendor"], vendor) and re.search(rule["product"], product) \
                and not (rule.get("exclude") and re.search(rule["exclude"], product)):
            return pid
    return None


def triage(kev: dict, watch: dict, covered: dict[str, list[str]]) -> dict[str, list[dict]]:
    ledger = {t["cve"]: t for t in watch.get("triaged") or []}
    res: dict[str, list[dict]] = {"new": [], "deferred": [], "decided": [], "covered": []}
    for v in kev.get("vulnerabilities", []):
        pid = platform_of(v, watch["platforms"])
        if not pid or v.get("dateAdded", "") < watch["since"]:
            continue
        row = {"cve": v["cveID"], "platform": pid, "added": v.get("dateAdded", ""),
               "product": v.get("product", "").strip(), "name": v.get("vulnerabilityName", ""),
               "ransomware": v.get("knownRansomwareCampaignUse", "")}
        if row["cve"] in covered:
            res["covered"].append({**row, "refs": covered[row["cve"]]})
        elif row["cve"] in ledger:
            t = ledger[row["cve"]]
            res["deferred" if t["decision"] == "deferred" else "decided"].append({**row, **t})
        else:
            res["new"].append(row)
    for k in res:
        res[k].sort(key=lambda r: (r["added"], r["cve"]), reverse=True)
    return res


def kev_dates(kev: dict, watch: dict) -> dict[str, dict[str, str]]:
    """CISA's dateAdded for each KEV entry on a watched platform since `since`,
    by platform, oldest first. Parsed from the feed, never typed in."""
    out: dict[str, dict[str, str]] = {}
    for v in sorted(kev.get("vulnerabilities", []), key=lambda v: (v.get("dateAdded", ""), v.get("cveID", ""))):
        pid = platform_of(v, watch["platforms"])
        if pid and v.get("dateAdded", "") >= watch["since"]:
            out.setdefault(pid, {})[v["cveID"]] = v["dateAdded"]
    return dict(sorted(out.items()))


def date_drift(watch: dict, dates: dict[str, dict[str, str]]) -> list[dict]:
    """Where the ledger's kev_added and the feed disagree: missing, changed, or gone from KEV."""
    have = {(pid, c): d for pid, cs in (watch.get("kev_added") or {}).items() for c, d in cs.items()}
    want = {(pid, c): d for pid, cs in dates.items() for c, d in cs.items()}
    out = [{"platform": p, "cve": c, "ledger": have.get((p, c), "missing"), "feed": want.get((p, c), "not in KEV")}
           for (p, c) in sorted(set(have) | set(want)) if have.get((p, c)) != want.get((p, c))]
    return out


def upstream_changes(watch: dict, files: dict[str, str], getter=fetch) -> list[dict]:
    out = []
    for iid, want in sorted(watch.get("upstream", {}).items()):
        url = files.get(iid)
        try:
            got = hashlib.sha256(getter(url)).hexdigest() if url else None
            if got != want:
                out.append({"id": iid, "url": url, "was": want, "now": got or "no file_url"})
        except Exception as e:  # unreachable is reported, not fatal
            out.append({"id": iid, "url": url, "was": want, "now": f"unreachable: {e.__class__.__name__}"})
    return out


def report(kev: dict, res: dict, changes: list[dict] | None, drift: list[dict] | None = None) -> str:
    L = [f"# Advisory watch - KEV catalog {kev.get('catalogVersion', '?')}", ""]
    L.append("Nothing here is added to the repository automatically. For each item: read the vendor's "
             "advisory and any government or researcher publication it cites, then add a pack or an "
             "indicator set if a primary source publishes indicators, or record a decision in "
             "`artifacts/watch/kev-watch.yml`. The validator gates either.")
    L += ["", f"## New - not covered and not triaged ({len(res['new'])})", ""]
    if res["new"]:
        L += ["| Added | CVE | Platform | KEV product | Name | Ransomware |", "|---|---|---|---|---|---|"]
        L += [f"| {r['added']} | {r['cve']} | {r['platform']} | {r['product']} | {r['name']} | {r['ransomware']} |"
              for r in res["new"]]
    else:
        L.append("None.")
    if changes is not None:
        L += ["", f"## Indicator files changed upstream ({len(changes)})", ""]
        L += [f"- {c['id']}: {c['url']} - was `{c['was'][:12]}`, now `{c['now'][:40]}`. Re-parse, diff, "
              "re-validate." for c in changes] or ["None."]
    if drift is not None:
        L += ["", f"## KEV dates out of step with the ledger ({len(drift)})", ""]
        if drift:
            L.append("The site compares each record's last change with these dates. Run with `--dates` and replace "
                     "`kev_added` in `artifacts/watch/kev-watch.yml` with the block it prints.")
            L += ["", "| Platform | CVE | Ledger | Feed |", "|---|---|---|---|"]
            L += [f"| {r['platform']} | {r['cve']} | {r['ledger']} | {r['feed']} |" for r in drift]
        else:
            L.append("None.")
    L += ["", f"## Deferred - still to triage ({len(res['deferred'])})", ""]
    L += [f"- {r['added']} {r['cve']} ({r['platform']}, {r['product']}): {r['basis']}"
          for r in res["deferred"]] or ["None."]
    L += ["", f"Covered by packs: {len(res['covered'])}. Decided without a pack: {len(res['decided'])}."]
    return "\n".join(L) + "\n"


def draft(res: dict, today: str) -> str:
    return yaml.safe_dump([{"cve": r["cve"], "platform": r["platform"], "decision": "deferred", "date": today,
                            "basis": "not yet triaged against primary sources"} for r in res["new"]],
                          sort_keys=False)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--kev", type=Path, help="local copy of known_exploited_vulnerabilities.json")
    ap.add_argument("--watch", type=Path, default=WATCH)
    ap.add_argument("--upstream", action="store_true", help="re-hash the publisher files behind indicator sets")
    ap.add_argument("--draft", action="store_true", help="print ledger stubs for new entries")
    ap.add_argument("--dates", action="store_true", help="print the kev_added block for the ledger, from the feed")
    ap.add_argument("--out", type=Path, help="write the Markdown report here")
    a = ap.parse_args(argv)
    watch = load_watch(a.watch)
    kev = json.loads(a.kev.read_bytes() if a.kev else fetch(watch["kev_url"]))
    if not kev.get("vulnerabilities"):
        print("KEV catalog has no vulnerabilities - refusing to report on an empty or wrong file", file=sys.stderr)
        return 1
    res = triage(kev, watch, pack_cves())
    changes = upstream_changes(watch, ioc_files()) if a.upstream else None
    dates = kev_dates(kev, watch)
    drift = date_drift(watch, dates)
    if a.dates:   # the block alone, so it can be pasted over kev_added
        print(yaml.safe_dump({"kev_added": dates}, sort_keys=False), end="")
        return 0
    text = report(kev, res, changes, drift)
    if a.out:
        a.out.write_text(text)
    print(text)
    if a.draft and res["new"]:
        print(draft(res, kev.get("dateReleased", "")[:10]))
    return NEEDS_TRIAGE if res["new"] or changes or drift else 0


if __name__ == "__main__":
    sys.exit(main())
