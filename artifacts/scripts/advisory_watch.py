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
    python artifacts/scripts/advisory_watch.py --records > artifacts/watch/kev-records.yml

artifacts/watch/kev-records.yml is CISA's own fields for every KEV entry the
site shows: each one on a watched platform since `since`, and each one a
record in the repository names in a structured field (a pack's `cves`, an
artifact's, a hunt's, a hardening control's `blunts`...). It is printed by
--records and written by the person who runs it, never by this script. The
site builds one CVE record from each, and flags a record file changed before
its platform's newest entry. When the feed and the file differ, the report
says so.

Exit status: 0 nothing new, 10 something needs triage or the records are out of step, 1 error.
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
RECORDS = ROOT / "artifacts" / "watch" / "kev-records.yml"
NEEDS_TRIAGE = 10
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
# KEV's field names, and what the records file calls them. Kept verbatim.
KEV_FIELDS = {"vendorProject": "vendor", "product": "product", "vulnerabilityName": "name", "dateAdded": "added",
              "dueDate": "due", "knownRansomwareCampaignUse": "ransomware", "forensicTriage": "forensic_triage",
              "cwes": "cwes", "requiredAction": "action", "shortDescription": "description", "notes": "notes"}


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


def structured_refs(root: Path = ROOT) -> set[str]:
    """Every CVE id a repository record names in a structured field. Prose
    mentions do not count: a CVE the repo only talks about is not a record."""
    out: set[str] = set()

    def take(vals) -> None:
        out.update(str(v) for v in vals or [] if CVE_RE.fullmatch(str(v)))
    a = root / "artifacts"
    for p in sorted((a / "packs").glob("*.yml")):
        take(yaml.safe_load(p.read_text()).get("cves"))
    for p in sorted((a / "catalog").glob("*.yml")):
        for art in yaml.safe_load(p.read_text()).get("artifacts", []):
            take(art.get("seen_in"))   # CVE ids and actor names; only the CVE-shaped ones count
    for p in sorted((a / "hunts").glob("*.yml")):
        take(yaml.safe_load(p.read_text()).get("cves"))
    for p in sorted((a / "hardening").glob("*.yml")):
        for c in yaml.safe_load(p.read_text()).get("controls", []):
            take(c.get("blunts"))
    for sub in ("iocs", "implants", "actors"):
        for p in sorted((a / "intel" / sub).glob("*.yml")):
            take(yaml.safe_load(p.read_text()).get("cves"))
    return out


def kev_records(kev: dict, watch: dict, refs: set[str]) -> list[dict]:
    """CISA's fields, verbatim, for each KEV entry on a watched platform since
    `since` and each one the repository names. `platform` is the watch rule the
    entry matches, or null when KEV files it under a product nobody watches."""
    out = []
    for v in kev.get("vulnerabilities", []):
        pid = platform_of(v, watch["platforms"])
        if not ((pid and v.get("dateAdded", "") >= watch["since"]) or v.get("cveID") in refs):
            continue
        rec = {"cve": v["cveID"], "platform": pid}
        for src, dst in KEV_FIELDS.items():
            val = v.get(src, [] if src == "cwes" else "")
            rec[dst] = [str(x) for x in val] if src == "cwes" else str(val).strip()
        out.append(rec)
    return sorted(out, key=lambda r: r["cve"])


def records_text(kev: dict, recs: list[dict]) -> str:
    head = ("# CISA's Known Exploited Vulnerabilities fields, verbatim, for every CVE the\n"
            "# site shows. Generated - do not edit by hand:\n"
            "#   python artifacts/scripts/advisory_watch.py --records > artifacts/watch/kev-records.yml\n"
            "# Schema: ../schema/kev-records.schema.json. The weekly watch reports drift.\n")
    body = {"catalog": str(kev.get("catalogVersion", "")), "released": str(kev.get("dateReleased", ""))[:10], "records": recs}
    return head + yaml.safe_dump(body, sort_keys=False, allow_unicode=True, width=120)


CVE_API = "https://cveawg.mitre.org/api/cve/"
CVE_RECORDS = ROOT / "artifacts" / "watch" / "cve-records.yml"


def cve_record(doc: dict) -> dict:
    """The fields the site shows from one CVE record (CVE JSON 5): when it was
    published and by whom, the CNA's weakness names, and CISA's own Vulnrichment
    decision points (the inputs BOD 26-04 names for its remediation timelines)."""
    meta, cons = doc.get("cveMetadata", {}), doc.get("containers", {})
    cwes = []
    for pt in cons.get("cna", {}).get("problemTypes", []):
        for x in pt.get("descriptions", []):
            m = re.match(r"(CWE-\d+)[\s:]*(.*)", x.get("cweId") or x.get("description", ""))
            cid = x.get("cweId") or (m.group(1) if m else "")
            if cid and cid not in [c["id"] for c in cwes]:
                name = re.sub(rf"^{re.escape(cid)}[\s:]*", "", x.get("description", "")).strip()
                cwes.append({"id": cid, "name": name})
    ssvc = None
    for adp in cons.get("adp", []):
        if adp.get("providerMetadata", {}).get("shortName") != "CISA-ADP":
            continue
        for mt in adp.get("metrics", []):
            o = mt.get("other", {})
            if o.get("type") == "ssvc":
                opts = {k: v for d in o.get("content", {}).get("options", []) for k, v in d.items()}
                ssvc = {"exploitation": str(opts.get("Exploitation", "")), "automatable": str(opts.get("Automatable", "")),
                        "technical_impact": str(opts.get("Technical Impact", "")),
                        "assessed": str(o.get("content", {}).get("timestamp", ""))[:10]}
    return {"cve": meta.get("cveId", ""), "published": str(meta.get("datePublished", ""))[:10],
            "assigner": meta.get("assignerShortName", ""), "cwes": cwes, "cisa_ssvc": ssvc}


def cve_records_text(cves: list[str], getter=fetch) -> str:
    out, missing = [], []
    for c in sorted(cves):
        try:
            out.append(cve_record(json.loads(getter(CVE_API + c))))
        except Exception as e:  # an unreachable record is listed, never guessed
            missing.append(f"{c}: {e.__class__.__name__}")
    head = ("# Fields from each CVE's public record at CVE.org (CVE JSON 5), verbatim, for every CVE the\n"
            "# site shows. Generated - do not edit by hand:\n"
            "#   python artifacts/scripts/advisory_watch.py --cve-records > artifacts/watch/cve-records.yml\n"
            "# cisa_ssvc is CISA's Vulnrichment decision points (CISA-ADP container). Schema:\n"
            "# ../schema/cve-records.schema.json.\n"
            + "".join(f"# not fetched: {m}\n" for m in missing))
    return head + yaml.safe_dump({"source": CVE_API, "records": out}, sort_keys=False, allow_unicode=True, width=120)


def records_drift(have: list[dict], want: list[dict]) -> list[dict]:
    """Where the records file and the feed disagree: missing, changed, or gone from KEV."""
    h, w = {r["cve"]: r for r in have}, {r["cve"]: r for r in want}
    out = []
    for c in sorted(set(h) | set(w)):
        if c not in h:
            out.append({"cve": c, "change": "missing from the file"})
        elif c not in w:
            out.append({"cve": c, "change": "no longer selected or not in KEV"})
        else:
            diff = sorted(k for k in set(h[c]) | set(w[c]) if h[c].get(k) != w[c].get(k))
            if diff:
                out.append({"cve": c, "change": "changed: " + ", ".join(diff)})
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
        L += ["", f"## KEV records out of step with the feed ({len(drift)})", ""]
        if drift:
            L.append("The site's CVE records and its re-read flag read `artifacts/watch/kev-records.yml`. Regenerate it "
                     "with `--records`, read the diff, and commit it.")
            L += ["", "| CVE | Change |", "|---|---|"] + [f"| {r['cve']} | {r['change']} |" for r in drift]
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
    ap.add_argument("--records", action="store_true", help="print kev-records.yml, from the feed")
    ap.add_argument("--records-file", type=Path, default=RECORDS, help="the records file to compare with the feed")
    ap.add_argument("--cve-records", action="store_true",
                    help="print cve-records.yml: each shown CVE's CVE.org record (published date, CWEs, CISA SSVC)")
    ap.add_argument("--out", type=Path, help="write the Markdown report here")
    a = ap.parse_args(argv)
    watch = load_watch(a.watch)
    kev = json.loads(a.kev.read_bytes() if a.kev else fetch(watch["kev_url"]))
    if not kev.get("vulnerabilities"):
        print("KEV catalog has no vulnerabilities - refusing to report on an empty or wrong file", file=sys.stderr)
        return 1
    res = triage(kev, watch, pack_cves())
    changes = upstream_changes(watch, ioc_files()) if a.upstream else None
    want = kev_records(kev, watch, structured_refs())
    if a.records:   # the file alone, for the person to redirect and commit
        print(records_text(kev, want), end="")
        return 0
    if a.cve_records:   # every CVE the site shows: the KEV records plus the CVEs records name
        print(cve_records_text(sorted({r["cve"] for r in want} | structured_refs())), end="")
        return 0
    have = (yaml.safe_load(a.records_file.read_text()) or {}).get("records") or [] if a.records_file.is_file() else []
    drift = records_drift(have, want)
    text = report(kev, res, changes, drift)
    if a.out:
        a.out.write_text(text)
    print(text)
    if a.draft and res["new"]:
        print(draft(res, kev.get("dateReleased", "")[:10]))
    return NEEDS_TRIAGE if res["new"] or changes or drift else 0


if __name__ == "__main__":
    sys.exit(main())
