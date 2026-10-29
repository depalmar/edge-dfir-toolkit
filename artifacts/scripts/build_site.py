#!/usr/bin/env python3
"""build_site.py - generate the GitHub Pages site from the repository.

  python artifacts/scripts/build_site.py          # write docs/site/index.html
  python artifacts/scripts/build_site.py --check  # data contract only, writes nothing

One self-contained HTML file: vanilla JS, no framework, no CDN, no build step,
never hand-edited and never committed. CI builds it at deploy time from the
catalog, the collection profiles, the detection packs, the rules, the intel and
the investigation guide, so the page cannot drift from the content.

Layout. Five libraries - artifacts, platforms, detections, rules and threat
intel - are rendered in the browser from one JSON block: a facet rail with live
counts, a search box, "N of M shown", a detail drawer with a deep link per
record, and CSV/JSON export. Filter state lives in the URL
(#artifacts?platform=EDGE-0003&volatility=live) so a filtered view can be sent
to someone. Collection plans, response playbooks, coverage and the guide are
rendered here, server-side, because they are documents rather than libraries.
"""
from __future__ import annotations

import datetime as _dt
import html
import inspect
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

from edgetriage import __version__  # noqa: E402
from edgetriage.checks import REGISTRY  # noqa: E402
from edgetriage.profiles import TIER_CLASS, TIER_ORDER, available_profiles, load_profile  # noqa: E402

OUT = ROOT / "docs" / "site" / "index.html"
REPO_URL = "https://github.com/depalmar/edge-dfir-toolkit"
AUTHOR, AUTHOR_URL = "Raymond DePalma", "https://www.linkedin.com/in/raymond-depalma/"
FIRM, FIRM_URL = "DePalma Research LLC", "https://www.linkedin.com/company/depalma-research"
TIERS = ("possible", "likely", "confirmed")
CLASSES = ["identity", "memory", "process", "sessions", "integrity", "config",
           "auth-logs", "web-logs", "system-logs", "filesystem", "persistence"]
ART_CLASSES = CLASSES + ["off-box"]
TIER_LABEL = {
    "V0": "Identity and clock", "V1": "Memory state", "V2": "Processes and sockets",
    "V3": "Active sessions", "P1": "Integrity", "P2": "Configuration", "P3": "Auth and VPN logs",
    "P4": "Web and portal logs", "P5": "System and crash logs", "P6": "Filesystem",
    "P7": "Persistence", "B": "Vendor bundles", "X": "Break-glass",
}
# Rule directories are numbered by when a platform was added, not by catalog id
# (08 is IOS XE = EDGE-0009). A new directory without an entry fails --check.
RULE_DIR_PLATFORM = {
    "01-panos-globalprotect": "EDGE-0001", "02-fortinet-fortios": "EDGE-0002",
    "03-ivanti-connect-secure": "EDGE-0003", "04-citrix-netscaler": "EDGE-0004",
    "05-cisco-asa-ftd": "EDGE-0005", "06-sonicwall-sma": "EDGE-0006",
    "07-checkpoint-quantum": "EDGE-0007", "08-cisco-ios-xe": "EDGE-0009",
    "09-juniper-junos": "EDGE-0008", "10-f5-bigip": "EDGE-0010",
}
# The facet keys each library understands. The JS defines the facets; it logs
# an error if its keys differ from these, and --check validates every static
# "#lib?key=value" link against them.
FACET_KEYS = {
    "artifacts": ["platform", "class", "volatility", "value", "evidence", "kind", "confidence", "basis", "seen"],
    "platforms": ["vendor", "shell", "memory", "profile"],
    "cves": ["platform", "triage", "expl", "ransomware", "coverage", "cwe", "year"],
    "detections": ["platform", "runs", "pack", "tier", "evidence", "type", "attack", "cve", "actor"],
    "intel": ["kind", "platform", "motivation", "type", "resides", "reboot", "coverage", "iocs", "reporter"],
    "hardening": ["platform", "category", "priority", "confidence"],
    "hunts": ["platform", "data", "actor", "confidence"],
}
LIBS = list(FACET_KEYS)
e = html.escape


def js_data(obj) -> str:
    """JSON for a <script> block, with "</" escaped so no string in the corpus
    can close the script element early."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).replace("</", "<\\/")


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def short(name: str) -> str:
    return re.sub(r"\s*\([^)]*\)", "", name).strip()


# The name a picker, facet or matrix column shows. Card headers keep the full
# name; --check fails if a catalog platform has no entry here.
PLATFORM_ABBR = {
    "EDGE-0001": "PAN-OS", "EDGE-0002": "FortiOS", "EDGE-0003": "Ivanti", "EDGE-0004": "NetScaler",
    "EDGE-0005": "ASA/FTD", "EDGE-0006": "SMA 100", "EDGE-0007": "Check Point", "EDGE-0008": "Junos",
    "EDGE-0009": "IOS XE", "EDGE-0010": "BIG-IP",
}


def build_date() -> _dt.date:
    return _dt.datetime.now(_dt.timezone.utc).date()


def ymd(v) -> float | None:
    """A date as a fractional year, for placing marks on a time axis."""
    m = re.match(r"^(\d{4})(?:-(\d{2}))?(?:-(\d{2}))?", str(v or ""))
    return int(m.group(1)) + (int(m.group(2) or 1) - 1) / 12 + (int(m.group(3) or 1) - 1) / 365 if m else None


def refs_of(items) -> list[dict]:
    return [{"title": r["title"], "url": r["url"]} for r in items or []]


# --------------------------------------------------------------------------- load
def git_dates() -> dict[str, str]:
    """Last commit date (YYYY-MM-DD) of every file under artifacts/, from one git
    log walk. Empty when git or the history is unavailable, so --check still runs;
    the Pages workflow checks out the full history (fetch-depth: 0) for real dates.
    Commits listed in .git-blame-ignore-revs (a reformat, a field rename) are
    skipped, so a mechanical sweep does not make every file look newly read."""
    ignore_file = ROOT / ".git-blame-ignore-revs"
    ignore = [ln.split("#")[0].strip() for ln in ignore_file.read_text().splitlines()] if ignore_file.is_file() else []
    ignore = [r for r in ignore if len(r) >= 7]
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "log", "--format=@%H %cs", "--name-only", "--", "artifacts"],
                             capture_output=True, text=True, timeout=60, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    dates: dict[str, str] = {}
    cur = ""
    for ln in out.splitlines():
        if ln.startswith("@"):
            sha, day = ln[1:].split()
            cur = "" if any(sha.startswith(r) for r in ignore) else day
        elif ln.strip() and cur:
            dates.setdefault(ln.strip(), cur)
    return dates


def cve_universe(d: dict) -> set[str]:
    """Every CVE the site gives a record: each one in the KEV records file, and each
    one a repository record names in a structured field (prose mentions do not count)."""
    out = {r["cve"] for r in d["kev"].get("records", [])}

    def take(vals) -> None:
        out.update(str(v) for v in vals or [] if CVE_FULL.fullmatch(str(v)))
    for p in d["packs"]:
        take(p.get("cves"))
    for c in d["catalog"]:
        for a in c.get("artifacts", []):
            take(a.get("seen_in"))
    for h in d["hunts"]:
        take(h.get("cves"))
    for h in d["hardening"].values():
        for c in h["controls"]:
            take(c.get("blunts"))
    for x in d["iocs"] + d["implants"] + d["actors"]:
        take(x.get("cves"))
    return out


def period_end(p: str) -> str:
    """The last day of a YYYY, YYYY-MM or YYYY-MM-DD period, for comparisons that must not
    read "August 2023" as earlier than it is."""
    if len(p) >= 10:
        return p[:10]
    if len(p) == 7:
        y, m = int(p[:4]), int(p[5:7])
        return (_dt.date(y + (m == 12), m % 12 + 1, 1) - _dt.timedelta(days=1)).isoformat()
    return p[:4] + "-12-31"


def platform_events(d: dict) -> dict[str, tuple[str, str]]:
    """The newest dated outside event for each platform: a KEV entry (CISA's
    dateAdded, from the ledger's kev_added) or an indicator set's publication."""
    ev: dict[str, tuple[str, str]] = {}

    def bump(pid: str, day: str, what: str) -> None:
        if day and (pid not in ev or day > ev[pid][0]):
            ev[pid] = (day, what)
    for pid, cves in (d["kev"].get("added") or {}).items():
        for c, day in cves.items():
            bump(pid, str(day), f"KEV {c}, added {day}")
    for st in d["iocs"]:
        for pid in st.get("platforms") or []:
            bump(pid, str(st["published"]), f"{st['publisher']} indicator set {st['id']}, published {st['published']}")
    return ev


def file_platforms(x: dict) -> list[str]:
    """The specific platforms a record file speaks for. ALL (baseline hardening,
    hunts for any device) is compared with nothing: no one platform's advisory dates it."""
    if "platform_id" in x:
        ps = [x["platform_id"]]
    elif "platforms" in x:
        ps = list(x["platforms"])
    elif re.fullmatch(r"EDGE-\d{4}", str(x.get("id", ""))):
        ps = [x["id"]]   # a catalog file is its platform
    else:
        ps = []
    return [p for p in ps if p != "ALL"]


def reread(x: dict, dates: dict[str, str], events: dict[str, tuple[str, str]]) -> list[str]:
    """[event date, what] when the file's last commit is older than the newest
    advisory on one of its platforms; [] otherwise, or when the date is unknown.
    A commit is not a review: an unrelated edit after the advisory clears it too."""
    day = dates.get(x.get("_file", ""), "")
    hits = [events[p] for p in file_platforms(x) if day and p in events and events[p][0] > day]
    return list(max(hits)) if hits else []


def _yml(p: Path) -> dict:
    """A YAML record plus the repository path it came from, for its last-changed date."""
    doc = yaml.safe_load(p.read_text())
    doc["_file"] = p.relative_to(ROOT).as_posix()
    return doc


def load() -> dict:
    catalog = sorted((_yml(p) for p in (ROOT / "artifacts" / "catalog").glob("*.yml")), key=lambda c: c["id"])
    profiles = sorted((load_profile(p) for p in available_profiles().values()), key=lambda p: p.platform_id)
    packs = [_yml(p) for p in sorted((ROOT / "artifacts" / "packs").glob("*.yml"))]
    rules = []
    for f in sorted(list(ROOT.glob("[0-9][0-9]-*/*.yml")) + list(ROOT.glob("[0-9][0-9]-*/*.yar"))):
        text = f.read_text()
        if f.suffix == ".yml":
            doc = yaml.safe_load(text)
            title, desc, level = doc.get("title", f.name), (doc.get("description") or "").strip(), doc.get("level", "")
            tags = doc.get("tags", [])
            cves = sorted({t.replace("cve.", "CVE-").upper() for t in tags if t.startswith("cve.")})
            attack = sorted({t.split(".", 1)[1].upper() for t in tags if re.match(r"attack\.t\d{4}", t)})
            fmt = "Sigma"
        else:
            names = re.findall(r"^rule\s+(\w+)", text, re.M)
            title = ", ".join(names)
            m = re.search(r'description\s*=\s*"([^"]+)"', text)
            desc, level, tags, fmt = (m.group(1) if m else ""), "", [], "YARA"
            cves, attack = sorted(set(re.findall(r'cve = "(CVE-\d{4}-\d+)"', text))), []
        rules.append({"file": f.relative_to(ROOT).as_posix(), "dir": f.parent.name, "format": fmt,
                      "title": title, "description": desc, "level": level, "tags": tags, "body": text,
                      "cves": cves, "attack": attack})
    guide = (ROOT / "docs" / "edge-dfir-investigation-guide.md").read_text()
    intel = ROOT / "artifacts" / "intel"
    actors = sorted((_yml(f) for f in (intel / "actors").glob("*.yml")), key=lambda a: a["id"])
    implants = sorted((_yml(f) for f in (intel / "implants").glob("*.yml")), key=lambda i: i["id"])
    iocs = sorted((yaml.safe_load(f.read_text()) for f in (intel / "iocs").glob("*.yml")), key=lambda i: i["id"])
    response = {f.stem: _yml(f) for f in sorted((ROOT / "artifacts" / "response").glob("*.yml"))}
    hardening = {f.stem: _yml(f) for f in sorted((ROOT / "artifacts" / "hardening").glob("*.yml"))}
    hunts = [_yml(f) for f in sorted((ROOT / "artifacts" / "hunts").glob("*.yml"))]
    watch = yaml.safe_load((ROOT / "artifacts" / "watch" / "kev-watch.yml").read_text())
    recs = yaml.safe_load((ROOT / "artifacts" / "watch" / "kev-records.yml").read_text())
    kev = {"since": str(watch["since"]), "triaged": [{**t, "date": str(t["date"]), "refs": t.get("refs") or []}
                                                    for t in watch.get("triaged") or []],
           "catalog": str(recs["catalog"]), "released": str(recs["released"]),
           "records": [{**r, "added": str(r["added"]), "due": str(r["due"])} for r in recs["records"]], "added": {}}
    cvf = ROOT / "artifacts" / "watch" / "cve-records.yml"
    cverec = {r["cve"]: r for r in (yaml.safe_load(cvf.read_text()) or {}).get("records", [])} if cvf.is_file() else {}
    xpf = intel / "exploitation.yml"   # when each CVE was exploited, in the sources' own words
    expl = {r["cve"]: r for r in (yaml.safe_load(xpf.read_text()) or {}).get("records", [])} if xpf.is_file() else {}
    for r in kev["records"]:   # the re-read flag's KEV events, by the platform KEV's own product strings map to
        if r["platform"]:
            kev["added"].setdefault(r["platform"], {})[r["cve"]] = r["added"]
    return {"catalog": catalog, "profiles": profiles, "packs": packs, "rules": rules, "guide": guide,
            "actors": actors, "implants": implants, "iocs": iocs, "response": response, "hardening": hardening, "hunts": hunts,
            "kev": kev, "cverec": cverec, "expl": expl, "dates": git_dates()}


# --------------------------------------------------------------------------- data for the libraries
def build_data(d: dict) -> dict:
    prof = {p.name: p for p in d["profiles"]}
    dates = d.get("dates") or {}
    events = platform_events(d)

    def changed(x: dict) -> str:
        return dates.get(x.get("_file", ""), "")

    def rr(x: dict) -> list[str]:
        return reread(x, dates, events)
    cve_set = cve_universe(d)
    steps = {p.name: {s.id: {"tier": s.tier, "impact": s.impact, "kind": s.kind, "cmd": s.cmd or s.list_cmd or "",
                             "purpose": s.purpose, "instructions": (s.instructions or "").strip(),
                             "confidence": s.confidence, "unverified": s.unverified} for s in p.steps}
             for p in d["profiles"]}
    plat_profile = {c["id"]: c.get("profile") for c in d["catalog"]}

    # Names and aliases -> intel id, so free-text "seen in" and pack actor/implant
    # names become links when (and only when) a profile exists.
    intel_ix: dict[str, str] = {}
    for x in d["actors"] + d["implants"]:
        for n in [x["name"], *x.get("aliases", [])]:
            for k in {n.lower(), short(n).lower()}:
                intel_ix.setdefault(k, x["id"])

    def intel_links(names) -> list[dict]:
        out, seen = [], set()
        for n in names or []:
            iid = intel_ix.get(n.lower()) or intel_ix.get(short(n).lower())
            key = iid or n
            if key in seen:
                continue
            seen.add(key)
            out.append({"label": n, "href": f"#intel/{iid}"} if iid else {"label": n})
        return out

    rule_by_file = {r["file"]: r for r in d["rules"]}
    dets = []
    for p in d["packs"]:
        for x in p["detect"]:
            src = x.get("sources", {}) or {}
            st = []
            for sid in src.get("steps", []):
                owner = next((plat_profile[pid] for pid in p["platforms"]
                              if plat_profile.get(pid) and sid in steps.get(plat_profile[pid], {})), None)
                st.append({"id": sid, "profile": owner, **(steps[owner][sid] if owner else {})})
            doc = inspect.cleandoc(REGISTRY[x["check"]].__doc__ or "") if x.get("check") in REGISTRY else ""
            dets.append({
                "id": x["id"], "title": x["title"], "pack": p["id"], "pack_name": p["name"],
                "platforms": p["platforms"], "type": x["type"], "check": x.get("check", ""), "check_doc": doc,
                "rule": x.get("rule", ""), "rule_id": slug(x["rule"]) if x.get("rule") else "",
                "tier": x["tier"], "evidence": x["evidence_class"], "attack": x.get("attack", []),
                "cves": p.get("cves", []), "actors": p.get("actors", []), "actor_links": intel_links(p.get("actors")),
                "implant_links": intel_links(p.get("implants")), "notes": (x.get("notes") or "").strip(),
                "pattern": x.get("pattern", ""), "exclude": x.get("exclude", []), "flags": x.get("flags", []),
                "steps": st, "files": src.get("files", []), "unv": bool(p.get("unverified")),
                "sigma": [slug(r) for r in x.get("sigma", [])],
                "runs": ["analyzer"] + (["siem"] if x.get("sigma") else []) + (["yara"] if x.get("type") == "yara" else []),
                "changed": changed(p), "reread": rr(p),
            })
    det_cves = {c for x in dets for c in x["cves"]}

    def seen_links(names) -> list[dict]:
        out = []
        for n in names or []:
            lk = intel_links([n])[0]
            if "href" not in lk and n in cve_set:
                lk = {"label": n, "href": f"#cves/{n}"}
            out.append(lk)
        return out

    artifacts = []
    for c in d["catalog"]:
        pname = plat_profile.get(c["id"])
        for i, a in enumerate(c.get("artifacts", []), 1):
            cb = a.get("collected_by", "manual")
            kind = "step" if pname and cb in steps.get(pname, {}) else ("ingest" if cb == "ingest" else "manual")
            artifacts.append({
                "id": f"{c['id']}.{i:02d}", "platform": c["id"], "locator": a["locator"], "class": a["class"],
                "volatility": a["volatility"], "retention": a.get("retention", ""), "value": a["forensic_value"],
                "evidence": a.get("evidence_type", []), "confidence": a["confidence"], "unv": bool(a.get("unverified")),
                "collected_by": cb, "kind": kind, "step": steps[pname][cb] if kind == "step" else None,
                "description": a["description"].strip(), "seen": seen_links(a.get("seen_in")),
                "seen_in": a.get("seen_in", []),
                "provides": (a.get("provides") or "").strip(), "normal": (a.get("normal") or "").strip(),
                "suspicious": (a.get("suspicious") or "").strip(), "basis": a.get("basis", ""),
                "detections": [x["id"] for x in dets if c["id"] in x["platforms"] and cb in [s["id"] for s in x["steps"]]],
                "changed": changed(c), "reread": rr(c),
            })

    packs_by_plat: dict[str, list[str]] = {}
    for p in d["packs"]:
        for pid in p["platforms"]:
            packs_by_plat.setdefault(pid, []).append(p["id"])
    platforms = []
    for c in d["catalog"]:
        unv = bool(c.get("unverified") or any(x.get("unverified") for x in c.get("collection", []))
                   or any(a.get("unverified") for a in c.get("artifacts", [])))
        platforms.append({
            "id": c["id"], "name": c["name"], "short": short(c["name"]), "vendor": c["vendor"],
            "products": c.get("products", []), "os_base": c.get("os_base", ""), "filesystem": (c.get("filesystem") or "").strip(),
            "shell": c["customer_shell"], "memory": c["memory_acquisition"], "confidence": c["confidence"], "unv": unv,
            "profile": c.get("profile") or "", "response": c.get("response") or "",
            "collection": [{"method": x["method"], "impact": x["impact"], "description": x["description"],
                            "confidence": x["confidence"], "unverified": bool(x.get("unverified"))} for x in c.get("collection", [])],
            "volatility": c.get("volatility", []),
            "anti_forensics": [{"technique": a["technique"], "seen_in": a.get("seen_in", ""), "detail": a.get("detail", "")}
                               for a in c.get("anti_forensics", [])],
            "notes": (c.get("notes") or "").strip(), "references": refs_of(c.get("references")),
            "packs": packs_by_plat.get(c["id"], []),
            "n_art": len(c.get("artifacts", [])), "n_steps": len(prof[c["profile"]].steps) if c.get("profile") else 0,
            "n_det": sum(1 for x in dets if c["id"] in x["platforms"]),
            "n_hard": sum(len(h["controls"]) for h in d["hardening"].values() if h["platform_id"] == c["id"]),
            "changed": changed(c), "reread": rr(c),
        })

    packs = [{"id": p["id"], "name": p["name"], "summary": p["summary"].strip(), "platforms": p["platforms"],
              "cves": p.get("cves", []), "confidence": p["confidence"], "unv": bool(p.get("unverified")),
              "references": refs_of(p.get("references")), "n": len(p["detect"])} for p in d["packs"]]

    used_by: dict[str, list[str]] = {}
    for x in dets:
        if x["rule"]:
            used_by.setdefault(x["rule"], []).append(x["id"])
    rules = [{"id": slug(r["file"]), "file": r["file"], "platform": RULE_DIR_PLATFORM.get(r["dir"], ""),
              "format": r["format"], "title": r["title"], "description": r["description"], "level": r["level"] or "-",
              "tags": r["tags"], "cves": r["cves"], "attack": r["attack"], "body": r["body"],
              "used_by": used_by.get(r["file"], []), "url": f"{REPO_URL}/blob/main/{r['file']}"} for r in d["rules"]]
    assert set(used_by) <= set(rule_by_file), "a detection names a rule file that does not exist"

    det_by_id = {x["id"]: x for x in dets}
    intel = []
    for a in d["actors"]:
        intel.append({
            "kind": "actor", "id": a["id"], "name": a["name"], "aliases": a.get("aliases", []),
            "reported_by": a["reported_by"], "link_confidence": a["link_confidence"],
            "stated_confidence": a["stated_confidence"], "state_nexus": a.get("state_nexus", ""),
            "motivation": a.get("motivation", "unknown"), "summary": a["summary"].strip(),
            "platforms": a["platforms"], "packs": a.get("packs", []), "implants": a.get("implants", []),
            "tradecraft": a.get("tradecraft", []), "victimology": a.get("victimology", []),
            "first_seen": str(a.get("first_seen", "")), "notes": (a.get("notes") or "").strip(),
            "references": refs_of(a.get("references")), "unv": bool(a.get("unverified")),
            "confidence": a["link_confidence"], "changed": changed(a), "reread": rr(a),
        })
    for i in d["implants"]:
        detections = i.get("detections", [])
        intel.append({
            "kind": "implant", "id": i["id"], "name": i["name"], "aliases": i.get("aliases", []),
            "type": i["type"], "resides": i["resides"], "reboot": str(i.get("survives_reboot", "unknown")),
            "upgrade": str(i.get("survives_upgrade", "unknown")),
            "factory_reset": str(i.get("survives_factory_reset", "")),
            "platforms": i["platforms"], "actors": i.get("actors", []), "cves": i.get("cves", []),
            "summary": i["summary"].strip(), "artifacts": i.get("artifacts", []),
            "anti_forensics": i.get("anti_forensics", []), "detections": detections,
            "detection_packs": {x: det_by_id[x]["pack"] for x in detections if x in det_by_id},
            "coverage": "covered" if detections else "gap", "gap": (i.get("gap") or "").strip(),
            "confidence": i["confidence"], "unv": bool(i.get("unverified")),
            "references": refs_of(i.get("references")), "changed": changed(i), "reread": rr(i),
        })

    # Hardening: baseline (platform ALL) first, then per platform. A CVE or actor
    # the source names becomes a link when the toolkit has something on it.
    def blunt_links(names) -> list[dict]:
        out = []
        for n in names or []:
            if re.fullmatch(r"CVE-\d{4}-\d+", n):
                out.append({"label": n, "href": f"#cves/{n}"} if n in cve_set else {"label": n})
            else:
                out.append(intel_links([n])[0])
        return out
    hard = []
    for stem, h in sorted(d["hardening"].items(), key=lambda kv: (kv[1]["platform_id"] != "ALL", kv[1]["platform_id"])):
        for c in h["controls"]:
            hard.append({
                "id": c["id"], "platform": h["platform_id"], "control": c["control"], "category": c["category"],
                "priority": c["priority"], "why": c["why"].strip(), "how": c["how"].strip(),
                "blunts": c.get("blunts", []), "blunt_links": blunt_links(c.get("blunts")),
                "confidence": c["confidence"], "unv": bool(c.get("unverified")),
                "sources": [{"title": x["title"], "url": x["url"], "quote": (x.get("quote") or "").strip()} for x in c["sources"]],
                "stem": stem, "changed": changed(h), "reread": rr(h),
            })

    iocs = [{
        "id": s_["id"], "title": s_["title"], "publisher": s_["publisher"], "published": str(s_["published"]),
        "page_url": s_["page_url"], "file_url": s_.get("file_url", ""), "license": s_["license"], "format": s_["file_format"],
        "staleness": s_["staleness"].strip(), "actors": s_["actors"], "implants": s_["implants"], "cves": s_.get("cves", []),
        "platforms": s_["platforms"],
        "ind": [[i["type"], str(i["value"]), i["role"], i["context"].strip()] for i in s_["indicators"]],
    } for s_ in d["iocs"]]
    for it in intel:
        it["iocs"] = [s_["id"] for s_ in iocs if it["id"] in (s_["actors"] if it["kind"] == "actor" else s_["implants"])]
    actor_name = {a["id"]: a["name"] for a in d["actors"]}
    hunts = [{
        "id": h["id"], "title": h["title"], "platforms": h["platforms"], "actors": h.get("actors", []),
        "actor_names": {x: actor_name.get(x, x) for x in h.get("actors", [])}, "seen_in": h.get("seen_in", []),
        "cves": h.get("cves", []), "cve_links": blunt_links(h.get("cves")), "hypothesis": h["hypothesis"].strip(),
        "data": h["data"], "data_detail": (h.get("data_detail") or "").strip(), "method": [m.strip() for m in h["method"]],
        "normal": h["normal"].strip(), "suspicious": h["suspicious"].strip(), "attack": h.get("attack", []),
        "sigma": [slug(r) for r in h.get("sigma", [])], "inferred": (h.get("inferred") or "").strip(),
        "confidence": h["confidence"], "unv": bool(h.get("unverified")),
        "sources": [{"title": x["title"], "url": x["url"], "quote": x["quote"].strip(), "read": x.get("read", "direct")} for x in h["sources"]],
        "changed": changed(h), "reread": rr(h),
    } for h in d["hunts"]]

    # Exploited CVEs: CISA's KEV fields beside everything the toolkit has for each one.
    rec_by = {r["cve"]: r for r in d["kev"].get("records", [])}
    ledger = {t["cve"]: t for t in d["kev"]["triaged"]}
    since = d["kev"]["since"]
    actor_ids = {a["id"] for a in d["actors"]}
    plat_order = [c["id"] for c in d["catalog"]]
    plat_resp = {c["id"]: c.get("response") for c in d["catalog"]}
    cves = []
    for cid in sorted(cve_set, key=lambda c: (rec_by.get(c, {}).get("added", ""), c), reverse=True):
        r = rec_by.get(cid) or {}
        dl = [x for x in dets if cid in x["cves"]]
        al = [a for a in artifacts if cid in a["seen_in"]]
        hu = [h for h in hunts if cid in h["cves"]]
        hc = [x for x in hard if cid in x["blunts"]]
        il = [i for i in intel if i["kind"] == "implant" and cid in i["cves"]]
        sl = [x for x in iocs if cid in x["cves"]]
        acts: set[str] = set()
        for x in dl:
            acts.update(lk["href"].split("/", 1)[1] for lk in x["actor_links"] if lk.get("href", "").startswith("#intel/"))
        for i in il:
            acts.update(i["actors"])
        for x in sl:
            acts.update(x["actors"])
        for h in hu:
            acts.update(h["actors"])
        # KEV's own product strings decide the platform when they map to one. Only when
        # they do not (an Apache CVE exploited on SMA 100) do the records that name it.
        plats = {r["platform"]} if r.get("platform") else set()
        if not plats:
            for x in dl:
                plats.update(x["platforms"])
            plats.update(a["platform"] for a in al)
            for h in hu:
                plats.update(h["platforms"])
            plats.update(x["platform"] for x in hc)
            for x in il + sl:
                plats.update(x["platforms"])
        plats_l = [p for p in plat_order if p in plats]
        t = ledger.get(cid)
        if dl:
            cov = "detections"
        elif t:
            cov = t["decision"]
        elif not r:
            cov = "not-in-kev"
        elif r["added"] < since:
            cov = "before-watch"
        elif not r.get("platform"):
            cov = "other-product"
        else:
            cov = "untriaged"
        cves.append({
            "id": cid, "in_kev": bool(r), "kev_platform": r.get("platform"), "name": r.get("name", ""),
            "vendor": r.get("vendor", ""), "product": r.get("product", ""), "added": r.get("added", ""),
            "due": r.get("due", ""), "year": r.get("added", "")[:4], "ransomware": r.get("ransomware", ""),
            "triage": r.get("forensic_triage", ""), "cwes": r.get("cwes", []), "action": r.get("action", ""),
            "description": r.get("description", ""),
            "links": [u.rstrip(";,.") for u in re.findall(r"https?://[^\s;]+", r.get("notes", ""))],
            "platforms": plats_l, "coverage": cov,
            "decision": {"decision": t["decision"], "date": t["date"], "basis": t["basis"].strip()} if t else None,
            "detections": [x["id"] for x in dl], "artifacts": [a["id"] for a in al], "hunts": [h["id"] for h in hu],
            "hardening": [x["id"] for x in hc], "implants": [i["id"] for i in il],
            "actors": sorted(acts & actor_ids), "iocs": [x["id"] for x in sl],
            "plans": [plat_profile[p] for p in plats_l if plat_profile.get(p)],
            "playbooks": [plat_resp[p] for p in plats_l if plat_resp.get(p)],
        })

    cverec = d.get("cverec") or {}
    expl = d.get("expl") or {}
    for c in cves:
        cr = cverec.get(c["id"]) or {}
        names = {w["id"]: w["name"] for w in cr.get("cwes", [])}
        c["cwes"] = list(dict.fromkeys(list(c["cwes"]) + list(names)))   # KEV's ids first, then the CNA's
        c["cwe_names"] = names
        c["published"] = cr.get("published", "")
        c["assigner"] = cr.get("assigner", "")
        c["ssvc"] = cr.get("cisa_ssvc")
        c["triage_k"] = (("yes" if c["triage"] == "Yes" else "no-after" if c["added"] >= BOD_ISSUED else "no-before")
                         if c["in_kev"] else "none")
        c["due_days"] = ((_dt.date.fromisoformat(c["due"]) - _dt.date.fromisoformat(c["added"])).days
                         if c["in_kev"] and c["due"] else None)
        # Exploitation dates: only what a quoted source states. "before" compares the END of the
        # period the source gives (a month, a year) with the CVE record's publication, so a
        # month-precise date is never read as earlier than it is.
        xr = expl.get(c["id"])
        reps = [{"publisher": rp["publisher"], "kind": rp["kind"], "title": rp["title"], "url": rp["url"],
                 "accessed": str(rp["accessed"]), "stated_on": str(rp["stated_on"]) if rp.get("stated_on") else None,
                 "stated_on_basis": " ".join(str(rp["stated_on_basis"]).split()), "activity": rp["activity"],
                 "earliest": str(rp["earliest"]) if rp.get("earliest") else None,
                 "earliest_words": " ".join(str(rp.get("earliest_words", "")).split()),
                 "quote": " ".join(str(rp["quote"]).split()), "note": " ".join(str(rp.get("note", "")).split()),
                 "read": rp["read"]} for rp in (xr or {}).get("reports", [])]
        dated = [x for x in reps if x["earliest"]]
        first = min(dated, key=lambda x: (x["earliest"], period_end(x["earliest"]))) if dated else None
        said = [x for x in reps if x["stated_on"]]
        fr = min(said, key=lambda x: x["stated_on"]) if said else None
        c["expl"] = reps
        c["expl_searched"] = [" ".join(str(x).split()) for x in xr["searched"]] if xr else None
        c["earliest"] = {"date": first["earliest"], "by": first["publisher"], "activity": first["activity"]} if first else None
        c["first_report"] = {"date": fr["stated_on"], "by": fr["publisher"]} if fr else None
        before = bool(first and c["published"] and period_end(first["earliest"]) < c["published"])
        c["expl_k"] = "before" if before else "dated" if first else "reported" if reps else "none" if xr else "unsearched"
    for p in platforms:
        mine = [c for c in cves if p["id"] in c["platforms"]]
        p["cves"] = [c["id"] for c in mine]
        p["n_cve_flag"] = sum(1 for c in mine if c["triage"] == "Yes")

    return {"platforms": platforms, "artifacts": artifacts, "detections": dets, "packs": packs, "rules": rules,
            "intel": intel, "iocs": iocs, "hardening": hard, "hunts": hunts, "facetKeys": FACET_KEYS, "repo": REPO_URL,
            "cves": cves, "bod": {"url": BOD_URL, "steps": BOD_STEPS, "note": BOD_NOTE, "patch": BOD_PATCH, "issued": BOD_ISSUED,
                                  "directive": BOD_DIRECTIVE, "triage_def": BOD_TRIAGE_DEF, "kev_reported": KEV_REPORTED,
                                  "catalog": d["kev"].get("catalog", ""), "released": d["kev"].get("released", "")},
            "abbr": PLATFORM_ABBR, "kev": {k: v for k, v in d["kev"].items() if k in ("since", "triaged")},
            "built": build_date().isoformat(),
            "steps": [[p.name, st.id, st.tier, st.cmd or st.list_cmd or "", st.purpose] for p in d["profiles"] for st in p.steps],
            "guideMins": max(1, round(len(re.findall(r"\w+", d["guide"])) / 230)),
            "profiles": [{"name": p.name, "ssh": "ssh" in p.transports, "validated": bool(p.validated_on),
                          "vars": sorted({v for s in p.steps for v in s.requires_vars})} for p in d["profiles"]]}


# --------------------------------------------------------------------------- markdown
# Platform notes in the guide start with a bold platform name. Each must map to
# a catalog id so the note can carry links into the libraries; --check fails if
# a platform has no note or a note names no platform.
NOTE_PLATFORM = {
    "PAN-OS / GlobalProtect": "EDGE-0001", "FortiOS": "EDGE-0002", "Ivanti Connect Secure": "EDGE-0003",
    "NetScaler": "EDGE-0004", "Cisco ASA / FTD": "EDGE-0005", "SonicWall SMA 100": "EDGE-0006",
    "Check Point Gaia": "EDGE-0007", "Juniper Junos": "EDGE-0008", "Cisco IOS XE": "EDGE-0009",
    "F5 BIG-IP": "EDGE-0010",
}
VERDICTS = ("NO-INDICATORS-FOUND", "LIKELY-COMPROMISED", "COMPROMISED", "SUSPICIOUS")


def md_inline(s: str) -> str:
    s = e(s, quote=False)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)", r'<a href="\2" rel="noopener">\1</a>', s)
    return s


def guide_inline(s: str, ctx: dict) -> str:
    """md_inline plus the guide's cross-links: verdict and tier names become the
    same badges the libraries use, and a CVE with detections links to them."""
    h = md_inline(s)
    for v in VERDICTS:
        h = h.replace(f"<code>{v}</code>", f'<span class="verdict v-{v.lower()}">{v}</span>')
    for t in TIERS:
        h = h.replace(f"<code>{t}</code>", f'<span class="badge tier t-{t}">{t}</span>')
    return re.sub(r"(?<![\w/=?-])(CVE-\d{4}-\d{4,})",
                  lambda m: f'<a href="#cves/{m.group(1)}">{m.group(1)}</a>' if m.group(1) in ctx["cves"] else m.group(1), h)


def note_links(pid: str, ctx: dict) -> str:
    p = ctx["platforms"][pid]
    out = []
    if p["profile"]:
        out.append(f'<a class="chip link" href="#plans/{e(p["profile"])}">Collection plan</a>')
    out.append(f'<a class="chip link" href="#artifacts?platform={pid}">{p["n_art"]} artifacts</a>')
    if p["n_det"]:
        out.append(f'<a class="chip link" href="#detections?platform={pid}">{p["n_det"]} detections</a>')
    if p["response"]:
        out.append(f'<a class="chip link" href="#response/{e(p["response"])}">Response</a>')
    return f'<div class="links">{"".join(out)}</div>'


def guide_toc(md: str) -> list[dict]:
    return [{"id": f"g-{slug(m.group(2))}", "title": m.group(2), "level": len(m.group(1))}
            for m in re.finditer(r"^(#{2,3})\s+(.*)$", md, re.M)]


def markdown(md: str, ctx: dict | None = None) -> str:
    """Enough Markdown for the guide: headings, paragraphs, lists, fences,
    tables and > callouts. With ctx, the guide's cross-links are added."""
    inl = (lambda t: guide_inline(t, ctx)) if ctx else md_inline
    out, lines, i = [], md.splitlines(), 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("```"):
            buf = []
            i += 1
            while i < len(lines) and not lines[i].startswith("```"):
                buf.append(lines[i])
                i += 1
            out.append(f'<div class="codewrap"><button class="copy" type="button">Copy</button><pre><code>{e(chr(10).join(buf))}</code></pre></div>')
            i += 1
            continue
        m = re.match(r"^(#{1,4})\s+(.*)", ln)
        if m:
            lvl = len(m.group(1)) + 1
            hid = f"g-{slug(m.group(2))}"
            anchor = (f'<a class="hlink" href="#guide/{hid[2:]}" aria-label="Link to this section">#</a>'
                      if ctx and lvl in (3, 4) else "")
            if ctx and lvl == 3:
                anchor += (f'<button type="button" class="copy sm hcopy" data-copylink="#guide/{hid[2:]}" '
                           f'aria-label="Copy a link to this section">Copy link</button>')
            out.append(f'<h{lvl} id="{hid}">{md_inline(m.group(2))}{anchor}</h{lvl}>')
            i += 1
            continue
        if ln.startswith(">"):
            buf = []
            while i < len(lines) and lines[i].startswith(">"):
                buf.append(lines[i].lstrip(">").strip())
                i += 1
            out.append(f'<div class="callout">{inl(" ".join(buf))}</div>')
            continue
        if ln.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            head, body = rows[0], [r for r in rows[1:] if not all(re.fullmatch(r":?-+:?", c) for c in r)]
            out.append("<div class=\"scroll\"><table class=\"tbl\"><thead><tr>" + "".join(f"<th>{inl(c)}</th>" for c in head)
                       + "</tr></thead><tbody>" + "".join("<tr>" + "".join(f"<td>{inl(c)}</td>" for c in r) + "</tr>" for r in body)
                       + "</tbody></table></div>")
            continue
        m = re.match(r"^(\s*)(-|\d+\.)\s+(.*)", ln)
        if m:
            tag = "ol" if m.group(2)[0].isdigit() else "ul"
            items = []
            while i < len(lines):
                mm = re.match(r"^\s*(-|\d+\.)\s+(.*)", lines[i])
                if mm:
                    items.append(mm.group(2))
                elif lines[i].startswith("  ") and items:
                    items[-1] += " " + lines[i].strip()
                else:
                    break
                i += 1
            out.append(f"<{tag}>" + "".join(f"<li>{inl(x)}</li>" for x in items) + f"</{tag}>")
            continue
        if not ln.strip():
            i += 1
            continue
        buf = []
        while i < len(lines) and lines[i].strip() and not re.match(r"^(#|```|\||>|\s*(-|\d+\.)\s)", lines[i]):
            buf.append(lines[i].strip())
            i += 1
        text = " ".join(buf)
        note = re.match(r"^\*\*([^*]+?)\.\*\*", text)
        if ctx and note and note.group(1) in NOTE_PLATFORM:
            pid = NOTE_PLATFORM[note.group(1)]
            ctx["notes_seen"].add(pid)
            out.append(f'<div class="pnote" id="g-note-{pid}"><p>{inl(text)}</p>{note_links(pid, ctx)}</div>')
        else:
            out.append(f"<p>{inl(text)}</p>")
    return "\n".join(out)


# --------------------------------------------------------------------------- server-rendered fragments
def badge(text: str, cls: str) -> str:
    return f'<span class="badge {cls}">{e(text)}</span>'


def impact_badge(impact: str) -> str:
    return badge(impact, {"none": "imp-none", "vendor-bundle": "imp-bundle", "break-glass": "imp-bg"}[impact])


def conf_badge(conf: str, unv: bool) -> str:
    out = badge(conf, f"conf c-{conf}")
    if unv:
        out += badge("unverified", "unv-b")
    return out


def tier_badge(tier: str) -> str:
    return badge(tier, f"tier t-{tier}")


def chips(items, cls="chip") -> str:
    return "".join(f'<span class="{cls}">{e(str(x))}</span>' for x in items)


def copyable(text: str) -> str:
    return f'<span class="cmd"><code>{e(text)}</code><button class="copy sm" type="button" data-copy="{e(text)}">Copy</button></span>'


# BOD 26-04 forensic triage: CISA's step names and target timelines, verbatim from the
# implementation guidance. A KEV entry whose forensicTriage is "Yes" carries them; the
# link beside each step is this toolkit's suggestion for where it starts, not the directive.
BOD_URL = ("https://www.cisa.gov/news-events/directives/"
           "bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk")
BOD_STEPS = [("Scoping", "Target timeline: within first two hours of KEV addition"),
             ("Preserve and Collect Evidence", "Target timeline: within 2-24 hours of KEV addition"),
             ("Critical Patching and Stabilization", "Target timeline: within 2-24 hours of KEV addition"),
             ("Contain and Control", "Target timeline: within 6-24 hours of KEV addition"),
             ("Triage Analysis", "Target timeline: within 24-48 hours of KEV addition"),
             ("Escalation Decision", "Target timeline: within 48-72 hours of KEV addition")]
BOD_NOTE = ("The requirement of BOD 26-04 is that an adequate forensic triage analysis is performed; "
            "the specific timeline below is not required.")
BOD_PATCH = "Collect all required evidence prior to this step as patching may jeopardize the availability of artifacts."
# From the directive itself (Appendix A, item 04) and the guidance's FAQ. Every KEV entry added
# before the directive was issued reads forensicTriage "No"; the flag is a federal deadline
# category, so the site never words "No" as "not required".
BOD_ISSUED = "2026-06-10"
BOD_DIRECTIVE = "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk"
BOD_TRIAGE_DEF = ("The text \u201c& forensic triage\u201d means that the agency must complete remediation or mitigation "
                  "action within the timeline (three days) and carry out a forensic triage of the asset to assess whether "
                  "the system is compromised.")
KEV_REPORTED = "When a vendor, researcher, or partner reports exploitation, CISA reviews the evidence."
CVE_FULL = re.compile(r"CVE-\d{4}-\d{4,}")

LIB_COPY = {
    # title, one-line lede, the long text behind "About this library", filter placeholder
    "artifacts": ("Artifacts", "What each trace proves, how long it lasts and the step that collects it.",
                  "Every artifact on every platform: what it proves, how long it lasts and the step that collects it. "
                  "Filter, open a row for the full record, and export what you picked as a collection checklist.",
                  "Filter artifacts: locator, description, implant, CVE"),
    "platforms": ("Platforms", "What a responder can reach on each platform, how, and what disappears if you wait.", "",
                  "Filter platforms, vendors, products"),
    "cves": ("CVEs", "One record per CVE: what CISA's catalog says about it, and everything the toolkit has for it.",
             "Every CISA KEV entry on the ten platforms since 2024, and every CVE a record here names. CISA's own fields "
             "(date added, due date, ransomware use, the BOD 26-04 forensic triage flag) are copied verbatim from the KEV "
             "catalog by `advisory_watch.py --records`; the rest joins what the toolkit has: detections, the traces "
             "artifacts record, hunts, hardening, playbooks, actors and indicator sets. A CVE CISA flags for forensic "
             "triage carries the directive's six steps, each beside the place the toolkit starts it.",
             "Filter CVEs: id, product, name, CWE"),
    "detections": ("Detections", "Each runs in the analyzer and reports hit, no hit or not evaluated, never a pass. "
                   "{sigma} also carry a Sigma rule for your SIEM.",
                   "Every detection runs in the analyzer against evidence collected from the device, and "
                   "reports hit, no hit or not evaluated - never a pass. Where the same indicator can be watched in your SIEM, "
                   "the detection carries its Sigma rule; YARA rules scan recovered files. Sigma rules convert with "
                   "`sigma convert -t <backend>`; no vendor query dialect is shipped.", "Filter detections: pattern, rule, CVE, ATT&CK"),
    "hardening": ("Hardening", "Controls that would have prevented or blunted the exploitation waves these platforms have seen.",
                  "Controls that would have prevented or blunted the exploitation waves these platforms "
                  "have seen - first among them, keeping management interfaces off the internet. The baseline applies to "
                  "every platform; each control cites the vendor or government source it comes from.",
                  "Filter controls, CVEs, settings"),
    "hunts": ("Hunts", "Hypotheses for data the intruder could not edit: NetFlow, SIEM, AAA, identity and proxy logs.",
              "Hypotheses to test in data that lives off the device - NetFlow, SIEM, AAA accounting, identity "
              "and proxy logs - because the device's own record is the one an intruder edits. The analyzer does not run "
              "these; each states what normal looks like, what would be a lead, and the source it rests on.",
              "Filter hunts: data source, actor, CVE"),
    "intel": ("Threat intel", "Attribution is reported, never computed: our link confidence beside the reporter's own words.",
              "Attribution is reported, never computed. Each actor carries our link confidence (how well "
              "sourced the link is) beside the reporting party's own words. Clusters are merged only where the reporters "
              "themselves equate them.", "Filter actors, implants, aliases, reporters, indicator values"),
}


def lib_panel(name: str, n_unv: int, rows: bool, n_sigma: int = 0) -> str:
    title, lede, about, ph = LIB_COPY[name]
    unv = (f'<button type="button" class="tgl unvT" aria-pressed="false" title="Only records nobody has confirmed on a device">'
           f'Unverified only <span class="n">{n_unv}</span></button>') if n_unv else ""
    extra = ('<button type="button" class="tgl grpT" aria-pressed="true">Group by platform</button>'
             '<button type="button" class="tgl cmpT" aria-pressed="false">Compact</button>') if rows else ""
    more = f'<details class="about"><summary>About this library</summary><p class="rx">{e(about)}</p></details>' if about else ""
    return f'''<section class="panel lib" id="tab-{name}" data-lib="{name}" role="tabpanel" hidden>
  <div class="lhead"><h2>{e(title)}</h2><p class="lede">{e(lede.format(sigma=n_sigma))}</p>{more}</div>
  <div class="controls">
    <label class="search"><span class="glyph" aria-hidden="true">&#8981;</span><input type="search" class="q" placeholder="{e(ph)}" aria-label="Filter {e(title.lower())}" autocomplete="off"></label>
    {unv}{extra}
    <span class="exp"><button type="button" class="tgl" data-act="copyview" title="Copy a link to this filtered view">Copy link</button><button type="button" class="tgl" data-exp="csv">CSV</button><button type="button" class="tgl" data-exp="json">JSON</button></span>
  </div>
  <div class="meta"><span class="count"></span><span class="active"></span><span class="picked"></span></div>
  <div class="summary"></div>
  <div class="results"></div>
</section>'''


def conf_counts(items, conf=lambda x: x["confidence"], unv=lambda x: x.get("unv")) -> dict:
    """high / medium / low, with anything unverified counted as low."""
    c = {"high": 0, "medium": 0, "low": 0}
    for x in items:
        c["low" if unv(x) else conf(x)] += 1
    return c


def conf_bar(c: dict, cls: str = "", words=("high", "medium", "low")) -> str:
    """A bar split high / medium / low. A segment is labelled when it is wide enough to hold the label."""
    tot = sum(c.values()) or 1
    segs = []
    for k, w in zip(("high", "medium", "low"), words):
        n = c.get(k, 0)
        if not n:
            continue
        lbl = f"{n} {w}" if n / tot >= .14 else (str(n) if n / tot >= .05 else "")
        segs.append(f'<span class="cs cs-{k}" style="flex:{n}" title="{n} {w}">{lbl}</span>')
    label = ", ".join(f"{c.get(k, 0)} {w}" for k, w in zip(("high", "medium", "low"), words))
    return f'<div class="cbar {cls}" role="img" aria-label="{e(label)}">{"".join(segs)}</div>'


def steps_by_source(d: dict):
    steps = [st for p in d["profiles"] for st in p.steps]
    hi = sum(1 for st in steps if st.confidence == "high" and not st.unverified)
    lo = sum(1 for st in steps if st.unverified)
    return steps, hi, len(steps) - hi - lo, lo


def validation_badge(p) -> str:
    if p.validated_on:
        runs = "; ".join(f'{v.get("release", "")} ({v.get("date", "")})' for v in p.validated_on)
        return f'<span class="badge conf c-high" title="{e(runs)}">run on a device</span>'
    return ('<span class="badge unv-b" title="No command in this profile has been run against a real device '
            'or a vendor virtual edition">not yet run on a real device</span>')


def unvalidated_banner(d: dict) -> str:
    """The collection profiles were written from vendor documentation and checked against
    synthetic replays only. Say so wherever someone might copy a command."""
    unval = [p for p in d["profiles"] if not p.validated_on]
    if not unval:
        return ""
    which = ("None of the collection profiles has" if len(unval) == len(d["profiles"])
             else f'{len(unval)} of {len(d["profiles"])} collection profiles have not')
    return (f'<div class="warnbox" role="note"><b>{which} been run against a real device or a vendor virtual '
            'edition yet.</b> Every command comes from vendor documentation and was checked only against '
            'synthetic replays. A command can fail, prompt, page differently or print a format the parsers do '
            'not recognise; the analyzer reports that as <i>not evaluated</i>, never as clean. Try a profile on a '
            'lab device or virtual edition first, read <code>plan</code> before you <code>collect</code>, and expect '
            'the collector to ask you to type <code>UNVALIDATED</code> (or pass <code>--accept-unvalidated</code>) '
            'before it connects. Report what you find - <a href="#guide/unvalidated-profiles">how to record a run</a>.</div>')


def _tier_kind(t: str) -> str:
    return {"B": "b", "X": "x"}.get(t, t[0].lower())


def plan_summary(p) -> str:
    c = conf_counts(p.steps, conf=lambda st: st.confidence, unv=lambda st: st.unverified)
    imp = {k: sum(1 for st in p.steps if st.impact == k) for k in ("none", "vendor-bundle", "break-glass")}
    tc = {t: sum(1 for st in p.steps if st.tier == t) for t in TIER_ORDER}
    mx = max(tc.values()) or 1
    strip = []
    for t in TIER_ORDER:
        h = 8 + round(26 * tc[t] / mx) if tc[t] else 2
        tip = f'{t} {TIER_LABEL[t]}: {tc[t]} step{"" if tc[t] == 1 else "s"}'
        strip.append(f'<li title="{e(tip)}"><span class="tb tb-{_tier_kind(t)}{"" if tc[t] else " e"}" style="height:{h}px"></span>'
                     f'<span class="tsl">{t}</span></li>')
    return (f'<div class="psum"><div class="psum-l"><div class="psum-n"><b>{len(p.steps)}</b> steps</div>'
            f'{conf_bar(c, "h18", ("high", "medium", "unverified"))}'
            f'<div class="small muted">{c["high"]} vendor-documented &#183; {c["medium"]} multi-source &#183; {c["low"]} unverified</div>'
            f'<div class="small muted">{imp["none"]} read-only &#183; {imp["vendor-bundle"]} write a bundle &#183; {imp["break-glass"]} break-glass</div></div>'
            f'<div class="psum-r"><ol class="tstrip" aria-label="Steps per tier, in the order they run: '
            + ", ".join(f"{t} {tc[t]}" for t in TIER_ORDER) + f'">{"".join(strip)}</ol>'
            f'<div class="small muted">Steps per tier, in the order they run</div></div></div>')


def render_plans(d: dict) -> str:
    picker, sections = [], []
    for i, p in enumerate(d["profiles"]):
        picker.append(f'<button type="button" class="pbtn" data-profile="{e(p.name)}" aria-pressed="{str(i == 0).lower()}" '
                      f'title="{e(p.display)}">{e(PLATFORM_ABBR.get(p.platform_id, short(p.display)))}</button>')
        groups = []
        for tier in TIER_ORDER:
            steps = [st for st in p.steps if st.tier == tier]
            if not steps:
                continue
            rows = []
            for st in steps:
                cmd = st.cmd or st.list_cmd
                what = copyable(cmd) if cmd else '<span class="muted">manual</span>'
                instr = (f'<details><summary>Instructions</summary><pre class="instr">{e(st.instructions.strip())}</pre></details>'
                         if st.instructions else "")
                needs = f'<div class="needs">needs <code>--var {e(", ".join(st.requires_vars))}</code></div>' if st.requires_vars else ""
                held = '<div class="whld">Withheld until you allow it in the builder</div>' if st.impact != "none" else ""
                rows.append(f'''<tr class="step imp-{e(st.impact)}{' unv' if st.unverified else ''}" data-impact="{e(st.impact)}">
  <td class="id">{e(st.id)}</td><td>{impact_badge(st.impact)}<div class="kind">{e(st.kind)}</div></td>
  <td>{what}{needs}<div class="purpose">{e(st.purpose)}</div>{held}{instr}</td>
  <td>{conf_badge(st.confidence, st.unverified)}</td></tr>''')
            groups.append(f'<tr class="tierrow"><th colspan="4"><span class="tchip">{e(tier)}</span> {e(TIER_LABEL[tier])} <span class="muted">- {e(TIER_CLASS[tier])}</span></th></tr>' + "".join(rows))
        sections.append(f'''
<section class="plan" data-profile="{e(p.name)}" id="plan-{e(p.name)}"{'' if i == 0 else ' hidden'}>
  <div class="plan-h"><div><span class="id">{e(p.platform_id)}</span> <h3>{e(p.display)}</h3> {validation_badge(p)}</div>
    <div class="links"><a class="chip link" href="#platforms/{e(p.platform_id)}">platform entry</a><a class="chip link" href="#artifacts?platform={e(p.platform_id)}">artifacts</a></div></div>
  {plan_summary(p)}
  <details class="guard"><summary>Read-only guard</summary>
    <div class="cols"><div><h4>Allow</h4>{chips(p.allow, 'chip code')}</div><div><h4>Deny</h4>{chips(p.deny, 'chip code')}</div>
    <div><h4>Session setup</h4>{chips(p.session_setup, 'chip code') or '<span class="muted">none</span>'}</div>
    <div><h4>Prompt / pager</h4>{chips([p.prompt] + ([p.pager] if p.pager else []), 'chip code')}</div></div></details>
  <div class="scroll"><table class="tbl steps"><thead><tr><th>Step</th><th>Impact</th><th>Command and purpose</th><th>Confidence</th></tr></thead>
  <tbody>{"".join(groups)}</tbody></table></div>
</section>''')
    builder = '''
<aside class="builder">
  <h3>Build the command</h3>
  <p class="muted">Nothing here leaves your browser. The password is never part of the command; supply it at the prompt or through an environment variable.</p>
  <div class="bwarn" id="b-warn" role="note"><b>Not yet run on a real device.</b> The collector will ask you to type <code>UNVALIDATED</code> before it connects.</div>
  <label>Case id<input id="b-case" value="IR-2026-001" autocomplete="off"></label>
  <label>Device address<input id="b-host" placeholder="192.0.2.10" autocomplete="off"></label>
  <label>Read-only user<input id="b-user" placeholder="ir-readonly" autocomplete="off"></label>
  <label>Operator<input id="b-op" placeholder="your name" autocomplete="off"></label>
  <div class="vars" id="b-vars"></div>
  <div class="b2"><label>Rebooted since incident<select id="b-reboot"><option>unknown</option><option>no</option><option>yes</option></select></label>
  <label>Upgraded since incident<select id="b-patch"><option>unknown</option><option>no</option><option>yes</option></select></label></div>
  <label class="tog"><input type="checkbox" id="b-bundle"> Allow vendor bundles <span class="muted">(writes to the device)</span></label>
  <label class="tog"><input type="checkbox" id="b-bg"> Break-glass <span class="muted">(runs last, asks for confirmation)</span></label>
  <label class="tog"><input type="checkbox" id="b-one"> One line, for pasting into a ticket</label>
  <div class="codewrap"><button class="copy" type="button" id="b-copy">Copy</button><pre><code id="b-out"></code></pre></div>
  <div class="muted" id="b-sum"></div>
</aside>'''
    return f'''<div class="lhead"><h2>Collection plans</h2><p class="lede">Every profile in order of volatility. Bundle and break-glass rows stay greyed out until you allow them in the builder, exactly as the collector behaves.</p></div>
{unvalidated_banner(d)}
<div class="picker">{"".join(picker)}</div>
<div class="planwrap"><div class="plans">{"".join(sections)}</div>{builder}</div>'''


def hard_link(pid: str, d: dict) -> str:
    n = sum(len(h["controls"]) for h in d["hardening"].values() if h["platform_id"] == pid)
    return f'<a class="chip link" href="#hardening?platform={pid}">hardening ({n})</a>' if n else ""


RESP_PHASES = [("preserve_first", "Preserve first", "before anything changes the device"),
               ("contain", "Contain", "stop further access without destroying evidence"),
               ("credential_exposure", "Rotate credentials", "everything the device held is exposed"),
               ("eradicate", "Eradicate", "remove the foothold"),
               ("recover", "Recover", "return to service on a trusted build"),
               ("verify", "Verify", "prove it, and hunt for the dwell period")]
RESP_VERDICTS = ("COMPROMISED", "LIKELY-COMPROMISED", "SUSPICIOUS", "NO-INDICATORS-FOUND")


def resp_total(r: dict) -> int:
    return sum(len(r.get(key, [])) for key, _, _ in RESP_PHASES)


def render_response(d: dict) -> str:
    """Containment and recovery, ordered: preserve, contain, rotate, eradicate,
    recover, verify. Guidance a human acts on, not automation: the page is a
    checklist a responder ticks through, filtered by the analyzer's verdict."""
    profile_of = {c["id"]: c.get("profile") for c in d["catalog"]}
    picker, options, secs = [], [], []
    rich = lambda t: f'<span class="rx">{e(t)}</span>'
    for n, (stem, r) in enumerate(sorted(d["response"].items(), key=lambda kv: kv[1]["platform_id"])):
        pid = r["platform_id"]
        ab = PLATFORM_ABBR.get(pid, short(r["name"]))
        picker.append(f'<button type="button" class="rbtn" data-resp="{e(stem)}" aria-pressed="{str(n == 0).lower()}" title="{e(r["name"])}">{e(ab)}</button>')
        options.append(f'<option value="{e(stem)}">{e(ab)}</option>')

        def when_attr(st):
            w = [x.strip() for x in str(st.get("when", "")).split(",") if x.strip()]
            return ",".join(w)

        def when_badges(w):
            return ('<span class="for">for</span>' + "".join(f'<span class="verdict v-{x.lower()}">{x}</span>' for x in w.split(","))) if w else ""

        phases, nav, total = [], [], 0
        for i, (key, title, sub) in enumerate(RESP_PHASES, 1):
            items = []
            if key == "credential_exposure":
                for j, c in enumerate(r.get(key, [])):
                    k = f"{key}:{j}"
                    items.append(f'<li class="rstep cred" data-k="{k}" data-when=""><label><input type="checkbox" class="rchk" data-k="{k}">'
                                 f'<span class="rbody"><b>{rich(c["what"])}</b><span class="cw"><span class="cl">Why</span>{rich(c["why"])}</span>'
                                 f'<span class="ca"><span class="cl">Do</span>{rich(c["action"])}</span>'
                                 f'<span class="rwhen"><span class="rtick"></span></span></span></label></li>')
            else:
                for j, st in enumerate(r.get(key, [])):
                    k, w = f"{key}:{j}", when_attr(st)
                    detail = f'<span class="rdet">{rich(st["detail"])}</span>' if st.get("detail") else ""
                    items.append(f'<li class="rstep" data-k="{k}" data-when="{e(w)}"><label><input type="checkbox" class="rchk" data-k="{k}">'
                                 f'<span class="rbody"><b>{rich(st["step"])}</b>{detail}<span class="rwhen">{when_badges(w)}<span class="rtick"></span></span></span></label>'
                                 f'<span class="roff"><span class="rofft">{e(st["step"])}</span>{when_badges(w)}</span></li>')
            total += len(items)
            anchor = f"r-{stem}-{key.replace('_', '-')}"
            nav.append(f'<a href="#{anchor}" data-jump="{anchor}"><span class="pn">{i}</span>{e(title)}<span class="rc" data-phase="{key}">{len(items)}</span></a>')
            phases.append(f'<section class="rphase" id="{anchor}" data-phase="{key}"><div class="rrail"><span class="pn">{i}</span></div>'
                          f'<div class="rcol"><h4>{e(title)} <span class="muted small">- {e(sub)}</span></h4>'
                          f'<ol class="rlist">{"".join(items) or "<li class=muted>Nothing specific to this platform.</li>"}</ol></div></section>')
        dont = "".join(f'<li><b>{rich(x["action"])}</b><span class="rdet">{rich(x["because"])}</span></li>' for x in r.get("do_not", []))
        fold = ('<p class="rfold small muted">The rest of the list is folded now that you have read it. Untick to show it again.</p>'
                if len(r.get("do_not", [])) > 3 else "")
        vg = "".join(f'<li><a href="{e(x["url"])}" rel="noopener" target="_blank">{e(x["title"])}</a></li>' for x in r.get("vendor_guidance", []))
        refs = "".join(f'<li><a href="{e(x["url"])}" rel="noopener" target="_blank">{e(x["title"])}</a></li>' for x in r["references"])
        prof = profile_of.get(pid)
        links = ([f'<a class="chip link" href="#plans/{e(prof)}">Collection plan</a>'] if prof else ['<span class="chip ghost">no collection profile</span>']) + [
            f'<a class="chip link" href="#detections?platform={e(pid)}">Detections</a>',
            f'<a class="chip link" href="#hunts?platform={e(pid)}">Hunts</a>',
            f'<a class="chip link" href="#intel?platform={e(pid)}">Threat intel</a>',
            hard_link(pid, d),
            f'<a class="chip link" href="#platforms/{e(pid)}">Platform entry</a>']
        conf = r.get("confidence", "medium")
        secs.append(f'''
<article class="card resp" id="response-{e(stem)}" data-resp="{e(stem)}" data-name="{e(r['name'])}" data-total="{total}"{'' if n == 0 else ' hidden'}>
  <header class="card-h"><div><span class="id">{e(pid)} &#183; <span title="How well sourced this playbook is">playbook confidence: {e(conf)}</span></span><h3>{e(r['name'])}</h3></div>
    <label class="rcase-l">Case <input class="rcase" type="text" autocomplete="off" spellcheck="false" placeholder="none" aria-label="Case id: ticks are kept per case"></label></header>
  <div class="links rlinks">{"".join(links)}</div>
  <div class="dont top"><div class="dont-h"><h4>Do not - read before touching the device</h4><label class="rack-l"><input type="checkbox" class="rack"> I have read these</label></div><ul class="plain dgrid">{dont}</ul>{fold}</div>
  <div class="rtool"><div class="rprog"><span class="rprog-t"><b class="rdone">0</b> of <b class="rall">{total}</b> steps done<span class="rfor"></span></span><span class="rbarw"><span class="rbar"></span></span></div>
    <div class="links"><button type="button" class="chip btnchip rcopy">Copy as checklist</button><button type="button" class="chip btnchip rprint">Print</button><button type="button" class="chip btnchip rreset">Clear ticks</button></div></div>
  <nav class="rnav" aria-label="Phases">{"".join(nav)}</nav>
  <div class="rtl">{"".join(phases)}</div>
  {f'<p class="note">{rich(r["notes"].strip())}</p>' if r.get('notes') else ''}
  <details class="rrefs"><summary>Vendor guidance and references ({len(r.get("vendor_guidance", [])) + len(r["references"])})</summary><ul>{vg}{refs}</ul></details>
</article>''')
    lens = "".join(f'<button type="button" class="vbtn" data-v="{v}" aria-pressed="false"><span class="verdict v-{v.lower()}">{v}</span><span class="vn"></span></button>' for v in RESP_VERDICTS)
    return f'''<div class="lhead"><h2>Response</h2><p class="lede">Containment and recovery in the order that protects evidence: <b>preserve</b>, contain, rotate credentials, eradicate, recover, verify. Guidance a person acts on; the toolkit never contains or remediates on its own.</p>
<details class="about"><summary>How to use this page</summary><p>The do-not list comes first because most evidence is destroyed by a well-meant action taken too early. Pick the verdict the analyzer gave to see only the steps it calls for, enter the case id so the ticks are kept per case, tick steps off as you go - each tick records the time - and copy the list into your case notes.</p></details></div>
<div class="rhead">
  <label class="rsel-l">Platform <select class="rsel" aria-label="Platform">{"".join(options)}</select></label>
  <div class="picker rpick">{"".join(picker)}</div>
  <div class="vlens" role="group" aria-label="Show the steps for a verdict"><span class="vl">Analyzer verdict</span><button type="button" class="vbtn" data-v="" aria-pressed="true">All steps<span class="vn"></span></button>{lens}</div>
  <p class="vhint muted small" hidden>Steps without a verdict condition apply whatever the verdict. Hidden steps are still in the playbook - choose All steps to see them.</p>
</div>
{"".join(secs)}'''


LEGEND = [
    ("Volatility - how long the trace lasts", [
        ("vol vol-live", "live", "exists only while the device runs; gone at reboot"),
        ("vol vol-rotating", "rotating", "overwritten as logs roll, often in hours"),
        ("vol vol-stable", "stable", "survives until someone changes or wipes it"),
        ("vol vol-off-box", "off-box", "a copy somewhere else: SIEM, syslog, management server")]),
    ("Detection tier - what a hit means", [
        ("tier t-possible", "possible", "an attempt, or a lead that needs a second signal"),
        ("tier t-likely", "likely", "post-exploitation trace with a plausible benign explanation"),
        ("tier t-confirmed", "confirmed", "no legitimate reason to exist on the device")]),
    ("Step impact - what collection does to the device", [
        ("imp-none", "none", "read-only; runs by default"),
        ("imp-bundle", "vendor-bundle", "writes to the device; needs --allow-bundle"),
        ("imp-bg", "break-glass", "can crash, reload or image it; needs --break-glass, runs last")]),
    ("Confidence - where a claim comes from", [
        ("conf c-high", "high", "vendor-documented or verified on a device"),
        ("conf c-medium", "medium", "several independent sources"),
        ("unv-b", "unverified", "single source or inferred - check before relying on it")]),
]
START_VERDICTS = ("COMPROMISED", "LIKELY-COMPROMISED", "SUSPICIOUS", "NO-INDICATORS-FOUND")


VOL_ORDER = ("live", "rotating", "stable", "off-box")
# The collector's order of volatility, grouped the way a reader needs it.
OOV_GROUPS = [
    ("Volatile state", "lost at reboot - collected first", "g-live", ["V0", "V1", "V2", "V3"]),
    ("Persistent evidence", "survives a reboot, not always an upgrade", "g-stable", ["P1", "P2", "P3", "P4", "P5", "P6", "P7"]),
    ("Vendor bundles", "writes to the device; opt-in", "g-bundle", ["B"]),
    ("Break-glass", "can crash, reload or image it; opt-in, always last", "g-bg", ["X"]),
]
FLOW = [
    ("Preflight", "Pull the off-box copies. Record whether it rebooted or was upgraded.", "#guide/before-you-touch-the-device"),
    ("Collect", "Read-only steps in order of volatility; anything that writes is opt-in.", "#plans"),
    ("Ingest", "Vendor bundles, SIEM copies, image triage - hashed into the same case.", "#guide/bringing-in-exports"),
    ("Analyze", "Each detection: hit, no hit or not evaluated. Gaps are reported, never passed.", "#detections"),
    ("Respond", "Preserve, contain, rotate, eradicate, recover, verify - in that order.", "#response"),
    ("Harden", "Prevent the next one: management off the internet, MFA, logs off-box, patch or replace.", "#hardening"),
]


# How hits become a verdict. Each line is the copy on Start and the scenarios it
# describes; test_verdict_ladder_matches_the_analyzer runs every scenario through
# analyze.verdict(), so the page cannot drift from the code.
LADDER = [
    ("COMPROMISED", "A <b>confirmed</b> hit, or <b>likely</b> hits in two different evidence classes.",
     [[("confirmed", "memory")], [("likely", "filesystem"), ("likely", "process")]]),
    ("LIKELY-COMPROMISED", "One <b>likely</b> hit, or <b>possible</b> hits in two evidence classes.",
     [[("likely", "web-logs")], [("likely", "web-logs"), ("likely", "web-logs")],
      [("possible", "web-logs"), ("possible", "auth-logs")]]),
    ("SUSPICIOUS", "A <b>possible</b> hit in one class: often an attempt, success not shown, or off-box logs that "
     "do not add up (the SIEM&#39;s copy disagreeing with the box, or going quiet while the device was busy).",
     [[("possible", "web-logs")], [("possible", "web-logs"), ("possible", "web-logs")], [("possible", "offbox-logs")]]),
    ("NO-INDICATORS-FOUND", "Nothing fired. Not a finding that the device is clean: read the evidence gaps.", [[]]),
]
BEFORE_YOU_TOUCH = [
    "<b>Do not reboot, upgrade, factory-reset or run the vendor&#39;s external integrity tool.</b> Each destroys "
    "evidence - the red share of every bar above - and several implants were built to survive or fool exactly those.",
    "<b>Pull the off-box copies first</b> - SIEM syslog, NetFlow for the management interface, IdP and MFA logs. "
    "A gap in them is itself evidence.",
    "<b>Record whether it has rebooted or been upgraded</b> since the suspected window. It changes what the report can claim.",
    "<b>Use a read-only account</b> where the platform has one, and pin the host key.",
]


def plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def sdot(state: str) -> str:
    """A status dot. The word is there for screen readers and on hover; colour is never the only signal."""
    word = {"ok": "in place", "thin": "thin", "none": "missing"}[state]
    return f'<i class="sd sd-{state}" title="{word}"></i><span class="sr">{word}: </span>'


def src_bar(parts) -> str:
    """parts: (count, words, high|medium|low). A thin bar and a key, for the trust card."""
    segs = "".join(f'<span class="cs cs-{k}" style="flex:{n}" title="{n} {t}"></span>' for n, t, k in parts if n)
    key = "".join(f'<span><i class="sw cs-{k}"></i>{n} {e(t)}</span>' for n, t, k in parts if n)
    label = ", ".join(f"{n} {t}" for n, t, _ in parts)
    return f'<div class="sbar10" role="img" aria-label="{e(label)}">{segs}</div><div class="skey">{key}</div>'


def platform_tile(p: dict, data: dict, prof: dict, resp: dict, d: dict) -> str:
    pid = p["id"]
    arts = [a for a in data["artifacts"] if a["platform"] == pid]
    vc = {v: sum(1 for a in arts if a["volatility"] == v) for v in VOL_ORDER}
    segs = "".join(f'<span class="vb vb-{v}" style="flex:{vc[v]}"></span>' for v in VOL_ORDER if vc[v])
    vkey = "".join(f'<span><i class="vd vb-{v}"></i>{vc[v]} {v}</span>' for v in VOL_ORDER if vc[v])
    vlabel = ", ".join(f"{vc[v]} {v}" for v in VOL_ORDER if vc[v])
    pr = prof.get(p["profile"])
    pd = [x for x in data["detections"] if pid in x["platforms"]]
    nconf = sum(1 for x in pd if x["tier"] == "confirmed")
    nh = sum(1 for h in data["hunts"] if pid in h["platforms"])
    ready = []
    if pr:
        hi = sum(1 for st in pr.steps if st.confidence == "high" and not st.unverified)
        ready.append(("Plan", f"{len(pr.steps)} steps, {hi} vendor-documented", "ok" if hi / len(pr.steps) >= .5 else "thin"))
    else:
        ready.append(("Plan", "none: exports and images only", "none"))
    ready.append(("Detect", f'{len(pd)} in {plural(len(p["packs"]), "pack")}, '
                  + (f"{nconf} confirmed-tier" if nconf else "none confirmed-tier"), "ok" if nconf else "thin"))
    ready.append(("Respond", f"{resp[pid]}-step playbook" if pid in resp else "no playbook", "ok" if pid in resp else "none"))
    ready.append(("Harden", f'{plural(p["n_hard"], "control")} &#183; {plural(nh, "hunt")}', "ok" if p["n_hard"] and nh else "thin"))
    grid = "".join(f'<dt>{sdot(st)}<b>{k}</b></dt><dd>{v}</dd>' for k, v, st in ready)
    acts = ""
    if pr:
        acts += f'<a class="btn-fill" href="#plans/{e(p["profile"])}">Collect</a>'
    if p["response"]:
        acts += f'<a class="btn-out" href="#response/{e(p["response"])}">Respond</a>'
    acts += (f'<span class="pt-more"><a href="#artifacts?platform={pid}">Artifacts</a>'
             f'<a href="#detections?platform={pid}">Detections</a><a href="#cves?platform={pid}">CVEs</a></span>')
    return (f'<div class="ptile"><a class="ptile-h" href="#platforms/{pid}"><span class="pt-id">{pid} &#183; {e(p["vendor"])}</span>'
            f'<b>{e(p["short"])}</b></a>'
            f'<div class="pt-vol"><div class="vbar2" role="img" aria-label="Artifacts by volatility: {vlabel}">{segs}</div>'
            f'<div class="pt-vk">{vkey}</div></div>'
            f'<dl class="pt-ready">{grid}</dl><div class="pt-act">{acts}</div></div>')


def render_start(d: dict, data: dict) -> str:
    """The landing page for someone with a device in front of them: how far to
    trust the content, which device, what not to do first, how a triage runs,
    how hits become a verdict, and the order the collector follows."""
    plats, dets = data["platforms"], data["detections"]
    prof = {p.name: p for p in d["profiles"]}
    resp = {r["platform_id"]: resp_total(r) for r in d["response"].values()}
    steps, hi, me, lo = steps_by_source(d)
    nval, nprof = sum(1 for p in d["profiles"] if p.validated_on), len(d["profiles"])
    nsig = sum(1 for x in dets if x["sigma"])
    dunv = sum(1 for x in dets if x["unv"])

    trust = ('<aside class="trust" aria-label="How far to trust it">'
             '<div class="trust-h"><b>How far to trust it</b><a href="#coverage">Sourcing and gaps &#8594;</a></div>'
             f'<div class="trust-fig"><b class="{"bad" if nval < nprof else "good"}">{nval} of {nprof}</b>'
             '<span>collection profiles have run on a real device. Try one on a lab device or virtual edition before an incident.</span></div>'
             f'<div class="trust-cap"><span>{len(steps)} collection steps by source</span><span>{hi} vendor-documented</span></div>'
             + src_bar([(hi, "vendor-documented", "high"), (me, "multiple sources", "medium"), (lo, "unverified", "low")])
             + f'<p class="trust-f">{len(dets)} detections: {nsig} carry a Sigma rule for your SIEM, {dunv} come from unverified packs.</p></aside>')
    kpis = [(len(data["artifacts"]), "artifacts", "#artifacts"),
            (len(dets), f'detections in {len(d["packs"])} packs', "#detections"),
            (len(data["hunts"]), "off-box hunts", "#hunts"),
            (len(data["intel"]), "actors and implants", "#intel"),
            (len(data["cves"]), "CVEs, with CISA's catalog entry where there is one", "#cves"),
            (sum(1 for c in data["cves"] if c["triage"] == "Yes"), "flagged for forensic triage under BOD 26-04", "#cves?triage=yes"),
            (len(data["hardening"]), "hardening controls", "#hardening"),
            (len(data["rules"]), "Sigma and YARA files", "#detections?runs=siem,yara"),
            (f'{sum(1 for p in plats if p["profile"])}/{len(plats)}', "platforms with a profile", "#coverage")]
    kpi = "".join(f'<a class="kpi" href="{h}"><b>{n}</b> {e(t)}</a>' for n, t, h in kpis)
    tiles = "".join(platform_tile(p, data, prof, resp, d) for p in plats)
    vol_key = "".join(f'<span class="vk"><span class="vb vb-{v}"></span>{v}</span>' for v in VOL_ORDER)
    bty = "".join(f'<li><span class="bn">{i}</span><div>{t}</div></li>' for i, t in enumerate(BEFORE_YOU_TOUCH, 1))
    flow = "".join(f'<li><a href="{href}"><span class="fn">{i}</span><b>{e(t)}</b><span>{e(txt)}</span></a></li>'
                   for i, (t, txt, href) in enumerate(FLOW, 1))
    ladder = "".join(f'<div class="lcell"><span class="verdict v-{v.lower()}">{v}</span><p>{t}</p></div>' for v, t, _ in LADDER)
    per = {t: sum(1 for st in steps if st.tier == t) for t in TIER_ORDER}
    groups = []
    for title, sub, cls, tiers in OOV_GROUPS:
        chips_ = "".join(f'<li title="{plural(per[t], "step")} across all profiles"><span class="tc">{t}</span>{e(TIER_LABEL[t])}'
                         f'<span class="tn">{per[t]}</span></li>' for t in tiers)
        groups.append(f'<div class="oovg {cls}" style="flex:{len(tiers) + 1}"><div class="oovh"><b>{e(title)}</b>'
                      f'<span>{e(sub)}</span></div><ol>{chips_}</ol></div>')
    legend = "".join(
        f'<div class="lg"><h4>{e(title)}</h4><dl>'
        + "".join(f'<dt><span class="badge {c}">{e(t)}</span></dt><dd>{e(m)}</dd>' for c, t, m in rows)
        + "</dl></div>" for title, rows in LEGEND)
    return "".join([
        '<div class="start">',
        '<div class="hero1"><div class="hero-l"><h2>Triage a compromised edge device</h2>',
        '<p class="lede">What a compromised VPN concentrator, firewall or gateway leaves behind, what each trace proves, '
        'how long it lasts, and in what order to collect it. For responders who know DFIR and need the parts that are '
        'different on these devices.</p>',
        f'<p class="byline">By <a href="{AUTHOR_URL}" rel="noopener" target="_blank">{e(AUTHOR)}</a> &#183; '
        f'<a href="{FIRM_URL}" rel="noopener" target="_blank">{e(FIRM)}</a></p></div>',
        trust, '</div>',
        f'<nav class="kpis" aria-label="What is here">{kpi}</nav>',

        '<div class="sechead"><h3 class="sect">1. Which device?</h3>',
        f'<div class="vkey"><span class="muted small">Artifacts by how long they last:</span>{vol_key}</div></div>',
        f'<div class="ptiles">{tiles}</div>',

        '<h3 class="sect">2. Before you touch it</h3>',
        f'<div class="callout btyt"><ol class="bty">{bty}</ol>{unvalidated_banner(d)}</div>',

        '<h3 class="sect">3. How a triage runs</h3>',
        f'<ol class="flowd" aria-label="Triage workflow">{flow}</ol>',
        '<details class="fold"><summary>The commands</summary>',
        '<div class="codewrap"><button class="copy" type="button">Copy</button><pre><code>'
        'python -m edgetriage plan    --profile &lt;platform&gt;          # read it first\n'
        'python -m edgetriage collect --profile &lt;platform&gt; --host &lt;ip&gt; --user &lt;ro-user&gt; \\\n'
        '                             --case-id IR-2026-001 --rebooted no --patched no\n'
        'python -m edgetriage ingest  cases/IR-2026-001 --label tsf --bundle &lt;file&gt;\n'
        'python -m edgetriage analyze cases/IR-2026-001</code></pre></div></details>',
        '<section class="card ladder" aria-labelledby="ladder-h"><div class="ladder-h"><b id="ladder-h">How hits become a verdict</b>'
        '<span class="muted small">Corroboration, not counting: repeated hits in one evidence class never raise the verdict. '
        'There is no &quot;clean&quot;.</span></div>',
        f'<div class="ladder-g">{ladder}</div></section>',

        '<h3 class="sect">4. The order the collector follows</h3>',
        '<p class="muted small">Every profile runs in this order and refuses to move a step that can reload the '
        'device ahead of the memory steps. The number on each tier is how many steps use it across all profiles.</p>',
        f'<div class="oov"><div class="oovarrow" aria-hidden="true"><span>collected first</span><span>last</span></div>'
        f'<div class="oovgs">{"".join(groups)}</div></div>',

        f'<details class="fold badgesd"><summary>Reading the badges</summary><div class="legend-grid">{legend}</div></details>',
        "</div>",
    ])


# --------------------------------------------------------------------------- coverage
VOLG = [("Volatile", ["memory", "process", "sessions"]), ("Identity and state", ["identity", "integrity", "config"]),
        ("Logs", ["auth-logs", "web-logs", "system-logs"]), ("On disk", ["filesystem", "persistence"])]
# KEV decisions, in the schema's own words (artifacts/schema/watch.schema.json)
DECISIONS = {"iocs": "indicators only, no on-box detection",
             "no-indicators": "primary sources read, nothing usable published",
             "lab-only": "signals only from lab reproduction",
             "out-of-scope": "not the watched product",
             "deferred": "not yet read"}
READY_CAPS = ["Profile", "Run on a device", "Memory evidence", "Confirmed tier", "SIEM rules 25%+",
              "Playbook", "Hardening 5+", "Hunts"]


def _pip(tier: str) -> str:
    return f'<i class="pip p-{tier}"></i>' if tier else ""


def heatmap(plats: list[dict], groups, total, cell, mx: int, label: str, miss=(), noun: str = "detection") -> str:
    """A platform x class grid. cell(p, c) -> (count, href, strongest tier or "");
    total(p) -> (count, href). Darker means more; the pip is the strongest tier."""
    cols = [c for _, cs in groups for c in cs]
    head1 = ('<div class="hrow" role="row"><span role="columnheader"></span>'
             + "".join(f'<span class="hg" role="columnheader" aria-colspan="{len(cs)}" style="grid-column:span {len(cs)}">{e(g)}</span>'
                       for g, cs in groups) + '<span role="columnheader"></span></div>')
    head2 = ('<div class="hrow" role="row"><span role="columnheader"><span class="sr">Platform</span></span>'
             + "".join(f'<span class="hk" role="columnheader">{e(c)}</span>' for c in cols)
             + '<span class="hk" role="columnheader">total</span></div>')
    tmax = max(total(p)[0] for p in plats) or 1
    rows = []
    for p in plats:
        ab = PLATFORM_ABBR[p["id"]]
        cells = []
        for c in cols:
            n, href, tier = cell(p, c)
            if n:
                tip = f"{ab} {c}: {plural(n, noun)}" + (f", strongest {tier}" if tier else "")
                heat = round(10 + 50 * min(n, mx) / mx)
                cells.append(f'<span class="hcw" role="cell"><a class="hc{" dk" if n >= 4 else ""}" href="{href}" style="--h:{heat}%" '
                             f'title="{e(tip)}" aria-label="{e(tip)}">{n}{_pip(tier)}</a></span>')
            else:
                tip = f"{ab} {c}: none" + (" - the most volatile evidence is out of reach" if c in miss else "")
                cells.append(f'<span class="hcw" role="cell" aria-label="{e(tip)}"><span class="hc e{" miss" if c in miss else ""}" title="{e(tip)}"></span></span>')
        tn, thref = total(p)
        rows.append(f'<div class="hrow" role="row"><span role="rowheader"><a class="hr" href="{thref}">{e(ab)}</a></span>{"".join(cells)}'
                    f'<span class="htot" role="cell" aria-label="{e(ab)} total: {plural(tn, noun)}">{tn}<i class="hbar"><b style="width:{round(100 * tn / tmax)}%"></b></i></span></div>')
    return (f'<div class="card hwrap"><div class="heat" style="--cols:{len(cols)}" role="table" aria-label="{e(label)}">'
            f'{head1}{head2}{"".join(rows)}</div></div>')


def render_coverage(d: dict, data: dict) -> str:
    """Coverage and trust, option 2d: how far to trust the content, how ready
    each platform is, where detections and artifacts sit, the gaps with what
    would close them, and whether the packs keep up with exploited CVEs.
    Every number is computed here and links into the filtered library."""
    plats, dets, arts = data["platforms"], data["detections"], data["artifacts"]
    prof = {p.name: p for p in d["profiles"]}
    ab = PLATFORM_ABBR
    steps, hi, me, lo = steps_by_source(d)
    nval, nprof = sum(1 for p in d["profiles"] if p.validated_on), len(d["profiles"])
    built = build_date()
    now = ymd(built.isoformat())

    # 1. how far to trust it
    dunv = sum(1 for x in dets if x["unv"])
    ntool = sum(1 for a in arts if a["basis"] == "toolkit")
    trust = [(f"{nval} of {nprof}", "collection profiles have run on a real device", nval < nprof, "#guide/unvalidated-profiles"),
             (f"{len(steps) - hi} of {len(steps)}", f"collection steps are not vendor-documented; {lo} are unverified",
              len(steps) - hi > 0, "#plans"),
             (f"{dunv} of {len(dets)}", "detections come from packs marked unverified", False, "#detections?unv=1"),
             (f"{ntool} of {len(arts)}", "artifacts' suspicious criterion is the toolkit's own inference", False, "#artifacts?basis=toolkit")]
    trust_html = "".join(f'<a class="ttile" href="{h}"><b class="{"bad" if bad else ""}">{n}</b><span>{e(t)}</span></a>'
                         for n, t, bad, h in trust)

    # 2a. confidence, library by library
    rows = [("Collection steps", conf_counts(steps, conf=lambda st: st.confidence, unv=lambda st: st.unverified), "#plans"),
            ("Artifacts", conf_counts(arts), "#artifacts"), ("Hunts", conf_counts(data["hunts"]), "#hunts"),
            ("Threat intel", conf_counts(data["intel"]), "#intel"), ("Hardening", conf_counts(data["hardening"]), "#hardening")]
    conf_html = "".join(f'<a class="crow" href="{h}"><span>{e(n)}</span>{conf_bar(c)}<span class="ctot">{sum(c.values())}</span></a>'
                        for n, c, h in rows)

    # 2b. indicator freshness
    sets = [(ymd(x["published"]), x) for x in data["iocs"]]
    y0, y1 = int(min(t for t, _ in sets)), built.year + 1
    span = y1 - y0
    old = sum(1 for t, _ in sets if now - t > 1)
    dots = "".join(f'<span class="fd{" old" if now - t > 1 else ""}" style="left:{(t - y0) / span * 100:.2f}%;top:{6 + i % 3 * 9}px" '
                   f'title="{e(x["publisher"])}, {e(x["published"])} &#183; {plural(len(x["ind"]), "value")}"></span>'
                   for i, (t, x) in enumerate(sets))
    ticks = "".join(f'<span style="left:{(y - y0) / span * 100:.2f}%">{y}</span>' for y in range(y0, y1 + 1))
    fresh_txt = f"{old} of {len(sets)} indicator sets were published more than a year ago (grey)."
    libs = [("Platforms and artifacts", d["catalog"]), ("Detection packs", d["packs"]),
            ("Threat intel", d["actors"] + d["implants"]), ("Hunts", d["hunts"]),
            ("Hardening", list(d["hardening"].values())), ("Response playbooks", list(d["response"].values()))]
    dates = d.get("dates") or {}
    events = platform_events(d)
    lrows, flagged = [], []
    for name, recs in libs:
        ds = sorted(dates.get(x.get("_file", ""), "") for x in recs)
        ds = [x for x in ds if x]
        if not ds:
            continue
        hits = [(x, reread(x, dates, events)) for x in recs]
        hits = [(x, h) for x, h in hits if h]
        flagged += hits
        lrows.append(f'<tr><td>{e(name)}</td><td class="num">{len(recs)}</td><td class="nw">{ds[-1]}</td><td class="nw">{ds[0]}</td>'
                     f'<td class="num">{len(hits)}</td></tr>')
    if lrows:
        prow = []
        for p in plats:
            ev_ = events.get(p["id"])
            n_ = sum(1 for x, h in flagged if p["id"] in file_platforms(x) and h[0] == (ev_ or ("",))[0])
            prow.append(f'<tr><td class="nw">{e(PLATFORM_ABBR[p["id"]])}</td><td>{e(ev_[1]) if ev_ else "none recorded"}</td>'
                        f'<td class="num">{n_}</td></tr>')
        if flagged:
            items = "".join(f'<li><a href="{REPO_URL}/blob/main/{e(x["_file"])}" rel="noopener"><code>{e(x["_file"])}</code></a> '
                            f'changed {dates[x["_file"]]}, before {e(h[1])}</li>'
                            for x, h in sorted(flagged, key=lambda t: (t[1][0], t[0]["_file"]), reverse=True))
            flist = (f'<details class="fold"><summary>{plural(len(flagged), "file")} to re-read</summary>'
                     f'<ul class="plain">{items}</ul></details>')
        else:
            flist = '<p class="small">No record file was last changed before its platform\'s newest advisory.</p>'
        changed_html = (
            f'<h4>Record files, last changed</h4><div class="scroll"><table class="tbl fresh"><thead><tr><th>Library</th><th>Files</th>'
            f'<th>Newest</th><th>Oldest</th><th>Changed before the newest advisory</th></tr></thead><tbody>{"".join(lrows)}</tbody></table></div>'
            f'<h4>Newest advisory, platform by platform</h4><div class="scroll"><table class="tbl fresh"><thead><tr><th>Platform</th>'
            f'<th>Newest KEV entry or indicator set</th><th>Files changed before it</th></tr></thead><tbody>{"".join(prow)}</tbody></table></div>'
            f'{flist}<p class="small muted">A file counts when its last commit is older than the newest KEV entry (CISA\'s date added) '
            'or indicator set on a platform it covers. It may need a re-read; it is not known to be wrong. Files that apply to every '
            'device are not compared. A commit is not a review: an unrelated edit after the advisory also clears the flag. '
            'Every record shows its own date in its quick facts.</p>')
    else:
        changed_html = '<p class="small muted">Last-changed dates come from the git history, which this build did not have.</p>'
    fresh = (f'<div class="ftrack" role="img" aria-label="{e(fresh_txt)} Dashed line: the build date, {built.isoformat()}.">{dots}'
             f'<span class="fnow" style="left:{(now - y0) / span * 100:.2f}%"></span></div>'
             f'<div class="fticks" aria-hidden="true">{ticks}</div><p class="small muted">{e(fresh_txt)} Dashed line: '
             f'the build date. Hover a dot for the publisher.</p>')
    fresh = '<h4>Indicator sets, by publication date</h4>' + fresh

    # 3. readiness scorecard
    ready = []
    for p in plats:
        pid, pr = p["id"], prof.get(p["profile"])
        pd = [x for x in dets if pid in x["platforms"]]
        sig = sum(1 for x in pd if x["sigma"])
        nh = sum(1 for h in data["hunts"] if pid in h["platforms"])
        has = [bool(pr), bool(pr and pr.validated_on), any(a["class"] == "memory" for a in arts if a["platform"] == pid),
               any(x["tier"] == "confirmed" for x in pd), bool(pd) and sig / len(pd) >= .25, bool(p["response"]),
               p["n_hard"] >= 5, nh >= 1]
        hrefs = [f'#plans/{e(p["profile"])}' if pr else f"#platforms/{pid}", "#guide/unvalidated-profiles",
                 f"#artifacts?platform={pid}&amp;class=memory", f"#detections?platform={pid}&amp;tier=confirmed",
                 f"#detections?platform={pid}&amp;runs=siem", f'#response/{e(p["response"])}' if p["response"] else "#response",
                 f"#hardening?platform={pid}", f"#hunts?platform={pid}"]
        ready.append((sum(has), p, has, hrefs))
    ready.sort(key=lambda r: -r[0])
    rhead = ('<div class="rrow rhead" role="row"><span role="columnheader">Platform</span>'
             + "".join(f'<span role="columnheader">{e(c)}</span>' for c in READY_CAPS) + '<span role="columnheader">Has</span></div>')
    rbody = []
    for score, p, has, hrefs in ready:
        cells = "".join(f'<span role="cell"><a class="rc{" y" if h else ""}" href="{hr}" aria-label="{e(c)}: {"yes" if h else "no"}" '
                        f'title="{e(c)}: {"yes" if h else "no"}">{"&#10003;" if h else "&#183;"}</a></span>'
                        for c, h, hr in zip(READY_CAPS, has, hrefs))
        tone = "ok" if score >= 6 else ("thin" if score >= 4 else "none")
        rbody.append(f'<div class="rrow" role="row"><span role="rowheader"><a href="#platforms/{p["id"]}">{e(p["short"])}</a></span>{cells}'
                     f'<span role="cell" class="rhas"><b>{score} of {len(READY_CAPS)}</b><i class="rsc"><b class="s-{tone}" '
                     f'style="width:{round(100 * score / len(READY_CAPS))}%"></b></i></span></div>')
    none_ran = ("No platform has a validated run yet, so that column is empty for every row." if not nval else
                f"{plural(nval, 'profile has', 'profiles have')} a recorded run on a device.")

    # 4. heatmaps
    tiers = ("possible", "likely", "confirmed")

    def det_cell(p, c):
        xs = [x["tier"] for x in dets if p["id"] in x["platforms"] and x["evidence"] == c]
        return len(xs), f'#detections?platform={p["id"]}&amp;evidence={e(c)}', max(xs, key=tiers.index) if xs else ""

    def art_cell(p, c):
        n = sum(1 for a in arts if a["platform"] == p["id"] and a["class"] == c)
        return n, f'#artifacts?platform={p["id"]}&amp;class={e(c)}', ""

    det_heat = heatmap(plats, VOLG, lambda p: (p["n_det"], f'#detections?platform={p["id"]}'), det_cell, 6,
                       "Detections by platform and evidence class")
    art_heat = heatmap(plats, VOLG + [("Off-box", ["off-box"])], lambda p: (p["n_art"], f'#artifacts?platform={p["id"]}'),
                       art_cell, 5, "Artifacts by platform and class", miss=("memory", "process"), noun="artifact")
    dhead = "".join(f'<th class="vert"><span>{e(c)}</span></th>' for c in CLASSES)

    def tier_cell(xs_tiers, href, label):
        if not xs_tiers:
            return '<td class="cell"></td>'
        t = max(xs_tiers, key=TIERS.index)
        return (f'<td class="cell t-{t}"><a href="{href}" title="{len(xs_tiers)} {label}, strongest {t}">'
                f'{len(xs_tiers)}</a></td>')
    prows = []
    for pk in d["packs"]:
        cells = "".join(tier_cell([x["tier"] for x in pk["detect"] if x["evidence_class"] == c],
                                  f'#detections?pack={e(pk["id"])}&amp;evidence={e(c)}', "detection(s)") for c in CLASSES)
        cves = pk.get("cves", [])
        prows.append(f'<tr><th class="rowh"><a href="#detections?pack={e(pk["id"])}">{e(pk["id"])}</a> '
                     f'<span class="muted">{e(", ".join(cves[:2]))}{" ..." if len(cves) > 2 else ""}</span></th>{cells}</tr>')

    # 5. gap ledger
    triaged = d["kev"]["triaged"]
    dc = {k: sum(1 for t in triaged if t["decision"] == k) for k in DECISIONS}
    mem_missing = [p["id"] for p in plats if not any(a["platform"] == p["id"] and a["class"] == "memory" for a in arts)]
    no_conf = [p["id"] for p in plats if p["n_det"] and not any(x["tier"] == "confirmed" for x in dets if p["id"] in x["platforms"])]
    log_dets = [x for x in dets if x["evidence"].endswith("logs")]
    log_nosig = sum(1 for x in log_dets if not x["sigma"])
    unrun = [p.platform_id for p in d["profiles"] if not p.validated_on]
    noprof = [p["id"] for p in plats if not p["profile"]]
    gimp = [i for i in data["intel"] if i["kind"] == "implant" and i["coverage"] == "gap"]
    nimp = sum(1 for i in data["intel"] if i["kind"] == "implant")
    nodet = sorted({t["platform"] for t in triaged if t["decision"] == "no-indicators"})
    gaps = [
        ("Profiles never run on a device", f"{len(unrun)} of {nprof}", "responders", unrun,
         "A command can fail, prompt or page differently; the analyzer then reports not evaluated.",
         "One run per profile on a vendor virtual edition, recorded in `validated_on`.", "#guide/unvalidated-profiles"),
        ("No memory evidence reachable", f"{len(mem_missing)} of {len(plats)}", "responders", mem_missing,
         "A memory-only implant there leaves nothing this toolkit can collect.",
         "Process and session state is the most volatile evidence it reaches; say so in each platform entry.", "#coverage/art"),
        ("No confirmed-tier detection", f"{len(no_conf)} of {len(plats)}", "detection engineers", no_conf,
         "Hits reach COMPROMISED only by corroborating across evidence classes.",
         "A host artifact with no legitimate reason to exist, once a vendor or researcher publishes one.", "#detections?tier=confirmed"),
        ("Log detections without a Sigma rule", f"{log_nosig} of {len(log_dets)}", "detection engineers", [],
         "The same pattern could be watched in the SIEM copy the intruder cannot edit.",
         "Add a Sigma rule per log-pattern detection; the validator already links them.",
         "#detections?evidence=auth-logs,web-logs,system-logs"),
        ("Collection steps not vendor-documented", f"{len(steps) - hi} of {len(steps)}", "responders", [],
         "Medium and low steps rest on several sources or one" + ("; none has run on hardware." if not nval else "."),
         "Corrections from virtual editions or sanitized replay captures.", "#plans"),
        ("No collection profile", f"{len(noprof)} of {len(plats)}", "responders", noprof,
         "Collection is manual: exports and images only.", "A TSR and image-mode profile (roadmap phase 2).",
         f"#platforms/{noprof[0]}" if len(noprof) == 1 else "#platforms?profile=no"),
        ("Exploited CVEs with nothing to detect", f'{dc["no-indicators"]} of {plural(len(triaged), "decision")}',
         "detection engineers", nodet,
         "KEV lists them as exploited, but no vendor or researcher published an indicator.",
         "Revisit each quarter; the advisory-watch job flags new publications.", "#coverage/kev"),
        ("Implants with no detection", f"{len(gimp)} of {nimp}", "threat intel", [i["platforms"][0] for i in gimp],
         "Each record says why." if gimp else "Closed: every implant record has at least one detection.",
         "Each gap states what evidence would be needed." if gimp else
         "Keep the validator rule that a detection-less implant must state its gap.",
         "#intel?coverage=gap" if gimp else "#intel?kind=implant"),
    ]
    gap_html = []
    for title, n, who, ids, why, close, href in gaps:
        closed = n.startswith("0 of")
        pchips = ("".join(f'<span class="gp{" on" if p["id"] in ids else ""}">{e(ab[p["id"]])}'
                          f'{"<span class=sr> (affected)</span>" if p["id"] in ids else ""}</span>' for p in plats)
                  if ids else "")
        gap_html.append(f'<article class="gcard{" closed" if closed else ""}"><div class="gcard-h"><b>{e(title)}</b>'
                        f'<span class="small muted">for {e(who)}</span></div><b class="gn">{e(n)}</b>'
                        + (f'<div class="gps" aria-label="Platforms affected">{pchips}</div>' if pchips else "")
                        + f'<p class="rx">{e(why)}</p><p><b class="gclose">Closes it:</b> <span class="rx">{e(close)}</span></p>'
                        f'<a class="small" href="{href}">See the records &#8594;</a></article>')

    # 6. keeping up with exploitation (KEV)
    since = d["kev"]["since"]
    pack_cves = sorted({c for pk in d["packs"] for c in pk.get("cves", [])})
    yc: dict[str, int] = {}
    for c in pack_cves:
        yc[c[4:8]] = yc.get(c[4:8], 0) + 1
    ymax = max(yc.values()) if yc else 1
    years = "".join(f'<li title="{plural(n, "pack CVE")} from {y}"><span class="yn">{n}</span>'
                    f'<span class="yb{" old" if y < since[:4] else ""}" style="height:{max(4, round(60 * n / ymax))}px"></span>'
                    f'<span class="yy">{y}</span></li>' for y, n in sorted(yc.items()))
    tot = sum(dc.values()) or 1
    dsegs = "".join(f'<span class="dseg dec-{k}" style="flex:{n}" title="{n} {k}">'
                    f'{f"{n} {k}" if n / tot >= .14 else (str(n) if n / tot >= .05 else "")}</span>' for k, n in dc.items() if n)
    dkey = "".join(f'<li><i class="sw dec-{k}"></i><b{" class=bad" if k == "deferred" and n else ""}>{n}</b><span>{e(k)}: {e(m)}</span></li>'
                   for k, m in DECISIONS.items() for n in [dc[k]])
    latest = max((t["date"] for t in triaged), default="")
    open_ = dc["deferred"]
    ioc_owner = {x["id"]: (x["actors"] + x["implants"]) for x in data["iocs"]}

    def ref_link(r: str) -> str:
        if r.startswith("EDGE-IOC-"):
            own = ioc_owner.get(r) or []
            href = f"#intel/{own[0]}" if own else "#intel?iocs=yes"
        elif r.startswith("EDGE-HUNT-"):
            href = f"#hunts/{r}"
        else:
            href = f"#detections?pack={r}"
        return f'<a class="chip link" href="{href}">{e(r)}</a>'
    krows = "".join(f'<tr><td class="kc"><a href="#cves/{e(t["cve"])}">{e(t["cve"])}</a></td><td>{e(ab.get(t["platform"], t["platform"]))}</td>'
                    f'<td><span class="badge decb dec-{e(t["decision"])}">{e(t["decision"])}</span></td>'
                    f'<td><span class="rx">{e(t["basis"])}</span>'
                    + (f'<div class="links">{"".join(ref_link(r) for r in t["refs"])}</div>' if t["refs"] else "")
                    + f'</td><td class="muted kd">{e(t["date"])}</td></tr>' for t in triaged)
    in_watch = [c for c in data["cves"] if c["kev_platform"] and c["added"] >= since]
    n_tri = sum(1 for c in in_watch if c["triage"] == "Yes")
    kev = (f'<section id="cov-kev" class="covsec"><h3 class="sect">Keeping up with exploitation</h3>'
           f'<p class="muted small lede2">Every CISA KEV entry added since {e(since)} on a watched platform is either in a pack or '
           f'carries a recorded decision. The weekly advisory-watch job opens an issue for anything else and never commits. '
           f'The decisions live in <code>artifacts/watch/kev-watch.yml</code>. {n_tri} of those {len(in_watch)} entries are '
           f'flagged for forensic triage under BOD 26-04: <a href="#cves?triage=yes">see them, step by step</a>.</p>'
           f'<div class="cov2"><div class="card"><div class="kpi3">'
           f'<div><b>{len(pack_cves)}</b><span>CVEs with a detection pack</span></div>'
           f'<div><b>{len(triaged)}</b><span>exploited CVEs with a decision instead</span></div>'
           f'<div><b class="{"bad" if open_ else "good"}">{open_}</b><span>waiting to be read</span></div></div>'
           f'<h4>Pack CVEs by the year of the CVE</h4><ol class="ychart" role="img" aria-label="'
           + e(", ".join(f"{y}: {n}" for y, n in sorted(yc.items()))) + f'">{years}</ol>'
           f'<p class="small muted">{sum(n for y, n in yc.items() if y >= since[:4])} of {len(pack_cves)} pack CVEs carry a year of '
           f'{since[:4]} or later. The year is the one in the CVE id, not when exploitation began.</p></div>'
           f'<div class="card"><b class="ch">Why an exploited CVE has no pack</b>'
           f'<div class="dbar" role="img" aria-label="' + e(", ".join(f"{n} {k}" for k, n in dc.items())) + f'">{dsegs}</div>'
           f'<ul class="dkey">{dkey}</ul><p class="small muted">Latest decision {e(latest)}. &quot;deferred&quot; would mean not yet '
           f'read; {"none is open." if not open_ else plural(open_, "is", "are") + " open."}</p></div></div>'
           f'<div class="card ktbl"><b class="ch">Exploited CVEs on watched platforms with no pack, and why</b>'
           f'<div class="scroll"><table class="tbl kev"><thead><tr><th>CVE</th><th>Platform</th><th>Decision</th>'
           f'<th>Basis, from the primary source</th><th>Decided</th></tr></thead><tbody>{krows}</tbody></table></div></div></section>')

    return "".join([
        '<div class="lhead"><h2>Coverage and trust</h2><p class="lede">Where the content is thin, how far to trust it, and whether it '
        'keeps up with exploitation. Computed from the repository at build time; every number opens the filtered library.</p></div>',
        f'<section id="cov-trust" class="covsec"><h3 class="sect">How far to trust it</h3><div class="ttiles">{trust_html}</div>',
        '<div class="cov2"><div class="card"><b class="ch">Confidence, library by library</b>'
        f'<div class="crows">{conf_html}</div><div class="skey"><span><i class="sw cs-high"></i>high - vendor-documented or verified</span>'
        '<span><i class="sw cs-medium"></i>medium - several sources</span><span><i class="sw cs-low"></i>low or unverified</span></div></div>',
        f'<div class="card"><b class="ch">How fresh the content is</b>{fresh}{changed_html}</div></div></section>',
        '<section id="cov-ready" class="covsec"><h3 class="sect">How ready is each platform</h3>',
        '<p class="muted small">Eight things a responder relies on. Sorted by how many each platform has; every cell opens the '
        'evidence behind it.</p>',
        f'<div class="card scroll rwrap"><div class="ready" role="table" aria-label="Readiness by platform">{rhead}{"".join(rbody)}</div></div>',
        f'<p class="muted small">{e(none_ran)}</p></section>',
        '<section id="cov-det" class="covsec"><h3 class="sect">Detections by platform and evidence class</h3>',
        '<p class="muted small">The number is how many detections; the darker the cell, the more. The pip is the strongest tier among them.</p>',
        det_heat,
        '<p class="small muted hlegend">Strongest tier: <i class="pip p-possible"></i> possible <i class="pip p-likely"></i> likely '
        '<i class="pip p-confirmed"></i> confirmed. Darker cell: more detections.</p></section>',
        '<section id="cov-art" class="covsec"><h3 class="sect">Artifacts by platform and class</h3>',
        '<p class="muted small">A red outline marks an empty memory or process cell: there, the most volatile evidence is out of reach.</p>',
        art_heat, '</section>',
        f'<details class="fold"><summary>Detections by pack and evidence class ({len(d["packs"])} packs)</summary>',
        f'<div class="scroll"><table class="cov"><thead><tr><th></th>{dhead}</tr></thead><tbody>{"".join(prows)}</tbody></table></div></details>',
        '<section id="cov-gaps" class="covsec"><h3 class="sect">Gaps worth knowing before you rely on this</h3>',
        '<p class="muted small">Each gap says who it affects, which platforms, and what would close it. A closed gap stays listed so '
        'the rule that keeps it closed stays visible.</p>',
        f'<div class="gcards">{"".join(gap_html)}</div></section>',
        kev,
    ])


# --------------------------------------------------------------------------- page
CSS = r"""
:root{
  --bg:#fbfbfa;--panel:#fff;--panel-2:#fbfbfa;--hover:#faf7f4;
  --ink:#1c1b19;--muted:#6b6862;--faint:#a09b90;--line:#e4e1db;--line-soft:#f0ede8;--field:#ddd8d0;
  --accent:#5e3a24;--accent-hover:#472a19;--accent-soft:#f2e9e2;--accent-border:#e0cfc1;--on-accent:#fff;
  --crit:#a12b2b;--high:#b4611c;--med:#8a7320;--low:#5c7a4a;
  --conf-strong:#3d5a80;--conf-mid:#5d7189;--conf-bg:#eef2f7;--alert-bg:#fdf6f2;
  --code-bg:#f6f4f0;--shadow:rgba(28,27,25,.07);--shadow-lg:rgba(28,27,25,.16);--hdr:150px;--ink-2:#3d3a35;
  --sans:system-ui,"Segoe UI Variable Text","Segoe UI",-apple-system,BlinkMacSystemFont,Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,"Cascadia Mono","Cascadia Code","SF Mono",SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
  --fs-xs:12px;--fs-sm:13px;--fs-base:14.5px;--fs-md:16px;--fs-lg:20px;--fs-xl:24px}
/* Dark is lifted off black: cards sit 1.16:1 above the page, outlines are 2:1 against a card
   and control borders 3:1 (WCAG 1.4.11), checked by test_dark_theme_outlines_are_visible. */
:root[data-theme=dark]{
  --bg:#1e1c1a;--panel:#2a2825;--panel-2:#312e2a;--hover:#38352f;
  --ink:#f4f1ec;--muted:#bab4aa;--faint:#928b81;--line:#5d5851;--line-soft:#403d38;--field:#7e786f;
  --accent:#ddc4b0;--accent-hover:#ecd9ca;--accent-soft:#3b2c22;--accent-border:#86664f;--on-accent:#1a1310;
  --crit:#f28c85;--high:#eaa965;--med:#d9c364;--low:#a6d18c;
  --conf-strong:#9ec0e0;--conf-mid:#7e94ab;--conf-bg:#253341;--alert-bg:#33261f;
  --code-bg:#312e2a;--shadow:rgba(0,0,0,.35);--shadow-lg:rgba(0,0,0,.55);--ink-2:#ddd8d0}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){
  --bg:#1e1c1a;--panel:#2a2825;--panel-2:#312e2a;--hover:#38352f;
  --ink:#f4f1ec;--muted:#bab4aa;--faint:#928b81;--line:#5d5851;--line-soft:#403d38;--field:#7e786f;
  --accent:#ddc4b0;--accent-hover:#ecd9ca;--accent-soft:#3b2c22;--accent-border:#86664f;--on-accent:#1a1310;
  --crit:#f28c85;--high:#eaa965;--med:#d9c364;--low:#a6d18c;
  --conf-strong:#9ec0e0;--conf-mid:#7e94ab;--conf-bg:#253341;--alert-bg:#33261f;
  --code-bg:#312e2a;--shadow:rgba(0,0,0,.35);--shadow-lg:rgba(0,0,0,.55);--ink-2:#ddd8d0}}
*{box-sizing:border-box}
html{scroll-padding-top:var(--hdr)}
body{margin:0;background:var(--bg);color:var(--ink);font:var(--fs-base)/1.55 var(--sans);-webkit-text-size-adjust:100%}
a{color:var(--accent)}
button,input,select{font:inherit;color:inherit}
button{cursor:pointer}
code,.mono,pre{font-family:var(--mono)}
p{text-wrap:pretty}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.skip{position:absolute;left:-9999px;top:0;z-index:100;background:var(--accent);color:var(--on-accent);padding:10px 16px}
.skip:focus{left:0}

/* ---- header ---- */
.hdr{position:sticky;top:0;z-index:30;background:var(--bg);border-bottom:1px solid var(--line)}
.hdr-in{max-width:1440px;margin:0 auto;padding:10px 28px 0}
.hdr-top{display:flex;flex-wrap:nowrap;gap:12px;align-items:center}
.hdr-id{flex:1 1 340px;min-width:0}
.h1row{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.dot{width:9px;height:9px;border-radius:50%;background:var(--accent);flex:none}
h1{margin:0;font-size:var(--fs-lg);font-weight:600;letter-spacing:-.01em}
.pill{font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted);background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:2px 8px}
.sub{margin:5px 0 0;font-size:var(--fs-sm);color:var(--muted);max-width:68ch}
.byline{margin:4px 0 0;font-size:var(--fs-xs);color:var(--muted)}.byline a,footer a{color:var(--ink-2)}
.hdr-right{display:flex;gap:8px;align-items:center;flex:none;margin-left:auto}
.hbtn{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:7px 12px;font-size:var(--fs-sm);color:var(--ink);text-decoration:none;white-space:nowrap}
.hbtn:hover{border-color:var(--accent)}
.tabs{display:flex;gap:2px;overflow-x:auto;scrollbar-width:none;flex:1;min-width:0}
.tabs::-webkit-scrollbar{display:none}
.tabs button{background:none;border:0;border-bottom:2px solid transparent;flex:none;white-space:nowrap;padding:9px 12px;font-size:var(--fs-sm);color:var(--muted);display:flex;gap:7px;align-items:center}
.tabs button:hover{color:var(--ink)}
.tabs button[aria-selected=true]{color:var(--ink);font-weight:600;border-bottom-color:var(--accent)}
.tabs .n{font-family:var(--mono);font-size:var(--fs-xs);background:var(--line-soft);border-radius:20px;padding:1px 7px;font-weight:400}

/* ---- shell: rail + content ---- */
.shell{max-width:1440px;margin:0 auto;display:grid;grid-template-columns:252px minmax(0,1fr)}
.shell.norail{grid-template-columns:minmax(0,1fr)}
.shell.norail .rail{display:none}
.rail{position:sticky;top:var(--hdr);align-self:start;max-height:calc(100vh - var(--hdr));overflow-y:auto;padding:18px 18px 40px 28px;border-right:1px solid var(--line);scrollbar-width:thin}
.railhead{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.railhead b{font-size:var(--fs-xs);letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.lnkbtn{background:none;border:0;padding:0;color:var(--accent);text-decoration:underline;font-size:var(--fs-sm)}
#railToggle{display:none}
.fgroup{margin:12px 0 4px}
.fhead{display:flex;gap:6px;align-items:center;width:100%;background:none;border:0;padding:4px 0;font-size:var(--fs-xs);letter-spacing:.07em;text-transform:uppercase;color:var(--muted);font-weight:600;text-align:left}
.fhead .car{transition:transform .15s;font-size:var(--fs-xs)}
.fgroup.shut .car{transform:rotate(-90deg)}
.fgroup.shut .fvals{display:none}
.fhead .fsel{margin-left:auto;background:var(--accent);color:var(--on-accent);border-radius:20px;padding:0 6px;font-size:var(--fs-xs);letter-spacing:0}
.fv{display:flex;align-items:center;gap:8px;padding:4px 6px 4px 8px;border-radius:6px;font-size:var(--fs-sm);cursor:pointer;color:var(--ink)}
.fv:hover{background:var(--hover)}
.fv input{position:absolute;opacity:0;pointer-events:none}
.fv .box{flex:none;width:13px;height:13px;border:1px solid var(--field);border-radius:3px;background:var(--panel)}
.fv.on{background:var(--accent-soft)}
.fv.on .box{background:var(--accent);border-color:var(--accent);box-shadow:inset 0 0 0 2px var(--panel)}
.fv input:focus-visible+.box{outline:2px solid var(--accent);outline-offset:1px}
.fv .fl{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fv .fc{font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted)}
.fv.zero{color:var(--muted)}
.more{background:none;border:0;color:var(--accent);font-size:var(--fs-xs);padding:3px 8px}
main{padding:20px 28px 60px;min-width:0}
.lhead h2{margin:0 0 4px;font-size:var(--fs-lg);font-weight:600;letter-spacing:-.01em}
.lede{color:var(--muted);margin:0 0 16px;max-width:90ch}

/* ---- library controls ---- */
.controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:8px}
.search{flex:1 1 300px;display:flex;align-items:center;gap:8px;background:var(--panel);border:1px solid var(--field);border-radius:9px;padding:0 12px}
.search:focus-within{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.search .glyph{color:var(--muted)}
.search input{flex:1;border:0;background:none;padding:10px 0;font-size:var(--fs-base);outline:0;min-width:0}
.tgl{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:9px 13px;font-size:var(--fs-sm);color:var(--ink);white-space:nowrap}
.tgl:hover{border-color:var(--accent)}
.tgl[aria-pressed=true]{background:var(--accent);color:var(--on-accent);border-color:var(--accent)}
.tgl .n{font-family:var(--mono);font-size:var(--fs-xs);background:var(--alert-bg);color:var(--crit);border-radius:20px;padding:1px 6px;margin-left:5px}
.exp{display:flex;gap:6px;align-items:center;margin-left:auto}
.exp .lbl{font-size:var(--fs-xs);letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.meta{display:flex;gap:10px;flex-wrap:wrap;align-items:center;min-height:28px;margin-bottom:10px;font-size:var(--fs-sm)}
.count{font-family:var(--mono);color:var(--muted)}
.active{display:flex;gap:5px;flex-wrap:wrap}
.achip{display:inline-flex;gap:6px;align-items:center;background:var(--accent-soft);border:1px solid var(--accent-border);color:var(--accent);border-radius:999px;padding:2px 6px 2px 10px;font-size:var(--fs-xs)}
.achip button{background:none;border:0;color:inherit;padding:0 4px;font-size:var(--fs-base);line-height:1}
.picked{margin-left:auto;color:var(--accent);font-size:var(--fs-sm)}
.summary:empty{display:none}
.summary{margin-bottom:14px}

/* ---- distribution bar + tiles ---- */
.dist{display:flex;gap:3px;height:30px;border-radius:9px;overflow:hidden}
.seg{border:0;min-width:46px;display:flex;align-items:center;justify-content:center;gap:5px;font-size:var(--fs-xs);color:var(--on-accent);opacity:.88;white-space:nowrap;overflow:hidden;padding:0 8px}
.seg:hover,.seg.on{opacity:1}
.seg.on{box-shadow:inset 0 0 0 2px var(--ink)}
.seg-live,.seg-confirmed{background:var(--crit)}.seg-rotating,.seg-likely{background:var(--high)}
.seg-stable,.seg-possible{background:var(--med)}.seg-off-box{background:var(--conf-strong)}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px;text-align:left;display:flex;flex-direction:column;gap:2px}
button.tile:hover{border-color:var(--accent)}
.tile.on{border-color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent)}
.tile b{font-size:var(--fs-lg);font-weight:600;letter-spacing:-.02em}
.tile span{font-size:var(--fs-sm);color:var(--muted);line-height:1.35}
.tile.warn b{color:var(--crit)}
.tile.ok b{color:var(--low)}

/* ---- rows (table library) ---- */
.rows{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden;overflow:clip}
.row{display:grid;grid-template-columns:24px 120px minmax(0,1fr) 92px 86px 64px 104px;gap:14px;padding:12px 16px;border-top:1px solid var(--line-soft);align-items:start}
.row.head span{font-size:inherit;line-height:1.4}
.row.head{border-top:0;padding-top:11px;padding-bottom:11px;font-size:var(--fs-xs);letter-spacing:.08em;text-transform:uppercase;color:var(--muted);font-weight:600;background:var(--panel)}
.row.item{cursor:pointer}
.row.item:hover{background:var(--hover)}
.row.item.sel{background:var(--accent-soft);box-shadow:inset 3px 0 0 var(--accent)}
.c-plat{font-size:var(--fs-sm);line-height:1.35}
.c-plat .id{display:block;margin-top:3px}
.c-main{min-width:0}
code.loc{display:inline-block;max-width:100%;background:var(--code-bg);border:1px solid var(--line-soft);border-radius:5px;padding:1px 6px;font-size:var(--fs-sm);word-break:break-word}
.c-main .desc{display:block;color:var(--ink-2);font-size:var(--fs-base);margin-top:6px;line-height:1.5;max-width:75ch}
.c-main .seen{display:flex;gap:4px;flex-wrap:wrap;margin-top:6px}
.rows.compact .desc,.rows.compact .seen,.rows.compact .lead{display:none}
.c-main .lead{display:block;color:var(--ink-2);font-size:var(--fs-sm);margin-top:4px;line-height:1.45;max-width:75ch}
.c-main .lead b{color:var(--high);font-weight:600}
.nvs{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:10px}
.nvs>div{border:1px solid var(--line-soft);border-radius:10px;padding:10px 12px}
.nvs-n{background:color-mix(in srgb,var(--low) 7%,var(--panel));border-color:color-mix(in srgb,var(--low) 28%,transparent)!important}
.nvs-s{background:color-mix(in srgb,var(--high) 8%,var(--panel));border-color:color-mix(in srgb,var(--high) 28%,transparent)!important}
.nvs-n>b{color:var(--low)}.nvs-s>b{color:var(--high)}
.nvs b{display:block;font-size:var(--fs-sm);margin-bottom:4px}.nvs p{margin:0}
@media (max-width:640px){.nvs{grid-template-columns:minmax(0,1fr)}}
.rows.compact .row{padding-top:8px;padding-bottom:8px}
.pick,.pickall{width:15px;height:15px;margin:2px 0 0;accent-color:var(--accent);cursor:pointer}

/* ---- cards (grid library) ---- */
.lgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(310px,100%),1fr));gap:14px}.lgrid>*{min-width:0}.lgrid code{overflow-wrap:anywhere}
.lc{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:15px 16px;cursor:pointer;display:flex;flex-direction:column;gap:9px;box-shadow:0 1px 2px var(--shadow);transition:border-color .12s,box-shadow .12s,transform .12s}
.lc:hover{border-color:var(--accent-border);box-shadow:0 4px 14px var(--shadow);transform:translateY(-1px)}
.lc.sel{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent)}
.lc-h{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}
.lc-t{min-width:0}
.dist .seg.hd{min-width:0}
.ioc-c{border-color:var(--crit);color:var(--crit)}
.djump{display:flex;flex-wrap:wrap;gap:6px;margin:12px 0 2px;padding-bottom:10px;border-bottom:1px solid var(--line-soft)}
.djump a{font-size:var(--fs-sm);padding:3px 10px;border:1px solid var(--line);border-radius:999px;text-decoration:none;color:var(--ink-2)}
.djump a:hover{border-color:var(--accent-border)}
.lc h3{margin:2px 0 0;font-size:var(--fs-md);font-weight:600;line-height:1.3}
.lc-sub{font-size:var(--fs-xs);color:var(--muted);margin-top:2px}
.lc .badges{flex:none;justify-content:flex-end}
.clamp{margin:0;color:var(--ink-2);font-size:var(--fs-sm);line-height:1.5;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}
.lc-f{display:flex;gap:5px;flex-wrap:wrap;margin-top:auto;padding-top:9px;border-top:1px solid var(--line-soft)}
.stats{display:flex;gap:14px;font-size:var(--fs-sm);color:var(--muted)}
.stats b{color:var(--ink);font-size:var(--fs-md);margin-right:2px}
q.quote{font-style:italic;color:var(--ink);font-size:var(--fs-sm)}

/* ---- drawer ---- */
.drawer{position:fixed;top:0;right:0;bottom:0;width:min(580px,100vw);background:var(--panel);border-left:1px solid var(--line);box-shadow:-12px 0 40px var(--shadow-lg);z-index:50;display:flex;flex-direction:column;animation:slide .16s ease-out}
.drawer.wide{width:min(900px,100vw)}
@keyframes slide{from{transform:translateX(24px);opacity:.4}to{transform:none;opacity:1}}
@media (prefers-reduced-motion:reduce){.drawer,.lc{animation:none;transition:none}}
.dhead{display:flex;gap:10px;align-items:flex-start;justify-content:space-between;padding:16px 18px 14px;border-bottom:1px solid var(--line)}
.dhead h2{margin:2px 0 0;font-size:var(--fs-md);font-weight:600;line-height:1.3}
.dacts{display:flex;gap:6px;flex:none}
.dacts button{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:5px 10px;font-size:var(--fs-sm);color:var(--ink)}
.dacts button:hover:not(:disabled){border-color:var(--accent)}
.dacts button:disabled{opacity:.35;cursor:default}
.dbody{padding:0 18px 40px;overflow-y:auto;flex:1;overscroll-behavior:contain}
.dbody h4{margin:20px 0 7px}
.dbody p{margin:6px 0}
.dloc{display:flex;gap:8px;align-items:flex-start;margin:14px 0 4px}
.dloc code{flex:1;background:var(--code-bg);border:1px solid var(--line-soft);border-radius:8px;padding:9px 11px;font-size:var(--fs-sm);word-break:break-word}
.stepbox{background:var(--panel-2);border:1px solid var(--line-soft);border-radius:10px;padding:10px 12px}
.stepbox .codewrap{margin:8px 0}
.refs{padding-left:18px}.refs li{margin:4px 0}
/* One scroller at a time: while a record is open the page is locked behind a scrim and only
   the drawer scrolls; the gutter stays reserved so the page does not shift when it locks. */
html{scrollbar-gutter:stable}
.scrim{position:fixed;inset:0;background:rgba(20,18,16,.32);z-index:45}
body.drawer-open{overflow:hidden}

/* ---- shared bits ---- */
h3{margin:0;font-size:var(--fs-md);font-weight:600}
h4{margin:14px 0 6px;font-size:var(--fs-xs);letter-spacing:.07em;text-transform:uppercase;color:var(--muted)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;box-shadow:0 1px 2px var(--shadow)}
.card-h{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:flex-start}
.card p{margin:10px 0}
.id{font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted)}
.muted{color:var(--muted)}.small{font-size:var(--fs-xs)}
.note{background:var(--alert-bg);border-left:3px solid var(--high);padding:8px 10px;border-radius:4px;font-size:var(--fs-sm)}
.badges,.links{display:flex;gap:5px;flex-wrap:wrap;align-items:center}
.links{margin:8px 0}
.badge{display:inline-block;font-size:var(--fs-xs);border-radius:20px;padding:1px 8px;border:1px solid var(--line);white-space:nowrap;line-height:1.6}
.imp-none{color:var(--low);border-color:currentColor}
.imp-bundle{color:var(--med);border-color:currentColor;background:var(--alert-bg)}
.imp-bg{color:var(--on-accent);background:var(--crit);border-color:var(--crit)}
.conf{color:var(--conf-mid)}.c-high{color:var(--conf-strong);background:var(--conf-bg);border-color:var(--conf-strong)}
.c-low{color:var(--muted)}
.unv-b{color:var(--crit);background:var(--alert-bg);border-color:var(--crit)}
.tier{font-weight:600}.t-possible{color:var(--med);border-color:var(--med)}
.t-likely{color:var(--high);border-color:var(--high)}.t-confirmed{color:var(--on-accent);background:var(--crit);border-color:var(--crit)}
.sh-yes{color:var(--low);border-color:currentColor}.sh-restricted{color:var(--med);border-color:currentColor}.sh-no{color:var(--crit);border-color:currentColor}
.mem{color:var(--muted)}
.chip{display:inline-block;font-size:var(--fs-xs);background:var(--line-soft);border-radius:6px;padding:1px 7px;color:var(--ink);text-decoration:none;border:1px solid transparent}
.chip.mono{font-family:var(--mono);font-size:var(--fs-xs);word-break:break-all}
a.chip.mono{color:var(--ink)}
a.chip.mono:hover{border-color:var(--accent-border)}
.chip.nw{white-space:nowrap;word-break:normal}
.chip.link{background:var(--accent-soft);color:var(--accent);border-color:var(--accent-border)}
.chip.link:hover{border-color:var(--accent)}
.chip.ghost{background:none;border:1px dashed var(--field);color:var(--muted)}
.chip.cve{background:var(--conf-bg);color:var(--conf-strong)}
.chip.actor{background:var(--alert-bg);color:var(--high)}
.chip.implant{background:var(--alert-bg);color:var(--crit)}
ul{margin:4px 0;padding-left:20px}ul.plain{list-style:none;padding:0}
ul.plain li{padding:7px 0;border-top:1px solid var(--line-soft)}
ul.plain li:first-child{border-top:0}
ul.plain .row2{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
details summary{cursor:pointer;color:var(--muted);font-size:var(--fs-sm);margin-top:8px}
.tbl{width:100%;border-collapse:collapse;font-size:var(--fs-sm);margin-top:10px}
.tbl th,.tbl td{text-align:left;vertical-align:top;padding:8px 8px;border-top:1px solid var(--line-soft)}
.tbl thead th{font-size:var(--fs-xs);letter-spacing:.05em;text-transform:uppercase;color:var(--muted);border-top:0}
.tbl td.id{white-space:nowrap}
.picker{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}
.pbtn,.rbtn{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:7px 12px;min-height:38px;font-size:var(--fs-sm);color:var(--ink-2)}
.pbtn:hover,.rbtn:hover{color:var(--ink);border-color:var(--accent-border)}
.pbtn[aria-pressed=true],.rbtn[aria-pressed=true]{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
.planwrap{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:18px;align-items:start}
.plan{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
.plan-h{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
.plan-h h3{display:inline}
.guard .cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px}
.guard .chip{display:block;margin:3px 0}
.tierrow th{background:var(--panel-2);font-size:var(--fs-sm);font-weight:600;padding:9px 8px}
.tchip{font-family:var(--mono);font-size:var(--fs-xs);background:var(--accent);color:var(--on-accent);border-radius:5px;padding:1px 6px;margin-right:6px}
.step.off{opacity:.42}
.step .kind{font-size:var(--fs-xs);color:var(--muted);margin-top:3px}
.purpose{color:var(--muted);font-size:var(--fs-sm);margin-top:4px}
.needs{font-size:var(--fs-xs);color:var(--high);margin-top:3px}
.cmd{display:flex;gap:6px;align-items:flex-start;max-width:100%}
.cmd code{flex:1;min-width:0}.cmd .copy{flex:none;min-height:26px}
.cmd code{background:var(--code-bg);border:1px solid var(--line-soft);border-radius:6px;padding:2px 6px;font-size:var(--fs-xs);word-break:break-all}
.copy{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:3px 8px;font-size:var(--fs-xs);color:var(--muted)}
.copy:hover{color:var(--ink);border-color:var(--accent)}
.copy.sm{padding:1px 6px;font-size:var(--fs-xs)}
.codewrap{position:relative;margin:10px 0}
.codewrap .copy{position:absolute;top:8px;right:8px}
.codewrap pre{padding-right:64px}
pre{background:var(--code-bg);border:1px solid var(--line-soft);border-radius:8px;padding:12px;overflow:auto;font-size:var(--fs-xs);margin:0;max-height:520px}
pre.instr,pre.wrap{white-space:pre-wrap;max-height:none}
.builder{position:sticky;top:calc(var(--hdr) + 16px);background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;display:flex;flex-direction:column;gap:9px}
.builder label{display:flex;flex-direction:column;font-size:var(--fs-xs);color:var(--muted);gap:3px}
.builder label.tog{display:block;color:var(--ink)}
.builder label.tog input{margin:0 6px 0 0;vertical-align:-1px}
.builder input:not([type]),.builder select{background:var(--bg);border:1px solid var(--field);border-radius:7px;padding:6px 9px;font-size:var(--fs-sm);color:var(--ink)}
.builder pre{white-space:pre-wrap;word-break:break-all;padding-right:56px}
.fmt-sigma{color:var(--conf-strong);border-color:currentColor}.fmt-yara{color:var(--high);border-color:currentColor}
.lvl-critical{color:var(--crit);border-color:currentColor}.lvl-high{color:var(--high);border-color:currentColor}.lvl-medium{color:var(--med);border-color:currentColor}
.scroll{overflow-x:auto;margin:10px 0 22px}
table.cov{border-collapse:collapse;font-size:var(--fs-sm);background:var(--panel)}
table.cov th,table.cov td{border:1px solid var(--line-soft);padding:6px 9px}
table.cov .rowh{text-align:left;white-space:nowrap;font-weight:400}
table.cov .vert{height:116px;vertical-align:bottom;white-space:nowrap;font-weight:400;font-size:var(--fs-xs)}
table.cov .vert span{writing-mode:vertical-rl;transform:rotate(180deg)}
table.cov .cell{width:44px;padding:0;text-align:center;font-family:var(--mono)}
table.cov .cell a{display:block;padding:7px 0;color:var(--ink);text-decoration:none}
table.cov .cell a:hover{box-shadow:inset 0 0 0 2px var(--accent)}
.cell.t-possible{background:color-mix(in srgb,var(--med) 22%,transparent)}
.cell.t-likely{background:color-mix(in srgb,var(--high) 32%,transparent)}
.cell.t-confirmed{background:color-mix(in srgb,var(--crit) 40%,transparent)}
table.cov .num{text-align:center;font-family:var(--mono);min-width:34px}
.num.warn{color:var(--crit)}
.legend{color:var(--muted);display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin:-12px 0 24px}
.guide{max-width:760px}
.guide h2{font-size:var(--fs-lg);margin:8px 0 10px}.guide h3{font-size:var(--fs-md);margin:26px 0 8px}.guide h4{font-size:var(--fs-xs)}
.guide p,.guide li{line-height:1.7;color:var(--ink-2)}
.guide code{background:var(--code-bg);border-radius:4px;padding:1px 4px;font-size:var(--fs-sm)}
.guide pre code{background:none;padding:0}
footer{max-width:1440px;margin:0 auto;padding:22px 28px 40px;color:var(--muted);font-size:var(--fs-xs);border-top:1px solid var(--line)}
.sect{margin:22px 0 10px;font-size:var(--fs-md)}
.cls{color:var(--muted)}
.vol-live{color:var(--crit);border-color:currentColor}.vol-rotating{color:var(--high);border-color:currentColor}
.vol-stable{color:var(--med);border-color:currentColor}.vol-off-box{color:var(--conf-strong);border-color:currentColor;background:var(--conf-bg)}
.fv-high{color:var(--on-accent);background:var(--accent);border-color:var(--accent)}.fv-medium{color:var(--accent);border-color:var(--accent-border)}.fv-low{color:var(--muted)}
.mot-espionage{color:var(--conf-strong);border-color:currentColor}.mot-financial{color:var(--high);border-color:currentColor}
.mot-unknown,.mot-mixed{color:var(--muted)}
.kind-actor{color:var(--high);border-color:currentColor}.kind-implant{color:var(--crit);border-color:currentColor}
.charts{margin:14px 0 4px}.charts>summary{cursor:pointer;font-weight:600;font-size:var(--fs-md);margin-bottom:8px}
.chg{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:12px}.chp{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px;min-width:0}
.chp.wide{grid-column:1/-1}.chp h4{margin:0 0 8px;font-size:var(--fs-sm);color:var(--ink-2)}
.tl{display:grid;gap:3px;padding-right:16px}.tlr{display:grid;grid-template-columns:150px minmax(0,1fr);align-items:center;gap:8px;font-size:var(--fs-sm);min-height:20px}
.tlr>a,.tlr>span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.tlr.un>a,.tlr.un>span{color:var(--muted)}
.tlk{position:relative;height:18px;border-bottom:1px dashed var(--line-soft)}.tlh .tlk{border-bottom:1px solid var(--line);height:16px}
.tlt{position:absolute;transform:translateX(-50%);font-size:var(--fs-xs);color:var(--muted);top:0}
.tlb{position:absolute;top:8px;height:3px;background:var(--accent-border);border-radius:2px}
.tld{position:absolute;top:4px;width:11px;height:11px;margin-left:-5px;border-radius:50%;background:var(--accent);border:2px solid var(--accent)}
.tld.first{background:var(--panel)}.tlr.un .tld{background:var(--faint);border-color:var(--faint)}
.tld.inl{position:relative;display:inline-block;top:1px;margin:0 2px 0 0}
.attg{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}.attg h4{margin:0 0 6px}
.sbar{display:flex;border-radius:7px;overflow:hidden;min-height:26px;font-size:var(--fs-xs)}
.sbar>span{display:flex;align-items:center;gap:4px;padding:0 8px;color:var(--on-accent);white-space:nowrap;overflow:hidden;min-width:28px}
.sbar .q1{background:var(--conf-mid)}.sbar .q2{background:var(--conf-strong)}
.role-actor-controlled{background:var(--crit)!important;color:var(--on-accent)!important;border-color:var(--crit)!important}
.sbar .role-compromised-infrastructure,.chip.role-compromised-infrastructure{background:var(--high);color:var(--on-accent);border-color:var(--high)}
.sbar .role-anonymiser,.chip.role-anonymiser{background:var(--med);color:var(--on-accent);border-color:var(--med)}
.sbar .role-multi-tenant,.chip.role-multi-tenant{background:var(--conf-mid);color:var(--on-accent);border-color:var(--conf-mid)}
.sbar .role-suspected,.sbar .role-unknown,.chip.role-suspected,.chip.role-unknown{background:var(--muted);color:var(--on-accent);border-color:var(--muted)}
.amx{border-collapse:collapse;font-size:var(--fs-xs)}.amx th,.amx td{padding:4px 6px;border-bottom:1px solid var(--line-soft);text-align:center}
.amx thead th{font-weight:500;white-space:nowrap}.amx tbody th{text-align:left;font-weight:500;white-space:nowrap}
.amd{display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;border-radius:50%;background:var(--accent);color:var(--on-accent);font-size:10px}
.iocset{border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin:10px 0}.iocset .callout{margin:8px 0;padding:8px 12px;font-size:var(--fs-sm)}
.btnchip{cursor:pointer;font:inherit;font-size:var(--fs-xs)}.btnchip:hover{border-color:var(--accent)}
.iocd .iocs{max-height:420px;overflow:auto;border:1px solid var(--line-soft);border-radius:8px}
.iocd summary{cursor:pointer;font-size:var(--fs-sm);margin:6px 0}.ioct{border-collapse:collapse;font-size:var(--fs-xs);width:100%}
.ioct td{padding:4px 6px;border-bottom:1px solid var(--line-soft);vertical-align:top}.ioct code{word-break:break-all}
.ioct td:nth-child(2){min-width:16ch}.ioct .chip{white-space:nowrap}
@media (max-width:900px){.chg,.attg{grid-template-columns:minmax(0,1fr)}.tlr{grid-template-columns:96px minmax(0,1fr)}}
.attrib{background:var(--panel-2);border:1px solid var(--line-soft);border-radius:8px;padding:9px 12px;margin:12px 0;font-size:var(--fs-sm);display:grid;gap:4px}
.attrib .k{display:inline-block;min-width:110px;font-size:var(--fs-xs);letter-spacing:.05em;text-transform:uppercase;color:var(--muted)}
.attrib q{font-style:italic;color:var(--ink)}
.gap-b{color:var(--on-accent);background:var(--crit);border-color:var(--crit)}
.surv-yes{color:var(--crit);border-color:currentColor}.surv-no{color:var(--low);border-color:currentColor}
.surv-partial{color:var(--high);border-color:currentColor}.surv-unknown{color:var(--muted)}
.itype{color:var(--accent);border-color:var(--accent-border);background:var(--accent-soft)}
.res-memory{color:var(--crit);border-color:currentColor}.res-boot{color:var(--on-accent);background:var(--crit);border-color:var(--crit)}
.res-disk,.res-memory\+disk{color:var(--high);border-color:currentColor}
.phases{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-top:8px}
.phase{background:var(--panel-2);border:1px solid var(--line-soft);border-radius:8px;padding:6px 12px 10px}
.phase ol,.resp ol{margin:4px 0;padding-left:18px}.phase li{margin:5px 0;font-size:var(--fs-sm)}
.pn{display:inline-grid;place-items:center;width:18px;height:18px;border-radius:50%;background:var(--accent);color:var(--on-accent);font-size:var(--fs-xs);margin-right:7px;vertical-align:1px;letter-spacing:0}
.when{font-size:var(--fs-xs);color:var(--high);margin-top:2px}
/* ---- response: verdict lens, timeline checklist */
.rhead{padding:6px 0 10px;margin-bottom:8px;border-bottom:1px solid var(--line-soft)}
.rsel-l{display:none;font-size:var(--fs-sm);color:var(--muted);gap:8px;align-items:center;margin-bottom:8px}
.rsel{font:inherit;font-size:var(--fs-base);padding:7px 10px;border:1px solid var(--field);border-radius:8px;background:var(--panel);color:var(--ink);flex:1}
.rpick{margin-bottom:8px}
.vlens{display:flex;flex-wrap:wrap;gap:6px;align-items:center}.vl{font-size:var(--fs-xs);text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-right:4px}
.vbtn{background:var(--panel);border:1px solid var(--line);border-radius:999px;padding:3px 6px;font-size:var(--fs-sm);color:var(--muted);cursor:pointer}
.vbtn[data-v=""]{padding:5px 12px}.vbtn .verdict{margin:0}
.vbtn[aria-pressed=true]{border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-soft);color:var(--ink)}
.vhint{margin:6px 0 0}
.rlinks{margin:10px 0 0}
.rtool{display:flex;flex-wrap:wrap;gap:10px 16px;align-items:center;justify-content:space-between;margin:14px 0 6px}
.rprog{display:flex;align-items:center;gap:10px;font-size:var(--fs-sm);flex:1;min-width:220px}
.rbarw{flex:1;max-width:320px;height:8px;border-radius:5px;background:var(--line-soft);overflow:hidden}.rbar{display:block;height:100%;width:0;background:var(--low);transition:width .2s}
.rnav{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0 4px}
.rnav a{display:inline-flex;align-items:center;gap:2px;font-size:var(--fs-sm);padding:4px 10px 4px 5px;border:1px solid var(--line);border-radius:999px;color:var(--ink-2);text-decoration:none;background:var(--panel)}
.rnav a:hover{border-color:var(--accent-border)}.rnav .rc{margin-left:6px;font-size:var(--fs-xs);color:var(--muted)}
.rtl{margin-top:6px;max-width:1000px}
.rphase{display:grid;grid-template-columns:30px minmax(0,1fr);gap:10px;scroll-margin-top:calc(var(--hdr) + 12px)}
.rrail{position:relative;display:flex;justify-content:center}.rrail::after{content:"";position:absolute;top:24px;bottom:-4px;width:2px;background:var(--line)}
.rphase:last-child .rrail::after{display:none}.rrail .pn{width:24px;height:24px;margin:10px 0 0;font-size:var(--fs-sm);position:relative;z-index:1}
.rcol{padding:8px 0 14px;min-width:0}.rcol h4{margin:12px 0 6px}
.rlist{list-style:none;margin:0;padding:0}
.rstep{border:1px solid var(--line-soft);border-radius:8px;background:var(--panel);margin:6px 0}
.rstep label{display:grid;grid-template-columns:22px minmax(0,1fr);gap:8px;padding:9px 12px;cursor:pointer;font-size:var(--fs-sm)}
.rchk{width:16px;height:16px;margin:2px 0 0;accent-color:var(--low)}
.rbody b{display:block;font-weight:600;color:var(--ink)}.rdet{display:block;color:var(--ink-2);margin-top:3px;line-height:1.5}
.rwhen{display:flex;flex-wrap:wrap;gap:4px;align-items:center;margin-top:5px}
.rwhen:not(:has(.verdict,.rtick:not(:empty))){display:none}
.rtick{margin-left:auto;font-size:var(--fs-xs);color:var(--low);white-space:nowrap}.rtick:empty{display:none}.rwhen .for{font-size:var(--fs-xs);color:var(--muted)}
.rwhen .verdict{font-size:var(--fs-xs);margin:0}
.rstep.done{background:var(--panel-2)}.rstep.done .rbody b{text-decoration:line-through;text-decoration-color:var(--faint);color:var(--muted)}
.roff{display:none}
.rstep.off{border-style:dashed;background:transparent}.rstep.off label{display:none}
.rstep.off .roff{display:flex;flex-wrap:wrap;gap:4px 6px;align-items:center;padding:5px 12px;font-size:var(--fs-xs);color:var(--muted)}
.rofft{flex:1 1 260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.roff .verdict{opacity:.6;font-size:var(--fs-xs);margin:0}
.rstep.cred .rbody{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.3fr) minmax(0,1.3fr);gap:4px 16px}
.cred .cw,.cred .ca{color:var(--ink-2);line-height:1.5}.cl{display:block;font-size:var(--fs-xs);text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.dont .rdet{color:var(--ink-2)}.dont li{padding:6px 0;border-bottom:1px solid var(--line-soft)}.dont li:last-child{border-bottom:0}
.rrefs{margin-top:12px}
@media (max-width:760px){
  .fv{min-height:44px}
  .achip{padding:2px 3px 2px 10px}.achip button{width:26px;height:26px;border-radius:50%;display:inline-grid;place-items:center;padding:0}
  .achip button:hover{background:var(--accent-border)}
  .copy.sm{min-height:32px}
}
@media (max-width:760px){.rsel-l{display:flex}.rpick{display:none}.rstep.cred .rbody{grid-template-columns:minmax(0,1fr)}
  .rphase{grid-template-columns:24px minmax(0,1fr);gap:6px}.rrail .pn{width:20px;height:20px;font-size:var(--fs-xs)}}
@media print{
  .hdr,.rhead,.rtool .links,.rnav,.rlinks,.rail,footer,.toast,.scrim,#drawer,.ps-box,.ps-scrim{display:none!important}
  .panel:not(#tab-response){display:none!important}.resp[hidden]{display:none!important}
  body{background:#fff}.card.resp{border:0;box-shadow:none;padding:0}.rstep{break-inside:avoid}.rstep.off{display:none}
  .rrail::after{display:none}.rrefs[open] summary,.rrefs{display:block}}
.dont{margin-top:14px;background:var(--alert-bg);border:1px solid var(--line-soft);border-left:3px solid var(--crit);border-radius:8px;padding:4px 12px 8px}
.dont h4{color:var(--crit)}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:var(--ink);color:var(--bg);border-radius:9px;padding:9px 16px;font-size:var(--fs-sm);z-index:60;box-shadow:0 6px 24px var(--shadow-lg)}
[hidden]{display:none!important}
.empty{color:var(--muted);padding:40px 0;text-align:center;background:var(--panel);border:1px dashed var(--line);border-radius:12px}
kbd{font-family:var(--mono);font-size:var(--fs-xs);border:1px solid var(--line);border-bottom-width:2px;border-radius:4px;padding:0 4px;background:var(--panel)}

@media (max-width:980px){.planwrap{grid-template-columns:minmax(0,1fr)}.builder{position:static;order:-1}}
@media (max-width:900px){
  .shell{grid-template-columns:1fr}
  .rail{position:static;max-height:none;border-right:0;border-bottom:1px solid var(--line);padding:10px 16px}
  .railhead{margin:0}
  #railToggle{display:inline-flex;gap:6px;align-items:center}
  .rail:not(.open) #rail{display:none}
  .rail:not(.open) #railReset{display:none}
}
@media (max-width:640px){
  .rail{top:0}
  .hdr-in,main,footer{padding-left:16px;padding-right:16px}
  .tabs{mask-image:linear-gradient(90deg,#000 85%,transparent);-webkit-mask-image:linear-gradient(90deg,#000 85%,transparent)}
      .exp{margin-left:0}
  .seg span{display:none}
  .railhead b{display:none}
  .lgrid{grid-template-columns:minmax(0,1fr)}
  .card,.plan{padding:14px}.tbl{font-size:var(--fs-xs)}
  .steps thead{display:none}.steps tr.step td{display:block;border:0;padding:3px 0}
  .steps tr.step{display:block;padding:10px 0;border-top:1px solid var(--line-soft)}
  .steps tr.step td:first-child{font-weight:600}.steps .tierrow th{display:block}
  .dhead{padding:12px 14px}.dbody{padding:0 14px 40px}
  .dacts #dWide{display:none}
}

/* ---- type system: one sans family; monospace only for literal strings ---- */
.id,.pill,.tabs .n,.tgl .n,.fv .fc,.count,.chip.mono,a.chip.mono,.tchip,table.cov .cell,table.cov .num,.mono,b.mono,.ptile .n{font-family:var(--sans);font-variant-numeric:tabular-nums}
.id{letter-spacing:.01em}
code,kbd,pre,.chip.code,code.loc{font-family:var(--mono);font-variant-ligatures:none}
p code,li code,dd code,.desc code,td code{font-size:.9em;background:var(--code-bg);border:1px solid var(--line-soft);border-radius:4px;padding:0 4px}
.chip.code{font-size:var(--fs-xs);word-break:break-all}

/* ---- tabs: workflow, then reference ---- */
.tabs{margin-top:8px}
.tabsep{flex:none;width:1px;background:var(--line);margin:8px 10px}
.tabs button[data-tab=start]{font-weight:600;color:var(--accent)}
.tabs button[data-tab=start][aria-selected=true]{color:var(--ink)}

/* ---- start ---- */
.start{max-width:1180px}
.hero h2{margin:0 0 6px;font-size:var(--fs-lg);font-weight:600;letter-spacing:-.01em}
.hero .lede{font-size:var(--fs-md);line-height:1.55;color:var(--ink-2);max-width:72ch}
.ptiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(232px,100%),1fr));gap:10px}
.ptile{background:var(--panel);border:1px solid var(--line);border-radius:12px;display:flex;flex-direction:column;overflow:hidden}
.ptile:hover{border-color:var(--accent-border);box-shadow:0 4px 14px var(--shadow)}
.ptile-h{display:flex;flex-direction:column;gap:1px;padding:12px 14px 8px;text-decoration:none;color:var(--ink)}
.ptile-h b{font-size:var(--fs-md);font-weight:600}
.ptile-l{display:flex;flex-wrap:wrap;gap:2px 12px;padding:8px 14px 11px;border-top:1px solid var(--line-soft);font-size:var(--fs-sm)}
.ptile-l a{text-decoration:none}.ptile-l a:hover{text-decoration:underline}
.ptile .n{color:var(--muted);font-size:var(--fs-xs)}
.startcols{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:8px 28px}
.callout{background:var(--alert-bg);border:1px solid var(--line-soft);border-left:3px solid var(--crit);border-radius:10px;padding:12px 16px;color:var(--ink)}
.warnbox{background:var(--alert-bg);border:1px solid var(--line-soft);border-left:3px solid var(--crit);border-radius:10px;padding:10px 14px;margin:12px 0;font-size:var(--fs-sm);line-height:1.55;color:var(--ink)}
.callout ol{margin:0;padding-left:20px}.callout li{margin:6px 0;line-height:1.55}
.flow{margin:0;padding-left:22px}.flow li{margin:0 0 12px;line-height:1.55}
.flow code{display:block;margin:6px 0;background:var(--code-bg);border:1px solid var(--line-soft);border-radius:7px;padding:7px 10px;font-size:var(--fs-sm);word-break:break-word}
.legend-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px}
.lg{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:4px 14px 12px}
.lg h4{color:var(--muted)}
.lg dl{display:grid;grid-template-columns:auto 1fr;gap:7px 10px;margin:0;align-items:baseline}
.lg dt{margin:0}.lg dd{margin:0;font-size:var(--fs-sm);color:var(--ink-2);line-height:1.4}
a.tile{text-decoration:none;color:var(--ink)}a.tile:hover{border-color:var(--accent)}
.verdict{display:inline-block;font-size:var(--fs-xs);font-weight:600;letter-spacing:.02em;border-radius:5px;padding:1px 7px;margin:1px 2px;border:1px solid currentColor;white-space:nowrap}
.v-compromised{color:var(--on-accent);background:var(--crit);border-color:var(--crit)}
.v-likely-compromised{color:var(--high)}.v-suspicious{color:var(--med)}.v-no-indicators-found{color:var(--muted)}

/* ---- coverage ---- */
details.fold{margin:8px 0 20px}details.fold summary{font-size:var(--fs-sm);color:var(--accent);font-weight:600}

/* ---- guide ---- */
.guide h2{font-size:var(--fs-lg);margin:6px 0 10px}
.guide h3{font-size:var(--fs-md);margin:30px 0 8px;padding-top:4px}
.guide h4{font-size:var(--fs-xs)}
.hlink{margin-left:8px;color:var(--muted);text-decoration:none;opacity:1;font-weight:400}
.hlink:hover{color:var(--accent)}
.guide h3 .hcopy{margin-left:8px;vertical-align:2px;font-weight:400;letter-spacing:0}
.guide .callout{margin:10px 0 14px}
.pnote{border-left:2px solid var(--line);padding:2px 0 2px 14px;margin:12px 0}
.pnote p{margin:0 0 6px}.pnote .links{margin:4px 0 0}
.guide .tbl td,.guide .tbl th{font-size:var(--fs-sm)}
.toc{display:flex;flex-direction:column;gap:1px;margin-top:6px}
.toc a{display:flex;align-items:center;min-height:32px;padding:5px 8px;border-radius:6px;color:var(--ink-2);text-decoration:none;font-size:var(--fs-sm);line-height:1.35;border-left:2px solid transparent}
.toc a.l3{padding-left:20px;color:var(--muted)}
.toc a:hover{background:var(--hover)}
.toc a.on{color:var(--accent);background:var(--accent-soft);border-left-color:var(--accent);font-weight:600}
@media (max-width:640px){.startcols{grid-template-columns:1fr}.tabsep{margin:8px 4px}}

/* ---- start visuals ---- */
.sechead{display:flex;justify-content:space-between;align-items:baseline;gap:6px 16px;flex-wrap:wrap}
.vkey{display:flex;gap:10px;align-items:center;flex-wrap:wrap;font-size:var(--fs-xs);color:var(--muted)}
.vk{display:inline-flex;gap:5px;align-items:center}.vk .vb{width:12px;height:8px;border-radius:2px;flex:none}
.vbwrap{padding:0 14px 10px;display:flex;flex-direction:column;gap:4px}
.vbar2{display:flex;gap:2px;height:7px;border-radius:4px;overflow:hidden;background:var(--line-soft)}
.vb-live{background:var(--crit)}.vb-rotating{background:var(--high)}.vb-stable{background:var(--med)}.vb-off-box{background:var(--conf-strong)}
.vbl{font-size:var(--fs-xs);color:var(--muted);font-variant-numeric:tabular-nums}
.callout ol.cols2{columns:2 340px;column-gap:32px}.callout ol.cols2 li{break-inside:avoid}
.flowd{list-style:none;padding:0;margin:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(min(165px,100%),1fr));gap:12px;counter-reset:f}
.flowd li{position:relative}
.flowd a{display:flex;flex-direction:column;gap:4px;height:100%;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px;text-decoration:none;color:var(--ink)}
.flowd a:hover{border-color:var(--accent)}
.flowd .fn{display:inline-grid;place-items:center;width:22px;height:22px;border-radius:50%;background:var(--accent);color:var(--on-accent);font-size:var(--fs-xs);font-weight:600}
.flowd b{font-size:var(--fs-md)}.flowd span:last-child{font-size:var(--fs-sm);color:var(--ink-2);line-height:1.45}
.flowd li:first-child a{border-color:var(--crit);background:var(--alert-bg)}
.flowd li:last-child a{border-color:var(--low);background:color-mix(in srgb,var(--low) 8%,var(--panel))}
.flowd li:last-child .fn{background:var(--low)}
.verdline{margin:12px 0 4px;line-height:2}
.oov{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.oovarrow{display:flex;justify-content:space-between;font-size:var(--fs-xs);color:var(--muted);margin-bottom:8px;position:relative;padding:0 2px}
.oovarrow::before{content:"";position:absolute;left:96px;right:40px;top:50%;border-top:1px dashed var(--field)}
.oovarrow::after{content:"";position:absolute;right:30px;top:50%;width:7px;height:7px;border-top:1px solid var(--muted);border-right:1px solid var(--muted);transform:translateY(-50%) rotate(45deg)}
.oovgs{display:flex;gap:8px;align-items:stretch}
.oovg{border-radius:9px;padding:8px 10px 10px;border:1px solid var(--line-soft);min-width:0}
.oovh{display:flex;flex-direction:column;margin-bottom:6px}.oovh b{font-size:var(--fs-sm)}.oovh span{font-size:var(--fs-xs);color:var(--muted);line-height:1.35}
.oovg ol{list-style:none;padding:0;margin:0;display:flex;flex-wrap:wrap;gap:4px}
.oovg li{display:inline-flex;gap:5px;align-items:center;font-size:var(--fs-xs);background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:2px 7px 2px 3px;white-space:nowrap}
.oovg .tc{font-weight:600;color:var(--on-accent);background:var(--accent);border-radius:4px;padding:0 5px;font-variant-numeric:tabular-nums}
.g-live{background:color-mix(in srgb,var(--crit) 10%,transparent);border-color:color-mix(in srgb,var(--crit) 35%,transparent)}
.g-stable{background:color-mix(in srgb,var(--med) 10%,transparent)}
.g-bundle{background:color-mix(in srgb,var(--high) 10%,transparent);border-style:dashed;border-color:var(--high)}
.g-bg{background:color-mix(in srgb,var(--crit) 14%,transparent);border-style:dashed;border-color:var(--crit)}
@media (max-width:1240px){.tabs button{padding:9px 9px}.tabsep{margin:8px 4px}}
@media (max-width:1120px){.tabs .n{display:none}.tabs{mask-image:linear-gradient(90deg,#000 92%,transparent);-webkit-mask-image:linear-gradient(90deg,#000 92%,transparent)}}
@media (max-width:1100px){.oovgs{flex-wrap:wrap}.oovg{flex:1 1 260px!important}}
@media (max-width:640px){.flowd{grid-template-columns:1fr;gap:8px}.flowd a{flex-direction:row;flex-wrap:wrap;align-items:center;column-gap:10px}.flowd span:last-child{flex:1 1 100%}
  .oovarrow{display:none}.vbwrap{padding:0 11px 8px}.vbl{display:none}}

/* ---- hardening ---- */
.pr{font-weight:600}.pr-critical{color:var(--on-accent);background:var(--crit);border-color:var(--crit)}
.pr-high{color:var(--high);border-color:currentColor}.pr-medium{color:var(--med);border-color:currentColor}
ol.steps{padding-left:20px;margin:0}ol.steps li{margin:6px 0;line-height:1.55}
.dist .seg.hd:nth-child(odd){background:var(--conf-strong)}.dist .seg.hd:nth-child(even){background:var(--conf-mid)}
.callout.inf{border-left-color:var(--med);margin:12px 0}
.srcs{padding-left:18px}.srcs li{margin:6px 0}
.srcs blockquote{margin:6px 0 0;padding:6px 10px;border-left:3px solid var(--line);color:var(--ink-2);font-size:var(--fs-sm);font-style:italic;background:var(--panel-2);border-radius:0 6px 6px 0}

.stepbox.rule{margin:8px 0}.stepbox.rule b{font-size:var(--fs-sm)}
.sumline{margin:8px 0 0}

/* ==================================================================== UX v2 */
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
mark{background:color-mix(in srgb,var(--med) 30%,transparent);color:inherit;border-radius:2px;padding:0 1px}
b.bad,.bad{color:var(--crit)}b.good,.good{color:var(--low)}
.sw{display:inline-block;width:10px;height:8px;border-radius:2px;flex:none}
.cs-high{background:var(--conf-strong)}.cs-medium{background:var(--conf-mid)}.cs-low{background:var(--crit)}
.cbar{display:flex;gap:2px;height:20px;border-radius:5px;overflow:hidden;background:var(--line-soft)}.cbar.h18{height:18px}
.cs{display:flex;align-items:center;padding:0 7px;font-size:var(--fs-xs);color:var(--on-accent);white-space:nowrap;overflow:hidden;min-width:4px;font-variant-numeric:tabular-nums}
.skey{display:flex;flex-wrap:wrap;gap:4px 14px;font-size:var(--fs-xs);color:var(--muted)}.skey span{display:inline-flex;align-items:center;gap:5px}
.lhead .about{margin:-8px 0 14px}.lhead .about summary{margin:0;font-size:var(--fs-sm)}.lhead .about p{max-width:90ch;color:var(--ink-2);margin:6px 0 0}
.lede{margin:0 0 12px}

/* header: one row (F1, F32) */
.brand{display:flex;align-items:center;gap:9px;text-decoration:none;color:var(--ink);flex:none}
h1{white-space:nowrap}
.hsearch{flex:1 1 auto;min-width:0;max-width:560px;min-height:38px;display:flex;align-items:center;gap:8px;background:var(--panel);border:1px solid var(--field);border-radius:9px;padding:7px 12px;font-size:var(--fs-sm);color:var(--muted);text-align:left;cursor:text}
.hsearch:hover{border-color:var(--accent-border)}
.hsearch .hs-l{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.hsearch .hs-s{display:none;flex:1}.hsearch kbd{flex:none}
.tabs{margin-top:6px}.tabs button{min-height:40px}
@media (max-width:760px){.wide-only{display:none!important}.hsearch .hs-l,.hsearch kbd{display:none}.hsearch .hs-s{display:inline}}
@media (max-width:640px){h1{font-size:var(--fs-md)}.hdr-top{gap:8px}.hdr-in{padding-top:8px}}

/* start, option 1a (F4, F5, F6) */
.hero1{display:flex;flex-wrap:wrap;gap:18px 28px;align-items:flex-start;margin-bottom:16px}
.hero-l{flex:1 1 420px;min-width:0}
.hero-l h2{margin:0 0 6px;font-size:var(--fs-lg);font-weight:600;letter-spacing:-.01em}
.hero-l .lede{font-size:var(--fs-md);line-height:1.55;color:var(--ink-2);max-width:62ch;margin:0 0 8px}
.hero-l .byline{margin:0}
.trust{flex:1 1 320px;max-width:460px;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px;box-shadow:0 1px 2px var(--shadow);display:flex;flex-direction:column;gap:8px}
.trust-h{display:flex;justify-content:space-between;align-items:baseline;gap:10px;font-size:var(--fs-sm)}.trust-h b{font-weight:600}
.trust-fig{display:flex;gap:12px;align-items:flex-start;font-size:var(--fs-sm);color:var(--ink-2);line-height:1.4}
.trust-fig b{font-size:var(--fs-xl);font-weight:600;line-height:1.05;white-space:nowrap;font-variant-numeric:tabular-nums}
.trust-cap{display:flex;justify-content:space-between;gap:8px;font-size:var(--fs-xs);color:var(--muted)}
.sbar10{display:flex;gap:2px;height:10px;border-radius:5px;overflow:hidden;background:var(--line-soft)}
.trust-f{margin:0;padding-top:8px;border-top:1px solid var(--line-soft);font-size:var(--fs-sm);color:var(--ink-2)}
.kpis{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 4px}
.kpi{display:inline-flex;align-items:center;gap:6px;min-height:34px;padding:5px 12px;border:1px solid var(--line);border-radius:999px;background:var(--panel);color:var(--muted);text-decoration:none;font-size:var(--fs-sm)}
.kpi b{font-size:var(--fs-md);color:var(--ink);font-variant-numeric:tabular-nums}.kpi:hover{border-color:var(--accent)}
.pt-id{font-size:var(--fs-xs);color:var(--muted)}
.ptile-h b{line-height:1.3}
.pt-vol{padding:0 14px 10px}.pt-vol .vbar2{height:8px}
.pt-vk{display:flex;flex-wrap:wrap;gap:2px 10px;margin-top:5px;font-size:var(--fs-xs);color:var(--muted)}.pt-vk span{display:inline-flex;align-items:center;gap:4px}
.vd{display:inline-block;width:9px;height:9px;border-radius:2px}
.pt-ready{display:grid;grid-template-columns:auto minmax(0,1fr);gap:3px 8px;margin:0;padding:10px 14px;border-top:1px solid var(--line-soft);font-size:var(--fs-xs);color:var(--ink-2);flex:1;align-content:start}
.pt-ready dt{display:flex;align-items:center;gap:6px;margin:0}.pt-ready dt b{font-weight:600;color:var(--ink)}.pt-ready dd{margin:0}
.sd{display:inline-block;width:8px;height:8px;border-radius:50%;flex:none}.sd-ok{background:var(--low)}.sd-thin{background:var(--med)}.sd-none{background:var(--crit)}
.pt-act{display:flex;flex-wrap:wrap;gap:6px 8px;align-items:center;padding:10px 14px 12px;border-top:1px solid var(--line-soft)}
.btn-fill,.btn-out{display:inline-flex;align-items:center;min-height:30px;border-radius:7px;padding:4px 11px;font-size:var(--fs-sm);text-decoration:none}
.btn-fill{background:var(--accent);color:var(--on-accent);font-weight:600;border:1px solid var(--accent)}.btn-fill:hover{background:var(--accent-hover)}
.btn-out{border:1px solid var(--accent-border);color:var(--accent)}.btn-out:hover{border-color:var(--accent)}
.pt-more{margin-left:auto;display:flex;gap:10px;font-size:var(--fs-xs)}
.callout.btyt{padding:14px 16px}
.btyt .bty{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(min(250px,100%),1fr));gap:12px 22px}
.btyt .bty li{display:flex;gap:10px;align-items:flex-start;margin:0;line-height:1.55;font-size:var(--fs-sm)}
.bn{flex:none;display:inline-grid;place-items:center;width:22px;height:22px;border-radius:50%;background:var(--crit);color:var(--on-accent);font-size:var(--fs-xs);font-weight:600;margin-top:1px}
.btyt .warnbox{background:none;border:0;border-top:1px solid var(--line);border-radius:0;margin:14px 0 0;padding:12px 0 0}
.card.ladder{margin:14px 0 4px}
.ladder-h{display:flex;flex-wrap:wrap;justify-content:space-between;gap:4px 16px;align-items:baseline;margin-bottom:10px}.ladder-h b{font-size:var(--fs-md)}
.ladder-g{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(200px,100%),1fr));gap:10px}
.lcell{border:1px solid var(--line-soft);border-radius:10px;padding:10px 12px;background:var(--panel-2)}
.lcell .verdict{margin:0}.card .lcell p{margin:8px 0 0;font-size:var(--fs-sm);line-height:1.5;color:var(--ink-2)}
.oovg .tn{margin-left:2px;color:var(--muted);font-variant-numeric:tabular-nums}
details.badgesd{margin-top:24px}details.badgesd>summary{font-size:var(--fs-md);font-weight:600;color:var(--ink)}
details.badgesd .legend-grid{margin-top:10px}

/* libraries (F7, F9, F10, F13) */
.search{min-height:38px}.tgl{min-height:38px}
.distcap{display:flex;justify-content:space-between;gap:10px;font-size:var(--fs-xs);color:var(--muted);margin:0 0 4px}
.results{container-type:inline-size}
.row .pl-line{display:none}
a.locl{text-decoration:none;color:inherit;display:inline-block;max-width:100%;border-radius:5px}
a.locl:hover code.loc{border-color:var(--accent-border)}
.c-main .desc{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.c-main .lead{display:-webkit-box;-webkit-line-clamp:1;-webkit-box-orient:vertical;overflow:hidden}
.row.sel .c-main .desc,.row.sel .c-main .lead{display:block}
.rows.compact .c-main .desc,.rows.compact .c-main .lead{display:none}
.grp{position:sticky;top:var(--hdr);z-index:2;display:flex;flex-wrap:wrap;align-items:center;gap:4px 10px;padding:8px 16px;background:var(--panel-2);border-top:1px solid var(--line);border-bottom:1px solid var(--line-soft)}
.grp a{font-size:var(--fs-sm);font-weight:600;color:var(--ink);text-decoration:none}.grp a:hover{text-decoration:underline}
.grp .gm{font-size:var(--fs-xs);color:var(--muted)}.grp .vbar2{width:110px;height:6px;margin-left:auto}
@container (max-width:860px){
  .row{grid-template-columns:24px minmax(0,1fr) 92px;gap:4px 12px}
  .row .c-pick,.row .c-main{grid-row:1/span 3}
  .row .c-plat,.row .c-val{display:none}
  .row .c-vol{grid-column:3;grid-row:1}.row .c-cls{grid-column:3;grid-row:2}.row .c-conf{grid-column:3;grid-row:3}
  .row .pl-line{display:block;font-size:var(--fs-xs);color:var(--muted);margin-bottom:4px}
  .row.head .c-pick,.row.head .c-main{grid-row:1}.row.head .c-cls,.row.head .c-conf{display:none}
}
@container (max-width:560px){
  .row{display:flex;flex-wrap:wrap;gap:6px 8px;padding:12px 14px}
  .row.head{display:none}
  .row .c-pick{order:9;margin-left:auto}
  .row .c-main{flex:1 1 100%}
  .row .c-val,.row .c-cls,.row .c-conf{display:block}
}
.runs{display:flex;flex-wrap:wrap;gap:4px 12px;align-items:center;font-size:var(--fs-xs);color:var(--muted)}
.runs .rk{letter-spacing:.06em;text-transform:uppercase}
.runs>span{display:inline-flex;align-items:center;gap:5px}
.runs i{width:9px;height:9px;border-radius:50%;border:1.5px solid var(--field);display:inline-block}
.runs .y{color:var(--ink-2)}.runs .y i{background:var(--conf-strong);border-color:var(--conf-strong)}

/* record drawer (F15) */
.dacts{align-items:center}.dacts button{height:34px;min-width:34px}
.dpos{font-size:var(--fs-xs);color:var(--muted);white-space:nowrap;margin-right:2px;font-variant-numeric:tabular-nums}
.dbody{position:relative}
.dsecs{position:sticky;top:0;z-index:2;display:flex;flex-wrap:wrap;gap:6px;padding:10px 0;margin:0 0 2px;background:var(--panel);border-bottom:1px solid var(--line-soft)}
.dsecs button{background:var(--panel);border:1px solid var(--line);border-radius:999px;padding:3px 10px;font-size:var(--fs-sm);color:var(--ink-2);min-height:28px}
.dsecs button:hover{border-color:var(--accent-border)}
.dfacts{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px 14px;padding:12px;background:var(--panel-2);border:1px solid var(--line-soft);border-radius:10px;margin:14px 0 4px}
.dfacts div{min-width:0}.dfacts dt{font-size:var(--fs-xs);color:var(--muted);margin:0 0 3px}.dfacts dd{margin:0;font-size:var(--fs-sm);overflow-wrap:anywhere}
.dconn{border:1px dashed var(--line);border-radius:10px;padding:2px 12px 12px;margin:18px 0 6px}.dconn h4{margin:10px 0 8px}
.dcg{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px 16px}.dcg .links{margin:0}
.dck{display:block;font-size:var(--fs-xs);color:var(--muted);margin-bottom:4px}

/* coverage and trust, option 2d (F17-F21) */
.covsec{scroll-margin-top:8px}   /* html already pads by the header height */
.ttiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(220px,100%),1fr));gap:10px}
.ttile{display:flex;flex-direction:column;gap:4px;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px;text-decoration:none;color:var(--ink-2);font-size:var(--fs-sm);line-height:1.4}
.ttile:hover{border-color:var(--accent)}
.ttile b{font-size:var(--fs-xl);font-weight:600;line-height:1.1;color:var(--ink);font-variant-numeric:tabular-nums}.ttile b.bad{color:var(--crit)}
.cov2{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(400px,100%),1fr));gap:12px;margin:12px 0}
.cov2>.card{min-width:0}
.ch{display:block;font-size:var(--fs-sm);font-weight:600;margin-bottom:10px}
.crows{display:flex;flex-direction:column;gap:7px;margin-bottom:10px}
.crow{display:grid;grid-template-columns:118px minmax(0,1fr) 36px;gap:10px;align-items:center;font-size:var(--fs-sm);color:var(--ink);text-decoration:none}
.crow:hover>span:first-child{text-decoration:underline}
.ctot{text-align:right;color:var(--muted);font-variant-numeric:tabular-nums}
.ftrack{position:relative;height:38px;border-bottom:1px solid var(--line);margin:4px 8px 0}
.fd{position:absolute;width:10px;height:10px;margin-left:-5px;border-radius:50%;background:var(--accent);box-shadow:0 0 0 2px var(--panel)}.fd.old{background:var(--faint)}
.fnow,.tlnow{position:absolute;top:0;bottom:0;width:0;border-left:1.5px dashed var(--crit)}
.fticks{position:relative;height:18px;margin:2px 8px 8px}.fticks span{position:absolute;transform:translateX(-50%);font-size:var(--fs-xs);color:var(--muted)}
.card.rwrap{padding:0;margin:10px 0 8px}
.ready{min-width:780px}
.rrow{display:grid;grid-template-columns:170px repeat(8,minmax(62px,1fr)) 104px;gap:6px;align-items:center;padding:6px 14px;border-top:1px solid var(--line-soft)}
.rrow.rhead{border-top:0;font-size:var(--fs-xs);font-weight:600;color:var(--muted);align-items:end;text-align:center;padding-top:10px;line-height:1.25}
.rrow.rhead span:first-child,.rrow.rhead span:last-child{text-align:left}
.rrow [role=rowheader] a{color:var(--ink);text-decoration:none;font-size:var(--fs-sm);font-weight:600}.rrow [role=rowheader] a:hover{text-decoration:underline}
.rc{display:grid;place-items:center;height:28px;border-radius:6px;border:1px solid var(--line);background:repeating-linear-gradient(135deg,var(--panel),var(--panel) 4px,var(--line-soft) 4px,var(--line-soft) 6px);color:var(--muted);font-weight:700;text-decoration:none}
.rc.y{border-color:var(--low);background:color-mix(in srgb,var(--low) 16%,var(--panel));color:var(--low)}
.rc:hover{box-shadow:0 0 0 2px var(--accent-border)}
.rhas{display:flex;flex-direction:column;gap:4px;font-size:var(--fs-sm)}
.rsc{display:block;height:6px;border-radius:3px;background:var(--line-soft);overflow:hidden}.rsc b{display:block;height:100%;border-radius:3px}
.s-ok{background:var(--low)}.s-thin{background:var(--med)}.s-none{background:var(--crit)}
.card.hwrap{overflow-x:auto;padding:12px 14px;margin:10px 0 8px}
.hrow{display:contents}.hcw{display:block;min-width:0}
.heat{display:grid;grid-template-columns:92px repeat(var(--cols),minmax(38px,1fr)) 70px;gap:3px;align-items:center;min-width:calc(162px + var(--cols) * 44px)}
.hg{font-size:var(--fs-xs);color:var(--muted);text-align:center;border-bottom:1px solid var(--line);padding-bottom:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hk{font-size:11px;color:var(--muted);text-align:center;line-height:1.2;align-self:end;overflow-wrap:anywhere;padding-top:4px}
.hr{font-size:var(--fs-sm);color:var(--ink)}
.hc{position:relative;display:grid;place-items:center;height:30px;border-radius:4px;font-size:var(--fs-sm);font-variant-numeric:tabular-nums;color:var(--ink);text-decoration:none;background:color-mix(in srgb,var(--accent) var(--h,0%),var(--panel))}
.hc.dk{color:var(--on-accent)}.hc.e{background:transparent}
.hc.e.miss{box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--crit) 45%,transparent)}
a.hc:hover{box-shadow:inset 0 0 0 2px var(--accent)}
.pip{display:inline-block;width:7px;height:7px;border-radius:50%;box-shadow:0 0 0 1.5px var(--panel)}
.hc .pip{position:absolute;top:3px;right:3px}
.p-possible{background:var(--med)}.p-likely{background:var(--high)}.p-confirmed{background:var(--crit)}
.hlegend .pip{margin:0 2px 0 8px}
.htot{display:flex;align-items:center;gap:6px;font-size:var(--fs-sm);font-variant-numeric:tabular-nums;padding-left:4px}
.hbar{flex:1;height:6px;border-radius:3px;background:var(--line-soft);overflow:hidden;display:block}.hbar b{display:block;height:100%;background:var(--accent);border-radius:3px}
.gcards{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(320px,100%),1fr));gap:12px}
.gcard{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px;display:flex;flex-direction:column;gap:7px;min-width:0}
.gcard.closed{border-color:var(--low)}
.gcard-h{display:flex;justify-content:space-between;gap:10px;align-items:baseline}.gcard-h b{font-size:var(--fs-sm);font-weight:600}
.gn{font-size:var(--fs-xl);font-weight:600;line-height:1.1;color:var(--crit);font-variant-numeric:tabular-nums}.gcard.closed .gn{color:var(--low)}
.gps{display:flex;flex-wrap:wrap;gap:4px}
.gp{font-size:11px;padding:1px 5px;border-radius:4px;border:1px solid var(--line);color:var(--muted);white-space:nowrap}
.gp.on{border-color:var(--crit);background:var(--alert-bg);color:var(--crit)}
.gcard p{margin:0;font-size:var(--fs-sm);line-height:1.5;color:var(--ink-2)}
.gclose{color:var(--low)}.gcard>a{margin-top:auto}
.lede2{max-width:90ch;margin-top:0}
.kpi3{display:flex;flex-wrap:wrap;gap:12px 28px;margin-bottom:6px}
.kpi3 div{display:flex;flex-direction:column}
.kpi3 b{font-size:var(--fs-xl);font-weight:600;line-height:1.1;font-variant-numeric:tabular-nums}.kpi3 span{font-size:var(--fs-xs);color:var(--muted)}
.ychart{list-style:none;margin:0;padding:0;display:flex;align-items:flex-end;gap:6px;height:104px}
.ychart li{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;gap:3px;min-width:0}
.yb{display:block;width:100%;background:var(--accent);border-radius:3px 3px 0 0}.yb.old{background:var(--accent-border)}
.yn,.yy{font-size:var(--fs-xs);color:var(--muted);font-variant-numeric:tabular-nums}
.dec-iocs{--dc:var(--high)}.dec-no-indicators{--dc:var(--conf-mid)}.dec-lab-only{--dc:var(--med)}.dec-out-of-scope{--dc:var(--muted)}.dec-deferred{--dc:var(--crit)}
.dbar{display:flex;gap:2px;height:20px;border-radius:5px;overflow:hidden;margin-bottom:10px}
.dseg{display:flex;align-items:center;padding:0 7px;font-size:var(--fs-xs);color:var(--on-accent);white-space:nowrap;overflow:hidden;min-width:4px;background:var(--dc)}
.dkey{list-style:none;margin:0 0 8px;padding:0;display:flex;flex-direction:column;gap:5px;font-size:var(--fs-sm)}
.dkey li{display:flex;gap:8px;align-items:baseline}.dkey .sw{width:10px;height:10px;align-self:center;background:var(--dc)}
.dkey b{min-width:18px;font-variant-numeric:tabular-nums}
.decb{color:var(--dc);border-color:currentColor;font-weight:600}
.tbl.kev td.kc{font-weight:600;white-space:nowrap}.tbl.kev td.kd{white-space:nowrap}.tbl.kev .links{margin:6px 0 0}
.ktbl .scroll{margin:0}

/* threat intel charts (F22, F23) */
.tl{gap:2px;padding-right:0}
.tlr{grid-template-columns:150px minmax(0,1fr) 84px;min-height:22px}
.tlrep{font-size:var(--fs-xs);color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tlk{height:22px}.tlh .tlk{height:18px}
.tlb{top:9px}
.tld{top:4px;width:13px;height:13px;margin-left:-6px;background:var(--accent);border:0;box-shadow:0 0 0 2px var(--panel)}
.tld.first{background:var(--panel);border:2px solid var(--accent);box-shadow:none}
.tld.inl{width:11px;height:11px;vertical-align:-1px}
.tlr.lane .tlk{height:28px;background:var(--panel-2);border-radius:4px;border-bottom:0}
.tlr.lane .tlrep{white-space:normal;line-height:1.2}
.tlh .tlt:first-child{transform:none}.tlh .tlt:last-child{transform:translateX(-100%)}
#dTitle:focus{outline:none}
.tlq{position:absolute;width:9px;height:9px;margin-left:-4px;border-radius:2px;background:var(--accent)}.tlq.un{background:var(--faint)}
.rolefig{display:flex;gap:14px;align-items:baseline;flex-wrap:wrap;margin-bottom:10px}
.rolefig .big{font-size:var(--fs-xl);font-weight:600;color:var(--crit);line-height:1.1;white-space:nowrap;font-variant-numeric:tabular-nums}
.rolefig .big span{font-size:var(--fs-md);color:var(--muted);font-weight:400}
.rolefig p{margin:0;flex:1 1 300px;font-size:var(--fs-sm);color:var(--ink-2)}
.rbar16{display:flex;gap:2px;height:16px;border-radius:5px;overflow:hidden;margin-bottom:10px}
.rr{min-width:3px}
.rr-actor-controlled{background:var(--crit)}.rr-compromised-infrastructure{background:var(--high)}.rr-anonymiser{background:var(--med)}
.rr-multi-tenant{background:var(--conf-mid)}.rr-suspected{background:var(--faint)}.rr-unknown{background:color-mix(in srgb,var(--muted) 55%,var(--panel))}
.rolel{list-style:none;margin:0 0 8px;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:5px 16px;font-size:var(--fs-sm)}
.rolel li{display:flex;align-items:center;gap:7px}.rolel .sw{width:10px;height:10px}.rolel .pct{margin-left:auto;color:var(--muted);font-variant-numeric:tabular-nums}
.attr2{display:flex;flex-wrap:wrap;gap:12px 24px;align-items:flex-start}
.attr2 .scroll{margin:0;flex:0 1 auto;max-width:100%}
.attr2 p{flex:1 1 220px;margin:0;font-size:var(--fs-sm);color:var(--ink-2)}
@media (max-width:900px){.tlr{grid-template-columns:96px minmax(0,1fr) 64px}}

/* response (F25, F26) */
.vbtn{display:inline-flex;align-items:center;gap:6px;min-height:34px;padding:4px 10px 4px 6px}
.vbtn[data-v=""]{padding:4px 10px}
.vn{font-size:var(--fs-xs);color:var(--muted);font-variant-numeric:tabular-nums}
.rcase-l{display:inline-flex;align-items:center;gap:8px;font-size:var(--fs-sm);color:var(--muted)}
.rcase{width:140px;font-family:var(--mono);font-size:var(--fs-sm);padding:6px 9px;border:1px solid var(--field);border-radius:7px;background:var(--panel);color:var(--ink)}
.rstep.cred .rwhen{grid-column:1/-1}
.dont-h{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:0 16px}.dont-h h4{margin:12px 0 6px}
.rack-l{display:inline-flex;align-items:center;gap:6px;font-size:var(--fs-sm);color:var(--ink-2);cursor:pointer}
.rack{width:16px;height:16px;margin:0;accent-color:var(--crit)}
.dont .dgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,max(300px,calc(50% - 11px))),1fr));gap:0 22px}
.dont .dgrid li:first-child{border-top:0}
.rfold{display:none;margin:4px 0 6px}
.dont.acked .dgrid li:nth-child(n+4){display:none}.dont.acked .rfold{display:block}

/* collection plans (F27, F28, F29) */
.psum{display:flex;flex-wrap:wrap;gap:12px 24px;align-items:flex-end;justify-content:space-between;background:var(--panel-2);border:1px solid var(--line-soft);border-radius:10px;padding:12px;margin:12px 0}
.psum-l{flex:1 1 280px;display:flex;flex-direction:column;gap:6px;min-width:0}
.psum-n{font-size:var(--fs-sm);color:var(--muted)}.psum-n b{font-size:var(--fs-lg);color:var(--ink);font-weight:600;margin-right:2px}
.psum-r{flex:0 1 auto;min-width:0;display:flex;flex-direction:column;gap:4px;max-width:100%;overflow-x:auto}
.tstrip{list-style:none;margin:0;padding:0;display:flex;gap:3px;align-items:flex-end;height:52px}
.tstrip li{display:flex;flex-direction:column;align-items:center;justify-content:flex-end;gap:3px;width:22px;flex:none}
.tb{display:block;width:100%;border-radius:3px 3px 0 0}
.tb-v{background:var(--accent)}.tb-p{background:var(--accent-border)}.tb-b{background:var(--high)}.tb-x{background:var(--crit)}.tb.e{background:var(--line)}
.tsl{font-family:var(--mono);font-size:11px;color:var(--muted)}
.whld{display:none;font-size:var(--fs-xs);color:var(--high);margin-top:3px}.step.off .whld{display:block}
.bwarn{background:var(--alert-bg);border:1px solid color-mix(in srgb,var(--crit) 35%,transparent);border-radius:9px;padding:8px 10px;font-size:var(--fs-sm);line-height:1.5}
.bwarn b{color:var(--crit)}
.b2{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:8px}
.b2 select{width:100%;min-width:0}

/* exploited CVEs */
.bod-b{color:var(--ink);background:var(--alert-bg);border-color:var(--crit);font-weight:600}
.rw-b{color:var(--crit);background:transparent;border-color:var(--crit)}
.xb{color:var(--ink);background:var(--accent-soft);border-color:var(--accent)}
.xcall{margin:0 0 10px;padding:8px 12px;font-size:var(--fs-sm)}
.xh{margin:12px 0 4px;font-size:var(--fs-sm)}
.xread{margin:6px 0}.xread>summary{cursor:pointer;color:var(--muted)}.xread ul{margin:6px 0;padding-left:18px}
ol.bod{list-style:none;margin:0 0 8px;padding:0;counter-reset:bod}
ol.bod>li{counter-increment:bod;display:grid;grid-template-columns:26px minmax(0,1fr);column-gap:10px;padding:10px 0;border-top:1px solid var(--line-soft)}
ol.bod>li::before{content:counter(bod);grid-row:span 3;width:24px;height:24px;border-radius:50%;background:var(--accent-soft);color:var(--ink);display:grid;place-items:center;font-size:var(--fs-xs);font-weight:600}
ol.bod .bod-t{font-size:var(--fs-xs);color:var(--muted)}
ol.bod .bod-go{display:flex;flex-wrap:wrap;gap:6px;margin-top:5px;align-items:center}
.cve-name{font-weight:600;margin:0 0 6px}
ul.arts>li{padding:7px 0;border-top:1px solid var(--line-soft)}
ul.arts>li:first-child{border-top:0}
.cvt{list-style:none;margin:0 0 6px;padding:0}
.cvt li{display:grid;grid-template-columns:96px minmax(0,1fr);column-gap:10px;padding:6px 0;border-top:1px solid var(--line-soft)}
.cvt li:first-child{border-top:0}
.cvt .cvt-d{grid-row:span 2;font-variant-numeric:tabular-nums;color:var(--ink-2);font-size:var(--fs-sm)}
.cvstats{border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:10px 14px;margin:0 0 14px}
.cvstats>summary{cursor:pointer;font-weight:600;font-size:var(--fs-sm)}
.cvs-tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin:10px 0}
.cvs-t{display:flex;flex-direction:column;align-items:flex-start;gap:2px;border:1px solid var(--line);border-radius:10px;padding:8px 10px;background:var(--panel-2);text-align:left;font:inherit;color:var(--ink)}
button.cvs-t{cursor:pointer}button.cvs-t:hover{background:var(--hover)}
.cvs-t b{font-size:var(--fs-lg)}.cvs-t span{font-size:var(--fs-xs);color:var(--muted)}
.cvs-cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:6px 24px}
.cvs-cols h4{margin:8px 0 4px}
.cvs-l{list-style:none;margin:0;padding:0}.cvs-l li{padding:6px 0;border-top:1px solid var(--line-soft)}
.cvs-r{display:flex;flex-direction:column;align-items:flex-start;background:none;border:0;padding:0;font:inherit;color:var(--ink);cursor:pointer;text-align:left}
.cvs-r:hover b{text-decoration:underline}.cvs-r span{font-size:var(--fs-xs);color:var(--muted)}
#tab-cves .lc [data-f]{cursor:pointer}

/* search everything (F2) */
.ps-scrim{position:fixed;inset:0;background:rgba(20,18,16,.38);z-index:65}
.ps-box{position:fixed;top:min(10vh,80px);left:50%;transform:translateX(-50%);width:min(700px,94%);max-height:76vh;display:flex;flex-direction:column;background:var(--panel);border:1px solid var(--line);border-radius:14px;box-shadow:0 18px 60px var(--shadow-lg);z-index:70;overflow:hidden}
.ps-in{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line)}
.ps-in .glyph{color:var(--muted)}
.ps-in input{flex:1;min-width:0;border:0;background:none;font-size:var(--fs-md);outline:0;color:var(--ink);padding:4px 0}
.ps-body{overflow-y:auto;overscroll-behavior:contain;flex:1;padding:4px 0 8px}
.ps-gh{display:flex;justify-content:space-between;padding:10px 16px 4px;font-size:var(--fs-xs);letter-spacing:.07em;text-transform:uppercase;color:var(--muted);font-weight:600}
.ps-r{display:flex;flex-direction:column;justify-content:center;min-height:44px;padding:6px 16px;text-decoration:none;color:var(--ink)}
.ps-r:hover{background:var(--hover)}
.ps-r.on{background:var(--accent-soft);box-shadow:inset 3px 0 0 var(--accent)}
.ps-t{font-size:var(--fs-sm);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.ps-t.m{font-family:var(--mono)}
.ps-s{font-size:var(--fs-xs);color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ps-all{display:block;padding:4px 16px 6px;font-size:var(--fs-xs)}
.ps-empty{padding:14px 16px;font-size:var(--fs-sm);color:var(--ink-2)}.ps-empty .links{margin-top:10px}
.ps-foot{display:flex;justify-content:space-between;gap:4px 14px;flex-wrap:wrap;padding:8px 16px;border-top:1px solid var(--line);font-size:var(--fs-xs);color:var(--muted)}
body.pal-open{overflow:hidden}
.tbl.fresh td.num{text-align:right;font-variant-numeric:tabular-nums}
.tbl.fresh .nw{white-space:nowrap}
.dfacts .rrw{display:block;margin-top:3px;font-size:var(--fs-xs);color:var(--muted)}

/* guide (F30) */
.rmin{text-transform:none;letter-spacing:0;font-weight:400;color:var(--muted);margin-left:6px}
"""

JS = r"""
(function(){
'use strict';
var D = JSON.parse(document.getElementById('data').textContent);
var root = document.documentElement;
function $(id){ return document.getElementById(id); }
function store(k, v){ try{ if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); }catch(_){ return null; } }
function esc(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); }
function b(t, cls){ return '<span class="badge ' + cls + '">' + esc(t) + '</span>'; }
function conf(c, u){ return b(c, 'conf c-' + c) + (u ? b('unverified', 'unv-b') : ''); }
function chips(a, cls){ return (a || []).map(function(x){ return '<span class="chip ' + (cls || '') + '">' + esc(x) + '</span>'; }).join(''); }
function lnk(href, t, cls){ return '<a class="chip link ' + (cls || '') + '" href="' + esc(href) + '">' + esc(t) + '</a>'; }
function lnks(a, cls){ return (a || []).map(function(x){ return x.href ? lnk(x.href, x.label) : '<span class="chip ' + (cls || '') + '">' + esc(x.label) + '</span>'; }).join(''); }
function refs(r){ return r && r.length ? '<h4>References</h4><ul class="refs">' + r.map(function(x){ return '<li><a href="' + esc(x.url) + '" rel="noopener" target="_blank">' + esc(x.title) + '</a></li>'; }).join('') + '</ul>' : ''; }
function sec(title, h){ return h ? '<h4>' + esc(title) + '</h4>' + h : ''; }
/* Prose stays in the sans face. Literal strings inside it - `quoted`, absolute
   paths and file names - are wrapped in <code>, so a sentence never switches
   font as a whole. */
var CODE_RE = /(`[^`]+`|\b(?:disk\d|bootflash|flash|harddisk):[\w.\-\/]*|(?<![\w.\/])\/[\w.\-*{}]+(?:\/[\w.\-*{}]*)*|\b[\w.\-]+\.(?:bin|b64|gz|tar|log|conf|php|py|pth|sh|so|zip|pcap|elg|xml|json|lua|cgi|pl|db|pkg|yar|yml|html|txt|ko|cfg|dat|out|tgz|ucs|qkview|pcapng)\d?\b)/g;
var TOKS = [];   // the current library's filter words, highlighted in rows and cards
function hl(s, toks){
  s = String(s == null ? '' : s);
  if (!toks || !toks.length) return esc(s);
  var re = new RegExp('(' + toks.map(function(t){ return t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }).join('|') + ')', 'gi');
  return s.split(re).map(function(p, i){ return i % 2 ? '<mark>' + esc(p) + '</mark>' : esc(p); }).join('');
}
function rich(t, toks){
  return String(t == null ? '' : t).split(CODE_RE).map(function(part, i){
    if (i % 2 === 0) return hl(part, toks);
    return '<code>' + hl(part.charAt(0) === '`' ? part.slice(1, -1) : part, toks) + '</code>';
  }).join('');
}
function para(t){ return t ? '<p>' + rich(t) + '</p>' : ''; }
function codeblk(t, wrap){ return '<div class="codewrap"><button class="copy" type="button">Copy</button><pre' + (wrap ? ' class="wrap"' : '') + '><code>' + esc(t) + '</code></pre></div>'; }
function att(a){ return (a || []).map(function(t){ var p = t.split('.'); return '<a class="chip mono" href="https://attack.mitre.org/techniques/' + p[0] + '/' + (p[1] ? p[1] + '/' : '') + '" rel="noopener" target="_blank" title="MITRE ATT&CK">' + esc(t) + '</a>'; }).join(''); }
function list(a){ return a && a.length ? '<ul>' + a.map(function(x){ return '<li>' + rich(x) + '</li>'; }).join('') + '</ul>' : ''; }
function hd(id, title, sub, badges){ return '<div class="lc-h"><div class="lc-t"><span class="id">' + esc(id) + '</span><h3>' + hl(title, TOKS) + '</h3>' + (sub ? '<div class="lc-sub">' + sub + '</div>' : '') + '</div><div class="badges">' + (badges || '') + '</div></div>'; }
var IMP = {'none':'imp-none','vendor-bundle':'imp-bundle','break-glass':'imp-bg'};
var TYPEN = {log_regex:'log pattern', check:'coded check', yara:'YARA', path_exists:'path exists'};
function runsStrip(x){
  return '<div class="runs"><span class="rk">Runs in</span>' + [['Analyzer', true], ['SIEM', x.sigma.length > 0], ['YARA', x.type === 'yara']].map(function(r){
    return '<span class="' + (r[1] ? 'y' : 'n') + '"><i></i>' + r[0] + '<span class="sr">' + (r[1] ? ': yes' : ': no') + '</span></span>'; }).join('') + '</div>';
}
var DREC = null;   // the record being drawn: its file's last-changed date joins the quick facts
function facts(rows){ rows = rows.filter(Boolean);
  if (DREC && DREC.changed) rows.push(['Last changed', esc(DREC.changed) + (DREC.reread && DREC.reread.length ?
    ' ' + b('may need a re-read', 'unv-b') + '<span class="rrw">before ' + esc(DREC.reread[1]) + '</span>' : '')]);
  return '<dl class="dfacts">' + rows.map(function(r){ return '<div><dt>' + esc(r[0]) + '</dt><dd>' + r[1] + '</dd></div>'; }).join('') + '</dl>'; }
function connects(cols, hunts){   // hunts: this box is where the intel drawer's Hunts jump lands
  var hid = hunts ? ' id="dj-hunt"' : '';
  cols = cols.filter(function(c){ return c[1] && c[1].filter(Boolean).length; });
  if (!cols.length) return hid ? '<div' + hid + '></div>' : '';
  return '<section class="dconn"' + hid + '><h4>How it connects</h4><div class="dcg">' + cols.map(function(c){
    return '<div><span class="dck">' + esc(c[0]) + '</span><div class="links">' + c[1].filter(Boolean).join('') + '</div></div>'; }).join('') + '</div></section>';
}
var SHELL = {yes:'shell: yes', restricted:'shell: restricted', no:'shell: none'};
var PN = {}, PLAT = {}; D.platforms.forEach(function(p){ PN[p.id] = p.short; PLAT[p.id] = p; });
var PACK = {}; D.packs.forEach(function(p){ PACK[p.id] = p; });
var INTEL = {}; D.intel.forEach(function(i){ INTEL[i.id] = i; });
var ABBR = D.abbr;   // short platform names, from PLATFORM_ABBR in the generator
var PORDER = ['ALL'].concat(D.platforms.map(function(p){ return p.id; }));   // platform facets keep catalog order
function pab(v){ return v === 'ALL' ? 'Every platform' : (ABBR[v] || PN[v] || v); }
function pfull(v){ return PLAT[v] ? PLAT[v].name : v; }
var IOC = {}; D.iocs.forEach(function(s){ IOC[s.id] = s; });
var ROLE = {'actor-controlled':'actor-controlled', 'compromised-infrastructure':'compromised third party', anonymiser:'VPN / anonymiser',
  'multi-tenant':'shared infrastructure', suspected:'suspected', unknown:'role not stated'};
function defang(t, v){
  if (t === 'ipv4' || t === 'domain') return v.replace(/\./g, '[.]');
  if (t === 'ipv6') return v.replace(/:/g, '[:]');
  if (t === 'url') return v.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
  return v;
}
function iocCsv(sets){
  var rows = [['set', 'publisher', 'published', 'type', 'value', 'role', 'context', 'source']];
  sets.forEach(function(s){ s.ind.forEach(function(i){ rows.push([s.id, s.publisher, s.published, i[0], i[1], i[2], i[3], s.page_url]); }); });
  return rows.map(function(r){ return r.map(csvq).join(','); }).join('\n');
}
function uuid4(){ if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c){ var r = Math.random() * 16 | 0; return (c === 'x' ? r : (r & 3 | 8)).toString(16); }); }
function stixPattern(t, v){
  var q = "'" + v.replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "'";
  switch (t){
    case 'ipv4': return '[ipv4-addr:value = ' + q + ']';
    case 'ipv6': return '[ipv6-addr:value = ' + q + ']';
    case 'domain': return '[domain-name:value = ' + q + ']';
    case 'url': return '[url:value = ' + q + ']';
    case 'sha256': return "[file:hashes.'SHA-256' = " + q + ']';
    case 'sha1': return "[file:hashes.'SHA-1' = " + q + ']';
    case 'md5': return "[file:hashes.MD5 = " + q + ']';
    case 'path': return '[file:name = ' + "'" + v.split('/').pop().replace(/'/g, "\\'") + "'" + ']';
    case 'account': return '[user-account:account_login = ' + q + ']';
    case 'user-agent': return "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = " + q + ']';
  }
  return null;
}
function iocStix(sets){
  var now = new Date().toISOString(), ident = 'identity--' + uuid4(), objs = [{type:'identity', spec_version:'2.1', id:ident, created:now, modified:now,
    name:'edge-dfir-toolkit export', identity_class:'system', description:'Re-export of publisher indicators; the publisher, role and context are in each indicator.'}];
  var IT = {'actor-controlled':'malicious-activity', 'compromised-infrastructure':'compromised', anonymiser:'anonymization', 'multi-tenant':'anomalous-activity', suspected:'unknown', unknown:'unknown'};
  sets.forEach(function(s){ s.ind.forEach(function(i){
    var pat = stixPattern(i[0], i[1]); if (!pat) return;
    objs.push({type:'indicator', spec_version:'2.1', id:'indicator--' + uuid4(), created:now, modified:now, created_by_ref:ident,
      name:i[0] + ' from ' + s.publisher, description:i[3] + (i[0] === 'path' ? ' (full path: ' + i[1] + ')' : '') + ' Role per publisher: ' + (ROLE[i[2]] || i[2]) + '. ' + s.staleness,
      indicator_types:[IT[i[2]] || 'unknown'], pattern:pat, pattern_type:'stix', valid_from:s.published + 'T00:00:00Z',
      external_references:[{source_name:s.publisher, url:s.page_url, description:s.title}]});
  }); });
  return JSON.stringify({type:'bundle', id:'bundle--' + uuid4(), objects:objs}, null, 2);
}
function ymd(v){ var m = /^(\d{4})(?:-(\d{2}))?(?:-(\d{2}))?/.exec(v || ''); return m ? +m[1] + ((+(m[2] || 1)) - 1) / 12 + ((+(m[3] || 1)) - 1) / 365 : null; }
function intelCharts(){
  var actors = D.intel.filter(function(i){ return i.kind === 'actor'; });
  /* 1. timeline: one row per actor; every indicator set shares the last lane */
  var now = ymd(D.built), lo = now;
  actors.forEach(function(a){ var f = ymd(a.first_seen); if (f) lo = Math.min(lo, f); });
  D.iocs.forEach(function(s){ lo = Math.min(lo, ymd(s.published)); });
  lo = Math.floor(lo); var hi = Math.floor(now) + 1, span = hi - lo;
  function x(t){ return ((t - lo) / span * 100).toFixed(2) + '%'; }
  var ticks = ''; for (var y = lo; y <= hi; y++) ticks += '<span class="tlt" style="left:' + x(y) + '">' + y + '</span>';
  var nowL = '<span class="tlnow" style="left:' + x(now) + '"></span>';
  var rows = actors.map(function(a){
    var pts = a.iocs.map(function(id){ return {t:ymd(IOC[id].published), l:IOC[id].publisher + ', ' + IOC[id].published}; }), f = ymd(a.first_seen);
    var ts = pts.map(function(p){ return p.t; }).concat(f ? [f] : []), mn = Math.min.apply(null, ts), mx = Math.max.apply(null, ts), nr = a.reported_by.length;
    var alt = a.name + ': ' + (f ? 'first seen ' + a.first_seen + '; ' : '') + (pts.length ? 'indicators published ' + pts.map(function(p){ return p.l; }).join('; ') : 'no indicator set') + '; ' + (nr === 1 ? '1 reporter' : nr + ' reporters');
    return '<div class="tlr"><a href="#intel/' + a.id + '">' + esc(a.name) + '</a><div class="tlk" role="img" aria-label="' + esc(alt) + '">' + nowL +
      (mx > mn ? '<span class="tlb" style="left:' + x(mn) + ';width:' + ((mx - mn) / span * 100).toFixed(2) + '%"></span>' : '') +
      (f ? '<span class="tld first" style="left:' + x(f) + '" title="First seen: ' + esc(a.first_seen) + '"></span>' : '') +
      pts.map(function(p){ return '<span class="tld" style="left:' + x(p.t) + '" title="Indicators published: ' + esc(p.l) + '"></span>'; }).join('') +
      '</div><span class="tlrep">' + (nr === 1 ? '1 reporter' : nr + ' reporters') + '</span></div>';
  }).join('');
  var lane = '<div class="tlr lane"><span>Every indicator set</span><div class="tlk" role="img" aria-label="' + esc(D.iocs.length + ' indicator sets, published ' +
    D.iocs.map(function(s){ return s.published; }).sort()[0] + ' to ' + D.iocs.map(function(s){ return s.published; }).sort().pop() + '; ' +
    D.iocs.filter(function(s){ return !s.actors.length; }).length + ' have no actor record') + '">' + nowL + D.iocs.map(function(s, i){
    return '<span class="tlq' + (s.actors.length ? '' : ' un') + '" style="left:' + x(ymd(s.published)) + ';top:' + (3 + (i % 3) * 8) + 'px" title="' +
      esc(s.publisher + ', ' + s.published + ': ' + s.title) + '"></span>'; }).join('') + '</div><span class="tlrep">grey: no actor record</span></div>';
  var tl = '<div class="tl"><div class="tlr tlh"><span></span><div class="tlk">' + ticks + '</div><span class="tlrep">reported by</span></div>' + rows + lane + '</div>' +
    '<p class="muted small"><span class="tld first inl"></span> first seen, as the actor record states it &#183; <span class="tld inl"></span> indicators published &#183; ' +
    'dashed line: the build date, ' + esc(D.built) + '. Actors get the rows; indicator sets share the last lane. Hover a mark for the publisher and date.</p>';
  /* 2. attribution: who touched which platform, and how many reporters stand behind each actor */
  var single = actors.filter(function(a){ return a.reported_by.length === 1; }).length;
  var plats = D.platforms.map(function(p){ return p.id; });
  var mx = '<div class="scroll"><table class="amx"><thead><tr><th></th>' + plats.map(function(p){ return '<th><a href="#platforms/' + p + '" title="' + esc(PN[p]) + '">' + esc(ABBR[p] || PLAT[p].short) + '</a></th>'; }).join('') + '</tr></thead><tbody>' +
    actors.map(function(a){ return '<tr><th><a href="#intel/' + a.id + '">' + esc(a.name) + '</a></th>' + plats.map(function(p){
      var on = a.platforms.indexOf(p) >= 0, n = a.implants.filter(function(z){ return INTEL[z] && INTEL[z].platforms.indexOf(p) >= 0; }).length;
      return '<td>' + (on ? '<span class="amd" title="' + esc(a.name + ' on ' + PN[p] + (n ? ': ' + n + ' implant record(s)' : '')) + '">' + (n || '') + '</span>' : '') + '</td>'; }).join('') + '</tr>'; }).join('') +
    '</tbody></table></div>';
  var attr = '<h4>Actors by platform</h4><div class="attr2">' + mx + '<p>' + single + ' of ' + actors.length + ' actors rest on a single reporting party, so our link ' +
    'confidence stays at medium however authoritative the reporter. A dot is a platform the actor record names; the number is implant records on it.</p></div>';
  /* 3. what published indicators are, by the publisher's own label */
  var rc = {}, tot = 0; D.iocs.forEach(function(s){ s.ind.forEach(function(i){ if (i[0] === 'ipv4' || i[0] === 'ipv6' || i[0] === 'domain'){ rc[i[2]] = (rc[i[2]] || 0) + 1; tot++; } }); });
  var own = rc['actor-controlled'] || 0, keys = Object.keys(ROLE).filter(function(k){ return rc[k]; });
  var ioc = '<h4>Published addresses and domains, by the publisher\'s own label</h4>' +
    '<div class="rolefig"><b class="big">' + own + '<span> of ' + tot + '</span></b><p>published addresses and domains are labelled actor-controlled by their own publisher. ' +
    'Block the rest with care and never attribute on them alone.</p></div>' +
    '<div class="rbar16" role="img" aria-label="' + esc(keys.map(function(k){ return rc[k] + ' ' + ROLE[k]; }).join(', ')) + '">' +
    keys.map(function(k){ return '<span class="rr rr-' + k + '" style="flex:' + rc[k] + '" title="' + esc(rc[k] + ' ' + ROLE[k]) + '"></span>'; }).join('') + '</div>' +
    '<ul class="rolel">' + keys.map(function(k){ return '<li><i class="sw rr-' + k + '"></i><b>' + rc[k] + '</b> ' + esc(ROLE[k]) + '<span class="pct">' + Math.round(100 * rc[k] / tot) + '%</span></li>'; }).join('') + '</ul>' +
    '<p class="muted small"><button type="button" class="chip btnchip" data-ioc="all" data-fmt="csv">All indicators, CSV</button> <button type="button" class="chip btnchip" data-ioc="all" data-fmt="stix">All indicators, STIX 2.1</button></p>';
  return '<details class="charts"' + (window.innerWidth > 760 ? ' open' : '') + '><summary>Timeline, attribution and indicators</summary><div class="chg">' +
    '<section class="chp wide"><h4>Reporting timeline</h4>' + tl + '</section>' +
    '<section class="chp wide">' + attr + '</section>' +
    '<section class="chp wide">' + ioc + '</section></div></details>';
}
function iocChip(i){ var n = i.iocs.reduce(function(t, x){ return t + IOC[x].ind.length; }, 0);
  return n ? '<span class="chip ioc-c" title="Indicators from the publishers\' own files">' + n + (n === 1 ? ' indicator' : ' indicators') + '</span>' : ''; }
document.addEventListener('click', function(ev){
  var a = ev.target.closest('[data-dj]'); if (!a) return; ev.preventDefault();
  var t = document.getElementById(a.dataset.dj); if (t) scrollBody(t);
});
function iocBlock(ids){
  return ids.map(function(id){
    var s = IOC[id], rc = {}; s.ind.forEach(function(i){ rc[i[2]] = (rc[i[2]] || 0) + 1; });
    var head = '<div class="iocset"><div class="ioch"><b>' + esc(s.publisher) + '</b> <span class="muted">' + esc(s.published) + ' · ' + s.ind.length + ' indicators · ' + esc(s.license) + '</span>' +
      '<div class="links" style="margin:6px 0 0"><a class="chip link" href="' + esc(s.page_url) + '" rel="noopener" target="_blank">Publication</a>' +
      (s.file_url ? '<a class="chip link" href="' + esc(s.file_url) + '" rel="noopener" target="_blank">Publisher\'s file</a>' : '') +
      '<button type="button" class="chip btnchip" data-ioc="' + id + '" data-fmt="csv">CSV</button><button type="button" class="chip btnchip" data-ioc="' + id + '" data-fmt="stix">STIX 2.1</button>' +
      '<button type="button" class="chip btnchip copy" data-copy="' + esc(s.ind.map(function(i){ return i[1]; }).join('\n')) + '">Copy values</button></div></div>';
    var roles = '<div class="links">' + Object.keys(ROLE).filter(function(k){ return rc[k]; }).map(function(k){ return '<span class="chip role role-' + k + '">' + rc[k] + ' ' + esc(ROLE[k]) + '</span>'; }).join('') + '</div>';
    var tbl = '<details class="iocd" open><summary>' + s.ind.length + ' values (defanged) - click to collapse</summary><div class="scroll iocs"><table class="ioct"><tbody>' +
      s.ind.map(function(i){ return '<tr><td class="muted">' + esc(i[0]) + '</td><td><code>' + esc(defang(i[0], i[1])) + '</code></td><td><span class="chip role role-' + i[2] + '">' + esc(ROLE[i[2]] || i[2]) + '</span></td><td class="small">' + esc(i[3]) + '</td></tr>'; }).join('') +
      '</tbody></table></div></details>';
    return head + '<div class="callout inf"><b>Staleness.</b> ' + rich(s.staleness) + '</div>' + roles + tbl + '</div>';
  }).join('');
}
document.addEventListener('click', function(ev){
  var b = ev.target.closest('[data-ioc]'); if (!b) return;
  var sets = b.dataset.ioc === 'all' ? D.iocs : [IOC[b.dataset.ioc]], stamp = new Date().toISOString().slice(0, 10), base = 'edge-dfir-iocs-' + (b.dataset.ioc === 'all' ? 'all' : b.dataset.ioc) + '-' + stamp;
  if (b.dataset.fmt === 'stix') download(base + '.stix.json', 'application/json', iocStix(sets));
  else download(base + '.csv', 'text/csv', iocCsv(sets));
  toast('Exported ' + sets.reduce(function(n, s){ return n + s.ind.length; }, 0) + ' indicators');
});
var RULE = {}; D.rules.forEach(function(r){ RULE[r.id] = r; });
var RUNS = {analyzer:'Analyzer, on collected evidence', siem:'Your SIEM (Sigma rule)', yara:'File scan (YARA rule)'};
function ruleBlock(r){
  return '<div class="stepbox rule"><div class="links" style="margin:0">' + b(r.format, 'fmt fmt-' + r.format.toLowerCase()) + (r.level !== '-' ? b(r.level, 'lvl lvl-' + r.level) : '') +
    '<b>' + esc(r.title) + '</b></div><p class="muted small">' + rich(r.description) + '</p>' +
    '<div class="links"><span class="chip code">' + esc(r.file) + '</span>' + att(r.attack) + '</div>' +
    (r.format === 'Sigma' ? '<p class="muted small">Convert with <code>sigma convert -t &lt;backend&gt; ' + esc(r.file) + '</code>.</p>' : '') +
    '<details><summary>Rule source</summary>' + codeblk(r.body) + '</details>' +
    '<div class="links"><a class="chip link" href="' + esc(r.url) + '" rel="noopener" target="_blank">View in the repository</a></div></div>';
}
function platLinks(ids){ return (ids || []).map(function(x){ return lnk('#platforms/' + x, PN[x] || x); }).join(''); }

/* ---------------------------------------------------------------- theme */
function isDark(){ var t = root.getAttribute('data-theme'); return t ? t === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches; }
function themeLabel(){ $('themeBtn').textContent = isDark() ? '☀ Light' : '☾ Dark'; }
// Light by default whatever the OS prefers; dark only when the viewer picked it.
var th = store('edt-theme'); root.setAttribute('data-theme', th === 'dark' ? 'dark' : 'light'); themeLabel();
$('themeBtn').addEventListener('click', function(){ var n = isDark() ? 'light' : 'dark'; root.setAttribute('data-theme', n); store('edt-theme', n); themeLabel(); });
function hdrH(){ root.style.setProperty('--hdr', document.querySelector('.hdr').offsetHeight + 'px'); }

window.addEventListener('resize', hdrH); hdrH();
var toastT; function toast(m){ var t = $('toast'); t.textContent = m; t.hidden = false; clearTimeout(toastT); toastT = setTimeout(function(){ t.hidden = true; }, 1800); }

/* ---------------------------------------------------------------- libraries */
function F(k, label, get, name, order, tip){ return {k:k, label:label, get:get, name:name || function(v){ return v; }, order:order, tip:tip}; }
var ORD = {vol:['live','rotating','stable','off-box'], hml:['high','medium','low'], tier:['confirmed','likely','possible'],
           level:['critical','high','medium','low','informational','-'], yn:['yes','partial','no','unknown']};
var KIND = {step:'Collection step', ingest:'Off-box export (ingest)', manual:'Manual'};
var HDATA = {netflow:'NetFlow', syslog:'Forwarded syslog / SIEM', 'aaa-accounting':'AAA command accounting', identity:'Identity and VPN logons',
  'web-proxy':'WAF or proxy in front', 'config-archive':'Configuration archive', edr:'EDR on adjacent hosts', dns:'DNS logs', scan:'Port scans of the device'};
var HSHORT = {netflow:'NetFlow', syslog:'SIEM', 'aaa-accounting':'AAA', identity:'Identity', 'web-proxy':'WAF/proxy', 'config-archive':'Configs', edr:'EDR', dns:'DNS', scan:'Scans'};
var ACTN = {}; D.hunts.forEach(function(h){ Object.keys(h.actor_names).forEach(function(k){ ACTN[k] = h.actor_names[k]; }); });
var BASIS = {vendor:'Vendor', researcher:'Researcher', government:'Government agency', toolkit:'Toolkit inference (no published contrast)'};
var HCAT = {exposure:'Internet exposure', access:'Management access', identity:'Accounts and MFA', services:'Unused services', logging:'Logging off-box', patching:'Patching and end of life', integrity:'Integrity and boot', recovery:'Backups and recovery'};

var LIB = {
artifacts: {
  noun:'artifacts', items:D.artifacts, view:'rows',
  head:['', 'Platform', 'Artifact and what it proves', 'Class', 'Volatility', 'Value', 'Confidence'],
  facets:[
    F('platform', 'Platform', function(a){ return [a.platform]; }, pab, PORDER, pfull),
    F('class', 'Artifact class', function(a){ return [a['class']]; }),
    F('volatility', 'Volatility', function(a){ return [a.volatility]; }, null, ORD.vol),
    F('value', 'Forensic value', function(a){ return [a.value]; }, null, ORD.hml),
    F('evidence', 'Evidence type', function(a){ return a.evidence; }),
    F('kind', 'Collected by', function(a){ return [a.kind]; }, function(v){ return KIND[v] || v; }),
    F('confidence', 'Confidence', function(a){ return [a.confidence]; }, null, ORD.hml),
    F('basis', 'Suspicious criterion from', function(a){ return a.basis ? [a.basis] : []; }, function(v){ return BASIS[v] || v; }),
    F('seen', 'Seen in', function(a){ return a.seen_in; })
  ],
  text:function(a){ return [a.id, PN[a.platform], a.locator, a.description, a['class'], a.volatility, a.collected_by, a.retention, a.seen_in.join(' '), a.evidence.join(' '), a.provides, a.normal, a.suspicious].join(' '); },
  row:function(a){
    return '<span class="c-pick"><input type="checkbox" class="pick" aria-label="Pick ' + esc(a.id) + '"' + (S.artifacts.picks[a.id] ? ' checked' : '') + '></span>' +
      '<span class="c-plat">' + esc(PN[a.platform]) + '<span class="id">' + esc(a.id) + '</span></span>' +
      '<span class="c-main"><span class="pl-line">' + esc(PN[a.platform]) + ' &#183; ' + esc(a.id) + '</span>' +
      '<a class="locl" href="#artifacts/' + encodeURIComponent(a.id) + '"><code class="loc">' + hl(a.locator, TOKS) + '</code></a><span class="desc">' + rich(a.description, TOKS) + '</span>' +
      (a.suspicious ? '<span class="lead"><b>Lead:</b> ' + rich(a.suspicious, TOKS) + '</span>' : '') +
      (a.seen_in.length ? '<span class="seen">' + chips(a.seen_in, 'implant') + '</span>' : '') + '</span>' +
      '<span class="c-cls">' + b(a['class'], 'cls') + '</span><span class="c-vol">' + b(a.volatility, 'vol vol-' + a.volatility) + '</span>' +
      '<span class="c-val">' + b(a.value, 'fv fv-' + a.value) + '</span><span class="c-conf">' + conf(a.confidence, a.unv) + '</span>';
  },
  title:function(a){ return PN[a.platform] + ' artifact'; },
  drawer:function(a){
    var p = PLAT[a.platform];
    var h = facts([['Class', b(a['class'], 'cls')], ['Volatility', b(a.volatility, 'vol vol-' + a.volatility)], ['Forensic value', b(a.value, 'fv fv-' + a.value)],
      ['Confidence', conf(a.confidence, a.unv)], ['Retention', esc(a.retention || 'not stated')],
      ['Collected by', esc((KIND[a.kind] || a.kind) + (a.kind === 'step' ? ': ' + a.collected_by : ''))]]);
    h += '<div class="dloc"><code>' + esc(a.locator) + '</code><button class="copy" type="button" data-copy="' + esc(a.locator) + '">Copy</button></div>';
    if (a.provides) h += sec('What it gives you', para(a.provides));
    h += sec('What it proves', para(a.description));
    if (a.suspicious) h += sec('Normal or suspicious', '<div class="nvs"><div class="nvs-n"><b>Normal</b>' + para(a.normal) + '</div>' +
      '<div class="nvs-s"><b>Suspicious</b>' + para(a.suspicious) + '</div></div>' +
      '<p class="muted small">Criterion from: ' + esc(BASIS[a.basis] || a.basis) + '. A lead is a reason to look harder, not a verdict; the analyzer\'s detections decide tiers.</p>');
    var c;
    if (a.kind === 'step'){
      var s = a.step;
      c = '<div class="stepbox"><div class="links" style="margin:0"><span class="tchip">' + esc(s.tier) + '</span><b class="mono">' + esc(a.collected_by) + '</b>' + b(s.impact, IMP[s.impact]) + conf(s.confidence, s.unverified) + '</div>' +
        (s.cmd ? codeblk(s.cmd) : (s.instructions ? codeblk(s.instructions, true) : '')) + '<p class="muted small">' + rich(s.purpose) + '</p>' +
        '<div class="links">' + lnk('#plans/' + p.profile, 'Open the ' + p.profile + ' collection plan') + '</div></div>';
    } else if (a.kind === 'ingest'){
      c = '<p>Not on the device, or not reachable from its CLI. Export it from where it lives - the syslog receiver, the SIEM, the management server - and add it to the case:</p>' + codeblk('edge-triage ingest <case> --label <name> --bundle <file>');
    } else c = '<p>Collected by hand. The platform entry lists the procedure and its impact.</p>';
    h += sec('How it is collected', c);
    h += sec('Evidence type', '<div class="links">' + chips(a.evidence, 'mono') + '</div>');
    h += connects([
      ['Collected by', a.kind === 'step' && p.profile ? [lnk('#plans/' + p.profile, p.profile + ' · ' + a.collected_by, 'mono')] : []],
      ['Read by detections', a.detections.map(function(id){ return lnk('#detections/' + id, id, 'mono'); })],
      ['Seen in', a.seen.length ? [lnks(a.seen, 'implant')] : []],
      ['Platform', [lnk('#platforms/' + p.id, p.short), lnk('#artifacts?platform=' + p.id, 'All ' + p.n_art + ' artifacts'),
                    p.response ? lnk('#response/' + p.response, 'Containment and recovery') : '']]]);
    return h;
  },
  exp:function(a){ return {id:a.id, platform:PN[a.platform], locator:a.locator, 'class':a['class'], volatility:a.volatility, retention:a.retention,
    value:a.value, evidence:a.evidence, confidence:a.confidence, unverified:a.unv, collected_by:a.collected_by,
    command:a.step ? a.step.cmd : '', seen_in:a.seen_in, description:a.description,
    provides:a.provides, normal:a.normal, suspicious:a.suspicious, basis:a.basis}; },
  summary:function(shown){ return dist('artifacts', 'volatility', ORD.vol, 'Volatility of the artifacts shown', shown); }
},

platforms: {
  noun:'platforms', items:D.platforms, view:'cards',
  facets:[
    F('vendor', 'Vendor', function(p){ return [p.vendor]; }),
    F('shell', 'Customer shell', function(p){ return [p.shell]; }, function(v){ return SHELL[v] || v; }),
    F('memory', 'Memory acquisition', function(p){ return [p.memory]; }),
    F('profile', 'Collection profile', function(p){ return [p.profile ? 'yes' : 'no']; }, function(v){ return v === 'yes' ? 'has a profile' : 'no profile yet'; })
  ],
  text:function(p){ return [p.id, p.name, p.vendor, p.os_base, p.products.join(' '), p.filesystem].join(' '); },
  card:function(p){
    return hd(p.id, p.short, esc(p.vendor), b(SHELL[p.shell], 'sh-' + p.shell) + conf(p.confidence, p.unv)) +
      '<p class="clamp">' + hl(p.os_base, TOKS) + '</p>' +
      '<div class="stats"><span><b>' + p.n_art + '</b>artifacts</span><span><b>' + p.n_steps + '</b>steps</span><span><b>' + p.n_det + '</b>detections</span><span><b>' + p.cves.length + '</b>CVEs</span></div>' +
      '<div class="lc-f">' + b('memory: ' + p.memory, 'mem') + (p.profile ? '<span class="chip code">' + esc(p.profile) + '</span>' : '<span class="chip ghost">no profile yet</span>') + '</div>';
  },
  title:function(p){ return p.name; },
  drawer:function(p){
    var h = facts([['Vendor', esc(p.vendor)], ['Customer shell', b(SHELL[p.shell], 'sh-' + p.shell)], ['Memory acquisition', b(p.memory, 'mem')],
      ['Confidence', conf(p.confidence, p.unv)], ['Artifacts', esc(String(p.n_art))], ['Detections', esc(String(p.n_det))],
      ['CVEs', esc(p.cves.length + (p.n_cve_flag ? ', ' + p.n_cve_flag + ' flagged for BOD 26-04 triage' : ''))]]);
    h += sec('Base', para(p.os_base));
    h += '<div class="links">' + lnk('#artifacts?platform=' + p.id, p.n_art + ' artifacts') +
      (p.profile ? lnk('#plans/' + p.profile, 'Collection plan: ' + p.profile + ' (' + p.n_steps + ' steps)') : '<span class="chip ghost">no profile yet</span>') +
      (p.n_det ? lnk('#detections?platform=' + p.id, p.n_det + ' detections') : '') +
      (p.cves.length ? lnk('#cves?platform=' + p.id, p.cves.length + ' CVEs') : '') +
      (p.response ? lnk('#response/' + p.response, 'Containment and recovery') : '') +
      (p.n_hard ? lnk('#hardening?platform=' + p.id, p.n_hard + ' hardening controls') : '') + '</div>';
    if (p.products.length) h += sec('Products', '<div class="links">' + chips(p.products) + '</div>');
    if (p.filesystem) h += sec('Filesystem', para(p.filesystem));
    h += sec('Collection paths', '<ul class="plain">' + p.collection.map(function(x){ return '<li><div class="row2">' + b(x.impact, IMP[x.impact]) + '<b>' + esc(x.method) + '</b>' + conf(x.confidence, x.unverified) + '</div><div class="muted small">' + rich(x.description) + '</div></li>'; }).join('') + '</ul>');
    if (p.volatility.length) h += sec('Lost on reboot or upgrade', list(p.volatility));
    if (p.anti_forensics.length) h += sec('Anti-forensics seen in public reporting', '<ul class="plain">' + p.anti_forensics.map(function(a){ return '<li><b>' + esc(a.technique) + '</b> <span class="muted">- ' + esc(a.seen_in) + '</span>' + (a.detail ? '<div class="muted small">' + rich(a.detail) + '</div>' : '') + '</li>'; }).join('') + '</ul>');
    if (p.cves.length) h += sec('CVEs', '<div class="links">' + p.cves.map(function(id){ var c = CVEIX[id];
      return lnk('#cves/' + id, id + (c.triage_k === 'yes' ? ' · forensic triage' : '') + (c.ransomware === 'Known' ? ' · ransomware' : '')); }).join('') + '</div>' +
      '<p class="small muted">Newest first. ' + lnk('#cves?platform=' + p.id, 'Open them as a filtered list') + '</p>');
    if (p.packs.length) h += sec('Detection packs', '<div class="links">' + p.packs.map(function(x){ return lnk('#detections?pack=' + x, x + ' - ' + PACK[x].name); }).join('') + '</div>');
    if (p.notes) h += '<p class="note">' + rich(p.notes) + '</p>';
    return h + refs(p.references);
  },
  exp:function(p){ return {id:p.id, name:p.name, vendor:p.vendor, os_base:p.os_base, shell:p.shell, memory:p.memory, profile:p.profile,
    artifacts:p.n_art, steps:p.n_steps, detections:p.n_det, confidence:p.confidence, unverified:p.unv}; }
},

detections: {
  noun:'detections', items:D.detections, view:'cards',
  facets:[
    F('platform', 'Platform', function(x){ return x.platforms; }, pab, PORDER, pfull),
    F('runs', 'Runs in', function(x){ return x.runs; }, function(v){ return RUNS[v] || v; }, ['analyzer','siem','yara']),
    F('tier', 'Tier', function(x){ return [x.tier]; }, null, ORD.tier),
    F('evidence', 'Evidence class', function(x){ return [x.evidence]; }),
    F('type', 'Type', function(x){ return [x.type]; }, function(v){ return TYPEN[v] || v; }),
    F('pack', 'Pack', function(x){ return [x.pack]; }, function(v){ return v.replace('EDGE-PACK-', '') + ' · ' + (PACK[v] ? PACK[v].name : ''); }),
    F('cve', 'CVE', function(x){ return x.cves; }),
    F('actor', 'Actor', function(x){ return x.actors; }),
    F('attack', 'ATT&CK', function(x){ return x.attack; })
  ],
  text:function(x){ return [x.id, x.title, x.pack, x.pack_name, x.notes, x.pattern, x.check, x.rule, x.evidence, x.cves.join(' '), x.attack.join(' '), x.actors.join(' '),
    x.sigma.map(function(r){ return RULE[r] ? RULE[r].file + ' ' + RULE[r].title : r; }).join(' ')].join(' '); },
  card:function(x){
    return hd(x.id, x.title, esc(x.pack + ' · ' + x.pack_name), b(x.tier, 'tier t-' + x.tier)) +
      (x.notes ? '<p class="clamp">' + rich(x.notes, TOKS) + '</p>' : '') + runsStrip(x) +
      '<div class="lc-f">' + '<span class="chip">' + esc(x.evidence) + '</span><span class="chip mono">' + esc(x.type === 'check' ? 'check:' + x.check : (TYPEN[x.type] || x.type)) + '</span>' +
      chips(x.attack.slice(0, 2), 'mono') +
      (x.unv ? b('unverified', 'unv-b') : '') + '</div>';
  },
  title:function(x){ return x.title; },
  drawer:function(x){
    var p = PACK[x.pack];
    var h = facts([['Tier', b(x.tier, 'tier t-' + x.tier)], ['Evidence class', esc(x.evidence)], ['Type', esc(TYPEN[x.type] || x.type)],
      ['Pack confidence', conf(p.confidence, p.unv)],
      ['Runs in', esc(x.runs.map(function(r){ return {analyzer:'analyzer', siem:'SIEM', yara:'YARA'}[r] || r; }).join(' · '))],
      ['Platforms', esc(x.platforms.map(function(q){ return ABBR[q] || q; }).join(', '))]]);
    if (x.notes) h += sec('What it means', para(x.notes));
    if (x.type === 'log_regex'){
      h += sec('Pattern' + (x.flags.length ? ' (' + x.flags.join(', ') + ')' : ''), codeblk(x.pattern, true));
      if (x.exclude.length) h += sec('Excluded when the line also matches', x.exclude.map(function(q){ return codeblk(q, true); }).join(''));
    } else if (x.type === 'check'){
      h += sec('Coded check: ' + x.check, x.check_doc ? '<pre class="wrap">' + esc(x.check_doc) + '</pre>' : '');
    } else if (x.type === 'yara' && RULE[x.rule_id]){
      h += sec('YARA rule - scans recovered files', ruleBlock(RULE[x.rule_id]));
    }
    if (x.sigma.length) h += sec(x.sigma.length > 1 ? 'Sigma rules for your SIEM' : 'Sigma rule for your SIEM', x.sigma.map(function(r){ return RULE[r] ? ruleBlock(RULE[r]) : ''; }).join(''));
    else if (x.evidence === 'web-logs' || x.evidence === 'auth-logs' || x.evidence === 'system-logs')
      h += sec('SIEM rule', '<p class="muted small">None yet. The pattern above can be watched in forwarded logs; a Sigma rule is welcome.</p>');
    if (x.files.length) h += sec('Reads these files', '<div class="links">' + chips(x.files, 'code') + '</div>');
    if (x.attack.length) h += sec('ATT&CK', '<div class="links">' + att(x.attack) + '</div>');
    h += connects([
      ['Reads steps', x.steps.map(function(s){ return s.profile ? lnk('#plans/' + s.profile, s.profile + ' · ' + s.id, 'mono') : '<span class="chip mono">' + esc(s.id) + '</span>'; })],
      ['CVEs', x.cves.map(function(c){ return lnk('#cves/' + c, c); })],
      ['Actors and implants', x.actor_links.length || x.implant_links.length ? [lnks(x.actor_links, 'actor') + lnks(x.implant_links, 'implant')] : []],
      ['Pack', [lnk('#detections?pack=' + p.id, p.id + ' · ' + p.name)]]]);
    h += sec('About pack ' + p.id, para(p.summary) + '<div class="links">' + platLinks(p.platforms) + lnk('#detections?pack=' + p.id, 'All ' + p.n + ' detections in this pack') + '</div>');
    return h + refs(p.references);
  },
  exp:function(x){ return {id:x.id, title:x.title, pack:x.pack, platforms:x.platforms.map(function(p){ return PN[p]; }), tier:x.tier, evidence_class:x.evidence,
    type:x.type, check:x.check, rule:x.rule, pattern:x.pattern, sigma_rules:x.sigma.map(function(r){ return RULE[r] ? RULE[r].file : r; }), cves:x.cves, attack:x.attack, notes:x.notes}; },
  summary:function(shown){
    var n = shown.filter(function(x){ return x.sigma.length; }).length, ny = shown.filter(function(x){ return x.type === 'yara'; }).length, st = S.detections.sel.runs || [];
    return dist('detections', 'tier', ORD.tier, 'Tiers of the detections shown', shown) +
      '<p class="muted small sumline">' + n + ' of ' + shown.length + ' shown carry a Sigma rule for your SIEM; ' + ny + (ny === 1 ? ' is a YARA file scan. ' : ' are YARA file scans. ') +
      '<button type="button" class="lnkbtn" data-f="runs" data-v="siem">' + (st.indexOf('siem') >= 0 ? 'Show all' : 'Show only those') + '</button></p>';
  }
},

intel: {
  noun:'actors and implants', items:D.intel, view:'cards',
  facets:[
    F('kind', 'Kind', function(i){ return [i.kind]; }, function(v){ return v === 'actor' ? 'Actors' : 'Implants'; }),
    F('coverage', 'Detection coverage', function(i){ return i.kind === 'implant' ? [i.coverage] : []; }, function(v){ return v === 'gap' ? 'coverage gap' : 'has detections'; }),
    F('reboot', 'Survives reboot', function(i){ return i.kind === 'implant' ? [i.reboot] : []; }, null, ORD.yn),
    F('resides', 'Resides in', function(i){ return i.kind === 'implant' ? [i.resides] : []; }),
    F('type', 'Implant type', function(i){ return i.kind === 'implant' ? [i.type] : []; }),
    F('motivation', 'Motivation', function(i){ return i.kind === 'actor' ? [i.motivation] : []; }),
    F('iocs', 'Published indicators', function(i){ return [i.iocs.length ? 'yes' : 'no']; }, function(v){ return v === 'yes' ? 'has published indicators' : 'none published'; }),
    F('reporter', 'Reported by', function(i){ return i.kind === 'actor' ? i.reported_by : []; }),
    F('platform', 'Platform', function(i){ return i.platforms; }, pab, PORDER, pfull)
  ],
  text:function(i){ return [i.id, i.name, (i.aliases || []).join(' '), i.summary, i.iocs.map(function(x){ return IOC[x].ind.map(function(v){ return v[1]; }).join(' '); }).join(' '), (i.reported_by || []).join(' '), (i.tradecraft || []).join(' '), (i.cves || []).join(' '), i.type, i.motivation].join(' '); },
  card:function(i){
    var nid = i.id.replace(/-/g, '\u2011');   // non-breaking hyphens: ids never split across lines
    if (i.kind === 'actor') return hd(nid, i.name, i.aliases.length ? 'also: ' + esc(i.aliases.join(', ')) : '', b('actor', 'kind-actor') + b(i.motivation, 'mot mot-' + i.motivation)) +
      '<p class="clamp"><q class="quote">' + esc(i.stated_confidence) + '</q></p>' +
      '<div class="lc-f">' + b('link: ' + i.link_confidence, 'conf c-' + i.link_confidence) + chips(i.platforms.map(function(p){ return PN[p]; })) +
      (i.packs.length ? '<span class="chip">' + i.packs.length + (i.packs.length === 1 ? ' pack' : ' packs') + '</span>' : '<span class="chip ghost">no pack</span>') + iocChip(i) +
      (i.unv ? b('unverified', 'unv-b') : '') + '</div>';
    return hd(nid, i.name, i.aliases.length ? esc(i.aliases.join(', ')) : '', b('implant', 'kind-implant') + b(i.type, 'itype')) +
      '<p class="clamp">' + rich(i.summary, TOKS) + '</p>' +
      '<div class="lc-f">' + b('resides: ' + i.resides, 'res res-' + i.resides) + b('reboot: ' + i.reboot, 'surv surv-' + i.reboot) +
      (i.coverage === 'gap' ? b('coverage gap', 'gap-b') : '<span class="chip">' + i.detections.length + ' detections</span>') + iocChip(i) +
      (i.unv ? b('unverified', 'unv-b') : '') + '</div>';
  },
  cls:function(i){ return i.kind === 'implant' && i.coverage === 'gap' ? ' gap' : ''; },
  title:function(i){ return i.name; },
  drawer:function(i){
    var h, aids = i.kind === 'actor' ? [i.id] : i.actors;
    var hunts = D.hunts.filter(function(x){ return x.actors.some(function(a){ return aids.indexOf(a) >= 0; }); });
    var resp = i.platforms.filter(function(p){ return PLAT[p] && PLAT[p].response; });
    var jumps = [['dj-ind', 'Indicators', i.iocs.reduce(function(n, x){ return n + IOC[x].ind.length; }, 0)], ['dj-hunt', 'Hunts', hunts.length], ['dj-resp', 'Response', resp.length]];
    var jump = '<nav class="djump" aria-label="In this record">' + jumps.map(function(j){ return '<a href="#" data-dj="' + j[0] + '">' + j[1] + ' <span class="muted">' + j[2] + '</span></a>'; }).join('') + '</nav>';
    var hl_ = hunts.length ? hunts.map(function(x){ return lnk('#hunts/' + x.id, x.title); })
      : ['<span class="muted small">No hunt names this ' + (i.kind === 'actor' ? 'actor' : 'implant\'s actor') + '. The platform hunts still apply: ' +
         i.platforms.map(function(p){ return '<a href="#hunts?platform=' + p + '">' + esc(ABBR[p] || PN[p]) + '</a>'; }).join(', ') + '.</span>'];
    var plats = i.platforms.map(function(p){ return lnk('#platforms/' + p, PN[p] || p); });
    if (i.kind === 'actor'){
      h = facts([['Kind', b('actor', 'kind-actor')], ['Motivation', b(i.motivation, 'mot mot-' + i.motivation)], ['Link confidence', b(i.link_confidence, 'conf c-' + i.link_confidence)],
        ['Reported by', esc(i.reported_by.join(', '))], ['First seen', esc(i.first_seen || 'not stated')], ['State nexus', esc(i.state_nexus || 'not stated')]]);
      if (i.aliases.length) h += '<p class="muted small">also: ' + esc(i.aliases.join(', ')) + '</p>';
      h += '<div class="attrib"><div><span class="k">In their words</span> <q>' + esc(i.stated_confidence) + '</q></div></div>';
      h += para(i.summary);
      h += sec('Tradecraft', list(i.tradecraft)) + sec('Victimology', list(i.victimology));
      h += connects([['Platforms', plats],
        ['Implants', i.implants.map(function(x){ return lnk('#intel/' + x, INTEL[x] ? INTEL[x].name : x, 'implant'); })],
        ['Detections', i.packs.length ? i.packs.map(function(x){ return lnk('#detections?pack=' + x, x, 'mono'); }) : ['<span class="chip ghost">no detection pack yet</span>']],
        ['Hunts', hl_]], true);
    } else {
      h = facts([['Kind', b('implant', 'kind-implant')], ['Type', b(i.type, 'itype')], ['Resides', b(i.resides, 'res res-' + i.resides)],
        ['Survives reboot', b(i.reboot, 'surv surv-' + i.reboot)], ['Survives upgrade', b(i.upgrade, 'surv surv-' + i.upgrade)],
        i.factory_reset ? ['Survives factory reset', b(i.factory_reset, 'surv surv-' + i.factory_reset)] : null,
        ['Coverage', i.detections.length ? esc(i.detections.length + (i.detections.length === 1 ? ' detection' : ' detections')) : b('coverage gap', 'gap-b')],
        ['Confidence', conf(i.confidence, i.unv)]]);
      if (i.aliases.length) h += '<p class="muted small">' + esc(i.aliases.join(', ')) + '</p>';
      h += para(i.summary);
      if (i.cves.length) h += '<div class="links">' + chips(i.cves, 'cve') + '</div>';
      if (!i.detections.length) h += sec('Detection coverage', '<div class="links">' + b('coverage gap', 'gap-b') + '</div>' + (i.gap ? '<p class="note">' + rich(i.gap) + '</p>' : ''));
      h += sec('Artifacts', list(i.artifacts));
      h += sec('Anti-forensics', list(i.anti_forensics));
      h += connects([['Platforms', plats],
        ['Actors', i.actors.map(function(x){ return lnk('#intel/' + x, INTEL[x] ? INTEL[x].name : x, 'actor'); })],
        ['Detections', i.detections.map(function(id){ return lnk('#detections/' + id, id, 'mono'); })],
        ['Hunts', hl_]], true);
    }
    if (i.notes) h += '<p class="note">' + rich(i.notes) + '</p>';
    h = jump + h;
    h += '<div id="dj-resp"></div>' + sec('Response', resp.length ? '<div class="links">' + resp.map(function(p){ return lnk('#response/' + PLAT[p].response, 'Contain and recover - ' + PN[p]); }).join('') + '</div>' : '<p class="muted small">No playbook for these platforms yet.</p>');
    h += '<div id="dj-ind"></div>';
    if (i.iocs.length) h += sec('Indicators', '<p class="muted small">Parsed from each publisher\'s own file or table, with the publisher\'s role for every value. Most published addresses are not the actor\'s own machines - read the roles before blocking or attributing.</p>' + iocBlock(i.iocs));
    else h += sec('Indicators', '<p class="muted small">No machine-readable indicators are published for this ' + i.kind + ', or none the toolkit could parse from the publisher\'s own file.</p>');
    return h + refs(i.references);
  },
  exp:function(i){ return i.kind === 'actor'
    ? {kind:'actor', id:i.id, name:i.name, aliases:i.aliases, reported_by:i.reported_by, link_confidence:i.link_confidence, stated:i.stated_confidence, motivation:i.motivation, platforms:i.platforms.map(function(p){ return PN[p]; })}
    : {kind:'implant', id:i.id, name:i.name, aliases:i.aliases, type:i.type, resides:i.resides, survives_reboot:i.reboot, detections:i.detections, gap:i.gap, platforms:i.platforms.map(function(p){ return PN[p]; })}; },
  summary:function(){
    var imps = D.intel.filter(function(i){ return i.kind === 'implant'; }), actors = D.intel.length - imps.length;
    var gaps = imps.filter(function(i){ return i.coverage === 'gap'; }).length, boot = imps.filter(function(i){ return i.reboot === 'yes'; }).length;
    var rep = {}; D.intel.forEach(function(i){ (i.reported_by || []).forEach(function(r){ rep[r] = 1; }); });
    var dets = {}; imps.forEach(function(i){ i.detections.forEach(function(x){ dets[x] = 1; }); });
    var st = S.intel.sel;
    function on(k, v){ return st[k] && st[k].length === 1 && st[k][0] === v && Object.keys(st).filter(function(x){ return st[x].length; }).length === 1; }
    function tile(n, label, k, v, warn, zero){ var w = warn ? (n > 0 ? ' warn' : ' ok') : '', l = n === 0 && zero ? zero : label;
      return k ? '<button type="button" class="tile' + w + (on(k, v) ? ' on' : '') + '" data-only="' + k + '" data-v="' + v + '"><b>' + n + '</b><span>' + esc(l) + '</span></button>'
      : '<div class="tile' + w + '"><b>' + n + '</b><span>' + esc(l) + '</span></div>'; }
    return '<div class="tiles">' + tile(actors, 'actors and named clusters', 'kind', 'actor') + tile(imps.length, 'implants and tool families', 'kind', 'implant') +
      tile(gaps, 'implants with no detection - each says why', 'coverage', 'gap', true, 'implants without a detection: every record has one') +
      tile(boot, 'implants that survive a reboot', 'reboot', 'yes', true) +
      tile(Object.keys(rep).length, 'reporting parties, quoted verbatim') + tile(Object.keys(dets).length, 'detections tied to a named implant') + '</div>' + intelCharts();
  }
},

hardening: {
  noun:'controls', items:D.hardening, view:'cards',
  facets:[
    F('platform', 'Applies to', function(c){ return [c.platform]; }, function(v){ return v === 'ALL' ? 'Every platform (baseline)' : pab(v); }, PORDER,
      function(v){ return v === 'ALL' ? 'Baseline controls that apply to every platform' : pfull(v); }),
    F('category', 'Category', function(c){ return [c.category]; }, function(v){ return HCAT[v] || v; }),
    F('priority', 'Priority', function(c){ return [c.priority]; }, null, ['critical','high','medium']),
    F('confidence', 'Confidence', function(c){ return [c.confidence]; }, null, ORD.hml)
  ],
  text:function(c){ return [c.id, c.control, c.why, c.how, c.category, c.platform === 'ALL' ? 'baseline every platform' : PN[c.platform], c.blunts.join(' '),
    c.sources.map(function(x){ return x.title; }).join(' ')].join(' '); },
  card:function(c){
    return hd(c.platform === 'ALL' ? 'Every platform' : PN[c.platform], c.control, '', b(c.priority, 'pr pr-' + c.priority)) +
      '<p class="clamp">' + rich(c.why, TOKS) + '</p>' +
      '<div class="lc-f">' + (c.platform === 'ALL' ? b('baseline', 'imp-none') : '') + '<span class="chip">' + esc(HCAT[c.category] || c.category) + '</span>' + chips(c.blunts.slice(0, 3), 'cve') +
      (c.blunts.length > 3 ? '<span class="chip ghost">+' + (c.blunts.length - 3) + '</span>' : '') + (c.unv ? b('unverified', 'unv-b') : '') + '</div>';
  },
  cls:function(c){ return c.platform === 'ALL' ? ' base' : ''; },
  title:function(c){ return c.control; },
  label:function(c){ return (c.platform === 'ALL' ? 'Baseline' : PN[c.platform]) + ' · ' + c.id; },
  drawer:function(c){
    var h = facts([['Priority', b(c.priority, 'pr pr-' + c.priority)], ['Category', esc(HCAT[c.category] || c.category)], ['Confidence', conf(c.confidence, c.unv)],
      ['Applies to', esc(c.platform === 'ALL' ? 'every platform' : PN[c.platform])]]);
    h += sec('Why', para(c.why));
    h += sec('How', '<div class="stepbox">' + c.how.split(/\n{2,}/).map(function(x){ return '<p>' + rich(x) + '</p>'; }).join('') + '</div>');
    if (c.blunts.length) h += sec('Would have blunted', '<div class="links">' + lnks(c.blunt_links, 'cve') + '</div>');
    h += sec('Sources', '<ul class="srcs">' + c.sources.map(function(x){ return '<li><a href="' + esc(x.url) + '" rel="noopener" target="_blank">' + esc(x.title) + '</a>' +
      (x.quote ? '<blockquote>' + esc(x.quote) + '</blockquote>' : '') + '</li>'; }).join('') + '</ul>');
    h += '<div class="links">' + (c.platform === 'ALL' ? lnk('#hardening?platform=ALL', 'All baseline controls')
      : lnk('#platforms/' + c.platform, PN[c.platform]) + lnk('#hardening?platform=' + c.platform, 'All ' + PN[c.platform] + ' controls') + lnk('#hardening?platform=ALL', 'Baseline')) + '</div>';
    return h;
  },
  exp:function(c){ return {id:c.id, applies_to:c.platform === 'ALL' ? 'all platforms' : PN[c.platform], control:c.control, category:c.category,
    priority:c.priority, why:c.why, how:c.how, blunts:c.blunts, confidence:c.confidence, unverified:c.unv,
    sources:c.sources.map(function(x){ return x.url; })}; },
  summary:function(){
    var all = D.hardening, st = S.hardening.sel;
    function n(k, v){ return all.filter(function(c){ return c[k] === v; }).length; }
    function on(k, v){ return st[k] && st[k].length === 1 && st[k][0] === v && Object.keys(st).filter(function(x){ return st[x].length; }).length === 1; }
    function tile(num, label, k, v, warn){ return '<button type="button" class="tile' + (warn ? (num > 0 ? ' warn' : ' ok') : '') + (on(k, v) ? ' on' : '') + '" data-only="' + k + '" data-v="' + v + '"><b>' + num + '</b><span>' + esc(label) + '</span></button>'; }
    var plats = {}; all.forEach(function(c){ if (c.platform !== 'ALL') plats[c.platform] = 1; });
    return '<div class="tiles">' + tile(n('platform', 'ALL'), 'baseline controls - start here, they apply to every platform', 'platform', 'ALL') +
      tile(n('category', 'exposure'), 'about what faces the internet - the management interface first', 'category', 'exposure', true) +
      tile(n('priority', 'critical'), 'critical-priority controls', 'priority', 'critical', true) +
      '<div class="tile"><b>' + Object.keys(plats).length + '</b><span>platforms with their own controls</span></div></div>';
  }
}
};

/* ---------------------------------------------------------------- exploited CVEs */
var COVN = {detections:'Has detections', iocs:'Indicators, no on-box detection', 'no-indicators':'No indicators published',
  'lab-only':'Lab reproduction only', 'out-of-scope':'Out of scope', deferred:'Not yet triaged',
  'before-watch':'No detection; in KEV before 2024', 'other-product':'No detection; KEV files it under another product',
  'not-in-kev':'No detection; not in KEV', untriaged:'No detection; not in the ledger yet'};
var CX = {}; ['artifacts', 'detections', 'hunts', 'hardening', 'intel'].forEach(function(n){ D[n].forEach(function(i){ CX[n + ':' + i.id] = i; }); });
var CYRS = []; D.cves.forEach(function(c){ if (c.year && CYRS.indexOf(c.year) < 0) CYRS.push(c.year); }); CYRS.sort().reverse();
function cveCov(c){ var n = c.detections.length; return c.coverage === 'detections' ? n + (n === 1 ? ' detection' : ' detections') : (COVN[c.coverage] || c.coverage); }
function cvePl(c){ return c.platforms.map(function(p){ return ABBR[p] || p; }).join(', '); }
function bodSteps(c){
  var p = c.kev_platform || c.platforms[0] || '', pl = PLAT[p] || {}, pa = ABBR[p] || p;
  var go = [
    p ? lnk('#platforms/' + p, 'What you can reach on ' + pa) : '',
    pl.profile ? lnk('#plans/' + pl.profile, pa + ' collection plan, most volatile first') :
      '<span class="small">No collection profile for ' + esc(pa) + ' yet; collect by hand from the platform record.</span>',
    '<span class="small">CISA: &quot;' + esc(D.bod.patch) + '&quot;</span>' + (pl.response ? lnk('#response/' + pl.response, pa + ' playbook: what not to do first') : ''),
    pl.response ? lnk('#response/' + pl.response, pa + ' response playbook') : '',
    (c.detections.length ? lnk('#detections?cve=' + c.id, cveCov(c)) : '<span class="chip">' + esc(cveCov(c)) + '</span>') +
      c.hunts.map(function(h){ var x = CX['hunts:' + h]; return lnk('#hunts/' + h, x ? x.title : h); }).join('') +
      '<span class="small">then <code>edgetriage analyze</code> on the case</span>',
    '<span class="small"><code>edgetriage analyze</code> writes <code>report.html</code> and <code>report.md</code> (verdict, evidence gaps, findings); ' +
      '<code>edgetriage timeline</code> adds the incident timeline. CISA\'s report also needs the timeline of actions taken.</span>'];
  return '<ol class="bod">' + D.bod.steps.map(function(st, i){ return '<li><b>' + esc(st[0]) + '</b><span class="bod-t">' + esc(st[1]) + '</span>' +
      '<div class="bod-go">' + go[i] + '</div></li>'; }).join('') + '</ol>' +
    '<p class="small muted">Step names and target timelines are quoted from <a href="' + esc(D.bod.url) + '" rel="noopener" target="_blank">CISA\'s BOD 26-04 implementation guidance</a>, ' +
    'which also says: &quot;' + esc(D.bod.note) + '&quot; The links are this toolkit\'s suggestion for where each step starts, not part of the directive. ' +
    'Where the playbook\'s order and CISA\'s steps differ, an agency bound by the directive follows the directive.</p>';
}
var CWEN = {}; D.cves.forEach(function(c){ Object.keys(c.cwe_names).forEach(function(k){ if (!CWEN[k]) CWEN[k] = c.cwe_names[k]; }); });
function cweShort(id){ var n = CWEN[id] || '', m = n.match(/\('([^']+)'\)/);
  return id + (m ? ' ' + m[1] : n ? ' ' + (n.length <= 34 ? n : n.slice(0, 32).replace(/\s+\S*$/, '') + '…') : ''); }
var TRIN = {yes:'Flagged for triage', 'no-after':'Not flagged', 'no-before':'Added before BOD 26-04', none:'Not in KEV'};
var CVEIX = {}; D.cves.forEach(function(c){ CVEIX[c.id] = c; });
var XPN = {before:'Exploited before the CVE record was published', dated:'Earliest exploitation dated', reported:'Reported exploited; start not dated',
  none:'Searched; no source dates it', unsearched:'Not searched yet'};
var XPT = {before:'A quoted source dates exploitation activity before CVE.org published the record (compared at the end of the month or year when that is all the source gives)',
  dated:'A quoted source dates the earliest exploitation, on or after the CVE record\'s publication', reported:'A quoted source reports exploitation but does not say when it began',
  none:'The sources read do not report a date; that is not a claim it was not exploited', unsearched:'Nobody has looked for exploitation dates for this CVE yet'};
var XKIND = {vendor:'vendor', researcher:'researcher who saw it', government:'government agency'};
function xplSources(c){
  if (c.expl_searched === null) return '<p class="small muted">Not yet searched for exploitation dates.</p>';
  var read = c.expl_searched.length ? '<details class="xread"><summary class="small">What was read for this CVE (' + c.expl_searched.length + ')</summary><ul class="small">' +
    c.expl_searched.map(function(s){ return '<li>' + esc(s) + '</li>'; }).join('') + '</ul></details>' : '';
  if (!c.expl.length) return '<p class="small"><b>No dated report found.</b> The sources read do not say when exploitation of this CVE began. That is not a claim it was not exploited.</p>' + read;
  return '<h4 class="xh">What the sources say</h4><ul class="srcs">' + c.expl.map(function(r){
    return '<li><a href="' + esc(r.url) + '" rel="noopener" target="_blank">' + esc(r.title) + '</a> <span class="small muted">' + esc(r.publisher) + ' · ' + esc(XKIND[r.kind] || r.kind) + '</span>' +
      (r.read === 'summariser' ? ' <span class="chip ghost">read through a summariser - check the quote</span>' : '') +
      '<blockquote>' + esc(r.quote) + '</blockquote>' + (r.note ? '<div class="small">' + esc(r.note) + '</div>' : '') +
      '<div class="small muted">' + (r.stated_on ? 'Stated ' + esc(r.stated_on) : 'Statement date not shown') +
      ' · ' + esc(r.stated_on_basis) + ' · read ' + esc(r.accessed) + '</div></li>'; }).join('') + '</ul>' + read;
}
function triageFact(c){
  if (c.triage_k === 'yes') return b('flagged: 3 days and forensic triage', 'bod-b');
  if (c.triage_k === 'no-after') return 'not flagged' + (c.due_days != null ? '; ' + c.due_days + '-day deadline' : '');
  return 'not flagged; added before BOD 26-04 (' + esc(D.bod.issued) + ')';
}
function cveDates(c){
  var ev = [];
  if (c.published) ev.push([c.published, 'CVE record published', 'CVE.org' + (c.assigner ? ', assigned by ' + c.assigner : '')]);
  c.expl.forEach(function(r){
    if (r.earliest) ev.push([r.earliest, r.activity === 'attempted' ? 'Earliest attempted exploitation, as reported' : 'Earliest exploitation, as reported',
      r.publisher + ': "' + r.earliest_words + '"' + (r.stated_on ? ', said ' + r.stated_on : '')]);
    if (r.stated_on) ev.push([r.stated_on, r.activity === 'attempted' ? 'Attempted exploitation reported' : 'Exploitation reported', r.publisher + ' (' + (XKIND[r.kind] || r.kind) + ')']);
  });
  if (c.in_kev) ev.push([c.added, 'Added to KEV', 'CISA']);
  if (c.ssvc && c.ssvc.assessed) ev.push([c.ssvc.assessed, 'CISA assessment', 'exploitation ' + c.ssvc.exploitation + ', automatable ' + c.ssvc.automatable + ', technical impact ' + c.ssvc.technical_impact]);
  if (c.in_kev && c.due) ev.push([c.due, 'Federal due date', c.added < D.bod.issued ? 'set under BOD 22-01, since revoked' : 'BOD 26-04' + (c.triage_k === 'yes' ? ', with forensic triage' : '')]);
  c.iocs.forEach(function(sid){ var st = IOC[sid]; if (st) ev.push([st.published, 'Indicators published', st.publisher + ' (' + sid + ')']); });
  ev.sort(function(x, y){ return x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0; });
  var acts = c.actors.map(function(a){ return CX['intel:' + a]; }).filter(function(y){ return y && y.first_seen; });
  var pre = c.expl_k === 'before' ? '<p class="callout xcall"><b>Exploited before the CVE record was published.</b> ' + esc(c.earliest.by) + ' dates ' +
    (c.earliest.activity === 'attempted' ? 'attempted exploitation' : 'exploitation') + ' to ' + esc(c.earliest.date) + '; CVE.org published the record on ' + esc(c.published) + '.</p>' : '';
  return pre + '<ol class="cvt">' + ev.map(function(e){ return '<li><span class="cvt-d">' + esc(e[0]) + '</span><b>' + esc(e[1]) + '</b><span class="small muted">' + esc(e[2]) + '</span></li>'; }).join('') + '</ol>' +
    (acts.length ? '<p class="small"><b>First activity reported for the actors tied to it:</b> ' + acts.map(function(y){
      return '<a href="#intel/' + esc(y.id) + '">' + esc(y.name) + '</a> ' + esc(y.first_seen) + ' (' + esc(y.reported_by.join(', ')) + ')'; }).join('; ') +
      '. These date the actor, not necessarily this CVE.</p>' : '') + xplSources(c) +
    '<p class="small muted">No feed records when exploitation of a CVE began. ' +
    (c.expl.length ? 'The exploitation dates here are the sources\' own, quoted above; a month or a year is as precise as the source gives. ' : '') +
    'CISA adds an entry after a report (&quot;' + esc(D.bod.kev_reported) + '&quot;), and exploitation can start before the CVE record is published.</p>';
}
function cveSameCwe(c){
  var rows = c.cwes.map(function(w){ var o = D.cves.filter(function(x){ return x.id !== c.id && x.cwes.indexOf(w) >= 0; });
    return '<li><a href="https://cwe.mitre.org/data/definitions/' + esc(w.slice(4)) + '.html" rel="noopener" target="_blank">' + esc(w) + '</a> ' + esc(CWEN[w] || '') +
      (o.length ? '<div class="links">' + o.map(function(x){ return lnk('#cves/' + x.id, x.id + ' · ' + cvePl(x)); }).join('') + '</div>' :
        '<div class="small muted">No other CVE here shares it.</div>') + '</li>'; });
  return rows.length ? '<ul class="plain arts">' + rows.join('') + '</ul>' : '';
}
function cveRelated(c){
  var rel = {}, mine = c.actors.concat(c.implants);
  D.cves.forEach(function(o){ if (o.id === c.id) return;
    var why = mine.filter(function(a){ return o.actors.indexOf(a) >= 0 || o.implants.indexOf(a) >= 0; })
      .map(function(a){ return CX['intel:' + a] ? CX['intel:' + a].name : a; });
    if (why.length) rel[o.id] = why; });
  var ids = Object.keys(rel);
  return ids.length ? '<ul class="plain arts">' + ids.map(function(id){ return '<li><a href="#cves/' + esc(id) + '">' + esc(id) + '</a> <span class="small muted">' +
    esc(cvePl(CVEIX[id])) + ' · through ' + esc(rel[id].join(', ')) + '</span></li>'; }).join('') + '</ul>' : '';
}
function cveStats(shown){
  if (!shown.length) return '';
  var tri = 0, rw = 0, det = 0, xb = 0, xd = 0, cw = {}, act = {};
  shown.forEach(function(c){ if (c.triage_k === 'yes') tri++; if (c.ransomware === 'Known') rw++; if (c.detections.length) det++;
    if (c.expl_k === 'before') xb++; if (c.earliest) xd++;
    c.cwes.forEach(function(w){ cw[w] = cw[w] || {n:0, p:{}}; cw[w].n++; c.platforms.forEach(function(p){ cw[w].p[p] = 1; }); });
    c.actors.concat(c.implants).forEach(function(a){ (act[a] = act[a] || []).push(c.id); }); });
  var tiles = [[shown.length, 'CVEs shown', ''], [tri, 'flagged for BOD 26-04 forensic triage', 'data-f="triage" data-v="yes"'],
    [rw, 'known ransomware use (KEV)', 'data-f="ransomware" data-v="Known"'],
    [xb, 'exploited before the CVE record was published, per a quoted source', 'data-f="expl" data-v="before"'],
    [xd, 'with a quoted date for the earliest exploitation', ''], [det, 'with detections here', 'data-f="coverage" data-v="detections"'],
    [shown.length - det, 'without a detection', '']];
  var shared = Object.keys(cw).filter(function(w){ return cw[w].n > 1; }).sort(function(x, y){ return cw[y].n - cw[x].n || (x < y ? -1 : 1); }).slice(0, 8);
  var acts = Object.keys(act).sort(function(x, y){ return act[y].length - act[x].length || (x < y ? -1 : 1); }).slice(0, 8);
  return '<details class="cvstats" open><summary>Patterns across the CVEs shown</summary><div class="cvs-tiles">' +
    tiles.map(function(t){ return t[2] ? '<button type="button" class="cvs-t" ' + t[2] + ' title="Filter to these"><b>' + t[0] + '</b><span>' + esc(t[1]) + '</span></button>' :
      '<div class="cvs-t"><b>' + t[0] + '</b><span>' + esc(t[1]) + '</span></div>'; }).join('') + '</div>' +
    '<div class="cvs-cols"><div><h4>Weaknesses shared across CVEs</h4>' + (shared.length ? '<ul class="cvs-l">' + shared.map(function(w){ var pl = Object.keys(cw[w].p);
      return '<li><button type="button" class="cvs-r" data-f="cwe" data-v="' + esc(w) + '" title="Filter by this weakness"><b>' + esc(cweShort(w)) + '</b><span>' + cw[w].n + ' CVEs on ' +
        esc(pl.map(function(p){ return ABBR[p] || p; }).join(', ') || 'no platform') + '</span></button></li>'; }).join('') + '</ul>' :
      '<p class="small muted">No weakness is shared by two of the CVEs shown.</p>') + '</div>' +
    '<div><h4>Actors and implants tied to them</h4>' + (acts.length ? '<ul class="cvs-l">' + acts.map(function(a){ var y = CX['intel:' + a];
      return '<li><a href="#intel/' + esc(a) + '">' + esc(y ? y.name : a) + '</a> <span class="small muted">' + act[a].length + (act[a].length === 1 ? ' CVE' : ' CVEs') + '</span>' +
        '<div class="links">' + act[a].map(function(id){ return lnk('#cves/' + id, id); }).join('') + '</div></li>'; }).join('') + '</ul>' :
      '<p class="small muted">None of the CVEs shown is tied to an actor or implant record.</p>') + '</div></div>' +
    '<p class="small muted">Weakness ids come from KEV and the CVE records; the ties to actors and implants come from the packs, implants, hunts and indicator sets here. ' +
    'Exploitation dates are the sources\' own, quoted under Dates in each record. Click a count or a weakness to filter.</p></details>';
}
LIB.cves = {
  noun:'CVEs', items:D.cves, view:'cards',
  facets:[
    F('platform', 'Platform', function(c){ return c.platforms; }, pab, PORDER, pfull),
    F('triage', 'BOD 26-04 forensic triage', function(c){ return [c.triage_k]; }, function(v){ return TRIN[v] || v; }, ['yes', 'no-after', 'no-before', 'none'],
      function(v){ return v === 'yes' ? 'CISA set a three-day deadline with forensic triage for federal agencies' : v === 'no-after' ? 'Added after BOD 26-04, without the triage requirement' :
        v === 'no-before' ? 'Added before BOD 26-04 was issued; every earlier KEV entry reads No' : 'Not in CISA\'s KEV catalog'; }),
    F('expl', 'Exploitation dates', function(c){ return [c.expl_k]; }, function(v){ return XPN[v] || v; }, ['before', 'dated', 'reported', 'none', 'unsearched'],
      function(v){ return XPT[v] || ''; }),
    F('ransomware', 'Ransomware use (KEV)', function(c){ return c.in_kev ? [c.ransomware] : []; }, null, ['Known', 'Unknown']),
    F('coverage', 'What the toolkit has', function(c){ return [c.coverage]; }, function(v){ return COVN[v] || v; }, Object.keys(COVN)),
    F('cwe', 'Weakness (CWE)', function(c){ return c.cwes; }, cweShort),
    F('year', 'Added to KEV', function(c){ return c.year ? [c.year] : []; }, null, CYRS)
  ],
  text:function(c){ return [c.id, c.name, c.vendor, c.product, c.description, c.action, c.cwes.map(function(w){ return w + ' ' + (CWEN[w] || ''); }).join(' '), cvePl(c),
    c.platforms.map(function(p){ return PN[p] || ''; }).join(' '), COVN[c.coverage] || '', c.decision ? c.decision.basis : '', c.assigner,
    c.triage_k === 'yes' ? 'forensic triage BOD 26-04' : '', c.ransomware === 'Known' ? 'ransomware' : '', XPN[c.expl_k] || '',
    c.expl.map(function(r){ return r.publisher + ' ' + r.earliest_words; }).join(' ')].join(' '); },
  card:function(c){
    var meta = (cvePl(c) || c.vendor || 'no platform') + (c.published ? ' · published ' + c.published : '') + (c.in_kev ? ' · KEV ' + c.added : ' · not in KEV');
    return hd(meta, c.id, '',
        (c.triage_k === 'yes' ? '<span class="badge bod-b" data-f="triage" data-v="yes" title="Filter: flagged for forensic triage">forensic triage</span>' : '') +
        (c.ransomware === 'Known' ? '<span class="badge rw-b" data-f="ransomware" data-v="Known" title="Filter: known ransomware use">ransomware</span>' : '') +
        (c.expl_k === 'before' ? '<span class="badge xb" data-f="expl" data-v="before" title="Filter: a quoted source dates exploitation before the CVE record was published">exploited before publication</span>' : '')) +
      (c.name ? '<p class="clamp">' + esc(c.name) + '</p>' : '') +
      '<div class="lc-f"><span class="chip">' + esc(cveCov(c)) + '</span>' +
      c.cwes.slice(0, 2).map(function(w){ return '<span class="chip" data-f="cwe" data-v="' + esc(w) + '" title="Filter by this weakness">' + esc(cweShort(w)) + '</span>'; }).join('') + '</div>';
  },
  title:function(c){ return c.name || c.id; },
  label:function(c){ return c.id; },
  drawer:function(c){
    var x = facts([['Platforms', esc(cvePl(c) || 'none')],
      c.published ? ['CVE record published', esc(c.published)] : null,
      c.earliest ? ['Earliest exploitation reported', esc(c.earliest.date) + ' <span class="small muted">' + esc(c.earliest.by) + (c.earliest.activity === 'attempted' ? ', attempted' : '') + ', quoted under Dates</span>'] : null,
      c.in_kev ? ['Added to KEV', esc(c.added)] : ['KEV', 'not in the catalog'],
      c.in_kev && c.due ? ['Federal due date', esc(c.due) + (c.added < D.bod.issued ? ' <span class="small muted">(BOD 22-01, revoked)</span>' : '')] : null,
      c.in_kev ? ['BOD 26-04 forensic triage', triageFact(c)] : null,
      c.in_kev ? ['Ransomware use (KEV)', c.ransomware === 'Known' ? '<a class="badge rw-b" href="#cves?ransomware=Known" title="All CVEs with known ransomware use">known</a>' : esc(c.ransomware.toLowerCase())] : null,
      c.ssvc ? ['CISA assessment', esc('automatable: ' + c.ssvc.automatable + ', impact: ' + c.ssvc.technical_impact)] : null,
      ['The toolkit has', esc(cveCov(c))]]);
    x += sec('Dates', cveDates(c));
    if (c.in_kev) x += sec('What CISA\'s catalog says', '<p class="cve-name">' + esc(c.name) + '</p><blockquote>' + esc(c.description) + '</blockquote>' +
      '<p><b>Required action.</b> ' + esc(c.action) + '</p>' +
      (c.links.length ? '<ul class="srcs">' + c.links.map(function(u){ return '<li><a href="' + esc(u) + '" rel="noopener" target="_blank">' + esc(u.replace(/^https?:\/\//, '')) + '</a></li>'; }).join('') + '</ul>' : '') +
      '<p class="small"><b>About the forensic triage flag.</b> <a href="' + esc(D.bod.directive) + '" rel="noopener" target="_blank">BOD 26-04</a>, issued ' + esc(D.bod.issued) + ': &quot;' + esc(D.bod.triage_def) + '&quot; ' +
      (c.triage_k === 'yes' ? 'CISA attached it to this entry. ' : c.triage_k === 'no-before' ? 'This entry was added before the directive, and every KEV entry added before it reads No. ' : 'CISA did not attach it to this entry. ') +
      'The flag sets a federal deadline; it does not say whether a device that may be compromised needs forensics.</p>' +
      '<p class="small muted">Copied from KEV catalog ' + esc(D.bod.catalog) + ' (released ' + esc(D.bod.released) + ').' +
      (c.kev_platform ? '' : ' KEV files it under ' + esc(c.vendor + ' ' + c.product) + ', which the watch does not map to a platform; the records here tie it to ' + esc(cvePl(c) || 'no platform') + '.') + '</p>');
    else x += sec('Not in KEV', '<p>CISA\'s catalog ' + esc(D.bod.catalog) + ' has no entry for this CVE. It is here because a record below names it.</p>');
    if (c.triage_k === 'yes') x += sec('Forensic triage under BOD 26-04', bodSteps(c));
    if (c.decision) x += sec('Why there is no detection', '<p><span class="badge decb dec-' + esc(c.decision.decision) + '">' + esc(c.decision.decision) + '</span> ' +
      '<span class="small muted">decided ' + esc(c.decision.date) + '</span></p><blockquote>' + esc(c.decision.basis) + '</blockquote>');
    if (c.detections.length) x += sec('Detections', '<ul class="plain arts">' + c.detections.map(function(id){ var dd = CX['detections:' + id];
      return '<li><a href="#detections/' + esc(id) + '">' + esc(dd.title) + '</a> ' + b(dd.tier, 'tier t-' + dd.tier) + ' <span class="small muted">' + esc(dd.evidence) + '</span></li>'; }).join('') + '</ul>');
    if (c.artifacts.length) x += sec('Traces on the device', '<ul class="plain arts">' + c.artifacts.map(function(id){ var a = CX['artifacts:' + id];
      return '<li><a href="#artifacts/' + esc(id) + '"><code>' + esc(a.locator) + '</code></a> <span class="small muted">' + esc(PN[a.platform] || a.platform) + '</span>' +
        (a.suspicious ? '<div class="small">' + rich(a.suspicious) + '</div>' : '') + '</li>'; }).join('') +
      '</ul><p class="small muted">The artifact records that name this CVE, with what each calls suspicious. Each cites its own source.</p>');
    x += sec('Weaknesses, and other CVEs here that share them', cveSameCwe(c));
    x += sec('Related through actors and implants', cveRelated(c));
    x += connects([['Platforms', c.platforms.map(function(p){ return lnk('#platforms/' + p, PN[p] || p); })],
      ['Collection plans', c.plans.map(function(p){ return lnk('#plans/' + p, p, 'mono'); })],
      ['Playbooks', c.playbooks.map(function(st){ return lnk('#response/' + st, st); })],
      ['Hunts', c.hunts.map(function(h){ var y = CX['hunts:' + h]; return lnk('#hunts/' + h, y ? y.title : h); })],
      ['Hardening', c.hardening.map(function(h){ var y = CX['hardening:' + h]; return lnk('#hardening/' + h, y ? y.control : h); })],
      ['Actors and implants', c.actors.concat(c.implants).map(function(i){ var y = CX['intel:' + i]; return lnk('#intel/' + i, y ? y.name : i); })],
      ['Indicator sets', c.iocs.map(function(sid){ var y = IOC[sid], own = y ? (y.actors[0] || y.implants[0]) : '';
        return lnk(own ? '#intel/' + own : '#intel?iocs=yes', y ? y.publisher + ', ' + y.published : sid); })]]);
    return x;
  },
  exp:function(c){ return {id:c.id, name:c.name, platforms:c.platforms.map(function(p){ return PN[p] || p; }), in_kev:c.in_kev,
    cve_record:{published:c.published, assigner:c.assigner, cwes:c.cwes.map(function(w){ return {id:w, name:CWEN[w] || ''}; }), cisa_ssvc:c.ssvc},
    exploitation:{reading:XPN[c.expl_k], earliest:c.earliest, reports:c.expl, searched:c.expl_searched},
    kev:c.in_kev ? {vendor:c.vendor, product:c.product, added:c.added, due:c.due, ransomware:c.ransomware, forensic_triage:c.triage,
      forensic_triage_reading:TRIN[c.triage_k], required_action:c.action, description:c.description, links:c.links, catalog:D.bod.catalog} : null,
    toolkit:cveCov(c), decision:c.decision, detections:c.detections, artifacts:c.artifacts, hunts:c.hunts, hardening:c.hardening,
    playbooks:c.playbooks, plans:c.plans, actors:c.actors, implants:c.implants, indicator_sets:c.iocs}; },
  summary:cveStats
};

LIB.hunts = {
  noun:'hunts', items:D.hunts, view:'cards',
  facets:[
    F('platform', 'Platform', function(h){ return h.platforms; }, function(v){ return v === 'ALL' ? 'Any edge device' : pab(v); }, PORDER,
      function(v){ return v === 'ALL' ? 'Hunts that apply to any edge device' : pfull(v); }),
    F('data', 'Data you need', function(h){ return h.data; }, function(v){ return HDATA[v] || v; }),
    F('actor', 'Actor', function(h){ return h.actors; }, function(v){ return ACTN[v] || v; }),
    F('confidence', 'Confidence', function(h){ return [h.confidence]; }, null, ORD.hml)
  ],
  text:function(h){ return [h.id, h.title, h.hypothesis, h.data_detail, h.method.join(' '), h.normal, h.suspicious, h.seen_in.join(' '),
    h.cves.join(' '), h.attack.join(' '), h.data.map(function(x){ return HDATA[x] || x; }).join(' '),
    h.platforms.map(function(x){ return PN[x] || 'any'; }).join(' '), h.sources.map(function(x){ return x.title; }).join(' ')].join(' '); },
  card:function(h){
    return hd(h.platforms.map(function(x){ return x === 'ALL' ? 'Any edge device' : PN[x]; }).join(' · '), h.title, '', conf(h.confidence, h.unv)) +
      '<p class="clamp">' + rich(h.hypothesis, TOKS) + '</p>' +
      '<div class="lc-f">' + h.data.map(function(x){ return '<span class="chip">' + esc(HDATA[x] || x) + '</span>'; }).join('') +
      chips(h.cves.slice(0, 2), 'cve') + '</div>';
  },
  title:function(h){ return h.title; },
  label:function(h){ return h.id; },
  drawer:function(h){
    var x = facts([['Confidence', conf(h.confidence, h.unv)], ['Data', esc(h.data.map(function(d){ return HSHORT[d] || d; }).join(', '))],
      ['Platforms', esc(h.platforms.map(function(p){ return p === 'ALL' ? 'any edge device' : (ABBR[p] || p); }).join(', '))],
      ['Sources', esc(h.sources.length + ' quoted')]]);
    x += sec('Hypothesis', para(h.hypothesis));
    if (h.data_detail) x += sec('Data', para(h.data_detail));
    x += sec('Method', '<ol class="steps">' + h.method.map(function(m){ return '<li>' + rich(m) + '</li>'; }).join('') + '</ol>');
    x += sec('Normal or suspicious', '<div class="nvs"><div class="nvs-n"><b>Normal</b>' + para(h.normal) + '</div><div class="nvs-s"><b>Suspicious</b>' + para(h.suspicious) + '</div></div>');
    if (h.inferred) x += '<div class="callout inf"><b>Toolkit inference.</b> ' + rich(h.inferred) + '</div>';
    if (h.sigma.length) x += sec('Sigma rule', h.sigma.map(function(r){ return RULE[r] ? ruleBlock(RULE[r]) : ''; }).join(''));
    x += sec('Sources', '<ul class="srcs">' + h.sources.map(function(s){ return '<li><a href="' + esc(s.url) + '" rel="noopener" target="_blank">' + esc(s.title) + '</a>' +
      (s.read === 'summariser' ? ' <span class="chip ghost">read through a summariser - check the quote</span>' : '') +
      '<blockquote>' + esc(s.quote) + '</blockquote></li>'; }).join('') + '</ul>');
    if (h.seen_in.length) x += sec('Seen in', '<div class="links">' + chips(h.seen_in) + '</div>');
    x += connects([['Platforms', h.platforms.filter(function(p){ return p !== 'ALL'; }).map(function(p){ return lnk('#platforms/' + p, PN[p]); })],
      ['Actors', h.actors.map(function(a){ return lnk('#intel/' + a, h.actor_names[a] || a); })],
      ['CVEs', h.cve_links.filter(function(c){ return c.href; }).map(function(c){ return lnk(c.href, c.label, 'cve'); })]]);
    return x;
  },
  exp:function(h){ return {id:h.id, title:h.title, platforms:h.platforms.map(function(p){ return p === 'ALL' ? 'any' : PN[p]; }),
    hypothesis:h.hypothesis, data:h.data, data_detail:h.data_detail, method:h.method, normal:h.normal, suspicious:h.suspicious,
    cves:h.cves, attack:h.attack, confidence:h.confidence, unverified:h.unv, sources:h.sources.map(function(s){ return s.url; })}; },
  summary:function(shown){
    var c = {}, sel = S.hunts.sel.data || [], tot = 0;
    shown.forEach(function(h){ h.data.forEach(function(d){ c[d] = (c[d] || 0) + 1; tot++; }); });
    var segs = Object.keys(HDATA).filter(function(k){ return c[k]; }).map(function(k){
      return '<button type="button" class="seg hd' + (sel.indexOf(k) >= 0 ? ' on' : '') + '" style="flex:' + c[k] + '" data-f="data" data-v="' + k + '" title="' + esc(HDATA[k]) + ': ' + c[k] + ' - click to filter" aria-label="' + esc(HDATA[k]) + ': ' + c[k] + '"><b>' + c[k] + '</b>' +
        (c[k] / tot >= .12 ? ' <span>' + esc(HSHORT[k] || k) + '</span>' : '') + '</button>'; });
    return segs.length ? '<div class="distcap"><span>Data the hunts shown need (a hunt can need several)</span><span>Click a segment to filter</span></div><div class="dist" role="group" aria-label="Data the hunts need">' + segs.join('') + '</div>' : '';
  }
};

/* sanity: the facet keys here must match the ones the generator validates links against */
Object.keys(LIB).forEach(function(n){ var a = LIB[n].facets.map(function(f){ return f.k; }).sort().join(','), want = (D.facetKeys[n] || []).slice().sort().join(',');
  if (a !== want) console.error('facet keys for ' + n + ' differ from the generator: ' + a + ' vs ' + want); });

var S = {}, LAST = {}, OPEN = {}, cur = null, openId = null, openLib = null;
Object.keys(LIB).forEach(function(n){
  S[n] = {q:'', sel:{}, unv:false, compact:false, group:true, picks:{}};
  LIB[n].items.forEach(function(i){ i._t = LIB[n].text(i).toLowerCase(); });
});
try{ if (store('edt-compact') === '1') S.artifacts.compact = true; if (store('edt-group') === '0') S.artifacts.group = false; }catch(_){}

function pass(n, st, it, skip){
  if (st.unv && !it.unv) return false;
  if (st.q){ var toks = st.q.toLowerCase().split(/\s+/); for (var t = 0; t < toks.length; t++) if (toks[t] && it._t.indexOf(toks[t]) < 0) return false; }
  var fs = LIB[n].facets;
  for (var i = 0; i < fs.length; i++){
    var f = fs[i], sel = st.sel[f.k];
    if (f.k === skip || !sel || !sel.length) continue;
    var vals = f.get(it) || [], hit = false;
    for (var j = 0; j < vals.length; j++) if (sel.indexOf(String(vals[j])) >= 0){ hit = true; break; }
    if (!hit) return false;
  }
  return true;
}
function shown(n){ var st = S[n]; return LIB[n].items.filter(function(i){ return pass(n, st, i, null); }); }

function dist(n, k, order, label, list_){
  var c = {}, tot = list_.length || 1; list_.forEach(function(i){ var v = i[k]; c[v] = (c[v] || 0) + 1; });
  var sel = S[n].sel[k] || [];
  var segs = order.filter(function(v){ return c[v]; }).map(function(v){
    return '<button type="button" class="seg seg-' + v + (sel.indexOf(v) >= 0 ? ' on' : '') + '" style="flex:' + c[v] + '" data-f="' + k + '" data-v="' + v + '" title="' + v + ': ' + c[v] + ' - click to filter" aria-label="' + v + ': ' + c[v] + '"><b>' + c[v] + '</b>' +
      (c[v] / tot >= .12 ? ' <span>' + esc(v) + '</span>' : '') + '</button>'; });
  return segs.length ? '<div class="distcap"><span>' + esc(label) + '</span><span>Click a segment to filter</span></div><div class="dist" role="group" aria-label="' + esc(label) + '">' + segs.join('') + '</div>' : '';
}

function renderRail(n){
  var L = LIB[n], st = S[n], h = '';
  L.facets.forEach(function(f){
    var tot = {}, cnt = {};
    L.items.forEach(function(i){ (f.get(i) || []).forEach(function(v){ tot[v] = (tot[v] || 0) + 1; }); });
    L.items.forEach(function(i){ if (pass(n, st, i, f.k)) (f.get(i) || []).forEach(function(v){ cnt[v] = (cnt[v] || 0) + 1; }); });
    var vals = Object.keys(tot);
    if (!vals.length) return;
    if (f.order) vals.sort(function(a, c){ var x = f.order.indexOf(a), y = f.order.indexOf(c); return (x < 0 ? 99 : x) - (y < 0 ? 99 : y); });
    // by total, never by the live count, so the list does not reorder as other filters change
    else vals.sort(function(a, c){ return tot[c] - tot[a] || f.name(a).localeCompare(f.name(c)); });
    var sel = st.sel[f.k] || [], key = n + ':' + f.k, open = OPEN[key], lim = open || vals.length <= 9 ? vals.length : 7;
    var shut = OPEN[key + ':shut'];
    h += '<div class="fgroup' + (shut ? ' shut' : '') + '"><button type="button" class="fhead" data-fold="' + key + '" aria-expanded="' + !shut + '"><span class="car">▼</span>' + esc(f.label) + (sel.length ? '<span class="fsel">' + sel.length + '</span>' : '') + '</button><div class="fvals">';
    vals.slice(0, lim).forEach(function(v){
      var on = sel.indexOf(v) >= 0, c = cnt[v] || 0;
      h += '<label class="fv' + (on ? ' on' : '') + (c || on ? '' : ' zero') + '" title="' + esc(f.tip ? f.tip(v) : f.name(v)) + '"><input type="checkbox" data-f="' + f.k + '" value="' + esc(v) + '"' + (on ? ' checked' : '') + '><span class="box"></span><span class="fl">' + esc(f.name(v)) + '</span><span class="fc">' + c + '</span></label>';
    });
    if (vals.length > lim) h += '<button type="button" class="more" data-more="' + key + '">Show all ' + vals.length + '</button>';
    else if (open) h += '<button type="button" class="more" data-more="' + key + '">Show fewer</button>';
    h += '</div></div>';
  });
  $('rail').innerHTML = h;
  var nact = Object.keys(st.sel).reduce(function(a, k){ return a + st.sel[k].length; }, 0) + (st.unv ? 1 : 0) + (st.q ? 1 : 0);
  $('railToggle').innerHTML = 'Filters' + (nact ? ' <span class="fsel">' + nact + '</span>' : '');
}

function activeChips(n){
  var st = S[n], L = LIB[n], h = '';
  if (st.q) h += '<span class="achip">"' + esc(st.q) + '"<button type="button" data-rm="q" aria-label="Clear search">×</button></span>';
  if (st.unv) h += '<span class="achip">unverified only<button type="button" data-rm="unv" aria-label="Remove">×</button></span>';
  L.facets.forEach(function(f){ (st.sel[f.k] || []).forEach(function(v){ h += '<span class="achip">' + esc(f.label) + ': ' + esc(f.name(v)) + '<button type="button" data-rm="' + f.k + '" data-v="' + esc(v) + '" aria-label="Remove">×</button></span>'; }); });
  if (h) h += '<button type="button" class="lnkbtn" data-act="reset">clear all</button>';
  return h;
}

function updatePicked(n){
  var k = Object.keys(S[n].picks).length, P = $('tab-' + n);
  P.querySelector('.picked').innerHTML = k ? k + ' picked - exports use the picks <button type="button" class="lnkbtn" data-act="unpick">clear</button>' : '';
}

function renderLib(n){
  var L = LIB[n], st = S[n], P = $('tab-' + n), items = shown(n);
  LAST[n] = items;
  TOKS = st.q ? st.q.toLowerCase().split(/\s+/).filter(Boolean).sort(function(a, c){ return c.length - a.length; }) : [];
  P.querySelector('.count').textContent = items.length + ' of ' + L.items.length + ' ' + L.noun + ' shown';
  P.querySelector('.active').innerHTML = activeChips(n);
  P.querySelector('.summary').innerHTML = L.summary ? L.summary(items) : '';
  updatePicked(n);
  var res = P.querySelector('.results'), sel = function(i){ return openId === i.id && openLib === n ? ' sel' : ''; };
  if (!items.length) res.innerHTML = '<div class="empty">Nothing matches these filters. <button type="button" class="lnkbtn" data-act="reset">Clear them</button></div>';
  else if (L.view === 'rows'){
    var allPicked = items.every(function(i){ return st.picks[i.id]; });
    res.innerHTML = '<div class="rows' + (st.compact ? ' compact' : '') + '"><div class="row head"><span><input type="checkbox" class="pickall" aria-label="Pick all shown"' + (allPicked ? ' checked' : '') + '></span>' +
      L.head.slice(1).map(function(x, ix){ return '<span class="' + ['c-plat','c-main','c-cls','c-vol','c-val','c-conf'][ix] + '">' + esc(x) + '</span>'; }).join('') + '</div>' +
      rowsHtml(L, st, items, sel) + '</div>';
  } else res.innerHTML = '<div class="lgrid">' + items.map(function(i){ return '<article class="lc item' + (i.unv ? ' unv' : '') + (L.cls ? L.cls(i) : '') + sel(i) + '" role="button" tabindex="0" data-id="' + esc(i.id) + '">' + L.card(i) + '</article>'; }).join('') + '</div>';
  renderRail(n);
  writeHash();
  navState();
}

function rerender(){ if (LIB[cur]) renderLib(cur); }
/* Artifact rows, grouped by platform unless exactly one platform is filtered (F9). */
function rowsHtml(L, st, items, sel){
  var grp = st.group && !(st.sel.platform && st.sel.platform.length === 1), last = null, out = [];
  items.forEach(function(i){
    if (grp && i.platform !== last){ last = i.platform; out.push(groupHead(i.platform, items)); }
    out.push('<div class="row item' + (i.unv ? ' unv' : '') + sel(i) + '" data-id="' + esc(i.id) + '">' + L.row(i) + '</div>');
  });
  return out.join('');
}
function groupHead(pid, items){
  var g = items.filter(function(x){ return x.platform === pid; }), c = {};
  g.forEach(function(x){ c[x.volatility] = (c[x.volatility] || 0) + 1; });
  var vs = ORD.vol.filter(function(v){ return c[v]; });
  return '<div class="grp"><a href="#platforms/' + pid + '">' + esc(PN[pid]) + '</a><span class="gm">' + g.length + (g.length === 1 ? ' artifact' : ' artifacts') + ' &#183; ' +
    vs.map(function(v){ return c[v] + ' ' + v; }).join(', ') + '</span><span class="vbar2" aria-hidden="true">' +
    vs.map(function(v){ return '<span class="vb vb-' + v + '" style="flex:' + c[v] + '"></span>'; }).join('') + '</span></div>';
}
function syncControls(n){
  var P = $('tab-' + n), st = S[n], q = P.querySelector('.q'), u = P.querySelector('.unvT'), c = P.querySelector('.cmpT'), g = P.querySelector('.grpT');
  if (q.value !== st.q) q.value = st.q;
  if (u) u.setAttribute('aria-pressed', String(st.unv));
  if (c) c.setAttribute('aria-pressed', String(st.compact));
  if (g) g.setAttribute('aria-pressed', String(st.group));
}

/* ---------------------------------------------------------------- URL state */
function qs(n){
  var st = S[n], parts = [];
  LIB[n].facets.forEach(function(f){ var v = st.sel[f.k]; if (v && v.length) parts.push(f.k + '=' + v.map(encodeURIComponent).join(',')); });
  if (st.q) parts.push('q=' + encodeURIComponent(st.q));
  if (st.unv) parts.push('unv=1');
  return parts.length ? '?' + parts.join('&') : '';
}
var pageAnchor = {};
function writeHash(){
  if (!cur) return;
  var a = LIB[cur] ? (openId && openLib === cur ? openId : '') : (pageAnchor[cur] || '');
  var h = '#' + cur + (a ? '/' + encodeURIComponent(a) : '') + (LIB[cur] ? qs(cur) : (cur === 'response' && RV ? '?verdict=' + RV : ''));
  if (location.hash !== h) history.replaceState(null, '', h);
}
function readQuery(n, query){
  var st = S[n]; st.q = ''; st.unv = false; st.sel = {};
  query.split('&').forEach(function(kv){
    if (!kv) return;
    var i = kv.indexOf('='), k = i < 0 ? kv : kv.slice(0, i), v = i < 0 ? '' : kv.slice(i + 1);
    if (k === 'q') st.q = decodeURIComponent(v);
    else if (k === 'unv') st.unv = v === '1';
    else st.sel[k] = v.split(',').map(decodeURIComponent).filter(Boolean);
  });
}

/* ---------------------------------------------------------------- tabs + routing */
var tabs = Array.prototype.slice.call(document.querySelectorAll('[data-tab]'));
var TABS = {}; tabs.forEach(function(t){ TABS[t.dataset.tab] = 1; });
function show(tab, anchor){
  var changed = cur !== tab;
  cur = tab;
  tabs.forEach(function(b){ b.setAttribute('aria-selected', String(b.dataset.tab === tab)); });
  var tb = document.querySelector('.tabs'), on = tb.querySelector('[aria-selected=true]');   // keep the current tab in view on phones
  if (on){ var r = on.getBoundingClientRect(), t = tb.getBoundingClientRect(); if (r.left < t.left || r.right > t.right) tb.scrollLeft += r.left - t.left - 16; }
  document.querySelectorAll('.panel').forEach(function(p){ p.hidden = p.id !== 'tab-' + tab; });
  document.querySelector('.shell').classList.toggle('norail', !LIB[tab] && tab !== 'guide');
  $('railTitle').textContent = tab === 'guide' ? 'Contents' : 'Filters';
  $('railReset').hidden = tab === 'guide';
  if (tab === 'guide') renderToc();
  if (changed) window.scrollTo(0, 0);
  if (LIB[tab]){
    syncControls(tab);
    if (anchor){
      var it0 = LIB[tab].items.filter(function(i){ return i.id === anchor; })[0];
      if (it0 && !pass(tab, S[tab], it0, null)){ S[tab].sel = {}; S[tab].q = ''; S[tab].unv = false; syncControls(tab); }
      openId = anchor; openLib = tab;
    }
    else if (openLib === tab || !LIB[openLib]) closeDrawer(false);
    renderLib(tab);
    if (anchor) openDrawer(tab, anchor);
    else if (openLib !== tab) closeDrawer(false);
  } else {
    closeDrawer(false);
    if (tab === 'plans' && anchor) pickProfile(anchor);
    if (tab === 'response' && anchor) pickResp(anchor);
    if (tab === 'coverage'){
      pageAnchor.coverage = anchor || '';
      var cv = anchor && document.getElementById('cov-' + anchor);
      if (cv) setTimeout(function(){ cv.scrollIntoView({block:'start'}); }, 0);
    }
    if (tab === 'guide'){
      pageAnchor.guide = anchor || '';
      document.querySelectorAll('.toc a').forEach(function(a){ a.classList.toggle('on', !!anchor && a.dataset.g === anchor); });
      var g = anchor && document.getElementById('g-' + anchor);
      if (g){ tocHold = Date.now() + 700; setTimeout(function(){ g.scrollIntoView({block:'start'}); }, 0); }
    }
    writeHash();
  }
}
function route(){
  var h = location.hash.slice(1), query = null, qi = h.indexOf('?');
  if (qi >= 0){ query = h.slice(qi + 1); h = h.slice(0, qi); }
  var parts = h.split('/'), tab = parts[0] || 'start', anchor = decodeURIComponent(parts.slice(1).join('/'));
  if (tab === 'packs'){ tab = 'detections'; if (anchor){ query = 'pack=' + encodeURIComponent(anchor); anchor = ''; } }
  if (tab === 'rules'){  // the Rules tab was merged into Detections
    tab = 'detections';
    var owner = anchor && D.detections.filter(function(x){ return x.sigma.indexOf(anchor) >= 0 || x.rule_id === anchor; })[0];
    if (owner) anchor = owner.id; else { anchor = ''; if (query === null) query = 'runs=siem'; }
  }
  if (!TABS[tab]){ var el = document.getElementById(h); tab = 'start'; anchor = '';
    if (el && el.closest('#tab-guide')){ tab = 'guide'; anchor = h.replace(/^g-/, ''); }
    else if (el){ el.scrollIntoView(); return; } }
  if (LIB[tab] && query !== null) readQuery(tab, query);
  if (tab === 'response'){ var m = /(?:^|&)verdict=([A-Z-]+)/.exec(query || ''); setVerdict(m && RESP_V.indexOf(m[1]) >= 0 ? m[1] : ''); }
  show(tab, anchor);
}
tabs.forEach(function(b){ b.addEventListener('click', function(){ var t = b.dataset.tab; location.hash = '#' + t + (LIB[t] ? qs(t) : ''); }); });
document.querySelector('.tabs').addEventListener('keydown', function(ev){
  if (ev.key !== 'ArrowRight' && ev.key !== 'ArrowLeft') return;
  var list = tabs.filter(function(t){ return t.closest('.tabs'); }), i = list.indexOf(document.activeElement); if (i < 0) return;
  var n = list[(i + (ev.key === 'ArrowRight' ? 1 : list.length - 1)) % list.length]; n.focus(); ev.preventDefault();
});
window.addEventListener('hashchange', route);

/* ---------------------------------------------------------------- guide contents */
var tocObs = null, tocHold = 0;   // a requested section stays marked while the page scrolls to it
function renderToc(){
  var cur_ = pageAnchor.guide || '';
  $('rail').innerHTML = '<nav class="toc" aria-label="Guide contents">' + D.toc.map(function(t){
    var id = t.id.slice(2);
    return '<a class="l' + t.level + (id === cur_ ? ' on' : '') + '" href="#guide/' + id + '" data-g="' + id + '">' + esc(t.title) + '</a>'; }).join('') + '</nav>';
  $('railToggle').textContent = 'Contents';
  $('railTitle').innerHTML = 'Contents<span class="rmin">about ' + D.guideMins + ' min</span>';
  if (tocObs || !('IntersectionObserver' in window)) return;
  tocObs = new IntersectionObserver(function(es){
    es.forEach(function(en){
      if (!en.isIntersecting || cur !== 'guide' || Date.now() < tocHold) return;
      var id = en.target.id.slice(2);
      document.querySelectorAll('.toc a').forEach(function(a){ a.classList.toggle('on', a.dataset.g === id); });
    });
  }, {rootMargin:'-20% 0px -70% 0px'});
  D.toc.forEach(function(t){ var el = document.getElementById(t.id); if (el) tocObs.observe(el); });
}

/* ---------------------------------------------------------------- drawer */
function markSel(){
  document.querySelectorAll('.item.sel').forEach(function(x){ x.classList.remove('sel'); });
  if (!openId || openLib !== cur) return;
  var el = document.querySelector('#tab-' + cur + ' .item[data-id="' + cssId(openId) + '"]');
  if (el){ el.classList.add('sel'); var r = el.getBoundingClientRect(); if (r.top < 0 || r.bottom > window.innerHeight) el.scrollIntoView({block:'center'}); }
}
function navState(){
  var l = LAST[openLib] || [], i = -1;
  for (var k = 0; k < l.length; k++) if (l[k].id === openId){ i = k; break; }
  $('dPrev').disabled = i <= 0; $('dNext').disabled = i < 0 || i >= l.length - 1;
  $('dPos').textContent = i >= 0 ? (i + 1) + ' of ' + l.length : '';
}
var dReturn = null;   // what had focus before the drawer opened; it gets focus back on close
function cssId(v){ return window.CSS && CSS.escape ? CSS.escape(v) : v; }
function openDrawer(n, id){
  var L = LIB[n], it = null;
  for (var k = 0; k < L.items.length; k++) if (L.items[k].id === id){ it = L.items[k]; break; }
  if (!it){ toast('Nothing called ' + id + ' in ' + n); closeDrawer(); return; }
  var opening = $('drawer').hidden;
  if (opening) dReturn = document.activeElement;
  openId = id; openLib = n;
  $('dId').textContent = L.label ? L.label(it) : it.id; $('dTitle').textContent = L.title(it);
  DREC = it; $('dBody').innerHTML = L.drawer(it); DREC = null; $('dBody').scrollTop = 0; buildSecs();
  $('drawer').hidden = false; $('scrim').hidden = false; document.body.classList.add('drawer-open');
  markSel(); navState(); writeHash();
  if (opening) $('dTitle').focus({preventScroll:true});
}
function closeDrawer(write){
  var was = !$('drawer').hidden, lastId = openId, lastLib = openLib;
  $('drawer').hidden = true; $('scrim').hidden = true; document.body.classList.remove('drawer-open');
  openId = null; markSel();
  if (write !== false && was) writeHash();
  if (!was) return;
  // back to what opened it; if a re-render replaced that row, to the row for the same record
  var r = dReturn; dReturn = null;
  if (!(r && r.isConnected && r.offsetParent !== null))
    r = lastLib === cur && lastId ? document.querySelector('#tab-' + cur + ' .item[data-id="' + cssId(lastId) + '"]') : null;
  if (r && !r.hasAttribute('tabindex')) r = r.querySelector('a.locl') || r;
  if (r && r.focus) r.focus({preventScroll:true});
}
/* One chip per section, pinned at the top of the record; on intel records the
   Indicators / Hunts / Response jumps come first and are not repeated (F15). */
function buildSecs(){
  var body = $('dBody'), dj = body.querySelector('.djump'), chips = [];
  Array.prototype.forEach.call(body.querySelectorAll('h4'), function(h, i){
    var t = h.textContent.split(' · ')[0].replace(/ \(.*$/, '').replace(/^About pack .*/, 'About the pack').trim();
    if ((dj && /^(Indicators|Hunts|Response)\b/.test(t)) || chips.length >= 8) return;
    h.id = h.id || 'ds-' + i;
    chips.push('<button type="button" data-ds="' + h.id + '">' + esc(t) + '</button>');
  });
  if (chips.length < 2) return;
  var nav = document.createElement('nav'); nav.className = 'dsecs'; nav.setAttribute('aria-label', 'Sections in this record'); nav.innerHTML = chips.join('');
  if (dj) dj.after(nav); else body.insertBefore(nav, body.firstChild);
}
function scrollBody(el){
  var body = $('dBody'), nav = body.querySelector('.dsecs');
  body.scrollTo({top:Math.max(0, el.offsetTop - (nav ? nav.offsetHeight : 0) - 8), behavior:'smooth'});
}
$('dBody').addEventListener('click', function(ev){ var c = ev.target.closest('[data-ds]'); if (c){ var el = $(c.dataset.ds); if (el) scrollBody(el); } });
function stepDrawer(dir){
  var l = LAST[openLib] || [];
  for (var k = 0; k < l.length; k++) if (l[k].id === openId){ var n = l[k + dir]; if (n) openDrawer(openLib, n.id); return; }
}
$('dClose').addEventListener('click', function(){ closeDrawer(); });
$('scrim').addEventListener('click', function(){ closeDrawer(); });
$('dPrev').addEventListener('click', function(){ stepDrawer(-1); });
$('dNext').addEventListener('click', function(){ stepDrawer(1); });
$('dWide').addEventListener('click', function(){ var w = $('drawer').classList.toggle('wide'); $('dWide').textContent = w ? 'Narrower' : 'Wider'; });
$('dLink').addEventListener('click', function(){ copyText(location.href, function(){ toast('Link to this record copied'); }); });

/* ---------------------------------------------------------------- library events */
function toggleSel(n, k, v, only){
  var st = S[n];
  if (only){ var same = st.sel[k] && st.sel[k].length === 1 && st.sel[k][0] === v; st.sel = {}; st.q = ''; st.unv = false; if (!same) st.sel[k] = [v]; }
  else { var a = st.sel[k] || []; var i = a.indexOf(v); if (i >= 0) a.splice(i, 1); else a.push(v); st.sel[k] = a; }
  syncControls(n); rerender();
}
function resetLib(n){ S[n].sel = {}; S[n].q = ''; S[n].unv = false; syncControls(n); rerender(); }

$('rail').addEventListener('change', function(ev){ var i = ev.target; if (i.dataset.f) toggleSel(cur, i.dataset.f, i.value); });
$('rail').addEventListener('click', function(ev){
  var m = ev.target.closest('[data-more]'); if (m){ OPEN[m.dataset.more] = !OPEN[m.dataset.more]; renderRail(cur); return; }
  var f = ev.target.closest('[data-fold]'); if (f){ OPEN[f.dataset.fold + ':shut'] = !OPEN[f.dataset.fold + ':shut']; renderRail(cur); }
});
$('railReset').addEventListener('click', function(ev){ ev.preventDefault(); if (LIB[cur]) resetLib(cur); });
$('railToggle').addEventListener('click', function(){ document.querySelector('.rail').classList.toggle('open'); });

var qT;
document.querySelectorAll('.panel.lib').forEach(function(P){
  var n = P.dataset.lib;
  P.querySelector('.q').addEventListener('input', function(ev){ clearTimeout(qT); var v = ev.target.value; qT = setTimeout(function(){ S[n].q = v.trim(); renderLib(n); }, 90); });
  var u = P.querySelector('.unvT'); if (u) u.addEventListener('click', function(){ S[n].unv = !S[n].unv; syncControls(n); renderLib(n); });
  var c = P.querySelector('.cmpT'); if (c) c.addEventListener('click', function(){ S[n].compact = !S[n].compact; store('edt-compact', S[n].compact ? '1' : '0'); syncControls(n); renderLib(n); });
  var g = P.querySelector('.grpT'); if (g) g.addEventListener('click', function(){ S[n].group = !S[n].group; store('edt-group', S[n].group ? '1' : '0'); syncControls(n); renderLib(n); });
  P.querySelectorAll('[data-exp]').forEach(function(x){ x.addEventListener('click', function(){ exportLib(n, x.dataset.exp); }); });
  P.addEventListener('change', function(ev){
    var t = ev.target;
    if (t.classList.contains('pick')){ var id = t.closest('.item').dataset.id; if (t.checked) S[n].picks[id] = 1; else delete S[n].picks[id]; updatePicked(n); }
    if (t.classList.contains('pickall')){ LAST[n].forEach(function(i){ if (t.checked) S[n].picks[i.id] = 1; else delete S[n].picks[i.id]; }); renderLib(n); }
  });
  P.addEventListener('click', function(ev){
    var t = ev.target, lk = t.closest('a.locl');
    if (lk && ev.button === 0 && !ev.metaKey && !ev.ctrlKey && !ev.shiftKey && !ev.altKey){ ev.preventDefault(); openDrawer(n, lk.closest('.item').dataset.id); return; }
    if (t.closest('.pick,.pickall,a,.copy')) return;
    var rm = t.closest('[data-rm]');
    if (rm){ var k = rm.dataset.rm; if (k === 'q') S[n].q = ''; else if (k === 'unv') S[n].unv = false; else { var a = S[n].sel[k] || []; a.splice(a.indexOf(rm.dataset.v), 1); } syncControls(n); renderLib(n); return; }
    var act = t.closest('[data-act]');
    if (act){ if (act.dataset.act === 'reset') resetLib(n); if (act.dataset.act === 'unpick'){ S[n].picks = {}; renderLib(n); }
      if (act.dataset.act === 'copyview') copyText(location.href, function(){ toast('Link to this view copied'); }); return; }
    var seg = t.closest('[data-f]'); if (seg){ toggleSel(n, seg.dataset.f, seg.dataset.v); return; }
    var only = t.closest('[data-only]'); if (only){ toggleSel(n, only.dataset.only, only.dataset.v, true); return; }
    var it = t.closest('.item'); if (it) openDrawer(n, it.dataset.id);
  });
  P.addEventListener('keydown', function(ev){
    var it = ev.target.closest && ev.target.closest('.item');
    if (it && ev.target === it && (ev.key === 'Enter' || ev.key === ' ')){ ev.preventDefault(); openDrawer(n, it.dataset.id); }
  });
});

/* ---------------------------------------------------------------- export */
function csvq(v){ if (Array.isArray(v)) v = v.join('; '); v = v == null ? '' : String(v); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }
function download(name, mime, text){
  var a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], {type:mime})); a.download = name;
  document.body.appendChild(a); a.click(); setTimeout(function(){ URL.revokeObjectURL(a.href); a.remove(); }, 0);
}
function exportLib(n, fmt){
  var st = S[n], picked = Object.keys(st.picks), rows = picked.length ? LIB[n].items.filter(function(i){ return st.picks[i.id]; }) : (LAST[n] || []);
  var recs = rows.map(LIB[n].exp), stamp = new Date().toISOString().slice(0, 10);
  if (!recs.length){ toast('Nothing to export'); return; }
  if (fmt === 'json') download('edge-dfir-' + n + '-' + stamp + '.json', 'application/json', JSON.stringify(recs, null, 2));
  else { var keys = Object.keys(recs[0]); download('edge-dfir-' + n + '-' + stamp + '.csv', 'text/csv', [keys.join(',')].concat(recs.map(function(r){ return keys.map(function(k){ return csvq(r[k]); }).join(','); })).join('\n')); }
  toast('Exported ' + recs.length + (picked.length ? ' picked ' : ' shown ') + LIB[n].noun);
}

/* ---------------------------------------------------------------- copy */
function copyText(text, done){
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, function(){});
  else { var ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select();
         try{ document.execCommand('copy'); done(); }catch(_){} document.body.removeChild(ta); }
}
document.addEventListener('click', function(ev){
  var b = ev.target.closest('.copy'); if (!b || b.id === 'dLink') return;
  var text = b.dataset.copylink ? location.href.split('#')[0] + b.dataset.copylink
    : (b.dataset.copy || ((b.parentElement.querySelector('code') || {}).textContent) || '');
  copyText(text, function(){ var t = b.textContent; b.textContent = 'Copied'; setTimeout(function(){ b.textContent = t; }, 1200); });
});

/* ---------------------------------------------------------------- keyboard */
document.addEventListener('keydown', function(ev){
  var tag = (document.activeElement || {}).tagName || '', typing = /INPUT|SELECT|TEXTAREA/.test(tag);
  if ((ev.key === 'k' || ev.key === 'K') && (ev.ctrlKey || ev.metaKey)){ ev.preventDefault(); palOpen(); return; }
  if (ev.key === '/' && !typing){ ev.preventDefault(); palOpen(); return; }
  if (!$('pal').hidden) return;
  if (ev.key === 'Escape'){
    if (!$('drawer').hidden){ closeDrawer(); return; }
    if (typing && document.activeElement.classList.contains('q')){ document.activeElement.value = ''; S[cur].q = ''; renderLib(cur); document.activeElement.blur(); }
    return;
  }
  if (!$('drawer').hidden && !typing && (ev.key === 'ArrowLeft' || ev.key === 'k')){ stepDrawer(-1); ev.preventDefault(); }
  if (!$('drawer').hidden && !typing && (ev.key === 'ArrowRight' || ev.key === 'j')){ stepDrawer(1); ev.preventDefault(); }
});

/* ---------------------------------------------------------------- search everything (F2) */
var PAL = null, palI = 0, palFlat = [], palReturn = null;
var PAL_ORDER = ['CVEs', 'Artifacts', 'Detections', 'Collection steps', 'Hunts', 'Threat intel', 'Indicators', 'Hardening', 'Platforms', 'Guide'];
var PAL_LIB = {'CVEs':'cves', 'Artifacts':'artifacts', 'Detections':'detections', 'Hunts':'hunts', 'Threat intel':'intel', 'Indicators':'intel', 'Hardening':'hardening', 'Platforms':'platforms'};
function palIndex(){
  if (PAL) return PAL;
  PAL = [];
  function add(g, t, sub, x, href, mono){ PAL.push({g:g, t:String(t), s:sub, x:String(x).toLowerCase(), href:href, mono:!!mono}); }
  D.artifacts.forEach(function(a){ add('Artifacts', a.locator, PN[a.platform] + ' · ' + a.id, a._t, '#artifacts/' + a.id, true); });
  D.detections.forEach(function(x){ add('Detections', x.title, x.id + ' · ' + x.pack, x._t, '#detections/' + x.id); });
  D.steps.forEach(function(st){ add('Collection steps', st[3] || st[1], st[0] + ' · ' + st[2] + ' ' + st[1] + ' · ' + st[4], st.join(' '), '#plans/' + st[0], !!st[3]); });
  D.hunts.forEach(function(h){ add('Hunts', h.title, h.id, h._t, '#hunts/' + h.id); });
  D.intel.forEach(function(i){ add('Threat intel', i.name, i.kind + ' · ' + i.id, i._t, '#intel/' + i.id); });
  D.iocs.forEach(function(set){ var to = set.actors[0] || set.implants[0];
    set.ind.forEach(function(v){ add('Indicators', defang(v[0], v[1]), (ROLE[v[2]] || v[2]) + ' · ' + set.publisher + ' · ' + set.id,
      v[1] + ' ' + v[0] + ' ' + v[3] + ' ' + set.id, to ? '#intel/' + to : '#intel?iocs=yes', true); }); });
  D.hardening.forEach(function(c){ add('Hardening', c.control, (c.platform === 'ALL' ? 'Baseline' : PN[c.platform]) + ' · ' + c.id, c._t, '#hardening/' + c.id); });
  D.platforms.forEach(function(p){ add('Platforms', p.name, p.vendor + ' · ' + p.id, p._t, '#platforms/' + p.id); });
  D.cves.forEach(function(c){ add('CVEs', c.id, (cvePl(c) || c.vendor || 'no platform') + ' · ' + (c.name || 'not in KEV') +
    (c.triage === 'Yes' ? ' · forensic triage (BOD 26-04)' : ''), c._t, '#cves/' + c.id); });
  D.toc.forEach(function(t){ add('Guide', t.title, 'Guide section', t.title, '#guide/' + t.id.slice(2)); });
  return PAL;
}
// a defanged paste matches too: 192.0.2[.]1, hxxps://, [:]
function palNorm(q){ return q.replace(/\[\.\]/g, '.').replace(/\[:\]/g, ':').replace(/\bhxxp/gi, 'http').toLowerCase(); }
function palSearch(q){
  var toks = palNorm(q).split(/\s+/).filter(Boolean), by = {};
  if (!toks.length) return {toks:[], groups:[]};
  palIndex().forEach(function(r){
    for (var i = 0; i < toks.length; i++) if (r.x.indexOf(toks[i]) < 0) return;
    var tl = r.t.toLowerCase();
    (by[r.g] = by[r.g] || []).push({r:r, sc:toks.every(function(t){ return tl.indexOf(t) >= 0; }) ? 2 : 1});
  });
  return {toks:toks, groups:PAL_ORDER.filter(function(g){ return by[g]; }).map(function(g){
    var a = by[g].sort(function(x, y){ return y.sc - x.sc; });
    return {g:g, n:a.length, items:a.slice(0, 5).map(function(o){ return o.r; })}; })};
}
function palRender(){
  var q = $('palQ').value, res = palSearch(q), h = '';
  palFlat = [];
  if (!q.trim()) h = '<div class="ps-empty">Try a CVE, a file path, a command or an address from a log line:<div class="links">' +
    ['CVE-2024-3400', 'lina', 'disk0:', '/var/tmp', 'show memory region', 'UNC3886'].map(function(t){ return '<button type="button" class="chip btnchip" data-pq="' + esc(t) + '">' + esc(t) + '</button>'; }).join('') + '</div></div>';
  else if (!res.groups.length) h = '<div class="ps-empty">Nothing matches every word. Fewer words, or a shorter fragment of the path, usually finds it.</div>';
  else res.groups.forEach(function(g){
    h += '<div class="ps-g" role="group" aria-label="' + esc(g.g) + '"><div class="ps-gh"><span>' + esc(g.g) + '</span><span>' + g.n + '</span></div>';
    g.items.forEach(function(r){ palFlat.push(r);
      h += '<a class="ps-r" role="option" aria-selected="false" href="' + esc(r.href) + '"><span class="ps-t' + (r.mono ? ' m' : '') + '">' + hl(r.t, res.toks) + '</span><span class="ps-s">' + esc(r.s) + '</span></a>'; });
    if (g.n > 5 && PAL_LIB[g.g]) h += '<a class="ps-all" href="#' + PAL_LIB[g.g] + '?q=' + encodeURIComponent(palNorm(q).trim()) + '">All ' + g.n + ' in ' + esc(g.g) + ' &#8594;</a>';
    h += '</div>';
  });
  $('palList').innerHTML = h;
  $('palList').querySelectorAll('.ps-r').forEach(function(a, i){ a.id = 'pal-r' + i; });
  palI = 0; palMark();
}
function palMark(){
  var rows = $('palList').querySelectorAll('.ps-r');
  rows.forEach(function(a, i){ var on = i === palI; a.classList.toggle('on', on); a.setAttribute('aria-selected', String(on)); if (on) a.scrollIntoView({block:'nearest'}); });
  if (rows[palI]) $('palQ').setAttribute('aria-activedescendant', rows[palI].id); else $('palQ').removeAttribute('aria-activedescendant');
}
function palOpen(){
  if (!$('pal').hidden){ $('palQ').focus(); return; }
  palReturn = document.activeElement;
  $('pal').hidden = false; $('palScrim').hidden = false; document.body.classList.add('pal-open');
  $('palQ').value = ''; palRender(); $('palQ').focus();
}
function palClose(restore){
  if ($('pal').hidden) return;
  $('pal').hidden = true; $('palScrim').hidden = true; document.body.classList.remove('pal-open');
  if (restore !== false && palReturn && palReturn.isConnected && palReturn.focus) palReturn.focus({preventScroll:true});
  palReturn = null;
}
function palGo(href){ palClose(false); if (location.hash === href) route(); else location.hash = href; }
$('searchBtn').addEventListener('click', palOpen);
$('palScrim').addEventListener('click', function(){ palClose(); });
$('palQ').addEventListener('input', palRender);
$('palQ').addEventListener('keydown', function(ev){
  if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp'){ ev.preventDefault(); if (palFlat.length){ palI = (palI + (ev.key === 'ArrowDown' ? 1 : palFlat.length - 1)) % palFlat.length; palMark(); } }
  else if (ev.key === 'Enter'){ ev.preventDefault(); if (palFlat[palI]) palGo(palFlat[palI].href); }
  else if (ev.key === 'Escape'){ ev.preventDefault(); ev.stopPropagation(); palClose(); }
  else if (ev.key === 'Tab') ev.preventDefault();   // the dialog is modal; results move with the arrow keys
});
$('palList').addEventListener('click', function(ev){
  var c = ev.target.closest('[data-pq]'); if (c){ $('palQ').value = c.dataset.pq; palRender(); $('palQ').focus(); return; }
  var a = ev.target.closest('a'); if (a && ev.button === 0 && !ev.metaKey && !ev.ctrlKey && !ev.shiftKey){ ev.preventDefault(); palGo(a.getAttribute('href')); }
});

/* ---------------------------------------------------------------- response: picker, verdict lens, case, checklist */
var RESP_V = ['COMPROMISED', 'LIKELY-COMPROMISED', 'SUSPICIOUS', 'NO-INDICATORS-FOUND'];
var RV = '';   // analyzer verdict the responder picked; '' = all steps
var CASE = (store('edt-case') || '').trim();   // ticks are kept per case; no case keeps the original per-platform key
document.querySelectorAll('.rx').forEach(function(el){ el.innerHTML = rich(el.textContent); });
function tkey(stem){ return 'edt-resp-' + (CASE ? CASE + '|' : '') + stem; }
function respTicks(stem){ try{ return JSON.parse(store(tkey(stem)) || '{}') || {}; }catch(_){ return {}; } }
function tickTime(v){ return typeof v === 'string' ? v : ''; }   // ticks saved before times were kept are stored as 1
function appliesV(li, v){ var w = li.dataset.when; return !v || !w || w.split(',').indexOf(v) >= 0; }
function applies(li){ return appliesV(li, RV); }
function respRefresh(art){
  if (!art) return;
  var ticks = respTicks(art.dataset.resp), done = 0, all = 0, steps = art.querySelectorAll('.rstep');
  steps.forEach(function(li){
    var on = applies(li), cb = li.querySelector('.rchk'), t = ticks[li.dataset.k], tk = li.querySelector('.rtick');
    li.classList.toggle('off', !on);
    cb.checked = !!t; li.classList.toggle('done', cb.checked);
    if (tk) tk.textContent = tickTime(t) ? 'ticked ' + tickTime(t) : '';
    if (on){ all++; if (cb.checked) done++; }
  });
  art.querySelectorAll('.rnav .rc').forEach(function(c){
    var lis = art.querySelectorAll('.rphase[data-phase="' + c.dataset.phase + '"] .rstep');
    c.textContent = Array.prototype.filter.call(lis, applies).length;
  });
  document.querySelectorAll('.vbtn').forEach(function(bn){
    bn.querySelector('.vn').textContent = Array.prototype.filter.call(steps, function(li){ return appliesV(li, bn.dataset.v); }).length;
  });
  art.querySelector('.rdone').textContent = done; art.querySelector('.rall').textContent = all;
  art.querySelector('.rfor').textContent = CASE ? ' for ' + CASE : '';
  art.querySelector('.rbar').style.width = (all ? Math.round(done / all * 100) : 0) + '%';
  var ack = !!ticks._ack, ab = art.querySelector('.rack');
  if (ab) ab.checked = ack;
  art.querySelector('.dont').classList.toggle('acked', ack);
  document.querySelectorAll('.rcase').forEach(function(x){ if (document.activeElement !== x) x.value = CASE; });
}
function pickResp(stem){
  if (!document.querySelector('.resp[data-resp="' + stem + '"]')) return;
  pageAnchor.response = stem;
  document.querySelectorAll('.rbtn').forEach(function(b){ b.setAttribute('aria-pressed', String(b.dataset.resp === stem)); });
  document.querySelectorAll('.rsel').forEach(function(x){ x.value = stem; });
  document.querySelectorAll('.resp').forEach(function(s){ s.hidden = s.dataset.resp !== stem; });
  respRefresh(document.querySelector('.resp[data-resp="' + stem + '"]'));
}
function setVerdict(v){
  RV = v || '';
  document.querySelectorAll('.vbtn').forEach(function(b){ b.setAttribute('aria-pressed', String(b.dataset.v === RV)); });
  document.querySelector('.vhint').hidden = !RV;
  respRefresh(document.querySelector('.resp:not([hidden])'));
}
function goResp(stem){ pickResp(stem); writeHash(); }
document.querySelectorAll('.rbtn').forEach(function(b){ b.addEventListener('click', function(){ goResp(b.dataset.resp); }); });
document.querySelectorAll('.rsel').forEach(function(x){ x.addEventListener('change', function(){ goResp(x.value); }); });
document.querySelectorAll('.vbtn').forEach(function(b){ b.addEventListener('click', function(){ setVerdict(b.dataset.v); writeHash(); }); });
document.querySelectorAll('.resp').forEach(function(art){
  art.addEventListener('change', function(ev){
    var cb = ev.target.closest('.rchk'), ack = ev.target.closest('.rack');
    if (!cb && !ack) return;
    var t = respTicks(art.dataset.resp);
    if (ack){ if (ack.checked) t._ack = 1; else delete t._ack; }
    else if (cb.checked) t[cb.dataset.k] = new Date().toISOString().slice(11, 16) + ' UTC';
    else delete t[cb.dataset.k];
    store(tkey(art.dataset.resp), JSON.stringify(t)); respRefresh(art);
  });
  art.querySelector('.rcase').addEventListener('input', function(ev){
    CASE = ev.target.value.trim(); store('edt-case', CASE);
    document.querySelectorAll('.rcase').forEach(function(x){ if (x !== ev.target) x.value = CASE; });
    respRefresh(art);
  });
  art.querySelector('.rreset').addEventListener('click', function(){ store(tkey(art.dataset.resp), '{}'); respRefresh(art); toast('Ticks cleared' + (CASE ? ' for ' + CASE : '')); });
  art.querySelector('.rprint').addEventListener('click', function(){ window.print(); });
  art.querySelector('.rcopy').addEventListener('click', function(){
    var ticks = respTicks(art.dataset.resp), stamp = new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
    var md = ['# ' + art.dataset.name + ' - response checklist',
      [CASE ? 'Case ' + CASE : '', RV ? 'analyzer verdict ' + RV : '', 'exported ' + stamp].filter(Boolean).join(' · '),
      'From the edge-dfir-toolkit playbook: ' + location.href.split('#')[0] + '#response/' + art.dataset.resp, '', '## Do not'];
    art.querySelectorAll('.dont li').forEach(function(li){ md.push('- **' + li.querySelector('b').textContent.trim() + '** - ' + li.querySelector('.rdet').textContent.trim()); });
    art.querySelectorAll('.rphase').forEach(function(ph, i){
      var lis = Array.prototype.filter.call(ph.querySelectorAll('.rstep'), applies); if (!lis.length) return;
      md.push('', '## ' + (i + 1) + '. ' + ph.querySelector('h4').childNodes[0].textContent.trim());
      lis.forEach(function(li){
        var t = tickTime(ticks[li.dataset.k]), box = li.querySelector('.rchk').checked ? '[x]' : '[ ]', title = li.querySelector('b').textContent.trim();
        var det = li.classList.contains('cred') ? ' - ' + li.querySelector('.ca').textContent.replace(/^Do/, '').trim() : (li.querySelector('.rdet') ? ' - ' + li.querySelector('.rdet').textContent.trim() : '');
        md.push('- ' + box + ' ' + title + det + (t ? ' (' + t + ')' : ''));
      });
    });
    copyText(md.join('\n'), function(){ toast('Checklist copied as Markdown'); });
  });
  art.querySelectorAll('.rnav a').forEach(function(a){ a.addEventListener('click', function(ev){ ev.preventDefault(); var t = document.getElementById(a.dataset.jump); if (t) t.scrollIntoView({behavior:'smooth', block:'start'}); }); });
});

/* ---------------------------------------------------------------- collection plan picker + command builder */
var curP = D.profiles[0] ? D.profiles[0].name : null;
function pickProfile(name){
  if (!D.profiles.some(function(p){ return p.name === name; })) return;
  curP = name; pageAnchor.plans = name;
  document.querySelectorAll('.pbtn').forEach(function(b){ b.setAttribute('aria-pressed', String(b.dataset.profile === name)); });
  document.querySelectorAll('.plan').forEach(function(s){ s.hidden = s.dataset.profile !== name; });
  renderVars(); build();
}
document.querySelectorAll('.pbtn').forEach(function(b){ b.addEventListener('click', function(){
  history.replaceState(null, '', '#plans/' + b.dataset.profile); pickProfile(b.dataset.profile); }); });
function prof(){ return D.profiles.filter(function(p){ return p.name === curP; })[0]; }
function renderVars(){
  var box = $('b-vars'); box.innerHTML = '';
  prof().vars.forEach(function(v){
    var l = document.createElement('label'); l.textContent = '--var ' + v;
    var i = document.createElement('input'); i.dataset['var'] = v; i.autocomplete = 'off'; i.placeholder = 'value';
    i.addEventListener('input', build); l.appendChild(i); box.appendChild(l);
  });
}
function sh(s){ return /^[\w@%+=:,./-]+$/.test(s) ? s : "'" + s.replace(/'/g, "'\\''") + "'"; }
function val(id, dflt){ var v = $(id).value.trim(); return v || dflt; }
function build(){
  var p = prof(); if (!p) return;
  var bundle = $('b-bundle').checked, bg = $('b-bg').checked, one = $('b-one').checked;
  var parts = ['python -m edgetriage collect', '--profile ' + p.name, '--case-id ' + sh(val('b-case', 'IR-2026-001'))];
  if (p.ssh){ parts.push('--host ' + sh(val('b-host', '<device>'))); parts.push('--user ' + sh(val('b-user', '<readonly-user>'))); }
  else parts.push('--replay ./' + p.name + '-checklist');
  var op = $('b-op').value.trim(); if (op) parts.push('--operator ' + sh(op));
  parts.push('--rebooted ' + $('b-reboot').value, '--patched ' + $('b-patch').value);
  document.querySelectorAll('#b-vars input').forEach(function(i){ if (i.value.trim()) parts.push('--var ' + sh(i.dataset['var'] + '=' + i.value.trim())); });
  if (bundle || bg) parts.push('--allow-bundle'); if (bg) parts.push('--break-glass');
  $('b-out').textContent = parts.join(one ? ' ' : ' \\\n    ');
  var n = 0, off = 0;
  document.querySelectorAll('.plan[data-profile="' + p.name + '"] .step').forEach(function(r){
    var imp = r.dataset.impact, on = imp === 'none' || (imp === 'vendor-bundle' && (bundle || bg)) || (imp === 'break-glass' && bg);
    r.classList.toggle('off', !on); if (on) n++; else off++;
  });
  $('b-warn').hidden = !!p.validated;
  $('b-sum').textContent = n + ' step(s) will run' + (off ? ', ' + off + ' withheld until you allow them' : '') + '.'
    + (p.ssh ? '' : ' There is nothing to connect to: the steps are recorded as manual.');
}
['b-case','b-host','b-user','b-op','b-reboot','b-patch','b-bundle','b-bg','b-one'].forEach(function(id){
  var el = $(id); el.addEventListener('input', build); el.addEventListener('change', build); });
if (curP){ renderVars(); build(); }
route();
})();
"""


def page(d: dict) -> tuple[str, dict]:
    data = build_data(d)
    n_det = len(data["detections"])
    unv = {n: sum(1 for i in data[n] if i.get("unv")) for n in LIBS}
    # Knowledge first - what each trace proves, per platform, what fires, who, how
    # to respond. How to operate the toolkit (plans, rules) and the reference
    # material sit after the divider; Start links every platform's plan directly.
    tabs = [("start", "Start", None), ("artifacts", "Artifacts", len(data["artifacts"])),
            ("platforms", "Platforms", len(data["platforms"])), ("cves", "CVEs", len(data["cves"])),
            ("detections", "Detections", n_det),
            ("hunts", "Hunts", len(data["hunts"])), ("intel", "Threat intel", len(data["intel"])), ("response", "Response", len(d["response"])),
            ("hardening", "Hardening", len(data["hardening"])), None,
            ("plans", "Collection plans", len(d["profiles"])), ("coverage", "Coverage", None), ("guide", "Guide", None)]
    tabbar = "".join('<span class="tabsep" aria-hidden="true"></span>' if t is None else
                     f'<button type="button" role="tab" data-tab="{t[0]}" aria-selected="false">{t[1]}'
                     + (f'<span class="n">{t[2]}</span>' if t[2] is not None else "") + "</button>" for t in tabs)
    ctx = {"cves": {x["id"] for x in data["cves"]},
           "platforms": {p["id"]: p for p in data["platforms"]}, "notes_seen": set()}
    guide_html = markdown(d["guide"], ctx)
    data["guideNotes"] = sorted(ctx["notes_seen"])
    data["toc"] = guide_toc(d["guide"])
    panels = f'<section class="panel" id="tab-start" role="tabpanel" hidden>{render_start(d, data)}</section>'
    n_sig = sum(1 for x in data["detections"] if x["sigma"])
    panels += "".join(lib_panel(n, unv[n], n == "artifacts", n_sig) for n in LIBS)
    panels += (f'<section class="panel" id="tab-plans" role="tabpanel" hidden>{render_plans(d)}</section>'
               f'<section class="panel" id="tab-response" role="tabpanel" hidden>{render_response(d)}</section>'
               f'<section class="panel" id="tab-coverage" role="tabpanel" hidden>{render_coverage(d, data)}</section>'
               f'<section class="panel" id="tab-guide" role="tabpanel" hidden><article class="guide">{guide_html}</article></section>')
    built = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    icon = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E"
            "%3Crect width='32' height='32' rx='7' fill='%235e3a24'/%3E%3Cpath d='M8 22V10h10M8 16h8M8 22h10' "
            "stroke='%23fff' stroke-width='2.6' fill='none' stroke-linecap='round'/%3E%3Cpath d='M21 10l4 6-4 6' "
            "stroke='%23ddc4b0' stroke-width='2.6' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E")
    html_doc = f"""<!doctype html>
<html lang="en" data-theme="light"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Edge DFIR Toolkit</title>
<meta name="description" content="Forensic triage for compromised VPN concentrators, firewalls and gateways: artifact library, collection plans, detections, threat intel and response playbooks.">
<meta name="color-scheme" content="light dark">
<link rel="icon" href="{icon}">
<style>{CSS}</style></head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="hdr"><div class="hdr-in">
  <div class="hdr-top">
    <a class="brand" href="#start" aria-label="Edge DFIR Toolkit: start"><span class="dot"></span><h1>Edge DFIR Toolkit</h1></a><span class="pill wide-only">v{e(__version__)} &#183; Apache-2.0</span>
    <button type="button" class="hsearch" id="searchBtn" aria-haspopup="dialog" aria-keyshortcuts="/ Control+K Meta+K"><span class="glyph" aria-hidden="true">&#8981;</span><span class="hs-l">Search everything: a CVE, path, command, address or actor</span><span class="hs-s">Search</span><kbd aria-hidden="true">/</kbd></button>
    <span class="hdr-right"><a class="hbtn wide-only" href="{REPO_URL}" rel="noopener">GitHub &#8599;</a>
      <button type="button" class="hbtn" id="themeBtn">Theme</button></span>
  </div>
  <nav class="tabs" role="tablist" aria-label="Sections">{tabbar}</nav>
</div></header>
<div class="shell">
  <aside class="rail" aria-label="Filters">
    <div class="railhead"><b id="railTitle">Filters</b><button type="button" class="hbtn" id="railToggle">Filters</button><a id="railReset" class="lnkbtn" href="#">reset</a></div>
    <div id="rail"></div>
  </aside>
  <main id="main"><noscript><p class="empty">The libraries need JavaScript. Everything on this page is also in the repository as YAML, Sigma and YARA.</p></noscript>{panels}</main>
</div>
<div class="scrim" id="scrim" hidden></div>
<aside class="drawer" id="drawer" hidden role="dialog" aria-modal="true" aria-labelledby="dTitle">
  <div class="dhead"><div><span class="id" id="dId"></span><h2 id="dTitle" tabindex="-1"></h2></div>
    <div class="dacts"><span class="dpos" id="dPos"></span><button type="button" id="dPrev" title="Previous (&#8592; or k)" aria-label="Previous record">&#8592;</button><button type="button" id="dNext" title="Next (&#8594; or j)" aria-label="Next record">&#8594;</button>
      <button type="button" id="dLink">Copy link</button><button type="button" id="dWide">Wider</button><button type="button" id="dClose" aria-label="Close (Esc)">&#215;</button></div></div>
  <div class="dbody" id="dBody"></div>
</aside>
<div class="toast" id="toast" role="status" hidden></div>
<div class="ps-scrim" id="palScrim" hidden></div>
<div class="ps-box" id="pal" role="dialog" aria-modal="true" aria-label="Search everything" hidden>
  <div class="ps-in"><span class="glyph" aria-hidden="true">&#8981;</span><input id="palQ" type="text" role="combobox" aria-expanded="true" aria-controls="palList" aria-autocomplete="list" autocomplete="off" spellcheck="false" placeholder="Search all libraries, plans, the guide and the KEV ledger" aria-label="Search everything"><kbd>Esc</kbd></div>
  <div class="ps-body" id="palList" role="listbox" aria-label="Results"></div>
  <div class="ps-foot"><span>&#8593; &#8595; move &#183; Enter open &#183; Esc close</span><span>Indicator values are matched refanged; paste an address as it appears in a log.</span></div>
</div>
<footer>
  {len(data['platforms'])} platforms &#183; {len(data['artifacts'])} artifacts &#183; {len(d['profiles'])} collection profiles &#183; {n_det} detections in {len(d['packs'])} packs &#183; {len(d['rules'])} rule files.
  Built from the repository on {built}; every figure is computed from the catalog, profiles, packs, rules and intel at build time.
  Detection content is Sigma and YARA only.<br>
  Built and maintained by <a href="{AUTHOR_URL}" rel="noopener" target="_blank">{e(AUTHOR)}</a> (LinkedIn) &#183; published by <a href="{FIRM_URL}" rel="noopener" target="_blank">{e(FIRM)}</a> (LinkedIn) &#183; <a href="{REPO_URL}" rel="noopener">source on GitHub</a>.
  Independent research, not affiliated with or endorsed by any former employer or by any vendor whose products it covers.
  Keyboard: <kbd>/</kbd> or <kbd>Ctrl</kbd> <kbd>K</kbd> search everything, <kbd>&#8592;</kbd> <kbd>&#8594;</kbd> step through records, <kbd>Esc</kbd> close.
</footer>
<script type="application/json" id="data">{js_data(data)}</script>
<script>{JS}</script>
</body></html>
"""
    return html_doc, data


# --------------------------------------------------------------------------- check
def check(d: dict, doc: str, data: dict) -> list[str]:
    problems = []
    ids = re.findall(r'\sid="([^"]+)"', doc)
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        problems.append(f"duplicate element ids: {dupes}")
    bad = [i for i in ids if not re.fullmatch(r"[A-Za-z0-9_.:-]+", i)]
    if bad:
        problems.append(f"ids that are not URL-safe: {bad}")
    lib_ids = {n: {str(i["id"]) for i in data[n]} for n in LIBS}
    plat = lib_ids["platforms"]
    for p in d["packs"]:
        for pid in p["platforms"]:
            if pid not in plat:
                problems.append(f"{p['id']} names platform {pid} not in catalog")
    for c in d["catalog"]:
        if c.get("profile") and c["profile"] not in {p.name for p in d["profiles"]}:
            problems.append(f"{c['id']} names profile {c['profile']} that does not exist")
    for r in d["rules"]:
        if r["dir"] not in RULE_DIR_PLATFORM:
            problems.append(f"rule directory {r['dir']} has no platform in RULE_DIR_PLATFORM")
    noabbr = sorted(plat - set(PLATFORM_ABBR))
    if noabbr:
        problems.append(f"no short name in PLATFORM_ABBR for {noabbr}")
    missing = sorted(plat - set(data.get("guideNotes", [])))
    if missing:
        problems.append(f"investigation guide has no platform note for {missing} (see NOTE_PLATFORM)")
    if len(lib_ids["artifacts"]) != len(data["artifacts"]):
        problems.append("artifact ids are not unique")
    pack_ids = {p["id"] for p in data["packs"]}

    def check_link(href: str, where: str):
        m = re.fullmatch(r"#([a-z]+)(?:/([^?]+))?(?:\?(.*))?", html.unescape(href))
        if not m:
            return
        tab, anchor, query = m.groups()
        if not anchor and not query and f'id="{tab}"' in doc:
            return  # an in-page anchor such as the skip link
        if tab not in LIBS + ["start", "plans", "response", "coverage", "guide", "packs", "rules"]:  # rules -> detections
            problems.append(f"{where}: link to unknown tab #{tab}")
            return
        if anchor:
            if tab in LIBS and anchor not in lib_ids[tab]:
                problems.append(f"{where}: dangling link #{tab}/{anchor}")
            if tab == "packs" and anchor not in pack_ids:
                problems.append(f"{where}: dangling link #packs/{anchor}")
            if tab in ("plans", "response") and f'id="{tab[:-1] if tab == "plans" else tab}-{anchor}"' not in doc:
                problems.append(f"{where}: dangling link #{tab}/{anchor}")
            if tab == "guide" and f'id="g-{anchor}"' not in doc:
                problems.append(f"{where}: dangling link #guide/{anchor}")
            if tab == "coverage" and f'id="cov-{anchor}"' not in doc:   # #coverage/kev scrolls to #cov-kev
                problems.append(f"{where}: dangling link #coverage/{anchor}")
        if query:
            if tab not in LIBS:
                problems.append(f"{where}: query on non-library tab #{tab}")
                return
            for kv in query.split("&"):
                k, _, v = kv.partition("=")
                if k not in FACET_KEYS[tab] + ["q", "unv"]:
                    problems.append(f"{where}: #{tab} has no facet {k}")
                vals = v.split(",")
                if k == "platform" and not set(vals) <= plat | {"ALL"}:
                    problems.append(f"{where}: unknown platform in {href}")
                if k == "pack" and not set(vals) <= pack_ids:
                    problems.append(f"{where}: unknown pack in {href}")

    for href in set(re.findall(r'href="(#[^"]+)"', doc.split('<script type="application/json"')[0])):
        check_link(href, "page")

    def walk(o, path="data"):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == "href" and isinstance(v, str):
                    check_link(v, path)
                else:
                    walk(v, f"{path}.{k}")
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, f"{path}[{i}]")
    walk(data)
    for a in data["artifacts"]:
        for x in a["detections"]:
            if x not in {y["id"] for y in data["detections"]}:
                problems.append(f"{a['id']} names detection {x} that does not exist")
    for i in data["intel"]:
        for x in i.get("detections", []):
            if x not in {y["id"] for y in data["detections"]}:
                problems.append(f"{i['id']} names detection {x} that does not exist")
        for x in i.get("implants", []) + (i.get("actors", []) if i["kind"] == "implant" else []):
            if x not in lib_ids["intel"]:
                problems.append(f"{i['id']} names {x} that is not in the intel library")
    for p in data["platforms"]:
        if p["profile"] and f'id="plan-{p["profile"]}"' not in doc:
            problems.append(f"{p['id']} links to plan {p['profile']} that is not rendered")
        if p["response"] and f'id="response-{p["response"]}"' not in doc:
            problems.append(f"{p['id']} links to response {p['response']} that is not rendered")
    data_block = re.search(r'<script type="application/json" id="data">(.*?)</script>', doc, re.S)
    if not data_block:
        problems.append("data block missing or closed early")
    else:
        json.loads(data_block.group(1).replace("<\\/", "</"))
    if re.search(r"<script[^>]+src=", doc) or re.search(r"<link[^>]+stylesheet", doc):
        problems.append("page must not load external scripts or stylesheets")
    return problems


def main() -> int:
    d = load()
    doc, data = page(d)
    problems = check(d, doc, data)
    if problems:
        for p in problems:
            print(f"FAIL  {p}")
        return 1
    if "--check" in sys.argv:
        print(f"OK  site data contract holds ({len(doc) // 1024} KiB, {len(data['artifacts'])} artifacts, "
              f"{len(data['detections'])} detections, {len(data['intel'])} intel records)")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(doc, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(doc) // 1024} KiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
