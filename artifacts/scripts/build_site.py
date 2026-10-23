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
    "artifacts": ["platform", "class", "volatility", "value", "evidence", "kind", "confidence", "seen"],
    "platforms": ["vendor", "shell", "memory", "profile"],
    "detections": ["platform", "runs", "pack", "tier", "evidence", "type", "attack", "cve", "actor"],
    "intel": ["kind", "platform", "motivation", "type", "resides", "reboot", "coverage", "reporter"],
    "hardening": ["platform", "category", "priority", "confidence"],
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


def refs_of(items) -> list[dict]:
    return [{"title": r["title"], "url": r["url"]} for r in items or []]


# --------------------------------------------------------------------------- load
def load() -> dict:
    catalog = sorted((yaml.safe_load(p.read_text()) for p in (ROOT / "artifacts" / "catalog").glob("*.yml")),
                     key=lambda c: c["id"])
    profiles = sorted((load_profile(p) for p in available_profiles().values()), key=lambda p: p.platform_id)
    packs = [yaml.safe_load(p.read_text()) for p in sorted((ROOT / "artifacts" / "packs").glob("*.yml"))]
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
    actors = sorted((yaml.safe_load(f.read_text()) for f in (intel / "actors").glob("*.yml")), key=lambda a: a["id"])
    implants = sorted((yaml.safe_load(f.read_text()) for f in (intel / "implants").glob("*.yml")), key=lambda i: i["id"])
    response = {f.stem: yaml.safe_load(f.read_text()) for f in sorted((ROOT / "artifacts" / "response").glob("*.yml"))}
    hardening = {f.stem: yaml.safe_load(f.read_text()) for f in sorted((ROOT / "artifacts" / "hardening").glob("*.yml"))}
    return {"catalog": catalog, "profiles": profiles, "packs": packs, "rules": rules, "guide": guide,
            "actors": actors, "implants": implants, "response": response, "hardening": hardening}


# --------------------------------------------------------------------------- data for the libraries
def build_data(d: dict) -> dict:
    prof = {p.name: p for p in d["profiles"]}
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
            })
    det_cves = {c for x in dets for c in x["cves"]}

    def seen_links(names) -> list[dict]:
        out = []
        for n in names or []:
            lk = intel_links([n])[0]
            if "href" not in lk and re.fullmatch(r"CVE-\d{4}-\d+", n) and n in det_cves:
                lk = {"label": n, "href": f"#detections?cve={n}"}
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
                "detections": [x["id"] for x in dets if c["id"] in x["platforms"] and cb in [s["id"] for s in x["steps"]]],
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
            "confidence": a["link_confidence"],
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
            "references": refs_of(i.get("references")),
        })

    # Hardening: baseline (platform ALL) first, then per platform. A CVE or actor
    # the source names becomes a link when the toolkit has something on it.
    def blunt_links(names) -> list[dict]:
        out = []
        for n in names or []:
            if re.fullmatch(r"CVE-\d{4}-\d+", n):
                out.append({"label": n, "href": f"#detections?cve={n}"} if n in det_cves else {"label": n})
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
                "stem": stem,
            })

    return {"platforms": platforms, "artifacts": artifacts, "detections": dets, "packs": packs, "rules": rules,
            "intel": intel, "hardening": hard, "facetKeys": FACET_KEYS, "repo": REPO_URL,
            "profiles": [{"name": p.name, "ssh": "ssh" in p.transports,
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
                  lambda m: f'<a href="#detections?cve={m.group(1)}">{m.group(1)}</a>' if m.group(1) in ctx["cves"] else m.group(1), h)


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


LIB_COPY = {
    "artifacts": ("Artifacts", "Every artifact on every platform: what it proves, how long it lasts and the step that collects it. "
                  "Filter, open a row for the full record, and export what you picked as a collection checklist.",
                  "Search locators, descriptions, implants, CVEs..."),
    "platforms": ("Platforms", "What a responder can reach on each platform, how, and what disappears if you wait.",
                  "Search platforms, vendors, products..."),
    "detections": ("Detections", "Every detection runs in the analyzer against evidence collected from the device, and "
                   "reports hit, no hit or not evaluated - never a pass. Where the same indicator can be watched in your SIEM, "
                   "the detection carries its Sigma rule; YARA rules scan recovered files. Sigma rules convert with "
                   "sigma convert -t <backend>; no vendor query dialect is shipped.", "Search detections, patterns, rules, CVEs, ATT&CK..."),
    "rules": ("Rules", "Vendor-neutral Sigma and YARA. Convert Sigma for your SIEM with sigma convert -t <backend>; "
              "no vendor query dialect is shipped.", "Search rules, files, tags..."),
    "hardening": ("Hardening", "Controls that would have prevented or blunted the exploitation waves these platforms "
                  "have seen - first among them, keeping management interfaces off the internet. The baseline applies to "
                  "every platform; each control cites the vendor or government source it comes from.",
                  "Search controls, CVEs, settings..."),
    "intel": ("Threat intel", "Attribution is reported, never computed. Each actor carries our link confidence (how well "
              "sourced the link is) beside the reporting party's own words. Clusters are merged only where the reporters "
              "themselves equate them.", "Search actors, implants, aliases, reporters..."),
}


def lib_panel(name: str, n_unv: int, rows: bool) -> str:
    title, lede, ph = LIB_COPY[name]
    unv = (f'<button type="button" class="tgl unvT" aria-pressed="false" title="Only records nobody has confirmed on a device">'
           f'Unverified only <span class="n">{n_unv}</span></button>') if n_unv else ""
    cmp_ = '<button type="button" class="tgl cmpT" aria-pressed="false">Compact rows</button>' if rows else ""
    return f'''<section class="panel lib" id="tab-{name}" data-lib="{name}" role="tabpanel" hidden>
  <div class="lhead"><h2>{e(title)}</h2><p class="lede">{e(lede)}</p></div>
  <div class="controls">
    <label class="search"><span class="glyph" aria-hidden="true">&#8981;</span><input type="search" class="q" placeholder="{e(ph)}" aria-label="Search {e(title.lower())}" autocomplete="off"></label>
    {unv}{cmp_}
    <span class="exp"><span class="lbl">Export</span><button type="button" class="tgl" data-exp="csv">CSV</button><button type="button" class="tgl" data-exp="json">JSON</button></span>
  </div>
  <div class="meta"><span class="count"></span><span class="active"></span><span class="picked"></span></div>
  <div class="summary"></div>
  <div class="results"></div>
</section>'''


def render_plans(d: dict) -> str:
    picker, sections = [], []
    for i, p in enumerate(d["profiles"]):
        picker.append(f'<button type="button" class="pbtn" data-profile="{e(p.name)}" aria-pressed="{str(i == 0).lower()}">{e(short(p.display))}</button>')
        groups = []
        for tier in TIER_ORDER:
            steps = [s for s in p.steps if s.tier == tier]
            if not steps:
                continue
            rows = []
            for s in steps:
                cmd = s.cmd or s.list_cmd
                what = copyable(cmd) if cmd else '<span class="muted">manual</span>'
                instr = (f'<details><summary>Instructions</summary><pre class="instr">{e(s.instructions.strip())}</pre></details>'
                         if s.instructions else "")
                needs = f'<div class="needs">needs <code>--var {e(", ".join(s.requires_vars))}</code></div>' if s.requires_vars else ""
                rows.append(f'''<tr class="step imp-{e(s.impact)}{' unv' if s.unverified else ''}" data-impact="{e(s.impact)}">
  <td class="id">{e(s.id)}</td><td>{impact_badge(s.impact)}<div class="kind">{e(s.kind)}</div></td>
  <td>{what}{needs}<div class="purpose">{e(s.purpose)}</div>{instr}</td>
  <td>{conf_badge(s.confidence, s.unverified)}</td></tr>''')
            groups.append(f'<tr class="tierrow"><th colspan="4"><span class="tchip">{e(tier)}</span> {e(TIER_LABEL[tier])} <span class="muted">- {e(TIER_CLASS[tier])}</span></th></tr>' + "".join(rows))
        sections.append(f'''
<section class="plan" data-profile="{e(p.name)}" id="plan-{e(p.name)}"{'' if i == 0 else ' hidden'}>
  <div class="plan-h"><div><span class="id">{e(p.platform_id)}</span> <h3>{e(p.display)}</h3></div>
    <div class="links"><a class="chip link" href="#platforms/{e(p.platform_id)}">platform entry</a><a class="chip link" href="#artifacts?platform={e(p.platform_id)}">artifacts</a></div></div>
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
  <label>Case id<input id="b-case" value="IR-2026-001" autocomplete="off"></label>
  <label>Device address<input id="b-host" placeholder="192.0.2.10" autocomplete="off"></label>
  <label>Read-only user<input id="b-user" placeholder="ir-readonly" autocomplete="off"></label>
  <label>Operator<input id="b-op" placeholder="your name" autocomplete="off"></label>
  <div class="vars" id="b-vars"></div>
  <label>Rebooted since incident<select id="b-reboot"><option>unknown</option><option>no</option><option>yes</option></select></label>
  <label>Upgraded since incident<select id="b-patch"><option>unknown</option><option>no</option><option>yes</option></select></label>
  <label class="tog"><input type="checkbox" id="b-bundle"> Allow vendor bundles <span class="muted">(writes to the device)</span></label>
  <label class="tog"><input type="checkbox" id="b-bg"> Break-glass <span class="muted">(runs last, asks for confirmation)</span></label>
  <div class="codewrap"><button class="copy" type="button" id="b-copy">Copy</button><pre><code id="b-out"></code></pre></div>
  <div class="muted" id="b-sum"></div>
</aside>'''
    return f'''<div class="lhead"><h2>Collection plans</h2><p class="lede">Every profile in order of volatility. Bundle and break-glass rows stay greyed out until you allow them in the builder, exactly as the collector behaves.</p></div>
<div class="picker">{"".join(picker)}</div>
<div class="planwrap"><div class="plans">{"".join(sections)}</div>{builder}</div>'''


def hard_link(pid: str, d: dict) -> str:
    n = sum(len(h["controls"]) for h in d["hardening"].values() if h["platform_id"] == pid)
    return f'<a class="chip link" href="#hardening?platform={pid}">hardening ({n})</a>' if n else ""


def render_response(d: dict) -> str:
    """Containment and recovery, ordered: preserve, contain, rotate, eradicate,
    recover, verify. Guidance a human acts on, not automation."""
    picker, secs = [], []
    for n, (stem, r) in enumerate(sorted(d["response"].items(), key=lambda kv: kv[1]["platform_id"])):
        picker.append(f'<button type="button" class="rbtn" data-resp="{e(stem)}" aria-pressed="{str(n == 0).lower()}">{e(short(r["name"]))}</button>')

        def steps(key):
            out = []
            for st in r.get(key, []):
                detail = f'<div class="muted">{e(st["detail"])}</div>' if st.get("detail") else ""
                when = f'<div class="when">applies to: {e(st["when"])}</div>' if st.get("when") else ""
                out.append(f'<li><b>{e(st["step"])}</b>{detail}{when}</li>')
            return "".join(out)
        cred = "".join(f'<tr><td><b>{e(c["what"])}</b></td><td class="muted">{e(c["why"])}</td><td>{e(c["action"])}</td></tr>'
                       for c in r.get("credential_exposure", []))
        dont = "".join(f'<li><b>{e(x["action"])}</b><div class="muted">{e(x["because"])}</div></li>' for x in r.get("do_not", []))
        vg = "".join(f'<li><a href="{e(x["url"])}" rel="noopener">{e(x["title"])}</a></li>' for x in r.get("vendor_guidance", []))
        refs = "".join(f'<li><a href="{e(x["url"])}" rel="noopener">{e(x["title"])}</a></li>' for x in r["references"])
        secs.append(f'''
<article class="card resp" id="response-{e(stem)}" data-resp="{e(stem)}"{'' if n == 0 else ' hidden'}>
  <header class="card-h"><div><span class="id">{e(r['platform_id'])}</span><h3>{e(r['name'])}</h3></div>
    <div class="badges"><a class="chip link" href="#platforms/{e(r['platform_id'])}">platform entry</a>{hard_link(r['platform_id'], d)}{conf_badge(r.get('confidence', 'medium'), False)}</div></header>
  <div class="dont top"><h4>Do not</h4><ul class="plain">{dont}</ul></div>
  <div class="phases">
    <div class="phase"><h4><span class="pn">1</span>Preserve first</h4><ol>{steps("preserve_first")}</ol></div>
    <div class="phase"><h4><span class="pn">2</span>Contain</h4><ol>{steps("contain")}</ol></div>
  </div>
  <h4><span class="pn">3</span>Credential exposure - rotate</h4>
  <div class="scroll"><table class="tbl"><thead><tr><th>What</th><th>Why it is exposed</th><th>Action</th></tr></thead><tbody>{cred}</tbody></table></div>
  <div class="phases">
    <div class="phase"><h4><span class="pn">4</span>Eradicate</h4><ol>{steps("eradicate")}</ol></div>
    <div class="phase"><h4><span class="pn">5</span>Recover</h4><ol>{steps("recover")}</ol></div>
    <div class="phase"><h4><span class="pn">6</span>Verify</h4><ol>{steps("verify")}</ol></div>
  </div>
  {f'<p class="note">{e(r["notes"].strip())}</p>' if r.get('notes') else ''}
  <details><summary>Vendor guidance and references</summary><ul>{vg}{refs}</ul></details>
</article>''')
    return f'''<div class="lhead"><h2>Response</h2><p class="lede">Containment and recovery for each platform, in the order that protects evidence: <b>preserve</b>, contain, rotate credentials, eradicate, recover, verify. The do-not list comes first because most evidence is destroyed by a well-meant action taken too early. Guidance a person acts on after triage - the toolkit never contains or remediates on its own.</p></div>
<div class="picker">{"".join(picker)}</div>
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


def vol_bar(arts: list[dict]) -> str:
    c = {v: sum(1 for a in arts if a["volatility"] == v) for v in VOL_ORDER}
    n = sum(c.values()) or 1
    segs = "".join(f'<span class="vb vb-{v}" style="flex:{c[v]}" title="{c[v]} {v}"></span>' for v in VOL_ORDER if c[v])
    live = round(100 * c["live"] / n)
    return (f'<div class="vbwrap" title="{c["live"]} live, {c["rotating"]} rotating, {c["stable"]} stable, {c["off-box"]} off-box">'
            f'<div class="vbar2">{segs}</div><span class="vbl">{live}% of its artifacts are live - gone at reboot</span></div>')


def render_start(d: dict, data: dict) -> str:
    """The landing page for someone who has never seen the site: which device
    and how much of its evidence is volatile, what not to do first, how a
    triage runs, the order the collector follows, and what the badges mean."""
    tiles = []
    for p in data["platforms"]:
        links = []
        links.append(f'<a href="#artifacts?platform={p["id"]}">Artifacts <span class="n">{p["n_art"]}</span></a>')
        if p["n_det"]:
            links.append(f'<a href="#detections?platform={p["id"]}">Detections <span class="n">{p["n_det"]}</span></a>')
        if p["profile"]:
            links.append(f'<a href="#plans/{e(p["profile"])}">Collect</a>')
        if p["response"]:
            links.append(f'<a href="#response/{e(p["response"])}">Respond</a>')
        if p["n_hard"]:
            links.append(f'<a href="#hardening?platform={p["id"]}">Harden</a>')
        arts = [a for a in data["artifacts"] if a["platform"] == p["id"]]
        tiles.append(
            f'<div class="ptile"><a class="ptile-h" href="#platforms/{p["id"]}"><span class="id">{p["id"]}</span>'
            f'<b>{e(p["short"])}</b><span class="muted small">{e(p["vendor"])}</span></a>'
            f'{vol_bar(arts)}<div class="ptile-l">{"".join(links)}</div></div>')
    vol_key = "".join(f'<span class="vk"><span class="vb vb-{v}"></span>{v}</span>' for v in VOL_ORDER)

    flow = "".join(f'<li><a href="{href}"><span class="fn">{i}</span><b>{e(t)}</b><span>{e(txt)}</span></a></li>'
                   for i, (t, txt, href) in enumerate(FLOW, 1))

    steps_per_tier = {t: sum(1 for pr in d["profiles"] for s in pr.steps if s.tier == t) for t in TIER_ORDER}
    groups = []
    for title, sub, cls, tiers in OOV_GROUPS:
        chips_ = "".join(f'<li title="{steps_per_tier[t]} steps across all profiles"><span class="tc">{t}</span>{e(TIER_LABEL[t])}</li>'
                         for t in tiers)
        groups.append(f'<div class="oovg {cls}" style="flex:{len(tiers) + 1}"><div class="oovh"><b>{e(title)}</b>'
                      f'<span>{e(sub)}</span></div><ol>{chips_}</ol></div>')

    legend = "".join(
        f'<div class="lg"><h4>{e(title)}</h4><dl>'
        + "".join(f'<dt><span class="badge {c}">{e(t)}</span></dt><dd>{e(m)}</dd>' for c, t, m in rows)
        + "</dl></div>" for title, rows in LEGEND)
    verdicts = "".join(f'<span class="verdict v-{v.lower()}">{v}</span>' for v in START_VERDICTS)
    n = {k: len(data[k]) for k in ("artifacts", "detections", "intel", "rules")}
    n_prof = sum(1 for p in data["platforms"] if p["profile"])
    return "".join([
        '<div class="start">',
        '<div class="hero"><h2>Triage a compromised edge device</h2>',
        '<p class="lede">For responders who know DFIR and need the parts that are different on a VPN concentrator, '
        'firewall or gateway: what each trace proves and how long it lasts, what to collect and in what order, what '
        'the detections look for, and how to contain and recover without destroying the evidence.</p></div>',

        '<div class="sechead"><h3 class="sect">1. Which device?</h3>',
        f'<div class="vkey"><span class="muted small">Each bar is that platform&#39;s artifacts by how long they last:</span>{vol_key}</div></div>',
        f'<div class="ptiles">{"".join(tiles)}</div>',

        '<h3 class="sect">2. Before you touch it</h3>',
        '<div class="callout"><ol class="cols2">',
        "<li><b>Do not reboot, upgrade, factory-reset or run the vendor&#39;s external integrity tool.</b> "
        "Each destroys evidence - the red share of every bar above - and several implants were built to survive "
        "or fool exactly those.</li>",
        "<li><b>Pull the off-box copies first</b> - SIEM syslog, NetFlow for the management interface, IdP and "
        "MFA logs. A gap in them is itself evidence.</li>",
        "<li><b>Record whether it has rebooted or been upgraded</b> since the suspected window. It changes what "
        "the report can claim.</li>",
        "<li><b>Use a read-only account</b> where the platform has one, and pin the host key.</li>",
        "</ol></div>",

        '<h3 class="sect">3. How a triage runs</h3>',
        f'<ol class="flowd" aria-label="Triage workflow">{flow}</ol>',
        f'<p class="muted small verdline">The verdict is one of {verdicts} - there is no &quot;clean&quot;. '
        'The <a href="#guide/analysis">guide</a> shows which hits produce which verdict.</p>',
        '<details class="fold"><summary>The commands</summary>',
        '<div class="codewrap"><button class="copy" type="button">Copy</button><pre><code>'
        'python -m edgetriage plan    --profile &lt;platform&gt;          # read it first\n'
        'python -m edgetriage collect --profile &lt;platform&gt; --host &lt;ip&gt; --user &lt;ro-user&gt; \\\n'
        '                             --case-id IR-2026-001 --rebooted no --patched no\n'
        'python -m edgetriage ingest  cases/IR-2026-001 --label tsf --bundle &lt;file&gt;\n'
        'python -m edgetriage analyze cases/IR-2026-001</code></pre></div></details>',

        '<h3 class="sect">4. The order the collector follows</h3>',
        '<p class="muted small">Every profile runs in this order and refuses to move a step that can reload the '
        'device ahead of the memory steps. Hover a tier for how many steps use it.</p>',
        f'<div class="oov"><div class="oovarrow" aria-hidden="true"><span>collected first</span><span>last</span></div>'
        f'<div class="oovgs">{"".join(groups)}</div></div>',

        '<h3 class="sect">Reading the badges</h3>',
        f'<div class="legend-grid">{legend}</div>',
        '<h3 class="sect">What is here</h3><div class="tiles">',
        f'<a class="tile" href="#artifacts"><b>{n["artifacts"]}</b><span>artifacts - what each trace proves and how long it lasts</span></a>',
        f'<a class="tile" href="#detections"><b>{n["detections"]}</b><span>detections in {len(d["packs"])} packs, each able to say &quot;not evaluated&quot;</span></a>',
        f'<a class="tile" href="#intel"><b>{n["intel"]}</b><span>actors and implants, attribution quoted from the reporter</span></a>',
        f'<a class="tile" href="#hardening"><b>{len(data["hardening"])}</b><span>hardening controls, each with its vendor or government source</span></a>',
        f'<a class="tile" href="#detections?runs=siem"><b>{n["rules"]}</b><span>Sigma and YARA rule files, attached to the detections they express</span></a>',
        f'<a class="tile" href="#coverage"><b>{n_prof}/{len(data["platforms"])}</b><span>platforms with a collection profile - coverage lists the gaps</span></a>',
        "</div></div>",
    ])


def _ramp(n: int) -> str:
    return "r4" if n >= 4 else f"r{n}"


def render_coverage(d: dict, data: dict) -> str:
    """Leads with the gaps, then the matrices. Count grids use one colour ramp;
    only the detection grids use tier colours, because there the colour is the
    tier. Every non-empty cell is a link into a filtered library."""
    plats, dets, arts = data["platforms"], data["detections"], data["artifacts"]
    prof = {p.name: p for p in d["profiles"]}

    gaps = []
    nop = [p for p in plats if not p["profile"]]
    if nop:
        gaps.append(("No collection profile",
                     ", ".join(f'<a href="#platforms/{p["id"]}">{e(p["short"])}</a>' for p in nop),
                     "Collection is manual: exports and images only."))
    noh = [p for p in plats if not p["n_hard"]]
    if noh and data["hardening"]:
        gaps.append(("No platform-specific hardening",
                     ", ".join(f'<a href="#platforms/{p["id"]}">{e(p["short"])}</a>' for p in noh),
                     "The cross-platform baseline still applies."))
    gimp = [i for i in data["intel"] if i["kind"] == "implant" and i["coverage"] == "gap"]
    if gimp:
        gaps.append((f"{len(gimp)} implants with no detection",
                     ", ".join(f'<a href="#intel/{i["id"]}">{e(i["name"])}</a>' for i in gimp),
                     "Each record says why - usually that the evidence is not reachable from the CLI."))
    mem = {a["platform"] for a in arts if a["class"] == "memory"}
    nomem = [p for p in plats if p["id"] not in mem]
    if nomem:
        gaps.append((f"No memory evidence on {len(nomem)} of {len(plats)} platforms",
                     ", ".join(f'<a href="#artifacts?platform={p["id"]}">{e(p["short"])}</a>' for p in nomem),
                     "A memory-only implant there leaves nothing this toolkit can collect; the most volatile "
                     "evidence it reaches is process and session state."))
    noconf = [p for p in plats if p["n_det"] and not any(x["tier"] == "confirmed" for x in dets if p["id"] in x["platforms"])]
    if noconf:
        gaps.append((f"No confirmed-tier detection on {len(noconf)} platforms",
                     ", ".join(f'<a href="#detections?platform={p["id"]}">{e(p["short"])}</a>' for p in noconf),
                     "Hits there reach COMPROMISED only by corroborating across evidence classes."))
    low = sum(1 for pr in d["profiles"] for st in pr.steps if st.unverified)
    med = sum(1 for pr in d["profiles"] for st in pr.steps if st.confidence == "medium")
    tot = sum(len(pr.steps) for pr in d["profiles"])
    gaps.append((f"{med + low} of {tot} collection steps are not vendor-documented",
                 f"{med} medium, {low} low and unverified",
                 "No profile has run on a real device yet. Corrections from virtual editions or sanitized "
                 "replay captures raise these."))
    gap_html = "".join(f'<li><b>{t}</b><div>{w}</div><div class="muted small">{why}</div></li>' for t, w, why in gaps)

    vrows = []
    for p in plats:
        if not p["profile"]:
            continue
        steps = prof[p["profile"]].steps
        c = {k: sum(1 for st in steps if st.confidence == k) for k in ("high", "medium", "low")}
        segs = "".join(f'<span class="vseg vs-{k}" style="flex:{c[k]}" title="{c[k]} {k}">{c[k]}</span>'
                       for k in ("high", "medium", "low") if c[k])
        vrows.append(f'<a class="vrow" href="#plans/{e(p["profile"])}"><span class="vname">{e(p["short"])}</span>'
                     f'<span class="vbar">{segs}</span><span class="muted small">{len(steps)} steps</span></a>')

    def tier_cell(xs_tiers, href, label):
        if not xs_tiers:
            return '<td class="cell"></td>'
        t = max(xs_tiers, key=TIERS.index)
        return (f'<td class="cell t-{t}"><a href="{href}" title="{len(xs_tiers)} {label}, strongest {t}">'
                f'{len(xs_tiers)}</a></td>')

    dhead = "".join(f'<th class="vert"><span>{e(c)}</span></th>' for c in CLASSES)
    drows = []
    for p in plats:
        cells = "".join(tier_cell([x["tier"] for x in dets if p["id"] in x["platforms"] and x["evidence"] == c],
                                  f'#detections?platform={p["id"]}&amp;evidence={e(c)}', "detection(s)") for c in CLASSES)
        drows.append(f'<tr><th class="rowh"><a href="#detections?platform={p["id"]}">{e(p["short"])}</a></th>'
                     f'{cells}<td class="num">{p["n_det"] or ""}</td></tr>')

    ahead = "".join(f'<th class="vert"><span>{e(c)}</span></th>' for c in ART_CLASSES)
    arows = []
    for p in plats:
        cells = []
        for c in ART_CLASSES:
            xs = [a for a in arts if a["platform"] == p["id"] and a["class"] == c]
            cells.append(f'<td class="cell {_ramp(len(xs))}"><a href="#artifacts?platform={p["id"]}&amp;class={e(c)}" '
                         f'title="{len(xs)} artifact(s)">{len(xs)}</a></td>' if xs else '<td class="cell"></td>')
        arows.append(f'<tr><th class="rowh"><a href="#artifacts?platform={p["id"]}">{e(p["short"])}</a></th>'
                     f'{"".join(cells)}<td class="num">{p["n_art"]}</td></tr>')

    prows = []
    for pk in d["packs"]:
        cells = "".join(tier_cell([x["tier"] for x in pk["detect"] if x["evidence_class"] == c],
                                  f'#detections?pack={e(pk["id"])}&amp;evidence={e(c)}', "detection(s)") for c in CLASSES)
        cves = pk.get("cves", [])
        prows.append(f'<tr><th class="rowh"><a href="#detections?pack={e(pk["id"])}">{e(pk["id"])}</a> '
                     f'<span class="muted">{e(", ".join(cves[:2]))}{" ..." if len(cves) > 2 else ""}</span></th>{cells}</tr>')

    total = '<th class="vert"><span>total</span></th>'
    return "".join([
        '<div class="lhead"><h2>Coverage</h2><p class="lede">Where the content is thin, computed from the repository '
        'at build time. Every number links into the matching library, already filtered.</p></div>',
        '<h3 class="sect">Gaps worth knowing before you rely on this</h3>',
        f'<ul class="gaps">{gap_html}</ul>',
        '<div class="covcols"><section>',
        '<h3 class="sect">Detections by platform and evidence class</h3>',
        '<p class="muted small">The number is how many detections; the colour is the strongest tier among them.</p>',
        f'<div class="scroll"><table class="cov"><thead><tr><th></th>{dhead}{total}</tr></thead><tbody>{"".join(drows)}</tbody></table></div>',
        f'<div class="legend">{tier_badge("possible")}{tier_badge("likely")}{tier_badge("confirmed")}</div>',
        '</section><section>',
        '<h3 class="sect">How each collection plan is sourced</h3>',
        '<p class="muted small">Steps by confidence. Nothing has run on a real device yet, so this is the honest '
        'measure of how far to trust a plan.</p>',
        f'<div class="vrows">{"".join(vrows)}</div>',
        '<div class="legend"><span class="badge conf c-high">high - vendor-documented</span>'
        '<span class="badge conf c-medium">medium</span><span class="badge unv-b">low - unverified</span></div>',
        '</section></div>',
        '<h3 class="sect">Artifacts by platform and class</h3>',
        '<p class="muted small">Darker means more artifacts. An empty memory or process column means the most '
        'volatile evidence on that platform is out of reach.</p>',
        f'<div class="scroll"><table class="cov"><thead><tr><th></th>{ahead}{total}</tr></thead><tbody>{"".join(arows)}</tbody></table></div>',
        f'<details class="fold"><summary>Detections by pack and evidence class ({len(d["packs"])} packs)</summary>',
        f'<div class="scroll"><table class="cov"><thead><tr><th></th>{dhead}</tr></thead><tbody>{"".join(prows)}</tbody></table></div></details>',
    ])


# --------------------------------------------------------------------------- page
CSS = r"""
:root{
  --bg:#fbfbfa;--panel:#fff;--panel-2:#fbfbfa;--hover:#faf7f4;
  --ink:#1c1b19;--muted:#6b6862;--faint:#a09b90;--line:#e4e1db;--line-soft:#f0ede8;--field:#ddd8d0;
  --accent:#5e3a24;--accent-hover:#472a19;--accent-soft:#f2e9e2;--accent-border:#e0cfc1;--on-accent:#fff;
  --crit:#a12b2b;--high:#b4611c;--med:#8a7320;--low:#5c7a4a;
  --conf-strong:#3d5a80;--conf-mid:#6b7f96;--conf-bg:#eef2f7;--alert-bg:#fdf6f2;
  --code-bg:#f6f4f0;--shadow:rgba(28,27,25,.07);--shadow-lg:rgba(28,27,25,.16);--hdr:150px;--ink-2:#3d3a35;
  --sans:system-ui,"Segoe UI Variable Text","Segoe UI",-apple-system,BlinkMacSystemFont,Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,"Cascadia Mono","Cascadia Code","SF Mono",SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
  --fs-xs:12px;--fs-sm:13px;--fs-base:14.5px;--fs-md:16px;--fs-lg:20px}
:root[data-theme=dark]{
  --bg:#121110;--panel:#1a1917;--panel-2:#211f1c;--hover:#262320;
  --ink:#f1eee9;--muted:#a9a39a;--faint:#7c766e;--line:#302d29;--line-soft:#262320;--field:#3a3631;
  --accent:#ddc4b0;--accent-hover:#ecd9ca;--accent-soft:#2d2118;--accent-border:#553a29;--on-accent:#1a1310;
  --crit:#f28c85;--high:#eaa965;--med:#d9c364;--low:#a6d18c;
  --conf-strong:#9ec0e0;--conf-mid:#7e94ab;--conf-bg:#1b2530;--alert-bg:#251a16;
  --code-bg:#211f1c;--shadow:rgba(0,0,0,.5);--shadow-lg:rgba(0,0,0,.6);--ink-2:#d6d1c9}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){
  --bg:#121110;--panel:#1a1917;--panel-2:#211f1c;--hover:#262320;
  --ink:#f1eee9;--muted:#a9a39a;--faint:#7c766e;--line:#302d29;--line-soft:#262320;--field:#3a3631;
  --accent:#ddc4b0;--accent-hover:#ecd9ca;--accent-soft:#2d2118;--accent-border:#553a29;--on-accent:#1a1310;
  --crit:#f28c85;--high:#eaa965;--med:#d9c364;--low:#a6d18c;
  --conf-strong:#9ec0e0;--conf-mid:#7e94ab;--conf-bg:#1b2530;--alert-bg:#251a16;
  --code-bg:#211f1c;--shadow:rgba(0,0,0,.5);--shadow-lg:rgba(0,0,0,.6);--ink-2:#d6d1c9}}
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
.hdr-in{max-width:1440px;margin:0 auto;padding:14px 28px 0}
.hdr-top{display:flex;flex-wrap:wrap;gap:10px 24px;align-items:flex-start}
.hdr-id{flex:1 1 340px;min-width:0}
.h1row{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.dot{width:9px;height:9px;border-radius:50%;background:var(--accent);flex:none}
h1{margin:0;font-size:var(--fs-lg);font-weight:600;letter-spacing:-.01em}
.pill{font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted);background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:2px 8px}
.sub{margin:5px 0 0;font-size:var(--fs-sm);color:var(--muted);max-width:68ch}
.hdr-right{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
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
.fhead{display:flex;gap:6px;align-items:center;width:100%;background:none;border:0;padding:4px 0;font-size:var(--fs-xs);letter-spacing:.07em;text-transform:uppercase;color:var(--faint);font-weight:600;text-align:left}
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
.fv .fc{font-family:var(--mono);font-size:var(--fs-xs);color:var(--faint)}
.fv.zero{color:var(--faint)}
.more{background:none;border:0;color:var(--accent);font-size:var(--fs-xs);padding:3px 8px}
main{padding:20px 28px 60px;min-width:0}
.lhead h2{margin:0 0 4px;font-size:var(--fs-lg);font-weight:600;letter-spacing:-.01em}
.lede{color:var(--muted);margin:0 0 16px;max-width:90ch}

/* ---- library controls ---- */
.controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:8px}
.search{flex:1 1 300px;display:flex;align-items:center;gap:8px;background:var(--panel);border:1px solid var(--field);border-radius:9px;padding:0 12px}
.search:focus-within{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.search .glyph{color:var(--faint)}
.search input{flex:1;border:0;background:none;padding:10px 0;font-size:var(--fs-base);outline:0;min-width:0}
.tgl{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:9px 13px;font-size:var(--fs-sm);color:var(--ink);white-space:nowrap}
.tgl:hover{border-color:var(--accent)}
.tgl[aria-pressed=true]{background:var(--accent);color:var(--on-accent);border-color:var(--accent)}
.tgl .n{font-family:var(--mono);font-size:var(--fs-xs);background:var(--alert-bg);color:var(--crit);border-radius:20px;padding:1px 6px;margin-left:5px}
.exp{display:flex;gap:6px;align-items:center;margin-left:auto}
.exp .lbl{font-size:var(--fs-xs);letter-spacing:.08em;text-transform:uppercase;color:var(--faint)}
.meta{display:flex;gap:10px;flex-wrap:wrap;align-items:center;min-height:28px;margin-bottom:10px;font-size:var(--fs-sm)}
.count{font-family:var(--mono);color:var(--muted)}
.active{display:flex;gap:5px;flex-wrap:wrap}
.achip{display:inline-flex;gap:6px;align-items:center;background:var(--accent-soft);border:1px solid var(--accent-border);color:var(--accent);border-radius:999px;padding:2px 6px 2px 10px;font-size:var(--fs-xs)}
.achip button{background:none;border:0;color:inherit;padding:0 4px;font-size:var(--fs-base);line-height:1}
.picked{margin-left:auto;color:var(--accent);font-size:var(--fs-sm)}
.summary:empty{display:none}
.summary{margin-bottom:14px}

/* ---- distribution bar + tiles ---- */
.dist{display:flex;gap:3px;height:34px;border-radius:9px;overflow:hidden}
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

/* ---- rows (table library) ---- */
.rows{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.row{display:grid;grid-template-columns:30px 150px minmax(0,1fr) 96px 92px 74px 104px;gap:14px;padding:13px 16px;border-top:1px solid var(--line-soft);align-items:start}
.row.head span{font-size:inherit;line-height:1.4}
.row.head{border-top:0;padding-top:11px;padding-bottom:11px;font-size:var(--fs-xs);letter-spacing:.08em;text-transform:uppercase;color:var(--faint);font-weight:600;background:var(--panel)}
.row.item{cursor:pointer}
.row.item:hover{background:var(--hover)}
.row.item.sel{background:var(--accent-soft);box-shadow:inset 3px 0 0 var(--accent)}
.row.unv .c-plat{box-shadow:inset 3px 0 0 var(--crit);padding-left:8px;margin-left:-8px}
.c-plat{font-size:var(--fs-sm);line-height:1.35}
.c-plat .id{display:block;margin-top:3px}
.c-main{min-width:0}
code.loc{display:inline-block;max-width:100%;background:var(--code-bg);border:1px solid var(--line-soft);border-radius:5px;padding:1px 6px;font-size:var(--fs-sm);word-break:break-word}
.c-main .desc{display:block;color:var(--ink-2);font-size:var(--fs-base);margin-top:6px;line-height:1.5;max-width:75ch}
.c-main .seen{display:flex;gap:4px;flex-wrap:wrap;margin-top:6px}
.rows.compact .desc,.rows.compact .seen{display:none}
.rows.compact .row{padding-top:8px;padding-bottom:8px}
.pick,.pickall{width:15px;height:15px;margin:2px 0 0;accent-color:var(--accent);cursor:pointer}

/* ---- cards (grid library) ---- */
.lgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:14px}
.lc{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:15px 16px;cursor:pointer;display:flex;flex-direction:column;gap:9px;box-shadow:0 1px 2px var(--shadow);transition:border-color .12s,box-shadow .12s,transform .12s}
.lc:hover{border-color:var(--accent-border);box-shadow:0 4px 14px var(--shadow);transform:translateY(-1px)}
.lc.sel{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent)}
.lc.unv{box-shadow:inset 3px 0 0 var(--crit),0 1px 2px var(--shadow)}
.lc.gap{box-shadow:inset 3px 0 0 var(--crit),0 1px 2px var(--shadow)}
.lc-h{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}
.lc-t{min-width:0}
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
.dbody{padding:4px 18px 40px;overflow-y:auto;flex:1}
.dbody h4{margin:20px 0 7px}
.dbody p{margin:6px 0}
.dloc{display:flex;gap:8px;align-items:flex-start;margin:14px 0 4px}
.dloc code{flex:1;background:var(--code-bg);border:1px solid var(--line-soft);border-radius:8px;padding:9px 11px;font-size:var(--fs-sm);word-break:break-word}
.stepbox{background:var(--panel-2);border:1px solid var(--line-soft);border-radius:10px;padding:10px 12px}
.stepbox .codewrap{margin:8px 0}
.refs{padding-left:18px}.refs li{margin:4px 0}
.scrim{display:none}
body.drawer-open{overflow:auto}

/* ---- shared bits ---- */
h3{margin:0;font-size:var(--fs-md);font-weight:600}
h4{margin:14px 0 6px;font-size:var(--fs-xs);letter-spacing:.07em;text-transform:uppercase;color:var(--faint)}
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
.c-low{color:var(--faint)}
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
.chip.ghost{background:none;border:1px dashed var(--line);color:var(--faint)}
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
.tbl thead th{font-size:var(--fs-xs);letter-spacing:.05em;text-transform:uppercase;color:var(--faint);border-top:0}
.tbl td.id{white-space:nowrap}
.picker{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}
.pbtn,.rbtn{background:var(--panel);border:1px solid var(--line);border-radius:999px;padding:6px 13px;font-size:var(--fs-sm);color:var(--muted)}
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
.step.off{opacity:.38}
.step .kind{font-size:var(--fs-xs);color:var(--faint);margin-top:3px}
.purpose{color:var(--muted);font-size:var(--fs-sm);margin-top:4px}
.needs{font-size:var(--fs-xs);color:var(--high);margin-top:3px}
.cmd{display:inline-flex;gap:6px;align-items:flex-start;max-width:100%}
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
.legend{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin:-12px 0 24px}
.guide{max-width:760px}
.guide h2{font-size:var(--fs-lg);margin:8px 0 10px}.guide h3{font-size:var(--fs-md);margin:26px 0 8px}.guide h4{font-size:var(--fs-xs)}
.guide p,.guide li{line-height:1.7;color:var(--ink-2)}
.guide code{background:var(--code-bg);border-radius:4px;padding:1px 4px;font-size:var(--fs-sm)}
.guide pre code{background:none;padding:0}
footer{max-width:1440px;margin:0 auto;padding:22px 28px 40px;color:var(--faint);font-size:var(--fs-xs);border-top:1px solid var(--line)}
.sect{margin:22px 0 10px;font-size:var(--fs-md)}
.cls{color:var(--muted)}
.vol-live{color:var(--crit);border-color:currentColor}.vol-rotating{color:var(--high);border-color:currentColor}
.vol-stable{color:var(--low);border-color:currentColor}.vol-off-box{color:var(--conf-strong);border-color:currentColor;background:var(--conf-bg)}
.fv-high{color:var(--on-accent);background:var(--accent);border-color:var(--accent)}.fv-medium{color:var(--accent);border-color:var(--accent-border)}.fv-low{color:var(--faint)}
.mot-espionage{color:var(--conf-strong);border-color:currentColor}.mot-financial{color:var(--high);border-color:currentColor}
.mot-unknown,.mot-mixed{color:var(--muted)}
.kind-actor{color:var(--high);border-color:currentColor}.kind-implant{color:var(--crit);border-color:currentColor}
.attrib{background:var(--panel-2);border:1px solid var(--line-soft);border-radius:8px;padding:9px 12px;margin:12px 0;font-size:var(--fs-sm);display:grid;gap:4px}
.attrib .k{display:inline-block;min-width:110px;font-size:var(--fs-xs);letter-spacing:.05em;text-transform:uppercase;color:var(--faint)}
.attrib q{font-style:italic;color:var(--ink)}
.gap-b{color:var(--on-accent);background:var(--crit);border-color:var(--crit)}
.surv-yes{color:var(--crit);border-color:currentColor}.surv-no{color:var(--low);border-color:currentColor}
.surv-partial{color:var(--high);border-color:currentColor}.surv-unknown{color:var(--faint)}
.itype{color:var(--accent);border-color:var(--accent-border);background:var(--accent-soft)}
.res-memory{color:var(--crit);border-color:currentColor}.res-boot{color:var(--on-accent);background:var(--crit);border-color:var(--crit)}
.res-disk,.res-memory\+disk{color:var(--high);border-color:currentColor}
.phases{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-top:8px}
.phase{background:var(--panel-2);border:1px solid var(--line-soft);border-radius:8px;padding:6px 12px 10px}
.phase ol,.resp ol{margin:4px 0;padding-left:18px}.phase li{margin:5px 0;font-size:var(--fs-sm)}
.pn{display:inline-grid;place-items:center;width:18px;height:18px;border-radius:50%;background:var(--accent);color:var(--on-accent);font-size:var(--fs-xs);margin-right:7px;vertical-align:1px;letter-spacing:0}
.when{font-size:var(--fs-xs);color:var(--high);margin-top:2px}
.dont{margin-top:14px;background:var(--alert-bg);border:1px solid var(--line-soft);border-left:3px solid var(--crit);border-radius:8px;padding:4px 12px 8px}
.dont h4{color:var(--crit)}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:var(--ink);color:var(--bg);border-radius:9px;padding:9px 16px;font-size:var(--fs-sm);z-index:60;box-shadow:0 6px 24px var(--shadow-lg)}
[hidden]{display:none!important}
.empty{color:var(--muted);padding:40px 0;text-align:center;background:var(--panel);border:1px dashed var(--line);border-radius:12px}
kbd{font-family:var(--mono);font-size:var(--fs-xs);border:1px solid var(--line);border-bottom-width:2px;border-radius:4px;padding:0 4px;background:var(--panel)}

@media (max-width:1100px){.row{grid-template-columns:28px 120px minmax(0,1fr) 92px 92px}.row .c-val,.row .c-conf{display:none}}
@media (max-width:980px){.planwrap{grid-template-columns:1fr}.builder{position:static}}
@media (max-width:900px){
  .shell{grid-template-columns:1fr}
  .rail{position:static;max-height:none;border-right:0;border-bottom:1px solid var(--line);padding:10px 16px}
  .railhead{margin:0}
  #railToggle{display:inline-flex;gap:6px;align-items:center}
  .rail:not(.open) #rail{display:none}
  .rail:not(.open) #railReset{display:none}
  .scrim{display:block;position:fixed;inset:0;background:rgba(0,0,0,.32);z-index:45}
  body.drawer-open{overflow:hidden}
}
@media (max-width:640px){
  .hdr{position:static}html{scroll-padding-top:0}
  .rail{top:0}
  .hdr-in,main,footer{padding-left:16px;padding-right:16px}
  .tabs{mask-image:linear-gradient(90deg,#000 85%,transparent);-webkit-mask-image:linear-gradient(90deg,#000 85%,transparent)}
      .exp{margin-left:0}
  .row.head{display:none}
  .seg span{display:none}
  .railhead b{display:none}
  .row{display:flex;flex-wrap:wrap;gap:6px 8px;padding:13px 14px}
  .row .c-pick{order:9;margin-left:auto}
  .row .c-plat{flex:1 1 100%;display:flex;gap:8px;align-items:baseline;font-weight:600}
  .row .c-plat .id{display:inline;margin:0;font-weight:400}
  .row .c-main{flex:1 1 100%}
  .row .c-val,.row .c-conf{display:block}
  .lgrid{grid-template-columns:1fr}
  .card,.plan{padding:14px}.tbl{font-size:var(--fs-xs)}
  .steps thead{display:none}.steps tr.step td{display:block;border:0;padding:3px 0}
  .steps tr.step{display:block;padding:10px 0;border-top:1px solid var(--line-soft)}
  .steps tr.step td:first-child{font-weight:600}.steps .tierrow th{display:block}
  .dhead{padding:12px 14px}.dbody{padding:4px 14px 40px}
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
.ptiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:10px}
.ptile{background:var(--panel);border:1px solid var(--line);border-radius:12px;display:flex;flex-direction:column;overflow:hidden}
.ptile:hover{border-color:var(--accent-border);box-shadow:0 4px 14px var(--shadow)}
.ptile-h{display:flex;flex-direction:column;gap:1px;padding:12px 14px 10px;text-decoration:none;color:var(--ink)}
.ptile-h b{font-size:var(--fs-md);font-weight:600}
.ptile-l{display:flex;flex-wrap:wrap;gap:2px 12px;padding:8px 14px 11px;border-top:1px solid var(--line-soft);font-size:var(--fs-sm)}
.ptile-l a{text-decoration:none}.ptile-l a:hover{text-decoration:underline}
.ptile .n{color:var(--faint);font-size:var(--fs-xs)}
.startcols{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:8px 28px}
.callout{background:var(--alert-bg);border:1px solid var(--line-soft);border-left:3px solid var(--crit);border-radius:10px;padding:12px 16px;color:var(--ink)}
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
.gaps{list-style:none;padding:0;margin:0 0 8px;display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:10px}
.gaps li{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--high);border-radius:10px;padding:10px 14px;display:flex;flex-direction:column;gap:3px}
.covcols{display:grid;grid-template-columns:minmax(0,auto) minmax(300px,1fr);gap:8px 32px;align-items:start}
.vrows{display:flex;flex-direction:column;gap:6px;margin-bottom:22px}
.vrow{display:grid;grid-template-columns:150px 1fr 64px;gap:10px;align-items:center;text-decoration:none;color:var(--ink);font-size:var(--fs-sm)}
.vrow:hover .vname{text-decoration:underline}
.vbar{display:flex;gap:2px;height:20px;border-radius:5px;overflow:hidden}
.vseg{display:flex;align-items:center;justify-content:center;font-size:var(--fs-xs);color:#fff;min-width:18px;font-variant-numeric:tabular-nums}
.vs-high{background:var(--conf-strong)}.vs-medium{background:var(--conf-mid)}.vs-low{background:var(--crit)}
.cell.r1{background:color-mix(in srgb,var(--accent) 12%,transparent)}.cell.r2{background:color-mix(in srgb,var(--accent) 26%,transparent)}
.cell.r3{background:color-mix(in srgb,var(--accent) 42%,transparent)}.cell.r4{background:color-mix(in srgb,var(--accent) 60%,transparent)}
.cell.r4 a{color:var(--on-accent)}
details.fold{margin:8px 0 20px}details.fold summary{font-size:var(--fs-sm);color:var(--accent);font-weight:600}

/* ---- guide ---- */
.guide h2{font-size:var(--fs-lg);margin:6px 0 10px}
.guide h3{font-size:var(--fs-md);margin:30px 0 8px;padding-top:4px}
.guide h4{font-size:var(--fs-xs)}
.hlink{margin-left:8px;color:var(--faint);text-decoration:none;opacity:0;font-weight:400}
.guide h3:hover .hlink,.guide h4:hover .hlink,.hlink:focus{opacity:1}
.guide .callout{margin:10px 0 14px}
.pnote{border-left:2px solid var(--line);padding:2px 0 2px 14px;margin:12px 0}
.pnote p{margin:0 0 6px}.pnote .links{margin:4px 0 0}
.guide .tbl td,.guide .tbl th{font-size:var(--fs-sm)}
.toc{display:flex;flex-direction:column;gap:1px;margin-top:6px}
.toc a{display:block;padding:5px 8px;border-radius:6px;color:var(--ink-2);text-decoration:none;font-size:var(--fs-sm);line-height:1.35;border-left:2px solid transparent}
.toc a.l3{padding-left:20px;color:var(--muted)}
.toc a:hover{background:var(--hover)}
.toc a.on{color:var(--accent);background:var(--accent-soft);border-left-color:var(--accent);font-weight:600}
@media (max-width:640px){.ptiles{grid-template-columns:1fr 1fr;gap:8px}.ptile-h{padding:10px 11px 8px}.ptile-h .id,.ptile-h .muted{display:none}
  .ptile-h b{font-size:var(--fs-base);line-height:1.3}.ptile-l{padding:7px 11px 9px;gap:2px 9px;font-size:var(--fs-xs)}
  .covcols{grid-template-columns:minmax(0,1fr)}.vrow{grid-template-columns:110px 1fr 54px}.startcols{grid-template-columns:1fr}.tabsep{margin:8px 4px}}

/* ---- start visuals ---- */
.sechead{display:flex;justify-content:space-between;align-items:baseline;gap:6px 16px;flex-wrap:wrap}
.vkey{display:flex;gap:10px;align-items:center;flex-wrap:wrap;font-size:var(--fs-xs);color:var(--muted)}
.vk{display:inline-flex;gap:5px;align-items:center}.vk .vb{width:12px;height:8px;border-radius:2px;flex:none}
.vbwrap{padding:0 14px 10px;display:flex;flex-direction:column;gap:4px}
.vbar2{display:flex;gap:2px;height:7px;border-radius:4px;overflow:hidden;background:var(--line-soft)}
.vb-live{background:var(--crit)}.vb-rotating{background:var(--high)}.vb-stable{background:var(--med)}.vb-off-box{background:var(--conf-strong)}
.vbl{font-size:var(--fs-xs);color:var(--muted);font-variant-numeric:tabular-nums}
.callout ol.cols2{columns:2 340px;column-gap:32px}.callout ol.cols2 li{break-inside:avoid}
.flowd{list-style:none;padding:0;margin:0;display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:14px;counter-reset:f}
.flowd li{position:relative}
.flowd li:not(:last-child)::after{content:"";position:absolute;top:50%;right:-12px;width:10px;height:10px;border-top:2px solid var(--accent-border);border-right:2px solid var(--accent-border);transform:translateY(-50%) rotate(45deg)}
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
@media (max-width:1100px){.flowd{grid-template-columns:repeat(auto-fit,minmax(170px,1fr))}.flowd li::after{display:none}.oovgs{flex-wrap:wrap}.oovg{flex:1 1 260px!important}}
@media (max-width:640px){.flowd{grid-template-columns:1fr;gap:8px}.flowd a{flex-direction:row;flex-wrap:wrap;align-items:center;column-gap:10px}.flowd span:last-child{flex:1 1 100%}
  .oovarrow{display:none}.vbwrap{padding:0 11px 8px}.vbl{display:none}}

/* ---- hardening ---- */
.pr{font-weight:600}.pr-critical{color:var(--on-accent);background:var(--crit);border-color:var(--crit)}
.pr-high{color:var(--high);border-color:currentColor}.pr-medium{color:var(--med);border-color:currentColor}
.lc.base{box-shadow:inset 3px 0 0 var(--low),0 1px 2px var(--shadow)}
.srcs{padding-left:18px}.srcs li{margin:6px 0}
.srcs blockquote{margin:6px 0 0;padding:6px 10px;border-left:3px solid var(--line);color:var(--ink-2);font-size:var(--fs-sm);font-style:italic;background:var(--panel-2);border-radius:0 6px 6px 0}

.stepbox.rule{margin:8px 0}.stepbox.rule b{font-size:var(--fs-sm)}
.sumline{margin:8px 0 0}
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
var CODE_RE = /(`[^`]+`|(?<![\w.\/])\/[\w.\-*{}]+(?:\/[\w.\-*{}]*)*|\b[\w.\-]+\.(?:bin|b64|gz|tar|log|conf|php|py|pth|sh|so|zip|pcap|elg|xml|json|lua|cgi|pl|db|pkg|yar|yml|html|txt|ko|cfg|dat|out|tgz|ucs|qkview|pcapng)\d?\b)/g;
function rich(t){
  return String(t == null ? '' : t).split(CODE_RE).map(function(part, i){
    if (i % 2 === 0) return esc(part);
    return '<code>' + esc(part.charAt(0) === '`' ? part.slice(1, -1) : part) + '</code>';
  }).join('');
}
function para(t){ return t ? '<p>' + rich(t) + '</p>' : ''; }
function codeblk(t, wrap){ return '<div class="codewrap"><button class="copy" type="button">Copy</button><pre' + (wrap ? ' class="wrap"' : '') + '><code>' + esc(t) + '</code></pre></div>'; }
function att(a){ return (a || []).map(function(t){ var p = t.split('.'); return '<a class="chip mono" href="https://attack.mitre.org/techniques/' + p[0] + '/' + (p[1] ? p[1] + '/' : '') + '" rel="noopener" target="_blank" title="MITRE ATT&CK">' + esc(t) + '</a>'; }).join(''); }
function list(a){ return a && a.length ? '<ul>' + a.map(function(x){ return '<li>' + rich(x) + '</li>'; }).join('') + '</ul>' : ''; }
function hd(id, title, sub, badges){ return '<div class="lc-h"><div class="lc-t"><span class="id">' + esc(id) + '</span><h3>' + esc(title) + '</h3>' + (sub ? '<div class="lc-sub">' + sub + '</div>' : '') + '</div><div class="badges">' + (badges || '') + '</div></div>'; }
var IMP = {'none':'imp-none','vendor-bundle':'imp-bundle','break-glass':'imp-bg'};
var SHELL = {yes:'shell: yes', restricted:'shell: restricted', no:'shell: none'};
var PN = {}, PLAT = {}; D.platforms.forEach(function(p){ PN[p.id] = p.short; PLAT[p.id] = p; });
var PACK = {}; D.packs.forEach(function(p){ PACK[p.id] = p; });
var INTEL = {}; D.intel.forEach(function(i){ INTEL[i.id] = i; });
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
var th = store('edt-theme'); if (th) root.setAttribute('data-theme', th); themeLabel();
$('themeBtn').addEventListener('click', function(){ var n = isDark() ? 'light' : 'dark'; root.setAttribute('data-theme', n); store('edt-theme', n); themeLabel(); });
function hdrH(){ root.style.setProperty('--hdr', document.querySelector('.hdr').offsetHeight + 'px'); }
window.addEventListener('resize', hdrH); hdrH();
var toastT; function toast(m){ var t = $('toast'); t.textContent = m; t.hidden = false; clearTimeout(toastT); toastT = setTimeout(function(){ t.hidden = true; }, 1800); }

/* ---------------------------------------------------------------- libraries */
function F(k, label, get, name, order){ return {k:k, label:label, get:get, name:name || function(v){ return v; }, order:order}; }
var ORD = {vol:['live','rotating','stable','off-box'], hml:['high','medium','low'], tier:['confirmed','likely','possible'],
           level:['critical','high','medium','low','informational','-'], yn:['yes','partial','no','unknown']};
var KIND = {step:'Collection step', ingest:'Off-box export (ingest)', manual:'Manual'};
var HCAT = {exposure:'Internet exposure', access:'Management access', identity:'Accounts and MFA', services:'Unused services', logging:'Logging off-box', patching:'Patching and end of life', integrity:'Integrity and boot', recovery:'Backups and recovery'};

var LIB = {
artifacts: {
  noun:'artifacts', items:D.artifacts, view:'rows',
  head:['', 'Platform', 'Artifact and what it proves', 'Class', 'Volatility', 'Value', 'Confidence'],
  facets:[
    F('platform', 'Platform', function(a){ return [a.platform]; }, function(v){ return PN[v] || v; }),
    F('class', 'Artifact class', function(a){ return [a['class']]; }),
    F('volatility', 'Volatility', function(a){ return [a.volatility]; }, null, ORD.vol),
    F('value', 'Forensic value', function(a){ return [a.value]; }, null, ORD.hml),
    F('evidence', 'Evidence type', function(a){ return a.evidence; }),
    F('kind', 'Collected by', function(a){ return [a.kind]; }, function(v){ return KIND[v] || v; }),
    F('confidence', 'Confidence', function(a){ return [a.confidence]; }, null, ORD.hml),
    F('seen', 'Seen in', function(a){ return a.seen_in; })
  ],
  text:function(a){ return [a.id, PN[a.platform], a.locator, a.description, a['class'], a.volatility, a.collected_by, a.retention, a.seen_in.join(' '), a.evidence.join(' ')].join(' '); },
  row:function(a){
    return '<span class="c-pick"><input type="checkbox" class="pick" aria-label="Pick ' + esc(a.id) + '"' + (S.artifacts.picks[a.id] ? ' checked' : '') + '></span>' +
      '<span class="c-plat">' + esc(PN[a.platform]) + '<span class="id">' + esc(a.id) + '</span></span>' +
      '<span class="c-main"><code class="loc">' + esc(a.locator) + '</code><span class="desc">' + rich(a.description) + '</span>' +
      (a.seen_in.length ? '<span class="seen">' + chips(a.seen_in, 'implant') + '</span>' : '') + '</span>' +
      '<span class="c-cls">' + b(a['class'], 'cls') + '</span><span class="c-vol">' + b(a.volatility, 'vol vol-' + a.volatility) + '</span>' +
      '<span class="c-val">' + b(a.value, 'fv fv-' + a.value) + '</span><span class="c-conf">' + conf(a.confidence, a.unv) + '</span>';
  },
  title:function(a){ return PN[a.platform] + ' artifact'; },
  drawer:function(a){
    var p = PLAT[a.platform], h = '<div class="links" style="margin-top:14px">' + b(a['class'], 'cls') + b(a.volatility, 'vol vol-' + a.volatility) + b('value: ' + a.value, 'fv fv-' + a.value) + conf(a.confidence, a.unv) + '</div>';
    h += '<div class="dloc"><code>' + esc(a.locator) + '</code><button class="copy" type="button" data-copy="' + esc(a.locator) + '">Copy</button></div>';
    h += sec('What it proves', para(a.description));
    if (a.retention) h += sec('Retention', para(a.retention));
    h += sec('Evidence type', '<div class="links">' + chips(a.evidence, 'mono') + '</div>');
    if (a.seen.length) h += sec('Seen in', '<div class="links">' + lnks(a.seen, 'implant') + '</div>');
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
    if (a.detections.length) h += sec('Detections that read it', '<div class="links">' + a.detections.map(function(id){ return lnk('#detections/' + id, id, 'mono'); }).join('') + '</div>');
    h += sec('Platform', '<div class="links">' + lnk('#platforms/' + p.id, p.short) + lnk('#artifacts?platform=' + p.id, 'All ' + p.n_art + ' artifacts on this platform') +
      (p.response ? lnk('#response/' + p.response, 'Containment and recovery') : '') + '</div>');
    return h;
  },
  exp:function(a){ return {id:a.id, platform:PN[a.platform], locator:a.locator, 'class':a['class'], volatility:a.volatility, retention:a.retention,
    value:a.value, evidence:a.evidence, confidence:a.confidence, unverified:a.unv, collected_by:a.collected_by,
    command:a.step ? a.step.cmd : '', seen_in:a.seen_in, description:a.description}; },
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
      '<p class="clamp">' + esc(p.os_base) + '</p>' +
      '<div class="stats"><span><b>' + p.n_art + '</b>artifacts</span><span><b>' + p.n_steps + '</b>steps</span><span><b>' + p.n_det + '</b>detections</span></div>' +
      '<div class="lc-f">' + b('memory: ' + p.memory, 'mem') + (p.profile ? '<span class="chip code">' + esc(p.profile) + '</span>' : '<span class="chip ghost">no profile yet</span>') + '</div>';
  },
  title:function(p){ return p.name; },
  drawer:function(p){
    var h = '<div class="links" style="margin-top:14px">' + b(SHELL[p.shell], 'sh-' + p.shell) + b('memory: ' + p.memory, 'mem') + conf(p.confidence, p.unv) + '</div>';
    h += para(p.vendor + ' - ' + p.os_base);
    h += '<div class="links">' + lnk('#artifacts?platform=' + p.id, p.n_art + ' artifacts') +
      (p.profile ? lnk('#plans/' + p.profile, 'Collection plan: ' + p.profile + ' (' + p.n_steps + ' steps)') : '<span class="chip ghost">no profile yet</span>') +
      (p.n_det ? lnk('#detections?platform=' + p.id, p.n_det + ' detections') : '') +
      (p.response ? lnk('#response/' + p.response, 'Containment and recovery') : '') +
      (p.n_hard ? lnk('#hardening?platform=' + p.id, p.n_hard + ' hardening controls') : '') + '</div>';
    if (p.products.length) h += sec('Products', '<div class="links">' + chips(p.products) + '</div>');
    if (p.filesystem) h += sec('Filesystem', para(p.filesystem));
    h += sec('Collection paths', '<ul class="plain">' + p.collection.map(function(x){ return '<li><div class="row2">' + b(x.impact, IMP[x.impact]) + '<b>' + esc(x.method) + '</b>' + conf(x.confidence, x.unverified) + '</div><div class="muted small">' + rich(x.description) + '</div></li>'; }).join('') + '</ul>');
    if (p.volatility.length) h += sec('Lost on reboot or upgrade', list(p.volatility));
    if (p.anti_forensics.length) h += sec('Anti-forensics seen in public reporting', '<ul class="plain">' + p.anti_forensics.map(function(a){ return '<li><b>' + esc(a.technique) + '</b> <span class="muted">- ' + esc(a.seen_in) + '</span>' + (a.detail ? '<div class="muted small">' + rich(a.detail) + '</div>' : '') + '</li>'; }).join('') + '</ul>');
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
    F('platform', 'Platform', function(x){ return x.platforms; }, function(v){ return PN[v] || v; }),
    F('runs', 'Runs in', function(x){ return x.runs; }, function(v){ return RUNS[v] || v; }, ['analyzer','siem','yara']),
    F('tier', 'Tier', function(x){ return [x.tier]; }, null, ORD.tier),
    F('evidence', 'Evidence class', function(x){ return [x.evidence]; }),
    F('type', 'Type', function(x){ return [x.type]; }, function(v){ return {log_regex:'log pattern', check:'coded check', yara:'YARA'}[v] || v; }),
    F('pack', 'Pack', function(x){ return [x.pack]; }, function(v){ return v.replace('EDGE-PACK-', '') + ' · ' + (PACK[v] ? PACK[v].name : ''); }),
    F('cve', 'CVE', function(x){ return x.cves; }),
    F('actor', 'Actor', function(x){ return x.actors; }),
    F('attack', 'ATT&CK', function(x){ return x.attack; })
  ],
  text:function(x){ return [x.id, x.title, x.pack, x.pack_name, x.notes, x.pattern, x.check, x.rule, x.evidence, x.cves.join(' '), x.attack.join(' '), x.actors.join(' '),
    x.sigma.map(function(r){ return RULE[r] ? RULE[r].file + ' ' + RULE[r].title : r; }).join(' ')].join(' '); },
  card:function(x){
    return hd(x.id, x.title, esc(x.pack + ' · ' + x.pack_name), b(x.tier, 'tier t-' + x.tier)) +
      (x.notes ? '<p class="clamp">' + rich(x.notes) + '</p>' : '') +
      '<div class="lc-f">' + '<span class="chip">' + esc(x.evidence) + '</span><span class="chip mono">' + esc(x.type === 'check' ? 'check:' + x.check : x.type) + '</span>' +
      (x.sigma.length ? b('Sigma', 'fmt fmt-sigma') : '') + (x.type === 'yara' ? b('YARA', 'fmt fmt-yara') : '') + chips(x.attack.slice(0, 2), 'mono') + '</div>';
  },
  title:function(x){ return x.title; },
  drawer:function(x){
    var p = PACK[x.pack], h = '<div class="links" style="margin-top:14px">' + b(x.tier, 'tier t-' + x.tier) + '<span class="chip">' + esc(x.evidence) + '</span><span class="chip mono">' + esc(x.type) + '</span>' + conf(p.confidence, p.unv) + '</div>';
    if (x.notes) h += para(x.notes);
    if (x.type === 'log_regex'){
      h += sec('Pattern' + (x.flags.length ? ' (' + x.flags.join(', ') + ')' : ''), codeblk(x.pattern, true));
      if (x.exclude.length) h += sec('Excluded when the line also matches', x.exclude.map(function(p){ return codeblk(p, true); }).join(''));
    } else if (x.type === 'check'){
      h += sec('Coded check: ' + x.check, x.check_doc ? '<pre class="wrap">' + esc(x.check_doc) + '</pre>' : '');
    } else if (x.type === 'yara' && RULE[x.rule_id]){
      h += sec('YARA rule - scans recovered files', ruleBlock(RULE[x.rule_id]));
    }
    if (x.sigma.length) h += sec(x.sigma.length > 1 ? 'Sigma rules for your SIEM' : 'Sigma rule for your SIEM', x.sigma.map(function(r){ return RULE[r] ? ruleBlock(RULE[r]) : ''; }).join(''));
    else if (x.evidence === 'web-logs' || x.evidence === 'auth-logs' || x.evidence === 'system-logs')
      h += sec('SIEM rule', '<p class="muted small">None yet. The pattern above can be watched in forwarded logs; a Sigma rule is welcome.</p>');
    if (x.steps.length) h += sec('Reads these collection steps', '<ul class="plain">' + x.steps.map(function(s){
      return '<li><div class="row2"><b class="mono">' + esc(s.id) + '</b>' + (s.tier ? '<span class="tchip">' + esc(s.tier) + '</span>' : '') + (s.profile ? lnk('#plans/' + s.profile, s.profile) : '') + '</div>' + (s.cmd ? '<code class="loc">' + esc(s.cmd) + '</code>' : '') + '</li>'; }).join('') + '</ul>');
    if (x.files.length) h += sec('Reads these files', '<div class="links">' + chips(x.files, 'code') + '</div>');
    if (x.attack.length) h += sec('ATT&CK', '<div class="links">' + att(x.attack) + '</div>');
    if (x.cves.length) h += sec('CVEs', '<div class="links">' + x.cves.map(function(c){ return lnk('#detections?cve=' + c, c); }).join('') + '</div>');
    if (x.actor_links.length || x.implant_links.length) h += sec('Actors and implants', '<div class="links">' + lnks(x.actor_links, 'actor') + lnks(x.implant_links, 'implant') + '</div>');
    h += sec('Pack ' + p.id, '<p><b>' + esc(p.name) + '</b></p>' + para(p.summary) + '<div class="links">' + platLinks(p.platforms) + lnk('#detections?pack=' + p.id, 'All ' + p.n + ' detections in this pack') + '</div>');
    return h + refs(p.references);
  },
  exp:function(x){ return {id:x.id, title:x.title, pack:x.pack, platforms:x.platforms.map(function(p){ return PN[p]; }), tier:x.tier, evidence_class:x.evidence,
    type:x.type, check:x.check, rule:x.rule, pattern:x.pattern, sigma_rules:x.sigma.map(function(r){ return RULE[r] ? RULE[r].file : r; }), cves:x.cves, attack:x.attack, notes:x.notes}; },
  summary:function(shown){
    var n = shown.filter(function(x){ return x.sigma.length; }).length, st = S.detections.sel.runs || [];
    return dist('detections', 'tier', ORD.tier, 'Tiers of the detections shown', shown) +
      '<p class="muted small sumline">' + n + ' of ' + shown.length + ' shown have a Sigma rule for your SIEM. ' +
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
    F('reporter', 'Reported by', function(i){ return i.kind === 'actor' ? i.reported_by : []; }),
    F('platform', 'Platform', function(i){ return i.platforms; }, function(v){ return PN[v] || v; })
  ],
  text:function(i){ return [i.id, i.name, (i.aliases || []).join(' '), i.summary, (i.reported_by || []).join(' '), (i.tradecraft || []).join(' '), (i.cves || []).join(' '), i.type, i.motivation].join(' '); },
  card:function(i){
    if (i.kind === 'actor') return hd(i.id, i.name, i.aliases.length ? 'also: ' + esc(i.aliases.join(', ')) : '', b('actor', 'kind-actor') + b(i.motivation, 'mot mot-' + i.motivation)) +
      '<p class="clamp"><q class="quote">' + esc(i.stated_confidence) + '</q></p>' +
      '<div class="lc-f">' + b('link: ' + i.link_confidence, 'conf c-' + i.link_confidence) + chips(i.platforms.map(function(p){ return PN[p]; })) + '</div>';
    return hd(i.id, i.name, i.aliases.length ? esc(i.aliases.join(', ')) : '', b('implant', 'kind-implant') + b(i.type, 'itype')) +
      '<p class="clamp">' + rich(i.summary) + '</p>' +
      '<div class="lc-f">' + b('resides: ' + i.resides, 'res res-' + i.resides) + b('reboot: ' + i.reboot, 'surv surv-' + i.reboot) +
      (i.coverage === 'gap' ? b('coverage gap', 'gap-b') : '<span class="chip">' + i.detections.length + ' detections</span>') + '</div>';
  },
  cls:function(i){ return i.kind === 'implant' && i.coverage === 'gap' ? ' gap' : ''; },
  title:function(i){ return i.name; },
  drawer:function(i){
    var h;
    if (i.kind === 'actor'){
      h = '<div class="links" style="margin-top:14px">' + b('actor', 'kind-actor') + b(i.motivation, 'mot mot-' + i.motivation) + b('link: ' + i.link_confidence, 'conf c-' + i.link_confidence) + '</div>';
      if (i.aliases.length) h += '<p class="muted small">also: ' + esc(i.aliases.join(', ')) + '</p>';
      h += '<div class="attrib"><div><span class="k">Reported by</span> ' + esc(i.reported_by.join(', ')) + '</div><div><span class="k">In their words</span> <q>' + esc(i.stated_confidence) + '</q></div>' +
        (i.state_nexus ? '<div><span class="k">State nexus</span> ' + esc(i.state_nexus) + '</div>' : '') +
        (i.first_seen ? '<div><span class="k">First seen</span> ' + esc(i.first_seen) + '</div>' : '') + '</div>';
      h += para(i.summary);
      h += '<div class="links">' + platLinks(i.platforms) + i.packs.map(function(x){ return lnk('#detections?pack=' + x, x); }).join('') +
        (i.packs.length ? '' : '<span class="chip ghost">no detection pack yet</span>') + i.implants.map(function(x){ return lnk('#intel/' + x, INTEL[x] ? INTEL[x].name : x, 'implant'); }).join('') + '</div>';
      h += sec('Tradecraft', list(i.tradecraft)) + sec('Victimology', list(i.victimology));
    } else {
      h = '<div class="links" style="margin-top:14px">' + b('implant', 'kind-implant') + b(i.type, 'itype') + b('resides: ' + i.resides, 'res res-' + i.resides) + conf(i.confidence, i.unv) + '</div>';
      if (i.aliases.length) h += '<p class="muted small">' + esc(i.aliases.join(', ')) + '</p>';
      h += '<div class="links">' + b('reboot: ' + i.reboot, 'surv surv-' + i.reboot) + b('upgrade: ' + i.upgrade, 'surv surv-' + i.upgrade) + (i.factory_reset ? b('factory reset: ' + i.factory_reset, 'surv surv-' + i.factory_reset) : '') + '</div>';
      h += para(i.summary);
      h += '<div class="links">' + platLinks(i.platforms) + i.actors.map(function(x){ return lnk('#intel/' + x, INTEL[x] ? INTEL[x].name : x, 'actor'); }).join('') + chips(i.cves, 'cve') + '</div>';
      h += sec('Detection coverage', i.detections.length ? '<div class="links">' + i.detections.map(function(id){ return lnk('#detections/' + id, id, 'mono'); }).join('') + '</div>'
        : '<div class="links">' + b('coverage gap', 'gap-b') + '</div>' + (i.gap ? '<p class="note">' + rich(i.gap) + '</p>' : ''));
      h += sec('Artifacts', list(i.artifacts));
      h += sec('Anti-forensics', list(i.anti_forensics));
    }
    if (i.notes) h += '<p class="note">' + rich(i.notes) + '</p>';
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
    function tile(n, label, k, v, warn){ return k ? '<button type="button" class="tile' + (warn ? ' warn' : '') + (on(k, v) ? ' on' : '') + '" data-only="' + k + '" data-v="' + v + '"><b>' + n + '</b><span>' + esc(label) + '</span></button>'
      : '<div class="tile"><b>' + n + '</b><span>' + esc(label) + '</span></div>'; }
    return '<div class="tiles">' + tile(actors, 'actors and named clusters', 'kind', 'actor') + tile(imps.length, 'implants and tool families', 'kind', 'implant') +
      tile(gaps, 'implants with no detection - each says why', 'coverage', 'gap', true) + tile(boot, 'implants that survive a reboot', 'reboot', 'yes', true) +
      tile(Object.keys(rep).length, 'reporting parties, quoted verbatim') + tile(Object.keys(dets).length, 'detections tied to a named implant') + '</div>';
  }
},

hardening: {
  noun:'controls', items:D.hardening, view:'cards',
  facets:[
    F('platform', 'Applies to', function(c){ return [c.platform]; }, function(v){ return v === 'ALL' ? 'Every platform (baseline)' : (PN[v] || v); }),
    F('category', 'Category', function(c){ return [c.category]; }, function(v){ return HCAT[v] || v; }),
    F('priority', 'Priority', function(c){ return [c.priority]; }, null, ['critical','high','medium']),
    F('confidence', 'Confidence', function(c){ return [c.confidence]; }, null, ORD.hml)
  ],
  text:function(c){ return [c.id, c.control, c.why, c.how, c.category, c.platform === 'ALL' ? 'baseline every platform' : PN[c.platform], c.blunts.join(' '),
    c.sources.map(function(x){ return x.title; }).join(' ')].join(' '); },
  card:function(c){
    return hd(c.platform === 'ALL' ? 'Every platform' : PN[c.platform], c.control, '', b(c.priority, 'pr pr-' + c.priority)) +
      '<p class="clamp">' + rich(c.why) + '</p>' +
      '<div class="lc-f"><span class="chip">' + esc(HCAT[c.category] || c.category) + '</span>' + chips(c.blunts.slice(0, 3), 'cve') +
      (c.blunts.length > 3 ? '<span class="chip ghost">+' + (c.blunts.length - 3) + '</span>' : '') + '</div>';
  },
  cls:function(c){ return c.platform === 'ALL' ? ' base' : ''; },
  title:function(c){ return c.control; },
  label:function(c){ return (c.platform === 'ALL' ? 'Baseline' : PN[c.platform]) + ' · ' + c.id; },
  drawer:function(c){
    var h = '<div class="links" style="margin-top:14px">' + b(c.priority, 'pr pr-' + c.priority) + '<span class="chip">' + esc(HCAT[c.category] || c.category) + '</span>' + conf(c.confidence, c.unv) + '</div>';
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
    function tile(num, label, k, v, warn){ return '<button type="button" class="tile' + (warn ? ' warn' : '') + (on(k, v) ? ' on' : '') + '" data-only="' + k + '" data-v="' + v + '"><b>' + num + '</b><span>' + esc(label) + '</span></button>'; }
    var plats = {}; all.forEach(function(c){ if (c.platform !== 'ALL') plats[c.platform] = 1; });
    return '<div class="tiles">' + tile(n('platform', 'ALL'), 'baseline controls - start here, they apply to every platform', 'platform', 'ALL') +
      tile(n('category', 'exposure'), 'about what faces the internet - the management interface first', 'category', 'exposure', true) +
      tile(n('priority', 'critical'), 'critical-priority controls', 'priority', 'critical', true) +
      '<div class="tile"><b>' + Object.keys(plats).length + '</b><span>platforms with their own controls</span></div></div>';
  }
}
};

/* sanity: the facet keys here must match the ones the generator validates links against */
Object.keys(LIB).forEach(function(n){ var a = LIB[n].facets.map(function(f){ return f.k; }).sort().join(','), want = (D.facetKeys[n] || []).slice().sort().join(',');
  if (a !== want) console.error('facet keys for ' + n + ' differ from the generator: ' + a + ' vs ' + want); });

var S = {}, LAST = {}, OPEN = {}, cur = null, openId = null, openLib = null;
Object.keys(LIB).forEach(function(n){
  S[n] = {q:'', sel:{}, unv:false, compact:false, picks:{}};
  LIB[n].items.forEach(function(i){ i._t = LIB[n].text(i).toLowerCase(); });
});
try{ var cp = store('edt-compact'); if (cp === '1') S.artifacts.compact = true; }catch(_){}

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
  var c = {}; list_.forEach(function(i){ var v = i[k]; c[v] = (c[v] || 0) + 1; });
  var sel = S[n].sel[k] || [];
  var segs = order.filter(function(v){ return c[v]; }).map(function(v){
    return '<button type="button" class="seg seg-' + v + (sel.indexOf(v) >= 0 ? ' on' : '') + '" style="flex:' + c[v] + '" data-f="' + k + '" data-v="' + v + '" title="' + v + ': ' + c[v] + ' - click to filter"><b>' + c[v] + '</b> <span>' + esc(v) + '</span></button>'; });
  return segs.length ? '<div class="dist" role="group" aria-label="' + esc(label) + '">' + segs.join('') + '</div>' : '';
}

function renderRail(n){
  var L = LIB[n], st = S[n], h = '';
  L.facets.forEach(function(f){
    var tot = {}, cnt = {};
    L.items.forEach(function(i){ (f.get(i) || []).forEach(function(v){ tot[v] = 1; }); });
    L.items.forEach(function(i){ if (pass(n, st, i, f.k)) (f.get(i) || []).forEach(function(v){ cnt[v] = (cnt[v] || 0) + 1; }); });
    var vals = Object.keys(tot);
    if (!vals.length) return;
    if (f.order) vals.sort(function(a, c){ var x = f.order.indexOf(a), y = f.order.indexOf(c); return (x < 0 ? 99 : x) - (y < 0 ? 99 : y); });
    else vals.sort(function(a, c){ return (cnt[c] || 0) - (cnt[a] || 0) || f.name(a).localeCompare(f.name(c)); });
    var sel = st.sel[f.k] || [], key = n + ':' + f.k, open = OPEN[key], lim = open || vals.length <= 9 ? vals.length : 7;
    var shut = OPEN[key + ':shut'];
    h += '<div class="fgroup' + (shut ? ' shut' : '') + '"><button type="button" class="fhead" data-fold="' + key + '" aria-expanded="' + !shut + '"><span class="car">▼</span>' + esc(f.label) + (sel.length ? '<span class="fsel">' + sel.length + '</span>' : '') + '</button><div class="fvals">';
    vals.slice(0, lim).forEach(function(v){
      var on = sel.indexOf(v) >= 0, c = cnt[v] || 0;
      h += '<label class="fv' + (on ? ' on' : '') + (c || on ? '' : ' zero') + '" title="' + esc(f.name(v)) + '"><input type="checkbox" data-f="' + f.k + '" value="' + esc(v) + '"' + (on ? ' checked' : '') + '><span class="box"></span><span class="fl">' + esc(f.name(v)) + '</span><span class="fc">' + c + '</span></label>';
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
      items.map(function(i){ return '<div class="row item' + (i.unv ? ' unv' : '') + sel(i) + '" role="button" tabindex="0" data-id="' + esc(i.id) + '">' + L.row(i) + '</div>'; }).join('') + '</div>';
  } else res.innerHTML = '<div class="lgrid">' + items.map(function(i){ return '<article class="lc item' + (i.unv ? ' unv' : '') + (L.cls ? L.cls(i) : '') + sel(i) + '" role="button" tabindex="0" data-id="' + esc(i.id) + '">' + L.card(i) + '</article>'; }).join('') + '</div>';
  renderRail(n);
  writeHash();
  navState();
}

function rerender(){ if (LIB[cur]) renderLib(cur); }
function syncControls(n){
  var P = $('tab-' + n), st = S[n], q = P.querySelector('.q'), u = P.querySelector('.unvT'), c = P.querySelector('.cmpT');
  if (q.value !== st.q) q.value = st.q;
  if (u) u.setAttribute('aria-pressed', String(st.unv));
  if (c) c.setAttribute('aria-pressed', String(st.compact));
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
  var h = '#' + cur + (a ? '/' + encodeURIComponent(a) : '') + (LIB[cur] ? qs(cur) : '');
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
    if (tab === 'guide'){
      pageAnchor.guide = anchor || '';
      document.querySelectorAll('.toc a').forEach(function(a){ a.classList.toggle('on', !!anchor && a.dataset.g === anchor); });
      var g = anchor && document.getElementById('g-' + anchor);
      if (g) setTimeout(function(){ g.scrollIntoView({block:'start'}); }, 0);
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
var tocObs = null;
function renderToc(){
  var cur_ = pageAnchor.guide || '';
  $('rail').innerHTML = '<nav class="toc" aria-label="Guide contents">' + D.toc.map(function(t){
    var id = t.id.slice(2);
    return '<a class="l' + t.level + (id === cur_ ? ' on' : '') + '" href="#guide/' + id + '" data-g="' + id + '">' + esc(t.title) + '</a>'; }).join('') + '</nav>';
  $('railToggle').textContent = 'Contents';
  if (tocObs || !('IntersectionObserver' in window)) return;
  tocObs = new IntersectionObserver(function(es){
    es.forEach(function(en){
      if (!en.isIntersecting || cur !== 'guide') return;
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
  var el = document.querySelector('#tab-' + cur + ' .item[data-id="' + (window.CSS && CSS.escape ? CSS.escape(openId) : openId) + '"]');
  if (el){ el.classList.add('sel'); var r = el.getBoundingClientRect(); if (r.top < 0 || r.bottom > window.innerHeight) el.scrollIntoView({block:'center'}); }
}
function navState(){
  var l = LAST[openLib] || [], i = -1;
  for (var k = 0; k < l.length; k++) if (l[k].id === openId){ i = k; break; }
  $('dPrev').disabled = i <= 0; $('dNext').disabled = i < 0 || i >= l.length - 1;
}
function openDrawer(n, id){
  var L = LIB[n], it = null;
  for (var k = 0; k < L.items.length; k++) if (L.items[k].id === id){ it = L.items[k]; break; }
  if (!it){ toast('Nothing called ' + id + ' in ' + n); closeDrawer(); return; }
  openId = id; openLib = n;
  $('dId').textContent = L.label ? L.label(it) : it.id; $('dTitle').textContent = L.title(it);
  $('dBody').innerHTML = L.drawer(it); $('dBody').scrollTop = 0;
  $('drawer').hidden = false; $('scrim').hidden = false; document.body.classList.add('drawer-open');
  markSel(); navState(); writeHash();
}
function closeDrawer(write){
  var was = !$('drawer').hidden;
  $('drawer').hidden = true; $('scrim').hidden = true; document.body.classList.remove('drawer-open');
  openId = null; markSel();
  if (write !== false && was) writeHash();
}
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
  P.querySelectorAll('[data-exp]').forEach(function(x){ x.addEventListener('click', function(){ exportLib(n, x.dataset.exp); }); });
  P.addEventListener('change', function(ev){
    var t = ev.target;
    if (t.classList.contains('pick')){ var id = t.closest('.item').dataset.id; if (t.checked) S[n].picks[id] = 1; else delete S[n].picks[id]; updatePicked(n); }
    if (t.classList.contains('pickall')){ LAST[n].forEach(function(i){ if (t.checked) S[n].picks[i.id] = 1; else delete S[n].picks[i.id]; }); renderLib(n); }
  });
  P.addEventListener('click', function(ev){
    var t = ev.target;
    if (t.closest('.pick,.pickall,a,.copy')) return;
    var rm = t.closest('[data-rm]');
    if (rm){ var k = rm.dataset.rm; if (k === 'q') S[n].q = ''; else if (k === 'unv') S[n].unv = false; else { var a = S[n].sel[k] || []; a.splice(a.indexOf(rm.dataset.v), 1); } syncControls(n); renderLib(n); return; }
    var act = t.closest('[data-act]');
    if (act){ if (act.dataset.act === 'reset') resetLib(n); if (act.dataset.act === 'unpick'){ S[n].picks = {}; renderLib(n); } return; }
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
  var text = b.dataset.copy || ((b.parentElement.querySelector('code') || {}).textContent) || '';
  copyText(text, function(){ var t = b.textContent; b.textContent = 'Copied'; setTimeout(function(){ b.textContent = t; }, 1200); });
});

/* ---------------------------------------------------------------- keyboard */
document.addEventListener('keydown', function(ev){
  var tag = (document.activeElement || {}).tagName || '', typing = /INPUT|SELECT|TEXTAREA/.test(tag);
  if (ev.key === '/' && !typing && LIB[cur]){ ev.preventDefault(); $('tab-' + cur).querySelector('.q').focus(); return; }
  if (ev.key === 'Escape'){
    if (!$('drawer').hidden){ closeDrawer(); return; }
    if (typing && document.activeElement.classList.contains('q')){ document.activeElement.value = ''; S[cur].q = ''; renderLib(cur); document.activeElement.blur(); }
    return;
  }
  if (!$('drawer').hidden && !typing && (ev.key === 'ArrowLeft' || ev.key === 'k')){ stepDrawer(-1); ev.preventDefault(); }
  if (!$('drawer').hidden && !typing && (ev.key === 'ArrowRight' || ev.key === 'j')){ stepDrawer(1); ev.preventDefault(); }
});

/* ---------------------------------------------------------------- response picker */
function pickResp(stem){
  if (!document.querySelector('.resp[data-resp="' + stem + '"]')) return;
  pageAnchor.response = stem;
  document.querySelectorAll('.rbtn').forEach(function(b){ b.setAttribute('aria-pressed', String(b.dataset.resp === stem)); });
  document.querySelectorAll('.resp').forEach(function(s){ s.hidden = s.dataset.resp !== stem; });
}
document.querySelectorAll('.rbtn').forEach(function(b){ b.addEventListener('click', function(){ history.replaceState(null, '', '#response/' + b.dataset.resp); pickResp(b.dataset.resp); }); });

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
  var bundle = $('b-bundle').checked, bg = $('b-bg').checked;
  var parts = ['python -m edgetriage collect', '--profile ' + p.name, '--case-id ' + sh(val('b-case', 'IR-2026-001'))];
  if (p.ssh){ parts.push('--host ' + sh(val('b-host', '<device>'))); parts.push('--user ' + sh(val('b-user', '<readonly-user>'))); }
  else parts.push('--replay ./' + p.name + '-checklist   # nothing to connect to; steps are recorded as manual');
  var op = $('b-op').value.trim(); if (op) parts.push('--operator ' + sh(op));
  parts.push('--rebooted ' + $('b-reboot').value, '--patched ' + $('b-patch').value);
  document.querySelectorAll('#b-vars input').forEach(function(i){ if (i.value.trim()) parts.push('--var ' + sh(i.dataset['var'] + '=' + i.value.trim())); });
  if (bundle || bg) parts.push('--allow-bundle'); if (bg) parts.push('--break-glass');
  $('b-out').textContent = parts.join(' \\\n    ');
  var n = 0, off = 0;
  document.querySelectorAll('.plan[data-profile="' + p.name + '"] .step').forEach(function(r){
    var imp = r.dataset.impact, on = imp === 'none' || (imp === 'vendor-bundle' && (bundle || bg)) || (imp === 'break-glass' && bg);
    r.classList.toggle('off', !on); if (on) n++; else off++;
  });
  $('b-sum').textContent = n + ' step(s) will run' + (off ? ', ' + off + ' withheld' : '') + '.';
}
['b-case','b-host','b-user','b-op','b-reboot','b-patch','b-bundle','b-bg'].forEach(function(id){
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
            ("platforms", "Platforms", len(data["platforms"])), ("detections", "Detections", n_det),
            ("intel", "Threat intel", len(data["intel"])), ("response", "Response", len(d["response"])),
            ("hardening", "Hardening", len(data["hardening"])), None,
            ("plans", "Collection plans", len(d["profiles"])), ("coverage", "Coverage", None), ("guide", "Guide", None)]
    tabbar = "".join('<span class="tabsep" aria-hidden="true"></span>' if t is None else
                     f'<button type="button" role="tab" data-tab="{t[0]}" aria-selected="false">{t[1]}'
                     + (f'<span class="n">{t[2]}</span>' if t[2] is not None else "") + "</button>" for t in tabs)
    ctx = {"cves": {c for x in data["detections"] for c in x["cves"]},
           "platforms": {p["id"]: p for p in data["platforms"]}, "notes_seen": set()}
    guide_html = markdown(d["guide"], ctx)
    data["guideNotes"] = sorted(ctx["notes_seen"])
    data["toc"] = guide_toc(d["guide"])
    panels = f'<section class="panel" id="tab-start" role="tabpanel" hidden>{render_start(d, data)}</section>'
    panels += "".join(lib_panel(n, unv[n], n == "artifacts") for n in LIBS)
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
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Edge DFIR Toolkit</title>
<meta name="description" content="Forensic triage for compromised VPN concentrators, firewalls and gateways: artifact library, collection plans, detections, threat intel and response playbooks.">
<meta name="color-scheme" content="light dark">
<link rel="icon" href="{icon}">
<style>{CSS}</style></head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="hdr"><div class="hdr-in">
  <div class="hdr-top">
    <div class="hdr-id"><div class="h1row"><span class="dot"></span><h1>Edge DFIR Toolkit</h1><span class="pill">v{e(__version__)} &#183; Apache-2.0</span></div>
      <p class="sub">What a compromised VPN concentrator, firewall or gateway leaves behind, what each trace proves, how long it lasts, and in what order to collect it.</p></div>
    <div class="hdr-right">
      <a class="hbtn" href="{REPO_URL}" rel="noopener">GitHub &#8599;</a>
      <button type="button" class="hbtn" id="themeBtn">Theme</button>
    </div>
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
<aside class="drawer" id="drawer" hidden aria-labelledby="dTitle">
  <div class="dhead"><div><span class="id" id="dId"></span><h2 id="dTitle"></h2></div>
    <div class="dacts"><button type="button" id="dPrev" title="Previous (&#8592; or k)" aria-label="Previous record">&#8592;</button><button type="button" id="dNext" title="Next (&#8594; or j)" aria-label="Next record">&#8594;</button>
      <button type="button" id="dLink">Copy link</button><button type="button" id="dWide">Wider</button><button type="button" id="dClose" aria-label="Close (Esc)">&#215;</button></div></div>
  <div class="dbody" id="dBody"></div>
</aside>
<div class="toast" id="toast" role="status" hidden></div>
<footer>
  {len(data['platforms'])} platforms &#183; {len(data['artifacts'])} artifacts &#183; {len(d['profiles'])} collection profiles &#183; {n_det} detections in {len(d['packs'])} packs &#183; {len(d['rules'])} rule files.
  Built from the repository on {built}; every figure is computed from the catalog, profiles, packs, rules and intel at build time.
  Detection content is Sigma and YARA only. Independent project, not affiliated with any employer or with any vendor whose products it covers.
  Keyboard: <kbd>/</kbd> search, <kbd>&#8592;</kbd> <kbd>&#8594;</kbd> step through records, <kbd>Esc</kbd> close.
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
