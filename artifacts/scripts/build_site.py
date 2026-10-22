#!/usr/bin/env python3
"""build_site.py - generate the GitHub Pages site from the repository.

  python artifacts/scripts/build_site.py          # write docs/site/index.html
  python artifacts/scripts/build_site.py --check  # data contract only, writes nothing

One self-contained HTML file: vanilla JS, no framework, no CDN, no build step,
never hand-edited and never committed. CI builds it at deploy time from the
catalog, the collection profiles, the detection packs, the rules and the
investigation guide, so the page cannot drift from the content.
"""
from __future__ import annotations

import datetime as _dt
import html
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

from edgetriage import __version__  # noqa: E402
from edgetriage.profiles import TIER_CLASS, TIER_ORDER, available_profiles, load_profile  # noqa: E402

OUT = ROOT / "docs" / "site" / "index.html"
REPO_URL = "https://github.com/depalmar/edge-dfir-toolkit"
TIERS = ("possible", "likely", "confirmed")
CLASSES = ["identity", "memory", "process", "sessions", "integrity", "config",
           "auth-logs", "web-logs", "system-logs", "filesystem", "persistence"]
TIER_LABEL = {
    "V0": "Identity and clock", "V1": "Memory state", "V2": "Processes and sockets",
    "V3": "Active sessions", "P1": "Integrity", "P2": "Configuration", "P3": "Auth and VPN logs",
    "P4": "Web and portal logs", "P5": "System and crash logs", "P6": "Filesystem",
    "P7": "Persistence", "B": "Vendor bundles", "X": "Break-glass",
}
e = html.escape


def js_data(obj) -> str:
    """JSON for a <script> block, with "</" escaped so no string in the corpus
    can close the script element early."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).replace("</", "<\\/")


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


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
            fmt = "Sigma"
        else:
            names = re.findall(r"^rule\s+(\w+)", text, re.M)
            title = ", ".join(names)
            m = re.search(r'description\s*=\s*"([^"]+)"', text)
            desc, level, tags, fmt = (m.group(1) if m else ""), "", [], "YARA"
        rules.append({"file": f.relative_to(ROOT).as_posix(), "dir": f.parent.name, "format": fmt,
                      "title": title, "description": desc, "level": level, "tags": tags, "body": text})
    guide = (ROOT / "docs" / "edge-dfir-investigation-guide.md").read_text()
    intel = ROOT / "artifacts" / "intel"
    actors = sorted((yaml.safe_load(f.read_text()) for f in (intel / "actors").glob("*.yml")), key=lambda a: a["id"])
    implants = sorted((yaml.safe_load(f.read_text()) for f in (intel / "implants").glob("*.yml")), key=lambda i: i["id"])
    response = {f.stem: yaml.safe_load(f.read_text()) for f in sorted((ROOT / "artifacts" / "response").glob("*.yml"))}
    return {"catalog": catalog, "profiles": profiles, "packs": packs, "rules": rules, "guide": guide,
            "actors": actors, "implants": implants, "response": response}


# --------------------------------------------------------------------------- markdown
def md_inline(s: str) -> str:
    s = e(s, quote=False)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)", r'<a href="\2" rel="noopener">\1</a>', s)
    return s


def markdown(md: str) -> str:
    """Enough Markdown for the guide: headings, paragraphs, lists, fences, tables."""
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
            out.append(f'<h{lvl} id="g-{slug(m.group(2))}">{md_inline(m.group(2))}</h{lvl}>')
            i += 1
            continue
        if ln.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            head, body = rows[0], [r for r in rows[1:] if not all(re.fullmatch(r":?-+:?", c) for c in r)]
            out.append("<table class=\"tbl\"><thead><tr>" + "".join(f"<th>{md_inline(c)}</th>" for c in head)
                       + "</tr></thead><tbody>" + "".join("<tr>" + "".join(f"<td>{md_inline(c)}</td>" for c in r) + "</tr>" for r in body)
                       + "</tbody></table>")
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
            out.append(f"<{tag}>" + "".join(f"<li>{md_inline(x)}</li>" for x in items) + f"</{tag}>")
            continue
        if not ln.strip():
            i += 1
            continue
        buf = []
        while i < len(lines) and lines[i].strip() and not re.match(r"^(#|```|\||\s*(-|\d+\.)\s)", lines[i]):
            buf.append(lines[i].strip())
            i += 1
        out.append(f"<p>{md_inline(' '.join(buf))}</p>")
    return "\n".join(out)


# --------------------------------------------------------------------------- fragments
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


def search_blob(*parts) -> str:
    return e(" ".join(str(p) for p in parts if p).lower())


def render_platforms(d: dict, packs_by_platform: dict) -> str:
    cards = []
    shell = {"yes": "shell: yes", "restricted": "shell: restricted", "no": "shell: none"}
    for c in d["catalog"]:
        unv = c.get("unverified") or any(x.get("unverified") for x in c.get("collection", []))
        coll = "".join(
            f'<li><div class="row">{impact_badge(x["impact"])} <b>{e(x["method"])}</b> {conf_badge(x["confidence"], x.get("unverified", False))}</div>'
            f'<div class="muted">{e(x["description"])}</div></li>' for x in c["collection"])
        vol = "".join(f"<li>{e(v)}</li>" for v in c.get("volatility", []))
        af = "".join(f'<li><b>{e(a["technique"])}</b> <span class="muted">- {e(a["seen_in"])}</span>'
                     + (f'<div class="muted">{e(a["detail"])}</div>' if a.get("detail") else "") + "</li>"
                     for a in c.get("anti_forensics", []))
        pk = "".join(f'<a class="chip link" href="#packs/{e(p)}">{e(p)}</a>' for p in packs_by_platform.get(c["id"], []))
        prof = (f'<a class="chip link" href="#plans/{e(c["profile"])}">profile: {e(c["profile"])}</a>'
                if c.get("profile") else '<span class="chip ghost">no profile yet</span>')
        refs = "".join(f'<li><a href="{e(r["url"])}" rel="noopener">{e(r["title"])}</a></li>' for r in c["references"])
        unv = unv or any(a.get("unverified") for a in c.get("artifacts", []))
        art_rows = "".join(
            f'<tr class="{"unv" if a.get("unverified") else ""}"><td><code class="loc">{e(a["locator"])}</code>'
            f'<div class="muted small">{e(a["description"])}</div>'
            + (f'<div class="small">{chips(a["seen_in"], "chip implant")}</div>' if a.get("seen_in") else "")
            + f'</td><td>{badge(a["class"], "cls")}</td><td>{badge(a["volatility"], "vol vol-" + a["volatility"])}'
            + (f'<div class="muted small">{e(a["retention"])}</div>' if a.get("retention") else "")
            + f'</td><td>{badge(a["forensic_value"], "fv fv-" + a["forensic_value"])}</td>'
            f'<td>{chips(a["evidence_type"], "chip mono nw")}</td>'
            f'<td><span class="chip mono nw">{e(a.get("collected_by", "-"))}</span></td>'
            f'<td>{conf_badge(a["confidence"], a.get("unverified", False))}</td></tr>'
            for a in c.get("artifacts", []))
        artifacts = (f'<details class="arts" open><summary>Artifacts ({len(c.get("artifacts", []))})</summary>'
                     f'<div class="scroll"><table class="tbl arttbl"><thead><tr><th>Locator and what it proves</th><th>Class</th>'
                     f'<th>Volatility</th><th>Value</th><th>Evidence</th><th>Collected by</th><th>Conf.</th></tr></thead>'
                     f'<tbody>{art_rows}</tbody></table></div></details>') if art_rows else ""
        resp = (f'<a class="chip link" href="#response/{e(c["response"])}">containment and recovery</a>'
                if c.get("response") else "")
        cards.append(f'''
<article class="card item{' unv' if unv else ''}" id="platform-{e(c['id'])}"
  data-search="{search_blob(c['id'], c['name'], c['vendor'], c.get('os_base'), *c.get('products', []))}">
  <header class="card-h">
    <div><span class="id">{e(c['id'])}</span><h3>{e(c['name'])}</h3><div class="muted">{e(c['vendor'])} - {e(c['os_base'])}</div></div>
    <div class="badges">{badge(shell[c['customer_shell']], 'sh-' + c['customer_shell'])}{badge('memory: ' + c['memory_acquisition'], 'mem')}{conf_badge(c['confidence'], c.get('unverified', False))}</div>
  </header>
  {f'<p class="fs">{e(c["filesystem"])}</p>' if c.get('filesystem') else ''}
  <div class="links">{prof}{pk}{resp}</div>
  <h4>Collection paths</h4><ul class="plain">{coll}</ul>
  {artifacts}
  {f'<h4>Lost on reboot or upgrade</h4><ul>{vol}</ul>' if vol else ''}
  {f'<h4>Anti-forensics seen in public reporting</h4><ul class="plain">{af}</ul>' if af else ''}
  {f'<p class="note">{e(c["notes"])}</p>' if c.get('notes') else ''}
  <details><summary>References</summary><ul>{refs}</ul></details>
</article>''')
    return f'<div class="lede">What a responder can reach on each platform, how, and what disappears if you wait. Each card lists its artifacts with forensic value, volatility and the step that collects them. Cards marked <span class="badge unv-b">unverified</span> carry at least one claim nobody has confirmed on a device.</div><div class="stack">{"".join(cards)}</div>'


def render_plans(d: dict) -> str:
    picker, sections = [], []
    for i, p in enumerate(d["profiles"]):
        picker.append(f'<button type="button" class="pbtn" data-profile="{e(p.name)}" aria-pressed="{str(i == 0).lower()}">{e(p.display)}</button>')
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
                rows.append(f'''<tr class="item step imp-{e(s.impact)}{' unv' if s.unverified else ''}" data-impact="{e(s.impact)}"
  data-search="{search_blob(s.id, cmd, s.purpose, s.instructions)}">
  <td class="id">{e(s.id)}</td><td>{impact_badge(s.impact)}<div class="kind">{e(s.kind)}</div></td>
  <td>{what}{needs}<div class="purpose">{e(s.purpose)}</div>{instr}</td>
  <td>{conf_badge(s.confidence, s.unverified)}</td></tr>''')
            groups.append(f'<tr class="tierrow"><th colspan="4"><span class="tchip">{e(tier)}</span> {e(TIER_LABEL[tier])} <span class="muted">- {e(TIER_CLASS[tier])}</span></th></tr>' + "".join(rows))
        sections.append(f'''
<section class="plan" data-profile="{e(p.name)}" id="plan-{e(p.name)}"{'' if i == 0 else ' hidden'}>
  <div class="plan-h"><div><span class="id">{e(p.platform_id)}</span> <h3>{e(p.display)}</h3></div>
    <a class="chip link" href="#platforms/{e(p.platform_id)}">platform entry</a></div>
  <details class="guard"><summary>Read-only guard</summary>
    <div class="cols"><div><h4>Allow</h4>{chips(p.allow, 'chip mono')}</div><div><h4>Deny</h4>{chips(p.deny, 'chip mono')}</div>
    <div><h4>Session setup</h4>{chips(p.session_setup, 'chip mono') or '<span class="muted">none</span>'}</div>
    <div><h4>Prompt / pager</h4>{chips([p.prompt] + ([p.pager] if p.pager else []), 'chip mono')}</div></div></details>
  <table class="tbl steps"><thead><tr><th>Step</th><th>Impact</th><th>Command and purpose</th><th>Confidence</th></tr></thead>
  <tbody>{"".join(groups)}</tbody></table>
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
  <label class="tog"><input type="checkbox" id="b-bundle"> Allow vendor bundles <span class="muted">(writes a temp file on the device)</span></label>
  <label class="tog"><input type="checkbox" id="b-bg"> Break-glass <span class="muted">(runs last, asks for confirmation)</span></label>
  <div class="codewrap"><button class="copy" type="button" id="b-copy">Copy</button><pre><code id="b-out"></code></pre></div>
  <div class="muted" id="b-sum"></div>
</aside>'''
    return f'''<div class="lede">Every profile in order of volatility. Bundle and break-glass rows stay greyed out until you allow them in the builder, exactly as the collector behaves.</div>
<div class="picker">{"".join(picker)}</div>
<div class="planwrap"><div class="plans">{"".join(sections)}</div>{builder}</div>'''


def render_packs(d: dict, plat_names: dict) -> str:
    filt = ['<button type="button" class="fbtn" data-plat="" aria-pressed="true">All platforms</button>']
    filt += [f'<button type="button" class="fbtn" data-plat="{e(pid)}" aria-pressed="false">{e(n)}</button>' for pid, n in plat_names.items()]
    cards = []
    for p in d["packs"]:
        rows = "".join(f'''<tr><td class="id">{e(x["id"])}</td><td>{e(x["title"])}{f'<div class="muted small">{e(x["notes"])}</div>' if x.get("notes") else ''}</td>
<td><span class="chip mono nw">{e(x["type"])}{(":" + e(x["check"])) if x.get("check") else ""}</span></td><td>{tier_badge(x["tier"])}</td>
<td>{e(x["evidence_class"])}</td><td>{chips(x.get("attack", []), "chip mono")}</td></tr>''' for x in p["detect"])
        refs = "".join(f'<li><a href="{e(r["url"])}" rel="noopener">{e(r["title"])}</a></li>' for r in p["references"])
        top = max((x["tier"] for x in p["detect"]), key=TIERS.index)
        cards.append(f'''
<article class="card item pack{' unv' if p.get('unverified') else ''}" id="pack-{e(p['id'])}" data-plat="{e(' '.join(p['platforms']))}"
  data-search="{search_blob(p['id'], p['name'], *p.get('cves', []), *p.get('actors', []), *p.get('implants', []), *[x['id'] for x in p['detect']])}">
  <header class="card-h"><div><span class="id">{e(p['id'])}</span><h3>{e(p['name'])}</h3>
    <div class="links">{''.join(f'<a class="chip link" href="#platforms/{e(x)}">{e(plat_names.get(x, x))}</a>' for x in p['platforms'])}</div></div>
    <div class="badges">{conf_badge(p['confidence'], p.get('unverified', False))}{tier_badge('up to ' + top)}</div></header>
  <div class="links">{chips(p.get('cves', []), 'chip cve')}{chips(p.get('actors', []), 'chip actor')}{chips(p.get('implants', []), 'chip implant')}</div>
  <p>{e(p['summary'].strip())}</p>
  <table class="tbl"><thead><tr><th>Detection</th><th>What it finds</th><th>Type</th><th>Tier</th><th>Class</th><th>ATT&amp;CK</th></tr></thead><tbody>{rows}</tbody></table>
  <details><summary>References</summary><ul>{refs}</ul></details>
</article>''')
    return f'''<div class="lede">Each detection reports <b>hit</b>, <b>no hit</b> or <b>not evaluated</b>. Not evaluated is never a pass: it becomes an evidence gap in the report.</div>
<div class="filters">{"".join(filt)}</div><div class="stack">{"".join(cards)}</div>'''


def render_rules(d: dict) -> str:
    out = []
    for r in d["rules"]:
        meta = f'{badge(r["format"], "fmt fmt-" + r["format"].lower())}' + (badge(r["level"], "lvl lvl-" + r["level"]) if r["level"] else "")
        out.append(f'''
<details class="rule item" id="rule-{slug(r['file'])}" data-search="{search_blob(r['file'], r['title'], r['description'], *r['tags'])}">
  <summary><div class="rhead">{meta}<b>{e(r['title'])}</b></div><div class="rfile">{e(r['file'])}</div></summary>
  <p class="muted">{e(r['description'])}</p>
  {f'<div class="links">{chips(r["tags"], "chip mono")}</div>' if r['tags'] else ''}
  <div class="codewrap"><button class="copy" type="button">Copy</button><pre><code>{e(r['body'])}</code></pre></div>
</details>''')
    return ('<div class="lede">Vendor-neutral Sigma and YARA. Convert Sigma for your SIEM with '
            '<code>sigma convert -t &lt;backend&gt;</code>; no vendor query dialect is shipped.</div>' + "".join(out))


def render_intel(d: dict, plat_names: dict) -> str:
    """Actors and implants. Attribution is reported, never computed: each actor
    shows our link confidence (provenance) beside the reporter's own words, and
    each implant shows which detections cover it or why nothing does."""
    imp_by_id = {i["id"]: i for i in d["implants"]}
    det_owner = {x["id"]: p["id"] for p in d["packs"] for x in p["detect"]}
    actors = []
    for a in d["actors"]:
        imps = "".join(f'<a class="chip implant" href="#intel/{e(i)}">{e(imp_by_id[i]["name"] if i in imp_by_id else i)}</a>'
                       for i in a.get("implants", []))
        pks = "".join(f'<a class="chip link" href="#packs/{e(x)}">{e(x)}</a>' for x in a.get("packs", []))
        plats = "".join(f'<a class="chip link" href="#platforms/{e(x)}">{e(plat_names.get(x, x))}</a>' for x in a["platforms"])
        trade = "".join(f"<li>{e(t)}</li>" for t in a.get("tradecraft", []))
        refs = "".join(f'<li><a href="{e(r["url"])}" rel="noopener">{e(r["title"])}</a></li>' for r in a["references"])
        nopack = '' if a.get("packs") else '<span class="chip ghost">no detection pack yet</span>'
        actors.append(f'''
<article class="card item" id="intel-{e(a['id'])}" data-search="{search_blob(a['id'], a['name'], *a.get('aliases', []), *a.get('reported_by', []), a.get('summary'))}">
  <header class="card-h"><div><span class="id">{e(a['id'])}</span><h3>{e(a['name'])}</h3>
    {f'<div class="muted small">also: {e(", ".join(a["aliases"]))}</div>' if a.get('aliases') else ''}</div>
    <div class="badges">{badge(a.get('motivation', 'unknown'), 'mot mot-' + a.get('motivation', 'unknown'))}{badge('link: ' + a['link_confidence'], 'conf c-' + a['link_confidence'])}</div></header>
  <div class="attrib"><div><span class="k">Reported by</span> {e(", ".join(a["reported_by"]))}</div>
    <div><span class="k">In their words</span> <q>{e(a["stated_confidence"])}</q></div>
    {f'<div><span class="k">State nexus</span> {e(a["state_nexus"])}</div>' if a.get("state_nexus") else ''}</div>
  <p>{e(a['summary'].strip())}</p>
  <div class="links">{plats}{pks}{nopack}{imps}</div>
  {f'<h4>Tradecraft</h4><ul>{trade}</ul>' if trade else ''}
  {f'<p class="note">{e(a["notes"].strip())}</p>' if a.get('notes') else ''}
  <details><summary>References</summary><ul>{refs}</ul></details>
</article>''')
    implants = []
    for i in d["implants"]:
        dets = "".join(f'<a class="chip mono nw link" href="#packs/{e(det_owner.get(x, ""))}">{e(x)}</a>' for x in i.get("detections", []))
        cov = dets or '<span class="badge gap-b">coverage gap</span>'
        surv = "".join(badge(f"{k.replace('survives_', '').replace('_', ' ')}: {i[k]}", "surv surv-" + str(i[k]))
                       for k in ("survives_reboot", "survives_upgrade", "survives_factory_reset") if k in i)
        arts = "".join(f"<li><code>{e(x)}</code></li>" for x in i.get("artifacts", []))
        af = "".join(f"<li>{e(x)}</li>" for x in i.get("anti_forensics", []))
        refs = "".join(f'<li><a href="{e(r["url"])}" rel="noopener">{e(r["title"])}</a></li>' for r in i["references"])
        implants.append(f'''
<article class="card item{' gapcard' if not i.get('detections') else ''}" id="intel-{e(i['id'])}"
  data-search="{search_blob(i['id'], i['name'], *i.get('aliases', []), *i.get('cves', []), i.get('summary'))}">
  <header class="card-h"><div><span class="id">{e(i['id'])}</span><h3>{e(i['name'])}</h3>
    {f'<div class="muted small">{e(", ".join(i["aliases"]))}</div>' if i.get('aliases') else ''}</div>
    <div class="badges">{badge(i['type'], 'itype')}{badge('resides: ' + i['resides'], 'res res-' + i['resides'])}{conf_badge(i['confidence'], i.get('unverified', False))}</div></header>
  <div class="links">{surv}</div>
  <div class="links">{chips(i.get('cves', []), 'chip cve')}</div>
  <p>{e(i['summary'].strip())}</p>
  {f'<h4>Artifacts</h4><ul>{arts}</ul>' if arts else ''}
  {f'<h4>Anti-forensics</h4><ul>{af}</ul>' if af else ''}
  <h4>Detection coverage</h4><div class="links">{cov}</div>
  {f'<p class="note">{e(i["gap"].strip())}</p>' if i.get('gap') else ''}
  <details><summary>References</summary><ul>{refs}</ul></details>
</article>''')
    n_gap = sum(1 for i in d["implants"] if not i.get("detections"))
    return f'''<div class="lede">Attribution here is <b>reported, never computed</b>. Each actor carries two confidences: our <b>link</b> confidence (how well-sourced the link is) and the reporting party's <b>own words</b>, quoted. Clusters are only merged where the reporters themselves equate them.</div>
<h3 class="sect">Actors <span class="muted">({len(d["actors"])})</span></h3><div class="grid">{"".join(actors)}</div>
<h3 class="sect">Implants <span class="muted">({len(d["implants"])}, {n_gap} with a coverage gap)</span></h3>
<div class="lede">What survives a reboot, an upgrade or a factory reset decides your recovery. An implant with no detection shows its gap and why.</div>
<div class="grid">{"".join(implants)}</div>'''


def render_response(d: dict, plat_names: dict) -> str:
    """Containment and recovery, ordered: preserve, contain, rotate, eradicate,
    recover, verify. Guidance a human acts on, not automation."""
    secs = []
    for stem, r in d["response"].items():
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
<article class="card item resp" id="response-{e(stem)}" data-search="{search_blob(r['name'], r['platform_id'], stem)}">
  <header class="card-h"><div><span class="id">{e(r['platform_id'])}</span><h3>{e(r['name'])}</h3></div>
    <div class="badges"><a class="chip link" href="#platforms/{e(r['platform_id'])}">platform entry</a>{conf_badge(r.get('confidence', 'medium'), False)}</div></header>
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
  <div class="dont"><h4>Do not</h4><ul class="plain">{dont}</ul></div>
  {f'<p class="note">{e(r["notes"].strip())}</p>' if r.get('notes') else ''}
  <details><summary>Vendor guidance and references</summary><ul>{vg}{refs}</ul></details>
</article>''')
    return f'''<div class="lede">Containment and recovery for each platform, in the order that protects evidence: <b>preserve</b>, contain, rotate credentials, eradicate, recover, verify. This is guidance a person acts on after triage - the toolkit never contains or remediates on its own. Always follow the vendor's current guidance for your exact release.</div>
<div class="stack">{"".join(secs)}</div>'''


def render_coverage(d: dict, plat_names: dict) -> str:
    head = "".join(f'<th class="vert"><span>{e(c)}</span></th>' for c in CLASSES)
    rows = []
    for p in d["packs"]:
        cells = []
        for c in CLASSES:
            ts = [x["tier"] for x in p["detect"] if x["evidence_class"] == c]
            if ts:
                t = max(ts, key=TIERS.index)
                cells.append(f'<td class="cell t-{t}" title="{len(ts)} detection(s), up to {t}">{len(ts)}</td>')
            else:
                cells.append('<td class="cell"></td>')
        rows.append(f'<tr><th class="rowh"><a href="#packs/{e(p["id"])}">{e(p["id"])}</a> <span class="muted">{e(", ".join(p.get("cves", [])[:2]))}{" ..." if len(p.get("cves", [])) > 2 else ""}</span></th>{"".join(cells)}</tr>')
    prow = []
    for p in d["profiles"]:
        counts = {t: sum(1 for s in p.steps if s.tier == t) for t in TIER_ORDER}
        unv = sum(1 for s in p.steps if s.unverified)
        cells = "".join(f'<td class="num">{counts[t] or ""}</td>' for t in TIER_ORDER)
        prow.append(f'<tr><th class="rowh"><a href="#plans/{e(p.name)}">{e(p.display)}</a></th>{cells}<td class="num warn">{unv or ""}</td></tr>')
    th = "".join(f'<th>{e(t)}</th>' for t in TIER_ORDER)
    return f'''<div class="lede">Where the detection content is thin. Cells show detection counts, coloured by the strongest tier.</div>
<h3>Detections by evidence class</h3>
<div class="scroll"><table class="cov"><thead><tr><th></th>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>
<div class="legend">{tier_badge('possible')}{tier_badge('likely')}{tier_badge('confirmed')}</div>
<h3>Collection steps by tier</h3>
<div class="scroll"><table class="cov"><thead><tr><th></th>{th}<th>unverified</th></tr></thead><tbody>{"".join(prow)}</tbody></table></div>'''


# --------------------------------------------------------------------------- page
CSS = r"""
:root{
  --bg:#fbfbfa;--panel:#fff;--panel-2:#fbfbfa;--hover:#faf7f4;
  --ink:#1c1b19;--muted:#6b6862;--faint:#a09b90;--line:#e4e1db;--line-soft:#f0ede8;
  --accent:#5e3a24;--accent-soft:#f2e9e2;--accent-border:#e0cfc1;--on-accent:#fff;
  --crit:#a12b2b;--high:#b4611c;--med:#8a7320;--low:#5c7a4a;
  --conf-strong:#3d5a80;--conf-mid:#6b7f96;--conf-bg:#eef2f7;--alert-bg:#fdf6f2;
  --code-bg:#f6f4f0;--shadow:rgba(28,27,25,.07)}
:root[data-theme=dark]{
  --bg:#121110;--panel:#1a1917;--panel-2:#211f1c;--hover:#262320;
  --ink:#f1eee9;--muted:#a9a39a;--faint:#7c766e;--line:#302d29;--line-soft:#262320;
  --accent:#ddc4b0;--accent-soft:#2d2118;--accent-border:#553a29;--on-accent:#1a1310;
  --crit:#f28c85;--high:#eaa965;--med:#d9c364;--low:#a6d18c;
  --conf-strong:#9ec0e0;--conf-mid:#7e94ab;--conf-bg:#1b2530;--alert-bg:#251a16;
  --code-bg:#211f1c;--shadow:rgba(0,0,0,.5)}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){
  --bg:#121110;--panel:#1a1917;--panel-2:#211f1c;--hover:#262320;
  --ink:#f1eee9;--muted:#a9a39a;--faint:#7c766e;--line:#302d29;--line-soft:#262320;
  --accent:#ddc4b0;--accent-soft:#2d2118;--accent-border:#553a29;--on-accent:#1a1310;
  --crit:#f28c85;--high:#eaa965;--med:#d9c364;--low:#a6d18c;
  --conf-strong:#9ec0e0;--conf-mid:#7e94ab;--conf-bg:#1b2530;--alert-bg:#251a16;
  --code-bg:#211f1c;--shadow:rgba(0,0,0,.5)}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-text-size-adjust:100%}
a{color:var(--accent)}
button,input,select{font:inherit;color:inherit}
button{cursor:pointer}
code,.mono,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.skip{position:absolute;left:-9999px;top:0;z-index:100;background:var(--accent);color:var(--on-accent);padding:10px 16px}
.skip:focus{left:0}
.hdr{position:sticky;top:0;z-index:20;background:var(--bg);border-bottom:1px solid var(--line)}
.hdr-in{max-width:1440px;margin:0 auto;padding:14px 28px 0}
.hdr-top{display:flex;flex-wrap:wrap;gap:10px 24px;align-items:flex-start}
.hdr-id{flex:1 1 340px;min-width:0}
.h1row{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.dot{width:9px;height:9px;border-radius:50%;background:var(--accent);flex:none}
h1{margin:0;font-size:19px;font-weight:600;letter-spacing:-.01em}
.pill{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;color:var(--muted);background:var(--panel);border:1px solid var(--line);border-radius:20px;padding:2px 8px}
.sub{margin:5px 0 0;font-size:13.5px;color:var(--muted);max-width:68ch}
.hdr-right{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.hbtn{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:7px 11px;font-size:12.5px;color:var(--muted);text-decoration:none}
.hbtn:hover{color:var(--ink);border-color:var(--accent)}
.hbtn[aria-pressed=true]{background:var(--accent);color:var(--on-accent);border-color:var(--accent)}
.hbtn .n{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;background:var(--alert-bg);color:var(--crit);border-radius:20px;padding:1px 6px;margin-left:5px}
#search{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:7px 11px;font-size:13px;width:240px;max-width:100%}
#search:focus{outline:2px solid var(--accent-border);border-color:var(--accent)}
.tabs{display:flex;gap:2px;margin-top:8px;overflow-x:auto;scrollbar-width:thin}
.tabs button{background:none;border:0;border-bottom:2px solid transparent;flex:none;white-space:nowrap;padding:9px 12px;font-size:13.5px;color:var(--muted);display:flex;gap:7px;align-items:center}
.tabs button[aria-selected=true]{color:var(--ink);font-weight:600;border-bottom-color:var(--accent)}
.tabs .n{font-family:ui-monospace,Menlo,monospace;font-size:10.5px;background:var(--line-soft);border-radius:20px;padding:1px 7px}
main{max-width:1440px;margin:0 auto;padding:20px 28px 60px}
.lede{color:var(--muted);margin:0 0 16px;max-width:90ch}
h3{margin:0;font-size:16px;font-weight:600}
h4{margin:14px 0 6px;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--faint)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(420px,1fr));gap:14px}
.stack{display:flex;flex-direction:column;gap:14px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;box-shadow:0 1px 2px var(--shadow)}
.card:target{outline:2px solid var(--accent)}
.card,.plan,.rule{scroll-margin-top:150px}
.card-h{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:flex-start}
.card p{margin:10px 0}
.id{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:var(--muted)}
.muted{color:var(--muted)}.small{font-size:12px}
.fs{color:var(--muted);font-size:13px}
.note{background:var(--alert-bg);border-left:3px solid var(--high);padding:8px 10px;border-radius:4px;font-size:13px}
.badges,.links{display:flex;gap:5px;flex-wrap:wrap;align-items:center}
.links{margin:8px 0}
.badge{display:inline-block;font-size:11px;border-radius:20px;padding:1px 8px;border:1px solid var(--line);white-space:nowrap}
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
.chip{display:inline-block;font-size:11.5px;background:var(--line-soft);border-radius:6px;padding:1px 7px;color:var(--ink);text-decoration:none}
.chip.mono{font-family:ui-monospace,Menlo,monospace;font-size:11px;word-break:break-all}
.chip.nw{white-space:nowrap;word-break:normal}
.chip.link{background:var(--accent-soft);color:var(--accent);border:1px solid var(--accent-border)}
.chip.link:hover{border-color:var(--accent)}
.chip.ghost{background:none;border:1px dashed var(--line);color:var(--faint)}
.chip.cve{background:var(--conf-bg);color:var(--conf-strong)}
.chip.actor{background:var(--alert-bg);color:var(--high)}
.chip.implant{background:var(--alert-bg);color:var(--crit)}
ul{margin:4px 0;padding-left:20px}ul.plain{list-style:none;padding:0}
ul.plain li{padding:6px 0;border-top:1px solid var(--line-soft)}
ul.plain .row{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
details summary{cursor:pointer;color:var(--muted);font-size:12.5px;margin-top:8px}
.tbl{width:100%;border-collapse:collapse;font-size:13px;margin-top:10px}
.tbl th,.tbl td{text-align:left;vertical-align:top;padding:8px 8px;border-top:1px solid var(--line-soft)}
.tbl thead th{font-size:11px;letter-spacing:.05em;text-transform:uppercase;color:var(--faint);border-top:0}
.tbl td.id{white-space:nowrap}
.picker,.filters{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}
.pbtn,.fbtn{background:var(--panel);border:1px solid var(--line);border-radius:999px;padding:6px 13px;font-size:12.5px;color:var(--muted)}
.pbtn[aria-pressed=true],.fbtn[aria-pressed=true]{background:var(--accent);border-color:var(--accent);color:var(--on-accent)}
.planwrap{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:18px;align-items:start}
.plan{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
.plan-h{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
.plan-h h3{display:inline}
.guard .cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px}
.guard .chip{display:block;margin:3px 0}
.tierrow th{background:var(--panel-2);font-size:12.5px;font-weight:600;padding:9px 8px}
.tchip{font-family:ui-monospace,Menlo,monospace;font-size:11px;background:var(--accent);color:var(--on-accent);border-radius:5px;padding:1px 6px;margin-right:6px}
.step.off{opacity:.38}
.step .kind{font-size:11px;color:var(--faint);margin-top:3px}
.purpose{color:var(--muted);font-size:12.5px;margin-top:4px}
.needs{font-size:12px;color:var(--high);margin-top:3px}
.cmd{display:inline-flex;gap:6px;align-items:flex-start;max-width:100%}
.cmd code{background:var(--code-bg);border:1px solid var(--line-soft);border-radius:6px;padding:2px 6px;font-size:12px;word-break:break-all}
.copy{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:3px 8px;font-size:11px;color:var(--muted)}
.copy:hover{color:var(--ink);border-color:var(--accent)}
.copy.sm{padding:1px 6px;font-size:10.5px}
.codewrap{position:relative;margin:10px 0}
.codewrap .copy{position:absolute;top:8px;right:8px}
pre{background:var(--code-bg);border:1px solid var(--line-soft);border-radius:8px;padding:12px;overflow:auto;font-size:12px;margin:0;max-height:480px}
pre.instr{white-space:pre-wrap;max-height:none}
.builder{position:sticky;top:120px;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;display:flex;flex-direction:column;gap:9px}
.builder label{display:flex;flex-direction:column;font-size:12px;color:var(--muted);gap:3px}
.builder label.tog{display:block;color:var(--ink)}
.builder label.tog input{margin:0 6px 0 0;vertical-align:-1px}
.builder input:not([type]),.builder select{background:var(--bg);border:1px solid var(--line);border-radius:7px;padding:6px 9px;font-size:13px;color:var(--ink)}
.builder pre{white-space:pre-wrap;word-break:break-all;padding-right:56px}
.rule{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 14px;margin-bottom:8px}
.rule summary{margin:0;list-style:none;color:var(--ink)}
.rhead{display:flex;gap:7px;align-items:center;flex-wrap:wrap}
.rfile{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;color:var(--muted);margin-top:2px}
.fmt-sigma{color:var(--conf-strong);border-color:currentColor}.fmt-yara{color:var(--high);border-color:currentColor}
.lvl-critical{color:var(--crit);border-color:currentColor}.lvl-high{color:var(--high);border-color:currentColor}.lvl-medium{color:var(--med);border-color:currentColor}
.scroll{overflow-x:auto;margin:10px 0 22px}
table.cov{border-collapse:collapse;font-size:12.5px}
table.cov th,table.cov td{border:1px solid var(--line-soft);padding:6px 9px}
table.cov .rowh{text-align:left;white-space:nowrap;font-weight:500}
table.cov .vert{height:120px;vertical-align:bottom;white-space:nowrap;font-weight:500;font-size:11.5px}
table.cov .vert span{writing-mode:vertical-rl;transform:rotate(180deg)}
table.cov .cell{width:42px;text-align:center;font-family:ui-monospace,Menlo,monospace}
.cell.t-possible{background:color-mix(in srgb,var(--med) 22%,transparent)}
.cell.t-likely{background:color-mix(in srgb,var(--high) 32%,transparent)}
.cell.t-confirmed{background:color-mix(in srgb,var(--crit) 40%,transparent)}
table.cov .num{text-align:center;font-family:ui-monospace,Menlo,monospace;min-width:34px}
.num.warn{color:var(--crit)}
.legend{display:flex;gap:6px;margin:-12px 0 24px}
.guide{max-width:820px}
.guide h2{font-size:21px;margin:8px 0 10px}.guide h3{font-size:16px;margin:26px 0 8px}.guide h4{font-size:12px}
.guide p,.guide li{line-height:1.65}
.guide code{background:var(--code-bg);border-radius:4px;padding:1px 4px;font-size:12.5px}
.guide pre code{background:none;padding:0}
footer{max-width:1440px;margin:0 auto;padding:22px 28px 40px;color:var(--faint);font-size:12px;border-top:1px solid var(--line)}
.sect{margin:26px 0 10px;font-size:15px}
.arts{margin-top:12px}.arts summary{font-size:12.5px;font-weight:600;color:var(--ink)}
.arttbl td{font-size:12.5px}.arttbl code.loc{background:var(--code-bg);border-radius:5px;padding:1px 5px;word-break:break-all;font-size:12px}
.arttbl tr.unv td:first-child{box-shadow:inset 3px 0 0 var(--crit)}
.cls{color:var(--muted)}
.vol-live{color:var(--crit);border-color:currentColor}.vol-rotating{color:var(--high);border-color:currentColor}
.vol-stable{color:var(--low);border-color:currentColor}.vol-off-box{color:var(--conf-strong);border-color:currentColor;background:var(--conf-bg)}
.fv-high{color:var(--on-accent);background:var(--accent);border-color:var(--accent)}.fv-medium{color:var(--accent);border-color:var(--accent-border)}.fv-low{color:var(--faint)}
.mot-espionage{color:var(--conf-strong);border-color:currentColor}.mot-financial{color:var(--high);border-color:currentColor}
.mot-unknown,.mot-mixed{color:var(--muted)}
.attrib{background:var(--panel-2);border:1px solid var(--line-soft);border-radius:8px;padding:8px 11px;margin:10px 0;font-size:13px;display:grid;gap:3px}
.attrib .k{display:inline-block;min-width:104px;font-size:11px;letter-spacing:.05em;text-transform:uppercase;color:var(--faint)}
.attrib q{font-style:italic;color:var(--ink)}
.gap-b{color:var(--on-accent);background:var(--crit);border-color:var(--crit)}
.gapcard{border-left:3px solid var(--crit)}
.surv-yes{color:var(--crit);border-color:currentColor}.surv-no{color:var(--low);border-color:currentColor}
.surv-partial{color:var(--high);border-color:currentColor}.surv-unknown{color:var(--faint)}
.itype{color:var(--accent);border-color:var(--accent-border);background:var(--accent-soft)}
.res-memory{color:var(--crit);border-color:currentColor}.res-boot{color:var(--on-accent);background:var(--crit);border-color:var(--crit)}
.res-disk,.res-memory\+disk{color:var(--high);border-color:currentColor}
.phases{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-top:8px}
.phase{background:var(--panel-2);border:1px solid var(--line-soft);border-radius:8px;padding:6px 12px 10px}
.phase ol,.resp ol{margin:4px 0;padding-left:18px}.phase li{margin:5px 0;font-size:13px}
.pn{display:inline-grid;place-items:center;width:18px;height:18px;border-radius:50%;background:var(--accent);color:var(--on-accent);font-size:10.5px;margin-right:7px;vertical-align:1px;letter-spacing:0}
.when{font-size:11.5px;color:var(--high);margin-top:2px}
.dont{margin-top:14px;background:var(--alert-bg);border:1px solid var(--line-soft);border-left:3px solid var(--crit);border-radius:8px;padding:4px 12px 8px}
.dont h4{color:var(--crit)}
[hidden]{display:none!important}
.empty{color:var(--muted);padding:30px 0;text-align:center}
@media (max-width:980px){.planwrap{grid-template-columns:1fr}.builder{position:static}}
@media (max-width:640px){.hdr{position:static}.hdr-in,main,footer{padding-left:16px;padding-right:16px}
  .grid{grid-template-columns:1fr}.card,.plan{padding:14px}#search{width:100%}.tbl{font-size:12px}
  .card,.plan,.rule{scroll-margin-top:10px}
  .steps thead{display:none}.steps tr.step td{display:block;border:0;padding:3px 0}
  .steps tr.step{display:block;padding:10px 0;border-top:1px solid var(--line-soft)}
  .steps tr.step td:first-child{font-weight:600}.steps .tierrow th{display:block}
  .pack .tbl thead{display:none}.pack .tbl tr{display:block;padding:8px 0;border-top:1px solid var(--line-soft)}
  .pack .tbl td{display:inline-block;border:0;padding:2px 6px 2px 0}.pack .tbl td:nth-child(2){display:block}}
"""

JS = r"""
(function(){
var D = JSON.parse(document.getElementById('data').textContent);
var root = document.documentElement;
function store(k, v){ try{ if(v===undefined) return localStorage.getItem(k); localStorage.setItem(k, v); }catch(_){ return null; } }
var th = store('edt-theme'); if (th) root.setAttribute('data-theme', th);
document.getElementById('themeBtn').addEventListener('click', function(){
  var dark = root.getAttribute('data-theme') === 'dark' ||
    (!root.getAttribute('data-theme') && window.matchMedia('(prefers-color-scheme: dark)').matches);
  var next = dark ? 'light' : 'dark'; root.setAttribute('data-theme', next); store('edt-theme', next);
});

/* tabs + hash routing: #tab or #tab/anchor */
var tabs = Array.prototype.slice.call(document.querySelectorAll('.tabs button'));
function show(tab, anchor){
  tabs.forEach(function(b){ b.setAttribute('aria-selected', String(b.dataset.tab === tab)); });
  document.querySelectorAll('.panel').forEach(function(p){ p.hidden = p.id !== 'tab-' + tab; });
  if (tab === 'plans' && anchor) pickProfile(anchor);
  if (anchor){
    var prefix = {platforms:'platform-', packs:'pack-', plans:'plan-', intel:'intel-', response:'response-'}[tab] || '';
    var el = document.getElementById(prefix + anchor);
    if (el) setTimeout(function(){ el.scrollIntoView({block:'start'}); }, 0);
  }
  applySearch();
}
tabs.forEach(function(b){ b.addEventListener('click', function(){ history.replaceState(null, '', '#' + b.dataset.tab); show(b.dataset.tab); }); });
function route(){ var h = (location.hash || '#platforms').slice(1).split('/'); show(tabs.some(function(b){return b.dataset.tab===h[0];}) ? h[0] : 'platforms', h[1]); }
window.addEventListener('hashchange', route);

/* search + unverified filter + pack platform filter */
var q = document.getElementById('search'), unvBtn = document.getElementById('unvBtn'), plat = '';
function applySearch(){
  var term = (q.value || '').trim().toLowerCase(), unvOnly = unvBtn.getAttribute('aria-pressed') === 'true';
  var panel = document.querySelector('.panel:not([hidden])'); if (!panel) return;
  var shown = 0, items = panel.querySelectorAll('.item');
  items.forEach(function(el){
    var ok = (!term || (el.dataset.search || el.textContent.toLowerCase()).indexOf(term) >= 0) &&
             (!unvOnly || el.classList.contains('unv')) &&
             (!plat || !el.dataset.plat || el.dataset.plat.split(' ').indexOf(plat) >= 0);
    el.hidden = !ok; if (ok) shown++;
  });
  var empty = panel.querySelector('.empty');
  if (empty) empty.hidden = !items.length || shown > 0;
}
q.addEventListener('input', applySearch);
document.addEventListener('keydown', function(ev){
  if (ev.key === '/' && document.activeElement !== q && !/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName)){ ev.preventDefault(); q.focus(); }
  if (ev.key === 'Escape' && document.activeElement === q){ q.value=''; applySearch(); q.blur(); }
});
unvBtn.addEventListener('click', function(){ unvBtn.setAttribute('aria-pressed', String(unvBtn.getAttribute('aria-pressed') !== 'true')); applySearch(); });
document.querySelectorAll('.fbtn').forEach(function(b){ b.addEventListener('click', function(){
  plat = b.dataset.plat; document.querySelectorAll('.fbtn').forEach(function(x){ x.setAttribute('aria-pressed', String(x === b)); }); applySearch(); }); });

/* copy buttons */
document.addEventListener('click', function(ev){
  var b = ev.target.closest('.copy'); if (!b) return;
  var text = b.dataset.copy || (b.parentElement.querySelector('code') || {}).textContent || '';
  function done(){ var t = b.textContent; b.textContent = 'Copied'; setTimeout(function(){ b.textContent = t; }, 1200); }
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, function(){});
  else { var ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select();
         try{ document.execCommand('copy'); done(); }catch(_){} document.body.removeChild(ta); }
});

/* collection plan picker + command builder */
var cur = D.profiles[0] ? D.profiles[0].name : null;
function pickProfile(name){
  if (!D.profiles.some(function(p){ return p.name === name; })) return;
  cur = name;
  document.querySelectorAll('.pbtn').forEach(function(b){ b.setAttribute('aria-pressed', String(b.dataset.profile === name)); });
  document.querySelectorAll('.plan').forEach(function(s){ s.hidden = s.dataset.profile !== name; });
  renderVars(); build();
}
document.querySelectorAll('.pbtn').forEach(function(b){ b.addEventListener('click', function(){
  history.replaceState(null, '', '#plans/' + b.dataset.profile); pickProfile(b.dataset.profile); }); });
function prof(){ return D.profiles.filter(function(p){ return p.name === cur; })[0]; }
function renderVars(){
  var box = document.getElementById('b-vars'); box.innerHTML = '';
  prof().vars.forEach(function(v){
    var l = document.createElement('label'); l.textContent = '--var ' + v;
    var i = document.createElement('input'); i.dataset.var = v; i.autocomplete = 'off'; i.placeholder = 'value';
    i.addEventListener('input', build); l.appendChild(i); box.appendChild(l);
  });
}
function sh(s){ return /^[\w@%+=:,./-]+$/.test(s) ? s : "'" + s.replace(/'/g, "'\\''") + "'"; }
function val(id, dflt){ var v = document.getElementById(id).value.trim(); return v || dflt; }
function build(){
  var p = prof(); if (!p) return;
  var bundle = document.getElementById('b-bundle').checked, bg = document.getElementById('b-bg').checked;
  var parts = ['python -m edgetriage collect', '--profile ' + p.name, '--case-id ' + sh(val('b-case','IR-2026-001'))];
  if (p.ssh){ parts.push('--host ' + sh(val('b-host','<device>'))); parts.push('--user ' + sh(val('b-user','<readonly-user>'))); }
  else parts.push('--replay ./ivanti-checklist   # nothing to connect to; steps are recorded as manual');
  var op = document.getElementById('b-op').value.trim(); if (op) parts.push('--operator ' + sh(op));
  parts.push('--rebooted ' + document.getElementById('b-reboot').value, '--patched ' + document.getElementById('b-patch').value);
  document.querySelectorAll('#b-vars input').forEach(function(i){ if (i.value.trim()) parts.push('--var ' + sh(i.dataset.var + '=' + i.value.trim())); });
  if (bundle || bg) parts.push('--allow-bundle'); if (bg) parts.push('--break-glass');
  document.getElementById('b-out').textContent = parts.join(' \\\n    ');
  var n = 0, off = 0;
  document.querySelectorAll('.plan[data-profile="' + p.name + '"] .step').forEach(function(r){
    var imp = r.dataset.impact, on = imp === 'none' || (imp === 'vendor-bundle' && (bundle || bg)) || (imp === 'break-glass' && bg);
    r.classList.toggle('off', !on); if (on) n++; else off++;
  });
  document.getElementById('b-sum').textContent = n + ' step(s) will run' + (off ? ', ' + off + ' withheld' : '') + '.';
}
['b-case','b-host','b-user','b-op','b-reboot','b-patch','b-bundle','b-bg'].forEach(function(id){
  var el = document.getElementById(id); el.addEventListener('input', build); el.addEventListener('change', build); });
if (cur){ renderVars(); build(); }
route();
})();
"""


def page(d: dict) -> tuple[str, dict]:
    plat_names = {c["id"]: c["name"] for c in d["catalog"]}
    packs_by_platform: dict[str, list[str]] = {}
    for p in d["packs"]:
        for pid in p["platforms"]:
            packs_by_platform.setdefault(pid, []).append(p["id"])
    n_det = sum(len(p["detect"]) for p in d["packs"])
    n_unv = (sum(1 for p in d["profiles"] for s in p.steps if s.unverified)
             + sum(1 for c in d["catalog"] if c.get("unverified") or any(x.get("unverified") for x in c["collection"]))
             + sum(1 for p in d["packs"] if p.get("unverified")))
    data = {"profiles": [{"name": p.name, "ssh": "ssh" in p.transports,
                          "vars": sorted({v for s in p.steps for v in s.requires_vars})} for p in d["profiles"]]}
    tabs = [("platforms", "Platforms", len(d["catalog"])), ("plans", "Collection plans", len(d["profiles"])),
            ("packs", "Detection packs", len(d["packs"])), ("intel", "Threat intel", len(d["actors"]) + len(d["implants"])),
            ("response", "Response", len(d["response"])), ("rules", "Rules", len(d["rules"])),
            ("coverage", "Coverage", None), ("guide", "Investigation guide", None)]
    tabbar = "".join(f'<button type="button" role="tab" data-tab="{t}" aria-selected="false">{label}'
                     + (f'<span class="n">{n}</span>' if n is not None else "") + "</button>" for t, label, n in tabs)
    empty = '<div class="empty" hidden>Nothing matches the current filter.</div>'
    panels = {
        "platforms": render_platforms(d, packs_by_platform) + empty,
        "plans": render_plans(d) + empty,
        "packs": render_packs(d, plat_names) + empty,
        "intel": render_intel(d, plat_names) + empty,
        "response": render_response(d, plat_names) + empty,
        "rules": render_rules(d) + empty,
        "coverage": render_coverage(d, plat_names),
        "guide": f'<article class="guide">{markdown(d["guide"])}</article>',
    }
    body = "".join(f'<section class="panel" id="tab-{k}" role="tabpanel" hidden>{v}</section>' for k, v in panels.items())
    built = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    icon = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E"
            "%3Crect width='32' height='32' rx='7' fill='%235e3a24'/%3E%3Cpath d='M8 22V10h10M8 16h8M8 22h10' "
            "stroke='%23fff' stroke-width='2.6' fill='none' stroke-linecap='round'/%3E%3Cpath d='M21 10l4 6-4 6' "
            "stroke='%23ddc4b0' stroke-width='2.6' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E")
    html_doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Edge DFIR Toolkit</title>
<meta name="description" content="Forensic triage for compromised VPN concentrators, firewalls and gateways: platform catalog, collection plans, detection packs and rules.">
<link rel="icon" href="{icon}">
<style>{CSS}</style></head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="hdr"><div class="hdr-in">
  <div class="hdr-top">
    <div class="hdr-id"><div class="h1row"><span class="dot"></span><h1>Edge DFIR Toolkit</h1><span class="pill">v{e(__version__)}</span></div>
      <p class="sub">Forensic triage for compromised VPN concentrators, firewalls and gateways. {len(d['catalog'])} platforms, {len(d['profiles'])} collection profiles, {len(d['packs'])} detection packs with {n_det} detections, {len(d['rules'])} rule files.</p></div>
    <div class="hdr-right">
      <input id="search" type="search" placeholder="Search  ( / )" aria-label="Search the current tab">
      <button type="button" class="hbtn" id="unvBtn" aria-pressed="false" title="Show only content nobody has confirmed on a device">Unverified<span class="n">{n_unv}</span></button>
      <button type="button" class="hbtn" id="themeBtn">Theme</button>
      <a class="hbtn" href="{REPO_URL}" rel="noopener">Repository</a>
    </div>
  </div>
  <nav class="tabs" role="tablist">{tabbar}</nav>
</div></header>
<main id="main">{body}</main>
<footer>
  Independent personal project, not affiliated with any employer or any vendor whose products it covers. Built from the repository on {built};
  every figure on this page is computed from the catalog, profiles, packs and rules at build time. Detection content is Sigma and YARA only.
  Code Apache-2.0.
</footer>
<script type="application/json" id="data">{js_data(data)}</script>
<script>{JS}</script>
</body></html>
"""
    return html_doc, data


# --------------------------------------------------------------------------- check
def check(d: dict, doc: str) -> list[str]:
    problems = []
    ids = re.findall(r'\sid="([^"]+)"', doc)
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        problems.append(f"duplicate element ids: {dupes}")
    bad = [i for i in ids if not re.fullmatch(r"[A-Za-z0-9_.:-]+", i)]
    if bad:
        problems.append(f"ids that are not URL-safe: {bad}")
    plat = {c["id"] for c in d["catalog"]}
    for p in d["packs"]:
        for pid in p["platforms"]:
            if pid not in plat:
                problems.append(f"{p['id']} names platform {pid} not in catalog")
    for c in d["catalog"]:
        if c.get("profile") and c["profile"] not in {p.name for p in d["profiles"]}:
            problems.append(f"{c['id']} names profile {c['profile']} that does not exist")
    for href in set(re.findall(r'href="#(\w+)/([^"]+)"', doc)):
        prefix = {"platforms": "platform-", "packs": "pack-", "plans": "plan-", "intel": "intel-", "response": "response-"}.get(href[0])
        if prefix and f'id="{prefix}{href[1]}"' not in doc:
            problems.append(f"dangling link #{href[0]}/{href[1]}")
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
    doc, _ = page(d)
    problems = check(d, doc)
    if problems:
        for p in problems:
            print(f"FAIL  {p}")
        return 1
    if "--check" in sys.argv:
        print(f"OK  site data contract holds ({len(doc) // 1024} KiB)")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(doc, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(doc) // 1024} KiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
