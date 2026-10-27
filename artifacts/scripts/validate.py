#!/usr/bin/env python3
"""validate.py - the gate CI runs. Never merge while it reports problems.

Checks the platform catalog, the detection packs and the collection profiles
against their schemas AND against each other:

  * ids are unique and permanent-looking; pack files are named after their id
  * low confidence always carries unverified: true
  * every pack platform exists in the catalog
  * every regex compiles, every YARA rule compiles, every coded check exists
  * every step a pack reads exists in a profile for one of the pack's platforms
  * every profile loads (which runs the read-only guard) and names a real platform
  * every numbered rule directory has a README

Run from the repository root:  python artifacts/scripts/validate.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import json  # noqa: E402

import yaml  # noqa: E402
from jsonschema import Draft202012Validator  # noqa: E402

from edgetriage.checks import REGISTRY  # noqa: E402
from edgetriage.profiles import ProfileError, available_profiles, load_profile  # noqa: E402

problems: list[str] = []


def err(msg: str) -> None:
    problems.append(msg)


def schema(name: str) -> Draft202012Validator:
    return Draft202012Validator(json.loads((ROOT / "artifacts" / "schema" / name).read_text()))


def validate_doc(v: Draft202012Validator, doc, where: str) -> None:
    for e in sorted(v.iter_errors(doc), key=lambda e: list(e.path)):
        loc = "/".join(str(p) for p in e.path) or "<root>"
        err(f"{where}: {loc}: {e.message}")


def main() -> int:
    # ---- catalog
    pv = schema("platform.schema.json")
    platforms: dict[str, dict] = {}
    for p in sorted((ROOT / "artifacts" / "catalog").glob("*.yml")):
        doc = yaml.safe_load(p.read_text())
        validate_doc(pv, doc, p.name)
        pid = doc.get("id")
        if pid in platforms:
            err(f"{p.name}: duplicate platform id {pid}")
        platforms[pid] = doc
        if doc.get("confidence") == "low" and not doc.get("unverified"):
            err(f"{p.name}: low confidence requires unverified: true")
        for c in doc.get("collection", []):
            if c.get("confidence") == "low" and not c.get("unverified"):
                err(f"{p.name}: collection '{c['method']}' is low confidence without unverified: true")

    # ---- profiles
    profiles = {}
    for name, path in available_profiles().items():
        try:
            prof = load_profile(path)
        except (ProfileError, KeyError, yaml.YAMLError) as e:
            err(f"profiles/{path.name}: {e}")
            continue
        profiles[name] = prof
        if prof.platform_id not in platforms:
            err(f"profiles/{path.name}: platform {prof.platform_id} not in catalog")
    for pid, doc in platforms.items():
        if doc.get("profile") and doc["profile"] not in profiles:
            err(f"catalog {pid}: profile {doc['profile']} does not exist")
    steps_by_platform: dict[str, set[str]] = {}
    for prof in profiles.values():
        steps_by_platform.setdefault(prof.platform_id, set()).update(s.id for s in prof.steps)

    # ---- packs
    kv = schema("pack.schema.json")
    pack_ids, det_ids = set(), set()
    pack_cves: dict[str, set[str]] = {}
    try:
        import yara  # type: ignore
    except ImportError:
        yara = None
        print("note: yara-python not installed; YARA rules referenced by packs are not compiled", file=sys.stderr)
    for p in sorted((ROOT / "artifacts" / "packs").glob("*.yml")):
        doc = yaml.safe_load(p.read_text())
        validate_doc(kv, doc, p.name)
        pid = doc.get("id", "")
        if pid in pack_ids:
            err(f"{p.name}: duplicate pack id {pid}")
        pack_ids.add(pid)
        for c in doc.get("cves", []):
            pack_cves.setdefault(c, set()).add(pid)
        if not p.name.startswith(pid + "-"):
            err(f"{p.name}: file name must start with its id {pid}")
        if doc.get("confidence") == "low" and not doc.get("unverified"):
            err(f"{p.name}: low confidence requires unverified: true")
        known_steps: set[str] = set()
        for plat in doc.get("platforms", []):
            if plat not in platforms:
                err(f"{p.name}: platform {plat} not in catalog")
            known_steps |= steps_by_platform.get(plat, set())
        for d in doc.get("detect", []):
            did = d.get("id")
            if did in det_ids:
                err(f"{p.name}: duplicate detection id {did}")
            det_ids.add(did)
            for field in ("pattern",):
                if field in d:
                    try:
                        re.compile(d[field].encode())
                    except re.error as e:
                        err(f"{p.name}/{did}: bad regex: {e}")
            for x in d.get("exclude", []):
                try:
                    re.compile(x.encode())
                except re.error as e:
                    err(f"{p.name}/{did}: bad exclude regex: {e}")
            if d.get("type") == "check" and d.get("check") not in REGISTRY:
                err(f"{p.name}/{did}: unknown check {d.get('check')}")
            if d.get("type") == "yara":
                rule = ROOT / d.get("rule", "")
                if not rule.is_file():
                    err(f"{p.name}/{did}: rule file missing: {d.get('rule')}")
                elif yara is not None:
                    try:
                        yara.compile(filepath=str(rule))
                    except yara.Error as e:
                        err(f"{p.name}/{did}: YARA does not compile: {e}")
            for sid in (d.get("sources") or {}).get("steps", []):
                if sid not in known_steps:
                    err(f"{p.name}/{did}: reads step '{sid}' that no profile for {doc.get('platforms')} defines")

    # A catalog artifact's collected_by must name a real step, 'ingest' or 'manual'.
    for pid, doc in platforms.items():
        steps = steps_by_platform.get(pid, set())
        for a in doc.get("artifacts", []):
            cb = a.get("collected_by")
            if cb and cb not in steps and cb not in ("ingest", "manual"):
                err(f"catalog {pid}: artifact collected_by '{cb}' is not a step, 'ingest' or 'manual'")
            if a.get("confidence") == "low" and not a.get("unverified"):
                err(f"catalog {pid}: a low-confidence artifact needs unverified: true")
            # Reading guidance travels together: a suspicious criterion always says
            # where it comes from, and is never stated without the normal baseline.
            g = [k for k in ("normal", "suspicious", "basis") if a.get(k)]
            if g and len(g) != 3:
                err(f"catalog {pid}: artifact '{a.get('locator')}' has {g} - normal, suspicious and basis go together")

    # ---- threat intel: implants and actors
    iv = schema("implant.schema.json")
    implant_ids: dict[str, dict] = {}
    for p in sorted((ROOT / "artifacts" / "intel" / "implants").glob("*.yml")):
        doc = yaml.safe_load(p.read_text())
        validate_doc(iv, doc, p.name)
        iid = doc.get("id", "")
        if iid in implant_ids:
            err(f"{p.name}: duplicate implant id {iid}")
        implant_ids[iid] = doc
        if not p.name.startswith(iid + "-"):
            err(f"{p.name}: file name must start with its id {iid}")
        for plat in doc.get("platforms", []):
            if plat not in platforms:
                err(f"{p.name}: platform {plat} not in catalog")
        for cve in doc.get("cves", []):
            pass  # shape only
        # Every detection an implant claims must be a real detection id.
        for did in doc.get("detections", []):
            if did not in det_ids:
                err(f"{p.name}: lists detection '{did}' that no pack defines")
        # An implant with no detections must say why (gap), so a silent hole is impossible.
        if not doc.get("detections") and not doc.get("gap"):
            err(f"{p.name}: no detections and no 'gap' explaining the coverage hole")
        if doc.get("confidence") == "low" and not doc.get("unverified"):
            err(f"{p.name}: low confidence requires unverified: true")

    av = schema("actor.schema.json")
    actor_ids: set[str] = set()
    for p in sorted((ROOT / "artifacts" / "intel" / "actors").glob("*.yml")):
        doc = yaml.safe_load(p.read_text())
        validate_doc(av, doc, p.name)
        aid = doc.get("id", "")
        if aid in actor_ids:
            err(f"{p.name}: duplicate actor id {aid}")
        actor_ids.add(aid)
        if not p.name.startswith(aid.lower() + "-") and not p.name.startswith(aid + "-"):
            err(f"{p.name}: file name must start with its id {aid}")
        for plat in doc.get("platforms", []):
            if plat not in platforms:
                err(f"{p.name}: platform {plat} not in catalog")
        for pk in doc.get("packs", []):
            if pk not in pack_ids:
                err(f"{p.name}: references pack '{pk}' that does not exist")
        for im in doc.get("implants", []):
            if im not in implant_ids:
                err(f"{p.name}: references implant '{im}' that does not exist")

    # Implant->actor links resolve the other way too.
    for iid, doc in implant_ids.items():
        for aid in doc.get("actors", []):
            if aid not in actor_ids:
                err(f"implant {iid}: references actor '{aid}' that has no profile")

    # ---- response playbooks
    rv = schema("response.schema.json")
    response_stems: set[str] = set()
    for p in sorted((ROOT / "artifacts" / "response").glob("*.yml")):
        doc = yaml.safe_load(p.read_text())
        validate_doc(rv, doc, p.name)
        response_stems.add(p.stem)
        if doc.get("platform_id") not in platforms:
            err(f"response/{p.name}: platform {doc.get('platform_id')} not in catalog")
        # `when` is read by the site's verdict filter, so it must name analyzer verdicts.
        verdicts = {"COMPROMISED", "LIKELY-COMPROMISED", "SUSPICIOUS", "NO-INDICATORS-FOUND"}
        for phase in ("preserve_first", "contain", "eradicate", "recover", "verify"):
            for st in doc.get(phase) or []:
                bad = [w.strip() for w in str(st.get("when", "")).split(",") if w.strip() and w.strip() not in verdicts]
                if bad:
                    err(f"response/{p.name}: {phase} step '{st.get('step', '')[:40]}' has when values that are not verdicts: {bad}")
    # A catalog entry that names a response playbook must have one, and vice versa.
    for pid, doc in platforms.items():
        r = doc.get("response")
        if r and r not in response_stems:
            err(f"catalog {pid}: response playbook '{r}' does not exist")

    # ---- Sigma <-> detection links. A rule nobody links must say why it stands alone.
    sigma_files = {p.relative_to(ROOT).as_posix() for p in ROOT.glob("[0-9][0-9]-*/*.yml")}
    linked: set[str] = set()
    for p in sorted((ROOT / "artifacts" / "packs").glob("*.yml")):
        for x in yaml.safe_load(p.read_text()).get("detect", []):
            for rp in x.get("sigma", []):
                linked.add(rp)
                if rp not in sigma_files:
                    err(f"{p.name}: {x.get('id')} links Sigma rule {rp} that does not exist")
    for rp in sorted(sigma_files - linked):
        if "edge-dfir.standalone" not in (yaml.safe_load((ROOT / rp).read_text()).get("tags") or []):
            err(f"{rp}: no detection links this rule; link it from a pack or tag it edge-dfir.standalone")

    # ---- hardening: every control cites a primary source; low confidence is flagged
    hv = schema("hardening.schema.json")
    hardening_stems: set[str] = set()
    control_ids: set[str] = set()
    n_controls = 0
    for p in sorted((ROOT / "artifacts" / "hardening").glob("*.yml")):
        doc = yaml.safe_load(p.read_text())
        validate_doc(hv, doc, f"hardening/{p.name}")
        hardening_stems.add(p.stem)
        pid = doc.get("platform_id")
        if pid != "ALL" and pid not in platforms:
            err(f"hardening/{p.name}: platform {pid} not in catalog")
        if (pid == "ALL") != (p.stem == "baseline"):
            err(f"hardening/{p.name}: only baseline.yml may use platform_id ALL, and it must")
        for c in doc.get("controls", []):
            n_controls += 1
            if c.get("id") in control_ids:
                err(f"hardening/{p.name}: duplicate control id {c.get('id')}")
            control_ids.add(c.get("id"))
            if c.get("confidence") == "low" and not c.get("unverified"):
                err(f"hardening/{p.name}: {c.get('id')} is low confidence without unverified: true")
            for x in c.get("blunts", []):
                if x.startswith("CVE") and not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", x):
                    err(f"hardening/{p.name}: {c.get('id')} has a malformed CVE {x}")
    for pid, doc in platforms.items():
        h = doc.get("hardening")
        if h and h not in hardening_stems:
            err(f"catalog {pid}: hardening '{h}' does not exist")

    # ---- hunts: off-box hypotheses, each quoting the source it rests on
    huv = schema("hunt.schema.json")
    hunt_ids: set[str] = set()
    for p in sorted((ROOT / "artifacts" / "hunts").glob("*.yml")):
        doc = yaml.safe_load(p.read_text())
        validate_doc(huv, doc, f"hunts/{p.name}")
        hid = doc.get("id", "")
        if not p.name.startswith(f"{hid}-"):
            err(f"hunts/{p.name}: file must be named <id>-<slug>.yml")
        if hid in hunt_ids:
            err(f"hunts/{p.name}: duplicate id {hid}")
        hunt_ids.add(hid)
        for pid in doc.get("platforms", []):
            if pid != "ALL" and pid not in platforms:
                err(f"hunts/{p.name}: platform {pid} not in catalog")
        for aid in doc.get("actors", []):
            if aid not in actor_ids:
                err(f"hunts/{p.name}: actor {aid} does not exist")
        for rp in doc.get("sigma", []):
            if not (ROOT / rp).is_file():
                err(f"hunts/{p.name}: Sigma rule {rp} does not exist")
        if doc.get("confidence") == "low" and not doc.get("unverified"):
            err(f"hunts/{p.name}: low confidence without unverified: true")
        # A quote that only came through a summariser is not a read of the source.
        if all(s.get("read") == "summariser" for s in doc.get("sources", [])) and not doc.get("unverified"):
            err(f"hunts/{p.name}: every source was read through a summariser; mark it unverified")

    # ---- indicators: parsed from the publisher's own file, every value well-formed
    def _is_ipv6(v: str) -> bool:
        import ipaddress
        try:
            return ipaddress.ip_address(v).version == 6 and v == ipaddress.ip_address(v).compressed
        except ValueError:
            return False

    iv2 = schema("ioc.schema.json")
    ioc_ids: set[str] = set()
    ioc_docs: dict[str, dict] = {}
    n_ind = 0
    fmt = {"ipv4": r"(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}", "sha256": r"[0-9a-f]{64}",
           "sha1": r"[0-9a-f]{40}", "md5": r"[0-9a-f]{32}", "ja3": r"[0-9a-f]{32}", "domain": r"[a-z0-9.-]+\.[a-z]{2,}",
           "url": r"https?://\S+", "path": r"/\S*"}
    for p in sorted((ROOT / "artifacts" / "intel" / "iocs").glob("*.yml")):
        doc = yaml.safe_load(p.read_text())
        validate_doc(iv2, doc, f"iocs/{p.name}")
        rid = doc.get("id", "")
        if not p.name.startswith(f"{rid}-") or rid in ioc_ids:
            err(f"iocs/{p.name}: file must be named <id>-<slug>.yml with a unique id")
        ioc_ids.add(rid)
        ioc_docs[rid] = doc
        for aid in doc.get("actors", []):
            if aid not in actor_ids:
                err(f"iocs/{p.name}: actor {aid} does not exist")
        for im in doc.get("implants", []):
            if im not in implant_ids:
                err(f"iocs/{p.name}: implant {im} does not exist")
        seen = set()
        for i in doc.get("indicators", []):
            t, v = i.get("type"), str(i.get("value", ""))
            n_ind += 1
            if t == "ipv6" and not _is_ipv6(v):
                err(f"iocs/{p.name}: {t} value {v!r} is not well-formed")
            if t in fmt and not re.fullmatch(fmt[t], v, re.I):
                err(f"iocs/{p.name}: {t} value is malformed: {v[:40]}")
            if "[.]" in v or "hxxp" in v:
                err(f"iocs/{p.name}: store values refanged; the site defangs them for display")
            if (t, v) in seen:
                err(f"iocs/{p.name}: duplicate {t} {v[:40]}")
            seen.add((t, v))

    # ---- advisory watch: every KEV decision points at something real and stays current
    wf = ROOT / "artifacts" / "watch" / "kev-watch.yml"
    w = yaml.safe_load(wf.read_text()) if wf.is_file() else None
    if w is None:
        err("artifacts/watch/kev-watch.yml is missing")
    else:
        validate_doc(schema("watch.schema.json"), w, "watch/kev-watch.yml")
        for pid, rule in (w.get("platforms") or {}).items():
            if pid not in platforms:
                err(f"watch: platform {pid} does not exist")
            for k in ("vendor", "product", "exclude"):
                try:
                    re.compile(rule.get(k) or "")
                except re.error as e:
                    err(f"watch: {pid} {k} regex does not compile: {e}")
        missing = set(platforms) - set(w.get("platforms") or {})
        if missing:
            err(f"watch: platforms not watched: {sorted(missing)}")
        for iid in (w.get("upstream") or {}):
            if not ioc_docs.get(iid, {}).get("file_url"):
                err(f"watch: upstream {iid} is not an indicator set with a file_url")
        rf = ROOT / "artifacts" / "watch" / "kev-records.yml"
        recs = (yaml.safe_load(rf.read_text()) or {}) if rf.is_file() else None
        added_at: dict[str, str | None] = {}   # CVE -> the platform KEV's own product strings map it to
        if recs is None:
            err("artifacts/watch/kev-records.yml is missing; run advisory_watch.py --records")
        else:
            validate_doc(schema("kev-records.schema.json"), recs, "watch/kev-records.yml")
            for r in recs.get("records") or []:
                c = r.get("cve", "")
                if c in added_at:
                    err(f"kev-records: {c} appears twice")
                added_at[c] = r.get("platform")
                if r.get("platform") and r["platform"] not in (w.get("platforms") or {}):
                    err(f"kev-records: {c} names unwatched platform {r['platform']}")
        seen_cve: set[str] = set()
        for t in w.get("triaged") or []:
            c, refs = t.get("cve", ""), t.get("refs", [])
            if c in seen_cve:
                err(f"watch: {c} triaged twice")
            seen_cve.add(c)
            if recs is not None and added_at.get(c) != t.get("platform"):
                err(f"watch: {c} has no KEV record under {t.get('platform')}; run advisory_watch.py --records")
            if t.get("platform") not in platforms:
                err(f"watch: {c} names unknown platform {t.get('platform')}")
            if c in pack_cves:
                err(f"watch: {c} is covered by {sorted(pack_cves[c])}; remove its ledger entry")
            if t.get("decision") == "iocs":
                if not any(r in ioc_docs and c in ioc_docs[r].get("cves", []) for r in refs):
                    err(f"watch: {c} decision iocs needs a ref to an indicator set listing that CVE")
            for r in refs:
                if not (r in ioc_ids or r in pack_ids or r in hunt_ids):
                    err(f"watch: {c} refers to missing {r}")

    # ---- rule directories
    for d in sorted(ROOT.glob("[0-9][0-9]-*")):
        if d.is_dir() and not (d / "README.md").is_file():
            err(f"{d.name}: missing README.md")

    if problems:
        for p in problems:
            print(f"FAIL  {p}")
        print(f"\n{len(problems)} problem(s)")
        return 1
    n_det = len(det_ids)
    print(f"OK  {len(platforms)} platforms, {len(profiles)} profiles, {len(pack_ids)} packs, "
          f"{n_det} detections, {len(actor_ids)} actors, {len(implant_ids)} implants, "
          f"{len(response_stems)} response playbooks, {n_controls} hardening controls, {len(hunt_ids)} hunts, "
          f"{n_ind} indicators from {len(ioc_ids)} publications")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
