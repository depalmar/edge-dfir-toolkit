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

    # ---- rule directories
    for d in sorted(ROOT.glob("0[0-9]-*")):
        if d.is_dir() and not (d / "README.md").is_file():
            err(f"{d.name}: missing README.md")

    if problems:
        for p in problems:
            print(f"FAIL  {p}")
        print(f"\n{len(problems)} problem(s)")
        return 1
    n_det = len(det_ids)
    print(f"OK  {len(platforms)} platforms, {len(profiles)} profiles, {len(pack_ids)} packs, {n_det} detections")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
