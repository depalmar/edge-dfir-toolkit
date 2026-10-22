"""Vendor collection profiles: load, validate, order, and gate.

A profile is declarative YAML under collectors/profiles/. The engine never runs
a command a profile did not declare, and a profile cannot load if any of its
impact-free steps would fail the read-only guard. The guard is enforced at load
time, not at run time, so a bad profile fails CI rather than an engagement.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .util import REPO_ROOT

PROFILE_DIR = REPO_ROOT / "collectors" / "profiles"

# Order of volatility. Collection runs strictly in this order.
#   V0 identity and clock (needed to interpret everything after it)
#   V1 memory and memory-layout state (lost on reboot, sabotaged by implants)
#   V2 process / socket / module state
#   V3 active sessions (admin, VPN, AAA)
#   P1 integrity checks (vendor hash tools)
#   P2 configuration
#   P3 auth and VPN logs     P4 web / portal logs     P5 system and crash logs
#   P6 filesystem metadata   P7 persistence locations
#   B  vendor diagnostic bundles (write a file on the device)
#   X  break-glass (memory / core dumps, imaging; vendor-assisted or disruptive)
TIER_ORDER = ["V0", "V1", "V2", "V3", "P1", "P2", "P3", "P4", "P5", "P6", "P7", "B", "X"]

# What each tier proves, used for evidence-gap reporting.
TIER_CLASS = {
    "V0": "identity", "V1": "memory", "V2": "process", "V3": "sessions",
    "P1": "integrity", "P2": "config", "P3": "auth-logs", "P4": "web-logs",
    "P5": "system-logs", "P6": "filesystem", "P7": "persistence",
    "B": "bundle", "X": "memory",
}

IMPACTS = ("none", "vendor-bundle", "break-glass")
KINDS = ("command", "fetch", "manual")


class ProfileError(ValueError):
    pass


@dataclass
class Step:
    id: str
    tier: str
    kind: str
    purpose: str
    impact: str = "none"
    cmd: str | None = None
    list_cmd: str | None = None          # fetch: command that prints one remote path per line
    paths: list[str] = field(default_factory=list)  # fetch: literal remote paths
    instructions: str | None = None      # manual steps
    requires_vars: list[str] = field(default_factory=list)
    timeout: int = 120
    confidence: str = "medium"           # how sure we are the command exists as written
    unverified: bool = False
    references: list[str] = field(default_factory=list)

    @property
    def order_key(self) -> int:
        return TIER_ORDER.index(self.tier)

    def render(self, variables: dict[str, str]) -> "Step":
        """Return a copy with {var} placeholders filled. Missing vars raise KeyError."""
        def fill(s: str | None) -> str | None:
            return s.format(**variables) if s else s
        return Step(**{**self.__dict__, "cmd": fill(self.cmd), "list_cmd": fill(self.list_cmd),
                       "paths": [fill(p) for p in self.paths]})


@dataclass
class Profile:
    name: str
    platform_id: str
    display: str
    transports: list[str]
    prompt: str
    pager: str | None
    session_setup: list[str]
    allow: list[str]
    deny: list[str]
    expected_evidence: list[str]
    steps: list[Step]
    notes: str = ""
    source: Path | None = None

    def ordered(self, allow_bundle: bool = False, break_glass: bool = False) -> list[Step]:
        """Steps in order of volatility, filtered by the impact the operator allowed."""
        permitted = {"none"}
        if allow_bundle:
            permitted.add("vendor-bundle")
        if break_glass:
            permitted.update({"vendor-bundle", "break-glass"})
        # Stable sort: declaration order is preserved inside a tier.
        return sorted((s for s in self.steps if s.impact in permitted), key=lambda s: s.order_key)

    def check_command(self, cmd: str) -> None:
        """Raise ProfileError if an impact-free command fails the read-only guard."""
        if not any(re.search(a, cmd) for a in self.allow):
            raise ProfileError(f"{self.name}: command not on allow-list: {cmd!r}")
        for d in self.deny:
            if re.search(d, cmd):
                raise ProfileError(f"{self.name}: command matches deny rule {d!r}: {cmd!r}")


def _step(raw: dict[str, Any], pname: str) -> Step:
    for k in ("id", "tier", "kind", "purpose"):
        if k not in raw:
            raise ProfileError(f"{pname}: step missing {k}: {raw}")
    if raw["tier"] not in TIER_ORDER:
        raise ProfileError(f"{pname}/{raw['id']}: unknown tier {raw['tier']}")
    if raw["kind"] not in KINDS:
        raise ProfileError(f"{pname}/{raw['id']}: unknown kind {raw['kind']}")
    impact = raw.get("impact", "none")
    if impact not in IMPACTS:
        raise ProfileError(f"{pname}/{raw['id']}: unknown impact {impact}")
    s = Step(
        id=raw["id"], tier=raw["tier"], kind=raw["kind"], purpose=raw["purpose"].strip(),
        impact=impact, cmd=raw.get("cmd"), list_cmd=raw.get("list_cmd"),
        paths=list(raw.get("paths", [])), instructions=raw.get("instructions"),
        requires_vars=list(raw.get("requires_vars", [])), timeout=int(raw.get("timeout", 120)),
        confidence=raw.get("confidence", "medium"), unverified=bool(raw.get("unverified", False)),
        references=list(raw.get("references", [])),
    )
    if s.kind == "command" and not s.cmd:
        raise ProfileError(f"{pname}/{s.id}: command step needs cmd")
    if s.kind == "fetch" and not (s.paths or s.list_cmd):
        raise ProfileError(f"{pname}/{s.id}: fetch step needs paths or list_cmd")
    if s.kind == "manual" and not s.instructions:
        raise ProfileError(f"{pname}/{s.id}: manual step needs instructions")
    if s.confidence == "low" and not s.unverified:
        raise ProfileError(f"{pname}/{s.id}: low-confidence step must carry unverified: true")
    return s


def load_profile(path: Path) -> Profile:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    name = raw["profile"]
    cli = raw.get("cli", {}) or {}
    steps = [_step(s, name) for s in raw.get("steps", [])]
    ids = [s.id for s in steps]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ProfileError(f"{name}: duplicate step ids {sorted(dupes)}")
    prof = Profile(
        name=name, platform_id=raw["platform_id"], display=raw["display"],
        transports=list(raw.get("transports", [])), prompt=cli.get("prompt", r"[>#$] ?$"),
        pager=cli.get("pager"), session_setup=list(cli.get("session_setup", [])),
        allow=list(cli.get("allow", [])), deny=list(cli.get("deny", [])),
        expected_evidence=list(raw.get("expected_evidence", [])), steps=steps,
        notes=raw.get("notes", ""), source=path,
    )
    # Load-time guard: every impact-free command and list_cmd must pass, with
    # placeholders filled by an inert value. The engine checks again after the
    # operator's real values are substituted, so a --var cannot smuggle in ';'.
    for s in steps:
        if s.impact != "none":
            continue
        probe = s.render({v: "/placeholder" for v in s.requires_vars})
        for c in (probe.cmd, probe.list_cmd):
            if c:
                prof.check_command(c)
    for c in prof.session_setup:
        if not re.search(r"^(set cli |terminal (pager|length|width) )", c):
            raise ProfileError(f"{name}: session_setup must be session-scoped only: {c!r}")
    return prof


def available_profiles() -> dict[str, Path]:
    return {p.stem: p for p in sorted(PROFILE_DIR.glob("*.yaml"))}


def get_profile(name: str) -> Profile:
    paths = available_profiles()
    if name not in paths:
        raise ProfileError(f"unknown profile {name!r}; have {sorted(paths)}")
    return load_profile(paths[name])
