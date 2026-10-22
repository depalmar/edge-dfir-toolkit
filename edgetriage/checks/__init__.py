"""Coded checks for logic a declarative pack cannot express.

A check returns (evaluated, hits). `evaluated=False` means the evidence it
needs was not in the case - that is reported as a gap, never as a pass.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

REGISTRY: dict[str, Callable[..., tuple[bool, list["Hit"]]]] = {}


@dataclass
class Hit:
    source: str
    detail: str
    line: int | None = None
    ts: str | None = None
    tz_known: bool = False
    excerpt: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def check(name: str):
    def deco(fn):
        if name in REGISTRY:
            raise ValueError(f"duplicate check {name}")
        REGISTRY[name] = fn
        return fn
    return deco


def excerpt(raw: bytes | str, limit: int = 240) -> str:
    """Printable, length-capped excerpt. Non-printable bytes are shown as \\xNN
    so a memory-leak signature stays visible in the report without breaking it."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    out = []
    for b in raw[:limit]:
        out.append(chr(b) if 0x20 <= b < 0x7F or b == 0x09 else f"\\x{b:02x}")
    return "".join(out) + ("..." if len(raw) > limit else "")


# Import modules so their @check decorators register.
from . import cisco, f5, fortinet, generic, netscaler  # noqa: E402,F401
