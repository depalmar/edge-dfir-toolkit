"""Small shared helpers: time, hashing, naming."""
from __future__ import annotations

import datetime as _dt
import hashlib
import re
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent
REPO_ROOT = PKG_DIR.parent


def utcnow() -> str:
    """UTC timestamp with millisecond precision, Z suffix."""
    now = _dt.datetime.now(_dt.timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def tool_hash() -> str:
    """Hash of every module in the package, in a stable order.

    Recorded in the custody manifest so a reviewer can tell which build of the
    tool produced a case. Hashing one file would miss a change to a check module.
    """
    h = hashlib.sha256()
    for p in sorted(PKG_DIR.rglob("*.py")):
        h.update(p.relative_to(PKG_DIR).as_posix().encode())
        h.update(p.read_bytes())
    return h.hexdigest()


_SLUG = re.compile(r"[^A-Za-z0-9]+")


def slugify(text: str, limit: int = 120) -> str:
    return _SLUG.sub("_", text).strip("_").lower()[:limit] or "cmd"


def safe_relpath(remote: str) -> Path:
    """Map a remote absolute path to a relative path under files/.

    Drops '..' and leading separators so a hostile listing cannot steer a write
    outside the case directory.
    """
    parts = [p for p in remote.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    return Path(*parts) if parts else Path("_root")
