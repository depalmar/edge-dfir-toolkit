"""Platform-independent checks."""
from __future__ import annotations

import json
import re

from . import Hit, check, excerpt

_HASHLINE = re.compile(r"\b(?P<hash>[0-9a-f]{64})\b.*?(?P<path>/[\w./+@-]+)|(?P<path2>/[\w./+@-]+).*?\b(?P<hash2>[0-9a-f]{64})\b", re.I)


def _parse_hashes(text: str) -> dict[str, tuple[str, int]]:
    out = {}
    for n, line in enumerate(text.splitlines(), 1):
        m = _HASHLINE.search(line)
        if m:
            h = (m.group("hash") or m.group("hash2")).lower()
            p = m.group("path") or m.group("path2")
            out[p] = (h, n)
    return out


@check("hash_baseline")
def hash_baseline(view, det, baseline: dict | None = None, **_):
    """Compare device-reported file hashes with a known-good baseline.

    The baseline is a JSON object {path: sha256} built from a clean device or
    vendor image of the SAME build. Without one the check is not evaluated:
    a list of hashes with nothing to compare against proves nothing, and saying
    otherwise is how a rootkit gets a clean bill of health.
    """
    step = det.get("args", {}).get("step", "fs_hash")
    text = view.step_text(step)
    if text is None or baseline is None:
        return False, []
    seen = _parse_hashes(text)
    hits = []
    for path, (h, n) in sorted(seen.items()):
        want = baseline.get(path)
        if want is None:
            hits.append(Hit(f"step:{step}", f"not in baseline: {path}", line=n,
                            extra={"kind": "unknown", "sha256": h, "tier": "possible"}))
        elif want.lower() != h:
            hits.append(Hit(f"step:{step}", f"hash differs from baseline: {path}", line=n,
                            extra={"kind": "mismatch", "sha256": h, "expected": want, "tier": "likely"}))
    return True, hits


def load_baseline(path) -> dict[str, str]:
    data = json.loads(open(path, encoding="utf-8").read())
    if not isinstance(data, dict):
        raise ValueError("baseline must be a JSON object {path: sha256}")
    return {k: str(v) for k, v in data.items()}


__all__ = ["hash_baseline", "load_baseline", "excerpt"]
