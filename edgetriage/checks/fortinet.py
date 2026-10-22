"""Fortinet FortiOS checks."""
from __future__ import annotations

import re

from . import Hit, check, excerpt

# busybox/GNU ls -l symlink row: "lrwxrwxrwx 1 0 0 1 Apr 10 12:00 name -> target"
_LINK = re.compile(r"^l[rwxsStT-]{9}.*?\s(?P<name>\S+) -> (?P<target>\S+)\s*$")
ROOT_DIRS = ("/", "/bin", "/sbin", "/lib", "/usr", "/etc", "/data", "/migadmin", "/var")


def _rootish(target: str) -> bool:
    t = target.rstrip("/") or "/"
    return t == "/" or any(t == d or t.startswith(d + "/") for d in ROOT_DIRS[1:])


@check("fortios_symlink_to_root")
def fortios_symlink_to_root(view, det):
    """Symbolic links reaching into the root filesystem.

    The 2025 FortiGate persistence was a symlink in the SSL-VPN language-file
    directory that exposed the root filesystem read-only to the attacker and
    survived patching. Any link from a served directory to a root path needs an
    explanation. Links are read from listing steps and from archive members the
    extractor refused, since a bundle that carried the link is evidence too.
    """
    listings = [s for s in view.manifest.get("steps", [])
                if s["step_id"].startswith("listing_") and s.get("status") == "ok"]
    rejected = view.rejected_members()
    if not listings and not rejected:
        return False, []
    hits = []
    for s in listings:
        text = view.step_text(s["step_id"]) or ""
        in_lang = s["step_id"] == "listing_sslvpn_lang"
        for n, line in enumerate(text.splitlines(), 1):
            m = _LINK.match(line.strip())
            if m and (in_lang or _rootish(m.group("target"))):
                hits.append(Hit(f"step:{s['step_id']}",
                                f"symlink {m.group('name')} -> {m.group('target')}",
                                line=n, excerpt=excerpt(line)))
    for label, reason in rejected:
        m = re.match(r"(?P<name>.+): link -> (?P<target>.+)$", reason)
        if m and ("lang" in m.group("name").lower() or _rootish(m.group("target"))):
            hits.append(Hit(f"bundle:{label}", f"archived symlink {m.group('name')} -> {m.group('target')}"))
    return True, hits
