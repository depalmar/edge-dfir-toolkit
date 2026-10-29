"""SonicWall SMA 1000 checks."""
from __future__ import annotations

import re

from ..evidence import iter_lines
from . import Hit, check, excerpt

# Volexity (17 July 2026), after `find / -perm -4000`: "The following binaries may
# show up legitimately". Copied from the post; ROOTRUN (/usr/bin/xzfind) was one more.
SETUID_EXPECTED = frozenset({
    "/usr/lib/mysql/plugin/auth_pam_tool_dir/auth_pam_tool",
    "/usr/libexec/ssh-keysign",
    "/usr/local/workplace/conf",
    "/usr/bin/umount",
    "/usr/bin/su",
    "/usr/bin/mount",
    "/usr/bin/newgrp",
    "/usr/bin/at",
    "/usr/bin/ping",
    "/usr/bin/sudo",
    "/usr/bin/ping6",
})
_PATH = re.compile(r"/[\w./+@-]+")


@check("sma1000_setuid_outside_expected")
def setuid_outside_expected(view, det, **_):
    """Setuid binaries outside Volexity's expected list.

    The listing is the profile's setuid_listing step, or an ingested file whose
    name starts setuid-listing. Only lines that are a bare absolute path count;
    find's own errors and anything else are skipped. A listing with no path at
    all (find missing, the step refused, an error message) is not evaluated, so
    a failed find is never read as "no unexpected setuid binaries".
    """
    step = (det.get("args") or {}).get("step", "setuid_listing")
    srcs = [s for s in [view.step_source(step)] if s] + view.files(["**/setuid-listing*"])
    paths, hits = 0, []
    for src in srcs:
        for n, raw in iter_lines(src):
            line = raw.decode("utf-8", errors="replace").strip()
            if not _PATH.fullmatch(line):
                continue
            paths += 1
            if line not in SETUID_EXPECTED:
                hits.append(Hit(src.label(), f"setuid binary outside Volexity's expected list: {line}",
                                line=n, excerpt=excerpt(raw), extra={"path": line}))
    return paths > 0, hits
