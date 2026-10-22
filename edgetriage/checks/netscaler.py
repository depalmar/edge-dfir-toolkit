"""Citrix NetScaler checks."""
from __future__ import annotations

import re

from ..evidence import iter_lines, parse_ts
from . import Hit, check, excerpt

# find -ls:  inode blocks perms links owner group size month day time|year path
_LS = re.compile(r"^\s*\d+\s+\d+\s+(?P<perms>[-dlcbps][rwxsStT-]{9})\s+\d+\s+\S+\s+\S+\s+(?P<size>\d+)\s+\w{3}\s+\d+\s+[\d:]+\s+(?P<path>/.+)$")


@check("netscaler_php_writable")
def netscaler_php_writable(view, det):
    """PHP under a NetScaler web root that is writable by anyone.

    Shipped PHP is read-only. A writable PHP file is the permission heuristic
    used by Dissect-based NetScaler triage. It is a lead on its own, and
    combines with a content hit on the same file.
    """
    text = view.step_text("php_stat")
    if text is None:
        return False, []
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        m = _LS.match(line)
        if not m:
            continue
        perms = m.group("perms")
        if "w" in perms[1:]:
            hits.append(Hit("step:php_stat", f"writable PHP {m.group('path')} ({perms})",
                            line=n, excerpt=excerpt(line), extra={"path": m.group("path")}))
    return True, hits


_AUTH = re.compile(rb"LOGIN_FAILED|Authentication is rejected", re.I)


@check("netscaler_auth_nonprintable")
def netscaler_auth_nonprintable(view, det):
    """Authentication-failure records carrying non-printable bytes.

    CVE-2025-5777 leaks heap memory; the leaked bytes surface in ns.log inside
    authentication-failure messages. A burst of such lines is attempted
    exploitation - success has to be shown through session reuse, not here.
    """
    srcs = view.files(["**/ns.log*"])
    if not srcs:
        return False, []
    hits = []
    for src in srcs:
        for n, raw in iter_lines(src):
            if not _AUTH.search(raw):
                continue
            if any((b < 0x20 and b != 0x09) or b >= 0x7F for b in raw):
                ts, tzk = parse_ts(raw.decode("latin-1"))
                hits.append(Hit(src.label(), "auth failure with non-printable bytes", line=n,
                                ts=ts, tz_known=tzk, excerpt=excerpt(raw)))
    return True, hits
