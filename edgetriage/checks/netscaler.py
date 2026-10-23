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


# NetScaler's own form: "AAA Message" ... "Authentication is rejected for " with
# bytes 128-255 after the marker (vendor awk: $1~/AAA Message/ && $2~/[\x80-\xff]/).
_VENDOR_MARK = b"Authentication is rejected for "
# Huntress's form: AAA LOGIN_FAILED with an unprintable User value.
_HUNTRESS = re.compile(rb"LOGIN_FAILED.*?\bUser (?P<rest>.*)$", re.S)


def _leaky(raw: bytes) -> bool:
    if _VENDOR_MARK in raw:
        head, _, tail = raw.partition(_VENDOR_MARK)
        if b"AAA Message" in head and any(b >= 0x80 for b in tail):
            return True
    m = _HUNTRESS.search(raw)
    return bool(m) and any((b < 0x20 and b != 0x09) or b >= 0x7F for b in m.group("rest"))


@check("netscaler_auth_nonprintable")
def netscaler_auth_nonprintable(view, det):
    """Authentication-failure records carrying leaked, non-printable bytes.

    CVE-2025-5777 leaks heap memory; the leaked bytes surface in ns.log inside
    authentication-failure messages. NetScaler publishes the "AAA Message" /
    "Authentication is rejected for" form with bytes 128-255 after the marker;
    Huntress publishes LOGIN_FAILED lines with an unprintable User value. Only
    the part of the line after the marker is scored. A burst of such lines is
    attempted exploitation - success has to be shown through session reuse.
    """
    srcs = view.files(["**/ns.log*"])
    if not srcs:
        return False, []
    hits = []
    for src in srcs:
        for n, raw in iter_lines(src):
            if _leaky(raw):
                ts, tzk = parse_ts(raw.decode("latin-1"))
                hits.append(Hit(src.label(), "auth failure with non-printable bytes", line=n,
                                ts=ts, tz_known=tzk, excerpt=excerpt(raw)))
    return True, hits
