"""Cisco ASA / FTD checks."""
from __future__ import annotations

import re

from . import Hit, check, excerpt

# `show memory region` on ASA prints /proc/maps-style rows, not a 0x-prefixed
# length column. The real format (confirmed against Cisco's command reference
# and the Talos ArcaneDoor write-up) joins start and end with a hyphen and has
# no length field:
#
#   Address                   Perm Offset   Dev   Inode   Pathname
#   561d9fee9000-561d9feea000 r-xp 02696000 00:02 5955    /asa/bin/lina
#
# Length is end - start. An earlier version of this check expected a
# "0x<start> 0x<end> 0x<length> r-xp" layout that no device produces, so it
# matched nothing and reported "evaluated, no hit" on a compromised box. That is
# the worst failure mode for this tool, so the format is pinned by a fixture
# taken from the published example.
_REGION = re.compile(
    r"^(?P<start>[0-9a-f]+)-(?P<end>[0-9a-f]+)\s+(?P<perms>[r-][w-][x-][ps-])\s+\S+\s+\S+\s+\S+\s+(?P<name>\S*lina\S*)\s*$",
    re.I,
)


# Linux smaps mapping header: start-end perms offset dev inode [path]
_SMAPS_HDR = re.compile(r"^(?P<start>[0-9a-f]+)-(?P<end>[0-9a-f]+)\s+(?P<perms>[r-][w-][x-][ps-])\s+\S+\s+\S+\s+\d+", re.I)
_PRIV_DIRTY = re.compile(r"^Private_Dirty:\s+(?P<kb>\d+)\s*kB", re.I)


@check("iosxe_iosd_rwx_dirty")
def iosxe_iosd_rwx_dirty(view, det):
    """Executable and writable IOSd memory with dirty pages.

    Cisco's IOS XE forensic guide: in the smaps of the iosd process, an rwxp
    segment whose Private_Dirty is above zero "may indicate" the running code
    has been tampered with. Unmodified code pages are clean copies of the image,
    so a dirty executable-and-writable page means something wrote to code.

    Zero parsed mapping headers (an error message, a switch that needs the
    `switch active` form, a truncated capture) is 'not evaluated', never 'no hit'.
    """
    hits, headers = [], 0
    for step in ("iosd_smaps", "iosd_smaps_switch"):   # router form, Catalyst switch form
        text = view.step_text(step)
        if text is not None:
            headers += _scan_smaps(text, step, hits)
    if headers == 0:
        return False, []
    return True, hits


def _scan_smaps(text: str, step: str, hits: list) -> int:
    headers = 0
    cur = None  # (line_no, header_line, perms)
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        h = _SMAPS_HDR.match(line)
        if h:
            headers += 1
            cur = (n, line, h.group("perms").lower())
            continue
        d = _PRIV_DIRTY.match(line)
        if d and cur and cur[2] == "rwxp" and int(d.group("kb")) > 0:
            hits.append(Hit(f"step:{step}",
                            f"rwxp iosd segment with Private_Dirty {d.group('kb')} kB",
                            line=cur[0], excerpt=excerpt(cur[1]),
                            extra={"private_dirty_kb": int(d.group("kb"))}))
            cur = None
    return headers


@check("asa_lina_exec_regions")
def asa_lina_exec_regions(view, det):
    """LINE DANCER indicator from the vendor's ArcaneDoor guidance.

    The indicator is more than one executable (r-x) memory region mapped to
    lina, one often exactly 0x1000 bytes. This is a lead, not proof: NCSC's
    analysis notes that some healthy devices legitimately show two (and in one
    case five) executable lina regions, so the hit tier is 'likely' and the
    region list is handed to the analyst to judge, never auto-confirmed.
    """
    text = view.step_text("mem_region_lina") or view.step_text("mem_region_full")
    src = "step:mem_region_lina" if view.step_text("mem_region_lina") else "step:mem_region_full"
    if text is None:
        return False, []
    execs, parsed = [], 0
    for n, line in enumerate(text.splitlines(), 1):
        m = _REGION.match(line.strip())
        if not m:
            continue
        parsed += 1
        if m.group("perms").lower().startswith("r-x"):
            length = int(m.group("end"), 16) - int(m.group("start"), 16)
            execs.append((n, line.strip(), length))
    # An error message, a truncated capture or a format change parses to zero
    # rows. That is "could not evaluate", never "no hit".
    if parsed == 0:
        return False, []
    if len(execs) <= 1:
        return True, []
    page = [e for e in execs if e[2] == 0x1000]
    detail = f"{len(execs)} executable lina regions"
    if page:
        detail += f"; {len(page)} of exactly 0x1000 bytes"
    detail += " (NCSC notes 2 or occasionally 5 can be normal; review the list)"
    return True, [Hit(src, detail, line=n, excerpt=excerpt(line),
                      extra={"length": hex(length)}) for n, line, length in execs]
