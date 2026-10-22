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
    execs = []
    for n, line in enumerate(text.splitlines(), 1):
        m = _REGION.match(line.strip())
        if m and m.group("perms").lower().startswith("r-x"):
            length = int(m.group("end"), 16) - int(m.group("start"), 16)
            execs.append((n, line.strip(), length))
    if len(execs) <= 1:
        return True, []
    page = [e for e in execs if e[2] == 0x1000]
    detail = f"{len(execs)} executable lina regions"
    if page:
        detail += f"; {len(page)} of exactly 0x1000 bytes"
    detail += " (NCSC notes 2 or occasionally 5 can be normal; review the list)"
    return True, [Hit(src, detail, line=n, excerpt=excerpt(line),
                      extra={"length": hex(length)}) for n, line, length in execs]
