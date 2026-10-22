"""Cisco ASA / FTD checks."""
from __future__ import annotations

import re

from . import Hit, check, excerpt

# show memory region rows: start end length perms offset ... name
_REGION = re.compile(
    r"(?P<start>0x[0-9a-f]+)\s+(?P<end>0x[0-9a-f]+)\s+(?P<length>0x[0-9a-f]+)\s+(?P<perms>[r-][w-][x-][ps-])\b.*?(?P<name>\S*lina\S*)\s*$",
    re.I,
)


@check("asa_lina_exec_regions")
def asa_lina_exec_regions(view, det):
    """LINE DANCER indicator from the vendor's ArcaneDoor guidance.

    One r-xp region for lina is normal. More than one is the indicator; one of
    exactly 0x1000 bytes is called out as especially suspicious. The full region
    output is preferred when present because a filtered capture can drop the
    header the parser does not need but a reviewer does.
    """
    text = view.step_text("mem_region_lina") or view.step_text("mem_region_full")
    src = "step:mem_region_lina" if view.step_text("mem_region_lina") else "step:mem_region_full"
    if text is None:
        return False, []
    execs = []
    for n, line in enumerate(text.splitlines(), 1):
        m = _REGION.search(line)
        if m and m.group("perms").lower().startswith("r-x"):
            execs.append((n, line.strip(), int(m.group("length"), 16)))
    if len(execs) <= 1:
        return True, []
    page = [e for e in execs if e[2] == 0x1000]
    detail = f"{len(execs)} executable lina regions"
    if page:
        detail += f"; {len(page)} of exactly 0x1000 bytes"
    return True, [Hit(src, detail, line=n, excerpt=excerpt(line),
                      extra={"length": hex(length)}) for n, line, length in execs]
