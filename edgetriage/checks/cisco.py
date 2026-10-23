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
    """Executable IOSd memory with dirty pages.

    Cisco's IOS XE forensic guide checks the iosd smaps "for non-zero values in
    the Private Dirty entry for each segment with the executable flag set (i.e.,
    r-xp or rwxp)". Its worked example of possible tampering is an rwxp segment
    with Private_Dirty above zero, so that is the default; a detection can pass
    `args: {perms: [r-xp]}` to report dirty r-xp segments separately, at a lower
    tier, since Cisco gives no example of what a dirty r-xp segment means.

    Zero parsed mapping headers (an error message, a switch that needs another
    form of the command, a truncated capture) is 'not evaluated', never 'no hit'.
    """
    perms = tuple(p.lower() for p in (det.get("args") or {}).get("perms", ["rwxp"]))
    hits, headers = [], 0
    # Router form, Catalyst switch form, and the switch form with r0 for rp.
    for step in ("iosd_smaps", "iosd_smaps_switch", "iosd_smaps_switch_r0"):
        text = view.step_text(step)
        if text is not None:
            headers += _scan_smaps(text, step, hits, perms)
    if headers == 0:
        return False, []
    return True, hits


def _scan_smaps(text: str, step: str, hits: list, perms: tuple[str, ...] = ("rwxp",)) -> int:
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
        if d and cur and cur[2] in perms and int(d.group("kb")) > 0:
            hits.append(Hit(f"step:{step}",
                            f"{cur[2]} iosd segment with Private_Dirty {d.group('kb')} kB",
                            line=cur[0], excerpt=excerpt(cur[1]),
                            extra={"private_dirty_kb": int(d.group("kb"))}))
            cur = None
    return headers


@check("asa_lina_exec_regions")
def asa_lina_exec_regions(view, det):
    """LINE DANCER indicator from the vendor's ArcaneDoor guidance.

    The indicator is more than one executable (r-x) memory region mapped to
    lina, especially one of exactly 0x1000 bytes (Talos). NCSC's 2 or 5 is the
    number of lina regions of all permissions, which varies by release and "in
    itself is not an indicator of compromise"; a split text section giving
    "multiple executable memory regions for lina" is what NCSC calls suspicious,
    and one of size 0x1000 "a strong indicator of compromise". The hit tier is
    'likely' and the region list is handed to the analyst, never auto-confirmed.
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
    detail += (" (Talos and NCSC treat more than one r-xp lina region as the indicator; NCSC's"
               " 2 or 5 counts lina regions of all permissions and is not a normal range for r-xp)")
    return True, [Hit(src, detail, line=n, excerpt=excerpt(line),
                      extra={"length": hex(length)}) for n, line, length in execs]


# `show checkheaps` as printed in Cisco's detection guide for the 2025 ArcaneDoor
# activity:
#
#   Time elapsed since last run      : 28 secs
#   ...
#   Total number of runs             : 6352
_CH_RUNS = re.compile(r"^\s*Total number of runs\s*:\s*(\d+)\s*$", re.I | re.M)
_CH_ELAPSED = re.compile(r"^\s*Time elapsed since last run\s*:\s*(\d+)\s*secs?\s*$", re.I | re.M)


@check("asa_checkheaps_stalled")
def asa_checkheaps_stalled(view, det):
    """Checkheaps counter that did not move between two snapshots.

    Cisco: checkheaps runs every 60 seconds by default and the actor disabled it.
    CISA's ED 25-03 procedure takes two readings: "Wait at least five minutes,
    then run "show checkheaps" again", and "If there is no positive change in
    "Total number of runs," this is evidence of a potential compromise." The
    profile takes its two readings at the start and the end of collection; it
    does not wait, so the gap between them can be shorter than CISA's five
    minutes, and the hit detail says so.

    The rule for short gaps is this toolkit's: an unchanged counter is a hit only
    when the second reading says a minute or more has passed since the last run,
    or its elapsed time did not advance. An unchanged counter after less than a
    minute is not evaluated - too little time has passed to tell.
    """
    first, last = view.step_text("show_checkheaps"), view.step_text("show_checkheaps_late")
    if first is None or last is None:
        return False, []
    r1, r2 = _CH_RUNS.search(first), _CH_RUNS.search(last)
    if not r1 or not r2:
        return False, []
    runs1, runs2 = int(r1.group(1)), int(r2.group(1))
    if runs2 > runs1:
        return True, []
    e1, e2 = _CH_ELAPSED.search(first), _CH_ELAPSED.search(last)
    if not e2:
        return False, []
    el1, el2 = (int(e1.group(1)) if e1 else None), int(e2.group(1))
    if el2 < 60 and (el1 is None or el2 > el1):
        return False, []
    gap = _reading_gap(view)
    detail = (f"checkheaps Total number of runs stayed at {runs2}; "
              f"{el2} s since the last run in the second reading")
    if gap is not None and gap >= 300:
        detail += f"; readings {gap} s apart, meeting CISA's five-minute wait."
    else:
        detail += ((f"; readings only {gap} s apart" if gap is not None else "; gap between readings unknown")
                   + ". CISA's procedure waits at least five minutes between readings: repeat by hand before relying on it.")
    return True, [Hit("step:show_checkheaps_late", detail, excerpt=excerpt(r2.group(0).strip()),
                      extra={"runs_first": runs1, "runs_last": runs2, "elapsed_last": el2,
                             "reading_gap_s": gap})]


def _reading_gap(view) -> int | None:
    """Seconds between the two checkheaps readings, from the manifest's step
    start times. None when the view has no step records (or no times)."""
    from datetime import datetime
    step = getattr(view, "step", None)
    if step is None:
        return None
    a, b = step("show_checkheaps"), step("show_checkheaps_late")
    try:
        t1 = datetime.fromisoformat(a["started_utc"].replace("Z", "+00:00"))
        t2 = datetime.fromisoformat(b["started_utc"].replace("Z", "+00:00"))
    except (TypeError, KeyError, ValueError, AttributeError):
        return None
    return int((t2 - t1).total_seconds())
