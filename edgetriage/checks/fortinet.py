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


# The researcher Fortinet credits for FG-IR-25-934 shows the clean language
# directory carrying one link, "custom -> /data2/custom_lang" (pgj11.com).
LANG_NORMAL_TARGETS = ("/data2/custom_lang",)
# Listings where a link into the root filesystem is unexpected. System-binary
# directories (/bin, /data/bin) are full of links to /bin/init on a clean device
# (Mandiant's published `fnsysctl ls -la /bin`), so they are not scored here.
ROOTISH_LISTINGS = ("listing_sslvpn_lang", "listing_data")


def _lang_link_suspicious(target: str) -> bool:
    return (target.rstrip("/") or "/") not in LANG_NORMAL_TARGETS


@check("fortios_symlink_to_root")
def fortios_symlink_to_root(view, det):
    """Symbolic links reaching into the root filesystem.

    The 2025 FortiGate persistence modified the SSL-VPN language directory's
    `custom` link so that it pointed at the root filesystem, exposing it
    read-only to the attacker; it survived patching. A clean directory has one
    link, custom -> /data2/custom_lang. Any other link there, and any link from
    the /data listing into a root path, needs an explanation. Links are read
    from listing steps and from archive members the extractor refused, since a
    bundle that carried the link is evidence too.
    """
    listings = [s for s in view.manifest.get("steps", [])
                if s["step_id"] in ROOTISH_LISTINGS and s.get("status") == "ok"]
    rejected = view.rejected_members()
    if not listings and not rejected:
        return False, []
    hits = []
    for s in listings:
        text = view.step_text(s["step_id"]) or ""
        in_lang = s["step_id"] == "listing_sslvpn_lang"
        for n, line in enumerate(text.splitlines(), 1):
            m = _LINK.match(line.strip())
            if not m:
                continue
            target = m.group("target")
            if (in_lang and _lang_link_suspicious(target)) or (not in_lang and _rootish(target)):
                hits.append(Hit(f"step:{s['step_id']}",
                                f"symlink {m.group('name')} -> {target}",
                                line=n, excerpt=excerpt(line)))
    for label, reason in rejected:
        m = re.match(r"(?P<name>.+): link -> (?P<target>.+)$", reason)
        if not m:
            continue
        name, target = m.group("name"), m.group("target")
        if ("lang" in name.lower() and _lang_link_suspicious(target)) or \
                ("lang" not in name.lower() and _rootish(target)):
            hits.append(Hit(f"bundle:{label}", f"archived symlink {name} -> {target}"))
    return True, hits


# Fortinet's tech tip for CVE-2022-42475 prints the crash as separate rows:
#   xxxx: [ Date & Time ] <.....> application sslvpnd
#   xxxx: [ Date & Time ] <.....> *** signal 11 (Segmentation fault) received ***
# Rows of one crash share the bracketed process token.
_CRASH_ROW = re.compile(r"<(?P<tok>[^<>\s]+)>\s+(?P<msg>.*)$")
_APP = re.compile(r"^application\s+(?P<app>\S+)")
_SEGV = re.compile(r"signal 11 \(Segmentation fault\) received", re.I)


def _crashlog_segv(view, apps: frozenset[str]):
    """Signal-11 crashes of the named applications in `diagnose debug crashlog read`.

    The crash log puts the application name and the signal on separate rows,
    so a same-line regex never fires on it. A signal-11 row is attributed to an
    application when the nearest preceding `application` row with the same
    process token names it. Zero parsed crash rows is not-evaluated.
    """
    text = view.step_text("crashlog")
    if text is None:
        return False, []
    rows = 0
    app_by_tok: dict[str, str] = {}
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        m = _CRASH_ROW.search(line)
        if not m:
            continue
        rows += 1
        tok, msg = m.group("tok"), m.group("msg").strip()
        a = _APP.match(msg)
        if a:
            app_by_tok[tok] = a.group("app")
        elif _SEGV.search(msg) and app_by_tok.get(tok) in apps:
            hits.append(Hit("step:crashlog", f"{app_by_tok[tok]} signal 11 (Segmentation fault)",
                            line=n, excerpt=excerpt(line)))
    if rows == 0:
        return False, []
    return True, hits


@check("fortios_crashlog_sslvpnd_segv")
def fortios_crashlog_sslvpnd_segv(view, det):
    """sslvpnd crash with signal 11 (Fortinet's CVE-2022-42475 tech tip)."""
    return _crashlog_segv(view, frozenset({"sslvpnd"}))


@check("fortios_crashlog_peerstitch_segv")
def fortios_crashlog_peerstitch_segv(view, det):
    """miglogd, iked or syslogd crash with signal 11 (Unit 42's PEERSTITCH hunting row)."""
    return _crashlog_segv(view, frozenset({"miglogd", "iked", "syslogd"}))
