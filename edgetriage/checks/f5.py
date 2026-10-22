"""F5 BIG-IP checks."""
from __future__ import annotations

import re
from collections import defaultdict

from ..evidence import iter_lines, parse_ts
from . import Hit, check, excerpt

# F5 K000162605 example (CVE-2026-94127):
#   err tmm1[30975]: 01990004:3: <PROFILE>: Request UserInfo from Source ID (null)
#   IP <IP> failed. Error Code (invalid_token) Error Description (The access token is invalid.)
_USERINFO_FAIL = re.compile(
    rb"01990004:\d+:.*Request UserInfo .*?IP (?P<ip>[0-9a-fA-F:.]+) failed\. Error Code \(invalid_token\)")
BURST = 10  # F5's own threshold: 10 or more from one IP


@check("f5_apm_oauth_userinfo_burst")
def f5_apm_oauth_userinfo_burst(view, det):
    """Bursts of invalid-token UserInfo failures from one source.

    F5's CVE-2026-94127 guidance is to alert on 10 or more of these from a single
    address. It shows an attempt, not success: F5 describes the successful
    pattern as OAuth failures, then suspicious commands in /var/log/audit, then a
    TMM SIGABRT. Only APM configured as an OAuth Authorization Server is exposed.
    """
    srcs = view.files(["**/apm*", "**/log/apm*"])
    if not srcs:
        return False, []
    per_ip: dict[str, list[tuple[str, int, str | None, bool, bytes]]] = defaultdict(list)
    for src in srcs:
        for n, raw in iter_lines(src):
            m = _USERINFO_FAIL.search(raw)
            if m:
                ts, tzk = parse_ts(raw.decode("latin-1"))
                per_ip[m.group("ip").decode()].append((src.label(), n, ts, tzk, raw))
    hits = []
    for ip, rows in sorted(per_ip.items()):
        if len(rows) >= BURST:
            label, n, ts, tzk, raw = rows[0]
            hits.append(Hit(label, f"{len(rows)} invalid_token UserInfo failures from {ip} (threshold {BURST})",
                            line=n, ts=ts, tz_known=tzk, excerpt=excerpt(raw), extra={"ip": ip, "count": len(rows)}))
    return True, hits
