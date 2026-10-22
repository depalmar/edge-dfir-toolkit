"""F5 BIG-IP checks."""
from __future__ import annotations

import re
from collections import Counter

from ..evidence import iter_lines, parse_ts
from . import Hit, check, excerpt

# F5 K000162605 example (CVE-2026-94127):
#   err tmm1[30975]: 01990004:3: <PROFILE>: Request UserInfo from Source ID (null)
#   IP <IP> failed. Error Code (invalid_token) Error Description (The access token is invalid.)
# The address may carry a BIG-IP route-domain suffix (10.0.0.1%2); F5 does not say
# whether this message prints one, so the pattern accepts it.
_USERINFO_FAIL = re.compile(
    rb"01990004:\d+:.*Request UserInfo .*?IP (?P<ip>[0-9a-fA-F:.]+(?:%\d+)?) failed\. Error Code \(invalid_token\)")
THRESHOLD = 10  # F5: ">= 10 in one log"


@check("f5_apm_oauth_userinfo_burst")
def f5_apm_oauth_userinfo_burst(view, det):
    """Ten or more invalid-token UserInfo failures in one log file.

    F5's CVE-2026-94127 indicator is ">= 10 in one log ... especially if all
    observed from a single IP", and F5 rates it medium confidence. The threshold
    is per log file, not per address - grouping by address would miss an attempt
    spread across several sources. Whether one address accounts for all of them
    is reported, because that is what F5 says strengthens the signal.

    It shows an attempt, not success: F5 describes the successful pattern as
    OAuth failures, then suspicious commands in /var/log/audit, then a TMM
    SIGABRT. Only APM configured as an OAuth Authorization Server is exposed.
    """
    srcs = view.files(["**/apm*", "**/log/apm*"])
    if not srcs:
        return False, []
    hits = []
    for src in srcs:
        ips: Counter[str] = Counter()
        first = None
        for n, raw in iter_lines(src):
            m = _USERINFO_FAIL.search(raw)
            if m:
                ips[m.group("ip").decode()] += 1
                if first is None:
                    first = (n, raw)
        total = sum(ips.values())
        if total < THRESHOLD:
            continue
        n, raw = first
        ts, tzk = parse_ts(raw.decode("latin-1"))
        single = len(ips) == 1
        top_ip, top_n = ips.most_common(1)[0]
        detail = (f"{total} invalid_token UserInfo failures in one log "
                  + (f"(all from {top_ip})" if single else f"from {len(ips)} addresses; most from {top_ip} ({top_n})"))
        hits.append(Hit(src.label(), detail, line=n, ts=ts, tz_known=tzk, excerpt=excerpt(raw),
                        extra={"total": total, "addresses": len(ips), "single_source": single,
                               "top_ip": top_ip}))
    return True, hits
