# 12-sonicwall-sonicos/ - SonicWall firewalls (SonicOS)

Platform: `EDGE-0012` (see `artifacts/catalog/`).  
Detection packs: `EDGE-PACK-0038`, `EDGE-PACK-0039` (see `artifacts/packs/`).

## Rules

| File | Format | Detects |
|---|---|---|
| `sonicos_log_cleared.yml` | Sigma | event 5, Log Cleared, in the syslog stream (Arctic Wolf: the actors "commonly sought to delete firewall logs") |
| `sonicos_wan_admin_login.yml` | Sigma | event 236, an administrator login from the WAN zone, which SonicWall's CVE-2024-40766 workaround removes |
| `sonicos_cve_2024_53704_session_reuse.yml` | Sigma | the SSL VPN Session message SonicWall lists for CVE-2024-53704 ("Reuse SSLVPN session") |

## Notes

The rules read the raw syslog line (`Message`). SonicOS syslog carries the
event id as `m=` and the message as `msg=`; the Log Clear rule needs both, the
other two need only the message text, which the console's System Logs export
also carries. The analyzer runs the same patterns over ingested exports named
`sonicos-system-logs*` and `sonicos-syslog*`; SonicWall publishes no file layout
for its CSV or text export, so the names are the toolkit's convention.

What the 2024 and 2025 campaigns left on the firewall was an ordinary SSL VPN
login (event 1080 or 238). Whether one was malicious depends on where it came
from and which account it used, which is a hunt over the syslog copy, not a
rule: `EDGE-HUNT-0029` (hosting-provider sources), `EDGE-HUNT-0030` (the
directory synchronisation account on the VPN) and `EDGE-HUNT-0031` (internal
scanning minutes after a VPN login). The published addresses are in
`artifacts/intel/iocs/` (EDGE-IOC-0019 to 0023).

No YARA here: SonicOS gives the customer no file system or memory to scan.
