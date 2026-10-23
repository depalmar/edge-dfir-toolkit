# 01-panos-globalprotect/ - PAN-OS / GlobalProtect

Platform: `EDGE-0001` (see `artifacts/catalog/`).  
Detection packs: `EDGE-PACK-0001`, `EDGE-PACK-0002`, `EDGE-PACK-0025` (see `artifacts/packs/`).

## Rules

| File | Format | Detects |
|---|---|---|
| `panos_cve_2024_3400_gpsvc_unmarshal.yml` | Sigma | CVE-2024-3400 exploitation attempts in gpsvc.log |
| `panos_cron_download_exec.yml` | Sigma | cron piping a download into a shell (post-exploitation persistence) |
| `panos_cve_2024_0012_auth_bypass.yml` | Sigma | CVE-2024-0012 management-interface bypass requests |
| `panos_cve_2026_0257_poc_host_id.yml` | Sigma | GlobalProtect sessions carrying the CVE-2026-0257 proof of concept's default host IDs or names |
| `panos_upstyle_backdoor.yar` | YARA | UPSTYLE payload and its .pth loader |

## Notes

The TSF is the richest customer-reachable source. Take it before upgrading: the vendor says some logs from the prior installation become inaccessible on the device after an upgrade.

CVE-2026-0300 left its tunnelling tools in /var/tmp and /tmp after clearing crash records; with no customer shell, those paths are checked only against files TAC or an image recovers.
