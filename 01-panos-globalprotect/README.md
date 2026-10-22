# 01-panos-globalprotect/ - PAN-OS / GlobalProtect

Platform: `EDGE-0001` (see `artifacts/catalog/`).  
Detection packs: `EDGE-PACK-0001`, `EDGE-PACK-0002` (see `artifacts/packs/`).

## Rules

| File | Format | Detects |
|---|---|---|
| `panos_cve_2024_3400_gpsvc_unmarshal.yml` | Sigma | CVE-2024-3400 exploitation attempts in gpsvc.log |
| `panos_cron_download_exec.yml` | Sigma | cron piping a download into a shell (post-exploitation persistence) |
| `panos_cve_2024_0012_auth_bypass.yml` | Sigma | CVE-2024-0012 management-interface bypass requests |
| `panos_upstyle_backdoor.yar` | YARA | UPSTYLE payload and its .pth loader |

## Notes

The TSF is the richest customer-reachable source. Take it before upgrading: logs from the previous install become inaccessible after an upgrade.
