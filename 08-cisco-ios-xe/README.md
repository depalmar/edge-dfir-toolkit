# 08-cisco-ios-xe/ - Cisco IOS XE

Platform: `EDGE-0009` (see `artifacts/catalog/`).  
Detection packs: `EDGE-PACK-0011`, `EDGE-PACK-0012` (see `artifacts/packs/`).

## Rules

| File | Format | Detects |
|---|---|---|
| `ios_xe_cve_2023_20198_webui_implant.yml` | Sigma | web UI programmatic configuration and install messages from the vendor advisory |
| `ios_xe_wsma_endpoint_request.yml` | Sigma | requests to the web UI services endpoint, including double-encoded forms (AA25-239A) |

## Notes

Do not reboot before collecting: the 2023 implant lived in memory, but the
privilege-15 accounts it created survive. CVE-2026-20273 (August 2026
hardening release) is a different flaw from CVE-2023-20273.
