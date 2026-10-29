# 04-citrix-netscaler/ - Citrix NetScaler ADC / Gateway

Platform: `EDGE-0004` (see `artifacts/catalog/`).  
Detection packs: `EDGE-PACK-0004`, `EDGE-PACK-0005`, `EDGE-PACK-0027`, `EDGE-PACK-0028`, `EDGE-PACK-0034` (see `artifacts/packs/`).

## Rules

| File | Format | Detects |
|---|---|---|
| `php_webshell_generic.yar` | YARA | small PHP web shells under appliance web roots (also used by EDGE-PACK-0002) |
| `netscaler_cve_2025_5777_nonprintable_auth.yml` | Sigma | authentication failures carrying leaked non-printable bytes (CVE-2025-5777); regex on `Message` |
| `netscaler_cve_2026_88771_pitboss_log_poisoning.yml` | Sigma | pitboss lines in ns.log carrying injected text (CVE-2026-88771); regex on `Message` |
| `netscaler_cve_2026_3055_wsfed_wctx.yml` | Sigma | WS-Federation request with a bare wctx parameter (CVE-2026-3055); regex on `Message` |

## Notes

Regex rules match `Message`, the full raw log line as the appliance sent it; map
it to your raw-message field in the Sigma pipeline. Keyword rules need no mapping.


The memory-disclosure signature (non-printable bytes inside authentication-failure lines in ns.log) is implemented as a coded check, `netscaler_auth_nonprintable`, because Lucene-family backends cannot express it reliably in Sigma.

Core dumps: NCSC-NL's own YARA rules for NetScaler packet-engine core files
(`core-dump-checks/iocs.yar` in github.com/NCSC-NL/citrix-2025, CVE-2025-5349,
CVE-2025-5777 and CVE-2025-6543) are EUPL-licensed and not copied here. Copy
the `NSPPE-*` files off `/var/core`, ingest them with `--evidence-class memory`
and pass NCSC-NL's file to `analyze` with `--memory-yara`.
