# 04-citrix-netscaler/ - Citrix NetScaler ADC / Gateway

Platform: `EDGE-0004` (see `artifacts/catalog/`).  
Detection packs: `EDGE-PACK-0004`, `EDGE-PACK-0005` (see `artifacts/packs/`).

## Rules

| File | Format | Detects |
|---|---|---|
| `php_webshell_generic.yar` | YARA | small PHP web shells under appliance web roots (also used by EDGE-PACK-0002) |

## Notes

The memory-disclosure signature (non-printable bytes inside authentication-failure lines in ns.log) is implemented as a coded check, `netscaler_auth_nonprintable`, because Lucene-family backends cannot express it reliably in Sigma.
