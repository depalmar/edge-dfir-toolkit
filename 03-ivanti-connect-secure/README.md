# 03-ivanti-connect-secure/ - Ivanti Connect Secure / Policy Secure

Platform: `EDGE-0003` (see `artifacts/catalog/`).  
Detection packs: `EDGE-PACK-0007`, `EDGE-PACK-0026`, `EDGE-PACK-0029`, `EDGE-PACK-0033` (see `artifacts/packs/`).

## Rules

| File | Format | Detects |
|---|---|---|
| `ivanti_cve_2023_46805_totp_traversal.yml` | Sigma | the 2024 authentication-bypass traversal |
| `ivanti_cve_2024_21887_traversal_to_injection.yml` | Sigma | the traversal reaching the license/keys-status injection endpoint (the full 2024 chain) |
| `ivanti_2024_webshells_mandiant.yar` | YARA | Mandiant's hunting rules for BUSHWALK, CHAINLINE, LIGHTWIRE and WARPWIRE (2024); FRAMESTING left out (its published string is ambiguous); files from a snapshot or image only |
| `ivanti_spawn_family_mandiant_2025.yar` | YARA | Mandiant's published rules for SPAWNSNAIL, SPAWNANT, SPAWNMOLE, SPAWNSNARE, SPAWNSLOTH, PHASEJAM and DRYHOOK (2025); files from a snapshot or image only |
| `ivanti_cve_2024_21893_saml20_soap.yml` | Sigma | POST to /dana-ws/saml20.ws, the CVE-2024-21893 SSRF endpoint |
| `ivanti_uta0576_rce_request_volexity.yar` | YARA | Volexity's rule for the CVE-2026-104935 request header (`X-DSCGI-PATH` naming wu.cgi); its scan context is file and memory |
| `ivanti_uta0576_eop_python_volexity.yar` | YARA | Volexity's rule for UTA0576's in-memory privilege-escalation script (2026); its scan context is memory |
| `ivanti_pysoxy_volexity.yar` | YARA | Volexity's rule for PySoxy, the proxy UTA0178 ran from /tmp (2024); file and memory |

## Notes

Do not treat a clean Integrity Checker Tool result as a clean device. Off-box logs and a hypervisor snapshot with memory carry the weight here.

The 2026 chain (`EDGE-PACK-0026`) patched a library in memory only; Volexity
reports the ICT does not see it. Its on-disk traces are under /data/.icscap and
are reachable only through a VM snapshot.

Memory: Volexity's three rules read only their strings, so `analyze` runs them
over every memory image ingested with `--evidence-class memory`. Mandiant's
rules check for an ELF header or a file size and stay file rules.
