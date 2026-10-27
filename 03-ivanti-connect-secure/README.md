# 03-ivanti-connect-secure/ - Ivanti Connect Secure / Policy Secure

Platform: `EDGE-0003` (see `artifacts/catalog/`).  
Detection packs: `EDGE-PACK-0007`, `EDGE-PACK-0026`, `EDGE-PACK-0029` (see `artifacts/packs/`).

## Rules

| File | Format | Detects |
|---|---|---|
| `ivanti_cve_2023_46805_totp_traversal.yml` | Sigma | the 2024 authentication-bypass traversal |
| `ivanti_cve_2024_21887_traversal_to_injection.yml` | Sigma | the traversal reaching the license/keys-status injection endpoint (the full 2024 chain) |
| `ivanti_spawn_family_mandiant_2025.yar` | YARA | Mandiant's published rules for SPAWNSNAIL, SPAWNANT, SPAWNMOLE, SPAWNSNARE, SPAWNSLOTH, PHASEJAM and DRYHOOK (2025); files from a snapshot or image only |

## Notes

Do not treat a clean Integrity Checker Tool result as a clean device. Off-box logs and a hypervisor snapshot with memory carry the weight here.

The 2026 chain (`EDGE-PACK-0026`) patched a library in memory only; Volexity
reports the ICT does not see it. Its on-disk traces are under /data/.icscap and
are reachable only through a VM snapshot.
