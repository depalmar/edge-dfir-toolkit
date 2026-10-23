# 05-cisco-asa-ftd/ - Cisco ASA / FTD

Platform: `EDGE-0005` (see `artifacts/catalog/`).  
Detection packs: `EDGE-PACK-0006`, `EDGE-PACK-0018`, `EDGE-PACK-0019` (see `artifacts/packs/`).

## Rules

| File | Format | Detects |
|---|---|---|
| `asa_cve_2023_20269_default_group_session.yml` | Sigma | clientless SSL VPN sessions through `DefaultADMINGroup` or `DefaultL2LGroup` (Cisco's CVE-2023-20269 indicator) |
| `asa_vpn_authentication_rejections.yml` | Sigma | the rejection messages Cisco lists for spraying and the CVE-2024-20481 flood; feed to a rate threshold |

## Notes

The implants themselves leave no reliable log signature: LINE DANCER disabled
syslog, and the 2025 activity suppressed IDs 302013, 302014, 609002 and 710005
in memory. Absence is the signal, which Sigma cannot express - see the hunt for
missing connection syslog. On-box detection is state-based: the memory-region
check (LINE DANCER only; NCSC reports LINE VIPER no longer splits lina), the
FXOS `lina_cs` process, `firmware_update.log` on disk0, the checkheaps counter,
and a core dump scanned with CISA's RayDetect. Order matters: memory state is
collected before anything that could reload the device, and a Firepower device
is not power-cycled before `lina_cs` is checked.
