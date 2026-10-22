# 07-checkpoint-quantum/ - Check Point Gaia (Gateway and Management)

Platform: `EDGE-0007` (see `artifacts/catalog/`).  
Detection packs: `EDGE-PACK-0009`, `EDGE-PACK-0013`, `EDGE-PACK-0014` (see `artifacts/packs/`).

## Rules

| File | Format | Detects |
|---|---|---|
| `checkpoint_cve_2024_24919_mycrl.yml` | Sigma | requests to the CVE-2024-24919 endpoint |
| `checkpoint_cve_2026_85102_cert_subject.yml` | Sigma | Mobile Access logins with certificate subjects seen in CVE-2026-85102 exploitation |
| `checkpoint_cve_2026_93616_cpm_username.yml` | Sigma | pre-filter for CPM login records; the over-1000-character test is in EDGE-PACK-0013 |

## Notes

Most 2026 hunting runs in SmartConsole log queries, which the `checkpoint-gaia`
profile records as a manual export step. On a management server, patching
CVE-2026-93616 does not reveal earlier compromise, and LivePatch does not fix it.
