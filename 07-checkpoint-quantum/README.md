# 07-checkpoint-quantum/ - Check Point Quantum (Gaia)

Platform: `EDGE-0007` (see `artifacts/catalog/`).  
Detection packs: `EDGE-PACK-0009` (see `artifacts/packs/`).

## Rules

| File | Format | Detects |
|---|---|---|
| `checkpoint_cve_2024_24919_mycrl.yml` | Sigma | requests to the CVE-2024-24919 endpoint |

## Notes

The file read leaves no on-box trace beyond the request. Correlate with local-account and LDAP-account VPN logins in the hours that follow.
