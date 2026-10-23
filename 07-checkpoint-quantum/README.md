# 07-checkpoint-quantum/ - Check Point Gaia (Gateway and Management)

Platform: `EDGE-0007` (see `artifacts/catalog/`).  
Detection packs: `EDGE-PACK-0009`, `EDGE-PACK-0013`, `EDGE-PACK-0014` (see `artifacts/packs/`).

## Rules

| File | Format | Detects |
|---|---|---|
| `checkpoint_cve_2024_24919_mycrl.yml` | Sigma | requests to the CVE-2024-24919 endpoint |
| `checkpoint_cve_2026_85102_cert_subject.yml` | Sigma | Mobile Access logins with certificate subjects seen in CVE-2026-85102 exploitation |
| `checkpoint_cve_2026_93616_cpm_username.yml` | Sigma | pre-filter for CPM login records; the over-1000-character test is in EDGE-PACK-0013 |
| `checkpoint_cve_2024_24919_vpnd_traversal_blocked.yml` | Sigma | the patched gateway blocking a CVE-2024-24919 traversal |
| `checkpoint_cve_2026_50751_ikev1_quick_mode.yml` | Sigma | Check Point's IKEv1 Quick Mode hunting query (pre-filter) |
| `checkpoint_cve_2026_16232_application_token.yml` | Sigma | Check Point's application-token hunting query (pre-filter) |
| `checkpoint_cve_2026_93616_cpm_indicators.yml` | Sigma | Check Point's CPM indicators 2a, 2b and 2c; regex on `Message` |

## Notes

Regex rules match `Message`, the full raw log line as the appliance sent it; map
it to your raw-message field in the Sigma pipeline. Keyword rules need no mapping.


Most 2026 hunting runs in SmartConsole log queries, which the `checkpoint-gaia`
profile records as a manual export step. On a management server, installing the
CVE-2026-93616 fix does not tell you whether the server was attacked before (the
toolkit's guidance; run the sk1000171 indicators), and LivePatch does not fix it.
