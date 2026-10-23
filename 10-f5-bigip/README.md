# 10-f5-bigip/ - F5 BIG-IP (TMOS / APM)

Platform: `EDGE-0010` (see `artifacts/catalog/`).  
Detection packs: `EDGE-PACK-0015`, `EDGE-PACK-0016`, `EDGE-PACK-0017` (see `artifacts/packs/`).

## Rules

| File | Format | Detects |
|---|---|---|
| `f5_rest_util_bash_hubble.yml` | Sigma | c05d5254 REST call to util/bash (CVE-2025-53521 follow-on) |
| `f5_apm_oauth_userinfo_invalid_token.yml` | Sigma | CVE-2026-94127 UserInfo invalid-token failures |
| `f5_selinux_setenforce_zero.yml` | Sigma | SELinux set permissive (c05d5254) |
| `f5_tmsh_run_util_bash.yml` | Sigma | `run util bash -c` in the tmsh audit log |
| `f5_rest_util_bash_post.yml` | Sigma | iControl REST POSTs to /mgmt/tm/util/bash (CVE-2022-1388, CVE-2023-46747 follow-on) |
| `f5_cve_2023_46748_tomcat_shell.yml` | Sigma | a shell banner in catalina.out (CVE-2023-46748) |
| `f5_tmm_sigabrt.yml` | Sigma | TMM SIGABRT, the last step of the CVE-2026-94127 sequence |

## Notes

Do not trust sys-icheck on a suspect device: c05d5254 tampered with it. F5's
System Scanner, run from known-good media, is the integrity check. A UCS backup
taken after compromise can carry the malware back; restore only from one taken
before.
