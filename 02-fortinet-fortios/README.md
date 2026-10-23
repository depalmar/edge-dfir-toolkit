# 02-fortinet-fortios/ - FortiOS (FortiGate / FortiProxy)

Platform: `EDGE-0002` (see `artifacts/catalog/`).  
Detection packs: `EDGE-PACK-0003`, `EDGE-PACK-0023`, `EDGE-PACK-0024` (see `artifacts/packs/`).

## Rules

| File | Format | Detects |
|---|---|---|
| `fortios_sslvpnd_crash_signal11.yml` | Sigma | sslvpnd crashes the vendor published as an SSL-VPN exploitation indicator |
| `fortios_cve_2024_55591_jsconsole_admin_login.yml` | Sigma | administrator login from jsconsole (CVE-2024-55591) |
| `fortios_cve_2024_55591_jsconsole_admin_add.yml` | Sigma | administrator created from jsconsole |
| `fortios_cve_2022_41328_hs20_icon_traversal.yml` | Sigma | hs20-icon upload with a traversal path - logged only when it fails (Mandiant) |

## Notes

Fortinet says the symlink persistence disclosed in 2025 "took place in the user filesystem and avoided detection"; no published log event records it. It is found by listing the filesystem (`fortios_symlink_to_root` check) and by comparing `diagnose sys filesystem hash` with a baseline of the same build (`hash_baseline` check).

The crash log (`diagnose debug crashlog read`) prints `application sslvpnd` and `*** signal 11 (Segmentation fault) received ***` on separate rows, so the crash-log form is scored by the `fortios_crashlog_sslvpnd_segv` check; the Sigma rule covers the event-log form.
