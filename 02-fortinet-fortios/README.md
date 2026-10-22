# 02-fortinet-fortios/ - FortiOS (FortiGate / FortiProxy)

Platform: `EDGE-0002` (see `artifacts/catalog/`).  
Detection packs: `EDGE-PACK-0003` (see `artifacts/packs/`).

## Rules

| File | Format | Detects |
|---|---|---|
| `fortios_sslvpnd_crash_signal11.yml` | Sigma | sslvpnd crashes the vendor published as an SSL-VPN exploitation indicator |

## Notes

The symlink persistence disclosed in 2025 produces no log event. It is found by listing the filesystem (`fortios_symlink_to_root` check) and by comparing `diagnose sys filesystem hash` with a baseline of the same build (`hash_baseline` check).
