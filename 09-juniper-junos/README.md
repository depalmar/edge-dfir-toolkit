# 09-juniper-junos/ - Juniper Junos OS / Junos OS Evolved

Platform: `EDGE-0008` (see `artifacts/catalog/`).  
Detection packs: `EDGE-PACK-0010`, `EDGE-PACK-0020` (see `artifacts/packs/`).

## Rules

| File | Format | Detects |
|---|---|---|
| `junos_unc3886_tinyshell.yar` | YARA | strings Mandiant published for the UNC3886 TINYSHELL variants |
| `junos_shell_started_from_cli.yml` | Sigma | `start shell` recorded in the CLI command log |

## Notes

UNC3886 deleted log lines containing "root" and redirected syslog to /dev/null,
so the off-box syslog copy is the record to trust. JMRT quick-scan deletes what
it finds by default; collect first.

The J-Web pack (`EDGE-PACK-0020`) rests on one researcher's reproduction and is
low confidence; Juniper's own advisory needs a support login.
