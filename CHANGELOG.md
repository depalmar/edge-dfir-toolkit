# Changelog

## 0.3.0 - 2026-10-22

### Platforms
- **Juniper Junos** (`EDGE-0008`, profile `junos`, pack 0010): UNC3886 TINYSHELL
  backdoors - masquerading process names, staging files, login-record backups,
  published YARA strings. CLI-only collection; JMRT quick-scan is break-glass
  because it deletes evidence by default.
- **Cisco IOS XE** (`EDGE-0009`, profile `cisco-iosxe`, packs 0011-0012): the
  2023 web UI implant (syslog strings, Talos-named accounts, Cisco's implant
  check) and AA25-239A tradecraft (captures on bootflash, shell trace logs,
  encoded web services requests). New coded check for executable and writable
  IOSd memory with dirty pages, from Cisco's forensic guide.
- **F5 BIG-IP** (`EDGE-0010`, profile `f5-bigip`, packs 0015-0017): c05d5254
  after CVE-2025-53521, CVE-2026-94127 (APM OAuth), and the 2022-2023
  control-plane flaws. New coded check for bursts of invalid-token UserInfo
  failures, using F5's rule of 10 or more in one log (especially from one address).
- **Check Point** (`EDGE-0007`): now has a profile, and packs 0013-0014 cover
  CVE-2026-93616, CVE-2026-16232, CVE-2026-85102 and CVE-2026-50751 using
  Check Point's published indicators.

### Intel and response
- Actors: UNC3886 now linked to Juniper; new AA25-239A profile that keeps the
  agencies' refusal to adopt a vendor name and records the Talos disagreement.
- Implants: UNC3886 Junos TINYSHELL, IOS XE web UI implant, F5 c05d5254.
- Response playbooks for Juniper, IOS XE and F5; Check Point rewritten for the
  2026 flaws with per-CVE fixes, interim mitigations and the sk182336 rotation list.

### Engine
- Coded checks report "not evaluated" when they parse nothing, so an error
  message can never pass as a clean device (applied to the ASA check as well).
- Profile steps can declare `var_examples` so the load-time guard probes with
  realistic values (an IOS XE `bootflash:` path rather than `/placeholder`).
- Rule directories may now be numbered past 09.
- Rotated `.gz` logs are now decompressed before matching. Previously every
  rotated log was searched as compressed bytes and silently came back no-hit.

### Verification round 2 (same day)
- F5 audit detection matched `cmd=` instead of the real `cmd_data=` field.
- Check Point `cpinfo` now runs with `-D -d` so it never uploads to the vendor
  or self-updates; the vpnd detection uses the real blocked-traversal message.
- Junos: listing patterns tolerate `file list` type markers (they matched
  nothing before); JMRT integrity-check is opt-in because it writes a test file;
  process-name detection lowered to possible; new hijacked-cat, payload-file and
  syslog.conf0 detections; /mfs/var/etc listing.
- IOS XE: image hashing follows packages.conf to each .pkg; the Catalyst switch
  form of the IOSd memory map is collected and read; the Sigma web services rule
  accepts mixed encodings.
- Every correction is in `docs/VERIFICATION.md`.

## 0.2.0 - 2026-10-22

### Verification
- Every claim checked against primary sources in three independent passes. Full
  audit trail with the basis for each change in `docs/VERIFICATION.md`.
- **Fixed a silent false negative:** the ASA `show memory region` parser expected
  a layout no device prints, so it reported "no hit" on a compromised ASA. It
  now parses the real `/proc/maps` format and is pinned by a regression test.
- Corrected attribution (UTA0576 is assessed criminal, not espionage), the
  Ivanti syslog-blocking attribution (operator commands, not SPAWN malware),
  and fifteen further facts. Secondary sources replaced with primaries.

### Artifacts
- Every platform entry now carries per-artifact rows: locator, what it proves,
  evidence class, volatility and retention, forensic value, evidence type, the
  step that collects it, and confidence.

### Threat intelligence and attribution
- `artifacts/intel/actors/` - 6 actor profiles. Attribution is reported, never
  computed: each carries our link confidence and the reporter's own words.
- `artifacts/intel/implants/` - 9 implant entries with what survives reboot,
  upgrade and factory reset. An implant with no detection must state its gap.

### Containment and recovery
- `artifacts/response/` - 7 playbooks ordered preserve, contain, rotate
  credentials, eradicate, recover, verify, each with a "do not" list.

### Site
- New Threat intel and Response tabs; artifact tables on every platform card.
- Validator cross-checks actors, implants, response playbooks and every
  `collected_by` reference.

## 0.1.0 - 2026-10-22

First cut.

### Engine (`edgetriage`)
- `plan`, `collect`, `ingest`, `analyze`, `timeline`, `brief` subcommands.
- Order-of-volatility tiers (V0-V3, P1-P7, B, X) enforced by the engine.
- Read-only guard enforced at profile load and again after `--var` substitution.
- Impact gating: vendor bundles behind `--allow-bundle`, break-glass behind
  `--break-glass` plus typed confirmation, always last.
- SSH transport for restricted CLIs (pager handling, echo/ANSI stripping,
  host-key pinning or known_hosts, no trust-on-first-use); replay transport.
- Chain-of-custody manifest with tool hash, profile hash, per-artifact SHA-256,
  preflight answers and a previous-manifest hash on every rewrite.
- Hostile-archive extraction: regular files only, refusals recorded.
- Analyzer with `hit` / `no-hit` / `not-evaluated`, cross-class corroboration
  scoring, evidence-gap reporting, Markdown report.

### Content
- Profiles: `panos`, `fortios`, `netscaler`, `cisco-asa`, `ivanti-ics`.
- Catalog: EDGE-0001 to EDGE-0007.
- Packs: EDGE-PACK-0001 to EDGE-PACK-0009 (28 detections).
- 7 Sigma rules, 2 YARA files (5 rules).

### Security hardening (independent review, same day)
- Allow rules are full-command grammars matched with `fullmatch`; the old
  prefix rules let a newline-separated second command through.
- Control characters refused in every command, `session_setup` line and `--var`
  value; `--var` values limited to path and host characters for every impact.
- NetScaler `shell find` restricted to a fixed option grammar (quote and
  backslash tricks admitted `-delete` and `-exec`); `show` limited to four commands.
- Transport tests only the last line for prompt and pager, and requires a quiet
  period after a prompt, so device output cannot end a capture or delete text.
- Fetch refuses non-plain paths from device listings, pseudo-filesystems,
  non-regular files and files over 512 MiB.
- Ingest validates labels; extraction refuses duplicate and clashing members and
  drive-qualified names, and records an aborted extraction instead of crashing.

### Not yet verified
- No profile has been run against a real device. See `docs/ROADMAP.md`.
