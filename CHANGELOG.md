# Changelog

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
