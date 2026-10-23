# Changelog

## 0.7.0 - 2026-10-23

### Source verification, round 3
Every cited URL (155) and quote (111) and roughly 870 unquoted claims were
re-read against the primary source, with Firecrawl for pages earlier passes could
not render. 196 issues found and corrected (23 high-severity); each correction is
in `docs/VERIFICATION.md` with the verbatim passage it rests on. Highlights:
- Three earlier corrections were themselves wrong and are reversed: lina region
  count (NCSC: the count is not an indicator; the split text section is), the
  SonicWall fixed firmware (10.2.2.2-92sv, not 10.2.1.15-81sv), and UNC6148's
  confidence wording.
- Detections fixed: the NetScaler pitboss pattern now matches Rapid7's published
  form too; the FortiOS sslvpnd crash is a coded check that pairs crash-log rows
  instead of a one-line regex that could never fire; the FortiOS symlink check no
  longer flags the stock `custom -> /data2/custom_lang` link; SonicWall
  `ld.so.preload` fires only with more than 2 bytes (GTIG), via YARA; Check Point
  CVE-2026-93616 username indicator is an attempt (possible), per Check Point.
- New detections from primary sources, among them CISA's on-box LINE VIPER check
  (opt-in break-glass), the published OVERSTEP hashes, COATHANGER CLI checks from
  the MIVD/AIVD advisory, CVE-2022-42475 file indicators, IOS XE web-login and
  dirty r-xp checks, and Mandiant's TINYSHELL hunting rules.
- Attribution: UPSTYLE was attempted, not installed (Volexity, Unit 42); UTA0178
  is no longer an alias of UNC5221 (neither reporter equates them); UTA0218 adds
  Volexity's "moderate confidence" China-based assessment; hunts tagged to an
  actor cite a source that names it.
- Hardening: the F5 httpd control now follows F5's actual CVE-2022-1388 mitigation;
  FortiOS fixed releases updated for the CVE-2025-68686 bypass.

## 0.6.1 - 2026-10-23

### Response
- Each playbook is now one top-to-bottom timeline in the fixed order (preserve,
  contain, rotate, eradicate, recover, verify) with a phase bar to jump between
  phases.
- Verdict filter: pick the analyzer's verdict and only the steps it calls for
  stay open; the rest collapse to a greyed line naming the verdicts they need.
  The choice is in the URL (`#response/cisco-asa?verdict=SUSPICIOUS`). The
  validator keeps every `when:` a list of real verdicts.
- Checklist: tick steps as you go (kept in your browser, per platform), with a
  progress bar, Copy as checklist (Markdown for case notes), Print, and Clear.
- Links from each playbook to its collection plan, detections, hunts, threat
  intel, hardening and platform entry; commands render as code; a platform menu
  replaces the pill row on phones; credential rows stack on narrow screens.

### Threat intel
- Cards show indicator and pack counts; a "Published indicators" filter.
- The record panel opens with a jump bar (Indicators, Hunts, Response) and adds
  the hunts tied to the actor and the response playbooks for its platforms.
- Chart bars no longer cut their labels short; charts start collapsed on phones.

### Site
- Light theme by default, whatever the operating system prefers; dark only when
  the viewer picks it.
- Byline and footer credit Raymond DePalma and DePalma Research LLC, with LinkedIn
  links; README, NOTICE and pyproject carry the same.

## 0.6.0 - 2026-10-23

### Detections
- Rules and detections merged: every Sigma rule is attached to the pack
  detection it expresses (`sigma:`), or tagged `edge-dfir.standalone`; the
  validator fails on an unlinked rule. The Rules tab became a filter of
  Detections (`#detections?runs=siem`), and old `#rules` links still land.
- 14 new Sigma rules (25 in all) and 11 new packs (`EDGE-PACK-0018` to `-0028`) for CISA KEV
  CVEs on the ten platforms that had none, wherever a primary source publishes
  an indicator: ASA ArcaneDoor 2025-2026 (FXOS `lina_cs`, `firmware_update.log`,
  stalled checkheaps), ASA remote-access VPN abuse, Junos J-Web, IOS XE Zero
  Disco, SMA 100 2025, FortiOS jsconsole bypass and CVE-2022-41328, PAN-OS
  CVE-2026-0300/0257, Ivanti CVE-2026-104935 and NetScaler CVE-2025-6543 and the
  2026 log-poisoning chain. The KEV CVEs with no published indicator are listed
  in `docs/VERIFICATION.md`.
- New read-only collection steps: ASA `show kernel process | include lina_cs`
  and a second checkheaps reading, Junos J-Web jail listing, and five NetScaler
  reads (httpd.conf, rc.netscaler, LogonPoint custom, /flash/nsconfig, /bin/sh).

### Hunts
- New `artifacts/hunts/`: 25 off-box hunts (NetFlow, SIEM, AAA accounting,
  identity, proxies) from CISA/FBI, Cisco, Talos, Mandiant/GTIG, Check Point,
  Fortinet, Volexity, Unit 42 and ASD guidance. Each gives the hypothesis, data,
  method, normal versus suspicious and the quote it rests on. A Hunts library on
  the site.

### Artifacts
- Every catalog artifact now says what it gives you and what normal and
  suspicious look like, and whether the suspicious criterion comes from the
  vendor, a researcher, a government or this toolkit's inference.

### Threat intel
- 358 indicators from 11 publications, parsed from the publishers' own files,
  each with the publisher's role (actor-controlled, compromised third party,
  VPN exit, shared infrastructure, unstated) and a staleness note. Shown
  defanged in each actor and implant, exported as CSV or STIX 2.1.
- A reporting timeline, reporter and motivation splits, an actor-by-platform
  matrix and the share of published addresses that are actually actor-owned.
- New implant record for the FXOS `lina_cs` persistence (`EDGE-IMP-0013`).

## 0.5.0 - 2026-10-22

### Prevention and hardening
- New `artifacts/hardening/`: 83 controls - a 12-control baseline for every
  edge device (CISA BOD 23-02, the 2025 joint edge-device guidance, NCSC-UK's
  forensic-monitoring specification, NSA) and vendor-specific controls for all
  ten platforms, led by keeping management interfaces off the internet.
- Every control states what to do, why (with the CVEs or campaigns the source
  says it blunts, linked into the detections and intel), how in the vendor's
  own syntax - or says the vendor gives none - and its sources with verbatim
  quotes. The validator requires a source on every control and flags low
  confidence.
- Site: a Hardening library (filters for applies-to, category, priority,
  confidence), a sixth "Harden" step on Start, hardening links from platforms
  and response playbooks, and a "Prevent the next one" section in the guide.

## 0.4.2 - 2026-10-22

### Site
- Tabs put the knowledge first - Start, Artifacts, Platforms, Detections,
  Threat intel, Response - with Collection plans, Rules, Coverage and the Guide
  after the divider. Start still links each platform's plan directly.
- Start gains three visuals, each computed from the repository: a volatility
  bar on every platform tile (the share of its artifacts that are live and gone
  at reboot), a five-step triage flow linking to the right tab or guide
  section, and the order-of-volatility band the collector enforces.
- Tabs fit at tablet widths (counts hide below 1120px, the bar fades when it
  scrolls).

## 0.4.1 - 2026-10-22

### Site
- New **Start** landing page for first-time visitors: a platform picker that
  links each device to its collection plan, artifacts, detections and response;
  the first-hour rules; the collect-analyze-respond workflow; and a legend for
  every badge.
- Tabs reordered to follow an investigation (Start, Platforms, Collection
  plans, Artifacts, Detections, Threat intel, Response), with Rules, Coverage
  and the Guide after a divider. The guide is a normal tab, not a floating
  button.
- Coverage leads with computed gaps (no profile, implants with no detection,
  platforms without memory evidence or a confirmed-tier detection, steps that
  are not vendor-documented), then a platform-by-evidence-class detection grid,
  a per-profile verification bar and an artifact grid on one colour ramp. The
  per-pack grid is folded. Count grids no longer reuse the tier colours.
- Investigation guide: contents in the side rail with the current section
  highlighted, linkable sections (`#guide/analysis`), notes for all ten
  platforms (Check Point, Juniper, IOS XE, F5 and SonicWall were missing) with
  links into the libraries, a verdict decision table, a warning callout, and
  verdict and tier names shown as the same badges the libraries use.
- Typography: one sans family and five sizes (was 21-23 font, size and weight
  combinations per view across 11 sizes). Monospace only for literal strings -
  commands, paths, file names, patterns, rules - and code inside prose is
  wrapped inline instead of setting whole sentences in monospace. Artifact
  descriptions are larger and higher-contrast. Font stacks prefer Segoe UI and
  Cascadia Mono on Windows.
- `--check` fails if a platform has no note in the guide or a guide link points
  at a missing section.

## 0.4.0 - 2026-10-22

### Site
- Rebuilt around five filterable libraries - artifacts (new, 78 rows across
  every platform), platforms, detections (68, no longer grouped under packs),
  rules and threat intel - each with a facet rail and live counts, search with
  "N of M shown", a detail drawer with a deep link per record and keyboard
  stepping, and CSV/JSON export of the picked or shown records.
- Filter state is in the URL, so a filtered view can be shared. Old
  `#packs/<id>` links land on the detections library filtered to that pack.
- Coverage matrices are clickable, and a new artifacts-by-platform-and-class
  matrix shows where collection is thin.
- Threat intel opens with clickable summary tiles (coverage gaps, implants that
  survive a reboot); response playbooks are one platform at a time with the
  do-not list first.
- Phone layout: filters fold into one button, rows become cards, the drawer goes
  full screen.
- `tests/test_site.py` drives the page in Chromium (skipped without Playwright).

### Project
- Verification no longer assumes a hardware lab: vendor virtual editions,
  contributed sanitized replay captures and vendor-documented output samples
  (ROADMAP, CONTRIBUTING).

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
