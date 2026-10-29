# Project context

Read this before working in this repository. It exists so a session starts
with the rules already loaded instead of rediscovering them.

## What this is

A triage toolkit for compromised edge devices. Three layers:

- `collectors/profiles/*.yaml` - what to run on each platform, in order of
  volatility, with a read-only guard.
- `edgetriage/` - the engine: collect over SSH (or replay), ingest exports,
  analyze against packs, timeline, LLM brief.
- `artifacts/` - the platform catalog (`EDGE-NNNN`) and detection packs
  (`EDGE-PACK-NNNN`) the analyzer runs, plus their schemas and the validator.

The numbered `0N-*` directories hold Sigma and YARA rules per platform. Packs
reference the YARA files there.

## Commands

Run from the repository root.

```bash
python artifacts/scripts/validate.py          # the gate; never commit while it fails
python -m pytest -q tests/                    # suite against synthetic fixtures
python tests/make_fixtures.py /tmp/fx         # regenerate fixtures to poke at by hand
python -m edgetriage plan --profile <name> [--allow-bundle] [--break-glass]
python -m edgetriage collect --profile <name> --case-id X --replay /tmp/fx/<fixture>
python -m edgetriage analyze cases/X [--baseline b.json] [--window-start ISO] [--forwarded siem.jsonl] [--activity signins.jsonl]
python artifacts/scripts/build_site.py --check   # site data contract, writes nothing
python artifacts/scripts/build_site.py           # docs/site/index.html (CI does this; never commit it)
python artifacts/scripts/mappings.py [--check]   # MAPPINGS.md is generated
python artifacts/scripts/advisory_watch.py [--kev f.json] [--upstream] [--draft]   # KEV vs packs; reports, never edits
python artifacts/scripts/check_quotes.py [--only file.yml] [--out r.md]   # every quote against its live page; reports, never edits
sigma convert -t lucene --without-pipeline 01-panos-globalprotect/*.yml   # syntax gate only
```

## Rules that are not negotiable

**Read-only by default.** An impact-free profile step must pass the profile's
allow-list and miss its deny-list, and the engine re-checks after `--var`
substitution. Anything that writes to the device declares `impact:
vendor-bundle`; anything that can crash, reload, reboot or image it declares
`impact: break-glass`. Allow rules are matched with `re.fullmatch`, so write
them as complete grammars, not prefixes; `shell` on NetScaler hands the line to
sh, which strips quotes and backslashes, so its rules must not admit free text.
Control characters are refused in every command and `--var` value. Do not
loosen an allow-list to make a step pass - change the step. Every guard bypass
found so far has a regression test in `test_guard_refuses_smuggled_commands`. FortiOS paging is answered by the transport, never with
`config system console`, because that changes configuration.

**Order of volatility is enforced by `TIER_ORDER`.** The ASA memory-region
check is V1 for a reason: LINE DANCER hooked the core-dump routine so that a
dump request reloaded the device. Never move a step that can reload the device
ahead of memory-state steps.

**Not evaluated is not passed.** Every detection must be able to say it did not
have the evidence it needs. A coded check returns `(False, [])` in that case.
The hash-baseline check refuses to run without a baseline for exactly this
reason.

**Never call a device clean.** The lowest verdict is `NO-INDICATORS-FOUND`,
and the report always carries the standing gap about on-box tampering.

**Confidence reflects provenance.** `high` = vendor-documented or verified on a
device; `medium` = multiple independent sources; `low` = single-source or
inferred and **must** carry `unverified: true`. A government cyber authority's
own publication (CISA, NSA, FBI, NCSC-UK, ASD's ACSC, CCCS, NCSC-NL, AIVD/MIVD,
and joint advisories they sign) is documentation of what that authority
recommends or reports: a hardening control or playbook step it states verbatim
is `high` on that one source, provided the `how` adds nothing the sources do
not say. It documents a vendor's CLI syntax, log format or file path only where
it prints them. This applies to profile steps
too: a CLI command nobody has run on a real device is not `high`. The FortiOS
SSL-VPN language directory is supplied by the operator because its path is not
confirmed; do not hard-code a guess.

**Omit rather than guess.** A missing step or detection is honest. A guessed
command or path becomes somebody's failed collection during an incident.

**Placeholders need realistic examples.** The load-time guard renders `{var}`
with `/placeholder` unless the step declares `var_examples`. Declare one
whenever a value has a shape a path does not (an IOS XE `bootflash:` file).

**Bash-shell profiles get the strictest guards.** F5 and Check Point run in
bash, so their allow-lists are fixed command grammars, pipes are refused except
F5's trailing `| cat`, and mutating tmsh verbs are denied anywhere in the line,
not just first (`tmsh list apm session delete all` once passed).

**A parser that sees nothing must say so.** Every coded check returns
not-evaluated when it parsed zero rows. The ASA and IOS XE checks have tests
that feed them an error message.

**Ids are permanent.** `EDGE-0004` and `EDGE-PACK-0006` never change meaning.
New entries take the next free id. Pack files are named `<id>-<slug>.yml` and
the validator enforces it.

**Every Sigma rule is attached to the detection it expresses.** A pack
detection lists its SIEM rules in `sigma:`; the validator fails on a link to a
missing file and on a rule nothing links, unless the rule is tagged
`edge-dfir.standalone`. Regex rules match `Message`, the raw log line.

**Detections are Sigma and YARA only.** No SPL, KQL, XQL, ES|QL or any vendor
dialect. Converting inside CI to prove a rule parses is fine; committing the
output is not. Do not name the maintainer's former employers anywhere in
the repository - the disclaimer says "any former employer" deliberately. The
publisher is the maintainer's own firm, DePalma Research LLC; credit it and
Raymond DePalma only in the README, NOTICE, pyproject and the site's byline and
footer (`AUTHOR` and `FIRM` in the generator). Citing a vendor's or a research
team's publication as a source is not naming an employer.

**Defensive content only.** Fixtures carry the minimum content to exercise a
detection. No working exploit, implant or exploitation steps.

**Synthetic data only.** Fixtures use documentation address ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and placeholder names.

**Artifacts say what normal looks like.** A catalog artifact's `normal`,
`suspicious` and `basis` go together, and `basis: toolkit` marks this project's
own inference. Copy the contrast from the source; where none is published, say
so with `toolkit` rather than dressing an inference up as a vendor's.

**Hunts are off-box and quoted.** `artifacts/hunts/` holds hypotheses for data
the device's owner keeps elsewhere (NetFlow, SIEM, AAA accounting, identity,
proxies). Each quotes its source; a quote that came through a summarising fetch
is `read: summariser`, and a hunt resting only on such quotes is `unverified`.
The analyzer never runs hunts, with one coded exception: given `--forwarded`,
`edgetriage/offbox.py` lines the SIEM's copy of the device's syslog up with
the logs on the box (EDGE-HUNT-0027) and lists gaps in the forwarded stream
(EDGE-HUNT-0009).
- It lines the copies up by message, never by clock, and only between the
  first and last line they share, so rotation and a clock in another zone
  are not deletion.
- It lines them up in order (a patience diff anchored on messages that occur
  once in each copy). A repeated message pairs only within its own stretch,
  and such a `loose` pair neither ends a run nor counts toward one. Never go
  back to counting messages as a bag: a deleted logout then "finds" a copy
  hundreds of lines away and splits the run.
- One-sided runs of `RUN_MIN` or more lines are `possible`, in their own
  evidence class (`offbox-logs`).
- It says not-evaluated when the copies share fewer than `MIN_SHARED` lines
  or differ by level (`MIN_SHARE`).
- Stream gaps are listed, never scored on their own. Given `--activity` (what
  the device did, from a source it does not control), a gap with `ACTIVE_MIN`
  or more events inside it, `EDGE_MARGIN_S` in from each end, is `possible`
  (`offbox-silent-while-active`, EDGE-HUNT-0009). A gap the export does not
  span is not tested; a gap with no year cannot be placed. NetFlow is one
  activity source, never a requirement - most owners have sign-in or
  next-firewall logs instead.

No vendor query dialect in hunts either.

**Exploited CVEs are triaged, not ignored.** `artifacts/watch/kev-watch.yml`
holds the KEV-to-platform mapping and a ledger: every KEV entry on a watched
platform since `since` is in a pack's `cves` or has a decision (`iocs`,
`no-indicators`, `out-of-scope`, `deferred`) with a date and basis. The weekly
`advisory-watch` workflow opens an issue for anything else and for changed
upstream indicator files; it never commits. `deferred` means not yet read -
never use it for a decision you made. A CVE that gains a pack leaves the ledger.
`artifacts/watch/kev-records.yml` holds CISA's own KEV fields, verbatim, for
every one of those entries and every KEV entry a record names in a structured
field. That means date added, due date, ransomware use, `forensicTriage` (BOD
26-04), CWEs, required action and notes. It is written only by
`advisory_watch.py --records > artifacts/watch/kev-records.yml`, never typed or
edited. The watch reports drift, and the validator fails when a triaged CVE has
no record under its platform. `platform` there is the watch rule KEV's own
product strings match, or null.

**A CVE record is a join, not a claim.** The CVEs library has one record per CVE
in `kev-records.yml` or in a structured field (a pack's `cves`, an artifact's
`seen_in`, a hunt's `cves`, a control's `blunts`, an indicator set's or
implant's `cves`). It adds no prose of its own:
- KEV's text is shown as CISA's, with the catalog version.
- What exploitation leaves behind comes from the artifact records that cite the
  CVE.
- KEV's platform wins; linked records decide only when KEV's product maps to no
  watched platform.
- The BOD 26-04 step names and target timelines are quoted from CISA's
  implementation guidance (`BOD_STEPS`). The links beside them are labelled as
  the toolkit's suggestion.
- Never say a playbook contains something it does not. The patching step quotes
  CISA instead.

CVE mentions anywhere on the site link to `#cves/<id>`.

`artifacts/watch/cve-records.yml` holds each shown CVE's CVE.org fields: the
record's publication date, the assigner, the CNA's weakness names and CISA's
SSVC decision points. It is written only by `advisory_watch.py --cve-records`.
KEV's `forensicTriage` is a BOD 26-04 deadline category: every entry added
before 2026-06-10 (`BOD_ISSUED`) reads No. So never word No as "not required";
the site reads it as "added before BOD 26-04" or "not flagged". No feed dates
when exploitation began. Show the dates the sources give, each labelled with
what it is. An actor's first-seen date dates the actor, not the CVE.

**Exploitation dates are quoted, never inferred.** `artifacts/intel/exploitation.yml`
holds, per CVE, what primary sources say about when it was exploited:
- Primary sources are the vendor, the team that saw the exploitation and a
  government cyber authority. News, NVD and aggregators are leads only, and a
  KEV-addition alert is not a report.
- `stated_on` is when the quoted text was published. For an updated page, use
  the revision that added it, and say how in `stated_on_basis`. Make it `null`
  when the page does not show it.
- `earliest` is only as precise as the source (year, month or day). Its words
  (`earliest_words`) must sit inside the quote, which the validator checks.
- Never take `earliest` from IOC or actor first-seen dates, PoC or patch
  dates, a count of IPs, a window of investigations, or "additional"
  exploitation. Never move it between chained CVEs. "Attempted" stays
  `activity: attempted`.
- A year missing from the quote, a CVE named only in a heading, a translation
  or a hedge elsewhere on the page goes in `note`.
- `searched` lists what was read, including what was rejected and why. An
  empty `reports` is not a claim the CVE was never exploited.
- "Exploited before the CVE record was published" is computed only from
  `earliest` and CVE.org's date, comparing the end of the source's period
  (`period_end`).
- Check every quote against its page before committing: `check_quotes.py`
  where the shell can fetch it, and a rendered fetch for what it lists as
  needing one. The monthly `quote-check` workflow re-runs it on every quoted
  source and opens an issue when a quote is gone; it never commits.
- The weekly advisory-watch report lists every shown CVE with no record here.
  A new KEV entry is not done until it has one, even an empty one.

## Threat intel and response rules

**Indicators are parsed, never retyped.** `artifacts/intel/iocs/` sets come from
the publisher's own file or table, parsed in code from a copy in its own
directory (run the parser with `python -I`). Each value keeps the publisher's
role - most published addresses are compromised third parties, VPN exits or
shared hosting, not the actor - and every set states when it was valid. Store
values refanged; the site defangs them. Never infer a role the publisher did
not state; use `unknown`.

**Attribution is reported, never computed.** An actor profile carries two
confidences: `link_confidence` is ours and measures provenance (one reporting
party is `medium`, however authoritative); `stated_confidence` is the
attributing party's own words, verbatim. Never upgrade a reporter's hedge, and
never merge two clusters unless the reporters themselves equate them.

**Motivation comes from the reporter.** UTA0576 was first filed as espionage;
Volexity's own assessment was "low confidence" criminal. Read the source.

**Attribute the action to the right actor.** The 2025 Ivanti syslog block was
the exploit's script running iptables (GTIG: "the exploit and script"), not
SPAWN malware; SPAWNSLOTH's log suppression is a separate claim. Malware
behaviour, exploit-script behaviour and hands-on-keyboard behaviour are
different claims - name the one the reporter names.

**Re-read, do not remember.** Round 3 of `docs/VERIFICATION.md` found three
earlier "corrections" that were themselves wrong. Before changing a claim, read
the passage on the live primary page (Firecrawl renders the vendor knowledge
bases); never correct from memory or from a summary.

**An implant with no detection states its gap.** `detections: []` without a
`gap` fails the validator, so a coverage hole is always visible.

**Response playbooks are guidance, not automation.** The toolkit never contains
or remediates. Order is fixed: preserve, contain, rotate, eradicate, recover,
verify. Every playbook has a `do_not` list - most evidence is destroyed by a
well-meant action taken too early.

**Hardening controls cite their source.** Every control in
`artifacts/hardening/` has at least one vendor or government source and states
the vendor's own syntax or says there is none - never a guessed command. A CVE
or campaign goes in `blunts` only when the source ties it to the control.

**Prefer primary sources.** A press summary is a placeholder until replaced by
the vendor, government or researcher's own publication. Record every
correction in `docs/VERIFICATION.md`.

## Where the sharp edges are

- `SSHTransport` has only been exercised against a scripted fake channel
  (`test_ssh_transport_handles_pager_echo_and_ansi`). Prompt and pager regexes
  in each profile are untested against real devices. The maintainer has no
  hardware lab: verify on vendor virtual editions or from contributed, sanitized
  replay captures, and record any correction in `docs/VERIFICATION.md`.
- Several profile commands are `medium` or `low` confidence for the same reason.
  `edge-triage plan` prints `[unverified]` beside the low ones.
- The ASA region parser was once written against an invented format and
  silently passed compromised devices. It now matches the published
  `/proc/maps` row; `test_asa_region_parser_matches_published_format` pins it.
  Never change a parser without a fixture copied from published output.
- The ns.log memory-leak check depends on raw bytes surviving. Do not "fix"
  `iter_lines` to decode text.
- `iter_lines` decompresses gzip by magic bytes. Rotated logs were once read as
  compressed bytes and silently passed; `test_rotated_gzip_logs_are_read` pins it.
- Vendor diagnostic bundles must not phone home. `cpinfo` runs with `-D -d`;
  check any new bundle command for a default upload.
- Junos `file list` appends type markers (`*`, `|`, `/`). Listing patterns end in
  `[*/|@=]?\s*$`; an anchor on the bare name once matched nothing.
- `safe_extract` refuses links but records them. The FortiOS symlink check reads
  those refusals; keep the `"<name>: link -> <target>"` format stable.

## Site generation

`artifacts/scripts/build_site.py` emits one self-contained vanilla-JS HTML file.
Artifacts, platforms, CVEs, detections, hunts, intel and hardening are client-side libraries
built from one JSON block (facet rail, search, drawer, export); filter state is
in the URL (`#artifacts?platform=EDGE-0003&volatility=live`). `FACET_KEYS` in the
generator must match the facets the JS defines - the page logs an error if they
differ, and `--check` validates every static `#lib?key=` link against it. Rule
directories map to platforms through `RULE_DIR_PLATFORM`; a new directory
without an entry fails `--check`. `tests/test_site.py` drives the page in
Chromium and skips when Playwright is not installed. No framework, no CDN, no
build step; never hand-edited, never committed. The Pages workflow builds it at deploy time. Every embedded data blob goes through
`js_data()`, which escapes `</` so a rule body cannot close the script element.
Tab order puts knowledge first (Start, Artifacts, Platforms, CVEs, Detections, Hunts,
Threat intel, Response, Hardening) and toolkit operation plus reference after
the divider (Collection plans, Coverage, Guide); Start is the default route.
Rules live inside Detections (`#rules` redirects to `#detections?runs=siem`).
Indicator values are defanged on screen and exported refanged. Type:
one sans family, sizes only from the `--fs-*` tokens, monospace only for
literal strings (commands, paths, file names, patterns); prose goes through
`rich()` in the JS, which wraps the literals inline. Every platform needs a
note in the guide's Platform notes section, keyed in `NOTE_PLATFORM`, and a short
name in `PLATFORM_ABBR` (pickers, facets, matrices; `--check` fails without one).
Start's verdict ladder (`LADDER`) is run through `analyze.verdict()` by
`tests/test_site_contract.py`: change the copy and the code together. Coverage
reads the KEV ledger from `artifacts/watch/kev-watch.yml`; `#coverage/<anchor>`
scrolls to `id="cov-<anchor>"` and `--check` validates it. `--faint` is for lines
and decoration only, never text. Search everything (`/`, Ctrl+K) indexes the
libraries, `D.steps`, the guide and the KEV ledger, and refangs the query before
matching. A record's "Last changed" date comes from `git_dates()` (one `git log`
walk over `artifacts/`). Pages checks out with `fetch-depth: 0`. A build without
history shows no date rather than a guessed one. List mechanical sweeps (a
reformat, a field rename) in `.git-blame-ignore-revs` so they do not reset
dates. Freshness is "changed before the platform's newest advisory" (KEV
`dateAdded` or an indicator set's `published`), never calendar age. It is
worded "may need a re-read", not "out of date", and `ALL` files are not
compared.
Page changes go in the generator. `--check` fails on duplicate or non-URL-safe
element ids, dangling `#tab/anchor` links and any external script or stylesheet.

## What is next

See `docs/ROADMAP.md`.
