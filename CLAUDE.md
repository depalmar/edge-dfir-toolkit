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
python -m edgetriage analyze cases/X [--baseline b.json] [--window-start ISO]
python artifacts/scripts/build_site.py --check   # site data contract, writes nothing
python artifacts/scripts/build_site.py           # docs/site/index.html (CI does this; never commit it)
python artifacts/scripts/mappings.py [--check]   # MAPPINGS.md is generated
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
inferred and **must** carry `unverified: true`. This applies to profile steps
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

**Detections are Sigma and YARA only.** No SPL, KQL, XQL, ES|QL or any vendor
dialect. Converting inside CI to prove a rule parses is fine; committing the
output is not. Do not name the maintainer's employer anywhere in the
repository - the disclaimer says "any employer" deliberately.

**Defensive content only.** Fixtures carry the minimum content to exercise a
detection. No working exploit, implant or exploitation steps.

**Synthetic data only.** Fixtures use documentation address ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and placeholder names.

## Threat intel and response rules

**Attribution is reported, never computed.** An actor profile carries two
confidences: `link_confidence` is ours and measures provenance (one reporting
party is `medium`, however authoritative); `stated_confidence` is the
attributing party's own words, verbatim. Never upgrade a reporter's hedge, and
never merge two clusters unless the reporters themselves equate them.

**Motivation comes from the reporter.** UTA0576 was first filed as espionage;
Volexity's own assessment was "low confidence" criminal. Read the source.

**Attribute the action to the right actor.** The 2025 Ivanti syslog block was
the operator's iptables command, not SPAWN malware. Malware behaviour and
hands-on-keyboard behaviour are different claims.

**An implant with no detection states its gap.** `detections: []` without a
`gap` fails the validator, so a coverage hole is always visible.

**Response playbooks are guidance, not automation.** The toolkit never contains
or remediates. Order is fixed: preserve, contain, rotate, eradicate, recover,
verify. Every playbook has a `do_not` list - most evidence is destroyed by a
well-meant action taken too early.

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
Artifacts, platforms, detections, rules and intel are client-side libraries
built from one JSON block (facet rail, search, drawer, export); filter state is
in the URL (`#artifacts?platform=EDGE-0003&volatility=live`). `FACET_KEYS` in the
generator must match the facets the JS defines - the page logs an error if they
differ, and `--check` validates every static `#lib?key=` link against it. Rule
directories map to platforms through `RULE_DIR_PLATFORM`; a new directory
without an entry fails `--check`. `tests/test_site.py` drives the page in
Chromium and skips when Playwright is not installed. No framework, no CDN, no
build step; never hand-edited, never committed. The Pages workflow builds it at deploy time. Every embedded data blob goes through
`js_data()`, which escapes `</` so a rule body cannot close the script element.
Tab order follows an investigation and Start is the default route. Type:
one sans family, sizes only from the `--fs-*` tokens, monospace only for
literal strings (commands, paths, file names, patterns); prose goes through
`rich()` in the JS, which wraps the literals inline. Every platform needs a
note in the guide's Platform notes section, keyed in `NOTE_PLATFORM`.
Page changes go in the generator. `--check` fails on duplicate or non-URL-safe
element ids, dangling `#tab/anchor` links and any external script or stylesheet.

## What is next

See `docs/ROADMAP.md`.
