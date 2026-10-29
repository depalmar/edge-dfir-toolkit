# Edge DFIR Toolkit

**Forensic triage for compromised VPN concentrators, firewalls and gateways.**

By [Raymond DePalma](https://www.linkedin.com/in/raymond-depalma/) · published by [DePalma Research LLC](https://www.linkedin.com/company/depalma-research)

> [!WARNING]
> **The collection profiles have not been run against real devices.** Every
> command in `collectors/profiles/` comes from vendor documentation and has been
> checked only against synthetic replays - the maintainer has no hardware lab.
> A command may fail, prompt, page differently or print a format the parsers do
> not recognise. The analyzer reports that as *not evaluated*, never as clean,
> but do not let an incident be the first run: try a profile on a lab device or
> a vendor virtual edition first. Live `collect` asks you to type `UNVALIDATED`
> (or pass `--accept-unvalidated`) until a profile records a verified run in its
> `validated_on` list.

A collector, an analyzer and a vendor-neutral detection pack for the edge
devices that keep getting exploited: PAN-OS / GlobalProtect, FortiOS, Ivanti
Connect Secure, Citrix NetScaler, Cisco ASA / FTD, Check Point, Juniper Junos,
Cisco IOS XE, F5 BIG-IP and SonicWall SMA.

It exists because the usual answer - run a Unix live-response collector on the
box - does not work on most of these devices. PAN-OS, FortiOS, ASA and Ivanti
give customers no shell. The ones that do (NetScaler, Check Point expert mode)
answer with binaries an implant may control. And the evidence that decides
most cases is volatile: in-memory implants, memory-disk files and fast-rotating
logs disappear the moment someone reboots or patches.

So this toolkit does three things a generic collector does not:

1. **Drives each vendor's restricted CLI** in order of volatility, through a
   declarative profile with a read-only guard enforced at load time.
2. **Ingests what the vendor lets you export** (tech support files, crash logs,
   image-triage output, SIEM copies) into the same hash-chained case.
3. **Reports what it could not see** as loudly as what it found. The best
   verdict it will give is `NO-INDICATORS-FOUND`, never "clean", and every
   report lists its evidence gaps.

**Browse it at [depalmar.github.io/edge-dfir-toolkit](https://depalmar.github.io/edge-dfir-toolkit/)** -
filterable libraries of every artifact (with what normal and suspicious look
like), platform, detection with its Sigma or YARA rule, off-box hunt, and threat
actor or implant with the publishers' own indicators (CSV and STIX 2.1) (facet filters with live counts, a detail panel per record,
shareable filtered links, CSV/JSON export of what you pick), every collection
plan in order of volatility with a command builder, containment and recovery
playbooks, prevention and hardening controls with their sources, clickable coverage matrices and the
[investigation guide](docs/edge-dfir-investigation-guide.md). It is rebuilt from
this repository on every push, so the page cannot drift from the content.

License: Apache 2.0.

---

## Disclaimer

This is independent research by Raymond DePalma, published by DePalma Research
LLC. It is not affiliated with, endorsed by, or produced on behalf of any former
employer or any vendor whose products it covers. All content is derived from public sources: vendor advisories,
government advisories and published research. Product names are used only to
identify the platforms covered.

---

## Structure

```
edge-dfir-toolkit/
├── 01-panos-globalprotect/   # Sigma + YARA, one directory per platform
├── 02-fortinet-fortios/
├── 03-ivanti-connect-secure/
├── 04-citrix-netscaler/
├── 05-cisco-asa-ftd/
├── 06-sonicwall-sma/
├── 07-checkpoint-quantum/
├── 08-cisco-ios-xe/
├── 09-juniper-junos/
├── 10-f5-bigip/
├── 11-sonicwall-sma1000/
├── edgetriage/               # the engine: collect, ingest, analyze, timeline, brief
├── collectors/profiles/      # declarative per-vendor collection profiles
├── artifacts/
│   ├── catalog/              # EDGE-NNNN platforms: access, collection paths, per-artifact detail
│   ├── packs/                # EDGE-PACK-NNNN per-CVE detection packs the analyzer runs
│   ├── intel/actors/         # EDGE-TA-NNNN actor profiles (attribution reported, not computed)
│   ├── intel/implants/       # EDGE-IMP-NNNN implants: survival, coverage, gaps
│   ├── intel/iocs/           # EDGE-IOC-NNNN indicators parsed from each publisher's own file
│   ├── hunts/                # EDGE-HUNT-NNNN off-box hunts: NetFlow, SIEM, AAA, identity
│   ├── hardening/            # prevention controls, each with its source
│   ├── response/             # containment and recovery playbook per platform
│   ├── schema/               # JSON schemas for all of the above
│   └── scripts/validate.py   # the CI gate
├── docs/                     # investigation guide, roadmap, verification log
└── tests/                    # synthetic fixtures and the test suite
```

---

## Quick start

> [!CAUTION]
> Run these first against a lab device or vendor virtual edition, not a device
> under investigation. See the warning at the top of this page.

```bash
pip install -r requirements.txt

# What will run against a PAN-OS device, in what order?
python -m edgetriage plan --profile panos --allow-bundle

# Collect (read-only by default). Answer the preflight honestly - it changes the report.
python -m edgetriage collect --profile panos --host 192.0.2.10 --user ir-readonly \
    --case-id IR-2026-031 --operator rdepalma --rebooted no --patched no

# Add the tech support file you exported through the web UI
python -m edgetriage ingest cases/IR-2026-031 --label tsf --bundle ~/Downloads/techsupport.tgz

# A hypervisor snapshot's memory or a vendor core dump: analyze reads it as memory
# (memory-safe pack rules, your --memory-yara rules, published indicators as text)
python -m edgetriage ingest cases/IR-2026-031 --label mem --bundle snapshot.lime --evidence-class memory

# Analyze, then build a timeline and an LLM brief. --forwarded (optional) lines the
# SIEM's copy of the device's syslog up with the logs on the box; --activity (optional)
# tests its gaps against what the device did, from sign-in, firewall or flow logs
python -m edgetriage analyze  cases/IR-2026-031 --window-start 2026-09-01T00:00:00 \
    --forwarded siem-export.jsonl --activity idp-signins.jsonl --activity-match 192.0.2.1
python -m edgetriage timeline cases/IR-2026-031
python -m edgetriage brief    cases/IR-2026-031
```

No device to hand? Every profile can run against recorded output:

```bash
python tests/make_fixtures.py /tmp/fx
python -m edgetriage collect --profile cisco-asa --case-id DEMO --replay /tmp/fx/asa-compromised
python -m edgetriage analyze cases/DEMO
```

### Case layout

```
cases/IR-2026-031/
├── commands/<step>.txt        # every CLI output, hashed in the manifest
├── files/<step>/<remote path> # fetched files (SFTP where the device allows it)
├── bundles/<label>/           # ingested exports, original + safely extracted copy
├── manifest.json              # chain of custody; each rewrite records the previous hash
├── manifest.sha256
├── collection.log
├── findings.json / report.md  # analyzer output
├── timeline.jsonl / .csv
└── llm_brief.md               # prompt with numbered, hashed records
```

---

## Platforms

| Platform | Shell? | Profile | Packs | Notes |
|---|---|---|---|---|
| PAN-OS / GlobalProtect | no | `panos` | 0001, 0002 | Take the TSF before upgrading |
| FortiOS | restricted | `fortios` | 0003 | Filesystem hash needs a baseline of the same build |
| Ivanti Connect Secure | no | `ivanti-ics` (manual checklist) | 0007 | ICT is one signal, never a verdict |
| Citrix NetScaler | yes | `netscaler` | 0004, 0005 | Memory-disk root dies on reboot |
| Cisco ASA / FTD | restricted | `cisco-asa` | 0006 | Memory-region check runs before anything that could reload |
| SonicWall SMA 100 | no | - | 0008 | Image-only by design |
| Check Point Gaia | yes (expert) | `checkpoint-gaia` | 0009, 0013, 0014 | Most 2026 hunting is SmartConsole exports; LivePatch does not fix CVE-2026-93616 |
| Juniper Junos | yes | `junos` | 0010 | CLI only, never the shell; JMRT quick-scan deletes evidence by default |
| Cisco IOS XE | restricted | `cisco-iosxe` | 0011, 0012 | Do not reboot first; the 2023 implant was memory-only |
| F5 BIG-IP | yes (bash) | `f5-bigip` | 0015, 0016, 0017 | Do not trust sys-icheck; never restore a post-compromise UCS |
| SonicWall SMA 1000 | yes (root over SSH) | `sonicwall-sma1000` (unvalidated) | 0036, 0037 | Capture memory before any restart: UTA0533's implants live in the workplace JVM |

---

## Design rules

**Read-only by default.** Allow rules are full-command grammars (matched with
`fullmatch`, never as prefixes), and a profile cannot load if an impact-free
step fails them or matches a deny rule. Control characters are refused in every
command, so a newline cannot carry a second command past an approved first
one. Operator `--var` values are restricted to path-and-host characters and
re-checked after substitution. Vendor bundles (`--allow-bundle`) write a
temporary file on the device. Break-glass steps (`--break-glass`: core dumps,
imaging, external integrity tools that reboot) always run last and require
typed confirmation.

**Order of volatility is code, not advice.** Steps run V0 → V1 (memory) → V2
(process) → V3 (sessions) → P1-P7 (integrity, config, logs, filesystem,
persistence) → B (bundles) → X (break-glass).

**Not evaluated is not passed.** Every detection reports `hit`, `no-hit` or
`not-evaluated`. The third becomes an evidence gap in the report.

**Corroboration, not counting.** `possible` indicators in two evidence classes
raise the verdict to `LIKELY-COMPROMISED`; `likely` indicators in two classes
raise it to `COMPROMISED`. Repeated hits in one class do not.

**Bundles are hostile input.** Archives from a compromised device are extracted
regular-file-only. Traversal paths, links and device nodes are refused and
recorded, and a refused symlink is still evidence the analyzer reads.

**LLMs narrate; they do not decide.** `brief` writes a prompt that hands a
model numbered, hashed records and tells it not to change the verdict. Run it
against a local or tenant-controlled model: configurations carry secrets.

**Detections are Sigma and YARA only.** No vendor query dialect is committed.
Convert with pySigma for your platform.

**Attribution is reported, never computed.** Each actor carries two
confidences: ours (how well-sourced the link is) and the reporting party's own
words, quoted. Clusters are merged only where the reporters themselves equate
them.

**Every claim is sourced.** Content was checked against primary sources;
`docs/VERIFICATION.md` records every correction and what is still unverified.

---

## Testing

```bash
python artifacts/scripts/validate.py     # catalog, packs, profiles, rules - the CI gate
python artifacts/scripts/build_site.py --check   # site data contract, writes nothing
python -m pytest -q tests/               # 71 tests against synthetic fixtures
```

All fixture data is synthetic: documentation-range addresses, placeholder
hosts and users, and the minimum content needed to exercise each detection.

---

## Keeping up with new exploitation

A weekly workflow (`.github/workflows/advisory-watch.yml`) compares CISA's
Known Exploited Vulnerabilities catalog with the detection packs and re-hashes
the publisher files behind every indicator set. Anything exploited on a covered
platform that has neither a pack nor a recorded decision in
`artifacts/watch/kev-watch.yml`, and any indicator file that changed upstream,
is posted to an issue labelled `advisory-watch`. It never commits: content
lands only through a pull request that the validator gates, after someone has
read the primary sources. Run it locally with
`python artifacts/scripts/advisory_watch.py --upstream`. The same report lists
every CVE on the site that has not yet been searched for when its exploitation
began.

Quotes age too: a vendor rewords an advisory, or a page moves. A monthly
workflow (`.github/workflows/quote-check.yml`) re-fetches every page a record
quotes and opens an issue labelled `quote-check` when a quote is no longer on
its page. Pages that only render in a browser are listed for a manual check
rather than counted as changed. Run it locally with
`python artifacts/scripts/check_quotes.py`.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). The short version: cite a public
source, add a malicious and a benign fixture, mark low-confidence content
`unverified: true`, and keep every profile step read-only unless it declares
its impact.

---

**Maintainer:** [Raymond DePalma](https://www.linkedin.com/in/raymond-depalma/),
Founder and President of [DePalma Research LLC](https://www.linkedin.com/company/depalma-research),
a research and advisory firm for digital forensics and incident response.
Not affiliated with any former employer.
