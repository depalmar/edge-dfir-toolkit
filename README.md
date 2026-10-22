# Edge DFIR Toolkit

**Forensic triage for compromised VPN concentrators, firewalls and gateways.**

A collector, an analyzer and a vendor-neutral detection pack for the edge
devices that keep getting exploited: PAN-OS / GlobalProtect, FortiOS, Ivanti
Connect Secure, Citrix NetScaler, Cisco ASA / FTD, SonicWall SMA, Check Point
and Cisco IOS XE.

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

License: Apache 2.0.

---

## Disclaimer

This is an independent personal project. It is not affiliated with, endorsed
by, or produced on behalf of any employer or any vendor whose products it
covers. All content is derived from public sources: vendor advisories,
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
├── edgetriage/               # the engine: collect, ingest, analyze, timeline, brief
├── collectors/profiles/      # declarative per-vendor collection profiles
├── artifacts/
│   ├── catalog/              # EDGE-NNNN platform entries: access, collection paths, anti-forensics
│   ├── packs/                # EDGE-PACK-NNNN per-CVE detection packs the analyzer runs
│   ├── schema/               # JSON schemas for both
│   └── scripts/validate.py   # the CI gate
├── docs/                     # roadmap and design notes
└── tests/                    # synthetic fixtures and the test suite
```

---

## Quick start

```bash
pip install -r requirements.txt

# What will run against a PAN-OS device, in what order?
python -m edgetriage plan --profile panos --allow-bundle

# Collect (read-only by default). Answer the preflight honestly - it changes the report.
python -m edgetriage collect --profile panos --host 192.0.2.10 --user ir-readonly \
    --case-id IR-2026-031 --operator rdepalma --rebooted no --patched no

# Add the tech support file you exported through the web UI
python -m edgetriage ingest cases/IR-2026-031 --label tsf --bundle ~/Downloads/techsupport.tgz

# Analyze, then build a timeline and an LLM brief
python -m edgetriage analyze  cases/IR-2026-031 --window-start 2026-09-01T00:00:00
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
| Check Point Gaia | yes (expert) | - | 0009 | Sigma + pack; collector planned |
| Cisco IOS XE | restricted | - | - | Sigma only |

---

## Design rules

**Read-only by default.** A profile cannot load if an impact-free step fails
its allow-list or matches its deny-list, and operator-supplied `--var` values
are re-checked after substitution. Vendor bundles (`--allow-bundle`) write a
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

---

## Testing

```bash
python artifacts/scripts/validate.py     # catalog, packs, profiles, rules - the CI gate
python -m pytest -q tests/               # 31 tests against synthetic fixtures
```

All fixture data is synthetic: documentation-range addresses, placeholder
hosts and users, and the minimum content needed to exercise each detection.

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). The short version: cite a public
source, add a malicious and a benign fixture, mark low-confidence content
`unverified: true`, and keep every profile step read-only unless it declares
its impact.

---

**Maintainer:** Raymond DePalma - independent security researcher.
This is a personal project and is not affiliated with any employer.
