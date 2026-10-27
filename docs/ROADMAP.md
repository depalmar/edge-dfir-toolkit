# Roadmap

Ordered by value. Effort figures are judgment, not measurement.

## Phase 1 - make the MVP true on real devices (now)

1. **Verify every profile without a hardware lab.** There is no physical
   device access, so verification has three sources, in this order:
   - *Vendor virtual editions* under evaluation or trial licences - VM-Series,
     FortiGate-VM, NetScaler VPX, ASAv, Catalyst 8000V (or Cisco Modeling
     Labs), vSRX, BIG-IP VE, CloudGuard. Check each vendor's current terms;
     they change. These confirm prompts, pagers, command syntax and output
     shape, which is most of what is unverified today.
   - *Sanitized replay captures* contributed by responders (see
     CONTRIBUTING.md). A capture from a real appliance becomes a fixture and can
     raise a step's confidence.
   - *Vendor documentation* with a published output sample, which is what most
     `high` ratings rest on now.
   What a virtual edition cannot show - hardware-specific paths, appliance-only
   filesystems, Ivanti and SonicWall SMA behaviour without a VA - stays
   `medium` or `low` until a capture confirms it. Record each correction in
   `docs/VERIFICATION.md`.
2. **TSF parser.** Map the PAN-OS tech support file layout so packs can target
   known paths instead of broad globs, and list which persistence locations the
   TSF does *not* carry.
3. **Baseline corpus tooling.** `edge-triage baseline` to build `{path: sha256}`
   from a known-good device of the same build, signed, versioned per build. This
   is the long-term maintenance cost of the project.
4. **CACAO playbook** for "edge device suspected compromised": preflight →
   collect → ingest → analyze → decide on break-glass → containment, wired to
   these commands. Reuse the validator from the sibling toolkit.

## Phase 2 - breadth

- Profiles for SonicWall (TSR + image mode) and FortiManager. Check Point, F5,
  Juniper and IOS XE landed in 0.3.0.
- Packs still missing: Junos Evolved PTX (CVE-2026-21902, once primary
  indicators exist). J-Web and IOS XE SNMP landed in 0.6.0 at low confidence;
  raise them when a second source or Juniper's own advisory is read.
- KEV CVEs with no published indicator (listed in `VERIFICATION.md`): revisit
  each quarter for new vendor or researcher indicators.
- PAN-OS XML API transport, so collection works where SSH is disabled.
- Dissect-based image ingestion for NetScaler and SonicWall, producing the same
  `files/` view the analyzer already reads.
- Ivanti October 2026 (UTA0576): `EDGE-PACK-0026` covers `/data/.icscap`
  tooling and leftover payloads; still missing are the `/tmp/*.py` and `*.json`
  staging names (read only through a summariser) and debuglog / audit.log gaps,
  which need the off-box copy.

## Phase 3 - analysis

- Off-box correlation: syslog forwarding gaps, NetFlow to and from the
  management plane, IdP and AD events tied to the device's addresses. The 25
  hunts in `artifacts/hunts/` describe these by hand; the next step is an
  `ingest` mode that evaluates the simplest (syslog gap, device-sourced
  transfers) against exported data.
- Follow-ups from the 2026-10-27 KEV triage (listed at the end of that section
  in `docs/VERIFICATION.md`): read-only FortiOS steps for /tmp and for process
  memory maps, NetScaler /var/core listing, PEERSTITCH hashes and YARA, BUSHWALK,
  two FortiOS hardening controls and a RADIUS hunt for CVE-2020-3259.
- Clock-skew correction applied to every timeline row, using the V0 clock step.
- Plaso / Timesketch export.
- Evaluate the LLM brief against the fixture corpus before anyone relies on it.

## Ongoing

- New-CVE packs within days of a public advisory.
- Quarterly re-verification of every profile against current releases.
