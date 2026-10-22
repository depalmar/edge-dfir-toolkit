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
- Packs still missing: Juniper J-Web (CVE-2023-36844 chain), Junos Evolved PTX
  (CVE-2026-21902, once primary indicators exist), IOS XE SNMP (CVE-2025-20352).
- PAN-OS XML API transport, so collection works where SSH is disabled.
- Dissect-based image ingestion for NetScaler and SonicWall, producing the same
  `files/` view the analyzer already reads.
- Ivanti October 2026 (UTA0576) pack once indicators are stable: core dumps
  produced by exploitation, `/tmp/*.py` and `*.json` staging, capture files under
  `/data/.icscap/`, and gaps in debuglog and audit.log. (The read-write root
  remount and iptables syslog block belong to the 2025 UNC5221 activity, not
  this one.)

## Phase 3 - analysis

- Off-box correlation: syslog forwarding gaps, NetFlow to and from the
  management plane, IdP and AD events tied to the device's addresses.
- Clock-skew correction applied to every timeline row, using the V0 clock step.
- Plaso / Timesketch export.
- Evaluate the LLM brief against the fixture corpus before anyone relies on it.

## Ongoing

- New-CVE packs within days of a public advisory.
- Quarterly re-verification of every profile against current releases.
