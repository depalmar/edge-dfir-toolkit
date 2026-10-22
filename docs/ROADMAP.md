# Roadmap

Ordered by value. Effort figures are judgment, not measurement.

## Phase 1 - make the MVP true on real devices (now)

1. **Lab-verify every profile.** PA-VM, FortiGate-VM, NetScaler VPX and ASAv
   first. For each: prompt and pager regexes, every command's existence and
   output shape, SFTP availability on NetScaler. Raise `confidence` only for
   what ran. Record each correction in `docs/VERIFICATION.md`.
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

- Profiles for Check Point (expert mode), F5 BIG-IP (bash + qkview), Juniper
  Junos (shell + JMRT orchestration), SonicWall (TSR + image mode), IOS XE.
- PAN-OS XML API transport, so collection works where SSH is disabled.
- Dissect-based image ingestion for NetScaler and SonicWall, producing the same
  `files/` view the analyzer already reads.
- Ivanti October 2026 (UTA0576) pack once indicators are stable: core dumps
  produced by exploitation, `/tmp/*.py` and `*.json` staging, root mounted
  read-write, iptables rules dropping syslog.

## Phase 3 - analysis

- Off-box correlation: syslog forwarding gaps, NetFlow to and from the
  management plane, IdP and AD events tied to the device's addresses.
- Clock-skew correction applied to every timeline row, using the V0 clock step.
- Plaso / Timesketch export.
- Evaluate the LLM brief against the fixture corpus before anyone relies on it.

## Ongoing

- New-CVE packs within days of a public advisory.
- Quarterly re-verification of every profile against current releases.
