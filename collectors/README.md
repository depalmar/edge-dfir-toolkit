# collectors/ - Edge device collection profiles

Declarative profiles that tell `edgetriage` what to run on each platform, in
what order, and what it is allowed to touch. The engine never runs a command a
profile did not declare.

## Profile anatomy

```yaml
profile: cisco-asa
platform_id: EDGE-0005           # artifacts/catalog entry
cli:
  prompt: '[\w.()/-]+[>#] ?$'    # when the device is ready for the next command
  pager: '<--- More --->'        # answered with a space by the transport
  session_setup: [terminal pager 0]   # session-scoped only; validated
  allow: ['^show ...', '^dir ...']    # every impact-free step must match one
  deny:  ['^(reload|write|copy|...)'] # and none of these
expected_evidence: [identity, memory, ...]   # missing classes become evidence gaps
steps:
  - id: mem_region_lina
    tier: V1                     # order of volatility, see below
    kind: command                # command | fetch | manual
    impact: none                 # none | vendor-bundle | break-glass
    cmd: show memory region | include lina
    purpose: why this exists and what it proves
    confidence: high             # low requires unverified: true
    references: [...]
```

## Tiers

| Tier | Class | Example |
|---|---|---|
| V0 | identity, clock | `show clock`, `show version` |
| V1 | memory state | ASA memory-region map, hypervisor snapshot |
| V2 | process, sockets | `show system resources`, `sockstat` |
| V3 | sessions | admin, VPN, AAA sessions |
| P1 | integrity | `diagnose sys filesystem hash`, ICT history |
| P2 | configuration | running config, config audit log |
| P3-P5 | auth, web, system logs | gpsvc.log, ns.log, crash log |
| P6-P7 | filesystem, persistence | web-root PHP, cron, SUID, disk0 |
| B | vendor bundles | PAN-OS TSF export (writes on the device) |
| X | break-glass | core dump, disk image, external ICT (reboots) |

The engine sorts by tier, so a profile cannot run a disruptive step early by
accident.

## Impact

| Impact | Flag | What it means |
|---|---|---|
| `none` | default | Read-only. Must pass allow/deny at load and after `--var` substitution. |
| `vendor-bundle` | `--allow-bundle` | Generates a diagnostic file on the device. |
| `break-glass` | `--break-glass` + typed confirmation | Can crash, reload, reboot or image the device. Usually `manual`. |

## Manual steps

Some platforms expose nothing to type at (Ivanti), and some evidence needs the
vendor (PAN-OS memory, ASA core dumps). Those steps are `kind: manual`: the
engine records them as `pending-manual` with instructions, and the operator
brings the output in with `edge-triage ingest`. Pending manual steps appear in
the report's evidence gaps until something is ingested.

## Credentials

Passwords come from `--password-env` or an interactive prompt and are never
written to the case. Use a read-only account where the platform has one.
Host keys are checked against `known_hosts` or pinned with `--hostkey-sha256`;
an unknown key aborts the connection rather than being trusted silently.
