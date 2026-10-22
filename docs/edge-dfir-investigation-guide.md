# Edge device investigation guide

How to triage a VPN concentrator, firewall or gateway you suspect is
compromised, using this toolkit. Written for responders who already know DFIR
and need the parts that are different on appliances.

## What is different about edge devices

- **No shell, or a shell you cannot trust.** PAN-OS, FortiOS, Cisco ASA and
  Ivanti Connect Secure give customers no root shell. NetScaler and Check Point
  do, but an implant that hooks the C library lies to `ps`, `ls` and `stat`.
- **The decisive evidence is volatile.** Memory-only implants (LINE DANCER on
  ASA, in-memory library patching on Ivanti in 2026), memory-disk roots
  (NetScaler) and gateway logs that rotate in hours are gone after a reboot,
  an upgrade or a busy afternoon.
- **The integrity tools have been beaten.** Ivanti's Integrity Checker was
  modified and its manifest re-signed; a FortiGate persistence mechanism
  survived patching; LINE DANCER turned core-dump requests into reloads. A
  clean vendor check is one signal, never a verdict.
- **Patched does not mean clean.** Most backdoored NetScalers in the 2023
  campaign had already been patched. Persistence outlives the vulnerability.

## Before you touch the device

1. **Do not reboot, upgrade, factory-reset or run an external integrity tool.**
   Each of those destroys evidence. On PAN-OS, logs from the previous install
   become inaccessible after an upgrade.
2. **Pull the off-box copies first.** SIEM syslog, NetFlow to and from the
   management interface, IdP and MFA logs, AD authentication from the device's
   addresses. These are the copies the attacker is least likely to have touched,
   and a gap in them is itself evidence.
3. **Record the preflight honestly.** Has the device rebooted or been upgraded
   since the suspected window? The answers change what the report can claim.
4. **Use a read-only account** where the platform has one, and pin the host key.

## Collection

```bash
python -m edgetriage plan --profile <platform>            # read it before you run it
python -m edgetriage collect --profile <platform> --host <ip> --user <ro-user> \
    --case-id IR-YYYY-NNN --operator <you> --rebooted no --patched no
```

The engine runs steps in order of volatility and refuses anything the profile
did not declare. Vendor bundles need `--allow-bundle`; core dumps, imaging and
anything that reboots need `--break-glass` and run last.

### Platform notes

**PAN-OS / GlobalProtect.** Collect, then export the tech support file through
the web UI and `ingest` it. The TSF does not necessarily carry cron or Python
site-packages; ask the vendor for those through a support case if CVE-2024-3400
is in scope.

**FortiOS.** `diagnose sys filesystem hash` is only meaningful against a
baseline from the same build. Supply the SSL-VPN language directory with
`--var sslvpn_lang_dir=...` so the symlink check can run.

**Ivanti Connect Secure.** Nothing to type at. Snapshot the virtual appliance
with memory first, then export logs and configuration, then (and only then) the
external Integrity Checker, which reboots the appliance.

**NetScaler.** Live response works, but image the disks (break-glass) before
anyone reboots: anything on the memory-disk root is lost.

**Cisco ASA / FTD.** The memory-region check runs before anything else. Do not
request a core dump until it has been reviewed; then follow the CISA ED 25-03
procedure and scan the dump with RayDetect.

## Bringing in exports

```bash
python -m edgetriage ingest cases/IR-YYYY-NNN --label tsf --bundle techsupport.tgz \
    --evidence-class bundle --evidence-class filesystem
```

Every ingest is hashed and copied, archives are extracted regular-file-only,
and refused members (traversal paths, symlinks) are recorded. A refused symlink
is still evidence: the FortiOS symlink check reads those refusals.

## Analysis

```bash
python -m edgetriage analyze cases/IR-YYYY-NNN --window-start 2026-09-01T00:00:00 \
    [--baseline known-good-hashes.json]
```

Read the report in this order:

1. **Evidence gaps.** What the analysis could not see. A detection that was
   `not-evaluated` did not pass; it never ran.
2. **Verdict.** `COMPROMISED`, `LIKELY-COMPROMISED`, `SUSPICIOUS` or
   `NO-INDICATORS-FOUND`. There is no "clean".
3. **Findings.** Each hit with its source, line and excerpt.

| Tier | Typically means |
|---|---|
| possible | exploitation attempted, or a lead that needs a second signal |
| likely | post-exploitation artefact with a plausible benign explanation |
| confirmed | artefact with no legitimate reason to exist on the device |

Two `possible` indicators in different evidence classes raise the verdict to
`LIKELY-COMPROMISED`; two `likely` indicators in different classes raise it to
`COMPROMISED`. Repeated hits in one class do not.

## Timeline and narrative

```bash
python -m edgetriage timeline cases/IR-YYYY-NNN
python -m edgetriage brief    cases/IR-YYYY-NNN
```

The timeline puts device events and your own collection steps on one axis, so
a log that ends two minutes before you connected is visible. Timestamps the
device did not qualify are marked device-local.

The brief is a prompt for a model, not a verdict. It numbers and hashes every
record, requires a citation for every claim, and tells the model not to change
the verdict. Run it against a local or tenant-controlled model: device
configurations carry credentials and keys.

## After triage

- **Compromised or likely:** treat credentials the device held as exposed (VPN
  users, LDAP bind accounts, local admins, certificates), hunt from the device
  into the network, and plan replacement or vendor-guided rebuild rather than
  in-place cleanup.
- **No indicators:** close the listed gaps before closing the case. The most
  common honest outcome is "no indicators in the evidence available".
