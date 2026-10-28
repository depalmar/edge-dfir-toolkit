# Edge device investigation guide

How to triage a VPN concentrator, firewall or gateway you suspect is
compromised, using this toolkit. Written for responders who already know DFIR
and need the parts that are different on appliances.

## What is different about edge devices

- **No shell, or a shell you cannot trust.** PAN-OS, FortiOS, Cisco ASA and
  Ivanti Connect Secure give customers no root shell. NetScaler, Check Point
  (Expert mode), F5 (Advanced Shell) and Junos do, but an implant that hooks
  the C library lies to `ps`, `ls` and `stat`.
- **The decisive evidence is volatile.** Memory-only implants (LINE DANCER on
  ASA), memory-only exploitation that leaves no implant (UTA0576's transient
  libdsplibs.so patch on Ivanti in 2026), memory-disk roots
  (NetScaler) and gateway logs that rotate in hours are gone after a reboot,
  an upgrade or a busy afternoon.
- **The integrity tools have been beaten.** Ivanti's Integrity Checker was
  modified and its manifest re-signed; a FortiGate persistence mechanism
  survived patching; LINE DANCER turned core-dump requests into reloads. A
  clean vendor check is one signal, never a verdict.
- **Patched does not mean clean.** Most backdoored NetScalers in the 2023
  campaign were patched after the web shell was planted, and the patch did not
  remove it. Persistence outlives the vulnerability.

## Before you touch the device

> **Read this before you connect.** Most evidence on an appliance is destroyed
> by a well-meant action taken in the first hour: a reboot, an upgrade, or the
> vendor's own integrity tool.

1. **Do not reboot, upgrade, factory-reset or run an external integrity tool.**
   Each of those destroys evidence. On PAN-OS, the vendor says some logs from
   the prior installation become inaccessible on the device after an upgrade.
2. **Pull the off-box copies first.** SIEM syslog, NetFlow to and from the
   management interface, IdP and MFA logs, AD authentication from the device's
   addresses. These are the copies the attacker is least likely to have touched,
   and a gap in them is itself evidence.
3. **Record the preflight honestly.** Has the device rebooted or been upgraded
   since the suspected window? The answers change what the report can claim.
4. **Use a read-only account** where the platform has one, and pin the host key.
5. **On Cisco ASA and Firepower, do not use tab completion.** CISA: "Do NOT use
   the “tab” autocomplete or any other autocomplete function. The threat actor
   has hooked these commands to crash the device."

## Collection

```bash
python -m edgetriage plan --profile <platform>            # read it before you run it
python -m edgetriage collect --profile <platform> --host <ip> --user <ro-user> \
    --case-id IR-YYYY-NNN --operator <you> --rebooted no --patched no
```

The engine runs steps in order of volatility and refuses anything the profile
did not declare. Vendor bundles need `--allow-bundle`; core dumps, imaging and
anything that reboots need `--break-glass` and run last.

### Unvalidated profiles

No profile has yet been run against a real device or a vendor virtual edition.
Every command comes from the vendor's documentation and has been checked only
against synthetic replays, so a command can fail, prompt, page differently or
print a format the parsers do not recognise. The analyzer reports such a step
as not evaluated - never as clean - and the report carries an
`unvalidated-profile` gap, but a failed collection during an incident still
costs time you do not have.

`plan` prints a warning for an unvalidated profile, and a live `collect` asks
you to type `UNVALIDATED` (or pass `--accept-unvalidated` when there is no
terminal) before it connects. Replays are not affected. Try a profile on a lab
device or virtual edition first.

A profile becomes validated when someone runs it on a real device or virtual
edition and records the run: an entry in the profile's `validated_on` list
(`release`, `date`, `basis`) and a row under Device verification in
`docs/VERIFICATION.md` with any command that had to change. Sanitised replay
captures from such a run are the most useful contribution to this project.

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
supplemental direction (updated April 24, 2026), which has separate procedures
for Firepower and Secure Firewall with FTD software, Firepower and Secure
Firewall with ASA software, and ASA devices - CISA: "instructions and commands
vary". It adds the FIRESTARTER persistence mechanism on Firepower and Secure
Firewall devices. Scan the dump with RayDetect.

**SonicWall SMA 100.** No collection profile yet. Export the tech support report
and logs through the management UI and `ingest` them. GTIG advises disk images
because the rootkit hides from on-box tools; physical units may need
SonicWall's help.

**Check Point Gaia.** Collect in Expert mode; entering Expert from Clish asks
for a second password, so the collection account needs `/bin/bash` as its
shell. Gateway and management roles keep different logs, so a role's log that
is absent is a gap, not a pass. Export the SmartConsole hunting queries over the
full retention window. `cpinfo` writes a file and by default uploads to Check
Point and updates itself; the profile runs it with `-D -d`, behind
`--allow-bundle`. Patching CVE-2026-93616 does not show whether the server was
attacked before the patch.

**Juniper Junos.** Everything runs from the operational CLI with `| no-more`.
The JMRT integrity check writes and runs a test file and adds syslog lines, so
it is opt-in and runs after the logs are collected. JMRT quick-scan deletes
malicious files and kills processes by default: it is break-glass, runs last,
and should report only. UNC3886 deleted log lines containing "root" and
redirected logging during its sessions, so the syslog receiver's copy outranks
the device's.

**Cisco IOS XE.** Do not reboot: the 2023 web UI implant lived only in memory,
though the accounts it created survive. The IOSd memory map is collected first;
routers and Catalyst switches use different forms of the command and the
profile collects both. In install mode, hash each package listed in
`packages.conf`, not `packages.conf` itself. Run Cisco's HTTP implant check from
a workstation; a negative result does not rule out an implant that never became
active, because it only activates once the web server restarts.

**F5 BIG-IP.** Do not trust `sys-icheck` on a suspect device: c05d5254 tampered
with it. Use F5 System Scanner from known-good media (break-glass), and take a
`qkview` behind `--allow-bundle`. Never restore a UCS archive taken after the
compromise; F5 warns it can carry the malware back.

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
    [--baseline known-good-hashes.json] [--forwarded siem-export.jsonl]
```

`--forwarded` takes the device's syslog as your SIEM or collector received it,
for the same hours: raw lines, or JSON or CSV with a `Message` field. The
analyzer lines it up with the logs on the box by message and in order, like a
diff, never by clock. A message repeated throughout the log, such as a logout,
only pairs with a copy nearby. The analyzer reports two things as possible
indicators:
- runs of forwarded lines that are gone from the box;
- runs of local lines the SIEM never received.

It also lists the longest silences in the forwarded stream without scoring
them. When the two copies share too few lines (the device forwards a different
format than it keeps, or logs at a different level), it says the comparison
was not evaluated. Use `--forwarded-local` to name the local file when it is
not a `*.log`, `messages` or `syslog` file.

Read the report in this order:

1. **Evidence gaps.** What the analysis could not see. A detection that was
   `not-evaluated` did not pass; it never ran.
2. **Verdict.** `COMPROMISED`, `LIKELY-COMPROMISED`, `SUSPICIOUS` or
   `NO-INDICATORS-FOUND`. There is no "clean".
3. **Findings.** Each hit with its source, line and excerpt.

| Tier | Typically means |
|---|---|
| `possible` | exploitation attempted, a lead that needs a second signal, or the SIEM's copy of the logs disagreeing with the box |
| `likely` | post-exploitation artefact with a plausible benign explanation |
| `confirmed` | artefact with no legitimate reason to exist on the device |

The verdict follows from the strongest evidence, and corroboration counts only
across different evidence classes; repeated hits in one class do not raise it.

| What fired | Verdict |
|---|---|
| any `confirmed` indicator | `COMPROMISED` |
| `likely` indicators in two or more evidence classes | `COMPROMISED` |
| `likely` indicators in one class | `LIKELY-COMPROMISED` |
| `possible` indicators in two or more evidence classes | `LIKELY-COMPROMISED` |
| `possible` indicators in one class | `SUSPICIOUS` |
| nothing | `NO-INDICATORS-FOUND` |

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

## Prevent the next one

Most of the intrusions behind this toolkit started at a management interface or
VPN portal reachable from the internet, an administrator login without MFA, or
a device past its end of life, and were then hard to investigate because the
logs only lived on the device. The site's Hardening section lists the controls
for each platform with their vendor or government sources. The baseline, from
CISA BOD 23-02 and the 2025 joint edge-device guidance:

- **Take management interfaces off the internet**, or put them behind a policy
  enforcement point that is separate from the device.
- **Phishing-resistant MFA** for every administrator and VPN user, with device
  administration kept out of the corporate AD forest.
- **Forward logs off the device in real time** to a store it cannot modify.
- **Replace end-of-life devices**, and patch knowing that a patch does not
  remove an implant that is already there.

