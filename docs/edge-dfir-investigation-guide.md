# Edge device investigation guide

How to triage a VPN concentrator, firewall or gateway you suspect is
compromised, using this toolkit. Written for responders who already know DFIR
and need the parts that are different on appliances.

## The workflow at a glance

<!-- figure:workflow -->

Each step has a section below:

1. Preserve: before you touch the device.
2. Plan.
3. Collect or ingest.
4. The case folder.
5. Analyze.
6. Read the report.
7. Decide, then close the gaps.
8. Respond.

Two loops matter more than the straight line:
- **A `NO-INDICATORS-FOUND` verdict.** It sends you back to close evidence
  gaps, not to close the case.
- **A step that can reload, crash or image the device.** It waits until
  everything volatile is already in the case folder.

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

**Memory comes first, by the safest route.** On a virtual appliance, a
hypervisor snapshot that includes memory captures what no command on the
device will, and nothing running inside the guest can interfere with it. Take
it before the first live command. On hardware, the vendor's own core dump is
the only route. It is break-glass and runs after everything else, because
LINE DANCER turned a dump request into a reload. Ingest a snapshot or dump
with `--evidence-class memory`.

### When a step fails

A step that fails, times out or prints something the profile did not expect
is recorded with its status in `manifest.json`: `unavailable`, `error` or
`refused`. The detections that needed it then report not evaluated. Read
`collection.log` before you read the verdict.

To test a profile without a device, use `collect --replay <dir>`. It serves
recorded outputs exactly as a live run would see them: the output of each
command in `commands/<slug of the command>.txt`, and pulled files under
`files/<path on the device>`. A command with no recording is reported
unavailable, just as on a device that lacks it.
A sanitized capture from a real device is the most useful contribution you can
make (see CONTRIBUTING.md). It turns a guessed output format into a tested
one.

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

## The case folder

Everything the toolkit knows about a case is in one folder. Archive it whole.

| Path | What it holds |
|---|---|
| `manifest.json` | Case, operator, platform, preflight answers, every step with its status and the sha256 of its output, every ingest |
| `manifest.sha256` | The manifest's own hash. Each save also records the previous manifest's hash, so edits form a chain |
| `collection.log` | Each step and ingest on one line, in the order they happened |
| `commands/` | Each command's output, one file per step id |
| `files/` | Files pulled from the device, under the step that pulled them |
| `bundles/` | Ingested exports and vendor bundles, extracted regular-file-only |
| `findings.json`, `report.md`, `report.html` | The analysis: verdict, findings, evidence gaps |
| `timeline.jsonl`, `timeline.csv` | Device events and your own collection steps on one axis |
| `llm_brief.md` | The prompt for a model, with every record numbered and hashed |

`analyze`, `timeline` and `brief` rewrite only their own output files, so you can
re-run them as often as you like. They never touch the evidence the case holds.

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

It also lists the longest silences in the forwarded stream. When the two
copies share too few lines (the device forwards a different format than it
keeps, or logs at a different level), it says the comparison was not
evaluated. Use `--forwarded-local` to name the local file when it is not a
`*.log`, `messages` or `syslog` file.

A silence on its own is not scored: a quiet night is not an indicator. An
intruder who stops local logging and forwarding together leaves two copies
that still agree, and then the only evidence is the device doing work while
its logs say nothing. `--activity` takes that work from a source the device
does not control, one event per record or line:
- sign-ins through it (identity provider or RADIUS);
- sessions from its inside address on the next firewall;
- connections from its VPN pool in EDR;
- flows to and from it, if you have NetFlow.

```bash
python -m edgetriage analyze cases/IR-YYYY-NNN --forwarded siem-export.jsonl \
    --activity idp-signins.jsonl --activity-match 192.0.2.1
```

A gap with three or more of those events inside it, not counting five minutes
at each end, is a possible indicator. A gap the export spans with no events
is reported as quiet there too. A gap the export does not span is not counted
as tested. The forwarded copy needs timestamps with a year (a JSON or CSV
export with the SIEM's time field), or its gaps cannot be placed. A poll that
happens anyway, such as an SNMP sample or a ping, shows the device was up,
not that it was busy, so export only events the device caused.
`--activity-match` keeps the records that name the device's address or host
name as a whole token, so `192.0.2.1` does not match `192.0.2.10`.

`report.md` and `report.html` hold the same findings, in the order to read
them:

1. **Verdict and what to do next.** The verdict is `COMPROMISED`,
   `LIKELY-COMPROMISED`, `SUSPICIOUS` or `NO-INDICATORS-FOUND`; there is no
   "clean". The next steps quote the platform playbook's do-not list.
2. **Evidence gaps.** What the analysis could not see. A detection that was
   `not-evaluated` did not pass; it never ran. Each gap says what it needed
   (the step that failed, the file it had nothing to scan) and how to close it.
3. **Findings, strongest first.** Each hit gives the command and line that
   produced it, an excerpt, and the confidence of the pack behind it.

The header also carries the case manifest's sha256, so a report can be tied to
the exact case folder it came from.

| Tier | Typically means |
|---|---|
| `possible` | exploitation attempted, a lead that needs a second signal, or off-box logs that do not add up (the SIEM's copy disagreeing with the box, or going quiet while the device was busy) |
| `likely` | post-exploitation artefact with a plausible benign explanation |
| `confirmed` | artefact with no legitimate reason to exist on the device |

The verdict follows from the strongest evidence, and corroboration counts only
across different evidence classes; repeated hits in one class do not raise it.

### A worked example

A synthetic Junos case, built from the toolkit's own test fixtures (nothing in
it came from a real device):

```bash
python tests/make_fixtures.py fx
python -m edgetriage collect --profile junos --case-id IR-2026-EX1 --replay fx/junos-compromised \
    --operator analyst --rebooted no --patched no
python -m edgetriage analyze cases/IR-2026-EX1 --window-start 2026-10-01T00:00:00
```

The parts of `report.md` that matter, in the order to read them (`...` marks
lines left out):

```text
**Verdict: COMPROMISED**
likely indicators corroborated across evidence classes (filesystem, persistence): junos-login-record-backups, junos-syslog-conf-backup, junos-unc3886-null-fifo, junos-unc3886-payload-files
...
## What to do next
- Preserve before you act: the case folder may be the only copy of what the device held. Do not reboot, upgrade or factory-reset it until the playbook's preservation steps are done.
...
From the playbook, do not:
- **Run JMRT quick-scan with its default clean action before collecting.** It deletes the malicious files and kills the processes it finds.
...
## Evidence gaps
- **missing-evidence-class** - no integrity evidence in the case
  Close it: The junos plan's integrity steps: jmrt_integrity_check (needs --allow-bundle), not run. ...
- **detection-not-evaluated** - junos-unc3886-tinyshell-yara, junos-tinyshell-mandiant-hunting (EDGE-PACK-0010): needs a file to scan: a recovered binary or an ingested image
- **detection-not-evaluated** - junos-jweb-php-log-anonymous, junos-jweb-php-log-session-null (EDGE-PACK-0020): needs step jweb_php_log (`file show /var/jail/sess/php.log | no-more`), which was unavailable, or a file matching **/php.log*
...
## Findings
...
### [LIKELY] Backup copies of the login records
`junos-login-record-backups` - EDGE-PACK-0010 (pack confidence high) - CVE-2025-21590 - 2 hit(s), evidence class persistence
- `file list /var/log detail | no-more` (step listing_var_log), line 5
  `-rw-r--r--  1 root  wheel    4410 Oct 14 07:10 wtmp0`
...
### [POSSIBLE] File named by a 64-character hex digest in /var/tmp or the J-Web jail
`junos-jweb-hex-named-upload` - EDGE-PACK-0020 (pack confidence low, unverified) - ...
```

How to read it:

1. **The verdict and why.** `COMPROMISED` rests on likely hits in two
   evidence classes, filesystem and persistence, which corroborate each
   other. The two possible process hits did not raise it; one class of
   possible hits never would.
2. **What to do next comes before anything else.** The do-not lines are
   quoted from the Junos playbook. The first is the one that would destroy
   this evidence: JMRT quick-scan's default action deletes what it finds.
3. **The gaps say what the verdict cannot see.** The integrity check never
   ran (it writes to the device, so it needs `--allow-bundle`), so nothing
   here says whether veriexec is intact. No recovered binary was scanned, so
   TINYSHELL's presence is unknown, not ruled out. The J-Web log step failed,
   so J-Web exploitation is unexamined. Each gap ends with how to close it.
4. **Then the findings, strongest first.** Each names the command and line to
   re-check by hand, and how far to trust the detection behind it. The
   leftover `wtmp0` means the login records themselves may have been altered,
   so weigh the session list accordingly. The J-Web finding comes from a
   low-confidence, single-source pack: read the file before you count it.
5. **What to tell the incident lead.** "Compromised. The artifacts match
   tradecraft Mandiant reports for UNC3886; that is a lead, not attribution.
   Credentials the router held are exposed. The integrity check, a binary
   scan and the J-Web logs are still outstanding."

`--baseline` takes a `{path: sha256}` JSON from a known-good device of the
same build. The hash comparison refuses to run without one rather than call
every file unknown, so it shows as not evaluated until you supply one.

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

**Clocks.** On every platform with a command line, one of the first
collection steps reads the device's clock (FortiOS's `get system status`,
Junos's `show system uptime`, `show clock` on Cisco and PAN-OS, `date` in the
bash shells). Ivanti gives you no command line, so take the time from the
hypervisor and the exported logs. Compare the device's clock with your own and
note the difference before you line device times up with anything else. A device clock
that is off by minutes moves every event you correlate against the SIEM, the
IdP or the firewall. The off-box checks never depend on it: they line the
copies up by message, and they test gaps against activity in UTC.

The brief is a prompt for a model, not a verdict. It numbers and hashes every
record, requires a citation for every claim, and tells the model not to change
the verdict. Run it against a local or tenant-controlled model: device
configurations carry credentials and keys.

## Hunting off the box

The analyzer reads what is on the device. The Hunts library holds hypotheses
for what an intruder could not edit, the data you already keep elsewhere: SIEM
syslog, sign-in logs, AAA accounting, the next firewall's sessions, proxies,
NetFlow. Filter it by *Data you need* to see the hunts your data supports. Each
hunt quotes its sources, says what normal looks like, and links the CVEs and
actors it came from. Two of them run in code (`--forwarded`, `--activity`); the
rest you run in your own tools, in whatever query language they speak.

## Using the threat intelligence

- **An indicator is not the actor.** Most published addresses are compromised
  third parties, VPN exits or shared hosting. Each value keeps the role its
  publisher gave it, and `unknown` when none was given. Read the role before you
  block, and never attribute on one.
- **Indicators have a shelf life.** Each set states when it was valid and when
  it was published. Infrastructure gets recycled, so an old address in your logs
  last week may be someone else's now.
- **Attribution is reported, not computed.** An actor record carries two
  confidences. The *link confidence* is the toolkit's: it measures provenance,
  and one reporting party is medium however authoritative. The *stated
  confidence* is the reporter's own words, verbatim.
- **The site shows values defanged; exports are refanged.** Paste from the
  export into your SIEM, not from the page.

## Exploited CVEs and BOD 26-04

The CVEs library has one record per CVE: CISA's KEV fields verbatim, the
CVE.org record, and everything the toolkit has for it (detections, artifacts,
hunts, hardening, playbooks). Read the BOD 26-04 forensic triage flag carefully:
- It is a deadline category. Every KEV entry added before the directive
  (2026-06-10) reads No, which means "added before BOD 26-04", not "no triage
  needed".
- A flagged CVE lists CISA's implementation steps with their target timelines,
  quoted.
- Exploitation dates are the primary sources' own words, quoted with the page
  they came from. A CVE without one has simply not been dated by a primary
  source.

## After triage

- **Compromised or likely:** treat credentials the device held as exposed (VPN
  users, LDAP bind accounts, local admins, certificates), hunt from the device
  into the network, and plan replacement or vendor-guided rebuild rather than
  in-place cleanup.
- **Follow the platform's response playbook, in its order:** preserve, contain,
  rotate, eradicate, recover, verify. Read its *do not* list first; most
  evidence is destroyed by a well-meant action taken too early. The toolkit
  never contains or remediates for you.
- **Suspicious:** find the second signal before you escalate. A hit in a
  different evidence class is what raises the verdict, and the off-box hunts are
  where most second signals come from.
- **No indicators:** close the listed gaps before closing the case. The most
  common honest outcome is "no indicators in the evidence available".
- **Telling people.** Say the verdict in the toolkit's words. "No indicators
  found in the evidence available" is not "clean", and "suspicious" is not
  "breached". Attach the evidence gaps; they are what a reader will ask about.

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

## Terms

| Term | Meaning here |
|---|---|
| evidence class | What a detection reads (web-logs, memory, persistence, offbox-logs...). Corroboration counts only across classes |
| tier | How much one hit says: `possible`, `likely`, `confirmed` |
| not evaluated | The detection did not have the evidence it needs. It never ran, so it did not pass |
| evidence gap | Something the analysis could not see, with how to close it |
| vendor-bundle | A step that writes to the device (a tech support file, `cpinfo`). Needs `--allow-bundle` |
| break-glass | A step that can crash, reload, reboot or image the device. Needs `--break-glass` and runs last |
| off-box | Data the device's owner keeps elsewhere, which an intruder on the device could not edit |
| baseline | Hashes from a known-good device of the same build |

