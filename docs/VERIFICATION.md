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
| ASA region check tier | Treated >1 executable region as the indicator | Same, but the detail now says 2 (occasionally 5) can be normal and asks for review | NCSC-UK LINE DANCER analysis |
| LINE RUNNER filename (`EDGE-PACK-0006`) | `client_bundle_install\.zip` | `client_bundle[\w-]*\.zip` | Talos: the ASA loader matches `client_bundle*.zip`, so other names are possible |
| Ivanti injection endpoints (`EDGE-PACK-0007`) | `license/keys-status` or `cloud-server-test-connection` | `license/keys-status` only | keys-status confirmed by Assetnote; cloud-server-test-connection could not be confirmed as a sink from a primary |

### Corrections to facts and attribution

| Item | Was | Now | Basis |
|---|---|---|---|
| UTA0576 motivation | espionage | financial; Volexity's own words quoted | Volexity, 13 Oct 2026: "low confidence" assessment that UTA0576 is a criminal actor |
| Ivanti syslog blocking | Attributed to SPAWN-family malware | iptables DROP rules and the read-write remount were the operator's commands; SPAWNSLOTH suppresses logging in-process | Mandiant, 8 Jan 2025 |
| SPAWNSLOTH | "edited local logs" | suppresses logging while the SSH backdoor runs; `sed` removal was manual | Mandiant, 8 Jan 2025 |
| Ivanti 2026 in-memory patch | "restored on disk", "no on-disk implant" | library patched in memory only (on-disk copy never modified), patch restored; on-disk tooling still in `/tmp` and `/data/.icscap/` | Volexity, 13 Oct 2026 |
| CISA AA24-060B ICT wording | "then-current external ICT" | "previous external ICT" | AA24-060B text |
| Ivanti web shells | CGI and Perl | CGI, Perl and Python (GIFTEDVISITOR and WIREFIRE are Python) | Mandiant, 11 Jan 2024 |
| CVE-2024-3400 trigger (`EDGE-PACK-0001`) | "through device telemetry" | telemetry was the original trigger; vendor later said it need not be enabled | Palo Alto advisory, Unit 42 |
| PAN-OS "Level 3" | Attributed to the vendor advisory | Attributed to Unit 42 | The level scheme is not in the advisory |
| CVE-2025-6543 (`EDGE-PACK-0004`) | Listed as code execution | Removed from the RCE pack; vendor titles it memory overflow / DoS, RCE only from NCSC-NL field reports | Citrix CVE record, NCSC-NL |
| ASA `show version` | "last reload reason" | uptime only; ASA does not print a reload reason (that is IOS) | Cisco ASA documentation |
| RayDetect scope | Unscoped | ASA 5500-X on 9.12 and 9.14 only; not Firepower or ASAv | RayDetect README |
| NetScaler persistent disk | `da0` | `da0`, `ad0` or `ada0` by model, BIOS and hypervisor | Citrix support articles, fox-it README |
| FortiOS filesystem hash | 7.2.6+ | 7.0.13+, 7.2.6+ and 7.4.0+ | Fortinet docs and community tech tip |
| UNC6148 / Abyss link | "moderate confidence overlap with Abyss" | GTIG gives no confidence level for the Abyss link; its "moderate confidence" concerns zero-day use | GTIG, 16 Jul 2025 |
| SonicWall fixed firmware | 10.2.2.2-92sv | 10.2.1.15-81sv | GTIG, 16 Jul 2025 |
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
- CISA ED 25-03 and the 13 Oct 2026 Ivanti alert: cisa.gov refused automated fetches; content confirmed through mirrors and press.
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
| `EDGE-PACK-0009` vpnd detection | `Invalid filename`, which is not the blocked-traversal message | `Suspected path traversal attack from` | Check Point sk182336 hunting guidance |
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
| F5 System Scanner | `--scan-procs` named as the process check | K000160515 |

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

## Device verification

| Date | Platform / release | Step | Change | Basis |
|---|---|---|---|---|
| - | - | - | No real-device runs yet. | - |
