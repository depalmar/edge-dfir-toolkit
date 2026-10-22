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

## Device verification

| Date | Platform / release | Step | Change | Basis |
|---|---|---|---|---|
| - | - | - | No real-device runs yet. | - |
