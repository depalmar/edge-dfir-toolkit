/*
   Unit 42's YARA rule for the PEERSTITCH FortiGate implant, published with its October 2026
   report. Extracted in code from the page's own rule block and reproduced as published; only
   this comment is the toolkit's. The rule matches the implant's files, which sit in
   /data2/template/ and delete themselves; it runs only against files from an image.

   Reference: https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/
*/

rule u42_apt_linux_PEERSTITCH_fortigate_implant
{
  meta:
    author = "Unit 42 - PaloAltoNetworks"
    description = "Identifies FortiGate process memory patching implant (ptrace injector targeting miglogd/iked)"
    hash = "b9fb0b27ddd59b58d3ae53c7227298a3e0de1e6f868b9429ae21533bb9cd1e70"
    malware_family = "PEERSTITCH_fortigate_implant"

  strings:
    // ARM64 mmap shellcode template (.rodata 0x45A688)
    // Allocates 16KB RWX via mmap, writes trampoline, jumps to it
    // Full 45-byte sequence: MOV X0-X5,X8 setup -> SVC #0 -> MOV W1,#0xD4200000 -> STR -> BR X0
    $shellcode_template = {
      00 00 80 D2 // MOV X0, #0
      01 00 88 D2 // MOV X1, #0x4000
      E2 00 80 D2 // MOV X2, #7 (RWX)
      43 04 80 D2 // MOV X3, #0x22 (MAP_PRIVATE|MAP_ANONYMOUS)
      04 00 80 D2 // MOV X4, #0
      05 00 80 D2 // MOV X5, #0
      C8 1B 80 D2 // MOV X8, #0xDE (__NR_mmap)
      01 00 00 D4 // SVC #0
      01 84 BA 52 // MOV W1, #0xD4200000
      01 00 00 B9 // STR W1, [X0]
      00 00 1F D6 // BR  X0
    }
    // Injection payload entry prologue (.data 0x494048)
    // ADR+LDUR dispatch -> stack frame 0x110 -> bulk STP register save
    $injection_entry = {
      1E 00 00 10 // ADR X30, #0
      DE C3 40 F8 // LDUR X30, [X30, #0xC]
      C0 03 1F D6 // RET
      00 00 00 00
      00 00 00 00
      00 00 00 00
      FF 43 04 D1 // SUB SP, SP, #0x110
      E0 0F 00 F9 // STR X0, [SP, #0x18]
      E1 0B 02 A9 // STP X1, X2, [SP, #0x20]
      E3 13 03 A9 // STP X3, X4, [SP, #0x30]
      E5 1B 04 A9 // STP X5, X6, [SP, #0x40]
      E7 23 05 A9 // STP X7, X8, [SP, #0x50]
      E9 2B 06 A9 // STP X9, X10, [SP, #0x60]
      EB 33 07 A9 // STP X11, X12, [SP, #0x70]
      ED 3B 08 A9 // STP X13, X14, [SP, #0x80]
      EF 43 09 A9 // STP X15, X16, [SP, #0x90]
      F1 4B 0A A9 // STP X17, X18, [SP, #0xA0]
      F3 53 0B A9 // STP X19, X20, [SP, #0xB0]
      F5 5B 0C A9 // STP X21, X22, [SP, #0xC0]
      F7 63 0D A9 // STP X23, X24, [SP, #0xD0]
      F9 6B 0E A9 // STP X25, X26, [SP, #0xE0]
      FB 73 0F A9 // STP X27, X28, [SP, #0xF0]
      FD 7B 10 A9 // STP X29, X30, [SP, #0x100]
    }

    // Operational strings (.rodata 0x45A600-0x45A678)
    $s_miglogd = "/bin/miglogd"
    $s_iked = "/bin/iked"
    $s_match_ip = "169.254.0.1"
    $s_cover_path = "/tmp/apache2/conf/md-acme.conf"
    $s_cover_content = "#0 certs managed by ACME"
    $s_proc_mem = "/proc/%d/mem"
  condition:
    uint32(0) == 0x464C457F and (
      $shellcode_template or
      $injection_entry or
      (4 of ($s_*))
    )
}
