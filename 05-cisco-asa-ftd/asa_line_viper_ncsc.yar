/*
   NCSC's YARA rules for LINE VIPER, the shellcode loader RayInitiator deploys into lina, from
   its malware analysis report "RayInitiator & LINE VIPER" (September 2025). NCSC gives each
   "Precision: No false positives have been identified."
   Extracted in code from the PDF's text. The PDF wraps long lines; the only change is that
   wrapped lines are joined again - descriptions and hex strings with a space, rule names and
   base64 strings with nothing, since neither holds a space.
   The base64 strings in LINE_VIPER_shellcode_deobfuscation_routine were checked in code to be
   the base64 of that rule's own hex bytes at the three byte alignments, and the regexes in
   LINE_VIPER_shellcode_initial_execution to match the base64 of its hex pattern; a wrong join
   would break both.

   NCSC: "If a core dump is attempted before upgrading to Cisco's patched firmware and the device
   immediately reboots without producing a core dump, then this could indicate that LINE VIPER
   was deployed." The conditions read only the rules' strings, so the memory checks run them
   over every memory image in a case.

   Source: https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-rayinitiator-line-viper.pdf
   NCSC: "Detection mechanisms such as rules, signatures and scripts are licensed under the
   terms of the Open Government Licence v3.0 except where otherwise stated."
   (c) Crown copyright 2025. Contains public sector information licensed under the Open Government Licence v3.0:
   https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/
*/

rule LINE_VIPER_shellcode_deobfuscation_routine {
    meta:
        author = "NCSC"
        description = "Detects LINE VIPER Cisco ASA malware code as part of a shellcode deobfuscation routine."
        date = "2025/09/25"
    strings:
        $ = {48 8B 7F 08 48 8D 5F 70 49 C7 C1 00 18 00 00 49 C7 C0 20 00 00 00 48 89 DF 8A 01 32 07 48 FF C7 41 FF C8 4D 85 C0 75 F3 88 01 48 FF C1 41 FF C9 4D 85 C9 75 DA}
        $ = "SIt/CEiNX3BJx8EAGAAAScfAIAAAAEiJ34oBMgdI/8dB/8hNhcB184gBSP/BQf/JTYXJdd"
        $ = "iLfwhIjV9wScfBABgAAEnHwCAAAABIid+KATIHSP/HQf/ITYXAdfOIAUj/wUH/yU2FyXXa"
        $ = "Ii38ISI1fcEnHwQAYAABJx8AgAAAASInfigEyB0j/x0H/yE2FwHXziAFI/8FB/8lNhcl12"
    condition:
        any of them
}

rule LINE_VIPER_shellcode_initial_execution {
    meta:
        author = "NCSC"
        description = "Detects LINE VIPER Cisco ASA malware code as part of shellcode initial execution."
        date = "2025/09/25"
    strings:
        $ = {48 8D B7 80 00 00 00 BA 00 20 00 00 [19] 48 C7 C6 00 90 00 00 BA 07 00 00 00}
        $ = /SI23gAAAALoAIAAA[A-Za-z0-9+\/]{26}jHxgCQAAC6BwAAA/
        $ = /iNt4AAAAC6ACAAA[A-Za-z0-9+\/]{26}Ix8YAkAAAugcAAA/
        $ = /IjbeAAAAAugAgAA[A-Za-z0-9+\/]{26}SMfGAJAAALoHAAAA/
    condition:
        any of them
}

rule LINE_VIPER_rsa_encrypted_random_aes_key_generation {
    meta:
        author = "NCSC"
        description = "Detects LINE VIPER Cisco ASA malware code as part of RSA encrypted random AES key generation."
        date = "2025/09/25"
    strings:
        $ = {48 31 C0 49 89 06 49 89 46 08 49 83 C6 10 49 83 ED 10 4D 85 ED 75 D8 BF 30 00 00 00}
        $ = {0F 85 57 01 00 00 49 8B 44 24 08 48 83 F8 2F 7C 33 41 BD F0 02 00 00 4D 8D 74 24 10 49 8B 3E}
        $ = {85 C0 0F 8E EE 00 00 00 41 BD F0 02 00 00 4D 8D 7C 24 10 49 8B 3F 48 85 FF 74 0D 49 83 C7 10 49 83 ED 10 4D 85 ED 75 EB 4D 89 37 BF 70 00 00 00}
        $ = {48 85 C0 0F 84 3F 00 00 00 48 89 45 B0 BF 80 00 00 00 4C 89 EE 48 89 C2 48 8B 4D A8 41 B8 01 00 00 00}
    condition:
        3 of them
}

rule LINE_VIPER_aes_encrypted_tasking_and_exfiltration {
    meta:
        author = "NCSC"
        description = "Detects LINE VIPER Cisco ASA malware code as part of AES encrypted tasking and exfiltration."
        date = "2025/09/25"
    strings:
        $ = {48 31 C0 48 89 45 D8 49 89 FC 49 89 F5 49 89 D6 48 8B 47 08 48 89 45 B8 48 8D 40 40 48 89 45 E0 48 8D 70 E0 48 89 75 B0 48 8D 78 F0 48 89 7D E8 BA 10 00 00 00}
        $ = {48 85 C0 0F 84 EA 00 00 00 48 89 45 A8 4C 89 EF 48 89 C6 4C 89 F2 48 8B 4D A0 4C 8B 45 B0 4D 31 C9}
        $ = {48 85 C0 0F 84 82 00 00 00 49 89 C7 48 8B 7D E0 BE 00 01 00 00 48 8B 55 A0}
        $ = {48 8B 7D D0 49 83 C7 10 49 C1 EF 04 49 C1 E7 04 4C 89 FE 48 8D 55 D8}
    condition:
        3 of them
}

rule LINE_VIPER_icmp_tasking_shellcode_payloads {
    meta:
        author = "NCSC"
        description = "Detects LINE VIPER Cisco ASA malware code as part of ICMP tasking shellcode payloads."
        date = "2025/09/25"
    strings:
        $ = {55 53 41 54 41 55 41 56 41 57 48 89 E5 48 83 EC 60 48 31 C0 B9 07 00 00 00 48 8D 7D A8 F3 48 AB BF 01 00 00 00 BE 30 00 00 00}
        $ = {49 89 C7 48 C7 C2 38 DF FF FF 64 48 8B 0A 48 8B 99 00 01 00 00 48 89 81 00 01 00 00}
        $ = {49 8B 47 10 48 8D 55 B0 BE 01 20 01 00 4C 89 FF FF 90 90 00 00 00 48 8B 7D B0 48 85 FF 0F 84 3C 00 00 00}
        $ = {49 8B 47 10 BE 08 20 01 00 4C 89 FF 48 8D 55 A8 FF 90 90 00 00 00 48 8B 7D B0 49 89 7E 20 48 8B 7D A8 49 89 7E 28}
    condition:
        3 of them
}
