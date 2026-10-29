/*
   NCSC's YARA rules for the RayInitiator GRUB bootkit's stage code, from its malware analysis
   report "RayInitiator & LINE VIPER" (September 2025). NCSC gives each "Precision: No false
   positives have been identified."
   Extracted in code from the PDF's text. The PDF wraps long lines; the only change is that
   wrapped lines are joined again - descriptions and hex strings with a space, rule names and
   base64 strings with nothing, since neither holds a space.

   NCSC does not say which artefact holds the stage code. For a core dump it points to its
   Appendix 1 script, which looks for the bootkit's hook in lina's WebVPN XML element handler
   table, as CISA's RayDetect does. No hit from these rules does not clear RayInitiator.
   The conditions read only the rules' strings, so the memory checks run them over every
   memory image in a case.

   Source: https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-mar-rayinitiator-line-viper.pdf
   NCSC: "Detection mechanisms such as rules, signatures and scripts are licensed under the
   terms of the Open Government Licence v3.0 except where otherwise stated."
   (c) Crown copyright 2025. Contains public sector information licensed under the Open Government Licence v3.0:
   https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/
*/

rule RayInitiator_stage_1_search_for_booting_kernel_string {
    meta:
        author = "NCSC"
        description = "Detects RayInitiator GRUB bootkit stage 1 code that searches for the 'Booting the kernel' string."
        date = "2025/09/25"
    strings:
        $ = {BB 00 00 40 00 43 81 FB 00 00 60 00 0F 87 AB 00 00 00 8B 3B 81 FF 64 6F 6E 65 75 E9 83 C3 04 8B 3B 81 FF 2E 0A 42 6F 75 DC 83 C3 04 8B 3B 81 FF 6F 74 69 6E 75 CF 83 C3 04 8B 3B 81 FF 67 20 74 68 75 C2 83 C3 04 8B 3B 81 FF 65 20 6B 65 75 B5 83 C3 04 8B 3B 81 FF 72 6E 65 6C 75 A8 83 EB 14}
    condition:
        any of them
}

rule RayInitiator_stage_2_identify_syscall_table {
    meta:
        author = "NCSC"
        description = "Detects RayInitiator GRUB bootkit stage 2 code that identifies the Linux kernel syscall table."
        date = "2025/09/25"
    strings:
        $ = {49 89 E0 48 83 F8 30 0F 84 70 00 00 00 49 01 C0 49 8B 10 48 83 C0 08 66 85 D2 75 E4 BF ?? ?? 60 00 48 8B 3C 17 48 BE 6E 6D 69 5F 6D 61 78 5F}
    condition:
        any of them
}

rule RayInitiator_stage_3_install_phase_search_for_client_cert_fail_string {
    meta:
        author = "NCSC"
        description = "Detects RayInitiator GRUB bootkit stage 3 install phase code that searches for the 'client-cert-fail' string."
        date = "2025/09/25"
    strings:
        $ = {48 81 EE 00 00 00 08 48 B8 63 6C 69 65 6E 74 2D 63 49 B8 65 72 74 2D 66 61 69 6C 48 FF C6 48 39 D6 0F 87 D2 00 00 00 48 8B 3E 48 39 C7}
    condition:
        any of them
}

rule RayInitiator_stage_3_deploy_phase_copy_LINE_VIPER_shellcode_stub {
    meta:
        author = "NCSC"
        description = "Detects RayInitiator GRUB bootkit stage 3 deploy phase code that copies LINE VIPER shellcode stub and marks executable."
        date = "2025/09/25"
    strings:
        $ = {48 89 FA 48 83 C7 40 4C 89 CE B9 D0 01 00 00 F3 A4 48 89 D7 48 83 C7 40 48 89 3A 48 C1 EF 0C 48 C1 E7 0C BA 07 00 00 00 48 C7 C6 00 20 00 00}
    condition:
        any of them
}
