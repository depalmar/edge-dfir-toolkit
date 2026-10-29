/*
   NCSC's YARA rule for LINE DANCER, from its Malware Tipper "Line Dancer: In-memory shellcode
   loader targeting Cisco Adaptive Security Appliance (ASA) devices" (TLP:CLEAR, 2024).
   Extracted in code from the PDF's text. The PDF wraps long lines; the only change is that
   wrapped lines are joined again - descriptions and hex strings with a space, rule names and
   base64 strings with nothing, since neither holds a space.

   NCSC: "Line Dancer has only been seen in memory and hence no file hash has been provided";
   it sat in a 20KB region that "cannot be dumped with a copy system:memory/text CLI command".
   The rule needs a memory image that holds that region: a hypervisor snapshot of an ASAv, or a
   core dump - which LINE DANCER could turn into a reload, so collect every live step first.
   The condition reads only the rule's strings, so the memory checks run it over every memory
   image in a case.

   Source: https://www.ncsc.gov.uk/sites/default/files/documents/ncsc-tip-line-dancer.pdf
   (c) Crown copyright 2024. Contains public sector information licensed under the Open Government Licence v3.0:
   https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/
*/

rule Line_Dancer {
    meta:
        author = "NCSC"
        description = "Targets code sections of Line Dancer, a shellcode loader targeting Cisco ASA devices."
    strings:
        $ = {48 8D 5E 20 48 8D 3D BB FF FF FF BA 20 00 00 00}
        $ = {4C 89 EE 44 89 F2 48 8D 3D 9A 27 00 00}
        $ = {41 FF D7 41 5F 41 5E 41 5D 41 5C 5B 5D 48 C7 C0 01 00 00 00 5F}
    condition:
        all of them
}
