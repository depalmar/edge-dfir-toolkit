/*
   CISA's YARA rule for the FIRESTARTER shellcode, from CISA and NCSC Malware Analysis Report
   AR26-113A, "FIRESTARTER Backdoor" (23 April 2026). Copied from the page's Table 1, line breaks
   as published; the STIX bundle carries the same strings and condition, and the same
   tool_type value "unknownk".

   CISA: FIRESTARTER "injects a block of shellcode 0x200 bytes before the end of the library's
   text segment" - libstdc++ inside the LINA process - so the shellcode is in memory, and in a
   core dump of LINA. CISA and NCSC: "Use the YARA rules to detect FIRESTARTER malware against
   either a disk image or core dump of a device."

   Reproduced as published: $3 reads B9 D0 01 00 F3 A4, where NCSC's RayInitiator stage 3
   deploy rule has B9 D0 01 00 00 F3 A4 for the same instruction run (a move into ECX takes a
   four-byte immediate). The condition needs 3 of the 4 strings, so it does not depend on $3.

   Source: https://www.cisa.gov/news-events/analysis-reports/ar26-113a
   STIX:   https://www.cisa.gov/sites/default/files/2026-04/stix-FIRESTARTER.json
*/

rule CISA_261290_02 : FIRESTARTER_shellcode backdoor captures_system_state_data cleans_traces_of_infection fingerprints_host persists_after_system_reboot
{
   meta:
      author = "CISA Code & Media Analysis"
      incident = "261290"
      date = "2026-4-3"
      last_modified = "20260406_732"
      actor = "n/a"
      family = "n/a"
      capabilities = "captures-system-state-data cleans-traces-of-infection fingerprints-host persists-after-system-reboot"
      malware_type = "backdoor"
      tool_type = "unknownk"
      description = "Detects CISCO Firepower FIRESTARTER_shellcode samples"
   strings:
       $1 = { 57 4C 8B 47 18 4D 85 C0 0F 84 C7 01 00 00 49 8B 38 48 85 FF }
       $2 = { 48 83 C6 08 4C 39 C6 0F 87 7A 01 00 00 4C 8B 0E }
       $3 = { 48 89 D7 4C 89 CE B9 D0 01 00 F3 A4 48 89 D7 57 48 C1 EF 0C 48 C1 E7 0C }
       $4 = { 0F 05 58 5F FF E0 90 90 }
   condition:
       3 of them
}
