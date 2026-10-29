/*
   CISA's YARA rule for the FIRESTARTER injector (the lina_cs ELF), from CISA and NCSC Malware
   Analysis Report AR26-113A, "FIRESTARTER Backdoor" (23 April 2026). Copied from the page's
   Table 1, line breaks as published; the STIX bundle CISA publishes with the report carries the
   same strings and condition.

   CISA and NCSC: "Use the YARA rules to detect FIRESTARTER malware against either a disk image
   or core dump of a device." On disk the injector is /usr/bin/lina_cs or its staging copy
   /opt/cisco/platform/logs/var/log/svc_samcore.log, both in FXOS and not visible from the ASA CLI.
   The condition reads only the rule's strings, so the memory checks run it over every memory
   image in a case. Several of the strings are paths (/asa/bin/lina, /proc/%d/maps) that need not
   be unique to the malware; the rule needs five of its seven.

   Source: https://www.cisa.gov/news-events/analysis-reports/ar26-113a
   STIX:   https://www.cisa.gov/sites/default/files/2026-04/stix-FIRESTARTER.json
*/

rule CISA_261290_01 : FIRESTARTER backdoor captures_system_state_data cleans_traces_of_infection fingerprints_host persists_after_system_reboot
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
      tool_type = "unknown"
      description = "Detects CISCO Firepower FIRESTARTER injector samples"
  strings:
       $s1 = { 57 48 C1 EF 0C 48 C1 E7 0C BA 07 00 00 00 48 C7 C6 00 20 00 00 }
       $s2 = { 2f 6f 70 74 2f 63 69 73 63 6f 2f 70 6c 61 74 66 6f 72 6d 2f 6c 6f 67 73 2f 76 61 72 2f 6c 6f 67 2f }
       $s3 = { 2f 6f 70 74 2f 63 69 73 63 6f 2f 63 6f 6e 66 69 67 2f 70 6c 61 74 66 6f 72 6d 2f 72 6d 64 62 2f }
       $s4 = { 2f 76 61 72 2f 72 75 6e 2f 72 75 6e 6c 65 76 65 6c}
       $s5 = { 2f 70 72 6f 63 2f 25 73 2f 63 6f 6d 6d }
       $s6 = { 2f 70 72 6f 63 2f 25 64 2f 6d 61 70 73 }
       $s7 = { 2f 61 73 61 2f 62 69 6e 2f 6c 69 6e 61 }
  condition:
       5 of them
}
