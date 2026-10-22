/*
   UNC3886 TINYSHELL-based backdoors on Juniper Junos (Mandiant, 12 March 2025).
   Strings are the magic values, kill string and RC4 keys Mandiant published for
   the irad, lmpad and jdosd variants. For files recovered from a device through
   JTAC or an image - the Junos CLI cannot read the binaries.

   Reference: https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers
*/

rule Junos_UNC3886_TINYSHELL_Published_Strings
{
    meta:
        description = "Magic, kill string or RC4 key published for the UNC3886 Junos TINYSHELL variants"
        author = "Raymond DePalma (edge-dfir-toolkit)"
        date = "2026-10-22"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers"
        cve = "CVE-2025-21590"
        severity = "critical"
    strings:
        $irad_magic = "uSarguuS62bKRA0J" ascii
        $irad_kill  = "1spCq0BMbJwCoeZn" ascii
        $lmpad_rc4  = "0b3330c0b41d1ae2" ascii
        $jdosd_rc4  = "4fd37426-65dd-4a8d-8ba6-1382a011dae9" ascii
    condition:
        filesize < 20MB and any of them
}
