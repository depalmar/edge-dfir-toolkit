/*
   SHA256 values Google Threat Intelligence Group published for OVERSTEP on SonicWall SMA 100
   (16 July 2025, Host-Based IOCs table):
     /cf/xxx.elf, /cf/libsamba-errors.so.6, /usr/lib/libsamba-errors.so.6 - OVERSTEP
     /etc/rc.d/rc.fwboot - "Modified legitimate boot RC file"
   The values are the ones parsed into artifacts/intel/iocs/EDGE-IOC-0008. A file with another
   name and the same hash is still a hit; a rebuilt or modified sample will not match, so no hit
   is not a clean result.

   Reference: https://cloud.google.com/blog/topics/threat-intelligence/sonicwall-secure-mobile-access-exploitation-overstep-backdoor
*/

import "hash"

rule SonicWall_SMA_OVERSTEP_Published_Hash
{
    meta:
        description = "File matching a SHA256 GTIG published for OVERSTEP or its modified rc.fwboot"
        author = "Raymond DePalma (edge-dfir-toolkit)"
        date = "2026-10-23"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/sonicwall-secure-mobile-access-exploitation-overstep-backdoor"
        severity = "critical"
    condition:
        filesize < 20MB and (
            hash.sha256(0, filesize) == "b28d57269fe4cd90d1650bde5e9056116de26d211966262e59359d0e2a67d473" or
            hash.sha256(0, filesize) == "f0e0db06ca665907770e2202957d3eccd5a070acac1debaf0889d0d48c10e149"
        )
}
