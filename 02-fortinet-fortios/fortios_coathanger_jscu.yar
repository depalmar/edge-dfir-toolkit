/*
   MIVD and AIVD's YARA rules for COATHANGER, from JSCU-NL's repository
   (github.com/JSCU-NL/COATHANGER, iocs/coathanger.yar), whose README lists "YARA rules as
   provided in the advisory" of 6 February 2024. The file is copied byte for byte below.

   File rules: each checks for an ELF header and a file size under 5 MB, so they read a disk
   image or recovered binaries, never a memory image. COATHANGER hides its own files on a
   running device, so a file to scan comes from an image taken off the device.

   Advisory: https://www.ncsc.nl/documenten/publicaties/2024/februari/6/mivd-aivd-advisory-coathanger-tlp-clear
   Repository: https://github.com/JSCU-NL/COATHANGER
   Licensed by JSCU-NL under the Apache License, Version 2.0 (the toolkit's own licence; see LICENSE).
*/

rule COATHANGER_beacon
{
    meta:
        description = "Detects COATHANGER beaconing code (GET / HTTP/2\nHost: www.google.com\n\n)"
        malware = "COATHANGER"
        author = "NLD MIVD - JSCU"
        date = "20240206"
    strings:
        $chunk_1 = {
            48 B8 47 45 54 20 2F 20 48 54
            48 89 45 B0
            48 B8 54 50 2F 32 0A 48 6F 73
            48 89 45 B8
            48 B8 74 3A 20 77 77 77 2E 67
            48 89 45 C0
            48 B8 6F 6F 67 6C 65 2E 63 6F
        }

    condition:
        uint32(0) == 0x464c457f and filesize < 5MB and
        any of them
}


rule COATHANGER_files
{
    meta:
        description = "Detects COATHANGER files by used filenames"
        malware = "COATHANGER"
        author = "NLD MIVD - JSCU"
        date = "20240206"
    strings:
        $1 = "/data2/"
        $2 = "/httpsd"
        $3 = "/preload.so"
        $4 = "/authd"
        $5 = "/tmp/packfile"
        $6 = "/smartctl"
        $7 = "/etc/ld.so.preload"
        $8 = "/newcli"
        $9 = "/bin/busybox"

    condition:
        (uint32(0) == 0x464c457f or uint32(4) == 0x464c457f)
        and filesize < 5MB and 4 of them
}
