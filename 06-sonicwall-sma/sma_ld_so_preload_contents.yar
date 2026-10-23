/*
   OVERSTEP persistence through the dynamic linker's preload file on SonicWall SMA 100
   (Google Threat Intelligence Group, 16 July 2025; hunting guidance updated 16 September 2025).

   GTIG: "Presence of the file /etc/ld.so.preload on a disk image with greater than 2 bytes of
   contents. This file should not exist with actual contents on a standard SMA appliance, and
   the rootkit will hide it from a live system."

   The rule is GTIG's size threshold and nothing more, so a present-but-empty (or 1-2 byte)
   file is evaluated and does not fire. Run it against /etc/ld.so.preload from an offline image,
   both the root filesystem and the extracted INITRD (OVERSTEP's rc.fwboot change writes
   /usr/lib/libsamba-errors.so.6 into the INITRD copy).

   Reference: https://cloud.google.com/blog/topics/threat-intelligence/sonicwall-secure-mobile-access-exploitation-overstep-backdoor
*/

rule SonicWall_SMA_LD_SO_Preload_Has_Contents
{
    meta:
        description = "ld.so.preload with more than 2 bytes of contents (GTIG's OVERSTEP hunting threshold)"
        author = "Raymond DePalma (edge-dfir-toolkit)"
        date = "2026-10-23"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/sonicwall-secure-mobile-access-exploitation-overstep-backdoor"
        severity = "high"
    condition:
        filesize > 2
}
