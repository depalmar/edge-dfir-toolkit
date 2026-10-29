/*
   Volexity's rule for ROOTRUN, the setuid privilege-escalation utility UTA0533 wrote to
   /usr/bin/xzfind on SonicWall SMA 1000 appliances in 2026, from its threat-intel repository
   (2026/2026-07-17 SonicWall/rules.yar), published with Volexity's post of 17 July 2026. Copied
   byte for byte. Its scan_context is "file,memory". The name xzfind is the actor's choice; the
   rule reads the binary's strings, so a renamed copy still matches.

   Post:  https://www.volexity.com/blog/2026/07/17/proxying-to-compromise-sonicwall-secure-mobile-access-0-day-exploitation/
   Rules: https://github.com/volexity/threat-intel/tree/main/2026/2026-07-17%20SonicWall

   Volexity's licence, reproduced as its condition 1 requires:

   Copyright 2022 by Volexity, Inc.

   The 2-Clause BSD License

   Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

rule apt_malware_linux_rootrun: UTA0533 ROOTRUN
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-07-06"
    description = "Detects rootrun a setuid privilege escalation utility for Linux written in C using strings."
    hash1 = "81a9af3846bad3a1107164ff7cf0a08e020b31a3b32fd17866e17d4c1565f7f2"
    os = "linux"
    os_arch = "all"
    scan_context = "file,memory"
    severity = "high"
    last_modified = "2026-07-14T08:18:49Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13232
    version = 4

  strings:
    $s1 = "rootrun" ascii
    $s2 = "execlp" ascii
    $s3 = "Usage: rootrun rootrun <command>\n" ascii
    $s4 = "Failed to setuid" ascii

  condition:
    all of them
}
