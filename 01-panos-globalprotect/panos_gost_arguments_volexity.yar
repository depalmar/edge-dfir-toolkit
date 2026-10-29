/*
   Volexity's rule for GOST tunnel arguments in small scripts such as cron jobs, from its
   threat-intel repository (2024/2024-04-12 Palo Alto Networks GlobalProtect/indicators/rules.yar),
   published with Volexity's post of 12 April 2024. Copied byte for byte. Its scan_context is
   "file", and it checks the file's size, so it never runs against memory. The post shows
   UTA0218's script versions that fetch GOST "to establish SOCKS5 and RTCP tunnels".

   Post:  https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/
   Rules: https://github.com/volexity/threat-intel/tree/main/2024/2024-04-12%20Palo%20Alto%20Networks%20GlobalProtect/indicators

   Volexity's licence, reproduced as its condition 1 requires:

   Copyright 2022 by Volexity, Inc.

   The 2-Clause BSD License

   Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

rule susp_any_gost_arguments
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-04-10"
        description = "Looks for common arguments passed to the hacktool GOST that are sometimes used by attackers in scripts (for example cronjobs etc)."
        os = "all"
        os_arch = "all"
        report = "TIB-20240412"
        scan_context = "file"
        severity = "critical"
        last_modified = "2024-04-12T13:06:14Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10425
        version = 2

    strings:
        $s1 = "-L=socks5://" ascii
        $s2 = "-L rtcp://" ascii

    condition:
        filesize < 10KB and
        any of them
}
