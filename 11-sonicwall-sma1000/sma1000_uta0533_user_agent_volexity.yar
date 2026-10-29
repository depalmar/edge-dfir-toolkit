/*
   Volexity's rule for the user agent UTA0533's SonicWall SMA 1000 implants gate on, from its
   threat-intel repository (2026/2026-07-17 SonicWall/rules.yar), published with Volexity's post of
   17 July 2026. Copied byte for byte. Its scan_context is "file,memory", and Volexity describes it
   as identifying "any blob" carrying the string. The post: the string "resembles a legitimate
   user agent but uses version numbers that are inconsistent with any real-world user agent".
   It names KNUCKLEBALL as its sample, so a match there is also a KNUCKLEBALL match; in a proxy
   or web log it is a request made with the actor's user agent.

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

rule apt_malware_any_uta0533_ua: UTA0533
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-07-06"
    description = "Identify any blob containing a bogus user-agent used in different components of an attack attributed to UTA0533."
    hash1 = "8c470301dcb7278f73e622f1950073567b34011c64b60cdfbb0f89803923a5a3"
    os = "all"
    os_arch = "all"
    scan_context = "file,memory"
    severity = "critical"
    report1 = "TIB-20260714B"
    last_modified = "2026-07-14T09:45:26Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13237
    version = 3

  strings:
    $s1 = "Mozilla/6.0 (Windows NT 11.0; Win64; x64) AppleWebKit/1537.136 (KHTML, like Gecko) Chrome/149.0.0.1 Safari/1537.136" ascii

  condition:
    $s1
}
