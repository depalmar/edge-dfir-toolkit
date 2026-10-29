/*
   Volexity's rules for ORANGETAIL, the Behinder-like Java web shell UTA0533 injected into the
   workplace JVM of SonicWall SMA 1000 appliances in 2026, from its threat-intel repository
   (2026/2026-07-17 SonicWall/rules.yar), published with Volexity's post of 17 July 2026. Copied
   byte for byte. Both rules' scan_context is "file,memory". apt_webshell_java_orangetail_b
   matches the user-agent gate and names two samples: hash1 is agent_wp8.jar, which the post
   calls a modified Suo5, and hash2 is agent_wp9.jar, ORANGETAIL. The post says both payload
   classes gate on the same user agent, so the rule finds either.

   The post: KNUCKLEBALL writes both JARs to /tmp, injects them into the
   workplace.startup.CommandStartup process and deletes them, so on a running appliance they are
   found in memory.

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

rule apt_webshell_java_orangetail_b: UTA0533 ORANGETAIL
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-07-06"
    description = "Detection for the accept logic of ORANGETAIL, a custom Java webshell used by UTA0533."
    hash1 = "1e1e68bbb899450a57274a8b12082ed4e2040a2aae77014f20431689d2b4edee"
    hash2 = "ea9154e374e4f77bc2cf54282e23543573980342a85bc888cb23f20b8bbba081"
    os = "all"
    os_arch = "all"
    scan_context = "file,memory"
    severity = "critical"
    report1 = "TIB-20260714B"
    last_modified = "2026-07-14T09:45:38Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13240
    version = 6

  strings:
    $s1 = ".equals($1.getHeader(\"User-Agent\"))) {  javax.servlet.jsp.JspFactory" ascii
    $s2 = " $2.setStatus(404);  $2.setContentLength(0);  $2.flushBuffer();  return;" ascii

  condition:
    all of them
}

rule apt_webshell_java_orangetail: UTA0533 ORANGETAIL
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-07-06"
    description = "Detection for ORANGETAIL, a custom Java webshell used by UTA0533."
    hash1 = "ea9154e374e4f77bc2cf54282e23543573980342a85bc888cb23f20b8bbba081"
    os = "all"
    os_arch = "all"
    scan_context = "file,memory"
    severity = "critical"
    report1 = "TIB-20260714B"
    last_modified = "2026-07-14T09:45:31Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13239
    version = 5

  strings:
    $s1 = "agentmain called args="
    $s2 = "tryInject="
    $s3 = "agentmain ex:"
    $s4 = "javassist="
    $s5 = "tryInject exception"
    $s6 = "found loaded class:"

  condition:
    4 of ($s*)
}
