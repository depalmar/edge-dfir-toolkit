/*
   Volexity's rule for KNUCKLEBALL, the Python injector UTA0533 wrote to
   /usr/lib/python3.11/site-packages/deploy_new.py on SonicWall SMA 1000 appliances in 2026 and
   started from /etc/init.d/workplace, from its threat-intel repository
   (2026/2026-07-17 SonicWall/rules.yar), published with Volexity's post of 17 July 2026. Copied
   byte for byte. Its scan_context is "file,memory".

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

rule apt_malware_python_knuckleball: UTA0533 KNUCKLEBALL
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-07-06"
    description = "Detects KNUCKLEBALL, a python based injector malware, using string patterns."
    hash1 = "8c470301dcb7278f73e622f1950073567b34011c64b60cdfbb0f89803923a5a3"
    os = "linux"
    os_arch = "all"
    scan_context = "file,memory"
    severity = "high"
    report1 = "TIB-20260714B"
    last_modified = "2026-07-14T09:45:44Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13233
    version = 5

  strings:
    $s1 = "/tmp/.java_pid{pid}" ascii
    $s2 = "/tmp/.attach_pid{pid}" ascii
    $s3 = "timeout waiting for JVMTI attach socket" ascii
    $s4 = "workplace.startup.CommandStartup" ascii
    $s5 = "/var/run/control.unit.sock" ascii

    $func1 = "unit_put(" ascii
    $func2 = "check_gate(" ascii
    $func3 = "inject_jar(" ascii
    $func4 = "find_wp_pid(" ascii

  condition:
    2 of ($s*) or
    3 of ($func*)
}
