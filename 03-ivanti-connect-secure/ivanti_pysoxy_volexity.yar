/*
   Volexity's rule for PySoxy, from its threat-intel repository (2024/2024-01-10 Ivanti Connect
   Secure/indicators/yara.yar), published with "Active Exploitation of Two Zero-Day
   Vulnerabilities in Ivanti Connect Secure VPN" (10 January 2024). Copied byte for byte; the
   file's other rules are for web servers, not the appliance, and are left out. Its own
   scan_context is "file,memory".

   Volexity: the attacker "created and executed a number of files from the system's /tmp/
   directory", including /tmp/s.py; "By carving files from the disk images", Volexity recovered
   a proxy utility "it believes was likely s.py. This was discovered to be a copy of PySoxy".
   PySoxy is a public tool, so the rule matches any copy of it, not only UTA0178's.

   Post: https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/
   Rules: https://github.com/volexity/threat-intel/tree/main/2024/2024-01-10%20Ivanti%20Connect%20Secure/indicators

   Volexity's licence, reproduced as its condition 1 requires:

   Copyright 2022 by Volexity, Inc.

   The 2-Clause BSD License

   Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

rule hacktool_py_pysoxy
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-01-09"
        description = "SOCKS5 proxy tool used to relay connections."
        hash1 = "e192932d834292478c9b1032543c53edfc2b252fdf7e27e4c438f4b249544eeb"
        os = "all"
        os_arch = "all"
        reference = "https://github.com/MisterDaneel/pysoxy/blob/master/pysoxy.py"
        report = "TIB-20240109"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-01-09T13:45:28Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10065
        version = 3

    strings:
        $s1 = "proxy_loop" ascii
        $s2 = "connect_to_dst" ascii
        $s3 = "request_client" ascii
        $s4 = "subnegotiation_client" ascii
        $s5 = "bind_port" ascii

    condition:
        all of them
}
