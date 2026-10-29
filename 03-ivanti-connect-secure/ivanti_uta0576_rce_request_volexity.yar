/*
   Volexity's rule for the CVE-2026-104935 exploit request, from its threat-intel repository
   (2026/2026-10-13 Ivanti/rules.yar), published with "A Series of Unauthenticated Events:
   Chained Exploitation of Ivanti Connect Secure Zero-Days" (13 October 2026). Copied byte for
   byte. Its own scan_context is "file,memory".

   Volexity: the request to the public welcome.cgi "names a different script in its headers,
   X-DSCGI-PATH: /home/webserver/htdocs/dana/fb/smb/wu.cgi". The appliance's own logs are not
   shown to keep request headers; a memory image, a packet capture or a reverse proxy's log can.

   Post: https://www.volexity.com/blog/2026/10/13/a-series-of-unauthenticated-events-chained-exploitation-of-ivanti-connect-secure-zero-days/
   Rules: https://github.com/volexity/threat-intel/tree/main/2026/2026-10-13%20Ivanti

   Volexity's licence, reproduced as its condition 1 requires:

   Copyright 2022 by Volexity, Inc.

   The 2-Clause BSD License

   Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

rule exploit_log_ivanti_rce: CVE_2026_104935
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-10-12"
    description = "Identifies files or memory regions containing request headers matching RCE vulnerability for Ivanti."
    os = "linux"
    os_arch = "all"
    scan_context = "file,memory"
    severity = "critical"
    report1 = "TIB-20261012"
    last_modified = "2026-10-12T19:35:53Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13503
    version = 1

  strings:
    $s1 = "X-DSCGI-PATH: /home/webserver/htdocs/dana/fb/smb/wu.cgi" ascii

  condition:
    $s1
}
