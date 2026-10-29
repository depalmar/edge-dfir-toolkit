/*
   Volexity's rule for UTA0576's privilege-escalation script, from its threat-intel repository
   (2026/2026-10-13 Ivanti/rules.yar), published with "A Series of Unauthenticated Events:
   Chained Exploitation of Ivanti Connect Secure Zero-Days" (13 October 2026). Copied byte for
   byte. Its own scan_context is "memory".

   Volexity: the delivered Python script "is executed via exec(), meaning the raw script is only
   ever stored in memory", and the privilege-escalation exploit "was passed via the in-memory
   Python script executed by the RCE Perl script". Volexity: "Volexity worked with Ivanti to
   collect memory and disk images of the impacted device along with analyzing core dumps that
   were generated as a result of exploitation."

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

rule exploit_py_ivanti_oct26: CVE_2026_104935 UTA0576
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-10-10"
    description = "Detection for EoP vuln implementation in Python used by UTA0576."
    hash1 = "25b95f47359c327e3a5ae5ac5cd147f8d9afd98092faf136822ee287e25e3dc8"
    os = "linux"
    os_arch = "all"
    scan_context = "memory"
    severity = "critical"
    report1 = "TIB-20261012"
    last_modified = "2026-10-12T19:36:10Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13500
    version = 3

  strings:
    $magic1 = "target dsinvoked broker is busy; stop retries and clear its current child" ascii
    $magic2 = "PATCH_LOCATOR arch=%s offset=%s sha256=%s encoding=%s open=%s call=%s evidence=%s"

    $pycombo1 = "import os,socket,time,_frozen_importlib_external as ie"
    $pycombo2 = "def say(*x): print(*x,flush=True)"

  condition:
    any of ($magic*) or
    all of ($pycombo*)
}
