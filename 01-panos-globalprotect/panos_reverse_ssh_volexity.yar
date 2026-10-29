/*
   Volexity's rules for the reverse-SSH tool UTA0218 ran on GlobalProtect firewalls after
   exploiting CVE-2024-3400, from its threat-intel repository (2024/2024-04-12 Palo Alto Networks
   GlobalProtect/indicators/rules.yar), published with Volexity's post of 12 April 2024. Copied
   byte for byte. Both rules' scan_context is "file,memory", and both name the same sample
   (hash1 161fd76c...), the binary the post shows fetched to /tmp/lowdp and started with
   "nohup /tmp/lowdp -l -p 31289". reverse-ssh is a public tool, so the rules match any copy.

   Volexity says customers cannot collect the firewall's memory themselves; the vendor's
   technical support has to.

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

rule hacktool_golang_reversessh_fahrj
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-04-10"
        description = "Detects a reverse SSH utility available on GitHub. Attackers may use this tool or similar tools in post-exploitation activity."
        hash1 = "161fd76c83e557269bee39a57baa2ccbbac679f59d9adff1e1b73b0f4bb277a6"
        os = "all"
        os_arch = "all"
        reference = "https://github.com/Fahrj/reverse-ssh"
        report = "TIB-20240412"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-04-12T13:06:01Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10423
        version = 5

    strings:
        $fun_1 = "createLocalPortForwardingCallback"
        $fun_2 = "createReversePortForwardingCallback"
        $fun_3 = "createPasswordHandler"
        $fun_4 = "createPublicKeyHandler"
        $fun_5 = "createSFTPHandler"
        $fun_6 = "dialHomeAndListen"
        $fun_7 = "createExtraInfoHandler"
        $fun_8 = "createSSHSessionHandler"
        $fun_9 = "createReversePortForwardingCallback"

        $proj_1 = "github.com/Fahrj/reverse-ssh"

    condition:
        any of ($proj_*) or
        4 of ($fun_*)
}

rule susp_any_jarischf_user_path
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-04-10"
        description = "Detects paths embedded in samples in released projects written by Ferdinand Jarisch, a pentester in AISEC. These tools are sometimes used by attackers in real world intrusions."
        hash1 = "161fd76c83e557269bee39a57baa2ccbbac679f59d9adff1e1b73b0f4bb277a6"
        os = "all"
        os_arch = "all"
        report = "TIB-20240412"
        scan_context = "file,memory"
        severity = "high"
        last_modified = "2024-04-15T13:48:06Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10424
        version = 4

    strings:
        $proj_1 = "/home/jarischf/"

    condition:
        any of ($proj_*)
}
