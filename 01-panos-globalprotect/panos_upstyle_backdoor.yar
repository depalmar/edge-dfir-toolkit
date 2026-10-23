/*
   UPSTYLE - Python backdoor UTA0218 attempted to deploy after CVE-2024-3400
   exploitation (Volexity and Unit 42 report the attempts failed). As written,
   persistence is a .pth file in site-packages, which Python executes at
   interpreter start. The payload reads base64 commands embedded in requests
   that nginx writes to the SSL VPN error log, appends output to a CSS file
   served by the GlobalProtect portal, then removes its log line and restores
   the files and their timestamps.

   PANOS_UPSTYLE_Payload uses the strings and stage logic of Volexity's own
   rule apt_malware_py_upstyle (rule_id 10429, TIB-20240412), credited here.
   Licence: https://github.com/volexity/threat-intel/blob/main/LICENSE.txt
   PANOS_Pth_Base64_Exec_Loader is this toolkit's generic heuristic.

   Reference: Volexity, 12 April 2024
   https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/
*/

rule PANOS_UPSTYLE_Payload
{
    meta:
        description = "UPSTYLE stages, using the strings Volexity published in apt_malware_py_upstyle"
        author = "Raymond DePalma (edge-dfir-toolkit); strings and condition from Volexity (threatintel@volexity.com)"
        date = "2026-10-23"
        reference = "https://github.com/volexity/threat-intel/blob/main/2024/2024-04-12%20Palo%20Alto%20Networks%20GlobalProtect/indicators/rules.yar"
        cve = "CVE-2024-3400"
        severity = "critical"
    strings:
        $stage1_str1 = "/opt/pancfg/mgmt/licenses/PA_VM"
        $stage1_str2 = "exec(base64."
        $stage2_str1 = "signal.signal(signal.SIGTERM,stop)"
        $stage2_str2 = "exec(base64."
        $stage3_str1 = "write(\"/*\"+output+\"*/\")"
        $stage3_str2 = "SHELL_PATTERN"
    condition:
        all of ($stage1*) or all of ($stage2*) or all of ($stage3*)
}

rule PANOS_Pth_Base64_Exec_Loader
{
    meta:
        description = "Python .pth file that executes a base64 blob at interpreter start - the UPSTYLE loader shape (toolkit heuristic)"
        author = "Raymond DePalma (edge-dfir-toolkit)"
        date = "2026-10-22"
        reference = "https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/"
        cve = "CVE-2024-3400"
        severity = "high"
    strings:
        $imp  = "import" ascii
        $exec = /exec\s*\(\s*(base64\.)?b64decode\s*\(/ ascii
        $blob = /[A-Za-z0-9+\/]{200,}={0,2}/ ascii
    condition:
        filesize < 100KB and $imp and $exec and $blob
}
