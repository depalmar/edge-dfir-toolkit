/*
   UPSTYLE - Python backdoor deployed after CVE-2024-3400 exploitation.
   Persistence was a .pth file in site-packages, which Python executes at
   interpreter start. The payload read base64 commands embedded in requests
   that nginx wrote to the SSL VPN error log, wrote output into a CSS file
   served by the GlobalProtect portal, then removed its log lines and restored
   file timestamps.

   Reference: Volexity, 12 April 2024
   https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/
*/

rule PANOS_UPSTYLE_Payload
{
    meta:
        description = "UPSTYLE decoded payload: command channel through the SSL VPN error log and output through a portal CSS file"
        author = "Raymond DePalma (edge-dfir-toolkit)"
        date = "2026-10-22"
        reference = "https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/"
        cve = "CVE-2024-3400"
        severity = "critical"
    strings:
        $log  = "sslvpn_ngx_error.log" ascii
        $cmd  = "img\\[" ascii
        $css1 = "bootstrap.min.css" ascii
        $css2 = "global-protect/portal/css" ascii
        $ts1  = "os.utime" ascii
        $b64  = "b64decode" ascii
    condition:
        filesize < 200KB and $log and ($cmd or 1 of ($css*)) and ($ts1 or $b64)
}

rule PANOS_Pth_Base64_Exec_Loader
{
    meta:
        description = "Python .pth file that executes a base64 blob at interpreter start - the UPSTYLE loader shape"
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
