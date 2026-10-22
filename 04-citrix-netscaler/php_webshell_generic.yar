/*
   Small PHP web shells of the kind dropped under appliance web roots after
   code-execution flaws (NetScaler 2023 mass exploitation, PAN-OS management
   interface 2024). Scoped to small files: appliance web roots hold few PHP
   files and shells are tiny, so the size cap removes most framework noise.

   These rules are for appliance web roots. On a general web server they will
   match plenty of legitimate admin tooling.
*/

rule PHP_Webshell_Eval_Decoder
{
    meta:
        description = "eval of decoded or decompressed input"
        author = "Raymond DePalma (edge-dfir-toolkit)"
        date = "2026-10-22"
        reference = "https://www.nccgroup.com/research/approximately-2000-citrix-netscalers-backdoored-in-mass-exploitation-campaign/"
        severity = "high"
    strings:
        $php = "<?" ascii
        $e1 = /eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|rawurldecode)\s*\(/ nocase ascii
        $e2 = /assert\s*\(\s*(base64_decode|gzinflate|str_rot13)\s*\(/ nocase ascii
    condition:
        filesize < 512KB and $php and any of ($e*)
}

rule PHP_Webshell_Request_To_Exec
{
    meta:
        description = "request parameter passed straight to a command or code execution sink"
        author = "Raymond DePalma (edge-dfir-toolkit)"
        date = "2026-10-22"
        reference = "https://github.com/fox-it/citrix-netscaler-triage"
        severity = "high"
    strings:
        $php = "<?" ascii
        $s1 = /(system|passthru|shell_exec|exec|popen|proc_open|eval|assert)\s*\(\s*(@\s*)?\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/ nocase ascii
        $s2 = /array_(filter|map|walk)\s*\(\s*(array\s*\()?\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase ascii
        $s3 = /preg_replace\s*\(\s*['"][^'"]{1,64}\/e['"]/ nocase ascii
        $s4 = /create_function\s*\([^)]{0,64}\$_(GET|POST|REQUEST|COOKIE)/ nocase ascii
    condition:
        filesize < 512KB and $php and any of ($s*)
}

rule PHP_Webshell_Variable_Function_Call
{
    meta:
        description = "function name taken from the request and called - a common one-line shell"
        author = "Raymond DePalma (edge-dfir-toolkit)"
        date = "2026-10-22"
        severity = "medium"
    strings:
        $php = "<?" ascii
        $v1 = /\$\w{1,16}\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*;\s*@?\$\w{1,16}\s*\(/ nocase ascii
    condition:
        filesize < 64KB and $php and $v1
}
