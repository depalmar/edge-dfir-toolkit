/*
   Mandiant's hunting rules for the January 2024 Ivanti Connect Secure web shells and
   credential harvester (BUSHWALK, CHAINLINE, LIGHTWIRE, WARPWIRE), published in "Cutting
   Edge, Part 2" (31 January 2024). Extracted in code from the page. Changes: wrapped meta
   descriptions are joined with a space, and the LIGHTWIRE regex, which the page wraps
   straight after the backslash of "\(", is joined back. Mandiant's FRAMESTING rule is left
   out: its string wraps after a comma and the page does not show whether a space belongs
   there.

   The shells sit in system files a customer cannot read; these run only against files
   from a VM snapshot, the external ICT's snapshot or an image.

   Reference: https://cloud.google.com/blog/topics/threat-intelligence/investigating-ivanti-zero-day-exploitation
*/

rule M_Hunting_Webshell_BUSHWALK_1 {
  meta:
    author = "Mandiant"
    description = "This rule detects BUSHWALK, a webshell written in Perl CGI that is embedded into a legitimate Pulse Secure file to enable file transfers"

  strings:
    $s1 = "SafariiOS" ascii
    $s2 = "command" ascii
    $s3 = "change" ascii
    $s4 = "update" ascii
    $s5 = "$data = RC4($key, $data);" ascii
  condition:
    filesize < 5KB
    and all of them
}

rule M_Hunting_Webshell_CHAINLINE_1 {
  meta:
    author = "Mandiant"
    description = "This rule detects the CHAINLINE webshell, which receives RC4 encrypted commands and returns the execution result"
    md5 = "3045f5b3d355a9ab26ab6f44cc831a83"
  strings:
    $s1 = "crypt(command: str)" ascii
    $s2 = "tmp[i] = chr(ord(tmp[i])" ascii
    $s3 = "ord(RC4_KEY[i % len(RC4_KEY)])" ascii
    $s4 = "class Health(Resource)" ascii
    $s5 = "crypt(base64.b64decode(command.encode(" ascii
    $s6 = "base64.b64encode(crypt(result)" ascii
    $s7 = "{\"message\": 'ok', \"stats\": result}" ascii
  condition:
    filesize < 100KB and
    any of them
}

rule M_Hunting_Webshell_LIGHTWIRE_4 {
  meta:
    author = "Mandiant"
    description = "Detects LIGHTWIRE based on the RC4 decoding and execution 1-liner."
    md5 = "3d97f55a03ceb4f71671aa2ecf5b24e9"
  strings:
    $re1 = /eval\{my.{1,20}Crypt::RC4->new\(\".{1,50}->RC4\(decode_base64\(CGI::param\(\'.{1,30};eval\s\$.{1,30}\"Compatibility\scheck:\s\$@\";\}/
  condition:
    filesize < 1MB and all of them
}

rule M_Hunting_CredTheft_WARPWIRE_strings
{
    meta:
        author = "Mandiant"
        description = "Detects strings within WARPWIRE credential harvester"
        md5 = "b15f47e234b5d26fb2cc81fc6fd89775"
    strings:
        $header = "function SetLastRealm(sValue) {"

        // password fields
        $username = "document.frmLogin.username.value;"
        $password = "document.frmLogin.password.value;"

        // post version
        $btoa = "btoa("
        $xhr_post = /xhr.open\(.POST.,( )?url,/

        // get version
        $xhr_get = /xhr.open\(.GET.,( )?url,/
        $xhr_send = "xhr.send(null);"

    condition:
        $header in (0..100)
        and $password in (@username[1]..@username[1]+100)
        and ((#btoa > 1 and $xhr_post) or ($xhr_send in (@xhr_get[1]..
@xhr_get[1]+50)))
}
