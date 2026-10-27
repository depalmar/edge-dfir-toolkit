/*
   Mandiant's own YARA rules for the SPAWN family, PHASEJAM and DRYHOOK, published by
   Google Threat Intelligence Group with its Ivanti Connect Secure reports of January 2025
   (CVE-2025-0282) and April 2025 (CVE-2025-22457). Extracted in code from the saved pages
   and reproduced as Mandiant printed them; the only change is that meta descriptions the
   blog wraps across lines are joined with single spaces, because a YARA string cannot hold
   a raw newline. Several are hunting rules ("Hunting rule ..." in their description).

   These match files on the appliance's root filesystem, which a customer cannot read. They
   run only against files from a VM snapshot, an external ICT snapshot or a vendor-assisted
   image; with none of those ingested, the detection is not evaluated.

   References:
     https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day
     https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-exploiting-critical-ivanti-vulnerability
*/

rule M_APT_Installer_SPAWNSNAIL_1
{
    meta:
        author = "Mandiant"
        description = "Detects SPAWNSNAIL. SPAWNSNAIL is an SSH backdoor targeting Ivanti devices. It has an ability to inject a specified binary to other process, running local SSH backdoor when injected to dsmdm process, as well as injecting additional malware to dslogserver"
        md5 = "e7d24813535f74187db31d4114f607a1"

    strings:
        $priv = "PRIVATE KEY-----" ascii fullword

        $key1 = "%d/id_ed25519" ascii fullword
        $key2 = "%d/id_ecdsa" ascii fullword
        $key3 = "%d/id_rsa" ascii fullword

        $sl1 = "[selinux] enforce" ascii fullword
        $sl2 = "DSVersion::getReleaseStr()" ascii fullword

        $ssh1 = "ssh_set_server_callbacks" ascii fullword
        $ssh2 = "ssh_handle_key_exchange" ascii fullword
        $ssh3 = "ssh_add_set_channel_callbacks" ascii fullword
        $ssh4 = "ssh_channel_close" ascii fullword

    condition:
        uint32(0) == 0x464c457f and $priv and any of ($key*)
and any of ($sl*) and any of ($ssh*)
}

rule M_APT_Installer_SPAWNANT_1
{
    meta:
        author = "Mandiant"
        description = "Detects SPAWNANT. SPAWNANT is an Installer targeting Ivanti devices. Its purpose is to persistently install other malware from the SPAWN family (SPAWNSNAIL, SPAWNMOLE) as well as drop additional webshells on the box."

    strings:
        $s1 = "dspkginstall" ascii fullword
        $s2 = "vsnprintf" ascii fullword
        $s3 = "bom_files" ascii fullword
        $s4 = "do-install" ascii
        $s5 = "ld.so.preload" ascii
        $s6 = "LD_PRELOAD" ascii
        $s7 = "scanner.py" ascii

    condition:
        uint32(0) == 0x464c457f and 5 of ($s*)
}

rule M_Tunneler_SPAWNMOLE_3
{
    meta:
        author = "Mandiant"
        description = "Hunting rule looking for strings and code identified in SPAWNMOLE samples"
        md5 = "a638fd203ddb540d0484d8e00490df06"
    strings:
        $str1 = "/proc/self/exe"
        $str2 = "/proc/%d/maps"
        $str3 = "=> encrypt buf"
        $str4 = "=> decrypt buf"
        $str5 = "%s    <malformed>"
        $comparison1 = { 3C 16 74 [1] 0F B6 [2] 3C 03 74 [1] 0F B6 [2] 3C 01 0F 85 }
        $comparison2 = { 81 [2] E2 E3 49 FB 0F 85 [4] 81 [2] 61 83 C3 1B 0F 85}
        $code1 = { 8D 55 B8 8B 45 F0 01 D0 0F B6 10 8B 4D F0 8B 45 0C 01 C8 0F
B6 00 31 C2 8D 4D B8 8B 45 F0 01 C8 88 10 83 45 F0 01 83 7D F0 2F 7E D4 }
        $code2 = { 81 7D E8 E2 E3 49 FB 0F 85 CD 00 00 00 81 7D E4 61 83 C3 1B }
    condition:
        uint32(0) == 0x464c457f and
        (all of ($s*)) and
        (1 of ($comparison*)) and
        (1 of ($code*))
}

rule M_Dropper_PHASEJAM_1 {
    meta:
        author = "Mandiant"
        description = "Hunting rule looking for strings identified in the PHASEJAM dropper"
        md5 = "d18e5425ecd9608ecb992606b974e15d"
	strings:

		$str1 = "AccessAllow()"
		$str2 = "/jam/getComponent.cgi"
		$str3 = "jam/getComponent.cgi.bak"
		$str4 = "sh=$(echo CnN1Y"
		$str5 = "up=$(echo CnN1Y"
		$str6 = "grep -q 'sub AccessAllow()'"
		$str7 = "cp -f /home/bin/remotedebug /home/bin/remotedebug.bak"
		$str8 = "chmod 777 /home/bin/remotedebug.bak"
		$str9 = "cp -f /home/perl/DSUpgrade.pm /home/perl/DSUpgrade.pm.bak"
		$str10 = "pkill cgi-server"
	condition:
		8 of them and filesize < 20KB

}

rule M_Credtheft_DRYHOOK_1 {
    meta:
        author = "Mandiant"
        description = "Hunting rule looking for strings identified in the DRYHOOK credential stealer"
        md5 = "61bb586dc4e047ab081ef6ca65684e48"
	strings:

		$str1 = "/home/perl/DSAuth.pm"
		$str2 = "replace_content"
		$str3 = "replace1_content"
		$str4 = "replace2_content"
		$str5 = "pkill cgi-server"
		$str6 = "setPrompt ="
		$str7 = "runSignin = \\*DSAuthc::RealmSignin_runSignin"
		$str8 = "/bin/mount -o remount,rw / > /dev/null 2>&1"
		$str9 = {64 61 74 61 20 3d 20 72 65 2e 73 75 62 28 62 22
5c 2a 72 75 6e 53 69 67 6e 69 6e 45 42 53 4c 20 3d 2e 2a 3b 22 2c
62 61 73 65 36 34 2e 62 36 34 64 65 63 6f 64 65 28 72 65 70 6c 61
63 65 32 5f 63 6f 6e 74 65 6e 74 2e 65 6e 63 6f 64 65 28 29 29 2e 64
65 63 6f 64 65 28 29 2e 65 6e 63 6f 64 65 28 22 75 6e 69 63 6f 64 65
5f 65 73 63 61 70 65 22 29 2c 64 61 74 61 29}
	condition:
		8 of them and filesize < 20KB

}

rule M_Utility_SPAWNSNARE_1 {
    meta:
    	 author = "Mandiant"
        description = "SPAWNSNARE is a utility written in C that targets Linux systems by extracting the uncompressed Linux kernel image into a file and encrypting it with AES."

    strings:
        $s1 = "\x00extract_vmlinux\x00"
        $s2 = "\x00encrypt_file\x00"
        $s3 = "\x00decrypt_file\x00"
        $s4 = "\x00lbb_main\x00"
        $s5 = "\x00busybox\x00"
        $s6 = "\x00/etc/busybox.conf\x00"

    condition:
        uint32(0) == 0x464c457f
        and all of them

}

rule M_APT_Utility_SPAWNSLOTH_2
{
    meta:
        author = "Mandiant"
        description = "Hunting rule to identify strings found in SPAWNSLOTH"

    strings:
        $dslog = "dslogserver" ascii fullword
        $hook1 = "g_do_syslog_servers_exist" ascii fullword
        $hook2 = "ZN5DSLog4File3addEPKci" ascii fullword
        $hook3 = "funchook" ascii fullword

    condition:
        uint32(0) == 0x464c457f and all of them
}
