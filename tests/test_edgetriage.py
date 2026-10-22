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
                        prof.check_command(c.format(**{v: "/data/lang/custom" for v in s.requires_vars}))


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
