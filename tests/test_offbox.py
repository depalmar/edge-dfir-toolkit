"""Off-box comparison: the SIEM's copy of a device's syslog against the logs left on
the box. Lined up by message, never by clock; one-sided runs are possible
indicators; copies that do not line up are not evaluated, never 'all missing'."""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from edgetriage.analyze import analyze  # noqa: E402
from edgetriage.custody import Case  # noqa: E402


def _msg(i: int) -> str:
    return f"UI_CMDLINE_READ_LINE: User 'ir-ro', command 'show route 198.51.100.{i % 250}' seq {i}"


def _logout_every(n: int):
    """Messages where every nth line is the same logout, as in a real Junos log."""
    return lambda i: "UI_LOGOUT_EVENT: User 'ir-ro' logout" if i % n == 0 else _msg(i)


def _local(i: int, t: datetime, msg=_msg) -> str:
    return f"{t:%b %d %H:%M:%S} mx-lab-01 mgd[2210]: {msg(i)}"


def _forwarded(i: int, t: datetime, msg=_msg) -> str:
    return f"<190>{t:%b %d %H:%M:%S} mx-lab-01 mgd[2210]: {msg(i)}"


T0 = datetime(2026, 10, 22, 9, 0, 0)


def _case(tmp: Path, local_lines: list[str], name: str = "IR-OFFBOX") -> Path:
    (tmp / f"{name}-src").mkdir()
    src = tmp / f"{name}-src" / "messages"   # named as on the device, so the default local globs find it
    src.write_text("\n".join(local_lines) + "\n")
    case = Case(tmp / name)
    m = Case.new_manifest(name, "tester", "EDGE-0008", None)
    m["expected_evidence"] = []
    m["ingested"].append(case.ingest(src, "local-messages", extract=False, evidence_classes=["system-logs"]))
    case.save(m)
    return case.root


def _det(out: dict, rid: str) -> dict:
    return next(r for r in out["detections"] if r["id"] == rid)


def test_runs_on_either_side_are_possible_indicators(tmp_path):
    """Eight lines the SIEM holds are gone from the box, and six local lines never reached
    the SIEM. Both are found as runs between shared lines; nothing else is."""
    idx = range(120)
    gone = set(range(40, 48))          # deleted locally after forwarding
    unsent = set(range(80, 86))        # written while forwarding was blocked
    local = [_local(i, T0 + timedelta(minutes=i)) for i in idx if i not in gone]
    fwd = [_forwarded(i, T0 + timedelta(minutes=i)) for i in idx if i not in unsent]
    root = _case(tmp_path, local)
    (tmp_path / "siem.log").write_text("\n".join(fwd) + "\n")
    out = analyze(root, forwarded=[tmp_path / "siem.log"])
    g, u = _det(out, "offbox-gone-from-box"), _det(out, "offbox-never-forwarded")
    assert g["status"] == "hit" and g["hit_count"] == 1 and g["hits"][0]["extra"]["lines"] == 8
    assert u["status"] == "hit" and u["hit_count"] == 1 and u["hits"][0]["extra"]["lines"] == 6
    assert all(h["tier"] == "possible" for h in g["hits"] + u["hits"])
    assert "seq 40" in g["hits"][0]["excerpt"] and "seq 80" in u["hits"][0]["excerpt"]
    assert out["verdict"]["level"] == "SUSPICIOUS"   # one evidence class, possible tier
    assert "disagree" in out["verdict"]["rationale"] and "exploitation attempted" not in out["verdict"]["rationale"]
    assert out["offbox"]["forwarded"][0]["sha256"] and out["offbox"]["shared"] == 120 - 8 - 6
    md = (root / "report.md").read_text()
    assert "## Off-box comparison" in md and "Gone from the box | 1 run(s) found" in md
    assert "| Collected | no live collection |" in md and "None" not in md   # an ingest-only case says so
    html = (root / "report.html").read_text()
    assert "Off-box comparison" in html and "#hunts/EDGE-HUNT-0027" in html


def test_a_deleted_stretch_with_repeated_messages_is_still_one_run(tmp_path):
    """Every third line is the same logout. Eleven forwarded lines gone from the box and seven
    local lines never forwarded both include logouts, and each stretch ends just before a
    logout both copies keep. A logout pairs only with a copy in its own stretch, the one
    beside it first, so each stretch is one run with every line counted and the right end.
    (A logout used to pair with any copy anywhere in the log, which split both stretches
    into runs of two.)"""
    m = _logout_every(3)
    gone, unsent = set(range(40, 51)), set(range(80, 87))
    local = [_local(i, T0 + timedelta(minutes=i), m) for i in range(140) if i not in gone]
    fwd = [_forwarded(i, T0 + timedelta(minutes=i), m) for i in range(140) if i not in unsent]
    root = _case(tmp_path, local)
    (tmp_path / "siem.log").write_text("\n".join(fwd) + "\n")
    out = analyze(root, forwarded=[tmp_path / "siem.log"])
    g, u = _det(out, "offbox-gone-from-box"), _det(out, "offbox-never-forwarded")
    assert g["status"] == "hit" and g["hit_count"] == 1 and g["hits"][0]["extra"]["lines"] == 11
    assert u["status"] == "hit" and u["hit_count"] == 1 and u["hits"][0]["extra"]["lines"] == 7
    assert "seq 40" in g["hits"][0]["excerpt"] and "seq 80" in u["hits"][0]["excerpt"]
    assert g["hits"][0]["extra"]["end"] == "Oct 22 09:50:00"   # line 50, not the kept logout at 51
    assert u["hits"][0]["extra"]["end"] == "Oct 22 10:26:00"   # line 86, not the kept logout at 87


def test_rotation_with_repeated_messages_is_not_deletion(tmp_path):
    """Every tenth line is the same logout and the box has rotated away its first 40 lines. A
    rotated logout must not pair with a later copy on the box and pull the rotated lines into
    the comparison, where they would read as deleted."""
    m = _logout_every(10)
    local = [_local(i, T0 + timedelta(minutes=i), m) for i in range(40, 120)]
    root = _case(tmp_path, local)
    (tmp_path / "siem.log").write_text("\n".join(_forwarded(i, T0 + timedelta(minutes=i), m) for i in range(120)) + "\n")
    out = analyze(root, forwarded=[tmp_path / "siem.log"])
    assert _det(out, "offbox-gone-from-box")["status"] == "no-hit"
    assert _det(out, "offbox-never-forwarded")["status"] == "no-hit"
    assert out["offbox"]["before_box"]["lines"] == 40


def test_lines_the_collector_received_late_are_not_deletion(tmp_path):
    """Eight lines reached the SIEM thirty lines late. Each message occurs once in each copy,
    so they are the same lines wherever they sit: no run on either side."""
    local = [_local(i, T0 + timedelta(minutes=i)) for i in range(120)]
    order = [i for i in range(120) if i not in range(40, 48)]
    at = order.index(77) + 1
    order[at:at] = list(range(40, 48))
    root = _case(tmp_path, local)
    (tmp_path / "siem.log").write_text("\n".join(_forwarded(i, T0 + timedelta(minutes=i)) for i in order) + "\n")
    out = analyze(root, forwarded=[tmp_path / "siem.log"])
    assert _det(out, "offbox-gone-from-box")["status"] == "no-hit"
    assert _det(out, "offbox-never-forwarded")["status"] == "no-hit"


def test_identical_copies_evaluate_with_no_hit(tmp_path):
    local = [_local(i, T0 + timedelta(minutes=i)) for i in range(60)]
    root = _case(tmp_path, local)
    (tmp_path / "siem.log").write_text("\n".join(_forwarded(i, T0 + timedelta(minutes=i)) for i in range(60)) + "\n")
    out = analyze(root, forwarded=[tmp_path / "siem.log"])
    assert _det(out, "offbox-gone-from-box")["status"] == "no-hit"
    assert _det(out, "offbox-never-forwarded")["status"] == "no-hit"
    assert out["verdict"]["level"] == "NO-INDICATORS-FOUND"


def test_a_device_clock_in_another_zone_and_rotation_are_not_deletion(tmp_path):
    """The SIEM stamps lines five hours off the device, and the box has rotated away the
    first 30 lines: the copies still line up, and the older lines are reported as older
    than the box, not as gone from it."""
    local = [_local(i, T0 + timedelta(minutes=i)) for i in range(30, 90)]
    fwd = [_forwarded(i, T0 + timedelta(hours=5, minutes=i)) for i in range(90)]
    root = _case(tmp_path, local)
    (tmp_path / "siem.log").write_text("\n".join(fwd) + "\n")
    out = analyze(root, forwarded=[tmp_path / "siem.log"])
    assert _det(out, "offbox-gone-from-box")["status"] == "no-hit"
    assert out["offbox"]["before_box"]["lines"] == 30


def test_json_lines_and_csv_exports_line_up_like_raw_lines(tmp_path):
    local = [_local(i, T0 + timedelta(minutes=i)) for i in range(60) if i not in range(20, 27)]
    root = _case(tmp_path, local)
    rows = [{"_time": (T0 + timedelta(minutes=i)).isoformat() + "Z", "Message": _forwarded(i, T0 + timedelta(minutes=i))}
            for i in range(60)]
    (tmp_path / "siem.jsonl").write_text("\n".join(json.dumps(r) for r in reversed(rows)) + "\n")   # newest first
    with open(tmp_path / "siem.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["_time", "Message"])
        w.writeheader()
        w.writerows(rows)
    for name, fmt in (("siem.jsonl", "jsonl"), ("siem.csv", "csv")):
        out = analyze(root, forwarded=[tmp_path / name])
        g = _det(out, "offbox-gone-from-box")
        assert out["offbox"]["forwarded"][0]["format"] == fmt
        assert g["status"] == "hit" and g["hits"][0]["extra"]["lines"] == 7, name
        assert g["hits"][0]["ts"].startswith("2026-10-22T09:20"), name   # put back in time order


def test_copies_that_do_not_line_up_are_not_evaluated(tmp_path):
    """A device that forwards a different format than it keeps shares no messages with the
    SIEM's copy: that is a gap, not 60 missing lines."""
    root = _case(tmp_path, [_local(i, T0 + timedelta(minutes=i)) for i in range(60)])
    other = [f"<14>1,2026/10/22 09:{i % 60:02d}:00,007951000012345,SYSTEM,general,0,{i}" for i in range(60)]
    (tmp_path / "siem.log").write_text("\n".join(other) + "\n")
    out = analyze(root, forwarded=[tmp_path / "siem.log"])
    assert {_det(out, k)["status"] for k in ("offbox-gone-from-box", "offbox-never-forwarded")} == {"not-evaluated"}
    assert any(g["kind"] == "offbox-not-compared" for g in out["evidence_gaps"])
    assert out["verdict"]["level"] == "NO-INDICATORS-FOUND"


def test_a_level_difference_is_not_read_as_deletion(tmp_path):
    """The device forwards every line but keeps only every other one locally: most of the
    span is one-sided, so the comparison says why it did not evaluate."""
    local = [_local(i, T0 + timedelta(minutes=i)) for i in range(0, 120, 2)]
    root = _case(tmp_path, local)
    (tmp_path / "siem.log").write_text("\n".join(_forwarded(i, T0 + timedelta(minutes=i)) for i in range(120)) + "\n")
    out = analyze(root, forwarded=[tmp_path / "siem.log"])
    g = _det(out, "offbox-gone-from-box")
    assert g["status"] == "not-evaluated" and "level or facility" in g["reason"]
    assert _det(out, "offbox-never-forwarded")["status"] == "no-hit"


def test_stream_gaps_are_listed_not_scored(tmp_path):
    """A three-hour silence in the forwarded stream is listed, flagged when it falls in the
    window, and never raises the verdict on its own."""
    times = [T0 + timedelta(minutes=i) for i in range(40)] + [T0 + timedelta(hours=3, minutes=40 + i) for i in range(40)]
    local = [_local(i, t) for i, t in enumerate(times)]
    root = _case(tmp_path, local)
    rows = [{"timestamp": t.isoformat() + "Z", "message": _forwarded(i, t)} for i, t in enumerate(times)]
    (tmp_path / "siem.json").write_text(json.dumps(rows))
    out = analyze(root, forwarded=[tmp_path / "siem.json"], window_start="2026-10-22T08:00:00")
    gaps = out["offbox"]["gaps"]
    assert len(gaps) == 1 and gaps[0]["seconds"] == 3 * 3600 + 60 and gaps[0]["in_window"]
    assert out["verdict"]["level"] == "NO-INDICATORS-FOUND"
    assert "Listed, not scored" in (root / "report.md").read_text()


# --------------------------------------------------------------------------- --activity
# A three-hour silence, 09:39 to 12:40, in both copies: forwarding and local logging stopped
# together, so only another source can say whether the device was working meanwhile.
GAP_FROM, GAP_TO = T0 + timedelta(minutes=39), T0 + timedelta(hours=3, minutes=40)


def _gap_case(tmp_path: Path) -> tuple[Path, Path]:
    times = [T0 + timedelta(minutes=i) for i in range(40)] + [T0 + timedelta(hours=3, minutes=40 + i) for i in range(40)]
    root = _case(tmp_path, [_local(i, t) for i, t in enumerate(times)])
    rows = [{"timestamp": t.isoformat() + "Z", "message": _forwarded(i, t)} for i, t in enumerate(times)]
    (tmp_path / "siem.json").write_text(json.dumps(rows))
    return root, tmp_path / "siem.json"


def _every(start: datetime, end: datetime, minutes: int = 10) -> list[datetime]:
    out, t = [], start
    while t <= end:
        out.append(t)
        t += timedelta(minutes=minutes)
    return out


def _signins(tmp_path: Path, times: list[datetime], name: str = "idp.jsonl", nas: str = "192.0.2.1") -> Path:
    """Identity-provider sign-ins that passed through the VPN gateway (Okta's System Log field)."""
    p = tmp_path / name
    with open(p, "a") as fh:
        for t in times:
            fh.write(json.dumps({"published": t.isoformat() + "Z", "eventType": "user.authentication.sso",
                                 "debugContext": {"nas": nas}}) + "\n")
    return p


def test_a_gap_while_another_source_shows_the_device_working_is_a_possible_indicator(tmp_path):
    root, siem = _gap_case(tmp_path)
    act = _signins(tmp_path, _every(T0 - timedelta(hours=1), T0 + timedelta(hours=5)))
    out = analyze(root, forwarded=[siem], activity=[act])
    d = _det(out, "offbox-silent-while-active")
    assert d["status"] == "hit" and d["hit_count"] == 1 and d["hits"][0]["tier"] == "possible"
    assert d["hits"][0]["extra"]["events"] == 17 and d["evidence_class"] == "offbox-logs"
    assert out["verdict"]["level"] == "SUSPICIOUS"
    assert "quiet while another source shows the device" in out["verdict"]["rationale"]
    gap = out["offbox"]["gaps"][0]
    assert gap["activity"][0] == {"file": "idp.jsonl", "events": 17, "covers": True}
    md = (root / "report.md").read_text()
    assert "active: 17 event(s) in idp.jsonl" in md and "idp.jsonl (jsonl" in md


def test_a_gap_that_is_quiet_in_the_other_source_too_is_not_scored(tmp_path):
    """Sign-ins before and after the gap but none inside it: a quiet stretch, not a hit. The
    five minutes at each end of the gap do not count, because two systems' clocks disagree."""
    root, siem = _gap_case(tmp_path)
    times = _every(T0 - timedelta(hours=1), GAP_FROM) + _every(GAP_TO, T0 + timedelta(hours=5))
    times += [GAP_FROM + timedelta(minutes=2), GAP_TO - timedelta(minutes=2)] * 3
    act = _signins(tmp_path, sorted(times))
    out = analyze(root, forwarded=[siem], activity=[act])
    assert _det(out, "offbox-silent-while-active")["status"] == "no-hit"
    assert out["verdict"]["level"] == "NO-INDICATORS-FOUND"
    assert "quiet in idp.jsonl too" in (root / "report.md").read_text()


def test_an_activity_export_that_does_not_span_the_gap_is_not_evaluated(tmp_path):
    """Sign-ins only from 13:00: silence in that file says nothing about 09:39 to 12:40."""
    root, siem = _gap_case(tmp_path)
    act = _signins(tmp_path, _every(T0 + timedelta(hours=4), T0 + timedelta(hours=5)))
    out = analyze(root, forwarded=[siem], activity=[act])
    d = _det(out, "offbox-silent-while-active")
    assert d["status"] == "not-evaluated" and "do not span any listed gap" in d["reason"]
    assert any(g["kind"] == "offbox-activity-missing" for g in out["evidence_gaps"])


def test_without_an_activity_export_a_gap_stays_listed_and_says_what_would_test_it(tmp_path):
    root, siem = _gap_case(tmp_path)
    out = analyze(root, forwarded=[siem])
    d = _det(out, "offbox-silent-while-active")
    assert d["status"] == "not-evaluated" and "--activity" in d["reason"]
    assert out["verdict"]["level"] == "NO-INDICATORS-FOUND"
    assert any(g["kind"] == "offbox-activity-missing" for g in out["evidence_gaps"])
    md = (root / "report.md").read_text()
    section = md.split("## Off-box")[1].split("## Evidence gaps")[0]
    assert "Listed, not scored" in section and "sign-ins" in section and "NetFlow" not in section


def test_no_gap_means_nothing_to_corroborate(tmp_path):
    root = _case(tmp_path, [_local(i, T0 + timedelta(minutes=i)) for i in range(60)])
    rows = [{"timestamp": (T0 + timedelta(minutes=i)).isoformat() + "Z", "message": _forwarded(i, T0 + timedelta(minutes=i))}
            for i in range(60)]
    (tmp_path / "siem.json").write_text(json.dumps(rows))
    out = analyze(root, forwarded=[tmp_path / "siem.json"])
    assert _det(out, "offbox-silent-while-active")["status"] == "no-hit"
    assert not any(g["kind"] == "offbox-activity-missing" for g in out["evidence_gaps"])


def test_gaps_in_a_raw_export_without_a_year_cannot_be_placed_against_another_source(tmp_path):
    times = [T0 + timedelta(minutes=i) for i in range(40)] + [T0 + timedelta(hours=3, minutes=40 + i) for i in range(40)]
    root = _case(tmp_path, [_local(i, t) for i, t in enumerate(times)])
    (tmp_path / "siem.log").write_text("\n".join(_forwarded(i, t) for i, t in enumerate(times)) + "\n")
    act = _signins(tmp_path, _every(T0 - timedelta(hours=1), T0 + timedelta(hours=5)))
    out = analyze(root, forwarded=[tmp_path / "siem.log"], activity=[act])
    d = _det(out, "offbox-silent-while-active")
    assert d["status"] == "not-evaluated" and "no year" in d["reason"]


def test_activity_match_keeps_only_records_that_name_the_device(tmp_path):
    """The export holds sign-ins for two gateways. Only 192.0.2.10 was busy during the gap;
    192.0.2.1 must not borrow its events, and the match must not read .10 as .1."""
    root, siem = _gap_case(tmp_path)
    act = _signins(tmp_path, _every(T0 - timedelta(hours=1), GAP_FROM) + _every(GAP_TO, T0 + timedelta(hours=5)))
    _signins(tmp_path, _every(T0 - timedelta(hours=1), T0 + timedelta(hours=5)), nas="192.0.2.10")
    busy = analyze(root, forwarded=[siem], activity=[act])
    assert _det(busy, "offbox-silent-while-active")["status"] == "hit"   # without the match, .10 counts
    out = analyze(root, forwarded=[siem], activity=[act], activity_match=["192.0.2.1"])
    assert _det(out, "offbox-silent-while-active")["status"] == "no-hit"
    assert out["offbox"]["activity"][0]["kept"] < out["offbox"]["activity"][0]["records"]


def test_activity_exports_in_other_shapes_are_read_by_their_time_field(tmp_path):
    """Entra sign-ins as CSV (createdDateTime), Zeek conn.log as JSON lines (ts, epoch
    seconds) and plain lines with ISO times all place the same events in the gap."""
    root, siem = _gap_case(tmp_path)
    times = _every(T0 - timedelta(hours=1), T0 + timedelta(hours=5))
    with open(tmp_path / "entra.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["createdDateTime", "userPrincipalName", "ipAddress"])
        w.writeheader()
        w.writerows({"createdDateTime": t.isoformat() + "Z", "userPrincipalName": "user@example.com",
                     "ipAddress": "192.0.2.1"} for t in times)
    epoch = [(t - datetime(1970, 1, 1)).total_seconds() for t in times]
    (tmp_path / "conn.log").write_text("".join(json.dumps({"ts": e, "id.orig_h": "192.0.2.1", "id.resp_h": "198.51.100.9"}) + "\n"
                                               for e in epoch))
    (tmp_path / "fw.log").write_text("".join(f"{t.isoformat()}Z fw-core-01 session start src=192.0.2.1\n" for t in times))
    for name, fmt in (("entra.csv", "csv"), ("conn.log", "jsonl"), ("fw.log", "text")):
        out = analyze(root, forwarded=[siem], activity=[tmp_path / name])
        d = _det(out, "offbox-silent-while-active")
        assert out["offbox"]["activity"][0]["format"] == fmt, name
        assert d["status"] == "hit" and d["hits"][0]["extra"]["events"] == 17, name


def test_a_raw_export_whose_lines_start_with_a_bracket_is_read_as_lines(tmp_path):
    from edgetriage.offbox import read_forwarded
    p = tmp_path / "raw.log"
    p.write_text("[2026-10-22 09:00:00] mx-lab-01 mgd[2210]: one\n[2026-10-22 09:01:00] mx-lab-01 mgd[2210]: two\n")
    lines, fmt = read_forwarded(p)
    assert fmt == "text" and [ln.key for ln in lines] == ["one", "two"]


def test_without_a_forwarded_copy_nothing_changes(tmp_path):
    root = _case(tmp_path, [_local(i, T0 + timedelta(minutes=i)) for i in range(30)])
    out = analyze(root)
    assert "offbox" not in out and not any(r["id"].startswith("offbox-") for r in out["detections"])
