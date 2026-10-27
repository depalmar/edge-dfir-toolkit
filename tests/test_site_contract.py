"""Static contracts between the site and the engine. No browser needed, so these
run everywhere the core suite runs."""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from edgetriage.analyze import verdict  # noqa: E402


def _site():
    spec = importlib.util.spec_from_file_location("build_site_contract", ROOT / "artifacts" / "scripts" / "build_site.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_verdict_ladder_matches_the_analyzer():
    """The Start page explains how hits become a verdict (F6). Every scenario a
    ladder line describes is run through analyze.verdict(), so the copy cannot
    drift from the code."""
    bs = _site()
    assert [lvl for lvl, _, _ in bs.LADDER] == list(bs.RESP_VERDICTS)
    for level, _, scenarios in bs.LADDER:
        for sc in scenarios:
            results = [{"id": f"d{i}", "evidence_class": cls, "hits": [{"tier": tier}]} for i, (tier, cls) in enumerate(sc)]
            assert verdict(results)["level"] == level, (level, sc)
    d = bs.load()
    doc, _ = bs.page(d)
    for _, text, _ in bs.LADDER:
        assert text in doc
    # repeated hits in one class never raise the verdict: the page says so, and verdict() agrees
    assert "repeated hits in one evidence class never raise the verdict" in doc
    two_possible_one_class = [{"id": "a", "evidence_class": "web-logs", "hits": [{"tier": "possible"}, {"tier": "possible"}]}]
    assert verdict(two_possible_one_class)["level"] == "SUSPICIOUS"


def test_every_platform_has_a_short_name_and_readiness_row():
    bs = _site()
    d = bs.load()
    doc, data = bs.page(d)
    assert {p["id"] for p in data["platforms"]} <= set(bs.PLATFORM_ABBR)
    assert len(re.findall(r'<div class="rrow" role="row">', doc)) == len(data["platforms"])
    assert len(re.findall(r'<td class="kc">', doc)) == len(d["kev"]["triaged"])


def _contrast(a: str, b: str) -> float:
    def lum(h):
        ch = [int(h.lstrip("#")[i:i + 2], 16) / 255 for i in (0, 2, 4)]
        ch = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in ch]
        return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2]
    hi, lo = sorted((lum(a), lum(b)), reverse=True)
    return (hi + .05) / (lo + .05)


def test_dark_theme_outlines_are_visible():
    """Dark mode was near-black with outlines at 1.3:1, so cards and inputs vanished.
    Floors: cards stand off the page, card outlines 2:1, control borders 3:1
    (WCAG 1.4.11), muted text 4.5:1 on every surface it sits on."""
    bs = _site()
    block = re.search(r":root\[data-theme=dark\]\{(.*?)\}", bs.CSS, re.S).group(1)
    t = dict(re.findall(r"--([\w-]+):(#[0-9a-f]{6})", block))
    assert _contrast(t["panel"], t["bg"]) >= 1.15
    assert _contrast(t["line"], t["panel"]) >= 2 and _contrast(t["line"], t["bg"]) >= 2
    assert _contrast(t["field"], t["panel"]) >= 3 and _contrast(t["field"], t["bg"]) >= 3
    for surface in ("bg", "panel", "panel-2", "hover"):
        assert _contrast(t["muted"], t[surface]) >= 4.5, surface
    media = re.search(r"@media \(prefers-color-scheme:dark\)\{:root:not\(\[data-theme=light\]\)\{(.*?)\}\}", bs.CSS, re.S).group(1)
    assert dict(re.findall(r"--([\w-]+):(#[0-9a-f]{6})", media)) == t   # both dark blocks agree


def test_heatmaps_are_tables_with_a_label_on_every_cell():
    """F35: a coverage heatmap is a table: two header rows, one row per platform with
    a row header, and every cell (filled or empty) says what it holds."""
    bs = _site()
    d = bs.load()
    doc, data = bs.page(d)
    heats = re.findall(r'<div class="heat" style="--cols:(\d+)" role="table" aria-label="[^"]+">(.*?)</div></div>', doc, re.S)
    assert len(heats) == 2
    for cols, body in heats:
        rows = body.split('<div class="hrow" role="row">')[1:]
        assert len(rows) == len(data["platforms"]) + 2
        assert rows[1].count('role="columnheader"') == int(cols) + 2
        for row in rows[2:]:
            assert row.count('role="rowheader"') == 1
            cells = re.findall(r'role="cell"( aria-label="[^"]+")?>(<a [^>]*aria-label="[^"]+")?', row)
            assert len(cells) == int(cols) + 1
            assert all(own or inner for own, inner in cells)


def test_records_carry_their_last_changed_date():
    """F21: a record's date is its file's last commit, from git; a build without
    history shows none rather than a guessed date."""
    bs = _site()
    d = bs.load()
    for path, day in bs.git_dates().items():
        assert path.startswith("artifacts/") and re.fullmatch(r"\d{4}-\d{2}-\d{2}", day)
    first = d["catalog"][0]
    d["dates"] = {first["_file"]: "2026-01-02"}
    doc, data = bs.page(d)
    assert next(p for p in data["platforms"] if p["id"] == first["id"])["changed"] == "2026-01-02"
    assert {a["changed"] for a in data["artifacts"] if a["platform"] == first["id"]} == {"2026-01-02"}
    assert "Record files, last changed" in doc
    d["dates"] = {}
    doc, data = bs.page(d)
    assert not any(p["changed"] for p in data["platforms"])
    assert "which this build did not have" in doc


def test_records_changed_before_their_platforms_newest_advisory_are_flagged():
    """A record whose file was last committed before its platform's newest KEV
    entry or indicator set says it may need a re-read. Same day is not before,
    and a file for every device (ALL) is compared with nothing."""
    import datetime as dt
    bs = _site()
    d = bs.load()
    ev = bs.platform_events(d)
    for pid, cves in d["kev"]["added"].items():
        assert ev[pid][0] >= max(cves.values())
    day, what = ev["EDGE-0001"]
    before = (dt.date.fromisoformat(day) - dt.timedelta(days=1)).isoformat()
    pack = next(p for p in d["packs"] if p["platforms"] == ["EDGE-0001"])
    cat = next(c for c in d["catalog"] if c["id"] == "EDGE-0001")
    base = next(h for h in d["hardening"].values() if h["platform_id"] == "ALL")
    d["dates"] = {pack["_file"]: before, cat["_file"]: day, base["_file"]: "2000-01-01"}
    doc, data = bs.page(d)
    assert {tuple(x["reread"]) for x in data["detections"] if x["pack"] == pack["id"]} == {(day, what)}
    assert next(p for p in data["platforms"] if p["id"] == "EDGE-0001")["reread"] == []
    assert not any(c["reread"] for c in data["hardening"] if c["platform"] == "ALL")
    assert "1 file to re-read" in doc and pack["_file"] in doc
    d["dates"] = {}                                   # no history: no date, so nothing to compare
    doc, data = bs.page(d)
    assert not any(x["reread"] for x in data["detections"])


def test_git_dates_skip_the_ignored_revisions(tmp_path, monkeypatch):
    """A commit listed in .git-blame-ignore-revs (a reformat) does not make a file look newly read."""
    import os
    import subprocess
    bs = _site()
    (tmp_path / "artifacts").mkdir()
    f = tmp_path / "artifacts" / "x.yml"

    def commit(text, when):
        f.write_text(text)
        env = {**os.environ, "GIT_AUTHOR_DATE": when, "GIT_COMMITTER_DATE": when,
               "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True, env=env)
        subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "c"], check=True, env=env)
        return subprocess.run(["git", "-C", str(tmp_path), "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout.strip()
    subprocess.run(["git", "-C", str(tmp_path), "init", "-q"], check=True)
    commit("a: 1\n", "2026-01-02T12:00:00Z")
    sweep = commit("a:   1\n", "2026-03-04T12:00:00Z")
    monkeypatch.setattr(bs, "ROOT", tmp_path)
    assert bs.git_dates() == {"artifacts/x.yml": "2026-03-04"}
    (tmp_path / ".git-blame-ignore-revs").write_text(f"# reformat\n{sweep}\n")
    assert bs.git_dates() == {"artifacts/x.yml": "2026-01-02"}


def test_cve_records_join_kev_and_the_repository():
    """One record per CVE: every KEV record the watcher wrote, plus every CVE a record
    names in a structured field. KEV's own platform wins; the BOD 26-04 steps are CISA's."""
    import yaml as _yaml
    bs = _site()
    d = bs.load()
    doc, data = bs.page(d)
    recs = _yaml.safe_load((ROOT / "artifacts" / "watch" / "kev-records.yml").read_text())["records"]
    by = {c["id"]: c for c in data["cves"]}
    assert set(by) == {r["cve"] for r in recs} | bs.cve_universe(d)
    for r in recs:
        c = by[r["cve"]]
        assert c["in_kev"] and c["triage"] == r["forensic_triage"] and c["added"] == str(r["added"])
        if r["platform"]:
            assert c["platforms"] == [r["platform"]]
    for c in data["cves"]:
        assert c["platforms"], c["id"]
        assert (c["coverage"] == "detections") == bool(c["detections"])
        if not c["in_kev"]:
            assert c["coverage"] == "not-in-kev" and not c["triage"]
    assert sum(c["triage"] == "Yes" for c in data["cves"]) == sum(r["forensic_triage"] == "Yes" for r in recs)
    assert [s[0] for s in bs.BOD_STEPS] == ["Scoping", "Preserve and Collect Evidence", "Critical Patching and Stabilization",
                                           "Contain and Control", "Triage Analysis", "Escalation Decision"]
    assert all(st[1].startswith("Target timeline: within ") for st in bs.BOD_STEPS)
    assert "#detections?cve=" not in doc.split('<script type="application/json"')[0]   # CVE mentions open the record


def test_forensic_triage_flag_is_read_as_cisa_defines_it():
    """KEV's forensicTriage is a BOD 26-04 deadline category. Every entry added before the
    directive reads No, so the site reads those as 'added before BOD 26-04', never as
    'not required'. CVE.org fields join every KEV record; platforms list their CVEs."""
    import yaml as _yaml
    bs = _site()
    d = bs.load()
    doc, data = bs.page(d)
    for c in data["cves"]:
        if not c["in_kev"]:
            assert c["triage_k"] == "none"
        elif c["added"] < bs.BOD_ISSUED:
            assert c["triage"] == "No" and c["triage_k"] == "no-before", c["id"]
        else:
            assert c["triage_k"] == ("yes" if c["triage"] == "Yes" else "no-after")
        if c["triage_k"] == "yes":
            assert c["due_days"] == 3, c["id"]      # the directive: "within the timeline (three days)"
    cve_js = doc[doc.index("LIB.cves = {"):doc.index("LIB.hunts = {")]
    assert "not required" not in cve_js.lower()     # a playbook may say it of a feature; the CVE records never do
    recs = {r["cve"]: r for r in _yaml.safe_load((ROOT / "artifacts" / "watch" / "cve-records.yml").read_text())["records"]}
    for c in data["cves"]:
        if c["in_kev"]:
            assert c["id"] in recs and c["published"] == recs[c["id"]]["published"]
            assert {w["id"] for w in recs[c["id"]]["cwes"]} <= set(c["cwes"])
    for p in data["platforms"]:
        assert set(p["cves"]) == {c["id"] for c in data["cves"] if p["id"] in c["platforms"]}
    assert "cwe" in bs.FACET_KEYS["cves"]
