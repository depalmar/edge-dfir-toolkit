"""check_quotes.py: a faithful copy matches, a reworded one does not, and a page that
only renders in a browser is reported as unchecked, never as changed."""
import importlib.util
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_quotes", ROOT / "artifacts/scripts/check_quotes.py")
cq = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cq)


def test_norm_forgives_only_what_a_faithful_copy_can_differ_in():
    page = cq.norm(cq.text_of(b"<p>It\xe2\x80\x99s <a href='x'>FG-IR-23-097</a> )\xc2\xa0exploited \xe2\x80\x94 "
                              b"<b>really</b>.</p><script>var q='hidden';</script>"))
    assert cq.norm("It's FG-IR-23-097) exploited - really.") in page
    assert "hidden" not in page
    assert cq.norm("such as:  Evidence of clearing") == cq.norm("such as: Evidence of clearing")   # PDF bullet
    assert cq.norm("logs had been wiped") not in cq.norm("logs had been archived")


def test_inline_tags_join_and_blocks_separate():
    t = cq.norm(cq.text_of(b"<p>exploit<b>ed</b> in the wild</p><li>next item</li>"))
    assert "exploited in the wild next item" in t


def test_collect_finds_every_quoted_https_source(tmp_path):
    (tmp_path / "artifacts").mkdir()
    (tmp_path / "artifacts" / "x.yml").write_text(yaml.safe_dump({
        "records": [{"cve": "CVE-2099-0001", "reports": [
            {"url": "https://example.com/a", "quote": "one"}, {"url": "http://example.com/b", "quote": "not https"}]}],
        "sources": [{"url": "https://example.com/c", "quote": "two", "read": "summariser"}]}))
    got = sorted((s["record"], s["url"], s["read"]) for s in cq.collect(tmp_path))
    assert got == [("CVE-2099-0001", "https://example.com/a", "direct"), ("x", "https://example.com/c", "summariser")]


def test_check_sorts_matched_changed_rendered_and_unfetched():
    pages = {"https://example.com/a": b"<p>The appliance logs had been wiped.</p>",
             "https://support.citrix.com/k": b"<html><div id='app'></div></html>"}

    def getter(u):
        if u not in pages:
            raise OSError("offline")
        return pages[u]
    src = [{"file": "f", "record": "r1", "url": "https://example.com/a", "quote": "logs had been wiped", "read": "direct"},
           {"file": "f", "record": "r2", "url": "https://example.com/a", "quote": "logs had been archived", "read": "direct"},
           {"file": "f", "record": "r3", "url": "https://support.citrix.com/k", "quote": "observed", "read": "direct"},
           {"file": "f", "record": "r4", "url": "https://example.com/gone", "quote": "x", "read": "direct"},
           {"file": "f", "record": "r5", "url": "https://example.com/a", "quote": "had been wiped", "read": "summariser"}]
    res = {r["record"]: r for r in cq.check(src, getter)}
    assert res["r1"]["status"] == "ok"
    assert res["r2"]["status"] == "missing" and 0 < res["r2"]["closest"] < 1
    assert res["r3"]["status"] == "rendered"        # a browser-built page is unchecked, not changed
    assert res["r4"]["status"].startswith("unfetched")
    text = cq.report(list(res.values()))
    assert "No longer on the page (1)" in text and "Needs a rendered check (1)" in text
    assert "can become `read: direct`" in text       # a summariser quote now matched word for word


def test_exit_status_flags_only_a_changed_quote(monkeypatch):
    one = [{"file": "f", "record": "r", "url": "https://example.com/a", "quote": "wiped", "read": "direct"}]
    monkeypatch.setattr(cq, "collect", lambda *_a, **_k: one)
    monkeypatch.setattr(cq, "fetch", lambda _u: b"<p>wiped</p>")
    assert cq.main([]) == 0
    monkeypatch.setattr(cq, "fetch", lambda _u: b"<p>archived</p>")
    assert cq.main([]) == cq.NEEDS_REVIEW
    monkeypatch.setattr(cq, "collect", lambda *_a, **_k: [])
    assert cq.main([]) == 1
