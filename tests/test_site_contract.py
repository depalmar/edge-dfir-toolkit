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
