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
