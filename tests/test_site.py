"""Browser smoke test for the generated site.

The static contract (`build_site.py --check`) proves the data and links are
consistent; it cannot prove the JavaScript runs. This test loads the page in
Chromium, walks every tab, opens a record in each library, follows deep links
and checks phone width for horizontal scroll. It skips when Playwright or a
browser is not installed, so the core suite never depends on it.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
pw = pytest.importorskip("playwright.sync_api")


def _build(tmp_path: Path) -> str:
    spec = importlib.util.spec_from_file_location("build_site", ROOT / "artifacts" / "scripts" / "build_site.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["build_site"] = mod
    spec.loader.exec_module(mod)
    d = mod.load()
    doc, data = mod.page(d)
    assert not mod.check(d, doc, data)
    out = tmp_path / "index.html"
    out.write_text(doc, encoding="utf-8")
    return out.as_uri()


def _counts(page, lib: str) -> tuple[int, int]:
    import re
    m = re.match(r"(\d+) of (\d+) ", page.locator(f"#tab-{lib} .count").inner_text())
    assert m, "count line missing"
    return int(m.group(1)), int(m.group(2))


@pytest.fixture(scope="module")
def browser():
    with pw.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as exc:  # no browser binary on this machine
            pytest.skip(f"chromium not available: {exc}")
        yield b
        b.close()


def test_site_runs_without_errors(browser, tmp_path):
    url = _build(tmp_path)
    errors: list[str] = []
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.goto(url)
    shown, total = _counts(page, "artifacts")
    assert shown == total > 0

    for lib in ("artifacts", "platforms", "detections", "rules", "intel"):
        page.goto(f"{url}#{lib}")
        page.locator(f"#tab-{lib}").wait_for(state="visible")
        items = page.locator(f"#tab-{lib} .item")
        assert items.count() > 0, lib
        items.first.click()
        page.locator("#drawer").wait_for(state="visible")
        assert page.locator("#dBody").inner_text().strip(), lib
        page.keyboard.press("Escape")
        page.locator("#drawer").wait_for(state="hidden")

    for tab in ("plans", "response", "coverage", "guide"):
        page.goto(f"{url}#{tab}")
        page.locator(f"#tab-{tab}").wait_for(state="visible")
    assert not errors, errors


def test_filters_live_in_the_url(browser, tmp_path):
    url = _build(tmp_path)
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{url}#artifacts?volatility=live")
    shown, total = _counts(page, "artifacts")
    assert 0 < shown < total
    page.locator("#rail label:has(input[value='memory'])").click()  # the box is drawn; the input is visually hidden
    assert "class=memory" in page.url and "volatility=live" in page.url
    # an old pack link still lands on the detections library, filtered to the pack
    page.goto(f"{url}#packs/EDGE-PACK-0006")
    page.wait_for_url("**#detections?pack=EDGE-PACK-0006")
    # a deep link to a record outside the current filter clears the filter instead of hiding the record
    page.goto(f"{url}#artifacts/EDGE-0009.01")
    page.locator("#drawer").wait_for(state="visible")
    assert page.locator("#tab-artifacts .item.sel").count() == 1


def test_phone_width_has_no_horizontal_scroll(browser, tmp_path):
    url = _build(tmp_path)
    page = browser.new_page(viewport={"width": 390, "height": 844})
    for tab in ("artifacts", "detections", "intel", "plans", "response", "coverage"):
        page.goto(f"{url}#{tab}")
        page.locator(f"#tab-{tab}").wait_for(state="visible")
        assert not page.evaluate("document.documentElement.scrollWidth > window.innerWidth"), tab
