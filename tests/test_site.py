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
    # a first visit lands on Start, with one tile per platform
    page.locator("#tab-start").wait_for(state="visible")
    assert page.locator("#tab-start .ptile").count() == 10
    page.goto(f"{url}#artifacts")
    page.locator("#tab-artifacts").wait_for(state="visible")
    shown, total = _counts(page, "artifacts")
    assert shown == total > 0

    for lib in ("artifacts", "platforms", "detections", "hunts", "intel", "hardening"):
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
    for tab in ("start", "artifacts", "detections", "hunts", "intel", "hardening", "plans", "response", "coverage", "guide"):
        page.goto(f"{url}#{tab}")
        page.locator(f"#tab-{tab}").wait_for(state="visible")
        assert not page.evaluate("document.documentElement.scrollWidth > window.innerWidth"), tab


def test_guide_has_contents_and_section_links(browser, tmp_path):
    url = _build(tmp_path)
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{url}#guide/analysis")
    page.locator("#tab-guide").wait_for(state="visible")
    assert page.locator(".toc a").count() >= 8
    assert page.locator(".toc a.on").inner_text() == "Analysis"
    # every platform has a note, and each note links into the libraries
    assert page.locator("#tab-guide .pnote").count() == 10
    page.locator("#g-note-EDGE-0008 a", has_text="detections").click()
    page.wait_for_url("**#detections?platform=EDGE-0008")


def test_prose_never_switches_to_monospace(browser, tmp_path):
    """Implant artifacts were once set entirely in <code>. Literal strings may be
    code; the sentence around them must stay in the sans face."""
    url = _build(tmp_path)
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{url}#intel/EDGE-IMP-0010")
    page.locator("#drawer").wait_for(state="visible")
    li = page.locator("#dBody li", has_text="Payload files").first
    assert "monospace" not in li.evaluate("e => getComputedStyle(e).fontFamily").lower()
    assert li.locator("code", has_text="loader.bin").count() == 1


def test_rules_live_inside_detections(browser, tmp_path):
    """The Rules tab was merged into Detections: old links still land, and a
    detection shows the Sigma rule that expresses it for a SIEM."""
    url = _build(tmp_path)
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{url}#rules")
    page.wait_for_url("**#detections?runs=siem")
    shown, total = _counts(page, "detections")
    assert 0 < shown < total
    page.goto(f"{url}#rules/10-f5-bigip-f5-cve-2023-46748-tomcat-shell-yml")
    page.wait_for_url("**#detections/f5-46748-tomcat-shell*")
    page.locator("#drawer").wait_for(state="visible")
    assert "f5_cve_2023_46748_tomcat_shell.yml" in page.locator("#dBody").inner_text()


def test_hunts_and_artifact_reading_guidance(browser, tmp_path):
    """Hunts carry normal vs suspicious and flag quotes read through a
    summariser; artifacts carry the same contrast and where it comes from."""
    url = _build(tmp_path)
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{url}#hunts/EDGE-HUNT-0010")
    page.locator("#drawer").wait_for(state="visible")
    body = page.locator("#dBody").inner_text()
    assert "Normal" in body and "Suspicious" in body and "302013" in body
    # Both quotes were re-read on the live pages (2026-10-23); no hunt quote is
    # summariser-only any more, so the flag must not appear here.
    assert "read through a summariser" not in body
    page.goto(f"{url}#hunts?data=aaa-accounting")
    page.wait_for_timeout(300)
    shown, total = _counts(page, "hunts")
    assert 0 < shown < total
    page.goto(f"{url}#artifacts/EDGE-0005.10")
    page.locator("#drawer").wait_for(state="visible")
    body = page.locator("#dBody").inner_text()
    assert "what it gives you" in body.lower() and "Criterion from: Vendor" in body
    assert page.locator("#dBody code", has_text="disk0:/asdm.bin").count() >= 1


def test_intel_indicators_and_charts(browser, tmp_path):
    """Actors carry the publisher's indicators, defanged for display with the
    publisher's role on each; the intel page draws the timeline and matrix."""
    url = _build(tmp_path)
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{url}#intel")
    page.locator(".charts .tl").wait_for(state="visible")
    assert page.locator(".charts .tlr").count() >= 8
    assert page.locator(".charts .amx tbody tr").count() == 7
    page.goto(f"{url}#intel/EDGE-TA-0003")
    page.locator("#drawer").wait_for(state="visible")
    body = page.locator("#dBody")
    assert "actor-controlled" in body.inner_text() and "shared infrastructure" in body.inner_text()
    assert body.locator("details.iocd").count() == body.locator("details.iocd[open]").count() > 0   # lists open by default
    codes = body.locator(".ioct code").all_inner_texts()
    assert codes and all("[.]" in c for c in codes)            # addresses are defanged on screen
    with page.expect_download() as dl:
        body.locator('[data-ioc="EDGE-IOC-0004"][data-fmt="stix"]').click()
    import json
    bundle = json.loads(open(dl.value.path()).read())
    inds = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(inds) == 60 and all(o["pattern"].startswith("[ipv4-addr:value = '") for o in inds)
    assert "[.]" not in inds[0]["pattern"]                     # exports carry the real value


def test_response_verdict_lens_and_checklist(browser, tmp_path):
    """The verdict lens hides steps the analyzer's verdict does not call for and
    lives in the URL; ticks survive a reload; commands render as code."""
    url = _build(tmp_path)
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    page = ctx.new_page()
    page.goto(f"{url}#response/cisco-asa")
    art = page.locator('.resp[data-resp="cisco-asa"]')
    art.wait_for(state="visible")
    total = int(art.locator(".rall").inner_text())
    page.locator('.vbtn[data-v="SUSPICIOUS"]').click()
    assert page.url.endswith("#response/cisco-asa?verdict=SUSPICIOUS")
    shown = int(art.locator(".rall").inner_text())
    assert 0 < shown < total and art.locator(".rstep.off").count() == total - shown
    assert art.locator("code", has_text="show kernel process").count() >= 1
    art.locator(".rchk").first.check()
    assert art.locator(".rdone").inner_text() == "1"
    page.reload()
    art.wait_for(state="visible")
    assert art.locator(".rchk").first.is_checked()           # kept per viewer, per platform
    assert page.locator('.vbtn[data-v="SUSPICIOUS"]').get_attribute("aria-pressed") == "true"
    ctx.close()


def test_light_theme_is_the_default(browser, tmp_path):
    url = _build(tmp_path)
    page = browser.new_page(color_scheme="dark")
    page.goto(f"{url}#start")
    assert page.evaluate("document.documentElement.getAttribute('data-theme')") == "light"


def test_intel_drawer_jumps_and_indicator_filter(browser, tmp_path):
    url = _build(tmp_path)
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{url}#intel?iocs=yes")
    page.wait_for_timeout(300)
    shown, total = _counts(page, "intel")
    assert 0 < shown < total
    page.goto(f"{url}#intel/EDGE-TA-0003")
    page.locator("#drawer").wait_for(state="visible")
    jumps = page.locator("#dBody .djump a").all_inner_texts()
    assert [j.split()[0] for j in jumps] == ["Indicators", "Hunts", "Response"]
    assert page.locator('#dBody a[href="#response/cisco-asa"]').count() == 1
    assert page.locator('#dBody a[href^="#hunts/EDGE-HUNT-"]').count() >= 3


def test_byline_credits_the_author_and_firm(browser, tmp_path):
    url = _build(tmp_path)
    page = browser.new_page()
    page.goto(f"{url}#start")
    hrefs = page.locator(".byline a").evaluate_all("els => els.map(e => e.href)")
    assert hrefs == ["https://www.linkedin.com/in/raymond-depalma/", "https://www.linkedin.com/company/depalma-research"]
    assert "DePalma Research LLC" in page.locator("footer").inner_text()


def test_drawer_is_a_dialog_and_focus_round_trips(browser, tmp_path):
    """F16: opening a record moves focus into the drawer; closing it returns
    focus to the row that opened it, so a keyboard user keeps their place."""
    url = _build(tmp_path)
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{url}#artifacts")
    row = page.locator("#tab-artifacts .item").nth(2)
    rid = row.get_attribute("data-id")
    row.locator("a.locl").focus()                              # the locator is the row's link (F34)
    page.keyboard.press("Enter")
    page.locator("#drawer").wait_for(state="visible")
    assert page.locator("#drawer").get_attribute("role") == "dialog"
    assert page.locator("#drawer").get_attribute("aria-modal") == "true"
    assert page.evaluate("document.activeElement.id") == "dTitle"
    page.keyboard.press("j")                                   # stepping keeps focus where it is
    assert page.evaluate("document.activeElement.id") == "dTitle"
    page.keyboard.press("k")
    page.keyboard.press("Escape")
    page.locator("#drawer").wait_for(state="hidden")
    assert page.evaluate("document.activeElement.closest('.item').dataset.id") == rid


def test_text_is_never_the_faint_token(browser, tmp_path):
    """F33: --faint is for lines and decoration. Facet heads and table heads
    were set in it and failed contrast."""
    url = _build(tmp_path)
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    faint = ("() => { const s = document.createElement('span'); s.style.color = 'var(--faint)';"
             " document.body.appendChild(s); const c = getComputedStyle(s).color; s.remove(); return c; }")
    page.goto(f"{url}#artifacts")
    page.locator("#rail .fhead").first.wait_for(state="visible")
    f = page.evaluate(faint)
    for sel in ("#rail .fhead", "#tab-artifacts .row.head", "#rail .fv .fc", "footer"):
        assert page.locator(sel).first.evaluate("e => getComputedStyle(e).color") != f, sel
    page.goto(f"{url}#plans/panos")
    th = page.locator("#plan-panos .tbl thead th").first
    th.wait_for(state="visible")
    assert th.evaluate("e => getComputedStyle(e).color") != f


def test_platform_facets_use_short_names_and_keep_their_order(browser, tmp_path):
    """F8/F24: one short name everywhere a platform is picked, the full name on
    hover; the rail no longer reorders when another filter changes the counts."""
    url = _build(tmp_path)
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{url}#artifacts")
    lab = page.locator('#rail label:has(input[data-f="platform"][value="EDGE-0001"])')
    assert lab.locator(".fl").inner_text() == "PAN-OS"
    assert lab.get_attribute("title") == "PAN-OS / GlobalProtect"
    order = page.locator('#rail input[data-f="platform"]').evaluate_all("els => els.map(e => e.value)")
    assert order == sorted(order)                              # catalog order
    page.locator("#rail label:has(input[value='memory'])").click()
    assert page.locator('#rail input[data-f="platform"]').evaluate_all("els => els.map(e => e.value)") == order
    page.goto(f"{url}#response/cisco-asa")
    assert page.locator('.rbtn[data-resp="cisco-asa"]').inner_text() == "ASA/FTD"


def test_unvalidated_collection_warning(browser, tmp_path):
    url = _build(tmp_path)
    page = browser.new_page()
    page.goto(f"{url}#start")
    assert "been run against a real device" in page.locator("#tab-start .warnbox").inner_text()
    page.goto(f"{url}#plans/panos")
    assert page.locator("#tab-plans .warnbox").is_visible()
    assert "not yet run on a real device" in page.locator("#plan-panos .plan-h").inner_text()
    assert "type UNVALIDATED" in page.locator("#b-warn").inner_text()   # the builder's warning block (F29)
    page.locator("#tab-plans .warnbox a").click()
    page.wait_for_url("**#guide/unvalidated-profiles")
    page.locator("#tab-guide").wait_for(state="visible")
    page.locator("[id$='unvalidated-profiles']").first.wait_for(state="visible")


def test_coverage_readiness_and_kev_ledger(browser, tmp_path):
    """F17/F20: one readiness row per platform, one KEV ledger row per recorded
    decision, and #coverage/kev lands on the section under the sticky header."""
    import yaml
    url = _build(tmp_path)
    triaged = yaml.safe_load((ROOT / "artifacts" / "watch" / "kev-watch.yml").read_text())["triaged"]
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{url}#coverage/kev")
    page.locator("#tab-coverage").wait_for(state="visible")
    assert page.locator("#cov-ready [role=table] .rrow:not(.rhead)").count() == 10
    labels = page.locator("#cov-ready .rc").evaluate_all("els => els.map(e => e.getAttribute('aria-label'))")
    assert len(labels) == 80 and all(lab.endswith((": yes", ": no")) for lab in labels)
    assert page.locator("#cov-kev table.kev tbody tr").count() == len(triaged)
    page.wait_for_function("() => window.scrollY > 0")
    top = page.evaluate("document.getElementById('cov-kev').getBoundingClientRect().top")
    hdr = page.evaluate("document.querySelector('.hdr').offsetHeight")
    assert hdr <= top < hdr + 60


def test_response_lens_counts_and_case_ticks(browser, tmp_path):
    """F25/F26: each verdict button shows how many steps it keeps; a tick records
    its time and belongs to the case id; the read do-not list folds to three."""
    import re
    url = _build(tmp_path)
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    page = ctx.new_page()
    page.goto(f"{url}#response/cisco-asa")
    art = page.locator('.resp[data-resp="cisco-asa"]')
    art.wait_for(state="visible")
    for v in ("", "COMPROMISED", "LIKELY-COMPROMISED", "SUSPICIOUS", "NO-INDICATORS-FOUND"):
        btn = page.locator(f'.vbtn[data-v="{v}"]')
        n = int(btn.locator(".vn").inner_text())
        btn.click()
        assert int(art.locator(".rall").inner_text()) == n, v
    page.locator('.vbtn[data-v=""]').click()
    art.locator(".rcase").fill("IR-TEST-7")
    first = art.locator(".rstep").first
    first.locator(".rchk").check()
    assert re.fullmatch(r"ticked \d\d:\d\d UTC", first.locator(".rtick").inner_text())
    assert "for IR-TEST-7" in art.locator(".rprog-t").inner_text()
    assert "edt-resp-IR-TEST-7|cisco-asa" in page.evaluate("Object.keys(localStorage)")
    art.locator(".rcase").fill("")
    assert not first.locator(".rchk").is_checked()            # no case id: the original per-platform list
    art.locator(".rack").check()
    assert art.locator(".dont .dgrid li:visible").count() == 3
    assert art.locator(".rfold").is_visible()
    ctx.close()


def test_artifact_rows_group_highlight_and_link(browser, tmp_path):
    """F9/F10/F13/F34: rows grouped by platform until one platform is filtered,
    filter words marked, the locator is the row's link, detections show where they run."""
    url = _build(tmp_path)
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{url}#artifacts")
    page.locator("#tab-artifacts .grp").first.wait_for(state="visible")
    assert page.locator("#tab-artifacts .grp").count() == 10
    assert page.locator("#tab-artifacts .row.item[role=button], #tab-artifacts .row.item[tabindex]").count() == 0
    assert page.locator("#tab-artifacts .row.item a.locl").count() == page.locator("#tab-artifacts .row.item").count()
    page.goto(f"{url}#artifacts?platform=EDGE-0005")
    page.wait_for_timeout(200)
    assert page.locator("#tab-artifacts .grp").count() == 0
    page.goto(f"{url}#artifacts?q=lina")
    page.wait_for_timeout(200)
    marks = page.locator("#tab-artifacts .results mark").all_inner_texts()
    assert marks and all(m.lower() == "lina" for m in marks)
    page.goto(f"{url}#detections")
    page.locator("#tab-detections .lc").first.wait_for(state="visible")
    assert page.locator("#tab-detections .lc .runs").count() == page.locator("#tab-detections .lc").count()
    page.locator("#searchBtn").click()                        # until the palette ships it filters the library in view
    assert page.evaluate("document.activeElement.classList.contains('q')")


def test_record_drawer_facts_sections_and_connections(browser, tmp_path):
    """F15: quick facts first, a chip per section, position in the list, and
    a How it connects box with links into the other libraries."""
    url = _build(tmp_path)
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.goto(f"{url}#artifacts/EDGE-0005.10")
    page.locator("#drawer").wait_for(state="visible")
    assert page.locator("#dBody .dfacts dt").all_inner_texts()[:3] == ["Class", "Volatility", "Forensic value"]
    assert page.locator("#dPos").inner_text().endswith(" of 92")
    assert "How it connects" in page.locator("#dBody .dsecs button").all_inner_texts()
    page.locator("#dBody .dsecs button", has_text="How it connects").click()
    page.wait_for_function("() => document.getElementById('dBody').scrollTop > 0")
    assert page.locator("#dBody .dconn a[href^='#plans/']").count() == 1
    page.goto(f"{url}#intel/EDGE-TA-0003")
    page.locator("#drawer").wait_for(state="visible")
    first_two = page.locator("#dBody > nav").evaluate_all("els => els.map(e => e.className)")
    assert first_two[:2] == ["djump", "dsecs"]                 # the intel jumps stay first
