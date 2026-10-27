"""advisory_watch.py: reports, never edits, and the ledger is honoured."""
import importlib.util
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("advisory_watch", ROOT / "artifacts/scripts/advisory_watch.py")
aw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aw)

WATCH = {
    "since": "2024-01-01",
    "platforms": {"EDGE-0001": {"vendor": "^ExampleVendor$", "product": "^ExampleOS"},
                  "EDGE-0006": {"vendor": "^OtherVendor$", "product": "SMA ?100(?!0)"}},
    "upstream": {"EDGE-IOC-0001": "0" * 64},
    "triaged": [{"cve": "CVE-2099-0003", "platform": "EDGE-0001", "decision": "deferred",
                 "date": "2099-01-01", "basis": "not yet triaged"}],
}


def kev(*rows):
    keys = ("cveID", "vendorProject", "product", "dateAdded")
    return {"catalogVersion": "2099.01.01", "vulnerabilities": [dict(zip(keys, r)) for r in rows]}


def test_new_covered_triaged_and_out_of_scope_are_separated():
    k = kev(("CVE-2099-0001", "ExampleVendor", "ExampleOS", "2099-01-02"),   # new
            ("CVE-2099-0002", "ExampleVendor", "ExampleOS", "2099-01-02"),   # covered by a pack
            ("CVE-2099-0003", "ExampleVendor", "ExampleOS", "2099-01-02"),   # in the ledger
            ("CVE-2099-0004", "ExampleVendor", "ExampleOS", "2023-12-31"),   # before `since`
            ("CVE-2099-0005", "ExampleVendor", "OtherProduct", "2099-01-02"),  # not a watched product
            ("CVE-2099-0006", "OtherVendor", "SMA1000 Appliances", "2099-01-02"))  # the other product line
    res = aw.triage(k, WATCH, {"CVE-2099-0002": ["EDGE-PACK-9999"]})
    assert [r["cve"] for r in res["new"]] == ["CVE-2099-0001"]
    assert [r["cve"] for r in res["covered"]] == ["CVE-2099-0002"]
    assert [r["cve"] for r in res["deferred"]] == ["CVE-2099-0003"]
    assert "CVE-2099-0001" in aw.report(k, res, None)


def test_upstream_change_and_unreachable_are_both_reported():
    files = {"EDGE-IOC-0001": "https://example.invalid/iocs.csv"}
    assert aw.upstream_changes(WATCH, files, getter=lambda _u: b"changed")[0]["id"] == "EDGE-IOC-0001"

    def down(_u):
        raise OSError("offline")
    assert "unreachable" in aw.upstream_changes(WATCH, files, getter=down)[0]["now"]


def test_exit_codes_and_empty_catalog_refused(tmp_path):
    empty = tmp_path / "kev.json"
    empty.write_text(json.dumps({"vulnerabilities": []}))
    assert aw.main(["--kev", str(empty)]) == 1
    watch = tmp_path / "watch.yml"
    watch.write_text(yaml.safe_dump({**WATCH, "kev_added": {}}))
    one = tmp_path / "kev1.json"
    one.write_text(json.dumps(kev(("CVE-2099-0001", "NobodyWatched", "x", "2099-01-02"))))
    assert aw.main(["--kev", str(one), "--watch", str(watch)]) == 0
    watched = tmp_path / "kev2.json"   # a watched entry with no date in the ledger is drift
    watched.write_text(json.dumps(kev(("CVE-2099-0003", "ExampleVendor", "ExampleOS", "2099-01-02"))))
    assert aw.main(["--kev", str(watched), "--watch", str(watch)]) == aw.NEEDS_TRIAGE


def test_kev_dates_and_drift_come_from_the_feed():
    k = kev(("CVE-2099-0001", "ExampleVendor", "ExampleOS", "2099-01-05"),
            ("CVE-2099-0002", "ExampleVendor", "ExampleOS", "2099-01-02"),
            ("CVE-2099-0004", "ExampleVendor", "ExampleOS", "2023-12-31"))   # before `since`
    dates = aw.kev_dates(k, WATCH)
    assert dates == {"EDGE-0001": {"CVE-2099-0002": "2099-01-02", "CVE-2099-0001": "2099-01-05"}}
    assert aw.date_drift({**WATCH, "kev_added": dates}, dates) == []
    ledger = {"EDGE-0001": {"CVE-2099-0002": "2099-01-01", "CVE-2099-0009": "2099-01-01"}}
    drift = {r["cve"]: (r["ledger"], r["feed"]) for r in aw.date_drift({**WATCH, "kev_added": ledger}, dates)}
    assert drift == {"CVE-2099-0001": ("missing", "2099-01-05"), "CVE-2099-0002": ("2099-01-01", "2099-01-02"),
                     "CVE-2099-0009": ("2099-01-01", "not in KEV")}
    assert "KEV dates out of step" in aw.report(k, aw.triage(k, WATCH, {}), None, aw.date_drift(WATCH, dates))


def test_the_repository_ledger_matches_the_shipped_watch_config():
    # Every watched platform resolves, and the real ledger loads with the real packs.
    w = aw.load_watch()
    res = aw.triage({"vulnerabilities": []}, w, aw.pack_cves())
    assert res == {"new": [], "deferred": [], "decided": [], "covered": []}
    assert set(aw.ioc_files()) >= set(w["upstream"])
