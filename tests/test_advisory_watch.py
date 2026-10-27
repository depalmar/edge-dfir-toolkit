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
    watch.write_text(yaml.safe_dump(WATCH))
    recs = tmp_path / "recs.yml"
    recs.write_text(yaml.safe_dump({"catalog": "x", "released": "2099-01-01", "records": []}))
    one = tmp_path / "kev1.json"
    one.write_text(json.dumps(kev(("CVE-2099-0001", "NobodyWatched", "x", "2099-01-02"))))
    args = ["--watch", str(watch), "--records-file", str(recs)]
    assert aw.main(["--kev", str(one)] + args) == 0
    watched = tmp_path / "kev2.json"   # a watched entry missing from the records file is drift
    watched.write_text(json.dumps(kev(("CVE-2099-0003", "ExampleVendor", "ExampleOS", "2099-01-02"))))
    assert aw.main(["--kev", str(watched)] + args) == aw.NEEDS_TRIAGE


def test_kev_records_come_from_the_feed_verbatim():
    k = kev(("CVE-2099-0001", "ExampleVendor", "ExampleOS", "2099-01-05"),
            ("CVE-2099-0002", "ExampleVendor", "ExampleOS", "2023-06-01"),   # before `since`, but a record names it
            ("CVE-2099-0004", "ExampleVendor", "ExampleOS", "2023-12-31"),   # before `since`, named by nothing
            ("CVE-2099-0007", "Apache", "HTTP Server", "2099-02-01"))        # another product, named by a record
    k["vulnerabilities"][0].update(forensicTriage="Yes", knownRansomwareCampaignUse="Known", cwes=["CWE-22"],
                                   notes="https://vendor.example/adv ; https://nvd.nist.gov/vuln/detail/CVE-2099-0001")
    recs = aw.kev_records(k, WATCH, {"CVE-2099-0002", "CVE-2099-0007"})
    assert [(r["cve"], r["platform"]) for r in recs] == [("CVE-2099-0001", "EDGE-0001"), ("CVE-2099-0002", "EDGE-0001"),
                                                          ("CVE-2099-0007", None)]
    first = recs[0]
    assert (first["forensic_triage"], first["ransomware"], first["cwes"], first["added"]) == ("Yes", "Known", ["CWE-22"], "2099-01-05")
    assert first["notes"].startswith("https://vendor.example/adv")
    assert aw.records_drift(recs, recs) == []
    stale = [dict(recs[0], forensic_triage="No"), recs[1], {"cve": "CVE-2099-0009"}]
    drift = {r["cve"]: r["change"] for r in aw.records_drift(stale, recs)}
    assert drift == {"CVE-2099-0001": "changed: forensic_triage", "CVE-2099-0007": "missing from the file",
                     "CVE-2099-0009": "no longer selected or not in KEV"}
    text = aw.records_text(k, recs)
    assert text.startswith("# CISA's Known Exploited Vulnerabilities fields") and yaml.safe_load(text)["records"] == recs
    assert "KEV records out of step" in aw.report(k, aw.triage(k, WATCH, {}), None, aw.records_drift([], recs))


def test_structured_refs_ignore_prose():
    refs = aw.structured_refs()
    assert "CVE-2024-3400" in refs and all(aw.CVE_RE.fullmatch(c) for c in refs)


def test_the_repository_ledger_matches_the_shipped_watch_config():
    # Every watched platform resolves, and the real ledger loads with the real packs.
    w = aw.load_watch()
    res = aw.triage({"vulnerabilities": []}, w, aw.pack_cves())
    assert res == {"new": [], "deferred": [], "decided": [], "covered": []}
    assert set(aw.ioc_files()) >= set(w["upstream"])


def test_cve_record_keeps_the_cna_weakness_and_cisa_ssvc():
    doc = {"cveMetadata": {"cveId": "CVE-2099-0001", "datePublished": "2099-01-03T10:00:00Z", "assignerShortName": "example"},
           "containers": {"cna": {"problemTypes": [{"descriptions": [
               {"cweId": "CWE-22", "description": "CWE-22 Improper Limitation of a Pathname ('Path Traversal')"},
               {"description": "CWE-20 Improper Input Validation"}]}]},
               "adp": [{"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": [{"other": {"type": "ssvc", "content": {
                   "timestamp": "2099-01-04T00:00:00Z",
                   "options": [{"Exploitation": "active"}, {"Automatable": "no"}, {"Technical Impact": "total"}]}}}]},
                   {"providerMetadata": {"shortName": "CVE"}}]}}
    r = aw.cve_record(doc)
    assert r == {"cve": "CVE-2099-0001", "published": "2099-01-03", "assigner": "example",
                 "cwes": [{"id": "CWE-22", "name": "Improper Limitation of a Pathname ('Path Traversal')"},
                          {"id": "CWE-20", "name": "Improper Input Validation"}],
                 "cisa_ssvc": {"exploitation": "active", "automatable": "no", "technical_impact": "total", "assessed": "2099-01-04"}}
    text = aw.cve_records_text(["CVE-2099-0001", "CVE-2099-0002"],
                               getter=lambda u: json.dumps(doc).encode() if u.endswith("0001") else (_ for _ in ()).throw(OSError()))
    assert "# not fetched: CVE-2099-0002: OSError" in text and yaml.safe_load(text)["records"] == [r]
