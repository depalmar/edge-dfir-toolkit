"""Memory images: format sniffing, the chunked scan, the indicator sweep, Volatility plumbing.

Every image here is synthetic: zero-filled bytes with planted strings, and the
indicator sets are written into a temporary directory with documentation
addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and example domains.
"""
from __future__ import annotations

import gzip
import json
import os
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from edgetriage import memory  # noqa: E402
from edgetriage.analyze import analyze, verdict  # noqa: E402
from edgetriage.custody import Case  # noqa: E402
from edgetriage.evidence import EvidenceView  # noqa: E402

JUNOS = "EDGE-0008"
PEL = [b"pel_client_init", b"pel_server_init", b"pel_send_msg", b"pel_recv_msg"]   # Mandiant's hunting rule needs 4


def lime(body: bytes) -> bytes:
    """A one-range LiME file: lime.h's header (magic, version, s_addr, e_addr, reserved) then the bytes."""
    return struct.pack("<IIQQ8s", memory.LIME_MAGIC, 1, 0, len(body) - 1, b"\0" * 8) + body


def plant(size: int, items: list[tuple[int, bytes]]) -> bytes:
    b = bytearray(size)
    for off, s in items:
        b[off:off + len(s)] = s
    return bytes(b)


def ioc_dir(tmp: Path) -> Path:
    d = tmp / "iocs"
    d.mkdir(exist_ok=True)
    (d / "EDGE-IOC-9001-test.yml").write_text(
        "id: EDGE-IOC-9001\npublisher: Test publisher\nplatforms: [EDGE-0008]\nstaleness: synthetic\nindicators:\n"
        "  - {type: ipv4, value: 198.51.100.7, role: unknown, context: test}\n"
        "  - {type: ipv4, value: 203.0.113.9, role: actor-controlled, context: test}\n"
        "  - {type: domain, value: update.example.net, role: unknown, context: test}\n"
        "  - {type: sha256, value: '" + "0" * 64 + "', role: unknown, context: a hash is not searched as text}\n")
    return d


def mem_case(tmp: Path, data: bytes, name: str = "mem.lime", classes=("memory",), case_id: str = "IR-MEM",
             gz: bool = False) -> Path:
    src = tmp / ("src-" + case_id) / name
    src.parent.mkdir(parents=True)
    src.write_bytes(gzip.compress(data) if gz else data)
    case = Case(tmp / case_id)
    m = Case.new_manifest(case_id, "tester", JUNOS, None)
    m["expected_evidence"] = ["memory"]
    m["ingested"].append(case.ingest(src, "mem", evidence_classes=list(classes)))
    case.save(m)
    return case.root


def row(out: dict, rid: str) -> dict:
    return next(r for r in out["detections"] if r["id"] == rid)


@pytest.fixture
def small_pieces(monkeypatch):
    """Pieces of 4 KiB that overlap by 1 KiB, so a seam is easy to straddle."""
    monkeypatch.setattr(memory, "CHUNK", 4096)
    monkeypatch.setattr(memory, "OVERLAP", 1024)
    monkeypatch.setattr(memory, "MARGIN", 64)


# ------------------------------------------------------------------ what a file is
def test_sniff_tells_images_from_files(tmp_path):
    def s(data: bytes, gz: bool = False) -> dict:
        p = tmp_path / f"f{len(list(tmp_path.iterdir()))}"
        p.write_bytes(gzip.compress(data) if gz else data)
        return memory.sniff(p)
    assert s(lime(b"\0" * 64))["format"] == "lime"
    be = struct.pack(">IIQQ8s", memory.LIME_MAGIC, 1, 0, 63, b"\0" * 8) + b"\0" * 64
    assert s(be)["format"] == "lime"
    core = b"\x7fELF\x02\x01\x01" + b"\0" * 9 + struct.pack("<H", 4) + b"\0" * 64      # e_type ET_CORE
    assert s(core)["format"] == "elf-core"
    exe = b"\x7fELF\x02\x01\x01" + b"\0" * 9 + struct.pack("<H", 2) + b"\0" * 64       # ET_EXEC: a recovered binary
    assert s(exe)["format"] == "elf"
    assert s(b"RayDetect report\nno findings\n")["format"] == "text"
    assert s(b"")["format"] == "empty"
    assert s(b"\0\x01\x02" * 100)["format"] == "raw"
    g = s(lime(b"\0" * 64), gz=True)
    assert g["format"] == "lime" and g["compressed"]


def test_only_rules_that_read_nothing_but_strings_run_against_memory():
    """Every rule in the repository is parsed, and the split is pinned: a size limit, a header
    check, a whole-file hash or a string offset describes a file, not memory."""
    import glob
    conds = {}
    for f in sorted(glob.glob(str(ROOT / "0*" / "*.yar"))):
        conds.update(memory.rule_conditions(Path(f).read_text()))
    assert all(c is not None for c in conds.values())
    safe = {n for n, c in conds.items() if memory.layout_reads(c) is None}
    assert safe == {"PANOS_UPSTYLE_Payload", "M_Hunting_PacketEncryptionLayer_1", "M_Hunting_TINYSHELL_5"}
    assert "the file's size" in memory.layout_reads(conds["Junos_UNC3886_TINYSHELL_Published_Strings"])
    assert "bytes at fixed offsets" in memory.layout_reads(conds["u42_apt_linux_PEERSTITCH_fortigate_implant"])
    assert "a module" in memory.layout_reads(conds["SonicWall_SMA_OVERSTEP_Published_Hash"])
    assert "where its strings sit" in memory.layout_reads(conds["M_Hunting_CredTheft_WARPWIRE_strings"])
    yara = pytest.importorskip("yara")
    for f in sorted(glob.glob(str(ROOT / "0*" / "*.yar"))):     # the parser sees every rule YARA compiles
        assert {r.identifier for r in yara.compile(filepath=f)} <= set(conds), f


def test_a_text_report_ingested_as_memory_stays_a_file(tmp_path):
    root = mem_case(tmp_path, b"RayDetect: no RayInitiator found\n", name="raydetect.txt")
    v = EvidenceView(root)
    assert v.memory_images() == [] and [s.ref for s in v.all_files()] == ["[mem]/raydetect.txt"]
    out = analyze(root)
    assert "memory" not in out and not any(g["kind"] == "missing-evidence-class" for g in out["evidence_gaps"])


# ------------------------------------------------------------------ the scan
def test_memory_image_is_not_scanned_as_a_file(tmp_path):
    """The TINYSHELL file rule guards on filesize: against a dump it could only say no-hit. It is
    not evaluated instead, and the memory section names it as not run, with the reason."""
    pytest.importorskip("yara")
    root = mem_case(tmp_path, lime(plant(1 << 16, [(4000, b"uSarguuS62bKRA0J")])))
    out = analyze(root, ioc_dir=ioc_dir(tmp_path))
    file_rule = row(out, "junos-unc3886-tinyshell-yara")
    assert file_rule["status"] == "not-evaluated"
    assert "a memory image is not a file to this rule" in file_rule["needs"]
    skipped = {r["rule"]: r["why"] for r in out["memory"]["yara"]["rules_not_run"]}
    assert skipped["Junos_UNC3886_TINYSHELL_Published_Strings"] == "the file's size"
    assert row(out, "memory-yara")["status"] == "no-hit"
    md = (root / "report.md").read_text()
    assert "## Memory" in md and "Junos_UNC3886_TINYSHELL_Published_Strings (junos_unc3886_tinyshell.yar) reads the file's size" in md


def test_a_rule_across_a_seam_is_found_once(tmp_path, small_pieces):
    """Two sets of the four strings: one straddling the first seam (step = 3072), one wholly inside
    the overlap that both pieces read. Each of the eight string matches is counted once, at its
    offset in the image."""
    pytest.importorskip("yara")
    a = [(2990, PEL[0]), (3020, PEL[1]), (3080, PEL[2]), (3110, PEL[3])]           # straddles 3072
    b = [(3400 + 40 * i, s) for i, s in enumerate(PEL)]                              # inside 3072..4096
    body = plant(12000, a + b)
    root = mem_case(tmp_path, lime(body))
    out = analyze(root, ioc_dir=ioc_dir(tmp_path))
    r = row(out, "memory-yara")
    assert r["status"] == "hit" and r["hit_count"] == 1
    h = r["hits"][0]
    assert h["extra"]["rule"] == "M_Hunting_PacketEncryptionLayer_1"
    assert h["extra"]["string_matches"] == 8 and h["extra"]["offset"] == 32 + 2990  # LiME header is 32 bytes
    assert "8 string matches, first at offset 0xbce" in h["detail"]
    assert h["excerpt"] == "pel_client_init · pel_server_init"                 # the text, not \x00 after \x00
    assert h["tier"] == "likely"                                                      # the pack's tier, at most likely
    assert out["verdict"]["level"] == "LIKELY-COMPROMISED"
    assert out["memory"]["images"][0]["bytes_read"] == 32 + 12000


def test_gzip_image_is_read_through(tmp_path, small_pieces):
    pytest.importorskip("yara")
    body = plant(9000, [(5000 + 30 * i, s) for i, s in enumerate(PEL)])
    out = analyze(mem_case(tmp_path, lime(body), name="mem.lime.gz", gz=True), ioc_dir=ioc_dir(tmp_path))
    assert row(out, "memory-yara")["status"] == "hit"
    im = out["memory"]["images"][0]
    assert im["compressed"] and im["bytes_read"] == 32 + 9000


def test_indicators_are_whole_text_matches_with_the_publishers_role(tmp_path, small_pieces):
    """ASCII and UTF-16LE text, whole addresses only, and every hit is a lead that does not corroborate."""
    pytest.importorskip("yara")
    items = [
        (100, b"conn from 198.51.100.7:443 refused"),
        (300, b"198.51.100.70 is another address"),          # longer number: not the indicator
        (400, b"x1198.51.100.7 y"),                           # digit before: not the indicator
        (500, b"ip 198.51.100.7.5 dotted"),                   # inside a longer dotted run: not the indicator
        (5000, "peer 203.0.113.9 seen".encode("utf-16-le")),
        (7000, b"GET http://Update.Example.NET/x"),
        (9000, b"Linux version 5.10.0-synthetic (b@h) (gcc 10) #1 SMP\n"),
    ]
    root = mem_case(tmp_path, lime(plant(12000, items)))
    out = analyze(root, ioc_dir=ioc_dir(tmp_path))
    r = row(out, "memory-indicators")
    by = {h["extra"]["value"]: h for h in r["hits"]}
    assert set(by) == {"198.51.100.7", "203.0.113.9", "update.example.net"}
    assert by["198.51.100.7"]["extra"]["places"] == 1 and by["198.51.100.7"]["extra"]["offset"] == 32 + 110
    assert by["203.0.113.9"]["extra"]["encodings"] == ["UTF-16LE"] and by["203.0.113.9"]["extra"]["roles"] == ["actor-controlled"]
    assert by["203.0.113.9"]["excerpt"] == "peer 203.0.113.9 seen"            # UTF-16 read as text, padding dropped
    assert by["198.51.100.7"]["excerpt"] == "conn from 198.51.100.7:443 refused"
    assert all(h["tier"] == "possible" and h["corroborates"] is False for h in r["hits"])
    assert out["memory"]["indicators"]["values"] == 3                     # the hash is not searched as text
    assert out["memory"]["banners"][0]["banner"].startswith("Linux version 5.10.0-synthetic")
    md = (root / "report.md").read_text()
    assert "198[.]51[.]100[.]7" in md and "198.51.100.7 (ipv4" not in md   # defanged in the report
    assert "lead" in out["verdict"]["rationale"] and out["verdict"]["level"] == "SUSPICIOUS"


def test_memory_leads_never_corroborate():
    web = {"id": "w", "evidence_class": "web-logs", "hits": [{"tier": "possible"}]}
    lead = {"id": "memory-indicators", "evidence_class": "memory", "hits": [{"tier": "possible", "corroborates": False}]}
    assert verdict([web, lead])["level"] == "SUSPICIOUS"
    assert verdict([web, dict(lead, hits=[{"tier": "possible"}])])["level"] == "LIKELY-COMPROMISED"
    disk = {"id": "f", "evidence_class": "persistence", "hits": [{"tier": "likely"}]}
    same = {"id": "memory-yara", "evidence_class": "memory", "hits": [{"tier": "likely", "corroborates": False}]}
    assert verdict([disk, same])["level"] == "LIKELY-COMPROMISED"


def test_a_memory_match_on_a_rule_that_hit_as_a_file_does_not_count_again():
    mem = {"yara": {"rules_run": [{"file": "f.yar", "rule": "R", "detection": "d", "pack": "P", "cves": [],
                                   "attack": [], "tier": "likely"}],
                    "found": {"[mem]/m": {"f.yar::R": {"offsets": [10], "excerpt": None}}}, "status": "evaluated"},
           "own": None, "indicators": {"status": "evaluated", "found": {}}, "_vals": {}}
    h = memory.results(mem, {("f.yar", "R")})[0]["hits"][0]
    assert h["corroborates"] is False and "does not count again" in h["detail"]
    assert "corroborates" not in memory.results(mem, set())[0]["hits"][0]


def test_own_rules_run_against_memory(tmp_path, small_pieces):
    pytest.importorskip("yara")
    rules = tmp_path / "mine.yar"
    rules.write_text('rule Own_Marker { strings: $a = "edge-test-marker" condition: $a }\n')
    out = analyze(mem_case(tmp_path, lime(plant(9000, [(6000, b"edge-test-marker")]))),
                  memory_yara=[rules], ioc_dir=ioc_dir(tmp_path))
    r = row(out, "memory-yara-own")
    assert r["status"] == "hit" and r["hits"][0]["tier"] == "possible" and r["hits"][0]["extra"]["offset"] == 32 + 6000
    bad = tmp_path / "bad.yar"
    bad.write_text("rule Broken { condition: nonsense_identifier }\n")
    out = analyze(mem_case(tmp_path, lime(b"\0" * 100), case_id="IR-MEM-BAD"), memory_yara=[bad], ioc_dir=ioc_dir(tmp_path))
    assert row(out, "memory-yara-own")["status"] == "not-evaluated"
    assert "did not compile" in row(out, "memory-yara-own")["reason"]


def test_nothing_read_is_not_evaluated(tmp_path):
    pytest.importorskip("yara")
    out = analyze(mem_case(tmp_path, b"", name="empty.raw"), ioc_dir=ioc_dir(tmp_path))
    for rid in ("memory-yara", "memory-indicators"):
        assert row(out, rid)["status"] == "not-evaluated" and "read 0 bytes" in row(out, rid)["reason"]
    assert any(g["kind"] == "memory-not-scanned" for g in out["evidence_gaps"])


def test_without_yara_the_memory_checks_say_not_evaluated(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "yara", None)       # import yara raises ImportError
    out = analyze(mem_case(tmp_path, lime(b"\0" * 100)), ioc_dir=ioc_dir(tmp_path))
    for rid in ("memory-yara", "memory-indicators"):
        assert row(out, rid)["status"] == "not-evaluated" and "yara-python" in row(out, rid)["reason"]
    gap = next(g for g in out["evidence_gaps"] if g["kind"] == "memory-not-scanned")
    assert "pip install" in gap["close"]
    assert out["verdict"]["level"] == "NO-INDICATORS-FOUND"


def test_a_truncated_gzip_image_is_an_incomplete_read(tmp_path, small_pieces):
    pytest.importorskip("yara")
    data = gzip.compress(lime(os.urandom(20000)))
    src = tmp_path / "cut.lime.gz"
    src.write_bytes(data[: len(data) // 2])
    case = Case(tmp_path / "IR-CUT")
    m = Case.new_manifest("IR-CUT", "tester", JUNOS, None)
    m["ingested"].append(case.ingest(src, "mem", evidence_classes=["memory"]))
    case.save(m)
    out = analyze(case.root, ioc_dir=ioc_dir(tmp_path))
    assert out["memory"]["images"][0]["error"].startswith("stopped at offset")
    assert any(g["kind"] == "memory-read-incomplete" for g in out["evidence_gaps"])


def test_a_memory_ingest_is_not_mistaken_for_a_zip(tmp_path):
    """is_zipfile finds an end-of-directory record near the end of a file; a dump holding a cached
    zip there must stay one image, not be 'extracted' into nothing."""
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("cached.txt", "synthetic")
    data = lime(b"\0" * 5000) + buf.getvalue()
    assert zipfile.is_zipfile(io.BytesIO(data))           # the trap is real
    root = mem_case(tmp_path, data)
    rec = json.loads((root / "manifest.json").read_text())["ingested"][0]
    assert rec["extracted_to"] is None
    assert [i.format for i in EvidenceView(root).memory_images()] == ["lime"]


# ------------------------------------------------------------------ Volatility 3
FAKE_VOL = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
if "--help" in args:
    print("Volatility 3 Framework 9.9.9")
    print("plugins:")
    for p in ("linux.pslist.PsList", "linux.lsmod.Lsmod", "linux.malware.malfind.Malfind"):
        print("    " + p + "  something")
    sys.exit(0)
with open(os.environ["VOL_LOG"], "a") as fh:
    fh.write(json.dumps(args) + "\n")
if args[-1] == "linux.lsmod.Lsmod":
    sys.stderr.write("Volatility 3 Framework 9.9.9\nUnable to validate the plugin requirements: ['x']\n")
    sys.exit(1)
print(json.dumps([{"PID": 1, "__children": []}, {"PID": 2, "__children": []}]))
'''


@pytest.mark.skipif(sys.platform == "win32", reason="the fake vol is a POSIX script")
def test_volatility_runs_offline_records_outputs_and_is_not_rerun(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    vol = bin_dir / "vol"
    vol.write_text(FAKE_VOL)
    vol.chmod(0o755)
    log = tmp_path / "vol.log"
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setenv("VOL_LOG", str(log))
    symbols = tmp_path / "symbols"
    symbols.mkdir()
    root = mem_case(tmp_path, lime(b"\0" * 4096))
    out = analyze(root, memory_symbols=symbols, ioc_dir=ioc_dir(tmp_path))
    v = out["memory"]["volatility"][0]
    assert v["status"] == "ran" and v["version"] == "9.9.9"
    p = {x["name"]: x for x in v["plugins"]}
    assert p["pslist"]["status"] == "ok" and p["pslist"]["rows"] == 2
    assert p["malfind"]["plugin"] == "linux.malware.malfind.Malfind"          # the newest name this vol has
    assert p["lsmod"]["status"] == "failed" and "Unable to validate" in p["lsmod"]["reason"]
    assert p["sockstat"]["status"] == "unavailable"
    saved = root / p["pslist"]["output"]
    import hashlib
    assert hashlib.sha256(saved.read_bytes()).hexdigest() == p["pslist"]["sha256"]
    calls = [json.loads(x) for x in log.read_text().splitlines()]
    assert calls and all("--offline" in c and "-s" in c for c in calls)
    assert "pslist 2 row(s)" in (root / "report.md").read_text()
    analyze(root, memory_symbols=symbols, ioc_dir=ioc_dir(tmp_path))
    again = [json.loads(x) for x in log.read_text().splitlines()]
    assert [c[-1] for c in again[len(calls):]] == ["linux.lsmod.Lsmod"]      # only the failed plugin runs again


def test_volatility_needs_symbols(tmp_path):
    out = analyze(mem_case(tmp_path, lime(b"\0" * 100)), ioc_dir=ioc_dir(tmp_path))
    assert out["memory"]["volatility"][0] == {"ref": "[mem]/mem.lime", "status": "not run",
                                              "reason": "no symbols given (--memory-symbols DIR)"}
