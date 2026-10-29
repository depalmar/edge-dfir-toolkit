"""Memory images: what each one is, and what is in it.

A memory image comes into a case by `ingest --evidence-class memory`: the memory
of a hypervisor snapshot, a LiME capture, a vendor core dump. The file
detections never read it - a file rule's size limit, header check or whole-file
hash describes a file, not memory, so scanned as a file it could only ever say
no-hit. It is read here instead, in overlapping pieces, and three checks report
beside the packs:

- memory-yara: the platform packs' YARA rules whose condition reads nothing but
  their strings. A rule that reads the file's size, bytes at fixed offsets, a
  module or where its strings sit is listed as not run, with the reason.
- memory-yara-own: rules the operator supplies with --memory-yara.
- memory-indicators: the platform's published network indicators, as ASCII and
  UTF-16LE text. A lead that never corroborates: the device may hold the
  address because it logged the connection a log detection already found.

A match shows the bytes were in memory, not where they came from, so a pack
rule's tier is capped at likely. A raw image keeps physical pages in no order:
the strings of one program can sit far apart, so a rule that needs several can
miss, and no hit is weak evidence.

Volatility 3 runs only when the operator passes symbols for the image's kernel
(--memory-symbols), always offline. Its outputs are kept in the case with their
hashes; the analyzer does not parse or score them.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import re
import shutil
import struct
import subprocess
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterator

import yaml

from .checks import Hit
from .util import REPO_ROOT

IOC_DIR = REPO_ROOT / "artifacts" / "intel" / "iocs"
CHUNK = 64 << 20      # bytes read and scanned at a time
OVERLAP = 1 << 20     # carried from one piece into the next, so a match across the seam is seen whole
MARGIN = 4096         # an indicator's offset belongs to one piece, MARGIN in from its seams, so its neighbours are there
PROBE = 64 << 10      # bytes read to tell what a file is
GZIP_MAGIC = b"\x1f\x8b"
LIME_MAGIC = 0x4C694D45   # LiME src/lime.h: "#define LIME_MAGIC 0x4C694D45 //LiME"
ET_CORE = 4               # elf.h: "#define ET_CORE 4 /* Core file */"
IMAGE_FORMATS = ("lime", "elf-core", "raw", "empty")
TIERS = ("possible", "likely", "confirmed")
TIER_CAP = "likely"
NET_TYPES = ("ipv4", "ipv6", "domain", "url")
MAX_KEPT = 50
# init/version-timestamp.c: linux_banner = "Linux version " UTS_RELEASE " (" LINUX_COMPILE_BY "@" ...
BANNER = b"Linux version "
VOL_TIMEOUT = 3600
VOL_PLUGINS = (   # (name in the case, plugin names newest first); recorded, never scored
    ("pslist", ("linux.pslist.PsList",)),
    ("psaux", ("linux.psaux.PsAux",)),
    ("lsmod", ("linux.lsmod.Lsmod",)),
    ("hidden_modules", ("linux.malware.hidden_modules.Hidden_modules", "linux.hidden_modules.Hidden_modules")),
    ("check_syscall", ("linux.malware.check_syscall.Check_syscall", "linux.check_syscall.Check_syscall")),
    ("malfind", ("linux.malware.malfind.Malfind", "linux.malfind.Malfind")),
    ("netfilter", ("linux.malware.netfilter.Netfilter", "linux.netfilter.Netfilter")),
    ("sockstat", ("linux.sockstat.Sockstat",)),
    ("bash", ("linux.bash.Bash",)),
)

YARA_NOTE = ("A match shows the bytes were in memory, not where they came from: a program the device ran, a file it "
             "cached, a request it received. A pack rule's tier is capped at likely here. A raw image keeps physical pages "
             "in no order, so the strings of one program can sit far apart and a rule that needs several can miss: no hit "
             "is weak evidence. A match on the same rule as a file hit in this case does not count again.")
OWN_NOTE = ("Rules you supplied with --memory-yara. Their confidence is yours to state; the analyzer scores a match as "
            "possible.")
IOC_NOTE = ("Published network indicators found as text in memory, with the publisher's role for each. A lead, not "
            "corroboration: the device may hold the address because it logged, refused or routed the same connection a "
            "log detection found. Most published addresses are compromised third parties, VPN exits or shared hosting.")


# --------------------------------------------------------------------------- what a file is
TEXT_BYTES = frozenset(b"\t\n\r" + bytes(range(0x20, 0x7F)))


@dataclass
class Image:
    """One memory image in the case."""
    label: str              # the ingest label
    ref: str                # how the report names it: [label]/file
    local: Path
    sha256: str | None      # the ingest record's hash of the stored file
    format: str
    compressed: bool
    detail: str


def _head(path: Path, n: int = PROBE) -> tuple[bytes, bool]:
    with open(path, "rb") as fh:
        compressed = fh.read(2) == GZIP_MAGIC
    try:
        with (gzip.open(path, "rb") if compressed else open(path, "rb")) as fh:
            return fh.read(n), compressed
    except (EOFError, OSError, zlib.error):
        return b"", compressed


def sniff(path: Path) -> dict[str, Any]:
    """What a file ingested as memory is: LiME, an ELF core, text, or raw bytes. Only
    LiME, ELF core, raw and empty files are images; text (a scanner's report) and other
    ELF files (a recovered binary) stay files for the packs to read."""
    head, gz = _head(path)
    out: dict[str, Any] = {"compressed": gz}
    if not head:
        return out | {"format": "empty", "detail": "no bytes" + (" after decompression" if gz else "")}
    le, be = struct.pack("<I", LIME_MAGIC), struct.pack(">I", LIME_MAGIC)
    if len(head) >= 24 and head[:4] in (le, be):
        ver, start, end = struct.unpack(("<" if head[:4] == le else ">") + "IQQ", head[4:24])
        return out | {"format": "lime", "detail": f"LiME, header version {ver}, first range 0x{start:x}-0x{end:x}"}
    if head[:4] == b"\x7fELF" and len(head) >= 18 and head[5] in (1, 2):
        etype = struct.unpack(("<" if head[5] == 1 else ">") + "H", head[16:18])[0]
        if etype == ET_CORE:
            return out | {"format": "elf-core", "detail": "ELF core file (e_type ET_CORE)"}
        return out | {"format": "elf", "detail": f"ELF file of type {etype}, not a core file: read as a file"}
    if all(b in TEXT_BYTES for b in head):
        return out | {"format": "text", "detail": "text, not a memory image: read as a file"}
    return out | {"format": "raw", "detail": "no LiME or ELF core header: read as raw memory"}


def chunks(img: Image) -> Iterator[tuple[int, bytes, bool]]:
    """(offset in the image, bytes, last piece). Each piece repeats the last OVERLAP
    bytes of the one before. A gzip-compressed image is decompressed as it is read."""
    step = CHUNK - OVERLAP
    with (gzip.open(img.local, "rb") if img.compressed else open(img.local, "rb")) as fh:
        data, base = fh.read(CHUNK), 0
        while data:
            more = fh.read(step)
            yield base, data, not more
            if not more:
                return
            data, base = data[step:] + more, base + step


# --------------------------------------------------------------------------- which rules can read memory
_RULE = re.compile(r"^[ \t]*(?:(?:private|global)\s+)*rule\s+(\w+)(?:\s*:\s*[\w \t]+?)?\s*\{", re.M)
_COND = re.compile(r"\bcondition\s*:")
LAYOUT = (   # what a condition can read that a memory image does not keep
    (re.compile(r"\bfilesize\b"), "the file's size"),
    (re.compile(r"\bu?int(?:8|16|32)(?:be)?\s*\("), "bytes at fixed offsets"),
    (re.compile(r"\bentrypoint\b"), "the entry point"),
    (re.compile(r"\b(?:pe|elf|macho|dex|dotnet|hash|math|magic|cuckoo|lnk)\s*\."), "a module"),
    (re.compile(r"@\w*|\bat\b|\bin\s*\("), "where its strings sit"),
)


def rule_conditions(text: str) -> dict[str, str | None]:
    """Each rule's condition, comments removed; None when it could not be read."""
    starts = [(m.start(), m.group(1)) for m in _RULE.finditer(text)]
    out: dict[str, str | None] = {}
    for i, (pos, name) in enumerate(starts):
        sec = text[pos:starts[i + 1][0] if i + 1 < len(starts) else len(text)]
        end = sec.rfind("}")
        conds = [c for c in _COND.finditer(sec) if c.end() <= end]
        if not conds:
            out[name] = None
            continue
        cond = re.sub(r"/\*.*?\*/", " ", sec[conds[-1].end():end], flags=re.S)
        out[name] = " ".join(re.sub(r"//[^\n]*", " ", cond).split())
    return out


def layout_reads(cond: str | None) -> str | None:
    """None when a condition reads only its strings; otherwise what else it reads."""
    if cond is None:
        return "a condition this parser could not read"
    why = [w for rx, w in LAYOUT if rx.search(cond)]
    return ", ".join(why) if why else None


def pack_rules(packs: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The packs' YARA rules split into those that can run against memory and those that cannot."""
    run, skip, seen = [], [], set()
    for pack in packs:
        for det in pack.get("detect", []):
            if det.get("type") != "yara" or det["rule"] in seen:
                continue
            seen.add(det["rule"])
            text = (REPO_ROOT / det["rule"]).read_text(encoding="utf-8")
            base = {"file": det["rule"], "detection": det["id"], "pack": pack["id"], "cves": pack.get("cves", []),
                    "attack": det.get("attack", []), "tier": min(det["tier"], TIER_CAP, key=TIERS.index)}
            for name, cond in rule_conditions(text).items():
                why = layout_reads(cond)
                (skip if why else run).append(base | {"rule": name, **({"why": why} if why else {})})
    return run, skip


# --------------------------------------------------------------------------- indicators
def network_indicators(platform_id: str | None, ioc_dir: Path = IOC_DIR) -> tuple[dict[str, dict[str, Any]], int]:
    """The platform's published network values, one entry per value with every set that
    publishes it. Values YARA cannot hold as text are counted, not guessed at."""
    vals: dict[str, dict[str, Any]] = {}
    skipped = 0
    for p in sorted(ioc_dir.glob("*.yml")):
        s = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if platform_id not in (s.get("platforms") or []):
            continue
        for i in s.get("indicators") or []:
            if i.get("type") not in NET_TYPES:
                continue
            v = str(i.get("value", ""))
            if not v or any(not 0x20 < ord(c) < 0x7F for c in v):
                skipped += 1
                continue
            key = v.lower() if i["type"] == "domain" else v
            e = vals.setdefault(key, {"value": v, "type": i["type"], "sets": []})
            e["sets"].append({"set": s.get("id"), "publisher": s.get("publisher"), "role": i.get("role") or "unknown",
                              "context": i.get("context"), "staleness": s.get("staleness")})
    return vals, skipped


def _internal_rule(vals: dict[str, dict[str, Any]]) -> tuple[str, dict[str, str]]:
    ids, lines = {}, []
    for n, (key, e) in enumerate(vals.items()):
        lit = e["value"].replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'    $i{n} = "{lit}" ascii wide fullword' + (" nocase" if e["type"] == "domain" else ""))
        ids[f"$i{n}"] = key
    lines.append('    $banner = "Linux version " ascii')
    return "rule edge_memory_internal {\n  strings:\n" + "\n".join(lines) + "\n  condition:\n    any of them\n}\n", ids


def _alnum(b: bytes) -> bool:
    return len(b) == 1 and b.isalnum()


def _dotted_neighbour(data: bytes, off: int, length: int, w: int) -> bool:
    """An address inside a longer dotted run (198.51.100.7.5, 1.198.51.100.7) is not that address.
    fullword already refuses a letter or digit right beside it; this looks one dot further."""
    after, before = off + length, off - 2 * w
    dot = b"." + b"\x00" * (w - 1)
    return ((data[after:after + w] == dot and _alnum(data[after + w:after + w + 1]))
            or (before >= 0 and data[off - w:off] == dot and _alnum(data[before:before + 1])))


def defang(v: str) -> str:
    return v.replace("http", "hxxp").replace(".", "[.]")


# --------------------------------------------------------------------------- the scan
def _owned(rel: int, first: bool, last: bool) -> bool:
    """Whether an offset in this piece belongs to it: pieces overlap, and each offset is counted once."""
    m = min(MARGIN, OVERLAP // 2)
    return (rel >= m or first) and (rel < CHUNK - OVERLAP + m or last)


def _context(data: bytes, off: int, length: int, wide: bool) -> str:
    """The text around a match. Memory is mostly padding, so runs of bytes that are not printable
    ASCII are shown as one separator rather than as \\x00 after \\x00."""
    pad = 96 if wide else 48
    lo = max(0, off - pad)
    lo += (off - lo) % 2 if wide else 0       # keep UTF-16 code units aligned
    ctx = data[lo:off + length + pad]
    ctx = ctx[0::2] if wide else ctx
    return " · ".join(p.decode("ascii") for p in re.split(rb"[^\x20-\x7e]+", ctx) if p)


def scan(view: Any, platform_id: str | None, packs: list[dict[str, Any]], own: list[Path] | None = None,
         ioc_dir: Path = IOC_DIR) -> dict[str, Any]:
    """Read every memory image in the case once, running the pack rules that can read memory,
    the operator's rules and the indicator sweep over each piece."""
    images = view.memory_images()
    run, skip = pack_rules(packs)
    vals, skipped = network_indicators(platform_id, ioc_dir)
    out: dict[str, Any] = {
        "images": [], "chunk_bytes": CHUNK, "overlap_bytes": OVERLAP,
        "yara": {"status": "evaluated", "reason": None, "rules_run": run, "rules_not_run": skip, "found": {}},
        "own": None if not own else {"status": "evaluated", "reason": None, "files": [str(p) for p in own], "found": {}},
        "indicators": {"status": "evaluated", "reason": None, "values": len(vals), "skipped": skipped,
                       "sets": sorted({s["set"] for e in vals.values() for s in e["sets"]}), "found": {}},
        "banners": [],
    }
    try:
        import yara  # type: ignore
    except ImportError:
        yara = None
    if yara is None:
        why = "yara-python is not installed (pip install '.[yara]')"
        for k in ("yara", "own", "indicators"):
            if out[k]:
                out[k] |= {"status": "not-evaluated", "reason": why}
    if not run and out["yara"]["status"] == "evaluated":
        out["yara"] |= {"status": "not-evaluated", "reason": (
            f"none of the {len(skip)} YARA rules in this platform's packs reads only its strings" if skip else
            "this platform's packs have no YARA rules")}
    if not vals and out["indicators"]["status"] == "evaluated":
        out["indicators"] |= {"status": "not-evaluated",
                              "reason": "the toolkit holds no published network indicators for this platform"}
    packs_rx = own_rx = None
    if yara is not None:
        if run:
            files = sorted({r["file"] for r in run})
            packs_rx = yara.compile(filepaths={f"p{i}": str(REPO_ROOT / f) for i, f in enumerate(files)})
            ns_file = {f"p{i}": f for i, f in enumerate(files)}
            wanted = {(r["file"], r["rule"]): r for r in run}
        if own:
            try:
                own_rx = yara.compile(filepaths={f"o{i}": str(p) for i, p in enumerate(own)})
                own_file = {f"o{i}": str(p) for i, p in enumerate(own)}
            except yara.Error as e:
                out["own"] |= {"status": "not-evaluated", "reason": f"your rules did not compile: {e}"}
        internal_src, ids = _internal_rule(vals)
        internal_rx = yara.compile(source=internal_src)
    banners: dict[str, int] = {}
    for img in images:
        rec = {"label": img.label, "ref": img.ref, "format": img.format, "compressed": img.compressed,
               "detail": img.detail, "sha256": img.sha256, "bytes_read": 0, "error": None}
        out["images"].append(rec)
        if yara is None:
            continue
        try:
            for base, data, last in chunks(img):
                first = base == 0
                rec["bytes_read"] = base + len(data)
                for rx, kind in ((packs_rx, "yara"), (own_rx, "own")):
                    if rx is None or out[kind]["status"] != "evaluated":
                        continue
                    for m in rx.match(data=data, timeout=120):
                        if kind == "yara":
                            r = wanted.get((ns_file[m.namespace], m.rule))
                            if r is None:   # a rule of the same file that reads more than its strings
                                continue
                            key = f"{r['file']}::{m.rule}"
                        else:
                            key = f"{own_file[m.namespace]}::{m.rule}"
                        # A rule matches once per piece; its string matches have offsets in the image, so the
                        # pieces' overlap is removed by keeping each offset once.
                        f = out[kind]["found"].setdefault(img.ref, {}).setdefault(key, {"offsets": set(), "excerpt": None})
                        insts = sorted((i for s in m.strings for i in s.instances), key=lambda i: i.offset)
                        for i in insts:
                            if len(f["offsets"]) < 1000:
                                f["offsets"].add(base + i.offset)
                        if f["excerpt"] is None and insts:
                            f["excerpt"] = _context(data, insts[0].offset, insts[0].matched_length, False)
                for m in internal_rx.match(data=data, timeout=120):
                    for s in m.strings:
                        for inst in s.instances:
                            if not _owned(inst.offset, first, last):
                                continue
                            if s.identifier == "$banner":
                                tail = data[inst.offset:inst.offset + 256]
                                line = re.split(rb"[\n\x00]", tail, maxsplit=1)[0]
                                if all(b in TEXT_BYTES for b in line) and len(line) > len(BANNER):
                                    t = line.decode("ascii")
                                    banners[t] = banners.get(t, 0) + 1
                                continue
                            key = ids[s.identifier]
                            md = inst.matched_data
                            wide = len(md) > 1 and md[1:2] == b"\x00"
                            w = 2 if wide else 1
                            if vals[key]["type"] == "ipv4" and _dotted_neighbour(data, inst.offset, inst.matched_length, w):
                                continue
                            f = out["indicators"]["found"].setdefault(img.ref, {}).setdefault(
                                key, {"offsets": [], "encodings": [], "excerpt": None})
                            if len(f["offsets"]) < 1000:
                                f["offsets"].append(base + inst.offset)
                            enc = "UTF-16LE" if wide else "ASCII"
                            if enc not in f["encodings"]:
                                f["encodings"].append(enc)
                            if f["excerpt"] is None:
                                f["excerpt"] = _context(data, inst.offset, inst.matched_length, wide)
        except (EOFError, OSError, zlib.error, yara.Error) as e:
            rec["error"] = f"stopped at offset 0x{rec['bytes_read']:x}: {type(e).__name__}: {e}"
    out["banners"] = [{"banner": b, "count": n} for b, n in sorted(banners.items(), key=lambda kv: -kv[1])[:10]]
    if images and yara is not None and not sum(r["bytes_read"] for r in out["images"]):
        why = f"read 0 bytes from {len(images)} memory image(s)"
        for k in ("yara", "own", "indicators"):
            if out[k] and out[k]["status"] == "evaluated":
                out[k] |= {"status": "not-evaluated", "reason": why}
    out["_vals"] = vals
    return out


# --------------------------------------------------------------------------- results
CLOSE = {
    "yara-missing": "Install yara-python (pip install '.[yara]') and re-run analyze.",
    "no-rules": "Scan with rules written for memory: pass them with --memory-yara FILE (the vendor's or your own), or run "
                "Volatility 3's linux.vmayarascan.VmaYaraScan over process memory when you have symbols for the kernel.",
    "no-indicators": "Pass your own indicators as a YARA rule with --memory-yara.",
    "empty": "Check the image: re-acquire it, or decompress it if it is in an archive the toolkit did not open.",
}


def _close(reason: str | None) -> str:
    r = reason or ""
    if "yara-python" in r:
        return CLOSE["yara-missing"]
    if "YARA rules" in r:
        return CLOSE["no-rules"]
    if "indicators" in r:
        return CLOSE["no-indicators"]
    if "0 bytes" in r:
        return CLOSE["empty"]
    return "Fix the rule file and re-run analyze."


def _row(rid: str, title: str, tier: str, part: dict[str, Any], hits: list[dict[str, Any]], note: str,
         cves: list[str], attack: list[str]) -> dict[str, Any]:
    status = "not-evaluated" if part["status"] == "not-evaluated" else ("hit" if hits else "no-hit")
    row = {"pack": "MEMORY", "pack_name": "Memory images", "cves": cves, "id": rid, "title": title, "type": "memory",
           "tier": tier, "evidence_class": "memory", "attack": attack, "status": status, "hit_count": len(hits),
           "hits": hits[:MAX_KEPT], "notes": note, "reason": part.get("reason")}
    if status == "not-evaluated":
        row["needs"], row["close"] = part.get("reason") or "", _close(part.get("reason"))
    return row


def _places(offs: list[int], what: str = "place") -> str:
    if not offs:
        return "matched with no string at an offset"
    return f"{len(offs)} {what}{'' if len(offs) == 1 else 'es' if what.endswith('h') else 's'}, first at offset 0x{offs[0]:x}"


def results(mem: dict[str, Any], file_hits: set[tuple[str, str]] | None = None) -> list[dict[str, Any]]:
    """The memory checks as detection results. file_hits: (rule file, rule) pairs that already hit
    as a file in this case; a memory match on the same rule is the same artefact and does not corroborate."""
    file_hits = file_hits or set()
    by = {(r["file"], r["rule"]): r for r in mem["yara"]["rules_run"]}
    hits, cves, attack = [], set(), set()
    for ref, found in mem["yara"]["found"].items():
        for key, f in found.items():
            file, rule = key.split("::", 1)
            r = by[(file, rule)]
            offs = sorted(f["offsets"])
            d = asdict(Hit(ref, f"YARA {rule} ({file}, from {r['detection']}): {_places(offs, 'string match')}",
                           excerpt=f["excerpt"], extra={"rule": rule, "file": file, "detection": r["detection"],
                                                        "pack": r["pack"], "offset": offs[0] if offs else None,
                                                        "string_matches": len(offs)}))
            d["tier"] = r["tier"]
            if (file, rule) in file_hits:
                d["corroborates"] = False
                d["detail"] += "; the same rule hit as a file in this case, so this match does not count again"
            hits.append(d)
            cves.update(r["cves"])
            attack.update(r["attack"])
    rows = [_row("memory-yara", "Pack YARA rules match in a memory image", TIER_CAP, mem["yara"], hits, YARA_NOTE,
                 sorted(cves), sorted(attack))]
    if mem.get("own"):
        own_hits = []
        for ref, found in mem["own"]["found"].items():
            for key, f in found.items():
                file, rule = key.split("::", 1)
                offs = sorted(f["offsets"])
                d = asdict(Hit(ref, f"YARA {rule} ({Path(file).name}): {_places(offs, 'string match')}",
                               excerpt=f["excerpt"],
                               extra={"rule": rule, "file": file, "offset": offs[0] if offs else None,
                                      "string_matches": len(offs)}))
                d["tier"] = "possible"
                own_hits.append(d)
        rows.append(_row("memory-yara-own", "Your YARA rules match in a memory image", "possible", mem["own"],
                         own_hits, OWN_NOTE, [], []))
    ioc_hits = []
    vals = mem.get("_vals") or {}
    for ref, found in mem["indicators"]["found"].items():
        for key, f in found.items():
            e = vals.get(key) or {"value": key, "type": "?", "sets": []}
            roles = sorted({s["role"] for s in e["sets"]})
            sets = ", ".join(f"{s['set']} ({s['publisher']})" for s in e["sets"])
            d = asdict(Hit(ref, f"{defang(e['value'])} ({e['type']}, role {' / '.join(roles) or 'unknown'}) from {sets}: "
                                f"{_places(f['offsets'])}, as {' and '.join(f['encodings'])} text",
                           excerpt=f["excerpt"], extra={"value": e["value"], "type": e["type"], "roles": roles,
                                                        "sets": [s["set"] for s in e["sets"]], "offset": f["offsets"][0],
                                                        "places": len(f["offsets"]), "encodings": f["encodings"]}))
            d["tier"] = "possible"
            d["corroborates"] = False
            ioc_hits.append(d)
    rows.append(_row("memory-indicators", "Published network indicators as text in a memory image", "possible",
                     mem["indicators"], ioc_hits, IOC_NOTE, [], []))
    return rows


def summary(mem: dict[str, Any]) -> dict[str, Any]:
    """What findings.json keeps: the images, the rules run and not run, the sweep; the hits live in detections."""
    out = {k: v for k, v in mem.items() if k != "_vals"}
    for k in ("yara", "own", "indicators"):
        if out.get(k):
            out[k] = {x: y for x, y in out[k].items() if x != "found"} | {
                "matched": sum(len(f) for f in out[k]["found"].values())}
    return out


# --------------------------------------------------------------------------- Volatility 3
def _slug(ref: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", ref).strip("_") or "image"


def _vol_help(vol: str) -> tuple[str | None, set[str]]:
    p = subprocess.run([vol, "--help"], capture_output=True, text=True, timeout=300)
    text = (p.stdout or "") + "\n" + (p.stderr or "")
    v = re.search(r"Volatility 3 Framework (\S+)", text)
    return (v.group(1) if v else None), set(re.findall(r"^ {4}([a-z]\w*(?:\.\w+)+)", p.stdout or "", re.M))


def volatility(images: list[Image], symbols: Path | None, out_root: Path) -> list[dict[str, Any]]:
    """Run a fixed set of Volatility 3 Linux plugins over each image, offline, with the operator's
    symbols. Outputs go to memory/<image>/ in the case with their hashes; nothing is scored. A
    plugin already run on the same image, symbols and version is not run again."""
    if not images:
        return []
    if symbols is None:
        return [{"ref": i.ref, "status": "not run", "reason": "no symbols given (--memory-symbols DIR)"} for i in images]
    vol = shutil.which("vol")
    if vol is None:
        return [{"ref": i.ref, "status": "not run", "reason": "Volatility 3 is not installed (pip install volatility3)"}
                for i in images]
    try:
        version, have = _vol_help(vol)
    except (OSError, subprocess.SubprocessError) as e:
        return [{"ref": i.ref, "status": "not run", "reason": f"vol --help failed: {e}"} for i in images]
    symbols = Path(symbols).resolve()
    res = []
    for img in images:
        if img.compressed or img.format not in ("lime", "elf-core", "raw"):
            res.append({"ref": img.ref, "status": "not run", "reason": (
                "the image is gzip-compressed; Volatility reads it uncompressed" if img.compressed else
                f"a {img.format} file is not an image Volatility reads")})
            continue
        d = out_root / _slug(img.ref)
        (d / "cache").mkdir(parents=True, exist_ok=True)
        st = img.local.stat()
        key = img.sha256 or f"{st.st_size}:{st.st_mtime_ns}"
        idx_p = d / "volatility.json"
        try:
            old = json.loads(idx_p.read_text()) if idx_p.is_file() else {}
        except ValueError:
            old = {}
        same = (old.get("image") == key and old.get("symbols") == str(symbols) and old.get("version") == version)
        plugins = []
        for name, cands in VOL_PLUGINS:
            plugin = next((c for c in cands if c in have), None)
            if plugin is None:
                plugins.append({"name": name, "plugin": cands[0], "status": "unavailable",
                                "reason": "not in this Volatility's plugin list"})
                continue
            prev = next((p for p in old.get("plugins", []) if p["name"] == name), None) if same else None
            outp = d / f"{name}.json"
            if (prev and prev.get("status") == "ok" and prev.get("plugin") == plugin and outp.is_file()
                    and hashlib.sha256(outp.read_bytes()).hexdigest() == prev.get("sha256")):
                plugins.append(prev)
                continue
            cmd = [vol, "-q", "--offline", "--cache-path", str((d / "cache").resolve()), "-s", str(symbols),
                   "-r", "json", "-f", str(img.local.resolve()), plugin]
            try:
                p = subprocess.run(cmd, capture_output=True, timeout=VOL_TIMEOUT)
            except subprocess.TimeoutExpired:
                plugins.append({"name": name, "plugin": plugin, "status": "failed",
                                "reason": f"timed out after {VOL_TIMEOUT} s"})
                continue
            err = [x for x in p.stderr.decode("utf-8", "replace").splitlines() if x.strip()]
            rows = None
            try:
                parsed = json.loads(p.stdout) if p.returncode == 0 else None
                rows = len(parsed) if isinstance(parsed, list) else None
            except ValueError:
                pass
            if rows is None:
                (d / f"{name}.err.txt").write_bytes(p.stderr + b"\n" + p.stdout)
                plugins.append({"name": name, "plugin": plugin, "status": "failed",
                                "reason": (err[-1] if err else f"exit {p.returncode}")[:300]})
                continue
            outp.write_bytes(p.stdout)
            plugins.append({"name": name, "plugin": plugin, "status": "ok", "rows": rows,
                            "output": str(outp.relative_to(out_root.parent)), "sha256": hashlib.sha256(p.stdout).hexdigest()})
        idx = {"image": key, "symbols": str(symbols), "version": version, "plugins": plugins}
        idx_p.write_text(json.dumps(idx, indent=2) + "\n")
        res.append({"ref": img.ref, "status": "ran", "version": version, "symbols": str(symbols), "plugins": plugins})
    return res
