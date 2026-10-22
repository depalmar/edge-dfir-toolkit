"""Read-only view over a case: command outputs, fetched files, ingested bundles."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

from .custody import Case


@lru_cache(maxsize=512)
def glob_regex(pattern: str) -> re.Pattern[str]:
    """Translate a path glob (with **) into a regex over posix relative paths."""
    out, i = "", 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
            continue
        if pattern.startswith("**", i):
            out += ".*"
            i += 2
            continue
        out += {"*": "[^/]*", "?": "[^/]"}.get(c, re.escape(c))
        i += 1
    return re.compile(out + r"\Z")


@dataclass
class Source:
    """One unit of evidence the analyzer can read."""
    kind: str        # "step" | "file"
    ref: str         # step id, or the device-side path the file came from
    local: Path      # where it lives in the case

    def label(self) -> str:
        return f"step:{self.ref}" if self.kind == "step" else self.ref


class EvidenceView:
    def __init__(self, case_root: Path):
        self.case = Case(case_root)
        if not self.case.exists():
            raise FileNotFoundError(f"no manifest in {case_root}")
        self.root = self.case.root
        self.manifest: dict[str, Any] = self.case.load()
        self._files: list[Source] | None = None

    # -- steps --------------------------------------------------------------
    def step(self, step_id: str) -> dict[str, Any] | None:
        for s in self.manifest.get("steps", []):
            if s["step_id"] == step_id:
                return s
        return None

    def step_source(self, step_id: str) -> Source | None:
        s = self.step(step_id)
        if s and s.get("status") == "ok" and s.get("output"):
            return Source("step", step_id, self.root / s["output"])
        return None

    def step_text(self, step_id: str) -> str | None:
        src = self.step_source(step_id)
        return src.local.read_text(encoding="utf-8", errors="replace") if src else None

    # -- files --------------------------------------------------------------
    def all_files(self) -> list[Source]:
        """Every collected or ingested file, keyed by the path it had on the device
        (fetched files) or inside its bundle (ingested archives)."""
        if self._files is not None:
            return self._files
        found: list[Source] = []
        files_root = self.root / "files"
        if files_root.is_dir():
            for p in sorted(files_root.rglob("*")):
                if p.is_file():
                    rel = p.relative_to(files_root).parts
                    found.append(Source("file", "/" + "/".join(rel[1:]), p))  # drop step-id dir
        for b in self.manifest.get("ingested", []):
            bdir = self.root / "bundles" / b["label"]
            if b.get("extracted_to"):
                ex = self.root / b["extracted_to"]
                for p in sorted(ex.rglob("*")):
                    if p.is_file():
                        found.append(Source("file", f"[{b['label']}]/{p.relative_to(ex).as_posix()}", p))
            else:
                p = bdir / b["source_name"]
                if p.is_file():
                    found.append(Source("file", f"[{b['label']}]/{b['source_name']}", p))
        self._files = found
        return found

    def files(self, patterns: list[str]) -> list[Source]:
        regs = [glob_regex(p.lstrip("/")) for p in patterns]
        out = []
        for s in self.all_files():
            ref = s.ref.lstrip("/")
            # Bundle members are matched without the [label]/ prefix as well.
            bare = ref.split("]/", 1)[1] if ref.startswith("[") and "]/" in ref else ref
            if any(r.match(ref) or r.match(bare) for r in regs):
                out.append(s)
        return out

    def rejected_members(self) -> list[tuple[str, str]]:
        """Archive members refused at extraction - symlinks are evidence too."""
        out = []
        for b in self.manifest.get("ingested", []):
            for r in b.get("extract_rejected", []):
                out.append((b["label"], r))
        return out

    def sources(self, spec: dict[str, Any]) -> list[Source]:
        out: list[Source] = []
        for sid in spec.get("steps", []):
            src = self.step_source(sid)
            if src:
                out.append(src)
        if spec.get("files"):
            out.extend(self.files(spec["files"]))
        return out

    # -- coverage -----------------------------------------------------------
    def covered_classes(self) -> set[str]:
        from .profiles import TIER_CLASS
        covered = set()
        for s in self.manifest.get("steps", []):
            if s.get("status") == "ok":
                covered.add(TIER_CLASS.get(s["tier"], "other"))
        for b in self.manifest.get("ingested", []):
            covered.update(b.get("evidence_classes") or ["bundle"])
        return covered


def iter_lines(src: Source, limit_bytes: int = 512 * 1024 * 1024) -> Iterator[tuple[int, bytes]]:
    """Yield (line_no, raw bytes). Raw so non-printable bytes survive for checks
    that depend on them (memory-disclosure signatures)."""
    with open(src.local, "rb") as fh:
        read = 0
        for n, line in enumerate(fh, 1):
            read += len(line)
            if read > limit_bytes:
                return
            yield n, line.rstrip(b"\r\n")


_TS = [
    (re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?"), "iso"),
    (re.compile(r"(\d{4})/(\d{2})/(\d{2}) (\d{2}:\d{2}:\d{2})"), "ymd-slash"),
    (re.compile(r"(\d{2})/(\d{2})/(\d{4}):(\d{2}:\d{2}:\d{2}) GMT"), "netscaler"),
]


def parse_ts(text: str) -> tuple[str | None, bool]:
    """Return (ISO-ish timestamp, tz_known). Timezone is only claimed when the
    source states one; everything else is device-local until skew is applied."""
    for rx, kind in _TS:
        m = rx.search(text)
        if not m:
            continue
        if kind == "iso":
            tz = m.group(4)
            ts = f"{m.group(1)}T{m.group(2)}{m.group(3) or ''}"
            if tz:
                return ts + ("Z" if tz == "Z" else tz), True
            return ts, False
        if kind == "ymd-slash":
            return f"{m.group(1)}-{m.group(2)}-{m.group(3)}T{m.group(4)}", False
        if kind == "netscaler":
            return f"{m.group(3)}-{m.group(1)}-{m.group(2)}T{m.group(4)}Z", True
    return None, False


def dump_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, default=str) + "\n", encoding="utf-8")
