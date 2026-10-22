"""Case directory and chain-of-custody manifest.

Every write to a case goes through here so the manifest stays the single
record of what was collected, by whom, how, and with which build of the tool.
A manifest rewrite (ingest after collection, say) records the hash of the
manifest it replaced, so the history of a case is a hash chain rather than an
overwrite.
"""
from __future__ import annotations

import getpass
import json
import platform
import shutil
import socket
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from . import __version__
from .util import safe_relpath, sha256_file, tool_hash, utcnow

MANIFEST = "manifest.json"
MAX_EXTRACT_BYTES = 8 * 1024**3   # 8 GiB: a bundle bigger than this is an image, not a bundle


class Case:
    def __init__(self, root: Path):
        self.root = Path(root)

    # -- layout -----------------------------------------------------------
    @property
    def manifest_path(self) -> Path:
        return self.root / MANIFEST

    def exists(self) -> bool:
        return self.manifest_path.is_file()

    def load(self) -> dict[str, Any]:
        return json.loads(self.manifest_path.read_text(encoding="utf-8"))

    @staticmethod
    def new_manifest(case_id: str, operator: str | None, platform_id: str | None,
                     profile: str | None) -> dict[str, Any]:
        return {
            "case_id": case_id,
            "tool": "edgetriage",
            "tool_version": __version__,
            "tool_sha256": tool_hash(),
            "operator": operator or getpass.getuser(),
            "collector_host": socket.gethostname(),
            "collector_platform": platform.platform(),
            "platform_id": platform_id,
            "profile": profile,
            "created_utc": utcnow(),
            "previous_manifest_sha256": None,
            "steps": [],
            "ingested": [],
        }

    def save(self, manifest: dict[str, Any]) -> str:
        self.root.mkdir(parents=True, exist_ok=True)
        if self.manifest_path.exists():
            manifest["previous_manifest_sha256"] = sha256_file(self.manifest_path)
        manifest["manifest_written_utc"] = utcnow()
        self.manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        digest = sha256_file(self.manifest_path)
        (self.root / "manifest.sha256").write_text(f"{digest}  {MANIFEST}\n", encoding="utf-8")
        self._write_log(manifest)
        return digest

    def _write_log(self, m: dict[str, Any]) -> None:
        lines = [
            f"edgetriage collection log - case {m['case_id']}",
            f"operator={m['operator']} collector={m['collector_host']} profile={m.get('profile')}",
            f"tool={m['tool_version']} tool_sha256={m['tool_sha256']}",
            "-" * 78,
        ]
        for s in m.get("steps", []):
            digest = (s.get("sha256") or "")[:16]
            lines.append(f"[{s['status']:>15}] {s['tier']:>2} {s['step_id']:<32} {digest} {s.get('error') or ''}".rstrip())
            for f in s.get("files", []):
                lines.append(f"{'':>19}file {f['sha256'][:16]} {f['remote']}")
        for b in m.get("ingested", []):
            lines.append(f"[{'ingested':>15}] {b['label']:<35} {b['sha256'][:16]} {b['source_name']}")
        (self.root / "collection.log").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # -- evidence writers ---------------------------------------------------
    def write_command(self, step_id: str, text: str) -> tuple[str, str, int]:
        p = self.root / "commands" / f"{step_id}.txt"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return str(p.relative_to(self.root)), sha256_file(p), p.stat().st_size

    def file_dest(self, step_id: str, remote: str) -> Path:
        return self.root / "files" / step_id / safe_relpath(remote)

    # -- ingest -------------------------------------------------------------
    def ingest(self, source: Path, label: str, extract: bool = True,
               evidence_classes: list[str] | None = None) -> dict[str, Any]:
        """Copy a vendor bundle or exported log into the case, hash it, and
        optionally extract it. Extraction treats the archive as hostile."""
        source = Path(source)
        src_hash = sha256_file(source)
        dest_dir = self.root / "bundles" / label
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / source.name
        shutil.copy2(source, dest)
        rec: dict[str, Any] = {
            "label": label,
            "source_name": source.name,
            "sha256": src_hash,
            "copy_verified": sha256_file(dest) == src_hash,
            "bytes": dest.stat().st_size,
            "ingested_utc": utcnow(),
            "extracted_to": None,
            "extract_rejected": [],
            "evidence_classes": evidence_classes or ["bundle"],
        }
        if extract and _is_archive(dest):
            out = dest_dir / "extracted"
            rec["extract_rejected"] = safe_extract(dest, out)
            rec["extracted_to"] = str(out.relative_to(self.root))
        return rec


def _is_archive(p: Path) -> bool:
    return zipfile.is_zipfile(p) or tarfile.is_tarfile(p)


def _member_ok(name: str) -> bool:
    pp = PurePosixPath(name.replace("\\", "/"))
    return not pp.is_absolute() and ".." not in pp.parts and name.strip() != ""


def safe_extract(archive: Path, out: Path) -> list[str]:
    """Extract regular files only. Returns the members refused, with reasons.

    Bundles pulled from a compromised device are attacker-influenced input.
    Absolute paths, '..' traversal, links and device nodes are refused rather
    than sanitized, and every refusal is recorded so the analyst can see it.
    """
    rejected: list[str] = []
    total = 0
    out.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if not _member_ok(info.filename):
                    rejected.append(f"{info.filename}: unsafe path")
                    continue
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    rejected.append(f"{info.filename}: symlink")
                    continue
                total += info.file_size
                if total > MAX_EXTRACT_BYTES:
                    rejected.append(f"{info.filename}: size cap reached")
                    break
                dest = out / safe_relpath(info.filename)
                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(dest, "wb") as dst:
                    shutil.copyfileobj(src, dst)
        return rejected
    with tarfile.open(archive) as tf:
        for m in tf.getmembers():
            if m.isdir():
                continue
            if not _member_ok(m.name):
                rejected.append(f"{m.name}: unsafe path")
                continue
            if m.issym() or m.islnk():
                rejected.append(f"{m.name}: link -> {m.linkname}")
                continue
            if not m.isfile():
                rejected.append(f"{m.name}: not a regular file")
                continue
            total += m.size
            if total > MAX_EXTRACT_BYTES:
                rejected.append(f"{m.name}: size cap reached")
                break
            dest = out / safe_relpath(m.name)
            dest.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                rejected.append(f"{m.name}: unreadable")
                continue
            with src, open(dest, "wb") as dst:
                shutil.copyfileobj(src, dst)
    return rejected
