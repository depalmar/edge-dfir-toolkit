"""Off-box comparison: the device's syslog as the SIEM received it, against the
logs left on the box (EDGE-HUNT-0027), plus the gaps in the forwarded stream
(EDGE-HUNT-0009).

The two copies are lined up by content, not by clock. Each line is reduced to
the message after its syslog header, and a forwarded line counts as still on
the box when a local line carries the same message. The comparison only runs
between the first and the last line the copies share, so rotation at either
end, and a device clock in another time zone, never read as deletion.

When the copies share too few lines - the device forwards a different format,
or logs locally and remotely at different levels - the comparison says it was
not evaluated instead of reporting everything as missing.

A run of lines present on one side only, with shared lines on both sides of
it, is a `possible` indicator: removed from the box after it was forwarded, or
written locally while forwarding was blocked. Both have benign causes (lost UDP
datagrams, a collector outage, a facility logged at one end only), and the
report names them. Gaps in the forwarded stream are listed, never scored: a
quiet night is not an indicator without NetFlow showing traffic.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import re
import statistics
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .checks import Hit, excerpt
from .evidence import EvidenceView, Source, iter_lines, parse_ts
from .util import sha256_file

MESSAGE_KEYS = ("Message", "message", "_raw", "raw", "msg", "log", "syslog")
TIME_KEYS = ("_time", "@timestamp", "timestamp", "time", "TimeGenerated", "EventTime", "ReceivedTime", "receive_time")
LOCAL_GLOBS = ["**/*.log*", "**/*log", "**/messages*", "**/syslog*"]
MIN_SHARED = 20      # fewer shared lines than this and the copies do not line up
MIN_SHARE = 0.8      # inside the span, at least this share of a side must be shared
RUN_MIN = 5          # consecutive one-sided lines, with shared lines either side
MIN_KEY = 8          # shorter messages are too generic to line up
GAP_FLOOR_S = 1800   # forwarded-stream gaps shorter than 30 minutes are not listed
GAP_FACTOR = 20      # ... nor gaps shorter than 20 times the median interval
MAX_GAPS = 10
LIMIT_BYTES = 512 * 1024 * 1024

_PRI = re.compile(r"^\s*<\d{1,3}>\s*(?:1\s+)?")
_LEAD = re.compile(r"^(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)\s+")
_MON = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
_BSD = re.compile(r"\b([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\b")

GONE_NOTE = ("A run of lines the SIEM received that are no longer on the box, with lines the two copies share on "
             "both sides. Deletion after forwarding is one explanation (AA25-239A: review forwarded logs for "
             "\"Evidence of clearing locally stored logs\"). Others are a facility or level the device forwards but "
             "does not keep locally, and duplicate messages lined up out of order. Read the run before calling it "
             "tampering. See EDGE-HUNT-0027.")
UNSENT_NOTE = ("A run of lines on the box that the SIEM never received, with shared lines on both sides. Forwarding "
               "blocked during hands-on activity is one explanation (Mandiant on CVE-2025-0282: the threat actor "
               "\"uses iptables to block syslog forwarding\"). Others are lost UDP datagrams, a collector outage and "
               "a facility kept locally but not forwarded. Check the collector's own health for those hours. See "
               "EDGE-HUNT-0027 and EDGE-HUNT-0009.")


@dataclass
class Line:
    n: int                 # position in its stream, from 1
    raw: str
    key: str
    when: datetime | None  # for arithmetic only; naive, UTC when the source gave a zone
    shown: str | None      # the timestamp as written
    year_known: bool


# --------------------------------------------------------------------------- parsing
def message_key(raw: str) -> str:
    """The message after the syslog header: PRI, timestamp, host and tag removed."""
    s = _PRI.sub("", raw).strip()
    i = s.find(": ")
    s = s[i + 2:] if 0 <= i <= 160 else _LEAD.sub("", s)
    return " ".join(s.split())


def _when_from_text(text: str) -> tuple[datetime | None, str | None, bool]:
    ts, _tz = parse_ts(text)
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt, ts, True
        except ValueError:
            pass
    m = _BSD.search(text)
    if m and m.group(1) in _MON:   # syslog's own timestamp has no year
        try:
            dt = datetime(2000, _MON[m.group(1)], int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)))
            return dt, m.group(0), False
        except ValueError:
            pass
    return None, None, False


def _when_from_field(v: Any) -> tuple[datetime | None, str | None, bool]:
    if isinstance(v, (int, float)) or (isinstance(v, str) and re.fullmatch(r"\d{9,13}(\.\d+)?", v.strip())):
        x = float(v)
        x = x / 1000 if x > 1e11 else x   # milliseconds
        dt = datetime.fromtimestamp(x, timezone.utc).replace(tzinfo=None)
        return dt, dt.isoformat(timespec="seconds") + "Z", True
    return _when_from_text(str(v)) if v not in (None, "") else (None, None, False)


def _pick(rec: dict[str, Any], keys: tuple[str, ...]) -> Any:
    low = {str(k).lower(): k for k in rec}
    for k in keys:
        if k in rec and rec[k] not in (None, ""):
            return rec[k]
        if k.lower() in low and rec[low[k.lower()]] not in (None, ""):
            return rec[low[k.lower()]]
    return None


def read_forwarded(path: Path, limit_bytes: int = LIMIT_BYTES) -> tuple[list[Line], str]:
    """The SIEM's copy: raw syslog lines, JSON (array or lines) or CSV with a message field.
    Exports often come newest first, so a stream that is almost fully timestamped, with
    years, is put in time order."""
    with open(path, "rb") as fh:
        gz = fh.read(2) == b"\x1f\x8b"
    with (gzip.open(path, "rb") if gz else open(path, "rb")) as fh:
        text = fh.read(limit_bytes).decode("utf-8", "replace")
    stripped = text.lstrip()
    first = next((ln for ln in text.splitlines() if ln.strip()), "")
    recs: list[tuple[str, Any]] = []
    doc: Any = None
    if stripped.startswith("["):   # a JSON array, or a raw log whose lines start with "["
        try:
            doc = json.loads(stripped)
        except ValueError:
            doc = None
    if isinstance(doc, list):
        fmt = "json"
        recs = [(str(_pick(r, MESSAGE_KEYS)), _pick(r, TIME_KEYS)) for r in doc
                if isinstance(r, dict) and _pick(r, MESSAGE_KEYS) is not None]
    elif first.lstrip().startswith("{"):
        fmt = "jsonl"
        for ln in text.splitlines():
            if ln.strip():
                try:
                    r = json.loads(ln)
                except ValueError:
                    continue
                if isinstance(r, dict) and _pick(r, MESSAGE_KEYS) is not None:
                    recs.append((str(_pick(r, MESSAGE_KEYS)), _pick(r, TIME_KEYS)))
    elif any(f.strip().strip('"').lower() in {k.lower() for k in MESSAGE_KEYS} for f in next(csv.reader([first]), [])):
        fmt = "csv"
        for r in csv.DictReader(io.StringIO(text)):
            msg = _pick(r, MESSAGE_KEYS)
            if msg is not None:
                recs.append((str(msg), _pick(r, TIME_KEYS)))
    else:
        fmt = "text"
        recs = [(ln, None) for ln in text.splitlines() if ln.strip()]
    if fmt != "text" and not recs:
        raise ValueError(f"{path.name}: no record carries a message field ({', '.join(MESSAGE_KEYS)})")
    lines = []
    for n, (msg, tv) in enumerate(recs, 1):
        dt, shown, yk = _when_from_field(tv) if tv is not None else _when_from_text(msg)
        if dt is None and tv is not None:
            dt, shown, yk = _when_from_text(msg)
        lines.append(Line(n, msg.rstrip("\r\n"), message_key(msg), dt, shown, yk))
    timed = [ln for ln in lines if ln.when is not None]
    if lines and len(timed) >= 0.9 * len(lines) and all(ln.year_known for ln in timed):
        lines.sort(key=lambda ln: (ln.when or datetime.min, ln.n))
        for i, ln in enumerate(lines, 1):
            ln.n = i
    return lines, fmt


def read_local(src: Source) -> list[Line]:
    out = []
    for n, raw in iter_lines(src):
        s = raw.decode("utf-8", "replace")
        dt, shown, yk = _when_from_text(s)
        out.append(Line(n, s, message_key(s), dt, shown, yk))
    return out


def local_sources(view: EvidenceView, patterns: list[str] | None) -> list[Source]:
    """Log files in the case, plus the output of any step whose id names a log."""
    srcs = view.files(patterns or LOCAL_GLOBS)
    if not patterns:
        for s in view.manifest.get("steps", []):
            if "log" in s["step_id"].lower():
                src = view.step_source(s["step_id"])
                if src:
                    srcs.append(src)
    return srcs


# --------------------------------------------------------------------------- comparison
def _match(lines: list[Line], other: Counter) -> list[bool | None]:
    """True shared, False one-sided, None too generic to line up."""
    left = Counter(other)
    out: list[bool | None] = []
    for ln in lines:
        if len(ln.key) < MIN_KEY:
            out.append(None)
        elif left[ln.key] > 0:
            left[ln.key] -= 1
            out.append(True)
        else:
            out.append(False)
    return out


def _runs(flags: list[bool | None]) -> tuple[tuple[int, int] | None, list[tuple[int, int]], float]:
    """(span of shared lines, one-sided runs inside it, share of the span that is shared)."""
    idx = [i for i, f in enumerate(flags) if f is True]
    if not idx:
        return None, [], 0.0
    lo, hi = idx[0], idx[-1]
    inside = [f for f in flags[lo:hi + 1] if f is not None]
    share = sum(1 for f in inside if f) / len(inside) if inside else 0.0
    runs, start = [], None
    for i in range(lo, hi + 1):
        if flags[i] is False:
            start = i if start is None else start
        elif flags[i] is True and start is not None:
            if sum(1 for f in flags[start:i] if f is False) >= RUN_MIN:
                runs.append((start, i - 1))
            start = None
    return (lo, hi), runs, share


def _span_text(a: Line, b: Line) -> str:
    return f"{a.shown or f'line {a.n}'} to {b.shown or f'line {b.n}'}"


def _run_hit(lines: list[Line], flags: list[bool | None], run: tuple[int, int], source: str, what: str) -> dict[str, Any]:
    a, b = lines[run[0]], lines[run[1]]
    n = sum(1 for f in flags[run[0]:run[1] + 1] if f is False)
    h = asdict(Hit(source, f"{n} {what}, {_span_text(a, b)}", line=a.n,
                   ts=a.shown if a.year_known else None, tz_known=False, excerpt=excerpt(a.raw),
                   extra={"lines": n, "end": b.shown, "end_line": b.n}))
    h["tier"] = "possible"
    return h


def stream_gaps(lines: list[Line], window_start: str | None) -> tuple[list[dict[str, Any]], float | None]:
    """The longest silences in the forwarded stream, measured against its own cadence."""
    timed = [ln for ln in lines if ln.when is not None]
    if len(timed) < MIN_SHARED:
        return [], None
    shift, prev, pts = timedelta(0), None, []
    for ln in timed:   # syslog's year-less timestamps wrap at New Year
        t = ln.when + shift
        if prev is not None and not ln.year_known and (prev - t) > timedelta(days=180):
            shift += timedelta(days=365)
            t = ln.when + shift
        pts.append((t, ln))
        prev = t
    deltas = [(b[0] - a[0]).total_seconds() for a, b in zip(pts, pts[1:])]
    pos = [d for d in deltas if d > 0]
    if not pos:
        return [], None
    floor = max(GAP_FLOOR_S, GAP_FACTOR * statistics.median(pos))
    gaps = []
    for (_ta, a), (_tb, b), d in zip(pts, pts[1:], deltas):
        if d >= floor:
            in_win = bool(window_start and a.year_known and b.year_known and b.shown
                          and str(b.shown)[:19] >= window_start[:19])
            gaps.append({"from": a.shown, "to": b.shown, "seconds": int(d), "after_line": a.n, "in_window": in_win})
    gaps.sort(key=lambda g: -g["seconds"])
    return gaps[:MAX_GAPS], floor


def compare(view: EvidenceView, forwarded: list[Path], local_patterns: list[str] | None = None,
            window_start: str | None = None) -> dict[str, Any]:
    fwd: list[Line] = []
    files = []
    for p in forwarded:
        lines, fmt = read_forwarded(p)
        files.append({"path": str(p), "sha256": sha256_file(p), "format": fmt, "lines": len(lines)})
        for ln in lines:
            ln.n = len(fwd) + 1
            fwd.append(ln)
    fwd_keys = Counter(ln.key for ln in fwd if len(ln.key) >= MIN_KEY)
    local, comparable = [], []
    for src in local_sources(view, local_patterns):
        lines = read_local(src)
        flags = _match(lines, fwd_keys)
        shared = sum(1 for f in flags if f)
        entry = {"source": src.label(), "lines": len(lines), "shared": shared, "comparable": shared >= MIN_SHARED}
        local.append(entry)
        if entry["comparable"]:
            comparable.append((src, lines, flags))
    gaps, floor = stream_gaps(fwd, window_start)
    out: dict[str, Any] = {"forwarded": files, "local": local, "gaps": gaps,
                           "gap_floor_seconds": int(floor) if floor else None,
                           "gone_from_box": {"status": "not-evaluated", "hits": []},
                           "never_forwarded": {"status": "not-evaluated", "hits": []}}
    if not fwd:
        out["reason"] = "the forwarded copy has no lines"
        return out
    if not comparable:
        out["reason"] = (f"no local log shares {MIN_SHARED} or more messages with the forwarded copy; the device "
                         "probably forwards a different format than it keeps, or the copies cover different hours")
        return out
    local_keys = Counter(ln.key for _s, lines, _f in comparable for ln in lines if len(ln.key) >= MIN_KEY)
    fflags = _match(fwd, local_keys)
    span, runs, share = _runs(fflags)
    out["shared"] = sum(1 for f in fflags if f)
    if span:
        a, b = fwd[span[0]], fwd[span[1]]
        out["span"] = {"from": a.shown, "to": b.shown, "first_line": a.n, "last_line": b.n}
        before = [ln for ln in fwd[:span[0]] if len(ln.key) >= MIN_KEY]
        if before:
            out["before_box"] = {"lines": len(before), "from": before[0].shown, "to": before[-1].shown}
    gone = out["gone_from_box"]
    if share < MIN_SHARE:
        gone["reason"] = (f"only {share:.0%} of the forwarded lines between the first and last shared line are on the "
                          "box; the device probably forwards more than it keeps (a level or facility difference)")
    else:
        gone["status"] = "evaluated"
        gone["hits"] = [_run_hit(fwd, fflags, r, "forwarded copy", "forwarded lines not on the box") for r in runs]
    unsent = out["never_forwarded"]
    reasons, hits, evaluated = [], [], False
    for src, lines, _f in comparable:
        lflags = _match(lines, fwd_keys)
        _span, lruns, lshare = _runs(lflags)
        if lshare < MIN_SHARE:
            reasons.append(f"{src.label()}: only {lshare:.0%} of its lines in the shared span were forwarded")
            continue
        evaluated = True
        hits += [_run_hit(lines, lflags, r, src.label(), "local lines the SIEM never received") for r in lruns]
    if evaluated:
        unsent["status"] = "evaluated"
        unsent["hits"] = hits
    if reasons:
        unsent["reason"] = "; ".join(reasons)
    return out


def results(off: dict[str, Any]) -> list[dict[str, Any]]:
    """The two comparisons as detection results, so they sit in the verdict beside the packs."""
    rows = []
    for key, rid, title, note in (("gone_from_box", "offbox-gone-from-box", "Forwarded lines no longer on the box", GONE_NOTE),
                                  ("never_forwarded", "offbox-never-forwarded", "Local lines the SIEM never received", UNSENT_NOTE)):
        part = off[key]
        hits = list(part["hits"])
        status = "not-evaluated" if part["status"] == "not-evaluated" else ("hit" if hits else "no-hit")
        rows.append({"pack": "OFFBOX", "pack_name": "Off-box comparison", "cves": [], "id": rid, "title": title,
                     "type": "offbox", "tier": "possible", "evidence_class": "offbox-logs", "attack": ["T1070"],
                     "status": status, "hit_count": len(hits), "hits": hits, "notes": note,
                     "hunt": "EDGE-HUNT-0027", "reason": part.get("reason") or off.get("reason")})
    return rows
