"""Collection engine: run a profile against a transport into a case."""
from __future__ import annotations

from typing import Any, Callable

from .custody import Case
from .profiles import Profile, ProfileError, Step
from .transport import CommandUnavailable, Transport, TransportError
from .util import sha256_file, utcnow


class CollectionRefused(RuntimeError):
    pass


def plan(profile: Profile, allow_bundle: bool, break_glass: bool,
         variables: dict[str, str]) -> list[tuple[Step, str | None]]:
    """Ordered steps with a skip reason (or None) for each."""
    out: list[tuple[Step, str | None]] = []
    for s in profile.ordered(allow_bundle, break_glass):
        missing = [v for v in s.requires_vars if v not in variables]
        out.append((s, f"needs --var {', '.join(missing)}" if missing else None))
    return out


def collect(profile: Profile, transport: Transport, case: Case, *, case_id: str,
            operator: str | None, target: dict[str, Any], preflight: dict[str, str],
            variables: dict[str, str], allow_bundle: bool = False, break_glass: bool = False,
            confirm: Callable[[str], bool] | None = None) -> dict[str, Any]:
    if case.exists():
        raise CollectionRefused(f"case already exists: {case.root} (use a new --case-id)")

    steps = plan(profile, allow_bundle, break_glass, variables)
    if break_glass and any(s.impact == "break-glass" for s, _ in steps):
        if confirm is None or not confirm(
                "Break-glass steps can crash, reload or image the device. They run LAST, "
                "after all volatile state is recorded."):
            raise CollectionRefused("break-glass not confirmed")

    m = Case.new_manifest(case_id, operator, profile.platform_id, profile.name)
    m.update({
        "profile_sha256": sha256_file(profile.source) if profile.source else None,
        "target": {**target, "transport": transport.name},
        "preflight": preflight,
        "options": {"allow_bundle": allow_bundle, "break_glass": break_glass,
                    "variables": sorted(variables)},   # names only; values may be paths/hosts
        "expected_evidence": profile.expected_evidence,
        "collection_start_utc": utcnow(),
    })
    case.save(m)  # write early: a crash mid-collection still leaves a manifest

    try:
        transport.open()
    except TransportError:
        raise
    except Exception as e:  # paramiko auth / socket errors
        m["collection_error"] = f"{type(e).__name__}: {e}"
        case.save(m)
        raise TransportError(f"could not open {transport.name} session: {e}") from e
    try:
        observed = getattr(transport, "observed_hostkey", None)
        if observed:
            m["target"]["observed_hostkey"] = observed
        for cmd in profile.session_setup:
            try:
                transport.run(cmd, timeout=30)
            except TransportError:
                pass  # pager handling in the transport covers a refused setup command
        for step, skip in steps:
            m["steps"].append(_run_step(step, skip, transport, case, variables, profile))
            case.save(m)
    finally:
        transport.close()

    m["collection_end_utc"] = utcnow()
    counts: dict[str, int] = {}
    for s in m["steps"]:
        counts[s["status"]] = counts.get(s["status"], 0) + 1
    m["summary"] = counts
    case.save(m)
    return m


def _run_step(step: Step, skip: str | None, transport: Transport, case: Case,
              variables: dict[str, str], profile: Profile) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "step_id": step.id, "tier": step.tier, "kind": step.kind, "impact": step.impact,
        "purpose": step.purpose, "status": None, "started_utc": utcnow(), "ended_utc": None,
        "cmd": None, "output": None, "sha256": None, "bytes": None, "error": None, "files": [],
    }
    if skip:
        rec.update(status="skipped", error=skip, ended_utc=utcnow())
        return rec
    s = step.render(variables)
    rec["cmd"] = s.cmd
    if s.impact == "none":
        try:
            for c in (s.cmd, s.list_cmd):
                if c:
                    profile.check_command(c)
        except ProfileError as e:
            rec.update(status="refused", error=str(e), ended_utc=utcnow())
            return rec

    if s.kind == "manual":
        rec.update(status="pending-manual", error=None, ended_utc=utcnow(),
                   instructions=s.instructions.strip(), references=s.references)
        return rec

    try:
        if s.kind == "command":
            before = utcnow()
            text = transport.run(s.cmd, timeout=s.timeout)
            rec["collector_utc_at_send"] = before
            rel, digest, size = case.write_command(s.id, text)
            rec.update(output=rel, sha256=digest, bytes=size, status="ok")
        elif s.kind == "fetch":
            remotes = list(s.paths)
            if s.list_cmd:
                listing = transport.run(s.list_cmd, timeout=s.timeout)
                rel, digest, size = case.write_command(f"{s.id}.listing", listing)
                rec.update(output=rel, sha256=digest, bytes=size, cmd=s.list_cmd)
                remotes += [ln.strip() for ln in listing.splitlines() if ln.strip().startswith("/")]
            got = 0
            for remote in remotes:
                dest = case.file_dest(s.id, remote)
                try:
                    transport.fetch(remote, dest)
                except CommandUnavailable as e:
                    rec["files"].append({"remote": remote, "error": str(e), "sha256": ""})
                    continue
                rec["files"].append({
                    "remote": remote, "local": str(dest.relative_to(case.root)),
                    "sha256": sha256_file(dest), "bytes": dest.stat().st_size,
                })
                got += 1
            rec["status"] = "ok" if got or not remotes else "unavailable"
            if not remotes:
                rec["error"] = "listing returned no paths"
        rec["ended_utc"] = utcnow()
    except CommandUnavailable as e:
        rec.update(status="unavailable", error=str(e), ended_utc=utcnow())
    except TransportError as e:
        rec.update(status="error", error=str(e), ended_utc=utcnow())
    return rec
