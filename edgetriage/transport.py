"""Transports: how commands reach the device.

ReplayTransport  serves recorded outputs from a directory. Used for tests, for
                 training, and for re-running collection logic against outputs
                 an operator captured by hand.
SSHTransport     drives a restricted vendor CLI over an interactive SSH channel
                 (paramiko). It never opens an exec channel or a shell the
                 vendor did not expose; it types what the profile declared.
"""
from __future__ import annotations

import re
import time
from pathlib import Path

from .util import slugify

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[=>]")


class TransportError(RuntimeError):
    pass


class CommandUnavailable(TransportError):
    """The device (or recording) has no output for this command."""


class Transport:
    name = "base"

    def open(self) -> None: ...
    def close(self) -> None: ...

    def run(self, cmd: str, timeout: int = 120) -> str:
        raise NotImplementedError

    def fetch(self, remote: str, local: Path, max_bytes: int | None = None) -> None:
        raise NotImplementedError

    def device_clock_note(self) -> str | None:
        return None


class ReplayTransport(Transport):
    """Recorded outputs: <dir>/commands/<slug>.txt and <dir>/files/<remote path>."""

    name = "replay"

    def __init__(self, root: Path):
        self.root = Path(root)
        if not (self.root / "commands").is_dir():
            raise TransportError(f"replay dir has no commands/: {self.root}")

    def run(self, cmd: str, timeout: int = 120) -> str:
        p = self.root / "commands" / f"{slugify(cmd)}.txt"
        if not p.is_file():
            raise CommandUnavailable(f"no recording for {cmd!r} ({p.name})")
        return p.read_text(encoding="utf-8", errors="replace")

    def fetch(self, remote: str, local: Path, max_bytes: int | None = None) -> None:
        src = self.root / "files" / remote.lstrip("/")
        if not src.is_file():
            raise CommandUnavailable(f"no recording for file {remote}")
        if max_bytes is not None and src.stat().st_size > max_bytes:
            raise CommandUnavailable(f"{remote} exceeds the {max_bytes}-byte fetch cap")
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(src.read_bytes())


class SSHTransport(Transport):
    """Interactive CLI over SSH.

    Restricted appliance CLIs (PAN-OS, FortiOS, ASA) do not support exec
    channels reliably, so this opens one PTY, waits for the prompt, sends each
    declared command, answers pagers with a space, and strips echo and ANSI.
    Host keys are checked against known_hosts unless the operator pins one with
    --hostkey-sha256; an unknown key aborts rather than being trusted silently.
    """

    name = "ssh"

    def __init__(self, host: str, username: str, password: str | None = None,
                 key_filename: str | None = None, port: int = 22, prompt: str = r"[>#$] ?$",
                 pager: str | None = None, hostkey_sha256: str | None = None,
                 known_hosts: str | None = None):
        self.host, self.port, self.username = host, port, username
        self.password, self.key_filename = password, key_filename
        # Matched against the stripped last line only (fullmatch), never searched.
        self.prompt = re.compile(prompt.removesuffix("$").removesuffix(" ?") + " ?")
        self.pager = re.compile(r"\s*(?:" + pager + r")\s*") if pager else None
        self.hostkey_sha256 = hostkey_sha256
        self.known_hosts = known_hosts
        self.client = None
        self.chan = None
        self.observed_hostkey: str | None = None

    def open(self) -> None:
        try:
            import paramiko  # type: ignore
        except ImportError as e:  # pragma: no cover
            raise TransportError("paramiko is required for SSH collection: pip install paramiko") from e
        import base64
        import hashlib

        client = paramiko.SSHClient()
        if self.hostkey_sha256:
            expected = self.hostkey_sha256.removeprefix("SHA256:")

            class Pin(paramiko.MissingHostKeyPolicy):
                def missing_host_key(self, _c, _h, key):
                    got = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
                    if got != expected.rstrip("="):
                        raise TransportError(f"host key mismatch: got SHA256:{got}")
            client.set_missing_host_key_policy(Pin())
        else:
            client.load_system_host_keys()
            if self.known_hosts:
                client.load_host_keys(self.known_hosts)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(self.host, port=self.port, username=self.username, password=self.password,
                       key_filename=self.key_filename, look_for_keys=bool(self.key_filename),
                       allow_agent=False, timeout=20, banner_timeout=30, auth_timeout=30)
        key = client.get_transport().get_remote_server_key()
        self.observed_hostkey = "SHA256:" + base64.b64encode(
            hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        self.client = client
        self.chan = client.invoke_shell(width=511, height=1000)
        self._read_until_prompt(30)

    def close(self) -> None:
        if self.client:
            self.client.close()

    QUIET = 0.4  # seconds of silence required after a prompt-shaped last line

    def _read_until_prompt(self, timeout: int) -> str:
        """Read until the device is idle at its prompt.

        Device output is attacker-influenced: a log line can end in text that
        looks like a prompt or a pager marker. So only the LAST line of the
        buffer is ever tested, a pager marker is stripped only from that line,
        and a prompt-shaped last line must be followed by a quiet period before
        it is believed. A crafted line can still end a capture early if it
        arrives exactly at a pause; outputs are hashed as received, so a short
        capture is visible rather than silent.
        """
        buf = ""
        deadline = time.monotonic() + timeout
        prompt_seen_at = None
        while time.monotonic() < deadline:
            if self.chan.recv_ready():
                buf += self.chan.recv(65535).decode("utf-8", errors="replace")
                prompt_seen_at = None
                head, _, last = buf.rpartition("\n")
                last_clean = ANSI.sub("", last).rstrip("\r")
                if self.pager and self.pager.fullmatch(last_clean.strip()):
                    buf = head + ("\n" if head else "")
                    self.chan.send(" ")
                    continue
                if self.prompt.fullmatch(last_clean.strip()):
                    prompt_seen_at = time.monotonic()
            elif prompt_seen_at is not None and time.monotonic() - prompt_seen_at >= self.QUIET:
                return buf
            else:
                time.sleep(0.05)
        raise TransportError(f"timed out after {timeout}s waiting for prompt")

    def run(self, cmd: str, timeout: int = 120) -> str:
        if self.chan is None:
            raise TransportError("transport not open")
        self.chan.send(cmd + "\n")
        raw = ANSI.sub("", self._read_until_prompt(timeout)).replace("\r", "")
        lines = raw.split("\n")
        if lines and cmd.strip() in lines[0]:
            lines = lines[1:]           # drop echoed command
        if lines and self.prompt.fullmatch(lines[-1].strip()):
            lines = lines[:-1]          # drop trailing prompt
        return "\n".join(lines).strip("\n") + "\n"

    def fetch(self, remote: str, local: Path, max_bytes: int | None = None) -> None:
        try:
            sftp = self.client.open_sftp()
        except Exception as e:
            raise CommandUnavailable(f"SFTP not available on device: {e}") from e
        try:
            import stat as _stat
            st = sftp.stat(remote)
            if not _stat.S_ISREG(st.st_mode or 0):
                raise CommandUnavailable(f"{remote} is not a regular file")
            if max_bytes is not None and (st.st_size or 0) > max_bytes:
                raise CommandUnavailable(f"{remote} exceeds the {max_bytes}-byte fetch cap")
            local.parent.mkdir(parents=True, exist_ok=True)
            sftp.get(remote, str(local))
        except OSError as e:
            raise CommandUnavailable(f"fetch failed for {remote}: {e}") from e
        finally:
            sftp.close()
