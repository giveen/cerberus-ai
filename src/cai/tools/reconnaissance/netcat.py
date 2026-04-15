"""Managed Netcat socket controller with scope checks, jitter, and forensic auditing."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from datetime import UTC, datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import random
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import threading
from typing import Any, Dict, Iterable, List, Optional, Sequence

from pydantic import BaseModel, Field

from cai.memory.logic import clean_data
from cai.repl.commands.shell import SecureSubprocess
from cai.repl.ui.logging import get_cerebro_logger
from cai.sdk.agents import function_tool
from cai.tools.misc.cli_utils import CLI_UTILS
from cai.tools.validation import is_valid_host, sanitize_tool_output
from cai.tools.workspace import get_project_space


_MAX_TIMEOUT_SECONDS = 30
_MAX_PORTS_PER_REQUEST = 128
_MAX_DATA_BYTES = 131072
_DEFAULT_JITTER_MIN_MS = 75
_DEFAULT_JITTER_MAX_MS = 250
_RED_FLAG_ARGS = {
    "-e",
    "-c",
    "-l",
    "--exec",
    "--sh-exec",
    "--lua-exec",
    "--listen",
}
_DEFAULT_SERVICE_MAP = (
    (re.compile(r"^SSH-", re.IGNORECASE), "ssh", 0.98),
    (re.compile(r"^HTTP/\d", re.IGNORECASE), "http", 0.97),
    (re.compile(r"\bSMTP\b|^220\s", re.IGNORECASE), "smtp", 0.88),
    (re.compile(r"\bFTP\b", re.IGNORECASE), "ftp", 0.88),
    (re.compile(r"\bIMAP\b|\*\s+OK", re.IGNORECASE), "imap", 0.78),
    (re.compile(r"\bPOP3\b|\+OK", re.IGNORECASE), "pop3", 0.76),
    (re.compile(r"\bMYSQL\b", re.IGNORECASE), "mysql", 0.74),
    (re.compile(r"\bREDIS\b", re.IGNORECASE), "redis", 0.74),
)


class ServiceBanner(BaseModel):
    service_type: str = Field(default="unknown")
    confidence: float = Field(default=0.0)
    normalized_banner: str = Field(default="")


class PortObservation(BaseModel):
    target: str
    port: int
    success: bool
    duration_ms: int
    bytes_sent: int
    bytes_received: int
    exit_code: Optional[int] = None
    timeout: bool = False
    banner: Optional[ServiceBanner] = None
    evidence_path: Optional[str] = None
    evidence_sha256: Optional[str] = None
    stderr: str = ""
    error: Optional[str] = None


class NetcatOperationReport(BaseModel):
    ok: bool
    binary: str
    binary_type: str
    target: str
    reason: str
    observations: List[PortObservation] = Field(default_factory=list)


class CerebroNetcatTool:
    """Asynchronous netcat/ncat controller with OPSEC and forensic controls."""

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._evidence_dir = (self._workspace / "evidence" / "network" / "netcat").resolve()
        self._audit_path = (self._workspace / ".cai" / "audit" / "netcat_connections.jsonl").resolve()
        self._secure_subprocess = SecureSubprocess(workspace_root=self._workspace)
        self._logger = get_cerebro_logger()
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._evidence_dir.mkdir(parents=True, exist_ok=True)
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _run_coro(self, coro: Any, timeout: float = 180.0) -> Dict[str, Any]:
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=timeout)

    def run(
        self,
        *,
        host: str,
        port: Optional[int] = None,
        ports: Optional[Sequence[int]] = None,
        data: str = "",
        timeout: int = 8,
        reason: str = "Scoped network reconnaissance",
        jitter_min_ms: int = _DEFAULT_JITTER_MIN_MS,
        jitter_max_ms: int = _DEFAULT_JITTER_MAX_MS,
        save_incoming: bool = True,
        extra_args: str = "",
    ) -> Dict[str, Any]:
        return self._run_coro(
            self._run_async(
                host=host,
                port=port,
                ports=ports,
                data=data,
                timeout=timeout,
                reason=reason,
                jitter_min_ms=jitter_min_ms,
                jitter_max_ms=jitter_max_ms,
                save_incoming=save_incoming,
                extra_args=extra_args,
            ),
            timeout=max(45.0, float(timeout) * 2.5),
        )

    async def _run_async(
        self,
        *,
        host: str,
        port: Optional[int],
        ports: Optional[Sequence[int]],
        data: str,
        timeout: int,
        reason: str,
        jitter_min_ms: int,
        jitter_max_ms: int,
        save_incoming: bool,
        extra_args: str,
    ) -> Dict[str, Any]:
        target = (host or "").strip()
        if not target or not is_valid_host(target):
            return self._error("invalid_target", f"Target host is invalid: {host!r}")

        timeout = max(1, min(int(timeout), _MAX_TIMEOUT_SECONDS))
        payload = (data or "").encode("utf-8", errors="replace")
        if len(payload) > _MAX_DATA_BYTES:
            return self._error("payload_too_large", f"Payload exceeds {_MAX_DATA_BYTES} byte policy limit")

        target_ports = self._normalize_ports(port=port, ports=ports)
        if not target_ports:
            return self._error("missing_port", "Provide a port or list of ports to connect")

        binary_name, binary_path = self._select_binary()
        if not binary_path:
            return self._error("missing_dependency", "Neither nc nor ncat executable is available")

        binary_type = self._verify_binary(binary_name=binary_name, binary_path=binary_path)
        if binary_type == "unknown":
            return self._error("unsupported_binary", "Resolved binary is not a supported nc/ncat implementation")

        scope_error = self._validate_scope(target=target, ports=target_ports)
        if scope_error:
            return self._error("scope_violation", scope_error)

        extra_tokens = self._parse_extra_args(extra_args)
        if isinstance(extra_tokens, str):
            return self._error("invalid_args", extra_tokens)

        clean_env, redactions = self._secure_subprocess.build_clean_environment()
        observations: List[PortObservation] = []

        for idx, port_num in enumerate(target_ports):
            if idx > 0 and len(target_ports) > 1:
                await self._sleep_with_jitter(jitter_min_ms, jitter_max_ms)

            started = datetime.now(tz=UTC)
            obs = await self._connect_once(
                binary_path=binary_path,
                binary_type=binary_type,
                target=target,
                port=port_num,
                payload=payload,
                timeout=timeout,
                extra_tokens=extra_tokens,
                redactions=redactions,
                base_env=clean_env,
                save_incoming=save_incoming,
            )
            finished = datetime.now(tz=UTC)
            await self._audit_connection(
                reason=reason,
                target=target,
                port=port_num,
                success=obs.success,
                duration_ms=obs.duration_ms,
                started_at=started,
                finished_at=finished,
                binary=binary_name,
                error=obs.error or obs.stderr,
            )
            observations.append(obs)

        report = NetcatOperationReport(
            ok=any(item.success for item in observations),
            binary=str(binary_path),
            binary_type=binary_type,
            target=target,
            reason=reason,
            observations=observations,
        )
        return clean_data(report.model_dump())

    async def _connect_once(
        self,
        *,
        binary_path: Path,
        binary_type: str,
        target: str,
        port: int,
        payload: bytes,
        timeout: int,
        extra_tokens: Sequence[str],
        redactions: Dict[str, str],
        base_env: Dict[str, str],
        save_incoming: bool,
    ) -> PortObservation:
        argv = self._build_argv(
            binary_path=binary_path,
            binary_type=binary_type,
            target=target,
            port=port,
            timeout=timeout,
            extra_tokens=extra_tokens,
        )

        started = asyncio.get_running_loop().time()
        timed_out = False
        stdout_text = ""
        stderr_text = ""
        exit_code: Optional[int] = None

        with CLI_UTILS.managed_env_context(base_env=base_env) as env:
            process = await asyncio.create_subprocess_exec(
                *argv,
                cwd=str(self._workspace),
                env=env,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                out, err = await asyncio.wait_for(process.communicate(input=payload or b""), timeout=float(timeout) + 1.0)
            except asyncio.TimeoutError:
                timed_out = True
                process.terminate()
                with suppress(Exception):
                    await asyncio.wait_for(process.wait(), timeout=1.5)
                if process.returncode is None:
                    process.kill()
                    await process.wait()
                out, err = b"", b""
            exit_code = process.returncode

        elapsed = int((asyncio.get_running_loop().time() - started) * 1000)
        stdout_text = self._redact_socket_data(self._secure_subprocess.redact_text(out.decode("utf-8", errors="replace"), redactions))
        stderr_text = self._redact_socket_data(self._secure_subprocess.redact_text(err.decode("utf-8", errors="replace"), redactions))
        stdout_text = sanitize_tool_output("netcat_stdout", stdout_text)
        stderr_text = sanitize_tool_output("netcat_stderr", stderr_text)

        banner = self._normalize_banner(stdout_text)
        evidence_path = None
        evidence_hash = None
        if save_incoming and stdout_text:
            evidence_path, evidence_hash = await self._write_evidence(target=target, port=port, content=stdout_text)

        success = (not timed_out) and (exit_code in (0, None)) and (bool(stdout_text) or bool(payload) or not stderr_text)
        error = None
        if timed_out:
            error = "connection_timeout"
        elif exit_code not in (0, None):
            error = f"exit_code_{exit_code}"

        return PortObservation(
            target=target,
            port=port,
            success=success,
            duration_ms=elapsed,
            bytes_sent=len(payload),
            bytes_received=len(stdout_text.encode("utf-8", errors="replace")),
            exit_code=exit_code,
            timeout=timed_out,
            banner=banner,
            evidence_path=evidence_path,
            evidence_sha256=evidence_hash,
            stderr=stderr_text,
            error=error,
        )

    @staticmethod
    def _build_argv(
        *,
        binary_path: Path,
        binary_type: str,
        target: str,
        port: int,
        timeout: int,
        extra_tokens: Sequence[str],
    ) -> List[str]:
        argv = [str(binary_path)]
        if binary_type == "ncat":
            argv.extend(["-w", str(timeout)])
        else:
            argv.extend(["-w", str(timeout)])
        argv.extend(extra_tokens)
        argv.extend([target, str(port)])
        return argv

    @staticmethod
    def _normalize_ports(*, port: Optional[int], ports: Optional[Sequence[int]]) -> List[int]:
        found: List[int] = []
        if port is not None:
            found.append(int(port))
        if ports:
            for value in ports:
                found.append(int(value))
        unique = sorted({p for p in found if 1 <= int(p) <= 65535})
        return unique[:_MAX_PORTS_PER_REQUEST]

    @staticmethod
    def _parse_extra_args(args: str) -> Sequence[str] | str:
        raw = (args or "").strip()
        if not raw:
            return []
        try:
            tokens = shlex.split(raw, posix=True)
        except ValueError as exc:
            return f"unable to parse extra args: {exc}"
        for token in tokens:
            if token in _RED_FLAG_ARGS:
                return f"unsafe netcat option blocked: {token}"
            if token.startswith("--exec") or token.startswith("--sh-exec"):
                return f"unsafe netcat option blocked: {token}"
        return tokens

    @staticmethod
    def _select_binary() -> tuple[str, Optional[Path]]:
        ncat = shutil.which("ncat")
        if ncat:
            return "ncat", Path(ncat)
        nc = shutil.which("nc")
        if nc:
            return "nc", Path(nc)
        return "", None

    @staticmethod
    def _verify_binary(*, binary_name: str, binary_path: Path) -> str:
        name = binary_path.name.lower()
        if name not in {"nc", "ncat"}:
            return "unknown"
        help_output = ""
        for flag in ("--help", "-h"):
            with suppress(Exception):
                cp = subprocess.run(
                    [str(binary_path), flag],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    check=False,
                    text=True,
                )
                out = cp.stdout or ""
                if out:
                    help_output = out.lower()
                    break
        if "ncat" in help_output:
            return "ncat"
        if "openbsd" in help_output or "traditional" in help_output or binary_name == "nc":
            return "nc"
        return "ncat" if binary_name == "ncat" else "nc"

    def _validate_scope(self, *, target: str, ports: Sequence[int]) -> Optional[str]:
        target_ok, reason = self._target_in_scope(target)
        if not target_ok:
            return reason
        allowed_ports = self._allowed_ports()
        blocked = [str(p) for p in ports if p not in allowed_ports]
        if blocked:
            return f"ports out of engagement scope: {', '.join(blocked)}"
        return None

    def _target_in_scope(self, target: str) -> tuple[bool, str]:
        patterns = self._allowed_target_patterns()
        if not patterns:
            return True, ""
        host_l = target.lower()
        with suppress(Exception):
            ip = ipaddress.ip_address(target)
            for item in patterns:
                if "/" in item:
                    with suppress(Exception):
                        if ip in ipaddress.ip_network(item, strict=False):
                            return True, ""
                elif item == target:
                    return True, ""
            return False, f"target {target} not present in CEREBRO_ENGAGEMENT_SCOPE/CEREBRO_ALLOWED_TARGETS"
        for item in patterns:
            norm = item.lower()
            if norm.startswith("*.") and host_l.endswith(norm[1:]):
                return True, ""
            if host_l == norm:
                return True, ""
        return False, f"target {target} not present in CEREBRO_ENGAGEMENT_SCOPE/CEREBRO_ALLOWED_TARGETS"

    @staticmethod
    def _allowed_target_patterns() -> List[str]:
        raw = ",".join(
            [
                os.getenv("CEREBRO_ENGAGEMENT_SCOPE", ""),
                os.getenv("CEREBRO_ALLOWED_TARGETS", ""),
            ]
        )
        values = [x.strip() for x in raw.split(",") if x.strip()]
        return sorted(set(values))

    @staticmethod
    def _allowed_ports() -> set[int]:
        raw = os.getenv("CEREBRO_ALLOWED_PORTS", "").strip()
        if not raw:
            return set(range(1, 65536))
        allowed: set[int] = set()
        for token in raw.split(","):
            chunk = token.strip()
            if not chunk:
                continue
            if "-" in chunk:
                a, b = chunk.split("-", 1)
                with suppress(Exception):
                    start = max(1, int(a))
                    end = min(65535, int(b))
                    for port in range(min(start, end), max(start, end) + 1):
                        allowed.add(port)
            else:
                with suppress(Exception):
                    port_num = int(chunk)
                    if 1 <= port_num <= 65535:
                        allowed.add(port_num)
        return allowed or set(range(1, 65536))

    @staticmethod
    async def _sleep_with_jitter(jitter_min_ms: int, jitter_max_ms: int) -> None:
        low = max(0, int(jitter_min_ms))
        high = max(low, int(jitter_max_ms))
        wait_ms = random.randint(low, high)
        await asyncio.sleep(float(wait_ms) / 1000.0)

    def _normalize_banner(self, banner_text: str) -> Optional[ServiceBanner]:
        sample = "\n".join((banner_text or "").splitlines()[:3]).strip()
        if not sample:
            return None
        for pattern, service, confidence in _DEFAULT_SERVICE_MAP:
            if pattern.search(sample):
                return ServiceBanner(service_type=service, confidence=confidence, normalized_banner=sample)
        return ServiceBanner(service_type="unknown", confidence=0.3, normalized_banner=sample)

    def _redact_socket_data(self, text: str) -> str:
        redacted = text or ""
        markers = {
            socket.gethostname(),
            os.getenv("USER", ""),
            os.getenv("LOGNAME", ""),
            "jabbatheduck",
            "cerberus-ai",
        }
        for marker in markers:
            marker = marker.strip()
            if marker:
                redacted = redacted.replace(marker, "[REDACTED_INTERNAL]")
        redacted = re.sub(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[REDACTED_IP]", redacted)
        redacted = re.sub(r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "[REDACTED_IP]", redacted)
        redacted = re.sub(r"\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b", "[REDACTED_IP]", redacted)
        return redacted

    async def _write_evidence(self, *, target: str, port: int, content: str) -> tuple[str, str]:
        timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        suffix = secrets.token_hex(4)
        stem = f"NETCAT_{target.replace(':', '_')}_{port}_{timestamp}_{suffix}"
        data_path = self._evidence_dir / f"{stem}.txt"
        meta_path = self._evidence_dir / f"{stem}.json"
        raw = content.encode("utf-8", errors="replace")
        digest = hashlib.sha256(raw).hexdigest()

        def _persist() -> None:
            data_path.write_bytes(raw)
            metadata = {
                "timestamp": datetime.now(tz=UTC).isoformat(),
                "target": target,
                "port": port,
                "sha256": digest,
                "bytes": len(raw),
                "file": data_path.name,
            }
            meta_path.write_text(json.dumps(clean_data(metadata), ensure_ascii=True, indent=2), encoding="utf-8")

        await asyncio.to_thread(_persist)
        return self._display_path(data_path), digest

    async def _audit_connection(
        self,
        *,
        reason: str,
        target: str,
        port: int,
        success: bool,
        duration_ms: int,
        started_at: datetime,
        finished_at: datetime,
        binary: str,
        error: str,
    ) -> None:
        row = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "reason": reason,
            "target": target,
            "port": port,
            "success": success,
            "duration_ms": duration_ms,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "binary": binary,
            "error": (error or "")[:800],
        }
        line = json.dumps(clean_data(row), ensure_ascii=True) + "\n"

        def _append() -> None:
            self._audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self._audit_path.open("a", encoding="utf-8") as handle:
                handle.write(line)

        await asyncio.to_thread(_append)
        if self._logger is not None:
            with suppress(Exception):
                self._logger.audit(
                    "netcat connection audited",
                    actor="netcat",
                    data=clean_data(row),
                    tags=["netcat", "network", "audit"],
                )

    def _display_path(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self._workspace))
        except ValueError:
            return str(path.resolve())

    @staticmethod
    def _error(code: str, message: str) -> Dict[str, Any]:
        return clean_data({"ok": False, "error": {"code": code, "message": message}})


NETCAT_TOOL = CerebroNetcatTool()


@function_tool
def netcat(
    host: str,
    port: int,
    data: str = "",
    args: str = "",
    timeout: int = 10,
    reason: str = "Scoped network reconnaissance",
) -> Dict[str, Any]:
    return NETCAT_TOOL.run(
        host=host,
        port=port,
        data=data,
        timeout=timeout,
        reason=reason,
        extra_args=args,
        save_incoming=True,
    )


@function_tool
def netcat_scan(
    host: str,
    ports: str,
    timeout: int = 5,
    reason: str = "Port discovery and banner validation",
    jitter_min_ms: int = _DEFAULT_JITTER_MIN_MS,
    jitter_max_ms: int = _DEFAULT_JITTER_MAX_MS,
    args: str = "",
) -> Dict[str, Any]:
    parsed_ports: List[int] = []
    for token in (ports or "").split(","):
        item = token.strip()
        if not item:
            continue
        if "-" in item:
            try:
                start_s, end_s = item.split("-", 1)
                start_i = max(1, int(start_s))
                end_i = min(65535, int(end_s))
                for p in range(min(start_i, end_i), max(start_i, end_i) + 1):
                    parsed_ports.append(p)
            except Exception:
                continue
        else:
            with suppress(Exception):
                parsed_ports.append(int(item))
    return NETCAT_TOOL.run(
        host=host,
        ports=parsed_ports,
        timeout=timeout,
        reason=reason,
        jitter_min_ms=jitter_min_ms,
        jitter_max_ms=jitter_max_ms,
        extra_args=args,
        save_incoming=True,
    )


__all__ = ["CerebroNetcatTool", "NETCAT_TOOL", "netcat", "netcat_scan"]
