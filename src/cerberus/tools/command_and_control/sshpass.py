"""Managed, audited SSH password tool for Cerberus AI.

Security properties:
- Uses `sshpass -d <fd>` to inject password without exposing it in argv/history.
- Applies workspace-scoped host key policy (strict by default, TOFU in discovery mode).
- Redacts sensitive data from command output and recorded artifacts.
- Emits semantic, strategy-friendly error categories for callers.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import shutil
import subprocess  # nosec B404
import threading
from typing import Any, Dict, Optional

from cerberus.sdk.agents import function_tool
from cerberus.memory.logic import clean_data
from cerberus.repl.commands.shell import SecureSubprocess
from cerberus.tools.validation import is_valid_host
from cerberus.tools.workspace import get_project_space


@dataclass(frozen=True)
class SemanticError:
    code: str
    message: str
    retryable: bool
    category: str


class CerebroSSHPassTool:
    """Managed SSH password execution with sanitization and forensic tracking."""

    TOOL_NAME = "cerebro_sshpass"
    AUDIT_FILE = Path(".cerberus/audit/sshpass_audit.jsonl")
    KNOWN_HOSTS_FILE = Path(".cerberus/ssh/known_hosts")

    def __init__(self) -> None:
        self._workspace_root = get_project_space().ensure_initialized().resolve()
        self._subprocess_guard = SecureSubprocess(workspace_root=self._workspace_root)

    def execute(
        self,
        *,
        host: str,
        username: str,
        password: str,
        command: str,
        port: int = 22,
        timeout_seconds: int = 20,
        discovery_mode: bool = False,
    ) -> Dict[str, Any]:
        return self._run_blocking(
            self._execute_async(
                host=host,
                username=username,
                password=password,
                command=command,
                port=port,
                timeout_seconds=timeout_seconds,
                discovery_mode=discovery_mode,
            )
        )

    def _run_blocking(self, coro: Any) -> Dict[str, Any]:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)

        result: Dict[str, Any] = {}
        failure: Dict[str, BaseException] = {}

        def _runner() -> None:
            try:
                result["value"] = asyncio.run(coro)
            except BaseException as exc:  # pragma: no cover - defensive bridge.
                failure["error"] = exc

        thread = threading.Thread(target=_runner, daemon=True)
        thread.start()
        thread.join()

        if "error" in failure:
            raise RuntimeError("CerebroSSHPassTool async execution failed") from failure["error"]
        return result.get("value", {})

    async def _execute_async(
        self,
        *,
        host: str,
        username: str,
        password: str,
        command: str,
        port: int,
        timeout_seconds: int,
        discovery_mode: bool,
    ) -> Dict[str, Any]:
        started_at = datetime.now(tz=UTC)
        sshpass_path = shutil.which("sshpass")
        ssh_path = shutil.which("ssh")

        dependency_error = self._dependency_error(sshpass_path=sshpass_path, ssh_path=ssh_path)
        if dependency_error is not None:
            response = self._error_response(
                destination=host,
                username=username,
                port=port,
                started_at=started_at,
                semantic=dependency_error,
                stdout="",
                stderr="",
                timed_out=False,
                exit_code=None,
                host_fingerprint=None,
                discovery_mode=discovery_mode,
            )
            self._write_audit(response)
            return response

        input_error = self._validate_input(host=host, username=username, password=password, command=command, port=port)
        if input_error is not None:
            response = self._error_response(
                destination=host,
                username=username,
                port=port,
                started_at=started_at,
                semantic=input_error,
                stdout="",
                stderr="",
                timed_out=False,
                exit_code=None,
                host_fingerprint=None,
                discovery_mode=discovery_mode,
            )
            self._write_audit(response)
            return response

        known_hosts_path = self._prepare_known_hosts()
        host_fingerprint = self._collect_host_fingerprint(host=host, port=port, timeout_seconds=timeout_seconds)
        strict_mode = "accept-new" if discovery_mode else "yes"
        ssh_argv = [
            str(sshpass_path),
            "-d",
            "3",
            str(ssh_path),
            "-o",
            f"StrictHostKeyChecking={strict_mode}",
            "-o",
            f"UserKnownHostsFile={known_hosts_path}",
            "-o",
            "BatchMode=no",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-o",
            f"ConnectTimeout={max(1, int(timeout_seconds))}",
            "-p",
            str(port),
            f"{username}@{host}",
            "--",
            command,
        ]

        clean_env, redaction_map = self._subprocess_guard.build_clean_environment()
        redaction_map = dict(redaction_map)
        redaction_map[password] = "[REDACTED_SECRET]"

        read_fd: Optional[int] = None
        write_fd: Optional[int] = None
        timed_out = False
        exit_code: Optional[int] = None
        stdout_text = ""
        stderr_text = ""

        try:
            read_fd, write_fd = os.pipe()
            os.set_inheritable(read_fd, True)

            process = await asyncio.create_subprocess_exec(
                *ssh_argv,
                cwd=str(self._workspace_root),
                env=clean_env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                pass_fds=(read_fd,),
            )

            # Parent no longer needs the read end after spawn.
            os.close(read_fd)
            read_fd = None

            os.write(write_fd, password.encode("utf-8", errors="ignore") + b"\n")
            os.close(write_fd)
            write_fd = None

            try:
                raw_stdout, raw_stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=max(1, int(timeout_seconds) + 2),
                )
            except asyncio.TimeoutError:
                timed_out = True
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=3)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                raw_stdout, raw_stderr = b"", b"ssh execution timeout\n"

            stdout_text = self._subprocess_guard.redact_text(
                raw_stdout.decode("utf-8", errors="replace"),
                redaction_map,
            )
            stderr_text = self._subprocess_guard.redact_text(
                raw_stderr.decode("utf-8", errors="replace"),
                redaction_map,
            )
            exit_code = process.returncode

        finally:
            if read_fd is not None:
                try:
                    os.close(read_fd)
                except OSError:
                    pass
            if write_fd is not None:
                try:
                    os.close(write_fd)
                except OSError:
                    pass

        semantic = self._normalize_error(exit_code=exit_code, stderr=stderr_text, timed_out=timed_out)
        ok = semantic is None
        response = {
            "tool": self.TOOL_NAME,
            "ok": ok,
            "destination": host,
            "username": username,
            "port": port,
            "discovery_mode": discovery_mode,
            "host_fingerprint": host_fingerprint,
            "started_at": started_at.isoformat(),
            "finished_at": datetime.now(tz=UTC).isoformat(),
            "timed_out": timed_out,
            "exit_code": exit_code,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "semantic_error": asdict(semantic) if semantic else None,
        }
        self._write_audit(response)
        return clean_data(response)

    def _dependency_error(self, *, sshpass_path: Optional[str], ssh_path: Optional[str]) -> Optional[SemanticError]:
        missing = []
        if not sshpass_path:
            missing.append("sshpass")
        if not ssh_path:
            missing.append("ssh")
        if not missing:
            return None
        return SemanticError(
            code="dependency_missing",
            message=f"Missing required dependency: {', '.join(missing)}",
            retryable=False,
            category="dependency",
        )

    def _validate_input(
        self,
        *,
        host: str,
        username: str,
        password: str,
        command: str,
        port: int,
    ) -> Optional[SemanticError]:
        if not is_valid_host(host):
            return SemanticError(
                code="invalid_target",
                message="Host is not a valid IP or hostname.",
                retryable=False,
                category="input",
            )
        if not username or any(ch in username for ch in "\r\n\0 "):
            return SemanticError(
                code="invalid_username",
                message="Username is empty or contains unsupported characters.",
                retryable=False,
                category="input",
            )
        if not password:
            return SemanticError(
                code="invalid_password",
                message="Password cannot be empty.",
                retryable=False,
                category="input",
            )
        if not command.strip() or "\x00" in command:
            return SemanticError(
                code="invalid_command",
                message="Command is empty or contains null bytes.",
                retryable=False,
                category="input",
            )
        if not (1 <= int(port) <= 65535):
            return SemanticError(
                code="invalid_port",
                message="Port must be between 1 and 65535.",
                retryable=False,
                category="input",
            )
        return None

    def _prepare_known_hosts(self) -> Path:
        known_hosts = (self._workspace_root / self.KNOWN_HOSTS_FILE).resolve()
        known_hosts.parent.mkdir(parents=True, exist_ok=True)
        if not known_hosts.exists():
            known_hosts.touch()
        try:
            os.chmod(known_hosts, 0o600)
        except OSError:
            pass
        return known_hosts

    def _collect_host_fingerprint(self, *, host: str, port: int, timeout_seconds: int) -> Optional[str]:
        keyscan = shutil.which("ssh-keyscan")
        keygen = shutil.which("ssh-keygen")
        if not keyscan or not keygen:
            return None

        try:
            scan = subprocess.run(  # nosec B603
                [keyscan, "-T", str(max(2, timeout_seconds)), "-p", str(port), host],
                capture_output=True,
                text=True,
                check=False,
                timeout=max(3, timeout_seconds + 1),
            )
            if scan.returncode != 0 or not scan.stdout.strip():
                return None

            digest = subprocess.run(  # nosec B603
                [keygen, "-lf", "-"],
                input=scan.stdout,
                capture_output=True,
                text=True,
                check=False,
                timeout=max(3, timeout_seconds + 1),
            )
            if digest.returncode != 0:
                return None
            line = digest.stdout.strip().splitlines()
            return line[0] if line else None
        except Exception:
            return None

    def _normalize_error(self, *, exit_code: Optional[int], stderr: str, timed_out: bool) -> Optional[SemanticError]:
        text = (stderr or "").lower()
        if timed_out:
            return SemanticError(
                code="timeout",
                message="SSH execution timed out.",
                retryable=True,
                category="network",
            )
        if exit_code in (0, None) and "permission denied" not in text:
            return None

        if "permission denied" in text or exit_code == 5:
            return SemanticError(
                code="auth_failed",
                message="Authentication failed. Credentials were rejected.",
                retryable=True,
                category="authentication",
            )
        if "host key verification failed" in text or exit_code in {6, 7}:
            return SemanticError(
                code="host_key_verification_failed",
                message="Host key verification failed.",
                retryable=False,
                category="trust",
            )
        if "connection refused" in text:
            return SemanticError(
                code="connection_refused",
                message="Remote SSH service refused the connection.",
                retryable=True,
                category="network",
            )
        if "connection timed out" in text or "operation timed out" in text:
            return SemanticError(
                code="timeout",
                message="Connection timed out before completion.",
                retryable=True,
                category="network",
            )
        if "no route to host" in text or "network is unreachable" in text:
            return SemanticError(
                code="network_unreachable",
                message="Host is unreachable from current network path.",
                retryable=True,
                category="network",
            )
        if exit_code == 255:
            return SemanticError(
                code="ssh_transport_error",
                message="SSH transport failed before command execution.",
                retryable=True,
                category="transport",
            )
        return SemanticError(
            code="remote_command_failed",
            message="Remote SSH command failed.",
            retryable=True,
            category="execution",
        )

    def _error_response(
        self,
        *,
        destination: str,
        username: str,
        port: int,
        started_at: datetime,
        semantic: SemanticError,
        stdout: str,
        stderr: str,
        timed_out: bool,
        exit_code: Optional[int],
        host_fingerprint: Optional[str],
        discovery_mode: bool,
    ) -> Dict[str, Any]:
        return clean_data(
            {
                "tool": self.TOOL_NAME,
                "ok": False,
                "destination": destination,
                "username": username,
                "port": port,
                "discovery_mode": discovery_mode,
                "host_fingerprint": host_fingerprint,
                "started_at": started_at.isoformat(),
                "finished_at": datetime.now(tz=UTC).isoformat(),
                "timed_out": timed_out,
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "semantic_error": asdict(semantic),
            }
        )

    def _write_audit(self, payload: Dict[str, Any]) -> None:
        destination = str(payload.get("destination", ""))
        username = str(payload.get("username", ""))
        port = int(payload.get("port", 22)) if str(payload.get("port", "")).isdigit() else 22
        semantic = payload.get("semantic_error") or {}
        record = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "tool": self.TOOL_NAME,
            "destination": destination,
            "username": username,
            "port": port,
            "discovery_mode": bool(payload.get("discovery_mode", False)),
            "success": bool(payload.get("ok", False)),
            "timed_out": bool(payload.get("timed_out", False)),
            "exit_code": payload.get("exit_code"),
            "host_fingerprint": payload.get("host_fingerprint"),
            "semantic_error_code": semantic.get("code") if isinstance(semantic, dict) else None,
        }

        audit_path = (self._workspace_root / self.AUDIT_FILE).resolve()
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        with audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(clean_data(record), ensure_ascii=True, default=str) + "\n")


SSH_PASS_TOOL = CerebroSSHPassTool()


@function_tool
def run_ssh_command_with_credentials(
    host: str,
    username: str,
    password: str,
    command: str,
    port: int = 22,
    timeout_seconds: int = 20,
    discovery_mode: bool = False,
) -> Dict[str, Any]:
    """Execute a remote SSH command using password authentication with audit controls."""
    return SSH_PASS_TOOL.execute(
        host=host,
        username=username,
        password=password,
        command=command,
        port=port,
        timeout_seconds=timeout_seconds,
        discovery_mode=discovery_mode,
    )


__all__ = ["CerebroSSHPassTool", "run_ssh_command_with_credentials"]
