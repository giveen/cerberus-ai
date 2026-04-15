"""Hardened SMB client engine with forensic transfer controls."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import stat
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Union

from cerberus.memory.logic import clean_data
from cerberus.repl.commands.shell import SecureSubprocess
from cerberus.repl.ui.logging import get_cerberus_logger
from cerberus.tools import validation
from cerberus.tools.workspace import get_project_space


@dataclass
class SMBTransferRecord:
    transfer_id: str
    host: str
    share: str
    remote_path: str
    local_path: str
    status: str
    started_at: str
    ended_at: str
    bytes_written: int
    sha256: str
    stderr_tail: str


class CerebroSMBClientTool:
    """SMB enumeration and exfiltration with strict workspace containment."""

    DEFAULT_TIMEOUT = 60
    DEFAULT_MAX_DEPTH = 4

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._evidence_root = (self._workspace / "evidence" / "exfiltration" / "smb").resolve()
        self._evidence_root.mkdir(parents=True, exist_ok=True)
        self._audit_log = self._evidence_root / "smb_audit.jsonl"
        self._secure_subprocess = SecureSubprocess(workspace_root=self._workspace)
        self._logger = get_cerberus_logger()
        self._transfer_tasks: Dict[str, asyncio.Task[Dict[str, Any]]] = {}
        self._transfer_results: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def list_shares(
        self,
        host: str,
        username: Optional[str],
        password: Optional[str],
        ntlm_hash: Optional[str],
        domain: Optional[str],
        port: int,
        timeout: int,
    ) -> Dict[str, Any]:
        host_err = self._validate_host(host)
        if host_err:
            return self._error("invalid_host", host_err)

        if not self._has_smbclient():
            return self._error("missing_dependency", "smbclient binary not found on host PATH.")

        argv = [self._smbclient_path(), "-L", host, "-p", str(max(1, int(port)))]
        auth_file = self._write_auth_file(username=username, password=password, ntlm_hash=ntlm_hash, domain=domain)
        argv.extend(["-A", auth_file])

        self._audit("connection_attempt", {"host": host, "operation": "list_shares", "port": port})
        result = await self._run_argv(argv=argv, timeout=timeout)
        self._remove_file(auth_file)

        if not result["ok"]:
            return result

        parsed = self._parse_share_listing(result["stdout"])
        self._audit("shares_listed", {"host": host, "share_count": len(parsed)})
        return clean_data({"ok": True, "host": host, "shares": parsed, "raw": result["stdout"]})

    async def run_smbclient(
        self,
        host: str,
        share: str,
        username: Optional[str],
        password: Optional[str],
        ntlm_hash: Optional[str],
        domain: Optional[str],
        port: int,
        commands: Optional[Union[str, Sequence[str]]],
        extra_args: Optional[Sequence[str]],
        timeout: int,
    ) -> Dict[str, Any]:
        hs_err = self._validate_host_share(host, share)
        if hs_err:
            return self._error("invalid_target", hs_err)

        if not self._has_smbclient():
            return self._error("missing_dependency", "smbclient binary not found on host PATH.")

        service = self._service_path(host, share)
        argv = [self._smbclient_path(), service, "-p", str(max(1, int(port)))]

        auth_file = self._write_auth_file(username=username, password=password, ntlm_hash=ntlm_hash, domain=domain)
        argv.extend(["-A", auth_file])

        if extra_args:
            argv.extend([str(arg) for arg in extra_args])

        if commands:
            command_text = "; ".join(commands) if isinstance(commands, (list, tuple)) else str(commands)
            argv.extend(["-c", command_text])

        self._audit("connection_attempt", {"host": host, "share": share, "operation": "run_command", "port": port})
        result = await self._run_argv(argv=argv, timeout=timeout)
        self._remove_file(auth_file)
        return result

    async def list_files(
        self,
        host: str,
        share: str,
        username: Optional[str],
        password: Optional[str],
        ntlm_hash: Optional[str],
        domain: Optional[str],
        port: int,
        root_path: str,
        max_depth: int,
        timeout: int,
    ) -> Dict[str, Any]:
        hs_err = self._validate_host_share(host, share)
        if hs_err:
            return self._error("invalid_target", hs_err)

        depth_limit = max(0, min(int(max_depth), 8))
        queue: List[tuple[str, int]] = [(root_path.strip() or ".", 0)]
        seen: set[str] = set()
        files: List[Dict[str, Any]] = []

        while queue:
            current, depth = queue.pop(0)
            key = current.lower()
            if key in seen:
                continue
            seen.add(key)

            cmd = [f'cd "{self._escape_smb_token(current)}"', "ls"]
            run = await self.run_smbclient(
                host=host,
                share=share,
                username=username,
                password=password,
                ntlm_hash=ntlm_hash,
                domain=domain,
                port=port,
                commands=cmd,
                extra_args=None,
                timeout=timeout,
            )
            if not run.get("ok"):
                files.append({"path": current, "type": "error", "error": (run.get("error") or {}).get("message", "ls failed")})
                continue

            entries = self._parse_ls_output(str(run.get("stdout", "")), base=current)
            files.extend(entries["files"])
            if depth < depth_limit:
                for directory in entries["dirs"]:
                    queue.append((directory, depth + 1))

        self._audit("files_listed", {"host": host, "share": share, "count": len(files), "max_depth": depth_limit})
        return clean_data({"ok": True, "host": host, "share": share, "max_depth": depth_limit, "entries": files})

    async def download_file(
        self,
        host: str,
        share: str,
        remote_path: str,
        username: Optional[str],
        password: Optional[str],
        ntlm_hash: Optional[str],
        domain: Optional[str],
        port: int,
        timeout: int,
    ) -> Dict[str, Any]:
        hs_err = self._validate_host_share(host, share)
        if hs_err:
            return self._error("invalid_target", hs_err)

        remote_clean = (remote_path or "").strip().replace("\\", "/")
        if not remote_clean:
            return self._error("invalid_path", "remote_path is required")

        local_name = self._forensic_file_name(host=host, share=share, remote_path=remote_clean)
        local_path = (self._evidence_root / local_name).resolve()
        cmd = [f'get "{self._escape_smb_token(remote_clean)}" "{self._escape_smb_token(str(local_path))}"']

        self._audit("file_transfer_start", {"host": host, "share": share, "remote_path": remote_clean, "local_path": str(local_path)})
        run = await self.run_smbclient(
            host=host,
            share=share,
            username=username,
            password=password,
            ntlm_hash=ntlm_hash,
            domain=domain,
            port=port,
            commands=cmd,
            extra_args=None,
            timeout=timeout,
        )
        if not run.get("ok"):
            return run

        sha = self._sha256_file(local_path)
        size = local_path.stat().st_size if local_path.exists() else 0
        metadata_path = local_path.with_suffix(local_path.suffix + ".metadata.json")
        metadata = {
            "agent_id": self._agent_id(),
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "host": host,
            "share": share,
            "remote_path": remote_clean,
            "local_path": str(local_path),
            "sha256": sha,
            "size_bytes": size,
        }
        metadata_path.write_text(json.dumps(clean_data(metadata), indent=2, ensure_ascii=True), encoding="utf-8")

        self._audit("file_transfer_complete", {"host": host, "share": share, "remote_path": remote_clean, "sha256": sha, "size_bytes": size})
        return clean_data(
            {
                "ok": True,
                "host": host,
                "share": share,
                "remote_path": remote_clean,
                "local_path": str(local_path),
                "metadata_path": str(metadata_path),
                "sha256": sha,
                "size_bytes": size,
                "stdout": run.get("stdout", ""),
            }
        )

    async def download_file_background(
        self,
        host: str,
        share: str,
        remote_path: str,
        username: Optional[str],
        password: Optional[str],
        ntlm_hash: Optional[str],
        domain: Optional[str],
        port: int,
        timeout: int,
    ) -> Dict[str, Any]:
        transfer_id = f"smb-{secrets.token_hex(6)}"

        async def _job() -> Dict[str, Any]:
            return await self.download_file(
                host=host,
                share=share,
                remote_path=remote_path,
                username=username,
                password=password,
                ntlm_hash=ntlm_hash,
                domain=domain,
                port=port,
                timeout=timeout,
            )

        async with self._lock:
            self._transfer_tasks[transfer_id] = asyncio.create_task(_job())

        self._audit("file_transfer_queued", {"transfer_id": transfer_id, "host": host, "share": share, "remote_path": remote_path})
        return {"ok": True, "transfer_id": transfer_id, "status": "queued"}

    async def transfer_status(self, transfer_id: str) -> Dict[str, Any]:
        async with self._lock:
            if transfer_id in self._transfer_results:
                return self._transfer_results[transfer_id]
            task = self._transfer_tasks.get(transfer_id)

        if task is None:
            return self._error("transfer_not_found", f"Unknown transfer_id: {transfer_id}")
        if not task.done():
            return {"ok": True, "transfer_id": transfer_id, "status": "running"}

        with suppress(Exception):
            result = task.result()
        if "result" not in locals():
            result = self._error("transfer_failed", "Transfer task failed unexpectedly.")

        payload = {"ok": bool(result.get("ok", False)), "transfer_id": transfer_id, "status": "completed", "result": result}
        async with self._lock:
            self._transfer_results[transfer_id] = clean_data(payload)
            self._transfer_tasks.pop(transfer_id, None)
        return payload

    async def read_text_file(
        self,
        host: str,
        share: str,
        remote_path: str,
        username: Optional[str],
        password: Optional[str],
        ntlm_hash: Optional[str],
        domain: Optional[str],
        port: int,
        timeout: int,
        max_chars: int = 24000,
    ) -> Dict[str, Any]:
        download = await self.download_file(
            host=host,
            share=share,
            remote_path=remote_path,
            username=username,
            password=password,
            ntlm_hash=ntlm_hash,
            domain=domain,
            port=port,
            timeout=timeout,
        )
        if not download.get("ok"):
            return download

        local = Path(str(download.get("local_path", "")))
        try:
            text = local.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            return self._error("read_failed", str(exc))

        clean = self._redact_text(text)
        if len(clean) > max_chars:
            clean = clean[:max_chars] + "\n...[truncated]..."

        return clean_data({"ok": True, "remote_path": remote_path, "local_path": str(local), "content": clean})

    async def _run_argv(self, argv: Sequence[str], timeout: int) -> Dict[str, Any]:
        command_line = " ".join(shlex.quote(part) for part in argv)
        self._secure_subprocess.enforce_denylist(command_line)
        guardrail = validation.validate_command_guardrails(command_line)
        if guardrail:
            return self._error("guardrail_blocked", guardrail)

        clean_env, redaction_map = self._secure_subprocess.build_clean_environment()
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                cwd=str(self._workspace),
                env=clean_env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            return self._error("missing_dependency", "smbclient binary not found on PATH.")

        timed_out = False
        try:
            out, err = await asyncio.wait_for(process.communicate(), timeout=max(1, int(timeout)))
        except asyncio.TimeoutError:
            timed_out = True
            process.terminate()
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(process.wait(), timeout=1.5)
            if process.returncode is None:
                process.kill()
                await process.wait()
            out, err = b"", b"SMB command timed out"

        stdout = self._redact_text(self._secure_subprocess.redact_text(out.decode("utf-8", errors="replace"), redaction_map))
        stderr = self._redact_text(self._secure_subprocess.redact_text(err.decode("utf-8", errors="replace"), redaction_map))
        ok = (not timed_out) and (process.returncode == 0)
        payload = {
            "ok": ok,
            "exit_code": process.returncode,
            "timed_out": timed_out,
            "stdout": validation.sanitize_tool_output("smbclient", stdout),
            "stderr": validation.sanitize_tool_output("smbclient", stderr),
        }
        if not ok:
            payload["error"] = {"code": "smbclient_failed", "message": payload["stderr"] or "SMB command failed."}
        return clean_data(payload)

    def _write_auth_file(
        self,
        *,
        username: Optional[str],
        password: Optional[str],
        ntlm_hash: Optional[str],
        domain: Optional[str],
    ) -> str:
        user = (username or "guest").strip()
        secret = (ntlm_hash or password or "").strip()
        if any(ch in user for ch in "\r\n\x00"):
            raise ValueError("Invalid username")
        if any(ch in secret for ch in "\r\n\x00"):
            raise ValueError("Invalid credential")

        temp_dir = (self._workspace / ".cerberus" / "tmp").resolve()
        temp_dir.mkdir(parents=True, exist_ok=True)
        handle = tempfile.NamedTemporaryFile(prefix="smb_auth_", suffix=".conf", dir=str(temp_dir), delete=False, mode="w", encoding="utf-8")
        with handle:
            handle.write(f"username = {user}\n")
            handle.write(f"password = {secret}\n")
            if domain:
                handle.write(f"domain = {domain.strip()}\n")
        with suppress(Exception):
            os.chmod(handle.name, stat.S_IRUSR | stat.S_IWUSR)
        return handle.name

    @staticmethod
    def _remove_file(path: str) -> None:
        with suppress(Exception):
            os.remove(path)

    @staticmethod
    def _validate_host(host: str) -> Optional[str]:
        value = (host or "").strip()
        if not value:
            return "Host is required."
        if not validation.is_valid_host(value):
            return f"Invalid host '{value}'"
        return None

    def _validate_host_share(self, host: str, share: str) -> Optional[str]:
        host_err = self._validate_host(host)
        if host_err:
            return host_err
        share_value = (share or "").strip()
        if not share_value:
            return "Share is required."
        if any(ch in share_value for ch in ["\n", "\r", "\x00"]):
            return "Invalid share name."
        return None

    @staticmethod
    def _service_path(host: str, share: str) -> str:
        return f"//{host}/{share}"

    def _has_smbclient(self) -> bool:
        return bool(self._smbclient_path())

    @staticmethod
    def _smbclient_path() -> str:
        return shutil.which("smbclient") or ""

    def _parse_share_listing(self, raw: str) -> List[Dict[str, str]]:
        rows: List[Dict[str, str]] = []
        in_table = False
        for line in (raw or "").splitlines():
            text = line.strip()
            if not text:
                continue
            if text.lower().startswith("sharename"):
                in_table = True
                continue
            if not in_table:
                continue
            parts = text.split()
            if len(parts) < 2:
                continue
            name = parts[0]
            kind = parts[1]
            comment = " ".join(parts[2:]) if len(parts) > 2 else ""
            if name in {"Server", "Workgroup"}:
                continue
            rows.append({"share": name, "type": kind, "comment": comment})
        return rows

    def _parse_ls_output(self, raw: str, base: str) -> Dict[str, List[Dict[str, str]]]:
        files: List[Dict[str, str]] = []
        dirs: List[str] = []
        root = base.rstrip("/") or "."
        for line in (raw or "").splitlines():
            if not line.strip():
                continue
            if line.lstrip().startswith("."):
                continue
            stripped = line.strip()
            parts = stripped.split()
            if len(parts) < 2:
                continue
            type_token = parts[-4] if len(parts) >= 4 else ""
            name_parts = parts[:-4] if len(parts) >= 4 else parts[:-1]
            name = " ".join(name_parts).strip()
            if not name or name in {".", ".."}:
                continue
            full = f"{root}/{name}".replace("//", "/")
            is_dir = "D" in type_token.upper()
            files.append({"path": full, "type": "dir" if is_dir else "file"})
            if is_dir:
                dirs.append(full)
        return {"files": files, "dirs": dirs}

    def _forensic_file_name(self, *, host: str, share: str, remote_path: str) -> str:
        agent = self._agent_id()
        ts = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        leaf = Path(remote_path).name or "artifact.bin"
        safe_leaf = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in leaf)
        safe_host = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in host)
        safe_share = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in share)
        return f"SMB_{agent}_{ts}_{safe_host}_{safe_share}_{safe_leaf}"

    @staticmethod
    def _sha256_file(path: Path) -> str:
        if not path.exists() or not path.is_file():
            return ""
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _agent_id() -> str:
        for key in ("CERBERUS_AGENT_ID", "AGENT_ID", "CERBERUS_AGENT", "CERBERUS_AGENT_TYPE"):
            value = os.getenv(key, "").strip()
            if value:
                return "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in value)[:48]
        return "unknown-agent"

    @staticmethod
    def _escape_smb_token(value: str) -> str:
        return str(value).replace('"', '""')

    @staticmethod
    def _redact_text(value: str) -> str:
        text = value or ""
        patterns = [
            (r"(?i)(password\s*[=:]\s*)([^\s]+)", r"\1[REDACTED_SECRET]"),
            (r"(?i)(passwd\s*[=:]\s*)([^\s]+)", r"\1[REDACTED_SECRET]"),
            (r"(?i)(api[_-]?key\s*[=:]\s*)([^\s]+)", r"\1[REDACTED_SECRET]"),
            (r"(?i)(token\s*[=:]\s*)([^\s]+)", r"\1[REDACTED_SECRET]"),
            (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_PII]"),
        ]
        for pattern, repl in patterns:
            text = __import__("re").sub(pattern, repl, text)
        return text

    def _audit(self, event: str, data: Dict[str, Any]) -> None:
        payload = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "event": event,
            "agent_id": self._agent_id(),
            "data": clean_data(data),
        }
        self._audit_log.parent.mkdir(parents=True, exist_ok=True)
        with self._audit_log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=True) + "\n")

        if self._logger is not None:
            with suppress(Exception):
                self._logger.audit("SMB operation", actor="smbclient", data=payload, tags=["smb", event])

    @staticmethod
    def _error(code: str, message: str) -> Dict[str, Any]:
        return {"ok": False, "error": {"code": code, "message": message}}


SMB_TOOL = CerebroSMBClientTool()


async def run_smbclient(
    host: str,
    share: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    domain: Optional[str] = None,
    port: int = 445,
    commands: Optional[Union[str, List[str]]] = None,
    use_auth_file: bool = False,
    extra_args: Optional[List[str]] = None,
    timeout: int = 60,
) -> str:
    _ = use_auth_file
    result = await SMB_TOOL.run_smbclient(
        host=host,
        share=share,
        username=username,
        password=password,
        ntlm_hash=None,
        domain=domain,
        port=port,
        commands=commands,
        extra_args=extra_args,
        timeout=timeout,
    )
    if result.get("ok"):
        out = str(result.get("stdout", "")).strip()
        return out or "SMB command completed successfully"
    return str((result.get("error") or {}).get("message", "SMB command failed."))


async def list_shares(
    host: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    domain: Optional[str] = None,
    port: int = 445,
    use_auth_file: bool = False,
    timeout: int = 30,
) -> str:
    _ = use_auth_file
    result = await SMB_TOOL.list_shares(
        host=host,
        username=username,
        password=password,
        ntlm_hash=None,
        domain=domain,
        port=port,
        timeout=timeout,
    )
    if not result.get("ok"):
        return str((result.get("error") or {}).get("message", "Failed to list shares."))
    shares = result.get("shares", [])
    if not shares:
        return "No shares discovered."
    lines = [f"{row.get('share')}\t{row.get('type')}\t{row.get('comment', '')}" for row in shares]
    return "\n".join(lines)


async def download_file(
    host: str,
    share: str,
    remote_path: str,
    local_path: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    domain: Optional[str] = None,
    port: int = 445,
    use_auth_file: bool = False,
    timeout: int = 120,
) -> str:
    _ = (local_path, use_auth_file)
    result = await SMB_TOOL.download_file(
        host=host,
        share=share,
        remote_path=remote_path,
        username=username,
        password=password,
        ntlm_hash=None,
        domain=domain,
        port=port,
        timeout=timeout,
    )
    if not result.get("ok"):
        return str((result.get("error") or {}).get("message", "Download failed."))
    return json.dumps(clean_data(result), ensure_ascii=True)


__all__ = ["CerebroSMBClientTool", "SMB_TOOL", "run_smbclient", "list_shares", "download_file"]
