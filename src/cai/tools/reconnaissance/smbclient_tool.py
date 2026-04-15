"""Unified SMB courier for reconnaissance and controlled file operations."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import shutil
import stat
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Tuple

from pydantic import BaseModel, Field

from cai.memory.logic import clean_data
from cai.repl.commands.shell import SecureSubprocess
from cai.repl.ui.logging import get_cerebro_logger
from cai.sdk.agents import function_tool
from cai.tools.misc.cli_utils import CLI_UTILS
from cai.tools.validation import is_valid_host, sanitize_tool_output, validate_command_guardrails
from cai.tools.workspace import get_project_space


_MAX_RECURSION_DEPTH = 4
_MAX_TIMEOUT_SECONDS = 180
_MAX_LISTING_ENTRIES = 2000


class SMBShare(BaseModel):
    name: str
    share_type: str = ""
    comment: str = ""


class SMBFileEntry(BaseModel):
    path: str
    entry_type: str
    size_bytes: int = 0
    modified_hint: str = ""


class SMBTransferResult(BaseModel):
    ok: bool
    operation: str
    host: str
    share: str
    remote_path: str = ""
    local_path: str = ""
    sha256: str = ""
    size_bytes: int = 0
    stderr: str = ""
    error: Optional[Dict[str, Any]] = None


class CerebroSMB:
    """Single SMB controller for share listing and controlled file movement."""

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._loot_dir = (self._workspace / "loot" / "smb").resolve()
        self._tmp_dir = (self._workspace / ".cai" / "tmp").resolve()
        self._audit_log = (self._workspace / ".cai" / "audit" / "smb_courier.jsonl").resolve()
        self._secure = SecureSubprocess(workspace_root=self._workspace)
        self._logger = get_cerebro_logger()
        self._loot_dir.mkdir(parents=True, exist_ok=True)
        self._tmp_dir.mkdir(parents=True, exist_ok=True)
        self._audit_log.parent.mkdir(parents=True, exist_ok=True)

    async def list_shares(
        self,
        *,
        host: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        ntlm_hash: Optional[str] = None,
        domain: Optional[str] = None,
        port: int = 445,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        error = self._validate_host(host)
        if error:
            return self._error("invalid_host", error)
        binary = self._smbclient_path()
        if not binary:
            return self._error("missing_dependency", "smbclient binary not found on PATH")

        auth_path = self._write_credentials(username=username, password=password, ntlm_hash=ntlm_hash, domain=domain)
        argv = [binary, "-g", "-L", host.strip(), "-p", str(self._normalize_port(port)), "-A", str(auth_path)]
        if ntlm_hash:
            argv.append("--pw-nt-hash")

        result = await self._run(argv=argv, timeout=timeout, operation="list_shares", host=host, share="")
        self._remove_file(auth_path)
        if not result.get("ok"):
            return result

        shares = self._parse_share_listing(str(result.get("stdout", "")))
        payload = {"ok": True, "host": host.strip(), "shares": [share.model_dump() for share in shares]}
        await self._audit("list_shares", payload)
        return clean_data(payload)

    async def list_files(
        self,
        *,
        host: str,
        share: str,
        root_path: str = ".",
        username: Optional[str] = None,
        password: Optional[str] = None,
        ntlm_hash: Optional[str] = None,
        domain: Optional[str] = None,
        port: int = 445,
        timeout: int = 60,
        max_depth: int = _MAX_RECURSION_DEPTH,
    ) -> Dict[str, Any]:
        error = self._validate_host_share(host, share)
        if error:
            return self._error("invalid_target", error)
        binary = self._smbclient_path()
        if not binary:
            return self._error("missing_dependency", "smbclient binary not found on PATH")

        depth_limit = max(0, min(int(max_depth), _MAX_RECURSION_DEPTH))
        queue: List[Tuple[str, int]] = [(self._normalize_remote_path(root_path), 0)]
        seen: set[str] = set()
        entries: List[SMBFileEntry] = []

        while queue and len(entries) < _MAX_LISTING_ENTRIES:
            current, depth = queue.pop(0)
            if current in seen:
                continue
            seen.add(current)
            listed = await self._list_one_directory(
                host=host,
                share=share,
                directory=current,
                username=username,
                password=password,
                ntlm_hash=ntlm_hash,
                domain=domain,
                port=port,
                timeout=timeout,
            )
            if not listed.get("ok"):
                entries.append(SMBFileEntry(path=current, entry_type="error", modified_hint=(listed.get("error") or {}).get("message", "ls failed")))
                continue
            for item in listed.get("entries", []):
                entry = SMBFileEntry(**item)
                entries.append(entry)
                if entry.entry_type == "directory" and depth < depth_limit:
                    queue.append((entry.path, depth + 1))

        payload = {
            "ok": True,
            "host": host.strip(),
            "share": share.strip(),
            "root_path": self._normalize_remote_path(root_path),
            "max_depth": depth_limit,
            "entries": [entry.model_dump() for entry in entries[:_MAX_LISTING_ENTRIES]],
        }
        await self._audit("list_files", payload)
        return clean_data(payload)

    async def download_file(
        self,
        *,
        host: str,
        share: str,
        remote_path: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        ntlm_hash: Optional[str] = None,
        domain: Optional[str] = None,
        port: int = 445,
        timeout: int = 120,
    ) -> Dict[str, Any]:
        error = self._validate_host_share(host, share)
        if error:
            return self._error("invalid_target", error)
        remote_clean = self._normalize_remote_path(remote_path)
        if remote_clean in {"", "."}:
            return self._error("invalid_path", "remote_path is required")

        destination = self._loot_destination(host=host, share=share, remote_path=remote_clean)
        commands = [
            "prompt OFF",
            f'lcd "{self._smb_escape(str(destination.parent))}"',
            f'cd "{self._smb_escape(str(PurePosixPath(remote_clean).parent))}"' if str(PurePosixPath(remote_clean).parent) not in {"", "."} else "cd .",
            f'get "{self._smb_escape(PurePosixPath(remote_clean).name)}" "{self._smb_escape(destination.name)}"',
        ]
        run = await self._invoke_share_command(
            host=host,
            share=share,
            commands=commands,
            username=username,
            password=password,
            ntlm_hash=ntlm_hash,
            domain=domain,
            port=port,
            timeout=timeout,
            operation="download_file",
        )
        if not run.get("ok"):
            return run
        if not destination.exists():
            return self._error("download_missing", "smbclient reported success but no file was written to loot/smb")

        digest = self._sha256_file(destination)
        size_bytes = destination.stat().st_size
        metadata = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "host": host.strip(),
            "share": share.strip(),
            "remote_path": remote_clean,
            "local_path": str(destination),
            "sha256": digest,
            "size_bytes": size_bytes,
        }
        metadata_path = destination.with_suffix(destination.suffix + ".metadata.json")
        metadata_path.write_text(json.dumps(clean_data(metadata), ensure_ascii=True, indent=2), encoding="utf-8")

        payload = SMBTransferResult(
            ok=True,
            operation="download_file",
            host=host.strip(),
            share=share.strip(),
            remote_path=remote_clean,
            local_path=str(destination),
            sha256=digest,
            size_bytes=size_bytes,
            stderr=str(run.get("stderr", "")),
        )
        await self._audit("download_file", payload.model_dump())
        return clean_data(payload.model_dump() | {"metadata_path": str(metadata_path)})

    async def upload_file(
        self,
        *,
        host: str,
        share: str,
        local_path: str,
        remote_path: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        ntlm_hash: Optional[str] = None,
        domain: Optional[str] = None,
        port: int = 445,
        timeout: int = 120,
    ) -> Dict[str, Any]:
        error = self._validate_host_share(host, share)
        if error:
            return self._error("invalid_target", error)
        source = self._validate_local_source(local_path)
        if isinstance(source, str):
            return self._error("invalid_local_path", source)
        remote_clean = self._normalize_remote_path(remote_path)
        if remote_clean in {"", "."}:
            return self._error("invalid_path", "remote_path is required")

        parent = str(PurePosixPath(remote_clean).parent)
        name = PurePosixPath(remote_clean).name
        commands = [
            "prompt OFF",
            f'lcd "{self._smb_escape(str(source.parent))}"',
            f'cd "{self._smb_escape(parent)}"' if parent not in {"", "."} else "cd .",
            f'put "{self._smb_escape(source.name)}" "{self._smb_escape(name)}"',
        ]
        run = await self._invoke_share_command(
            host=host,
            share=share,
            commands=commands,
            username=username,
            password=password,
            ntlm_hash=ntlm_hash,
            domain=domain,
            port=port,
            timeout=timeout,
            operation="upload_file",
        )
        if not run.get("ok"):
            return run

        payload = SMBTransferResult(
            ok=True,
            operation="upload_file",
            host=host.strip(),
            share=share.strip(),
            remote_path=remote_clean,
            local_path=str(source),
            sha256=self._sha256_file(source),
            size_bytes=source.stat().st_size,
            stderr=str(run.get("stderr", "")),
        )
        await self._audit("upload_file", payload.model_dump())
        return clean_data(payload.model_dump())

    async def _list_one_directory(
        self,
        *,
        host: str,
        share: str,
        directory: str,
        username: Optional[str],
        password: Optional[str],
        ntlm_hash: Optional[str],
        domain: Optional[str],
        port: int,
        timeout: int,
    ) -> Dict[str, Any]:
        commands = [f'cd "{self._smb_escape(directory)}"' if directory not in {"", "."} else "cd .", "ls"]
        run = await self._invoke_share_command(
            host=host,
            share=share,
            commands=commands,
            username=username,
            password=password,
            ntlm_hash=ntlm_hash,
            domain=domain,
            port=port,
            timeout=timeout,
            operation="list_files",
        )
        if not run.get("ok"):
            return run
        parsed = self._parse_ls_output(base=directory, text=str(run.get("stdout", "")))
        return {"ok": True, "entries": [item.model_dump() for item in parsed]}

    async def _invoke_share_command(
        self,
        *,
        host: str,
        share: str,
        commands: Sequence[str],
        username: Optional[str],
        password: Optional[str],
        ntlm_hash: Optional[str],
        domain: Optional[str],
        port: int,
        timeout: int,
        operation: str,
    ) -> Dict[str, Any]:
        binary = self._smbclient_path()
        if not binary:
            return self._error("missing_dependency", "smbclient binary not found on PATH")

        auth_path = self._write_credentials(username=username, password=password, ntlm_hash=ntlm_hash, domain=domain)
        argv = [binary, f"//{host.strip()}/{share.strip()}", "-p", str(self._normalize_port(port)), "-A", str(auth_path)]
        if ntlm_hash:
            argv.append("--pw-nt-hash")
        argv.extend(["-c", "; ".join(commands)])

        result = await self._run(argv=argv, timeout=timeout, operation=operation, host=host, share=share)
        self._remove_file(auth_path)
        return result

    async def _run(self, *, argv: Sequence[str], timeout: int, operation: str, host: str, share: str) -> Dict[str, Any]:
        masked_command = self._masked_command(argv)
        guard = validate_command_guardrails(masked_command)
        if guard:
            return self._error("guardrail_blocked", guard)

        clean_env, redactions = self._secure.build_clean_environment()
        with CLI_UTILS.managed_env_context(base_env=clean_env) as runtime_env:
            try:
                process = await asyncio.create_subprocess_exec(
                    *argv,
                    cwd=str(self._workspace),
                    env=runtime_env,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError:
                return self._error("missing_dependency", "smbclient binary not found on PATH")

            timed_out = False
            try:
                out, err = await asyncio.wait_for(process.communicate(), timeout=max(1, min(int(timeout), _MAX_TIMEOUT_SECONDS)))
            except asyncio.TimeoutError:
                timed_out = True
                process.terminate()
                with suppress(Exception):
                    await asyncio.wait_for(process.wait(), timeout=2.0)
                if process.returncode is None:
                    process.kill()
                    await process.wait()
                out, err = b"", b"SMB operation timed out by policy"

        stdout = sanitize_tool_output(operation, self._secure.redact_text(out.decode("utf-8", errors="replace"), redactions))
        stderr = sanitize_tool_output(operation, self._secure.redact_text(err.decode("utf-8", errors="replace"), redactions))
        ok = (not timed_out) and (process.returncode == 0)
        payload: Dict[str, Any] = {
            "ok": ok,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": process.returncode,
            "timed_out": timed_out,
            "command_masked": masked_command,
        }
        if not ok:
            payload["error"] = {
                "code": "smbclient_failed" if not timed_out else "timeout",
                "message": stderr or "SMB operation failed",
            }
        await self._audit("command", {"operation": operation, "host": host.strip(), "share": share.strip(), "ok": ok, "timed_out": timed_out, "command": masked_command})
        return clean_data(payload)

    def _parse_share_listing(self, text: str) -> List[SMBShare]:
        shares: List[SMBShare] = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line or not line.startswith(("Disk|", "IPC|", "Printer|")):
                continue
            parts = [part.strip() for part in line.split("|")]
            if len(parts) < 2:
                continue
            shares.append(SMBShare(share_type=parts[0], name=parts[1], comment=parts[2] if len(parts) > 2 else ""))
        return shares

    def _parse_ls_output(self, *, base: str, text: str) -> List[SMBFileEntry]:
        out: List[SMBFileEntry] = []
        base_path = PurePosixPath(self._normalize_remote_path(base))
        for raw in text.splitlines():
            line = raw.rstrip()
            if not line.strip() or line.lstrip().startswith((".", "..")):
                continue
            if "blocks available" in line.lower():
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            entry_type = "directory" if "D" in parts[1] else "file"
            size_bytes = 0
            modified_hint = ""
            for token in parts[2:]:
                if token.isdigit():
                    size_bytes = int(token)
                    break
            if len(parts) > 4:
                modified_hint = " ".join(parts[-4:])
            name_tokens = parts[:-5] if len(parts) > 5 else parts[:-1]
            name = " ".join(name_tokens).strip()
            if not name or name in {".", ".."}:
                continue
            candidate = str((base_path / name).as_posix()).lstrip("./") or name
            out.append(SMBFileEntry(path=candidate, entry_type=entry_type, size_bytes=size_bytes, modified_hint=modified_hint))
        return out

    def _write_credentials(
        self,
        *,
        username: Optional[str],
        password: Optional[str],
        ntlm_hash: Optional[str],
        domain: Optional[str],
    ) -> Path:
        user = (username or "guest").strip()
        secret = (ntlm_hash or password or "").strip()
        if any(ch in user for ch in "\r\n\x00") or any(ch in secret for ch in "\r\n\x00"):
            raise ValueError("Invalid credential characters")
        fd, temp_path = tempfile.mkstemp(prefix="smb_auth_", suffix=".conf", dir=str(self._tmp_dir), text=True)
        os.close(fd)
        auth_path = Path(temp_path)
        lines = [f"username = {user}", f"password = {secret}"]
        if domain and domain.strip():
            lines.append(f"domain = {domain.strip()}")
        auth_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with suppress(Exception):
            auth_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        return auth_path

    def _validate_local_source(self, local_path: str) -> Path | str:
        raw = Path((local_path or "").strip()).expanduser()
        if not str(raw):
            return "local_path is required"
        resolved = raw.resolve() if raw.is_absolute() else (self._workspace / raw).resolve()
        allowed_roots = [self._workspace, Path(tempfile.gettempdir()).resolve(), Path("/var/tmp").resolve()]
        if not any(self._is_within(root, resolved) for root in allowed_roots):
            return "local_path must stay inside workspace or approved temp directories"
        if not resolved.exists() or not resolved.is_file():
            return "local_path must point to an existing file"
        return resolved

    def _loot_destination(self, *, host: str, share: str, remote_path: str) -> Path:
        stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        remote_name = PurePosixPath(remote_path).name or "download.bin"
        safe_name = self._safe_name(f"{host}_{share}_{stamp}_{remote_name}")
        return (self._loot_dir / safe_name).resolve()

    @staticmethod
    def _safe_name(text: str) -> str:
        out = []
        for ch in text:
            out.append(ch if ch.isalnum() or ch in {".", "_", "-"} else "_")
        return "".join(out)[:180] or "smb_object"

    @staticmethod
    def _normalize_remote_path(value: str) -> str:
        clean = str(PurePosixPath((value or ".").replace("\\", "/"))).strip()
        return "." if clean in {"", "/"} else clean.lstrip("/")

    @staticmethod
    def _normalize_port(port: int) -> int:
        try:
            port_num = int(port)
        except Exception:
            return 445
        return port_num if 1 <= port_num <= 65535 else 445

    @staticmethod
    def _validate_host(host: str) -> Optional[str]:
        token = (host or "").strip()
        if not token:
            return "host is required"
        if not is_valid_host(token):
            return f"invalid SMB host: {host!r}"
        return None

    def _validate_host_share(self, host: str, share: str) -> Optional[str]:
        host_error = self._validate_host(host)
        if host_error:
            return host_error
        share_name = (share or "").strip().strip("/")
        if not share_name or any(ch in share_name for ch in "\\\r\n\x00"):
            return "share is required and must not contain path separators or control characters"
        return None

    @staticmethod
    def _smb_escape(value: str) -> str:
        return str(value).replace('"', '\\"')

    @staticmethod
    def _is_within(root: Path, candidate: Path) -> bool:
        try:
            candidate.relative_to(root)
            return True
        except ValueError:
            return False

    @staticmethod
    def _remove_file(path: Path) -> None:
        with suppress(Exception):
            path.unlink(missing_ok=True)

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _masked_command(self, argv: Sequence[str]) -> str:
        masked: List[str] = []
        skip_next = False
        for token in argv:
            if skip_next:
                masked.append("[REDACTED_AUTH_FILE]")
                skip_next = False
                continue
            if token == "-A":
                masked.append(token)
                skip_next = True
                continue
            masked.append(shlex.quote(str(token)))
        return " ".join(masked)

    async def _audit(self, event: str, payload: Dict[str, Any]) -> None:
        row = {"timestamp": datetime.now(tz=UTC).isoformat(), "event": event, "data": clean_data(payload)}
        line = json.dumps(row, ensure_ascii=True) + "\n"

        def _append() -> None:
            self._audit_log.parent.mkdir(parents=True, exist_ok=True)
            with self._audit_log.open("a", encoding="utf-8") as handle:
                handle.write(line)

        await asyncio.to_thread(_append)
        if self._logger is not None:
            with suppress(Exception):
                self._logger.audit("smb courier event", actor="smbclient", data=clean_data(row), tags=["smb", event])

    @staticmethod
    def _error(code: str, message: str) -> Dict[str, Any]:
        return {"ok": False, "error": {"code": code, "message": message}}

    @staticmethod
    def _smbclient_path() -> str:
        return shutil.which("smbclient") or ""


SMB_COURIER = CerebroSMB()


@function_tool
async def smb_list_shares(
    host: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    domain: Optional[str] = None,
    port: int = 445,
    use_auth_file: bool = False,
    timeout: int = 30,
    ntlm_hash: Optional[str] = None,
) -> Dict[str, Any]:
    _ = use_auth_file
    return await SMB_COURIER.list_shares(
        host=host,
        username=username,
        password=password,
        ntlm_hash=ntlm_hash,
        domain=domain,
        port=port,
        timeout=timeout,
    )


@function_tool
async def smb_run_smbclient(
    host: str,
    share: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    domain: Optional[str] = None,
    port: int = 445,
    commands: Optional[str] = None,
    use_auth_file: bool = False,
    extra_args: Optional[List[str]] = None,
    timeout: int = 60,
    ntlm_hash: Optional[str] = None,
) -> Dict[str, Any]:
    _ = (use_auth_file, extra_args)
    command_text = (commands or "").strip()
    if not command_text or command_text.lower() in {"ls", "dir", "list", "list_files"}:
        return await SMB_COURIER.list_files(
            host=host,
            share=share,
            root_path=".",
            username=username,
            password=password,
            ntlm_hash=ntlm_hash,
            domain=domain,
            port=port,
            timeout=timeout,
        )

    lowered = command_text.lower()
    if lowered.startswith("list_files"):
        suffix = command_text[len("list_files"):].strip() or "."
        return await SMB_COURIER.list_files(
            host=host,
            share=share,
            root_path=suffix,
            username=username,
            password=password,
            ntlm_hash=ntlm_hash,
            domain=domain,
            port=port,
            timeout=timeout,
        )
    if lowered.startswith("get ") or lowered.startswith("download "):
        parts = command_text.split(maxsplit=1)
        remote_path = parts[1].strip() if len(parts) > 1 else ""
        return await SMB_COURIER.download_file(
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
    if lowered.startswith("put ") or lowered.startswith("upload "):
        parts = command_text.split(maxsplit=2)
        if len(parts) < 3:
            return {"ok": False, "error": {"code": "invalid_command", "message": "upload/put requires local_path and remote_path"}}
        return await SMB_COURIER.upload_file(
            host=host,
            share=share,
            local_path=parts[1],
            remote_path=parts[2],
            username=username,
            password=password,
            ntlm_hash=ntlm_hash,
            domain=domain,
            port=port,
            timeout=timeout,
        )
    return {"ok": False, "error": {"code": "unsupported_command", "message": "Supported actions: list_files [path], get <remote_path>, put <local_path> <remote_path>"}}


@function_tool
async def smb_download_file(
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
    ntlm_hash: Optional[str] = None,
) -> Dict[str, Any]:
    _ = (local_path, use_auth_file)
    return await SMB_COURIER.download_file(
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


@function_tool
async def smb_upload_file(
    host: str,
    share: str,
    local_path: str,
    remote_path: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    domain: Optional[str] = None,
    port: int = 445,
    timeout: int = 120,
    ntlm_hash: Optional[str] = None,
) -> Dict[str, Any]:
    return await SMB_COURIER.upload_file(
        host=host,
        share=share,
        local_path=local_path,
        remote_path=remote_path,
        username=username,
        password=password,
        ntlm_hash=ntlm_hash,
        domain=domain,
        port=port,
        timeout=timeout,
    )


@function_tool
async def smb_list_files(
    host: str,
    share: str,
    root_path: str = ".",
    username: Optional[str] = None,
    password: Optional[str] = None,
    domain: Optional[str] = None,
    port: int = 445,
    timeout: int = 60,
    max_depth: int = _MAX_RECURSION_DEPTH,
    ntlm_hash: Optional[str] = None,
) -> Dict[str, Any]:
    return await SMB_COURIER.list_files(
        host=host,
        share=share,
        root_path=root_path,
        username=username,
        password=password,
        ntlm_hash=ntlm_hash,
        domain=domain,
        port=port,
        timeout=timeout,
        max_depth=max_depth,
    )


__all__ = [
    "CerebroSMB",
    "SMB_COURIER",
    "smb_list_shares",
    "smb_run_smbclient",
    "smb_download_file",
    "smb_upload_file",
    "smb_list_files",
]
