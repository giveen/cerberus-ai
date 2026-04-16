"""Governed resource retrieval engine for controlled wget downloads and mirroring."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import threading
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from cerberus.memory.logic import clean_data
from cerberus.repl.commands.shell import SecureSubprocess
from cerberus.repl.ui.logging import get_cerberus_logger
from cerberus.agents import function_tool
from cerberus.tools._lazy import LazyToolProxy
from cerberus.tools.misc.cli_utils import CLI_UTILS
from cerberus.tools.validation import sanitize_tool_output, validate_command_guardrails
from cerberus.tools.workspace import get_project_space
from cerberus.utils.process_handler import StreamingContext, capture_streaming_context, run_streaming_subprocess


_ALLOWED_SCHEMES = {"http", "https", "ftp"}
_MAX_TIMEOUT_SECONDS = 3600
_DEFAULT_SIZE_LIMIT_MB = 250
_DEFAULT_MAX_FILES = 250
_DEFAULT_MAX_DEPTH = 2
_MAX_EXTRA_ARGS = 40
_PERCENT_RE = re.compile(r"(\d{1,3})%")
_SPEED_RE = re.compile(r"(\d+(?:\.\d+)?\s*[KMG]?B/s)", re.IGNORECASE)
_SAFE_FLAG_VALUES = {
    "--limit-rate",
    "--header",
    "--timeout",
    "--tries",
    "--wait",
    "--read-timeout",
    "--dns-timeout",
    "--connect-timeout",
}
_SAFE_STANDALONE_FLAGS = {
    "--no-check-certificate",
    "--continue",
    "--timestamping",
    "--no-clobber",
    "--no-verbose",
    "--quiet",
    "--compression=auto",
}
_BLOCKED_FLAGS = {
    "-O",
    "--output-document",
    "-P",
    "--directory-prefix",
    "--input-file",
    "-i",
    "--execute",
    "-e",
    "--post-file",
    "--body-file",
}
_USER_AGENTS = ["Cerberus-AI"]


class DownloadArtifact(BaseModel):
    relative_path: str
    source_url: str
    sha256: str
    size_bytes: int
    timestamp: str


class WgetJobResult(BaseModel):
    ok: bool
    job_id: str
    url: str
    status: str
    progress_percentage: float = 0.0
    speed: str = ""
    downloaded_bytes: int = 0
    file_count: int = 0
    size_limit_mb: int = _DEFAULT_SIZE_LIMIT_MB
    max_files: int = _DEFAULT_MAX_FILES
    max_depth: int = _DEFAULT_MAX_DEPTH
    domain_lock: bool = True
    evidence_dir: str = ""
    artifacts: List[DownloadArtifact] = Field(default_factory=list)
    error: Optional[Dict[str, Any]] = None
    status_updates: List[str] = Field(default_factory=list)


@dataclass
class _JobState:
    url: str
    work_dir: Path
    started_at: str
    status: str = "queued"
    progress_percentage: float = 0.0
    speed: str = ""
    downloaded_bytes: int = 0
    file_count: int = 0
    status_updates: List[str] = None  # type: ignore[assignment]
    process: Optional[asyncio.subprocess.Process] = None
    artifacts: List[DownloadArtifact] = None  # type: ignore[assignment]
    error: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        if self.status_updates is None:
            self.status_updates = ["Queued"]
        if self.artifacts is None:
            self.artifacts = []


class CerebroWgetTool:
    """Asynchronous wget controller with workspace siloing and kill-switch guardrails."""

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._downloads_root = (self._workspace / "evidence" / "downloads").resolve()
        self._audit_log = (self._workspace / ".cerberus" / "audit" / "wget_downloads.jsonl").resolve()
        self._secure = SecureSubprocess(workspace_root=self._workspace)
        self._logger = get_cerberus_logger()
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._jobs: Dict[str, _JobState] = {}
        self._downloads_root.mkdir(parents=True, exist_ok=True)
        self._audit_log.parent.mkdir(parents=True, exist_ok=True)

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _run_coro(self, coro: Any, timeout: float = 120.0) -> Dict[str, Any]:
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=timeout)

    def start_download(
        self,
        *,
        url: str,
        timeout: int = 300,
        recursive: bool = False,
        max_depth: int = _DEFAULT_MAX_DEPTH,
        max_files: int = _DEFAULT_MAX_FILES,
        size_limit_mb: int = _DEFAULT_SIZE_LIMIT_MB,
        domain_lock: bool = True,
        authorized_domains: Optional[Sequence[str]] = None,
        extra_args: str = "",
        user_agent_profile: str = "rotate",
    ) -> Dict[str, Any]:
        parsed_or_error = self._validate_url(url)
        if isinstance(parsed_or_error, str):
            return self._error("invalid_url", parsed_or_error)
        if not shutil.which("wget"):
            return self._error("missing_dependency", "wget binary not found on PATH")
        tokens_or_error = self._parse_extra_args(extra_args)
        if isinstance(tokens_or_error, str):
            return self._error("invalid_args", tokens_or_error)

        stream_context = capture_streaming_context()

        parsed = parsed_or_error
        host = parsed.hostname or "target"
        job_id = f"wget-{datetime.now(tz=UTC).strftime('%Y%m%d%H%M%S')}-{len(self._jobs)+1}"
        work_dir = (self._downloads_root / self._safe_name(f"{host}_{job_id}")).resolve()
        work_dir.mkdir(parents=True, exist_ok=True)
        state = _JobState(url=url, work_dir=work_dir, started_at=datetime.now(tz=UTC).isoformat())
        self._jobs[job_id] = state

        asyncio.run_coroutine_threadsafe(
            self._download_async(
                job_id=job_id,
                parsed=parsed,
                timeout=max(5, min(int(timeout), _MAX_TIMEOUT_SECONDS)),
                recursive=recursive,
                max_depth=max_depth,
                max_files=max_files,
                size_limit_mb=size_limit_mb,
                domain_lock=domain_lock,
                authorized_domains=list(authorized_domains or []),
                extra_tokens=list(tokens_or_error),
                user_agent_profile=user_agent_profile,
                stream_context=stream_context,
            ),
            self._loop,
        )
        return clean_data({"ok": True, "job_id": job_id, "status": "queued", "evidence_dir": self._display_path(work_dir)})

    def job_status(self, job_id: str) -> Dict[str, Any]:
        state = self._jobs.get((job_id or "").strip())
        if state is None:
            return self._error("unknown_job", f"Unknown wget job id: {job_id}")
        return clean_data(
            WgetJobResult(
                ok=state.error is None and state.status not in {"failed", "killed"},
                job_id=job_id,
                url=state.url,
                status=state.status,
                progress_percentage=round(state.progress_percentage, 2),
                speed=state.speed,
                downloaded_bytes=state.downloaded_bytes,
                file_count=state.file_count,
                evidence_dir=self._display_path(state.work_dir),
                artifacts=state.artifacts,
                error=state.error,
                status_updates=state.status_updates[-20:],
            ).model_dump()
        )

    async def _download_async(
        self,
        *,
        job_id: str,
        parsed: Any,
        timeout: int,
        recursive: bool,
        max_depth: int,
        max_files: int,
        size_limit_mb: int,
        domain_lock: bool,
        authorized_domains: Sequence[str],
        extra_tokens: Sequence[str],
        user_agent_profile: str,
        stream_context: StreamingContext,
    ) -> None:
        state = self._jobs[job_id]
        state.status = "running"
        state.status_updates.append("Download started")
        clean_env, redactions = self._secure.build_clean_environment()
        user_agent = self._select_user_agent(user_agent_profile)
        argv = self._build_argv(
            url=parsed.geturl(),
            host=parsed.hostname or "",
            out_dir=state.work_dir,
            recursive=recursive,
            max_depth=max_depth,
            max_files=max_files,
            domain_lock=domain_lock,
            authorized_domains=authorized_domains,
            extra_tokens=extra_tokens,
            user_agent=user_agent,
        )
        guard = validate_command_guardrails(self._masked_command(argv))
        if guard:
            state.status = "failed"
            state.error = {"code": "guardrail_blocked", "message": guard}
            return

        with CLI_UTILS.managed_env_context(base_env=clean_env) as runtime_env:
            stderr_lines: List[str] = []

            def _redact_stream(text: str) -> str:
                return self._secure.redact_text(text, redactions)

            def _on_process_started(process: asyncio.subprocess.Process) -> None:
                state.process = process

            async def _on_stderr(text: str) -> None:
                stripped = text.strip()
                if stripped:
                    stderr_lines.append(stripped)
                self._update_progress_from_line(state, stripped)

            watchdog_task = asyncio.create_task(self._watch_job(state, size_limit_mb=size_limit_mb, max_files=max_files))
            try:
                result = await run_streaming_subprocess(
                    argv=argv,
                    cwd=self._workspace,
                    env=runtime_env,
                    timeout_seconds=timeout,
                    redactor=_redact_stream,
                    event_callback=stream_context.callback,
                    stderr_callback=_on_stderr,
                    session_id=stream_context.session_id,
                    emit_stdout=False,
                    emit_stderr=True,
                    started_callback=_on_process_started,
                    timeout_message="Download exceeded timeout policy",
                )
            finally:
                watchdog_task.cancel()
                await asyncio.gather(watchdog_task, return_exceptions=True)

        state.process = None
        state.progress_percentage = 100.0 if result.exit_code == 0 and not result.timed_out and state.error is None else state.progress_percentage
        state.downloaded_bytes, state.file_count = self._measure_tree(state.work_dir)
        if result.exit_code == 0 and state.error is None:
            artifacts = await self._finalize_artifacts(state, source_url=parsed.geturl())
            state.artifacts = artifacts
            state.status = "completed"
            state.status_updates.append(f"Completed with {len(artifacts)} files")
            await self._audit_summary(job_id=job_id, state=state, command=self._masked_command(argv), ok=True, error="")
        elif state.error is None:
            if result.timed_out:
                state.status = "killed"
                state.error = {"code": "timeout", "message": "Download exceeded timeout policy"}
                await self._audit_summary(job_id=job_id, state=state, command=self._masked_command(argv), ok=False, error=state.error["message"])
                return
            sem = self._translate_wget_error("\n".join(stderr_lines), result.exit_code)
            state.status = "failed"
            state.error = {"code": sem[0], "message": sem[1]}
            await self._audit_summary(job_id=job_id, state=state, command=self._masked_command(argv), ok=False, error=sem[1])
        else:
            await self._audit_summary(job_id=job_id, state=state, command=self._masked_command(argv), ok=False, error=state.error.get("message", ""))

    async def _watch_job(self, state: _JobState, *, size_limit_mb: int, max_files: int) -> None:
        while True:
            await asyncio.sleep(1.0)
            bytes_total, file_count = self._measure_tree(state.work_dir)
            state.downloaded_bytes = bytes_total
            state.file_count = file_count
            if bytes_total > max(1, int(size_limit_mb)) * 1024 * 1024:
                state.status = "killed"
                state.error = {"code": "size_limit_exceeded", "message": "Download exceeded size limit kill-switch"}
                state.status_updates.append("Killed by size limit")
                if state.process and state.process.returncode is None:
                    state.process.terminate()
                return
            if file_count > max(1, int(max_files)):
                state.status = "killed"
                state.error = {"code": "file_limit_exceeded", "message": "Download exceeded max files kill-switch"}
                state.status_updates.append("Killed by file-count limit")
                if state.process and state.process.returncode is None:
                    state.process.terminate()
                return

    async def _finalize_artifacts(self, state: _JobState, *, source_url: str) -> List[DownloadArtifact]:
        artifacts: List[DownloadArtifact] = []

        def _rename_and_hash() -> List[DownloadArtifact]:
            found: List[DownloadArtifact] = []
            for path in sorted(state.work_dir.rglob("*")):
                if not path.is_file():
                    continue
                sanitized = self._sanitize_filename(path.name)
                if sanitized != path.name:
                    target = path.with_name(self._dedupe_name(path.parent, sanitized))
                    path.rename(target)
                    path = target
                digest = self._sha256_file(path)
                rel = self._display_path(path)
                found.append(
                    DownloadArtifact(
                        relative_path=rel,
                        source_url=source_url,
                        sha256=digest,
                        size_bytes=path.stat().st_size,
                        timestamp=datetime.now(tz=UTC).isoformat(),
                    )
                )
            return found

        artifacts = await asyncio.to_thread(_rename_and_hash)
        for artifact in artifacts:
            await self._audit_file(artifact)
        return artifacts

    async def _wait_for_completion(self, *, job_id: str, timeout: int) -> Dict[str, Any]:
        started = asyncio.get_running_loop().time()
        while True:
            payload = self.job_status(job_id)
            if payload.get("status") in {"completed", "failed", "killed"}:
                return payload
            if (asyncio.get_running_loop().time() - started) > float(timeout):
                return {"ok": False, "error": {"code": "status_timeout", "message": "Timed out waiting for wget job completion"}}
            await asyncio.sleep(0.5)

    @staticmethod
    def _build_argv(
        *,
        url: str,
        host: str,
        out_dir: Path,
        recursive: bool,
        max_depth: int,
        max_files: int,
        domain_lock: bool,
        authorized_domains: Sequence[str],
        extra_tokens: Sequence[str],
        user_agent: str,
    ) -> List[str]:
        argv = [
            shutil.which("wget") or "wget",
            "--user-agent",
            user_agent,
            "--directory-prefix",
            str(out_dir),
            "--no-host-directories",
            "--progress=bar:force:noscroll",
            "--show-progress",
            "--server-response",
        ]
        if recursive:
            argv.extend(["--recursive", "--level", str(max(0, int(max_depth))), "--no-parent"])
            if domain_lock:
                domains = [host, *[d for d in authorized_domains if d and d != host]]
                argv.extend(["--domains", ",".join(domains)])
                if len(domains) > 1:
                    argv.append("--span-hosts")
            argv.extend(["--accept-regex", r".*"])
        argv.extend(extra_tokens)
        argv.append(url)
        return argv

    @staticmethod
    def _validate_url(url: str) -> Any:
        raw = (url or "").strip()
        if not raw:
            return "url is required"
        parsed = urlparse(raw)
        if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
            return f"URL scheme must be one of: {', '.join(sorted(_ALLOWED_SCHEMES))}"
        if not parsed.netloc:
            return "URL must include a hostname"
        return parsed

    @staticmethod
    def _parse_extra_args(extra_args: str) -> Sequence[str] | str:
        raw = (extra_args or "").strip()
        if not raw:
            return []
        try:
            tokens = shlex.split(raw, posix=True)
        except ValueError as exc:
            return f"unable to parse args: {exc}"
        if len(tokens) > _MAX_EXTRA_ARGS:
            return f"too many extra args (max {_MAX_EXTRA_ARGS})"
        out: List[str] = []
        i = 0
        while i < len(tokens):
            token = tokens[i]
            lower = token.lower()
            if lower in _BLOCKED_FLAGS or any(lower.startswith(flag + "=") for flag in _BLOCKED_FLAGS):
                return f"flag not allowed: {token}"
            if lower in _SAFE_STANDALONE_FLAGS:
                out.append(token)
                i += 1
                continue
            if lower in _SAFE_FLAG_VALUES:
                if i + 1 >= len(tokens):
                    return f"missing value for flag: {token}"
                out.extend([token, tokens[i + 1]])
                i += 2
                continue
            if any(lower.startswith(flag + "=") for flag in _SAFE_FLAG_VALUES):
                out.append(token)
                i += 1
                continue
            return f"unsupported wget arg: {token}"
        return out

    @staticmethod
    def _select_user_agent(profile: str) -> str:
        _ = profile
        return _USER_AGENTS[0]

    def _update_progress_from_line(self, state: _JobState, line: str) -> None:
        if not line:
            return
        percent = _PERCENT_RE.search(line)
        speed = _SPEED_RE.search(line)
        if percent:
            state.progress_percentage = max(state.progress_percentage, min(100.0, float(percent.group(1))))
        if speed:
            state.speed = speed.group(1).replace(" ", "")
        if percent or speed:
            update = f"{state.progress_percentage:.1f}%"
            if state.speed:
                update += f" at {state.speed}"
            if not state.status_updates or state.status_updates[-1] != update:
                state.status_updates.append(update)

    @staticmethod
    def _measure_tree(root: Path) -> Tuple[int, int]:
        total = 0
        count = 0
        for path in root.rglob("*"):
            if path.is_file():
                count += 1
                with suppress(Exception):
                    total += path.stat().st_size
        return total, count

    @staticmethod
    def _sanitize_filename(name: str) -> str:
        safe = []
        for char in name:
            safe.append(char if char.isalnum() or char in {".", "_", "-"} else "_")
        cleaned = "".join(safe).strip("._")
        return cleaned[:180] or "download.bin"

    @staticmethod
    def _dedupe_name(parent: Path, name: str) -> str:
        candidate = name
        stem = Path(name).stem
        suffix = Path(name).suffix
        index = 1
        while (parent / candidate).exists():
            candidate = f"{stem}_{index}{suffix}"
            index += 1
        return candidate

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _translate_wget_error(stderr: str, exit_code: Optional[int]) -> Tuple[str, str]:
        text = (stderr or "").lower()
        if "404 not found" in text:
            return ("not_found", "Remote resource returned 404 Not Found")
        if "403 forbidden" in text:
            return ("forbidden", "Remote resource returned 403 Forbidden")
        if "connection refused" in text:
            return ("connection_refused", "Remote host refused the connection")
        if "unable to resolve host" in text or "name or service not known" in text:
            return ("dns_failure", "Unable to resolve remote hostname")
        if exit_code == 8:
            return ("server_error", "Server issued an error response during wget retrieval")
        return ("wget_failed", sanitize_tool_output("wget", stderr or f"wget exited with code {exit_code}"))

    async def _audit_file(self, artifact: DownloadArtifact) -> None:
        payload = {"event": "file_downloaded", **artifact.model_dump()}
        await self._append_audit(payload)

    async def _audit_summary(self, *, job_id: str, state: _JobState, command: str, ok: bool, error: str) -> None:
        payload = {
            "event": "job_summary",
            "job_id": job_id,
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "url": state.url,
            "status": state.status,
            "command": command,
            "ok": ok,
            "downloaded_bytes": state.downloaded_bytes,
            "file_count": state.file_count,
            "error": error[:1000],
        }
        await self._append_audit(payload)

    async def _append_audit(self, payload: Dict[str, Any]) -> None:
        line = json.dumps(clean_data(payload), ensure_ascii=True) + "\n"

        def _write() -> None:
            self._audit_log.parent.mkdir(parents=True, exist_ok=True)
            with self._audit_log.open("a", encoding="utf-8") as handle:
                handle.write(line)

        await asyncio.to_thread(_write)
        if self._logger is not None:
            with suppress(Exception):
                self._logger.audit("wget event", actor="wget", data=clean_data(payload), tags=["wget", payload.get("event", "audit")])

    def _masked_command(self, argv: Sequence[str]) -> str:
        return " ".join(shlex.quote(str(x)) for x in argv)

    def _display_path(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self._workspace))
        except ValueError:
            return str(path.resolve())

    @staticmethod
    def _safe_name(text: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_")
        return cleaned[:120] or "wget_job"

    @staticmethod
    def _error(code: str, message: str) -> Dict[str, Any]:
        return {"ok": False, "error": {"code": code, "message": message}}


WGET_TOOL = LazyToolProxy(CerebroWgetTool)


@function_tool
def wget(
    url: str,
    args: str = "",
    timeout: int = 60,
    recursive: bool = False,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    max_files: int = _DEFAULT_MAX_FILES,
    size_limit_mb: int = _DEFAULT_SIZE_LIMIT_MB,
    domain_lock: bool = True,
    wait: bool = False,
) -> Dict[str, Any]:
    started = WGET_TOOL.start_download(
        url=url,
        timeout=timeout,
        recursive=recursive,
        max_depth=max_depth,
        max_files=max_files,
        size_limit_mb=size_limit_mb,
        domain_lock=domain_lock,
        extra_args=args,
    )
    if not wait or not started.get("ok"):
        return started
    job_id = str(started.get("job_id", ""))
    return WGET_TOOL._run_coro(WGET_TOOL._wait_for_completion(job_id=job_id, timeout=max(30, int(timeout)) + 30), timeout=max(60.0, float(timeout) + 45.0))


@function_tool
def wget_status(job_id: str) -> Dict[str, Any]:
    return WGET_TOOL.job_status(job_id)


__all__ = ["CerebroWgetTool", "WGET_TOOL", "wget", "wget_status"]
