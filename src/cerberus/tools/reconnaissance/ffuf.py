"""Managed ffuf discovery engine with triage, calibration, and forensic evidence capture."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import re
import secrets
import shutil
import time
from typing import Any, Dict, List, Optional, Sequence, Union
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from cerberus.memory.logic import clean_data
from cerberus.repl.commands.config import CONFIG_STORE
from cerberus.repl.commands.shell import SecureSubprocess
from cerberus.repl.ui.logging import get_cerberus_logger
from cerberus.tools._lazy import LazyToolProxy
from cerberus.tools.misc.cli_utils import CLI_UTILS
from cerberus.tools.validation import sanitize_tool_output, validate_command_guardrails
from cerberus.tools.workspace import get_project_space
from cerberus.utils.process_handler import StreamingContext, capture_streaming_context, run_streaming_subprocess


_ALLOWED_METHODS = {"GET", "POST", "HEAD"}
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_INTERESTING_EXTENSIONS = {".git", ".env", ".bak", ".zip", ".tar", ".gz", ".sql", ".old", ".config", ".yml", ".yaml"}
_PROGRESS_RE = re.compile(r"(\d{1,9})\/(\d{1,9})")
_SENSITIVE_HEADER_RE = re.compile(r"(?i)^(authorization|cookie|proxy-authorization|x-api-key|x-auth-token)\s*:")


@dataclass
class FfufFinding:
    url: str
    status: int
    length: int
    words: int
    lines: int
    content_type: str = ""
    interesting_score: int = 0


@dataclass
class FfufJob:
    job_id: str
    target_url: str
    method: str
    wordlist_path: str
    started_at: str
    raw_json_path: str
    stderr_log_path: str
    status: str = "queued"
    process: Optional[asyncio.subprocess.Process] = None
    total_candidates: int = 0
    progress_percentage: float = 0.0
    current_hits: int = 0
    stderr_tail: List[str] = field(default_factory=list)
    baseline_status: int = 0
    baseline_length: int = 0
    summary: Optional[Dict[str, Any]] = None
    return_code: Optional[int] = None


class CerebroFfufTool:
    """Asynchronous ffuf runner with result triage and workspace evidence capture."""

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._wordlists_dir = (self._workspace / "config" / "wordlists").resolve()
        self._evidence_dir = (self._workspace / "evidence" / "discovery" / "ffuf").resolve()
        self._audit_log = (self._workspace / ".cerberus" / "audit" / "ffuf_jobs.jsonl").resolve()
        self._wordlists_dir.mkdir(parents=True, exist_ok=True)
        self._evidence_dir.mkdir(parents=True, exist_ok=True)

        self._secure_subprocess = SecureSubprocess(workspace_root=self._workspace)
        self._logger = get_cerberus_logger()
        self._jobs: Dict[str, FfufJob] = {}
        self._loop = asyncio.new_event_loop()
        self._thread = __import__("threading").Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _run_coro(self, coro: Any, timeout: float = 180.0) -> Any:
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=timeout)

    def start_fuzz(
        self,
        *,
        url: str,
        wordlist: Union[str, List[str]],
        headers: Optional[List[str]] = None,
        method: Optional[str] = None,
        data: Optional[str] = None,
        threads: Optional[int] = None,
        rate: Optional[Union[int, float, str]] = None,
        timeout: int = 300,
        extra_args: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        stream_context = capture_streaming_context()
        try:
            return self._run_coro(
                self._start_fuzz_async(
                    url=url,
                    wordlist=wordlist,
                    headers=headers,
                    method=method,
                    data=data,
                    threads=threads,
                    rate=rate,
                    timeout=timeout,
                    extra_args=extra_args,
                    stream_context=stream_context,
                ),
                timeout=max(60.0, float(timeout) + 15.0),
            )
        except Exception as exc:
            return self._error("ffuf_start_failed", str(exc))

    def get_status(self, job_id: str) -> Dict[str, Any]:
        job = self._jobs.get(job_id)
        if not job:
            return self._error("job_not_found", f"Unknown ffuf job: {job_id}")
        return clean_data(
            {
                "ok": True,
                "job_id": job.job_id,
                "status": job.status,
                "progress_percentage": round(job.progress_percentage, 2),
                "current_hits": job.current_hits,
                "stderr_tail": job.stderr_tail[-8:],
                "summary": job.summary,
            }
        )

    def wait_for_job(self, job_id: str, timeout: int = 300) -> Dict[str, Any]:
        try:
            return self._run_coro(self._wait_for_job_async(job_id, timeout), timeout=max(30.0, float(timeout) + 15.0))
        except Exception as exc:
            return self._error("wait_failed", str(exc))

    async def _start_fuzz_async(
        self,
        *,
        url: str,
        wordlist: Union[str, List[str]],
        headers: Optional[List[str]],
        method: Optional[str],
        data: Optional[str],
        threads: Optional[int],
        rate: Optional[Union[int, float, str]],
        timeout: int,
        extra_args: Optional[List[str]],
        stream_context: StreamingContext,
    ) -> Dict[str, Any]:
        valid, message = self._validate_url(url)
        if not valid:
            return self._error("invalid_url", message)

        ffuf_bin = shutil.which("ffuf")
        if not ffuf_bin:
            return self._error("missing_dependency", "ffuf binary not found on host PATH")

        method_norm = (method or "GET").strip().upper()
        if method_norm not in _ALLOWED_METHODS:
            return self._error("method_not_allowed", f"Unsupported method: {method_norm}")

        wordlists = self._resolve_wordlists(wordlist)
        if not wordlists:
            return self._error("missing_wordlist", "No valid wordlist resolved")
        if len(wordlists) > 1:
            return self._error("unsupported_wordlists", "Managed ffuf tool currently supports one wordlist at a time")
        wordlist_path = wordlists[0]

        safe_headers = self._sanitize_headers(headers or [])
        if safe_headers is None:
            return self._error("invalid_header", "Headers must use 'Name: Value' format with safe names")

        job_id = f"ffuf-{secrets.token_hex(6)}"
        timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        target_label = self._safe_label(urlparse(url).netloc or "target")
        raw_json_path = self._evidence_dir / f"FFUF_{timestamp}_{target_label}_{job_id}.json"
        stderr_log_path = self._evidence_dir / f"FFUF_{timestamp}_{target_label}_{job_id}.stderr.log"

        rate_value = self._resolve_politeness_rate(rate)
        argv = [
            ffuf_bin,
            "-u",
            url,
            "-w",
            str(wordlist_path),
            "-json",
            "-o",
            str(raw_json_path),
            "-mc",
            "all",
            "-timeout",
            str(min(max(int(timeout), 5), 600)),
            "-rate",
            str(rate_value),
        ]
        if method_norm != "GET":
            argv.extend(["-X", method_norm])
        if data:
            argv.extend(["-d", data])
        if threads:
            argv.extend(["-t", str(max(1, min(int(threads), 80)))])
        for header in safe_headers:
            argv.extend(["-H", header])
        for extra in (extra_args or []):
            argv.append(str(extra))

        preview = " ".join(shlex_quote(part) for part in argv)
        guard = validate_command_guardrails(preview)
        if guard:
            return self._error("guardrail_blocked", guard)
        self._secure_subprocess.enforce_denylist(preview)

        baseline_status, baseline_length = await self._calibrate_false_positive(url, method_norm, safe_headers, data)
        total_candidates = self._count_wordlist_entries(wordlist_path)

        clean_env, redactions = self._secure_subprocess.build_clean_environment()
        job = FfufJob(
            job_id=job_id,
            target_url=url,
            method=method_norm,
            wordlist_path=str(wordlist_path),
            started_at=datetime.now(tz=UTC).isoformat(),
            raw_json_path=str(raw_json_path),
            stderr_log_path=str(stderr_log_path),
            status="running",
            total_candidates=total_candidates,
            baseline_status=baseline_status,
            baseline_length=baseline_length,
        )
        self._jobs[job_id] = job
        with CLI_UTILS.managed_env_context(base_env=clean_env) as runtime_env:
            asyncio.create_task(
                self._monitor_job(
                    job_id,
                    argv=argv,
                    runtime_env=dict(runtime_env),
                    timeout=min(max(int(timeout), 5), 600),
                    redactions=redactions,
                    stream_context=stream_context,
                )
            )
        self._audit("ffuf_job_started", {"job_id": job_id, "url": url, "rate": rate_value, "wordlist": str(wordlist_path)})
        return {"ok": True, "job_id": job_id, "status": "running", "progress_percentage": 0.0, "current_hits": 0}

    async def _wait_for_job_async(self, job_id: str, timeout: int) -> Dict[str, Any]:
        started = time.monotonic()
        while time.monotonic() - started < max(5, int(timeout)):
            job = self._jobs.get(job_id)
            if not job:
                return self._error("job_not_found", f"Unknown ffuf job: {job_id}")
            if job.status in {"completed", "failed"}:
                return clean_data({"ok": True, "job_id": job_id, "status": job.status, "summary": job.summary})
            await asyncio.sleep(0.5)
        return self._error("timeout", f"Timed out waiting for ffuf job {job_id}")

    async def _monitor_job(
        self,
        job_id: str,
        *,
        argv: Sequence[str],
        runtime_env: Dict[str, str],
        timeout: int,
        redactions: Dict[str, str],
        stream_context: StreamingContext,
    ) -> None:
        job = self._jobs[job_id]

        stderr_log = Path(job.stderr_log_path)
        stderr_log.parent.mkdir(parents=True, exist_ok=True)

        def _redact_stream(text: str) -> str:
            return self._secure_subprocess.redact_text(text, redactions)

        def _on_process_started(process: asyncio.subprocess.Process) -> None:
            job.process = process

        async def _on_stderr(text: str) -> None:
            clean_text = self._redact_sensitive(text.rstrip("\r\n"))
            if not clean_text:
                return
            job.stderr_tail.append(clean_text)
            job.stderr_tail = job.stderr_tail[-40:]
            with stderr_log.open("a", encoding="utf-8") as handle:
                handle.write(clean_text + "\n")
            match = _PROGRESS_RE.search(clean_text)
            if match and job.total_candidates:
                current = int(match.group(1))
                total = int(match.group(2)) or job.total_candidates
                denom = max(total, job.total_candidates, 1)
                job.progress_percentage = min(100.0, (current / denom) * 100.0)
            job.current_hits = self._count_hits(Path(job.raw_json_path))

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
            timeout_message="ffuf exceeded timeout policy.",
        )

        job.process = None
        job.return_code = result.exit_code
        job.current_hits = self._count_hits(Path(job.raw_json_path))
        job.progress_percentage = 100.0
        if result.exit_code == 0 and not result.timed_out:
            summary = self._summarize_results(Path(job.raw_json_path), baseline_status=job.baseline_status, baseline_length=job.baseline_length)
            job.status = "completed"
            job.summary = summary
            self._audit("ffuf_job_completed", {"job_id": job_id, "hits": job.current_hits, "interesting": len(summary.get('interesting_findings', []))})
        else:
            job.status = "failed"
            if result.timed_out:
                job.summary = self._error("timeout", "ffuf exceeded timeout policy")
            else:
                job.summary = self._error("ffuf_failed", "ffuf exited with a non-zero status")
            self._audit("ffuf_job_failed", {"job_id": job_id, "return_code": result.exit_code})

    async def _calibrate_false_positive(
        self,
        url: str,
        method: str,
        headers: Sequence[str],
        data: Optional[str],
    ) -> tuple[int, int]:
        token = f"cerberus-cal-{secrets.token_hex(6)}"
        target = url.replace("FUZZ", token)
        header_map: Dict[str, str] = {}
        for header in headers:
            name, _sep, value = header.partition(":")
            header_map[name.strip()] = value.lstrip()
        req = Request(target, data=(data.encode("utf-8") if data else None), headers=header_map, method=method)
        try:
            response = await asyncio.to_thread(urlopen, req, timeout=5)
            status = getattr(response, "status", 200)
            body = await asyncio.to_thread(response.read)
            return int(status), len(body or b"")
        except HTTPError as exc:
            with suppress(Exception):
                body = exc.read()
                return int(exc.code), len(body or b"")
            return int(exc.code), 0
        except URLError:
            return 0, 0
        except Exception:
            return 0, 0

    def _summarize_results(self, raw_json_path: Path, *, baseline_status: int, baseline_length: int) -> Dict[str, Any]:
        findings: List[FfufFinding] = []
        grouped: Dict[str, int] = {}
        if raw_json_path.exists():
            for line in raw_json_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                result = row.get("result") if isinstance(row, dict) and "result" in row else row
                if not isinstance(result, dict):
                    continue
                status = int(result.get("status", 0) or 0)
                length = int(result.get("length", 0) or 0)
                if baseline_status and status == baseline_status and abs(length - baseline_length) <= max(8, int(baseline_length * 0.03)):
                    continue
                url = str(result.get("url") or result.get("input", {}).get("FUZZ") or "")
                words = int(result.get("words", 0) or 0)
                lines = int(result.get("lines", 0) or 0)
                content_type = str(result.get("content-type", "") or "")
                score = self._interesting_score(url=url, status=status, length=length, content_type=content_type)
                findings.append(FfufFinding(url=url, status=status, length=length, words=words, lines=lines, content_type=content_type, interesting_score=score))
                grouped[str(status)] = grouped.get(str(status), 0) + 1

        findings.sort(key=lambda item: (item.interesting_score, -item.status, -item.length), reverse=True)
        top = findings[:15]
        report = {
            "ok": True,
            "grouped_statuses": grouped,
            "interesting_findings": [asdict(item) for item in top],
            "raw_output": str(raw_json_path),
            "total_candidates_returned": len(findings),
            "discarded_false_positives": max(0, self._count_hits(raw_json_path) - len(findings)),
        }
        return clean_data(report)

    def _interesting_score(self, *, url: str, status: int, length: int, content_type: str) -> int:
        score = 0
        if status in {401, 403, 500, 204}:
            score += 6
        elif status in {200, 201, 301, 302}:
            score += 2
        path = urlparse(url).path.lower()
        for ext in _INTERESTING_EXTENSIONS:
            if path.endswith(ext):
                score += 8
                break
        if length and (length < 30 or length > 150_000):
            score += 4
        if "json" in content_type.lower() or "xml" in content_type.lower():
            score += 3
        if any(token in path for token in ["admin", "backup", "debug", "internal", "api", "config"]):
            score += 5
        return score

    def _resolve_wordlists(self, wordlist: Union[str, List[str]]) -> List[Path]:
        requested = [wordlist] if isinstance(wordlist, str) else list(wordlist)
        resolved: List[Path] = []
        alias_map = {
            "common": "common.txt",
            "small": "common.txt",
            "medium": "raft-medium-directories.txt",
            "api": "api.txt",
            "params": "parameters.txt",
        }
        for item in requested:
            name = str(item).strip()
            if not name:
                continue
            candidate_name = alias_map.get(name.lower(), name)
            candidate = Path(candidate_name)
            if not candidate.is_absolute():
                candidate = (self._wordlists_dir / candidate_name).resolve()
            else:
                candidate = candidate.resolve()
            if candidate.exists() and candidate.is_file():
                resolved.append(candidate)
        return resolved

    def _sanitize_headers(self, headers: Sequence[str]) -> Optional[List[str]]:
        out: List[str] = []
        for header in headers:
            if "\n" in header or "\r" in header or ":" not in header:
                return None
            name, _sep, value = header.partition(":")
            if not _HEADER_NAME_RE.fullmatch(name.strip()):
                return None
            out.append(f"{name.strip()}: {value.lstrip()}")
        return out

    def _resolve_politeness_rate(self, explicit: Optional[Union[int, float, str]]) -> float:
        if explicit is not None and str(explicit).strip():
            try:
                return max(0.5, min(float(explicit), 500.0))
            except Exception:
                pass
        for key in ("CERBERUS_FFUF_POLITENESS_RPS", "CERBERUS_DISCOVERY_RPS", "CERBERUS_SAFE_RPS"):
            value = CONFIG_STORE.get(key)
            if value and value != "Not set":
                try:
                    return max(0.5, min(float(value), 500.0))
                except Exception:
                    continue
            env = os.getenv(key, "")
            if env:
                try:
                    return max(0.5, min(float(env), 500.0))
                except Exception:
                    continue
        return 25.0

    @staticmethod
    def _validate_url(url: str) -> tuple[bool, str]:
        parsed = urlparse((url or "").strip())
        if parsed.scheme.lower() not in {"http", "https"}:
            return False, "Target URL must use http or https"
        if "FUZZ" not in url:
            return False, "Target URL must contain the FUZZ placeholder"
        if not parsed.netloc:
            return False, "Target URL must include a hostname"
        return True, ""

    @staticmethod
    def _count_wordlist_entries(path: Path) -> int:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                return sum(1 for line in handle if line.strip())
        except Exception:
            return 0

    @staticmethod
    def _count_hits(path: Path) -> int:
        if not path.exists():
            return 0
        try:
            return sum(1 for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
        except Exception:
            return 0

    @staticmethod
    def _safe_label(value: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_.-]", "_", value)[:80] or "target"

    @staticmethod
    def _redact_sensitive(text: str) -> str:
        red = text or ""
        red = re.sub(r"(?i)(authorization:)(\s*\S+)", r"\1 [REDACTED_TOKEN]", red)
        red = re.sub(r"(?i)(cookie:)(\s*.+)", r"\1 [REDACTED_COOKIE]", red)
        red = re.sub(r"(?i)(proxy-authorization:)(\s*\S+)", r"\1 [REDACTED_TOKEN]", red)
        red = re.sub(r"(?i)(token=)([^&\s]+)", r"\1[REDACTED_TOKEN]", red)
        return red

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
                self._logger.audit("ffuf discovery event", actor="ffuf", data=payload, tags=["ffuf", event])

    @staticmethod
    def _agent_id() -> str:
        for key in ("CERBERUS_AGENT_ID", "AGENT_ID", "CERBERUS_AGENT", "CERBERUS_AGENT_TYPE"):
            value = os.getenv(key, "").strip()
            if value:
                return value
        return "unknown-agent"

    @staticmethod
    def _error(code: str, message: str) -> Dict[str, Any]:
        return {"ok": False, "error": {"code": code, "message": message}}


def shlex_quote(value: str) -> str:
    import shlex

    return shlex.quote(str(value))


FFUF_TOOL = LazyToolProxy(CerebroFfufTool)


def run_ffuf(
    url: str,
    wordlist: Union[str, List[str]],
    headers: Optional[List[str]] = None,
    method: Optional[str] = None,
    data: Optional[str] = None,
    threads: Optional[int] = None,
    rate: Optional[Union[int, float, str]] = None,
    proxy: Optional[str] = None,
    json_output: bool = False,
    output_file: Optional[str] = None,
    timeout: int = 300,
    extra_args: Optional[List[str]] = None,
) -> str:
    _ = (proxy, json_output, output_file)
    start = FFUF_TOOL.start_fuzz(
        url=url,
        wordlist=wordlist,
        headers=headers,
        method=method,
        data=data,
        threads=threads,
        rate=rate,
        timeout=timeout,
        extra_args=extra_args,
    )
    if not start.get("ok"):
        return str((start.get("error") or {}).get("message", "ffuf start failed"))
    wait = FFUF_TOOL.wait_for_job(str(start["job_id"]), timeout=timeout)
    if not wait.get("ok"):
        return str((wait.get("error") or {}).get("message", "ffuf wait failed"))
    summary = wait.get("summary") or {}
    if not summary.get("ok", True):
        return str((summary.get("error") or {}).get("message", "ffuf failed"))
    report = {
        "grouped_statuses": summary.get("grouped_statuses", {}),
        "interesting_findings": summary.get("interesting_findings", []),
        "raw_output": summary.get("raw_output", ""),
        "discarded_false_positives": summary.get("discarded_false_positives", 0),
    }
    return sanitize_tool_output("ffuf", json.dumps(clean_data(report), ensure_ascii=True, indent=2))


__all__ = ["CerebroFfufTool", "FFUF_TOOL", "run_ffuf"]
