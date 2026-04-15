"""Hardened web interaction gateway backed by curl subprocess execution."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from hashlib import sha256
import json
from pathlib import Path
import re
import shlex
import shutil
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from cai.memory.logic import clean_data
from cai.repl.commands.shell import SecureSubprocess
from cai.repl.ui.logging import get_cerebro_logger
from cai.sdk.agents import function_tool
from cai.tools.misc.cli_utils import CLI_UTILS
from cai.tools.validation import sanitize_tool_output, validate_command_guardrails
from cai.tools.workspace import get_project_space
from cai.utils.streamer import run_streaming_subprocess


ALLOWED_PROTOCOLS = {"http", "https"}
ALLOWED_METHODS = {"GET", "POST", "HEAD"}
SENSITIVE_REQUEST_HEADERS = {
    "proxy-authorization",
    "x-internal-token",
    "x-auth-token",
    "x-forwarded-for",
}


@dataclass(frozen=True)
class CurlAuditEntry:
    timestamp: str
    method: str
    url: str
    response_sha256: str
    status_code: int
    evidence_path: str


class CerebroCurlTool:
    """Secure async curl gateway with redaction and forensic evidence capture."""

    LARGE_RESPONSE_THRESHOLD = 16_000

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._secure_subprocess = SecureSubprocess(workspace_root=self._workspace)
        self._logger = get_cerebro_logger()
        self._evidence_dir = (self._workspace / "evidence" / "web").resolve()
        self._audit_path = (self._workspace / ".cai" / "audit" / "web_requests.jsonl").resolve()
        self._evidence_dir.mkdir(parents=True, exist_ok=True)

    async def request(self, *, target: str, args: str = "", timeout: int = 30) -> Dict[str, Any]:
        target = (target or "").strip()
        if not target:
            return self._error("invalid_target", "target is required")

        valid, message = self._validate_target(target)
        if not valid:
            return self._error("invalid_target", message)

        curl_bin = shutil.which("curl")
        if not curl_bin:
            return self._error("missing_dependency", "curl executable not found on host PATH")

        timeout = max(3, min(int(timeout), 600))
        parse = self._parse_and_sanitize_args(args)
        if not parse["ok"]:
            return parse

        method = str(parse["method"])
        extra = list(parse["argv"])
        substituted = str(parse["substitution"])

        if method not in ALLOWED_METHODS:
            return self._error("method_not_allowed", f"HTTP method {method} is not allowed")

        ts = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        host_label = self._safe_label(urlparse(target).netloc or "target")
        body_path = (self._evidence_dir / f"WEB_{ts}_{host_label}.body").resolve()
        header_path = (self._evidence_dir / f"WEB_{ts}_{host_label}.headers").resolve()

        argv = [
            curl_bin,
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=http,https",
            "--proto-redir",
            "=http,https",
            "--connect-timeout",
            str(min(10, timeout)),
            "--max-time",
            str(timeout),
            "--request",
            method,
            "--dump-header",
            str(header_path),
            "--output",
            str(body_path),
            "--write-out",
            "%{http_code}",
            *extra,
            target,
        ]

        command_preview = " ".join(shlex.quote(part) for part in argv)
        guard = validate_command_guardrails(command_preview)
        if guard:
            return self._error("guardrail_blocked", guard)
        self._secure_subprocess.enforce_denylist(command_preview)

        clean_env, redactions = self._secure_subprocess.build_clean_environment()
        def _redact_stream(text: str) -> str:
            return self._redact_text(self._secure_subprocess.redact_text(text, redactions))

        with CLI_UTILS.managed_env_context(base_env=clean_env) as runtime_env:
            result = await run_streaming_subprocess(
                argv=argv,
                cwd=self._workspace,
                env=runtime_env,
                timeout_seconds=timeout + 2,
                redactor=_redact_stream,
                emit_stdout=False,
                emit_stderr=True,
                timeout_message="request timed out",
            )

        http_code = self._parse_status_code(result.stdout)
        stderr_text = result.stderr

        body_bytes = body_path.read_bytes() if body_path.exists() else b""
        header_bytes = header_path.read_bytes() if header_path.exists() else b""
        response_hash = sha256(header_bytes + b"\n" + body_bytes).hexdigest()

        red_headers = self._redact_text(header_bytes.decode("utf-8", errors="replace"))
        red_body = self._redact_text(body_bytes.decode("utf-8", errors="replace"))

        evidence_needed = bool(parse["forced_download"]) or len(red_body) > self.LARGE_RESPONSE_THRESHOLD
        if evidence_needed:
            body_preview = red_body[:4000] + "\n...[stored in evidence]..."
        else:
            body_preview = red_body

        audit = CurlAuditEntry(
            timestamp=datetime.now(tz=UTC).isoformat(),
            method=method,
            url=target,
            response_sha256=response_hash,
            status_code=http_code,
            evidence_path=str(body_path),
        )
        self._append_audit(audit)

        payload = {
            "ok": (not result.timed_out and (result.exit_code == 0)),
            "method": method,
            "url": target,
            "status_code": http_code,
            "headers": sanitize_tool_output("curl_headers", red_headers),
            "body": sanitize_tool_output("curl_body", body_preview),
            "stderr": sanitize_tool_output("curl_stderr", stderr_text),
            "timed_out": result.timed_out,
            "response_sha256": response_hash,
            "evidence": {
                "body_path": str(body_path),
                "headers_path": str(header_path),
            },
            "substitution": substituted,
        }
        return clean_data(payload)

    def _parse_and_sanitize_args(self, args: str) -> Dict[str, Any]:
        tokens = shlex.split(args or "")
        method = "GET"
        out: List[str] = []
        substitution = ""
        forced_download = False

        i = 0
        while i < len(tokens):
            tok = tokens[i]
            low = tok.lower()

            if tok == "-x" or low in {"--proxy", "--socks5", "--socks5-hostname"}:
                return self._error("proxy_not_allowed", "Proxy options are not allowed by policy")

            if tok == "-X" or low == "--request":
                if i + 1 >= len(tokens):
                    return self._error("invalid_args", "Missing method after -X/--request")
                candidate = tokens[i + 1].upper()
                if candidate in ALLOWED_METHODS:
                    method = candidate
                    i += 2
                    continue
                return self._error("method_not_allowed", f"Requested method {candidate} is not allowed")

            if low == "-i" or low == "--head":
                method = "HEAD" if low == "--head" else method
                out.append(tok)
                i += 1
                continue

            if low in {"-h", "--header"}:
                if i + 1 >= len(tokens):
                    return self._error("invalid_args", "Missing header value after -H/--header")
                header_raw = tokens[i + 1]
                keep, sanitized = self._sanitize_request_header(header_raw)
                if keep:
                    out.extend([tok, sanitized])
                i += 2
                continue

            if low in {"-o", "--output"}:
                forced_download = True
                substitution = "Output path substituted to workspace evidence silo"
                i += 2
                continue

            if low in {"-d", "--data", "--data-raw", "--data-binary", "-u", "--user", "-A", "--user-agent", "-k", "--insecure", "-L", "--location", "-I", "--include", "--compressed", "--retry", "--retry-delay"}:
                out.append(tok)
                if low in {"-d", "--data", "--data-raw", "--data-binary", "-u", "--user", "-A", "--user-agent", "--retry", "--retry-delay"} and i + 1 < len(tokens):
                    out.append(tokens[i + 1])
                    i += 2
                    continue
                i += 1
                continue

            if low.startswith("--"):
                # Unknown advanced flag blocked to reduce accidental unsafe behaviors.
                return self._error("unsupported_flag", f"Unsupported curl flag: {tok}")

            out.append(tok)
            i += 1

        return {"ok": True, "method": method, "argv": out, "substitution": substitution, "forced_download": forced_download}

    @staticmethod
    def _sanitize_request_header(header: str) -> tuple[bool, str]:
        key, sep, value = header.partition(":")
        if not sep:
            return False, ""
        name = key.strip().lower()
        if name in SENSITIVE_REQUEST_HEADERS:
            return False, ""
        return True, f"{key.strip()}: {value.lstrip()}"

    def _validate_target(self, target: str) -> tuple[bool, str]:
        parsed = urlparse(target)
        if parsed.scheme.lower() not in ALLOWED_PROTOCOLS:
            return False, "Only http and https protocols are allowed"
        if not parsed.netloc:
            return False, "Target URL must include a hostname"
        return True, ""

    @staticmethod
    def _parse_status_code(text: str) -> int:
        t = (text or "").strip()
        if t.isdigit():
            return int(t)
        match = re.search(r"(\d{3})", t)
        return int(match.group(1)) if match else 0

    @staticmethod
    def _safe_label(value: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_.-]", "_", value)[:80] or "target"

    @staticmethod
    def _redact_text(text: str) -> str:
        out = text or ""
        out = re.sub(r"(?im)^(set-cookie\s*:\s*)(.+)$", r"\1[REDACTED_COOKIE]", out)
        out = re.sub(r"(?im)^(authorization\s*:\s*)(.+)$", r"\1[REDACTED_AUTH]", out)
        out = re.sub(r"(?im)^(proxy-authorization\s*:\s*)(.+)$", r"\1[REDACTED_AUTH]", out)
        out = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-+/=]+", r"\1[REDACTED_TOKEN]", out)
        out = re.sub(r"(?i)(token\s*[=:]\s*)(\S+)", r"\1[REDACTED_TOKEN]", out)
        out = re.sub(r"(?i)(password\s*[=:]\s*)(\S+)", r"\1[REDACTED_SECRET]", out)
        return out

    def _append_audit(self, entry: CurlAuditEntry) -> None:
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self._audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(entry), ensure_ascii=True) + "\n")
        if self._logger is not None:
            try:
                self._logger.audit("Web request executed", actor="curl_tool", data=asdict(entry), tags=["web", "curl", "audit"])
            except Exception:
                pass

    @staticmethod
    def _error(code: str, message: str) -> Dict[str, Any]:
        return {"ok": False, "error": {"code": code, "message": message}}


CURL_TOOL = CerebroCurlTool()


@function_tool
async def curl(target: str, args: str = "", timeout: int = 30) -> str:
    result = await CURL_TOOL.request(target=target, args=args, timeout=timeout)
    if not result.get("ok"):
        return str((result.get("error") or {}).get("message", "curl request failed"))

    summary = [
        f"HTTP {result.get('status_code', 0)} {result.get('method', 'GET')} {result.get('url', '')}",
        "",
        "=== Headers (Redacted) ===",
        str(result.get("headers", "")),
        "",
        "=== Body (Redacted) ===",
        str(result.get("body", "")),
    ]
    if result.get("substitution"):
        summary.extend(["", f"Substitution: {result['substitution']}"])
    summary.extend(["", f"Response SHA-256: {result.get('response_sha256', '')}"])
    summary.extend([f"Evidence: {result.get('evidence', {}).get('body_path', '')}"])
    return "\n".join(summary)


__all__ = ["CerebroCurlTool", "CURL_TOOL", "curl"]
