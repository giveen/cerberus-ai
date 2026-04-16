"""Structured Network Audit Engine for secure Nmap discovery."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from datetime import UTC, datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import threading
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from pydantic import BaseModel, Field

from cerberus.memory.logic import clean_data
from cerberus.repl.commands.shell import SecureSubprocess
from cerberus.repl.ui.logging import get_cerberus_logger
from cerberus.sdk.agents import function_tool
from cerberus.tools._lazy import LazyToolProxy
from cerberus.tools.misc.cli_utils import CLI_UTILS
from cerberus.tools.validation import is_valid_target, sanitize_tool_output
from cerberus.tools.workspace import get_project_space
from cerberus.utils.process_handler import StreamingContext, capture_streaming_context, run_streaming_subprocess


_MAX_TIMEOUT_SECONDS = 1800
_MAX_TARGET_TOKENS = 64
_MAX_EXTRA_ARGS = 64
_INTRUSIVE_SCRIPT_PATTERNS = (
    "dos",
    "flood",
    "brute",
    "broadcast",
    "exploit",
)
_FORBIDDEN_EXTRA_FLAGS = {
    "-oX",
    "-oN",
    "-oG",
    "-oA",
    "-iL",
    "--append-output",
}
_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_./,:=+-]+$")
_PROGRESS_RE = re.compile(r"About\s+([0-9]{1,3}(?:\.[0-9]+)?)%\s+done", re.IGNORECASE)


class NmapScriptResult(BaseModel):
    id: str
    output: str = ""
    table: Dict[str, str] = Field(default_factory=dict)


class NmapService(BaseModel):
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    cpe: List[str] = Field(default_factory=list)


class NmapPort(BaseModel):
    portid: int
    protocol: str
    state: str
    reason: str = ""
    service: NmapService = Field(default_factory=NmapService)
    scripts: Dict[str, NmapScriptResult] = Field(default_factory=dict)


class NmapHost(BaseModel):
    status: str
    reason: str = ""
    addresses: Dict[str, str] = Field(default_factory=dict)
    hostnames: List[str] = Field(default_factory=list)
    os_matches: List[str] = Field(default_factory=list)
    ports: List[NmapPort] = Field(default_factory=list)


class NmapResult(BaseModel):
    ok: bool
    scan_profile: str
    target_expression: str
    command_line: List[str]
    nmap_version: str
    started_at: str
    ended_at: str
    duration_ms: int
    status_updates: List[str] = Field(default_factory=list)
    xml_sha256: str = ""
    hosts: List[NmapHost] = Field(default_factory=list)
    raw_xml_path: str = ""
    parsed_json_path: str = ""
    error: Optional[Dict[str, str]] = None


class CerebroNmapTool:
    """Managed Nmap controller with structured parsing, profiles, and forensic logs."""

    PROFILES: Dict[str, List[str]] = {
        "STEALTH": ["-sS", "-sV", "-O", "-n", "-Pn", "-T2", "--randomize-hosts", "--max-retries", "2"],
        "AGGRESSIVE": ["-A", "-T4", "-n"],
        "QUICK_UDP": ["-sU", "--top-ports", "40", "-T3", "-sV", "-n"],
        "BALANCED": ["-sV", "-O", "-T3", "-n"],
        "DEFAULT": ["-sV", "-O", "-T3", "-n"],
        "MINIMAL": ["-sV", "-T2", "-n"],
    }

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._evidence_dir = (self._workspace / "evidence" / "network" / "nmap").resolve()
        self._audit_log = (self._workspace / ".cerberus" / "audit" / "nmap_scans.jsonl").resolve()
        self._secure = SecureSubprocess(workspace_root=self._workspace)
        self._logger = get_cerberus_logger()
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._evidence_dir.mkdir(parents=True, exist_ok=True)
        self._audit_log.parent.mkdir(parents=True, exist_ok=True)

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _run_coro(self, coro: Any, timeout: float) -> Dict[str, Any]:
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=timeout)

    def scan(
        self,
        *,
        target: str,
        profile: str = "BALANCED",
        timeout: int = 300,
        nse_scripts: str = "",
        allow_intrusive_scripts: bool = False,
        operator_override: bool = False,
        extra_args: str = "",
        reason: str = "Structured network audit",
    ) -> Dict[str, Any]:
        effective_timeout = max(10, min(int(timeout), _MAX_TIMEOUT_SECONDS))
        stream_context = capture_streaming_context()
        return self._run_coro(
            self._scan_async(
                target=target,
                profile=profile,
                timeout=effective_timeout,
                nse_scripts=nse_scripts,
                allow_intrusive_scripts=allow_intrusive_scripts,
                operator_override=operator_override,
                extra_args=extra_args,
                reason=reason,
                stream_context=stream_context,
            ),
            timeout=max(float(effective_timeout) + 90.0, 180.0),
        )

    async def _scan_async(
        self,
        *,
        target: str,
        profile: str,
        timeout: int,
        nse_scripts: str,
        allow_intrusive_scripts: bool,
        operator_override: bool,
        extra_args: str,
        reason: str,
        stream_context: StreamingContext,
    ) -> Dict[str, Any]:
        started = datetime.now(tz=UTC)
        nmap_bin = shutil.which("nmap")
        if not nmap_bin:
            return self._error("missing_dependency", "nmap binary not found on system PATH")

        target_expr = (target or "").strip().rstrip(".,;:")
        if not target_expr:
            return self._error("invalid_target", "target is required")

        target_tokens = self._tokenize_targets(target_expr)
        if not target_tokens:
            return self._error("invalid_target", "target expression has no valid tokens")
        if len(target_tokens) > _MAX_TARGET_TOKENS:
            return self._error("target_limit", f"too many target tokens (max {_MAX_TARGET_TOKENS})")
        if not self._targets_in_scope(target_tokens):
            return self._error("scope_violation", "target expression is outside engagement scope")

        profile_name = (profile or "BALANCED").strip().upper()
        base_profile = self.PROFILES.get(profile_name)
        if not base_profile:
            available = ", ".join(sorted(self.PROFILES.keys()))
            return self._error("invalid_profile", f"unknown scan profile: {profile}. available: {available}")

        scripts_value = (nse_scripts or "").strip()
        script_error = self._validate_scripts(
            scripts=scripts_value,
            allow_intrusive=allow_intrusive_scripts,
            operator_override=operator_override,
        )
        if script_error:
            return self._error("script_blocked", script_error)

        extra_tokens_or_error = self._validate_extra_args(extra_args)
        if isinstance(extra_tokens_or_error, str):
            return self._error("invalid_args", extra_tokens_or_error)

        command = [nmap_bin, *base_profile, "--stats-every", "5s", "-oX", "-", *extra_tokens_or_error]
        if scripts_value:
            command.extend(["--script", scripts_value])
        command.extend(target_tokens)

        clean_env, redactions = self._secure.build_clean_environment()
        status_updates: List[str] = ["Scan started (0% complete)"]

        with CLI_UTILS.managed_env_context(base_env=clean_env) as runtime_env:
            stdout_chunks: List[str] = []
            stderr_chunks: List[str] = []

            def _redact_stream(text: str) -> str:
                return self._secure.redact_text(text, redactions)

            async def _on_stdout(text: str) -> None:
                stdout_chunks.append(text)

            async def _on_stderr(text: str) -> None:
                stripped = text.strip()
                if stripped:
                    stderr_chunks.append(stripped)
                hit = _PROGRESS_RE.search(stripped)
                if hit:
                    pct = min(100.0, max(0.0, float(hit.group(1))))
                    status_updates.append(f"Scan {pct:.1f}% complete")

            result = await run_streaming_subprocess(
                argv=command,
                cwd=self._workspace,
                env=runtime_env,
                timeout_seconds=timeout,
                redactor=_redact_stream,
                event_callback=stream_context.callback,
                stdout_callback=_on_stdout,
                stderr_callback=_on_stderr,
                session_id=stream_context.session_id,
                stdout_mode="chunk",
                emit_stdout=False,
                emit_stderr=True,
                timeout_message="nmap scan exceeded timeout policy.",
            )

        ended = datetime.now(tz=UTC)
        duration_ms = int((ended - started).total_seconds() * 1000)
        stderr_text = sanitize_tool_output("nmap_stderr", "\n".join(stderr_chunks))
        raw_xml = "".join(stdout_chunks).strip()

        if result.timed_out:
            status_updates.append("Scan timed out")
            await self._log_audit(
                command_line=command,
                xml_sha256="",
                reason=reason,
                success=False,
                duration_ms=duration_ms,
                error="timeout",
            )
            return self._error("timeout", "nmap scan exceeded timeout policy")

        if result.exit_code not in (0, None):
            await self._log_audit(
                command_line=command,
                xml_sha256="",
                reason=reason,
                success=False,
                duration_ms=duration_ms,
                error=stderr_text[:800],
            )
            return self._error("scan_failed", stderr_text or f"nmap exited with code {result.exit_code}")

        if not raw_xml:
            await self._log_audit(
                command_line=command,
                xml_sha256="",
                reason=reason,
                success=False,
                duration_ms=duration_ms,
                error="empty_xml",
            )
            return self._error("empty_output", "nmap returned empty XML output")

        xml_hash = hashlib.sha256(raw_xml.encode("utf-8", errors="replace")).hexdigest()
        parse_result = self._parse_xml(raw_xml)
        if isinstance(parse_result, str):
            return self._error("parse_error", parse_result)

        timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        label = self._safe_label(target_expr)
        xml_path = self._evidence_dir / f"NMAP_{timestamp}_{label}.xml"
        json_path = self._evidence_dir / f"NMAP_{timestamp}_{label}.json"
        await self._write_evidence(xml_path=xml_path, json_path=json_path, raw_xml=raw_xml, parsed=parse_result)

        status_updates.append("Scan 100.0% complete")
        status_updates.append(f"Saved evidence to {self._display_path(xml_path)}")

        result = NmapResult(
            ok=True,
            scan_profile=profile_name,
            target_expression=target_expr,
            command_line=command,
            nmap_version=self._extract_nmap_version(raw_xml),
            started_at=started.isoformat(),
            ended_at=ended.isoformat(),
            duration_ms=duration_ms,
            status_updates=status_updates,
            xml_sha256=xml_hash,
            hosts=parse_result,
            raw_xml_path=self._display_path(xml_path),
            parsed_json_path=self._display_path(json_path),
        )

        await self._log_audit(
            command_line=command,
            xml_sha256=xml_hash,
            reason=reason,
            success=True,
            duration_ms=duration_ms,
            error="",
        )
        return clean_data(result.model_dump())

    @staticmethod
    def _tokenize_targets(target_expr: str) -> List[str]:
        tokens = [tok.strip() for tok in re.split(r"[\s,]+", target_expr) if tok.strip()]
        out: List[str] = []
        for token in tokens:
            if is_valid_target(token):
                out.append(token)
        return out

    @staticmethod
    def _validate_extra_args(extra_args: str) -> Sequence[str] | str:
        raw = (extra_args or "").strip()
        if not raw:
            return []
        try:
            tokens = shlex.split(raw, posix=True)
        except ValueError as exc:
            return f"unable to parse extra args: {exc}"
        if len(tokens) > _MAX_EXTRA_ARGS:
            return f"too many extra args (max {_MAX_EXTRA_ARGS})"
        for token in tokens:
            if token in _FORBIDDEN_EXTRA_FLAGS:
                return f"extra arg not allowed: {token}"
            if token.startswith("-o"):
                return "output flags are managed internally"
            if not _SAFE_TOKEN_RE.fullmatch(token):
                return f"unsafe token in extra args: {token}"
        return tokens

    @staticmethod
    def _validate_scripts(*, scripts: str, allow_intrusive: bool, operator_override: bool) -> Optional[str]:
        if not scripts:
            return None
        lowered = scripts.lower()
        if allow_intrusive or operator_override:
            return None
        for marker in _INTRUSIVE_SCRIPT_PATTERNS:
            if marker in lowered:
                return f"NSE script group blocked by policy without operator override: {marker}"
        return None

    def _targets_in_scope(self, tokens: Sequence[str]) -> bool:
        allowed = self._allowed_scope_tokens()
        if not allowed:
            return True
        for token in tokens:
            if not self._token_in_scope(token, allowed):
                return False
        return True

    @staticmethod
    def _allowed_scope_tokens() -> List[str]:
        raw = ",".join([
            os.getenv("CERBERUS_ENGAGEMENT_SCOPE", ""),
            os.getenv("CERBERUS_ALLOWED_TARGETS", ""),
        ])
        return [x.strip() for x in raw.split(",") if x.strip()]

    @staticmethod
    def _token_in_scope(token: str, allowed: Sequence[str]) -> bool:
        token_l = token.lower()
        normalized_allowed = {item.lower() for item in allowed}
        if token_l in normalized_allowed:
            return True

        token_ip = None
        token_net = None
        with suppress(Exception):
            token_ip = ipaddress.ip_address(token)
        with suppress(Exception):
            token_net = ipaddress.ip_network(token, strict=False)

        for entry in allowed:
            entry_l = entry.lower()
            if entry_l.startswith("*.") and token_l.endswith(entry_l[1:]):
                return True
            if token_l == entry_l:
                return True

            with suppress(Exception):
                allow_net = ipaddress.ip_network(entry, strict=False)
                if token_ip and token_ip in allow_net:
                    return True
                if token_net and token_net.version == allow_net.version:
                    token_start = int(token_net.network_address)
                    token_end = int(token_net.broadcast_address)
                    allow_start = int(allow_net.network_address)
                    allow_end = int(allow_net.broadcast_address)
                    if token_start >= allow_start and token_end <= allow_end:
                        return True

        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){2}\.\d{1,3}-\d{1,3}", token):
            base, octet_range = token.rsplit(".", 1)
            start_octet_s, end_octet_s = octet_range.split("-", 1)
            with suppress(Exception):
                start_ip = ipaddress.ip_address(f"{base}.{int(start_octet_s)}")
                end_ip = ipaddress.ip_address(f"{base}.{int(end_octet_s)}")
                for entry in allowed:
                    with suppress(Exception):
                        allow_net = ipaddress.ip_network(entry, strict=False)
                        if start_ip in allow_net and end_ip in allow_net:
                            return True

        return False

    @staticmethod
    def _extract_nmap_version(raw_xml: str) -> str:
        with suppress(Exception):
            root = ET.fromstring(raw_xml)
            return root.attrib.get("version", "")
        return ""

    @staticmethod
    def _parse_xml(raw_xml: str) -> List[NmapHost] | str:
        try:
            root = ET.fromstring(raw_xml)
        except ET.ParseError as exc:
            return f"invalid XML from nmap: {exc}"

        hosts: List[NmapHost] = []
        for host_node in root.findall("host"):
            status_node = host_node.find("status")
            status_value = status_node.attrib.get("state", "unknown") if status_node is not None else "unknown"
            status_reason = status_node.attrib.get("reason", "") if status_node is not None else ""

            addresses: Dict[str, str] = {}
            for addr in host_node.findall("address"):
                addrtype = addr.attrib.get("addrtype", "unknown")
                addrval = addr.attrib.get("addr", "")
                if addrval:
                    addresses[addrtype] = addrval

            hostnames: List[str] = []
            for hn in host_node.findall("hostnames/hostname"):
                name = hn.attrib.get("name", "")
                if name:
                    hostnames.append(name)

            os_matches: List[str] = []
            for match in host_node.findall("os/osmatch"):
                name = match.attrib.get("name", "")
                if name:
                    os_matches.append(name)

            ports: List[NmapPort] = []
            for port_node in host_node.findall("ports/port"):
                portid = 0
                with suppress(Exception):
                    portid = int(port_node.attrib.get("portid", "0"))
                if portid <= 0:
                    continue
                protocol = port_node.attrib.get("protocol", "")

                state_node = port_node.find("state")
                state = state_node.attrib.get("state", "unknown") if state_node is not None else "unknown"
                reason = state_node.attrib.get("reason", "") if state_node is not None else ""

                service_node = port_node.find("service")
                service = NmapService(
                    name=(service_node.attrib.get("name", "") if service_node is not None else ""),
                    product=(service_node.attrib.get("product", "") if service_node is not None else ""),
                    version=(service_node.attrib.get("version", "") if service_node is not None else ""),
                    extrainfo=(service_node.attrib.get("extrainfo", "") if service_node is not None else ""),
                    tunnel=(service_node.attrib.get("tunnel", "") if service_node is not None else ""),
                    cpe=[node.text or "" for node in port_node.findall("service/cpe") if (node.text or "").strip()],
                )

                scripts: Dict[str, NmapScriptResult] = {}
                for script_node in port_node.findall("script"):
                    script_id = script_node.attrib.get("id", "")
                    if not script_id:
                        continue
                    script_output = script_node.attrib.get("output", "")
                    table_data: Dict[str, str] = {}
                    for elem in script_node.findall("elem"):
                        key = elem.attrib.get("key", "value")
                        val = (elem.text or "").strip()
                        if val:
                            table_data[key] = val
                    scripts[script_id] = NmapScriptResult(id=script_id, output=script_output, table=table_data)

                ports.append(
                    NmapPort(
                        portid=portid,
                        protocol=protocol,
                        state=state,
                        reason=reason,
                        service=service,
                        scripts=scripts,
                    )
                )

            hosts.append(
                NmapHost(
                    status=status_value,
                    reason=status_reason,
                    addresses=addresses,
                    hostnames=hostnames,
                    os_matches=os_matches,
                    ports=ports,
                )
            )

        return hosts

    async def _write_evidence(self, *, xml_path: Path, json_path: Path, raw_xml: str, parsed: List[NmapHost]) -> None:
        payload = [host.model_dump() for host in parsed]

        def _write() -> None:
            xml_path.write_text(raw_xml, encoding="utf-8")
            json_path.write_text(json.dumps(clean_data(payload), ensure_ascii=True, indent=2), encoding="utf-8")

        await asyncio.to_thread(_write)

    async def _log_audit(
        self,
        *,
        command_line: Sequence[str],
        xml_sha256: str,
        reason: str,
        success: bool,
        duration_ms: int,
        error: str,
    ) -> None:
        record = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "command_line": list(command_line),
            "xml_sha256": xml_sha256,
            "reason": reason,
            "success": success,
            "duration_ms": duration_ms,
            "error": (error or "")[:1000],
        }
        line = json.dumps(clean_data(record), ensure_ascii=True) + "\n"

        def _append() -> None:
            self._audit_log.parent.mkdir(parents=True, exist_ok=True)
            with self._audit_log.open("a", encoding="utf-8") as handle:
                handle.write(line)

        await asyncio.to_thread(_append)
        if self._logger is not None:
            with suppress(Exception):
                self._logger.audit(
                    "nmap scan audited",
                    actor="nmap",
                    data=clean_data(record),
                    tags=["nmap", "network", "audit"],
                )

    def _display_path(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self._workspace))
        except ValueError:
            return str(path.resolve())

    @staticmethod
    def _safe_label(text: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_")
        return cleaned[:80] or "target"

    @staticmethod
    def _error(code: str, message: str) -> Dict[str, Any]:
        return clean_data({"ok": False, "error": {"code": code, "message": message}})


NMAP_TOOL = LazyToolProxy(CerebroNmapTool)


@function_tool(risk_tier=4)
def nmap(
    target: str,
    args: str = "",
    timeout: int = 300,
    profile: str = "BALANCED",
    nse_scripts: str = "",
    allow_intrusive_scripts: bool = False,
    operator_override: bool = False,
    reason: str = "Structured network audit",
) -> Dict[str, Any]:
    return NMAP_TOOL.scan(
        target=target,
        profile=profile,
        timeout=timeout,
        nse_scripts=nse_scripts,
        allow_intrusive_scripts=allow_intrusive_scripts,
        operator_override=operator_override,
        extra_args=args,
        reason=reason,
    )


__all__ = [
    "NmapScriptResult",
    "NmapService",
    "NmapPort",
    "NmapHost",
    "NmapResult",
    "CerebroNmapTool",
    "NMAP_TOOL",
    "nmap",
]
