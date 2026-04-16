"""Hardened Shodan external attack surface monitor with scope, credit, and evidence controls."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import threading
from typing import Any, Dict, List, Optional, Sequence, Tuple

from pydantic import BaseModel, Field

from cerberus.memory.logic import clean_data
from cerberus.repl.commands.config import get_env_var_value
from cerberus.repl.ui.logging import get_cerberus_logger
from cerberus.agents import function_tool
from cerberus.tools._lazy import LazyToolProxy
from cerberus.tools.workspace import get_project_space

try:
    import shodan  # type: ignore[import-not-found]
    from shodan.exception import APIError as ShodanAPIError  # type: ignore[import-not-found]
except Exception:
    shodan = None
    ShodanAPIError = Exception


_MAX_LIMIT = 100
_DEFAULT_LIMIT = 20
_MAX_QUERY_LENGTH = 512
_EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_FROM_NAME_RE = re.compile(r"(?im)^from:\s*([^<\r\n]+)(<[^>]+>)?\s*$")


@dataclass(frozen=True)
class SemanticError:
    code: str
    message: str
    retryable: bool
    category: str


class VulnerabilitySummary(BaseModel):
    cves: List[str] = Field(default_factory=list)


class CertificateSummary(BaseModel):
    subject_cn: str = ""
    issuer_cn: str = ""
    valid_from: str = ""
    valid_until: str = ""
    serial: str = ""


class LocationSummary(BaseModel):
    country: str = ""
    city: str = ""
    region: str = ""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: str = ""


class ServiceSummary(BaseModel):
    port: int
    transport: str = ""
    service: str = ""
    product: str = ""
    version: str = ""
    banner_excerpt: str = ""


class ShodanTargetSummary(BaseModel):
    target: str
    host_ip: str = ""
    hostnames: List[str] = Field(default_factory=list)
    open_ports: List[int] = Field(default_factory=list)
    services: List[ServiceSummary] = Field(default_factory=list)
    vulnerabilities: VulnerabilitySummary = Field(default_factory=VulnerabilitySummary)
    certificate: CertificateSummary = Field(default_factory=CertificateSummary)
    location: LocationSummary = Field(default_factory=LocationSummary)


class ShodanReport(BaseModel):
    ok: bool
    query_type: str
    target: str
    query: str
    generated_at: str
    summaries: List[ShodanTargetSummary] = Field(default_factory=list)
    evidence_path: str = ""
    error: Optional[Dict[str, Any]] = None


class CerebroShodanTool:
    """Asynchronous Shodan monitor with strict API handling and scoped discovery."""

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._evidence_dir = (self._workspace / "evidence" / "osint" / "shodan").resolve()
        self._audit_log = (self._workspace / ".cerberus" / "audit" / "shodan_queries.jsonl").resolve()
        self._quota_state = (self._workspace / ".cerberus" / "audit" / "shodan_quota_state.json").resolve()
        self._logger = get_cerberus_logger()
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._evidence_dir.mkdir(parents=True, exist_ok=True)
        self._audit_log.parent.mkdir(parents=True, exist_ok=True)

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _run_coro(self, coro: Any, timeout: float) -> Dict[str, Any]:
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=timeout)

    def start_search(self, *, target: str, query: str, limit: int = _DEFAULT_LIMIT) -> Dict[str, Any]:
        job_id = f"shodan-{datetime.now(tz=UTC).strftime('%Y%m%d%H%M%S')}-{len(self._jobs)+1}"
        self._jobs[job_id] = {
            "status": "queued",
            "target": target,
            "query": query,
            "started_at": datetime.now(tz=UTC).isoformat(),
            "result": None,
        }
        asyncio.run_coroutine_threadsafe(
            self._run_search_job(job_id=job_id, target=target, query=query, limit=limit),
            self._loop,
        )
        return clean_data({"ok": True, "job_id": job_id, "status": "queued"})

    def job_status(self, job_id: str) -> Dict[str, Any]:
        payload = self._jobs.get((job_id or "").strip())
        if not payload:
            return self._error("unknown_job", f"No Shodan job found for id: {job_id}")
        return clean_data(payload)

    def host_lookup(self, *, target: str, wait: bool = True) -> Dict[str, Any]:
        if wait:
            return self._run_coro(self._host_lookup_async(target=target), timeout=120.0)
        return self.start_search(target=target, query=f"ip:{target}", limit=1)

    async def _run_search_job(self, *, job_id: str, target: str, query: str, limit: int) -> None:
        self._jobs[job_id]["status"] = "running"
        result = await self._search_async(target=target, query=query, limit=limit)
        self._jobs[job_id]["status"] = "completed" if result.get("ok") else "failed"
        self._jobs[job_id]["finished_at"] = datetime.now(tz=UTC).isoformat()
        self._jobs[job_id]["result"] = result

    async def _host_lookup_async(self, *, target: str) -> Dict[str, Any]:
        api = self._build_api_client()
        if isinstance(api, SemanticError):
            return self._error_from_semantic(api)

        scope_err = self._scope_error(target)
        if scope_err:
            return self._error("scope_violation", scope_err)

        credit_err = await self._credit_guardrail(api=api, planned_queries=1)
        if credit_err:
            return self._error_from_semantic(credit_err)

        try:
            host_data = await asyncio.to_thread(api.host, target)
            summaries = [self._normalize_host(target=target, host_payload=host_data)]
            report = await self._persist_report(
                query_type="host",
                target=target,
                query=f"host:{target}",
                summaries=summaries,
            )
            await self._audit("host_lookup", target=target, query=f"host:{target}", ok=True, error="")
            return report
        except ShodanAPIError as exc:
            sem = self._translate_api_error(str(exc))
            await self._audit("host_lookup", target=target, query=f"host:{target}", ok=False, error=sem.message)
            return self._error_from_semantic(sem)

    async def _search_async(self, *, target: str, query: str, limit: int) -> Dict[str, Any]:
        api = self._build_api_client()
        if isinstance(api, SemanticError):
            return self._error_from_semantic(api)

        query_s = (query or "").strip()
        if not query_s or len(query_s) > _MAX_QUERY_LENGTH:
            return self._error("invalid_query", f"Query must be 1..{_MAX_QUERY_LENGTH} characters")

        scope_err = self._scope_error(target)
        if scope_err:
            return self._error("scope_violation", scope_err)

        safe_limit = max(1, min(int(limit), _MAX_LIMIT))
        credit_err = await self._credit_guardrail(api=api, planned_queries=1)
        if credit_err:
            return self._error_from_semantic(credit_err)

        try:
            result = await asyncio.to_thread(api.search, query_s, limit=safe_limit)
            matches = result.get("matches", []) if isinstance(result, dict) else []
            summaries = self._normalize_search_matches(target=target, matches=matches)
            report = await self._persist_report(
                query_type="search",
                target=target,
                query=query_s,
                summaries=summaries,
            )
            await self._record_credit_use(units=1)
            await self._audit("search", target=target, query=query_s, ok=True, error="")
            return report
        except ShodanAPIError as exc:
            sem = self._translate_api_error(str(exc))
            await self._audit("search", target=target, query=query_s, ok=False, error=sem.message)
            return self._error_from_semantic(sem)

    def _build_api_client(self) -> Any:
        if shodan is None:
            return SemanticError(
                code="missing_dependency",
                message="Official shodan Python package is not installed",
                retryable=False,
                category="dependency",
            )
        api_key = (get_env_var_value("SHODAN_API_KEY") or "").strip()
        if not api_key or api_key == "HIDDEN_BY_POLICY":
            return SemanticError(
                code="missing_api_key",
                message="SHODAN_API_KEY is not configured in environment manager",
                retryable=False,
                category="configuration",
            )
        return shodan.Shodan(api_key)

    def _scope_error(self, target: str) -> Optional[str]:
        token = (target or "").strip()
        if not token:
            return "target is required for scope validation"

        allowed = self._allowed_scope_tokens()
        if not allowed:
            return None
        if self._token_in_scope(token, allowed):
            return None
        return f"Target {target} is outside allowed scope"

    @staticmethod
    def _allowed_scope_tokens() -> List[str]:
        raw = ",".join(
            [
                os.getenv("CERBERUS_ENGAGEMENT_SCOPE", ""),
                os.getenv("CERBERUS_ALLOWED_TARGETS", ""),
            ]
        )
        return [item.strip() for item in raw.split(",") if item.strip()]

    @staticmethod
    def _token_in_scope(token: str, allowed: Sequence[str]) -> bool:
        token_l = token.lower()
        if token_l in {a.lower() for a in allowed}:
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
                    if int(token_net.network_address) >= int(allow_net.network_address) and int(token_net.broadcast_address) <= int(allow_net.broadcast_address):
                        return True
        return False

    async def _credit_guardrail(self, *, api: Any, planned_queries: int) -> Optional[SemanticError]:
        quota_raw = (os.getenv("CERBERUS_SHODAN_QUERY_QUOTA", "") or "").strip()
        usage = await self._read_quota_state()
        if quota_raw.isdigit():
            quota = int(quota_raw)
            if usage + planned_queries > quota:
                return SemanticError(
                    code="project_quota_exceeded",
                    message="Planned Shodan query would exceed project quota budget",
                    retryable=True,
                    category="quota",
                )

        try:
            info = await asyncio.to_thread(api.info)
            credits = int(info.get("query_credits", 0)) if isinstance(info, dict) else 0
            if credits < planned_queries:
                return SemanticError(
                    code="query_credit_exhausted",
                    message="Insufficient Shodan query credits",
                    retryable=True,
                    category="quota",
                )
        except ShodanAPIError as exc:
            sem = self._translate_api_error(str(exc))
            if sem.code in {"query_credit_exhausted", "rate_limited"}:
                return sem
        return None

    async def _read_quota_state(self) -> int:
        def _read() -> int:
            if not self._quota_state.exists():
                return 0
            with suppress(Exception):
                payload = json.loads(self._quota_state.read_text(encoding="utf-8"))
                if isinstance(payload, dict):
                    return int(payload.get("used_queries", 0))
            return 0

        return await asyncio.to_thread(_read)

    async def _record_credit_use(self, units: int) -> None:
        def _write() -> None:
            current = 0
            if self._quota_state.exists():
                with suppress(Exception):
                    obj = json.loads(self._quota_state.read_text(encoding="utf-8"))
                    if isinstance(obj, dict):
                        current = int(obj.get("used_queries", 0))
            payload = {
                "updated_at": datetime.now(tz=UTC).isoformat(),
                "used_queries": current + max(0, int(units)),
            }
            self._quota_state.parent.mkdir(parents=True, exist_ok=True)
            self._quota_state.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")

        await asyncio.to_thread(_write)

    def _normalize_search_matches(self, *, target: str, matches: Sequence[Dict[str, Any]]) -> List[ShodanTargetSummary]:
        grouped: Dict[str, Dict[str, Any]] = {}
        for row in matches:
            ip = str(row.get("ip_str") or "").strip()
            if not ip:
                continue
            bucket = grouped.setdefault(
                ip,
                {
                    "host_ip": ip,
                    "hostnames": set(),
                    "ports": set(),
                    "services": [],
                    "cves": set(),
                    "ssl": {},
                    "asn": str(row.get("asn") or ""),
                    "location": row.get("location") or {},
                },
            )
            for name in row.get("hostnames") or []:
                bucket["hostnames"].add(str(name))
            port = row.get("port")
            if isinstance(port, int):
                bucket["ports"].add(port)

            service = ServiceSummary(
                port=int(port or 0),
                transport=str(row.get("transport") or ""),
                service=str(row.get("_shodan", {}).get("module") or ""),
                product=str(row.get("product") or ""),
                version=str(row.get("version") or ""),
                banner_excerpt=self._redact_banner(str(row.get("data") or ""), target=target),
            )
            bucket["services"].append(service)

            vulns = row.get("vulns") or {}
            if isinstance(vulns, dict):
                for cve in vulns.keys():
                    bucket["cves"].add(str(cve))
            elif isinstance(vulns, list):
                for cve in vulns:
                    bucket["cves"].add(str(cve))

            ssl_data = row.get("ssl") or {}
            if isinstance(ssl_data, dict) and not bucket["ssl"]:
                bucket["ssl"] = ssl_data

        summaries: List[ShodanTargetSummary] = []
        for ip, data in grouped.items():
            summaries.append(
                ShodanTargetSummary(
                    target=target,
                    host_ip=ip,
                    hostnames=sorted(data["hostnames"]),
                    open_ports=sorted(data["ports"]),
                    services=data["services"][:80],
                    vulnerabilities=VulnerabilitySummary(cves=sorted(data["cves"])),
                    certificate=self._certificate_summary(data.get("ssl") or {}),
                    location=self._location_summary(data.get("location") or {}, data.get("asn") or ""),
                )
            )
        return summaries[:50]

    def _normalize_host(self, *, target: str, host_payload: Dict[str, Any]) -> ShodanTargetSummary:
        services: List[ServiceSummary] = []
        cves: set[str] = set()
        ssl_data: Dict[str, Any] = {}
        for row in host_payload.get("data") or []:
            if not isinstance(row, dict):
                continue
            port = int(row.get("port") or 0)
            services.append(
                ServiceSummary(
                    port=port,
                    transport=str(row.get("transport") or ""),
                    service=str(row.get("_shodan", {}).get("module") or ""),
                    product=str(row.get("product") or ""),
                    version=str(row.get("version") or ""),
                    banner_excerpt=self._redact_banner(str(row.get("data") or ""), target=target),
                )
            )

            vulns = row.get("vulns") or {}
            if isinstance(vulns, dict):
                for cve in vulns.keys():
                    cves.add(str(cve))
            elif isinstance(vulns, list):
                for cve in vulns:
                    cves.add(str(cve))

            if not ssl_data and isinstance(row.get("ssl"), dict):
                ssl_data = row.get("ssl") or {}

        ports = sorted({int(p) for p in (host_payload.get("ports") or []) if isinstance(p, int)})
        return ShodanTargetSummary(
            target=target,
            host_ip=str(host_payload.get("ip_str") or ""),
            hostnames=[str(x) for x in (host_payload.get("hostnames") or [])][:50],
            open_ports=ports,
            services=services[:120],
            vulnerabilities=VulnerabilitySummary(cves=sorted(cves)),
            certificate=self._certificate_summary(ssl_data),
            location=self._location_summary(host_payload.get("location") or {}, str(host_payload.get("asn") or "")),
        )

    @staticmethod
    def _certificate_summary(ssl_data: Dict[str, Any]) -> CertificateSummary:
        cert = ssl_data.get("cert") if isinstance(ssl_data, dict) else {}
        cert = cert if isinstance(cert, dict) else {}
        subject_raw = cert.get("subject")
        issuer_raw = cert.get("issuer")
        subject: Dict[str, Any] = subject_raw if isinstance(subject_raw, dict) else {}
        issuer: Dict[str, Any] = issuer_raw if isinstance(issuer_raw, dict) else {}
        return CertificateSummary(
            subject_cn=str(subject.get("CN") or ""),
            issuer_cn=str(issuer.get("CN") or ""),
            valid_from=str(cert.get("issued") or ""),
            valid_until=str(cert.get("expires") or ""),
            serial=str(cert.get("serial") or ""),
        )

    @staticmethod
    def _location_summary(location: Dict[str, Any], asn: str) -> LocationSummary:
        return LocationSummary(
            country=str(location.get("country_name") or ""),
            city=str(location.get("city") or ""),
            region=str(location.get("region_code") or ""),
            latitude=location.get("latitude") if isinstance(location.get("latitude"), (int, float)) else None,
            longitude=location.get("longitude") if isinstance(location.get("longitude"), (int, float)) else None,
            asn=asn,
        )

    def _redact_banner(self, text: str, *, target: str) -> str:
        cleaned = text[:1000]
        cleaned = _EMAIL_RE.sub("[REDACTED_EMAIL]", cleaned)
        cleaned = _FROM_NAME_RE.sub("From: [REDACTED_NAME] \\2", cleaned)

        allowed_ips: set[str] = set()
        with suppress(Exception):
            ipaddress.ip_address(target)
            allowed_ips.add(target)

        def _replace_ip(match: re.Match[str]) -> str:
            ip_txt = match.group(0)
            with suppress(Exception):
                ipaddress.ip_address(ip_txt)
                if ip_txt in allowed_ips:
                    return ip_txt
                return "[REDACTED_IP]"
            return ip_txt

        cleaned = _IPV4_RE.sub(_replace_ip, cleaned)
        return cleaned

    async def _persist_report(
        self,
        *,
        query_type: str,
        target: str,
        query: str,
        summaries: List[ShodanTargetSummary],
    ) -> Dict[str, Any]:
        timestamp = datetime.now(tz=UTC)
        stamp = timestamp.strftime("%Y%m%dT%H%M%SZ")
        target_slug = re.sub(r"[^A-Za-z0-9._-]+", "_", target).strip("_")[:80] or "target"
        path = self._evidence_dir / f"SHODAN_{query_type}_{target_slug}_{stamp}.json"

        report = ShodanReport(
            ok=True,
            query_type=query_type,
            target=target,
            query=query,
            generated_at=timestamp.isoformat(),
            summaries=summaries,
            evidence_path=self._display_path(path),
        )
        payload = clean_data(report.model_dump())

        def _write() -> None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")

        await asyncio.to_thread(_write)
        return payload

    async def _audit(self, event: str, *, target: str, query: str, ok: bool, error: str) -> None:
        row = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "event": event,
            "target": target,
            "query": query,
            "ok": ok,
            "error": error[:800],
        }
        line = json.dumps(clean_data(row), ensure_ascii=True) + "\n"

        def _append() -> None:
            self._audit_log.parent.mkdir(parents=True, exist_ok=True)
            with self._audit_log.open("a", encoding="utf-8") as handle:
                handle.write(line)

        await asyncio.to_thread(_append)
        if self._logger is not None:
            with suppress(Exception):
                self._logger.audit("shodan event", actor="shodan", data=clean_data(row), tags=["shodan", event])

    @staticmethod
    def _translate_api_error(message: str) -> SemanticError:
        msg = (message or "").strip()
        low = msg.lower()
        if "invalid api key" in low or "access denied" in low:
            return SemanticError("invalid_key", "Shodan API key is invalid or unauthorized", False, "auth")
        if "query credits" in low or "out of query credits" in low:
            return SemanticError("query_credit_exhausted", "Shodan query credits exhausted", True, "quota")
        if "rate limit" in low or "too many requests" in low:
            return SemanticError("rate_limited", "Shodan API rate limit reached, pause and retry later", True, "throttle")
        if "no information available" in low or "not found" in low:
            return SemanticError("target_not_found", "Shodan has no indexed information for this target", False, "data")
        return SemanticError("api_error", msg or "Shodan API request failed", True, "api")

    def _display_path(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self._workspace))
        except ValueError:
            return str(path.resolve())

    @staticmethod
    def _error(code: str, message: str) -> Dict[str, Any]:
        return {"ok": False, "error": {"code": code, "message": message}}

    @staticmethod
    def _error_from_semantic(err: SemanticError) -> Dict[str, Any]:
        return {
            "ok": False,
            "error": {
                "code": err.code,
                "message": err.message,
                "retryable": err.retryable,
                "category": err.category,
            },
        }


SHODAN_TOOL = LazyToolProxy(CerebroShodanTool)


@function_tool
def shodan_search(target: str, query: str = "", limit: int = _DEFAULT_LIMIT, wait: bool = False) -> Dict[str, Any]:
    if wait:
        return SHODAN_TOOL._run_coro(
            SHODAN_TOOL._search_async(target=target, query=query or f"ip:{target}", limit=limit),
            timeout=180.0,
        )
    return SHODAN_TOOL.start_search(target=target, query=query or f"ip:{target}", limit=limit)


@function_tool
def shodan_host_info(target: str, wait: bool = True) -> Dict[str, Any]:
    return SHODAN_TOOL.host_lookup(target=target, wait=wait)


@function_tool
def shodan_job_status(job_id: str) -> Dict[str, Any]:
    return SHODAN_TOOL.job_status(job_id)


__all__ = [
    "SemanticError",
    "VulnerabilitySummary",
    "CertificateSummary",
    "LocationSummary",
    "ServiceSummary",
    "ShodanTargetSummary",
    "ShodanReport",
    "CerebroShodanTool",
    "SHODAN_TOOL",
    "shodan_search",
    "shodan_host_info",
    "shodan_job_status",
]
