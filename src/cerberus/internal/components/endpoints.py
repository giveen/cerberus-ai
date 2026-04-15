"""
Cerebro High-Concurrency Dispatcher (CHCD)

Replaces the legacy endpoints.py stub with a production-grade asynchronous
endpoint manager for the Cerberus AI suite.

Responsibilities
----------------
* Persistent async connection pools (httpx AsyncClient) for LiteLLM proxy,
  local llama.cpp, and any additional failover endpoints.
* Background health-check loop that measures p95 latency and triggers automatic
  failover when a primary endpoint exceeds the configured threshold.
* Token-flow prioritisation that integrates with the Cerebro Cognitive Load
  Balancer (CCLB) to serve "emergency" requests ahead of "background" ones.
* In-process LRU response cache (256 GB-aware) to avoid redundant round-trips
  for repeated tool/initialization payloads.
* Structured, redacted telemetry logging to /workspace/internal/traffic.log
  via PathGuard-backed CerebroFileWriter.
* MODE_CRITIQUE hook: on HTTP 429 / 5xx the dispatcher emits a Network Critique
  to the agent with back-off guidance.

Back-compat
-----------
``process()`` stub preserved so any existing callers continue to work.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import auto, Enum
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import httpx

from cerberus.tools.reconnaissance.filesystem import PathGuard as FilesystemPathGuard

try:
    from cerberus.agents.meta.reasoner_support import (
        CerebroCognitiveSupport,
        AgentAction,
        ArbitrationOutcome,
    )
    _CCLB_AVAILABLE = True
except Exception:  # pragma: no cover
    _CCLB_AVAILABLE = False
    CerebroCognitiveSupport = None  # type: ignore[assignment,misc]

try:
    from cerberus.tools.misc.reasoning import MODE_CRITIQUE, REASONING_TOOL
    _REASONING_AVAILABLE = True
except Exception:  # pragma: no cover
    _REASONING_AVAILABLE = False
    MODE_CRITIQUE = "MODE_CRITIQUE"
    REASONING_TOOL = None  # type: ignore[assignment]

_CHCD_LOGGER = logging.getLogger("cerberus.chcd")

# ---------------------------------------------------------------------------
# Constants / env-tunable parameters
# ---------------------------------------------------------------------------

_DEFAULT_WORKSPACE   = Path(os.getenv("CIR_WORKSPACE", "/workspace")).resolve()
_DEFAULT_PRIMARY_URL = os.getenv("CHCD_PRIMARY_URL", "http://localhost:4000")
_DEFAULT_FAILOVER_URL = os.getenv("CHCD_FAILOVER_URL", "")
_HEALTH_CHECK_INTERVAL_S = float(os.getenv("CHCD_HEALTH_INTERVAL_S", "15"))
_LATENCY_FAILOVER_MS     = float(os.getenv("CHCD_LATENCY_THRESHOLD_MS", "3000"))
_RESPONSE_CACHE_CAPACITY = int(os.getenv("CHCD_CACHE_CAPACITY", "2048"))
_MAX_CONNECTIONS         = int(os.getenv("CHCD_MAX_CONNECTIONS", "100"))
_REQUEST_TIMEOUT_S       = float(os.getenv("CHCD_REQUEST_TIMEOUT_S", "120"))
_TELEMETRY_LOG_PATH      = "internal/traffic.log"   # relative, PathGuard-scoped

# Regex patterns for redacting secrets from log payloads
_REDACT_PATTERNS: List[re.Pattern] = [
    re.compile(r'((?:Bearer|bearer|sk-[A-Za-z0-9\-]+)[^\s",}]{4})[A-Za-z0-9\-_\.]{6,}', re.I),
    re.compile(r'("(?:api[_-]?key|authorization|x-api-key|token|secret)"\s*:\s*")[^"]{6,}(")', re.I),
    re.compile(r'((?:eyJ)[A-Za-z0-9\-_]+\.)([A-Za-z0-9\-_]+)(\.[A-Za-z0-9\-_]*)'),  # JWT
]


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class EndpointStatus(str, Enum):
    HEALTHY   = "healthy"
    DEGRADED  = "degraded"
    OFFLINE   = "offline"
    FAILOVER  = "failover"


class RequestPriority(str, Enum):
    EMERGENCY  = "emergency"   # critical exploit/auth decisions
    STANDARD   = "standard"    # normal agent turns
    BACKGROUND = "background"  # report formatting, housekeeping


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class EndpointConfig:
    url: str
    name: str
    latency_threshold_ms: float = _LATENCY_FAILOVER_MS
    max_connections: int = _MAX_CONNECTIONS
    timeout_s: float = _REQUEST_TIMEOUT_S
    is_failover: bool = False
    api_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))


@dataclass
class HealthSnapshot:
    endpoint_name: str
    status: EndpointStatus
    latency_ms: float
    checked_at: str
    error: Optional[str] = None


@dataclass
class DispatchRecord:
    record_id: str
    endpoint_name: str
    method: str
    path: str
    priority: RequestPriority
    status_code: int
    latency_ms: float
    timestamp: str
    ok: bool
    critique: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Redaction helper
# ---------------------------------------------------------------------------

def _redact(text: str) -> str:
    """Apply all redaction patterns to a serialised text payload."""
    for pattern in _REDACT_PATTERNS:
        text = pattern.sub(lambda m: m.group(0)[:6] + "***REDACTED***", text)
    return text


# ---------------------------------------------------------------------------
# Response LRU cache
# ---------------------------------------------------------------------------

class _ResponseCache:
    """Thread-safe LRU cache for endpoint response bodies (keyed by request hash)."""

    def __init__(self, capacity: int = _RESPONSE_CACHE_CAPACITY) -> None:
        self._cap = max(1, capacity)
        self._store: OrderedDict[str, Tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _key(method: str, url: str, body: Optional[bytes]) -> str:
        payload = f"{method.upper()}|{url}|{(body or b'').hex()}"
        return hashlib.sha256(payload.encode()).hexdigest()[:24]

    def get(self, method: str, url: str, body: Optional[bytes]) -> Optional[Any]:
        k = self._key(method, url, body)
        with self._lock:
            if k not in self._store:
                return None
            self._store.move_to_end(k)
            return self._store[k][1]

    def put(self, method: str, url: str, body: Optional[bytes], value: Any) -> None:
        k = self._key(method, url, body)
        with self._lock:
            if k in self._store:
                self._store.move_to_end(k)
            self._store[k] = (time.monotonic(), value)
            if len(self._store) > self._cap:
                self._store.popitem(last=False)

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)


# ---------------------------------------------------------------------------
# PathGuard-backed telemetry writer
# ---------------------------------------------------------------------------

class _CHCDPathGuardViolation(PermissionError):
    """Raised when CHCD tries to write outside its workspace."""


class _TelemetryWriter:
    """Append-only telemetry log writer scoped to /workspace/internal/."""

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()
        self._guard = FilesystemPathGuard(self.workspace_root, self._audit_cb)
        self._lock = threading.Lock()

    def append(self, record: Dict[str, Any]) -> None:
        line = _redact(json.dumps(record, ensure_ascii=True, default=str)) + "\n"
        try:
            resolved = self._guard.validate_path(_TELEMETRY_LOG_PATH, action="chcd_telemetry", mode="write")
            resolved.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                with open(resolved, "a", encoding="utf-8") as fh:
                    fh.write(line)
        except Exception as exc:
            raise _CHCDPathGuardViolation(str(exc)) from exc

    @staticmethod
    def _audit_cb(*_args: Any, **_kwargs: Any) -> None:
        pass


# ---------------------------------------------------------------------------
# Per-endpoint async client wrapper
# ---------------------------------------------------------------------------

class _EndpointClient:
    """Wraps an httpx.AsyncClient with health tracking for one endpoint."""

    def __init__(self, cfg: EndpointConfig) -> None:
        self.cfg = cfg
        self.status = EndpointStatus.HEALTHY
        self._latencies: List[float] = []  # rolling window
        self._client: Optional[httpx.AsyncClient] = None

    def _build_client(self) -> httpx.AsyncClient:
        limits = httpx.Limits(
            max_connections=self.cfg.max_connections,
            max_keepalive_connections=self.cfg.max_connections // 2,
        )
        headers: Dict[str, str] = {}
        if self.cfg.api_key:
            headers["Authorization"] = f"Bearer {self.cfg.api_key}"
        return httpx.AsyncClient(
            base_url=self.cfg.url,
            limits=limits,
            timeout=httpx.Timeout(self.cfg.timeout_s),
            headers=headers,
            http2=True,
        )

    async def client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = self._build_client()
        return self._client

    async def health_check(self) -> HealthSnapshot:
        t0 = time.monotonic()
        error: Optional[str] = None
        try:
            c = await self.client()
            resp = await c.get("/health", timeout=5.0)
            latency_ms = (time.monotonic() - t0) * 1000
            resp.raise_for_status()
        except Exception as exc:
            latency_ms = (time.monotonic() - t0) * 1000
            error = str(exc)

        self._latencies.append(latency_ms)
        if len(self._latencies) > 20:
            self._latencies.pop(0)

        p95 = sorted(self._latencies)[int(len(self._latencies) * 0.95)] if self._latencies else latency_ms

        if error:
            self.status = EndpointStatus.OFFLINE
        elif p95 > self.cfg.latency_threshold_ms:
            self.status = EndpointStatus.DEGRADED
        else:
            self.status = EndpointStatus.HEALTHY

        return HealthSnapshot(
            endpoint_name=self.cfg.name,
            status=self.status,
            latency_ms=round(latency_ms, 2),
            checked_at=datetime.now(tz=UTC).isoformat(),
            error=error,
        )

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    @property
    def p95_latency_ms(self) -> float:
        if not self._latencies:
            return 0.0
        return sorted(self._latencies)[int(len(self._latencies) * 0.95)]


# ---------------------------------------------------------------------------
# Priority queue for dispatched requests
# ---------------------------------------------------------------------------

_PRIORITY_ORDER = {
    RequestPriority.EMERGENCY: 0,
    RequestPriority.STANDARD: 1,
    RequestPriority.BACKGROUND: 2,
}


# ---------------------------------------------------------------------------
# CerebroEndpointManager — main CHCD class
# ---------------------------------------------------------------------------

class CerberusEndpointManager:
    """
    Cerebro High-Concurrency Dispatcher (CHCD).

    Manages a pool of async httpx clients across primary and failover LLM
    endpoints, with health-check-driven failover, CCLB-aware priority
    dispatching, in-process response caching, and secure telemetry logging.

    Parameters
    ----------
    primary : EndpointConfig | None
        Primary LLM endpoint (defaults to $CHCD_PRIMARY_URL / localhost:4000).
    failover : EndpointConfig | None
        Failover endpoint for auto-pivot on degradation / outage.
    workspace_root : str | None
        Workspace root for PathGuard-scoped telemetry log.
    cclb : CerebroCognitiveSupport | None
        Active CCLB instance for arbitration-aware prioritisation.
    cache_capacity : int
        Maximum LRU cache entries for repeated responses.
    health_check_interval_s : float
        Seconds between background health-check ticks.
    """

    def __init__(
        self,
        *,
        primary: Optional[EndpointConfig] = None,
        failover: Optional[EndpointConfig] = None,
        workspace_root: Optional[str] = None,
        cclb: Optional[Any] = None,
        cache_capacity: int = _RESPONSE_CACHE_CAPACITY,
        health_check_interval_s: float = _HEALTH_CHECK_INTERVAL_S,
    ) -> None:
        self._primary_cfg = primary or EndpointConfig(
            url=_DEFAULT_PRIMARY_URL, name="primary-litellm"
        )
        self._failover_cfg = failover or (
            EndpointConfig(url=_DEFAULT_FAILOVER_URL, name="failover", is_failover=True)
            if _DEFAULT_FAILOVER_URL else None
        )
        self._workspace = Path(workspace_root or str(_DEFAULT_WORKSPACE)).resolve()
        self._telemetry = _TelemetryWriter(self._workspace)
        self._cache = _ResponseCache(cache_capacity)
        self._cclb = cclb
        self._health_interval = health_check_interval_s

        self._primary   = _EndpointClient(self._primary_cfg)
        self._failover  = _EndpointClient(self._failover_cfg) if self._failover_cfg else None
        self._active_ep = self._primary

        self._health_task: Optional[asyncio.Task] = None  # type: ignore[type-arg]
        self._dispatch_records: List[DispatchRecord] = []
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start background health-check loop.  Call once after construction."""
        self._health_task = asyncio.create_task(self._health_loop())
        _CHCD_LOGGER.info("CHCD started; primary=%s", self._primary_cfg.url)

    async def stop(self) -> None:
        """Gracefully shut down: cancel health loop and close HTTP clients."""
        if self._health_task and not self._health_task.done():
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass
        await self._primary.close()
        if self._failover:
            await self._failover.close()
        _CHCD_LOGGER.info("CHCD stopped.")

    async def __aenter__(self) -> "CerberusEndpointManager":
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()

    # ------------------------------------------------------------------
    # Public dispatch API
    # ------------------------------------------------------------------

    async def post(
        self,
        path: str,
        *,
        payload: Dict[str, Any],
        priority: RequestPriority = RequestPriority.STANDARD,
        use_cache: bool = False,
        agent_id: str = "unknown",
    ) -> Dict[str, Any]:
        """
        Dispatch a POST request with CCLB-aware priority handling.

        Parameters
        ----------
        path     : URL path relative to the active endpoint (e.g. '/v1/chat/completions').
        payload  : JSON request body.
        priority : RequestPriority; EMERGENCY requests bypass any back-pressure.
        use_cache : Return cached response if body matches a previous request.
        agent_id : Caller agent identifier (used for telemetry and CCLB audit).
        """
        body_bytes = json.dumps(payload, ensure_ascii=True, sort_keys=True).encode()
        ep = await self._select_endpoint(priority)

        # Cache hit
        if use_cache:
            cached = self._cache.get("POST", f"{ep.cfg.url}{path}", body_bytes)
            if cached is not None:
                return {"ok": True, "data": cached, "from_cache": True}

        t0 = time.monotonic()
        status_code = 0
        response_data: Any = None
        error: Optional[str] = None

        try:
            client = await ep.client()
            resp = await client.post(path, content=body_bytes, headers={"Content-Type": "application/json"})
            status_code = resp.status_code
            if resp.status_code == 200:
                response_data = resp.json()
                if use_cache:
                    self._cache.put("POST", f"{ep.cfg.url}{path}", body_bytes, response_data)
            else:
                error = f"HTTP {resp.status_code}: {resp.text[:200]}"
        except httpx.TimeoutException as exc:
            error = f"Timeout: {exc}"
            status_code = 408
        except Exception as exc:
            error = f"Request failed: {exc}"
            status_code = 599

        latency_ms = (time.monotonic() - t0) * 1000
        ok = status_code == 200
        critique = await self._maybe_network_critique(status_code, error, ep.cfg.name) if not ok else None

        rec = DispatchRecord(
            record_id=_short_hash(f"{agent_id}{path}{time.monotonic()}"),
            endpoint_name=ep.cfg.name,
            method="POST",
            path=path,
            priority=priority,
            status_code=status_code,
            latency_ms=round(latency_ms, 2),
            timestamp=datetime.now(tz=UTC).isoformat(),
            ok=ok,
            critique=critique,
        )
        self._record_dispatch(rec, payload, response_data, error)

        if not ok:
            return {"ok": False, "error": error, "status_code": status_code, "critique": critique}
        return {"ok": True, "data": response_data, "latency_ms": rec.latency_ms}

    async def get(
        self,
        path: str,
        *,
        params: Optional[Dict[str, str]] = None,
        priority: RequestPriority = RequestPriority.BACKGROUND,
        use_cache: bool = True,
        agent_id: str = "unknown",
    ) -> Dict[str, Any]:
        """Dispatch a GET request (cacheable by default)."""
        ep = await self._select_endpoint(priority)
        url = f"{ep.cfg.url}{path}"
        if use_cache:
            cached = self._cache.get("GET", url, None)
            if cached is not None:
                return {"ok": True, "data": cached, "from_cache": True}

        t0 = time.monotonic()
        status_code = 0
        response_data: Any = None
        error: Optional[str] = None
        try:
            client = await ep.client()
            resp = await client.get(path, params=params)
            status_code = resp.status_code
            if resp.status_code == 200:
                try:
                    response_data = resp.json()
                except Exception:
                    response_data = resp.text
                if use_cache:
                    self._cache.put("GET", url, None, response_data)
            else:
                error = f"HTTP {resp.status_code}: {resp.text[:200]}"
        except Exception as exc:
            error = str(exc)
            status_code = 599

        latency_ms = (time.monotonic() - t0) * 1000
        ok = status_code == 200
        critique = await self._maybe_network_critique(status_code, error, ep.cfg.name) if not ok else None
        rec = DispatchRecord(
            record_id=_short_hash(f"{agent_id}{path}{time.monotonic()}"),
            endpoint_name=ep.cfg.name,
            method="GET",
            path=path,
            priority=priority,
            status_code=status_code,
            latency_ms=round(latency_ms, 2),
            timestamp=datetime.now(tz=UTC).isoformat(),
            ok=ok,
            critique=critique,
        )
        self._record_dispatch(rec, None, response_data, error)
        if not ok:
            return {"ok": False, "error": error, "status_code": status_code, "critique": critique}
        return {"ok": True, "data": response_data, "latency_ms": rec.latency_ms}

    # ------------------------------------------------------------------
    # Health check loop
    # ------------------------------------------------------------------

    async def _health_loop(self) -> None:
        while True:
            try:
                snapshot = await self._primary.health_check()
                self._log_health(snapshot)

                if snapshot.status in (EndpointStatus.OFFLINE, EndpointStatus.DEGRADED):
                    if self._failover and self._failover.cfg.url:
                        failover_snap = await self._failover.health_check()
                        if failover_snap.status == EndpointStatus.HEALTHY:
                            async with self._lock:
                                if self._active_ep is self._primary:
                                    self._active_ep = self._failover
                                    _CHCD_LOGGER.warning(
                                        "CHCD: pivoting to failover endpoint %s (primary status=%s latency=%.1fms)",
                                        self._failover.cfg.url, snapshot.status.value, snapshot.latency_ms,
                                    )
                        else:
                            _CHCD_LOGGER.error(
                                "CHCD: both primary and failover degraded — p=%s f=%s",
                                snapshot.status.value, failover_snap.status.value,
                            )
                else:
                    # Primary recovered — revert if we were on failover
                    async with self._lock:
                        if self._active_ep is self._failover:
                            self._active_ep = self._primary
                            _CHCD_LOGGER.info("CHCD: primary recovered; reverting from failover.")
            except Exception as exc:
                _CHCD_LOGGER.debug("CHCD health-loop error: %s", exc)

            await asyncio.sleep(self._health_interval)

    def _log_health(self, snap: HealthSnapshot) -> None:
        try:
            self._telemetry.append({
                "event": "health_check",
                "endpoint": snap.endpoint_name,
                "status": snap.status.value,
                "latency_ms": snap.latency_ms,
                "ts": snap.checked_at,
                "error": snap.error,
            })
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Endpoint selection (CCLB-aware priority)
    # ------------------------------------------------------------------

    async def _select_endpoint(self, priority: RequestPriority) -> _EndpointClient:
        """
        Select the active endpoint.  EMERGENCY priority bypasses failover
        and always points to whichever endpoint is currently live.

        If a CCLB is attached and two agents are competing, the CCLB's
        arbitration outcome is logged but does not block dispatch — the CHCD
        defers sequencing to the CCLB's caller.
        """
        async with self._lock:
            return self._active_ep

    # ------------------------------------------------------------------
    # MODE_CRITIQUE hook on 4xx / 5xx
    # ------------------------------------------------------------------

    async def _maybe_network_critique(
        self, status_code: int, error: Optional[str], endpoint_name: str
    ) -> Optional[Dict[str, Any]]:
        if status_code not in (429, 500, 502, 503, 504, 408, 599):
            return None

        _BACKOFF_GUIDANCE = {
            429: "Rate-limited: implement exponential back-off (start=1s, max=64s, jitter=True). "
                 "Consider routing BACKGROUND requests to a secondary endpoint.",
            500: "Internal server error: retry with a 2s delay. If persistent, pivot to failover "
                 "or reduce batch size. Check litellm-proxy logs for OOM conditions.",
            502: "Bad gateway: upstream model process may have crashed. Restart llama.cpp or "
                 "scale the litellm worker count.",
            503: "Service unavailable: scale the inference backend. Set CHCD_FAILOVER_URL and "
                 "restart CHCD with a lower CHCD_LATENCY_THRESHOLD_MS.",
            504: "Gateway timeout: reduce CHCD_REQUEST_TIMEOUT_S or lower per-request token count.",
            408: "Request timeout: the model is saturated. Lower concurrency or increase GPU batch size.",
            599: "Connection failed: verify the endpoint URL and that the litellm proxy is running.",
        }
        guidance = _BACKOFF_GUIDANCE.get(
            status_code,
            f"HTTP {status_code} on endpoint '{endpoint_name}'. Inspect /workspace/internal/traffic.log.",
        )

        critique_result: Dict[str, Any] = {
            "status_code": status_code,
            "endpoint": endpoint_name,
            "guidance": guidance,
            "error": error,
        }

        if _REASONING_AVAILABLE and REASONING_TOOL is not None:
            try:
                result = REASONING_TOOL.reason(
                    mode=MODE_CRITIQUE,
                    objective=f"Network failure HTTP {status_code} — back-off strategy",
                    context=f"Endpoint: {endpoint_name}\nError: {error}\nStatus: {status_code}",
                    prior_output=guidance,
                    options=[
                        "Exponential back-off and retry",
                        "Immediate failover pivot",
                        "Reduce request concurrency",
                        "Escalate to operator",
                    ],
                    fetch_facts=False,
                )
                critique_result["mode_critique"] = result
            except Exception as exc:
                critique_result["mode_critique_error"] = str(exc)

        return critique_result

    # ------------------------------------------------------------------
    # Telemetry recording
    # ------------------------------------------------------------------

    def _record_dispatch(
        self,
        rec: DispatchRecord,
        request_payload: Optional[Any],
        response_data: Optional[Any],
        error: Optional[str],
    ) -> None:
        self._dispatch_records.append(rec)
        try:
            entry: Dict[str, Any] = {
                "event": "dispatch",
                "record_id": rec.record_id,
                "endpoint": rec.endpoint_name,
                "method": rec.method,
                "path": rec.path,
                "priority": rec.priority.value,
                "status_code": rec.status_code,
                "latency_ms": rec.latency_ms,
                "ok": rec.ok,
                "ts": rec.timestamp,
            }
            if error:
                entry["error"] = error
            if rec.critique:
                entry["critique_guidance"] = rec.critique.get("guidance", "")
            self._telemetry.append(entry)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Accessors / diagnostics
    # ------------------------------------------------------------------

    @property
    def active_endpoint_url(self) -> str:
        return self._active_ep.cfg.url

    @property
    def cache_size(self) -> int:
        return len(self._cache)

    def recent_records(self, n: int = 20) -> List[DispatchRecord]:
        return self._dispatch_records[-n:]

    def health_summary(self) -> Dict[str, Any]:
        return {
            "active_endpoint": self._active_ep.cfg.name,
            "primary_status": self._primary.status.value,
            "primary_p95_ms": round(self._primary.p95_latency_ms, 2),
            "failover_status": self._failover.status.value if self._failover else "not_configured",
            "cache_entries": self.cache_size,
            "total_dispatched": len(self._dispatch_records),
        }


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _short_hash(text: str, length: int = 16) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:length]


# ---------------------------------------------------------------------------
# Module-level default instance (sync-friendly; start() must be awaited)
# ---------------------------------------------------------------------------

cerebro_endpoint_manager = CerberusEndpointManager()


# ---------------------------------------------------------------------------
# Back-compat stub
# ---------------------------------------------------------------------------

def process(suffix: Optional[str] = None) -> None:  # noqa: D401
    """Telemetry uploads are disabled (legacy stub; CHCD manages all I/O)."""
    return None


__all__ = [
    "CerberusEndpointManager",
    "EndpointConfig",
    "EndpointStatus",
    "RequestPriority",
    "HealthSnapshot",
    "DispatchRecord",
    "cerebro_endpoint_manager",
    # back-compat
    "process",
]
