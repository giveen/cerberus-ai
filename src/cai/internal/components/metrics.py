"""Cerebro Performance & Telemetry Engine (CPTE).

Real-time analytics and hardware telemetry for Cerberus AI agent swarms.

Responsibilities
----------------
* Sample RAM and GPU utilisation with low overhead.
* Track cognitive velocity: tokens-per-second, thought latency, and
  reasoning-to-execution ratio.
* Aggregate offensive efficacy outcomes per agent and per capability.
* Export a heartbeat snapshot to /workspace/internal/metrics.json every 60s via
  PathGuard-protected writer.
* Detect anomalies such as memory spikes and sustained success-rate collapse.
* Provide MODE_CRITIQUE bottleneck guidance when performance degrades.

Back-compat
-----------
``process_metrics`` and ``process_intermediate_logs`` are preserved.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
import json
import logging
import os
from pathlib import Path
import threading
import time
from typing import Any, Deque, Dict, Iterable, List, Literal, Optional, Tuple

from cai.tools.reconnaissance.filesystem import PathGuard as FilesystemPathGuard

try:
    import psutil  # type: ignore
    _PSUTIL_AVAILABLE = True
except Exception:  # pragma: no cover
    psutil = None  # type: ignore[assignment]
    _PSUTIL_AVAILABLE = False

try:
    import pynvml  # type: ignore
    _PYNVML_AVAILABLE = True
except Exception:  # pragma: no cover
    pynvml = None  # type: ignore[assignment]
    _PYNVML_AVAILABLE = False

try:
    from cai.tools.misc.reasoning import MODE_CRITIQUE, REASONING_TOOL
    _REASONING_AVAILABLE = True
except Exception:  # pragma: no cover
    MODE_CRITIQUE = "MODE_CRITIQUE"
    REASONING_TOOL = None  # type: ignore[assignment]
    _REASONING_AVAILABLE = False


_CPTE_LOGGER = logging.getLogger("cai.cpte")

_DEFAULT_WORKSPACE = Path(os.getenv("CIR_WORKSPACE", "/workspace")).resolve()
_HEARTBEAT_INTERVAL_S = float(os.getenv("CPTE_HEARTBEAT_INTERVAL_S", "60"))
_MEMORY_SPIKE_THRESHOLD_PCT = float(os.getenv("CPTE_MEMORY_SPIKE_THRESHOLD_PCT", "12"))
_SUCCESS_DROP_THRESHOLD = float(os.getenv("CPTE_SUCCESS_DROP_THRESHOLD", "0.30"))
_VRAM_ALERT_THRESHOLD_PCT = float(os.getenv("CPTE_VRAM_ALERT_THRESHOLD_PCT", "92"))
_THOUGHT_LATENCY_ALERT_MS = float(os.getenv("CPTE_THOUGHT_LATENCY_ALERT_MS", "7000"))
_RATIO_ALERT_THRESHOLD = float(os.getenv("CPTE_REASON_EXEC_RATIO_ALERT", "4.0"))
_MAX_SAMPLE_POINTS = int(os.getenv("CPTE_MAX_SAMPLE_POINTS", "512"))
_METRICS_PATH = "internal/metrics.json"

OutcomeCategory = Literal["Success", "Blocked_by_WAF", "Timed_Out", "System_Error"]


@dataclass
class GPUStats:
    gpu_name: str = "unavailable"
    vram_used_mb: float = 0.0
    vram_total_mb: float = 0.0
    vram_pct: float = 0.0
    compute_util_pct: float = 0.0
    temperature_c: Optional[float] = None
    power_draw_w: Optional[float] = None
    power_limit_w: Optional[float] = None
    sampled_at: str = field(default_factory=lambda: datetime.now(tz=UTC).isoformat())


@dataclass
class SystemMemoryStats:
    ram_used_gb: float
    ram_total_gb: float
    ram_pct: float
    process_rss_gb: float
    sampled_at: str = field(default_factory=lambda: datetime.now(tz=UTC).isoformat())


@dataclass
class CognitiveVelocityStats:
    tps_avg: float = 0.0
    thought_latency_ms_avg: float = 0.0
    reasoning_to_execution_ratio: float = 0.0
    samples: int = 0


@dataclass
class OffensiveEfficacyStats:
    success: int = 0
    blocked_by_waf: int = 0
    timed_out: int = 0
    system_error: int = 0
    handshake_attempts: int = 0
    handshake_successes: int = 0
    shell_attempts: int = 0
    shell_successes: int = 0

    @property
    def total(self) -> int:
        return self.success + self.blocked_by_waf + self.timed_out + self.system_error

    @property
    def success_rate(self) -> float:
        return self.success / self.total if self.total else 0.0

    @property
    def handshake_capture_rate(self) -> float:
        return self.handshake_successes / self.handshake_attempts if self.handshake_attempts else 0.0

    @property
    def shell_conversion_rate(self) -> float:
        return self.shell_successes / self.shell_attempts if self.shell_attempts else 0.0


@dataclass
class AnomalyAlert:
    alert_type: str
    severity: str
    message: str
    created_at: str = field(default_factory=lambda: datetime.now(tz=UTC).isoformat())
    critique: Optional[Dict[str, Any]] = None


@dataclass
class HeartbeatSnapshot:
    session_id: str
    created_at: str
    gpu: GPUStats
    memory: SystemMemoryStats
    cognitive_velocity: CognitiveVelocityStats
    offensive_efficacy: Dict[str, OffensiveEfficacyStats]
    active_alerts: List[AnomalyAlert]
    total_events: int


class _CPTEPathGuardViolation(PermissionError):
    """Raised when CPTE attempts to write outside the workspace."""


class _MetricsWriter:
    """PathGuard-backed writer for internal metrics exports."""

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()
        self._guard = FilesystemPathGuard(self.workspace_root, self._audit)
        self._lock = threading.Lock()

    def write_json(self, relative_path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            resolved = self._guard.validate_path(relative_path, action="cpte_write", mode="write")
        except Exception as exc:
            raise _CPTEPathGuardViolation(str(exc)) from exc
        resolved.parent.mkdir(parents=True, exist_ok=True)
        body = json.dumps(payload, ensure_ascii=True, indent=2, default=str)
        with self._lock:
            resolved.write_text(body, encoding="utf-8")
        return {"ok": True, "path": str(resolved), "bytes_written": len(body.encode("utf-8"))}

    @staticmethod
    def _audit(*_args: Any, **_kwargs: Any) -> None:
        pass


class CerebroMetricsEngine:
    """Non-blocking performance telemetry engine for Cerberus AI."""

    def __init__(
        self,
        *,
        session_id: Optional[str] = None,
        workspace_root: Optional[str] = None,
        heartbeat_interval_s: float = _HEARTBEAT_INTERVAL_S,
    ) -> None:
        self.session_id = session_id or self._make_session_id()
        self.workspace_root = Path(workspace_root or str(_DEFAULT_WORKSPACE)).resolve()
        self._writer = _MetricsWriter(self.workspace_root)
        self._heartbeat_interval_s = max(5.0, float(heartbeat_interval_s))

        self._lock = threading.Lock()
        self._nvml_ready = False
        self._nvml_handle: Any = None
        self._alerts: Deque[AnomalyAlert] = deque(maxlen=64)

        self._tps_samples: Deque[float] = deque(maxlen=_MAX_SAMPLE_POINTS)
        self._thought_latency_ms_samples: Deque[float] = deque(maxlen=_MAX_SAMPLE_POINTS)
        self._reason_exec_ratio_samples: Deque[float] = deque(maxlen=_MAX_SAMPLE_POINTS)
        self._ram_pct_samples: Deque[float] = deque(maxlen=_MAX_SAMPLE_POINTS)
        self._event_count = 0

        self._efficacy: Dict[str, OffensiveEfficacyStats] = defaultdict(OffensiveEfficacyStats)
        self._task_assignments: Dict[str, float] = {}
        self._last_snapshot: Optional[HeartbeatSnapshot] = None
        self._heartbeat_task: Optional[asyncio.Task[Any]] = None

        self._init_nvml()

    async def start(self) -> None:
        if self._heartbeat_task is None or self._heartbeat_task.done():
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    async def stop(self) -> None:
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        self._shutdown_nvml()

    async def __aenter__(self) -> "CerebroMetricsEngine":
        await self.start()
        return self

    async def __aexit__(self, *_args: Any) -> None:
        await self.stop()

    def record_token_flow(
        self,
        *,
        tokens: int,
        duration_s: float,
        task_id: Optional[str] = None,
        thought_latency_ms: Optional[float] = None,
        reasoning_duration_s: Optional[float] = None,
        execution_duration_s: Optional[float] = None,
    ) -> None:
        t0 = time.perf_counter()
        tps = float(tokens) / max(duration_s, 1e-6)
        ratio = 0.0
        if reasoning_duration_s is not None and execution_duration_s is not None:
            ratio = reasoning_duration_s / max(execution_duration_s, 1e-6)

        with self._lock:
            self._tps_samples.append(tps)
            if thought_latency_ms is not None:
                self._thought_latency_ms_samples.append(thought_latency_ms)
            elif task_id and task_id in self._task_assignments:
                latency_ms = (time.monotonic() - self._task_assignments[task_id]) * 1000.0
                self._thought_latency_ms_samples.append(latency_ms)
            if ratio:
                self._reason_exec_ratio_samples.append(ratio)
            self._event_count += 1

        self._maybe_alert_from_velocity()
        self._budget_check(t0, "record_token_flow")

    def mark_task_assigned(self, task_id: str) -> None:
        t0 = time.perf_counter()
        with self._lock:
            self._task_assignments[task_id] = time.monotonic()
            self._event_count += 1
        self._budget_check(t0, "mark_task_assigned")

    def mark_action_generated(self, task_id: str) -> None:
        t0 = time.perf_counter()
        with self._lock:
            started = self._task_assignments.pop(task_id, None)
            if started is not None:
                self._thought_latency_ms_samples.append((time.monotonic() - started) * 1000.0)
            self._event_count += 1
        self._maybe_alert_from_velocity()
        self._budget_check(t0, "mark_action_generated")

    def record_tool_outcome(self, agent_id: str, outcome: OutcomeCategory, *, waf_block: bool = False) -> None:
        t0 = time.perf_counter()
        with self._lock:
            stats = self._efficacy[agent_id]
            if outcome == "Success":
                stats.success += 1
            elif outcome == "Blocked_by_WAF" or waf_block:
                stats.blocked_by_waf += 1
            elif outcome == "Timed_Out":
                stats.timed_out += 1
            else:
                stats.system_error += 1
            self._event_count += 1
        self._maybe_alert_from_success_rate(agent_id)
        self._budget_check(t0, "record_tool_outcome")

    def record_handshake_attempt(self, *, success: bool) -> None:
        t0 = time.perf_counter()
        with self._lock:
            stats = self._efficacy["cwika"]
            stats.handshake_attempts += 1
            if success:
                stats.handshake_successes += 1
                stats.success += 1
            self._event_count += 1
        self._budget_check(t0, "record_handshake_attempt")

    def record_shell_conversion(self, *, success: bool) -> None:
        t0 = time.perf_counter()
        with self._lock:
            stats = self._efficacy["red_teamer"]
            stats.shell_attempts += 1
            if success:
                stats.shell_successes += 1
                stats.success += 1
            self._event_count += 1
        self._budget_check(t0, "record_shell_conversion")

    def sample_hardware(self) -> Tuple[GPUStats, SystemMemoryStats]:
        gpu = self._sample_gpu()
        mem = self._sample_memory()
        with self._lock:
            self._ram_pct_samples.append(mem.ram_pct)
            self._event_count += 1
        self._maybe_alert_from_memory(mem, gpu)
        return gpu, mem

    async def export_heartbeat(self) -> Dict[str, Any]:
        snapshot = self._build_snapshot()
        payload = self._snapshot_to_dict(snapshot)
        result = await asyncio.to_thread(self._writer.write_json, _METRICS_PATH, payload)
        with self._lock:
            self._last_snapshot = snapshot
        return result

    def get_summary(self) -> str:
        snapshot = self._last_snapshot or self._build_snapshot()
        rows = [
            ("GPU Compute %", f"{snapshot.gpu.compute_util_pct:.1f}"),
            ("GPU VRAM %", f"{snapshot.gpu.vram_pct:.1f}"),
            ("RAM %", f"{snapshot.memory.ram_pct:.1f}"),
            ("TPS Avg", f"{snapshot.cognitive_velocity.tps_avg:.2f}"),
            ("Thought Latency Avg (ms)", f"{snapshot.cognitive_velocity.thought_latency_ms_avg:.1f}"),
            ("Reason:Exec Ratio", f"{snapshot.cognitive_velocity.reasoning_to_execution_ratio:.2f}"),
            ("Active Alerts", str(len(snapshot.active_alerts))),
        ]
        lines = ["| Metric | Value |", "|---|---|"]
        lines.extend(f"| {name} | {value} |" for name, value in rows)
        for agent_id, stats in sorted(snapshot.offensive_efficacy.items()):
            lines.append(f"| {agent_id} Success Rate | {stats.success_rate:.2%} |")
            if agent_id == "cwika":
                lines.append(f"| {agent_id} Handshake Capture Rate | {stats.handshake_capture_rate:.2%} |")
            if agent_id == "red_teamer":
                lines.append(f"| {agent_id} Shell Conversion Rate | {stats.shell_conversion_rate:.2%} |")
        return "\n".join(lines)

    def latest_alerts(self) -> List[AnomalyAlert]:
        with self._lock:
            return list(self._alerts)

    def latest_snapshot(self) -> Optional[HeartbeatSnapshot]:
        with self._lock:
            return self._last_snapshot

    async def _heartbeat_loop(self) -> None:
        while True:
            try:
                await self.export_heartbeat()
            except Exception as exc:
                _CPTE_LOGGER.debug("CPTE heartbeat export failed: %s", exc)
            await asyncio.sleep(self._heartbeat_interval_s)

    def _build_snapshot(self) -> HeartbeatSnapshot:
        gpu = self._sample_gpu()
        mem = self._sample_memory()
        with self._lock:
            velocity = CognitiveVelocityStats(
                tps_avg=self._avg(self._tps_samples),
                thought_latency_ms_avg=self._avg(self._thought_latency_ms_samples),
                reasoning_to_execution_ratio=self._avg(self._reason_exec_ratio_samples),
                samples=len(self._tps_samples),
            )
            efficacy_copy = {agent: self._clone_efficacy(stats) for agent, stats in self._efficacy.items()}
            alerts = list(self._alerts)
            total_events = self._event_count
        return HeartbeatSnapshot(
            session_id=self.session_id,
            created_at=datetime.now(tz=UTC).isoformat(),
            gpu=gpu,
            memory=mem,
            cognitive_velocity=velocity,
            offensive_efficacy=efficacy_copy,
            active_alerts=alerts,
            total_events=total_events,
        )

    def _sample_memory(self) -> SystemMemoryStats:
        if _PSUTIL_AVAILABLE and psutil is not None:
            vm = psutil.virtual_memory()
            process = psutil.Process(os.getpid())
            return SystemMemoryStats(
                ram_used_gb=vm.used / (1024 ** 3),
                ram_total_gb=vm.total / (1024 ** 3),
                ram_pct=float(vm.percent),
                process_rss_gb=process.memory_info().rss / (1024 ** 3),
            )
        return SystemMemoryStats(ram_used_gb=0.0, ram_total_gb=256.0, ram_pct=0.0, process_rss_gb=0.0)

    def _sample_gpu(self) -> GPUStats:
        if self._nvml_ready and _PYNVML_AVAILABLE and pynvml is not None and self._nvml_handle is not None:
            try:
                mem = pynvml.nvmlDeviceGetMemoryInfo(self._nvml_handle)
                util = pynvml.nvmlDeviceGetUtilizationRates(self._nvml_handle)
                power = None
                power_limit = None
                temp = None
                try:
                    power = pynvml.nvmlDeviceGetPowerUsage(self._nvml_handle) / 1000.0
                    power_limit = pynvml.nvmlDeviceGetEnforcedPowerLimit(self._nvml_handle) / 1000.0
                except Exception:
                    pass
                try:
                    temp = float(pynvml.nvmlDeviceGetTemperature(self._nvml_handle, pynvml.NVML_TEMPERATURE_GPU))
                except Exception:
                    pass
                name = pynvml.nvmlDeviceGetName(self._nvml_handle)
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="ignore")
                total_mb = mem.total / (1024 ** 2)
                used_mb = mem.used / (1024 ** 2)
                return GPUStats(
                    gpu_name=str(name),
                    vram_used_mb=used_mb,
                    vram_total_mb=total_mb,
                    vram_pct=(used_mb / total_mb * 100.0) if total_mb else 0.0,
                    compute_util_pct=float(util.gpu),
                    temperature_c=temp,
                    power_draw_w=power,
                    power_limit_w=power_limit,
                )
            except Exception as exc:
                _CPTE_LOGGER.debug("CPTE GPU sample failed: %s", exc)
        return GPUStats()

    def _maybe_alert_from_memory(self, mem: SystemMemoryStats, gpu: GPUStats) -> None:
        alerts: List[AnomalyAlert] = []
        with self._lock:
            baseline = self._avg(self._ram_pct_samples)
        if baseline and (mem.ram_pct - baseline) >= _MEMORY_SPIKE_THRESHOLD_PCT:
            alerts.append(self._make_alert(
                "memory_spike",
                "high",
                f"System RAM usage jumped from baseline {baseline:.1f}% to {mem.ram_pct:.1f}%.",
            ))
        if gpu.vram_pct >= _VRAM_ALERT_THRESHOLD_PCT:
            alerts.append(self._make_alert(
                "vram_pressure",
                "high",
                f"GPU VRAM utilisation is {gpu.vram_pct:.1f}% on {gpu.gpu_name}.",
            ))
        for alert in alerts:
            self._push_alert(alert)

    def _maybe_alert_from_success_rate(self, agent_id: str) -> None:
        with self._lock:
            stats = self._efficacy[agent_id]
            if stats.total < 5:
                return
            success_rate = stats.success_rate
        if success_rate < _SUCCESS_DROP_THRESHOLD:
            self._push_alert(self._make_alert(
                "success_rate_drop",
                "medium",
                f"Agent {agent_id} success rate dropped to {success_rate:.2%}; possible IP ban or control-plane issue.",
            ))

    def _maybe_alert_from_velocity(self) -> None:
        with self._lock:
            thought_latency = self._avg(self._thought_latency_ms_samples)
            ratio = self._avg(self._reason_exec_ratio_samples)
        if thought_latency >= _THOUGHT_LATENCY_ALERT_MS:
            self._push_alert(self._make_alert(
                "thought_latency",
                "medium",
                f"Average thought latency is {thought_latency:.1f} ms.",
            ))
        if ratio >= _RATIO_ALERT_THRESHOLD:
            self._push_alert(self._make_alert(
                "reason_execution_loop",
                "medium",
                f"Reasoning-to-execution ratio is {ratio:.2f}; the agent may be looping.",
            ))

    def _make_alert(self, alert_type: str, severity: str, message: str) -> AnomalyAlert:
        critique = None
        if _REASONING_AVAILABLE and REASONING_TOOL is not None and alert_type in {
            "memory_spike", "success_rate_drop", "thought_latency", "reason_execution_loop", "vram_pressure"
        }:
            try:
                critique = REASONING_TOOL.reason(
                    mode=MODE_CRITIQUE,
                    objective="Identify telemetry bottleneck and likely root cause",
                    context=message,
                    prior_output=(
                        "Determine whether the bottleneck is caused by local network pressure, model inference speed, "
                        "or an inefficient Python script in the isolated runtime."
                    ),
                    options=[
                        "Local network bottleneck",
                        "Model inference slowdown",
                        "Isolated runtime inefficiency",
                        "Need more telemetry samples",
                    ],
                    fetch_facts=False,
                )
            except Exception as exc:
                critique = {"error": str(exc)}
        return AnomalyAlert(alert_type=alert_type, severity=severity, message=message, critique=critique)

    def _push_alert(self, alert: AnomalyAlert) -> None:
        with self._lock:
            if self._alerts and self._alerts[-1].alert_type == alert.alert_type and self._alerts[-1].message == alert.message:
                return
            self._alerts.append(alert)

    def _snapshot_to_dict(self, snapshot: HeartbeatSnapshot) -> Dict[str, Any]:
        return {
            "session_id": snapshot.session_id,
            "created_at": snapshot.created_at,
            "gpu": {
                "gpu_name": snapshot.gpu.gpu_name,
                "vram_used_mb": round(snapshot.gpu.vram_used_mb, 2),
                "vram_total_mb": round(snapshot.gpu.vram_total_mb, 2),
                "vram_pct": round(snapshot.gpu.vram_pct, 2),
                "compute_util_pct": round(snapshot.gpu.compute_util_pct, 2),
                "temperature_c": snapshot.gpu.temperature_c,
                "power_draw_w": snapshot.gpu.power_draw_w,
                "power_limit_w": snapshot.gpu.power_limit_w,
                "sampled_at": snapshot.gpu.sampled_at,
            },
            "memory": {
                "ram_used_gb": round(snapshot.memory.ram_used_gb, 2),
                "ram_total_gb": round(snapshot.memory.ram_total_gb, 2),
                "ram_pct": round(snapshot.memory.ram_pct, 2),
                "process_rss_gb": round(snapshot.memory.process_rss_gb, 2),
                "sampled_at": snapshot.memory.sampled_at,
            },
            "cognitive_velocity": {
                "tps_avg": round(snapshot.cognitive_velocity.tps_avg, 3),
                "thought_latency_ms_avg": round(snapshot.cognitive_velocity.thought_latency_ms_avg, 3),
                "reasoning_to_execution_ratio": round(snapshot.cognitive_velocity.reasoning_to_execution_ratio, 3),
                "samples": snapshot.cognitive_velocity.samples,
            },
            "offensive_efficacy": {
                agent: {
                    "success": stats.success,
                    "blocked_by_waf": stats.blocked_by_waf,
                    "timed_out": stats.timed_out,
                    "system_error": stats.system_error,
                    "success_rate": round(stats.success_rate, 4),
                    "handshake_attempts": stats.handshake_attempts,
                    "handshake_successes": stats.handshake_successes,
                    "handshake_capture_rate": round(stats.handshake_capture_rate, 4),
                    "shell_attempts": stats.shell_attempts,
                    "shell_successes": stats.shell_successes,
                    "shell_conversion_rate": round(stats.shell_conversion_rate, 4),
                }
                for agent, stats in snapshot.offensive_efficacy.items()
            },
            "active_alerts": [
                {
                    "alert_type": alert.alert_type,
                    "severity": alert.severity,
                    "message": alert.message,
                    "created_at": alert.created_at,
                    "critique": alert.critique,
                }
                for alert in snapshot.active_alerts
            ],
            "total_events": snapshot.total_events,
        }

    def _init_nvml(self) -> None:
        if not _PYNVML_AVAILABLE or pynvml is None:
            return
        try:
            pynvml.nvmlInit()
            count = pynvml.nvmlDeviceGetCount()
            if count > 0:
                self._nvml_handle = pynvml.nvmlDeviceGetHandleByIndex(0)
                self._nvml_ready = True
        except Exception as exc:
            self._nvml_ready = False
            self._nvml_handle = None
            _CPTE_LOGGER.debug("CPTE NVML init failed: %s", exc)

    def _shutdown_nvml(self) -> None:
        if not self._nvml_ready or not _PYNVML_AVAILABLE or pynvml is None:
            return
        try:
            pynvml.nvmlShutdown()
        except Exception:
            pass
        self._nvml_ready = False
        self._nvml_handle = None

    @staticmethod
    def _avg(values: Iterable[float]) -> float:
        data = list(values)
        return sum(data) / len(data) if data else 0.0

    @staticmethod
    def _clone_efficacy(stats: OffensiveEfficacyStats) -> OffensiveEfficacyStats:
        return OffensiveEfficacyStats(
            success=stats.success,
            blocked_by_waf=stats.blocked_by_waf,
            timed_out=stats.timed_out,
            system_error=stats.system_error,
            handshake_attempts=stats.handshake_attempts,
            handshake_successes=stats.handshake_successes,
            shell_attempts=stats.shell_attempts,
            shell_successes=stats.shell_successes,
        )

    @staticmethod
    def _make_session_id() -> str:
        return f"cpte-{int(time.time())}-{os.getpid()}"

    @staticmethod
    def _budget_check(start: float, operation: str) -> None:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        if elapsed_ms > 3.0:
            _CPTE_LOGGER.debug("CPTE hot-path budget exceeded in %s: %.3f ms", operation, elapsed_ms)


async def process_metrics(path: str, sid: Optional[str] = None) -> bool:
    """Legacy telemetry hook preserved for compatibility."""
    engine = CerebroMetricsEngine(session_id=sid)
    try:
        await engine.export_heartbeat()
        return True
    except Exception:
        return False


async def process_intermediate_logs(path: str, sid: Optional[str] = None) -> bool:
    """Legacy intermediate-log hook preserved for compatibility."""
    return await process_metrics(path, sid=sid)


__all__ = [
    "CerebroMetricsEngine",
    "GPUStats",
    "SystemMemoryStats",
    "CognitiveVelocityStats",
    "OffensiveEfficacyStats",
    "AnomalyAlert",
    "HeartbeatSnapshot",
    "process_metrics",
    "process_intermediate_logs",
]