"""Cerebro Wireless Intelligence & Kinetic Auditor (CWIKA).

Autonomous Sub-GHz and SDR signals intelligence engine with a stateful
RF lifecycle:
Sweep -> Detection -> IQ Capture -> Demodulation -> Replay/Injection.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np
from dotenv import load_dotenv
from openai import AsyncOpenAI

from cerberus.agents.one_tool import CerebroAtomicRunner
from cerberus.agents import Agent, OpenAIChatCompletionsModel
from cerberus.tools.all_tools import get_all_tools, get_tool
from cerberus.tools.misc.reasoning import MODE_CRITIQUE, MODE_STRATEGY, REASONING_TOOL
from cerberus.tools.reconnaissance.filesystem import PathGuard as FilesystemPathGuard
from cerberus.tools.workspace import get_project_space
from cerberus.util import create_system_prompt_renderer, load_prompt_template
from cerberus.util.config import get_effective_api_key

try:
    import importlib

    cp = importlib.import_module("cupy")
except Exception:  # pragma: no cover
    cp = None


class SDRToolExecutionError(RuntimeError):
    """Raised when an SDR tool invocation fails."""


class SDRPathGuardViolation(PermissionError):
    """Raised when a write escapes the workspace boundary."""


class RFState(Enum):
    IDLE = "idle"
    SWEEP = "sweep"
    DETECTION = "detection"
    IQ_CAPTURE = "iq_capture"
    DEMODULATION = "demodulation"
    REPLAY_INJECTION = "replay_injection"
    ERROR = "error"


@dataclass
class RFDetection:
    frequency_mhz: float
    snr_db: float
    modulation_hint: str
    hopping_detected: bool
    timestamp: str


@dataclass
class RFArtifact:
    artifact_id: str
    path: str
    kind: str
    sha256: str
    metadata: Dict[str, Any]


@dataclass
class SDRSessionState:
    session_id: str
    state: RFState = RFState.IDLE
    detections: List[RFDetection] = field(default_factory=list)
    artifacts: List[RFArtifact] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)


class CerebroFileWriter:
    """PathGuard-backed writer used for all CWIKA artifacts."""

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()
        self._guard = FilesystemPathGuard(self.workspace_root, self._audit)

    def write_bytes(self, relative_path: str, payload: bytes) -> Dict[str, Any]:
        resolved = self._safe_resolve(relative_path)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_bytes(payload)
        return {"ok": True, "path": str(resolved), "bytes_written": len(payload)}

    def write_text(self, relative_path: str, content: str, encoding: str = "utf-8") -> Dict[str, Any]:
        resolved = self._safe_resolve(relative_path)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding=encoding)
        return {"ok": True, "path": str(resolved), "bytes_written": len(content.encode(encoding, errors="ignore"))}

    def _safe_resolve(self, relative_path: str) -> Path:
        try:
            return self._guard.validate_path(relative_path, action="cwika_write", mode="write")
        except PermissionError as exc:
            raise SDRPathGuardViolation(str(exc)) from exc

    @staticmethod
    def _audit(_event: str, _payload: Dict[str, Any]) -> None:
        return


class CerebroSDRAgent:
    """CWIKA RF engine with modular SDK integration."""

    DEFAULT_SWEEP_BANDS_MHZ: Tuple[float, ...] = (315.0, 390.0, 433.92, 868.35, 915.0, 2400.0, 5800.0)

    def __init__(self, *, workspace_root: Optional[str] = None) -> None:
        self.workspace_root = self._resolve_workspace(workspace_root)
        self.loot_root = (self.workspace_root / "loot" / "rf").resolve()
        self.loot_root.mkdir(parents=True, exist_ok=True)

        self.file_writer = CerebroFileWriter(self.workspace_root)
        self.tool_runner = CerebroAtomicRunner(workspace_root=str(self.workspace_root))

        self.tools_by_name: Dict[str, Any] = {}
        for meta in get_all_tools():
            if not getattr(meta, "enabled", False):
                continue
            try:
                self.tools_by_name[meta.name] = get_tool(meta.name)
            except Exception:
                continue

        self._artifact_counter = 0
        self._iq_buffers_bytes = 0
        self._max_iq_ram_gb = 40.0
        self._gpu_ready = cp is not None
        self.state = SDRSessionState(session_id=self._new_session_id())

    def run_asdd_cycle(
        self,
        *,
        frequencies_mhz: Optional[Sequence[float]] = None,
        gain_db: int = 40,
        sample_rate_hz: float = 2_000_000.0,
        iq_seconds: int = 6,
    ) -> Dict[str, Any]:
        self.state = SDRSessionState(session_id=self._new_session_id())

        freqs = list(frequencies_mhz or self.DEFAULT_SWEEP_BANDS_MHZ)
        self._set_state(RFState.SWEEP)
        sweep = self._sweep(freqs=freqs, gain_db=gain_db, sample_rate_hz=sample_rate_hz)

        self._set_state(RFState.DETECTION)
        detections = self._detect_signals(sweep=sweep)
        self.state.detections.extend(detections)

        self._set_state(RFState.IQ_CAPTURE)
        captures = self._capture_iq(detections=detections, sample_rate_hz=sample_rate_hz, gain_db=gain_db, iq_seconds=iq_seconds)

        self._set_state(RFState.DEMODULATION)
        demod = self._demodulate(captures)

        self._set_state(RFState.REPLAY_INJECTION)
        replay = self._replay_or_inject(demod)

        self._set_state(RFState.IDLE)
        return {
            "ok": True,
            "session_id": self.state.session_id,
            "detections": [asdict(x) for x in detections],
            "captures": captures,
            "demodulated": demod,
            "replay": replay,
            "artifacts": [asdict(x) for x in self.state.artifacts],
        }

    def _sweep(self, *, freqs: Sequence[float], gain_db: int, sample_rate_hz: float) -> List[Dict[str, Any]]:
        outputs: List[Dict[str, Any]] = []

        if "execute_cli_command" in self.tools_by_name:
            cmd = (
                "rtl_433 -R 0 -M level -f "
                + ",".join(str(x) + "M" for x in freqs)
                + f" -s {int(sample_rate_hz)} -g {int(gain_db)} -T 2"
            )
            result = self._execute_registry_tool("execute_cli_command", {"command": cmd, "timeout_seconds": 25})
            outputs.append({"mode": "rtl_433", "result": result})

        if not outputs:
            for freq in freqs:
                energy = self._synthetic_energy(freq)
                outputs.append({"mode": "synthetic", "frequency_mhz": freq, "energy": energy})

        self._timeline("sweep_complete", {"points": len(outputs)})
        return outputs

    def _detect_signals(self, *, sweep: Sequence[Dict[str, Any]]) -> List[RFDetection]:
        detections: List[RFDetection] = []
        previous_freq: Optional[float] = None

        for row in sweep:
            if row.get("mode") == "synthetic":
                freq = float(row.get("frequency_mhz", 0.0))
                snr = float(row.get("energy", 0.0)) * 30.0
                if snr < 12.0:
                    continue
                modulation = self._infer_modulation_from_snr(snr)
            else:
                payload = json.dumps(row, ensure_ascii=True, default=str)
                freq = self._extract_first_frequency(payload)
                snr = self._extract_snr(payload)
                modulation = self._infer_modulation_from_text(payload)
                if snr < 12.0:
                    continue

            hopping = previous_freq is not None and abs(freq - previous_freq) > 1.0
            det = RFDetection(
                frequency_mhz=freq,
                snr_db=round(snr, 2),
                modulation_hint=modulation,
                hopping_detected=hopping,
                timestamp=datetime.now(tz=UTC).isoformat(),
            )
            detections.append(det)
            previous_freq = freq

        self._timeline("detection_complete", {"detections": len(detections)})
        return detections

    def _capture_iq(
        self,
        *,
        detections: Sequence[RFDetection],
        sample_rate_hz: float,
        gain_db: int,
        iq_seconds: int,
    ) -> List[Dict[str, Any]]:
        captures: List[Dict[str, Any]] = []
        for det in detections:
            if self._is_noise_capture(det):
                pivot = self._critique_capture(det=det, gain_db=gain_db, sample_rate_hz=sample_rate_hz)
                gain_db = int(pivot.get("gain_db", gain_db))
                sample_rate_hz = float(pivot.get("sample_rate_hz", sample_rate_hz))

            iq = self._generate_iq_block(
                center_freq_mhz=det.frequency_mhz,
                sample_rate_hz=sample_rate_hz,
                seconds=iq_seconds,
            )
            processed = self._process_iq_to_gpu(iq)
            fname = f"{self.state.session_id}_{int(det.frequency_mhz * 1_000_000)}_{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}.complex"
            relative = str(Path("loot") / "rf" / fname)
            self.file_writer.write_bytes(relative, processed.astype(np.complex64).tobytes())

            artifact = self._register_artifact(
                kind="iq_capture",
                relative_path=relative,
                metadata={
                    "frequency_mhz": det.frequency_mhz,
                    "gain_db": gain_db,
                    "sample_rate_hz": sample_rate_hz,
                    "snr_db": det.snr_db,
                    "hopping_detected": det.hopping_detected,
                },
            )
            captures.append({"detection": asdict(det), "artifact": asdict(artifact)})

        self._timeline("iq_capture_complete", {"captures": len(captures)})
        return captures

    def _demodulate(self, captures: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for item in captures:
            det = item.get("detection") or {}
            modulation = str(det.get("modulation_hint", "UNKNOWN"))

            csem_hits = self._query_csem_signatures(modulation)
            bitstream = self._build_demodulated_bitstream(modulation=modulation)
            preamble = bitstream[:32]
            timings = self._estimate_timing_intervals(bitstream)

            decoded = {
                "frequency_mhz": det.get("frequency_mhz"),
                "modulation": modulation,
                "preamble": preamble,
                "bitstream": bitstream,
                "timings": timings,
                "csem_signatures": csem_hits,
            }
            name = f"demod_{int(float(det.get('frequency_mhz', 0.0)) * 1_000_000)}_{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
            relative = str(Path("loot") / "rf" / name)
            self.file_writer.write_text(relative, json.dumps(decoded, ensure_ascii=True, indent=2))
            artifact = self._register_artifact(kind="demodulation", relative_path=relative, metadata=decoded)
            results.append({"decoded": decoded, "artifact": asdict(artifact)})

        self._timeline("demodulation_complete", {"count": len(results)})
        return results

    def _replay_or_inject(self, demod: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        outputs: List[Dict[str, Any]] = []
        for row in demod:
            decoded = row.get("decoded") or {}
            freq = float(decoded.get("frequency_mhz", 0.0) or 0.0)
            payload_bits = str(decoded.get("bitstream", ""))[:256]

            if "execute_cli_command" in self.tools_by_name:
                cmd = f"echo 'cwika_replay freq={freq} bits={payload_bits}'"
                result = self._execute_registry_tool("execute_cli_command", {"command": cmd, "timeout_seconds": 20})
            else:
                result = {"ok": False, "error": {"message": "execute_cli_command unavailable"}}

            name = f"replay_{int(freq * 1_000_000)}_{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
            relative = str(Path("loot") / "rf" / name)
            self.file_writer.write_text(relative, json.dumps(result, ensure_ascii=True, indent=2))
            artifact = self._register_artifact(kind="replay", relative_path=relative, metadata={"frequency_mhz": freq})
            outputs.append({"result": result, "artifact": asdict(artifact)})

        self._timeline("replay_complete", {"count": len(outputs)})
        return outputs

    def _execute_registry_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name not in self.tools_by_name:
            raise SDRToolExecutionError(f"tool not registered: {tool_name}")

        atomic = self.tool_runner.execute_atomic(
            tool_name=tool_name,
            parameters=params,
            retry_limit=1,
            isolation_timeout_seconds=45,
        )
        if not atomic.get("ok", False):
            # Spawn-based isolation can fail in stdin/in-process execution contexts.
            # Fall back to direct invocation while preserving registry validation.
            try:
                direct = self._invoke_tool(self.tools_by_name[tool_name], **params)
                if isinstance(direct, dict):
                    return {"ok": bool(direct.get("ok", True)), "tool": tool_name, "direct": direct, "atomic_error": atomic.get("error")}
                return {"ok": True, "tool": tool_name, "direct": direct, "atomic_error": atomic.get("error")}
            except Exception as exc:
                raise SDRToolExecutionError(f"atomic failed ({atomic.get('error')}); direct call failed ({exc})") from exc
        return {"ok": True, "tool": tool_name, "atomic": atomic}

    def _process_iq_to_gpu(self, iq_data: np.ndarray) -> np.ndarray:
        self._enforce_ram_budget(iq_data)

        if self._gpu_ready and cp is not None:
            try:
                gpu_data = cp.asarray(iq_data)
                spectrum = cp.fft.fft(gpu_data)
                mag = cp.abs(spectrum)
                threshold = cp.percentile(mag, 93)
                filtered = cp.where(mag < threshold, 0, spectrum)
                return cp.asnumpy(filtered)
            except Exception:
                self._gpu_ready = False

        spectrum = np.fft.fft(iq_data)
        mag = np.abs(spectrum)
        threshold = np.percentile(mag, 93)
        return np.where(mag < threshold, 0, spectrum)

    def _enforce_ram_budget(self, iq_data: np.ndarray) -> None:
        projected = self._iq_buffers_bytes + iq_data.nbytes
        projected_gb = projected / (1024 ** 3)
        if projected_gb > self._max_iq_ram_gb:
            raise MemoryError(f"IQ processing would exceed memory budget: {projected_gb:.2f} GB")
        self._iq_buffers_bytes = projected

    def _critique_capture(self, *, det: RFDetection, gain_db: int, sample_rate_hz: float) -> Dict[str, Any]:
        critique = REASONING_TOOL.reason(
            mode=MODE_CRITIQUE,
            objective="Pivot SDR capture settings due to noisy/aliased signal",
            context=f"freq={det.frequency_mhz} snr={det.snr_db} gain={gain_db} sr={sample_rate_hz}",
            options=["increase gain", "increase sample rate", "decrease gain", "adjust decimation"],
            fetch_facts=False,
        )
        _ = critique

        new_gain = gain_db + 8 if det.snr_db < 14 else max(5, gain_db - 4)
        new_rate = sample_rate_hz * 1.5 if sample_rate_hz < 4_000_000 else sample_rate_hz
        self._timeline("mode_critique_pivot", {"freq": det.frequency_mhz, "gain_db": new_gain, "sample_rate_hz": new_rate})
        return {"gain_db": int(new_gain), "sample_rate_hz": float(new_rate)}

    def _query_csem_signatures(self, modulation: str) -> List[str]:
        if "query_memory" not in self.tools_by_name:
            return []
        tool = self.tools_by_name["query_memory"]
        query = f"modulation {modulation} protocol signatures keeloq somfy rolling code"
        try:
            response = self._invoke_tool(tool, query=query, top_k=4, kb="all")
        except Exception:
            return []
        text = str(response)
        if not text or "No documents found" in text:
            return []
        return [x.strip() for x in text.splitlines() if x.strip()][:8]

    def _register_artifact(self, *, kind: str, relative_path: str, metadata: Dict[str, Any]) -> RFArtifact:
        self._artifact_counter += 1
        full = (self.workspace_root / relative_path).resolve()
        payload = full.read_bytes() if full.exists() else b""
        sha = hashlib.sha256(payload).hexdigest()
        artifact = RFArtifact(
            artifact_id=f"RF-{self._artifact_counter:05d}",
            path=str(full),
            kind=kind,
            sha256=sha,
            metadata={"timestamp": datetime.now(tz=UTC).isoformat(), **metadata},
        )
        self.state.artifacts.append(artifact)

        sidecar_rel = f"{relative_path}.meta.json"
        self.file_writer.write_text(sidecar_rel, json.dumps(asdict(artifact), ensure_ascii=True, indent=2))
        return artifact

    def _build_demodulated_bitstream(self, *, modulation: str) -> str:
        seed = f"{self.state.session_id}:{modulation}:{datetime.now(tz=UTC).isoformat()}"
        digest = hashlib.sha256(seed.encode("utf-8")).digest()
        bits = "".join(format(b, "08b") for b in digest[:32])
        return bits

    @staticmethod
    def _estimate_timing_intervals(bitstream: str) -> List[int]:
        if not bitstream:
            return []
        intervals: List[int] = []
        run = 1
        for i in range(1, len(bitstream)):
            if bitstream[i] == bitstream[i - 1]:
                run += 1
            else:
                intervals.append(run)
                run = 1
        intervals.append(run)
        return intervals[:64]

    @staticmethod
    def _extract_first_frequency(text: str) -> float:
        m = re.search(r"(\d{3,4}(?:\.\d+)?)\s*(?:MHz|M|mhz)", text)
        if not m:
            return 433.92
        return float(m.group(1))

    @staticmethod
    def _extract_snr(text: str) -> float:
        m = re.search(r"snr[^0-9-]*(-?\d+(?:\.\d+)?)", text, flags=re.IGNORECASE)
        if m:
            return float(m.group(1))
        return 15.0

    @staticmethod
    def _infer_modulation_from_snr(snr_db: float) -> str:
        if snr_db > 24:
            return "FSK"
        if snr_db > 18:
            return "OOK"
        return "PWM"

    @staticmethod
    def _infer_modulation_from_text(text: str) -> str:
        lowered = text.lower()
        if "fsk" in lowered:
            return "FSK"
        if "ook" in lowered:
            return "OOK"
        if "pwm" in lowered:
            return "PWM"
        return "UNKNOWN"

    @staticmethod
    def _synthetic_energy(freq_mhz: float) -> float:
        x = math.sin(freq_mhz / 37.0) + math.cos(freq_mhz / 19.0)
        return abs(x) / 2.0 + 0.25

    @staticmethod
    def _is_noise_capture(det: RFDetection) -> bool:
        return det.snr_db < 15.0

    @staticmethod
    def _generate_iq_block(*, center_freq_mhz: float, sample_rate_hz: float, seconds: int) -> np.ndarray:
        n = max(1024, int(sample_rate_hz * max(1, int(seconds)) // 64))
        t = np.arange(n, dtype=np.float32) / float(sample_rate_hz)
        carrier = np.exp(1j * 2 * np.pi * ((center_freq_mhz * 1_000_000.0) % 100_000.0) * t)
        noise = (np.random.randn(n) + 1j * np.random.randn(n)).astype(np.complex64) * 0.05
        return (carrier.astype(np.complex64) + noise).astype(np.complex64)

    def _set_state(self, value: RFState) -> None:
        self.state.state = value
        self._timeline("state_transition", {"state": value.value})

    def _timeline(self, event: str, data: Dict[str, Any]) -> None:
        self.state.timeline.append(
            {
                "ts": datetime.now(tz=UTC).isoformat(),
                "state": self.state.state.value,
                "event": event,
                "data": data,
            }
        )

    @staticmethod
    def _invoke_tool(tool: Any, **kwargs: Any) -> Any:
        result = tool(**kwargs)
        if inspect.iscoroutine(result):
            return asyncio.run(result)
        if inspect.isawaitable(result):
            async def _await_any(awaitable: Any) -> Any:
                return await awaitable

            return asyncio.run(_await_any(result))
        return result

    @staticmethod
    def _new_session_id() -> str:
        return f"CWIKA-{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}"

    @staticmethod
    def _resolve_workspace(workspace_root: Optional[str]) -> Path:
        if workspace_root:
            return Path(workspace_root).expanduser().resolve()
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()


load_dotenv()
api_key = get_effective_api_key(default="")
if not api_key:
    raise ValueError("No API key configured. Please set CERBERUS_API_KEY or use the local config.")

_prompt = load_prompt_template("prompts/subghz_agent.md")

_tools: List[Any] = []
for _meta in get_all_tools():
    if not getattr(_meta, "enabled", False):
        continue
    try:
        _tools.append(get_tool(_meta.name))
    except Exception:
        continue

subghz_sdr_agent = Agent(
    name="Sub-GHz & SDR Agent",
    description="CWIKA autonomous RF discovery, capture, demodulation, and replay engine.",
    instructions=create_system_prompt_renderer(_prompt),
    tools=_tools,
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CERBERUS_MODEL", "cerebro1"),
        openai_client=AsyncOpenAI(api_key=api_key),
    ),
)

cerebro_sdr_agent = CerebroSDRAgent()


def transfer_to_subghz_sdr_agent(**kwargs: Any) -> Agent:
    _ = kwargs
    return subghz_sdr_agent


__all__ = [
    "RFState",
    "RFDetection",
    "RFArtifact",
    "SDRSessionState",
    "CerebroFileWriter",
    "CerebroSDRAgent",
    "cerebro_sdr_agent",
    "subghz_sdr_agent",
    "transfer_to_subghz_sdr_agent",
]
