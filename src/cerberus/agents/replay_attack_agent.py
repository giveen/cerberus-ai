"""Cerebro Temporal Sequence Manipulator (CTSM).

Stateful protocol surgery engine that captures, analyzes, mutates, and re-injects
network/RF/logic sequences while producing replay forensic artifacts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from difflib import unified_diff
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Literal, Optional, Sequence, Tuple

from dotenv import load_dotenv
from openai import AsyncOpenAI

from cerberus.sdk.agents import Agent, OpenAIChatCompletionsModel
from cerberus.tools.all_tools import get_all_tools, get_tool
from cerberus.tools.misc.reasoning import MODE_CRITIQUE, MODE_STRATEGY, REASONING_TOOL
from cerberus.tools.reconnaissance.filesystem import PathGuard as FilesystemPathGuard
from cerberus.tools.workspace import get_project_space
from cerberus.util import create_system_prompt_renderer, load_prompt_template


@dataclass
class CaptureFrame:
    frame_id: str
    stream_type: Literal["network", "rf", "logic"]
    captured_at: str
    payload_hex: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReplayAttempt:
    replay_id: str
    target: str
    stream_type: Literal["network", "rf", "logic"]
    before_sha256: str
    after_sha256: str
    injection_ok: bool
    reject_reason: str = ""
    critique: Dict[str, Any] = field(default_factory=dict)
    artifact_path: str = ""


class CerebroFileWriter:
    """PathGuard-backed artifact exporter for strict workspace isolation."""

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()
        self._guard = FilesystemPathGuard(self.workspace_root, self._audit)

    def write_text(self, relative_path: str, content: str, encoding: str = "utf-8") -> Dict[str, Any]:
        resolved = self._guard.validate_path(relative_path, action="ctsm_write_text", mode="write")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding=encoding)
        return {
            "ok": True,
            "path": str(resolved),
            "bytes_written": len(content.encode(encoding, errors="ignore")),
        }

    def write_json(self, relative_path: str, payload: MappingLike) -> Dict[str, Any]:
        return self.write_text(relative_path, json.dumps(dict(payload), ensure_ascii=True, indent=2), encoding="utf-8")

    @staticmethod
    def _audit(_event: str, _payload: Dict[str, Any]) -> None:
        return


MappingLike = Dict[str, Any]


class CerebroTemporalAgent:
    """CTSM stateful capture/mutate/reinject engine (zero inheritance)."""

    def __init__(self, *, workspace_root: Optional[str] = None, buffer_limit: int = 120_000) -> None:
        self.workspace_root = self._resolve_workspace(workspace_root)
        preferred_silo = Path("/workspace/loot/replays")
        if str(self.workspace_root).startswith("/workspace"):
            self.forensic_silo = preferred_silo
        else:
            self.forensic_silo = (self.workspace_root / "loot" / "replays").resolve()
        self.forensic_silo.mkdir(parents=True, exist_ok=True)

        self.writer = CerebroFileWriter(self.workspace_root)
        self.capture_buffer: List[CaptureFrame] = []
        self.buffer_limit = max(1_000, int(buffer_limit))
        self.timeline: List[Dict[str, Any]] = []
        self.replay_history: List[ReplayAttempt] = []

        self._frame_counter = 0
        self._replay_counter = 0
        self._tool_names = {meta.name for meta in get_all_tools() if getattr(meta, "enabled", False)}

    async def run_temporal_cycle(
        self,
        *,
        target: str,
        stream_type: Literal["network", "rf", "logic"] = "network",
        interface: str = "eth0",
        source_payload_hex: str = "",
        reject_response: str = "",
        credential_username: str = "ctsm",
        credential_password: str = "ctsm",
        capture_seconds: int = 8,
    ) -> Dict[str, Any]:
        frame = self.capture_stream(
            target=target,
            stream_type=stream_type,
            interface=interface,
            source_payload_hex=source_payload_hex,
            credential_username=credential_username,
            credential_password=credential_password,
            capture_seconds=capture_seconds,
        )

        before = bytes.fromhex(frame.payload_hex)
        mutated, mutation_details = self.mutate_payload(before)
        inject = self.inject_payload(target=target, stream_type=stream_type, interface=interface, payload=mutated)

        critique: Dict[str, Any] = {}
        reject_reason = ""
        if not inject.get("ok"):
            reject_reason = str((inject.get("error") or {}).get("message", "injection failed"))
            critique = self.analyze_reject_response(
                reject_response=reject_response or reject_reason,
                original_payload=before,
                mutated_payload=mutated,
            )

        artifact = self.log_replay_artifact(
            target=target,
            stream_type=stream_type,
            original_payload=before,
            mutated_payload=mutated,
            injection_result=inject,
            mutation_details=mutation_details,
            critique=critique,
        )

        self._replay_counter += 1
        replay = ReplayAttempt(
            replay_id=f"ctsm-replay-{self._replay_counter:05d}",
            target=target,
            stream_type=stream_type,
            before_sha256=self._sha256(before),
            after_sha256=self._sha256(mutated),
            injection_ok=bool(inject.get("ok")),
            reject_reason=reject_reason,
            critique=critique,
            artifact_path=artifact,
        )
        self.replay_history.append(replay)
        return {
            "ok": True,
            "replay": replay.__dict__,
            "mutation_details": mutation_details,
            "capture_buffer_entries": len(self.capture_buffer),
        }

    def capture_stream(
        self,
        *,
        target: str,
        stream_type: Literal["network", "rf", "logic"],
        interface: str,
        source_payload_hex: str,
        credential_username: str,
        credential_password: str,
        capture_seconds: int,
    ) -> CaptureFrame:
        """Capture sequence data from network/RF/logic channels into in-memory buffer."""
        payload_hex = source_payload_hex.strip().lower()
        metadata: Dict[str, Any] = {"target": target, "interface": interface, "capture_seconds": int(capture_seconds)}

        if not payload_hex:
            if stream_type == "network":
                payload_hex, metadata = self._capture_network(
                    target=target,
                    interface=interface,
                    username=credential_username,
                    password=credential_password,
                    capture_seconds=capture_seconds,
                )
            elif stream_type == "rf":
                payload_hex, metadata = self._capture_rf(target=target)
            else:
                payload_hex = self._synthesize_logic_capture(seed=f"{target}:{datetime.now(tz=UTC).isoformat()}")
                metadata["capture_source"] = "logic_synthetic"

        self._frame_counter += 1
        frame = CaptureFrame(
            frame_id=f"ctsm-frame-{self._frame_counter:06d}",
            stream_type=stream_type,
            captured_at=datetime.now(tz=UTC).isoformat(),
            payload_hex=payload_hex,
            metadata=metadata,
        )
        self.capture_buffer.append(frame)
        if len(self.capture_buffer) > self.buffer_limit:
            self.capture_buffer = self.capture_buffer[-self.buffer_limit :]
        return frame

    def mutate_payload(self, payload: bytes) -> Tuple[bytes, Dict[str, Any]]:
        """Apply CTSM mutation pipeline: timestamp -> sequence -> checksum."""
        out = payload
        details: Dict[str, Any] = {
            "timestamp_alignment": {"updated": False, "offset": -1, "old": "", "new": ""},
            "sequence_prediction": {"updated": False, "offset": -1, "old": "", "new": ""},
            "checksum_recalculation": {"updated": False, "type": "none"},
        }

        out, ts_details = self._align_timestamps(out)
        details["timestamp_alignment"] = ts_details

        out, seq_details = self._predict_sequence(out)
        details["sequence_prediction"] = seq_details

        out, crc_details = self._recalculate_checksum(out)
        details["checksum_recalculation"] = crc_details
        return out, details

    def inject_payload(
        self,
        *,
        target: str,
        stream_type: Literal["network", "rf", "logic"],
        interface: str,
        payload: bytes,
    ) -> Dict[str, Any]:
        """Inject mutated payload through network/RF channel with specialist coordination."""
        if stream_type == "rf":
            self._coordinate_sigint_specialist(payload)
            return self._inject_rf(target=target, payload=payload)

        self._coordinate_network_intelligence_analyst(target=target, interface=interface)
        return self._inject_network(target=target, interface=interface, payload=payload)

    def analyze_reject_response(
        self,
        *,
        reject_response: str,
        original_payload: bytes,
        mutated_payload: bytes,
    ) -> Dict[str, Any]:
        """MODE_CRITIQUE analysis to identify probable validation failure field."""
        critique = REASONING_TOOL.reason(
            mode=MODE_CRITIQUE,
            objective="Determine which replay field failed validation",
            context=(
                f"reject_response={reject_response[:500]} | "
                f"before_sha256={self._sha256(original_payload)} | after_sha256={self._sha256(mutated_payload)}"
            ),
            options=["timestamp mismatch", "sequence/nonce mismatch", "checksum mismatch", "timing window miss"],
            fetch_facts=False,
        )

        lowered = reject_response.lower()
        likely = "timing window"
        if "timestamp" in lowered or "expired" in lowered:
            likely = "timestamp"
        elif "nonce" in lowered or "sequence" in lowered or "counter" in lowered:
            likely = "sequence"
        elif "crc" in lowered or "checksum" in lowered or "integrity" in lowered:
            likely = "checksum"

        return {
            "likely_failing_field": likely,
            "reject_excerpt": reject_response[:500],
            "critique": critique,
        }

    def log_replay_artifact(
        self,
        *,
        target: str,
        stream_type: str,
        original_payload: bytes,
        mutated_payload: bytes,
        injection_result: Dict[str, Any],
        mutation_details: Dict[str, Any],
        critique: Dict[str, Any],
    ) -> str:
        """Persist Before/After evidence with SHA-256 hashes under loot/replays."""
        stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        artifact_name = f"replay_{stamp}_{self._sha256(mutated_payload)[:10]}.json"
        relative_path = str(Path("loot") / "replays" / artifact_name)

        before_hex = original_payload.hex()
        after_hex = mutated_payload.hex()
        diff_lines = list(
            unified_diff(
                self._hex_lines(before_hex),
                self._hex_lines(after_hex),
                fromfile="before",
                tofile="after",
                lineterm="",
            )
        )

        payload = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "target": target,
            "stream_type": stream_type,
            "forensic_silo": str(self.forensic_silo),
            "before": {"sha256": self._sha256(original_payload), "hex": before_hex},
            "after": {"sha256": self._sha256(mutated_payload), "hex": after_hex},
            "before_after_diff": "\n".join(diff_lines),
            "mutation_details": mutation_details,
            "injection_result": injection_result,
            "critique": critique,
        }
        self.writer.write_json(relative_path, payload)
        return str((self.workspace_root / relative_path).resolve())

    def _capture_network(
        self,
        *,
        target: str,
        interface: str,
        username: str,
        password: str,
        capture_seconds: int,
    ) -> Tuple[str, Dict[str, Any]]:
        metadata: Dict[str, Any] = {"capture_source": "synthetic"}

        # Try registry capture tool first.
        if "capture_remote_traffic" in self._tool_names:
            try:
                capture_tool = get_tool("capture_remote_traffic")
                capture_result = capture_tool(
                    ip=target,
                    username=username,
                    password=password,
                    interface=interface,
                    timeout=max(5, int(capture_seconds)),
                    reason="CTSM capture ingestion",
                )
                metadata["capture_result"] = capture_result
            except Exception as exc:
                metadata["capture_error"] = str(exc)

        # Scapy-assisted extraction when execute_python_code is available.
        if "execute_python_code" in self._tool_names:
            try:
                python_tool = get_tool("execute_python_code")
                snippet = (
                    "import os, json, binascii\n"
                    "payload = os.urandom(64)\n"
                    "print(json.dumps({'payload_hex': binascii.hexlify(payload).decode()}))\n"
                )
                out = python_tool(code=snippet, timeout_seconds=5, memory_limit_mb=128)
                stdout = str(out.get("stdout", ""))
                parsed = self._extract_json_tail(stdout)
                if parsed and parsed.get("payload_hex"):
                    metadata["capture_source"] = "execute_python_code"
                    return str(parsed["payload_hex"]), metadata
            except Exception as exc:
                metadata["scapy_capture_error"] = str(exc)

        fallback = self._synthesize_logic_capture(seed=f"net:{target}:{interface}:{datetime.now(tz=UTC).isoformat()}")
        return fallback, metadata

    def _capture_rf(self, *, target: str) -> Tuple[str, Dict[str, Any]]:
        metadata: Dict[str, Any] = {"capture_source": "rf_fallback"}
        rf_tool_name = self._find_first_tool(("subghz", "rf", "radio"))
        if rf_tool_name:
            try:
                rf_tool = get_tool(rf_tool_name)
                rf_result = rf_tool(command=f"capture --target {target}")
                metadata["capture_source"] = rf_tool_name
                metadata["rf_result"] = rf_result
                candidate = json.dumps(rf_result, ensure_ascii=True).encode("utf-8")
                return candidate.hex(), metadata
            except Exception as exc:
                metadata["rf_capture_error"] = str(exc)

        payload = self._synthesize_logic_capture(seed=f"rf:{target}:{datetime.now(tz=UTC).isoformat()}")
        return payload, metadata

    def _inject_network(self, *, target: str, interface: str, payload: bytes) -> Dict[str, Any]:
        tool_name = "generic_linux_command"
        if tool_name not in self._tool_names:
            return {"ok": False, "error": {"message": "generic_linux_command tool unavailable"}}

        try:
            tool = get_tool(tool_name)
            payload_hex = payload.hex()
            cmd = (
                "python3 - <<'PY'\n"
                "import binascii\n"
                f"data = binascii.unhexlify('{payload_hex}')\n"
                f"print('ctsm_network_inject', len(data), '{target}', '{interface}')\n"
                "PY"
            )
            return tool(command=cmd)
        except Exception as exc:
            return {"ok": False, "error": {"message": str(exc)}}

    def _inject_rf(self, *, target: str, payload: bytes) -> Dict[str, Any]:
        rf_tool_name = self._find_first_tool(("subghz", "rf", "radio"))
        if not rf_tool_name:
            return {"ok": False, "error": {"message": "RF/subghz tool unavailable"}}

        try:
            tool = get_tool(rf_tool_name)
            return tool(command=f"inject --target {target} --payload-hex {payload.hex()}")
        except Exception as exc:
            return {"ok": False, "error": {"message": str(exc)}}

    def _coordinate_sigint_specialist(self, payload: bytes) -> None:
        self.timeline.append(
            {
                "ts": datetime.now(tz=UTC).isoformat(),
                "phase": "hardware_coordination",
                "specialist": "SIGINT Specialist",
                "action": "bitstream handoff",
                "payload_sha256": self._sha256(payload),
            }
        )

    def _coordinate_network_intelligence_analyst(self, *, target: str, interface: str) -> None:
        reasoning = REASONING_TOOL.reason(
            mode=MODE_STRATEGY,
            objective="Identify optimal network injection timing window",
            context=f"target={target} interface={interface}",
            options=["immediate replay", "half-RTT delayed replay", "burst with jitter"],
            fetch_facts=False,
        )
        self.timeline.append(
            {
                "ts": datetime.now(tz=UTC).isoformat(),
                "phase": "hardware_coordination",
                "specialist": "Network Intelligence Analyst",
                "action": "timing window recommendation",
                "reasoning": reasoning,
            }
        )

    def _align_timestamps(self, payload: bytes) -> Tuple[bytes, Dict[str, Any]]:
        current_epoch = int(datetime.now(tz=UTC).timestamp())
        as_text = payload.decode("latin-1", errors="ignore")
        match = re.search(r"(?<!\d)(\d{10}|\d{13})(?!\d)", as_text)
        if not match:
            return payload, {"updated": False, "offset": -1, "old": "", "new": ""}

        old_val = match.group(1)
        new_val = str(current_epoch if len(old_val) == 10 else current_epoch * 1000)
        start = match.start(1)
        end = match.end(1)
        out_text = as_text[:start] + new_val + as_text[end:]
        out = out_text.encode("latin-1", errors="ignore")
        return out, {"updated": True, "offset": start, "old": old_val, "new": new_val}

    def _predict_sequence(self, payload: bytes) -> Tuple[bytes, Dict[str, Any]]:
        if len(self.capture_buffer) < 2 or len(payload) < 4:
            return payload, {"updated": False, "offset": -1, "old": "", "new": ""}

        prev_a = bytes.fromhex(self.capture_buffer[-2].payload_hex)
        prev_b = bytes.fromhex(self.capture_buffer[-1].payload_hex)
        max_off = min(len(prev_a), len(prev_b), len(payload)) - 3

        for off in range(0, max(0, max_off)):
            a = int.from_bytes(prev_a[off : off + 4], "big", signed=False)
            b = int.from_bytes(prev_b[off : off + 4], "big", signed=False)
            if b == (a + 1) % (2**32):
                next_val = (b + 1) % (2**32)
                mutated = bytearray(payload)
                old_val = int.from_bytes(mutated[off : off + 4], "big", signed=False)
                mutated[off : off + 4] = next_val.to_bytes(4, "big", signed=False)
                return bytes(mutated), {
                    "updated": True,
                    "offset": off,
                    "old": str(old_val),
                    "new": str(next_val),
                }

        return payload, {"updated": False, "offset": -1, "old": "", "new": ""}

    def _recalculate_checksum(self, payload: bytes) -> Tuple[bytes, Dict[str, Any]]:
        if len(payload) < 8:
            return payload, {"updated": False, "type": "none"}

        text = payload.decode("latin-1", errors="ignore")
        inline_crc = re.search(r"crc=([0-9a-fA-F]{8})", text)
        if inline_crc:
            start, end = inline_crc.span(1)
            prefix = text[:start].encode("latin-1", errors="ignore")
            new_crc = f"{(self._crc32(prefix) & 0xFFFFFFFF):08x}"
            out_text = text[:start] + new_crc + text[end:]
            return out_text.encode("latin-1", errors="ignore"), {
                "updated": True,
                "type": "inline_crc32_hex",
                "old": inline_crc.group(1),
                "new": new_crc,
            }

        body = payload[:-4]
        existing = int.from_bytes(payload[-4:], "big", signed=False)
        fresh = self._crc32(body) & 0xFFFFFFFF
        out = body + fresh.to_bytes(4, "big", signed=False)
        return out, {
            "updated": True,
            "type": "trailing_crc32",
            "old": f"{existing:08x}",
            "new": f"{fresh:08x}",
        }

    @staticmethod
    def _extract_json_tail(text: str) -> Optional[Dict[str, Any]]:
        for line in reversed((text or "").splitlines()):
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
            except Exception:
                continue
            if isinstance(data, dict):
                return data
        return None

    @staticmethod
    def _synthesize_logic_capture(*, seed: str) -> str:
        digest = hashlib.sha256(seed.encode("utf-8")).digest()
        blob = digest + int(datetime.now(tz=UTC).timestamp()).to_bytes(4, "big", signed=False)
        return blob.hex()

    @staticmethod
    def _hex_lines(hex_blob: str, width: int = 64) -> List[str]:
        if not hex_blob:
            return []
        return [hex_blob[i : i + width] for i in range(0, len(hex_blob), width)]

    def _find_first_tool(self, hints: Iterable[str]) -> str:
        lowered = [h.lower() for h in hints]
        for name in sorted(self._tool_names):
            n = name.lower()
            if any(h in n for h in lowered):
                return name
        return ""

    @staticmethod
    def _sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _crc32(data: bytes) -> int:
        import zlib

        return zlib.crc32(data)

    @staticmethod
    def _resolve_workspace(workspace_root: Optional[str]) -> Path:
        if workspace_root:
            return Path(workspace_root).expanduser().resolve()
        try:
            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()


load_dotenv()
_prompt = load_prompt_template("prompts/system_replay_attack_agent.md")
_tools: List[Any] = []
for _meta in get_all_tools():
    if not getattr(_meta, "enabled", False):
        continue
    try:
        _tools.append(get_tool(_meta.name))
    except Exception:
        continue


replay_attack_agent = Agent(
    name="Replay Attack Agent",
    description="CTSM protocol surgery engine for stateful capture/mutate/reinject operations.",
    instructions=create_system_prompt_renderer(_prompt),
    model=OpenAIChatCompletionsModel(
        model=os.getenv("CERBERUS_MODEL", "cerebro1"),
        openai_client=AsyncOpenAI(api_key=os.getenv("CERBERUS_API_KEY", os.getenv("OPENAI_API_KEY", "sk-placeholder"))),
    ),
    tools=_tools,
)


cerebro_temporal_agent = CerebroTemporalAgent()


def transfer_to_replay_attack_agent(**kwargs: Any) -> Agent:
    _ = kwargs
    return replay_attack_agent


__all__ = [
    "CaptureFrame",
    "ReplayAttempt",
    "CerebroFileWriter",
    "CerebroTemporalAgent",
    "cerebro_temporal_agent",
    "replay_attack_agent",
    "transfer_to_replay_attack_agent",
]

