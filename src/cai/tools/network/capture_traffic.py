"""Hardened forensic network capture engine for Cerberus AI."""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import threading
import time
from typing import Any, Dict, List, Optional
from uuid import uuid4

from cai.memory.logic import clean_data
from cai.repl.commands.config import CONFIG_STORE
from cai.repl.commands.shell import SecureSubprocess
from cai.repl.ui.logging import get_cerebro_logger
from cai.sdk.agents import function_tool
from cai.tools.workspace import get_project_space


_VALID_BPF_RE = re.compile(r"^[a-zA-Z0-9_ .:()\-+/=*<>!&|\[\],']*$")
_VALID_IFACE_RE = re.compile(r"^[a-zA-Z0-9_.:-]{1,64}$")


@dataclass
class CaptureStats:
    timestamp: str
    packet_count: int
    protocol_distribution: Dict[str, int]
    bytes_on_disk: int


@dataclass
class CaptureSession:
    capture_id: str
    agent_id: str
    interface: str
    capture_filter: str
    reason: str
    header_only: bool
    slice_bytes: int
    started_at: str
    pcap_path: Path
    metadata_path: Path
    size_limit_mb: int
    process: Optional[asyncio.subprocess.Process] = None
    stderr_tail: List[str] = field(default_factory=list)
    status: str = "starting"
    stop_reason: str = ""
    ended_at: str = ""
    packet_count: int = 0
    protocol_distribution: Dict[str, int] = field(default_factory=dict)
    bytes_on_disk: int = 0
    stats_history: List[CaptureStats] = field(default_factory=list)


class CerebroCaptureTool:
    """Asynchronous capture orchestration with privacy and forensic guarantees."""

    DEFAULT_SIZE_LIMIT_MB = 500
    DEFAULT_SLICE_BYTES = 96
    MIN_SLICE_BYTES = 64
    MAX_SLICE_BYTES = 96
    SAMPLE_INTERVAL_SECONDS = 5

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._evidence_root = self._workspace / "evidence" / "network"
        self._evidence_root.mkdir(parents=True, exist_ok=True)

        self._secure_subprocess = SecureSubprocess(workspace_root=self._workspace)
        self._logger = get_cerebro_logger()
        self._captures: Dict[str, CaptureSession] = {}
        self._captures_lock = threading.Lock()

        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(target=self._run_loop, daemon=True)
        self._loop_thread.start()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _run_coro(self, coro: Any, timeout: float = 25.0) -> Any:
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=timeout)

    def start_capture(
        self,
        *,
        interface: str,
        reason: str,
        capture_filter: str = "",
        header_only: bool = True,
        slice_bytes: int = DEFAULT_SLICE_BYTES,
        size_limit_mb: int = DEFAULT_SIZE_LIMIT_MB,
    ) -> Dict[str, Any]:
        try:
            return self._run_coro(
                self._start_capture_async(
                    interface=interface,
                    reason=reason,
                    capture_filter=capture_filter,
                    header_only=header_only,
                    slice_bytes=slice_bytes,
                    size_limit_mb=size_limit_mb,
                )
            )
        except Exception as exc:
            return {"ok": False, "error": {"code": "capture_start_failed", "message": str(exc)}}

    def monitor_capture(self, capture_id: str, intervals: int = 1) -> Dict[str, Any]:
        try:
            intervals = max(1, min(int(intervals), 6))
            return self._run_coro(self._monitor_capture_async(capture_id=capture_id, intervals=intervals), timeout=40.0)
        except Exception as exc:
            return {"ok": False, "error": {"code": "monitor_failed", "message": str(exc)}}

    def stop_capture(self, capture_id: str, reason: str = "manual_stop") -> Dict[str, Any]:
        try:
            return self._run_coro(self._stop_capture_async(capture_id=capture_id, reason=reason), timeout=30.0)
        except Exception as exc:
            return {"ok": False, "error": {"code": "stop_failed", "message": str(exc)}}

    def list_captures(self) -> Dict[str, Any]:
        with self._captures_lock:
            captures = [self._session_public_dict(session) for session in self._captures.values()]
        return {"ok": True, "captures": captures}

    async def _start_capture_async(
        self,
        *,
        interface: str,
        reason: str,
        capture_filter: str,
        header_only: bool,
        slice_bytes: int,
        size_limit_mb: int,
    ) -> Dict[str, Any]:
        interface = self._sanitize_interface(interface)
        self._enforce_interface_policy(interface)

        if not reason or not reason.strip():
            return {"ok": False, "error": {"code": "invalid_reason", "message": "Capture reason is required."}}

        capture_filter = self._sanitize_bpf(capture_filter)
        size_limit_mb = max(50, min(int(size_limit_mb), 2048))
        if header_only:
            slice_bytes = max(self.MIN_SLICE_BYTES, min(int(slice_bytes), self.MAX_SLICE_BYTES))
        else:
            slice_bytes = 0

        agent_id = self._agent_id()
        timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        cap_name = f"CAP_{agent_id}_{timestamp}_{self._filename_safe(interface)}.pcap"

        pcap_path = (self._evidence_root / cap_name).resolve()
        metadata_path = pcap_path.with_suffix(".metadata.json")
        capture_id = f"cap-{uuid4().hex[:12]}"

        command = self._build_capture_argv(interface, pcap_path, capture_filter, header_only, slice_bytes)
        self._secure_subprocess.enforce_denylist(" ".join(shlex.quote(part) for part in command))
        clean_env, _ = self._secure_subprocess.build_clean_environment()

        proc = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(self._workspace),
            env=clean_env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )

        session = CaptureSession(
            capture_id=capture_id,
            agent_id=agent_id,
            interface=interface,
            capture_filter=capture_filter,
            reason=reason.strip(),
            header_only=header_only,
            slice_bytes=slice_bytes,
            started_at=datetime.now(tz=UTC).isoformat(),
            pcap_path=pcap_path,
            metadata_path=metadata_path,
            size_limit_mb=size_limit_mb,
            process=proc,
            status="running",
        )

        with self._captures_lock:
            self._captures[capture_id] = session

        asyncio.create_task(self._stderr_reader(session.capture_id))
        asyncio.create_task(self._stats_sampler(session.capture_id))
        asyncio.create_task(self._size_guard(session.capture_id))
        asyncio.create_task(self._wait_for_exit(session.capture_id))

        if self._logger is not None:
            try:
                self._logger.audit(
                    "Network capture started",
                    actor="capture_traffic",
                    data={
                        "capture_id": capture_id,
                        "interface": interface,
                        "filter": capture_filter,
                        "header_only": header_only,
                        "slice_bytes": slice_bytes,
                        "artifact": str(pcap_path.relative_to(self._workspace)),
                    },
                    tags=["capture", "network", "start"],
                )
            except Exception:
                pass

        return {
            "ok": True,
            "capture_id": capture_id,
            "status": "running",
            "artifact": str(pcap_path),
            "metadata": str(metadata_path),
            "monitor_hint": "Call monitor_capture(capture_id, intervals=1+) to receive 5-second capture stats.",
        }

    async def _monitor_capture_async(self, capture_id: str, intervals: int) -> Dict[str, Any]:
        snapshots: List[Dict[str, Any]] = []
        for _ in range(intervals):
            await asyncio.sleep(self.SAMPLE_INTERVAL_SECONDS)
            with self._captures_lock:
                session = self._captures.get(capture_id)
                if not session:
                    return {
                        "ok": False,
                        "error": {"code": "capture_not_found", "message": f"Capture ID not found: {capture_id}"},
                    }
                snapshots.append(
                    {
                        "timestamp": datetime.now(tz=UTC).isoformat(),
                        "status": session.status,
                        "packet_count": session.packet_count,
                        "protocol_distribution": dict(session.protocol_distribution),
                        "bytes_on_disk": session.bytes_on_disk,
                    }
                )
                if session.status != "running":
                    break
        return {"ok": True, "capture_id": capture_id, "samples": snapshots}

    async def _stop_capture_async(self, capture_id: str, reason: str) -> Dict[str, Any]:
        with self._captures_lock:
            session = self._captures.get(capture_id)
            if not session:
                return {
                    "ok": False,
                    "error": {"code": "capture_not_found", "message": f"Capture ID not found: {capture_id}"},
                }

        if session.status in {"stopped", "failed"}:
            return {
                "ok": True,
                "capture_id": capture_id,
                "status": session.status,
                "artifact": str(session.pcap_path),
                "metadata": str(session.metadata_path),
            }

        if session.process and session.process.returncode is None:
            session.stop_reason = reason
            session.status = "stopping"
            session.process.terminate()
            try:
                await asyncio.wait_for(session.process.wait(), timeout=4.0)
            except asyncio.TimeoutError:
                session.process.kill()
                await session.process.wait()

        await self._finalize_capture(session, reason)
        return {
            "ok": True,
            "capture_id": capture_id,
            "status": session.status,
            "artifact": str(session.pcap_path),
            "metadata": str(session.metadata_path),
        }

    async def _stderr_reader(self, capture_id: str) -> None:
        while True:
            with self._captures_lock:
                session = self._captures.get(capture_id)
                if not session or not session.process or not session.process.stderr:
                    return
                stream = session.process.stderr

            line = await stream.readline()
            if not line:
                return
            text = line.decode("utf-8", errors="replace").strip()
            if text:
                with self._captures_lock:
                    if capture_id in self._captures:
                        session = self._captures[capture_id]
                        session.stderr_tail.append(text)
                        session.stderr_tail = session.stderr_tail[-30:]

    async def _stats_sampler(self, capture_id: str) -> None:
        while True:
            await asyncio.sleep(self.SAMPLE_INTERVAL_SECONDS)
            with self._captures_lock:
                session = self._captures.get(capture_id)
                if not session:
                    return
                if session.status not in {"running", "stopping"}:
                    return
                pcap_path = session.pcap_path

            stats = self._compute_live_stats(pcap_path)
            with self._captures_lock:
                session = self._captures.get(capture_id)
                if not session:
                    return
                session.packet_count = stats["packet_count"]
                session.protocol_distribution = stats["protocol_distribution"]
                session.bytes_on_disk = stats["bytes_on_disk"]
                session.stats_history.append(
                    CaptureStats(
                        timestamp=datetime.now(tz=UTC).isoformat(),
                        packet_count=session.packet_count,
                        protocol_distribution=dict(session.protocol_distribution),
                        bytes_on_disk=session.bytes_on_disk,
                    )
                )
                session.stats_history = session.stats_history[-24:]

    async def _size_guard(self, capture_id: str) -> None:
        while True:
            await asyncio.sleep(2)
            with self._captures_lock:
                session = self._captures.get(capture_id)
                if not session:
                    return
                if session.status != "running":
                    return
                limit_bytes = session.size_limit_mb * 1024 * 1024
                file_size = session.pcap_path.stat().st_size if session.pcap_path.exists() else 0
                if file_size <= limit_bytes:
                    continue

            await self._stop_capture_async(capture_id, reason="kill_switch_size_limit")
            return

    async def _wait_for_exit(self, capture_id: str) -> None:
        with self._captures_lock:
            session = self._captures.get(capture_id)
            if not session or not session.process:
                return
            proc = session.process

        return_code = await proc.wait()
        with self._captures_lock:
            session = self._captures.get(capture_id)
            if not session:
                return
            if return_code != 0 and session.status == "running":
                session.status = "failed"
                session.stop_reason = f"capture_process_exit_{return_code}"
        await self._finalize_capture(session, session.stop_reason or "process_exit")

    async def _finalize_capture(self, session: CaptureSession, reason: str) -> None:
        if session.ended_at:
            return

        session.ended_at = datetime.now(tz=UTC).isoformat()
        if session.status not in {"failed", "stopped"}:
            session.status = "stopped"
        if not session.stop_reason:
            session.stop_reason = reason or "manual_stop"

        stats = self._compute_live_stats(session.pcap_path)
        session.packet_count = stats["packet_count"]
        session.protocol_distribution = stats["protocol_distribution"]
        session.bytes_on_disk = stats["bytes_on_disk"]

        sha256 = self._sha256_file(session.pcap_path)
        metadata = {
            "capture_id": session.capture_id,
            "forensic_name": session.pcap_path.name,
            "agent_id": session.agent_id,
            "started_at": session.started_at,
            "ended_at": session.ended_at,
            "interface": session.interface,
            "capture_filter": session.capture_filter,
            "reasoning": session.reason,
            "header_only": session.header_only,
            "slice_bytes": session.slice_bytes,
            "size_limit_mb": session.size_limit_mb,
            "status": session.status,
            "stop_reason": session.stop_reason,
            "packet_count": session.packet_count,
            "protocol_distribution": session.protocol_distribution,
            "bytes_on_disk": session.bytes_on_disk,
            "sha256": sha256,
            "stderr_tail": session.stderr_tail[-12:],
        }
        session.metadata_path.parent.mkdir(parents=True, exist_ok=True)
        session.metadata_path.write_text(json.dumps(clean_data(metadata), indent=2, ensure_ascii=True), encoding="utf-8")

        if self._logger is not None:
            try:
                self._logger.audit(
                    "Network capture finalized",
                    actor="capture_traffic",
                    data={
                        "capture_id": session.capture_id,
                        "status": session.status,
                        "stop_reason": session.stop_reason,
                        "artifact": str(session.pcap_path.relative_to(self._workspace)),
                        "sha256": sha256,
                    },
                    tags=["capture", "network", "finalize"],
                )
            except Exception:
                pass

    def _compute_live_stats(self, pcap_path: Path) -> Dict[str, Any]:
        size = pcap_path.stat().st_size if pcap_path.exists() else 0
        if not pcap_path.exists() or size == 0:
            return {"packet_count": 0, "protocol_distribution": {}, "bytes_on_disk": size}

        protocols: Dict[str, int] = {}
        packet_count = 0

        try:
            from scapy.layers.inet import ICMP, IP, TCP, UDP
            from scapy.layers.inet6 import IPv6
            from scapy.layers.l2 import ARP, Ether
            from scapy.utils import RawPcapReader

            for raw_pkt, _metadata in RawPcapReader(str(pcap_path)):
                packet_count += 1
                proto = "OTHER"
                try:
                    frame = Ether(raw_pkt)
                    if frame.haslayer(ARP):
                        proto = "ARP"
                    elif frame.haslayer(TCP):
                        proto = "TCP"
                    elif frame.haslayer(UDP):
                        proto = "UDP"
                    elif frame.haslayer(ICMP):
                        proto = "ICMP"
                    elif frame.haslayer(IP):
                        proto = "IP"
                    elif frame.haslayer(IPv6):
                        proto = "IPv6"
                except Exception:
                    proto = "OTHER"
                protocols[proto] = protocols.get(proto, 0) + 1
        except Exception:
            packet_count = 0
            protocols = {}

        return {
            "packet_count": packet_count,
            "protocol_distribution": protocols,
            "bytes_on_disk": size,
        }

    def _build_capture_argv(
        self,
        interface: str,
        pcap_path: Path,
        capture_filter: str,
        header_only: bool,
        slice_bytes: int,
    ) -> List[str]:
        tcpdump = shutil.which("tcpdump")
        if not tcpdump:
            raise RuntimeError("tcpdump executable not found in PATH.")

        argv = [
            tcpdump,
            "-U",
            "-n",
            "-i",
            interface,
            "-w",
            str(pcap_path),
        ]
        if header_only:
            argv.extend(["-s", str(slice_bytes)])
        if capture_filter:
            argv.extend(shlex.split(capture_filter))
        return argv

    def _sanitize_bpf(self, capture_filter: str) -> str:
        filter_text = (capture_filter or "").strip()
        if not filter_text:
            return ""
        if len(filter_text) > 300:
            raise ValueError("BPF filter too long.")
        if not _VALID_BPF_RE.fullmatch(filter_text):
            raise ValueError("BPF filter contains unsupported characters.")
        return filter_text

    def _sanitize_interface(self, interface: str) -> str:
        value = (interface or "").strip()
        if not value:
            raise ValueError("Network interface is required.")
        if not _VALID_IFACE_RE.fullmatch(value):
            raise ValueError("Invalid network interface format.")
        return value

    def _enforce_interface_policy(self, interface: str) -> None:
        available = {name for _idx, name in socket.if_nameindex()}
        if interface not in available:
            raise ValueError(f"Interface not present on host: {interface}")

        permitted = self._permitted_interfaces()
        if interface not in permitted:
            raise PermissionError(
                f"Interface '{interface}' denied by policy. Permitted interfaces: {', '.join(sorted(permitted))}"
            )

    def _permitted_interfaces(self) -> set[str]:
        config_keys = [
            "CEREBRO_CAPTURE_PERMITTED_INTERFACES",
            "CEREBRO_PERMITTED_CAPTURE_INTERFACES",
            "PERMITTED_INTERFACES",
        ]
        raw = ""
        for key in config_keys:
            value = CONFIG_STORE.get(key)
            if value and value != "Not set":
                raw = value
                break
        if not raw:
            raw = os.getenv("CEREBRO_CAPTURE_PERMITTED_INTERFACES", "")

        parsed: set[str] = set()
        if raw:
            text = raw.strip()
            if text.startswith("["):
                try:
                    parsed = {str(item).strip() for item in json.loads(text) if str(item).strip()}
                except Exception:
                    parsed = set()
            else:
                parsed = {item.strip() for item in text.split(",") if item.strip()}

        if not parsed:
            parsed = {"lo"}
        return parsed

    @staticmethod
    def _sha256_file(path: Path) -> str:
        if not path.exists():
            return ""
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _filename_safe(value: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_.-]", "_", value)[:64] or "iface"

    @staticmethod
    def _agent_id() -> str:
        for key in ("CEREBRO_AGENT_ID", "AGENT_ID", "CEREBRO_AGENT", "CEREBRO_AGENT_TYPE"):
            candidate = os.getenv(key, "").strip()
            if candidate:
                return re.sub(r"[^a-zA-Z0-9_-]", "_", candidate)[:40]
        return "unknown-agent"

    def _session_public_dict(self, session: CaptureSession) -> Dict[str, Any]:
        return clean_data(
            {
                "capture_id": session.capture_id,
                "agent_id": session.agent_id,
                "status": session.status,
                "interface": session.interface,
                "capture_filter": session.capture_filter,
                "header_only": session.header_only,
                "slice_bytes": session.slice_bytes,
                "started_at": session.started_at,
                "ended_at": session.ended_at,
                "bytes_on_disk": session.bytes_on_disk,
                "packet_count": session.packet_count,
                "protocol_distribution": session.protocol_distribution,
                "artifact": str(session.pcap_path),
                "metadata": str(session.metadata_path),
                "stop_reason": session.stop_reason,
                "stderr_tail": session.stderr_tail[-8:],
            }
        )


CAPTURE_TOOL = CerebroCaptureTool()


@function_tool
def capture_remote_traffic(
    ip: str,
    username: str,
    password: str,
    interface: str,
    capture_filter: str = "",
    port: int = 22,
    timeout: int = 10,
    reason: str = "Network forensic acquisition",
    header_only: bool = True,
    slice_bytes: int = 96,
    size_limit_mb: int = 500,
) -> Dict[str, Any]:
    """Backward-compatible tool name that now starts local hardened background capture."""
    _ = (ip, username, password, port, timeout)
    return CAPTURE_TOOL.start_capture(
        interface=interface,
        reason=reason,
        capture_filter=capture_filter,
        header_only=header_only,
        slice_bytes=slice_bytes,
        size_limit_mb=size_limit_mb,
    )


@function_tool
def monitor_capture(capture_id: str, intervals: int = 1) -> Dict[str, Any]:
    """Return capture packet count and protocol distribution snapshots every 5 seconds."""
    return CAPTURE_TOOL.monitor_capture(capture_id=capture_id, intervals=intervals)


@function_tool
def stop_capture(capture_id: str, reason: str = "manual_stop") -> Dict[str, Any]:
    """Stop a running background capture and finalize forensic metadata."""
    return CAPTURE_TOOL.stop_capture(capture_id=capture_id, reason=reason)


@function_tool
def list_captures() -> Dict[str, Any]:
    """List active and completed capture sessions managed by this runtime."""
    return CAPTURE_TOOL.list_captures()


@function_tool
@contextmanager
def remote_capture_session(
    ip: str,
    username: str,
    password: str,
    interface: str,
    capture_filter: str = "",
    port: int = 22,
    timeout: int = 10,
    reason: str = "Scoped forensic capture session",
    header_only: bool = True,
    slice_bytes: int = 96,
    size_limit_mb: int = 500,
):
    """Compatibility context manager for managed start/stop capture lifecycle."""
    start = capture_remote_traffic(
        ip=ip,
        username=username,
        password=password,
        interface=interface,
        capture_filter=capture_filter,
        port=port,
        timeout=timeout,
        reason=reason,
        header_only=header_only,
        slice_bytes=slice_bytes,
        size_limit_mb=size_limit_mb,
    )
    if not start.get("ok"):
        raise RuntimeError((start.get("error") or {}).get("message", "capture start failed"))

    capture_id = str(start["capture_id"])
    try:
        yield {
            "capture_id": capture_id,
            "pcap_path": start.get("artifact"),
            "metadata_path": start.get("metadata"),
        }
    finally:
        CAPTURE_TOOL.stop_capture(capture_id, reason="context_exit")


__all__ = [
    "CerebroCaptureTool",
    "capture_remote_traffic",
    "monitor_capture",
    "stop_capture",
    "list_captures",
    "remote_capture_session",
]