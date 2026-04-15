"""Cerebro Protocol Intelligence Engine (CPIE).

Transparent, high-velocity network intelligence for the Cerberus AI suite.

Key responsibilities:
- Async host liveness probing with high concurrency
- Service discovery and raw banner identification over standard asyncio streams
- RAM-resident live network map with immediate CCMB + CHPE commits
- Plain-text forensic audit logging with raw hex dumps of initial responses
- External-tool execution gated by validation.py and binary availability checks
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import importlib.util
import ipaddress
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
from typing import Any, Callable, Dict, List, Optional, Sequence, cast

_SCHEMA_WORKSPACE_ROOT = Path(os.getenv("CIR_WORKSPACE", Path.cwd())).resolve()
os.environ.setdefault("CIR_WORKSPACE", str(_SCHEMA_WORKSPACE_ROOT))

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore[assignment]

from cai.internal.components.schema import (
    CerebroFinding,
    ExecutionTelemetry,
    ToolRequest,
    ToolResult,
    VulnerabilityDetails,
)
from cai.memory.memory import CerebroMemoryBus
from cai.memory.storage import CerebroStorageHandler, EvidenceRecord
from cai.tools.reconnaissance.filesystem import PathGuard as FilesystemPathGuard
from cai.tools.validation import validate_resource_health

CerebroConfig = Any


def _load_config_factory() -> Callable[[], Any]:
    _CONFIG_MODULE_PATH = Path(__file__).resolve().parents[2] / "util" / "config.py"
    _CONFIG_SPEC = importlib.util.spec_from_file_location("cai.util.config", _CONFIG_MODULE_PATH)
    if _CONFIG_SPEC is None or _CONFIG_SPEC.loader is None:  # pragma: no cover
        raise ImportError(f"Unable to load Cerebro config module from {_CONFIG_MODULE_PATH}")
    _CONFIG_MODULE = importlib.util.module_from_spec(_CONFIG_SPEC)
    sys.modules.setdefault("cai.util.config", _CONFIG_MODULE)
    _CONFIG_SPEC.loader.exec_module(_CONFIG_MODULE)
    _CONFIG_MODULE.CerebroConfig.model_rebuild()
    return cast(Callable[[], Any], _CONFIG_MODULE.get_cerebro_config)


get_cerebro_config = _load_config_factory()


_CPIE_LOGGER = logging.getLogger("cai.cpie")

_DEFAULT_READ_TIMEOUT = 1.0
_DEFAULT_CONNECT_TIMEOUT = 1.5
_DEFAULT_PROBE_PORTS = (22, 80, 443, 445, 53)
_DEFAULT_SERVICE_PORTS = (21, 22, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443)
_BANNER_READ_BYTES = 2048


class _NetworkPathGuardViolation(PermissionError):
    """Raised when CPIE attempts to write outside the workspace."""


class _NetworkAuditWriter:
    """PathGuard-backed audit and evidence writer for CPIE."""

    def __init__(self, workspace_root: Path) -> None:
        self.workspace_root = workspace_root.resolve()
        self._guard = FilesystemPathGuard(self.workspace_root, self._audit)
        self._lock = threading.Lock()

    def append_json_line(self, relative_path: str, payload: Dict[str, Any]) -> Path:
        resolved = self._validate(relative_path, mode="write")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(payload, ensure_ascii=True, default=str) + "\n"
        with self._lock:
            with resolved.open("a", encoding="utf-8") as handle:
                handle.write(line)
        return resolved

    def write_text(self, relative_path: str, content: str) -> Path:
        resolved = self._validate(relative_path, mode="write")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            resolved.write_text(content, encoding="utf-8")
        return resolved

    def write_bytes(self, relative_path: str, content: bytes) -> Path:
        resolved = self._validate(relative_path, mode="write")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            resolved.write_bytes(content)
        return resolved

    def _validate(self, relative_path: str, *, mode: str) -> Path:
        try:
            return self._guard.validate_path(relative_path, action="cpie_write", mode=mode)
        except Exception as exc:
            raise _NetworkPathGuardViolation(str(exc)) from exc

    @staticmethod
    def _audit(*_args: Any, **_kwargs: Any) -> None:
        return


class CerebroProtocolEngine:
    """High-velocity network discovery and protocol identification engine."""

    def __init__(
        self,
        *,
        workspace_root: Optional[str] = None,
        config: Optional["CerebroConfig"] = None,
        memory_bus: Optional[CerebroMemoryBus] = None,
        storage_handler: Optional[CerebroStorageHandler] = None,
        max_concurrency: Optional[int] = None,
        connect_timeout: float = _DEFAULT_CONNECT_TIMEOUT,
        read_timeout: float = _DEFAULT_READ_TIMEOUT,
    ) -> None:
        self.config = config or get_cerebro_config()
        self.config.ensure_workspace_dirs()
        self.workspace_root = Path(workspace_root or str(self.config.workspace_root)).resolve()
        self.contract_root = Path(os.getenv("CIR_WORKSPACE", str(self.workspace_root))).resolve()
        self.path_guard = FilesystemPathGuard(self.contract_root, self._pathguard_audit)
        self.writer = _NetworkAuditWriter(self.contract_root)
        self.memory_bus = memory_bus or CerebroMemoryBus.get_instance(workspace_root=str(self.workspace_root))
        self.storage_handler = storage_handler or CerebroStorageHandler.get_instance(workspace_root=str(self.workspace_root))
        self.audit_log_path = "logs/network_audit.json"
        self.connect_timeout = float(connect_timeout)
        self.read_timeout = float(read_timeout)
        self.max_concurrency = max_concurrency or self._derive_max_concurrency()
        self._semaphore = asyncio.Semaphore(self.max_concurrency)
        self._lock = asyncio.Lock()
        self._live_network_map: Dict[str, Dict[str, Any]] = {}

    async def ping_sweep(
        self,
        targets: Sequence[str] | str,
        *,
        probe_ports: Optional[Sequence[int]] = None,
    ) -> List[Dict[str, Any]]:
        """Probe targets for liveness using transparent TCP connects.

        Since asyncio streams operate at the TCP layer, liveness is determined by
        connectability to one or more probe ports rather than ICMP.
        """
        hosts = self._expand_targets(targets)
        ports = list(probe_ports or _DEFAULT_PROBE_PORTS)
        tasks = [asyncio.create_task(self._probe_host_liveness(host, ports)) for host in hosts]
        results = await asyncio.gather(*tasks)
        live_hosts = [result for result in results if result.get("alive")]
        return live_hosts

    async def service_discovery(
        self,
        host: str,
        *,
        ports: Optional[Sequence[int]] = None,
    ) -> List[Dict[str, Any]]:
        """Identify open ports and collect high-fidelity service fingerprints."""
        scan_ports = list(ports or _DEFAULT_SERVICE_PORTS)
        tasks = [asyncio.create_task(self._transparent_identification(host, port)) for port in scan_ports]
        results = await asyncio.gather(*tasks)
        return [result for result in results if result.get("open")]

    async def banner_grab(
        self,
        host: str,
        port: int,
        *,
        protocol_hint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Open a raw stream and capture an initial service response."""
        async with self._semaphore:
            started_at = datetime.now(tz=UTC).isoformat(timespec="milliseconds")
            telemetry_before = self._capture_execution_telemetry()
            writer: Optional[asyncio.StreamWriter] = None
            response = b""
            error_message = ""
            connected = False
            identified_protocol = protocol_hint or self._guess_protocol_from_port(port)
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.connect_timeout,
                )
                connected = True
                request_payload = self._build_banner_probe(host, port, identified_protocol)
                if request_payload:
                    writer.write(request_payload)
                    await writer.drain()
                response = await asyncio.wait_for(reader.read(_BANNER_READ_BYTES), timeout=self.read_timeout)
            except Exception as exc:
                error_message = str(exc)
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

            hex_dump = response.hex()
            banner_text = response.decode("utf-8", errors="replace").strip()
            identified_protocol = self._identify_protocol(port, response, identified_protocol)
            result = {
                "host": host,
                "port": int(port),
                "open": connected,
                "protocol": identified_protocol,
                "banner": banner_text,
                "hex_dump": hex_dump,
                "raw_bytes": response,
                "error": error_message,
                "started_at": started_at,
                "telemetry": telemetry_before.model_dump(mode="json"),
            }
            await self._log_interaction(host=host, port=port, result=result)
            return result

    async def execute_external_tool(
        self,
        tool_name: str,
        *args: str,
    ) -> ToolResult:
        """Execute an external discovery binary after validator + binary checks."""
        health = await validate_resource_health(
            min_disk_free_mb=512,
            min_memory_free_mb=1024,
            max_cpu_load_1m=12.0,
        )
        if not health.get("ok"):
            raise RuntimeError(f"validation.py resource gate failed for {tool_name}: {health}")
        binary_path = shutil.which(tool_name)
        if not binary_path:
            raise FileNotFoundError(f"External discovery tool not available: {tool_name}")

        request = ToolRequest(
            tool_name=tool_name,
            parameters={"args": list(args), "binary_path": binary_path},
            requester_agent="cpie",
        )
        proc = await asyncio.create_subprocess_exec(
            binary_path,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_raw, stderr_raw = await proc.communicate()
        telemetry = self._capture_execution_telemetry()
        result = ToolResult(
            request_id=request.request_id,
            tool_name=tool_name,
            stdout=stdout_raw.decode("utf-8", errors="replace"),
            stderr=stderr_raw.decode("utf-8", errors="replace"),
            exit_code=int(proc.returncode or 0),
            telemetry=telemetry,
            artifacts={"binary_path": binary_path, "args": list(args)},
        )
        await self._log_external_tool(request=request, result=result)
        return result

    async def get_live_network_map(self) -> Dict[str, Dict[str, Any]]:
        """Return the in-memory network state map."""
        async with self._lock:
            return json.loads(json.dumps(self._live_network_map, default=str))

    async def process(self, target: str) -> Dict[str, Any]:
        """Backward-compatible wrapper that performs discovery on a target."""
        liveness = await self.ping_sweep([target])
        services = await self.service_discovery(target)
        return {
            "ok": True,
            "live": liveness,
            "services": services,
            "target": target,
        }

    async def _probe_host_liveness(self, host: str, probe_ports: Sequence[int]) -> Dict[str, Any]:
        for port in probe_ports:
            result = await self.banner_grab(host, port)
            if result.get("open") and not result.get("error"):
                await self._update_live_network_map(host, result)
                return {
                    "host": host,
                    "alive": True,
                    "responsive_port": port,
                    "protocol": result.get("protocol"),
                }
        return {"host": host, "alive": False}

    async def _transparent_identification(self, host: str, port: int) -> Dict[str, Any]:
        result = await self.banner_grab(host, port)
        if not result.get("open") or result.get("error"):
            return result
        await self._update_live_network_map(host, result)
        await self._commit_service_finding(host, port, result)
        return result

    async def _update_live_network_map(self, host: str, result: Dict[str, Any]) -> None:
        async with self._lock:
            host_entry = self._live_network_map.setdefault(
                host,
                {
                    "host": host,
                    "first_seen": datetime.now(tz=UTC).isoformat(timespec="milliseconds"),
                    "last_seen": datetime.now(tz=UTC).isoformat(timespec="milliseconds"),
                    "services": {},
                },
            )
            host_entry["last_seen"] = datetime.now(tz=UTC).isoformat(timespec="milliseconds")
            host_entry["services"][str(result["port"])] = {
                "protocol": result.get("protocol"),
                "banner": result.get("banner"),
                "hex_dump": result.get("hex_dump"),
            }

    async def _commit_service_finding(self, host: str, port: int, result: Dict[str, Any]) -> None:
        evidence_rel = f"loot/network/banners/{self._safe_host(host)}_{port}.txt"
        evidence_text = "\n".join(
            [
                f"host={host}",
                f"port={port}",
                f"protocol={result.get('protocol', 'unknown')}",
                f"banner={result.get('banner', '')}",
                f"hex_dump={result.get('hex_dump', '')}",
            ]
        )
        evidence_path = self.writer.write_text(evidence_rel, evidence_text)

        finding = CerebroFinding(
            target_id=host,
            service_vector=f"tcp/{port} {result.get('protocol', 'unknown')}",
            vulnerability_details=VulnerabilityDetails(
                severity="Info",
                title="Transparent Service Discovery",
                summary=(
                    f"Open service identified on {host}:{port} with protocol "
                    f"{result.get('protocol', 'unknown')} and captured banner data."
                ),
            ),
            evidence_pointer=evidence_path,
            validation_status="Confirmed",
            tags=["network", "service_discovery", result.get("protocol", "unknown")],
        )

        self.memory_bus.set_logic(
            f"host.{self._safe_host(host)}.port.{port}.protocol",
            result.get("protocol", "unknown"),
            importance=4,
            agent_id="cpie",
        )
        self.memory_bus.set_logic(
            f"host.{self._safe_host(host)}.port.{port}.banner",
            result.get("banner", ""),
            importance=3,
            agent_id="cpie",
        )
        self.storage_handler.append_now(
            EvidenceRecord(
                topic=f"network.service.{host}:{port}",
                finding=finding.to_jsonl(),
                source="cpie",
                tags=[host, str(port), str(result.get("protocol", "unknown"))],
                artifacts={"evidence_pointer": str(evidence_path)},
            )
        )

    async def _log_interaction(self, host: str, port: int, result: Dict[str, Any]) -> None:
        event = {
            "timestamp": datetime.now(tz=UTC).isoformat(timespec="milliseconds"),
            "host": host,
            "port": port,
            "protocol": result.get("protocol"),
            "open": result.get("open"),
            "banner": result.get("banner"),
            "hex_dump": result.get("hex_dump"),
            "error": result.get("error"),
            "telemetry": result.get("telemetry"),
        }
        await asyncio.to_thread(self.writer.append_json_line, self.audit_log_path, event)

    async def _log_external_tool(self, request: ToolRequest, result: ToolResult) -> None:
        event = {
            "timestamp": datetime.now(tz=UTC).isoformat(timespec="milliseconds"),
            "event": "external_tool_execution",
            "request": request.model_dump(mode="json"),
            "result": result.model_dump(mode="json"),
        }
        await asyncio.to_thread(self.writer.append_json_line, self.audit_log_path, event)

    def _derive_max_concurrency(self) -> int:
        configured = os.getenv("CEREBRO_NETWORK_MAX_CONCURRENCY")
        if configured:
            try:
                return max(16, min(512, int(configured)))
            except ValueError:
                pass
        reserve_gb = self.config.ram.system_reserve_gb
        derived = int(reserve_gb * 4)
        return max(64, min(256, derived))

    def _expand_targets(self, targets: Sequence[str] | str) -> List[str]:
        raw_targets = [targets] if isinstance(targets, str) else list(targets)
        expanded: List[str] = []
        for target in raw_targets:
            try:
                network = ipaddress.ip_network(target, strict=False)
                expanded.extend(str(host) for host in network.hosts())
            except ValueError:
                expanded.append(str(target))
        return expanded

    def _build_banner_probe(self, host: str, port: int, protocol: str) -> bytes:
        protocol_lower = protocol.lower()
        if protocol_lower in {"http", "https"}:
            return f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii", errors="ignore")
        if protocol_lower == "smtp":
            return b"EHLO cerebro.local\r\n"
        if protocol_lower == "pop3":
            return b"CAPA\r\n"
        if protocol_lower == "imap":
            return b"a1 CAPABILITY\r\n"
        if protocol_lower == "redis":
            return b"*1\r\n$4\r\nPING\r\n"
        if protocol_lower == "dns":
            return b""
        if protocol_lower == "smb":
            return bytes.fromhex(
                "00000054ff534d4272000000001843c8000000000000000000000000"
                "00000000000000006200025043204e4554574f524b2050524f4752414d"
                "20312e3000024c414e4d414e312e30000257696e646f777320666f722057"
                "6f726b67726f75707320332e316100024c4d312e325830303200024c414e"
                "4d414e322e3100024e54204c4d20302e313200"
            )
        return b"\r\n"

    def _guess_protocol_from_port(self, port: int) -> str:
        mapping = {
            21: "ftp",
            22: "ssh",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            139: "smb",
            143: "imap",
            443: "https",
            445: "smb",
            993: "imap",
            995: "pop3",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            6379: "redis",
            8080: "http",
            8443: "https",
        }
        return mapping.get(int(port), "raw")

    def _identify_protocol(self, port: int, response: bytes, fallback: str) -> str:
        if not response:
            return fallback
        response_upper = response.upper()
        if response.startswith(b"SSH-"):
            return "ssh"
        if b"HTTP/" in response_upper or b"SERVER:" in response_upper:
            return "http"
        if response.startswith(b"\xffSMB") or b"NT LM 0.12" in response_upper or b"SMB" in response_upper:
            return "smb"
        if response.startswith(b"220") and b"SMTP" in response_upper:
            return "smtp"
        if response.startswith(b"+OK"):
            return "pop3"
        if b"* OK" in response_upper or b"CAPABILITY" in response_upper:
            return "imap"
        if response.startswith(b"-ERR") or b"REDIS" in response_upper:
            return "redis"
        if b"RDP" in response_upper or port == 3389:
            return "rdp"
        return fallback

    def _capture_execution_telemetry(self) -> ExecutionTelemetry:
        ram_total_gb = self.config.total_system_ram_gb
        ram_used_gb = 0.0
        ram_pct = 0.0
        if psutil is not None:
            try:
                vm = psutil.virtual_memory()
                ram_total_gb = round(vm.total / (1024 ** 3), 2)
                ram_used_gb = round(vm.used / (1024 ** 3), 2)
                ram_pct = round(float(vm.percent), 1)
            except Exception:
                pass

        vram_used_mb = 0.0
        vram_total_mb = float(self.config.gpu.target_vram_mb)
        vram_pct = 0.0
        gpu_name = self.config.gpu.target_gpu_name
        try:
            output = subprocess.check_output(
                [
                    "nvidia-smi",
                    "--query-gpu=name,memory.used,memory.total",
                    "--format=csv,noheader,nounits",
                ],
                stderr=subprocess.DEVNULL,
                timeout=2,
            ).decode("utf-8", errors="replace").strip().splitlines()
            if output:
                parts = [part.strip() for part in output[0].split(",")]
                if len(parts) >= 3:
                    gpu_name = parts[0]
                    vram_used_mb = float(parts[1])
                    vram_total_mb = float(parts[2])
                    if vram_total_mb > 0:
                        vram_pct = round((vram_used_mb / vram_total_mb) * 100.0, 1)
        except Exception:
            pass

        return ExecutionTelemetry(
            ram_used_gb=ram_used_gb,
            ram_total_gb=ram_total_gb,
            ram_pct=ram_pct,
            vram_used_mb=vram_used_mb,
            vram_total_mb=vram_total_mb,
            vram_pct=vram_pct,
            gpu_name=gpu_name,
        )

    @staticmethod
    def _safe_host(host: str) -> str:
        return host.replace(":", "_").replace("/", "_").replace(".", "_")

    @staticmethod
    def _pathguard_audit(_event: str, _payload: Any) -> None:
        return


CerebroNetworkEngine = CerebroProtocolEngine


__all__ = ["CerebroNetworkEngine", "CerebroProtocolEngine"]
