"""Platform capability auditor for Cerebro REPL.

This module provides a structured, cached system audit covering:
- kernel / OS / architecture profiling
- virtualization and container detection
- common binary availability mapping
- security mitigation assessment
- privacy-aware fingerprint redaction
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cerberus.memory import MemoryManager
from cerberus.repl.commands.base import FrameworkCommand, register_command
from cerberus.tools.workspace import get_project_space

try:
    from cerberus.repl.commands.config import CONFIG_STORE
except Exception:  # pragma: no cover - config module may not be ready during bootstrap
    CONFIG_STORE = None


console = Console()


class KernelProfile(BaseModel):
    family: str = "unknown"
    release: str = "unknown"
    build: str = "unknown"


class OSProfile(BaseModel):
    family: str = "unknown"
    distribution: str = "unknown"
    version: str = "unknown"


class ArchitectureProfile(BaseModel):
    machine: str = "unknown"
    word_size_bits: int = 0


class VirtualizationProfile(BaseModel):
    container: Optional[str] = None
    virtual_machine: Optional[str] = None
    wsl: bool = False
    summary: str = "bare-metal"


class SecurityAssessment(BaseModel):
    aslr: str = "unknown"
    nx: str = "unknown"
    edr_present: bool = False
    edr_processes: List[str] = Field(default_factory=list)


class ToolPresence(BaseModel):
    name: str
    available: bool
    path: Optional[str] = None


class PlatformSpecs(BaseModel):
    audited_at: str
    kernel: KernelProfile
    os: OSProfile
    architecture: ArchitectureProfile
    virtualization: VirtualizationProfile
    tools: List[ToolPresence] = Field(default_factory=list)
    security: SecurityAssessment
    host_identifier: str = "[REDACTED]"
    privacy_redacted: bool = True


class SystemAuditor:
    """Cached capability auditor for the active execution platform."""

    _COMMON_TOOLS = (
        "nmap",
        "msfconsole",
        "gdb",
        "lldb",
        "radare2",
        "r2",
        "strace",
        "ltrace",
        "tcpdump",
        "tshark",
        "sqlmap",
        "nikto",
        "john",
        "hashcat",
        "hydra",
        "socat",
        "nc",
        "curl",
        "wget",
        "ssh",
    )

    _EDR_MARKERS = (
        "falcon",
        "crowdstrike",
        "sentinelone",
        "carbonblack",
        "cbagent",
        "mdatp",
        "defender",
        "elastic-endpoint",
        "cylance",
        "sophos",
        "trellix",
        "xdr",
    )

    def __init__(self, *, memory: MemoryManager, workspace_root: Path) -> None:
        self._memory = memory
        self._workspace_root = workspace_root.resolve()
        self._cache: Optional[PlatformSpecs] = None
        self._lock = asyncio.Lock()
        self._audit_path = self._workspace_root / ".cerberus" / "audit" / "platform_audit.jsonl"

    async def audit(self, *, refresh: bool = False) -> PlatformSpecs:
        async with self._lock:
            if self._cache is not None and not refresh:
                return self._cache

            specs = await self._collect_specs()
            self._cache = specs
            await asyncio.to_thread(self._record_audit, specs)
            return specs

    async def _collect_specs(self) -> PlatformSpecs:
        kernel = await asyncio.to_thread(self._collect_kernel)
        os_profile = await asyncio.to_thread(self._collect_os)
        arch = await asyncio.to_thread(self._collect_architecture)
        virt = await asyncio.to_thread(self._collect_virtualization)
        tools = await asyncio.to_thread(self._collect_tools)
        security = await asyncio.to_thread(self._collect_security)
        allow_fingerprint = self._allow_fingerprint()
        host_identifier = await asyncio.to_thread(self._collect_host_identifier, allow_fingerprint)

        return PlatformSpecs(
            audited_at=datetime.now(tz=UTC).isoformat(),
            kernel=kernel,
            os=os_profile,
            architecture=arch,
            virtualization=virt,
            tools=tools,
            security=security,
            host_identifier=host_identifier,
            privacy_redacted=not allow_fingerprint,
        )

    def _collect_kernel(self) -> KernelProfile:
        ostype = self._read_text_file(Path("/proc/sys/kernel/ostype")) or self._run_cmd(["uname", "-s"]) or "unknown"
        release = self._read_text_file(Path("/proc/sys/kernel/osrelease")) or self._run_cmd(["uname", "-r"]) or "unknown"
        build = self._read_text_file(Path("/proc/sys/kernel/version")) or self._run_cmd(["uname", "-v"]) or "unknown"
        return KernelProfile(family=ostype.strip(), release=release.strip(), build=build.strip())

    def _collect_os(self) -> OSProfile:
        data = self._parse_os_release()
        family = data.get("ID", data.get("NAME", "unknown"))
        distribution = data.get("PRETTY_NAME", data.get("NAME", "unknown"))
        version = data.get("VERSION_ID", data.get("VERSION", "unknown"))
        return OSProfile(family=family, distribution=distribution, version=version)

    def _collect_architecture(self) -> ArchitectureProfile:
        machine = self._run_cmd(["uname", "-m"]) or self._cpu_arch_from_proc() or "unknown"
        bits = 64 if machine in {"x86_64", "aarch64", "arm64", "ppc64le", "s390x"} else 32 if machine != "unknown" else 0
        return ArchitectureProfile(machine=machine, word_size_bits=bits)

    def _collect_virtualization(self) -> VirtualizationProfile:
        container = None
        virtual_machine = None
        wsl = False

        if Path("/.dockerenv").exists() or self._file_contains(Path("/proc/1/cgroup"), ("docker", "containerd", "kubepods")):
            container = "docker"
        elif self._file_contains(Path("/proc/1/environ"), ("container=podman",)):
            container = "podman"

        if os.getenv("WSL_INTEROP") or self._file_contains(Path("/proc/version"), ("microsoft", "wsl")):
            wsl = True

        detected_virt = self._run_cmd(["systemd-detect-virt", "--quiet", "--container"]) if shutil.which("systemd-detect-virt") else None
        if detected_virt:
            container = detected_virt.strip() or container

        vm_detect = self._run_cmd(["systemd-detect-virt", "--vm"]) if shutil.which("systemd-detect-virt") else None
        if vm_detect and vm_detect.strip() and vm_detect.strip() not in {"none", ""}:
            virtual_machine = vm_detect.strip()
        elif self._file_contains(Path("/sys/class/dmi/id/product_name"), ("virtualbox", "vmware", "kvm", "qemu", "hyper-v")):
            virtual_machine = (self._read_text_file(Path("/sys/class/dmi/id/product_name")) or "vm").strip()

        summary_parts: List[str] = []
        if container:
            summary_parts.append(f"container:{container}")
        if virtual_machine:
            summary_parts.append(f"vm:{virtual_machine}")
        if wsl:
            summary_parts.append("wsl")
        summary = ", ".join(summary_parts) if summary_parts else "bare-metal"

        return VirtualizationProfile(container=container, virtual_machine=virtual_machine, wsl=wsl, summary=summary)

    def _collect_tools(self) -> List[ToolPresence]:
        results: List[ToolPresence] = []
        seen: set[str] = set()
        for tool in self._COMMON_TOOLS:
            if tool in seen:
                continue
            seen.add(tool)
            path = shutil.which(tool)
            results.append(ToolPresence(name=tool, available=path is not None, path=path))
        return results

    def _collect_security(self) -> SecurityAssessment:
        aslr = "unknown"
        aslr_value = self._read_text_file(Path("/proc/sys/kernel/randomize_va_space"))
        if aslr_value is not None:
            value = aslr_value.strip()
            aslr = {"0": "disabled", "1": "conservative", "2": "full"}.get(value, f"unknown({value})")

        nx = "unknown"
        cpuinfo = self._read_text_file(Path("/proc/cpuinfo")) or ""
        lower_cpuinfo = cpuinfo.lower()
        if " nx " in f" {lower_cpuinfo} " or " nx\n" in lower_cpuinfo:
            nx = "enabled"
        elif lower_cpuinfo:
            nx = "not-detected"

        edr_processes = self._find_edr_processes()
        return SecurityAssessment(
            aslr=aslr,
            nx=nx,
            edr_present=bool(edr_processes),
            edr_processes=edr_processes,
        )

    def _collect_host_identifier(self, allow_fingerprint: bool) -> str:
        if not allow_fingerprint:
            return "[REDACTED]"

        for candidate in (
            Path("/etc/machine-id"),
            Path("/var/lib/dbus/machine-id"),
            Path("/sys/class/dmi/id/product_uuid"),
        ):
            value = self._read_text_file(candidate)
            if value:
                return value.strip()
        return "unknown"

    def _find_edr_processes(self) -> List[str]:
        text = self._run_cmd(["ps", "-eo", "comm="]) or ""
        lower_lines = [line.strip().lower() for line in text.splitlines() if line.strip()]
        hits: List[str] = []
        for line in lower_lines:
            for marker in self._EDR_MARKERS:
                if marker in line and line not in hits:
                    hits.append(line)
        return hits

    def _record_audit(self, specs: PlatformSpecs) -> None:
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "timestamp": specs.audited_at,
            "kernel": specs.kernel.model_dump(mode="python"),
            "os": specs.os.model_dump(mode="python"),
            "architecture": specs.architecture.model_dump(mode="python"),
            "virtualization": specs.virtualization.model_dump(mode="python"),
            "tools_found": [tool.name for tool in specs.tools if tool.available],
            "privacy_redacted": specs.privacy_redacted,
        }
        with self._audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=True) + "\n")

        self._memory.record(
            {
                "topic": "platform.audit",
                "finding": f"Platform capability audit completed ({specs.virtualization.summary})",
                "source": "platform_command",
                "tags": ["platform", "audit", "capabilities"],
                "artifacts": payload,
            }
        )

    def _allow_fingerprint(self) -> bool:
        key = "CERBERUS_PLATFORM_ALLOW_FINGERPRINT"
        env_value = os.getenv(key)
        if env_value is not None:
            return env_value.strip().lower() in {"1", "true", "yes", "on"}

        if CONFIG_STORE is not None:
            try:
                value, _tier = CONFIG_STORE.resolve(key)
                return str(value).strip().lower() in {"1", "true", "yes", "on"}
            except Exception:
                return False
        return False

    @staticmethod
    def _read_text_file(path: Path) -> Optional[str]:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None

    @staticmethod
    def _file_contains(path: Path, needles: tuple[str, ...]) -> bool:
        text = SystemAuditor._read_text_file(path)
        if not text:
            return False
        lowered = text.lower()
        return any(needle in lowered for needle in needles)

    @staticmethod
    def _run_cmd(argv: List[str]) -> Optional[str]:
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=2, check=False)
            text = (proc.stdout or "").strip()
            if text:
                return text
        except Exception:
            return None
        return None

    @staticmethod
    def _parse_os_release() -> Dict[str, str]:
        text = SystemAuditor._read_text_file(Path("/etc/os-release")) or ""
        result: Dict[str, str] = {}
        for line in text.splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip().strip('"')
        return result

    @staticmethod
    def _cpu_arch_from_proc() -> Optional[str]:
        cpuinfo = SystemAuditor._read_text_file(Path("/proc/cpuinfo")) or ""
        lowered = cpuinfo.lower()
        if "aarch64" in lowered or "arm64" in lowered:
            return "aarch64"
        if "x86_64" in lowered or "amd64" in lowered:
            return "x86_64"
        if lowered:
            return "unknown"
        return None


_GLOBAL_AUDITOR: Optional[SystemAuditor] = None


def get_system_auditor(memory: Optional[MemoryManager] = None) -> SystemAuditor:
    global _GLOBAL_AUDITOR
    if _GLOBAL_AUDITOR is None:
        mem = memory or MemoryManager()
        workspace_root = get_project_space().ensure_initialized().resolve()
        _GLOBAL_AUDITOR = SystemAuditor(memory=mem, workspace_root=workspace_root)
    return _GLOBAL_AUDITOR


class PlatformCommand(FrameworkCommand):
    """Platform capability auditor with human and agent-friendly output modes."""

    name = "/platform"
    description = "Audit kernel, tools, mitigations, and execution environment"
    aliases = ["/plat"]

    def __init__(self) -> None:
        super().__init__()
        self._memory = self._resolve_memory_manager()
        self._auditor = get_system_auditor(self._memory)

    @property
    def help(self) -> str:
        return (
            "Usage: /platform [--json|--table] [--refresh]\n"
            "  --json    Emit structured JSON for agent consumption\n"
            "  --table   Emit rich tables for human use (default)\n"
            "  --refresh Bypass cached result and re-run the audit\n"
            "Privacy: host identifiers remain redacted unless CERBERUS_PLATFORM_ALLOW_FINGERPRINT=true"
        )

    async def execute(self, args: List[str]) -> bool:
        output: Literal["table", "json"] = "table"
        refresh = False

        for token in args:
            if token in {"help", "--help", "-h"}:
                console.print(self.help)
                return True
            if token == "--json":
                output = "json"
                continue
            if token == "--table":
                output = "table"
                continue
            if token == "--refresh":
                refresh = True
                continue
            console.print(f"[red]Unknown option: {token}[/red]")
            console.print(self.help)
            return False

        specs = await self._auditor.audit(refresh=refresh)
        if output == "json":
            console.print(json.dumps(specs.model_dump(mode="json"), indent=2, ensure_ascii=True))
            return True

        self._render_table(specs, refresh=refresh)
        return True

    def _render_table(self, specs: PlatformSpecs, *, refresh: bool) -> None:
        summary = Table(title="Platform Capability Audit", box=box.SIMPLE_HEAVY)
        summary.add_column("Field", style="cyan")
        summary.add_column("Value", style="white")
        summary.add_row("Audited At", specs.audited_at)
        summary.add_row("Kernel", f"{specs.kernel.family} {specs.kernel.release}")
        summary.add_row("OS", f"{specs.os.distribution} ({specs.os.version})")
        summary.add_row("Architecture", f"{specs.architecture.machine} / {specs.architecture.word_size_bits}-bit")
        summary.add_row("Execution Mode", specs.virtualization.summary)
        summary.add_row("Privacy", "redacted" if specs.privacy_redacted else "explicitly allowed")
        summary.add_row("Host Identifier", specs.host_identifier)
        summary.caption = "Fresh audit" if refresh else "Cached after first successful run"
        console.print(summary)

        tools = Table(title="Tool Availability Map", box=box.SIMPLE)
        tools.add_column("Tool", style="cyan")
        tools.add_column("Available", style="green")
        tools.add_column("Path", style="yellow")
        for tool in specs.tools:
            tools.add_row(tool.name, "yes" if tool.available else "no", tool.path or "")
        console.print(tools)

        shields = Table(title="Security Level Assessment", box=box.SIMPLE)
        shields.add_column("Control", style="cyan")
        shields.add_column("State", style="white")
        shields.add_row("ASLR", specs.security.aslr)
        shields.add_row("DEP/NX", specs.security.nx)
        shields.add_row("EDR Present", "yes" if specs.security.edr_present else "no")
        shields.add_row("EDR Processes", ", ".join(specs.security.edr_processes) if specs.security.edr_processes else "none-detected")
        console.print(shields)

        console.print(
            Panel(
                "Capability Auditor completed. Use --json for agent-facing structured output.",
                border_style="green",
                title="Platform Ready",
            )
        )

    def _resolve_memory_manager(self) -> MemoryManager:
        if isinstance(self.memory, MemoryManager):
            return self.memory
        return MemoryManager()


PLATFORM_COMMAND_INSTANCE = PlatformCommand()
register_command(PLATFORM_COMMAND_INSTANCE)
