"""Virtualization command for hardened sandbox lifecycle management."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import shlex
import socket
import uuid
from typing import Any, Callable, Dict, List, Literal, Optional, Sequence

from pydantic import BaseModel, Field
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cai.memory import MemoryManager
from cai.memory.logic import clean, clean_data
from cai.repl.commands.base import CommandError, FrameworkCommand, register_command
from cai.repl.commands.config import CONFIG_STORE
from cai.repl.commands.shell import SecureSubprocess, SecureSubprocessResult, StreamLine
from cai.tools.workspace import get_project_space

console = Console()

_DEFAULT_RUNTIME = "docker"
_DEFAULT_TIMEOUT = 60
_STATE_FILE_NAME = "virtualization_state.json"


class VirtualizationOptions(BaseModel):
    subcommand: Literal["up", "exec", "purge", "status"]
    image: Optional[str] = None
    command: Optional[str] = None
    provider: Literal["docker", "podman", "proxmox", "esxi"] = "docker"
    timeout: int = Field(default=_DEFAULT_TIMEOUT, ge=1, le=7200)
    network: Literal["isolated", "targeted", "open"] = "isolated"
    target: Optional[str] = None


class SandboxState(BaseModel):
    provider: Literal["docker", "podman", "proxmox", "esxi"]
    runtime: str
    image: str
    instance_id: str
    container_name: str
    created_at: str
    workspace_root: str
    network_mode: Literal["isolated", "targeted", "open"]
    target: Optional[str] = None


class SandboxStats(BaseModel):
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    memory_percent: float = 0.0


@dataclass
class HealthPolicy:
    max_cpu_percent: float
    max_memory_mb: float


class SandboxDriver:
    """Abstract sandbox provider driver."""

    provider_name: str

    async def up(self, *, state: SandboxState, image: str, workspace_root: Path) -> None:
        raise NotImplementedError

    async def exec(self, *, state: SandboxState, command: str, timeout: int, on_line: Callable[[StreamLine], None]) -> SecureSubprocessResult:
        raise NotImplementedError

    async def purge(self, *, state: SandboxState) -> None:
        raise NotImplementedError

    async def stats(self, *, state: SandboxState) -> SandboxStats:
        raise NotImplementedError

    async def exists(self, *, state: SandboxState) -> bool:
        raise NotImplementedError


class DockerPodmanDriver(SandboxDriver):
    """Driver for docker/podman runtimes via SecureSubprocess."""

    def __init__(self, *, runtime: str, workspace_root: Path) -> None:
        self.provider_name = runtime
        self._runtime = runtime
        self._workspace_root = workspace_root
        self._subprocess = SecureSubprocess(workspace_root=workspace_root)

    async def up(self, *, state: SandboxState, image: str, workspace_root: Path) -> None:
        run_flags: List[str] = [
            self._runtime,
            "run",
            "-d",
            "--rm",
            "--name",
            state.container_name,
            "--label",
            "cai.sandbox=1",
            "--workdir",
            "/mnt",
            "-v",
            f"{workspace_root}:/mnt",
            "--security-opt",
            "no-new-privileges:true",
            "--cap-drop",
            "ALL",
            "--pids-limit",
            "512",
            "--memory",
            "4096m",
            "--cpus",
            "2.0",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=256m",
        ]

        if state.network_mode == "isolated":
            run_flags.extend(["--network", "none"])
        else:
            run_flags.extend(["--network", "bridge"])

        if state.network_mode == "targeted":
            run_flags.extend(["--cap-add", "NET_ADMIN"])

        run_flags.extend([image, "sleep", "infinity"])
        command = " ".join(shlex.quote(part) for part in run_flags)

        result = await self._run_command(command=command, timeout=90)
        if (result.exit_code or 0) != 0:
            msg = "\n".join(result.stderr_lines or result.stdout_lines)
            raise CommandError(
                f"Failed to start sandbox container: {msg or 'unknown runtime error'}",
                command_name="/virtualization",
            )

        if state.network_mode == "targeted" and state.target:
            await self._apply_targeted_network_policy(state=state)

    async def exec(self, *, state: SandboxState, command: str, timeout: int, on_line: Callable[[StreamLine], None]) -> SecureSubprocessResult:
        exec_cmd = " ".join(
            shlex.quote(part)
            for part in [
                self._runtime,
                "exec",
                state.container_name,
                "sh",
                "-lc",
                command,
            ]
        )
        return await self._subprocess.run(
            command=exec_cmd,
            timeout_seconds=timeout,
            cwd=self._workspace_root,
            shell_mode="auto",
            on_line=on_line,
        )

    async def purge(self, *, state: SandboxState) -> None:
        remove_cmd = " ".join(
            shlex.quote(part)
            for part in [self._runtime, "rm", "-f", state.container_name]
        )
        await self._run_command(command=remove_cmd, timeout=20)

    async def stats(self, *, state: SandboxState) -> SandboxStats:
        stats_cmd = " ".join(
            shlex.quote(part)
            for part in [
                self._runtime,
                "stats",
                "--no-stream",
                "--format",
                "{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}",
                state.container_name,
            ]
        )
        result = await self._run_command(command=stats_cmd, timeout=10)
        if (result.exit_code or 0) != 0 or not result.stdout_lines:
            return SandboxStats()

        line = result.stdout_lines[-1]
        cpu_raw, mem_raw, memp_raw = (line.split("|") + ["", "", ""])[:3]
        return SandboxStats(
            cpu_percent=self._parse_percent(cpu_raw),
            memory_mb=self._parse_mem_usage_mb(mem_raw),
            memory_percent=self._parse_percent(memp_raw),
        )

    async def exists(self, *, state: SandboxState) -> bool:
        inspect_cmd = " ".join(
            shlex.quote(part)
            for part in [self._runtime, "inspect", state.container_name]
        )
        result = await self._run_command(command=inspect_cmd, timeout=10)
        return (result.exit_code or 1) == 0

    async def _apply_targeted_network_policy(self, *, state: SandboxState) -> None:
        assert state.target is not None
        target_ip = self._resolve_target_ip(state.target)

        script = (
            "iptables -P OUTPUT DROP && "
            "iptables -A OUTPUT -d 127.0.0.0/8 -j ACCEPT && "
            "iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT && "
            f"iptables -A OUTPUT -d {target_ip} -j ACCEPT && "
            "iptables -A OUTPUT -d 10.0.0.0/8 -j REJECT && "
            "iptables -A OUTPUT -d 172.16.0.0/12 -j REJECT && "
            "iptables -A OUTPUT -d 192.168.0.0/16 -j REJECT"
        )

        policy_cmd = " ".join(
            shlex.quote(part)
            for part in [
                self._runtime,
                "exec",
                state.container_name,
                "sh",
                "-lc",
                script,
            ]
        )

        result = await self._run_command(command=policy_cmd, timeout=20)
        if (result.exit_code or 0) != 0:
            details = "\n".join(result.stderr_lines or result.stdout_lines)
            raise CommandError(
                "Failed to apply targeted network policy inside container. "
                f"Ensure the image has iptables available. {details}",
                command_name="/virtualization",
            )

    async def _run_command(self, *, command: str, timeout: int) -> SecureSubprocessResult:
        return await self._subprocess.run(
            command=command,
            timeout_seconds=timeout,
            cwd=self._workspace_root,
            shell_mode="auto",
            on_line=lambda _line: None,
        )

    @staticmethod
    def _parse_percent(value: str) -> float:
        stripped = value.strip().replace("%", "")
        try:
            return float(stripped)
        except ValueError:
            return 0.0

    @staticmethod
    def _parse_mem_usage_mb(value: str) -> float:
        # Example: "40.2MiB / 7.77GiB"
        usage = value.split("/")[0].strip().lower()
        multiplier = 1.0
        if usage.endswith("gib") or usage.endswith("gb"):
            multiplier = 1024.0
            usage = usage[:-3]
        elif usage.endswith("mib") or usage.endswith("mb"):
            usage = usage[:-3]
        elif usage.endswith("kib") or usage.endswith("kb"):
            multiplier = 1 / 1024.0
            usage = usage[:-3]
        try:
            return float(usage.strip()) * multiplier
        except ValueError:
            return 0.0

    @staticmethod
    def _resolve_target_ip(target: str) -> str:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror as exc:
            raise CommandError(
                f"Unable to resolve targeted network host '{target}'",
                command_name="/virtualization",
            ) from exc


class VMBackendDriver(SandboxDriver):
    """Optional VM backend stub for Proxmox/ESXi."""

    def __init__(self, provider_name: Literal["proxmox", "esxi"]) -> None:
        self.provider_name = provider_name

    async def up(self, *, state: SandboxState, image: str, workspace_root: Path) -> None:
        raise CommandError(
            f"Provider '{self.provider_name}' is not configured yet. "
            "Set up your enterprise hypervisor credentials and API integration first.",
            command_name="/virtualization",
        )

    async def exec(self, *, state: SandboxState, command: str, timeout: int, on_line: Callable[[StreamLine], None]) -> SecureSubprocessResult:
        raise CommandError(
            f"Provider '{self.provider_name}' does not support exec until configured.",
            command_name="/virtualization",
        )

    async def purge(self, *, state: SandboxState) -> None:
        raise CommandError(
            f"Provider '{self.provider_name}' does not support purge until configured.",
            command_name="/virtualization",
        )

    async def stats(self, *, state: SandboxState) -> SandboxStats:
        raise CommandError(
            f"Provider '{self.provider_name}' does not provide stats until configured.",
            command_name="/virtualization",
        )

    async def exists(self, *, state: SandboxState) -> bool:
        return False


class SandboxManager:
    """Manage active sandbox lifecycle and persistence."""

    def __init__(self, *, workspace_root: Path, memory: MemoryManager, user: str) -> None:
        self._workspace_root = workspace_root
        self._memory = memory
        self._user = user
        self._state_path = self._workspace_root / ".cai" / "session" / _STATE_FILE_NAME

    async def up(self, options: VirtualizationOptions) -> SandboxState:
        image = options.image or "kalilinux/kali-rolling:latest"
        image = self._normalize_image(image)
        self._ensure_trusted_registry(image)

        current_state = self.load_state()
        if current_state is not None:
            driver = self._driver_for(current_state.provider)
            if await driver.exists(state=current_state):
                raise CommandError(
                    f"Sandbox already active: {current_state.container_name}. Run virtualization purge first.",
                    command_name="/virtualization",
                )
            self.clear_state()

        instance_id = uuid.uuid4().hex[:8]
        container_name = f"cai-sandbox-{instance_id}"
        state = SandboxState(
            provider=options.provider,
            runtime=options.provider,
            image=image,
            instance_id=instance_id,
            container_name=container_name,
            created_at=datetime.now(tz=UTC).isoformat(),
            workspace_root=str(self._workspace_root),
            network_mode=options.network,
            target=options.target,
        )

        driver = self._driver_for(options.provider)
        await driver.up(state=state, image=image, workspace_root=self._workspace_root)

        self.save_state(state)
        await asyncio.to_thread(
            self._memory.record,
            {
                "topic": "virtualization",
                "finding": f"Sandbox up: {state.container_name} using {state.image}",
                "source": self._user,
                "tags": ["virtualization", "up", state.provider],
                "artifacts": clean_data(state.model_dump(mode="json")),
            },
        )
        return state

    async def exec(self, options: VirtualizationOptions) -> SecureSubprocessResult:
        state = self.require_state()
        command = options.command
        if not command:
            raise CommandError("virtualization exec requires a command", command_name="/virtualization", exit_code=2)

        driver = self._driver_for(state.provider)
        if not await driver.exists(state=state):
            self.clear_state()
            raise CommandError("No active sandbox found. Run virtualization up first.", command_name="/virtualization")

        health = self._health_policy()
        stop_event = asyncio.Event()
        exceeded: Dict[str, bool] = {"hit": False}

        def _on_line(line: StreamLine) -> None:
            style = "green" if line.stream == "stdout" else "red"
            console.print(f"[{style}]{line.at_ms:>6} {line.stream:<7} {line.text}[/{style}]")

        async def _monitor_health() -> None:
            while not stop_event.is_set():
                stats = await driver.stats(state=state)
                if stats.cpu_percent > health.max_cpu_percent or stats.memory_mb > health.max_memory_mb:
                    exceeded["hit"] = True
                    await driver.purge(state=state)
                    break
                await asyncio.sleep(1.0)

        async with asyncio.TaskGroup() as tg:
            exec_task = tg.create_task(
                driver.exec(
                    state=state,
                    command=command,
                    timeout=options.timeout,
                    on_line=_on_line,
                )
            )
            monitor_task = tg.create_task(_monitor_health())

        stop_event.set()
        _ = monitor_task
        result = exec_task.result()

        if exceeded["hit"]:
            self.clear_state()
            raise CommandError(
                "Sandbox exceeded health policy (CPU/RAM). Container was purged to protect host stability.",
                command_name="/virtualization",
            )

        await asyncio.to_thread(
            self._memory.record,
            {
                "topic": "virtualization",
                "finding": (
                    f"Sandbox exec in {state.container_name} exit_code={result.exit_code} "
                    f"timed_out={result.timed_out}"
                ),
                "source": self._user,
                "tags": ["virtualization", "exec", state.provider],
                "artifacts": clean_data(
                    {
                        "container": state.container_name,
                        "command": command,
                        "exit_code": result.exit_code,
                        "timed_out": result.timed_out,
                        "stdout": result.stdout_lines[:200],
                        "stderr": result.stderr_lines[:200],
                    }
                ),
            },
        )

        return result

    async def purge(self) -> bool:
        state = self.load_state()
        if state is None:
            return False

        driver = self._driver_for(state.provider)
        await driver.purge(state=state)
        self.clear_state()

        await asyncio.to_thread(
            self._memory.record,
            {
                "topic": "virtualization",
                "finding": f"Sandbox purged: {state.container_name}",
                "source": self._user,
                "tags": ["virtualization", "purge", state.provider],
                "artifacts": clean_data(state.model_dump(mode="json")),
            },
        )
        return True

    def load_state(self) -> Optional[SandboxState]:
        if not self._state_path.exists():
            return None
        try:
            payload = json.loads(self._state_path.read_text(encoding="utf-8"))
            return SandboxState.model_validate(payload)
        except Exception:
            return None

    def require_state(self) -> SandboxState:
        state = self.load_state()
        if state is None:
            raise CommandError("No active sandbox found", command_name="/virtualization")
        return state

    def save_state(self, state: SandboxState) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        self._state_path.write_text(
            json.dumps(state.model_dump(mode="json"), ensure_ascii=True, indent=2),
            encoding="utf-8",
        )

    def clear_state(self) -> None:
        if self._state_path.exists():
            self._state_path.unlink()

    def _driver_for(self, provider: str) -> SandboxDriver:
        if provider in {"docker", "podman"}:
            return DockerPodmanDriver(runtime=provider, workspace_root=self._workspace_root)
        if provider in {"proxmox", "esxi"}:
            return VMBackendDriver(provider_name=provider)  # type: ignore[arg-type]
        raise CommandError(f"Unsupported provider: {provider}", command_name="/virtualization", exit_code=2)

    def _trusted_registries(self) -> List[str]:
        raw = os.getenv("CEREBRO_TRUSTED_REGISTRIES", "").strip()
        if not raw:
            raw = CONFIG_STORE.get("CEREBRO_TRUSTED_REGISTRIES")
        if not raw or raw == "Not set":
            return ["docker.io", "ghcr.io", "quay.io", "registry.kali.org"]
        return [entry.strip().lower() for entry in raw.split(",") if entry.strip()]

    def _ensure_trusted_registry(self, image: str) -> None:
        registry = self._image_registry(image)
        trusted = set(self._trusted_registries())
        if registry not in trusted:
            raise CommandError(
                f"Image registry '{registry}' is not trusted. Allowed registries: {', '.join(sorted(trusted))}",
                command_name="/virtualization",
            )

    @staticmethod
    def _image_registry(image: str) -> str:
        image_no_tag = image.split("@", 1)[0]
        first = image_no_tag.split("/", 1)[0]
        if "." in first or ":" in first or first == "localhost":
            return first.lower()
        return "docker.io"

    @staticmethod
    def _normalize_image(image: str) -> str:
        if ":" in image or "@" in image:
            return image
        return f"{image}:latest"

    @staticmethod
    def _health_policy() -> HealthPolicy:
        try:
            max_cpu = float(os.getenv("CEREBRO_SANDBOX_MAX_CPU_PERCENT", "90"))
        except ValueError:
            max_cpu = 90.0
        try:
            max_mem = float(os.getenv("CEREBRO_SANDBOX_MAX_MEM_MB", "3072"))
        except ValueError:
            max_mem = 3072.0
        return HealthPolicy(max_cpu_percent=max_cpu, max_memory_mb=max_mem)


class VirtualizationCommand(FrameworkCommand):
    """Delegate high-risk execution into ephemeral sandbox backends."""

    name = "/virtualization"
    description = "Manage ephemeral sandbox containers/VMs for high-risk tool execution"
    aliases = ["/virt", "virtualization"]

    @property
    def help(self) -> str:
        return (
            "virtualization up <image> [--provider docker|podman|proxmox|esxi] [--network isolated|targeted|open] [--target host]\n"
            "virtualization exec [--timeout <seconds>] <cmd>\n"
            "virtualization purge\n"
            "virtualization status\n\n"
            "Notes:\n"
            "  - Workspace is mounted to /mnt inside container sandboxes.\n"
            "  - Image registry must be trusted via CEREBRO_TRUSTED_REGISTRIES.\n"
            "  - Health monitor enforces host CPU/RAM safety thresholds."
        )

    async def execute(self, args: List[str]) -> bool:
        if not args:
            console.print(self.help)
            return False

        options = self._parse_args(args)
        manager = self._manager()

        if options.subcommand == "up":
            state = await manager.up(options)
            self._render_up(state)
            return True

        if options.subcommand == "exec":
            result = await manager.exec(options)
            self._render_exec_summary(result)
            return (result.exit_code or 0) == 0 and not result.timed_out

        if options.subcommand == "purge":
            removed = await manager.purge()
            if removed:
                console.print("[green]Sandbox purged[/green]")
            else:
                console.print("[yellow]No active sandbox to purge[/yellow]")
            return True

        if options.subcommand == "status":
            self._render_status(manager.load_state())
            return True

        raise CommandError(f"Unsupported virtualization subcommand: {options.subcommand}", command_name=self.name)

    def _manager(self) -> SandboxManager:
        workspace_root = get_project_space().ensure_initialized().resolve()
        if isinstance(self.memory, MemoryManager):
            memory = self.memory
        else:
            memory = MemoryManager()
        memory.initialize()
        return SandboxManager(workspace_root=workspace_root, memory=memory, user=self.session.user)

    def _parse_args(self, args: Sequence[str]) -> VirtualizationOptions:
        sub = args[0].strip().lower()
        if sub not in {"up", "exec", "purge", "status"}:
            raise CommandError(
                f"Unknown virtualization subcommand: {sub}",
                command_name=self.name,
                exit_code=2,
            )

        if sub == "purge" or sub == "status":
            return VirtualizationOptions(subcommand=sub)  # type: ignore[arg-type]

        provider: Literal["docker", "podman", "proxmox", "esxi"] = _DEFAULT_RUNTIME  # type: ignore[assignment]
        timeout = _DEFAULT_TIMEOUT
        network: Literal["isolated", "targeted", "open"] = "isolated"
        target: Optional[str] = None
        image: Optional[str] = None
        command_tokens: List[str] = []

        idx = 1
        while idx < len(args):
            token = args[idx]
            if token == "--provider":
                idx += 1
                if idx >= len(args):
                    raise CommandError("--provider requires a value", command_name=self.name, exit_code=2)
                candidate = args[idx].strip().lower()
                if candidate not in {"docker", "podman", "proxmox", "esxi"}:
                    raise CommandError("Invalid provider", command_name=self.name, exit_code=2)
                provider = candidate  # type: ignore[assignment]
                idx += 1
                continue
            if token == "--timeout":
                idx += 1
                if idx >= len(args):
                    raise CommandError("--timeout requires a value", command_name=self.name, exit_code=2)
                try:
                    timeout = max(1, int(args[idx]))
                except ValueError as exc:
                    raise CommandError("--timeout must be an integer", command_name=self.name, exit_code=2) from exc
                idx += 1
                continue
            if token == "--network":
                idx += 1
                if idx >= len(args):
                    raise CommandError("--network requires a value", command_name=self.name, exit_code=2)
                candidate_net = args[idx].strip().lower()
                if candidate_net not in {"isolated", "targeted", "open"}:
                    raise CommandError("--network must be isolated|targeted|open", command_name=self.name, exit_code=2)
                network = candidate_net  # type: ignore[assignment]
                idx += 1
                continue
            if token == "--target":
                idx += 1
                if idx >= len(args):
                    raise CommandError("--target requires a host or IP", command_name=self.name, exit_code=2)
                target = args[idx].strip()
                idx += 1
                continue

            if sub == "up" and image is None:
                image = token
                idx += 1
                continue

            command_tokens.extend(args[idx:])
            break

        if sub == "up":
            if image is None:
                raise CommandError("virtualization up requires an image", command_name=self.name, exit_code=2)
            if network == "targeted" and not target:
                raise CommandError("--network targeted requires --target", command_name=self.name, exit_code=2)
            return VirtualizationOptions(
                subcommand="up",
                image=image,
                provider=provider,
                timeout=timeout,
                network=network,
                target=target,
            )

        if not command_tokens:
            raise CommandError("virtualization exec requires a command", command_name=self.name, exit_code=2)

        return VirtualizationOptions(
            subcommand="exec",
            command=" ".join(command_tokens),
            provider=provider,
            timeout=timeout,
            network=network,
            target=target,
        )

    def _render_up(self, state: SandboxState) -> None:
        table = Table(title="Sandbox Ready")
        table.add_column("Field", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        table.add_row("Provider", state.provider)
        table.add_row("Image", state.image)
        table.add_row("Container", state.container_name)
        table.add_row("Workspace", state.workspace_root)
        table.add_row("Network", state.network_mode)
        table.add_row("Target", state.target or "-")
        console.print(table)

    def _render_exec_summary(self, result: SecureSubprocessResult) -> None:
        status = "ok"
        color = "green"
        if result.timed_out:
            status = "timeout"
            color = "yellow"
        elif (result.exit_code or 0) != 0:
            status = "failed"
            color = "red"

        table = Table(title="Sandbox Execution Summary")
        table.add_column("Field", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        table.add_row("Status", f"[{color}]{status}[/{color}]")
        table.add_row("Exit code", str(result.exit_code))
        table.add_row("Duration", f"{result.duration_ms} ms")
        table.add_row("Stdout lines", str(len(result.stdout_lines)))
        table.add_row("Stderr lines", str(len(result.stderr_lines)))
        console.print(table)

    def _render_status(self, state: Optional[SandboxState]) -> None:
        if state is None:
            console.print(Panel("No active sandbox", title="Virtualization Status", border_style="yellow"))
            return

        payload = clean(json.dumps(state.model_dump(mode="json"), ensure_ascii=True, indent=2))
        console.print(Panel(payload, title="Virtualization Status", border_style="green"))


VIRTUALIZATION_COMMAND_INSTANCE = VirtualizationCommand()
register_command(VIRTUALIZATION_COMMAND_INSTANCE)
