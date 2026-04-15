"""Internal command dispatcher with guardrails and typed command envelopes."""

from __future__ import annotations

import argparse
import asyncio
from datetime import UTC, datetime
import getpass
import os
from pathlib import Path
import signal
import subprocess
import threading
from typing import Any, Optional
import importlib

from cerberus.internal.components.schema import CommandInvocation, ExecutionTelemetry, ToolResult
from cerberus.internal.registry.commands import CerberusCommandRegistry
from cerberus.internal.util.help_formatter import generate_command_help
from cerberus.tools.reconnaissance.filesystem import PathGuard
from cerberus.tools.validation import validate_resource_health
from cerberus.tools.workspace import get_project_space
from cerberus.util import get_system_telemetry


_HIGH_RISK_COMMANDS = {
    "/flush",
    "/env",
    "/k",
    "/kill",
    "/s",
    "/shell",
    "/virt",
    "/virtualization",
    "/exit",
    "/quit",
    "/q",
}


class CommandDispatcher:
    """Typed dispatcher that leaks CLI input directly to command backends."""

    def __init__(self) -> None:
        self._registry = CerberusCommandRegistry()
        self._last_result: Optional[ToolResult] = None

    @property
    def last_result(self) -> Optional[ToolResult]:
        return self._last_result

    def dispatch(self, command: str, args: Optional[list[str]] = None) -> ToolResult:
        envelope = self._build_envelope(command=command, args=args or [])
        entry = self._registry.resolve(envelope.command)
        if entry is None:
            result = self._build_result(
                request_id=envelope.request_id,
                tool_name=envelope.command,
                exit_code=1,
                stdout="",
                stderr=f"Unknown command: {envelope.command}",
                artifacts={"impact": "No-op (unknown command)"},
            )
            self._last_result = result
            return result

        if envelope.help_requested:
            help_target = envelope.help_target or envelope.command
            help_entry = self._registry.resolve(help_target) or entry
            risk_level, impact = self._registry.command_risk_impact(help_target)
            workspace_root = get_project_space().ensure_initialized().resolve()

            rendered_help = generate_command_help(
                command_name=help_target,
                command=help_entry,
                risk_level=risk_level,
                impact=impact,
                workspace_root=workspace_root,
            )

            help_result = self._build_result(
                request_id=envelope.request_id,
                tool_name=envelope.command,
                exit_code=0,
                stdout=rendered_help,
                stderr="",
                artifacts={
                    "impact": "Dynamic command documentation",
                    "help_target": help_target,
                    "canonical_command": help_entry.canonical,
                    "risk": risk_level,
                },
            )
            self._last_result = help_result
            return help_result

        if envelope.command in {"/help", "/h", "/?"} and envelope.help_target:
            doc = self._registry.command_docstring(envelope.help_target)
            doc_result = self._build_result(
                request_id=envelope.request_id,
                tool_name=envelope.command,
                exit_code=0,
                stdout=doc or f"No backend docstring available for {envelope.help_target}",
                stderr="",
                artifacts={
                    "impact": "Documentation lookup",
                    "help_target": envelope.help_target,
                },
            )
            self._last_result = doc_result
            return doc_result

        guard_error = self._pre_execute_guardrails(envelope)
        if guard_error:
            result = self._build_result(
                request_id=envelope.request_id,
                tool_name=envelope.command,
                exit_code=2,
                stdout="",
                stderr=guard_error,
                artifacts={"impact": "Blocked by guardrail policy"},
            )
            self._last_result = result
            return result

        if envelope.command in {"/exit", "/quit", "/q"}:
            self._run_exit_hooks()

        if envelope.command in {"/flush"}:
            self._flush_chpe_before_command()

        ok = bool(entry.command.handle(envelope.args))

        if envelope.command in {"/flush"}:
            self._flush_chpe_after_command()

        result = self._build_result(
            request_id=envelope.request_id,
            tool_name=envelope.command,
            exit_code=0 if ok else 1,
            stdout="command_success" if ok else "",
            stderr="" if ok else "command_failed",
            artifacts={
                "impact": self._technical_impact_label(envelope.command),
                "canonical_command": entry.canonical,
                "requested_command": envelope.command,
                "args": envelope.args,
            },
        )
        self._last_result = result
        return result

    def _build_envelope(self, *, command: str, args: list[str]) -> CommandInvocation:
        normalized = command.strip()
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"

        force = any(token.lower() == "--force" for token in args)
        help_requested = any(token.lower() in {"--help", "-h"} for token in args)
        normalized_args = [
            token
            for token in args
            if token.lower() not in {"--force", "--help", "-h"}
        ]
        help_target = None
        if normalized in {"/help", "/h", "/?"} and normalized_args:
            if normalized_args[0] and not normalized_args[0].startswith("-"):
                target = normalized_args[0].strip()
                help_target = target if target.startswith("/") else f"/{target}"
        elif help_requested:
            help_target = normalized if normalized.startswith("/") else f"/{normalized}"

        return CommandInvocation(
            command=normalized.lower(),
            args=normalized_args,
            force=force,
            help_requested=help_requested,
            help_target=help_target,
            user=self._safe_user(),
        )

    @staticmethod
    def _safe_user() -> str:
        try:
            return getpass.getuser()
        except Exception:
            return "unknown"

    def _pre_execute_guardrails(self, envelope: CommandInvocation) -> str:
        if envelope.command in {"/kill", "/k", "/exit", "/quit", "/q"}:
            if threading.current_thread() is not threading.main_thread():
                return "Signal-affecting commands must run in the main interpreter thread"

        if envelope.command in _HIGH_RISK_COMMANDS and not envelope.force:
            return f"{envelope.command} is high-risk; rerun with --force"

        if envelope.command in {"/shell", "/s", "/virtualization", "/virt"}:
            guard_error = self._validate_pathguard_and_validator(envelope)
            if guard_error:
                return guard_error

        if envelope.command in {"/parallel", "/par", "/p"}:
            guard_error = self._validate_parallel_capacity(envelope)
            if guard_error:
                return guard_error

        return ""

    def _validate_pathguard_and_validator(self, envelope: CommandInvocation) -> str:
        health = self._run_async(validate_resource_health(min_disk_free_mb=256, min_memory_free_mb=512))
        if not isinstance(health, dict) or not health.get("ok", False):
            return "Validator blocked execution due to insufficient host resources"

        workspace = get_project_space().ensure_initialized().resolve()
        guard = PathGuard(workspace, lambda _event, _payload: None)

        cwd_value = self._extract_cwd_arg(envelope.args)
        target_cwd = workspace
        if cwd_value:
            candidate = Path(cwd_value)
            target_cwd = candidate if candidate.is_absolute() else (workspace / candidate)

        try:
            guard.validate_path(target_cwd, action="dispatcher_preflight", mode="read")
        except Exception as exc:
            return f"PathGuard validation failed: {exc}"

        return ""

    @staticmethod
    def _extract_cwd_arg(args: list[str]) -> str:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--cwd", type=str, default="")
        try:
            parsed, _rest = parser.parse_known_args(args)
            return str(parsed.cwd or "")
        except Exception:
            return ""

    def _validate_parallel_capacity(self, envelope: CommandInvocation) -> str:
        if envelope.force:
            return ""

        max_workers = self._extract_parallel_workers(envelope.args)
        config = self._load_cerberus_config()

        available_ram_gb = self._available_ram_gb()
        required_ram_gb = max(2.0 * float(max_workers), 4.0)
        if available_ram_gb < required_ram_gb:
            return (
                f"Insufficient RAM headroom for /par: available={available_ram_gb:.2f}GB "
                f"required={required_ram_gb:.2f}GB"
            )

        if config.gpu.use_gpu_acceleration and max_workers > 1:
            available_vram_mb = self._available_vram_mb(config.gpu.target_vram_mb)
            required_vram_mb = max(1024.0 * float(max_workers), 2048.0)
            if available_vram_mb < required_vram_mb:
                return (
                    f"Insufficient VRAM headroom for /par: available={available_vram_mb:.0f}MB "
                    f"required={required_vram_mb:.0f}MB"
                )

        return ""

    @staticmethod
    def _load_cerberus_config() -> Any:
        module = importlib.import_module("cerberus.util.config")
        getter = getattr(module, "get_cerberus_config")
        return getter()

    @staticmethod
    def _extract_parallel_workers(args: list[str]) -> int:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--max-workers", type=int, default=2)
        try:
            parsed, _rest = parser.parse_known_args(args)
            return max(1, int(parsed.max_workers))
        except Exception:
            return 2

    @staticmethod
    def _available_ram_gb() -> float:
        try:
            import psutil  # type: ignore

            return float(psutil.virtual_memory().available) / (1024.0 ** 3)
        except Exception:
            return 0.0

    @staticmethod
    def _available_vram_mb(fallback_total: int) -> float:
        try:
            output = subprocess.check_output(
                [
                    "nvidia-smi",
                    "--query-gpu=memory.free",
                    "--format=csv,noheader,nounits",
                ],
                stderr=subprocess.DEVNULL,
                timeout=2,
            ).decode("utf-8", errors="replace").strip()
            first = output.splitlines()[0] if output else ""
            return float(first.strip())
        except Exception:
            return float(max(0, fallback_total - 2048))

    @staticmethod
    def _run_async(coro: Any) -> Any:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)

        future = asyncio.run_coroutine_threadsafe(coro, loop)
        return future.result(timeout=15)

    @staticmethod
    def _run_exit_hooks() -> None:
        workspace = str(get_project_space().ensure_initialized().resolve())
        try:
            from cerberus.memory.memory import CerberusMemoryBus

            bus = CerberusMemoryBus.get_instance(workspace_root=workspace)
            bus.commit()
        except Exception:
            pass

        try:
            from cerberus.internal.components.transfer import cost_engine

            cleanup = getattr(cost_engine, "_cleanup_staging", None)
            if callable(cleanup):
                cleanup()
        except Exception:
            pass

    @staticmethod
    def _flush_chpe_before_command() -> None:
        try:
            from cerberus.memory.storage import CerberusStorageHandler

            storage = CerberusStorageHandler.get_instance(
                workspace_root=str(get_project_space().ensure_initialized().resolve())
            )
            storage.flush_sync()
        except Exception:
            pass

    @staticmethod
    def _flush_chpe_after_command() -> None:
        try:
            from cerberus.memory.storage import CerberusStorageHandler

            storage = CerberusStorageHandler.get_instance(
                workspace_root=str(get_project_space().ensure_initialized().resolve())
            )
            storage.flush_sync()
        except Exception:
            pass

    @staticmethod
    def _technical_impact_label(command: str) -> str:
        mapping = {
            "/memory": "CCMB state mutation",
            "/cost": "COST accounting query/update",
            "/env": "Runtime environment mutation/read",
            "/flush": "CHPE/CCMB volatile state purge",
            "/parallel": "Concurrent subprocess orchestration",
            "/shell": "Sandboxed shell process execution",
            "/virtualization": "Virtualization runtime control",
            "/exit": "Lifecycle shutdown and persistence commit",
        }
        return mapping.get(command, "Command execution")

    def _build_result(
        self,
        *,
        request_id: str,
        tool_name: str,
        exit_code: int,
        stdout: str,
        stderr: str,
        artifacts: dict[str, Any],
    ) -> ToolResult:
        telemetry = self._collect_execution_telemetry()
        merged_artifacts = dict(artifacts)
        merged_artifacts["timestamp"] = datetime.now(tz=UTC).isoformat()
        return ToolResult(
            request_id=request_id,
            tool_name=tool_name,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            telemetry=telemetry,
            artifacts=merged_artifacts,
        )

    @staticmethod
    def _collect_execution_telemetry() -> ExecutionTelemetry:
        snapshot = get_system_telemetry()

        ram_total = float(snapshot.get("memory_total") or 0.0)
        ram_available = float(snapshot.get("memory_available") or 0.0)
        ram_used = max(0.0, ram_total - ram_available)
        ram_total_gb = ram_total / (1024.0 ** 3) if ram_total > 0 else 0.0
        ram_used_gb = ram_used / (1024.0 ** 3) if ram_used > 0 else 0.0

        vram_total_mb = 0.0
        vram_used_mb = 0.0
        gpu_name = "unknown"
        try:
            raw = subprocess.check_output(
                [
                    "nvidia-smi",
                    "--query-gpu=name,memory.total,memory.used",
                    "--format=csv,noheader,nounits",
                ],
                stderr=subprocess.DEVNULL,
                timeout=2,
            ).decode("utf-8", errors="replace").strip()
            first = raw.splitlines()[0] if raw else ""
            parts = [item.strip() for item in first.split(",")]
            if len(parts) >= 3:
                gpu_name = parts[0]
                vram_total_mb = float(parts[1])
                vram_used_mb = float(parts[2])
        except Exception:
            pass

        ram_pct = (ram_used_gb / ram_total_gb * 100.0) if ram_total_gb > 0 else 0.0
        vram_pct = (vram_used_mb / vram_total_mb * 100.0) if vram_total_mb > 0 else 0.0

        return ExecutionTelemetry(
            ram_used_gb=ram_used_gb,
            ram_total_gb=ram_total_gb,
            ram_pct=ram_pct,
            vram_used_mb=vram_used_mb,
            vram_total_mb=vram_total_mb,
            vram_pct=vram_pct,
            gpu_name=gpu_name,
        )


GLOBAL_COMMAND_DISPATCHER = CommandDispatcher()


__all__ = ["CommandDispatcher", "GLOBAL_COMMAND_DISPATCHER"]
