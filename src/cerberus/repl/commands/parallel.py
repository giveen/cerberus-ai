"""Parallel orchestration command for Cerebro REPL.

This module provides an async-first concurrent execution engine with:
- batched command execution from inline args or task files
- resource guardrails via max-worker concurrency limiter
- live task status dashboard
- error isolation and per-task summary reporting
- thread-safe memory/cost synchronization with redacted artifacts

Compatibility notes:
- preserves `ParallelConfig`, `PARALLEL_CONFIGS`, and `PARALLEL_AGENT_INSTANCES`
  used by other modules.
- preserves `ParallelCommand._get_message_signature()` used by TUI history merge flow.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from cerberus.agents import get_available_agents
from cerberus.memory import MemoryManager
from cerberus.repl.commands.base import Command, CommandError, register_command
from cerberus.repl.commands.cost import USAGE_TRACKER
from cerberus.agents.models.openai_chatcompletions import get_all_agent_histories
from cerberus.tools.workspace import get_project_space


console = Console()


_LEGACY_AGENT_DISPLAY_NAMES = {
    "redteam_agent": "Red Team Agent",
    "bug_bounter_agent": "Bug Bounty Agent",
    "blueteam_agent": "Blue Team Agent",
    "dfir_agent": "DFIR Agent",
}


def _safe_available_agents() -> Dict[str, Any]:
    try:
        return get_available_agents()
    except Exception:
        return {}


def _fallback_agent_display_name(agent_name: str) -> str:
    normalized_name = str(agent_name).strip().lower()
    if normalized_name in _LEGACY_AGENT_DISPLAY_NAMES:
        return _LEGACY_AGENT_DISPLAY_NAMES[normalized_name]

    label = agent_name.replace("_agent", "").replace("_", " ").strip()
    return label.title() if label else agent_name


PARALLEL_CONFIGS: List["ParallelConfig"] = []
PARALLEL_AGENT_INSTANCES: Dict[Tuple[str, int], Any] = {}


@dataclass
class ParallelConfig:
    """Parallel agent configuration structure kept for compatibility."""

    agent_name: str
    model: Optional[str] = None
    prompt: Optional[str] = None
    unified_context: bool = False
    id: Optional[str] = None

    def __str__(self) -> str:
        parts = [f"Agent: {self.agent_name}"]
        if self.model:
            parts.append(f"model: {self.model}")
        if self.prompt:
            preview = self.prompt if len(self.prompt) <= 40 else self.prompt[:37] + "..."
            parts.append(f"prompt: '{preview}'")
        return " | ".join(parts)


@dataclass(frozen=True)
class TaskSpec:
    """A unit of concurrent work."""

    task_id: str
    command: str
    source: str


@dataclass
class TaskState:
    """Mutable runtime state for one task."""

    task: TaskSpec
    status: str = "Pending"
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    return_code: Optional[int] = None
    output_preview: str = ""
    error: Optional[str] = None


@dataclass
class OrchestrationResult:
    """Summary results for a workflow execution."""

    total: int
    succeeded: int
    failed: int
    states: List[TaskState] = field(default_factory=list)


class WorkflowOrchestrator:
    """Async concurrent execution engine with guardrails and status reporting."""

    _SECRET_PATTERNS: Tuple[re.Pattern[str], ...] = (
        re.compile(r"(?i)\b(api[_-]?key|token|secret|password|passwd)\s*[:=]\s*([^\s,;]+)"),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"\b(?:sk|rk)-[A-Za-z0-9]{16,}\b"),
    )

    def __init__(self, *, memory: MemoryManager, workspace_root: Path) -> None:
        self._memory = memory
        self._workspace_root = workspace_root.resolve()
        self._memory_lock = asyncio.Lock()
        self._audit_lock = asyncio.Lock()
        self._audit_path = self._workspace_root / ".cerberus" / "audit" / "parallel_actions.jsonl"

    async def run(self, *, tasks: Sequence[TaskSpec], max_workers: int) -> OrchestrationResult:
        max_workers = max(1, max_workers)
        semaphore = asyncio.Semaphore(max_workers)

        states = [TaskState(task=t) for t in tasks]
        state_by_id = {st.task.task_id: st for st in states}

        dashboard_task = asyncio.create_task(self._dashboard_loop(states))

        async def _runner(spec: TaskSpec) -> None:
            state = state_by_id[spec.task_id]
            async with semaphore:
                await self._execute_one(state)

        try:
            if hasattr(asyncio, "TaskGroup"):
                async with asyncio.TaskGroup() as tg:  # type: ignore[attr-defined]
                    for spec in tasks:
                        tg.create_task(_runner(spec))
            else:
                await asyncio.gather(*[_runner(spec) for spec in tasks], return_exceptions=True)
        finally:
            dashboard_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await dashboard_task

        succeeded = sum(1 for st in states if st.status == "Completed")
        failed = sum(1 for st in states if st.status == "Failed")

        return OrchestrationResult(
            total=len(states),
            succeeded=succeeded,
            failed=failed,
            states=states,
        )

    async def _execute_one(self, state: TaskState) -> None:
        task = state.task
        state.status = "Running"
        state.started_at = datetime.now(tz=UTC).isoformat()

        started = datetime.now(tz=UTC)
        try:
            proc = await asyncio.create_subprocess_shell(
                task.command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self._workspace_root),
            )
            out_bytes, err_bytes = await proc.communicate()

            out_text = out_bytes.decode("utf-8", "ignore") if out_bytes else ""
            err_text = err_bytes.decode("utf-8", "ignore") if err_bytes else ""
            merged_text = (out_text + "\n" + err_text).strip()

            state.return_code = int(proc.returncode or 0)
            state.ended_at = datetime.now(tz=UTC).isoformat()
            state.output_preview = self._redact(merged_text)[:500]

            if state.return_code == 0:
                state.status = "Completed"
            else:
                state.status = "Failed"
                state.error = f"exit_code={state.return_code}"

            await self._sync_state(state, started)

        except Exception as exc:  # pylint: disable=broad-except
            state.status = "Failed"
            state.error = str(exc)
            state.ended_at = datetime.now(tz=UTC).isoformat()
            await self._sync_state(state, started)

    async def _sync_state(self, state: TaskState, started: datetime) -> None:
        elapsed_ms = int((datetime.now(tz=UTC) - started).total_seconds() * 1000)

        async with self._memory_lock:
            await asyncio.to_thread(
                self._memory.record,
                {
                    "topic": "parallel.task",
                    "finding": f"Task {state.task.task_id} {state.status.lower()}",
                    "source": "parallel_command",
                    "tags": ["parallel", "orchestration", state.status.lower()],
                    "artifacts": {
                        "task_id": state.task.task_id,
                        "command": self._redact(state.task.command),
                        "source": state.task.source,
                        "status": state.status,
                        "return_code": state.return_code,
                        "elapsed_ms": elapsed_ms,
                        "output_preview": state.output_preview,
                        "error": state.error,
                    },
                },
            )

        # Thread-safe cost ledger synchronization (zero-cost operational record).
        USAGE_TRACKER.record(
            agent_name="parallel-orchestrator",
            model="local",
            input_tokens=0,
            output_tokens=0,
            operation=f"parallel:{state.task.task_id}:{state.status.lower()}",
            cost=Decimal("0"),
        )

        event = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "task_id": state.task.task_id,
            "source": state.task.source,
            "command": self._redact(state.task.command),
            "status": state.status,
            "return_code": state.return_code,
            "error": state.error,
        }
        await self._append_audit(event)

    async def _append_audit(self, payload: Mapping[str, Any]) -> None:
        async with self._audit_lock:
            text = json.dumps(dict(payload), ensure_ascii=True) + "\n"
            await asyncio.to_thread(self._atomic_append_text, self._audit_path, text)

    @staticmethod
    def _atomic_append_text(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        final = existing + text

        fd, tmp_name = tempfile.mkstemp(prefix=".parallel_audit_", dir=str(path.parent))
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(final)
                handle.flush()
            tmp_path.replace(path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)

    async def _dashboard_loop(self, states: Sequence[TaskState]) -> None:
        with Live(self._build_dashboard(states), refresh_per_second=8, console=console, transient=True) as live:
            while True:
                await asyncio.sleep(0.2)
                live.update(self._build_dashboard(states))

    @staticmethod
    def _build_dashboard(states: Sequence[TaskState]) -> Table:
        table = Table(title="Parallel Task Dashboard", box=box.SIMPLE_HEAVY)
        table.add_column("Task", style="cyan", width=8)
        table.add_column("Status", style="white", width=11)
        table.add_column("Source", style="magenta", width=10)
        table.add_column("Command", style="green")
        table.add_column("Result", style="yellow", width=12)

        for state in states:
            result = "-"
            if state.status == "Completed":
                result = "ok"
            elif state.status == "Failed":
                result = state.error or f"code={state.return_code}"

            cmd_preview = state.task.command if len(state.task.command) <= 72 else state.task.command[:69] + "..."
            table.add_row(state.task.task_id, state.status, state.task.source, cmd_preview, result)

        return table

    def _redact(self, text: str) -> str:
        cleaned = text
        for pattern in self._SECRET_PATTERNS:
            cleaned = pattern.sub("[REDACTED]", cleaned)
        return cleaned


class ParallelCommand(Command):
    """Concurrent execution command with a legacy config-management surface."""

    name = "/parallel"
    description = "Configure multiple agents to run in parallel with different settings"
    aliases = ["/par", "/p"]

    def __init__(self) -> None:
        super().__init__(name=self.name, description=self.description, aliases=self.aliases)
        self._memory = self._resolve_memory_manager()
        self._workspace_root = get_project_space().ensure_initialized().resolve()
        self._orchestrator = WorkflowOrchestrator(memory=self._memory, workspace_root=self._workspace_root)
        self.add_subcommand("add", "Add an agent config to PARALLEL_CONFIGS", self.handle_add)
        self.add_subcommand("list", "List configured parallel agent entries", self.handle_list)
        self.add_subcommand("clear", "Clear configured parallel agent entries", self.handle_clear)
        self.add_subcommand("remove", "Remove configured parallel agent by index or ID", self.handle_remove)
        self.add_subcommand("override-models", "Override models for configured agents", self.handle_override_models)
        self.add_subcommand("merge", "Merge configured agent histories", self.handle_merge)
        self.add_subcommand("prompt", "Set a prompt for a configured agent", self.handle_prompt)

    @property
    def help(self) -> str:
        return (
            "Usage:\n"
            "  /parallel \"scan 192.168.1.1\" \"scan 192.168.1.2\" [--max-workers N]\n"
            "  /parallel --file tasks.txt [--max-workers N]\n"
            "\n"
            "Config compatibility:\n"
            "  /parallel add <agent_name> [--model MODEL] [--prompt PROMPT] [--unified]\n"
            "  /parallel list\n"
            "  /parallel clear\n"
            "  /parallel remove <index|ID>\n"
            "  /parallel prompt <index|ID> <prompt text>\n"
        )

    def handle(self, args: Optional[List[str]] = None) -> bool:  # type: ignore[override]
        try:
            clean = self.sanitize_args(args)
        except Exception as exc:
            console.print(f"[red]Input validation failed: {exc}[/red]")
            return False

        record = self._audit_before(clean)
        try:
            if not clean:
                result = self.handle_no_args()
            else:
                sub = clean[0].lower().strip()
                if sub in {"help", "--help", "-h"}:
                    console.print(self.help)
                    result = True
                else:
                    registered = self.subcommands.get(sub)
                    if registered and callable(registered.get("handler")):
                        result = bool(registered["handler"](clean[1:] or None))
                    else:
                        result = self._run_execute(clean)
        except CommandError as exc:
            self._audit_after(record, success=False, error=str(exc))
            console.print(f"[red]{self.name}: {exc}[/red]")
            return False
        except Exception as exc:  # pylint: disable=broad-except
            self._audit_after(record, success=False, error=repr(exc))
            raise

        self._audit_after(record, success=bool(result))
        return bool(result)

    def handle_no_args(self) -> bool:  # type: ignore[override]
        if not PARALLEL_CONFIGS:
            console.print(Panel("No parallel agent configs defined.", title="Parallel Status", border_style="yellow"))
            return True

        lines: List[str] = []
        for index, cfg in enumerate(PARALLEL_CONFIGS, start=1):
            cfg_id = cfg.id or f"P{index}"
            lines.append(f"{cfg_id}: {self._display_name_for_config(cfg)}")
            lines.append(f"Model: {cfg.model or 'default'}")
            if cfg.prompt:
                lines.append(f"Prompt: {cfg.prompt}")
            lines.append("")

        console.print(
            Panel(
                "\n".join(lines).strip(),
                title="Parallel Status",
                border_style="cyan",
            )
        )
        return self.handle_list([])

    def handle_add(self, args: Optional[List[str]] = None) -> bool:
        return self._cfg_add(list(args or []))

    def handle_list(self, args: Optional[List[str]] = None) -> bool:
        del args
        return self._cfg_list()

    def handle_clear(self, args: Optional[List[str]] = None) -> bool:
        del args
        return self._cfg_clear()

    def handle_remove(self, args: Optional[List[str]] = None) -> bool:
        return self._cfg_remove(list(args or []))

    def handle_override_models(self, args: Optional[List[str]] = None) -> bool:
        del args
        console.print("[yellow]override-models compatibility shim is not implemented in the legacy wrapper.[/yellow]")
        return True

    def handle_merge(self, args: Optional[List[str]] = None) -> bool:
        del args
        console.print("[yellow]merge compatibility shim is not implemented in the legacy wrapper.[/yellow]")
        return True

    def handle_prompt(self, args: Optional[List[str]] = None) -> bool:
        if not args or len(args) < 2:
            console.print("[red]Error: Agent ID/index and prompt required[/red]")
            return False

        target = str(args[0]).strip()
        prompt = " ".join(args[1:])
        cfg = self._resolve_config_target(target)
        if cfg is None:
            console.print(f"[red]Error: No agent found with ID/index '{target}'[/red]")
            return False

        old_prompt = cfg.prompt
        cfg.prompt = prompt
        cfg_id = cfg.id or target
        display_name = self._display_name_for_config(cfg)
        if old_prompt:
            console.print(f"[dim]Old prompt: {old_prompt}[/dim]")
        console.print(f"[green]Updated prompt for {display_name} (ID: {cfg_id})[/green]")
        return True

    async def execute(self, args: List[str]) -> bool:
        if not args:
            console.print(self.help)
            return True

        first = args[0].lower().strip()
        if first in {"help", "--help", "-h"}:
            console.print(self.help)
            return True

        if first in {"add", "list", "clear", "remove"}:
            return await self._execute_config_subcommand(first, args[1:])

        parsed = self._parse_execution_args(args)
        if parsed is None:
            return False

        tasks, max_workers = parsed
        if not tasks:
            console.print("[yellow]No tasks to execute[/yellow]")
            return True

        result = await self._orchestrator.run(tasks=tasks, max_workers=max_workers)
        self._render_summary(result, max_workers=max_workers)
        return result.failed == 0

    def _resolve_config_target(self, target: str) -> Optional[ParallelConfig]:
        if target.upper().startswith("P") and target[1:].isdigit():
            for index, cfg in enumerate(PARALLEL_CONFIGS, start=1):
                if (cfg.id or f"P{index}").upper() == target.upper():
                    return cfg
            return None

        if target.isdigit():
            one_based = int(target)
            if 1 <= one_based <= len(PARALLEL_CONFIGS):
                return PARALLEL_CONFIGS[one_based - 1]
        return None

    def _parse_agent_names(self, requested: List[str], all_histories: Mapping[str, Any]) -> List[str]:
        normalized_histories = {
            self._normalize_agent_name(str(agent_name)): str(agent_name)
            for agent_name in all_histories.keys()
        }

        resolved: List[str] = []
        duplicate_counts: Dict[str, int] = {}
        for index, cfg in enumerate(PARALLEL_CONFIGS, start=1):
            base_name = self._display_name_for_config(cfg)
            duplicate_counts[base_name] = duplicate_counts.get(base_name, 0) + 1
            candidate_name = base_name
            if duplicate_counts[base_name] > 1 or sum(1 for item in PARALLEL_CONFIGS if self._display_name_for_config(item) == base_name) > 1:
                candidate_name = f"{base_name} #{duplicate_counts[base_name]}"
            cfg_id = (cfg.id or f"P{index}").upper()
            normalized_histories.setdefault(self._normalize_agent_name(cfg_id), candidate_name)
            normalized_histories.setdefault(self._normalize_agent_name(candidate_name), candidate_name)
            normalized_histories.setdefault(self._normalize_agent_name(base_name), candidate_name)

        for item in requested:
            resolved_name = normalized_histories.get(self._normalize_agent_name(item))
            if resolved_name and resolved_name not in resolved:
                resolved.append(resolved_name)
        return resolved

    @staticmethod
    def _normalize_agent_name(name: str) -> str:
        return " ".join(str(name).strip().lower().split())

    @staticmethod
    def _display_name_for_config(config: ParallelConfig) -> str:
        normalized_name = str(config.agent_name).strip().lower()
        if normalized_name in _LEGACY_AGENT_DISPLAY_NAMES:
            return _LEGACY_AGENT_DISPLAY_NAMES[normalized_name]

        available_agents = _safe_available_agents()
        agent = available_agents.get(config.agent_name)
        if agent is not None and getattr(agent, "name", None):
            return str(agent.name)
        return _fallback_agent_display_name(str(config.agent_name))

    async def _execute_config_subcommand(self, sub: str, args: List[str]) -> bool:
        if sub == "add":
            return self._cfg_add(args)
        if sub == "list":
            return self._cfg_list()
        if sub == "clear":
            return self._cfg_clear()
        if sub == "remove":
            return self._cfg_remove(args)
        return False

    def _cfg_add(self, args: List[str]) -> bool:
        if not args:
            console.print("[red]Usage: /parallel add <agent_name> [--model MODEL] [--prompt PROMPT] [--unified][/red]")
            return False

        agent_name = args[0]
        available_agents = _safe_available_agents()
        if available_agents and agent_name not in available_agents:
            console.print(f"[red]Unknown agent: {agent_name}[/red]")
            return False

        model: Optional[str] = None
        prompt: Optional[str] = None
        unified = False

        i = 1
        while i < len(args):
            token = args[i]
            if token == "--model" and i + 1 < len(args):
                model = args[i + 1]
                i += 2
                continue
            if token == "--prompt" and i + 1 < len(args):
                prompt = " ".join(args[i + 1 :])
                i = len(args)
                continue
            if token == "--unified":
                unified = True
                i += 1
                continue
            i += 1

        config = ParallelConfig(agent_name=agent_name, model=model, prompt=prompt, unified_context=unified)
        config.id = f"P{len(PARALLEL_CONFIGS) + 1}"
        PARALLEL_CONFIGS.append(config)
        self._sync_env()
        console.print(f"[green]Added parallel agent config {config.id}: {agent_name}[/green]")
        return True

    def _cfg_list(self) -> bool:
        if not PARALLEL_CONFIGS:
            console.print("[yellow]No parallel agent configs defined[/yellow]")
            return True

        table = Table(title="Parallel Agent Configs", box=box.SIMPLE)
        table.add_column("#", style="dim")
        table.add_column("ID", style="magenta")
        table.add_column("Name", style="white")
        table.add_column("Agent", style="cyan")
        table.add_column("Model", style="green")
        table.add_column("Unified", style="yellow")
        table.add_column("Prompt", style="white")

        for idx, cfg in enumerate(PARALLEL_CONFIGS, start=1):
            prompt_text = ""
            if cfg.prompt:
                prompt_text = cfg.prompt if len(cfg.prompt) <= 40 else cfg.prompt[:37] + "..."
            table.add_row(
                str(idx),
                cfg.id or f"P{idx}",
                self._display_name_for_config(cfg),
                cfg.agent_name,
                cfg.model or "default",
                "yes" if cfg.unified_context else "no",
                prompt_text,
            )

        console.print(table)
        return True

    def _cfg_clear(self) -> bool:
        count = len(PARALLEL_CONFIGS)
        PARALLEL_CONFIGS.clear()
        PARALLEL_AGENT_INSTANCES.clear()
        self._sync_env()
        console.print(f"[green]Cleared {count} parallel agent configs[/green]")
        return True

    def _cfg_remove(self, args: List[str]) -> bool:
        if not args:
            console.print("[red]Usage: /parallel remove <index|ID>[/red]")
            return False

        target = args[0].strip()
        idx_to_remove: Optional[int] = None

        if target.upper().startswith("P") and target[1:].isdigit():
            for idx, cfg in enumerate(PARALLEL_CONFIGS):
                cfg_id = (cfg.id or f"P{idx + 1}").upper()
                if cfg_id == target.upper():
                    idx_to_remove = idx
                    break
        elif target.isdigit():
            one_based = int(target)
            if 1 <= one_based <= len(PARALLEL_CONFIGS):
                idx_to_remove = one_based - 1

        if idx_to_remove is None:
            console.print(f"[red]Could not find config '{target}'[/red]")
            return False

        removed = PARALLEL_CONFIGS.pop(idx_to_remove)
        for pos, cfg in enumerate(PARALLEL_CONFIGS, start=1):
            cfg.id = f"P{pos}"

        self._sync_env()
        console.print(f"[green]Removed parallel agent config {removed.id or '?'} ({removed.agent_name})[/green]")
        return True

    def _sync_env(self) -> None:
        if len(PARALLEL_CONFIGS) >= 2:
            os.environ["CERBERUS_PARALLEL"] = str(len(PARALLEL_CONFIGS))
            os.environ["CERBERUS_PARALLEL_AGENTS"] = ",".join(c.agent_name for c in PARALLEL_CONFIGS)
        else:
            os.environ["CERBERUS_PARALLEL"] = "1"
            os.environ["CERBERUS_PARALLEL_AGENTS"] = ",".join(c.agent_name for c in PARALLEL_CONFIGS)

    def _parse_execution_args(self, args: List[str]) -> Optional[Tuple[List[TaskSpec], int]]:
        max_workers = self._default_max_workers()
        file_path: Optional[str] = None
        inline_commands: List[str] = []

        i = 0
        while i < len(args):
            token = args[i]
            if token == "--max-workers":
                if i + 1 >= len(args):
                    console.print("[red]--max-workers requires an integer[/red]")
                    return None
                try:
                    max_workers = max(1, int(args[i + 1]))
                except ValueError:
                    console.print(f"[red]Invalid --max-workers value: {args[i + 1]}[/red]")
                    return None
                i += 2
                continue

            if token == "--file":
                if i + 1 >= len(args):
                    console.print("[red]--file requires a path[/red]")
                    return None
                file_path = args[i + 1]
                i += 2
                continue

            if token.startswith("--"):
                console.print(f"[red]Unknown option: {token}[/red]")
                return None

            inline_commands.append(token)
            i += 1

        commands: List[Tuple[str, str]] = []
        if file_path:
            file_commands = self._load_tasks_from_file(file_path)
            if file_commands is None:
                return None
            commands.extend((cmd, f"file:{file_path}") for cmd in file_commands)

        commands.extend((cmd, "inline") for cmd in inline_commands)

        tasks = [TaskSpec(task_id=f"T{idx}", command=cmd, source=src) for idx, (cmd, src) in enumerate(commands, start=1)]
        return tasks, max_workers

    def _load_tasks_from_file(self, candidate: str) -> Optional[List[str]]:
        raw = Path(candidate).expanduser()
        if raw.is_absolute():
            resolved = raw.resolve()
        else:
            cwd_candidate = (Path.cwd() / raw).resolve()
            ws_candidate = (self._workspace_root / raw).resolve()
            resolved = cwd_candidate if cwd_candidate.exists() else ws_candidate

        allowed_roots = [self._workspace_root.resolve(), Path.cwd().resolve()]
        if not any(self._is_within_root(resolved, root) for root in allowed_roots):
            console.print(f"[red]Security: task file escapes allowed roots: {resolved}[/red]")
            return None

        if not resolved.exists() or not resolved.is_file():
            console.print(f"[red]Task file not found: {resolved}[/red]")
            return None

        lines = resolved.read_text(encoding="utf-8").splitlines()
        tasks = [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]
        return tasks

    @staticmethod
    def _is_within_root(path: Path, root: Path) -> bool:
        try:
            path.resolve().relative_to(root.resolve())
            return True
        except Exception:
            return False

    @staticmethod
    def _default_max_workers() -> int:
        cpu = os.cpu_count() or 2
        return max(2, min(16, cpu))

    @staticmethod
    def _render_summary(result: OrchestrationResult, *, max_workers: int) -> None:
        table = Table(title="Parallel Execution Summary", box=box.SIMPLE_HEAVY)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Total Tasks", str(result.total))
        table.add_row("Max Workers", str(max_workers))
        table.add_row("Succeeded", str(result.succeeded))
        table.add_row("Failed", str(result.failed))
        console.print(table)

        details = Table(title="Task Outcomes", box=box.SIMPLE)
        details.add_column("Task", style="cyan", width=8)
        details.add_column("Status", style="white", width=11)
        details.add_column("Code", style="yellow", width=6)
        details.add_column("Error", style="red")

        for state in result.states:
            details.add_row(
                state.task.task_id,
                state.status,
                "-" if state.return_code is None else str(state.return_code),
                state.error or "",
            )
        console.print(details)

    def _resolve_memory_manager(self) -> MemoryManager:
        if isinstance(self.memory, MemoryManager):
            return self.memory
        return MemoryManager()

    def _get_message_signature(self, msg: Dict[str, Any]) -> Optional[str]:
        """Compatibility helper used by TUI to deduplicate merged messages."""
        role = msg.get("role")
        if not role:
            return None

        if role in {"user", "system"}:
            content = msg.get("content", "")
            normalized = " ".join(str(content).split()) if content else ""
            return f"{role}:{normalized}"

        if role == "assistant":
            content = msg.get("content", "") or ""
            normalized = " ".join(str(content).split()) if content else ""
            tool_calls = msg.get("tool_calls", [])
            if tool_calls:
                tc_parts = []
                for tc in tool_calls:
                    fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                    tc_parts.append(f"{fn.get('name', '')}:{fn.get('arguments', '')}")
                return f"assistant:{normalized}:tools:[{';'.join(sorted(tc_parts))}]"
            return f"assistant:{normalized}"

        if role == "tool":
            tool_call_id = msg.get("tool_call_id", "")
            content = msg.get("content", "")
            normalized = " ".join(str(content).split()) if content else ""
            return f"tool:{tool_call_id}:{normalized[:200]}"

        return None

PARALLEL_COMMAND_INSTANCE = ParallelCommand()
register_command(PARALLEL_COMMAND_INSTANCE)
