"""Supervised execution command for the Cerebro REPL."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from decimal import Decimal
import json
import math
import os
from pathlib import Path
import signal
import threading
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from cerberus.agents import get_agent_by_name
from cerberus.memory import MemoryManager
from cerberus.memory.logic import clean, clean_data
from cerberus.repl.commands.base import CommandError, FrameworkCommand, register_command
from cerberus.repl.commands.config import CONFIG_STORE, _is_secret, _mask
from cerberus.repl.commands.cost import CostCommand, USAGE_TRACKER
from cerberus.repl.commands.env import ENV_AUDITOR
from cerberus.sdk.agents.agent_registry import AGENT_REGISTRY
from cerberus.sdk.agents.items import ItemHelpers, MessageOutputItem, ReasoningItem, ToolCallItem, ToolCallOutputItem
from cerberus.sdk.agents.result import RunResultStreaming
from cerberus.sdk.agents.run import DEFAULT_MAX_TURNS, RunConfig, Runner
from cerberus.sdk.agents.simple_agent_manager import AGENT_MANAGER
from cerberus.sdk.agents.stream_events import AgentUpdatedStreamEvent, RunItemStreamEvent
from cerberus.tools.workspace import get_project_space

console = Console()

_EXTERNAL_TRACE_EXPORT_ENV_KEYS = (
    "LANGCHAIN_TRACING_V2",
    "LANGCHAIN_ENDPOINT",
    "LANGCHAIN_API_KEY",
    "LANGSMITH_TRACING",
    "LANGSMITH_ENDPOINT",
    "LANGSMITH_API_KEY",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_TRACES_EXPORTER",
)


def _disable_external_trace_export_env() -> None:
    for env_key in _EXTERNAL_TRACE_EXPORT_ENV_KEYS:
        os.environ.pop(env_key, None)
    os.environ["CERBERUS_TRACING"] = "false"

_DEFAULT_SAFE_MAX_TURNS = 8
_MAX_OUTPUT_PREVIEW = 400


class RunOptions(BaseModel):
    prompt: str
    agent_name: Optional[str] = None
    max_turns: int = Field(default=_DEFAULT_SAFE_MAX_TURNS, ge=1)
    think: bool = False
    json_output: bool = False


class LeakageFinding(BaseModel):
    source: Literal["config", "env", "pattern"]
    key: str
    masked_value: str


class BudgetSnapshot(BaseModel):
    active: bool
    exceeded: bool
    soft_lock: bool
    currency: str
    limit: str
    total_before: str


class PromptAudit(BaseModel):
    original_prompt: str
    sanitized_prompt: str
    findings: List[LeakageFinding] = Field(default_factory=list)


class ToolTrace(BaseModel):
    tool_name: str
    call_id: Optional[str] = None
    status: Literal["called", "completed", "interrupted"] = "called"
    output_excerpt: Optional[str] = None


class MemoryTurn(BaseModel):
    turn_number: int = Field(ge=1)
    agent_name: str
    user_input: Optional[str] = None
    reasoning: List[str] = Field(default_factory=list)
    tool_calls: List[ToolTrace] = Field(default_factory=list)
    assistant_messages: List[str] = Field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    interrupted: bool = False
    started_at: str = Field(default_factory=lambda: datetime.now(tz=UTC).isoformat())
    completed_at: Optional[str] = None


class ExecutionImpactSummary(BaseModel):
    run_id: str
    agent_name: str
    agent_id: Optional[str] = None
    status: Literal["completed", "soft-stopped", "hard-stopped", "failed"]
    started_at: str
    ended_at: str
    max_turns: int
    turns_completed: int
    think_enabled: bool
    soft_stop_requested: bool
    hard_stop_requested: bool
    budget: BudgetSnapshot
    leakage_findings: List[LeakageFinding] = Field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost_delta_usd: str = "0"
    tools_called: Dict[str, int] = Field(default_factory=dict)
    memory_records_added: int = 0
    turn_journal_path: str
    summary_path: str
    final_output_excerpt: str = ""
    failure_reason: Optional[str] = None


class ExecutionSupervisor:
    """Coordinate preflight safety, streamed execution, and persistence."""

    def __init__(self, *, memory: MemoryManager, workspace_root: Path, session_user: str) -> None:
        self._memory = memory
        self._workspace_root = workspace_root.resolve()
        self._session_user = session_user

    async def run(self, *, agent: Any, options: RunOptions) -> ExecutionImpactSummary:
        _disable_external_trace_export_env()
        started_at = datetime.now(tz=UTC)
        run_id = started_at.strftime("run-%Y%m%dT%H%M%S")
        journal_dir = self._workspace_root / ".cerberus" / "session" / "runs"
        turn_journal_path = journal_dir / f"{run_id}.turns.jsonl"
        summary_path = journal_dir / f"{run_id}.summary.json"

        usage_before = USAGE_TRACKER.session_total()
        input_before, output_before = USAGE_TRACKER.session_total_tokens()

        budget_snapshot, prompt_audit = await self._run_preflight(options.prompt)
        if budget_snapshot.active and budget_snapshot.exceeded:
            raise CommandError(
                "Session budget exceeded. Raise or reset it with /cost budget before starting a supervised run.",
                command_name="/run",
            )

        if prompt_audit.findings:
            console.print(
                Panel(
                    f"Prompt contained {len(prompt_audit.findings)} secret-bearing value(s). The supervised runner will use a redacted prompt.",
                    title="Run Preflight",
                    border_style="yellow",
                )
            )

        run_config = RunConfig(
            workflow_name="Supervised REPL Run",
        )
        streaming_result = Runner.run_streamed(
            agent,
            prompt_audit.sanitized_prompt,
            max_turns=options.max_turns,
            run_config=run_config,
        )

        soft_stop_requested = False
        hard_stop_requested = False
        stop_after_turn: Optional[int] = None
        tools_called: Dict[str, int] = {}
        turns: Dict[int, MemoryTurn] = {}
        live_tools: Dict[str, ToolTrace] = {}
        failure_reason: Optional[str] = None

        active_agent_state = {"name": getattr(agent, "name", options.agent_name or "agent")}
        agent_id = self._ensure_registry_entry(agent, options.agent_name)

        loop = asyncio.get_running_loop()
        can_install_sigint_handler = threading.current_thread() is threading.main_thread()
        original_sigint = signal.getsignal(signal.SIGINT) if can_install_sigint_handler else None

        def _sigint_handler(signum: int, frame: Any) -> None:
            nonlocal soft_stop_requested, hard_stop_requested, stop_after_turn
            if not soft_stop_requested:
                soft_stop_requested = True
                stop_after_turn = max(1, streaming_result.current_turn or 1)
                console.print("\n[yellow]Soft stop requested. Finishing the current turn before shutting down.[/yellow]")
                return

            hard_stop_requested = True
            loop.call_soon_threadsafe(lambda: None)
            if callable(original_sigint):
                try:
                    original_sigint(signum, frame)
                except KeyboardInterrupt:
                    pass

        if can_install_sigint_handler:
            signal.signal(signal.SIGINT, _sigint_handler)
        try:
            await self._consume_stream(
                streaming_result=streaming_result,
                prompt=prompt_audit.sanitized_prompt,
                think=options.think,
                turns=turns,
                live_tools=live_tools,
                tools_called=tools_called,
                current_agent_state=active_agent_state,
                soft_stop_requested=lambda: soft_stop_requested,
                hard_stop_requested=lambda: hard_stop_requested,
                stop_after_turn=lambda: stop_after_turn,
            )
        except Exception as exc:
            failure_reason = str(exc)
            if hard_stop_requested:
                failure_status = "hard-stopped"
            else:
                failure_status = "failed"
            self._finalize_turns(turns, interrupted=True)
            return await self._persist_summary(
                run_id=run_id,
                agent_name=active_agent_state["name"],
                agent_id=agent_id,
                status=failure_status,
                started_at=started_at,
                ended_at=datetime.now(tz=UTC),
                max_turns=options.max_turns,
                think_enabled=options.think,
                soft_stop_requested=soft_stop_requested,
                hard_stop_requested=hard_stop_requested,
                budget_snapshot=budget_snapshot,
                prompt_audit=prompt_audit,
                tools_called=tools_called,
                turns=turns,
                usage_before=usage_before,
                input_before=input_before,
                output_before=output_before,
                final_output=self._collect_partial_output(turns),
                turn_journal_path=turn_journal_path,
                summary_path=summary_path,
                failure_reason=failure_reason,
            )
        finally:
            if can_install_sigint_handler and original_sigint is not None:
                signal.signal(signal.SIGINT, original_sigint)

        status: Literal["completed", "soft-stopped", "hard-stopped", "failed"] = "completed"
        if hard_stop_requested:
            status = "hard-stopped"
        elif soft_stop_requested:
            status = "soft-stopped"

        if soft_stop_requested and stop_after_turn is not None and streaming_result.current_turn > stop_after_turn:
            status = "soft-stopped"

        self._hydrate_turn_usage(turns, streaming_result)
        self._finalize_turns(turns, interrupted=status != "completed")
        final_output = self._stringify_output(streaming_result.final_output) or self._collect_partial_output(turns)
        return await self._persist_summary(
            run_id=run_id,
            agent_name=active_agent_state["name"],
            agent_id=agent_id,
            status=status,
            started_at=started_at,
            ended_at=datetime.now(tz=UTC),
            max_turns=options.max_turns,
            think_enabled=options.think,
            soft_stop_requested=soft_stop_requested,
            hard_stop_requested=hard_stop_requested,
            budget_snapshot=budget_snapshot,
            prompt_audit=prompt_audit,
            tools_called=tools_called,
            turns=turns,
            usage_before=usage_before,
            input_before=input_before,
            output_before=output_before,
            final_output=final_output,
            turn_journal_path=turn_journal_path,
            summary_path=summary_path,
            failure_reason=failure_reason,
        )

    async def _run_preflight(self, prompt: str) -> tuple[BudgetSnapshot, PromptAudit]:
        async with asyncio.TaskGroup() as task_group:
            budget_task = task_group.create_task(self._snapshot_budget())
            prompt_task = task_group.create_task(self._audit_prompt(prompt))
        return budget_task.result(), prompt_task.result()

    async def _snapshot_budget(self) -> BudgetSnapshot:
        _ = CostCommand()
        policy = USAGE_TRACKER.budget
        return BudgetSnapshot(
            active=policy.active,
            exceeded=USAGE_TRACKER.budget_exceeded,
            soft_lock=policy.soft_lock,
            currency=policy.currency,
            limit=str(policy.limit),
            total_before=str(USAGE_TRACKER.session_total()),
        )

    async def _audit_prompt(self, prompt: str) -> PromptAudit:
        findings: List[LeakageFinding] = []
        replacements: Dict[str, str] = {}

        for _, entry, value, _tier in CONFIG_STORE.all_entries():
            if value in {"", "Not set"}:
                continue
            if not _is_secret(entry.name):
                continue
            if value and value in prompt:
                masked = _mask(entry.name, value)
                findings.append(LeakageFinding(source="config", key=entry.name, masked_value=masked))
                replacements[value] = masked

        for key, value in os.environ.items():
            if not value:
                continue
            if value in replacements:
                continue
            if not (ENV_AUDITOR._is_secret_like(key) or _is_secret(key)):
                continue
            if value in prompt:
                masked = ENV_AUDITOR.redact(key, value)
                findings.append(LeakageFinding(source="env", key=key, masked_value=masked))
                replacements[value] = masked

        sanitized_prompt = prompt
        for raw_value, masked_value in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
            sanitized_prompt = sanitized_prompt.replace(raw_value, masked_value)

        pattern_cleaned = clean(prompt)
        if pattern_cleaned != prompt:
            findings.append(
                LeakageFinding(
                    source="pattern",
                    key="generic-secret-pattern",
                    masked_value="[REDACTED_SECRET]",
                )
            )
            sanitized_prompt = clean(sanitized_prompt)

        return PromptAudit(
            original_prompt=prompt,
            sanitized_prompt=sanitized_prompt,
            findings=findings,
        )

    async def _consume_stream(
        self,
        *,
        streaming_result: RunResultStreaming,
        prompt: str,
        think: bool,
        turns: Dict[int, MemoryTurn],
        live_tools: Dict[str, ToolTrace],
        tools_called: Dict[str, int],
        current_agent_state: Dict[str, str],
        soft_stop_requested: Any,
        hard_stop_requested: Any,
        stop_after_turn: Any,
    ) -> None:
        stream_iterator = streaming_result.stream_events()
        printed_message = False
        debug_stream = self._debug_stream_enabled()
        try:
            async for event in stream_iterator:
                current_turn = max(1, streaming_result.current_turn or 1)
                current_agent_name = current_agent_state["name"]

                if hard_stop_requested():
                    self._mark_live_tools_interrupted(live_tools)
                    break

                stop_turn = stop_after_turn()
                if soft_stop_requested() and stop_turn is not None and streaming_result.current_turn > stop_turn:
                    self._mark_live_tools_interrupted(live_tools)
                    break

                turn = turns.setdefault(
                    current_turn,
                    MemoryTurn(
                        turn_number=current_turn,
                        agent_name=current_agent_name,
                        user_input=prompt if current_turn == 1 else None,
                    ),
                )

                if isinstance(event, AgentUpdatedStreamEvent):
                    current_agent_state["name"] = getattr(event.new_agent, "name", current_agent_name)
                    turn.agent_name = current_agent_state["name"]
                    continue

                if not isinstance(event, RunItemStreamEvent):
                    continue

                if event.name == "reasoning_item_created" and isinstance(event.item, ReasoningItem):
                    reasoning_text = self._normalize_text(ItemHelpers.text_reasoning_output(event.item))
                    if reasoning_text:
                        turn.reasoning.append(reasoning_text)
                        if think:
                            console.print(f"[dim][thinking][/dim] {reasoning_text}")
                    continue

                if event.name == "tool_called" and isinstance(event.item, ToolCallItem):
                    tool_name = self._tool_name(event.item)
                    call_id = getattr(event.item.raw_item, "call_id", None)
                    tools_called[tool_name] = tools_called.get(tool_name, 0) + 1
                    tool_trace = ToolTrace(tool_name=tool_name, call_id=call_id, status="called")
                    live_tools[call_id or f"{tool_name}:{len(turn.tool_calls) + 1}"] = tool_trace
                    turn.tool_calls.append(tool_trace)
                    if debug_stream:
                        console.print(f"[cyan]tool[/cyan] {tool_name}")
                    continue

                if event.name == "tool_output" and isinstance(event.item, ToolCallOutputItem):
                    call_id = None
                    if isinstance(event.item.raw_item, dict):
                        call_id = event.item.raw_item.get("call_id")
                    tool_trace = live_tools.get(call_id or "")
                    output_excerpt = self._truncate(self._stringify_output(event.item.output), limit=_MAX_OUTPUT_PREVIEW)
                    if tool_trace is None:
                        tool_trace = ToolTrace(tool_name="unknown", call_id=call_id, status="completed")
                        turn.tool_calls.append(tool_trace)
                    tool_trace.status = "completed"
                    tool_trace.output_excerpt = output_excerpt
                    continue

                if event.name == "message_output_created" and isinstance(event.item, MessageOutputItem):
                    message_text = self._normalize_text(ItemHelpers.text_message_output(event.item))
                    if message_text:
                        turn.assistant_messages.append(message_text)
                        console.print(message_text, highlight=False, end="")
                        printed_message = True

            if printed_message:
                console.print()
        finally:
            await stream_iterator.aclose()

    def _debug_stream_enabled(self) -> bool:
        debug_raw = os.getenv("CERBERUS_DEBUG", "0").strip().lower()
        verbose_raw = os.getenv("CERBERUS_VERBOSE", "0").strip().lower()
        return debug_raw not in {"", "0", "false", "off", "no"} or verbose_raw not in {
            "",
            "0",
            "false",
            "off",
            "no",
        }

    async def _persist_summary(
        self,
        *,
        run_id: str,
        agent_name: str,
        agent_id: Optional[str],
        status: Literal["completed", "soft-stopped", "hard-stopped", "failed"],
        started_at: datetime,
        ended_at: datetime,
        max_turns: int,
        think_enabled: bool,
        soft_stop_requested: bool,
        hard_stop_requested: bool,
        budget_snapshot: BudgetSnapshot,
        prompt_audit: PromptAudit,
        tools_called: Dict[str, int],
        turns: Dict[int, MemoryTurn],
        usage_before: Decimal,
        input_before: int,
        output_before: int,
        final_output: str,
        turn_journal_path: Path,
        summary_path: Path,
        failure_reason: Optional[str],
    ) -> ExecutionImpactSummary:
        usage_after = USAGE_TRACKER.session_total()
        input_after, output_after = USAGE_TRACKER.session_total_tokens()
        turn_rows = [turns[index] for index in sorted(turns)]
        final_excerpt = self._truncate(final_output, limit=_MAX_OUTPUT_PREVIEW)

        memory_records_added = 0
        if turn_rows:
            memory_payload = {
                "topic": "run-supervisor",
                "finding": f"{agent_name} finished with status={status} after {len(turn_rows)} turn(s).",
                "source": self._session_user,
                "tags": ["run", status, agent_name],
                "artifacts": {
                    "run_id": run_id,
                    "summary_path": str(summary_path),
                    "turn_journal_path": str(turn_journal_path),
                    "tool_count": sum(tools_called.values()),
                    "cost_delta_usd": str(usage_after - usage_before),
                },
            }
            await asyncio.to_thread(self._memory.record, memory_payload)
            memory_records_added = 1

        summary = ExecutionImpactSummary(
            run_id=run_id,
            agent_name=agent_name,
            agent_id=agent_id,
            status=status,
            started_at=started_at.isoformat(),
            ended_at=ended_at.isoformat(),
            max_turns=max_turns,
            turns_completed=len(turn_rows),
            think_enabled=think_enabled,
            soft_stop_requested=soft_stop_requested,
            hard_stop_requested=hard_stop_requested,
            budget=budget_snapshot,
            leakage_findings=prompt_audit.findings,
            input_tokens=max(0, input_after - input_before),
            output_tokens=max(0, output_after - output_before),
            total_tokens=max(0, (input_after - input_before) + (output_after - output_before)),
            cost_delta_usd=str(usage_after - usage_before),
            tools_called=tools_called,
            memory_records_added=memory_records_added,
            turn_journal_path=str(turn_journal_path),
            summary_path=str(summary_path),
            final_output_excerpt=final_excerpt,
            failure_reason=failure_reason,
        )

        async with asyncio.TaskGroup() as task_group:
            task_group.create_task(asyncio.to_thread(self._write_jsonl, turn_journal_path, turn_rows))
            task_group.create_task(asyncio.to_thread(self._write_json, summary_path, summary))

        return summary

    def _ensure_registry_entry(self, agent: Any, requested_agent_name: Optional[str]) -> Optional[str]:
        display_name = getattr(agent, "name", requested_agent_name or "agent")
        model_name = getattr(getattr(agent, "model", None), "model", os.getenv("CERBERUS_MODEL", "unknown"))

        for registered_id, info in AGENT_REGISTRY.get_all_agents():
            if info.display_name == display_name and info.model_name == model_name:
                AGENT_MANAGER.set_active_agent(agent, display_name, registered_id)
                return registered_id

        if getattr(agent, "model", None) is None:
            AGENT_MANAGER.set_active_agent(agent, display_name)
            return None

        agent_type = requested_agent_name or os.getenv("CERBERUS_AGENT_TYPE", display_name.lower().replace(" ", "_"))
        registered_id = AGENT_REGISTRY.register_agent(
            getattr(agent, "model"),
            agent_type=agent_type,
            display_name=display_name,
            is_parallel=False,
        )
        AGENT_MANAGER.set_active_agent(agent, display_name, registered_id)
        return registered_id

    def _hydrate_turn_usage(self, turns: Dict[int, MemoryTurn], streaming_result: RunResultStreaming) -> None:
        for index, response in enumerate(streaming_result.raw_responses, 1):
            turn = turns.get(index)
            if turn is None:
                continue
            turn.input_tokens = response.usage.input_tokens
            turn.output_tokens = response.usage.output_tokens
            turn.total_tokens = response.usage.total_tokens

    def _finalize_turns(self, turns: Dict[int, MemoryTurn], *, interrupted: bool) -> None:
        completed_at = datetime.now(tz=UTC).isoformat()
        for turn in turns.values():
            turn.completed_at = completed_at
            if interrupted and not turn.assistant_messages:
                turn.interrupted = True

    def _collect_partial_output(self, turns: Dict[int, MemoryTurn]) -> str:
        ordered_messages: List[str] = []
        for turn_number in sorted(turns):
            ordered_messages.extend(turns[turn_number].assistant_messages)
        return "\n".join(ordered_messages).strip()

    def _mark_live_tools_interrupted(self, live_tools: Dict[str, ToolTrace]) -> None:
        for trace in live_tools.values():
            if trace.status == "called":
                trace.status = "interrupted"

    def _tool_name(self, item: ToolCallItem) -> str:
        for attr_name in ("name", "action", "type"):
            value = getattr(item.raw_item, attr_name, None)
            if value:
                return str(value)
        return "unknown"

    def _stringify_output(self, output: Any) -> str:
        if output is None:
            return ""
        if isinstance(output, str):
            return clean(output)
        if isinstance(output, (dict, list, tuple)):
            return json.dumps(clean_data(output), ensure_ascii=True, indent=2)
        return clean(str(output))

    def _normalize_text(self, value: str) -> str:
        return clean(value).strip()

    def _truncate(self, value: str, *, limit: int) -> str:
        if len(value) <= limit:
            return value
        return value[: limit - 3] + "..."

    def _write_jsonl(self, path: Path, rows: List[MemoryTurn]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row.model_dump(mode="json"), ensure_ascii=True) + "\n")

    def _write_json(self, path: Path, payload: BaseModel) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload.model_dump(mode="json"), ensure_ascii=True, indent=2), encoding="utf-8")


class RunCommand(FrameworkCommand):
    """Managed execution command with budget, leakage, and memory supervision."""

    name = "/run"
    description = "Execute a supervised agent run with policy checks and workspace journaling"
    aliases = ["/r"]

    @property
    def help(self) -> str:
        default_turns = self._default_max_turns()
        return (
            "/run [--agent <agent>] [--max-turns <n>] [--think] [--json] <prompt>\n\n"
            "Examples:\n"
            "  /run --agent web_pentester_agent --max-turns 6 Investigate the exposed login flow\n"
            "  /run --think Summarize the current engagement status\n\n"
            f"Default max turns: {default_turns}. If CERBERUS_MAX_TURNS is unset or unbounded, the supervisor enforces {default_turns} turns for safety.\n"
            "Ctrl+C requests a soft stop first, then escalates on a second interrupt.\n"
            "Prompt inputs are audited for leaked secrets before dispatch and are redacted automatically when possible."
        )

    def sanitize_args(self, args: Optional[List[str]]) -> List[str]:
        if args is None:
            return []
        cleaned: List[str] = []
        for token in args:
            if "\x00" in token:
                raise CommandError("Arguments cannot contain null bytes", command_name=self.name, exit_code=2)
            cleaned.append(token.strip())
        return cleaned

    async def execute(self, args: List[str]) -> bool:
        if len(args) == 1 and args[0] in {"-h", "--help", "help"}:
            console.print(self.help)
            return True

        options = await self._parse_args(args)
        agent = self._resolve_agent(options.agent_name)
        memory_manager = self._resolve_memory_manager()
        workspace_root = get_project_space().ensure_initialized().resolve()
        supervisor = ExecutionSupervisor(
            memory=memory_manager,
            workspace_root=workspace_root,
            session_user=self.session.user,
        )
        summary = await supervisor.run(agent=agent, options=options)
        self._render_summary(summary, as_json=options.json_output)
        return summary.status in {"completed", "soft-stopped"}

    async def _parse_args(self, args: List[str]) -> RunOptions:
        agent_name: Optional[str] = None
        think = False
        json_output = False
        max_turns = self._default_max_turns()
        prompt_tokens: List[str] = []

        index = 0
        while index < len(args):
            token = args[index]
            if token == "--":
                prompt_tokens.extend(args[index + 1 :])
                break
            if token == "--agent":
                index += 1
                if index >= len(args):
                    raise CommandError("--agent requires a value", command_name=self.name, exit_code=2)
                agent_name = args[index]
                index += 1
                continue
            if token == "--max-turns":
                index += 1
                if index >= len(args):
                    raise CommandError("--max-turns requires a value", command_name=self.name, exit_code=2)
                try:
                    max_turns = max(1, int(args[index]))
                except ValueError as exc:
                    raise CommandError("--max-turns must be an integer", command_name=self.name, exit_code=2) from exc
                index += 1
                continue
            if token == "--think":
                think = True
                index += 1
                continue
            if token == "--json":
                json_output = True
                index += 1
                continue
            if token.startswith("--"):
                raise CommandError(f"Unknown option: {token}", command_name=self.name, exit_code=2)

            prompt_tokens.extend(args[index:])
            break

        prompt = " ".join(token for token in prompt_tokens if token)
        if not prompt:
            prompt = await asyncio.to_thread(Prompt.ask, "Run prompt")
        if not prompt.strip():
            raise CommandError("A prompt is required", command_name=self.name, exit_code=2)

        return RunOptions(
            prompt=prompt.strip(),
            agent_name=agent_name.strip() if agent_name else None,
            max_turns=max_turns,
            think=think,
            json_output=json_output,
        )

    def _resolve_agent(self, agent_name: Optional[str]) -> Any:
        active_agent = AGENT_MANAGER.get_active_agent()
        if active_agent is not None and agent_name is None:
            return active_agent

        requested_agent = agent_name or os.getenv("CERBERUS_AGENT_TYPE", "one_tool")
        try:
            return get_agent_by_name(requested_agent)
        except Exception as exc:
            raise CommandError(f"Unable to resolve agent '{requested_agent}': {exc}", command_name=self.name) from exc

    def _resolve_memory_manager(self) -> MemoryManager:
        if isinstance(self.memory, MemoryManager):
            self.memory.initialize()
            return self.memory
        memory_manager = MemoryManager()
        memory_manager.initialize()
        return memory_manager

    def _default_max_turns(self) -> int:
        if isinstance(DEFAULT_MAX_TURNS, int) and DEFAULT_MAX_TURNS > 0:
            return DEFAULT_MAX_TURNS
        if isinstance(DEFAULT_MAX_TURNS, float) and math.isfinite(DEFAULT_MAX_TURNS) and DEFAULT_MAX_TURNS > 0:
            return int(DEFAULT_MAX_TURNS)
        return _DEFAULT_SAFE_MAX_TURNS

    def _render_summary(self, summary: ExecutionImpactSummary, *, as_json: bool) -> None:
        if as_json:
            console.print_json(json.dumps(summary.model_dump(mode="json")))
            return

        table = Table(title="Cerebro Supervised Mission Summary")
        table.add_column("Field", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        table.add_row("Agent", summary.agent_name if summary.agent_id is None else f"{summary.agent_name} [{summary.agent_id}]")
        table.add_row("Status", summary.status)
        table.add_row("Turns", f"{summary.turns_completed}/{summary.max_turns}")
        table.add_row("Tokens", str(summary.total_tokens))
        table.add_row("Cost", f"${summary.cost_delta_usd}")
        table.add_row("Tools", ", ".join(f"{name} x{count}" for name, count in summary.tools_called.items()) or "none")
        table.add_row("Memory", f"{summary.memory_records_added} record(s)")
        table.add_row("Turn Journal", summary.turn_journal_path)
        table.add_row("Summary", summary.summary_path)
        console.print(table)

        if summary.leakage_findings:
            console.print(
                Panel(
                    "\n".join(
                        f"{finding.source}:{finding.key} -> {finding.masked_value}"
                        for finding in summary.leakage_findings
                    ),
                    title="Cerebro Prompt Redactions",
                    border_style="yellow",
                )
            )

        if summary.final_output_excerpt:
            console.print(Panel(summary.final_output_excerpt, title="Final Output", border_style="green"))


RUN_COMMAND_INSTANCE = RunCommand()
register_command(RUN_COMMAND_INSTANCE)
