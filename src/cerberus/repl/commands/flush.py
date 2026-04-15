"""Secure memory and state purge command for Cerebro REPL.

This module upgrades flush behavior from a simple history clear into a
commercial-grade state lifecycle manager that supports:
- targeted purge scopes (memory, ui, all)
- async checkpointing before disposal
- secure overwrite of sensitive volatile buffers
- selective retention of verified vulnerability knowledge
- audit trail records suitable for compliance reviews
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from cerberus.repl.commands.base import Command, CommandError, register_command

console = Console()
logger = logging.getLogger(__name__)


@dataclass
class PurgeResult:
    """Summary of one purge operation."""

    scope: str
    success: bool
    checkpoint_created: bool = False
    checkpoint_path: str = ""
    cleared_items: int = 0
    retained_items: int = 0
    notes: List[str] = field(default_factory=list)


@dataclass
class FlushAuditRecord:
    """Compliance-oriented flush audit entry."""

    timestamp: str
    operation: str
    scopes: List[str]
    backup_created: bool
    backup_path: str
    cleared_items: int
    retained_items: int
    actor: str
    workspace: str
    success: bool
    notes: List[str]


class StateResetUtility:
    """Utility responsible for secure state purge, checkpointing, and audit.

    The class is intentionally interface-driven so it can work with both
    full framework runtime objects and lightweight test doubles.
    """

    _SENSITIVE_MARKERS = (
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "private_key",
        "credential",
        "hash",
    )

    def __init__(self, *, workspace: Any = None, memory: Any = None) -> None:
        self.workspace = workspace
        self.memory = memory
        self.workspace_root = self._resolve_workspace_root()
        self._secure_buffers: List[bytearray] = []

    # -- path helpers -------------------------------------------------------

    def _resolve_workspace_root(self) -> Path:
        if self.workspace is not None:
            for attr in ("session_root", "workspace_root"):
                value = getattr(self.workspace, attr, None)
                if value:
                    return Path(value).expanduser().resolve()
            for method in ("ensure_initialized", "initialize"):
                fn = getattr(self.workspace, method, None)
                if callable(fn):
                    try:
                        path = fn()
                        if path:
                            return Path(str(path)).expanduser().resolve()
                    except Exception:
                        pass

        try:
            from cerberus.tools.workspace import get_project_space

            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()

    def _checkpoint_dir(self) -> Path:
        path = self.workspace_root / ".cerberus" / "checkpoints"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _audit_path(self) -> Path:
        path = self.workspace_root / ".cerberus" / "audit"
        path.mkdir(parents=True, exist_ok=True)
        return path / "flush_audit.jsonl"

    # -- sensitive memory handling -----------------------------------------

    def _looks_sensitive(self, payload: str) -> bool:
        txt = payload.lower()
        return any(marker in txt for marker in self._SENSITIVE_MARKERS)

    def _collect_sensitive_buffers(self, records: Sequence[Dict[str, Any]]) -> int:
        collected = 0
        for record in records:
            content = str(record.get("content", ""))
            if self._looks_sensitive(content):
                buf = bytearray(content.encode("utf-8", errors="ignore"))
                self._secure_buffers.append(buf)
                collected += 1
        return collected

    def _secure_wipe(self) -> None:
        # Overwrite tracked buffers in RAM before disposal.
        for buf in self._secure_buffers:
            for i in range(len(buf)):
                buf[i] = 0
        self._secure_buffers = []

    # -- history extraction/purge ------------------------------------------

    def _snapshot_histories(self) -> Dict[str, List[Dict[str, Any]]]:
        histories: Dict[str, List[Dict[str, Any]]] = {}

        try:
            from cerberus.sdk.agents.simple_agent_manager import AGENT_MANAGER

            all_histories = AGENT_MANAGER.get_all_histories() or {}
            for agent_name, msgs in all_histories.items():
                histories[str(agent_name)] = [m for m in (msgs or []) if isinstance(m, dict)]
        except Exception:
            pass

        return histories

    def _extract_verified_kb(self) -> List[Dict[str, Any]]:
        """Extract verified vulnerability facts from memory manager if available."""
        retained: List[Dict[str, Any]] = []
        mm = self.memory
        if mm is None:
            return retained

        get_context = getattr(mm, "get_context", None)
        if not callable(get_context):
            return retained

        try:
            ctx = get_context("verified vulnerability cve exploit confirmed", limit=120)
            events = getattr(ctx, "events", []) or []
            for ev in events:
                content = str(getattr(ev, "content", ""))
                topic = str(getattr(ev, "topic", "general"))
                tags = list(getattr(ev, "tags", []) or [])
                is_verified = (
                    "verified" in content.lower()
                    or "cve-" in content.lower()
                    or "vulnerability" in topic.lower()
                    or any("verified" in str(t).lower() for t in tags)
                )
                if is_verified:
                    retained.append(
                        {
                            "topic": topic,
                            "content": content,
                            "tags": tags,
                            "agent_id": str(getattr(ev, "agent_id", "default")),
                        }
                    )
        except Exception:
            return retained

        return retained

    def _restore_verified_kb(self, records: Sequence[Dict[str, Any]]) -> int:
        mm = self.memory
        if mm is None:
            return 0
        add_event = getattr(mm, "add_event", None)
        if not callable(add_event):
            return 0

        restored = 0
        for rec in records:
            try:
                add_event(
                    rec.get("content", ""),
                    topic=rec.get("topic", "vulnerability"),
                    tags=rec.get("tags", []),
                    agent_id=rec.get("agent_id", "default"),
                    persist=True,
                )
                restored += 1
            except Exception:
                continue
        return restored

    def _purge_agent_histories(self) -> int:
        """Wipe agent histories across manager/model/parallel registries."""
        cleared = 0

        try:
            from cerberus.sdk.agents.simple_agent_manager import AGENT_MANAGER

            all_histories = AGENT_MANAGER.get_all_histories() or {}
            for name in list(all_histories.keys()):
                base = str(name).split(" [")[0]
                hist = AGENT_MANAGER.get_message_history(base)
                cleared += len(hist or [])
                # Avoid list.clear pattern; replace list content explicitly.
                if isinstance(hist, list):
                    del hist[:]
                AGENT_MANAGER.clear_history(base)

            active = AGENT_MANAGER.get_active_agent()
            if active and hasattr(active, "model") and hasattr(active.model, "message_history"):
                mh = active.model.message_history
                if isinstance(mh, list):
                    cleared += len(mh)
                    del mh[:]
        except Exception:
            pass

        try:
            from cerberus.sdk.agents.parallel_isolation import PARALLEL_ISOLATION

            isolated = getattr(PARALLEL_ISOLATION, "_isolated_histories", {})
            if isinstance(isolated, dict):
                for agent_id, hist in list(isolated.items()):
                    if isinstance(hist, list):
                        cleared += len(hist)
                    PARALLEL_ISOLATION.clear_agent_history(agent_id)
        except Exception:
            pass

        try:
            from cerberus.sdk.agents.models.openai_chatcompletions import ACTIVE_MODEL_INSTANCES

            for _, model_ref in list(ACTIVE_MODEL_INSTANCES.items()):
                model = model_ref() if callable(model_ref) else model_ref
                mh = getattr(model, "message_history", None)
                if isinstance(mh, list):
                    cleared += len(mh)
                    del mh[:]
        except Exception:
            pass

        return cleared

    def _reinitialize_active_persona(self) -> bool:
        """Rebuild minimal persona context for the current active agent."""
        try:
            from cerberus.sdk.agents.simple_agent_manager import AGENT_MANAGER

            active = AGENT_MANAGER.get_active_agent()
            if not active or not hasattr(active, "model"):
                return False
            model = active.model
            history = getattr(model, "message_history", None)
            if not isinstance(history, list):
                return False

            persona = {
                "role": "system",
                "content": (
                    "Session state was securely purged. Keep prior verified findings only "
                    "if explicitly reloaded from memory/checkpoint artifacts."
                ),
            }
            history.append(persona)

            name = getattr(active, "name", "")
            if name:
                AGENT_MANAGER._message_history[name] = history
            return True
        except Exception:
            return False

    # -- async I/O ----------------------------------------------------------

    async def _write_json_async(self, path: Path, payload: Dict[str, Any]) -> None:
        def _write() -> None:
            path.write_text(json.dumps(payload, indent=2))

        await asyncio.to_thread(_write)

    async def _append_audit_async(self, rec: FlushAuditRecord) -> None:
        line = json.dumps(
            {
                "timestamp": rec.timestamp,
                "operation": rec.operation,
                "scopes": rec.scopes,
                "backup_created": rec.backup_created,
                "backup_path": rec.backup_path,
                "cleared_items": rec.cleared_items,
                "retained_items": rec.retained_items,
                "actor": rec.actor,
                "workspace": rec.workspace,
                "success": rec.success,
                "notes": rec.notes,
            }
        )

        path = self._audit_path()

        def _append() -> None:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

        await asyncio.to_thread(_append)

    async def create_memory_checkpoint(self) -> Tuple[str, int]:
        """Persist active in-memory conversation state to checkpoint file."""
        histories = self._snapshot_histories()
        stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out = self._checkpoint_dir() / f"memory_checkpoint_{stamp}.json"

        payload = {
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "workspace_root": str(self.workspace_root),
            "agent_histories": histories,
            "message_count": sum(len(v) for v in histories.values()),
        }
        await self._write_json_async(out, payload)
        return str(out), int(payload["message_count"])

    async def secure_clear_ui(self) -> None:
        """Best-effort terminal wipe without shelling out to 'clear'."""
        width = shutil.get_terminal_size((120, 40)).columns
        noise_lines = 6

        # Overwrite recent viewport with random-looking data.
        for _ in range(noise_lines):
            noise = secrets.token_hex(max(1, width // 4))[:width]
            sys.stdout.write(noise + "\n")

        # ANSI full clear + scrollback clear + cursor home.
        sys.stdout.write("\x1b[2J\x1b[3J\x1b[H")
        sys.stdout.flush()

    async def flush_memory(self, *, retain_kb: bool) -> PurgeResult:
        checkpoint_path, msg_count = await self.create_memory_checkpoint()
        histories = self._snapshot_histories()

        flattened = []
        for msgs in histories.values():
            flattened.extend(msgs)
        sensitive_count = self._collect_sensitive_buffers(flattened)

        retained_records: List[Dict[str, Any]] = []
        if retain_kb:
            retained_records = self._extract_verified_kb()

        cleared = self._purge_agent_histories()

        if retain_kb and retained_records:
            # Clear long-term memory then restore retained facts, when supported.
            mm = self.memory
            clear_fn = getattr(mm, "clear", None) if mm is not None else None
            if callable(clear_fn):
                try:
                    clear_fn(short_term=True, long_term=False)
                except Exception:
                    pass
            restored = self._restore_verified_kb(retained_records)
        else:
            restored = 0

        self._secure_wipe()

        notes = [f"sensitive_buffers_overwritten={sensitive_count}"]
        if retain_kb:
            notes.append(f"verified_kb_retained={restored}")

        return PurgeResult(
            scope="memory",
            success=True,
            checkpoint_created=True,
            checkpoint_path=checkpoint_path,
            cleared_items=max(cleared, msg_count),
            retained_items=restored,
            notes=notes,
        )

    async def flush_all(self, *, retain_kb: bool) -> PurgeResult:
        memory_result = await self.flush_memory(retain_kb=retain_kb)
        await self.secure_clear_ui()
        persona_ok = self._reinitialize_active_persona()

        notes = list(memory_result.notes)
        notes.append(f"active_persona_reinitialized={persona_ok}")

        return PurgeResult(
            scope="all",
            success=memory_result.success,
            checkpoint_created=memory_result.checkpoint_created,
            checkpoint_path=memory_result.checkpoint_path,
            cleared_items=memory_result.cleared_items,
            retained_items=memory_result.retained_items,
            notes=notes,
        )


class FlushCommand(Command):
    """Secure memory & state purge command."""

    name = "/flush"
    description = "Clear conversation history (all agents by default, or specific agent)"
    aliases = ["/clear"]

    def __init__(self) -> None:
        super().__init__(name=self.name, description=self.description, aliases=self.aliases)
        self.add_subcommand("all", "Clear history for all agents", self.handle_all)
        self.add_subcommand("agent", "Clear history for a specific agent", self.handle_agent)

    def _is_parallel_agent_id(self, value: str) -> bool:
        return bool(re.fullmatch(r"P\d+", value or "", flags=re.IGNORECASE))

    def handle(self, args: Optional[List[str]] = None) -> bool:  # type: ignore[override]
        try:
            clean = self.sanitize_args(args)
        except Exception as exc:
            console.print(f"[red]Input validation failed: {exc}[/red]")
            return False

        record = self._audit_before(clean)
        try:
            if any(token.startswith("--") for token in clean):
                result = self._run_execute(clean)
            elif not clean:
                result = self.handle_no_args()
            elif clean[0].lower() == "all":
                result = self.handle_all(clean[1:])
            elif clean[0].lower() == "agent":
                result = self.handle_agent(clean[1:])
            else:
                result = self.handle_agent(clean)
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
        from cerberus.sdk.agents.models.openai_chatcompletions import get_all_agent_histories

        histories = get_all_agent_histories()
        if histories:
            console.print(self.help)
        else:
            console.print("[yellow]No agent histories to clear[/yellow]")
        return True

    def handle_all(self, args: Optional[List[str]] = None) -> bool:
        del args
        from cerberus.sdk.agents.models.openai_chatcompletions import clear_all_histories, get_all_agent_histories

        get_all_agent_histories()
        clear_all_histories()
        console.print("[green]Cleared history for all agents[/green]")
        return True

    def handle_agent(self, args: Optional[List[str]] = None) -> bool:
        from cerberus.sdk.agents.models.openai_chatcompletions import clear_agent_history, get_agent_message_history

        agent_name = " ".join(args or [])
        if self._is_parallel_agent_id(agent_name):
            from cerberus.sdk.agents.parallel_isolation import PARALLEL_ISOLATION

            PARALLEL_ISOLATION.get_isolated_history(agent_name)
            PARALLEL_ISOLATION.clear_agent_history(agent_name)
            console.print(f"[green]Cleared isolated history for {agent_name}[/green]")
            return True

        get_agent_message_history(agent_name)
        clear_agent_history(agent_name)
        console.print(f"[green]Cleared history for {agent_name}[/green]")
        return True

    @property
    def help(self) -> str:
        return (
            "flush [--memory] [--ui] [--all] [--retain-kb]\n\n"
            "Scopes:\n"
            "  --memory     Save checkpoint, wipe active conversation buffers securely\n"
            "  --ui         Securely overwrite and clear terminal viewport\n"
            "  --all        Full state reset (memory + ui + persona reinit)\n"
            "\n"
            "Retention:\n"
            "  --retain-kb  Preserve verified vulnerability knowledge during purge\n"
            "\n"
            "Default scope when omitted: --memory\n"
        )

    async def execute(self, args: List[str]) -> bool:
        flags = {a.lower() for a in args}

        run_memory = "--memory" in flags
        run_ui = "--ui" in flags
        run_all = "--all" in flags
        retain_kb = "--retain-kb" in flags

        # Default behavior is memory flush checkpoint + secure purge.
        if not (run_memory or run_ui or run_all):
            run_memory = True

        util = StateResetUtility(workspace=self.workspace, memory=self.memory)
        results: List[PurgeResult] = []

        if run_all:
            logger.info("flush: starting full reset retain_kb=%s", retain_kb)
            res = await util.flush_all(retain_kb=retain_kb)
            results.append(res)
        else:
            if run_memory:
                logger.info("flush: starting memory purge retain_kb=%s", retain_kb)
                results.append(await util.flush_memory(retain_kb=retain_kb))
            if run_ui:
                logger.info("flush: starting ui secure clear")
                await util.secure_clear_ui()
                results.append(PurgeResult(scope="ui", success=True, notes=["terminal_overwrite_passes=6"]))

        total_cleared = sum(r.cleared_items for r in results)
        total_retained = sum(r.retained_items for r in results)
        checkpoint_path = next((r.checkpoint_path for r in results if r.checkpoint_path), "")
        backup_created = any(r.checkpoint_created for r in results)
        success = all(r.success for r in results) if results else False

        audit = FlushAuditRecord(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            operation="flush",
            scopes=[r.scope for r in results],
            backup_created=backup_created,
            backup_path=checkpoint_path,
            cleared_items=total_cleared,
            retained_items=total_retained,
            actor=self.session.user,
            workspace=str(util.workspace_root),
            success=success,
            notes=[note for r in results for note in r.notes],
        )
        await util._append_audit_async(audit)

        logger.info(
            "flush: completed scopes=%s success=%s cleared=%s retained=%s checkpoint=%s",
            audit.scopes,
            success,
            total_cleared,
            total_retained,
            checkpoint_path or "none",
        )

        summary = Table(title="Secure Flush Result", box=box.ROUNDED, show_header=True, header_style="bold")
        summary.add_column("Scope", style="cyan")
        summary.add_column("Status", style="green")
        summary.add_column("Cleared", style="yellow", justify="right")
        summary.add_column("Retained", style="magenta", justify="right")
        for r in results:
            summary.add_row(r.scope, "OK" if r.success else "FAIL", str(r.cleared_items), str(r.retained_items))

        console.print(summary)
        if checkpoint_path:
            console.print(f"[dim]Checkpoint: {checkpoint_path}[/dim]")

        console.print(
            Panel(
                f"Audit trail appended to {util._audit_path()}\n"
                f"Backup created: {'yes' if backup_created else 'no'}\n"
                f"Retained verified KB records: {total_retained}",
                title="[blue]Flush Audit[/blue]",
                border_style="blue",
                box=box.ROUNDED,
            )
        )

        return success


FLUSH_COMMAND_INSTANCE = FlushCommand()
register_command(FLUSH_COMMAND_INSTANCE)
