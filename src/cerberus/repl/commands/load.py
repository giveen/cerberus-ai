"""Session hydration command for Cerebro REPL.

This module provides a security-first loader that restores prior session state
with integrity verification, selective hydration modes, and conflict-aware
merge/overwrite behavior.
"""

from __future__ import annotations

from contextlib import ExitStack
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field, ValidationError
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cerberus.memory import MemoryManager
from cerberus.repl.commands.base import Command, CommandError, register_command
from cerberus.repl.commands.parallel import PARALLEL_CONFIGS, ParallelConfig
from cerberus.repl.commands.cost import USAGE_TRACKER, UsageRecord, BudgetPolicy
from cerberus.sdk.agents.models.openai_chatcompletions import get_all_agent_histories, get_agent_message_history
from cerberus.sdk.agents.run_to_jsonl import load_history_from_jsonl
from cerberus.sdk.agents.simple_agent_manager import AGENT_MANAGER
from cerberus.tools.workspace import get_project_space

console = Console()
DEFAULT_LEGACY_LOAD_SOURCE = "logs/last"


def _get_agent_manager() -> Any:
    from cerberus.sdk.agents.simple_agent_manager import AGENT_MANAGER as agent_manager

    return agent_manager


def _get_history_runtime_state() -> Tuple[Dict[Any, Any], Dict[str, List[Dict[str, Any]]]]:
    from cerberus.sdk.agents.models import openai_chatcompletions as chat_models

    return chat_models.ACTIVE_MODEL_INSTANCES, chat_models.PERSISTENT_MESSAGE_HISTORIES


class IntegrityError(Exception):
    """Raised when session envelope integrity validation fails."""


class LedgerRecord(BaseModel):
    """Serializable cost ledger record."""

    record_id: Optional[str] = None
    agent_name: str = ""
    model: str = ""
    operation: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cost: str = "0"
    timestamp: Optional[str] = None
    session_id: Optional[str] = None


class BudgetSnapshot(BaseModel):
    """Serializable budget policy snapshot."""

    limit: str = "0"
    currency: str = "USD"
    conversion_rate: str = "1"
    soft_lock: bool = True


class CostLedgerPayload(BaseModel):
    """Serializable cost ledger payload."""

    session_id: Optional[str] = None
    session_total_usd: Optional[str] = None
    budget: BudgetSnapshot = Field(default_factory=BudgetSnapshot)
    records: List[LedgerRecord] = Field(default_factory=list)


class AgentConfigPayload(BaseModel):
    """Serializable parallel agent configuration."""

    agent_name: str
    model: Optional[str] = None
    prompt: Optional[str] = None
    unified_context: bool = False
    id: Optional[str] = None


class AgentContextPayload(BaseModel):
    """Serializable agent-context payload."""

    active_agent: Optional[str] = None
    registry: Dict[str, str] = Field(default_factory=dict)
    histories: Dict[str, List[Dict[str, Any]]] = Field(default_factory=dict)
    parallel_configs: List[AgentConfigPayload] = Field(default_factory=list)


class MemoryStackPayload(BaseModel):
    """Serializable memory stack payload."""

    summaries: List[str] = Field(default_factory=list)
    histories: Dict[str, List[Dict[str, Any]]] = Field(default_factory=dict)


class SessionConfigPayload(BaseModel):
    """Serializable configuration payload."""

    env: Dict[str, str] = Field(default_factory=dict)
    settings: Dict[str, Any] = Field(default_factory=dict)


class SessionPayload(BaseModel):
    """Serializable full session payload."""

    workspace: str = ""
    memory: MemoryStackPayload = Field(default_factory=MemoryStackPayload)
    agents: AgentContextPayload = Field(default_factory=AgentContextPayload)
    cost: CostLedgerPayload = Field(default_factory=CostLedgerPayload)
    config: SessionConfigPayload = Field(default_factory=SessionConfigPayload)


class IntegrityProof(BaseModel):
    """Checksum metadata for payload integrity."""

    algorithm: str = "sha256"
    checksum: str


class SessionEnvelope(BaseModel):
    """Typed envelope for secure session hydration files."""

    schema_version: str = "1.0"
    created_at: str
    payload: SessionPayload
    integrity: IntegrityProof


class HydrationMode(BaseModel):
    """Requested hydration behavior."""

    source: Optional[str] = None
    history_only: bool = False
    config_only: bool = False
    overwrite: bool = False
    merge: bool = True


class SessionHydrator:
    """Performs validated session re-hydration into runtime components."""

    def __init__(self, *, memory_manager: MemoryManager, workspace: Any) -> None:
        self._memory = memory_manager
        self._workspace = workspace
        self._workspace_root = get_project_space().ensure_initialized().resolve()
        self._audit_file = self._workspace_root / ".cerberus" / "audit" / "load_actions.jsonl"

    @property
    def workspace_root(self) -> Path:
        return self._workspace_root

    def default_source(self) -> Path:
        return self._workspace_root / ".cerberus" / "session" / "latest.session.json"

    def resolve_source(self, candidate: Optional[str]) -> Path:
        raw = Path(candidate) if candidate else self.default_source()
        if not raw.is_absolute():
            raw = self._workspace_root / raw
        resolved = raw.expanduser().resolve()

        try:
            resolved.relative_to(self._workspace_root)
        except ValueError as exc:
            raise IntegrityError(
                f"Security Integrity Alert: path escapes workspace root ({resolved})"
            ) from exc

        return resolved

    def load(self, mode: HydrationMode, user: str) -> Tuple[bool, str]:
        source = self.resolve_source(mode.source)

        try:
            if source.suffix.lower() == ".jsonl":
                return self._load_jsonl_history(source=source, mode=mode, user=user)
            envelope = self._read_envelope(source)
            self._validate_integrity(envelope)
            self._apply_envelope(envelope=envelope, mode=mode)
            self._audit_attempt(
                user=user,
                source=source,
                success=True,
                detail="hydration-complete",
            )
            return True, f"Session hydrated from {source}"
        except (IntegrityError, ValidationError) as exc:
            detail = f"Security Integrity Alert: {exc}"
            self._audit_attempt(user=user, source=source, success=False, detail=detail)
            return False, detail
        except Exception as exc:  # pylint: disable=broad-except
            detail = f"Load failed: {exc}"
            self._audit_attempt(user=user, source=source, success=False, detail=detail)
            return False, detail

    def _read_envelope(self, source: Path) -> SessionEnvelope:
        if not source.exists():
            raise IntegrityError(f"session source not found: {source}")

        with ExitStack() as stack:
            handle = stack.enter_context(source.open("r", encoding="utf-8"))
            text = handle.read()

        return SessionEnvelope.model_validate_json(text)

    @staticmethod
    def _canonical_payload_json(payload: SessionPayload) -> str:
        obj = payload.model_dump(mode="json")
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    def _validate_integrity(self, envelope: SessionEnvelope) -> None:
        algo = envelope.integrity.algorithm.lower().strip()
        if algo != "sha256":
            raise IntegrityError(f"unsupported integrity algorithm: {algo}")

        expected = envelope.integrity.checksum.lower().strip()
        actual = sha256(self._canonical_payload_json(envelope.payload).encode("utf-8")).hexdigest()
        if actual != expected:
            raise IntegrityError("checksum mismatch; source may be tampered or corrupted")

    def _active_session_has_state(self) -> bool:
        if AGENT_MANAGER.get_registered_agents():
            return True
        if any(AGENT_MANAGER._message_history.values()):  # pylint: disable=protected-access
            return True
        if len(USAGE_TRACKER.all_records()) > 0:
            return True
        return False

    def _apply_envelope(self, *, envelope: SessionEnvelope, mode: HydrationMode) -> None:
        has_active = self._active_session_has_state()
        if has_active and mode.overwrite:
            self._wipe_current_state()

        if mode.config_only:
            self._restore_config(cfg=envelope.payload.config, overwrite=mode.overwrite)
            return

        self._restore_memory_stack(
            memory=envelope.payload.memory,
            merge=(mode.merge and not mode.overwrite),
            restore_histories=True,
        )

        if not mode.history_only:
            self._restore_agent_context(
                agents=envelope.payload.agents,
                merge=(mode.merge and not mode.overwrite),
            )
            self._restore_cost_ledger(
                ledger=envelope.payload.cost,
                merge=(mode.merge and not mode.overwrite),
            )
            self._restore_config(
                cfg=envelope.payload.config,
                overwrite=mode.overwrite,
            )

    def _wipe_current_state(self) -> None:
        AGENT_MANAGER._agent_registry.clear()  # pylint: disable=protected-access
        AGENT_MANAGER._message_history.clear()  # pylint: disable=protected-access
        PARALLEL_CONFIGS.clear()
        USAGE_TRACKER.reset_session()

        try:
            from cerberus.util import COST_TRACKER

            COST_TRACKER.session_total_cost = 0.0
            COST_TRACKER.last_total_cost = 0.0
            COST_TRACKER.last_interaction_cost = 0.0
        except Exception:
            pass

    def _restore_memory_stack(
        self,
        *,
        memory: MemoryStackPayload,
        merge: bool,
        restore_histories: bool,
    ) -> None:
        if restore_histories:
            for agent, entries in memory.histories.items():
                existing = AGENT_MANAGER._message_history.get(agent, [])  # pylint: disable=protected-access
                if merge:
                    merged = self._merge_messages(existing, entries)
                else:
                    merged = list(entries)
                AGENT_MANAGER._message_history[agent] = merged  # pylint: disable=protected-access

        for idx, summary in enumerate(memory.summaries, start=1):
            self._memory.record(
                {
                    "topic": "session.summary",
                    "finding": summary,
                    "source": "session_hydrator",
                    "tags": ["summary", "rehydration"],
                    "artifacts": {"ordinal": idx},
                }
            )

    def _restore_agent_context(self, *, agents: AgentContextPayload, merge: bool) -> None:
        for name, aid in agents.registry.items():
            if merge and name in AGENT_MANAGER._agent_registry:  # pylint: disable=protected-access
                continue
            AGENT_MANAGER._agent_registry[name] = aid  # pylint: disable=protected-access

        for name, entries in agents.histories.items():
            existing = AGENT_MANAGER._message_history.get(name, [])  # pylint: disable=protected-access
            if merge:
                AGENT_MANAGER._message_history[name] = self._merge_messages(existing, entries)  # pylint: disable=protected-access
            else:
                AGENT_MANAGER._message_history[name] = list(entries)  # pylint: disable=protected-access

        if agents.active_agent:
            AGENT_MANAGER._active_agent_name = agents.active_agent  # pylint: disable=protected-access

        if agents.parallel_configs:
            if not merge:
                PARALLEL_CONFIGS.clear()
            for cfg in agents.parallel_configs:
                if merge and any(c.id == cfg.id for c in PARALLEL_CONFIGS):
                    continue
                pc = ParallelConfig(
                    cfg.agent_name,
                    cfg.model,
                    cfg.prompt,
                    cfg.unified_context,
                )
                setattr(pc, "id", cfg.id)
                PARALLEL_CONFIGS.append(pc)

            if len(PARALLEL_CONFIGS) >= 2:
                os.environ["CERBERUS_PARALLEL"] = str(len(PARALLEL_CONFIGS))
                os.environ["CERBERUS_PARALLEL_AGENTS"] = ",".join(c.agent_name for c in PARALLEL_CONFIGS)

    def _restore_cost_ledger(self, *, ledger: CostLedgerPayload, merge: bool) -> None:
        incoming_records: List[UsageRecord] = []
        for rec in ledger.records:
            payload = {
                "record_id": rec.record_id or "",
                "agent_name": rec.agent_name,
                "model": rec.model,
                "operation": rec.operation,
                "input_tokens": rec.input_tokens,
                "output_tokens": rec.output_tokens,
                "cost": Decimal(str(rec.cost or "0")),
                "timestamp": rec.timestamp,
                "session_id": rec.session_id or ledger.session_id or "",
            }
            incoming_records.append(UsageRecord.model_validate(payload))

        with USAGE_TRACKER._lock:  # pylint: disable=protected-access
            existing = list(USAGE_TRACKER._records) if merge else []  # pylint: disable=protected-access
            merged = self._merge_records(existing, incoming_records)
            USAGE_TRACKER._records = merged  # pylint: disable=protected-access
            if ledger.session_id:
                USAGE_TRACKER._session_id = ledger.session_id  # pylint: disable=protected-access
            USAGE_TRACKER._budget = BudgetPolicy(  # pylint: disable=protected-access
                limit=Decimal(str(ledger.budget.limit)),
                currency=ledger.budget.currency,
                conversion_rate=Decimal(str(ledger.budget.conversion_rate)),
                soft_lock=ledger.budget.soft_lock,
            )
            total = sum((r.cost for r in USAGE_TRACKER._records), Decimal("0"))  # pylint: disable=protected-access
            USAGE_TRACKER._budget_exceeded = bool(  # pylint: disable=protected-access
                USAGE_TRACKER._budget.active and total >= USAGE_TRACKER._budget.limit  # pylint: disable=protected-access
            )

        try:
            from cerberus.util import COST_TRACKER

            session_total = float(ledger.session_total_usd) if ledger.session_total_usd else float(USAGE_TRACKER.session_total())
            COST_TRACKER.session_total_cost = session_total
            COST_TRACKER.last_total_cost = session_total
        except Exception:
            pass

    @staticmethod
    def _restore_config(*, cfg: SessionConfigPayload, overwrite: bool) -> None:
        for key, value in cfg.env.items():
            if not overwrite and key in os.environ:
                continue
            os.environ[str(key)] = str(value)

    @staticmethod
    def _merge_messages(existing: List[Dict[str, Any]], incoming: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = {SessionHydrator._msg_fingerprint(m) for m in existing}
        merged = list(existing)
        for msg in incoming:
            fp = SessionHydrator._msg_fingerprint(msg)
            if fp in seen:
                continue
            merged.append(msg)
            seen.add(fp)
        return merged

    @staticmethod
    def _msg_fingerprint(msg: Dict[str, Any]) -> str:
        stable = {
            "role": msg.get("role"),
            "content": msg.get("content"),
            "tool_call_id": msg.get("tool_call_id"),
            "timestamp": msg.get("timestamp") or msg.get("created_at"),
        }
        return sha256(json.dumps(stable, sort_keys=True, ensure_ascii=True).encode("utf-8")).hexdigest()

    @staticmethod
    def _merge_records(existing: List[UsageRecord], incoming: List[UsageRecord]) -> List[UsageRecord]:
        merged = list(existing)
        seen = {r.record_id for r in existing}
        for rec in incoming:
            if rec.record_id in seen:
                continue
            merged.append(rec)
            seen.add(rec.record_id)
        return merged

    def _load_jsonl_history(self, *, source: Path, mode: HydrationMode, user: str) -> Tuple[bool, str]:
        if mode.config_only:
            return False, "Security Integrity Alert: --config-only cannot load from jsonl source"

        histories: Dict[str, List[Dict[str, Any]]] = {}
        with ExitStack() as stack:
            handle = stack.enter_context(source.open("r", encoding="utf-8"))
            for line_no, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    item = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise IntegrityError(f"jsonl parse error line {line_no}: {exc}") from exc
                if not isinstance(item, dict):
                    continue
                agent_name = str(item.get("agent_name") or item.get("agent") or "default")
                raw_msg = item.get("message") if isinstance(item.get("message"), dict) else item
                if isinstance(raw_msg, dict):
                    message: Dict[str, Any] = dict(raw_msg)
                elif raw_msg is None:
                    continue
                else:
                    message = {"role": "system", "content": str(raw_msg)}
                histories.setdefault(agent_name, []).append(message)

        payload = MemoryStackPayload(histories=histories, summaries=[])
        self._restore_memory_stack(
            memory=payload,
            merge=(mode.merge and not mode.overwrite),
            restore_histories=True,
        )

        self._audit_attempt(
            user=user,
            source=source,
            success=True,
            detail="jsonl-history-loaded",
        )
        return True, f"Loaded history-only payload from {source}"

    def _audit_attempt(self, *, user: str, source: Path, success: bool, detail: str) -> None:
        payload = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "user": user,
            "source": str(source),
            "success": success,
            "detail": detail,
        }
        self._audit_file.parent.mkdir(parents=True, exist_ok=True)
        with ExitStack() as stack:
            handle = stack.enter_context(self._audit_file.open("a", encoding="utf-8"))
            handle.write(json.dumps(payload, ensure_ascii=True) + "\n")

        self._memory.record(
            {
                "topic": "load.audit",
                "finding": detail,
                "source": "load_command",
                "tags": ["session-load", "audit"],
                "artifacts": {
                    "user": user,
                    "source": str(source),
                    "success": success,
                },
            }
        )


class LoadCommand(Command):
    """Load legacy JSONL history or modern secure session payloads."""

    name = "/load"
    description = "Merge a jsonl file into agent histories with duplicate control (uses logs/last if no file specified)"
    aliases = ["/l"]

    def __init__(self) -> None:
        super().__init__(name=self.name, description=self.description, aliases=self.aliases)
        self._memory = self._resolve_memory_manager()
        self._hydrator = SessionHydrator(memory_manager=self._memory, workspace=self.workspace)
        self.add_subcommand("all", "Show all known agent histories", self.handle_all)
        self.add_subcommand("agent", "Load into a specific agent", self.handle_agent)
        self.add_subcommand("parallel", "Load into configured parallel agents", self.handle_parallel)

    @property
    def help(self) -> str:
        return (
            "Usage: /load [agent name] [jsonl file]\n"
            "       /load all\n"
            "       /load agent <agent name> [jsonl file]\n"
            "       /load parallel [jsonl file]\n"
            "       /load [<source>] [--history-only] [--config-only] [--merge|--overwrite]\n"
            "Examples:\n"
            "  /load\n"
            "  /load red_teamer\n"
            "  /load Bug Bounty Hunter logs/session.jsonl\n"
            "  /load parallel logs/session.jsonl\n"
            "  /load .cerberus/session/latest.session.json --merge\n"
            "Security: flag-based usage enables the secure workspace-contained session hydrator."
        )

    def handle(self, args: Optional[List[str]] = None) -> bool:  # type: ignore[override]
        try:
            clean = self.sanitize_args(args)
        except Exception as exc:
            console.print(f"[red]Input validation failed: {exc}[/red]")
            return False

        record = self._audit_before(clean)
        try:
            if self._should_use_secure_loader(clean):
                result = self._run_execute(clean)
            elif not clean:
                result = self.handle_no_args()
            else:
                sub = clean[0].lower()
                if sub == "all":
                    result = self.handle_all(clean[1:] or None)
                elif sub == "agent":
                    result = self.handle_agent(clean[1:] or None)
                elif sub == "parallel":
                    result = self.handle_parallel(clean[1:] or None)
                else:
                    result = self._handle_legacy_positional(clean)
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
        return self._legacy_load(agent_name=None, source=DEFAULT_LEGACY_LOAD_SOURCE)

    def handle_all(self, args: Optional[List[str]] = None) -> bool:
        del args
        histories = get_all_agent_histories() or {}
        if not isinstance(histories, dict):
            histories = {}

        normalized: Dict[str, List[Dict[str, Any]]] = {}
        for agent_name, history in histories.items():
            normalized[str(agent_name)] = history if isinstance(history, list) else []

        for configured_agent in self._configured_agent_names():
            normalized.setdefault(configured_agent, [])

        self._render_history_overview("Available Agent Histories", normalized)
        return True

    def handle_agent(self, args: Optional[List[str]] = None) -> bool:
        agent_name, source = self._parse_legacy_agent_and_source(args or [])
        return self._legacy_load(agent_name=agent_name, source=source)

    def handle_parallel(self, args: Optional[List[str]] = None) -> bool:
        _, source = self._parse_legacy_agent_and_source(args or [])
        if not PARALLEL_CONFIGS:
            return self._legacy_load(agent_name=None, source=source)

        try:
            messages = load_history_from_jsonl(source)
        except Exception as exc:  # pylint: disable=broad-except
            console.print(f"[red]Load failed: {exc}[/red]")
            return False

        manager = _get_agent_manager()
        agent_map = self._parallel_target_map()
        if not agent_map:
            return self._legacy_load(agent_name=None, source=source)

        canonical_targets = list(dict.fromkeys(agent_map.values()))
        routed: Dict[str, List[Dict[str, Any]]] = {name: [] for name in canonical_targets}
        found_agent_name = False

        for message in messages:
            if not isinstance(message, dict):
                continue
            sender = self._extract_message_agent_name(message)
            if sender:
                target = agent_map.get(self._normalize_agent_key(sender))
                if target:
                    routed[target].append(message)
                    found_agent_name = True
                    continue

            if str(message.get("role", "")).lower() == "user":
                for target in canonical_targets:
                    routed[target].append(message)

        if messages and not found_agent_name:
            console.print("[red]No parallel agent names were found in the loaded history.[/red]")
            return False

        for target in canonical_targets:
            existing = self._get_existing_history(target, manager)
            merged = SessionHydrator._merge_messages(existing, routed[target])
            self._set_message_history(target, merged, manager)

        return True

    async def execute(self, args: List[str]) -> bool:
        mode = self._parse_args(args)
        if mode is None:
            return False

        ok, detail = self._hydrator.load(mode=mode, user=self.session.user)
        if not ok:
            console.print(f"[red]{detail}[/red]")
            return False

        table = Table(title="Session Re-hydration", box=box.SIMPLE_HEAVY)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Source", str(self._hydrator.resolve_source(mode.source)))
        table.add_row("Mode", self._mode_label(mode))
        table.add_row("Conflict Policy", "overwrite" if mode.overwrite else "merge")
        console.print(table)
        console.print(Panel(detail, border_style="green", title="Load Complete"))
        return True

    @staticmethod
    def _should_use_secure_loader(args: List[str]) -> bool:
        return any(token.startswith("--") or token in {"help", "-h", "--help"} for token in args)

    def _handle_legacy_positional(self, args: List[str]) -> bool:
        agent_name, source = self._parse_legacy_agent_and_source(args)
        return self._legacy_load(agent_name=agent_name, source=source)

    def _legacy_load(self, *, agent_name: Optional[str], source: Optional[str]) -> bool:
        source = source or DEFAULT_LEGACY_LOAD_SOURCE
        try:
            messages = load_history_from_jsonl(source)
        except Exception as exc:  # pylint: disable=broad-except
            console.print(f"[red]Load failed: {exc}[/red]")
            return False

        manager = _get_agent_manager()
        target_agent = self._resolve_target_agent_name(agent_name)
        existing = self._get_existing_history(target_agent, manager)
        merged = SessionHydrator._merge_messages(existing, messages)
        self._set_message_history(target_agent, merged, manager)
        return True

    def _resolve_target_agent_name(self, requested_name: Optional[str]) -> str:
        manager = _get_agent_manager()
        candidate = str(requested_name or "").strip()
        if not candidate:
            active_agent = getattr(manager, "get_active_agent", lambda: None)()
            if active_agent is not None and getattr(active_agent, "name", None):
                return str(active_agent.name)

            active_agents = getattr(manager, "get_active_agents", lambda: {})()
            if isinstance(active_agents, dict) and active_agents:
                first_key = next(iter(active_agents.keys()))
                if first_key:
                    return str(first_key)

            registered_agents = getattr(manager, "get_registered_agents", lambda: {})()
            if isinstance(registered_agents, dict) and registered_agents:
                first_key = next(iter(registered_agents.keys()))
                if first_key:
                    return str(first_key)

            return "Default Agent"

        if candidate.upper().startswith("P") and candidate[1:].isdigit():
            resolved = self._resolve_parallel_agent_id(candidate, manager)
            if resolved:
                return resolved

        return candidate

    def _resolve_parallel_agent_id(self, candidate: str, manager: Any) -> Optional[str]:
        get_agent_by_id = getattr(manager, "get_agent_by_id", None)
        if callable(get_agent_by_id):
            resolved = get_agent_by_id(candidate)
            if resolved:
                return str(resolved)

        try:
            from cerberus.agents import get_available_agents

            available_agents = get_available_agents()
        except Exception:
            available_agents = {}

        for config in PARALLEL_CONFIGS:
            if getattr(config, "id", None) != candidate:
                continue
            agent = available_agents.get(getattr(config, "agent_name", ""))
            if agent is not None and getattr(agent, "name", None):
                return str(agent.name)
            if getattr(config, "agent_name", None):
                return str(config.agent_name)

        return None

    def _configured_agent_names(self) -> List[str]:
        names: List[str] = []
        for config in PARALLEL_CONFIGS:
            display = self._display_name_for_parallel_config(config)
            if display:
                names.append(display)
        return list(dict.fromkeys(names))

    def _parallel_target_map(self) -> Dict[str, str]:
        mapping: Dict[str, str] = {}
        manager = _get_agent_manager()
        for config in PARALLEL_CONFIGS:
            display = self._display_name_for_parallel_config(config)
            if not display:
                continue
            canonical = str(display)
            mapping[self._normalize_agent_key(canonical)] = canonical
            mapping[self._normalize_agent_key(str(getattr(config, "agent_name", canonical)))] = canonical
            config_id = getattr(config, "id", None)
            if config_id:
                mapping[self._normalize_agent_key(str(config_id))] = canonical
                resolved = self._resolve_parallel_agent_id(str(config_id), manager)
                if resolved:
                    mapping[self._normalize_agent_key(resolved)] = canonical
        return mapping

    @staticmethod
    def _display_name_for_parallel_config(config: ParallelConfig) -> str:
        try:
            from cerberus.agents import get_available_agents

            available_agents = get_available_agents()
        except Exception:
            available_agents = {}

        agent = available_agents.get(getattr(config, "agent_name", ""))
        if agent is not None and getattr(agent, "name", None):
            return str(agent.name)
        return str(getattr(config, "agent_name", "") or getattr(config, "id", ""))

    @staticmethod
    def _normalize_agent_key(value: str) -> str:
        return " ".join(str(value).strip().lower().split())

    @staticmethod
    def _extract_message_agent_name(message: Dict[str, Any]) -> str:
        for field in ("sender", "agent_name", "agent", "name"):
            value = message.get(field)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""

    def _parse_legacy_agent_and_source(self, args: List[str]) -> Tuple[Optional[str], str]:
        if not args:
            return None, DEFAULT_LEGACY_LOAD_SOURCE
        if len(args) == 1:
            token = args[0]
            if self._looks_like_file_path(token):
                return None, token
            return token, DEFAULT_LEGACY_LOAD_SOURCE

        if self._looks_like_file_path(args[-1]):
            agent_name = " ".join(args[:-1]).strip() or None
            return agent_name, args[-1]

        return " ".join(args).strip() or None, DEFAULT_LEGACY_LOAD_SOURCE

    @staticmethod
    def _looks_like_file_path(token: str) -> bool:
        lowered = token.lower()
        return (
            lowered == DEFAULT_LEGACY_LOAD_SOURCE
            or lowered.endswith(".jsonl")
            or lowered.endswith(".json")
            or token.startswith(("./", "../", "/", "~"))
            or os.path.sep in token
        )

    def _get_existing_history(self, agent_name: str, manager: Any) -> List[Dict[str, Any]]:
        get_message_history = getattr(manager, "get_message_history", None)
        if callable(get_message_history):
            history = get_message_history(agent_name)
            if isinstance(history, list):
                return list(history)

        histories = getattr(manager, "_message_history", None)
        if isinstance(histories, dict):
            history = histories.get(agent_name)
            if isinstance(history, list):
                return list(history)

        history = get_agent_message_history(agent_name)
        if isinstance(history, list):
            return list(history)

        _, persistent_histories = _get_history_runtime_state()
        history = persistent_histories.get(agent_name)
        if isinstance(history, list):
            return list(history)

        return []

    def _set_message_history(self, agent_name: str, history: List[Dict[str, Any]], manager: Any) -> None:
        histories = getattr(manager, "_message_history", None)
        if not isinstance(histories, dict):
            histories = {}
            setattr(manager, "_message_history", histories)
        histories[agent_name] = list(history)

        active_instances, persistent_histories = _get_history_runtime_state()
        persistent_histories[agent_name] = list(history)

        for _, model_ref in list(active_instances.items()):
            model = model_ref() if callable(model_ref) else model_ref
            if model is None:
                continue
            display_name = getattr(model, "_display_name", None) or getattr(model, "agent_name", None) or getattr(model, "name", None)
            if display_name != agent_name:
                continue
            message_history = getattr(model, "message_history", None)
            if isinstance(message_history, list):
                message_history[:] = list(history)

    @staticmethod
    def _render_history_overview(title: str, histories: Dict[str, List[Dict[str, Any]]]) -> None:
        if not histories:
            console.print(Panel("No agent histories available.", title=title, border_style="yellow"))
            return

        table = Table(title=title, box=box.ROUNDED)
        table.add_column("Agent", style="cyan")
        table.add_column("Messages", style="white", justify="right")
        for agent_name, history in histories.items():
            count = len(history) if isinstance(history, list) else 0
            table.add_row(str(agent_name), str(count))
        console.print(table)

    def _parse_args(self, args: List[str]) -> Optional[HydrationMode]:
        mode = HydrationMode()

        i = 0
        positional_source: Optional[str] = None
        while i < len(args):
            token = args[i]
            if token in {"--help", "-h", "help"}:
                console.print(self.help)
                return None
            if token == "--history-only":
                mode.history_only = True
                i += 1
                continue
            if token == "--config-only":
                mode.config_only = True
                i += 1
                continue
            if token == "--overwrite":
                mode.overwrite = True
                mode.merge = False
                i += 1
                continue
            if token == "--merge":
                mode.merge = True
                mode.overwrite = False
                i += 1
                continue
            if token == "--source":
                if i + 1 >= len(args):
                    console.print("[red]--source requires a path[/red]")
                    return None
                mode.source = args[i + 1]
                i += 2
                continue
            if token.startswith("--"):
                console.print(f"[red]Unknown argument: {token}[/red]")
                console.print(self.help)
                return None

            if positional_source is None:
                positional_source = token
                i += 1
                continue

            console.print(f"[red]Unexpected argument: {token}[/red]")
            console.print(self.help)
            return None

        if mode.history_only and mode.config_only:
            console.print("[red]Cannot combine --history-only and --config-only[/red]")
            return None

        if positional_source and not mode.source:
            mode.source = positional_source

        return mode

    @staticmethod
    def _mode_label(mode: HydrationMode) -> str:
        if mode.config_only:
            return "config-only"
        if mode.history_only:
            return "history-only"
        return "full"

    def _resolve_memory_manager(self) -> MemoryManager:
        candidate = self.memory
        if isinstance(candidate, MemoryManager):
            return candidate
        return MemoryManager()


LOAD_COMMAND_INSTANCE = LoadCommand()
register_command(LOAD_COMMAND_INSTANCE)
