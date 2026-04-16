"""Workspace merge command for Cerebro REPL.

Implements commercial-safe cross-workspace reconciliation with:
- schema-validated import envelopes
- technical fingerprint deduplication for findings
- conflict policies: ours/theirs/union
- cost ledger aggregation across workstreams
- chain-of-custody merge audit logs
- async + atomic IO for safety
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Dict, Iterable, List, Literal, Mapping, Optional, Sequence, Tuple

from pydantic import BaseModel, Field, ValidationError
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cerberus.memory import MemoryManager
from cerberus.memory.storage import EvidenceRecord, WorkspaceJSONStore
from cerberus.repl.commands.base import FrameworkCommand, register_command
from cerberus.repl.commands.cost import BudgetPolicy, USAGE_TRACKER, UsageRecord
from cerberus.agents.simple_agent_manager import AGENT_MANAGER
from cerberus.tools.workspace import get_project_space


console = Console()

SCHEMA_VERSION = "1.0"


class MergeError(Exception):
    """Raised when merge inputs are invalid or merge execution fails."""


class ImportedLedgerRecord(BaseModel):
    record_id: Optional[str] = None
    agent_name: str = ""
    model: str = ""
    operation: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cost: str = "0"
    timestamp: Optional[str] = None
    session_id: Optional[str] = None


class ImportedBudgetSnapshot(BaseModel):
    limit: str = "0"
    currency: str = "USD"
    conversion_rate: str = "1"
    soft_lock: bool = True


class ImportedCostLedger(BaseModel):
    session_id: Optional[str] = None
    session_total_usd: Optional[str] = None
    budget: ImportedBudgetSnapshot = Field(default_factory=ImportedBudgetSnapshot)
    records: List[ImportedLedgerRecord] = Field(default_factory=list)


class ImportedMemoryPayload(BaseModel):
    summaries: List[str] = Field(default_factory=list)
    histories: Dict[str, List[Dict[str, Any]]] = Field(default_factory=dict)


class ImportedAgentPayload(BaseModel):
    active_agent: Optional[str] = None
    registry: Dict[str, str] = Field(default_factory=dict)
    histories: Dict[str, List[Dict[str, Any]]] = Field(default_factory=dict)


class ImportedSessionPayload(BaseModel):
    workspace: str = ""
    memory: ImportedMemoryPayload = Field(default_factory=ImportedMemoryPayload)
    agents: ImportedAgentPayload = Field(default_factory=ImportedAgentPayload)
    cost: ImportedCostLedger = Field(default_factory=ImportedCostLedger)


class ImportedIntegrity(BaseModel):
    algorithm: str = "sha256"
    checksum: str


class ImportedSessionEnvelope(BaseModel):
    schema_version: str
    created_at: str
    payload: ImportedSessionPayload
    integrity: ImportedIntegrity


@dataclass(frozen=True)
class MergeAuditEntry:
    """Chain-of-custody row for one reconciled item."""

    kind: str
    key: str
    source_workspace: str
    strategy: str
    action: str


@dataclass(frozen=True)
class MergeResult:
    """Summary of merge activity."""

    source_workspace: str
    strategy: str
    findings_before: int
    findings_after: int
    findings_added: int
    findings_updated: int
    histories_agents_touched: int
    imported_cost_records: int
    consolidated_cost_records: int
    consolidated_total_usd: Decimal
    audit_rows: int


class DataReconciler:
    """Reconcile findings, observations, and cost data from another workspace."""

    _IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _PORT_IP_RE = re.compile(r"(?i)\bport\s*(\d{1,5})\b[^\n]{0,50}\b((?:\d{1,3}\.){3}\d{1,3})\b")
    _IP_PORT_RE = re.compile(r"(?i)\b((?:\d{1,3}\.){3}\d{1,3})\b[^\n]{0,50}\bport\s*(\d{1,5})\b")

    def __init__(self, *, memory_manager: MemoryManager, workspace_root: Path) -> None:
        self._memory = memory_manager
        self._workspace_root = workspace_root.resolve()
        self._store = WorkspaceJSONStore()
        self._audit_path = self._workspace_root / ".cerberus" / "audit" / "merge_audit.jsonl"

    async def reconcile(
        self,
        *,
        source_workspace: str,
        strategy: Literal["ours", "theirs", "union"],
        user: str,
    ) -> MergeResult:
        source_root = self._resolve_source_workspace(source_workspace)

        envelope = await self._load_source_envelope(source_root)
        incoming_findings = await self._load_source_findings(source_root)
        existing_findings = await asyncio.to_thread(self._store.load_all)

        merged_findings, findings_added, findings_updated, finding_audit = self._merge_findings(
            existing=existing_findings,
            incoming=incoming_findings,
            strategy=strategy,
            source_workspace=str(source_root),
        )

        histories_touched, history_audit = self._merge_histories(
            incoming_memory_histories=envelope.payload.memory.histories,
            incoming_agent_histories=envelope.payload.agents.histories,
            strategy=strategy,
            source_workspace=str(source_root),
        )

        incoming_usage = self._load_incoming_usage_records(envelope.payload.cost)
        consolidated_usage, cost_audit = self._merge_cost_records(
            incoming=incoming_usage,
            strategy=strategy,
            source_workspace=str(source_root),
        )
        consolidated_total = sum((r.cost for r in consolidated_usage), Decimal("0"))

        audit_rows = [*finding_audit, *history_audit, *cost_audit]

        await self._write_findings_atomically(merged_findings)
        await self._write_cost_rollup_atomically(
            source_workspace=str(source_root),
            strategy=strategy,
            usage_records=consolidated_usage,
            total_cost=consolidated_total,
        )
        await self._append_audit_rows_atomically(user=user, rows=audit_rows)

        self._apply_cost_tracker(consolidated_usage, envelope.payload.cost.budget)
        self._record_merge_evidence(
            source_workspace=str(source_root),
            strategy=strategy,
            findings_added=findings_added,
            findings_updated=findings_updated,
            histories_touched=histories_touched,
            imported_cost_records=len(incoming_usage),
            total_cost=consolidated_total,
        )

        return MergeResult(
            source_workspace=str(source_root),
            strategy=strategy,
            findings_before=len(existing_findings),
            findings_after=len(merged_findings),
            findings_added=findings_added,
            findings_updated=findings_updated,
            histories_agents_touched=histories_touched,
            imported_cost_records=len(incoming_usage),
            consolidated_cost_records=len(consolidated_usage),
            consolidated_total_usd=consolidated_total,
            audit_rows=len(audit_rows),
        )

    def _resolve_source_workspace(self, source_workspace: str) -> Path:
        candidate = Path(source_workspace).expanduser()
        if not candidate.is_absolute():
            candidate = (Path.cwd() / candidate).resolve()
        else:
            candidate = candidate.resolve()

        if not candidate.exists() or not candidate.is_dir():
            raise MergeError(f"Source workspace does not exist: {candidate}")
        if candidate == self._workspace_root:
            raise MergeError("Source workspace must differ from active workspace")
        return candidate

    async def _load_source_envelope(self, source_root: Path) -> ImportedSessionEnvelope:
        source_file = source_root / ".cerberus" / "session" / "latest.session.json"
        if not source_file.exists():
            raise MergeError(
                f"Missing source session envelope: {source_file}. "
                "Expected schema-validated workspace export."
            )

        text = await asyncio.to_thread(source_file.read_text, "utf-8")
        try:
            envelope = ImportedSessionEnvelope.model_validate_json(text)
        except ValidationError as exc:
            raise MergeError(f"Source envelope failed schema validation: {exc}") from exc

        if envelope.schema_version != SCHEMA_VERSION:
            raise MergeError(
                f"Schema mismatch: source={envelope.schema_version} current={SCHEMA_VERSION}"
            )

        payload_json = json.dumps(
            envelope.payload.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        checksum = sha256(payload_json.encode("utf-8")).hexdigest()
        if envelope.integrity.algorithm.lower().strip() != "sha256":
            raise MergeError("Unsupported source integrity algorithm")
        if checksum != envelope.integrity.checksum.lower().strip():
            raise MergeError("Source envelope checksum validation failed")

        return envelope

    async def _load_source_findings(self, source_root: Path) -> List[EvidenceRecord]:
        source_file = source_root / ".cerberus" / "memory" / "evidence.jsonl"
        if not source_file.exists():
            return []

        def _read_records() -> List[EvidenceRecord]:
            records: List[EvidenceRecord] = []
            with source_file.open("r", encoding="utf-8") as handle:
                for line in handle:
                    raw = line.strip()
                    if not raw:
                        continue
                    try:
                        obj = json.loads(raw)
                        records.append(EvidenceRecord.model_validate(obj))
                    except Exception:
                        continue
            return records

        return await asyncio.to_thread(_read_records)

    def _merge_findings(
        self,
        *,
        existing: List[EvidenceRecord],
        incoming: List[EvidenceRecord],
        strategy: Literal["ours", "theirs", "union"],
        source_workspace: str,
    ) -> Tuple[List[EvidenceRecord], int, int, List[MergeAuditEntry]]:
        merged: Dict[str, EvidenceRecord] = {}
        order: List[str] = []
        for rec in existing:
            fp = self._finding_fingerprint(rec)
            merged[fp] = rec
            order.append(fp)

        added = 0
        updated = 0
        audit: List[MergeAuditEntry] = []

        for incoming_rec in incoming:
            fp = self._finding_fingerprint(incoming_rec)
            if fp not in merged:
                merged[fp] = incoming_rec
                order.append(fp)
                added += 1
                audit.append(MergeAuditEntry("finding", fp, source_workspace, strategy, "added"))
                continue

            if strategy == "ours":
                audit.append(MergeAuditEntry("finding", fp, source_workspace, strategy, "kept-ours"))
                continue

            if strategy == "theirs":
                merged[fp] = incoming_rec
                updated += 1
                audit.append(MergeAuditEntry("finding", fp, source_workspace, strategy, "overwrote-with-theirs"))
                continue

            # union
            merged[fp] = self._union_evidence(merged[fp], incoming_rec)
            updated += 1
            audit.append(MergeAuditEntry("finding", fp, source_workspace, strategy, "unioned"))

        result = [merged[fp] for fp in order if fp in merged]
        return result, added, updated, audit

    def _merge_histories(
        self,
        *,
        incoming_memory_histories: Mapping[str, List[Dict[str, Any]]],
        incoming_agent_histories: Mapping[str, List[Dict[str, Any]]],
        strategy: Literal["ours", "theirs", "union"],
        source_workspace: str,
    ) -> Tuple[int, List[MergeAuditEntry]]:
        touched = 0
        audit: List[MergeAuditEntry] = []

        incoming_all: Dict[str, List[Dict[str, Any]]] = {}
        for name, msgs in incoming_memory_histories.items():
            incoming_all.setdefault(name, []).extend(msgs)
        for name, msgs in incoming_agent_histories.items():
            incoming_all.setdefault(name, []).extend(msgs)

        for agent_name, incoming_msgs in incoming_all.items():
            existing_msgs = AGENT_MANAGER._message_history.get(agent_name, [])  # pylint: disable=protected-access
            if not existing_msgs:
                AGENT_MANAGER._message_history[agent_name] = list(incoming_msgs)  # pylint: disable=protected-access
                touched += 1
                audit.append(MergeAuditEntry("history", agent_name, source_workspace, strategy, "added-agent-history"))
                continue

            if strategy == "ours":
                audit.append(MergeAuditEntry("history", agent_name, source_workspace, strategy, "kept-ours"))
                continue

            if strategy == "theirs":
                AGENT_MANAGER._message_history[agent_name] = list(incoming_msgs)  # pylint: disable=protected-access
                touched += 1
                audit.append(MergeAuditEntry("history", agent_name, source_workspace, strategy, "overwrote-with-theirs"))
                continue

            # union
            AGENT_MANAGER._message_history[agent_name] = self._merge_messages_union(existing_msgs, incoming_msgs)  # pylint: disable=protected-access
            touched += 1
            audit.append(MergeAuditEntry("history", agent_name, source_workspace, strategy, "unioned"))

        return touched, audit

    def _load_incoming_usage_records(self, cost_payload: ImportedCostLedger) -> List[UsageRecord]:
        incoming: List[UsageRecord] = []
        for item in cost_payload.records:
            incoming.append(
                UsageRecord.model_validate(
                    {
                        "record_id": item.record_id or "",
                        "agent_name": item.agent_name,
                        "model": item.model,
                        "operation": item.operation,
                        "input_tokens": item.input_tokens,
                        "output_tokens": item.output_tokens,
                        "cost": Decimal(str(item.cost or "0")),
                        "timestamp": item.timestamp,
                        "session_id": item.session_id or cost_payload.session_id or "",
                    }
                )
            )
        return incoming

    def _merge_cost_records(
        self,
        *,
        incoming: List[UsageRecord],
        strategy: Literal["ours", "theirs", "union"],
        source_workspace: str,
    ) -> Tuple[List[UsageRecord], List[MergeAuditEntry]]:
        existing = USAGE_TRACKER.all_records()
        by_id: Dict[str, UsageRecord] = {}
        order: List[str] = []
        audit: List[MergeAuditEntry] = []

        def key_for(rec: UsageRecord) -> str:
            if rec.record_id:
                return rec.record_id
            material = {
                "agent": rec.agent_name,
                "model": rec.model,
                "op": rec.operation,
                "in": rec.input_tokens,
                "out": rec.output_tokens,
                "cost": str(rec.cost),
                "ts": rec.timestamp.isoformat() if rec.timestamp else "",
            }
            return sha256(json.dumps(material, sort_keys=True, ensure_ascii=True).encode("utf-8")).hexdigest()

        for rec in existing:
            key = key_for(rec)
            by_id[key] = rec
            order.append(key)

        for rec in incoming:
            key = key_for(rec)
            if key not in by_id:
                by_id[key] = rec
                order.append(key)
                audit.append(MergeAuditEntry("cost", key, source_workspace, strategy, "added"))
                continue

            if strategy == "ours":
                audit.append(MergeAuditEntry("cost", key, source_workspace, strategy, "kept-ours"))
                continue

            if strategy == "theirs":
                by_id[key] = rec
                audit.append(MergeAuditEntry("cost", key, source_workspace, strategy, "overwrote-with-theirs"))
                continue

            # union - cost records are logically additive, keep existing dedup key.
            audit.append(MergeAuditEntry("cost", key, source_workspace, strategy, "deduped-union"))

        merged = [by_id[k] for k in order if k in by_id]
        return merged, audit

    def _apply_cost_tracker(self, merged_records: List[UsageRecord], budget: ImportedBudgetSnapshot) -> None:
        with USAGE_TRACKER._lock:  # pylint: disable=protected-access
            USAGE_TRACKER._records = list(merged_records)  # pylint: disable=protected-access
            USAGE_TRACKER._budget = BudgetPolicy(  # pylint: disable=protected-access
                limit=Decimal(str(budget.limit or "0")),
                currency=str(budget.currency or "USD"),
                conversion_rate=Decimal(str(budget.conversion_rate or "1")),
                soft_lock=bool(budget.soft_lock),
            )
            total = sum((r.cost for r in USAGE_TRACKER._records), Decimal("0"))  # pylint: disable=protected-access
            USAGE_TRACKER._budget_exceeded = bool(  # pylint: disable=protected-access
                USAGE_TRACKER._budget.active and total >= USAGE_TRACKER._budget.limit  # pylint: disable=protected-access
            )

        try:
            from cerberus.util import COST_TRACKER

            session_total = float(sum((r.cost for r in merged_records), Decimal("0")))
            COST_TRACKER.session_total_cost = session_total
            COST_TRACKER.last_total_cost = session_total
        except Exception:
            pass

    async def _write_findings_atomically(self, findings: List[EvidenceRecord]) -> None:
        target = self._store.file_path
        target.parent.mkdir(parents=True, exist_ok=True)

        lines = [json.dumps(rec.model_dump(mode="json"), ensure_ascii=True) + "\n" for rec in findings]
        await self._atomic_write_lines(target, lines)

    async def _write_cost_rollup_atomically(
        self,
        *,
        source_workspace: str,
        strategy: str,
        usage_records: List[UsageRecord],
        total_cost: Decimal,
    ) -> None:
        target = self._workspace_root / ".cerberus" / "session" / "merged_cost_ledger.json"
        payload = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": datetime.now(tz=UTC).isoformat(),
            "source_workspace": source_workspace,
            "strategy": strategy,
            "record_count": len(usage_records),
            "session_total_usd": str(total_cost),
            "records": [rec.to_dict() for rec in usage_records],
        }
        text = json.dumps(payload, ensure_ascii=True, indent=2)
        await self._atomic_write_text(target, text)

    async def _append_audit_rows_atomically(self, *, user: str, rows: List[MergeAuditEntry]) -> None:
        existing_text = ""
        if self._audit_path.exists():
            existing_text = await asyncio.to_thread(self._audit_path.read_text, "utf-8")
            existing_lines = existing_text.splitlines(keepends=True)
        else:
            existing_lines = []

        new_lines = list(existing_lines)
        ts = datetime.now(tz=UTC).isoformat()
        for row in rows:
            payload = {
                "timestamp": ts,
                "user": user,
                "kind": row.kind,
                "key": row.key,
                "source_workspace": row.source_workspace,
                "strategy": row.strategy,
                "action": row.action,
            }
            new_lines.append(json.dumps(payload, ensure_ascii=True) + "\n")

        await self._atomic_write_lines(self._audit_path, new_lines)

    async def _atomic_write_text(self, target: Path, text: str) -> None:
        await self._atomic_write_lines(target, [text])

    async def _atomic_write_lines(self, target: Path, lines: Sequence[str]) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)

        def _write() -> None:
            fd, tmp_name = tempfile.mkstemp(prefix=".merge_tmp_", dir=str(target.parent))
            tmp_path = Path(tmp_name)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    for line in lines:
                        handle.write(line)
                    handle.flush()
                tmp_path.replace(target)
            finally:
                if tmp_path.exists():
                    tmp_path.unlink(missing_ok=True)

        await asyncio.to_thread(_write)

    def _record_merge_evidence(
        self,
        *,
        source_workspace: str,
        strategy: str,
        findings_added: int,
        findings_updated: int,
        histories_touched: int,
        imported_cost_records: int,
        total_cost: Decimal,
    ) -> None:
        self._memory.record(
            {
                "topic": "merge.audit",
                "finding": f"Workspace merge completed from {source_workspace}",
                "source": "merge_command",
                "tags": ["merge", "audit", "chain-of-custody"],
                "artifacts": {
                    "source_workspace": source_workspace,
                    "strategy": strategy,
                    "findings_added": findings_added,
                    "findings_updated": findings_updated,
                    "histories_touched": histories_touched,
                    "imported_cost_records": imported_cost_records,
                    "consolidated_total_usd": str(total_cost),
                },
            }
        )

    @staticmethod
    def _merge_messages_union(
        existing: List[Dict[str, Any]],
        incoming: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        seen = {DataReconciler._message_fingerprint(msg) for msg in existing}
        merged = list(existing)
        for msg in incoming:
            fp = DataReconciler._message_fingerprint(msg)
            if fp in seen:
                continue
            merged.append(msg)
            seen.add(fp)
        return merged

    @staticmethod
    def _message_fingerprint(msg: Mapping[str, Any]) -> str:
        stable = {
            "role": msg.get("role"),
            "content": msg.get("content"),
            "tool_call_id": msg.get("tool_call_id"),
            "timestamp": msg.get("timestamp") or msg.get("created_at"),
        }
        return sha256(json.dumps(stable, sort_keys=True, ensure_ascii=True).encode("utf-8")).hexdigest()

    def _finding_fingerprint(self, record: EvidenceRecord) -> str:
        open_fp = self._open_port_fingerprint(record)
        if open_fp is not None:
            return open_fp

        stable = {
            "topic": record.topic.strip().lower(),
            "finding": record.finding.strip().lower(),
            "source": record.source.strip().lower(),
        }
        digest = sha256(json.dumps(stable, sort_keys=True, ensure_ascii=True).encode("utf-8")).hexdigest()
        return f"finding:{digest}"

    def _open_port_fingerprint(self, record: EvidenceRecord) -> Optional[str]:
        ip, port = self._extract_ip_port(record)
        if ip is None or port is None:
            return None
        if not self._is_valid_ipv4(ip):
            return None
        if not (1 <= port <= 65535):
            return None
        return f"open-port:{ip}:{port}"

    def _extract_ip_port(self, record: EvidenceRecord) -> Tuple[Optional[str], Optional[int]]:
        artifacts = record.artifacts if isinstance(record.artifacts, dict) else {}

        ip_candidates: List[str] = []
        port_candidates: List[int] = []

        for key in ("ip", "host", "target", "address", "dst_ip", "src_ip"):
            value = artifacts.get(key)
            if isinstance(value, str):
                ip_candidates.extend(self._IP_RE.findall(value))

        for key in ("port", "open_port", "service_port", "dst_port", "src_port"):
            value = artifacts.get(key)
            if isinstance(value, int):
                port_candidates.append(value)
            elif isinstance(value, str) and value.isdigit():
                port_candidates.append(int(value))

        text = f"{record.topic} {record.finding}"

        for m in self._IP_PORT_RE.finditer(text):
            ip_candidates.append(m.group(1))
            port_candidates.append(int(m.group(2)))

        for m in self._PORT_IP_RE.finditer(text):
            port_candidates.append(int(m.group(1)))
            ip_candidates.append(m.group(2))

        ip = next((candidate for candidate in ip_candidates if self._is_valid_ipv4(candidate)), None)
        port = next((candidate for candidate in port_candidates if 1 <= candidate <= 65535), None)
        return ip, port

    @staticmethod
    def _is_valid_ipv4(candidate: str) -> bool:
        parts = candidate.split(".")
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit():
                return False
            value = int(part)
            if value < 0 or value > 255:
                return False
        return True

    @staticmethod
    def _union_evidence(existing: EvidenceRecord, incoming: EvidenceRecord) -> EvidenceRecord:
        tags = sorted(set(existing.tags) | set(incoming.tags))
        artifacts = dict(existing.artifacts)
        for key, value in incoming.artifacts.items():
            if key not in artifacts:
                artifacts[key] = value

        finding_text = existing.finding
        if incoming.finding.strip() and incoming.finding.strip().lower() != existing.finding.strip().lower():
            finding_text = f"{existing.finding} | {incoming.finding}"

        payload = existing.model_dump(mode="python")
        payload["tags"] = tags
        payload["artifacts"] = artifacts
        payload["finding"] = finding_text
        return EvidenceRecord.model_validate(payload)


class MergeCommand(FrameworkCommand):
    """Import and reconcile data from another workspace into the current session."""

    name = "/merge"
    description = "Merge findings, observations, and costs from another workspace"
    aliases = ["/mrg"]

    def __init__(self) -> None:
        super().__init__()
        self._memory = self._resolve_memory_manager()
        self._workspace_root = get_project_space().ensure_initialized().resolve()
        self._reconciler = DataReconciler(
            memory_manager=self._memory,
            workspace_root=self._workspace_root,
        )

    @property
    def help(self) -> str:
        return (
            "Usage: /merge <source_workspace_path> [--strategy ours|theirs|union]\n"
            "Example:\n"
            "  /merge ../workspaces/run-20260412-102030-abc123 --strategy union\n"
            "\n"
            "Conflict strategy:\n"
            "  ours   -> keep current workspace data on conflicts\n"
            "  theirs -> prefer imported data on conflicts\n"
            "  union  -> combine both with dedupe (default)\n"
        )

    async def execute(self, args: List[str]) -> bool:
        parse = self._parse_args(args)
        if parse is None:
            return False

        source_workspace, strategy = parse
        try:
            result = await self._reconciler.reconcile(
                source_workspace=source_workspace,
                strategy=strategy,
                user=self.session.user,
            )
        except MergeError as exc:
            console.print(f"[red]Merge failed: {exc}[/red]")
            return False
        except Exception as exc:  # pylint: disable=broad-except
            console.print(f"[red]Merge failed unexpectedly: {exc}[/red]")
            return False

        summary = Table(title="Workspace Merge Summary", box=box.SIMPLE_HEAVY)
        summary.add_column("Field", style="cyan")
        summary.add_column("Value", style="white")
        summary.add_row("Source Workspace", result.source_workspace)
        summary.add_row("Strategy", result.strategy)
        summary.add_row("Findings Before", str(result.findings_before))
        summary.add_row("Findings After", str(result.findings_after))
        summary.add_row("Findings Added", str(result.findings_added))
        summary.add_row("Findings Updated", str(result.findings_updated))
        summary.add_row("Histories Touched", str(result.histories_agents_touched))
        summary.add_row("Imported Cost Records", str(result.imported_cost_records))
        summary.add_row("Consolidated Cost Records", str(result.consolidated_cost_records))
        summary.add_row("Consolidated Total USD", str(result.consolidated_total_usd))
        summary.add_row("Audit Rows", str(result.audit_rows))

        console.print(summary)
        console.print(
            Panel(
                f"Merge complete. Audit log written to {self._workspace_root / '.cerberus' / 'audit' / 'merge_audit.jsonl'}",
                title="Engagement Roll-up",
                border_style="green",
            )
        )
        return True

    def _parse_args(self, args: List[str]) -> Optional[Tuple[str, Literal["ours", "theirs", "union"]]]:
        if not args:
            console.print("[red]Missing source workspace path[/red]")
            console.print(self.help)
            return None

        source_workspace: Optional[str] = None
        strategy: Literal["ours", "theirs", "union"] = "union"

        i = 0
        while i < len(args):
            token = args[i]

            if token in {"--help", "-h", "help"}:
                console.print(self.help)
                return None

            if token == "--strategy":
                if i + 1 >= len(args):
                    console.print("[red]--strategy requires a value[/red]")
                    return None
                value = args[i + 1].strip().lower()
                if value not in {"ours", "theirs", "union"}:
                    console.print(f"[red]Invalid strategy: {value}[/red]")
                    return None
                strategy = value  # type: ignore[assignment]
                i += 2
                continue

            if token.startswith("--"):
                console.print(f"[red]Unknown option: {token}[/red]")
                return None

            if source_workspace is None:
                source_workspace = token
                i += 1
                continue

            console.print(f"[red]Unexpected argument: {token}[/red]")
            return None

        if source_workspace is None:
            console.print("[red]Missing source workspace path[/red]")
            return None

        return source_workspace, strategy

    def _resolve_memory_manager(self) -> MemoryManager:
        if isinstance(self.memory, MemoryManager):
            return self.memory
        return MemoryManager()


MERGE_COMMAND_INSTANCE = MergeCommand()
register_command(MERGE_COMMAND_INSTANCE)
