"""Real-time observability monitor for Cerebro RAG.

This module exposes a Framework-oriented monitor class and a function tool
entrypoint compatible with existing tool registration (`get_rag_status`).
"""

from __future__ import annotations

import asyncio
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from rich.console import Console
from rich.table import Table

from cerberus.memory.logic import clean_data
from cerberus.repl.ui.logging import get_cerberus_logger
from cerberus.agents import function_tool
from cerberus.tools.workspace import get_project_space

KB_SECURITY = "KB_SECURITY"
KB_WORKSPACE = "KB_WORKSPACE"
KB_CVE = "KB_CVE"

_QUERY_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-:\.]{3,}")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_METHOD_HINTS = {
    "sqlmap": "sqlmap",
    "metasploit": "metasploit",
    "python": "python-script",
    "powershell": "powershell",
    "curl": "curl",
    "nmap": "nmap",
    "manual": "manual-steps",
    "exploit-db": "exploitdb",
    "poc": "poc",
}


@dataclass
class CollectionHealth:
    kb: str
    document_count: int
    avg_embedding_norm: float
    p90_embedding_norm: float


class CerebroRAGMonitor:
    """Async, privacy-preserving RAG observability and audit monitor."""

    def __init__(self) -> None:
        workspace = get_project_space().ensure_initialized().resolve()
        self._workspace = workspace
        self._rag_root = (workspace / ".cerberus" / "rag_engine").resolve()
        self._audit_file = self._rag_root / "rag_audit.jsonl"
        self._index_state_file = self._rag_root / "workspace_index_state.json"
        self._kb_paths = {
            KB_SECURITY: self._rag_root / "kb_security.jsonl",
            KB_WORKSPACE: self._rag_root / "kb_workspace.jsonl",
            KB_CVE: self._rag_root / "kb_cve.jsonl",
        }
        self._logger = get_cerberus_logger()

    async def get_status(self, include_content: bool = False) -> Dict[str, Any]:
        health = await self.get_index_health_metrics()
        perf = await self.get_retrieval_performance_audit()
        drift = await self.detect_semantic_drift(include_content=include_content)
        topics = await self.get_top_queried_topics(limit=5)
        staleness = await self.get_staleness_report()
        trail = await self.get_knowledge_audit_trail(limit=25)
        visual = self._render_topics_table(topics)

        payload = {
            "ok": True,
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "index_health": health,
            "retrieval_audit": perf,
            "semantic_drift": drift,
            "top_topics": topics,
            "staleness": staleness,
            "knowledge_audit_trail": trail,
            "visual_report": visual,
            "privacy_mode": not include_content,
        }
        self._audit("rag.monitor.status", payload)
        return clean_data(payload)

    async def get_index_health_metrics(self) -> Dict[str, Any]:
        records_by_kb = await asyncio.gather(
            self._read_kb_records(KB_SECURITY),
            self._read_kb_records(KB_WORKSPACE),
            self._read_kb_records(KB_CVE),
        )
        health_rows: List[CollectionHealth] = []

        for kb_name, records in zip((KB_SECURITY, KB_WORKSPACE, KB_CVE), records_by_kb):
            norms = [self._vector_norm(row.get("embedding") or []) for row in records]
            avg_norm = (sum(norms) / len(norms)) if norms else 0.0
            p90_norm = self._percentile(norms, 0.90)
            health_rows.append(
                CollectionHealth(
                    kb=kb_name,
                    document_count=len(records),
                    avg_embedding_norm=round(avg_norm, 4),
                    p90_embedding_norm=round(p90_norm, 4),
                )
            )

        return {
            "collections": [
                {
                    "kb": row.kb,
                    "document_count": row.document_count,
                    "embedding_distribution": {
                        "avg_norm": row.avg_embedding_norm,
                        "p90_norm": row.p90_embedding_norm,
                    },
                }
                for row in health_rows
            ],
            "total_documents": sum(row.document_count for row in health_rows),
        }

    async def get_staleness_report(self) -> Dict[str, Any]:
        state = await self._read_index_state()
        stale: List[Dict[str, Any]] = []
        roots = [
            self._workspace / "work",
            self._workspace / "logs",
            self._workspace / "artifacts",
            self._workspace / "findings",
            self._workspace / "evidence",
        ]

        for root in roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                if path.suffix.lower() not in {".txt", ".md", ".log", ".json", ".yaml", ".yml", ".py", ".csv", ".sh", ".js", ".ts"}:
                    continue
                try:
                    mtime = int(path.stat().st_mtime)
                except OSError:
                    continue
                key = str(path.resolve())
                indexed_mtime = int(state.get(key, 0))
                if mtime > indexed_mtime:
                    stale.append(
                        {
                            "file": str(path.resolve().relative_to(self._workspace)),
                            "last_modified_epoch": mtime,
                            "indexed_epoch": indexed_mtime,
                            "lag_seconds": mtime - indexed_mtime,
                        }
                    )

        stale.sort(key=lambda item: item["lag_seconds"], reverse=True)
        return {
            "stale_count": len(stale),
            "stale_files": stale[:50],
            "healthy": len(stale) == 0,
        }

    async def get_retrieval_performance_audit(
        self,
        *,
        low_conf_threshold: float = 0.45,
        max_latency_ms: int = 600,
    ) -> Dict[str, Any]:
        events = await self._read_audit_events(limit=500)
        queries = [event for event in events if str(event.get("event")) == "rag.query"]
        adds = [event for event in events if str(event.get("event")) == "rag.add"]

        if not queries:
            return {
                "query_count": 0,
                "avg_latency_ms": 0,
                "avg_relevance": 0,
                "knowledge_gap": False,
                "message": "No query events available yet.",
            }

        latency_ms: List[int] = []
        relevance: List[float] = []
        low_conf_hits = 0

        # Approximate latency by neighboring timestamps in audit sequence.
        last_ts = None
        for q in queries:
            ts = self._parse_timestamp(q.get("timestamp"))
            if ts and last_ts:
                delta = int((ts - last_ts).total_seconds() * 1000)
                if 0 <= delta <= 20_000:
                    latency_ms.append(delta)
            if ts:
                last_ts = ts

            results = ((q.get("data") or {}).get("results") or [])
            top_score = 0.0
            if results:
                try:
                    top_score = float(results[0].get("score") or 0.0)
                except Exception:
                    top_score = 0.0
            relevance.append(top_score)
            if top_score < low_conf_threshold:
                low_conf_hits += 1

        avg_latency = int(sum(latency_ms) / len(latency_ms)) if latency_ms else 0
        avg_rel = (sum(relevance) / len(relevance)) if relevance else 0.0

        knowledge_gap = (avg_rel < low_conf_threshold) or (avg_latency > max_latency_ms) or (low_conf_hits >= max(3, len(queries) // 3))
        return {
            "query_count": len(queries),
            "index_add_events": len(adds),
            "avg_latency_ms": avg_latency,
            "avg_relevance": round(avg_rel, 4),
            "low_confidence_ratio": round(low_conf_hits / max(1, len(queries)), 4),
            "knowledge_gap": knowledge_gap,
            "knowledge_gap_reason": self._knowledge_gap_reason(
                avg_rel=avg_rel,
                avg_latency=avg_latency,
                low_conf_ratio=(low_conf_hits / max(1, len(queries))),
                low_conf_threshold=low_conf_threshold,
                max_latency_ms=max_latency_ms,
            ),
        }

    async def detect_semantic_drift(self, include_content: bool = False) -> Dict[str, Any]:
        events = await self._read_audit_events(limit=800)
        queries = [event for event in events if str(event.get("event")) == "rag.query"]

        methods_by_cve: Dict[str, set[str]] = defaultdict(set)
        examples: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for event in queries:
            data = event.get("data") or {}
            results = data.get("results") or []
            for item in results:
                text = str(item.get("text", ""))
                cves = {m.upper() for m in _CVE_RE.findall(text)}
                if not cves:
                    continue
                method = self._extract_method_signature(text)
                for cve in cves:
                    methods_by_cve[cve].add(method)
                    examples[cve].append(
                        {
                            "method": method,
                            "citation": item.get("citation"),
                            "kb": item.get("kb"),
                            "score": item.get("score"),
                            "snippet": text if include_content else None,
                        }
                    )

        conflicts = []
        for cve, methods in methods_by_cve.items():
            if len(methods) <= 1:
                continue
            conflicts.append(
                {
                    "cve": cve,
                    "method_count": len(methods),
                    "methods": sorted(methods),
                    "examples": examples[cve][:4],
                    "summary": f"{cve} retrieved with conflicting exploit approaches: {', '.join(sorted(methods))}",
                }
            )

        return {
            "conflict_count": len(conflicts),
            "conflicts": conflicts[:20],
            "drift_detected": len(conflicts) > 0,
        }

    async def get_top_queried_topics(self, limit: int = 5) -> List[Dict[str, Any]]:
        events = await self._read_audit_events(limit=600)
        queries = [event for event in events if str(event.get("event")) == "rag.query"]
        token_counter: Counter[str] = Counter()

        for event in queries:
            query = str((event.get("data") or {}).get("query") or "")
            for token in _QUERY_TOKEN_RE.findall(query.lower()):
                if len(token) < 3:
                    continue
                if token in {"and", "the", "for", "with", "from", "that", "this"}:
                    continue
                token_counter[token] += 1

        return [{"topic": topic, "count": count} for topic, count in token_counter.most_common(max(1, int(limit)))]

    async def get_knowledge_audit_trail(self, limit: int = 25) -> Dict[str, Any]:
        events = await self._read_audit_events(limit=800)
        queries = [event for event in events if str(event.get("event")) == "rag.query"]

        trail: List[Dict[str, Any]] = []
        for event in queries[-max(1, int(limit)) :]:
            data = event.get("data") or {}
            query = str(data.get("query") or "")
            results = data.get("results") or []
            agent_id = self._extract_agent_id(event)
            trail.append(
                {
                    "timestamp": event.get("timestamp"),
                    "agent_id": agent_id,
                    "query": query,
                    "kb": data.get("kb"),
                    "result_count": len(results),
                    "top_citation": (results[0].get("citation") if results else None),
                }
            )

        return {
            "entries": trail,
            "entry_count": len(trail),
        }

    async def cleanup_workspace_collection(
        self,
        *,
        max_age_days: int = 30,
        drop_source_types: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        records = await self._read_kb_records(KB_WORKSPACE)
        cutoff = datetime.now(tz=UTC) - timedelta(days=max(1, int(max_age_days)))
        drop_types = {x.strip().lower() for x in (drop_source_types or []) if str(x).strip()}

        keep: List[Dict[str, Any]] = []
        removed = 0
        for row in records:
            ts = self._parse_timestamp(row.get("timestamp"))
            source_type = str(row.get("source_type") or "").lower()
            too_old = bool(ts and ts < cutoff)
            bad_type = bool(drop_types and source_type in drop_types)
            if too_old or bad_type:
                removed += 1
                continue
            keep.append(row)

        path = self._kb_paths[KB_WORKSPACE]
        await asyncio.to_thread(self._write_jsonl, path, keep)

        payload = {
            "ok": True,
            "removed": removed,
            "remaining": len(keep),
            "collection": KB_WORKSPACE,
        }
        self._audit("rag.monitor.cleanup", payload)
        return payload

    # ------------------------------------------------------------------
    # File and parsing helpers
    # ------------------------------------------------------------------

    async def _read_kb_records(self, kb: str) -> List[Dict[str, Any]]:
        path = self._kb_paths.get(kb)
        if path is None:
            return []
        return await asyncio.to_thread(self._read_jsonl, path)

    async def _read_audit_events(self, limit: int = 500) -> List[Dict[str, Any]]:
        rows = await asyncio.to_thread(self._read_jsonl, self._audit_file)
        if len(rows) <= limit:
            return rows
        return rows[-limit:]

    async def _read_index_state(self) -> Dict[str, int]:
        if not self._index_state_file.exists():
            return {}

        def _loader() -> Dict[str, int]:
            try:
                payload = json.loads(self._index_state_file.read_text(encoding="utf-8"))
                return {str(k): int(v) for k, v in dict(payload).items()}
            except Exception:
                return {}

        return await asyncio.to_thread(_loader)

    @staticmethod
    def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
        if not path.exists():
            return []
        out: List[Dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                    if isinstance(payload, dict):
                        out.append(payload)
                except Exception:
                    continue
        return out

    @staticmethod
    def _write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(clean_data(row), ensure_ascii=True, default=str) + "\n")

    @staticmethod
    def _vector_norm(vec: Sequence[float]) -> float:
        if not vec:
            return 0.0
        return math.sqrt(sum(float(x) * float(x) for x in vec))

    @staticmethod
    def _percentile(values: Sequence[float], q: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        idx = int(max(0, min(len(ordered) - 1, round((len(ordered) - 1) * q))))
        return float(ordered[idx])

    @staticmethod
    def _parse_timestamp(value: Any) -> Optional[datetime]:
        if not value:
            return None
        try:
            text = str(value).replace("Z", "+00:00")
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.astimezone(UTC)
        except Exception:
            return None

    @staticmethod
    def _knowledge_gap_reason(
        *,
        avg_rel: float,
        avg_latency: int,
        low_conf_ratio: float,
        low_conf_threshold: float,
        max_latency_ms: int,
    ) -> str:
        reasons: List[str] = []
        if avg_rel < low_conf_threshold:
            reasons.append(f"average relevance {avg_rel:.3f} below threshold {low_conf_threshold:.3f}")
        if low_conf_ratio > 0.30:
            reasons.append(f"low-confidence ratio {low_conf_ratio:.2%} is elevated")
        if avg_latency > max_latency_ms:
            reasons.append(f"average latency {avg_latency}ms exceeds {max_latency_ms}ms")
        return "; ".join(reasons) if reasons else "healthy"

    @staticmethod
    def _extract_method_signature(text: str) -> str:
        lower = text.lower()
        for marker, label in _METHOD_HINTS.items():
            if marker in lower:
                return label
        if "```" in text:
            return "code-block"
        return "narrative"

    def _extract_agent_id(self, event: Dict[str, Any]) -> str:
        data = event.get("data") or {}
        for key in ("agent_id", "agent", "actor"):
            value = data.get(key)
            if value:
                return str(value)
        return os.getenv("CERBERUS_AGENT_ID", "unknown-agent")

    def _render_topics_table(self, topics: Sequence[Dict[str, Any]]) -> str:
        console = Console(record=True, force_terminal=False, width=96)
        table = Table(title="Top 5 Queried Topics")
        table.add_column("Rank", justify="right", style="cyan")
        table.add_column("Topic", style="magenta")
        table.add_column("Count", justify="right", style="green")

        for idx, item in enumerate(topics[:5], start=1):
            table.add_row(str(idx), str(item.get("topic", "n/a")), str(item.get("count", 0)))

        if not topics:
            table.add_row("1", "(no query telemetry yet)", "0")

        console.print(table)
        return console.export_text()

    def _audit(self, event: str, payload: Dict[str, Any]) -> None:
        row = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "event": event,
            "data": clean_data(payload),
        }
        monitor_audit_file = self._rag_root / "rag_monitor_audit.jsonl"
        monitor_audit_file.parent.mkdir(parents=True, exist_ok=True)
        with monitor_audit_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=True, default=str) + "\n")

        if self._logger is not None:
            try:
                self._logger.audit("RAG monitor event", actor="rag_monitor", data=row, tags=["rag", "monitor", event])
            except Exception:
                pass


RAG_MONITOR = CerebroRAGMonitor()


@function_tool
def get_rag_status(include_content: bool = False) -> Dict[str, Any]:
    """Return async RAG observability snapshot for operators and agents."""

    async def _run() -> Dict[str, Any]:
        return await RAG_MONITOR.get_status(include_content=include_content)

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_run())

    result: Dict[str, Any] = {}

    def _runner() -> None:
        result["value"] = asyncio.run(_run())

    import threading

    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    t.join()
    return result.get("value", {"ok": False, "error": "status unavailable"})


__all__ = ["CerebroRAGMonitor", "get_rag_status"]
