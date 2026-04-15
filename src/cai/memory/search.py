"""Memory retrieval, ranking helpers, and the Cerebro Audit Discovery Engine (CADE).

CADE provides high-velocity, evidence-first retrieval across all Cerebro memory
tiers (Logic, Episodic, Semantic) with full provenance traceability on every
result.  It is designed for the Transparent Auditor philosophy: no result is
suppressed, every hit carries its file path, agent ID, timestamp, and the
matched excerpt.

Backward compatibility
----------------------
The original :class:`MemorySearch` and :class:`SearchHit` classes are kept
unchanged so that existing ``__init__.py`` imports continue to work.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from cai.memory.storage import EvidenceRecord


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"[a-z0-9_\-]{2,}", flags=re.IGNORECASE)
_PATTERN_CACHE: dict[str, re.Pattern[str]] = {}
_PATTERN_CACHE_LOCK = threading.Lock()


def _tokenize(text: str) -> set[str]:
    return {token.lower() for token in _TOKEN_RE.findall(text)}


def _get_pattern(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern[str]:
    """Return a compiled regex pattern, using a shared cache."""
    key = f"{flags}:{pattern}"
    with _PATTERN_CACHE_LOCK:
        if key not in _PATTERN_CACHE:
            _PATTERN_CACHE[key] = re.compile(pattern, flags)
        return _PATTERN_CACHE[key]


# ---------------------------------------------------------------------------
# Legacy API (preserved for __init__.py compatibility)
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class SearchHit:
    """Ranked result container for memory queries."""

    score: float
    record: EvidenceRecord


class MemorySearch:
    """Lightweight keyword ranking over persisted memory records."""

    def query(self, topic: str, records: Iterable[EvidenceRecord], limit: int = 10) -> list[SearchHit]:
        prompt_tokens = _tokenize(topic)
        if not prompt_tokens:
            return []

        ranked: list[SearchHit] = []
        for record in records:
            score = self._score_record(record, prompt_tokens)
            if score <= 0:
                continue
            ranked.append(SearchHit(score=score, record=record))

        ranked.sort(key=lambda item: item.score, reverse=True)
        return ranked[: max(limit, 1)]

    def _score_record(self, record: EvidenceRecord, prompt_tokens: set[str]) -> float:
        topic_tokens = _tokenize(record.topic)
        finding_tokens = _tokenize(record.finding)
        tags_tokens = _tokenize(" ".join(record.tags))
        artifact_tokens = _tokenize(str(record.artifacts))

        score = 0.0
        score += 3.0 * len(prompt_tokens & topic_tokens)
        score += 2.0 * len(prompt_tokens & tags_tokens)
        score += 1.5 * len(prompt_tokens & finding_tokens)
        score += 0.5 * len(prompt_tokens & artifact_tokens)

        return score


# ---------------------------------------------------------------------------
# Cerebro Audit Discovery Engine (CADE)
# ---------------------------------------------------------------------------

_CADE_LOG = logging.getLogger("CerebroSearchEngine")
_DEFAULT_WORKSPACE = Path(os.getenv("CIR_WORKSPACE", "/workspace")).resolve()


@dataclass
class TraceabilityMeta:
    """Provenance block attached to every CADE result.

    Fields
    ------
    record_id    : Unique ID of the backing record / logic key.
    agent_id     : Agent or source that created the record.
    timestamp    : ISO 8601 creation / last-updated timestamp.
    topic        : Human-readable topic label.
    source       : Memory tier: "logic" | "episodic" | "semantic".
    storage_path : Absolute path to the backing file on disk.
    tags         : Labels carried by the original record.
    matched_field: Which field triggered the match (topic/finding/tag/…).
    match_excerpt: Short snippet around the matched text.
    """

    record_id: str
    agent_id: str
    timestamp: str
    topic: str
    source: str
    storage_path: str
    tags: list[str] = field(default_factory=list)
    matched_field: str = ""
    match_excerpt: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp,
            "topic": self.topic,
            "source": self.source,
            "storage_path": self.storage_path,
            "tags": self.tags,
            "matched_field": self.matched_field,
            "match_excerpt": self.match_excerpt,
        }


@dataclass
class CADEResult:
    """Single auditable search result from CADE."""

    score: float
    content: str
    provenance: TraceabilityMeta

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 4),
            "content": self.content,
            "provenance": self.provenance.to_dict(),
        }

    def to_markdown(self) -> str:
        p = self.provenance
        return (
            f"**{p.topic}** (score={self.score:.3f})\n"
            f"- **Source**: `{p.source}` | **Agent**: `{p.agent_id}`\n"
            f"- **Time**: {p.timestamp} | **ID**: `{p.record_id}`\n"
            f"- **Storage**: {p.storage_path}\n"
            f"- **Tags**: {', '.join(p.tags) or 'none'}\n"
            f"- **Match**: `{p.matched_field}` — {p.match_excerpt}\n"
            f"\n{self.content}\n"
        )


@dataclass
class CADEResponse:
    """Full multi-tier query response from CADE."""

    query: str
    elapsed_ms: float
    results: list[CADEResult]
    tier_counts: dict[str, int] = field(default_factory=dict)
    conceptual_suggestions: list[str] = field(default_factory=list)
    cross_ref_resolved: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "total_results": len(self.results),
            "tier_counts": self.tier_counts,
            "cross_ref_resolved": self.cross_ref_resolved,
            "conceptual_suggestions": self.conceptual_suggestions,
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_markdown(self) -> str:
        header = (
            f"## CADE Query: `{self.query}`\n\n"
            f"**Results**: {len(self.results)} | "
            f"**Elapsed**: {self.elapsed_ms:.2f}ms | "
            f"**Tiers**: {self.tier_counts}\n"
        )
        if self.cross_ref_resolved:
            header += f"**Cross-ref resolved**: `{self.cross_ref_resolved}`\n"
        if self.conceptual_suggestions:
            header += f"**Conceptual suggestions**: {', '.join(self.conceptual_suggestions)}\n"
        body = "\n---\n".join(r.to_markdown() for r in self.results)
        return f"{header}\n{body}" if body else f"{header}\n*(no results)*"


class CerebroSearchEngine:
    """Cerebro Audit Discovery Engine (CADE).

    High-velocity, evidence-first retrieval across three memory tiers:

    * **Logic** — structured fact / state nodes (``CerebroLogicEngine``)
    * **Episodic** — event stream (``WorkspaceJSONStore`` JSONL evidence)
    * **Semantic** — broad substring / partial-token scan for pattern recognition

    Every result carries a :class:`TraceabilityMeta` provenance block.
    Search logs are written to ``/workspace/memory/indices/`` via
    PathGuard-protected I/O so every query is auditable.

    Example::

        engine = CerebroSearchEngine.get_instance()
        resp = engine.search("RCE 10.0.0.5")
        print(resp.to_markdown())

        # Cross-reference: resolve a Logic key, search with its value
        resp = engine.cross_reference(
            "target.primary_ip",
            query_template="tool output {value}",
        )
    """

    _instance: Optional["CerebroSearchEngine"] = None
    _instance_lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Singleton factory
    # ------------------------------------------------------------------

    @classmethod
    def get_instance(cls, **kwargs: Any) -> "CerebroSearchEngine":
        """Return the process-wide singleton, creating it on first call."""
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls(**kwargs)
        return cls._instance

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(
        self,
        *,
        workspace_root: Optional[str] = None,
        max_results: int = 50,
        vector_fallback_hook: Optional[Callable[[str], list[str]]] = None,
        storage_backend: Any = None,
        logic_engine: Any = None,
    ) -> None:
        self.workspace_root = Path(
            workspace_root or str(_DEFAULT_WORKSPACE)
        ).resolve()
        self._max_results = max_results
        self._vector_fallback_hook = vector_fallback_hook
        # Optional injected backends; avoids duplicate workspace/engine creation
        # when CADE is used alongside a MemoryManager that already owns a store.
        self._storage_backend: Any = storage_backend
        self._logic_engine: Any = logic_engine
        self._lock = threading.RLock()

        # PathGuard writer — lazy-initialised to avoid circular import
        self._writer: Optional[_CADEWriter] = None
        self._writer_init_lock = threading.Lock()

        # Background indexer state
        self._stop_event = threading.Event()
        self._indexer_thread: Optional[threading.Thread] = None

        # Lightweight in-memory inverted index
        # token → list of (record_id, tier, base_weight)
        self._index: dict[str, list[tuple[str, str, float]]] = defaultdict(list)
        self._index_records: dict[str, tuple[EvidenceRecord, str]] = {}
        self._index_built_at: float = 0.0

        _CADE_LOG.info("[CADE] Initialised. workspace=%s", self.workspace_root)

    # ------------------------------------------------------------------
    # PathGuard writer (lazy)
    # ------------------------------------------------------------------

    def _ensure_writer(self) -> "_CADEWriter":
        if self._writer is None:
            with self._writer_init_lock:
                if self._writer is None:
                    self._writer = _CADEWriter(self.workspace_root)
        return self._writer

    # ------------------------------------------------------------------
    # Public search API
    # ------------------------------------------------------------------

    def search(
        self,
        query: str,
        *,
        tiers: Optional[tuple[str, ...]] = None,
        regex: bool = False,
        limit: Optional[int] = None,
    ) -> CADEResponse:
        """Multi-tier search returning a :class:`CADEResponse`.

        Args:
            query:  Search terms or a ``re.search`` pattern (when *regex* is
                    ``True``).
            tiers:  Subset of ``("logic", "episodic", "semantic")``.
                    Defaults to all three.
            regex:  Treat *query* as a compiled regex rather than keywords.
            limit:  Cap on results per tier (default: ``max_results``).
        """
        tiers = tiers or ("logic", "episodic", "semantic")
        cap = limit or self._max_results
        t0 = time.perf_counter()

        results: list[CADEResult] = []
        tier_counts: dict[str, int] = {}

        # Fan-out across tiers in parallel — each tier has its own thread so
        # slow I/O in one tier cannot block the others.
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=len(tiers), thread_name_prefix="cade"
        ) as pool:
            futures: dict[concurrent.futures.Future[list[CADEResult]], str] = {}
            if "logic" in tiers:
                futures[pool.submit(self._search_logic, query, regex, cap)] = "logic"
            if "episodic" in tiers:
                futures[pool.submit(self._search_episodic, query, regex, cap)] = "episodic"
            if "semantic" in tiers:
                futures[pool.submit(self._search_semantic, query, regex, cap)] = "semantic"

            for fut, tier in futures.items():
                try:
                    hits = fut.result(timeout=4.9)
                    tier_counts[tier] = len(hits)
                    results.extend(hits)
                except Exception as exc:
                    _CADE_LOG.warning("[CADE] Tier '%s' error: %s", tier, exc)
                    tier_counts[tier] = 0

        results.sort(key=lambda r: r.score, reverse=True)
        results = results[:cap]

        # Vector similarity fallback when keyword search returns nothing
        suggestions: list[str] = []
        if not results and self._vector_fallback_hook is not None:
            try:
                suggestions = self._vector_fallback_hook(query)
            except Exception:
                pass

        elapsed = (time.perf_counter() - t0) * 1000
        resp = CADEResponse(
            query=query,
            elapsed_ms=elapsed,
            results=results,
            tier_counts=tier_counts,
            conceptual_suggestions=suggestions,
        )

        # Non-blocking audit log write
        threading.Thread(
            target=self._log_query_audit, args=(resp,), daemon=True
        ).start()

        return resp

    def cross_reference(
        self,
        logic_key: str,
        query_template: str = "{value}",
        *,
        tiers: Optional[tuple[str, ...]] = None,
        limit: Optional[int] = None,
    ) -> CADEResponse:
        """Resolve a Logic-tier fact and search using its value.

        Useful for queries such as:
        *"Find all tool outputs related to the host currently marked as
        Primary Target"*::

            engine.cross_reference(
                "target.primary_ip",
                query_template="tool output {value}",
            )

        If the key is not found the raw key name is used as the search term.
        """
        from cai.memory.logic import CerebroLogicEngine  # deferred import

        logic = self._logic_engine or CerebroLogicEngine(workspace_root=str(self.workspace_root))
        resolved = logic.get(logic_key)
        resolved_str = str(resolved) if resolved is not None else logic_key
        if resolved is None:
            _CADE_LOG.warning("[CADE] cross_reference: key %r not in Logic tier", logic_key)

        query = query_template.replace("{value}", resolved_str)
        resp = self.search(query, tiers=tiers, limit=limit)
        resp.cross_ref_resolved = resolved_str
        resp.query = f"cross_ref({logic_key}={resolved_str!r}) → {query}"
        return resp

    # ------------------------------------------------------------------
    # Vector similarity hook (wired from vector.py when available)
    # ------------------------------------------------------------------

    def register_vector_hook(self, hook: Callable[[str], list[str]]) -> None:
        """Register a conceptual-match fallback callable.

        *hook* receives the query string and returns a list of alternative
        search suggestions (e.g. nearest neighbours from an embedding index in
        ``vector.py``).  It is called only when all tier searches return zero
        results.
        """
        self._vector_fallback_hook = hook

    # ------------------------------------------------------------------
    # Background indexer
    # ------------------------------------------------------------------

    def start_indexer(self, interval_seconds: float = 10.0) -> None:
        """Start a daemon thread that rebuilds the inverted index periodically."""
        with self._lock:
            if self._indexer_thread and self._indexer_thread.is_alive():
                return
            self._stop_event.clear()
            self._indexer_thread = threading.Thread(
                target=self._indexer_loop,
                args=(max(1.0, interval_seconds),),
                daemon=True,
                name="cade-indexer",
            )
            self._indexer_thread.start()
            _CADE_LOG.info(
                "[CADE] Background indexer started (interval=%.0fs)", interval_seconds
            )

    def stop_indexer(self) -> None:
        """Signal the background indexer to stop and wait for it."""
        self._stop_event.set()
        if self._indexer_thread:
            self._indexer_thread.join(timeout=5.0)
            self._indexer_thread = None

    def refresh_index(self) -> int:
        """Synchronously rebuild the inverted index from storage.

        Returns the number of records indexed.
        """
        from cai.memory.storage import WorkspaceJSONStore  # deferred import

        store = self._storage_backend
        if store is None:
            store = WorkspaceJSONStore()
        try:
            store.initialize()
            records = store.load_all()
        except Exception:
            records = []

        new_index: dict[str, list[tuple[str, str, float]]] = defaultdict(list)
        new_records: dict[str, tuple[EvidenceRecord, str]] = {}

        for record in records:
            tier = "episodic"
            new_records[record.id] = (record, tier)
            for token in _tokenize(record.topic):
                new_index[token].append((record.id, tier, 3.0))
            for token in _tokenize(record.finding):
                new_index[token].append((record.id, tier, 1.5))
            for tag in record.tags:
                for token in _tokenize(tag):
                    new_index[token].append((record.id, tier, 2.0))

        with self._lock:
            self._index = new_index
            self._index_records = new_records
            self._index_built_at = time.time()

        _CADE_LOG.debug("[CADE] Index refreshed: %d records", len(records))
        return len(records)

    def _indexer_loop(self, interval: float) -> None:
        while not self._stop_event.wait(timeout=interval):
            try:
                self.refresh_index()
            except Exception as exc:
                _CADE_LOG.debug("[CADE] Indexer error: %s", exc)

    # ------------------------------------------------------------------
    # Tier search implementations
    # ------------------------------------------------------------------

    def _search_logic(self, query: str, regex: bool, limit: int) -> list[CADEResult]:
        """Search the Logic tier (CerebroLogicEngine fact graph)."""
        from cai.memory.logic import CerebroLogicEngine  # deferred import

        logic = self._logic_engine or CerebroLogicEngine(workspace_root=str(self.workspace_root))
        all_nodes = logic.search("")  # dict[key, value]

        pat = _get_pattern(query) if regex else None
        q_tokens = _tokenize(query)
        storage_path = str(
            self.workspace_root / ".cai" / "memory" / "logic_nodes.json"
        )

        results: list[CADEResult] = []
        for key, value in all_nodes.items():
            text = f"{key} = {value}"
            score = _score_text(text, q_tokens, pat)
            if score <= 0:
                continue

            node = logic._nodes.get(key)  # noqa: SLF001
            agent_id = (
                (node.meta or {}).get("agent_id", "logic-engine")
                if node and node.meta
                else "logic-engine"
            )
            ts = node.updated_at if node else datetime.now(tz=UTC).isoformat()
            parent_keys = list(node.parent_keys) if node else []

            matched_field, excerpt = _find_match_location(text, q_tokens, pat)
            results.append(
                CADEResult(
                    score=score,
                    content=text,
                    provenance=TraceabilityMeta(
                        record_id=key,
                        agent_id=agent_id,
                        timestamp=ts,
                        topic=key,
                        source="logic",
                        storage_path=storage_path,
                        tags=parent_keys,
                        matched_field=matched_field,
                        match_excerpt=excerpt,
                    ),
                )
            )

        results.sort(key=lambda r: r.score, reverse=True)
        return results[:limit]

    def _search_episodic(self, query: str, regex: bool, limit: int) -> list[CADEResult]:
        """Episodic tier: exact token-match scan of EvidenceRecord JSONL store."""
        return self._scan_evidence_store(
            query, regex, limit,
            tier="episodic",
            partial_match=False,
        )

    def _search_semantic(self, query: str, regex: bool, limit: int) -> list[CADEResult]:
        """Semantic tier: broader substring scan for pattern recognition.

        Uses partial token containment (substring check) rather than
        whole-token equality, surfacing loosely related findings that exact
        token matching misses.  This tier acts as the retrieval layer for
        long-term pattern analysis; it integrates with :meth:`register_vector_hook`
        when a ``vector.py`` embedding index is available.
        """
        return self._scan_evidence_store(
            query, regex, limit,
            tier="semantic",
            partial_match=True,
        )

    def _scan_evidence_store(
        self,
        query: str,
        regex: bool,
        limit: int,
        *,
        tier: str,
        partial_match: bool,
    ) -> list[CADEResult]:
        from cai.memory.storage import WorkspaceJSONStore  # deferred import

        store = self._storage_backend
        if store is None:
            store = WorkspaceJSONStore()
        try:
            store.initialize()
            records: list[EvidenceRecord] = store.load_all()
        except Exception:
            records = []

        pat = _get_pattern(query) if regex else None
        q_tokens = _tokenize(query)
        storage_path = str(getattr(store, "file_path", self.workspace_root / ".cai/memory/evidence.jsonl"))

        results: list[CADEResult] = []
        for record in records:
            text = f"{record.topic} {record.finding} {' '.join(record.tags)}"
            score = (
                _score_text_partial(text, q_tokens, pat)
                if partial_match
                else _score_text(text, q_tokens, pat)
            )
            if score <= 0:
                continue

            matched_field, excerpt = _find_match_location(
                text, q_tokens, pat, record=record
            )
            results.append(
                CADEResult(
                    score=score,
                    content=record.finding,
                    provenance=TraceabilityMeta(
                        record_id=record.id,
                        agent_id=record.source,
                        timestamp=record.created_at.isoformat(timespec="milliseconds"),
                        topic=record.topic,
                        source=tier,
                        storage_path=storage_path,
                        tags=record.tags,
                        matched_field=matched_field,
                        match_excerpt=excerpt,
                    ),
                )
            )

        results.sort(key=lambda r: r.score, reverse=True)
        return results[:limit]

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def _log_query_audit(self, resp: CADEResponse) -> None:
        try:
            writer = self._ensure_writer()
            entry = {
                "ts": datetime.now(tz=UTC).isoformat(timespec="milliseconds"),
                "query": resp.query,
                "elapsed_ms": resp.elapsed_ms,
                "total": len(resp.results),
                "tiers": resp.tier_counts,
            }
            writer.append_jsonl("memory/indices/query_audit.jsonl", entry)
        except Exception as exc:
            _CADE_LOG.debug("[CADE] Audit log write failed: %s", exc)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Stop background tasks and release resources."""
        self.stop_indexer()
        _CADE_LOG.info("[CADE] Search engine closed")


# ---------------------------------------------------------------------------
# Module-level scoring helpers (used by both MemorySearch and CADE)
# ---------------------------------------------------------------------------

def _score_text(
    text: str,
    tokens: set[str],
    pat: Optional[re.Pattern[str]] = None,
) -> float:
    """Score *text* against *tokens* / *pat* using whole-token overlap."""
    if pat is not None:
        return (5.0 + float(len(tokens & _tokenize(text)))) if pat.search(text) else 0.0
    return float(len(tokens & _tokenize(text)))


def _score_text_partial(
    text: str,
    tokens: set[str],
    pat: Optional[re.Pattern[str]] = None,
) -> float:
    """Score *text* using substring containment (semantic / partial match)."""
    if pat is not None:
        return (5.0 + float(len(tokens & _tokenize(text)))) if pat.search(text) else 0.0
    text_lower = text.lower()
    score = 0.0
    for token in tokens:
        if token in text_lower:
            score += 1.0
    return score


def _find_match_location(
    text: str,
    tokens: set[str],
    pat: Optional[re.Pattern[str]] = None,
    *,
    record: Optional[EvidenceRecord] = None,
) -> tuple[str, str]:
    """Return ``(matched_field_name, excerpt)`` for the traceability block."""
    if pat is not None:
        m = pat.search(text)
        if m:
            start = max(0, m.start() - 30)
            end = min(len(text), m.end() + 30)
            excerpt = (
                ("…" if start > 0 else "")
                + text[start:end]
                + ("…" if end < len(text) else "")
            )
            return ("regex_match", excerpt)

    if record is not None:
        for field_name, field_text in [
            ("topic", record.topic),
            ("finding", record.finding),
            ("tags", " ".join(record.tags)),
            ("artifacts", str(record.artifacts)),
        ]:
            for token in tokens:
                idx = field_text.lower().find(token)
                if idx >= 0:
                    start = max(0, idx - 20)
                    end = min(len(field_text), idx + 40)
                    return (field_name, field_text[start:end])

    # Fallback: scan the full concatenated text
    for token in tokens:
        idx = text.lower().find(token)
        if idx >= 0:
            start = max(0, idx - 20)
            end = min(len(text), idx + 40)
            return ("full_text", text[start:end])

    return ("", "")


# ---------------------------------------------------------------------------
# PathGuard-gated writer for CADE indices and audit logs
# ---------------------------------------------------------------------------

class _CADEWriter:
    """Writes CADE index and audit artefacts via PathGuard.

    The PathGuard import is deferred inside ``__init__`` to avoid any
    potential circular import between the memory and filesystem modules.
    """

    def __init__(self, workspace_root: Path) -> None:
        from cai.tools.reconnaissance.filesystem import PathGuard as _PG  # noqa: PLC0415

        self.workspace_root = workspace_root.resolve()
        self._guard = _PG(self.workspace_root, self._audit)

    def append_jsonl(self, relative_path: str, entry: dict[str, Any]) -> None:
        resolved = self._guard.validate_path(
            relative_path, action="cade_audit_write", mode="write"
        )
        resolved.parent.mkdir(parents=True, exist_ok=True)
        with resolved.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")

    def write_json(self, relative_path: str, data: Any) -> None:
        resolved = self._guard.validate_path(
            relative_path, action="cade_index_write", mode="write"
        )
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    @staticmethod
    def _audit(_event: str, _payload: Any) -> None:
        return


__all__ = [
    "CerebroSearchEngine",
    "CADEResponse",
    "CADEResult",
    "TraceabilityMeta",
    "MemorySearch",
    "SearchHit",
]
