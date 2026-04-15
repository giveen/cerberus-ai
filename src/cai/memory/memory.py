"""Standalone memory module for agentic cybersecurity workflows.

This implementation is intentionally original and provides:
- Short-term volatile memory (deque)
- Long-term persistent memory (SQLite)
- Keyword-ranked retrieval
- Summarization for context grooming
- Redaction before persistence
- Workspace-aware storage paths
- Thread-safe writes/reads
"""

from __future__ import annotations

from collections import Counter, deque
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
import re
import sqlite3
import threading
from typing import Any, Optional
import uuid

from pydantic import BaseModel, Field, ConfigDict


_TOKEN_RE = re.compile(r"[a-z0-9_\-]{2,}", re.IGNORECASE)

# Redaction targets common secret formats and key-value disclosures.
_REDACTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(password|passwd|pwd|secret)\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"(?i)\b(api[_-]?key|token|access[_-]?key|private[_-]?key)\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:sk|rk)-[A-Za-z0-9]{16,}\b"),
)


class MemoryEvent(BaseModel):
    """Validated memory event shape for both short-term and long-term stores."""

    model_config = ConfigDict(extra="allow")

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    agent_id: str = Field(default="default")
    topic: str = Field(default="general", min_length=1)
    content: str = Field(min_length=1)
    tags: list[str] = Field(default_factory=list)
    importance: int = Field(default=1, ge=1, le=5)


class ContextWindow(BaseModel):
    """Result payload returned by get_context()."""

    query: str
    total_matches: int = Field(ge=0)
    events: list[MemoryEvent] = Field(default_factory=list)


class MemoryManager:
    """Epistemic memory manager with volatile and persistent layers.

    API:
    - add_event(...)
    - get_context(...)
    - clear(...)
    - summarize(...)
    """

    def __init__(
        self,
        *,
        short_term_size: int = 120,
        db_relative_path: str = ".cai/memory/memory.db",
    ) -> None:
        self._short_term: deque[MemoryEvent] = deque(maxlen=max(1, short_term_size))
        self._lock = threading.RLock()

        self._workspace_root = self._resolve_workspace_root()
        self._db_path = self._workspace_root / db_relative_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._configure_db()

    @property
    def workspace_root(self) -> Path:
        return self._workspace_root

    @property
    def database_path(self) -> Path:
        return self._db_path

    def _resolve_workspace_root(self) -> Path:
        try:
            from cai.tools.workspace import get_project_space

            return get_project_space().ensure_initialized().resolve()
        except Exception:
            return Path.cwd().resolve()

    def _configure_db(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.execute("PRAGMA busy_timeout=5000;")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS memory_events (
                    event_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    topic TEXT NOT NULL,
                    content TEXT NOT NULL,
                    tags TEXT NOT NULL,
                    importance INTEGER NOT NULL
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_memory_topic ON memory_events(topic);"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_memory_created_at ON memory_events(created_at);"
            )
            self._conn.commit()

    @contextmanager
    def _transaction(self):
        with self._lock:
            cursor = self._conn.cursor()
            try:
                yield cursor
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            finally:
                cursor.close()

    def add_event(
        self,
        content: str,
        *,
        topic: str = "general",
        tags: list[str] | None = None,
        agent_id: str = "default",
        importance: int = 1,
        persist: bool = True,
    ) -> MemoryEvent:
        """Add one event to short-term memory and optionally persist to long-term storage."""
        event = MemoryEvent(
            agent_id=agent_id,
            topic=topic,
            content=self._clean(content),
            tags=[self._clean(tag) for tag in (tags or [])],
            importance=importance,
        )

        with self._lock:
            self._short_term.append(event)

        if persist:
            with self._transaction() as cur:
                cur.execute(
                    """
                    INSERT OR REPLACE INTO memory_events
                    (event_id, created_at, agent_id, topic, content, tags, importance)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_id,
                        event.created_at.isoformat(),
                        event.agent_id,
                        event.topic,
                        event.content,
                        "|".join(event.tags),
                        event.importance,
                    ),
                )

        return event

    def get_context(
        self,
        query: str,
        *,
        limit: int = 12,
        include_short_term: bool = True,
        include_long_term: bool = True,
    ) -> ContextWindow:
        """Return ranked relevant context for a query.

        Ranking strategy:
        - topic token overlap has strongest weight
        - tags have medium weight
        - content token overlap contributes broad relevance
        - importance adds slight tie-breaking
        """
        ranked: dict[str, tuple[float, MemoryEvent]] = {}
        q_tokens = self._tokenize(query)

        if include_short_term:
            with self._lock:
                for event in list(self._short_term):
                    score = self._rank_event(event, q_tokens)
                    if score <= 0:
                        continue
                    ranked[event.event_id] = (score, event)

        if include_long_term:
            for event in self._fetch_all_events():
                score = self._rank_event(event, q_tokens)
                if score <= 0:
                    continue
                previous = ranked.get(event.event_id)
                if previous is None or score > previous[0]:
                    ranked[event.event_id] = (score, event)

        ordered = sorted(ranked.values(), key=lambda pair: pair[0], reverse=True)
        selected = [event for _, event in ordered[: max(1, limit)]]

        return ContextWindow(query=query, total_matches=len(ranked), events=selected)

    def clear(
        self,
        *,
        short_term: bool = True,
        long_term: bool = False,
        topic: str | None = None,
        agent_id: str | None = None,
    ) -> dict[str, int]:
        """Forget memory selectively from short-term and/or long-term layers."""
        short_cleared = 0
        long_cleared = 0

        if short_term:
            with self._lock:
                short_cleared = len(self._short_term)
                self._short_term.clear()

        if long_term:
            with self._transaction() as cur:
                where_parts: list[str] = []
                params: list[Any] = []

                if topic:
                    where_parts.append("topic = ?")
                    params.append(topic)
                if agent_id:
                    where_parts.append("agent_id = ?")
                    params.append(agent_id)

                sql = "DELETE FROM memory_events"
                if where_parts:
                    sql += " WHERE " + " AND ".join(where_parts)

                cur.execute(sql, params)
                long_cleared = cur.rowcount if cur.rowcount is not None else 0

        return {"short_term_cleared": short_cleared, "long_term_cleared": long_cleared}

    def summarize(
        self,
        *,
        max_events: int = 80,
        max_points: int = 8,
        include_short_term: bool = True,
        include_long_term: bool = True,
    ) -> str:
        """Compress memory into an executive technical summary string."""
        events: list[MemoryEvent] = []

        if include_long_term:
            events.extend(self._fetch_recent_events(limit=max_events))

        if include_short_term:
            with self._lock:
                events.extend(list(self._short_term))

        if not events:
            return "No memory events available."

        # Deduplicate by event_id and keep newest first.
        latest: dict[str, MemoryEvent] = {}
        for event in sorted(events, key=lambda e: e.created_at, reverse=True):
            latest[event.event_id] = event

        ordered = list(latest.values())[:max_events]
        topic_counts: Counter[str] = Counter(e.topic for e in ordered)

        key_points: list[str] = []
        for event in ordered:
            point = f"[{event.topic}] {event.content.strip()}"
            key_points.append(point)
            if len(key_points) >= max_points:
                break

        lines = [
            f"Events reviewed: {len(ordered)}",
            "Topic distribution: "
            + ", ".join(f"{topic}={count}" for topic, count in topic_counts.most_common(6)),
            "Key lessons learned:",
        ]
        lines.extend(f"- {self._clean(point)}" for point in key_points)

        return "\n".join(lines)

    def close(self) -> None:
        """Close persistent resources."""
        with self._lock:
            self._conn.close()

    def _fetch_all_events(self) -> list[MemoryEvent]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT event_id, created_at, agent_id, topic, content, tags, importance FROM memory_events"
            ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def _fetch_recent_events(self, *, limit: int) -> list[MemoryEvent]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT event_id, created_at, agent_id, topic, content, tags, importance
                FROM memory_events
                ORDER BY datetime(created_at) DESC
                LIMIT ?
                """,
                (max(1, limit),),
            ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def _row_to_event(self, row: sqlite3.Row) -> MemoryEvent:
        tags_raw = str(row["tags"]).strip()
        tags = [tag for tag in tags_raw.split("|") if tag] if tags_raw else []

        return MemoryEvent(
            event_id=str(row["event_id"]),
            created_at=datetime.fromisoformat(str(row["created_at"])),
            agent_id=str(row["agent_id"]),
            topic=str(row["topic"]),
            content=str(row["content"]),
            tags=tags,
            importance=int(row["importance"]),
        )

    def _rank_event(self, event: MemoryEvent, query_tokens: set[str]) -> float:
        if not query_tokens:
            return float(event.importance)

        topic_tokens = self._tokenize(event.topic)
        content_tokens = self._tokenize(event.content)
        tag_tokens = self._tokenize(" ".join(event.tags))

        score = 0.0
        score += 3.0 * len(query_tokens & topic_tokens)
        score += 2.0 * len(query_tokens & tag_tokens)
        score += 1.0 * len(query_tokens & content_tokens)
        score += 0.2 * event.importance
        return score

    def _tokenize(self, text: str) -> set[str]:
        return {token.lower() for token in _TOKEN_RE.findall(text)}

    def _clean(self, text: str) -> str:
        masked = text
        for pattern in _REDACTION_PATTERNS:
            if pattern.pattern.startswith("\\bAKIA") or pattern.pattern.startswith("\\b(?:sk|rk)"):
                masked = pattern.sub("[REDACTED_SECRET]", masked)
                continue

            def _replace(match: re.Match[str]) -> str:
                key = match.group(1)
                return f"{key}=[REDACTED_SECRET]"

            masked = pattern.sub(_replace, masked)
        return masked


__all__ = ["ContextWindow", "MemoryEvent", "MemoryManager", "CerebroMemoryBus"]


# =============================================================================
# CerebroMemoryBus — Cerebro Central Memory Bus (CCMB)
# =============================================================================

import json
import logging
import os

try:
    import msgpack as _msgpack  # type: ignore
    _MSGPACK_AVAILABLE = True
except ImportError:
    _msgpack = None  # type: ignore
    _MSGPACK_AVAILABLE = False

_CCMB_LOG = logging.getLogger("CerebroMemoryBus")
_DEFAULT_BUS_WORKSPACE = Path(os.getenv("CIR_WORKSPACE", "/workspace")).resolve()

# Importance threshold above which a Logic node is automatically mirrored to
# Semantic memory.
_MIRROR_IMPORTANCE_THRESHOLD = 3


class CerebroMemoryBus:
    """Cerebro Central Memory Bus (CCMB).

    Singleton coordinator that unifies:
    - :class:`~cai.memory.logic.CerebroLogicEngine` (structured fact/state nodes)
    - Episodic :class:`MemoryManager` (short-term event stream)
    - Semantic :class:`MemoryManager` (long-term pattern store)

    Key capabilities
    ----------------
    * ``commit()`` — synchronised snapshot across all sub-modules.
    * ``set_logic(key, value, importance=N)`` — writes to Logic engine and
      auto-mirrors high-importance facts to Semantic memory.
    * ``cross_query(query)`` — retrieves correlated results from Episodic and
      Logic tiers simultaneously.
    * Background saver daemon that periodically flushes RAM state to
      ``/workspace/memory/`` via a PathGuard-backed writer.
    * Health telemetry with automatic summarisation when Episodic history
      exceeds a configurable size threshold.
    """

    _instance: Optional["CerebroMemoryBus"] = None
    _instance_lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Singleton factory
    # ------------------------------------------------------------------

    @classmethod
    def get_instance(
        cls,
        *,
        workspace_root: Optional[str] = None,
        episodic_size: int = 500,
        episodic_db_path: str = ".cai/memory/episodic.db",
        semantic_db_path: str = ".cai/memory/semantic.db",
        auto_summarise_threshold: int = 400,
        mirror_importance: int = _MIRROR_IMPORTANCE_THRESHOLD,
    ) -> "CerebroMemoryBus":
        """Return the process-wide singleton, creating it on first call."""
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls(
                    workspace_root=workspace_root,
                    episodic_size=episodic_size,
                    episodic_db_path=episodic_db_path,
                    semantic_db_path=semantic_db_path,
                    auto_summarise_threshold=auto_summarise_threshold,
                    mirror_importance=mirror_importance,
                )
            return cls._instance

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(
        self,
        *,
        workspace_root: Optional[str] = None,
        episodic_size: int = 500,
        episodic_db_path: str = ".cai/memory/episodic.db",
        semantic_db_path: str = ".cai/memory/semantic.db",
        auto_summarise_threshold: int = 400,
        mirror_importance: int = _MIRROR_IMPORTANCE_THRESHOLD,
    ) -> None:
        self.workspace_root = Path(
            workspace_root or str(_DEFAULT_BUS_WORKSPACE)
        ).resolve()
        self._mirror_importance = max(1, mirror_importance)
        self._auto_summarise_threshold = max(10, auto_summarise_threshold)
        self._lock = threading.RLock()

        # --- Sub-system initialisation ---------------------------------
        # Deferred import avoids any circular-import risk at module level.
        from cai.memory.logic import CerebroLogicEngine  # noqa: PLC0415
        self.logic = CerebroLogicEngine(workspace_root=str(self.workspace_root))

        self.episodic = MemoryManager(
            short_term_size=episodic_size,
            db_relative_path=episodic_db_path,
        )
        self.semantic = MemoryManager(
            short_term_size=200,
            db_relative_path=semantic_db_path,
        )

        # --- PathGuard-backed writer ------------------------------------
        self._writer = _BusWriter(self.workspace_root)

        # --- Background saver state ------------------------------------
        self._saver_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._commit_count = 0

        _CCMB_LOG.info(
            "[CCMB] Memory Bus initialised. workspace=%s  mirror_threshold=%d",
            self.workspace_root,
            self._mirror_importance,
        )

    # ------------------------------------------------------------------
    # Logic / state interface
    # ------------------------------------------------------------------

    def set_logic(
        self,
        key: str,
        value: Any,
        *,
        importance: int = 1,
        parents: Optional[list[str]] = None,
        meta: Optional[dict[str, Any]] = None,
        agent_id: str = "default",
    ) -> None:
        """Write a fact to the Logic engine.

        If *importance* >= the bus mirror threshold the fact is also committed
        to Semantic memory for long-term pattern recognition.
        """
        self.logic.set(key, value, parents=parents, meta=meta)

        if importance >= self._mirror_importance:
            self.semantic.add_event(
                content=f"{key} = {value}",
                topic=key.split(".")[0] if "." in key else key,
                importance=min(5, importance),
                agent_id=agent_id,
                tags=[key],
                persist=True,
            )
            _CCMB_LOG.debug("[CCMB] Logic node mirrored to semantic: %s", key)

    def get_logic(self, key: str, default: Any = None) -> Any:
        """Shorthand for ``self.logic.get(key, default)``."""
        return self.logic.get(key, default)

    # ------------------------------------------------------------------
    # Cross-tier query
    # ------------------------------------------------------------------

    def cross_query(
        self,
        query: str,
        *,
        logic_prefix: Optional[str] = None,
        episodic_limit: int = 10,
        semantic_limit: int = 10,
    ) -> dict[str, Any]:
        """Correlated retrieval across Logic and Episodic tiers.

        Returns a dict with keys:
        - ``logic_nodes``: matching Logic facts (filtered by *logic_prefix* if
          supplied, otherwise all nodes whose key contains a token from *query*)
        - ``episodic``: :class:`ContextWindow` from Episodic memory
        - ``semantic``: :class:`ContextWindow` from Semantic memory
        """
        # Logic tier -------------------------------------------------------
        if logic_prefix:
            logic_hits = self.logic.search(logic_prefix)
        else:
            q_lower = query.lower()
            logic_hits = {
                k: v
                for k, v in self.logic.search("").items()
                if any(token in k.lower() for token in q_lower.split() if len(token) > 2)
            }

        # Episodic tier ----------------------------------------------------
        episodic_ctx = self.episodic.get_context(query, limit=episodic_limit)

        # Semantic tier ----------------------------------------------------
        semantic_ctx = self.semantic.get_context(query, limit=semantic_limit)

        return {
            "query": query,
            "logic_nodes": logic_hits,
            "episodic": episodic_ctx,
            "semantic": semantic_ctx,
        }

    # ------------------------------------------------------------------
    # Synchronised snapshot (commit)
    # ------------------------------------------------------------------

    def commit(self) -> dict[str, Any]:
        """Flush all sub-module state to disk atomically.

        Returns a summary dict with paths and counts.
        """
        with self._lock:
            ts = datetime.now(tz=UTC).isoformat(timespec="milliseconds")
            results: dict[str, Any] = {"committed_at": ts}

            # 1. Logic snapshot ------------------------------------------
            try:
                logic_path = self.logic.snapshot()
                results["logic_snapshot"] = str(logic_path)
            except Exception as exc:
                results["logic_snapshot_error"] = str(exc)
                _CCMB_LOG.warning("[CCMB] Logic snapshot failed: %s", exc)

            # 2. Episodic summary to disk ---------------------------------
            try:
                episodic_summary = self.episodic.summarize()
                self._writer.write_text(
                    "memory/episodic_summary.txt", episodic_summary
                )
                results["episodic_summary_path"] = str(
                    self.workspace_root / "memory/episodic_summary.txt"
                )
            except Exception as exc:
                results["episodic_summary_error"] = str(exc)
                _CCMB_LOG.warning("[CCMB] Episodic summary failed: %s", exc)

            # 3. Bus manifest (JSON or msgpack) ---------------------------
            try:
                manifest = {
                    "committed_at": ts,
                    "commit_seq": self._commit_count,
                    "workspace": str(self.workspace_root),
                    "health": self._health_snapshot(),
                }
                if _MSGPACK_AVAILABLE and _msgpack is not None:
                    raw = _msgpack.packb(manifest, use_bin_type=True)
                    self._writer.write_bytes("memory/bus_manifest.msgpack", raw)
                    results["manifest_format"] = "msgpack"
                else:
                    raw_text = json.dumps(manifest, indent=2, default=str)
                    self._writer.write_text("memory/bus_manifest.json", raw_text)
                    results["manifest_format"] = "json"
            except Exception as exc:
                results["manifest_error"] = str(exc)
                _CCMB_LOG.warning("[CCMB] Manifest write failed: %s", exc)

            self._commit_count += 1
            _CCMB_LOG.info("[CCMB] commit #%d completed", self._commit_count)
            return results

    # ------------------------------------------------------------------
    # Health telemetry
    # ------------------------------------------------------------------

    def health(self) -> dict[str, Any]:
        """Return a telemetry snapshot of all sub-module saturation levels."""
        return self._health_snapshot()

    def _health_snapshot(self) -> dict[str, Any]:
        short_term_used = len(self.episodic._short_term)  # noqa: SLF001
        short_term_max = self.episodic._short_term.maxlen or 1  # noqa: SLF001
        episodic_saturated = short_term_used >= self._auto_summarise_threshold

        if episodic_saturated:
            _CCMB_LOG.info(
                "[CCMB] Episodic saturation event triggered (%d/%d). Summarising.",
                short_term_used,
                short_term_max,
            )
            self._trigger_summarisation()

        return {
            "episodic_short_term_used": short_term_used,
            "episodic_short_term_max": short_term_max,
            "episodic_saturation_pct": round(
                100 * short_term_used / short_term_max, 1
            ),
            "episodic_auto_summarised": episodic_saturated,
            "logic_node_count": len(self.logic._nodes),  # noqa: SLF001
            "commit_count": self._commit_count,
        }

    def _trigger_summarisation(self) -> None:
        """Summarise and drain old short-term episodic events."""
        summary_text = self.episodic.summarize(
            max_events=self._auto_summarise_threshold,
            include_short_term=True,
            include_long_term=False,
        )
        # Store the compressed summary as a single high-importance semantic event.
        self.semantic.add_event(
            content=summary_text,
            topic="auto_summarisation",
            importance=4,
            agent_id="ccmb",
            tags=["summary", "episodic"],
        )
        # Clear short-term to free RAM.
        self.episodic.clear(short_term=True, long_term=False)

    # ------------------------------------------------------------------
    # Background saver
    # ------------------------------------------------------------------

    def start_background_saver(self, interval_seconds: float = 30.0) -> None:
        """Start a daemon thread that calls :meth:`commit` every *interval_seconds*."""
        with self._lock:
            if self._saver_thread and self._saver_thread.is_alive():
                return
            self._stop_event.clear()
            self._saver_thread = threading.Thread(
                target=self._saver_loop,
                args=(max(1.0, interval_seconds),),
                daemon=True,
                name="ccmb-saver",
            )
            self._saver_thread.start()
            _CCMB_LOG.info(
                "[CCMB] Background saver started (interval=%.0fs)", interval_seconds
            )

    def stop_background_saver(self) -> None:
        """Signal the background saver to stop and wait for it to exit."""
        self._stop_event.set()
        if self._saver_thread:
            self._saver_thread.join(timeout=5.0)
            self._saver_thread = None
        _CCMB_LOG.info("[CCMB] Background saver stopped")

    def _saver_loop(self, interval: float) -> None:
        while not self._stop_event.wait(timeout=interval):
            try:
                self.commit()
            except Exception as exc:  # pragma: no cover
                _CCMB_LOG.warning("[CCMB] Background commit failed: %s", exc)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Stop background tasks and close sub-system resources."""
        self.stop_background_saver()
        self.episodic.close()
        self.semantic.close()
        _CCMB_LOG.info("[CCMB] Memory Bus closed")


# ---------------------------------------------------------------------------
# Internal PathGuard-backed writer (no circular import risk)
# ---------------------------------------------------------------------------

class _BusWriter:
    """PathGuard-backed writer for bus-level persistence."""

    def __init__(self, workspace_root: Path) -> None:
        # Deferred import breaks any potential circular dependency.
        from cai.tools.reconnaissance.filesystem import PathGuard as _FPG  # noqa: PLC0415
        self.workspace_root = workspace_root.resolve()
        self._guard = _FPG(self.workspace_root, self._audit)

    def write_text(self, relative_path: str, content: str) -> None:
        resolved = self._safe_resolve(relative_path, mode="write")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding="utf-8")

    def write_bytes(self, relative_path: str, payload: bytes) -> None:
        resolved = self._safe_resolve(relative_path, mode="write")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_bytes(payload)

    def _safe_resolve(self, relative_path: str, *, mode: str) -> Path:
        try:
            return self._guard.validate_path(
                relative_path, action="ccmb_write", mode=mode
            )
        except PermissionError as exc:
            raise PermissionError(f"PathGuard violation: {exc}") from exc

    @staticmethod
    def _audit(_event: str, _payload: Any) -> None:
        return
