"""Modular memory package for CAI.

MemoryManager is the high-level interface used by commands, tools, and agents.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from cai.memory.logic import MemorySummary, summarize_events
from cai.memory.search import (
    CADEResponse,
    CADEResult,
    CerebroSearchEngine,
    MemorySearch,
    SearchHit,
    TraceabilityMeta,
)
from cai.memory.storage import (
    CerebroStorageHandler,
    EvidenceRecord,
    StorageBackend,
    WorkspaceJSONStore,
)


class QueryResult(BaseModel):
    """Structured response for memory queries."""

    topic: str
    count: int = Field(ge=0)
    records: list[EvidenceRecord] = Field(default_factory=list)


class MemoryManager:
    """Primary memory interface for the framework.

    Responsibilities:
    - Initialize memory storage in the active workspace.
    - Save validated evidence records.
    - Query relevant records with ranking.
    - Summarize long event streams for context compression.
    """

    def __init__(self, backend: StorageBackend | None = None) -> None:
        self._backend: StorageBackend = backend or WorkspaceJSONStore()
        self._search = MemorySearch()
        self._ready = False

    @property
    def storage_root(self) -> Path:
        return getattr(self._backend, "storage_root", Path.cwd())

    def initialize(self) -> Path:
        root = self._backend.initialize()
        self._ready = True
        return root

    def record(self, payload: EvidenceRecord | dict[str, Any]) -> EvidenceRecord:
        if not self._ready:
            self.initialize()
        return self._backend.append(payload)

    def query(self, topic: str, limit: int = 8) -> QueryResult:
        if not self._ready:
            self.initialize()

        records = self._backend.load_all()
        hits = self._search.query(topic=topic, records=records, limit=limit)
        selected = [hit.record for hit in hits]
        return QueryResult(topic=topic, count=len(selected), records=selected)

    def summarize(self, records: list[EvidenceRecord] | None = None, max_points: int = 8) -> MemorySummary:
        if records is None:
            if not self._ready:
                self.initialize()
            records = self._backend.load_all()

        payload = [record.model_dump(mode="python") for record in records]
        return summarize_events(payload, max_points=max_points)

    def ranked_query(self, topic: str, limit: int = 8) -> list[SearchHit]:
        if not self._ready:
            self.initialize()
        return self._search.query(topic=topic, records=self._backend.load_all(), limit=limit)


__all__ = [
    "CADEResponse",
    "CADEResult",
    "CerebroSearchEngine",
    "CerebroStorageHandler",
    "EvidenceRecord",
    "MemoryManager",
    "MemorySummary",
    "QueryResult",
    "SearchHit",
    "StorageBackend",
    "TraceabilityMeta",
    "WorkspaceJSONStore",
]
