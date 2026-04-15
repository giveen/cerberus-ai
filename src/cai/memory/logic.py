"""Memory processing logic for redaction and summarization.

This module contains pure functions that can be reused by storage and query
layers without coupling to any specific backend implementation.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field as dc_field
from datetime import UTC, datetime
import json
import logging
import os
from pathlib import Path
import re
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Set

from pydantic import BaseModel, Field


_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(password|passwd|pwd|secret)\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"(?i)\b(api[_-]?key|token|access[_-]?key|private[_-]?key)\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:sk|rk)-[A-Za-z0-9]{16,}\b"),
)


class MemorySummary(BaseModel):
    """Compact summary payload used for LLM context injection."""

    generated_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    total_events: int = Field(ge=0)
    topics: list[str] = Field(default_factory=list)
    key_points: list[str] = Field(default_factory=list)
    text: str


def clean(value: str) -> str:
    """Mask probable secrets in free text.

    The redaction intentionally favors safety over precision and replaces
    suspicious values with stable placeholders.
    """
    masked = value

    for pattern in _SECRET_PATTERNS:
        if pattern.pattern.startswith("\\bAKIA") or pattern.pattern.startswith("\\b(?:sk|rk)"):
            masked = pattern.sub("[REDACTED_SECRET]", masked)
            continue

        def _replace(match: re.Match[str]) -> str:
            key = match.group(1)
            return f"{key}=[REDACTED_SECRET]"

        masked = pattern.sub(_replace, masked)

    return masked


def clean_data(payload: Any) -> Any:
    """Recursively redact strings in complex objects prior to persistence."""
    if isinstance(payload, str):
        return clean(payload)
    if isinstance(payload, list):
        return [clean_data(item) for item in payload]
    if isinstance(payload, tuple):
        return tuple(clean_data(item) for item in payload)
    if isinstance(payload, dict):
        return {str(key): clean_data(value) for key, value in payload.items()}
    return payload


def summarize_events(events: Iterable[dict[str, Any]], max_points: int = 8) -> MemorySummary:
    """Compress a sequence of events into a concise technical state update."""
    items = list(events)
    if not items:
        return MemorySummary(total_events=0, text="No memory events captured yet.")

    topic_counter: Counter[str] = Counter()
    key_points: list[str] = []

    for event in items:
        topic = str(event.get("topic", "general")).strip() or "general"
        topic_counter[topic] += 1

        finding = event.get("finding") or event.get("summary") or event.get("details")
        if isinstance(finding, str) and finding.strip():
            key_points.append(clean(finding.strip()))

        if len(key_points) >= max_points:
            break

    topics_ranked = [topic for topic, _ in topic_counter.most_common(6)]

    lines = [
        f"Events analyzed: {len(items)}",
        f"Top topics: {', '.join(topics_ranked) if topics_ranked else 'none'}",
    ]
    if key_points:
        lines.append("Key findings:")
        for point in key_points[:max_points]:
            lines.append(f"- {point}")

    return MemorySummary(
        total_events=len(items),
        topics=topics_ranked,
        key_points=key_points[:max_points],
        text="\n".join(lines),
    )


# =============================================================================
# CerebroLogicEngine — Open State Synchronisation Engine
# =============================================================================

_DEFAULT_LOGIC_WORKSPACE = Path(os.getenv("CIR_WORKSPACE", "/workspace")).resolve()
_log = logging.getLogger("CerebroLogicEngine")


class _LogicViolation(PermissionError):
    """Raised when the engine tries to write outside the workspace."""


class _LogicWriter:
    """PathGuard-backed writer for logic audit log and snapshots."""

    def __init__(self, workspace_root: Path) -> None:
        # Deferred import breaks the logic ↔ filesystem circular dependency.
        from cai.tools.reconnaissance.filesystem import PathGuard as _FPG  # noqa: PLC0415
        self.workspace_root = workspace_root.resolve()
        self._guard = _FPG(self.workspace_root, self._audit)

    def write_text(self, relative_path: str, content: str) -> None:
        resolved = self._safe_resolve(relative_path, mode="write")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding="utf-8")

    def append_text(self, relative_path: str, line: str) -> None:
        resolved = self._safe_resolve(relative_path, mode="write")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        with resolved.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def write_bytes(self, relative_path: str, payload: bytes) -> None:
        resolved = self._safe_resolve(relative_path, mode="write")
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_bytes(payload)

    def _safe_resolve(self, relative_path: str, *, mode: str) -> Path:
        try:
            return self._guard.validate_path(
                relative_path, action="logic_engine_write", mode=mode
            )
        except PermissionError as exc:
            raise _LogicViolation(str(exc)) from exc

    @staticmethod
    def _audit(_event: str, _payload: Any) -> None:
        return


@dataclass
class LogicNode:
    """A single tracked mission-state fact."""

    key: str
    value: Any
    stale: bool = False
    parent_keys: Set[str] = dc_field(default_factory=set)
    updated_at: str = dc_field(
        default_factory=lambda: datetime.now(tz=UTC).isoformat()
    )
    meta: Dict[str, Any] = dc_field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
            "stale": self.stale,
            "parent_keys": sorted(self.parent_keys),
            "updated_at": self.updated_at,
            "meta": self.meta,
        }


class CerebroLogicEngine:
    """Open State Synchronisation Engine for Cerberus AI agent swarms.

    Maintains a flat, searchable dictionary of *Logic Nodes* keyed by
    dot-separated names such as ``host.10.0.0.1.status`` or
    ``credential.admin.validity``.  Every mutation is appended to a plain-text
    audit log and propagated through a dependency graph so that child nodes are
    automatically flagged stale when their parent changes.

    Thread-safe via an internal ``RLock``.

    Parameters
    ----------
    workspace_root:
        Absolute path that PathGuard uses as the sandbox root.  Defaults to
        the ``CIR_WORKSPACE`` environment variable or ``/workspace``.
    audit_log:
        Workspace-relative path for the plain-text audit log.
    """

    _AUDIT_LOG_REL = "memory/logic_audit.log"
    _SNAPSHOT_REL = "memory/logic_snapshot.json"

    def __init__(
        self,
        *,
        workspace_root: Optional[str] = None,
        audit_log: Optional[str] = None,
    ) -> None:
        self.workspace_root = Path(
            workspace_root or str(_DEFAULT_LOGIC_WORKSPACE)
        ).resolve()
        self._writer = _LogicWriter(self.workspace_root)
        self._audit_rel = audit_log or self._AUDIT_LOG_REL

        self._lock = threading.RLock()
        self._nodes: Dict[str, LogicNode] = {}
        # parent key → set of child keys
        self._children: Dict[str, Set[str]] = {}

        self._append_audit("ENGINE_INIT", {"workspace": str(self.workspace_root)})

    # ------------------------------------------------------------------
    # Core state mutation
    # ------------------------------------------------------------------

    def set(
        self,
        key: str,
        value: Any,
        *,
        parents: Optional[List[str]] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Create or update a Logic Node.

        Parameters
        ----------
        key:
            Dot-separated node name, e.g. ``host.10.0.0.1.status``.
        value:
            Any JSON-serialisable value.
        parents:
            Optional list of node keys this node depends on.  If any parent
            later changes, this node will be flagged stale.
        meta:
            Optional free-form metadata dict stored alongside the node.
        """
        with self._lock:
            old_value = self._nodes[key].value if key in self._nodes else _MISSING
            now = datetime.now(tz=UTC).isoformat()
            node = self._nodes.get(key) or LogicNode(key=key, value=None)
            node.key = key
            node.value = value
            node.stale = False
            node.updated_at = now
            if parents is not None:
                node.parent_keys = set(parents)
            if meta is not None:
                node.meta.update(meta)
            self._nodes[key] = node

            # Register child relationship
            for parent_key in node.parent_keys:
                self._children.setdefault(parent_key, set()).add(key)

            # Propagate staleness to children if this node already existed
            if old_value is not _MISSING:
                self._mark_children_stale(key)

            self._append_audit(
                "SET",
                {
                    "key": key,
                    "old": _safe_repr(old_value),
                    "new": _safe_repr(value),
                },
            )

    def get(self, key: str, default: Any = None) -> Any:
        """Return the current value for *key*, or *default* if absent."""
        with self._lock:
            node = self._nodes.get(key)
            return node.value if node is not None else default

    def get_node(self, key: str) -> Optional[LogicNode]:
        """Return the full :class:`LogicNode` for *key*, or ``None``."""
        with self._lock:
            return self._nodes.get(key)

    def delete(self, key: str) -> None:
        """Remove a node and all its child registrations."""
        with self._lock:
            if key not in self._nodes:
                return
            self._nodes.pop(key, None)
            self._children.pop(key, None)
            for children in self._children.values():
                children.discard(key)
            self._append_audit("DELETE", {"key": key})

    def mark_stale(self, key: str) -> None:
        """Manually flag a node as stale."""
        with self._lock:
            if key in self._nodes:
                self._nodes[key].stale = True
                self._append_audit("STALE", {"key": key, "reason": "manual"})

    def _mark_children_stale(self, parent_key: str) -> None:
        """Recursively flag all descendants of *parent_key* as stale."""
        queue: List[str] = list(self._children.get(parent_key, set()))
        visited: Set[str] = set()
        while queue:
            child = queue.pop()
            if child in visited:
                continue
            visited.add(child)
            if child in self._nodes:
                self._nodes[child].stale = True
                self._append_audit(
                    "STALE",
                    {"key": child, "reason": f"parent_changed:{parent_key}"},
                )
            queue.extend(self._children.get(child, set()))

    # ------------------------------------------------------------------
    # Prerequisite / check helpers
    # ------------------------------------------------------------------

    def is_authorized(self, target: str) -> bool:
        """Return ``True`` if the target is in an authorized/active state.

        Checks ``scope.<target>.status`` and ``host.<target>.authorized``
        nodes.
        """
        with self._lock:
            for pattern in (
                f"scope.{target}.status",
                f"host.{target}.authorized",
            ):
                node = self._nodes.get(pattern)
                if node and not node.stale:
                    v = str(node.value).strip().lower()
                    if v in ("true", "authorized", "active", "in_scope", "yes", "1"):
                        return True
            return False

    def has_credentials(self, service: str) -> bool:
        """Return ``True`` if a non-stale credential exists for *service*."""
        prefix = f"credential.{service}."
        with self._lock:
            for key, node in self._nodes.items():
                if key.startswith(prefix) and not node.stale:
                    v = str(node.value).strip().lower()
                    if v not in ("", "none", "null", "false", "invalid", "0"):
                        return True
            return False

    def is_stale(self, key: str) -> bool:
        """Return ``True`` if the node is missing or marked stale."""
        with self._lock:
            node = self._nodes.get(key)
            return node is None or node.stale

    def search(self, prefix: str) -> Dict[str, Any]:
        """Return a dict of ``{key: value}`` for all nodes whose key starts
        with *prefix*."""
        with self._lock:
            return {
                k: n.value
                for k, n in self._nodes.items()
                if k.startswith(prefix)
            }

    # ------------------------------------------------------------------
    # Snapshotting
    # ------------------------------------------------------------------

    def snapshot(self) -> Path:
        """Serialise full engine state to JSON via PathGuard writer.

        Returns the resolved output path.  Designed to complete in well under
        10 ms for typical mission-sized state dicts (<10 000 nodes).
        """
        with self._lock:
            payload = {
                "snapshot_at": datetime.now(tz=UTC).isoformat(),
                "workspace": str(self.workspace_root),
                "nodes": {k: n.as_dict() for k, n in self._nodes.items()},
            }
            raw = json.dumps(payload, indent=2, default=str)
            self._writer.write_text(self._SNAPSHOT_REL, raw)
            out = (self.workspace_root / self._SNAPSHOT_REL).resolve()
            self._append_audit("SNAPSHOT", {"path": str(out), "count": len(self._nodes)})
            return out

    def load_snapshot(self, path: Optional[str] = None) -> int:
        """Restore nodes from a previously saved JSON snapshot.

        Returns the number of nodes loaded.
        """
        rel = path or self._SNAPSHOT_REL
        disk_path = (self.workspace_root / rel).resolve()
        if not disk_path.exists():
            return 0
        raw = disk_path.read_text(encoding="utf-8")
        data = json.loads(raw)
        count = 0
        with self._lock:
            for node_data in data.get("nodes", {}).values():
                key = node_data["key"]
                self._nodes[key] = LogicNode(
                    key=key,
                    value=node_data.get("value"),
                    stale=node_data.get("stale", False),
                    parent_keys=set(node_data.get("parent_keys", [])),
                    updated_at=node_data.get("updated_at", ""),
                    meta=node_data.get("meta", {}),
                )
                for parent_key in self._nodes[key].parent_keys:
                    self._children.setdefault(parent_key, set()).add(key)
                count += 1
        self._append_audit("LOAD_SNAPSHOT", {"path": str(disk_path), "count": count})
        return count

    # ------------------------------------------------------------------
    # LLM context injection
    # ------------------------------------------------------------------

    def get_active_context(
        self,
        *,
        limit: int = 20,
        include_stale: bool = False,
    ) -> str:
        """Return a Markdown table of the most critical non-stale nodes.

        The table is suitable for direct injection into an LLM system prompt
        to prevent context drift by surfacing factual state rather than
        conversation history.

        Parameters
        ----------
        limit:
            Maximum number of rows to include.
        include_stale:
            If ``True``, stale nodes are included with a ``[STALE]`` marker.
        """
        with self._lock:
            rows: List[LogicNode] = sorted(
                (
                    n
                    for n in self._nodes.values()
                    if include_stale or not n.stale
                ),
                key=lambda n: n.updated_at,
                reverse=True,
            )[:limit]

        if not rows:
            return "_No active logic nodes._\n"

        lines = [
            "| Key | Value | Stale | Updated |",
            "|-----|-------|-------|---------|",
        ]
        for node in rows:
            stale_marker = "yes" if node.stale else "no"
            val_repr = str(node.value)[:60]
            ts = node.updated_at[:19].replace("T", " ")
            lines.append(
                f"| `{node.key}` | {val_repr} | {stale_marker} | {ts} |"
            )
        return "\n".join(lines) + "\n"

    # ------------------------------------------------------------------
    # Audit helpers
    # ------------------------------------------------------------------

    def _append_audit(self, event: str, detail: Dict[str, Any]) -> None:
        ts = datetime.now(tz=UTC).isoformat(timespec="milliseconds")
        entry = json.dumps({"ts": ts, "event": event, **detail}, default=str)
        try:
            self._writer.append_text(self._audit_rel, entry)
        except Exception as exc:  # pragma: no cover
            _log.warning("[CerebroLogicEngine] audit write failed: %s", exc)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

_MISSING = object()


def _safe_repr(value: Any, max_len: int = 120) -> str:
    """Return a safe, abbreviated string representation of *value*."""
    if value is _MISSING:
        return "<absent>"
    try:
        raw = json.dumps(value, default=str)
    except Exception:
        raw = repr(value)
    return raw[:max_len] + ("…" if len(raw) > max_len else "")
