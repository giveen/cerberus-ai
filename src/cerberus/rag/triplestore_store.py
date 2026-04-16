"""Global accessor for a singleton TripleStore instance.

Provides a `get_global_triplestore()` factory so different parts of
the application can share a single TripleStore without tight coupling
or circular imports.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cerberus.rag.triplestore import TripleStore


_GLOBAL_TRIPLESTORE: Optional[TripleStore] = None


def _default_triplestore_path() -> str:
    return os.environ.get("CERBERUS_TRIPLESTORE_PATH") or str(Path.cwd() / ".cerberus" / "triplestore.db")


def get_global_triplestore(db_path: Optional[str] = None, pragmas: Optional[Dict[str, str]] = None) -> TripleStore:
    """Return a singleton TripleStore, creating it on first use.

    If `db_path` is not provided the function will consult the
    `CERBERUS_TRIPLESTORE_PATH` env var, falling back to `.cerberus/triplestore.db`.
    The directory will be created if necessary. If disk-backed store
    cannot be opened, a memory-backed TripleStore is used as a fallback.
    """
    global _GLOBAL_TRIPLESTORE
    if _GLOBAL_TRIPLESTORE is None:
        path = db_path or _default_triplestore_path()
        # ensure directory exists for on-disk DB
        dirpath = Path(path).parent
        if dirpath and not dirpath.exists():
            try:
                dirpath.mkdir(parents=True, exist_ok=True)
            except Exception:
                # best-effort: ignore failures and let TripleStore fall back
                pass
        try:
            _GLOBAL_TRIPLESTORE = TripleStore(db_path=path, pragmas=pragmas)
        except Exception:
            _GLOBAL_TRIPLESTORE = TripleStore()
    return _GLOBAL_TRIPLESTORE


def set_global_triplestore(ts: TripleStore) -> None:
    """Replace the global TripleStore (useful for tests)."""
    global _GLOBAL_TRIPLESTORE
    _GLOBAL_TRIPLESTORE = ts


# ---------------------------------------------------------------------------
# CerebroRAMTripleStore — pure in-memory knowledge graph
# ---------------------------------------------------------------------------
import threading


class CerebroRAMTripleStore:
    """RAM-resident knowledge graph for sub-millisecond traversal.

    Stores the full graph in Python dicts backed by the 256 GB RAM budget.
    Supports BFS path enumeration and credential-reuse detection without
    any disk I/O.  Thread-safe via a single ``threading.RLock``.
    """

    def __init__(self) -> None:
        # forward index:   subject -> {predicate -> [objects]}
        self._fwd: Dict[str, Dict[str, List[str]]] = {}
        # reverse index:   object  -> {predicate -> [subjects]}
        self._rev: Dict[str, Dict[str, List[str]]] = {}
        self._lock = threading.RLock()
        self._triple_count: int = 0

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add(self, subject: str, predicate: str, obj: str) -> None:
        """Insert a triple (subject, predicate, object). Idempotent."""
        with self._lock:
            fwd_objs = self._fwd.setdefault(subject, {}).setdefault(predicate, [])
            if obj not in fwd_objs:
                fwd_objs.append(obj)
                self._rev.setdefault(obj, {}).setdefault(predicate, []).append(subject)
                self._triple_count += 1

    def remove(self, subject: str, predicate: str, obj: str) -> bool:
        """Remove a triple. Returns True if it existed."""
        with self._lock:
            try:
                self._fwd[subject][predicate].remove(obj)
                self._rev[obj][predicate].remove(subject)
                self._triple_count -= 1
                return True
            except (KeyError, ValueError):
                return False

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def query(
        self,
        subject: Optional[str] = None,
        predicate: Optional[str] = None,
        obj: Optional[str] = None,
    ) -> List[Tuple[str, str, str]]:
        """Pattern-match triples; ``None`` acts as a wildcard."""
        results: List[Tuple[str, str, str]] = []
        with self._lock:
            subjects = [subject] if subject is not None else list(self._fwd.keys())
            for s in subjects:
                preds = self._fwd.get(s, {})
                predicates = [predicate] if predicate is not None else list(preds.keys())
                for p in predicates:
                    objects = preds.get(p, [])
                    if obj is not None:
                        if obj in objects:
                            results.append((s, p, obj))
                    else:
                        for o in objects:
                            results.append((s, p, o))
        return results

    def neighbors(self, subject: str, predicate: Optional[str] = None) -> List[str]:
        """Return all objects reachable from ``subject`` (optionally via ``predicate``)."""
        with self._lock:
            preds = self._fwd.get(subject, {})
            if predicate:
                return list(preds.get(predicate, []))
            return [o for objs in preds.values() for o in objs]

    # ------------------------------------------------------------------
    # Security-domain traversal helpers
    # ------------------------------------------------------------------

    def find_lateral_paths(
        self,
        start: str,
        max_depth: int = 5,
        predicate_filter: Optional[List[str]] = None,
    ) -> List[List[str]]:
        """BFS from ``start`` returning all reachable paths up to ``max_depth``.

        Useful for enumerating lateral movement chains, e.g.::

            host -> service -> credential -> host

        If ``predicate_filter`` is provided, only edges with matching
        predicates are traversed.
        """
        paths: List[List[str]] = []
        queue: List[Tuple[str, List[str]]] = [(start, [start])]
        visited: set = set()
        while queue:
            node, path = queue.pop(0)
            state = (node, len(path))
            if state in visited:
                continue
            visited.add(state)
            if len(path) > 1:
                paths.append(list(path))
            if len(path) >= max_depth + 1:
                continue
            with self._lock:
                preds = dict(self._fwd.get(node, {}))
            for pred, objs in preds.items():
                if predicate_filter and pred not in predicate_filter:
                    continue
                for o in objs:
                    if o not in path:
                        queue.append((o, path + [o]))
        return paths

    def find_credential_reuse(self) -> Dict[str, List[str]]:
        """Return credentials reused across multiple hosts.

        A credential is considered reused if it appears as the object of a
        ``HAS_CREDENTIAL`` edge from two or more distinct subjects.
        """
        cred_to_hosts: Dict[str, List[str]] = {}
        for s, p, o in self.query(predicate="HAS_CREDENTIAL"):
            cred_to_hosts.setdefault(o, []).append(s)
        return {c: hosts for c, hosts in cred_to_hosts.items() if len(hosts) > 1}

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def snapshot(self) -> Dict:
        """Return a JSON-serialisable snapshot of the graph."""
        with self._lock:
            return {
                "fwd": {s: {p: list(ol) for p, ol in pd.items()} for s, pd in self._fwd.items()},
                "rev": {o: {p: list(sl) for p, sl in pd.items()} for o, pd in self._rev.items()},
                "triple_count": self._triple_count,
            }

    def load_snapshot(self, data: Dict) -> None:
        """Restore graph state from a snapshot dict (replaces current state)."""
        with self._lock:
            self._fwd = {s: {p: list(ol) for p, ol in pd.items()} for s, pd in data.get("fwd", {}).items()}
            self._rev = {o: {p: list(sl) for p, sl in pd.items()} for o, pd in data.get("rev", {}).items()}
            self._triple_count = int(data.get("triple_count", 0))

    @property
    def triple_count(self) -> int:
        with self._lock:
            return self._triple_count


__all__ = ["get_global_triplestore", "set_global_triplestore", "CerebroRAMTripleStore"]
