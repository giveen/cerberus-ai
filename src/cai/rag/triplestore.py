"""Lightweight SQLite triple-store for entity facts and contradiction detection.

This module provides a minimal, dependency-free TripleStore backed by
SQLite suitable for storing simple RDF-like triples and running quick
sanity/contradiction checks over recent facts.
"""
from __future__ import annotations

import sqlite3
import time
import json
from typing import Optional, Dict, Any, List


class TripleStore:
    def __init__(self, db_path: Optional[str] = ":memory:", pragmas: Optional[Dict[str, str]] = None):
        self.db_path = db_path or ":memory:"
        # allow easy use in tests by defaulting to in-memory
        self.conn = sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        self.conn.row_factory = sqlite3.Row
        # apply pragmas early if provided
        if pragmas:
            cur = self.conn.cursor()
            for k, v in pragmas.items():
                cur.execute(f"PRAGMA {k}={v}")
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS triples (
            id INTEGER PRIMARY KEY,
            subject TEXT NOT NULL,
            predicate TEXT NOT NULL,
            object TEXT,
            object_type TEXT,
            timestamp REAL,
            provenance TEXT,
            metadata TEXT
        )
        """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_triples_subject ON triples(subject)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_triples_pred ON triples(predicate)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_triples_object ON triples(object)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_triples_sp ON triples(subject, predicate)")
        self.conn.commit()

    def add_fact(
        self,
        subject: str,
        predicate: str,
        object: Optional[str],
        object_type: Optional[str] = None,
        timestamp: Optional[float] = None,
        provenance: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Insert a fact into the store and return the new row id."""
        ts = float(timestamp) if timestamp is not None else time.time()
        md = json.dumps(metadata or {}, ensure_ascii=False)
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO triples (subject, predicate, object, object_type, timestamp, provenance, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (subject, predicate, object, object_type, ts, provenance, md),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        try:
            d["metadata"] = json.loads(d.get("metadata") or "{}")
        except Exception:
            d["metadata"] = {}
        return d

    def query(
        self,
        subject: Optional[str] = None,
        predicate: Optional[str] = None,
        object: Optional[str] = None,
        limit: Optional[int] = None,
        order_by_timestamp: bool = False,
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM triples WHERE 1=1"
        params: List[Any] = []
        if subject is not None:
            sql += " AND subject = ?"
            params.append(subject)
        if predicate is not None:
            sql += " AND predicate = ?"
            params.append(predicate)
        if object is not None:
            sql += " AND object = ?"
            params.append(object)
        if order_by_timestamp:
            sql += " ORDER BY timestamp DESC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(int(limit))
        cur = self.conn.cursor()
        cur.execute(sql, tuple(params))
        rows = cur.fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_facts_for_entity(self, entity: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM triples WHERE subject = ? OR object = ?"
        params: List[Any] = [entity, entity]
        if limit is not None:
            sql += " LIMIT ?"
            params.append(int(limit))
        cur = self.conn.cursor()
        cur.execute(sql, tuple(params))
        rows = cur.fetchall()
        return [self._row_to_dict(r) for r in rows]

    def latest_fact(self, subject: str, predicate: str) -> Optional[Dict[str, Any]]:
        res = self.query(subject=subject, predicate=predicate, order_by_timestamp=True, limit=1)
        return res[0] if res else None

    def detect_contradictions(
        self,
        subject: Optional[str] = None,
        predicate: Optional[str] = None,
        window_seconds: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Return groups where the same (subject,predicate) has multiple distinct object values.

        Each returned dict contains: subject, predicate, objects (distinct values), facts (list of rows), and a simple 'type'
        that can be 'boolean_contradiction' or 'value_mismatch'.
        """
        sql = "SELECT subject, predicate, COUNT(DISTINCT object) as n FROM triples WHERE 1=1"
        params: List[Any] = []
        now = time.time()
        if window_seconds is not None:
            cutoff = now - float(window_seconds)
            sql += " AND timestamp >= ?"
            params.append(cutoff)
        if subject is not None:
            sql += " AND subject = ?"
            params.append(subject)
        if predicate is not None:
            sql += " AND predicate = ?"
            params.append(predicate)
        sql += " GROUP BY subject, predicate HAVING n > 1"

        cur = self.conn.cursor()
        cur.execute(sql, tuple(params))
        groups = cur.fetchall()
        out: List[Dict[str, Any]] = []
        for g in groups:
            s = g["subject"]
            p = g["predicate"]
            cur2 = self.conn.cursor()
            cur2.execute("SELECT * FROM triples WHERE subject = ? AND predicate = ? ORDER BY timestamp DESC", (s, p))
            rows = cur2.fetchall()
            objs: List[Any] = []
            facts: List[Dict[str, Any]] = []
            for r in rows:
                objs.append(r["object"])
                facts.append(self._row_to_dict(r))
            # preserve order but make distinct
            distinct_objs = list(dict.fromkeys(objs))
            norm = [str(o).strip().lower() if o is not None else "" for o in distinct_objs]
            true_vals = {"true", "1", "yes", "y", "t"}
            false_vals = {"false", "0", "no", "n", "f"}
            if any(v in true_vals for v in norm) and any(v in false_vals for v in norm):
                ctype = "boolean_contradiction"
            else:
                ctype = "value_mismatch"
            out.append({"subject": s, "predicate": p, "objects": distinct_objs, "facts": facts, "type": ctype})

        return out

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass


__all__ = ["TripleStore"]
