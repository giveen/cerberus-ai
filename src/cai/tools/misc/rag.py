"""Cerebro Semantic Retrieval Engine.

This module provides a production-oriented RAG tool with:
- Hybrid retrieval (vector similarity + BM25 keyword scoring)
- Dynamic knowledge-base switching (security/workspace/cve)
- Actionability-aware reranking
- Incremental workspace indexing with smart chunking
- Source attribution/citations on every result
- Privacy-aware embedding provider selection
- Async streaming retrieval for low time-to-first-thought
"""

from __future__ import annotations

import asyncio
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import threading
import time
from typing import Any, AsyncGenerator, Dict, Iterable, List, Optional, Sequence
from urllib import request as urllib_request

from cai.memory.logic import clean_data
from cai.repl.commands.config import CONFIG_STORE
from cai.repl.ui.logging import get_cerebro_logger
from cai.sdk.agents import function_tool
from cai.tools.workspace import get_project_space

KB_SECURITY = "KB_SECURITY"
KB_WORKSPACE = "KB_WORKSPACE"
KB_CVE = "KB_CVE"
_ALL_KBS = (KB_SECURITY, KB_WORKSPACE, KB_CVE)

_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-:\.]{2,}")
_CODE_FENCE_RE = re.compile(r"```[\s\S]*?```", re.MULTILINE)
_PATH_EXT_ALLOW = {
    ".txt",
    ".md",
    ".rst",
    ".log",
    ".json",
    ".yaml",
    ".yml",
    ".csv",
    ".py",
    ".js",
    ".ts",
    ".go",
    ".rs",
    ".sh",
    ".conf",
}


@dataclass
class RetrievedSnippet:
    id: str
    kb: str
    score: float
    text: str
    citation: str
    source_type: str
    timestamp: str
    vector_score: float
    bm25_score: float
    rerank_score: float


@dataclass
class ChunkRecord:
    id: str
    kb: str
    text: str
    citation: str
    source_type: str
    timestamp: str
    metadata: Dict[str, Any]
    embedding: List[float]


class CerebroRAGTool:
    """Hybrid semantic retrieval engine with workspace-native indexing."""

    def __init__(self) -> None:
        self._workspace = get_project_space().ensure_initialized().resolve()
        self._root = (self._workspace / ".cai" / "rag_engine").resolve()
        self._root.mkdir(parents=True, exist_ok=True)

        self._stores = {
            KB_SECURITY: self._root / "kb_security.jsonl",
            KB_WORKSPACE: self._root / "kb_workspace.jsonl",
            KB_CVE: self._root / "kb_cve.jsonl",
        }
        self._index_state_path = self._root / "workspace_index_state.json"
        self._cache: Dict[str, List[ChunkRecord]] = {kb: [] for kb in _ALL_KBS}
        self._cache_loaded = False
        self._cache_lock = threading.Lock()

        self._logger = get_cerebro_logger()
        self._bg_stop = threading.Event()
        self._bg_thread: Optional[threading.Thread] = None
        self._start_background_indexer()

    # ---------------------------------------------------------------------
    # Public APIs
    # ---------------------------------------------------------------------

    async def query(
        self,
        *,
        query: str,
        top_k: int = 5,
        kb: Optional[str] = None,
    ) -> Dict[str, Any]:
        await self._incremental_index_async()
        self._load_caches_if_needed()

        if not query.strip():
            return {"ok": False, "error": "query cannot be empty", "results": []}

        target_kbs = self._resolve_kbs(kb)
        all_rows: List[ChunkRecord] = []
        with self._cache_lock:
            for name in target_kbs:
                all_rows.extend(self._cache.get(name, []))

        if not all_rows:
            return {"ok": True, "results": [], "kb": target_kbs, "query": query}

        query_embedding = await self._embed_text(query)
        bm25_scores = self._bm25_scores(query, all_rows)

        ranked: List[RetrievedSnippet] = []
        for row in all_rows:
            vscore = self._cosine_similarity(query_embedding, row.embedding)
            bscore = bm25_scores.get(row.id, 0.0)
            hybrid = (0.62 * vscore) + (0.38 * self._normalize_bm25(bscore, bm25_scores))
            rerank = self._actionability_boost(row.text, query)
            final = hybrid + rerank

            ranked.append(
                RetrievedSnippet(
                    id=row.id,
                    kb=row.kb,
                    score=final,
                    text=row.text,
                    citation=row.citation,
                    source_type=row.source_type,
                    timestamp=row.timestamp,
                    vector_score=vscore,
                    bm25_score=bscore,
                    rerank_score=rerank,
                )
            )

        ranked.sort(key=lambda x: x.score, reverse=True)
        selected = ranked[: max(1, int(top_k))]

        payload = {
            "ok": True,
            "query": query,
            "kb": target_kbs,
            "results": [asdict(item) for item in selected],
            "retrieval_mode": "hybrid_vector_bm25_rerank",
        }
        self._audit("rag.query", payload)
        return clean_data(payload)

    async def stream_query(
        self,
        *,
        query: str,
        top_k: int = 5,
        kb: Optional[str] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        result = await self.query(query=query, top_k=top_k, kb=kb)
        for item in result.get("results", []):
            yield {"type": "chunk", "data": item}
            await asyncio.sleep(0)
        yield {"type": "done", "count": len(result.get("results", []))}

    async def add_text(
        self,
        *,
        text: str,
        kb: str,
        source_type: str,
        citation: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        target_kb = self._normalize_kb(kb)
        chunks = self._smart_chunk(text)
        if not chunks:
            return {"ok": False, "error": "no chunks generated"}

        created: List[ChunkRecord] = []
        for index, chunk in enumerate(chunks):
            embedding = await self._embed_text(chunk)
            stamp = datetime.now(tz=UTC).isoformat()
            chunk_id = self._chunk_id(target_kb, chunk, citation, index)
            row = ChunkRecord(
                id=chunk_id,
                kb=target_kb,
                text=chunk,
                citation=citation,
                source_type=source_type,
                timestamp=stamp,
                metadata=metadata or {},
                embedding=embedding,
            )
            created.append(row)

        self._append_records(target_kb, created)
        self._audit(
            "rag.add",
            {
                "kb": target_kb,
                "count": len(created),
                "source_type": source_type,
                "citation": citation,
            },
        )
        return clean_data({"ok": True, "kb": target_kb, "added": len(created), "citation": citation})

    def stop(self) -> None:
        self._bg_stop.set()

    # ---------------------------------------------------------------------
    # Incremental indexing
    # ---------------------------------------------------------------------

    async def _incremental_index_async(self) -> None:
        await asyncio.to_thread(self._incremental_index_sync)

    def _incremental_index_sync(self) -> None:
        state = self._load_index_state()
        changed_files: List[Path] = []

        watch_roots = [
            self._workspace / "work",
            self._workspace / "logs",
            self._workspace / "artifacts",
            self._workspace / "findings",
            self._workspace / "evidence",
        ]

        for root in watch_roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                if path.suffix.lower() not in _PATH_EXT_ALLOW:
                    continue
                try:
                    stat = path.stat()
                except OSError:
                    continue
                if stat.st_size > 1_500_000:
                    continue
                key = str(path.resolve())
                mtime = int(stat.st_mtime)
                if int(state.get(key, 0)) < mtime:
                    changed_files.append(path)
                    state[key] = mtime

        if not changed_files:
            self._save_index_state(state)
            return

        for path in changed_files:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            if not text.strip():
                continue

            # Synchronous safe bridge for indexing in background thread.
            payload = self._run_coro_sync(
                self.add_text(
                    text=text,
                    kb=KB_WORKSPACE,
                    source_type="workspace_artifact",
                    citation=str(path.resolve().relative_to(self._workspace)),
                    metadata={"path": str(path.resolve()), "indexed_via": "incremental_indexing"},
                )
            )
            _ = payload

        self._save_index_state(state)

    def _start_background_indexer(self) -> None:
        if self._bg_thread and self._bg_thread.is_alive():
            return

        def _worker() -> None:
            while not self._bg_stop.is_set():
                try:
                    self._incremental_index_sync()
                except Exception:
                    pass
                self._bg_stop.wait(12.0)

        self._bg_thread = threading.Thread(target=_worker, name="cerebro-rag-indexer", daemon=True)
        self._bg_thread.start()

    # ---------------------------------------------------------------------
    # Store and cache handling
    # ---------------------------------------------------------------------

    def _load_caches_if_needed(self) -> None:
        if self._cache_loaded:
            return
        with self._cache_lock:
            if self._cache_loaded:
                return
            for kb, path in self._stores.items():
                rows: List[ChunkRecord] = []
                if path.exists():
                    with path.open("r", encoding="utf-8") as handle:
                        for line in handle:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                payload = json.loads(line)
                                rows.append(
                                    ChunkRecord(
                                        id=str(payload["id"]),
                                        kb=str(payload["kb"]),
                                        text=str(payload["text"]),
                                        citation=str(payload.get("citation", "")),
                                        source_type=str(payload.get("source_type", "unknown")),
                                        timestamp=str(payload.get("timestamp", "")),
                                        metadata=dict(payload.get("metadata") or {}),
                                        embedding=[float(x) for x in (payload.get("embedding") or [])],
                                    )
                                )
                            except Exception:
                                continue
                self._cache[kb] = rows
            self._cache_loaded = True

    def _append_records(self, kb: str, records: Sequence[ChunkRecord]) -> None:
        self._load_caches_if_needed()
        path = self._stores[kb]
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("a", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(asdict(record), ensure_ascii=True, default=str) + "\n")

        with self._cache_lock:
            known = {r.id for r in self._cache.get(kb, [])}
            for record in records:
                if record.id in known:
                    continue
                self._cache[kb].append(record)

    # ---------------------------------------------------------------------
    # Retrieval internals
    # ---------------------------------------------------------------------

    def _resolve_kbs(self, kb: Optional[str]) -> List[str]:
        if kb is None or str(kb).strip().lower() in {"", "all", "_all_"}:
            return [KB_WORKSPACE, KB_SECURITY, KB_CVE]
        return [self._normalize_kb(kb)]

    def _normalize_kb(self, kb: str) -> str:
        candidate = str(kb).strip().upper()
        if candidate in _ALL_KBS:
            return candidate
        if candidate in {"WORKSPACE", "KB_WORK"}:
            return KB_WORKSPACE
        if candidate in {"SECURITY", "BEST_PRACTICES"}:
            return KB_SECURITY
        if candidate in {"CVE", "VULNS"}:
            return KB_CVE
        return KB_WORKSPACE

    @staticmethod
    def _tokens(text: str) -> List[str]:
        return [token.lower() for token in _TOKEN_RE.findall(text or "")]

    def _bm25_scores(self, query: str, rows: Sequence[ChunkRecord]) -> Dict[str, float]:
        tokens_q = self._tokens(query)
        if not tokens_q:
            return {row.id: 0.0 for row in rows}

        tokenized_docs = [self._tokens(row.text) for row in rows]
        doc_len = [len(doc) for doc in tokenized_docs]
        avgdl = (sum(doc_len) / len(doc_len)) if doc_len else 1.0

        df: Dict[str, int] = defaultdict(int)
        for doc in tokenized_docs:
            for token in set(doc):
                df[token] += 1

        scores: Dict[str, float] = {}
        k1 = 1.2
        b = 0.75

        for row, doc_tokens in zip(rows, tokenized_docs):
            tf = Counter(doc_tokens)
            score = 0.0
            for term in tokens_q:
                if term not in tf:
                    continue
                n_q = df.get(term, 0)
                idf = math.log(1 + ((len(rows) - n_q + 0.5) / (n_q + 0.5)))
                numer = tf[term] * (k1 + 1)
                denom = tf[term] + k1 * (1 - b + b * ((len(doc_tokens) / avgdl) if avgdl else 1.0))
                score += idf * (numer / denom)
            scores[row.id] = score

        return scores

    @staticmethod
    def _normalize_bm25(raw: float, table: Dict[str, float]) -> float:
        if not table:
            return 0.0
        max_v = max(table.values())
        if max_v <= 0:
            return 0.0
        return raw / max_v

    @staticmethod
    def _cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
        if not a or not b:
            return 0.0
        n = min(len(a), len(b))
        dot = sum(a[i] * b[i] for i in range(n))
        na = math.sqrt(sum(a[i] * a[i] for i in range(n)))
        nb = math.sqrt(sum(b[i] * b[i] for i in range(n)))
        if na == 0.0 or nb == 0.0:
            return 0.0
        return max(0.0, min(1.0, dot / (na * nb)))

    @staticmethod
    def _actionability_boost(text: str, query: str) -> float:
        lower = text.lower()
        q = query.lower()
        boost = 0.0

        if "```" in text:
            boost += 0.14
        if any(word in lower for word in ("exploit", "payload", "proof of concept", "poc", "mitigation", "patch", "steps")):
            boost += 0.12
        if re.search(r"\bcve-\d{4}-\d{4,}\b", lower):
            boost += 0.10
        if any(term in lower for term in ("def ", "class ", "import ", "curl ", "nmap ", "ssh ")):
            boost += 0.09
        if q and q in lower:
            boost += 0.08
        return boost

    # ---------------------------------------------------------------------
    # Embeddings
    # ---------------------------------------------------------------------

    async def _embed_text(self, text: str) -> List[float]:
        provider = self._choose_embedding_provider()
        if provider == "openai":
            vec = await self._embed_openai(text)
            if vec:
                return vec
        elif provider == "ollama":
            vec = await self._embed_ollama(text)
            if vec:
                return vec
        elif provider == "huggingface":
            vec = await self._embed_hf_local(text)
            if vec:
                return vec
        return self._embed_local_hash(text)

    def _choose_embedding_provider(self) -> str:
        privacy = self._is_privacy_mode()
        requested = os.getenv("CEREBRO_RAG_EMBEDDINGS_PROVIDER", "").strip().lower()

        if privacy:
            if requested in {"huggingface", "hf"}:
                return "huggingface"
            return "local"

        if requested in {"openai", "ollama", "huggingface", "hf", "local"}:
            return "huggingface" if requested in {"huggingface", "hf"} else requested

        if os.getenv("OPENAI_API_KEY", "").strip():
            return "openai"
        if os.getenv("CEREBRO_OLLAMA_URL", "").strip() or os.getenv("OLLAMA_HOST", "").strip():
            return "ollama"
        return "local"

    def _is_privacy_mode(self) -> bool:
        env_flag = os.getenv("CEREBRO_PRIVACY_MODE", "").strip().lower()
        if env_flag in {"1", "true", "yes", "on"}:
            return True
        try:
            value, _tier = CONFIG_STORE.resolve("CEREBRO_PRIVACY_MODE")
            return str(value).strip().lower() in {"1", "true", "yes", "on"}
        except Exception:
            return False

    async def _embed_openai(self, text: str) -> Optional[List[float]]:
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            return None

        endpoint = os.getenv(
            "OPENAI_EMBEDDINGS_URL",
            os.getenv("CEREBRO_API_BASE", "http://localhost:8000/v1").rstrip("/") + "/embeddings",
        )
        model = os.getenv("CEREBRO_RAG_OPENAI_EMBED_MODEL", "text-embedding-3-small")
        payload = json.dumps({"model": model, "input": text}).encode("utf-8")
        req = urllib_request.Request(endpoint, data=payload, method="POST")
        req.add_header("Authorization", f"Bearer {api_key}")
        req.add_header("Content-Type", "application/json")

        try:
            return await asyncio.to_thread(self._http_embedding_request, req)
        except Exception:
            return None

    async def _embed_ollama(self, text: str) -> Optional[List[float]]:
        base = os.getenv("CEREBRO_OLLAMA_URL", "").strip() or os.getenv("OLLAMA_HOST", "").strip() or "http://127.0.0.1:11434"
        endpoint = base.rstrip("/") + "/api/embeddings"
        model = os.getenv("CEREBRO_RAG_OLLAMA_MODEL", "bge-small")
        payload = json.dumps({"model": model, "prompt": text}).encode("utf-8")
        req = urllib_request.Request(endpoint, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")

        try:
            return await asyncio.to_thread(self._http_embedding_request_ollama, req)
        except Exception:
            return None

    async def _embed_hf_local(self, text: str) -> Optional[List[float]]:
        # Best-effort local huggingface mode; no hard dependency.
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore

            model_name = os.getenv("CEREBRO_RAG_HF_MODEL", "BAAI/bge-small-en-v1.5")
            model = SentenceTransformer(model_name)
            vec = model.encode([text], normalize_embeddings=True)
            return [float(x) for x in vec[0].tolist()]
        except Exception:
            return None

    @staticmethod
    def _http_embedding_request(req: urllib_request.Request) -> Optional[List[float]]:
        with urllib_request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
            data = payload.get("data") or []
            if not data:
                return None
            vec = data[0].get("embedding") or []
            return [float(x) for x in vec]

    @staticmethod
    def _http_embedding_request_ollama(req: urllib_request.Request) -> Optional[List[float]]:
        with urllib_request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
            vec = payload.get("embedding") or []
            return [float(x) for x in vec]

    @staticmethod
    def _embed_local_hash(text: str, dims: int = 256) -> List[float]:
        vec = [0.0] * dims
        tokens = _TOKEN_RE.findall(text.lower())
        if not tokens:
            return vec

        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            idx = int.from_bytes(digest[:4], "big") % dims
            sign = 1.0 if (digest[4] % 2 == 0) else -1.0
            vec[idx] += sign

        norm = math.sqrt(sum(x * x for x in vec))
        if norm > 0:
            vec = [x / norm for x in vec]
        return vec

    # ---------------------------------------------------------------------
    # Smart chunking
    # ---------------------------------------------------------------------

    def _smart_chunk(self, text: str, max_chars: int = 1200) -> List[str]:
        normalized = text.replace("\r\n", "\n")
        if not normalized.strip():
            return []

        chunks: List[str] = []
        cursor = 0

        for fence in _CODE_FENCE_RE.finditer(normalized):
            before = normalized[cursor : fence.start()]
            chunks.extend(self._chunk_non_code(before, max_chars=max_chars))
            code_block = fence.group(0).strip()
            if code_block:
                chunks.append(code_block)
            cursor = fence.end()

        tail = normalized[cursor:]
        chunks.extend(self._chunk_non_code(tail, max_chars=max_chars))

        final_chunks: List[str] = []
        for chunk in chunks:
            trimmed = chunk.strip()
            if not trimmed:
                continue
            if len(trimmed) <= max_chars:
                final_chunks.append(trimmed)
                continue
            final_chunks.extend(self._hard_wrap(trimmed, max_chars=max_chars))
        return final_chunks

    def _chunk_non_code(self, text: str, max_chars: int) -> List[str]:
        blocks = [b.strip() for b in re.split(r"\n\s*\n", text) if b.strip()]
        if not blocks:
            return []

        out: List[str] = []
        current: List[str] = []
        length = 0
        for block in blocks:
            # Prefer technical boundaries: headings, function/class starts.
            boundary = block.startswith("#") or block.startswith("def ") or block.startswith("class ")
            block_len = len(block)

            if current and (length + block_len + 2 > max_chars or boundary):
                out.append("\n\n".join(current))
                current = []
                length = 0

            current.append(block)
            length += block_len + 2

        if current:
            out.append("\n\n".join(current))
        return out

    @staticmethod
    def _hard_wrap(text: str, max_chars: int) -> List[str]:
        words = text.split()
        out: List[str] = []
        current: List[str] = []
        size = 0
        for word in words:
            extra = len(word) + (1 if current else 0)
            if current and size + extra > max_chars:
                out.append(" ".join(current))
                current = [word]
                size = len(word)
            else:
                current.append(word)
                size += extra
        if current:
            out.append(" ".join(current))
        return out

    # ---------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------

    @staticmethod
    def _chunk_id(kb: str, chunk: str, citation: str, index: int) -> str:
        raw = f"{kb}|{citation}|{index}|{chunk}".encode("utf-8", errors="ignore")
        return hashlib.sha256(raw).hexdigest()[:24]

    def _load_index_state(self) -> Dict[str, int]:
        if not self._index_state_path.exists():
            return {}
        try:
            payload = json.loads(self._index_state_path.read_text(encoding="utf-8"))
            return {str(k): int(v) for k, v in dict(payload).items()}
        except Exception:
            return {}

    def _save_index_state(self, state: Dict[str, int]) -> None:
        self._index_state_path.parent.mkdir(parents=True, exist_ok=True)
        self._index_state_path.write_text(json.dumps(state, ensure_ascii=True, indent=2), encoding="utf-8")

    def _audit(self, event: str, data: Dict[str, Any]) -> None:
        payload = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "event": event,
            "data": clean_data(data),
        }
        audit_file = self._root / "rag_audit.jsonl"
        with audit_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=True, default=str) + "\n")

        if self._logger is not None:
            try:
                self._logger.audit("RAG event", actor="rag", data=payload, tags=["rag", event])
            except Exception:
                pass

    def _run_coro_sync(self, coro: Any) -> Any:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)

        holder: Dict[str, Any] = {}
        failure: Dict[str, BaseException] = {}

        def _runner() -> None:
            try:
                holder["value"] = asyncio.run(coro)
            except BaseException as exc:  # pragma: no cover
                failure["error"] = exc

        thread = threading.Thread(target=_runner, daemon=True)
        thread.start()
        thread.join()

        if "error" in failure:
            raise RuntimeError("rag sync bridge failed") from failure["error"]
        return holder.get("value")


RAG_TOOL = CerebroRAGTool()


def _format_query_result(payload: Dict[str, Any], top_k: int) -> str:
    if not payload.get("ok"):
        return f"Error querying memory: {payload.get('error', 'unknown error')}"

    items = payload.get("results") or []
    if not items:
        return "No documents found in memory."

    lines: List[str] = []
    for row in items[: max(1, int(top_k))]:
        text = str(row.get("text", "")).strip()
        citation = str(row.get("citation", "unknown"))
        kb = str(row.get("kb", ""))
        lines.append(f"- [{kb}] {text} (citation: {citation})")
    return "\n".join(lines)


@function_tool
def query_memory(query: str, top_k: int = 3, kb: str = "all") -> str:
    """Query hybrid RAG memory across one or more knowledge bases."""
    result = RAG_TOOL._run_coro_sync(RAG_TOOL.query(query=query, top_k=top_k, kb=kb))
    return _format_query_result(result, top_k=top_k)


@function_tool
def add_to_memory_episodic(texts: str, step: int = 0) -> str:
    """Add engagement-local episodic knowledge into KB_WORKSPACE."""
    citation = f"workspace:episodic:step:{step}:{int(time.time())}"
    payload = RAG_TOOL._run_coro_sync(
        RAG_TOOL.add_text(
            text=texts,
            kb=KB_WORKSPACE,
            source_type="episodic",
            citation=citation,
            metadata={"step": step, "kind": "episodic"},
        )
    )
    if payload.get("ok"):
        return f"Added {payload.get('added', 0)} chunk(s) to {payload.get('kb')}"
    return f"Error adding documents to vector database: {payload.get('error', 'unknown error')}"


@function_tool
def add_to_memory_semantic(texts: str, step: int = 0) -> str:
    """Add generalized semantic knowledge into KB_SECURITY."""
    citation = f"security:semantic:step:{step}:{int(time.time())}"
    payload = RAG_TOOL._run_coro_sync(
        RAG_TOOL.add_text(
            text=texts,
            kb=KB_SECURITY,
            source_type="semantic",
            citation=citation,
            metadata={"step": step, "kind": "semantic"},
        )
    )
    if payload.get("ok"):
        return f"Added {payload.get('added', 0)} chunk(s) to {payload.get('kb')}"
    return f"Error adding documents to vector database: {payload.get('error', 'unknown error')}"


__all__ = [
    "CerebroRAGTool",
    "KB_SECURITY",
    "KB_WORKSPACE",
    "KB_CVE",
    "query_memory",
    "add_to_memory_episodic",
    "add_to_memory_semantic",
]
