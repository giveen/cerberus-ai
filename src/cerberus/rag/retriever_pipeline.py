"""Hybrid retrieval pipeline: dense + BM25 + optional reranker.

Provides lightweight, dependency-free implementations suitable for
local development and benchmarking. The pipeline composes:
- Dense retriever (wraps VectorDBAdapter.search)
- Sparse BM25 retriever (internal simple BM25 or `rank_bm25` if present)
- Reciprocal Rank Fusion combiner
- Optional reranker using embeddings-based cosine similarity
"""
from __future__ import annotations

import math
import re
import os
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from cerberus.rag.vector_db_adapter import VectorDBAdapter


def _tokenize(text: str) -> List[str]:
    return [t for t in re.findall(r"\w+", (text or "").lower())]


class DenseRetriever:
    def __init__(self, adapter: VectorDBAdapter, collection_name: str = "_all_"):
        self.adapter = adapter
        self.collection_name = collection_name

    def retrieve(self, query: str, top_k: int = 10) -> List[Dict[str, Any]]:
        # Delegate to adapter.search which may use embeddings internally
        res = self.adapter.search(collection_name=self.collection_name, query_text=query, limit=top_k)
        # Normalize into list of dicts if needed
        if isinstance(res, dict):
            return [res]
        if isinstance(res, str):
            return [{"id": None, "text": res, "metadata": {}, "score": None}]
        return list(res)


class SimpleBM25:
    def __init__(self, docs: List[Dict[str, Any]]):
        # docs: list of {id,text,metadata}
        self.docs = docs
        self.corpus_tokens = [ _tokenize(d.get("text", "")) for d in docs ]
        self.N = len(self.docs)
        self.avgdl = sum(len(toks) for toks in self.corpus_tokens) / max(1, self.N)
        self.k1 = 1.5
        self.b = 0.75
        # DF and term frequencies
        self.df: Dict[str, int] = {}
        self.tf: List[Dict[str, int]] = []
        for toks in self.corpus_tokens:
            freqs: Dict[str, int] = {}
            for t in toks:
                freqs[t] = freqs.get(t, 0) + 1
            self.tf.append(freqs)
            for t in freqs.keys():
                self.df[t] = self.df.get(t, 0) + 1

    def _idf(self, term: str) -> float:
        # BM25 idf with slight smoothing
        n_q = self.df.get(term, 0)
        return math.log(1 + (self.N - n_q + 0.5) / (n_q + 0.5))

    def score(self, query: str, idx: int) -> float:
        qterms = _tokenize(query)
        score = 0.0
        dl = len(self.corpus_tokens[idx])
        freqs = self.tf[idx]
        for term in qterms:
            if term not in freqs:
                continue
            idf = self._idf(term)
            f = freqs[term]
            denom = f + self.k1 * (1 - self.b + self.b * dl / self.avgdl)
            score += idf * (f * (self.k1 + 1)) / denom
        return float(score)

    def retrieve(self, query: str, top_k: int = 10) -> List[Dict[str, Any]]:
        if self.N == 0:
            return []
        scores = []
        for i in range(self.N):
            sc = self.score(query, i)
            scores.append((sc, i))
        scores.sort(key=lambda x: x[0], reverse=True)
        out = []
        for sc, i in scores[:top_k]:
            d = self.docs[i]
            out.append({"id": d.get("id"), "text": d.get("text"), "metadata": d.get("metadata", {}), "score": float(sc)})
        return out


class RetrieverCombiner:
    def __init__(self, rrf_k: int = 60):
        self.rrf_k = rrf_k

    def combine(self, lists: List[List[Dict[str, Any]]], top_k: int = 10) -> List[Dict[str, Any]]:
        # Reciprocal Rank Fusion
        scores: Dict[Any, float] = {}
        items: Dict[Any, Dict[str, Any]] = {}
        for lst in lists:
            for rank, item in enumerate(lst, start=1):
                key = item.get("id") or item.get("text")
                scores[key] = scores.get(key, 0.0) + 1.0 / (self.rrf_k + rank)
                # store a representative item
                if key not in items:
                    items[key] = item

        sorted_keys = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        out = []
        for key, score in sorted_keys[:top_k]:
            item = items.get(key, {})
            merged = dict(item)
            merged["score"] = float(score)
            out.append(merged)
        return out


class Reranker:
    def __init__(self, embeddings_provider: Optional[Any] = None):
        self.embeddings_provider = embeddings_provider

    def rerank(self, query: str, candidates: List[Dict[str, Any]], top_k: Optional[int] = None) -> List[Dict[str, Any]]:
        if not candidates:
            return []
        top_k = top_k or len(candidates)
        # compute query vector
        try:
            if self.embeddings_provider is None:
                # lazy import
                from cerberus.rag.embeddings import get_embeddings_provider

                self.embeddings_provider = get_embeddings_provider()
            qvec = self.embeddings_provider.embed_texts([query])[0]
        except Exception:
            # cannot rerank without embeddings
            return candidates[:top_k]

        texts = [c.get("text", "") for c in candidates]
        # Compute candidate vectors with the same provider used for query
        # to ensure dimensional consistency and fair comparisons.
        try:
            candidate_vecs = self.embeddings_provider.embed_texts(texts)
        except Exception:
            candidate_vecs = [None for _ in candidates]

        # compute cosine similarities
        def cos(a, b):
            denom = math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(x * x for x in b))
            if denom == 0:
                return 0.0
            return sum(float(x) * float(y) for x, y in zip(a, b)) / denom

        scored = []
        for i, vec in enumerate(candidate_vecs):
            if vec is None:
                sim = 0.0
            else:
                sim = cos(qvec, vec)
            item = dict(candidates[i])
            item["score"] = float(sim)
            scored.append((sim, item))

        scored.sort(key=lambda s: s[0], reverse=True)
        return [it for _, it in scored[:top_k]]


class CrossEncoderReranker(Reranker):
    """Reranker that prefers a sentence-transformers CrossEncoder model.

    Falls back to the embedding-based `Reranker` behavior or a cheap
    token-overlap heuristic when CrossEncoder isn't available.
    """

    def __init__(self, model_name: Optional[str] = None, embeddings_provider: Optional[Any] = None, device: str = "cpu"):
        super().__init__(embeddings_provider=embeddings_provider)
        self.model_name = model_name or os.getenv("CERBERUS_CE_MODEL", "cross-encoder/ms-marco-MiniLM-L-6-v2")
        self.device = device
        self._ce_model = None
        try:
            from sentence_transformers import CrossEncoder  # type: ignore

            # instantiate the cross-encoder; allow runtime failure to fall back
            self._ce_model = CrossEncoder(self.model_name, device=self.device)
        except Exception:
            logging.debug("CrossEncoder model not available; falling back to cheaper rerankers")
            self._ce_model = None

    def rerank(self, query: str, candidates: List[Dict[str, Any]], top_k: Optional[int] = None) -> List[Dict[str, Any]]:
        if not candidates:
            return []
        top_k = top_k or len(candidates)

        # If we have a cross-encoder model, use it directly on (query, doc)
        if self._ce_model is not None:
            try:
                texts = [c.get("text", "") for c in candidates]
                pairs = [[query, t] for t in texts]
                scores = self._ce_model.predict(pairs)
                scored = []
                for s, c in zip(scores, candidates):
                    item = dict(c)
                    item["score"] = float(s)
                    scored.append((float(s), item))
                scored.sort(key=lambda x: x[0], reverse=True)
                return [it for _, it in scored[:top_k]]
            except Exception:
                logging.debug("CrossEncoder prediction failed; falling back")

        # Fallback: try embeddings-based reranker (cosine)
        try:
            return super().rerank(query, candidates, top_k=top_k)
        except Exception:
            logging.debug("Embedding-based reranker failed; using token-overlap heuristic")

        # Cheap heuristic: token overlap ratio combined with original score
        qtokens = set(_tokenize(query))
        scored = []
        for c in candidates:
            t = c.get("text", "")
            tks = set(_tokenize(t))
            overlap = 0.0
            if qtokens or tks:
                overlap = len(qtokens & tks) / max(1, len(qtokens | tks))
            base_score = float(c.get("score") or 0.0)
            combined = base_score + overlap
            item = dict(c)
            item["score"] = float(combined)
            scored.append((combined, item))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [it for _, it in scored[:top_k]]


class RetrieverPipeline:
    def __init__(
        self,
        dense: Optional[DenseRetriever] = None,
        sparse: Optional[SimpleBM25] = None,
        combiner: Optional[RetrieverCombiner] = None,
        reranker: Optional[Reranker] = None,
        wakeup_index: Optional[Any] = None,
        wakeup_k: int = 3,
        wakeup_boost: float = 10.0,
        audit_log: bool = True,
        ccmb_integration: bool = False,
    ):
        self.dense = dense
        self.sparse = sparse
        self.combiner = combiner or RetrieverCombiner()
        self.reranker = reranker
        self.wakeup_index = wakeup_index
        self.wakeup_k = int(wakeup_k)
        self.wakeup_boost = float(wakeup_boost)
        self.audit_log = bool(audit_log)
        self.ccmb_integration = bool(ccmb_integration)
        # Lazy-init fidelity tracker and audit writer on first retrieve()
        self._fidelity: Any = None
        self._hw_monitor: Any = None

    def retrieve(self, query: str, top_k: int = 10, rerank_top_k: Optional[int] = None, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        lists = []
        if self.dense:
            lists.append(self.dense.retrieve(query, top_k=top_k * 2))
        if self.sparse:
            lists.append(self.sparse.retrieve(query, top_k=top_k * 2))

        combined = self.combiner.combine(lists, top_k=top_k)

        # Integrate wake-up (session) facts if available. We merge wake-up
        # candidates into the combined list, boosting their score so they
        # are prioritized. Duplicates (by id/key/text) are collapsed.
        if self.wakeup_index is not None and session_id:
            try:
                wakeup_hits = self.wakeup_index.search_facts(session_id, query, top_k=self.wakeup_k)
            except Exception:
                wakeup_hits = []

            if wakeup_hits:
                # build a map of existing candidates by unique key
                candidate_map: Dict[str, Dict[str, Any]] = {}
                def unique_key(item: Dict[str, Any]) -> str:
                    return str(item.get("id") or item.get("key") or item.get("text") or "")

                for item in combined:
                    key = unique_key(item)
                    # ensure score exists
                    item_score = float(item.get("score") or 0.0)
                    candidate_map[key] = dict(item)
                    candidate_map[key]["score"] = item_score

                # merge wakeup hits
                for w in wakeup_hits:
                    key = str(w.get("key") or w.get("id") or w.get("text") or "")
                    w_score = float(w.get("score") or 0.0) + self.wakeup_boost
                    w_item = {
                        "id": w.get("key") or w.get("id"),
                        "text": w.get("text"),
                        "metadata": w.get("metadata", {}),
                        "score": float(w_score),
                    }
                    if key in candidate_map:
                        # keep the higher score
                        candidate_map[key]["score"] = max(candidate_map[key].get("score", 0.0), w_item["score"])
                    else:
                        candidate_map[key] = w_item

                # rebuild combined list from map sorted by score
                merged_list = sorted(candidate_map.values(), key=lambda it: float(it.get("score", 0.0)), reverse=True)
                combined = merged_list[:top_k]

        if self.reranker:
            reranked = self.reranker.rerank(query, combined, top_k=rerank_top_k or top_k)
            return self._post_retrieve(query, reranked)
        return self._post_retrieve(query, combined)

    def _post_retrieve(
        self,
        query: str,
        results: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Emit audit events and optional CCMB write after retrieval completes."""
        if self.audit_log:
            try:
                if self._fidelity is None:
                    from cerberus.rag.metrics import RetrievalFidelityTracker  # type: ignore
                    self._fidelity = RetrievalFidelityTracker()
                self._fidelity.record(query=query, results=results)
            except Exception:
                pass
        if self.ccmb_integration:
            try:
                from cerberus.memory.memory import CerberusMemoryBus  # type: ignore
                bus = CerberusMemoryBus.get_instance()
                summary = f"RAG:{query[:80]}" if len(query) > 80 else f"RAG:{query}"
                bus.commit(summary, {
                    "source": "retriever_pipeline",
                    "hit_count": len(results),
                    "top_id": results[0].get("id") or results[0].get("text", "")[:60] if results else None,
                })
            except Exception:
                pass
        return results


__all__ = [
    "DenseRetriever",
    "SimpleBM25",
    "RetrieverCombiner",
    "Reranker",
    "CrossEncoderReranker",
    "RetrieverPipeline",
]
