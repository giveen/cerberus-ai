from typing import List, Dict, Any, Tuple

from cerberus.rag.vector_db_adapter import LocalFallbackAdapter
from cerberus.rag.embeddings import LocalDeterministicEmbeddingsProvider
from cerberus.rag.retriever_pipeline import (
    DenseRetriever,
    SimpleBM25,
    RetrieverCombiner,
    Reranker,
)


def _build_synthetic_dataset(num_docs: int = 50, num_topics: int = 5, vector_dim: int = 64) -> Tuple[LocalFallbackAdapter, List[Dict[str, Any]], List[str], List[str]]:
    """Create a small deterministic dataset and return adapter, docs, queries, ground_truth_ids.

    Returns:
      adapter: LocalFallbackAdapter with documents added to collection "test_coll"
      docs: list of document dicts as exported by the adapter
      queries: list of query strings (one per document)
      gt_ids: list of ground-truth document ids corresponding to each query
    """
    topics = [f"topic_{i}" for i in range(num_topics)]
    provider = LocalDeterministicEmbeddingsProvider({"vector_dim": vector_dim})
    adapter = LocalFallbackAdapter(config={"options": {}}, embeddings_provider=provider)
    coll = "test_coll"
    adapter.create_collection(coll)

    ids = []
    texts = []
    metas = []
    for i in range(num_docs):
        topic = topics[i % num_topics]
        doc_id = f"doc_{i}"
        text = f"This document covers {topic}. Unique marker: {doc_id}. More context about {topic} to make semantic signals." 
        ids.append(doc_id)
        texts.append(text)
        metas.append({"topic": topic})

    # Add to adapter in a single batch
    adapter.add_points(ids, coll, texts, metas)

    exported = adapter.export_collection(coll)

    # Build simple queries that are semantically related but not identical for variety
    queries = []
    gt_ids = []
    for i in range(num_docs):
        topic = topics[i % num_topics]
        # mix of formulations to exercise dense vs sparse
        if i % 3 == 0:
            q = f"details about {topic} and context"
        elif i % 3 == 1:
            q = f"what is known about {topic}"
        else:
            q = f"tell me about {topic} in the documents"
        queries.append(q)
        gt_ids.append(ids[i])

    return adapter, exported, queries, gt_ids


def _evaluate_recall(adapter, docs, queries: List[str], gt_ids: List[str], provider, top_ks=(1, 3, 5)) -> Dict[str, List[float]]:
    max_k = max(top_ks)
    # retrievers
    dense = DenseRetriever(adapter, collection_name="test_coll")
    sparse = SimpleBM25(docs)
    combiner = RetrieverCombiner()
    reranker = Reranker(embeddings_provider=provider)

    pipelines = {
        "dense": lambda q: dense.retrieve(q, top_k=max_k),
        "sparse": lambda q: sparse.retrieve(q, top_k=max_k),
        "combiner": lambda q: combiner.combine([dense.retrieve(q, top_k=max_k), sparse.retrieve(q, top_k=max_k)], top_k=max_k),
        "combiner_rerank": lambda q: reranker.rerank(q, combiner.combine([dense.retrieve(q, top_k=max_k), sparse.retrieve(q, top_k=max_k)], top_k=max_k), top_k=max_k),
    }

    results: Dict[str, List[float]] = {name: [0.0 for _ in top_ks] for name in pipelines.keys()}
    total = len(queries)

    for q, gt in zip(queries, gt_ids):
        for name, fn in pipelines.items():
            out = fn(q)
            ids = [str(it.get("id") or it.get("key") or it.get("text")) for it in out]
            for idx_k, k in enumerate(top_ks):
                top_ids = ids[:k]
                if gt in top_ids:
                    results[name][idx_k] += 1.0

    for name in results.keys():
        results[name] = [v / total for v in results[name]]

    return results


def test_retrieval_reproducible():
    provider = LocalDeterministicEmbeddingsProvider({"vector_dim": 64})
    adapter, docs, queries, gt_ids = _build_synthetic_dataset(num_docs=45, num_topics=5, vector_dim=64)

    r1 = _evaluate_recall(adapter, docs, queries, gt_ids, provider, top_ks=(1, 3, 5))
    r2 = _evaluate_recall(adapter, docs, queries, gt_ids, provider, top_ks=(1, 3, 5))

    # Results must be identical across repeated evaluations (deterministic embeddings + adapter)
    assert r1 == r2


def test_combiner_and_reranker_output_consistent():
    provider = LocalDeterministicEmbeddingsProvider({"vector_dim": 32})
    adapter, docs, queries, gt_ids = _build_synthetic_dataset(num_docs=30, num_topics=3, vector_dim=32)

    base = _evaluate_recall(adapter, docs, queries, gt_ids, provider, top_ks=(1, 5))
    # Basic sanity checks: recall values are within [0,1]
    for k in base.values():
        for val in k:
            assert 0.0 <= val <= 1.0
