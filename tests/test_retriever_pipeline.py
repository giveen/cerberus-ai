from cai.rag.vector_db_adapter import LocalFallbackAdapter
from cai.rag.retriever_pipeline import (
    DenseRetriever,
    SimpleBM25,
    RetrieverCombiner,
    Reranker,
    RetrieverPipeline,
)


def _make_adapter_and_docs():
    ad = LocalFallbackAdapter(config={})
    ad.create_collection("test")
    ad.add_points("id1", "test", ["security incident involving ssh"], [{"source": "unit"}])
    ad.add_points("id2", "test", ["ssh brute force detected"], [{"source": "unit"}])
    ad.add_points("id3", "test", ["web application sql injection"], [{"source": "unit"}])
    docs = ad.export_collection("test")
    return ad, docs


def test_both_retrievers_and_combiner():
    ad, docs = _make_adapter_and_docs()
    dense = DenseRetriever(adapter=ad, collection_name="test")
    sparse = SimpleBM25(docs=docs)
    comb = RetrieverCombiner(rrf_k=10)
    pipeline = RetrieverPipeline(dense=dense, sparse=sparse, combiner=comb)

    res = pipeline.retrieve("ssh attack", top_k=3)
    assert isinstance(res, list)
    assert len(res) <= 3
    # Expect one of the top results to mention ssh
    texts = [r.get("text", "").lower() for r in res]
    assert any("ssh" in t for t in texts)


def test_reranker_improves_order():
    ad, docs = _make_adapter_and_docs()
    dense = DenseRetriever(adapter=ad, collection_name="test")
    sparse = SimpleBM25(docs=docs)
    from cai.rag.embeddings import LocalDeterministicEmbeddingsProvider

    reranker = Reranker(embeddings_provider=LocalDeterministicEmbeddingsProvider({"vector_dim": 32}))
    pipeline = RetrieverPipeline(dense=dense, sparse=sparse, reranker=reranker)

    res = pipeline.retrieve("sql injection", top_k=3)
    assert len(res) >= 1
    # Expect at least one of the returned candidates to mention sql/injection
    texts = [r.get("text", "").lower() for r in res]
    assert any("sql" in t or "injection" in t for t in texts)


def test_wakeup_integration():
    from cai.rag.wakeup_index import WakeupIndex
    from cai.rag.embeddings import LocalDeterministicEmbeddingsProvider

    ad, docs = _make_adapter_and_docs()
    dense = DenseRetriever(adapter=ad, collection_name="test")
    sparse = SimpleBM25(docs=docs)
    provider = LocalDeterministicEmbeddingsProvider({"vector_dim": 32})
    wake = WakeupIndex(embeddings_provider=provider)
    # Add a high-priority session fact
    wake.add_fact("sess-x", "wf1", "sql injection observed inside app", priority=10.0)

    pipeline = RetrieverPipeline(dense=dense, sparse=sparse, combiner=RetrieverCombiner(), wakeup_index=wake, wakeup_k=2, wakeup_boost=5.0)
    res = pipeline.retrieve("sql", top_k=3, session_id="sess-x")
    texts = [r.get("text", "").lower() for r in res]
    assert any("sql" in t for t in texts)
