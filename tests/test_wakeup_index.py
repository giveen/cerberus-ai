import time

from cai.rag.wakeup_index import WakeupIndex
from cai.rag.embeddings import LocalDeterministicEmbeddingsProvider


def test_add_and_search_basic():
    provider = LocalDeterministicEmbeddingsProvider({"vector_dim": 32})
    idx = WakeupIndex(max_facts_per_session=10, embeddings_provider=provider)
    idx.add_fact("s1", "k1", "sql injection observed", metadata={"a": 1}, priority=5.0)
    idx.add_fact("s1", "k2", "ssh brute force", metadata={"a": 2}, priority=1.0)

    res = idx.search_facts("s1", "sql", top_k=3)
    assert len(res) >= 1
    keys = [r["key"] for r in res]
    assert "k1" in keys


def test_ttl_expiry():
    provider = LocalDeterministicEmbeddingsProvider({"vector_dim": 16})
    idx = WakeupIndex(max_facts_per_session=10, embeddings_provider=provider)
    idx.add_fact("s2", "k1", "temporary fact", ttl=1.0)
    time.sleep(1.1)
    res = idx.search_facts("s2", "temporary", top_k=5)
    assert res == []


def test_limit_eviction():
    provider = LocalDeterministicEmbeddingsProvider({"vector_dim": 16})
    idx = WakeupIndex(max_facts_per_session=2, embeddings_provider=provider)
    idx.add_fact("s3", "k1", "first", priority=1)
    idx.add_fact("s3", "k2", "second", priority=2)
    idx.add_fact("s3", "k3", "third", priority=3)

    res = idx.search_facts("s3", "", top_k=10)
    keys = [r["key"] for r in res]
    assert len(keys) == 2
    assert "k3" in keys and "k2" in keys


def test_purge_session():
    provider = LocalDeterministicEmbeddingsProvider({"vector_dim": 16})
    idx = WakeupIndex(embeddings_provider=provider)
    idx.add_fact("s4", "k1", "keep me")
    idx.purge_session("s4")
    res = idx.search_facts("s4", "keep", top_k=5)
    assert res == []
