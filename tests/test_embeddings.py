import math
import pytest

from cerberus.rag.embeddings import (
    LocalDeterministicEmbeddingsProvider,
    get_embeddings_provider,
)


def test_determinism_across_instances():
    cfg = {
        "vector_dim": 64,
        "batch_size": 8,
        "deterministic_seed": 123,
        "normalize": True,
        "cache_enabled": False,
    }
    p1 = LocalDeterministicEmbeddingsProvider(cfg)
    p2 = LocalDeterministicEmbeddingsProvider(cfg)
    texts = ["hello world", "some other text", ""]
    v1 = p1.embed_texts(texts)
    v2 = p2.embed_texts(texts)
    assert v1 == v2
    assert all(len(vec) == 64 for vec in v1)
    # Norm should be ~1.0 when normalize=True
    for vec in v1:
        norm = math.sqrt(sum(x * x for x in vec))
        assert pytest.approx(1.0, rel=1e-6) == norm


def test_cache_and_eviction_lru():
    cfg = {
        "vector_dim": 16,
        "batch_size": 2,
        "cache_enabled": True,
        "cache_max_size": 2,
    }
    p = LocalDeterministicEmbeddingsProvider(cfg)
    texts = ["a", "b", "c"]
    first_vecs = {}
    for t in texts:
        vec = p.embed_texts([t])[0]
        first_vecs[t] = vec

    # cache should have at most 2 entries (LRU enforced)
    assert len(p._cache) <= 2

    # Re-request the first text (which may have been evicted), ensure vector equals original
    vec_recomputed = p.embed_texts([texts[0]])[0]
    assert vec_recomputed == first_vecs[texts[0]]
    assert texts[0] in p._cache


def test_batch_consistency():
    texts = ["one", "two", "three", "four"]
    cfg1 = {"vector_dim": 32, "batch_size": 1, "cache_enabled": False}
    cfg2 = {"vector_dim": 32, "batch_size": 10, "cache_enabled": False}
    p1 = LocalDeterministicEmbeddingsProvider(cfg1)
    p2 = LocalDeterministicEmbeddingsProvider(cfg2)
    v1 = p1.embed_texts(texts)
    v2 = p2.embed_texts(texts)
    assert v1 == v2


def test_factory_default_provider():
    provider = get_embeddings_provider()
    assert hasattr(provider, "embed_texts")
    # Accept either the local deterministic provider or an OpenAI-backed
    # provider depending on the runtime environment and available keys.
    from cerberus.rag.embeddings import OpenAIEmbeddingsProvider

    assert isinstance(provider, (LocalDeterministicEmbeddingsProvider, OpenAIEmbeddingsProvider))
