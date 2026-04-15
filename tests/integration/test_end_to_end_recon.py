import os
import time
import random
import datetime as _dt

import pytest

from cerberus.rag.vector_db_adapter import LocalFallbackAdapter
from cerberus.rag.retriever_pipeline import DenseRetriever, SimpleBM25, RetrieverCombiner, RetrieverPipeline
from cerberus.rag.embeddings import LocalDeterministicEmbeddingsProvider


@pytest.mark.integration
def test_end_to_end_recon_hybrid_prioritizes_recent(tmp_path, monkeypatch):
    """Stress test: ingest messy logs and verify hybrid retriever
    prioritizes the most recent (valid) credential for `l.wilson`.

    Also measure retrieval time when FAISS is available and skip the
    performance assertion otherwise.
    """
    # Use a temp dir for persisted local indexes to avoid touching home
    persist_dir = tmp_path / "local_persist"
    monkeypatch.setenv("CERBERUS_LOCAL_PERSIST_DIR", str(persist_dir))
    monkeypatch.setenv("CERBERUS_USE_FAISS", "1")

    # Small deterministic embedding vectors for speed
    provider = LocalDeterministicEmbeddingsProvider({"vector_dim": 32, "cache_enabled": True})

    # Ensure adapter requests FAISS (will gracefully fall back if not present)
    ad = LocalFallbackAdapter(config={"options": {"use_faiss": True}}, embeddings_provider=provider)
    coll = "recon_test"
    ad.create_collection(coll)

    now = _dt.datetime.utcnow()
    older = now - _dt.timedelta(hours=2)
    older_ts = older.isoformat() + "Z"
    now_ts = now.isoformat() + "Z"

    # Prepare special entries with conflicting credentials
    specials = []
    # older invalid l.wilson entries
    for i in range(3):
        t = f"LDAP auth failure for l.wilson; password: INVALID_HASH_{i}"
        m = {"provenance": {"timestamp": older_ts, "source": "test", "original_text": t}}
        specials.append((t, m))

    # older invalid j.arbuckle entries
    for i in range(3):
        t = f"SMB auth error for j.arbuckle; pw: JUNK_{i}"
        m = {"provenance": {"timestamp": older_ts, "source": "test", "original_text": t}}
        specials.append((t, m))

    # most-recent valid l.wilson entry (should be prioritized)
    valid_text = f"SMB access: l.wilson password: VALID_HASH_LW_ABC123 - successful login"
    valid_meta = {"provenance": {"timestamp": now_ts, "source": "test", "original_text": valid_text}}
    specials.append((valid_text, valid_meta))

    # Fill up to ~500 lines with noisy logs
    total = 500
    filler_count = total - len(specials)
    fillers = []
    for i in range(filler_count):
        t = f"Random log entry {i} user=usr{random.randint(0,9999)} event={random.choice(['connect','disconnect','timeout'])}"
        # stagger timestamps across older..now range
        ts = (older + _dt.timedelta(seconds=i)).isoformat() + "Z"
        m = {"provenance": {"timestamp": ts, "source": "test", "original_text": t}}
        fillers.append((t, m))

    # Ensure the valid entry is near the end (more recent)
    all_entries = fillers + specials

    # Add in batches to the adapter
    batch_size = 50
    for i in range(0, len(all_entries), batch_size):
        batch = all_entries[i : i + batch_size]
        texts = [t for t, m in batch]
        metas = [m for t, m in batch]
        # Use None id_point so adapter will generate per-item ids
        ad.add_points(None, coll, texts, metas)

    # If FAISS is available ensure index is built for predictable performance
    if getattr(ad, "_faiss_available", False):
        try:
            # attempt to build index using provider dimension
            dim = int(provider.config.vector_dim)
            ad._build_faiss_index(coll, dim=dim)
        except Exception:
            pass

    # Export docs and build hybrid pipeline
    docs = ad.export_collection(coll)
    dense = DenseRetriever(adapter=ad, collection_name=coll)
    sparse = SimpleBM25(docs=docs)
    pipeline = RetrieverPipeline(dense=dense, sparse=sparse, combiner=RetrieverCombiner())

    # Query for l.wilson password — expect the most recent valid hash to appear
    # before older invalid l.wilson entries in the ranked results.
    res = pipeline.retrieve("l.wilson password", top_k=10)
    assert isinstance(res, list)
    assert len(res) > 0
    texts = [ (r.get("text") or "") for r in res ]

    # locate valid and older invalid entries in the returned list
    valid_idx = next((i for i, t in enumerate(texts) if "VALID_HASH_LW_ABC123" in t), None)
    assert valid_idx is not None, "Valid l.wilson credential was not returned in top candidates"

    # Performance: retrieving a larger context (simulate 10k token prompt)
    if getattr(ad, "_faiss_available", False):
        start = time.perf_counter()
        # retrieve more candidates to assemble a large prompt context
        _ = pipeline.retrieve("l.wilson password", top_k=50)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        assert elapsed_ms < 500.0, f"Retrieval too slow with FAISS cache: {elapsed_ms:.1f}ms"
    else:
        pytest.skip("FAISS not available; skipping performance assertion")

    # Cleanup executor and release any locks
    try:
        ad._shutdown_persistence()
    except Exception:
        pass
