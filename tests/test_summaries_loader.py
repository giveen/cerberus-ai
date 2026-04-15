import json

from cerberus.rag.summaries import (
    persist_summaries,
    read_persisted_summaries,
    load_summaries_for_session,
)
from cerberus.rag.wakeup_index import WakeupIndex
from cerberus.rag.embeddings import LocalDeterministicEmbeddingsProvider


def test_persist_and_read_summaries(tmp_path):
    p = tmp_path / "wakeup.json"
    # nothing persisted yet
    data = read_persisted_summaries(str(p))
    assert data == {}

    ok = persist_summaries("palace1", "L0 text here", "L1 longer text here", store_path=str(p))
    assert ok is True

    read_back = read_persisted_summaries(str(p))
    assert "palace1" in read_back
    assert read_back["palace1"]["L0"] == "L0 text here"
    assert read_back["palace1"]["L1"] == "L1 longer text here"


def test_load_persisted_only(tmp_path):
    p = tmp_path / "wakeup.json"
    persist_summaries("palace2", "Palace2 L0", "Palace2 L1", store_path=str(p))

    provider = LocalDeterministicEmbeddingsProvider({"vector_dim": 32})
    idx = WakeupIndex(max_facts_per_session=20, embeddings_provider=provider)

    added = load_summaries_for_session("sess1", palace_texts=None, wakeup_index=idx, store_path=str(p))
    # palace2 has two facts (L0 + L1)
    assert added == 2

    # internal storage should contain keys
    assert "sess1" in idx.list_sessions()
    assert f"palace2_L0" in idx._sessions["sess1"]
    assert f"palace2_L1" in idx._sessions["sess1"]


def test_regenerate_if_missing(tmp_path):
    p = tmp_path / "wakeup.json"
    # ensure no pre-existing file
    if p.exists():
        p.unlink()

    provider = LocalDeterministicEmbeddingsProvider({"vector_dim": 32})
    idx = WakeupIndex(max_facts_per_session=20, embeddings_provider=provider)

    palace_texts = {
        "palace3": [
            "First sentence about secret credentials.",
            "Second sentence describing more context and keys.",
        ]
    }

    added = load_summaries_for_session(
        "sess2",
        palace_texts=palace_texts,
        wakeup_index=idx,
        store_path=str(p),
        regenerate_if_missing=True,
    )
    # should have added L0 and L1
    assert added == 2

    # persisted file should now contain palace3
    persisted = read_persisted_summaries(str(p))
    assert "palace3" in persisted
    assert persisted["palace3"]["L0"]
    assert persisted["palace3"]["L1"]
