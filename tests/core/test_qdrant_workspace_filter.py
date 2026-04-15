from cai.rag.vector_db_adapter import QdrantAdapter


class _FakeQdrantClient:
    def __init__(self):
        self.last_add_points_call = None

    def search(self, collection_name: str, query_text: str, limit: int = 3):
        _ = (collection_name, query_text, limit)
        return [
            {
                "id": "a",
                "text": "target-a finding",
                "metadata": {
                    "workspace_root": "/workspace/workspaces/target-a",
                    "workspace_id": "target-a",
                },
                "score": 0.99,
            },
            {
                "id": "b",
                "text": "target-b finding",
                "metadata": {
                    "workspace_root": "/workspace/workspaces/target-b",
                    "workspace_id": "target-b",
                },
                "score": 0.98,
            },
            {
                "id": "c",
                "text": "unscoped finding",
                "metadata": {},
                "score": 0.97,
            },
        ]

    def create_collection(self, collection_name: str) -> bool:
        _ = collection_name
        return True

    def add_points(self, **kwargs):
        self.last_add_points_call = kwargs
        return True


def test_qdrant_search_filters_results_by_active_workspace(monkeypatch):
    monkeypatch.setenv("CEREBRO_WORKSPACE_ACTIVE_ROOT", "/workspace/workspaces/target-a")
    monkeypatch.setenv("CEREBRO_WORKSPACE", "target-a")

    adapter = QdrantAdapter(client=_FakeQdrantClient())
    result = adapter.search(collection_name="_all_", query_text="findings", limit=10)

    assert len(result) == 1
    assert result[0]["id"] == "a"
    assert result[0]["metadata"]["workspace_id"] == "target-a"


def test_qdrant_add_points_enriches_workspace_scope(monkeypatch):
    monkeypatch.setenv("CEREBRO_WORKSPACE_ACTIVE_ROOT", "/workspace/workspaces/target-a")
    monkeypatch.setenv("CEREBRO_WORKSPACE", "target-a")
    monkeypatch.setenv("CEREBRO_SESSION_ID", "sess-a")

    client = _FakeQdrantClient()
    adapter = QdrantAdapter(client=client)

    ok = adapter.add_points(
        id_point=["id1"],
        collection_name="_all_",
        texts=["hello"],
        metadata=[{}],
    )

    assert ok is True
    assert client.last_add_points_call is not None
    md = client.last_add_points_call["metadata"][0]
    assert md["workspace_root"] == "/workspace/workspaces/target-a"
    assert md["workspace_id"] == "target-a"
    assert md["session_id"] == "sess-a"
    assert md["provenance"]["workspace_root"] == "/workspace/workspaces/target-a"
    assert md["provenance"]["workspace_id"] == "target-a"
    assert md["provenance"]["session_id"] == "sess-a"
