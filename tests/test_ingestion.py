import time

from cai.rag.vector_db_adapter import LocalFallbackAdapter
from cai.rag.ingestion import get_ingestor, shutdown_all
from cai.rag.metrics import collector, export_metrics


def test_ingestion_batch_and_metrics():
    adapter = LocalFallbackAdapter()
    # create collection
    adapter.create_collection("testcol")

    ing = get_ingestor(adapter, batch_size=2, batch_interval=0.2, max_retries=2)

    # enqueue two docs and wait for flush
    ing.enqueue("testcol", "id1", ["hello world"], [{"provenance": {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}}])
    ing.enqueue("testcol", "id2", ["second doc"], [{"provenance": {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}}])

    # allow background worker to process
    time.sleep(0.5)

    exported = adapter.export_collection("testcol")
    assert len(exported) >= 2

    # metrics should have recorded ingest events
    m = export_metrics()
    # basic checks
    assert m["counters"].get("ingest_indexed_docs", 0) >= 2

    # cleanup
    shutdown_all()


def test_local_purge_older_than():
    adapter = LocalFallbackAdapter()
    adapter.create_collection("ttlcol")
    # add an old item via add_points with provenance timestamp far in the past
    old_ts = "2000-01-01T00:00:00Z"
    adapter.add_points("oldid", "ttlcol", ["old text"], [{"provenance": {"timestamp": old_ts}}])
    adapter.add_points("newid", "ttlcol", ["new text"], [{"provenance": {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}}])

    # purge items older than year 2010
    import datetime as _dt
    cutoff = _dt.datetime(2010, 1, 1, tzinfo=_dt.timezone.utc).timestamp()
    deleted = adapter.purge_older_than(cutoff)
    assert deleted >= 1
    exported = adapter.export_collection("ttlcol")
    # only new item should remain
    assert all(d["id"] != "oldid" for d in exported)
