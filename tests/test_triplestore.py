import time

from cerberus.rag.triplestore import TripleStore


def test_add_and_query():
    ts = TripleStore()
    rid = ts.add_fact("entity1", "is_a", "person", provenance="src:test", metadata={"src": "unit"})
    assert isinstance(rid, int) and rid > 0

    res = ts.query(subject="entity1")
    assert len(res) == 1
    r = res[0]
    assert r["subject"] == "entity1"
    assert r["predicate"] == "is_a"
    assert r["object"] == "person"
    assert r["metadata"].get("src") == "unit"
    ts.close()


def test_get_facts_for_entity_subject_and_object():
    ts = TripleStore()
    ts.add_fact("doc1", "mentions", "entityX")
    ts.add_fact("entityX", "is", "target")
    res = ts.get_facts_for_entity("entityX")
    # should include both facts where entityX is subject and object
    assert len(res) >= 2
    ts.close()


def test_detect_contradictions_simple():
    ts = TripleStore()
    ts.add_fact("e3", "color", "red")
    ts.add_fact("e3", "color", "blue")
    out = ts.detect_contradictions()
    assert any(d["subject"] == "e3" and d["predicate"] == "color" for d in out)
    grp = next(d for d in out if d["subject"] == "e3" and d["predicate"] == "color")
    assert "red" in grp["objects"] and "blue" in grp["objects"]
    assert grp["type"] == "value_mismatch"
    ts.close()


def test_detect_boolean_contradiction():
    ts = TripleStore()
    ts.add_fact("e4", "alive", "True")
    ts.add_fact("e4", "alive", "False")
    out = ts.detect_contradictions()
    grp = next(d for d in out if d["subject"] == "e4" and d["predicate"] == "alive")
    assert grp["type"] == "boolean_contradiction"
    ts.close()
