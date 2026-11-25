"""Snapshot guards and archive behavior; graph tests are explicit disposable opt-in."""

import os
from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from tests.test_grapharchive import RestoreSession, SourceSession
from tests.test_mtu_contract import observation

import hst.path as path
from hst.core import grapharchive
from hst.core.config import Settings
from hst.core.mtu import MtuContext
from hst.core.mtu_read import MTU_QUERY, read_mtu, resolve_constraints


def row(obs, cts=42, **extra):
    return {
        "subject_uid": obs.subject_uid,
        "observation_uid": obs.uid,
        "legacy_mtu": None,
        "observation": dict(obs.graph_props(), uid=obs.uid, collection_ts=cts, **extra),
    }


def test_unpinned_never_reads(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unpinned MTU must not read current or historic evidence")

    monkeypatch.setattr(path, "_read", forbidden)
    result = read_mtu(SimpleNamespace(), ["dev:missing"])
    assert result.gaps == ["MTU_SNAPSHOT_UNPINNED"]
    assert result.query_count == 0


def test_strict_snapshot_retired_duplicate_and_carried_evidence(monkeypatch):
    obs = observation()
    wrong_snapshot = observation(9000, source="other")
    retired = observation(9200, source="retired")
    monkeypatch.setattr(
        path,
        "_read",
        lambda *a, **k: [
            row(obs, carried=True, collected_at=10),
            row(obs),
            row(wrong_snapshot, 41),
            row(retired, _retired_at=40),
        ],
    )
    result = read_mtu(SimpleNamespace(cts=42), [obs.subject_uid])
    assert [o.uid for o in result.by_subject[obs.subject_uid]] == [obs.uid]
    assert result.carried_observation_uids == [obs.uid]
    assert result.provenance[obs.uid]["collected_at"] == 10
    assert result.query_count == 1
    assert "r.collection_ts = $snap" in MTU_QUERY
    assert "s._retired_at IS NULL" in MTU_QUERY
    assert "o._retired_at IS NULL" in MTU_QUERY


def test_subject_mtu_property_stays_ambiguous_and_no_default(monkeypatch):
    monkeypatch.setattr(
        path,
        "_read",
        lambda *a, **k: [
            {"subject_uid": "old", "legacy_mtu": 1514, "observation": None},
            {"subject_uid": "empty", "legacy_mtu": None, "observation": None},
        ],
    )
    result = read_mtu(SimpleNamespace(cts=42), ["old", "empty"])
    assert result.by_subject["old"][0].normalized_value is None
    assert not result.by_subject["empty"]
    assert result.unresolved_subjects == ["empty"]
    assert resolve_constraints(result.by_subject["old"], MtuContext(af=4)).constraints[0].value_bytes is None


def test_bounded_batch_read_count_and_truncation(monkeypatch):
    calls = []

    def read(session, query, **params):
        calls.append(params)
        return [row(observation(subject_uid=s)) for s in params["subject_uids"]]

    monkeypatch.setattr(path, "_read", read)
    result = read_mtu(SimpleNamespace(cts=42), [f"subject:{i}" for i in range(1000)])
    assert result.query_count == 4
    assert len(result.by_subject) == 1000
    assert not result.truncated
    small = read_mtu(SimpleNamespace(cts=42), [f"subject:{i}" for i in range(1000)], max_observations=5)
    assert small.truncated
    assert "MTU_PATH_COVERAGE_INCOMPLETE" in small.gaps
    assert sum(map(len, small.by_subject.values())) == 5


def test_tag_mismatch_and_old_normalization_cannot_be_applied():
    tag = observation(
        metric="l2_max_frame_bytes", profile_id="ethernet_frame_excluding_fcs", tag_depth=1, enforcement="l2"
    )
    result = resolve_constraints([tag], MtuContext(af=4, tag_depth=2))
    assert not result.constraints
    assert "MTU_SEMANTICS_UNKNOWN" in result.gaps
    old = observation(normalization_version="unrecognized")
    assert not resolve_constraints([old], MtuContext(af=4)).constraints


def test_exact_archive_preserves_observation_version_and_freshness(tmp_path):
    obs = observation(normalization_version="historical", observed_at_ms=5)
    props = dict(obs.graph_props(), uid=obs.uid, collection_ts=42, collected_at=10, carried=True)
    source = SourceSession(
        [{"uid": obs.uid, "labels": ["Obj", "Meta", "MtuObservation"], "props": props}], []
    )
    settings = Settings(hst_data_dir=tmp_path)
    key = Fernet.generate_key().decode()
    entry = grapharchive.write(source, settings, 42, key)
    assert entry["normalization_context"]["mtu_normalization_versions"] == ["historical"]
    target = RestoreSession()
    assert grapharchive.restore(target, settings, entry, key, 99) == (1, 0)
    restored = target.writes[0][1]["rows"][0]
    restored = restored.get("props", restored)
    assert restored["normalization_version"] == "historical"
    assert restored["collection_ts"] == 99
    assert restored["collected_at"] == 10
    assert restored["observed_at_ms"] == 5
    assert restored["carried"] is True


@pytest.mark.db
@pytest.mark.skipif(
    os.environ.get("HST_MTU_TEST_NEO4J_APPROVED") != "1",
    reason="requires approved disposable Neo4j and HST_MTU_TEST_NEO4J_APPROVED=1",
)
def test_real_graph_snapshot_endpoints_and_relation_pin():
    """Write only in a rolled-back transaction; never run on the live twin."""
    from neo4j import GraphDatabase

    from hst.path.session import CycleSession

    uri = os.environ["NEO4J_TEST_URI"]
    password = os.environ["NEO4J_TEST_PASSWORD"]
    if uri == Settings(_env_file=None).neo4j_uri:
        pytest.fail("refusing live twin URI")
    with (
        GraphDatabase.driver(uri, auth=(os.environ.get("NEO4J_TEST_USER", "neo4j"), password)) as driver,
        driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as session,
        session.begin_transaction() as tx,
    ):
        obs = observation(subject_uid="mtu:synthetic-db-only")
        tx.run(
            "CREATE (s:Obj:Interface {uid:$subject, collection_ts:42}) "
            "CREATE (o:Obj:MtuObservation) SET o=$props "
            "CREATE (s)-[:HAS_MTU {collection_ts:41}]->(o)",
            subject=obs.subject_uid,
            props=dict(obs.graph_props(), uid=obs.uid, collection_ts=42),
        ).consume()
        adapter = SimpleNamespace(execute_read=lambda work: work(tx))
        pinned = CycleSession(adapter, 42)
        assert not read_mtu(pinned, [obs.subject_uid]).by_subject[obs.subject_uid]
        tx.run(
            "MATCH (s:Obj {uid:$subject, collection_ts:42})-[r:HAS_MTU]->() SET r.collection_ts=42",
            subject=obs.subject_uid,
        ).consume()
        pinned = CycleSession(adapter, 42)
        assert read_mtu(pinned, [obs.subject_uid]).by_subject[obs.subject_uid][0].normalized_value == 1500
        assert not read_mtu(CycleSession(adapter, 41), [obs.subject_uid]).by_subject[obs.subject_uid]
        tx.rollback()
