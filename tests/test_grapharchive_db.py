"""Real-Neo4j coverage for graph archive endpoint identity and exact restore."""

from __future__ import annotations

import os

import pytest
from cryptography.fernet import Fernet

from hst.core import db as dbmod
from hst.core import grapharchive
from hst.core.config import Settings

URI = os.environ.get("NEO4J_TEST_URI")
SCOPE = "test:grapharchive-db"

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set"),
]


def _refuse_if_live() -> None:
    live = Settings(_env_file=None).neo4j_uri
    if dbmod.same_endpoint(URI or "", live):
        pytest.exit(
            f"NEO4J_TEST_URI ({URI}) is the live twin ({live}); use a scratch database",
            returncode=2,
        )


@pytest.fixture()
def session():
    from neo4j import GraphDatabase

    _refuse_if_live()
    driver = GraphDatabase.driver(
        URI,
        auth=(os.environ.get("NEO4J_TEST_USER", "neo4j"), os.environ["NEO4J_TEST_PASSWORD"]),
    )
    try:
        with driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as opened:
            _clear(opened)
            yield opened
            _clear(opened)
    finally:
        driver.close()


def _clear(session) -> None:
    session.run("MATCH (n:Obj {_scope: $scope}) DETACH DELETE n", scope=SCOPE).consume()


def test_roundtrip_preserves_unstamped_meta_endpoint_amid_duplicate_uid(tmp_path, session):
    source_ts, target_ts = 1_000, 2_000
    session.run(
        """
        CREATE (d:Obj:Device {
          uid: 'dev:archive', hostname: 'archive', collection_ts: $snap, _scope: $scope
        })
        CREATE (meta:Obj:Meta:Site {uid: 'site:hq', code: 'hq', _scope: $scope})
        CREATE (reported:Obj:Site {
          uid: 'site:hq', code: 'reported-hq', collection_ts: $snap, _scope: $scope
        })
        CREATE (d)-[:LOCATED_IN {assigned: true, _scope: $scope}]->(meta)
        """,
        snap=source_ts,
        scope=SCOPE,
    ).consume()
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    key = Fernet.generate_key().decode()

    entry = grapharchive.write(session, settings, source_ts, key, chunk_records=1)
    assert (entry["nodes"], entry["rels"]) == (3, 1)

    _clear(session)
    # Snapshot counts exclude the unstamped Site and LOCATED_IN metadata.
    assert grapharchive.restore(session, settings, entry, key, target_ts) == (2, 0)

    nodes = session.run(
        "MATCH (n:Obj {_scope: $scope}) RETURN n.uid AS uid, labels(n) AS labels, "
        "n.collection_ts AS cts, n.code AS code ORDER BY cts, code",
        scope=SCOPE,
    ).data()
    assert len(nodes) == 3
    assert sum(row["uid"] == "site:hq" for row in nodes) == 2
    assert any("Meta" in row["labels"] and row["cts"] is None and row["code"] == "hq" for row in nodes)
    assert any(
        "Meta" not in row["labels"] and row["cts"] == target_ts and row["code"] == "reported-hq"
        for row in nodes
    )

    relationships = session.run(
        "MATCH (d:Device {_scope: $scope})-[r:LOCATED_IN]->(s:Site) "
        "RETURN d.collection_ts AS device_cts, s.collection_ts AS site_cts, "
        "labels(s) AS site_labels, properties(r) AS props",
        scope=SCOPE,
    ).data()
    assert len(relationships) == 1
    relationship = relationships[0]
    assert relationship["device_cts"] == target_ts
    assert relationship["site_cts"] is None
    assert set(relationship["site_labels"]) == {"Obj", "Meta", "Site"}
    assert relationship["props"] == {"assigned": True, "_scope": SCOPE}


def test_archive_rejects_current_relationship_to_foreign_snapshot(tmp_path, session):
    session.run(
        """
        CREATE (d:Obj:Device {
          uid: 'dev:cross-generation', collection_ts: 1000, _scope: $scope
        })
        CREATE (s:Obj:Site {
          uid: 'site:foreign', collection_ts: 900, _scope: $scope
        })
        CREATE (d)-[:LOCATED_IN {collection_ts: 1000, _scope: $scope}]->(s)
        """,
        scope=SCOPE,
    ).consume()
    settings = Settings(_env_file=None, hst_data_dir=tmp_path)
    key = Fernet.generate_key().decode()

    with pytest.raises(grapharchive.ArchiveError, match="endpoint from a different snapshot"):
        grapharchive.write(session, settings, 1_000, key)
