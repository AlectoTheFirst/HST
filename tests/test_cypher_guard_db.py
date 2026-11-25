"""`run_readonly` against the scratch Neo4j database that NEO4J_TEST_URI sets.

NEO4J_TEST_URI=bolt://localhost:7699 NEO4J_TEST_PASSWORD=... pytest -m db
"""

from __future__ import annotations

import os

import neo4j.exceptions
import pytest
from tests.test_integration_db import URI, _refuse_if_live

from hst.app import tables
from hst.core import db as dbmod
from hst.core.config import Settings

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set"),
]

SCOPE = "test:cypher-guard"
MARKED = f"MATCH (n) WHERE n._scope = '{SCOPE}' RETURN count(n) AS n"


@pytest.fixture(scope="module")
def settings():
    _refuse_if_live()
    settings = Settings(
        _env_file=None,
        neo4j_uri=URI,
        neo4j_user=os.environ.get("NEO4J_TEST_USER", "neo4j"),
        neo4j_password=os.environ["NEO4J_TEST_PASSWORD"],
        neo4j_database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j"),
    )
    yield settings
    # A write that Neo4j did not refuse leaves this node.
    with dbmod.session(settings) as s:
        s.run("MATCH (n) WHERE n._scope = $scope DETACH DELETE n", scope=SCOPE).consume()


def _marked(settings: Settings) -> int:
    return tables.run_readonly(settings, MARKED, {})["data"][0]["row"][0]


def test_an_allowed_read_returns_its_table(settings):
    table = tables.run_readonly(
        settings, "MATCH (d:Device:Obj) WHERE d.collection_ts = $snap RETURN count(d) AS devices", {}
    )

    assert table["columns"] == ["devices"]
    assert table["truncated"] is False
    [row] = table["data"]
    assert isinstance(row["row"][0], int) and row["row"][0] >= 0


def test_an_allowed_procedure_returns_its_table(settings):
    table = tables.run_readonly(settings, "CALL db.labels() YIELD label RETURN label", {})

    assert table["columns"] == ["label"]
    assert all(isinstance(row["row"][0], str) for row in table["data"])


def test_neo4j_refuses_a_write_in_the_read_transaction(settings):
    before = _marked(settings)

    with pytest.raises(neo4j.exceptions.ClientError) as refusal:
        tables.run_readonly(settings, f"CREATE (n {{_scope: '{SCOPE}'}}) RETURN n", {})

    assert refusal.value.code == "Neo.ClientError.Statement.AccessMode"
    assert _marked(settings) == before


@pytest.mark.parametrize(
    ("query", "message"),
    [
        ("LOAD CSV FROM 'file:///hst-no-such-file.csv' AS row RETURN row", "LOAD CSV is not permitted"),
        ("CALL dbms.components() YIELD name RETURN name", "procedure 'dbms.components' is not permitted"),
        ("CALL db.awaitIndexes()", "procedure 'db.awaitIndexes' is not permitted"),
        ("USE system MATCH (n) RETURN n", "USE clauses are not permitted"),
        ("USE system SHOW DATABASES", "SHOW commands are not permitted"),
        ("CALL { USE system MATCH (n) RETURN n } RETURN n", "USE clauses are not permitted"),
    ],
)
def test_the_guard_refuses_the_query_ahead_of_neo4j(settings, query, message):
    with pytest.raises(tables.QueryRejected) as refusal:
        tables.run_readonly(settings, query, {})

    assert str(refusal.value).startswith(message)
