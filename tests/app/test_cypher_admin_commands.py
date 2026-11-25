"""POST /api/cypher refuses Neo4j administration commands before any read."""

import pytest
from tests.app.conftest import login

from hst.core import db as db_mod


@pytest.mark.parametrize(
    ("query", "keyword"),
    [
        ("SHOW TRANSACTIONS", "SHOW"),
        ("USE neo4j SHOW TRANSACTIONS", "SHOW"),
        ("USE GRAPH (graph.byName(toLower('NEO4J'))) SHOW TRANSACTIONS", "SHOW"),
        ("CYPHER 5 TERMINATE TRANSACTIONS 'neo4j-transaction-1'", "TERMINATE"),
    ],
)
async def test_the_cypher_route_rejects_an_admin_command(client, seeded, monkeypatch, query, keyword):
    """The route runs run_readonly untrusted, so check_readonly rejects the command,
    no session opens, and the attempt is recorded as rejected."""
    sessions: list[dict] = []

    def no_session(settings, **kwargs):
        sessions.append(kwargs)
        raise AssertionError("a rejected query opens no session")

    monkeypatch.setattr(db_mod, "session", no_session)
    await login(client, "otto")

    r = await client.post("/api/cypher", json={"query": query})

    assert r.status_code == 400
    assert r.json() == {"error": f"{keyword} commands are not permitted"}
    assert sessions == []
    events = await seeded.list_cypher_events()
    assert [(e.query, e.outcome, e.row_count) for e in events] == [(query, "rejected", 0)]


@pytest.mark.parametrize(
    "query",
    [
        "USE system MATCH (n) RETURN n",
        "MATCH (n:Device) RETURN n UNION USE system MATCH (n) RETURN n",
        "CALL { USE system MATCH (n) RETURN n } RETURN n",
    ],
)
async def test_the_cypher_route_rejects_a_use_clause(client, seeded, monkeypatch, query):
    sessions: list[dict] = []

    def no_session(settings, **kwargs):
        sessions.append(kwargs)
        raise AssertionError("a rejected query opens no session")

    monkeypatch.setattr(db_mod, "session", no_session)
    await login(client, "otto")

    r = await client.post("/api/cypher", json={"query": query})

    assert r.status_code == 400
    assert r.json() == {"error": "USE clauses are not permitted"}
    assert sessions == []
    events = await seeded.list_cypher_events()
    assert [(e.query, e.outcome, e.row_count) for e in events] == [(query, "rejected", 0)]
