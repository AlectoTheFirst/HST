"""Raw Cypher is operator-only, read-only, capped."""

import logging

import neo4j.exceptions
from tests.app.conftest import login

import hst.app.routes.cypher as cypher_route
import hst.app.tables as tables
from hst.app.crypto import GUIDANCE, SecretKeyError

TABLE = {"columns": ["n"], "data": [], "truncated": False}


# --- graph node label order ----------------------------------------------------------------


def test_node_labels_serialize_with_the_primary_label_first():
    """The domain label a collector registers, the one label not in
    RESERVED_LABELS, leads the list; the reserved bookkeeping and layer
    labels follow, sorted."""
    labels = tables._ordered_labels({"Obj", "Latest", "L3", "Prefix"})
    assert labels == ["Prefix", "L3", "Latest", "Obj"]


def test_node_labels_with_no_primary_label_stay_sorted():
    """A meta node carrying only reserved labels has no primary label to lead
    with, so it keeps plain sorted order."""
    labels = tables._ordered_labels({"Obj", "Latest", "L3"})
    assert labels == ["L3", "Latest", "Obj"]


async def test_viewer_is_forbidden_operator_allowed(client, monkeypatch):
    monkeypatch.setattr(cypher_route, "run_readonly", lambda s, q, p, graph=False: TABLE)
    await login(client, "vera")
    r = await client.post("/api/cypher", json={"query": "RETURN 1"})
    assert r.status_code == 403 and r.json() == {"error": "requires permission: cypher.run"}
    await login(client, "otto")
    r = await client.post("/api/cypher", json={"query": "RETURN 1", "params": {"x": 1}})
    assert r.status_code == 200 and r.json() == TABLE


async def _unraised_client(app):
    # Starlette's ServerErrorMiddleware (which runs the app-level Exception handler)
    # re-raises after sending the response, so the client here needs
    # raise_app_exceptions=False to see the response
    import httpx

    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://t",
        headers={"X-HST-CSRF": "1"},
    )


async def test_unexpected_errors_are_500_and_reveal_nothing(app, monkeypatch):
    """The catch-all must not render the exception. A StatementError from a users or
    sources write stringifies to `[SQL: ...] [parameters: ...]`, which is a password
    hash or a sealed secrets blob."""

    def boom(settings, query, params, graph=False):
        raise RuntimeError("password_hash=$argon2id$v=19$m=65536 leaked")

    monkeypatch.setattr(cypher_route, "run_readonly", boom)
    async with await _unraised_client(app) as c:
        await login(c, "otto")
        r = await c.post("/api/cypher", json={"query": "RETURN 1"})
        assert r.status_code == 500
        body = r.json()
        assert body["error"] == "internal error"
        assert body["request_id"]
        assert "argon2id" not in r.text and "RuntimeError" not in r.text


async def test_a_dead_twin_is_502_and_the_driver_text_goes_to_the_log(app, monkeypatch, caplog):
    def boom(settings, query, params, graph=False):
        raise neo4j.exceptions.ServiceUnavailable("Couldn't connect to twin-db.internal:7687")

    monkeypatch.setattr(cypher_route, "run_readonly", boom)
    async with await _unraised_client(app) as c:
        await login(c, "otto")
        with caplog.at_level(logging.ERROR, logger="hst.app.main"):
            r = await c.post("/api/cypher", json={"query": "RETURN 1"})
        assert r.status_code == 502
        assert r.json() == {"error": "twin unreachable"}
        assert "twin-db.internal:7687" in caplog.text


async def test_a_secret_key_error_is_500_and_the_file_path_goes_to_the_log(app, monkeypatch, caplog):
    def boom(settings, query, params, graph=False):
        raise SecretKeyError(
            "cannot read HST_SECRET_KEY_FILE: [Errno 2] No such file or directory: '/run/secrets/kek'"
        )

    monkeypatch.setattr(cypher_route, "run_readonly", boom)
    async with await _unraised_client(app) as c:
        await login(c, "otto")
        with caplog.at_level(logging.ERROR, logger="hst.app.main"):
            r = await c.post("/api/cypher", json={"query": "RETURN 1"})
        assert r.status_code == 500
        assert r.json() == {"error": GUIDANCE}
        assert "/run/secrets/kek" in caplog.text


async def test_bad_cypher_becomes_400(client, monkeypatch):
    def boom(settings, query, params, graph=False):
        raise neo4j.exceptions.ClientError("Invalid input 'MATCHX'")

    monkeypatch.setattr(cypher_route, "run_readonly", boom)
    await login(client, "otto")
    r = await client.post("/api/cypher", json={"query": "MATCHX (n) RETURN n"})
    assert r.status_code == 400
    assert r.json() == {"error": "ClientError: Invalid input 'MATCHX'"}


async def test_oversized_query_is_413(client):
    await login(client, "otto")
    r = await client.post("/api/cypher", json={"query": "RETURN " + "1," * 40_000})
    assert r.status_code == 413


# --- audit trail ----------------------------------------------------------------


async def test_a_successful_query_is_attributed_to_the_caller(client, seeded, monkeypatch):
    table = {"columns": ["n"], "data": [{"row": [1]}, {"row": [2]}], "truncated": False}
    monkeypatch.setattr(cypher_route, "run_readonly", lambda s, q, p, graph=False: table)
    await login(client, "otto")
    assert (await client.post("/api/cypher", json={"query": "MATCH (n) RETURN n"})).status_code == 200

    otto = await seeded.get_user_by_username("otto")
    events = await seeded.list_cypher_events()
    assert len(events) == 1
    e = events[0]
    assert (e.user_id, e.query, e.outcome, e.row_count) == (otto.id, "MATCH (n) RETURN n", "ok", 2)
    assert e.byte_count > 0


async def test_a_refused_query_is_recorded_too(client, seeded):
    await login(client, "otto")
    r = await client.post("/api/cypher", json={"query": "LOAD CSV FROM 'http://x/y' AS r RETURN r"})
    assert r.status_code == 400

    r = await client.post("/api/cypher", json={"query": "RETURN " + "1," * 40_000})
    assert r.status_code == 413

    events = await seeded.list_cypher_events()
    assert sorted(e.outcome for e in events) == ["rejected", "too_large"]
    assert all(e.row_count == 0 and e.byte_count == 0 for e in events)
    # the oversized query is stored truncated to the cap
    too_large = next(e for e in events if e.outcome == "too_large")
    assert len(too_large.query) <= cypher_route.MAX_QUERY_BYTES


async def test_bad_cypher_and_a_dead_twin_both_leave_a_row(app, monkeypatch):
    def bad(settings, query, params, graph=False):
        raise neo4j.exceptions.ClientError("Invalid input 'MATCHX'")

    def dead(settings, query, params, graph=False):
        raise neo4j.exceptions.ServiceUnavailable("no routing information")

    async with await _unraised_client(app) as c:
        await login(c, "otto")
        monkeypatch.setattr(cypher_route, "run_readonly", bad)
        assert (await c.post("/api/cypher", json={"query": "MATCHX (n)"})).status_code == 400
        monkeypatch.setattr(cypher_route, "run_readonly", dead)
        assert (await c.post("/api/cypher", json={"query": "MATCH (n) RETURN n"})).status_code == 502

    events = await app.state.store.list_cypher_events()
    assert [e.outcome for e in events] == ["error", "error"]


async def test_an_audit_write_failure_does_not_fail_the_query(client, app, monkeypatch):
    async def boom(**kwargs):
        raise RuntimeError("store is down")

    monkeypatch.setattr(cypher_route, "run_readonly", lambda s, q, p, graph=False: TABLE)
    monkeypatch.setattr(app.state.store, "record_cypher_event", boom)
    await login(client, "otto")
    r = await client.post("/api/cypher", json={"query": "RETURN 1"})
    assert r.status_code == 200 and r.json() == TABLE


async def test_a_forbidden_caller_leaves_no_row(client, seeded, monkeypatch):
    """The permission check runs first, so a viewer's 403 never reaches the
    recorder."""
    monkeypatch.setattr(cypher_route, "run_readonly", lambda s, q, p, graph=False: TABLE)
    await login(client, "vera")
    assert (await client.post("/api/cypher", json={"query": "RETURN 1"})).status_code == 403
    assert await seeded.list_cypher_events() == []


async def test_rows_from_the_rest_route_carry_the_rest_origin(client, seeded, monkeypatch):
    monkeypatch.setattr(cypher_route, "run_readonly", lambda s, q, p, graph=False: TABLE)
    await login(client, "otto")
    assert (await client.post("/api/cypher", json={"query": "RETURN 1"})).status_code == 200
    assert (await client.post("/api/cypher", json={"query": "RETURN " + "1," * 40_000})).status_code == 413

    events = await seeded.list_cypher_events()
    assert sorted((e.outcome, e.origin, e.ai_step_id) for e in events) == [
        ("ok", "rest", None),
        ("too_large", "rest", None),
    ]
