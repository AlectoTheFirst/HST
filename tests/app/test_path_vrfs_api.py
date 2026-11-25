"""GET /api/path/vrfs and the `start_table` and `start_vrf` parameters of GET /api/path."""

from contextlib import contextmanager

from tests.app.conftest import login

import hst.app.routes.path as path_route

TRACE = {"verdict": "ok", "notes": [], "hops": [], "legs": []}
VRFS = [
    {"name": "global_segment", "devices": 4},
    {"name": "hosting", "devices": 12},
]


@contextmanager
def _fake_session_cm(settings):
    yield object()


async def test_vrfs_require_auth(client):
    assert (await client.get("/api/path/vrfs")).status_code == 401


async def test_vrfs_answer_the_engine_list(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "start_vrfs", lambda session: VRFS)

    r = await client.get("/api/path/vrfs")

    assert r.status_code == 200 and r.json() == {"vrfs": VRFS}


async def test_vrfs_reject_a_snapshot_that_is_not_a_run_id(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "start_vrfs", lambda session: VRFS)

    assert (await client.get("/api/path/vrfs", params={"snapshot": "not-a-run"})).status_code == 400


async def test_path_passes_start_table_through(client, monkeypatch):
    await login(client, "vera")
    seen = {}

    def fake_trace(session, src, dst, **kw):
        seen.update(start_table=kw.get("start_table"))
        return dict(TRACE)

    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "trace", fake_trace)

    r = await client.get(
        "/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8", "start_table": "vrf:dev:border:hosting"}
    )

    assert r.status_code == 200
    assert seen == {"start_table": "vrf:dev:border:hosting"}


async def test_path_start_table_with_src_context_is_a_400(client, monkeypatch):
    await login(client, "vera")

    def fake_trace(session, src, dst, **kw):
        raise ValueError("start_table and src_context cannot both be set")

    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "trace", fake_trace)

    r = await client.get(
        "/api/path",
        params={"src": "10.0.0.5", "dst": "8.8.8.8", "start_table": "vrf:a", "src_context": "vrf:a"},
    )

    assert r.status_code == 400
    assert "cannot both be set" in r.json()["error"]


async def test_path_passes_start_vrf_to_the_vrf_trace(client, monkeypatch):
    await login(client, "vera")
    seen = {}

    def fake_trace_from_vrf(session, src, dst, vrf, **kw):
        seen.update(vrf=vrf, start_table=kw.get("start_table"))
        return dict(TRACE)

    def no_trace(session, src, dst, **kw):
        raise AssertionError("a start_vrf request is not a plain trace")

    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "trace_from_vrf", fake_trace_from_vrf)
    monkeypatch.setattr(path_route.pathmod, "trace", no_trace)

    r = await client.get("/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8", "start_vrf": "hosting"})

    assert r.status_code == 200
    assert seen == {"vrf": "hosting", "start_table": None}


async def test_path_start_vrf_with_start_table_is_a_400(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(path_route, "_session", _fake_session_cm)

    r = await client.get(
        "/api/path",
        params={"src": "10.0.0.5", "dst": "8.8.8.8", "start_vrf": "hosting", "start_table": "vrf:a"},
    )

    assert r.status_code == 400
    assert "start_vrf cannot be set with start_table or src_context" in r.json()["error"]
