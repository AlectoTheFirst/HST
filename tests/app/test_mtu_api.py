"""HTTP MTU validation and permission boundary without a graph database."""

from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from tests.app.conftest import login

from hst import path
from hst.app.routes import path as route
from hst.core import cycle as cyclemod
from hst.core import snapshot as snapshotmod
from hst.core.mtu import MtuRequest


@pytest.fixture(autouse=True)
def _no_run_node(monkeypatch):
    """These fakes hold no `:CycleRun` node, as a fixture load does: the reader
    lease's pruned-run check (routes/run_lease.py) reads the graph as it is."""
    monkeypatch.setattr(cyclemod, "run_present", lambda s, cts: False)


@pytest.fixture
def trace_capture(monkeypatch):
    calls = []
    monkeypatch.setattr(route, "_session", lambda *a: nullcontext(object()))
    monkeypatch.setattr(route.snapshotmod, "resolve", lambda *a: SimpleNamespace(cts=10))
    monkeypatch.setattr(route.ribsource, "for_snapshot", lambda *a: None)
    monkeypatch.setattr(route.cyclemod, "run_status", lambda *a: {"ts_ms": 10})
    monkeypatch.setattr(path, "pinned", lambda s, snap: s)
    monkeypatch.setattr(path, "trace", lambda *a, **kw: calls.append(kw) or {"verdict": "allow"})
    return calls


async def test_http_off_shape_and_packet_request(client, trace_capture):
    await login(client, "vera")
    base = "/api/path?src=192.0.2.1&dst=192.0.2.2"
    response = await client.get(base)
    assert response.status_code == 200
    assert "mtu" not in response.json() and "mtu" not in trace_capture[-1]
    response = await client.get(base + "&mtu_mode=packet&mtu_ip_packet_bytes=1500&mtu_ipv4_df=false")
    assert response.status_code == 200
    assert trace_capture[-1]["mtu"] == MtuRequest(mode="packet", ip_packet_bytes=1500, ipv4_df=False)


@pytest.mark.parametrize(
    "params",
    [
        "mtu_mode=packet",
        "mtu_mode=bad",
        "mtu_mode=off&mtu_ip_packet_bytes=1500",
        "mtu_mode=packet&mtu_ip_packet_bytes=1500&mtu_reply_ip_packet_bytes=1000",
        "mtu_mode=inventory&reply=true&snapshot_b=10",
    ],
)
async def test_invalid_http_combinations_never_trace(client, trace_capture, params):
    await login(client, "vera")
    response = await client.get("/api/path?src=192.0.2.1&dst=192.0.2.2&" + params)
    assert response.status_code in (400, 422)
    assert not trace_capture


async def test_audit_requires_authentication(client):
    response = await client.get("/api/mtu/audit")
    assert response.status_code == 401


async def test_audit_viewer_and_page_validation(client, monkeypatch):
    from hst.app.routes import mtu

    await login(client, "vera")
    monkeypatch.setattr(mtu, "_session", lambda *a: nullcontext(object()))
    monkeypatch.setattr(mtu.snapshotmod, "resolve", lambda *a: SimpleNamespace(cts=10))
    monkeypatch.setattr(path, "pinned", lambda s, snap: SimpleNamespace(cts=snap.cts))
    response = await client.get("/api/mtu/audit?limit=201")
    assert response.status_code == 400
    response = await client.get("/api/mtu/audit?scope=fabric")
    assert response.status_code == 400


@pytest.mark.parametrize("username", ["vera", "otto", "ada"])
async def test_audit_authorization_for_each_graph_reader(client, username, monkeypatch):
    from hst.app.routes import mtu

    await login(client, username)
    monkeypatch.setattr(mtu, "_session", lambda *a: nullcontext(object()))
    monkeypatch.setattr(mtu.snapshotmod, "resolve", lambda *a: SimpleNamespace(cts=10))
    monkeypatch.setattr(path, "pinned", lambda s, snap: SimpleNamespace(cts=snap.cts))
    monkeypatch.setattr(path, "_read", lambda *a, **kw: [])
    response = await client.get("/api/mtu/audit")
    assert response.status_code == 200
    assert response.json()["snapshot"] == 10
    assert response.json()["coverage_complete"] is False


async def test_audit_unknown_run_is_404_before_any_audit_read(client, monkeypatch):
    from hst.app.routes import mtu

    await login(client, "vera")
    reads: list = []
    audited: list = []
    monkeypatch.setattr(mtu, "_session", lambda *a: nullcontext(object()))
    monkeypatch.setattr(path, "_read", lambda s, query, **kw: reads.append((query, kw["snap"])) or [])
    monkeypatch.setattr(mtu, "audit_mtu", lambda *a, **kw: audited.append(kw))
    response = await client.get("/api/mtu/audit?snapshot=3000")
    assert response.status_code == 404
    assert response.json()["error"] == "unknown run: 3000"
    assert reads == [(snapshotmod._RETAINED_GRAPH, 3000)]
    assert audited == []


async def test_audit_run_id_that_is_not_digits_is_400_before_any_read(client, monkeypatch):
    from hst.app.routes import mtu

    await login(client, "vera")
    reads: list = []
    monkeypatch.setattr(mtu, "_session", lambda *a: nullcontext(object()))
    monkeypatch.setattr(path, "_read", lambda s, query, **kw: reads.append(query) or [])
    response = await client.get("/api/mtu/audit?snapshot=latest")
    assert response.status_code == 400
    assert "is not a run id" in response.json()["error"]
    assert reads == []


async def test_audit_retained_run_is_checked_and_then_audited(client, monkeypatch):
    from hst.app.routes import mtu

    await login(client, "vera")
    reads: list = []

    def read(s, query, **kw):
        reads.append(query)
        return [{"uid": "dev:a"}] if query == snapshotmod._RETAINED_GRAPH else []

    monkeypatch.setattr(mtu, "_session", lambda *a: nullcontext(object()))
    monkeypatch.setattr(path, "pinned", lambda s, snap: SimpleNamespace(cts=snap.cts))
    monkeypatch.setattr(path, "_read", read)
    response = await client.get("/api/mtu/audit?snapshot=3000")
    assert response.status_code == 200
    assert response.json()["snapshot"] == 3000
    assert reads[0] == snapshotmod._RETAINED_GRAPH


async def test_independent_reply_size_is_forwarded(client, trace_capture):
    await login(client, "vera")
    response = await client.get(
        "/api/path?src=192.0.2.1&dst=192.0.2.2&reply=true"
        "&mtu_mode=unfragmented&mtu_ip_packet_bytes=1500&mtu_reply_ip_packet_bytes=1000"
    )
    assert response.status_code == 200
    assert trace_capture[-1]["reply"] is True
    assert trace_capture[-1]["mtu"].reply_ip_packet_bytes == 1000
