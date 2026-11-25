"""Path and canned-query routes: viewer surface, Neo4j faked at module seams."""

from types import SimpleNamespace

import pytest
from tests.app.conftest import login

import hst.app.routes.path as path_route
import hst.app.routes.queries as queries_route

TRACE = {"verdict": "ok", "notes": [], "hops": [], "legs": []}


async def test_path_requires_auth(client):
    r = await client.get("/api/path", params={"src": "10.0.0.1", "dst": "8.8.8.8"})
    assert r.status_code == 401


async def test_path_traces(client, monkeypatch):
    await login(client, "vera")
    seen = {}

    def fake_trace(
        session, src, dst, *, port=None, proto="tcp", rib=None, src_context=None, dst_context=None
    ):
        seen.update(src=src, dst=dst, port=port, proto=proto)
        return TRACE

    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "trace", fake_trace)
    r = await client.get(
        "/api/path", params={"src": "192.168.10.0/24", "dst": "8.8.8.8", "port": "443", "proto": "udp"}
    )
    assert r.status_code == 200 and r.json() == {**TRACE, "run": None}
    assert seen == {"src": "192.168.10.0/24", "dst": "8.8.8.8", "port": 443, "proto": "udp"}


async def test_path_passes_src_and_dst_context_through_verbatim(client, monkeypatch):
    """The two params are anchor uids, never names, and the route forwards them
    to trace() as given."""
    await login(client, "vera")
    seen = {}

    def fake_trace(
        session, src, dst, *, port=None, proto="tcp", rib=None, src_context=None, dst_context=None
    ):
        seen.update(src_context=src_context, dst_context=dst_context)
        return TRACE

    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "trace", fake_trace)
    r = await client.get(
        "/api/path",
        params={
            "src": "10.0.0.5",
            "dst": "8.8.8.8",
            "src_context": "vrf:dev:r1:home",
            "dst_context": "vrf:dev:r2:guest",
        },
    )
    assert r.status_code == 200 and r.json() == {**TRACE, "run": None}
    assert seen == {"src_context": "vrf:dev:r1:home", "dst_context": "vrf:dev:r2:guest"}


async def test_path_missing_dst_is_422(client):
    await login(client, "vera")
    assert (await client.get("/api/path", params={"src": "10.0.0.1"})).status_code == 422


async def test_path_reply_refusal_is_a_400_with_the_engine_reason(client, monkeypatch):
    """The engine refuses a reply for a source that resolves to more than one
    forwarding interpretation by raising ValueError with the reason; the route
    hands that reason back as a 400."""
    await login(client, "vera")

    def fake_trace(session, src, dst, **kw):
        if kw.get("reply"):
            raise ValueError(
                "reply=True is not supported for '10.0.0.5': it exists in 2 source "
                "interpretations, and there is no single flow tuple for a reply to answer for"
            )
        return dict(TRACE)

    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "trace", fake_trace)
    r = await client.get("/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8", "reply": "true"})
    assert r.status_code == 400
    # the engine's own reason, not the word "source"
    assert "interpretations" in r.json()["error"]


async def test_path_reply_for_a_network_scoped_source_returns_the_lane_list(client, monkeypatch):
    """A prefix source with reply=true is a 200 carrying one reply lane
    per forward leg, each naming the forward leg it answers for."""
    await login(client, "vera")
    lanes = [
        {
            "forward_leg": 0,
            "src_label": "10.0.0.0/25",
            "destinations": ["10.0.0.0/25"],
            "verdict": "reply: egress via eth1",
            "notes": [],
            "hops": [],
            "legs": [],
            "asymmetric": False,
        },
        {
            "forward_leg": 1,
            "src_label": "10.0.0.128/25",
            "destinations": ["10.0.0.128/25"],
            "verdict": "reply: egress via eth2",
            "notes": [],
            "hops": [],
            "legs": [],
            "asymmetric": True,
        },
    ]
    nested = {"forward": dict(TRACE), "reply": lanes, "asymmetric": True, "notes": []}

    def fake_trace(session, src, dst, **kw):
        return dict(nested)

    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "trace", fake_trace)

    r = await client.get("/api/path", params={"src": "10.0.0.0/24", "dst": "8.8.8.8", "reply": "true"})

    assert r.status_code == 200
    assert r.json() == {**nested, "run": None}


async def test_path_reply_true_returns_the_nested_shape(client, monkeypatch):
    """reply=true calls trace(..., reply=True) and hands back its nested
    {forward, reply, asymmetric, notes} shape under the same `run` key every
    other response carries."""
    await login(client, "vera")
    seen = {}
    nested = {
        "forward": dict(TRACE),
        "reply": {"verdict": "ok", "notes": [], "hops": [], "legs": []},
        "asymmetric": False,
        "notes": [],
    }

    def fake_trace(
        session, src, dst, *, port=None, proto="tcp", rib=None, src_context=None, dst_context=None, **kw
    ):
        seen["reply"] = kw.get("reply", False)
        return dict(nested) if kw.get("reply") else dict(TRACE)

    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "trace", fake_trace)

    plain = await client.get("/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8"})
    assert plain.status_code == 200 and plain.json() == {**TRACE, "run": None}
    assert seen["reply"] is False

    replied = await client.get("/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8", "reply": "true"})
    assert replied.status_code == 200
    assert replied.json() == {**nested, "run": None}
    assert seen["reply"] is True


async def test_path_reply_and_snapshot_b_together_is_400(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "trace", lambda *a, **k: dict(TRACE))
    r = await client.get(
        "/api/path",
        params={"src": "10.0.0.5", "dst": "8.8.8.8", "reply": "true", "snapshot_b": "2000"},
    )
    assert r.status_code == 400
    body = r.json()["error"]
    assert "reply" in body and "snapshot_b" in body


async def test_catalog_lists_queries(client):
    await login(client, "vera")
    r = await client.get("/api/queries")
    body = r.json()["queries"]
    assert any(q["key"] == "devices" for q in body)
    assert all({"key", "title", "group", "cypher"} <= set(q) for q in body)


async def test_canned_query_runs_with_declared_params_only(client, monkeypatch):
    await login(client, "vera")
    calls = {}

    def fake_run_readonly(settings, cypher, params, trusted=False, graph=False):
        calls.update(cypher=cypher, params=params, trusted=trusted, graph=graph)
        return {"columns": ["x"], "data": [], "truncated": False}

    monkeypatch.setattr(queries_route, "run_readonly", fake_run_readonly)
    r = await client.post(
        "/api/queries/find-vlan", json={"params": {"vid": "30", "sneaky": "MATCH (n) RETURN n"}}
    )
    assert r.status_code == 200
    assert calls["params"] == {"vid": "30"}  # undeclared params dropped
    # the catalog's own Cypher bypasses the operator guard: `search` calls
    # db.index.fulltext.queryNodes, which the guard does not allow
    assert calls["trusted"] is True
    # the browser draws the node-link view from this; the agent's tool does not
    # ask for it
    assert calls["graph"] is True
    assert (await client.post("/api/queries/nope", json={})).status_code == 404


from contextlib import contextmanager  # noqa: E402


@contextmanager
def _fake_session_cm(settings):
    yield object()


class _RetainedRunSession:
    """Answers the run-existence check a named snapshot passes before the trace."""

    def __init__(self, retained: tuple[int, ...] = (2000,)) -> None:
        self.checked: list[int] = []
        self._retained = retained

    def execute_read(self, work):
        session = self

        class _Tx:
            def run(self, query, **params):
                session.checked.append(params["snap"])
                rows = [{"uid": "dev:a"}] if params["snap"] in session._retained else []
                return SimpleNamespace(data=lambda: rows)

        return work(_Tx())


def _retained_session_cm(session):
    @contextmanager
    def cm(settings):
        yield session

    return cm


async def test_scenario_entries_from_the_catalog_run(client, monkeypatch):
    """The rail lists scenario-* keys; running must accept what listing offers."""
    await login(client, "vera")
    calls = {}

    def fake_run_readonly(settings, cypher, params, trusted=False, graph=False):
        calls.update(cypher=cypher)
        return {"columns": ["x"], "data": [], "truncated": False}

    monkeypatch.setattr(queries_route, "run_readonly", fake_run_readonly)
    r = await client.post("/api/queries/scenario-dora-providers", json={})
    assert r.status_code == 200
    assert "Provider" in calls["cypher"]


async def test_path_carries_the_run_it_was_pinned_to(client, monkeypatch):
    """A pinned trace names its run and the run's health: degraded, carried and
    failed sources are part of the answer."""
    await login(client, "vera")
    status = {
        "snapshot": "2000",
        "created": "2026-09-01T00:00:00+00:00",
        "degraded": True,
        "sources_carried": ["vyos-gw"],
        "sources_failed": [],
        "sources_partial": [],
    }

    def fake_trace(
        session, src, dst, *, port=None, proto="tcp", rib=None, src_context=None, dst_context=None
    ):
        return dict(TRACE)

    monkeypatch.setattr(path_route, "_session", _retained_session_cm(_RetainedRunSession()))
    monkeypatch.setattr(path_route.pathmod, "trace", fake_trace)
    monkeypatch.setattr(
        path_route.cyclemod, "run_status", lambda s, snap: status if snap.cts == 2000 else None
    )
    r = await client.get("/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8", "snapshot": "2000"})
    assert r.status_code == 200
    assert r.json()["run"] == status


async def test_path_an_unknown_run_is_404_before_any_trace(client, monkeypatch):
    await login(client, "vera")
    session = _RetainedRunSession(retained=())
    traced: list = []
    monkeypatch.setattr(path_route, "_session", _retained_session_cm(session))
    monkeypatch.setattr(path_route.pathmod, "trace", lambda *a, **k: traced.append(a) or dict(TRACE))

    r = await client.get("/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8", "snapshot": "3000"})
    assert r.status_code == 404
    assert r.json()["error"] == "unknown run: 3000"
    assert session.checked == [3000]
    assert traced == []


async def test_path_compare_with_an_unknown_b_run_is_404_before_either_trace(client, monkeypatch):
    await login(client, "vera")
    session = _RetainedRunSession(retained=(2000,))
    traced: list = []
    monkeypatch.setattr(path_route, "_session", _retained_session_cm(session))
    monkeypatch.setattr(path_route.pathmod, "trace", lambda *a, **k: traced.append(a) or dict(TRACE))

    r = await client.get(
        "/api/path",
        params={"src": "10.0.0.5", "dst": "8.8.8.8", "snapshot": "2000", "snapshot_b": "3000"},
    )
    assert r.status_code == 404
    assert r.json()["error"] == "unknown run: 3000"
    assert session.checked == [2000, 3000]
    assert traced == []


@pytest.mark.parametrize("param", ["snapshot", "snapshot_b"])
async def test_path_a_run_id_that_is_not_digits_is_400_before_any_read(client, monkeypatch, param):
    await login(client, "vera")
    session = _RetainedRunSession()
    traced: list = []
    monkeypatch.setattr(path_route, "_session", _retained_session_cm(session))
    monkeypatch.setattr(path_route.pathmod, "trace", lambda *a, **k: traced.append(a) or dict(TRACE))

    params = {"src": "10.0.0.5", "dst": "8.8.8.8", "snapshot": "2000", param: "latest"}
    r = await client.get("/api/path", params=params)
    assert r.status_code == 400
    assert "is not a run id" in r.json()["error"]
    assert traced == []


def _status(snap) -> dict:
    return {
        "snapshot": str(snap.cts),
        "created": "2026-09-01T00:00:00+00:00",
        "degraded": False,
        "sources_carried": [],
        "sources_failed": [],
        "sources_partial": [],
    }


async def test_path_holds_a_lease_on_the_run_it_reads_for_the_length_of_the_trace(client, store, monkeypatch):
    """The prune keeps every leased run."""
    await login(client, "vera")
    held: list[set[int]] = []

    def fake_trace(session, src, dst, **kw):
        held.append({key for key, _ in store._run_leases.values()})
        return dict(TRACE)

    monkeypatch.setattr(path_route, "_session", _retained_session_cm(_RetainedRunSession((2000, 3000))))
    monkeypatch.setattr(path_route.pathmod, "trace", fake_trace)
    monkeypatch.setattr(path_route.cyclemod, "run_status", lambda s, snap: _status(snap))

    r = await client.get(
        "/api/path",
        params={"src": "10.0.0.5", "dst": "8.8.8.8", "snapshot": "2000", "snapshot_b": "3000"},
    )

    assert r.status_code == 200
    assert held == [{2000, 3000}, {2000, 3000}]  # both sides, each trace
    assert store._run_leases == {}  # released when the request ends


async def test_path_releases_its_lease_when_the_trace_fails(client, store, monkeypatch):
    await login(client, "vera")

    def fake_trace(session, src, dst, **kw):
        raise ValueError("unreadable port spec")

    monkeypatch.setattr(path_route, "_session", _retained_session_cm(_RetainedRunSession()))
    monkeypatch.setattr(path_route.pathmod, "trace", fake_trace)
    monkeypatch.setattr(path_route.cyclemod, "run_status", lambda s, snap: _status(snap))

    r = await client.get("/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8", "snapshot": "2000"})

    assert r.status_code == 400
    assert store._run_leases == {}


async def test_path_a_run_pruned_while_the_trace_ran_is_a_409_not_a_partial_answer(client, monkeypatch):
    """The prune removes a run's `:CycleRun` node before its objects, so a run that had its
    node when the request resolved it and has none after the trace has been pruned."""
    await login(client, "vera")
    reads: list[int] = []

    def run_status(s, snap):
        reads.append(snap.cts)
        return _status(snap) if len(reads) <= 2 else None  # resolved, checked, then gone

    monkeypatch.setattr(path_route, "_session", _retained_session_cm(_RetainedRunSession()))
    monkeypatch.setattr(path_route.pathmod, "trace", lambda *a, **k: dict(TRACE))
    monkeypatch.setattr(path_route.cyclemod, "run_status", run_status)

    r = await client.get("/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8", "snapshot": "2000"})

    assert r.status_code == 409
    assert r.json()["error"] == "run 2000 was pruned while the trace ran"


async def test_path_a_run_pruned_before_the_trace_starts_is_a_409(client, monkeypatch):
    await login(client, "vera")
    reads: list[int] = []

    def run_status(s, snap):
        reads.append(snap.cts)
        return _status(snap) if len(reads) == 1 else None

    traced: list = []
    monkeypatch.setattr(path_route, "_session", _retained_session_cm(_RetainedRunSession()))
    monkeypatch.setattr(path_route.pathmod, "trace", lambda *a, **k: traced.append(a) or dict(TRACE))
    monkeypatch.setattr(path_route.cyclemod, "run_status", run_status)

    r = await client.get("/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8", "snapshot": "2000"})

    assert r.status_code == 409
    assert traced == []


async def test_path_without_a_pinned_run_carries_no_run(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "trace", lambda *a, **k: dict(TRACE))
    r = await client.get("/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8"})
    assert r.status_code == 200 and r.json()["run"] is None


async def test_path_accepts_a_port_range_and_protocol_list_and_returns_sibling_legs(client, monkeypatch):
    """/api/path accepts a port range and a protocol list."""
    from tests.test_path_trace import GW, FakeGraph, _route, _rule, _src_row

    await login(client, "vera")
    g = FakeGraph()
    g.sources = [_src_row()]
    g.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    g.rb = {
        "rb_uid": "rb:1",
        "rb_name": "Standard",
        "vendor": "checkpoint",
        "default_action": "accept",
        "approximate": False,
    }
    g.rules = [_rule(uid="cp:deny", pos=1, action="drop", svc_any=False, protos=["tcp"], ports=["1-100"])]

    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path_route.pathmod, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    monkeypatch.setattr(path_route.pathmod, "load_gateways", lambda session: [GW])

    r = await client.get(
        "/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8", "port": "50-150", "proto": "tcp,udp"}
    )
    assert r.status_code == 200
    legs = r.json()["legs"]
    # the rule is scoped to tcp only, so udp never matches it and rides the
    # remainder whole; tcp splits into the rule's own decided sub-range and
    # what is left of it: three legs, one union-of-rectangles answer
    assert len(legs) == 3
    services = sorted(
        (tuple(ll["service"]["proto"]), tuple(map(tuple, ll["service"]["ports"])), ll["blocked"])
        for ll in legs
    )
    assert services == [
        (("tcp",), ((50, 100),), True),
        (("tcp",), ((101, 150),), False),
        (("udp",), ((50, 150),), False),
    ]


async def test_path_a_token_the_parser_cannot_resolve_400s(client, monkeypatch):
    await login(client, "vera")
    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "trace", lambda *a, **k: dict(TRACE))
    bad_proto = await client.get(
        "/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8", "proto": "not-a-protocol"}
    )
    assert bad_proto.status_code == 400
    bad_port = await client.get(
        "/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8", "port": "not-a-port"}
    )
    assert bad_port.status_code == 400


@pytest.mark.parametrize("proto", ["any", "tcp_udp"])
async def test_path_accepts_a_protocol_token_naming_more_than_one_protocol(client, monkeypatch, proto):
    """A single token can name a set of protocols: "any" and "tcp_udp" both do.
    They reach the trace as that set, so a rule scoped to one of its members
    decides its own region."""
    from tests.test_path_trace import GW, FakeGraph, _route, _rule, _src_row

    await login(client, "vera")
    g = FakeGraph()
    g.sources = [_src_row()]
    g.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    g.rb = {
        "rb_uid": "rb:1",
        "rb_name": "Standard",
        "vendor": "checkpoint",
        "default_action": "drop",
        "approximate": False,
    }
    g.rules = [_rule(uid="cp:ok", pos=1, action="accept", svc_any=False, protos=["tcp"], ports=["443"])]

    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path_route.pathmod, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    monkeypatch.setattr(path_route.pathmod, "load_gateways", lambda session: [GW])

    r = await client.get(
        "/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8", "port": "443", "proto": proto}
    )
    assert r.status_code == 200
    legs = r.json()["legs"]
    permitted = [ll for ll in legs if not ll["blocked"]]
    assert len(permitted) == 1
    assert permitted[0]["service"] == {"proto": ["tcp"], "ports": [[443, 443]]}
    # every other protocol the token names falls to the default action
    assert any(ll["blocked"] for ll in legs)


async def test_path_accepts_a_bare_protocol_number(client, monkeypatch):
    """A lone token that resolves to exactly one protocol is kept literal, a
    bare number such as "6" included: neither `port` nor `proto` states a
    range here, so the query runs the point path, which `_proto_matches`
    resolves by protocol number when the literal word misses.
    The point path never sets a leg's `service` field, so the rule's accept
    action is checked through `blocked`/`verdict`."""
    from tests.test_path_trace import GW, FakeGraph, _route, _rule, _src_row

    await login(client, "vera")
    g = FakeGraph()
    g.sources = [_src_row()]
    g.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    g.rb = {
        "rb_uid": "rb:1",
        "rb_name": "Standard",
        "vendor": "checkpoint",
        "default_action": "drop",
        "approximate": False,
    }
    g.rules = [_rule(uid="cp:ok", pos=1, action="accept", svc_any=False, protos=["tcp"], ports=["443"])]

    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path_route.pathmod, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    monkeypatch.setattr(path_route.pathmod, "load_gateways", lambda session: [GW])

    r = await client.get(
        "/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8", "port": "443", "proto": "6"}
    )
    assert r.status_code == 200
    legs = r.json()["legs"]
    permitted = [ll for ll in legs if not ll["blocked"]]
    assert len(permitted) == 1
    assert permitted[0]["blocked"] is False
    assert permitted[0]["detail"] == "egress via eth0"


async def test_path_accepts_the_canonical_icmpv6_spelling_against_a_rule_stored_as_icmp6(client, monkeypatch):
    """Check Point writes "icmp6" where the engine's table canon is "icmpv6"
    (addrsets._PROTO_NUM). `port="any"` alone states a range, so this query
    runs the ranged path."""
    from tests.test_path_trace import GW, FakeGraph, _route, _rule, _src_row

    await login(client, "vera")
    g = FakeGraph()
    g.sources = [_src_row()]
    g.routes = {"vrf:main": [_route("0.0.0.0/0", egress="eth0")]}
    g.rb = {
        "rb_uid": "rb:1",
        "rb_name": "Standard",
        "vendor": "checkpoint",
        "default_action": "drop",
        "approximate": False,
    }
    g.rules = [_rule(uid="cp:ok", pos=1, action="accept", svc_any=False, protos=["icmp6"], ports=["any"])]

    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path_route.pathmod, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    monkeypatch.setattr(path_route.pathmod, "load_gateways", lambda session: [GW])

    r = await client.get(
        "/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8", "port": "any", "proto": "icmpv6"}
    )
    assert r.status_code == 200
    legs = r.json()["legs"]
    permitted = [ll for ll in legs if not ll["blocked"]]
    assert len(permitted) == 1
    assert permitted[0]["service"] == {"proto": ["icmpv6"], "ports": [[0, 65535]]}


async def test_path_keeps_the_point_path_answer_for_a_canonical_name(client, monkeypatch):
    """A lone token that is one of the names no other key in the protocol
    table also names ("tcp") stays the literal word."""
    await login(client, "vera")
    seen = {}

    def fake_trace(
        session, src, dst, *, port=None, proto="tcp", rib=None, src_context=None, dst_context=None
    ):
        seen.update(port=port, proto=proto)
        return TRACE

    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "trace", fake_trace)
    r = await client.get(
        "/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8", "port": "443", "proto": "tcp"}
    )
    assert r.status_code == 200
    assert seen == {"port": 443, "proto": "tcp"}


async def test_path_a_no_route_leg_carries_the_service_its_group_answers_for(client, monkeypatch):
    """A leg that does not come from the firewall/NAT region fan-out (here, a
    "no route found" leg) answers only for the part of a ranged query
    its group carries, so it carries a `service` field like its siblings."""
    from tests.test_path_trace import GW, FakeGraph, _src_row

    await login(client, "vera")
    g = FakeGraph()
    g.sources = [_src_row()]
    g.routes = {"vrf:main": []}

    monkeypatch.setattr(path_route, "_session", _fake_session_cm)
    monkeypatch.setattr(path_route.pathmod, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path_route.pathmod, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    monkeypatch.setattr(path_route.pathmod, "load_gateways", lambda session: [GW])

    r = await client.get(
        "/api/path", params={"src": "10.0.0.5", "dst": "8.8.8.8", "port": "1-1024", "proto": "tcp,udp"}
    )
    assert r.status_code == 200
    legs = r.json()["legs"]
    assert len(legs) == 1
    assert legs[0]["detail"] == "no route found"
    assert legs[0]["service"] == {"proto": ["tcp", "udp"], "ports": [[1, 1024]]}
