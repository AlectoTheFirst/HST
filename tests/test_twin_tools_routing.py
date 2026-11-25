"""The routing tools: observed routes through the explore route body, BGP
sessions and paths, and route prediction. `test_twin_tools_routing_computed_search_policy.py`
tests the computed routes, the prefix search and the policy evaluation."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from tests.twin_tools_fakes import FakeGraph, call, context, install

from hst.app.agent import tools as tools_mod
from hst.core import bgpsource
from hst.twin_tools.routing import ADMIN_UNKNOWN

_RUN = "1700000001000-bbbbbbbb"
_DEVICE = ("MATCH (d:Device:Obj {uid: $uid, collection_ts: $snap})", [{"uid": "dev:r1"}])


def _node(label, name=None, device_uid=None):
    """The node lookup of the explore route body."""
    return ("CASE WHEN n:VrfInstance THEN", [{"label": label, "name": name, "device_uid": device_uid}])


@pytest.fixture
def rib_store(tmp_path):
    """One device's routes in two contexts, in a side store with no manifest."""
    pytest.importorskip("duckdb")
    from hst.core import ipenc, sidestore

    def row(prefix, next_hop, protocol, context_uid):
        lo, hi, prefixlen, af = ipenc.prefix_bounds(prefix)
        return {
            "device_uid": "dev:r1",
            "vrf": "x",
            "context_uid": context_uid,
            "prefix": prefix,
            "next_hop": next_hop,
            "interface": "eth0",
            "protocol": protocol,
            "metric": 1,
            "af": af,
            "prefixlen": prefixlen,
            "lo": lo,
            "hi": hi,
        }

    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "",
        _RUN,
        [
            row("0.0.0.0/0", "10.0.0.1", "static", "vrf:r1:blue"),
            row("10.1.0.0/16", "10.0.0.2", "ospf", "vrf:r1:blue"),
            row("10.1.2.0/24", "10.0.0.3", "bgp", "vrf:r1:blue"),
            row("192.0.2.0/24", "10.0.0.9", "bgp", "vrf:r1:red"),
        ],
        1700,
    )
    return tmp_path


# --- routing_routes ------------------------------------------------------------------------


def test_a_lookup_lists_the_covering_routes_of_a_named_context_longest_first(monkeypatch, rib_store):
    graph = install(
        monkeypatch,
        FakeGraph(
            [
                _DEVICE,
                ("toLower($context)", [{"uid": "vrf:r1:blue", "name": "blue"}]),
                _node("VrfInstance", "blue", "dev:r1"),
            ]
        ),
    )

    failed, envelope = call(
        "routing_routes",
        {"mode": "lookup", "device": "dev:r1", "context": "blue", "address": "10.1.2.7"},
        context(sidestore_dir=rib_store),
    )

    assert not failed, envelope
    result = envelope["result"]
    assert result["context_uid"] == "vrf:r1:blue"
    assert [r["prefix"] for r in result["routes"]] == ["10.1.2.0/24", "10.1.0.0/16", "0.0.0.0/0"]
    assert [r["longest_match"] for r in result["routes"]] == [True, False, False]
    assert all(r["admin"] is None for r in result["routes"])
    assert result["run_id"] == _RUN and result["approximate"] is True
    # no manifest governs the run, so no table outcome proves a row
    assert {r["evidence"]["result"]["word"] for r in result["routes"]} == {
        "recorded from an incomplete table"
    }
    assert envelope["evidence"]["result"]["word"] == "recorded from an incomplete table"
    assert ADMIN_UNKNOWN in envelope["evidence"]["unknowns"]
    (context_read,) = graph.reads("toLower($context)")
    assert context_read["device"] == "dev:r1" and context_read["context"] == "blue"


def test_an_observed_row_is_proven_when_the_table_was_recorded_complete(monkeypatch):
    from hst.app.routes import explore

    install(monkeypatch, FakeGraph([_DEVICE]))
    body = {
        "available": True,
        "approximate": False,
        "coverage": "complete",
        "device_uid": "dev:r1",
        "context_uid": None,
        "run_id": _RUN,
        "total": 1,
        "offset": 0,
        "limit": 50,
        "protocols": [],
        "items": [{"prefix": "10.1.2.0/24", "prefixlen": 24, "next_hop": "10.0.0.3"}],
    }
    monkeypatch.setattr(explore, "route_table", lambda *a, **k: body)

    failed, envelope = call("routing_routes", {"mode": "lookup", "device": "dev:r1", "address": "10.1.2.7"})

    assert not failed
    complete = envelope["result"]["routes"][0]["evidence"]
    assert complete["result"]["word"] == "recorded from a complete table"
    assert (complete["result"]["kind"], complete["basis"]) == ("record", "observed")
    assert envelope["evidence"]["result"]["word"] == "recorded from a complete table"
    assert envelope["evidence"]["coverage"] == "complete"
    assert envelope["evidence"]["complete"] is True


def test_an_empty_lookup_establishes_nothing(monkeypatch, rib_store):
    install(monkeypatch, FakeGraph([_DEVICE, _node("Device")]))

    failed, envelope = call(
        "routing_routes",
        {"mode": "lookup", "device": "dev:r1", "address": "2001:db8::1"},
        context(sidestore_dir=rib_store),
    )

    assert not failed
    assert envelope["result"]["routes"] == []
    assert envelope["evidence"]["result"]["word"] == "no record matches in the snapshot"
    assert envelope["evidence"]["absence"] == "not_recorded"


def test_a_table_pages_with_a_cursor(monkeypatch, rib_store):
    install(monkeypatch, FakeGraph([_DEVICE, _node("Device")]))
    ctx = context(sidestore_dir=rib_store)

    _, first = call("routing_routes", {"mode": "table", "device": "dev:r1", "limit": 3}, ctx)
    _, second = call(
        "routing_routes",
        {"mode": "table", "device": "dev:r1", "limit": 3, "cursor": first["page"]["next_cursor"]},
        ctx,
    )

    assert [r["prefix"] for r in first["result"]["routes"]] == ["0.0.0.0/0", "10.1.0.0/16", "10.1.2.0/24"]
    assert first["page"]["truncated"] is True and first["page"]["total"] == 4
    assert first["result"]["protocols"][0] == {"protocol": "bgp", "count": 2}
    assert [r["prefix"] for r in second["result"]["routes"]] == ["192.0.2.0/24"]
    assert second["page"]["truncated"] is False and second["page"]["next_cursor"] is None


def test_an_unknown_context_is_not_found_and_an_ambiguous_one_lists_candidates(monkeypatch):
    install(monkeypatch, FakeGraph([_DEVICE]))
    failed, error = call("routing_routes", {"mode": "table", "device": "dev:r1", "context": "green"})
    assert failed and error["error"]["code"] == "not_found" and error["error"]["field"] == "context"

    two = [{"uid": "vrf:r1:a", "name": "blue"}, {"uid": "vrf:r1:b", "name": "BLUE"}]
    install(monkeypatch, FakeGraph([_DEVICE, ("toLower($context)", two)]))
    failed, error = call("routing_routes", {"mode": "table", "device": "dev:r1", "context": "blue"})
    assert failed and error["error"]["code"] == "ambiguous"
    assert [c["uid"] for c in error["error"]["candidates"]] == ["vrf:r1:a", "vrf:r1:b"]


def test_a_lookup_refuses_an_address_that_is_not_one_before_any_read(monkeypatch):
    graph = install(monkeypatch, FakeGraph())

    failed, error = call("routing_routes", {"mode": "lookup", "device": "dev:r1", "address": "10.1.2"})

    assert failed and error["error"]["code"] == "invalid_argument" and error["error"]["field"] == "address"
    assert graph.calls == []


# --- routing_bgp ---------------------------------------------------------------------------


class _FakeBgp:
    """A BGP side-store reader with one observed session and one path table."""

    available = True
    approximate = False

    def __init__(self, coverage="complete"):
        self._coverage = coverage

    def session_state(self, uid):
        if uid == "bgp:r1:10.1.0.2":
            return {"state": "established", "established_since_ms": 5, "af": 4, "safi": "unicast"}
        return None

    def paths(self, device_uid, context_uid=None, prefix=None, *, direction=None, session_uid=None):
        self.asked = (device_uid, context_uid, prefix, direction, session_uid)
        return [
            {"prefix": "10.9.0.0/16", "direction": "accepted", "as_path": "65002", "best": True},
            {"prefix": "10.8.0.0/16", "direction": "accepted", "as_path": "65002 65003", "best": True},
        ]

    def coverage(self, device_uid, table=bgpsource.ROUTES):
        return self._coverage

    def direction_status(self, session_uid, direction):
        return "not-captured" if direction == "received" else "complete"

    def close(self):
        return None


_SESSIONS = [
    {
        "uid": "bgp:r1:10.1.0.2",
        "device_uid": "dev:r1",
        "vrf": "default",
        "peer_ip": "10.1.0.2",
        "peer_asn": 65002,
    },
    {
        "uid": "bgp:r1:10.1.0.3",
        "device_uid": "dev:r1",
        "vrf": "default",
        "peer_ip": "10.1.0.3",
        "peer_asn": 65003,
    },
]


def test_sessions_carry_their_observed_state_and_say_when_none_was_captured(monkeypatch):
    graph = install(monkeypatch, FakeGraph([("(s:BgpSession)", _SESSIONS)]))
    monkeypatch.setattr(bgpsource, "for_snapshot", lambda snap: _FakeBgp())

    failed, envelope = call("routing_bgp", {"mode": "sessions", "peer_asn": 65002})

    assert not failed
    first, second = envelope["result"]["items"]
    assert first["observed"]["state"] == "established"
    assert (
        first["evidence"]["result"]["word"] == "recorded in this run"
        and first["evidence"]["basis"] == "observed"
    )
    assert second["observed"] is None
    assert second["evidence"]["result"]["word"] == "configured; the session state was not captured"
    assert second["evidence"]["result"]["missing"][0]["code"] == "session-state-not-captured"
    assert (second["evidence"]["result"]["kind"], second["evidence"]["basis"]) == ("record", "configured")
    assert [m["code"] for m in second["evidence"]["result"]["missing"]] == ["session-state-not-captured"]
    assert envelope["evidence"]["result"]["word"] == "each item states its own result"
    assert any("not evidence that they are down" in u for u in envelope["evidence"]["unknowns"])
    (read,) = graph.reads("(s:BgpSession)")
    assert read["peer_asn"] == 65002 and read["device"] is None


def test_paths_report_the_direction_status_of_a_named_session(monkeypatch):
    install(monkeypatch, FakeGraph([_DEVICE]))
    reader = _FakeBgp()
    monkeypatch.setattr(bgpsource, "for_snapshot", lambda snap: reader)

    failed, envelope = call(
        "routing_bgp",
        {"mode": "paths", "device": "dev:r1", "session_uid": "bgp:r1:10.1.0.2", "limit": 1},
    )

    assert not failed
    result = envelope["result"]
    assert reader.asked == ("dev:r1", None, None, None, "bgp:r1:10.1.0.2")
    assert result["direction_status"] == {
        "received": "not-captured",
        "accepted": "complete",
        "advertised": "complete",
    }
    assert [i["prefix"] for i in result["items"]] == ["10.9.0.0/16"]
    assert envelope["page"]["truncated"] is True and envelope["page"]["total"] == 2
    assert envelope["evidence"]["result"]["word"] == "recorded from a complete table"
    assert any("received direction" in u for u in envelope["evidence"]["unknowns"])


# --- routing_predict_routes ----------------------------------------------------------------


def _prediction(delta_rows, baseline_rows=None, errors=()):
    return tools_mod.RoutePrediction(
        scope="dev:r1",
        scope_kind="device",
        delta=SimpleNamespace(rib=delta_rows, model_errors=list(errors)),
        baseline=None if baseline_rows is None else SimpleNamespace(rib=baseline_rows),
    )


def test_a_prediction_pages_over_vrfs_and_is_possible_at_most(monkeypatch):
    install(monkeypatch, FakeGraph([_DEVICE]))
    rows = [
        {"context_uid": "vrf:r1:a", "prefix": "10.1.0.0/16", "next_hop": "10.0.0.2"},
        {"context_uid": "vrf:r1:b", "prefix": "10.2.0.0/16", "next_hop": "10.0.0.3"},
    ]
    monkeypatch.setattr(tools_mod, "route_prediction", lambda *a, **k: _prediction(rows))

    failed, first = call("routing_predict_routes", {"scope": "dev:r1", "limit": 1})
    _, second = call(
        "routing_predict_routes", {"scope": "dev:r1", "limit": 1, "cursor": first["page"]["next_cursor"]}
    )

    assert not failed
    assert [v["context_uid"] for v in first["result"]["vrfs"]] == ["vrf:r1:a"]
    assert [v["context_uid"] for v in second["result"]["vrfs"]] == ["vrf:r1:b"]
    assert first["result"]["vrf_count"] == 2
    assert (
        first["result"]["vrfs"][0]["evidence"]["result"]["word"]
        == "computed from configuration; not observed"
    )
    assert first["result"]["vrfs"][0]["added"] is None
    assert first["evidence"]["result"]["word"] == "computed from configuration; not observed"
    assert f"model scope: {tools_mod.MODEL_SCOPE}" in first["evidence"]["unknowns"]


def test_a_prediction_with_intents_lists_what_the_change_adds_removes_and_changes(monkeypatch):
    install(monkeypatch, FakeGraph([_DEVICE]))
    before = [
        {"context_uid": "vrf:r1:a", "prefix": "10.1.0.0/16", "next_hop": "10.0.0.2"},
        {"context_uid": "vrf:r1:a", "prefix": "10.2.0.0/16", "next_hop": "10.0.0.2"},
    ]
    after = [
        {"context_uid": "vrf:r1:a", "prefix": "10.1.0.0/16", "next_hop": "10.0.0.9"},
        {"context_uid": "vrf:r1:a", "prefix": "10.3.0.0/16", "next_hop": "10.0.0.2"},
    ]
    not_modeled = {
        "kind": "not-modeled-yet",
        "detail": "fw_rule.add is not modeled",
        "subject": "fw_rule.add",
    }
    seen = {}

    def predict(pinned, scope, intents, *, baseline=False):
        seen.update(scope=scope, intents=intents, baseline=baseline)
        return _prediction(after, before, [not_modeled])

    monkeypatch.setattr(tools_mod, "route_prediction", predict)

    failed, envelope = call(
        "routing_predict_routes",
        {
            "scope": "dev:r1",
            "intents": [{"kind": "bgp_session.shut", "params": {"session": "s"}}, {"kind": "fw_rule.add"}],
        },
    )

    assert not failed
    assert seen["baseline"] is True
    assert [i["kind"] for i in seen["intents"]] == ["bgp_session.shut", "fw_rule.add"]
    (vrf,) = envelope["result"]["vrfs"]
    assert [r["prefix"] for r in vrf["added"]] == ["10.3.0.0/16"]
    assert [r["prefix"] for r in vrf["removed"]] == ["10.2.0.0/16"]
    assert [c["prefix"] for c in vrf["changed"]] == ["10.1.0.0/16"]
    (gap,) = envelope["evidence"]["gaps"]
    assert (gap["code"], gap["kind"], gap["subject"]) == ("not-modeled-yet", "not-modeled", "fw_rule.add")


def test_a_prediction_scope_that_names_no_device_is_not_found_on_the_scope_field(monkeypatch):
    install(monkeypatch, FakeGraph())

    failed, error = call("routing_predict_routes", {"scope": "edge-9"})

    assert failed and error["error"]["code"] == "not_found" and error["error"]["field"] == "scope"


def test_a_prediction_refuses_a_kind_outside_the_simulator_catalog(monkeypatch):
    graph = install(monkeypatch, FakeGraph())

    failed, error = call("routing_predict_routes", {"scope": "dev:r1", "intents": [{"kind": "vlan.add"}]})

    assert failed and error["error"]["code"] == "invalid_argument" and error["error"]["field"] == "intents"
    assert graph.session_kwargs == []
