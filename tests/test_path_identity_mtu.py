"""An MTU request on the ZPA brokered entry point (`trace_from_identity`).

The brokered trace runs its forward walk inside the request's scope, with
the address family taken from the connector's own address and the
segment's resolved destinations, on a session pinned once.
"""

# ruff: noqa: F811

import contextlib
import importlib

import pytest
from tests.test_path_trace import GW, ZPA_IDENTITY, ZPA_SEGMENT, _zpa_allow_graph, graph  # noqa: F401

from hst import path
from hst.core.mtu import MtuRequest

tracemod = importlib.import_module("hst.path.trace")

INVENTORY = MtuRequest(mode="inventory")


class _Pinned:
    """A pinned session stand-in: no `cts`, so the MTU evidence read issues no query."""


@pytest.fixture()
def pinned(graph, monkeypatch):
    marker = _Pinned()
    sessions = []

    def read(session, query, **p):
        sessions.append(session)
        return graph.read(query, **p)

    def read_one(session, query, **p):
        sessions.append(session)
        return graph.read_one(query, **p)

    monkeypatch.setattr(path, "pinned", lambda session, snapshot: marker)
    monkeypatch.setattr(path, "_read", read)
    monkeypatch.setattr(path, "_read_one", read_one)
    return marker, sessions


def _recording_scope(monkeypatch):
    entered = []

    @contextlib.contextmanager
    def record(request, af):
        entered.append((request, af))
        yield

    monkeypatch.setattr(tracemod, "mtu_request", record)
    return entered


def test_a_brokered_trace_runs_its_mtu_request_once_in_scope_on_a_pinned_session(graph, pinned, monkeypatch):
    marker, sessions = pinned
    _zpa_allow_graph(graph)
    entered = _recording_scope(monkeypatch)

    result = path.trace_from_identity(
        None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW], mtu=INVENTORY
    )

    assert entered == [(INVENTORY, 4)]
    assert "mtu" in result
    sessions_after_pin = sessions[sessions.index(marker) :]
    assert sessions_after_pin and all(s is marker for s in sessions_after_pin)
    assert len(result["legs"]) == 1


def test_a_brokered_trace_with_mtu_answers_the_same_walk_as_without(graph, pinned):
    _zpa_allow_graph(graph)
    plain = path.trace_from_identity(None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW])
    sized = path.trace_from_identity(
        None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW], mtu=INVENTORY
    )
    assert "mtu" not in plain
    assert sized["mtu"]["mode"] == "inventory"
    assert sized["verdict"] == plain["verdict"]
    assert [h["uid"] for h in sized["hops"]] == [h["uid"] for h in plain["hops"]]


def test_an_early_stop_answers_the_mtu_request(graph, pinned, monkeypatch):
    entered = _recording_scope(monkeypatch)
    # no identity group in the graph: the trace stops before a connector is chosen
    result = path.trace_from_identity(
        None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW], mtu=INVENTORY
    )
    assert result["indeterminate"] is True
    assert result["mtu"]["mode"] == "inventory"
    assert entered == []


def test_mixed_address_families_under_an_mtu_request_raise(graph, pinned, monkeypatch):
    _zpa_allow_graph(graph)
    graph.segment_resolution[ZPA_SEGMENT] = [{"addr": "10.0.30.10"}, {"addr": "2001:db8::10"}]
    entered = _recording_scope(monkeypatch)
    with pytest.raises(ValueError, match="MTU tracing requires one address family per request"):
        path.trace_from_identity(
            None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW], mtu=INVENTORY
        )
    assert entered == []


def test_an_mtu_request_that_is_off_runs_no_scope(graph, pinned, monkeypatch):
    _zpa_allow_graph(graph)
    entered = _recording_scope(monkeypatch)
    result = path.trace_from_identity(
        None, ZPA_IDENTITY, ZPA_SEGMENT, port=443, proto="tcp", gateways=[GW], mtu={"mode": "off"}
    )
    assert entered == []
    assert "mtu" not in result
