"""The site panel's per-pair `blocked` flag follows the projected answer."""

from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import hst.path as path_engine
from hst.app.routes import sites as sites_routes
from hst.core import ribsource
from hst.core import snapshot as snapshotmod

TRACES = {
    "no-gateway": {"legs": []},
    "no-route": {"legs": [{"blocked": False, "verdict": "no route found"}]},
    "undecided": {"legs": [{"blocked": False, "indeterminate": True}]},
    "denied": {"legs": [{"blocked": True}]},
    "forwarded": {"legs": [{"blocked": False}]},
}


def _pairs(monkeypatch):
    @contextmanager
    def session(settings):
        yield object()

    monkeypatch.setattr(sites_routes.dbmod, "session", session)
    monkeypatch.setattr(snapshotmod, "resolve", lambda raw, settings: None)
    monkeypatch.setattr(path_engine, "pinned", lambda raw, snap: object())
    monkeypatch.setattr(path_engine, "load_gateways", lambda session: {})
    monkeypatch.setattr(ribsource, "for_snapshot", lambda snap: None)
    monkeypatch.setattr(
        path_engine,
        "trace",
        lambda session, src, dst, port=None, proto=None, gateways=None, rib=None, **contexts: {
            "legs": [dict(leg) for leg in TRACES[dst]["legs"]],
        },
    )
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=object())))
    prefix = sites_routes.SitePrefix
    pairs = [(prefix("a", None, None), prefix(dst, None, None)) for dst in TRACES]
    out = sites_routes._trace_pairs(request, pairs, None, "tcp", None, set())
    return {p["dst"]: p for p in out}


def test_unforwarded_and_undecided_pairs_are_not_flagged_open(monkeypatch):
    pairs = _pairs(monkeypatch)
    for name, pair in pairs.items():
        answer = (pair["result"] or {}).get("answer")
        assert pair["blocked"] is {"false": True, "true": False}.get(answer), name
    assert pairs["forwarded"]["blocked"] is False
    for name in ("no-gateway", "no-route", "undecided"):
        assert pairs[name]["blocked"] is not False, name


def _run_node(monkeypatch, answers: list[bool]):
    """A graph session whose run node is present per read as `answers` gives it."""

    class Session:
        def run(self, query, **params):
            rows = [{"uid": params["uid"]}] if answers.pop(0) else []
            return SimpleNamespace(data=lambda: rows)

    @contextmanager
    def session(settings):
        yield Session()

    monkeypatch.setattr(sites_routes.dbmod, "session", session)
    monkeypatch.setattr(path_engine, "pinned", lambda raw, snap: object())
    monkeypatch.setattr(path_engine, "load_gateways", lambda session: {})
    monkeypatch.setattr(ribsource, "for_snapshot", lambda snap: None)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=object())))
    return request, SimpleNamespace(cts=7000)


def test_a_run_pruned_during_the_pair_traces_is_refused(monkeypatch):
    request, snap = _run_node(monkeypatch, [True, False])
    with pytest.raises(HTTPException) as refused:
        sites_routes._trace_pairs(request, [], None, "tcp", snap, set(), True)
    assert refused.value.status_code == 409
    assert refused.value.detail == "run 7000 was pruned while it was read"


def test_a_run_pruned_before_the_lease_is_refused_before_the_first_trace(monkeypatch):
    request, snap = _run_node(monkeypatch, [False])
    with pytest.raises(HTTPException) as refused:
        sites_routes._trace_pairs(request, [], None, "tcp", snap, set(), True)
    assert refused.value.status_code == 409


def test_a_graph_with_no_run_node_is_traced_as_it_is(monkeypatch):
    request, snap = _run_node(monkeypatch, [])
    assert sites_routes._trace_pairs(request, [], None, "tcp", snap, set(), False) == []
    assert sites_routes._run_present(request, SimpleNamespace(cts=None)) is False
