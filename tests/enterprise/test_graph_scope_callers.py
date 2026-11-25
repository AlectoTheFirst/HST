"""Every symbolic load is budgeted from the worker memory and scoped
to the devices its request touches, and a read past the scope is repeated
with the wider scope."""

from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from hst.analysis_model import graph as graphmod
from hst.analysis_model.graph import ScopeExtension
from hst.assessment import flow_match, rule_explain, service

from .test_reply_scope import _estate, _request


class _Stop(Exception):
    pass


def _capture(monkeypatch, result=None):
    calls = []

    def load_graph(session, snapshot, digest, **options):
        calls.append(options)
        if result is None:
            raise _Stop
        return result

    monkeypatch.setattr(graphmod, "load_graph", load_graph)
    return calls


def _context(scope):
    context = object.__new__(service.EvaluationContext)
    context.settings = SimpleNamespace(analysis_memory_mb=2048, analysis_timeout_s=30)
    context.session = object()
    context.snapshot = SimpleNamespace(cts=1)
    context.reference = {"manifest_sha256": "a" * 64, "estate": "estate"}
    context.network = _estate()
    context.request = _request()
    context.symbolic = None
    context._catalog = None
    context._scoped_loads = 0
    context.graph_scope = scope
    return context


def test_the_assessment_engine_loads_the_request_scope_within_the_worker_budget(monkeypatch):
    calls = _capture(monkeypatch)
    context = _context(service._REQUEST_SCOPE)

    with pytest.raises(_Stop):
        context._symbolic_engine()

    assert calls[0]["memory_mb"] == 2048
    assert calls[0]["devices"] == frozenset({"r1", "r2"})
    assert context.graph_scope == frozenset({"r1", "r2"})


class _Engine:
    def __init__(self, scope):
        self.graph = SimpleNamespace(scope=scope)
        self.closed = False

    def close(self):
        self.closed = True


def test_a_context_method_is_repeated_with_the_widened_scope():
    scope = frozenset({"r1"})
    context = _context(scope)
    engine = context.symbolic = _Engine(scope)
    calls = []

    def call():
        calls.append(context.graph_scope)
        if len(calls) == 1:
            raise ScopeExtension(frozenset({"r9"}), "past the scope", scope)
        return "answer"

    assert context._scoped(call) == "answer"
    assert calls == [scope, frozenset({"r1", "r9"})]
    assert engine.closed is True and context.symbolic is None


def test_a_read_of_another_contexts_graph_is_not_repeated_here():
    scope = frozenset({"r1"})
    context = _context(scope)
    context.symbolic = _Engine(scope)

    def call():
        raise ScopeExtension(frozenset({"r9"}), "past the scope", frozenset({"r1"}))

    with pytest.raises(ScopeExtension):
        context._scoped(call)


def test_a_job_that_reads_past_its_scope_runs_again_with_the_wider_scope(monkeypatch):
    seen = []

    def execute(settings, inputs, **options):
        seen.append(service._GRAPH_SCOPE.get())
        if len(seen) == 1:
            raise ScopeExtension(frozenset({"r9"}), "past the scope", frozenset({"r1"}))
        return {"result": True}

    monkeypatch.setattr(service, "_execute", execute)
    monkeypatch.setattr("hst.results.project.project_engine", lambda result, mode: result)

    assert service.execute(object(), {}) == {"result": True}
    assert seen == [service._REQUEST_SCOPE, frozenset({"r1", "r9"})]
    assert service._GRAPH_SCOPE.get() is service._REQUEST_SCOPE


@contextmanager
def _session(settings, access_mode=None):
    yield object()


def _patch_session(monkeypatch):
    monkeypatch.setattr("hst.core.db.session", _session)
    monkeypatch.setattr(
        "hst.core.snapshot.resolve", lambda session, settings, snapshot: SimpleNamespace(cts=1)
    )


def test_rule_explain_loads_the_firewall_scope_within_the_worker_budget(monkeypatch):
    _patch_session(monkeypatch)
    graph = object()
    calls = _capture(monkeypatch, result=graph)
    monkeypatch.setattr(rule_explain, "explain", lambda loaded, *args, **kwargs: {"graph": loaded})
    inputs = {
        "snapshot": {"snapshot": 1, "manifest_sha256": "a" * 64, "estate": "estate"},
        "rulebase": "rb",
        "rule": "rule",
        "address_family": 4,
        "firewall": "dev:fw",
        "offset": 0,
        "limit": 10,
    }

    assert rule_explain.execute_explain(SimpleNamespace(analysis_memory_mb=3072), inputs) == {"graph": graph}
    assert calls == [{"memory_mb": 3072, "devices": frozenset({"dev:fw"}), "cancelled": None}]


def test_flow_match_loads_the_device_scope_within_the_worker_budget(monkeypatch):
    _patch_session(monkeypatch)
    graph = object()
    calls = _capture(monkeypatch, result=graph)
    monkeypatch.setattr(flow_match, "match", lambda loaded, *args, **kwargs: {"graph": loaded})
    inputs = {
        "snapshot": {"snapshot": 1, "manifest_sha256": "a" * 64, "estate": "estate"},
        "device": "dev:fw",
        "flow": {},
        "address_family": 4,
    }

    assert flow_match.execute_match(SimpleNamespace(analysis_memory_mb=512), inputs) == {"graph": graph}
    assert calls == [{"memory_mb": 512, "devices": frozenset({"dev:fw"}), "cancelled": None}]


def test_a_scope_past_the_worker_budget_is_a_limit_not_an_unavailable_engine(monkeypatch):
    _patch_session(monkeypatch)

    def load_graph(*args, **options):
        raise graphmod.GraphTooLarge(
            "SCOPE_TOO_LARGE: the nodes of the objects of 1 devices exceed the budget"
        )

    monkeypatch.setattr(graphmod, "load_graph", load_graph)
    inputs = {
        "snapshot": {"snapshot": 1, "manifest_sha256": "a" * 64, "estate": "estate"},
        "device": "dev:fw",
        "flow": {},
        "address_family": 4,
    }

    error = flow_match.execute_match(SimpleNamespace(analysis_memory_mb=512), inputs)["error"]

    assert error["code"] == "limit_exceeded"
    assert error["message"].startswith("SCOPE_TOO_LARGE")


def test_a_job_past_the_worker_budget_stops_with_scope_too_large(monkeypatch):
    import json

    from hst.assessment import jobs

    sent = []
    connection = SimpleNamespace(send_bytes=sent.append, close=lambda: None)

    def execute(settings, inputs, **options):
        raise graphmod.GraphTooLarge("SCOPE_TOO_LARGE: the nodes of the whole run exceed the budget")

    # no address-space limit on the test process
    monkeypatch.setattr(jobs.sys, "platform", "darwin")
    cancellation = SimpleNamespace(is_set=lambda: False)
    jobs._execute_child(object(), {}, connection, cancellation, 1024, execute, "engine")

    message = json.loads(sent[-1])
    assert message["kind"] == "error"
    assert message["value"]["stop_reason"] == "scope-too-large"
    assert message["value"]["error"].startswith("SCOPE_TOO_LARGE")
