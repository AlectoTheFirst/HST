"""The legacy-v1 evaluation runs in the isolated child, under its deadline and process slot.

The child is ended at the deadline and holds the one process slot (`run_isolated`; the process
behavior is in tests/enterprise/test_direct_analysis.py). The routing calculation and the walk
also ask a checkpoint between steps, so the child stops itself as not established.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from hst.app.routes import impact as impact_route
from hst.assessment import direct, evaluation
from hst.assessment.jobs import PROCESS_CAPACITY
from hst.core import manifest
from hst.simul.errors import ErrorSink
from hst.simul.rib import RibInput, compute


def _routing() -> RibInput:
    return RibInput(
        contexts=[{"uid": "a", "device_uid": "dev:a", "platform": "nxos"}],
        connected=[{"context_uid": "a", "prefix": "192.0.2.0/24", "interface": "e0"}],
    )


def test_a_spent_checkpoint_stops_the_routing_calculation_as_not_the_answer() -> None:
    result = compute(_routing(), validate_observed=False, checkpoint=lambda: False)
    assert result.convergence["status"] == "budget-exhausted"
    assert "time budget" in result.convergence["detail"]
    assert "no-routing-fixed-point" in {e["kind"] for e in result.model_errors}


def test_a_checkpoint_with_time_left_changes_nothing() -> None:
    result = compute(_routing(), validate_observed=False, checkpoint=lambda: True)
    assert result.convergence["status"] == "settled"
    assert result.model_errors == []


def test_load_network_hands_the_checkpoint_to_the_walk_and_the_routing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(evaluation, "_model_interfaces", lambda session: ())
    monkeypatch.setattr(evaluation, "_context_domains", lambda session: {})
    monkeypatch.setattr(evaluation, "_contexts_in_scope", lambda interfaces, request: [])
    monkeypatch.setattr(
        evaluation.simul_read,
        "read_rib_input",
        lambda *a, **k: SimpleNamespace(input=_routing(), errors=ErrorSink()),
    )
    checkpoint = lambda: False  # noqa: E731
    network = evaluation.load_network(None, SimpleNamespace(mtu=None), checkpoint=checkpoint)
    assert network.checkpoint is checkpoint
    assert network.routes.convergence["status"] == "budget-exhausted"


_REQUEST = {
    "name": "app",
    "destination": "app",
    "sources": ["10.0.0.0/24"],
    "members": [{"name": "app", "addresses": ["10.1.0.0/24"]}],
    "condition": {"kind": "member", "member": "app"},
}


def _evaluate(settings: Any, **over: Any) -> Any:
    snapshot = SimpleNamespace(cts=2000, manifest=SimpleNamespace(estate="estate", devices=[]))
    return direct.evaluate_request(
        settings,
        None,
        snapshot,
        **{"intents": [], "requirement": None, "request": _REQUEST, "mode": "possible", **over},
    )


@pytest.fixture
def child(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    """The question handed to the isolated child, with the engine barred from this process."""
    asked: list[dict] = []

    def engine(*args: Any, **kwargs: Any) -> dict:
        raise AssertionError("the engine ran in the request thread")

    def isolated(settings: Any, inputs: dict) -> dict:
        asked.append(inputs)
        return {}

    monkeypatch.setattr(manifest, "digest_of", lambda settings, cts: "0" * 64)
    monkeypatch.setattr(impact_route, "evaluate_change", engine)
    monkeypatch.setattr(evaluation, "evaluate_change", engine)
    monkeypatch.setattr(direct, "run_isolated", isolated)
    return asked


def test_the_legacy_engine_question_goes_to_the_isolated_child_under_a_deadline(child: list[dict]) -> None:
    _evaluate(SimpleNamespace(analysis_engine="legacy-v1", analysis_timeout_s=500))
    (inputs,) = child
    assert inputs["definition"]["request"]["name"] == "app"
    assert inputs["analysis"]["kind"] == "evaluate"
    assert inputs["analysis"]["limits"]["max_seconds"] == 300  # the timeout is capped at 300
    assert inputs["snapshot_refs"][0]["snapshot"] == "2000"
    _evaluate(SimpleNamespace(analysis_engine="legacy-v1", analysis_timeout_s=60))
    assert child[1]["analysis"]["limits"]["max_seconds"] == 60


def test_the_legacy_engine_question_holds_the_process_slot_and_a_busy_slot_refuses_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ran: list[dict] = []
    monkeypatch.setattr(manifest, "digest_of", lambda settings, cts: "0" * 64)
    monkeypatch.setattr(
        direct, "_run_owned", lambda settings, inputs, *, execute=None: ran.append(inputs) or {}
    )
    settings = SimpleNamespace(analysis_engine="legacy-v1", analysis_timeout_s=60)
    assert PROCESS_CAPACITY.acquire(blocking=False)
    try:
        with pytest.raises(direct.CapacityBusy):
            _evaluate(settings)
    finally:
        PROCESS_CAPACITY.release()
    assert ran == []
    _evaluate(settings)
    assert len(ran) == 1
    assert PROCESS_CAPACITY.acquire(blocking=False)
    PROCESS_CAPACITY.release()


def test_the_slot_is_released_when_the_child_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    def failing(settings: Any, inputs: dict, *, execute: Any = None) -> dict:
        raise direct.HTTPException(503, "Analysis process exited without a result.")

    monkeypatch.setattr(manifest, "digest_of", lambda settings, cts: "0" * 64)
    monkeypatch.setattr(direct, "_run_owned", failing)
    for _ in range(3):
        with pytest.raises(direct.HTTPException):
            _evaluate(SimpleNamespace(analysis_engine="legacy-v1", analysis_timeout_s=60))
    assert PROCESS_CAPACITY.acquire(blocking=False)
    PROCESS_CAPACITY.release()


def test_an_oversize_change_set_is_refused_before_the_child(child: list[dict]) -> None:
    with pytest.raises(direct.HTTPException) as caught:
        _evaluate(SimpleNamespace(analysis_engine="legacy-v1"), intents=[{}] * 51)
    assert caught.value.status_code == 422
    assert child == []
