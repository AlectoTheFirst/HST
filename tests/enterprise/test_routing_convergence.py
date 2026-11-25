"""Bounded routing convergence in the RIB engine."""

from hst.simul.convergence import ConvergenceBudget, RepeatedStateDetector
from hst.simul.rib import RibInput, compute


def _input() -> RibInput:
    return RibInput(
        contexts=[{"uid": "a", "device_uid": "dev:a", "platform": "nxos"}],
        connected=[{"context_uid": "a", "prefix": "192.0.2.0/24", "interface": "e0"}],
    )


def test_model_can_settle_after_sixteen_rounds(monkeypatch):
    real_signature = __import__("hst.simul.rib", fromlist=["Table"]).Table.signature
    calls = {"count": 0}

    def delayed_signature(table):
        calls["count"] += 1
        if calls["count"] <= 17:
            return ("transient", calls["count"])
        return real_signature(table)

    monkeypatch.setattr("hst.simul.rib.Table.signature", delayed_signature)
    result = compute(_input(), validate_observed=False, budget=ConvergenceBudget(outer_rounds=24))

    assert result.rounds > 16
    assert result.convergence["status"] == "settled"
    assert "no-routing-fixed-point" not in {item["kind"] for item in result.model_errors}


def test_exact_nonadjacent_repeat_is_a_cycle_not_a_budget_guess(monkeypatch):
    calls = {"count": 0}

    def alternating_signature(_table):
        calls["count"] += 1
        return ("state", calls["count"] % 4)

    monkeypatch.setattr("hst.simul.rib.Table.signature", alternating_signature)
    result = compute(_input(), validate_observed=False, budget=ConvergenceBudget(outer_rounds=12))

    assert result.convergence["status"] == "cycle"
    assert result.convergence["repeated_from_round"] == 1
    assert result.convergence["repeated_at_round"] == 5
    assert "no-routing-fixed-point" in {item["kind"] for item in result.model_errors}


def test_repeated_state_detector_uses_exact_values():
    detector = RepeatedStateDetector()

    assert detector.observe(("a", 1), 1) is None
    assert detector.observe(("a", 2), 2) is None
    assert detector.observe(("a", 1), 3) == 1
