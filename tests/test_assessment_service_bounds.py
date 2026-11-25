"""Service budgets count real request evaluations and preserve partial findings."""

from contextlib import nullcontext
from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from tests.test_path_trace import _rule

from hst.assessment import service
from hst.assessment.search import FAILS, HOLDS, UNKNOWN, SearchLimits
from hst.core.manifest import DeviceEntry
from hst.core.model import TableOutcome
from hst.results.project import project_engine
from hst.results.words import ANSWER_OF_VALUE
from hst.simul.fw_overlay import Catalog, ChangeSet, parse_intents

REQUEST = {
    "name": "app",
    "destination": "app",
    "sources": ["10.0.0.1"],
    "members": [{"name": "app", "addresses": ["203.0.113.10"]}],
    "condition": {"kind": "member", "member": "app"},
}


def result(state):
    outcome = {
        "verdict": state,
        "holds": ["10.0.0.1"] if state == HOLDS else [],
        "fails": ["10.0.0.1"] if state == FAILS else [],
        "unknown": ["10.0.0.1"] if state == UNKNOWN else [],
        "isolated": state == FAILS,
    }
    return {
        "outcomes": {"after": outcome},
        "snapshot": "2000",
        "gaps": [],
        "evidence": {"count": 20, "items": [{"detail": "x" * 1000} for _ in range(20)]},
    }


@dataclass
class FakeNetwork:
    checkpoint: object = None


class Context:
    calls = []
    policy_rows = {"rb": [_rule(action="drop")]}
    manifest = SimpleNamespace(
        estate="estate",
        devices=[
            DeviceEntry(
                source="s",
                host="h",
                outcome="collected",
                device_uids=["d"],
                fetch_started_ms=2000,
                tables={"rib": TableOutcome(status="complete", observed_ms=2000)},
            )
        ],
    )
    fail_candidate = False

    def __init__(self, settings, reference, request):
        self.reference = reference
        self.snapshot = SimpleNamespace(manifest=self.manifest)
        self.network = FakeNetwork()
        self.session = None
        self.request = service.ev._request_from_body(service.ev.RequestBody(**request))

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def policies(self, targets=None):
        return self.policy_rows, {"rb"}

    def evaluate(self, intents, mode, request=None):
        self.calls.append((intents, request))
        if self.fail_candidate and intents:
            raise HTTPException(400, "Invalid candidate target")
        return result(HOLDS if intents or request is not None else FAILS)


@pytest.fixture
def context(monkeypatch):
    monkeypatch.setattr(service, "EvaluationContext", Context)
    monkeypatch.setattr(Context, "calls", [])
    monkeypatch.setattr(Context, "fail_candidate", False)
    from tests.test_impact_evaluate import ev as engine

    monkeypatch.setattr(engine, "apply", lambda network, overlay: network)

    def cost_answer(network, request, mode):
        Context.calls.append(([], None))
        return object()

    monkeypatch.setattr(engine, "answer", cost_answer)

    class Cost:
        def __init__(self, network, request, scope, *, evaluate):
            self.network, self.request, self.evaluate, self.baseline = network, request, evaluate, False

        def __call__(self, network):
            if not self.baseline:
                self.evaluate(self.network, self.request, "possible")
                self.baseline = True
            self.evaluate(network, self.request, "possible")
            return {"lower": 0, "upper": 0, "exact": True}

    monkeypatch.setattr(service, "ScopeCostOracle", Cost)
    monkeypatch.setattr(
        service.ev,
        "_change_set",
        lambda session, intents, errors: ChangeSet(parse_intents(intents, Catalog())),
    )
    return Context


def inputs(kind="repair", evaluations=5):
    return {
        "definition": {"request": REQUEST, "mode": "possible", "intents": []},
        "analysis": {
            "kind": kind,
            "limits": {"max_candidates": 2, "max_evaluations": evaluations},
            "allowed_targets": {"rb": "d"},
            "allowed_kinds": ["fw_rule.add"],
            "scope": {
                "source": ["10.0.0.1"],
                "destination": ["203.0.113.10"],
                "protocols": ["tcp"],
                "ports": ["443"],
            },
            "protected": [{"name": "protected", "request": REQUEST, "desired": "holds"}],
        },
        "snapshot_refs": [{"snapshot": "2000"}, {"snapshot": "1000"}],
    }


def generated(*_args, **_kwargs):
    return {
        "candidates": [
            {
                "id": name,
                "device": "d",
                "intents": [
                    {
                        "kind": "fw_rule.add",
                        "params": {
                            "rulebase": "rb",
                            "uid": name,
                            "position": 1,
                            "action": "accept",
                            "source": ["any"],
                            "destination": ["any"],
                        },
                    }
                ],
            }
            for name in ("a", "b")
        ],
        "allowed_targets": {"rb": "d"},
        "allowed_kinds": ["fw_rule.add"],
        "universe_complete": True,
        "excluded": [],
        "generator_version": "test",
    }


def test_shared_budget_counts_baseline_and_protections_preserving_verified_partial(context, monkeypatch):
    monkeypatch.setattr(service, "generate_firewall_candidates", generated)
    outcome = service.execute(None, inputs(evaluations=9))
    assert len(context.calls) == outcome["engine_evaluations"] == 9
    assert outcome["stop_reason"] == "evaluation-limit"
    assert not outcome["search_complete"] and not outcome["scoped_search_complete"]
    assert len(outcome["findings"]) == 1
    assert outcome["findings"][0]["candidates"] == ["a"]
    assert not outcome["findings"][0]["minimum_cost"]
    unresolved = next(t for t in outcome["trials"] if t["candidates"] == ["b"])
    assert unresolved["result"]["answer"] == ANSWER_OF_VALUE[UNKNOWN]
    assert unresolved["evaluation"]["protected"]["protected"]["answer"] == ANSWER_OF_VALUE[UNKNOWN]
    detail = outcome["findings"][0]["summary"]
    assert detail["evidence_count"] == 20 and len(detail["evidence_sample"]) == 2
    assert not detail["full_result_retained"] and len(detail["result_sha256"]) == 64


def test_http_proposal_errors_are_unknown_with_protected_ids_retained(context, monkeypatch):
    monkeypatch.setattr(service, "generate_firewall_candidates", generated)
    monkeypatch.setattr(context, "fail_candidate", True)
    outcome = service.execute(None, inputs(evaluations=10))
    assert not outcome["findings"]
    unknowns = [t for t in outcome["trials"] if t["candidates"]]
    assert all(t["result"]["answer"] == ANSWER_OF_VALUE[UNKNOWN] for t in unknowns)
    assert all("Invalid candidate target" in t["evaluation"]["reason"] for t in unknowns)


def test_deadline_includes_model_load_and_does_not_invoke_evaluator(context, monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(service.time, "monotonic", lambda: clock[0])

    def load(self):
        clock[0] = 100
        return self

    monkeypatch.setattr(context, "__enter__", load)
    outcome = service.execute(None, inputs("evaluate"))
    assert not context.calls and outcome["engine_evaluations"] == 0
    assert outcome["result"]["answer"] == ANSWER_OF_VALUE[UNKNOWN] and outcome["stop_reason"] == "time-limit"


def test_cancelled_before_baseline_returns_explicit_unknown(context):
    outcome = service.execute(None, inputs("evaluate"), cancelled=lambda: True)
    assert not context.calls and outcome["stop_reason"] == "cancelled"


def test_regression_old_baseline_consumes_same_budget(context):
    outcome = service.execute(None, inputs("regression", evaluations=1))
    assert len(context.calls) == 1
    assert outcome["stop_reason"] == "evaluation-limit" and not outcome["findings"]


def test_manifest_without_graph_is_rejected_before_network_load(monkeypatch):
    reference = {"snapshot": "2000", "manifest_sha256": "digest"}
    monkeypatch.setattr(service.db, "session", lambda _: nullcontext(object()))
    monkeypatch.setattr(service.snapshot, "resolve", lambda *_: SimpleNamespace(cts=2000, manifest=object()))
    monkeypatch.setattr(service.manifest, "digest_of", lambda *_: "digest")
    monkeypatch.setattr(service.pathmod, "_read", lambda *_args, **_kwargs: [])
    with (
        pytest.raises(ValueError, match="no retained graph objects"),
        service.EvaluationContext(None, reference, REQUEST),
    ):
        raise AssertionError("Graph-free context must not open")


def test_new_fetch_with_old_rib_cannot_verify_deployment(context, monkeypatch):
    recorded = SimpleNamespace(
        estate="estate",
        devices=[
            DeviceEntry(
                source="s",
                host="h",
                outcome="collected",
                fetch_started_ms=2000,
                tables={"rib": TableOutcome(status="unchanged", observed_ms=500)},
            )
        ],
    )
    monkeypatch.setattr(context, "manifest", recorded)
    data = inputs("verify")
    # the prediction is a stored run, written in the result vocabulary
    prediction = project_engine(result(FAILS), "possible")
    data.update(deployment={"deployed_at": "1970-01-01T00:00:01+00:00"}, prediction=prediction)
    outcome = service.execute(None, data)
    assert not outcome["post_deployment_evidence"]
    assert outcome["observation_floor_ms"] == 500
    assert outcome["state"] == "insufficient-evidence"


def test_configuration_realization_compares_supported_resolved_ordered_rules(context, monkeypatch):
    before_rows = {"rb": [_rule(uid="old", action="drop")]}
    after_rows = {"rb": [_rule(uid="collected", action="accept")]}
    monkeypatch.setattr(context, "policy_rows", before_rows)
    monkeypatch.setattr(
        service.ev, "_change_set", lambda _s, intents, _e: ChangeSet(parse_intents(intents, Catalog()))
    )
    data = inputs("verify")
    data["definition"]["intents"] = [
        {"kind": "fw_rule.modify", "params": {"rulebase": "rb", "rule": "old", "action": "accept"}}
    ]
    data["prediction"] = {"snapshot": "1000"}
    observed = SimpleNamespace(policies=lambda: (after_rows, {"rb"}))
    outcome = service._configuration_realization(
        None, data, observed, service._Budget(SearchLimits(), None), True
    )
    assert outcome["state"] == "matches"
    after_rows["rb"][0]["action"] = "drop"
    outcome = service._configuration_realization(
        None, data, observed, service._Budget(SearchLimits(), None), True
    )
    assert outcome["state"] == "differs" and outcome["different_rulebases"] == ["rb"]


def test_configuration_realization_explains_unsupported_family(context):
    data = inputs("verify")
    data["definition"]["intents"] = [
        {"kind": "zone.add_interface", "params": {"zone": "z", "interface": "i"}}
    ]
    outcome = service._configuration_realization(
        None, data, None, service._Budget(SearchLimits(), None), True
    )
    assert outcome["state"] == "not-decided" and "zone.add_interface" in outcome["reason"]


def test_saved_proposal_evaluation_rechecks_isolation_protection(context):
    data = inputs("evaluate")
    data["definition"]["intents"] = [{"kind": "fw_rule.remove", "params": {"rulebase": "rb", "rule": "r"}}]
    data["analysis"]["protected"][0]["desired"] = "isolated"
    outcome = service.execute(None, data)
    assert outcome["outcomes"]["after"]["result"]["answer"] == ANSWER_OF_VALUE[HOLDS]
    assert outcome["constraints"]["protected"]["protected"]["answer"] == ANSWER_OF_VALUE[FAILS]
    assert outcome["constraints"]["result"]["answer"] == ANSWER_OF_VALUE[FAILS]
    assert not outcome["constraints"]["verified"]
    assert outcome["engine_evaluations"] == 2
