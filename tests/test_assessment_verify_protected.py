"""Verification rechecks protected whole requests on collected state without proposals."""

from copy import deepcopy

import pytest
from tests.test_assessment_service_semantic_integration import REQUEST, inputs
from tests.test_assessment_service_semantic_integration import contexts as contexts
from tests.test_impact_evaluate import B, _firewall
from tests.test_impact_evaluate import ev as engine
from tests.test_impact_evaluate import graph as graph
from tests.test_path_trace import _rule

from hst.assessment import service
from hst.assessment.search import FAILS, HOLDS, UNKNOWN
from hst.results.project import project_engine
from hst.results.words import ANSWER_OF_VALUE


@pytest.fixture
def verified_inputs(graph, contexts, monkeypatch):
    _firewall(
        graph, B, "rb:b", [_rule(uid="deny", action="drop", svc_any=False, protos=["tcp"], ports=["8443"])]
    )
    calls = []

    def evaluate(self, intents, mode, request=None):
        calls.append((intents, request, mode))
        assert intents == [], "verification must never apply the proposal to collected observations"
        requested = (
            self.request
            if request is None
            else service.ev._request_from_body(service.ev.RequestBody(**request))
        )
        answer = engine.answer(self.network, requested, mode)
        return {
            "outcomes": {"after": service.ev.outcome(answer)},
            "evidence": {"count": 0, "items": []},
            "gaps": [],
            "snapshot": self.reference["snapshot"],
        }

    monkeypatch.setattr(service.EvaluationContext, "evaluate", evaluate)
    monkeypatch.setattr(service, "observation_floor", lambda record: 2000)
    monkeypatch.setattr(service, "observation_coverage", lambda *args, **kwargs: {"qualifies": True})
    monkeypatch.setattr(service, "_configuration_realization", lambda *args: {"state": "not-decided"})
    data = inputs("verify")
    protection = {**deepcopy(REQUEST), "port": "8443"}
    data["analysis"]["protected"] = [{"name": "protected", "request": protection, "desired": "holds"}]
    data["definition"]["intents"] = [
        {"kind": "fw_rule.remove", "params": {"rulebase": "rb:b", "rule": "deny"}}
    ]
    request = service.ev._request_from_body(service.ev.RequestBody(**REQUEST))
    predicted = service.ev.outcome(engine.answer(contexts[0]["1"], request, "possible"))
    # the prediction is a stored run, written in the result vocabulary
    data["prediction"] = project_engine(
        {
            "outcomes": {"after": predicted},
            "constraints": {
                "desired": HOLDS,
                "protected": {"protected": HOLDS},
                "verdict": HOLDS,
                "verified": True,
            },
        },
        "possible",
    )
    data["deployment"] = {"deployed_at": "1970-01-01T00:00:01Z"}
    return data, calls


def test_desired_agreement_with_protected_deviation_is_not_agreement(verified_inputs):
    data, calls = verified_inputs
    result = service.execute(None, data)
    assert result["prediction"]["outcomes"]["after"] == result["observed"]["outcomes"]["after"]
    assert result["state"] == "deviation"
    assert result["protected_comparison"]["changed"] == ["protected"]
    assert result["observed"]["constraints"]["protected"]["protected"]["answer"] == ANSWER_OF_VALUE[FAILS]
    assert result["engine_evaluations"] == len(calls) == 2


def test_missing_predicted_protection_prevents_verification_agreement(verified_inputs):
    data, _ = verified_inputs
    data["prediction"].pop("constraints")
    result = service.execute(None, data)
    assert result["state"] == "insufficient-evidence"
    assert result["protected_comparison"]["missing_predictions"] == ["protected"]


def test_protected_verification_shares_engine_budget(verified_inputs):
    data, calls = verified_inputs
    data["analysis"]["limits"]["max_evaluations"] = 1
    result = service.execute(None, data)
    assert result["state"] == "insufficient-evidence"
    assert result["stop_reason"] == "evaluation-limit" and result["engine_evaluations"] == len(calls) == 1
    assert result["observed"]["constraints"]["protected"]["protected"]["answer"] == ANSWER_OF_VALUE[UNKNOWN]


def test_missing_protected_request_never_compares_vacuously(verified_inputs):
    data, _ = verified_inputs
    data["analysis"]["protected"] = []
    result = service.execute(None, data)
    assert result["state"] == "insufficient-evidence"
    assert result["protected_comparison"]["missing_requests"] == ["protected"]
