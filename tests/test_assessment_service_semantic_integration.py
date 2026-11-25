from types import SimpleNamespace

import pytest
from tests.test_impact_evaluate import (
    VRF_A,
    VRF_B,
    VRF_R1,
    B,
    _changes,
    _firewall,
    _network,
    _routing,
    _static,
)
from tests.test_impact_evaluate import (
    ev as engine,
)
from tests.test_impact_evaluate import graph as graph
from tests.test_path_trace import _rule

from hst.assessment import service
from hst.assessment.dependencies import DependencyRecorder
from hst.assessment.models import Analyze
from hst.assessment.search import FAILS, HOLDS

REQUEST = {
    "name": "app",
    "sources": ["10.0.0.0/31"],
    "destination": "app",
    "members": [{"name": "app", "addresses": ["203.0.113.10/31"]}],
    "condition": {"kind": "member", "member": "app"},
    "proto": "tcp",
    "port": "443-444",
    "source_port": "1234",
}


@pytest.fixture
def contexts(monkeypatch):
    models = {
        "1": _network(_routing(bgp=False, static=[_static("203.0.113.0/24", "10.0.1.2")])),
        "2": _network(_routing(bgp=False, static=[_static("203.0.113.0/24", "10.0.2.2")])),
    }
    opened = {}

    class Context:
        def __init__(self, settings, reference, request, **kwargs):
            self.reference = reference
            self.request = service.ev._request_from_body(service.ev.RequestBody(**request))
            self.network = models[reference["snapshot"]]
            self.snapshot = SimpleNamespace(
                cts=reference["snapshot"], manifest=SimpleNamespace(estate="test")
            )
            self.session = None
            self.dependencies = DependencyRecorder("test", reference["snapshot"])

        def __enter__(self):
            opened[self.reference["snapshot"]] = True
            return self

        def __exit__(self, *args):
            opened[self.reference["snapshot"]] = False

        def evaluate(self, intents, mode, request=None):
            return self.evaluate_model(engine.apply(self.network, _changes(*intents)), mode)

        def evaluate_model(self, network, mode):
            assert opened[self.reference["snapshot"]]
            answer = engine.answer(network, self.request, mode)
            return {
                "outcomes": {"after": service.ev.outcome(answer)},
                "snapshot": self.reference["snapshot"],
                "evidence": {"count": 0, "items": []},
                "gaps": [],
            }

        def policies(self, targets=None):
            return {"rb:b": [_rule(uid="deny", action="drop")]}, {"rb:b"}

        def model_catalogs(self):
            return {"firewall": {}, "nat": {}}, set(), set(), {VRF_R1, VRF_A, VRF_B}

    monkeypatch.setattr(service, "EvaluationContext", Context)
    monkeypatch.setattr(service.ev, "_change_set", lambda session, intents, errors: _changes(*intents))
    monkeypatch.setattr(
        service,
        "read_snapshot_inputs",
        lambda session, snapshot, settings, **kwargs: {
            "snapshot": snapshot.cts,
            "complete": True,
            "records": [],
            "coverage": {},
            "limits": {},
            "stop_reason": "complete",
        },
    )
    return models, opened


def inputs(kind):
    return {
        "definition": {"request": REQUEST, "mode": "possible", "intents": []},
        "snapshot_refs": [{"snapshot": "2"}, {"snapshot": "1"}],
        "analysis": {
            "kind": kind,
            "limits": {"max_evaluations": 30},
            "allowed_targets": {"rb:b": B},
            "allowed_kinds": ["fw_rule.remove"],
            "protected": [],
            "scope": {
                "source": ["10.0.0.0/31"],
                "destination": ["203.0.113.10/31"],
                "protocols": ["tcp"],
                "ports": ["443-444"],
                "source_ports": ["1234"],
            },
        },
    }


def test_service_uses_both_snapshot_models_and_merges_dependencies(graph, contexts):
    _firewall(graph, B, "rb:b", [_rule(uid="deny", action="drop")])
    result = service.execute(None, inputs("regression"))
    assert result["before_verdict"] == HOLDS and result["after_verdict"] == FAILS
    assert result["findings"][0]["forward_replay"]["reproduces_failure"]
    assert {d["snapshot"] for d in result["dependencies"]} == {"1", "2"}
    assert not any(contexts[1].values())


def test_service_exact_scope_cost_and_reviewable_rule_diff(graph, contexts):
    _firewall(graph, B, "rb:b", [_rule(uid="deny", action="drop")])
    result = service.execute(None, inputs("repair"))
    assert result["search_complete"] and result["scope_cost_measured"]
    proposal = result["findings"][0]
    assert proposal["verified"] and proposal["minimum_cost"]
    assert proposal["cost"] == [1, 8, 1]
    assert proposal["diff"][0]["before"]["uid"] == "deny" and proposal["diff"][0]["after"] is None
    assert result["engine_evaluations"] == 5


def test_cost_order_schema_and_optional_source_port_universe():
    request = inputs("repair")["analysis"]
    parsed = Analyze(**request, cost_order=["newly_permitted_scope", "rule_edits", "devices"])
    assert parsed.scope["source_ports"] == ["1234"]
    with pytest.raises(ValueError, match="exactly once"):
        Analyze(**request, cost_order=["devices"] * 3)


def test_collected_nat_realization_compares_effective_semantics_with_new_rule_uid(
    graph, contexts, monkeypatch
):
    from tests.test_impact_evaluate import R1
    from tests.test_path_nat import _dnat_row

    from hst.assessment.search import SearchLimits

    data = inputs("verify")
    data["prediction"] = {"snapshot": "1"}
    data["definition"]["intents"] = [
        {
            "kind": "nat_rule.modify",
            "params": {
                "device": R1,
                "rule": "dnat:r10",
                "translation": "10.0.0.88",
                "xlate_dst": ["10.0.0.88"],
            },
        }
    ]
    before_rows = [_dnat_row()]
    overlay = _changes(*data["definition"]["intents"])
    collected = [{**row, "uid": "collector:assigned"} for row in overlay._rewrite_nat_rules(R1, before_rows)]

    def catalogs(self):
        rows = before_rows if self.reference["snapshot"] == "1" else collected
        return {"firewall": {}, "nat": {R1: rows}}, set(), {R1}, {VRF_R1}

    monkeypatch.setattr(service.EvaluationContext, "model_catalogs", catalogs)
    with service.EvaluationContext(None, {"snapshot": "2"}, REQUEST) as current:
        result = service._configuration_realization(
            None, data, current, service._Budget(SearchLimits(), None), True
        )
    assert result["state"] == "matches"
