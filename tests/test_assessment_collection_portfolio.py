"""Policy evidence and portfolio guidance preserve normal collector contracts."""

from types import SimpleNamespace

import pytest

from hst.assessment.evidence import portfolio, troubleshoot
from hst.collectors.recipes import section_recipe
from hst.core.manifest import DeviceEntry
from hst.core.model import SectionOutcome


def policy_result(kind="not-collected"):
    return {
        "verdict": "not-established",
        "evidence": {
            "items": [
                {
                    "outcome": "not-established",
                    "side": "after",
                    "member": "app",
                    "request_region": {"sources": ["10.0.0.0/24"]},
                    "steps": [
                        {
                            "stage": "firewall",
                            "kind": "observation-gap",
                            "device_uid": "fw",
                            "evidence_gap": {
                                "code": "policy-observation-incomplete",
                                "kind": kind,
                                "subject": "fw",
                                "dimension": "policy",
                            },
                        }
                    ],
                }
            ],
        },
    }


def recorded(status):
    return SimpleNamespace(
        sources=[SimpleNamespace(name="policy", type="checkpoint")],
        files=[],
        devices=[
            DeviceEntry(
                source="policy",
                host="",
                outcome="collected",
                device_uids=["fw"],
                sections={"access": SectionOutcome(status=status), "nat": SectionOutcome(status="ok")},
            )
        ],
    )


def test_missing_policy_uses_real_controller_discovery_and_never_an_unrelated_rib():
    guidance = troubleshoot(policy_result(), recorded("failed"), {"name": "web", "sources": ["10.0.0.0/24"]})
    (action,) = guidance["actions"]
    assert action["scope"] == "source" and action["host"] == ""
    assert action["tables"] == []
    assert "POST /web_api/show-access-rulebase" in action["commands"]
    assert "POST /web_api/show-access-layers" in action["commands"]
    for status in ("ok", "empty", "unsupported"):
        assert not troubleshoot(
            policy_result(), recorded(status), {"name": "web", "sources": ["10.0.0.0/24"]}
        )["actions"]
    assert not troubleshoot(
        policy_result("unsupported"), recorded("failed"), {"name": "web", "sources": ["10.0.0.0/24"]}
    )["actions"]


def test_shared_controller_action_sums_distinct_priorities_and_preserves_exact_origins():
    request = {"name": "same display name", "sources": ["10.0.0.0/24"]}
    result = troubleshoot(policy_result(), recorded("failed"), request)
    result["actions"][0]["origins"] = [{"assessment_id": "a", "run_id": "run-a", "action_id": "action-a"}]
    ranked = portfolio([("a", 7, result), ("b", 3, result), ("a", 7, result)])
    (action,) = ranked["actions"]
    assert action["priority"] == 10
    assert action["requirements"] == ["a", "b"]
    assert action["origins"][0]["run_id"] == "run-a"
    assert action["affected_source_addresses"] == 512


@pytest.mark.parametrize(
    "collector,section",
    [
        ("checkpoint", "nat"),
        ("apic", "endpoint"),
        ("unifi", "policy"),
        ("zpa", "connectors"),
        ("vyos", "config"),
        ("nxos", "interfaces"),
    ],
)
def test_observation_recipes_name_existing_operations(collector, section):
    recipe = section_recipe(collector, section)
    assert recipe and recipe.commands and recipe.prerequisites
    assert recipe.collector == collector and recipe.section == section
