from dataclasses import replace
from types import SimpleNamespace

from tests.test_impact_sessions import network, request

from hst.assessment.evidence import gap_from_step, rank_actions, troubleshoot
from hst.collectors import iosxe, iosxr, nxos
from hst.collectors.recipes import routing_recipe
from hst.core.manifest import DeviceEntry
from hst.core.model import SectionOutcome, TableOutcome
from hst.impact import answer


def manifest(collector="nxos", *, sections=None, tables=None, carried=False):
    return SimpleNamespace(
        sources=[SimpleNamespace(name="inventory", type=collector)],
        devices=[
            DeviceEntry(
                source="inventory",
                host="router",
                outcome="collected",
                device_uids=["r1"],
                sections=sections or {},
                tables=tables or {},
                carried=carried,
            )
        ],
    )


def unknown(*, stage="route", kind="incomplete", device="r1", sources=None):
    return {
        "not_established": {"after": {"count": 1}},
        "evidence": {
            "items": [
                {
                    "side": "after",
                    "outcome": "not-established",
                    "member": "app",
                    "request_region": {"sources": sources or ["10.0.0.0/25"]},
                    "steps": [
                        {
                            "stage": stage,
                            "kind": kind,
                            "device_uid": device,
                            "detail": "The producer text may be localized or rewritten.",
                        }
                    ],
                }
            ]
        },
    }


REQ = {"name": "service", "sources": ["10.0.0.0/24"]}


def test_supported_recipes_are_collector_commands_and_state_full_scope():
    for name, module in (("nxos", nxos), ("iosxe", iosxe), ("iosxr", iosxr)):
        recipe = routing_recipe(name, 4)
        assert recipe.commands == (module.SECTIONS["rib"].command,)
        assert recipe.scope == "device" and recipe.prerequisites
        assert routing_recipe(name, 6) is None
    assert "show ipv6 route" in routing_recipe("vyos", 6).commands[0]


def test_missing_rib_yields_typed_recipe_with_actual_region():
    result = troubleshoot(unknown(), manifest(), REQ, priority=3, device_uids={"r1"})
    assert len(result["actions"]) == 1
    action = result["actions"][0]
    assert action["recipe_id"] == "nxos.rib.ipv4"
    assert action["commands"] == [nxos.CMD_ROUTE]
    assert action["affected_source_addresses"] == 128
    assert action["priority"] == 3
    assert action["scope"] == "device"


def test_ipv4_completeness_cannot_close_ipv6_gap():
    recorded = manifest(
        sections={"rib": SectionOutcome(status="ok")}, tables={"rib": TableOutcome(status="complete")}
    )
    result = troubleshoot(
        unknown(sources=["2001:db8::/64"]), recorded, {"name": "ipv6", "sources": ["2001:db8::/64"]}
    )
    gap = next(g for g in result["gaps"] if g["code"] == "routing-observation-missing")
    assert gap["dimension"] == "ipv6-rib"
    assert gap["kind"] == "not-collected"
    assert gap["collection_capability"] == "unavailable"
    assert not result["actions"]


def test_complete_carried_evidence_is_not_automatically_a_missing_read():
    recorded = manifest(
        sections={"rib": SectionOutcome(status="ok")},
        tables={"rib": TableOutcome(status="unchanged")},
        carried=True,
    )
    result = troubleshoot(unknown(), recorded, REQ)
    assert not result["actions"]
    assert all(g["code"] != "routing-observation-missing" for g in result["gaps"])


def test_proven_and_model_only_outcomes_have_no_collection_action():
    result = unknown()
    result["not_established"]["after"]["count"] = 0
    assert not troubleshoot(result, manifest(), REQ)["actions"]
    modeled = troubleshoot(unknown(stage="forwarding", kind="beyond-interface"), manifest(), REQ)
    assert modeled["gaps"][0]["kind"] == "not-modeled"
    assert not modeled["actions"]
    unsupported = troubleshoot(unknown(stage="pbr", kind="unknown-predicate"), manifest(), REQ)
    assert unsupported["gaps"][0]["kind"] == "unsupported"
    assert not unsupported["actions"]


def test_table_unsupported_is_separate_from_reasoning_unsupported_and_has_no_retry():
    recorded = manifest(
        sections={"rib": SectionOutcome(status="unsupported")},
        tables={"rib": TableOutcome(status="unsupported")},
    )
    result = troubleshoot(unknown(), recorded, REQ)
    assert not result["actions"]
    gap = next(g for g in result["gaps"] if "collection_status" in g)
    assert gap["collection_status"]["table"] == "unsupported"
    assert gap["kind"] == "not-collected"


def test_partial_family_subtable_and_failed_publication_remain_open():
    recorded = manifest(
        "vyos",
        sections={
            "routes": SectionOutcome(status="ok"),
            "routes_table_100": SectionOutcome(status="partial"),
        },
        tables={"rib": TableOutcome(status="complete")},
    )
    assert troubleshoot(unknown(), recorded, REQ)["actions"]
    recorded.devices[0].sections["routes_table_100"] = SectionOutcome(status="ok")
    recorded.devices[0].tables["rib"] = TableOutcome(status="failed")
    result = troubleshoot(unknown(), recorded, REQ)
    assert result["actions"]
    gap = next(g for g in result["gaps"] if "collection_status" in g)
    assert "publication" in gap["detail"]


def test_rank_deduplicates_device_fetches_and_distinct_requirement_priorities():
    first = troubleshoot(unknown(), manifest(), REQ, priority=2)["actions"][0]
    second = troubleshoot(
        unknown(sources=["10.0.0.128/25"]), manifest(), {**REQ, "name": "other"}, priority=5
    )["actions"][0]
    ranked = rank_actions([first, first, second])
    assert len(ranked) == 1
    assert ranked[0]["priority"] == 7
    assert ranked[0]["affected_source_addresses"] == 256
    assert ranked[0]["requirements"] == ["service", "other"]


def test_same_device_ipv4_ipv6_recipes_are_one_actual_collection():
    request = {"name": "dual", "sources": ["10.0.0.0/24", "2001:db8::/64"]}
    actions = troubleshoot(unknown(), manifest("vyos"), request)["actions"]
    assert len(actions) == 1
    assert set(actions[0]["recipe_ids"]) == {"vyos.rib.ipv4", "vyos.rib.ipv6"}


def test_unclassified_prose_never_invents_a_command():
    result = {"verdict": "not-established", "missing_evidence": ["run show ip route to fix all things"]}
    response = troubleshoot(result, manifest(), REQ)
    assert response["gaps"][0]["kind"] == "unclassified"
    assert not response["actions"]
    assert gap_from_step({"stage": "custom", "kind": "missing"})["kind"] == "unclassified"


def test_engine_unknown_terminal_step_carries_typed_gap_from_producer():
    net = network()
    net = replace(net, interfaces=tuple(replace(i, context_uid=None) for i in net.interfaces))
    outcome = answer(net, request("forward"))
    gaps = [
        step.data["evidence_gap"]
        for member in outcome.members.values()
        for explanation in member.explanations
        for step in explanation.steps
        if "evidence_gap" in step.data
    ]
    assert gaps
    assert gaps[0]["code"] == "routing-context-missing"
    assert gaps[0]["kind"] == "not-collected"


def test_evidence_line_that_repeats_a_gap_detail_is_not_a_second_gap():
    # The engine's evidence line names the gap's subject before the same
    # detail text.
    detail = "missing graph identity: remote_device_uid, remote_context_uid"
    result = {
        "verdict": "not-established",
        "gaps": [
            {
                "code": "tunnel-decision-not-established",
                "kind": "unclassified",
                "detail": detail,
                "subject": "r1",
            }
        ],
        "missing_evidence": [f"tunnel on r1: {detail}", "an unrelated fact is not recorded"],
    }
    response = troubleshoot(result, manifest(), REQ)
    codes = sorted(g["code"] for g in response["gaps"])
    assert codes == ["legacy-evidence-gap", "tunnel-decision-not-established"]
    assert [g["detail"] for g in response["gaps"] if g["code"] == "legacy-evidence-gap"] == [
        "an unrelated fact is not recorded"
    ]
