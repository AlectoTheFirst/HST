"""Strict impact accounting for device-bound graph gates."""

from types import SimpleNamespace

import pytest

from hst.path.addrsets import _intervals, _ports, _protoset
from hst.path.gates.coverage import CreditedTransition, stage_gate_credits, strict_gate_coverage
from hst.path.state import Effect, FlowRegion


def _region():
    return FlowRegion.from_query(
        _intervals(["10.0.0.1"]), _intervals(["10.0.0.2"]), _protoset(["tcp"]), _ports(443)
    )


def _install(monkeypatch, missed, details):
    monkeypatch.setattr("hst.path.gates.coverage.unevaluated_gates", lambda *_args: missed)
    monkeypatch.setattr("hst.path._read", lambda *_args, **_kwargs: details)


def test_unknown_bound_gate_makes_the_whole_region_indeterminate(monkeypatch):
    _install(
        monkeypatch,
        [{"uid": "sdwan:1", "kind": "SdwanBusinessPolicy"}],
        [{"uid": "sdwan:1", "labels": ["Obj", "Gate", "SdwanBusinessPolicy"]}],
    )
    transition = strict_gate_coverage(
        object(),
        "dev:1",
        stage="forward",
        in_interface_uid="if:in",
        out_interface_uid="if:out",
        evaluated_ids=(),
    )

    ((_same, effect),) = transition.apply(_region())
    assert effect.kind == "indeterminate"
    assert effect.data["unknown_gates"] == ("sdwan:1",)


def test_explicit_evaluation_credit_removes_a_gate(monkeypatch):
    seen = {}

    def missed(_session, _devices, evaluated):
        seen["evaluated"] = evaluated
        return []

    monkeypatch.setattr("hst.path.gates.coverage.unevaluated_gates", missed)
    transition = strict_gate_coverage(
        object(),
        "dev:1",
        stage="forward",
        in_interface_uid="if:in",
        out_interface_uid="if:out",
        evaluated_ids={"rb:1"},
        composed_kinds={"FwRulebase"},
    )
    assert seen["evaluated"] == {"rb:1"}
    assert transition.apply(_region())[0][1].kind == "pass"


def test_other_chain_and_other_interface_pbr_are_inapplicable(monkeypatch):
    missed = [{"uid": "rb:input", "kind": "FwRulebase"}, {"uid": "pbr:other", "kind": "PbrPolicy"}]
    details = [
        {"uid": "rb:input", "labels": ["Gate", "FwRulebase"], "chain": "input"},
        {
            "uid": "pbr:other",
            "labels": ["Gate", "PbrPolicy"],
            "binding_interfaces": ["if:other"],
        },
    ]
    _install(monkeypatch, missed, details)
    transition = strict_gate_coverage(
        object(),
        "dev:1",
        stage="forward",
        in_interface_uid="if:in",
        out_interface_uid="if:out",
        evaluated_ids=(),
    )
    assert transition.unknowns == ()


def test_unknown_firewall_subtype_is_not_credited_by_class_support(monkeypatch):
    _install(
        monkeypatch,
        [{"uid": "rb:mystery", "kind": "FwRulebase"}],
        [
            {
                "uid": "rb:mystery",
                "labels": ["Gate", "FwRulebase"],
                "chain": "forward",
                "model_kind": "vendor-special",
                "match_context": "vendor-special",
            }
        ],
    )
    transition = strict_gate_coverage(
        object(),
        "dev:1",
        stage="forward",
        in_interface_uid="if:in",
        out_interface_uid="if:out",
        evaluated_ids=(),
        composed_kinds={"FwRulebase"},
    )
    assert [item.uid for item in transition.unknowns] == ["rb:mystery"]


def test_preflight_defers_only_a_known_supported_schema_shape(monkeypatch):
    missed = [
        {"uid": "rb:known", "kind": "FwRulebase"},
        {"uid": "rb:unknown", "kind": "FwRulebase"},
    ]
    details = [
        {
            "uid": "rb:known",
            "labels": ["Gate", "FwRulebase"],
            "chain": "forward",
            "model_kind": "access",
            "match_context": "device",
        },
        {
            "uid": "rb:unknown",
            "labels": ["Gate", "FwRulebase"],
            "chain": "forward",
            "model_kind": "vendor-special",
            "match_context": "device",
        },
    ]
    _install(monkeypatch, missed, details)
    transition = strict_gate_coverage(
        object(),
        "dev:1",
        stage="forward",
        in_interface_uid="if:in",
        out_interface_uid="if:out",
        evaluated_ids=(),
        composed_kinds={"FwRulebase"},
        preflight=True,
    )
    assert [item.uid for item in transition.unknowns] == ["rb:unknown"]


def test_unrecognized_firewall_chain_and_unknown_sdwan_egress_remain_applicable(monkeypatch):
    missed = [
        {"uid": "rb:chain", "kind": "FwRulebase"},
        {"uid": "sdwan:1", "kind": "SdwanBusinessPolicy"},
    ]
    details = [
        {
            "uid": "rb:chain",
            "labels": ["Gate", "FwRulebase"],
            "chain": "vendor-chain",
            "model_kind": "access",
            "match_context": "device",
        },
        {"uid": "sdwan:1", "labels": ["Gate", "SdwanBusinessPolicy"]},
    ]
    _install(monkeypatch, missed, details)
    transition = strict_gate_coverage(
        object(),
        "dev:1",
        stage="forward",
        in_interface_uid="if:in",
        out_interface_uid=None,
        evaluated_ids=(),
        composed_kinds={"FwRulebase"},
        preflight=True,
    )
    assert {item.uid for item in transition.unknowns} == {"rb:chain", "sdwan:1"}


def test_nat_rulebase_without_access_match_context_is_deferred_then_requires_credit(monkeypatch):
    _install(
        monkeypatch,
        [{"uid": "rb:nat", "kind": "FwRulebase"}],
        [{"uid": "rb:nat", "labels": ["Gate", "FwRulebase"], "model_kind": "nat"}],
    )
    kwargs = {
        "stage": "forward",
        "in_interface_uid": "if:in",
        "out_interface_uid": "if:out",
        "evaluated_ids": (),
        "composed_kinds": {"FwRulebase"},
    }
    assert not strict_gate_coverage(object(), "dev:1", **kwargs, preflight=True).unknowns
    assert [item.uid for item in strict_gate_coverage(object(), "dev:1", **kwargs).unknowns] == ["rb:nat"]


def test_missing_binding_detail_cannot_silently_drop_a_gate(monkeypatch):
    _install(monkeypatch, [{"uid": "gate:lost", "kind": "CustomGate"}], [])
    transition = strict_gate_coverage(
        object(),
        "dev:1",
        stage="local-input",
        in_interface_uid="if:in",
        out_interface_uid=None,
        evaluated_ids=(),
    )
    assert transition.unknowns[0].reason == "gate binding details were not observed"


def test_failed_policy_section_makes_empty_graph_evidence_unknown(monkeypatch):
    entry = SimpleNamespace(
        host="router-1",
        source="edge",
        outcome="partial",
        carried=False,
        effective_run="run-1",
        sections={"acl": SimpleNamespace(status="failed")},
    )
    manifest = SimpleNamespace(devices=[entry], sources=[SimpleNamespace(name="edge", type="iosxe")])
    session = SimpleNamespace(snapshot=SimpleNamespace(manifest=manifest))
    monkeypatch.setattr("hst.path.gates.coverage.unevaluated_gates", lambda *_args: [])
    monkeypatch.setattr(
        "hst.path._read",
        lambda _session, query, **_params: (
            [{"host": "router-1", "source": "edge", "scope": "edge:router-1"}]
            if "RETURN d.hostname AS host" in query
            else []
        ),
    )
    transition = strict_gate_coverage(
        session,
        "dev:1",
        stage="forward",
        in_interface_uid="if:in",
        out_interface_uid="if:out",
        evaluated_ids=(),
    )
    assert transition.unknowns[0].kind == "ObservationGap"
    assert "acl=failed" in transition.unknowns[0].reason


@pytest.mark.parametrize(
    ("status", "reason"),
    [("empty", None), ("failed", "interface_config=failed")],
)
def test_iosxr_declares_its_filter_bindings_as_policy_input(monkeypatch, status, reason):
    entry = SimpleNamespace(
        host="router-1",
        source="edge",
        outcome="collected",
        carried=False,
        effective_run="run-1",
        sections={"interface_config": SimpleNamespace(status=status)},
    )
    manifest = SimpleNamespace(devices=[entry], sources=[SimpleNamespace(name="edge", type="iosxr")])
    session = SimpleNamespace(snapshot=SimpleNamespace(manifest=manifest))
    monkeypatch.setattr("hst.path.gates.coverage.unevaluated_gates", lambda *_args: [])
    monkeypatch.setattr(
        "hst.path._read",
        lambda _session, query, **_params: (
            [{"host": "router-1", "source": "edge", "scope": "edge:router-1"}]
            if "RETURN d.hostname AS host" in query
            else []
        ),
    )
    transition = strict_gate_coverage(
        session,
        "dev:1",
        stage="forward",
        in_interface_uid="if:in",
        out_interface_uid="if:out",
        evaluated_ids=(),
    )
    if reason is None:
        assert transition.unknowns == ()
    else:
        assert transition.unknowns[0].kind == "ObservationGap"
        assert reason in transition.unknowns[0].reason


def test_complete_empty_policy_section_proves_absence(monkeypatch):
    entry = SimpleNamespace(
        host="router-1",
        source="edge",
        outcome="collected",
        carried=False,
        effective_run="run-1",
        sections={"acl": SimpleNamespace(status="empty")},
    )
    entry.sections.update(
        {
            "interface_config": SimpleNamespace(status="empty"),
            "nat": SimpleNamespace(status="empty"),
            # the VLAN access map bindings are policy input too
            "vlan_filter": SimpleNamespace(status="empty"),
        }
    )
    manifest = SimpleNamespace(devices=[entry], sources=[SimpleNamespace(name="edge", type="iosxe")])
    session = SimpleNamespace(snapshot=SimpleNamespace(manifest=manifest))
    monkeypatch.setattr("hst.path.gates.coverage.unevaluated_gates", lambda *_args: [])
    monkeypatch.setattr(
        "hst.path._read",
        lambda *_args, **_kwargs: [{"host": "router-1", "source": "edge"}],
    )
    transition = strict_gate_coverage(
        session,
        "dev:1",
        stage="forward",
        in_interface_uid="if:in",
        out_interface_uid="if:out",
        evaluated_ids=(),
    )
    assert transition.unknowns == ()


def test_empty_section_map_does_not_prove_policy_absence(monkeypatch):
    entry = SimpleNamespace(
        host="router-1",
        source="edge",
        outcome="collected",
        carried=False,
        effective_run="run-1",
        sections={},
    )
    manifest = SimpleNamespace(devices=[entry], sources=[SimpleNamespace(name="edge", type="iosxe")])
    session = SimpleNamespace(snapshot=SimpleNamespace(manifest=manifest))
    monkeypatch.setattr("hst.path.gates.coverage.unevaluated_gates", lambda *_args: [])

    def read(_session, query, **_params):
        if "RETURN d.hostname AS host" in query:
            return [{"host": "router-1", "source": "edge", "scope": "iosxe:router-1"}]
        if "UNWIND $uids AS uid" in query:
            return []
        raise AssertionError("unexpected coverage query")

    monkeypatch.setattr("hst.path._read", read)
    transition = strict_gate_coverage(
        session,
        "dev:1",
        stage="forward",
        in_interface_uid="if:in",
        out_interface_uid="if:out",
        evaluated_ids=(),
    )
    assert "lacks declared policy sections" in transition.unknowns[0].reason


def test_controller_device_uid_maps_to_collection_entry_with_a_different_host(monkeypatch):
    entry = SimpleNamespace(
        host="controller.example",
        source="campus",
        device_uids=["dev:switch-1"],
        outcome="collected",
        carried=False,
        effective_run="run-1",
        sections={"config": SimpleNamespace(status="empty")},
    )
    manifest = SimpleNamespace(devices=[entry], sources=[SimpleNamespace(name="campus", type="vyos")])
    session = SimpleNamespace(snapshot=SimpleNamespace(manifest=manifest))
    monkeypatch.setattr("hst.path.gates.coverage.unevaluated_gates", lambda *_args: [])
    monkeypatch.setattr(
        "hst.path._read",
        lambda *_args, **_kwargs: [{"host": "switch-1.example", "source": None}],
    )
    transition = strict_gate_coverage(
        session,
        "dev:switch-1",
        stage="forward",
        in_interface_uid="if:in",
        out_interface_uid="if:out",
        evaluated_ids=(),
    )
    assert transition.unknowns == ()


def test_stage_credits_only_rigorous_chain_and_interface_exclusions(monkeypatch):
    monkeypatch.setattr("hst.path.gates.coverage._other_chain_rulebases", lambda *_args: ["rb:input"])
    monkeypatch.setattr(
        "hst.path.gates.coverage._other_interface_pbr_policies",
        lambda *_args: ["pbr:other"],
    )
    credits = stage_gate_credits(object(), "dev:1", "forward", "if:in", "if:out", 4, {"rb:already"})
    assert credits == frozenset({"rb:already", "rb:input", "pbr:other"})


def test_credited_transition_exposes_ids_read_for_the_full_region():
    class Transition:
        considered = ["rb:considered"]

        def apply(self, region):
            return [
                (
                    region,
                    Effect("permit", "firewall", data={"rb_uid": "rb:deciding"}),
                )
            ]

    wrapped = CreditedTransition(Transition(), frozenset({"rb:excluded"}))
    effect = wrapped.apply(_region())[0][1]
    assert effect.data["gate_credits"] == (
        "rb:considered",
        "rb:deciding",
        "rb:excluded",
    )


def test_an_interface_acl_bound_to_several_interfaces_applies_on_a_hop_using_any_of_them(monkeypatch):
    """One rulebase per access list, one PROTECTED_BY edge per binding: an
    unevaluated list is reported on a hop through any of its interfaces and on
    no other hop."""
    missed = [{"uid": "acl:shared", "kind": "FwRulebase"}]
    details = [
        {
            "uid": "acl:shared",
            "labels": ["Gate", "FwRulebase"],
            "model_kind": "access",
            "match_context": "interface-acl",
            "binding_interfaces": ["if:a", "if:b", "if:c"],
        }
    ]
    _install(monkeypatch, missed, details)

    def unknowns(in_if, out_if):
        return strict_gate_coverage(
            object(),
            "dev:1",
            stage="forward",
            in_interface_uid=in_if,
            out_interface_uid=out_if,
            evaluated_ids=(),
        ).unknowns

    assert [u.uid for u in unknowns("if:x", "if:b")] == ["acl:shared"]
    assert [u.uid for u in unknowns("if:c", "if:y")] == ["acl:shared"]
    assert unknowns("if:x", "if:y") == ()
