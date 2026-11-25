"""Selection isolation and provenance pinning for collected ACL policies."""

from __future__ import annotations

import json
from pathlib import Path

from hst.policy.acl import compile_cisco_interface_acl
from hst.policy.ir import Unknown

FIXTURE = Path(__file__).parents[2] / "fixtures/enterprise/acl/cisco-interface-acl.json"


def _record() -> dict[str, object]:
    return json.loads(FIXTURE.read_text())


def test_unrelated_installation_does_not_contaminate_selected_binding():
    value = _record()
    value["rulebases"][1].pop("installed")  # type: ignore[index]
    selected = compile_cisco_interface_acl(value).policy_for_binding("Gi0/0", "in", "forward-ingress")
    assert selected.installation.__class__.__name__ == "Constant"


def test_incomplete_binding_that_could_match_contaminates_selection():
    value = _record()
    value["rulebases"][1].update({"interface": "Gi0/0", "direction": "in", "pipeline": None})  # type: ignore[index]
    selected = compile_cisco_interface_acl(value).policy_for_binding("Gi0/0", "in", "forward-ingress")
    assert len(selected.layers) == 2
    assert isinstance(selected.installation, Unknown)


def test_inventory_is_closed_when_more_than_one_binding_exists_and_digest_pins_selected_policy():
    model = compile_cisco_interface_acl(_record())
    assert isinstance(model.policy.installation, Unknown)
    selected = model.policy_for_binding("Gi0/0", "in", "forward-ingress", manifest_digest="a" * 64)
    assert selected.manifest_digest == "a" * 64


def test_conflicting_binding_is_conservatively_retained_for_every_selection():
    value = _record()
    value["rulebases"][0]["rules"][0]["in_interface"] = "Gi9/9"  # type: ignore[index]
    model = compile_cisco_interface_acl(value)
    selected = model.policy_for_binding("Gi0/1", "out", "forward-egress")
    assert {layer.uid for layer in selected.layers} == {"edge-in", "edge-out"}
    assert isinstance(selected.installation, Unknown)


def _shared_record() -> dict[str, object]:
    """The edge-in list as the graph holds it: one rulebase per access list, bound by
    one PROTECTED_BY edge per interface and direction."""
    value = _record()
    base = value["rulebases"][0]  # type: ignore[index]
    for field in ("interface", "direction"):
        base.pop(field)
    base["bindings"] = [
        {"interface": "Gi0/0", "direction": "in"},
        {"interface": "Gi0/2", "direction": "in"},
        {"interface": "Gi0/0", "direction": "out", "pipeline": "forward-egress"},
    ]
    value["rulebases"] = [base]
    return value


def test_one_list_bound_to_several_interfaces_is_selected_through_each_binding():
    model = compile_cisco_interface_acl(_shared_record())
    assert [(b.rulebase_uid, b.interface, b.direction, b.pipeline) for b in model.bindings] == [
        ("edge-in", "Gi0/0", "in", "forward-ingress"),
        ("edge-in", "Gi0/2", "in", "forward-ingress"),
        ("edge-in", "Gi0/0", "out", "forward-egress"),
    ]
    for interface, direction, pipeline in (
        ("Gi0/0", "in", "forward-ingress"),
        ("Gi0/2", "in", "forward-ingress"),
        ("Gi0/0", "out", "forward-egress"),
    ):
        selected = model.policy_for_binding(interface, direction, pipeline)
        assert selected.ordered_layers == ("edge-in",)
        assert selected.installation.__class__.__name__ == "Constant"
    # the inventory holds the list once, and asks for a binding to be selected
    assert model.policy.ordered_layers == ("edge-in",)
    assert isinstance(model.policy.installation, Unknown)


def test_one_list_is_not_selected_on_an_interface_or_direction_it_is_not_bound_to():
    model = compile_cisco_interface_acl(_shared_record())
    for interface, direction, pipeline in (
        ("Gi0/9", "in", "forward-ingress"),
        ("Gi0/2", "out", "forward-egress"),
    ):
        selected = model.policy_for_binding(interface, direction, pipeline)
        assert isinstance(selected.installation, Unknown)
        assert selected.installation.code == "ACL_BINDING_NOT_FOUND"


def test_a_list_with_no_binding_is_never_selected():
    value = _shared_record()
    value["rulebases"][0]["bindings"] = []  # type: ignore[index]
    model = compile_cisco_interface_acl(value)
    assert model.bindings == ()
    assert (
        model.policy_for_binding("Gi0/0", "in", "forward-ingress").installation.code
        == "ACL_BINDING_NOT_FOUND"
    )
    assert isinstance(model.policy.installation, Unknown)


def test_a_rulebase_without_bindings_takes_its_binding_from_the_rules():
    value = _record()
    base = value["rulebases"][0]  # type: ignore[index]
    for field in ("interface", "direction"):
        base.pop(field)
    for rule in base["rules"]:
        rule["in_interface"] = "Gi0/0"
    value["rulebases"] = [base]
    model = compile_cisco_interface_acl(value)
    assert [(b.interface, b.direction) for b in model.bindings] == [("Gi0/0", "in")]
    selected = model.policy_for_binding("Gi0/0", "in", "forward-ingress")
    assert selected.ordered_layers == ("edge-in",)
    assert selected.installation.__class__.__name__ == "Constant"
    assert (
        model.policy_for_binding("Gi0/1", "in", "forward-ingress").installation.code
        == "ACL_BINDING_NOT_FOUND"
    )
