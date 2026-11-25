"""Safety edges for the collected Cisco ACL adapter."""

from __future__ import annotations

import json
from pathlib import Path

from hst.policy.acl import compile_cisco_interface_acl
from hst.policy.ir import Unknown

FIXTURE = Path(__file__).parents[2] / "fixtures/enterprise/acl/cisco-interface-acl.json"


def record() -> dict[str, object]:
    return json.loads(FIXTURE.read_text())


def test_selection_never_composes_unrelated_interface_bindings():
    model = compile_cisco_interface_acl(record())
    inbound = model.policy_for_binding("Gi0/0", "in", "forward-ingress")
    outbound = model.policy_for_binding("Gi0/1", "out", "forward-egress")
    assert inbound.ordered_layers == ("edge-in",)
    assert outbound.ordered_layers == ("edge-out",)
    unknown = model.policy_for_binding("Gi0/9", "in", "forward-ingress")
    assert isinstance(unknown.installation, Unknown)


def test_family_mismatch_guards_the_whole_selected_layer():
    value = record()
    value["rulebases"][0]["af"] = 6  # type: ignore[index]
    selected = compile_cisco_interface_acl(value).policy_for_binding("Gi0/0", "in", "forward-ingress")
    assert isinstance(selected.installation, Unknown)
    assert selected.installation.code == "ADDRESS_FAMILY_MISMATCH"


def test_malformed_values_and_unclassified_fields_make_whole_rule_unknown():
    value = record()
    rule = value["rulebases"][0]["rules"][0]  # type: ignore[index]
    rule["ports"] = True
    opaque = compile_cisco_interface_acl(value)._entries[0][1].rules[0]
    assert opaque.action == "unknown"
    rule["ports"] = "443"
    rule["vendor_negation"] = True
    opaque = compile_cisco_interface_acl(value)._entries[0][1].rules[0]
    assert opaque.action == "unknown"


def test_rule_and_rulebase_binding_conflict_is_unknown():
    value = record()
    value["rulebases"][0]["rules"][0]["in_interface"] = "Gi9/9"  # type: ignore[index]
    binding = compile_cisco_interface_acl(value).bindings[0]
    assert isinstance(binding.applicability, Unknown)
