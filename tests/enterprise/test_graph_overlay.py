"""Ordered immutable graph policy overlays."""

from types import MappingProxyType

import pytest

from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.analysis_model.overlay import apply_overlay
from hst.simul.fw_overlay import ChangeSet, Intent, ProposalError


def _graph():
    nodes = {
        "rb": GraphNode("rb", frozenset({"FwRulebase"}), MappingProxyType({"default_action": "deny"})),
        "old": GraphNode(
            "old",
            frozenset({"FwRule"}),
            MappingProxyType(
                {"position": 20, "action": "deny", "src_any": True, "dst_any": True, "svc_any": True}
            ),
        ),
        "zone": GraphNode("zone", frozenset({"Zone"}), MappingProxyType({})),
        "if": GraphNode("if", frozenset({"Interface"}), MappingProxyType({})),
    }
    rels = [
        GraphRelation("has", "HAS_RULE", "rb", "old", MappingProxyType({})),
        GraphRelation("contains", "CONTAINS", "zone", "if", MappingProxyType({})),
    ]
    outgoing = {(rel.start, rel.kind): (rel,) for rel in rels}
    incoming = {(rel.end, rel.kind): (rel,) for rel in rels}
    return GraphInventory(
        "a" * 64,
        "base",
        MappingProxyType(nodes),
        MappingProxyType(
            {"FwRulebase": ("rb",), "FwRule": ("old",), "Zone": ("zone",), "Interface": ("if",)}
        ),
        MappingProxyType(outgoing),
        MappingProxyType(incoming),
        True,
        (),
        0,
    )


def test_add_modify_remove_and_zone_move_preserve_baseline_and_order():
    base = _graph()
    changes = ChangeSet(
        [
            Intent(
                "fw_rule.add",
                {
                    "rulebase": "rb",
                    "uid": "new",
                    "position": 10,
                    "action": "accept",
                    "source": "10.0.0.0/24",
                    "destination": "any",
                },
            ),
            Intent("fw_rule.modify", {"rulebase": "rb", "rule": "old", "action": "accept"}),
            Intent("zone.remove_interface", {"zone": "zone", "interface": "if"}),
        ]
    )
    overlaid = apply_overlay(base, changes)

    assert base.nodes["old"].props["action"] == "deny"
    assert overlaid.nodes["old"].props["action"] == "accept"
    assert {item.end for item in overlaid.outgoing["rb", "HAS_RULE"]} == {"old", "new"}
    assert overlaid.targets("new", "SRC")[0].props["cidr"] == "10.0.0.0/24"
    assert not overlaid.targets("zone", "CONTAINS")
    assert overlaid.fingerprint != base.fingerprint


def test_routing_and_unknown_nonrouting_intents_are_never_silently_ignored():
    with pytest.raises(ProposalError, match="RibInput"):
        apply_overlay(_graph(), ChangeSet([Intent("bgp_session.shut", {"session": "s"})]))
    with pytest.raises(ProposalError):
        apply_overlay(_graph(), ChangeSet([Intent("not-real", {})]))


def test_action_only_changes_fingerprint_and_sequential_overlays_keep_distinct_edges():
    base = _graph()
    changed = apply_overlay(
        base, ChangeSet([Intent("fw_rule.modify", {"rulebase": "rb", "rule": "old", "action": "accept"})])
    )
    first = apply_overlay(
        changed,
        ChangeSet(
            [
                Intent(
                    "fw_rule.add",
                    {"rulebase": "rb", "uid": "one", "position": 1, "action": "accept", "source": "10.0.0.1"},
                )
            ]
        ),
    )
    second = apply_overlay(
        first,
        ChangeSet(
            [
                Intent(
                    "fw_rule.add",
                    {"rulebase": "rb", "uid": "two", "position": 2, "action": "accept", "source": "10.0.0.2"},
                )
            ]
        ),
    )

    assert changed.fingerprint != base.fingerprint
    assert second.targets("one", "SRC")[0].props["ip"] == "10.0.0.1"
    assert second.targets("two", "SRC")[0].props["ip"] == "10.0.0.2"


def test_foreign_rulebase_target_is_rejected():
    with pytest.raises(ProposalError, match="not owned"):
        apply_overlay(
            _graph(),
            ChangeSet([Intent("fw_rule.modify", {"rulebase": "foreign", "rule": "old", "action": "accept"})]),
        )
