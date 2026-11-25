import json
from ipaddress import ip_address
from types import MappingProxyType

from tests.support import checkpoint_batch

from hst.analysis_model.checkpoint_graph import checkpoint_policy
from hst.analysis_model.compile import compile_model
from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.analysis_model.model import ChoiceAssignment, EntrySpec, ModelInput, NodeSpec, StateKey
from hst.analysis_model.native_changes import native_changes
from hst.analysis_model.overlay import _rebuild, apply_overlay
from hst.impact.symbolic_walk import walk
from hst.policy.ir import Constant, ExecutionContext
from hst.symbolic import header

from .test_assessment_symbolic_bridge import native as native


def _inventory(*batches):
    nodes = {
        item.uid: GraphNode(item.uid, frozenset({item.label}), MappingProxyType(item.props))
        for batch in batches
        for item in batch.nodes
    }
    relations = [
        GraphRelation(
            f"relation:{index}",
            item.rel_type,
            item.start_uid,
            item.end_uid,
            MappingProxyType({**item.key, **item.props}),
        )
        for index, item in enumerate(item for batch in batches for item in batch.rels)
    ]
    return _rebuild(GraphInventory("a" * 64, "seed", {}, {}, {}, {}, True, (), 0), nodes, relations)


def test_collected_checkpoint_envelopes_compile_strict_group_and_inline_policy(native):
    domain = {"uid": "domain"}
    any_object = {"uid": "any", "name": "Any", "type": "CpmiAnyObject", "domain": domain}
    action = {"uid": "accept", "name": "Accept", "type": "RulebaseAction", "domain": domain}
    host = {
        "uid": "host",
        "name": "client",
        "type": "host",
        "domain": domain,
        "ipv4-address": "192.0.2.1",
    }
    group = {
        "uid": "group",
        "name": "clients",
        "type": "group",
        "domain": domain,
        "members": ["host"],
    }
    service = {
        "uid": "https",
        "name": "https",
        "type": "service-tcp",
        "domain": domain,
        "port": "443",
        "source-port": "",
        "protocol": "",
        "match-by-protocol-signature": False,
    }
    rule = {
        "uid": "rule",
        "type": "access-rule",
        "domain": domain,
        "rule-number": 1,
        "enabled": True,
        "action": "accept",
        "source": ["group"],
        "destination": ["any"],
        "service": ["https"],
        "install-on": ["gw"],
        "source-negate": False,
        "destination-negate": False,
        "service-negate": False,
        "time": ["any"],
        "vpn": ["any"],
        "content": ["any"],
    }
    layer = {
        "uid": "layer",
        "name": "Network",
        "type": "access-layer",
        "domain": domain,
        "implicit-cleanup-action": "drop",
    }
    package = {
        "uid": "package",
        "name": "Policy",
        "type": "package",
        "domain": domain,
        "access-layers": ["layer"],
        "installation-targets": ["gw"],
    }
    raw = {
        "gateways": [{"uid": "gw", "name": "fw", "type": "simple-gateway"}],
        "layers": [layer],
        "packages": [package],
        "package_details": {"package": package},
        "package_revisions": {"package": "revision"},
        "rulebases": {
            "layer": [
                {
                    "rulebase": [rule],
                    "objects-dictionary": [any_object, action, host, group, service],
                }
            ]
        },
        "nat": {},
        "policy_section_errors": [],
        "management_release": "R81.20",
        "gateway_release": "R81.20",
        "api_version": "1.9",
        "implied_rules_complete": True,
    }
    batch = checkpoint_batch.normalize(raw, mgmt="manager", domain="domain")
    graph = _inventory(batch)
    rulebase = next(uid for uid in graph.labels["FwRulebase"] if graph.nodes[uid].props["kind"] == "access")
    context = ExecutionContext("estate", "manager", "domain", next(iter(graph.labels["Device"])), "vrf", 4)
    policy = checkpoint_policy(graph, (rulebase,), context, Constant(True))
    assert policy is not None and policy.semantic_profile == "explicit-filter-v1"
    key = StateKey("filter", context)
    packets = header(
        native,
        {"source_address": int(ip_address("192.0.2.1")), "protocol": 6, "destination_port": 443},
        explicitly_all=native.schema.field_names,
    )
    model = compile_model(
        ModelInput(
            "a" * 64,
            (NodeSpec(key, terminal="permit", policy=policy),),
            (EntrySpec(key),),
            (ChoiceAssignment("only"),),
            True,
        ),
        native,
        packets.known_fields,
    )
    result = walk(model, packets, request_id="checkpoint-graph")
    assert not result.bounds.lower.is_empty()

    other_raw = json.loads(json.dumps(raw))
    other_raw["package_details"]["package"]["domain"] = {"uid": "other"}
    other = checkpoint_batch.normalize(other_raw, mgmt="other-manager", domain="other")
    combined = _inventory(batch, other)
    policy = checkpoint_policy(combined, (rulebase,), context, Constant(True))
    assert policy is not None
    assert policy.context.authority == "manager"
    assert all(obj.key.authority == "manager" for obj in policy.objects)

    changed = apply_overlay(
        graph,
        native_changes(
            graph,
            [
                {
                    "kind": "fw_rule.modify",
                    "params": {
                        "rulebase": rulebase,
                        "rule": next(iter(graph.labels["FwRule"])),
                        "enabled": False,
                    },
                }
            ],
        ),
    )
    changed_policy = checkpoint_policy(changed, (rulebase,), context, Constant(True))
    assert changed_policy is not None
    assert changed_policy.layers[0].rules[0].enabled is False

    predicate_changed = apply_overlay(
        graph,
        native_changes(
            graph,
            [
                {
                    "kind": "fw_rule.modify",
                    "params": {
                        "rulebase": rulebase,
                        "rule": next(iter(graph.labels["FwRule"])),
                        "source": ["198.51.100.8"],
                        "protocols": ["tcp"],
                        "ports": ["80"],
                    },
                }
            ],
        ),
    )
    changed_policy = checkpoint_policy(predicate_changed, (rulebase,), context, Constant(True))
    assert changed_policy is not None
    changed_packets = header(
        native,
        {
            "source_address": int(ip_address("198.51.100.8")),
            "protocol": 6,
            "destination_port": 80,
        },
        explicitly_all=native.schema.field_names,
    )
    changed_model = compile_model(
        ModelInput(
            "a" * 64,
            (NodeSpec(key, terminal="permit", policy=changed_policy),),
            (EntrySpec(key),),
            (ChoiceAssignment("only"),),
            True,
        ),
        native,
        changed_packets.known_fields,
    )
    changed_result = walk(changed_model, changed_packets, request_id="checkpoint-overlay")
    assert not changed_result.bounds.lower.is_empty()

    added = apply_overlay(
        graph,
        native_changes(
            graph,
            [
                {
                    "kind": "fw_rule.add",
                    "params": {
                        "rulebase": rulebase,
                        "uid": "overlay-cp-rule",
                        "position": 0,
                        "action": "permit",
                        "source": ["203.0.113.9"],
                        "destination": ["any"],
                        "protocols": ["tcp"],
                        "ports": ["22"],
                    },
                }
            ],
        ),
    )
    added_policy = checkpoint_policy(added, (rulebase,), context, Constant(True))
    assert added_policy is not None and len(added_policy.layers[0].rules) == 2
    added_packets = header(
        native,
        {
            "source_address": int(ip_address("203.0.113.9")),
            "protocol": 6,
            "destination_port": 22,
        },
        explicitly_all=native.schema.field_names,
    )
    added_model = compile_model(
        ModelInput(
            "a" * 64,
            (NodeSpec(key, terminal="permit", policy=added_policy),),
            (EntrySpec(key),),
            (ChoiceAssignment("only"),),
            True,
        ),
        native,
        added_packets.known_fields,
    )
    added_result = walk(added_model, added_packets, request_id="checkpoint-add")
    assert not added_result.bounds.lower.is_empty()
