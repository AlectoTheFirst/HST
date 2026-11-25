"""Immutable graph policy catalogs retain native predicate envelopes."""

from __future__ import annotations

from types import MappingProxyType, SimpleNamespace

from hst.analysis_model.catalogs import project_catalogs
from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation


def _graph():
    nodes = {
        "device:one": GraphNode("device:one", frozenset({"Device"}), MappingProxyType({})),
        "rb:access": GraphNode(
            "rb:access",
            frozenset({"FwRulebase"}),
            MappingProxyType({"kind": "access", "configured_revision": "r1"}),
        ),
        "rule:one": GraphNode(
            "rule:one",
            frozenset({"FwRule"}),
            MappingProxyType(
                {"position": 10, "action": "permit", "src_any": True, "dst_any": True, "svc_any": False}
            ),
        ),
        "svc:group": GraphNode("svc:group", frozenset({"SvcObject"}), MappingProxyType({})),
        "svc:leaf": GraphNode(
            "svc:leaf", frozenset({"SvcObject"}), MappingProxyType({"proto": "tcp", "ports": "443"})
        ),
    }
    relations = (
        GraphRelation(
            "enforces",
            "ENFORCES",
            "device:one",
            "rb:access",
            MappingProxyType({"installed": True, "coverage": "complete", "installed_revision": "r1"}),
        ),
        GraphRelation("has", "HAS_RULE", "rb:access", "rule:one", MappingProxyType({})),
        GraphRelation("svc", "SVC", "rule:one", "svc:group", MappingProxyType({})),
        GraphRelation("member", "MEMBER_OF", "svc:leaf", "svc:group", MappingProxyType({})),
    )
    outgoing, incoming = {}, {}
    for relation in relations:
        outgoing.setdefault((relation.start, relation.kind), []).append(relation)
        incoming.setdefault((relation.end, relation.kind), []).append(relation)
    return GraphInventory(
        "a" * 64,
        "graph",
        MappingProxyType(nodes),
        MappingProxyType(
            {
                "Device": ("device:one",),
                "FwRulebase": ("rb:access",),
                "FwRule": ("rule:one",),
                "SvcObject": ("svc:group", "svc:leaf"),
            }
        ),
        MappingProxyType({key: tuple(value) for key, value in outgoing.items()}),
        MappingProxyType({key: tuple(value) for key, value in incoming.items()}),
        True,
        (),
        0,
    )


def test_catalog_retains_object_dag_and_binding_evidence_without_flattening():
    record = SimpleNamespace(
        device_uids=("device:one",),
        outcome="collected",
        carried=False,
        expected_sections=("access",),
        sections={"access": SimpleNamespace(status="ok")},
    )
    projected = project_catalogs(
        _graph(), manifest=SimpleNamespace(devices=(record,)), context_owners={"ctx:one": "device:one"}
    )
    catalogs, complete_fw, complete_nat, complete_contexts = projected.model_catalogs()
    row = catalogs["firewall"]["rb:access"][0]

    assert complete_fw == {"rb:access"}
    assert complete_nat == set()
    assert complete_contexts == {"ctx:one"}
    assert row["svc_opaque"] is True
    assert row["graph_object_refs"]["svc"] == ("svc:group",)
    bundle = projected.object_bundles[row["graph_object_bundle_ids"][0]]
    assert bundle["nodes"]["svc:leaf"]["props"]["ports"] == "443"
    assert row["graph_envelope"]["has_rule"][0]["uid"] == "has"
    assert row["graph_rule_fingerprint"] == row["graph_semantic_fingerprint"]


def _estate(hosts: int) -> GraphInventory:
    """Check Point shape: every host resolves to its address and is a member
    of one all-hosts group, one rule per host references the host and a last
    rule references the group."""
    nodes = {
        "rb": GraphNode("rb", frozenset({"FwRulebase"}), MappingProxyType({"kind": "access"})),
        "group": GraphNode("group", frozenset({"AddressGroup"}), MappingProxyType({})),
    }
    relations = []
    for index in range(hosts):
        host, address, rule = f"host:{index}", f"addr:{index}", f"rule:{index}"
        nodes[host] = GraphNode(host, frozenset({"Host"}), MappingProxyType({"name": host}))
        nodes[address] = GraphNode(
            address, frozenset({"IpAddress"}), MappingProxyType({"ip": f"10.0.{index // 250}.{index % 250}"})
        )
        nodes[rule] = GraphNode(rule, frozenset({"FwRule"}), MappingProxyType({"position": index}))
        relations += [
            GraphRelation(f"resolves:{index}", "RESOLVES_TO", host, address, MappingProxyType({})),
            GraphRelation(f"member:{index}", "MEMBER_OF", host, "group", MappingProxyType({})),
            # the closure carriage: the group resolves to every member's address
            GraphRelation(f"group-resolves:{index}", "RESOLVES_TO", "group", address, MappingProxyType({})),
            GraphRelation(f"has:{index}", "HAS_RULE", "rb", rule, MappingProxyType({})),
            GraphRelation(f"dst:{index}", "DST", rule, host, MappingProxyType({})),
        ]
    nodes["rule:group"] = GraphNode(
        "rule:group", frozenset({"FwRule"}), MappingProxyType({"position": hosts})
    )
    relations += [
        GraphRelation("has:group", "HAS_RULE", "rb", "rule:group", MappingProxyType({})),
        GraphRelation("dst:group", "DST", "rule:group", "group", MappingProxyType({})),
    ]
    outgoing: dict = {}
    incoming: dict = {}
    labels: dict = {}
    for relation in relations:
        outgoing.setdefault((relation.start, relation.kind), []).append(relation)
        incoming.setdefault((relation.end, relation.kind), []).append(relation)
    for uid, node in nodes.items():
        for label in node.labels:
            labels.setdefault(label, []).append(uid)
    return GraphInventory(
        "a" * 64,
        "graph",
        MappingProxyType(nodes),
        MappingProxyType({key: tuple(value) for key, value in labels.items()}),
        MappingProxyType({key: tuple(value) for key, value in outgoing.items()}),
        MappingProxyType({key: tuple(value) for key, value in incoming.items()}),
        True,
        (),
        0,
    )


def test_a_host_bundles_its_own_dag_and_not_the_groups_that_hold_it():
    projected = project_catalogs(_estate(50), manifest=None)
    rows = {row["uid"]: row for row in projected.model_catalogs()[0]["firewall"]["rb"]}

    host = projected.object_bundles[rows["rule:0"]["graph_object_bundle_ids"][0]]
    assert sorted(host["nodes"]) == ["addr:0", "host:0"]
    assert sorted(host["relations"]) == ["resolves:0"]
    # the group bundles its members and their addresses
    group = projected.object_bundles[rows["rule:group"]["graph_object_bundle_ids"][0]]
    assert len(group["nodes"]) == 1 + 2 * 50
    assert len(group["relations"]) == 3 * 50
    assert len(projected.object_bundles) == 51
