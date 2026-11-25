from types import MappingProxyType, SimpleNamespace

from hst.analysis_model.catalogs import project_catalogs
from hst.analysis_model.counterfactual import graph_for_counterfactual
from hst.analysis_model.graph import GraphInventory, GraphNode, GraphRelation
from hst.assessment.semantic import digest

MANIFEST = "a" * 64


def graph(nodes, relations):
    catalog = {node.uid: node for node in nodes}
    labels, outgoing, incoming = {}, {}, {}
    for node in nodes:
        for label in node.labels:
            labels.setdefault(label, []).append(node.uid)
    for relation in relations:
        outgoing.setdefault((relation.start, relation.kind), []).append(relation)
        incoming.setdefault((relation.end, relation.kind), []).append(relation)
    return GraphInventory(
        MANIFEST,
        "b" * 64,
        MappingProxyType(catalog),
        MappingProxyType({key: tuple(value) for key, value in labels.items()}),
        MappingProxyType({key: tuple(value) for key, value in outgoing.items()}),
        MappingProxyType({key: tuple(value) for key, value in incoming.items()}),
        True,
        (),
        0,
    )


def node(uid, label, **props):
    return GraphNode(uid, frozenset({label}), MappingProxyType(props))


def relation(uid, kind, start, end):
    return GraphRelation(uid, kind, start, end, MappingProxyType({}))


def test_failure_projection_marks_device_tunnel_and_connector_host():
    source = graph(
        [
            node("device", "Device"),
            node("tunnel", "Tunnel", state="up"),
            node("connector", "ZpaAppConnector", health="up"),
            node("host", "Vm"),
        ],
        [relation("runs", "RUNS_ON", "connector", "host")],
    )
    gates = SimpleNamespace(
        devices={"device", "host"},
        interfaces=set(),
        failed_tunnels={"tunnel"},
        addresses=set(),
        inner=None,
    )
    result = graph_for_counterfactual(source, SimpleNamespace(gates=gates))
    assert all(result.nodes[uid].props["counterfactual_failed"] for uid in ("device", "tunnel"))
    assert result.nodes["connector"].props["health"] == "down"


def test_policy_edit_checks_precondition_and_replaces_stable_rule():
    source = graph(
        [
            node("rb", "FwRulebase"),
            node("rule", "FwRule", action="allow", position=1),
            node("old-source", "NetworkObject", cidr="10.0.0.0/24"),
        ],
        [
            relation("owns", "HAS_RULE", "rb", "rule"),
            relation("old-selector", "SRC", "rule", "old-source"),
        ],
    )
    changed = graph(
        [
            node("rb", "FwRulebase"),
            node("rule", "FwRule", action="drop", position=2),
            node("new-source", "NetworkObject", cidr="192.0.2.0/24"),
        ],
        [
            relation("owns", "HAS_RULE", "rb", "rule"),
            relation("new-selector", "SRC", "rule", "new-source"),
        ],
    )
    before_catalogs = project_catalogs(source, manifest=None).model_catalogs()[0]
    after_catalogs = project_catalogs(changed, manifest=None).model_catalogs()[0]
    before = before_catalogs["firewall"]["rb"]
    after = after_catalogs["firewall"]["rb"]
    edit = {
        "family": "firewall",
        "selector": ["rb", "rule"],
        "before": before,
        "after": after,
        "preconditions": {"forward": digest(before), "reverse": digest(after)},
        "graph_object_bundles": {
            **before_catalogs["graph_object_bundles"],
            **after_catalogs["graph_object_bundles"],
        },
    }
    changes = SimpleNamespace(edits=[edit], direction="forward")
    session = SimpleNamespace(_changes=changes, _session=None)
    result = graph_for_counterfactual(
        source, SimpleNamespace(gates=SimpleNamespace(session=session, inner=None))
    )
    assert result.nodes["rule"].props["action"] == "drop"
    assert result.nodes["rule"].props["position"] == 2
    assert result.targets("rule", "SRC") == (result.nodes["new-source"],)
