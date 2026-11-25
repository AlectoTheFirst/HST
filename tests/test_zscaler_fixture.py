"""The Zscaler rows of the demo fixture have the shape the collectors write:
uids, property keys and types, value vocabulary and edges."""

from __future__ import annotations

from pathlib import Path

import yaml
from tests.test_zia import RAW as ZIA_RAW
from tests.test_zpa import RAW as ZPA_RAW

from hst.collectors.zia import normalize_zia
from hst.collectors.zpa import normalize_zpa

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "mini-enterprise.yaml"

ZSCALER_LABELS = {
    "ZscalerDc",
    "ZiaLocation",
    "ZiaLocationGroup",
    "ZiaForwardingRule",
    "ZpaAppSegment",
    "ZpaSegmentGroup",
    "ZpaServerGroup",
    "ZpaAppConnectorGroup",
    "ZpaAppConnector",
    "ZpaAccessRule",
    "ZpaClientForwardingRule",
    "ZpaProvisioningKey",
    "ZpaServiceEdge",
    "IdentityGroup",
    "AppServer",
}
# edges no collector writes, kept for the demo
HAND_BUILT = {
    ("ZpaAppSegment", "RESOLVES_TO", "DnsRecord"),  # the reasoner draws it on a run
    ("ZpaAppConnector", "RUNS_ON", "Vm"),  # no collector writes the connector's Vm
    ("SdwanBusinessPolicy", "STEERS_VIA", "ZscalerDc"),  # the demo shows the steer
}


def _collector_batches():
    zpa = normalize_zpa(ZPA_RAW, tenant="acme")
    zia = normalize_zia(ZIA_RAW, tenant="acme", location_sites={"1001": "hq"})
    return [zpa, zia]


def _fixture():
    data = yaml.safe_load(FIXTURE.read_text())
    nodes = {n["uid"]: n for n in data["nodes"]}
    zia_tunnels = {
        r["end"][1]
        for r in data["rels"]
        if r["type"] == "USES" and r["start"][0] == "ZiaLocation" and r["end"][0] == "Tunnel"
    }
    picked = {uid: n for uid, n in nodes.items() if n["label"] in ZSCALER_LABELS or uid in zia_tunnels}
    return data, picked


def _collector_shape():
    prefixes: dict[str, set[str]] = {}
    keys: dict[str, dict[str, type]] = {}
    for batch in _collector_batches():
        for n in batch.nodes:
            label = "ZiaTunnel" if n.label == "Tunnel" else n.label
            prefixes.setdefault(label, set()).add(n.uid.rsplit(":", 1)[0] + ":")
            for key, value in n.props.items():
                keys.setdefault(label, {})[key] = type(value)
    return prefixes, keys


def test_the_fixture_zscaler_uids_use_the_collector_grammar():
    prefixes, _keys = _collector_shape()
    _data, nodes = _fixture()
    for uid, node in nodes.items():
        label = "ZiaTunnel" if node["label"] == "Tunnel" else node["label"]
        if label not in prefixes:
            continue
        assert uid.rsplit(":", 1)[0] + ":" in prefixes[label], uid


def test_the_fixture_zscaler_properties_are_collector_properties():
    _prefixes, keys = _collector_shape()
    _data, nodes = _fixture()
    for uid, node in nodes.items():
        label = "ZiaTunnel" if node["label"] == "Tunnel" else node["label"]
        if label not in keys:
            continue
        for key, value in (node.get("props") or {}).items():
            assert key in keys[label], (uid, key)
            assert isinstance(value, keys[label][key]), (uid, key, value)


def test_the_fixture_zscaler_values_use_the_collector_vocabulary():
    _data, nodes = _fixture()
    healths = {"up", "down"}
    for node in nodes.values():
        props = node.get("props") or {}
        if node["label"] == "ZpaAppConnector":
            assert props.get("health") in healths
        if node["label"] == "ZpaAccessRule":
            assert props.get("action") in {"allow", "deny", "require_approval"}
        if node["label"] == "ZiaForwardingRule":
            assert props.get("forward_method") in {"zpa", "direct", "drop"}
        if node["label"] == "Tunnel":
            assert props.get("encap") in {"gre", "ipsec"}


def test_the_fixture_zscaler_edges_are_collector_edges_or_named_gaps():
    collector = set()
    labels: dict[str, str] = {}
    for batch in _collector_batches():
        labels.update({n.uid: n.label for n in batch.nodes})
    for batch in _collector_batches():
        for r in batch.rels:
            collector.add((labels.get(r.start_uid), r.rel_type, labels.get(r.end_uid)))
    data, nodes = _fixture()
    for r in data["rels"]:
        if r["start"][1] not in nodes and r["end"][1] not in nodes:
            continue
        shape = (r["start"][0], r["type"], r["end"][0])
        assert r["type"] not in ("EGRESSES_VIA", "FORWARDS_TO", "SAME_AS"), shape
        assert shape in collector or shape in HAND_BUILT, shape


def test_the_fixture_access_rules_carry_collector_conditions():
    import json

    rule = {
        "id": "100",
        "name": "x",
        "action": "ALLOW",
        "ruleOrder": "1",
        "priority": "1",
        "conditions": [
            {"operator": "OR", "operands": [{"objectType": "APP", "rhs": "2001"}]},
            {"operator": "OR", "operands": [{"objectType": "SCIM_GROUP", "rhs": "77101", "idpId": "7001"}]},
        ],
    }
    [written] = [
        n for n in normalize_zpa({"access_rules": [rule]}, tenant="acme").nodes if n.label == "ZpaAccessRule"
    ]
    _data, nodes = _fixture()
    rules = [n for n in nodes.values() if n["label"] == "ZpaAccessRule"]
    assert len(rules) == 2
    for node in rules:
        props = node.get("props") or {}
        blocks = json.loads(props["conditions"])
        assert isinstance(blocks, list) and blocks
        assert set(props) == set(written.props)
