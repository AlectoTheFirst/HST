"""The gateway ambiguity names each context by its VRF and device: contexts on
different devices can share one `l3dom` display string."""

import pytest
from tests.test_path_trace import GW, FakeGraph, _src_row

from hst import path

L3DOM = "inventory:acme-emea:hosting"
LEAVES = ["leaf-a", "leaf-b", "leaf-c", "leaf-d"]
GATEWAYS = [
    {
        **GW,
        "l3dom": L3DOM,
        "anchor": f"vrf:dev:{leaf}:hosting",
        "if_uid": f"if:{leaf}:vlan10",
        "dev_uid": f"dev:{leaf}",
        "dev_name": leaf,
    }
    for leaf in LEAVES
]


@pytest.fixture
def graph(monkeypatch):
    g = FakeGraph()
    vrf_names = {gw["anchor"]: "hosting" for gw in GATEWAYS}

    def read_one(session, query, **params):
        if query.startswith("MATCH (v:VrfInstance {uid: $u})"):
            name = vrf_names.get(params["u"])
            return {"n": name} if name else None
        return g.read_one(query, **params)

    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", read_one)
    return g


def test_same_l3dom_contexts_are_named_by_vrf_and_device(graph):
    result = path.trace(None, "10.0.0.0/24", "8.8.8.8", gateways=GATEWAYS)

    labels = "; ".join(f"VRF hosting on {leaf}" for leaf in LEAVES)
    assert result["legs"] == []
    assert result["indeterminate"] is True
    assert f"in 4 isolated L3 domains ({labels})" in result["verdict"]
    assert result["ambiguous_domains"] == [L3DOM] * 4
    assert result["ambiguous_contexts"] == [
        {"anchor": f"vrf:dev:{leaf}:hosting", "label": f"VRF hosting on {leaf}"} for leaf in LEAVES
    ]


def test_a_context_with_no_vrf_record_keeps_its_l3dom(graph):
    gateways = [{**GATEWAYS[0], "anchor": "legacy:home", "l3dom": "home"}, GATEWAYS[1]]

    result = path.trace(None, "10.0.0.0/24", "8.8.8.8", gateways=gateways)

    assert "(home on leaf-a; VRF hosting on leaf-b)" in result["verdict"]


# --- a distributed anycast gateway ------------------------------------------------------


def _anycast(graph, attach="dev:leaf-b"):
    """Every leaf serves 10.0.0.0/24 with the same gateway address 10.0.0.1,
    each in its own VrfInstance, and the four contexts share a declared
    routing domain. The host attaches to a port of `attach`."""
    anchors = [gw["anchor"] for gw in GATEWAYS]
    graph.domain_mates = {a: [b for b in anchors if b != a] for a in anchors}
    graph.gateway_addresses = {gw["if_uid"]: ["10.0.0.1"] for gw in GATEWAYS}
    graph.sources = [
        _src_row()
        | {
            "ep_uid": "ep:host",
            "ep_name": "host",
            "att_uid": f"port:{attach}-p5",
            "att_is_port": True,
            "att_name": "Ethernet1/5",
            "sw_uid": attach,
            "sw_name": attach.removeprefix("dev:"),
        }
    ]


def test_an_anycast_gateway_is_resolved_by_the_source_attachment(graph):
    _anycast(graph)

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=GATEWAYS)

    assert "ambiguous_domains" not in result
    assert ("Device", "leaf-b") in [(h["kind"], h["label"]) for h in result["hops"]]
    assert not {"leaf-a", "leaf-c", "leaf-d"} & {h["label"] for h in result["hops"]}
    assert any("distributed anycast gateway on 4 devices" in n and "via leaf-b" in n for n in result["notes"])


def _leaf(name):
    return {"uid": f"dev:{name}", "is_port": False, "label": name, "dev": None, "lag": None, "bds": []}


def _port(uid, label, dev):
    return {"uid": uid, "is_port": True, "label": label, "dev": dev, "lag": None, "bds": []}


def test_an_anycast_gateway_behind_an_access_switch_takes_the_nearest_leaf(graph):
    _anycast(graph, attach="dev:acc")
    graph.l2_chains = {
        ("dev:acc", "dev:leaf-c"): {
            "chain": [
                _port("port:acc-p48", "Port 48", "acc"),
                _port("port:leaf-c-e1", "Ethernet1/1", "leaf-c"),
                _leaf("leaf-c"),
            ]
        },
        ("dev:acc", "dev:leaf-a"): {
            "chain": [
                _port("port:acc-p48", "Port 48", "acc"),
                _port("port:leaf-c-e1", "Ethernet1/1", "leaf-c"),
                _port("port:leaf-c-e49", "Ethernet1/49", "leaf-c"),
                _port("port:leaf-a-e49", "Ethernet1/49", "leaf-a"),
                _leaf("leaf-a"),
            ]
        },
    }

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=GATEWAYS)

    assert "ambiguous_domains" not in result
    assert any("via leaf-c" in n and "nearest the source's attachment" in n for n in result["notes"])


def test_anycast_instances_in_no_shared_routing_domain_stay_ambiguous(graph):
    _anycast(graph)
    graph.domain_mates = {}

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=GATEWAYS)

    assert result["ambiguous_domains"] == [L3DOM] * 4


def test_gateways_with_no_common_address_stay_ambiguous(graph):
    _anycast(graph)
    graph.gateway_addresses = {gw["if_uid"]: [f"10.0.0.{i + 2}"] for i, gw in enumerate(GATEWAYS)}

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=GATEWAYS)

    assert result["ambiguous_domains"] == [L3DOM] * 4


def test_a_source_attached_to_none_of_the_leaves_with_no_cable_path_stays_ambiguous(graph):
    _anycast(graph, attach="dev:elsewhere")

    result = path.trace(None, "10.0.0.5", "8.8.8.8", gateways=GATEWAYS)

    assert result["ambiguous_domains"] == [L3DOM] * 4
