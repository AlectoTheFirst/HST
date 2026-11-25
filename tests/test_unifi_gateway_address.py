"""A UniFi classic rule side of type ADDRv4 or ADDRv6 names the gateway's own
address on a network. It resolves to that address, never to the
network's whole prefix and never to Any; only when the address is not known
is the side opaque and the rule not decided. Each verdict runs the gate's own
code with the graph reads answered from the batch (test_unifi_classic_scope).
"""

from __future__ import annotations

from tests.test_unifi import RAW, UDM
from tests.test_unifi_classic_scope import BR1, BR30, BR40, _rule, _verdict

from hst.collectors.unifi import normalize_unifi
from hst.path.verdict import DENY, INDETERMINATE, PERMIT


def _batch(rules):
    raw = {**RAW, "devices": RAW["devices"] + [UDM], "firewall_rules": rules}
    return normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default")


def _gateway_drop(ntype: str, network: str = "n1"):
    return _rule(
        "gw-drop",
        "LAN_IN",
        2000,
        "drop",
        src_networkconf_id="n30",
        src_networkconf_type="NETv4",
        dst_networkconf_id=network,
        dst_networkconf_type=ntype,
    )


def _rule_props(batch, rid):
    return next(n.props for n in batch.nodes if n.label == "FwRule" and n.props.get("rule_uid") == rid)


def _rels(batch):
    return {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}


def test_an_addrv4_side_resolves_to_the_gateway_address_of_its_network():
    batch = _batch([_gateway_drop("ADDRv4")])
    assert _rule_props(batch, "gw-drop")["dst_any"] is False
    gw = "unifi:default:net:n1:gw4"
    netobjs = {n.uid: n.props for n in batch.nodes if n.label == "NetObject"}
    assert netobjs[gw]["kind"] == "host" and "opaque" not in netobjs[gw]
    targets = [r.end_uid for r in batch.rels if r.rel_type == "RESOLVES_TO" and r.start_uid == gw]
    ips = {n.uid: n.props["ip"] for n in batch.nodes if n.label == "IpAddress"}
    assert [ips[t] for t in targets] == ["192.168.1.1"]
    assert ("DST", "unifi:default:fw:lan_in:gw-drop", gw) in _rels(batch)


def test_only_a_flow_to_the_gateway_address_matches(monkeypatch):
    batch = _batch([_gateway_drop("ADDRv4")])
    # the gateway address itself: the rule drops it
    v, outcome = _verdict(monkeypatch, batch, BR30, BR1, "192.168.30.50/32", "192.168.1.1/32", 443)
    assert outcome == DENY and v["rule_name"] == "gw-drop", v
    v, outcome = _verdict(monkeypatch, batch, BR30, BR1, "192.168.30.50/32", "192.168.1.20/32", 443)
    assert outcome == PERMIT, v
    v, outcome = _verdict(monkeypatch, batch, BR30, BR40, "192.168.30.50/32", "192.168.40.20/32", 443)
    assert outcome == PERMIT, v


def test_an_unknown_gateway_address_is_opaque_and_not_decided(monkeypatch):
    # the network is not in the payload
    batch = _batch([_gateway_drop("ADDRv4", network="n-gone")])
    assert _rule_props(batch, "gw-drop")["dst_any"] is False
    side = next(n.props for n in batch.nodes if n.uid == "unifi:default:net:n-gone:rule:gw-drop:dst")
    assert side["opaque"] is True
    assert "ADDRv4" in side["opaque_reason"] and "not among the collected networks" in side["opaque_reason"]
    v, outcome = _verdict(monkeypatch, batch, BR30, BR1, "192.168.30.50/32", "192.168.1.1/32", 443)
    assert outcome == INDETERMINATE, v


def test_a_network_with_no_subnet_has_no_gateway_address():
    batch = _batch([_gateway_drop("ADDRv4", network="n50")])
    side = next(n.props for n in batch.nodes if n.uid == "unifi:default:net:n50:rule:gw-drop:dst")
    assert side["opaque"] is True and "no subnet" in side["opaque_reason"]


def test_an_addrv6_side_with_no_ipv6_gateway_address_is_opaque():
    batch = _batch([_gateway_drop("ADDRv6")])
    assert _rule_props(batch, "gw-drop")["dst_any"] is False
    side = next(n.props for n in batch.nodes if n.uid == "unifi:default:net:n1:rule:gw-drop:dst")
    assert side["opaque"] is True and "IPv6" in side["opaque_reason"]
    assert not any(n.uid == "unifi:default:net:n1:gw6" for n in batch.nodes)


def test_a_netv4_sibling_on_the_same_network_resolves(monkeypatch):
    sibling = _rule(
        "net-drop",
        "LAN_IN",
        2001,
        "drop",
        src_networkconf_id="n30",
        src_networkconf_type="NETv4",
        dst_networkconf_id="n1",
        dst_networkconf_type="NETv4",
    )
    batch = _batch([_gateway_drop("ADDRv4"), sibling])
    netobjs = {n.uid: n.props for n in batch.nodes if n.label == "NetObject"}
    assert "opaque" not in netobjs["unifi:default:net:n1"]
    assert any(r.rel_type == "RESOLVES_TO" and r.start_uid == "unifi:default:net:n1" for r in batch.rels)
    v, outcome = _verdict(monkeypatch, batch, BR30, BR1, "192.168.30.50/32", "192.168.1.20/32", 443)
    assert outcome == DENY and v["rule_name"] == "net-drop", v


def test_a_type_with_no_network_id_reads_the_side_from_its_other_fields():
    """A networkconf type on a side that names no network id scopes nothing
    by itself."""
    bare = _rule("bare", "LAN_IN", 2000, "drop", src_networkconf_type="ADDRv4", dst_networkconf_type="ADDRv4")
    props = _rule_props(_batch([bare]), "bare")
    assert props["src_any"] is True and props["dst_any"] is True
    rule = _rule("no-net", "LAN_IN", 2000, "drop", dst_networkconf_type="ADDRv4", dst_address="192.168.1.1")
    batch = _batch([rule])
    assert _rule_props(batch, "no-net")["dst_any"] is False
    assert ("DST", "unifi:default:fw:lan_in:no-net", "unifi:default:addr:192.168.1.1") in _rels(batch)
