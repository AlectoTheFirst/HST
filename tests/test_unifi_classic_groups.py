"""A UniFi classic rule's firewall groups: an address group the payload does
not hold leaves that side opaque, never Any, and a port group keeps the
rule's protocol. Each verdict runs the gate's own candidate and verdict
code with the graph reads answered from the batch (test_unifi_classic_scope).
"""

from __future__ import annotations

from tests.test_unifi import RAW, UDM, ZONES, _gw_batch
from tests.test_unifi_classic_scope import BR1, BR30, _rule, _verdict

from hst.collectors.unifi import READ_PATHS, normalize_unifi, policy_gaps
from hst.path.verdict import DENY, INDETERMINATE, PERMIT

GROUPS = [
    {"_id": "g-admins", "name": "Admins", "group_type": "address-group", "group_members": ["192.168.30.5"]},
    {"_id": "g-mgmt", "name": "Mgmt", "group_type": "address-group", "group_members": ["192.168.1.20"]},
    {"_id": "g-web", "name": "Web", "group_type": "port-group", "group_members": ["443", "8000-8080"]},
]

SSH = [
    _rule(
        "admin-ssh",
        "LAN_IN",
        2000,
        "accept",
        protocol="tcp",
        dst_port="22",
        src_firewallgroup_ids=["g-admins"],
        dst_firewallgroup_ids=["g-mgmt"],
    ),
    _rule("lan-drop", "LAN_IN", 2001, "drop", src_address="192.168.30.0/24", dst_address="192.168.1.0/24"),
]

WEB = [
    _rule("web", "LAN_IN", 2000, "accept", protocol="tcp", dst_firewallgroup_ids=["g-web"]),
    _rule("lan-drop", "LAN_IN", 2001, "drop", src_address="192.168.30.0/24", dst_address="192.168.1.0/24"),
]


def _batch(rules, groups):
    raw = {**RAW, "devices": RAW["devices"] + [UDM], "firewall_rules": rules, "firewall_groups": groups}
    return normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default")


def _rule_props(batch, rid):
    return next(n.props for n in batch.nodes if n.label == "FwRule" and n.props.get("rule_uid") == rid)


def test_resolved_groups_decide_the_rule(monkeypatch):
    batch = _batch(SSH, GROUPS)
    _, outcome = _verdict(monkeypatch, batch, BR30, BR1, "192.168.30.5/32", "192.168.1.20/32", 22)
    assert outcome == PERMIT
    _, outcome = _verdict(monkeypatch, batch, BR30, BR1, "192.168.30.50/32", "192.168.1.20/32", 22)
    assert outcome == DENY


def test_an_address_group_missing_from_the_payload_is_opaque_not_any(monkeypatch):
    batch = _batch(SSH, [])
    props = _rule_props(batch, "admin-ssh")
    assert props["src_any"] is False and props["dst_any"] is False
    v, outcome = _verdict(monkeypatch, batch, BR30, BR1, "192.168.30.50/32", "192.168.1.20/32", 22)
    assert outcome == INDETERMINATE, v
    opaque = [n.props for n in batch.nodes if n.label == "NetObject" and n.props.get("opaque")]
    assert any("g-admins" in p["opaque_reason"] for p in opaque)
    assert any("g-mgmt" in p["opaque_reason"] for p in opaque)


def test_a_group_of_an_unmodeled_type_is_opaque():
    odd = [{"_id": "g-admins", "name": "Admins", "group_type": "mac-group", "group_members": []}]
    props = _rule_props(_batch(SSH, odd), "admin-ssh")
    assert props["src_any"] is False


def test_a_port_group_rule_keeps_its_protocol(monkeypatch):
    batch = _batch(WEB, GROUPS)
    v, outcome = _verdict(monkeypatch, batch, BR30, BR1, "192.168.30.50/32", "192.168.1.20/32", 443, "udp")
    assert outcome == DENY and v["rule_name"] == "lan-drop", v
    v, outcome = _verdict(monkeypatch, batch, BR30, BR1, "192.168.30.50/32", "192.168.1.20/32", 8000, "tcp")
    assert outcome == PERMIT and v["rule_name"] == "web", v
    v, outcome = _verdict(monkeypatch, batch, BR30, BR1, "192.168.30.50/32", "192.168.1.20/32", 22, "tcp")
    assert outcome == DENY and v["rule_name"] == "lan-drop", v


def test_policy_gaps_name_unresolved_groups_and_a_refused_group_read():
    raw = {
        **RAW,
        "devices": RAW["devices"] + [UDM],
        "firewall_rules": SSH,
        "firewall_groups": [],
        "refused_reads": [READ_PATHS["firewall_groups"]],
    }
    gaps = policy_gaps(raw)
    assert any("firewall group read was refused" in g for g in gaps)
    assert any("1 classic firewall rules name firewall groups" in g for g in gaps)
    assert policy_gaps({**raw, "firewall_groups": GROUPS, "refused_reads": []}) == []


def test_a_zone_policy_side_with_specific_inline_ips_is_decided():
    policy = {
        "_id": "p-ip",
        "name": "p-ip",
        "enabled": True,
        "action": "BLOCK",
        "index": 10000,
        "protocol": "all",
        "source": {"zone_id": "z1", "matching_target": "ANY"},
        "destination": {
            "zone_id": "z2",
            "matching_target": "IP",
            "matching_target_type": "SPECIFIC",
            "ip_group_id": None,
            "ips": ["192.168.40.9"],
        },
    }
    batch = _gw_batch(firewall_zones=ZONES, firewall_policies=[policy])
    props = _rule_props(batch, "p-ip")
    assert props["unmodeled_fields"] == [] and props["states_opaque"] is False


def _collector(**settings):
    from hst.collectors.unifi import UnifiCollector, UnifiConfig
    from hst.core import Settings

    cfg = UnifiConfig(
        url="https://c",
        auth={"method": "user_password", "username": "ro", "password": "pw"},
        source_name="unifi-branch-a",
    )
    return UnifiCollector(cfg, Settings(_env_file=None, **settings))


def test_clients_anchored_on_the_default_fabric_are_named_in_a_run_warning():
    """A console with no gateway anchors its client addresses on the bridge
    domain of the default fabric, which another branch shares."""
    batch = _collector().normalize(RAW)
    assert any("default L2 fabric 'fab0'" in w and "L2_FABRICS" in w for w in batch.warnings)


def test_a_declared_fabric_or_a_routing_gateway_leaves_no_warning():
    fabric = _collector(l2_fabrics={"branch-a": ["unifi-branch-a"]}).normalize(RAW)
    assert not any("L2 fabric" in w for w in fabric.warnings)
    # every client on a network the console's own gateway routes
    clients = [c for c in RAW["clients"] if c.get("network_id") in ("n1", "n30")]
    routed = _collector().normalize({**RAW, "devices": RAW["devices"] + [UDM], "clients": clients})
    assert not any("L2 fabric" in w for w in routed.warnings)
    # a vlan-only client keeps the bridge-domain anchor even beside a gateway
    mixed = _collector().normalize({**RAW, "devices": RAW["devices"] + [UDM]})
    assert any("2 client addresses" in w for w in mixed.warnings)
