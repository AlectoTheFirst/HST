"""normalize_cisco / side_rows tests against a hand-built intermediate-shape
fixture and a cross-family contract check on each family's `parse()`."""

import pytest
from tests.test_iosxe import RAW as IOSXE_RAW
from tests.test_iosxr import RAW as IOSXR_RAW
from tests.test_nxos import RAW as NXOS_RAW

from hst.collectors import iosxe, iosxr, nxos
from hst.collectors.cisco_common import (
    ace_port_spec,
    ace_qualifier_reason,
    cdp_device_id,
    fallback_device_uid,
    normalize_cisco,
    parse_access_groups,
    parse_nat_config,
    resolve_acl_sources,
    side_rows,
    vrf_rt_fields,
    wildcard_cidr,
)
from hst.collectors.util import GraphBuilder, canonical_mac
from hst.core import uid
from hst.core.identity import MemoryResolver
from hst.core.labels import IdentityCollision
from hst.core.model import Batch, NodeRecord

L3DOM = "corp"
SCOPE = "nxos:sw1"
SOURCE = "nxos"
SERIAL = "FDO1234ABCD"
# minted by the in-memory registry from the hostname in INTER
DEV = "dev:sw1"

INTER = {
    "device": {"hostname": "sw1", "serial": SERIAL, "platform": "nxos", "os_version": "9.3(5)"},
    "interfaces": [
        {
            "name": "Ethernet1/1",
            "kind": "phys",
            "mac": "aabbccddee01",
            "admin_up": True,
            "ips": [{"ip": "10.0.0.1", "prefixlen": 24, "vrf": ""}],
            "vlan": None,
        },
        {"name": "port-channel1", "kind": "lag", "mac": None, "admin_up": True, "ips": [], "vlan": None},
        {
            "name": "loopback0",
            "kind": "loopback",
            "mac": None,
            "admin_up": True,
            "ips": [{"ip": "10.255.0.1", "prefixlen": 32, "vrf": "mgmt"}],
            "vlan": None,
        },
        {
            "name": "Vlan10",
            "kind": "svi",
            "mac": "aabbccddee10",
            "admin_up": True,
            "ips": [{"ip": "10.10.10.1", "prefixlen": 24, "vrf": ""}],
            "vlan": 10,
        },
    ],
    "neighbors": [
        {
            "local_port": "Ethernet1/1",
            "name": "core1",
            "mac": "aabbccddef01",
            "port": "Ethernet2/1",
            "proto": "lldp",
        },
        {"local_port": "Ethernet1/1", "name": "core1", "mac": None, "port": "Ethernet2/1", "proto": "cdp"},
    ],
    "vlans": [{"vid": 10, "name": "DATA"}],
    "vrfs": [
        {"name": "mgmt", "rd": "65000:1", "rt_import": ["65000:100"], "rt_export": ["65000:100", "65000:200"]}
    ],
    "rib": [
        {"vrf": "default", "prefix": "10.0.0.0/24", "next_hop": None, "protocol": "direct", "metric": 0},
        {
            "vrf": "mgmt",
            "prefix": "10.255.0.0/32",
            "next_hop": "10.255.0.2",
            "protocol": "static",
            "metric": 1,
        },
    ],
    "mac_table": [{"vlan": 10, "mac": "aabbccddef99", "port_name": "Ethernet1/1"}],
    "arp": [{"vrf": "default", "ip": "10.0.0.5", "mac": "aabbccddefaa", "interface_name": "Ethernet1/1"}],
}


def _batch():
    return normalize_cisco(INTER, source=SOURCE, scope=SCOPE, l3dom=L3DOM)


NO_SERIAL_INTER = {**INTER, "device": {**INTER["device"], "serial": None}}


def test_fallback_device_uid_uses_hostname_when_present():
    registry = MemoryResolver()
    assert fallback_device_uid({"device": {"hostname": "sw1"}}, "iosxr:core-9k", registry) == "dev:sw1"
    assert registry.resolve_device("ref", "iosxr:core-9k:sw1", None) == "dev:sw1"


def test_fallback_device_uid_defaults_to_unknown_when_no_hostname():
    registry = MemoryResolver()
    device = fallback_device_uid({"device": {}}, "iosxr:core-9k", registry)
    assert device.startswith("dev:unknown-")
    assert registry.resolve_device("ref", "iosxr:core-9k:unknown", None) == device
    assert fallback_device_uid({}, "iosxr:core-9k", registry) == device


def test_normalize_falls_back_to_fallback_device_uid_keyed_by_scope_not_source():
    # SOURCE ("nxos") and SCOPE ("nxos:sw1") differ, and the ref is keyed by scope.
    registry = MemoryResolver()
    batch = normalize_cisco(NO_SERIAL_INTER, source=SOURCE, scope=SCOPE, l3dom=L3DOM, resolver=registry)
    dev = next(n for n in batch.nodes if n.label == "Device")
    assert dev.uid == registry.resolve_device("ref", f"{SCOPE}:sw1", None) == "dev:sw1"
    assert registry.resolve_device("ref", f"{SOURCE}:sw1", "sw1") != dev.uid


def test_a_uid_redeclared_with_another_anchor_is_a_collision_error():
    """The anchor segment of a Prefix/IpAddress uid folds characters outside the
    slug alphabet, so two anchors can land on one uid."""
    b = GraphBuilder()
    colliding = uid.prefix("vrf:dev:x:corp", "10.0.0.0/24")
    b.node("Prefix", colliding, cidr="10.0.0.0/24", anchor="vrf:dev:x:corp")
    b.node("Prefix", colliding, cidr="10.0.0.0/24", af=4)  # same object, more props: merges
    with pytest.raises(IdentityCollision, match="one uid cannot name two objects"):
        b.node("Prefix", colliding, cidr="10.0.0.0/24", anchor="vrf-dev-x-corp")

    # a Batch assembled without GraphBuilder (fixtures, merged batches, replay)
    # reaches the loader through validate_registry, which runs the same check
    batch = Batch(
        source="nxos",
        scope=SCOPE,
        nodes=[
            NodeRecord(label="Prefix", uid=colliding, props={"cidr": "10.0.0.0/24", "anchor": "a"}),
            NodeRecord(label="Prefix", uid=colliding, props={"cidr": "10.0.0.0/24", "anchor": "b"}),
        ],
    )
    with pytest.raises(IdentityCollision):
        batch.validate_registry()


def test_a_box_without_a_hostname_is_named_by_the_host_the_collector_reached():
    """IOS-XR reads no hostname."""
    nameless = {**INTER, "device": {**INTER["device"], "hostname": None}}
    batch = normalize_cisco(
        nameless, source=SOURCE, scope=SCOPE, l3dom=L3DOM, target_host="core-9k.corp.example"
    )
    assert next(n.uid for n in batch.nodes if n.label == "Device") == "dev:core-9k"
    # a reported hostname wins over the target host
    batch = normalize_cisco(
        INTER, source=SOURCE, scope=SCOPE, l3dom=L3DOM, target_host="core-9k.corp.example"
    )
    assert next(n.uid for n in batch.nodes if n.label == "Device") == DEV


def test_a_device_uid_redeclared_with_another_hostname_is_a_collision_error():
    """A Device uid is minted one time and then kept, so inside one batch a
    second hostname on one uid is two boxes. The same rule holds for a VrfInstance's name."""
    b = GraphBuilder()
    b.node("Device", DEV, hostname="sw1", role="switch")
    b.node("Device", DEV, mgmt_ip="10.0.0.1")  # no hostname: no claim, no collision
    with pytest.raises(IdentityCollision):
        b.node("Device", DEV, hostname="sw2")

    b.node("VrfInstance", uid.vrf(DEV, "corp"), name="corp")
    with pytest.raises(IdentityCollision):
        b.node("VrfInstance", uid.vrf(DEV, "corp"), name="CORP")


def test_device_uid_is_the_hostname_and_the_registry_keys_it_by_the_serial():
    registry = MemoryResolver()
    batch = normalize_cisco(INTER, source=SOURCE, scope=SCOPE, l3dom=L3DOM, resolver=registry)
    dev = next(n for n in batch.nodes if n.label == "Device")
    assert dev.uid == DEV == registry.resolve_device("serial", SERIAL, None)
    assert dev.props["hostname"] == "sw1"
    assert dev.props["identities"] == ["sw1"]
    assert dev.props["vendor"] == "cisco"


def test_vlan_name_database_merges_onto_vlan_instance():
    batch = _batch()
    vu = uid.vlan(SCOPE, 10)
    vlan_node = next(n for n in batch.nodes if n.uid == vu and n.label == "VlanInstance")
    assert vlan_node.props["name"] == "DATA"


def test_the_collector_places_no_device_itself():
    """Where a device sits is the operator's answer, and one writer applies it:
    core/cycle.py apply_site_assignments."""
    batch = _batch()
    assert not [n for n in batch.nodes if n.label == "Site"]
    assert not [r for r in batch.rels if r.rel_type == "LOCATED_IN"]


def test_phys_interface_splits_into_port_and_interface():
    batch = _batch()
    iu = uid.interface(DEV, "Ethernet1/1")
    pu = uid.port(DEV, "Ethernet1/1")
    uids = {n.uid for n in batch.nodes}
    assert iu in uids and pu in uids
    assert any(n.uid == iu and n.label == "Interface" for n in batch.nodes)
    assert any(n.uid == pu and n.label == "Port" for n in batch.nodes)
    realized = [(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "REALIZED_BY"]
    assert (iu, pu) in realized
    on_device = {(r.start_label, r.start_uid) for r in batch.rels if r.rel_type == "ON" and r.end_uid == DEV}
    assert ("Interface", iu) in on_device
    assert ("Port", pu) in on_device


def test_lag_interface_also_splits_into_port_and_interface():
    batch = _batch()
    iu = uid.interface(DEV, "port-channel1")
    pu = uid.port(DEV, "port-channel1")
    uids = {n.uid for n in batch.nodes}
    assert iu in uids and pu in uids
    assert any(n.uid == iu and n.label == "Interface" for n in batch.nodes)
    assert any(n.uid == pu and n.label == "Port" for n in batch.nodes)
    realized = [(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "REALIZED_BY"]
    assert (iu, pu) in realized


def test_svi_creates_vlan_instance_and_shared_bridge_domain():
    batch = _batch()
    iu = uid.interface(DEV, "Vlan10")
    vu = uid.vlan(SCOPE, 10)
    seg = "bd:vlan:fab0:10"
    assert any(n.uid == vu and n.label == "VlanInstance" for n in batch.nodes)
    assert any(n.uid == seg and n.label == "BridgeDomain" for n in batch.nodes)
    assert (vu, seg) in [(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "REALIZES"]
    assert (iu, vu) in [(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "BOUND_TO"]


def test_has_ip_and_connected_prefix():
    """Routed/connected addressing anchors on the owning VrfInstance uid."""
    batch = _batch()
    iu = uid.interface(DEV, "Ethernet1/1")
    default_vrf = uid.vrf(DEV, "default")
    ipu = uid.ip(default_vrf, "10.0.0.1")
    pfu = uid.prefix(default_vrf, "10.0.0.0/24")
    ip_node = next(n for n in batch.nodes if n.uid == ipu)
    pfx_node = next(n for n in batch.nodes if n.uid == pfu)
    assert ip_node.label == "IpAddress"
    assert ip_node.props["anchor"] == default_vrf and ip_node.props["l3dom"] == L3DOM
    assert pfx_node.label == "Prefix" and pfx_node.props["kind"] == "connected"
    assert pfx_node.props["anchor"] == default_vrf
    assert (iu, ipu) in [(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "HAS_IP"]
    assert (ipu, pfu) in [(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "IN"]
    assert (default_vrf, pfu) in [(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ORIGINATES"]


def test_in_vrf_from_member_interfaces():
    batch = _batch()
    iu = uid.interface(DEV, "loopback0")
    mgmt_vrf = uid.vrf(DEV, "mgmt")
    assert any(n.uid == mgmt_vrf and n.label == "VrfInstance" for n in batch.nodes)
    assert (iu, mgmt_vrf) in [(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "IN_VRF"]


def test_pre_registration_and_interface_loop_memoize_onto_one_rt_bearing_vrfinstance():
    """The pre-registration loop (over inter["vrfs"]) runs before the interface
    loop's bare vrf_node(name) calls."""
    batch = _batch()
    mgmt_vrf = uid.vrf(DEV, "mgmt")
    mgmt_nodes = [n for n in batch.nodes if n.uid == mgmt_vrf and n.label == "VrfInstance"]
    assert len(mgmt_nodes) == 1
    assert mgmt_nodes[0].props["rd"] == "65000:1"

    rt100, rt200 = uid.route_target("65000:100"), uid.route_target("65000:200")
    imports = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "IMPORTS"}
    exports = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "EXPORTS"}
    assert (mgmt_vrf, rt100) in imports
    assert (mgmt_vrf, rt100) in exports
    assert (mgmt_vrf, rt200) in exports
    assert (mgmt_vrf, rt200) not in imports  # 65000:200 is export-only for mgmt


def test_global_table_fallback_vrfinstance_carries_is_global():
    """Ethernet1/1 and Vlan10 both carry an address with vrf="" (the graph-side
    convention for "no VRF configured"), so vrf_node("") gives the DEFAULT_VRF
    fallback."""
    batch = _batch()
    default_vrf = uid.vrf(DEV, "default")
    node = next(n for n in batch.nodes if n.uid == default_vrf and n.label == "VrfInstance")
    assert node.props["is_global"] is True


# --- forwarding-context identity ----------------------------------------------------


def test_two_vrfs_same_subnet_yield_two_distinct_prefix_uids_anchored_on_their_vrf():
    """Two VRFs holding the same subnet are two Prefix nodes."""
    inter = {
        **INTER,
        "interfaces": [
            {
                "name": "Ethernet1/1",
                "kind": "phys",
                "mac": "aabbccddee01",
                "admin_up": True,
                "ips": [{"ip": "10.5.5.1", "prefixlen": 24, "vrf": "RED"}],
                "vlan": None,
            },
            {
                "name": "Ethernet1/2",
                "kind": "phys",
                "mac": "aabbccddee02",
                "admin_up": True,
                "ips": [{"ip": "10.5.5.1", "prefixlen": 24, "vrf": "BLUE"}],
                "vlan": None,
            },
        ],
        "vrfs": [],
    }
    batch = normalize_cisco(inter, source=SOURCE, scope=SCOPE, l3dom=L3DOM)
    prefixes = [n for n in batch.nodes if n.label == "Prefix" and n.props["cidr"] == "10.5.5.0/24"]
    assert len(prefixes) == 2
    red_vrf, blue_vrf = uid.vrf(DEV, "RED"), uid.vrf(DEV, "BLUE")
    assert {n.uid for n in prefixes} == {
        uid.prefix(red_vrf, "10.5.5.0/24"),
        uid.prefix(blue_vrf, "10.5.5.0/24"),
    }
    assert {n.props["anchor"] for n in prefixes} == {red_vrf, blue_vrf}


def test_anchor_prop_present_on_every_emitted_prefix_and_ip():
    """Every IpAddress/Prefix this collector emits carries `anchor`, and the
    uid's identity segment is `uid.slug(anchor)`."""
    batch = _batch()
    anchored = [n for n in batch.nodes if n.label in ("Prefix", "IpAddress")]
    assert anchored
    for n in anchored:
        assert "anchor" in n.props, n.uid
        assert n.uid.split(":", 2)[1] == uid.slug(n.props["anchor"]), n.uid


def test_lldp_and_cdp_props_on_the_port():
    batch = _batch()
    pu = uid.port(DEV, "Ethernet1/1")
    port = next(n for n in batch.nodes if n.uid == pu)
    assert port.props["lldp_neighbor_name"] == "core1"
    assert port.props["lldp_neighbor_mac"] == "aabbccddef01"
    assert port.props["lldp_neighbor_port"] == "Ethernet2/1"
    assert port.props["cdp_neighbor_name"] == "core1"
    assert port.props["cdp_neighbor_port"] == "Ethernet2/1"
    assert "cdp_neighbor_mac" not in port.props  # neighbor mac is None


def test_neighbor_resolves_when_the_two_commands_spell_the_port_differently():
    """`show interfaces` prints the full name and `show cdp neighbors` prints the
    abbreviation."""
    inter = {
        **INTER,
        "interfaces": [
            {
                "name": "TwoGigabitEthernet1/0/1",
                "kind": "phys",
                "mac": "aabbccddee09",
                "admin_up": True,
                "ips": [],
                "vlan": None,
            }
        ],
        "neighbors": [
            {
                "local_port": "Tw1/0/1",
                "name": "access1",
                "mac": None,
                "port": "Gi1/0/24",
                "proto": "cdp",
            }
        ],
    }
    batch = normalize_cisco(inter, source=SOURCE, scope=SCOPE, l3dom=L3DOM)
    pu = uid.port(DEV, "TwoGigabitEthernet1/0/1")
    port = next(n for n in batch.nodes if n.uid == pu)
    assert port.props["cdp_neighbor_name"] == "access1"
    assert port.props["cdp_neighbor_port"] == "Gi1/0/24"


def test_mgmt_interface_gets_a_port_and_its_lldp_neighbor_survives():
    """mgmt0 gets a Port node and keeps its LLDP neighbor row."""
    inter = {
        **INTER,
        "interfaces": [
            {
                "name": "mgmt0",
                "kind": "mgmt",
                "mac": "aabbccddee0f",
                "admin_up": True,
                "ips": [],
                "vlan": None,
            }
        ],
        "neighbors": [
            {
                "local_port": "mgmt0",
                "name": "oob-switch",
                "mac": "aabbccddef02",
                "port": "Ethernet0/1",
                "proto": "lldp",
            }
        ],
    }
    batch = normalize_cisco(inter, source=SOURCE, scope=SCOPE, l3dom=L3DOM)
    pu = uid.port(DEV, "mgmt0")
    port = next(n for n in batch.nodes if n.uid == pu and n.label == "Port")
    assert port.props["lldp_neighbor_name"] == "oob-switch"
    assert port.props["lldp_neighbor_mac"] == "aabbccddef02"
    assert port.props["lldp_neighbor_port"] == "Ethernet0/1"


def test_side_rows_exact_columns_with_device_uid_stamped():
    rows = side_rows(INTER, DEV)
    assert set(rows) == {"rib", "mac", "arp"}
    assert {frozenset(r) for r in rows["rib"]} == {
        frozenset(
            {
                "device_uid",
                "vrf",
                "context_uid",
                "prefix",
                "next_hop",
                # the table a leaked route's next hop resolves in
                "next_hop_context_uid",
                "interface",
                "protocol",
                # a Null0 route is a discard route
                "discard",
                "metric",
                "af",
                "prefixlen",
                "lo",
                "hi",
            }
        )
    }
    assert {frozenset(r) for r in rows["mac"]} == {
        frozenset({"device_uid", "vlan", "mac", "port_name", "bridge_domain_uid"})
    }
    assert {frozenset(r) for r in rows["arp"]} == {
        frozenset({"device_uid", "vrf", "context_uid", "ip", "mac", "interface_name", "af"})
    }
    assert all(r["device_uid"] == DEV for table in rows.values() for r in table)
    assert rows["rib"][0]["prefix"] == "10.0.0.0/24"
    # context_uid is the uid of the VrfInstance node normalize_cisco emits for that table
    batch = _batch()
    vrf_nodes = {n.props["name"]: n.uid for n in batch.nodes if n.label == "VrfInstance"}
    assert all(r["context_uid"] == vrf_nodes[r["vrf"]] for r in rows["rib"])
    assert all(r["context_uid"] == vrf_nodes[r["vrf"]] for r in rows["arp"])
    assert rows["mac"][0]["mac"] == "aabbccddef99"
    assert rows["arp"][0]["ip"] == "10.0.0.5"
    assert rows["arp"][0]["af"] == 4
    # bridge_domain_uid is the uid of the BridgeDomain node normalize_cisco emits for that VLAN
    bd_nodes = {n.props["vid"]: n.uid for n in batch.nodes if n.label == "VlanInstance"}
    vlan_to_bd = {
        rel.start_uid: rel.end_uid
        for rel in batch.rels
        if rel.rel_type == "REALIZES"
        and rel.start_label == "VlanInstance"
        and rel.end_label == "BridgeDomain"
    }
    assert all(r["bridge_domain_uid"] == vlan_to_bd[bd_nodes[r["vlan"]]] for r in rows["mac"])
    # rib/mac_table/arp never enter the batch itself
    assert not any("next_hop" in n.props or "port_name" in n.props for n in batch.nodes)
    assert not any("next_hop" in r.props or "port_name" in r.props for r in batch.rels)


def test_side_rows_mac_bridge_domain_uid_uses_the_passed_l2fabric():
    """`side_rows`'s `l2fabric` must be the same value passed to
    `normalize_cisco` for this device, so a mac row's `bridge_domain_uid`
    matches this run's BridgeDomain nodes."""
    rows = side_rows(INTER, DEV, l2fabric="dmz")
    assert rows["mac"][0]["bridge_domain_uid"] == uid.bridge_domain("dmz", 10)


def test_side_rows_rib_context_uid_falls_back_to_default_for_an_empty_vrf_column():
    """side_rows() maps an empty vrf column to the default context."""
    inter = {
        **INTER,
        "rib": [{"vrf": "", "prefix": "10.0.0.0/24", "next_hop": None, "protocol": "direct", "metric": 0}],
    }
    rows = side_rows(inter, DEV)
    assert rows["rib"][0]["context_uid"] == uid.vrf(DEV, "default")


def test_host_length_address_creates_no_connected_prefix():
    batch = _batch()
    prefixes = {n.props["cidr"] for n in batch.nodes if n.label == "Prefix"}
    assert "10.255.0.1/32" not in prefixes
    # the loopback address itself still lands, attached to its interface,
    # anchored on the owning VrfInstance uid ("mgmt"), not the l3dom string
    ipu = uid.ip(uid.vrf(DEV, "mgmt"), "10.255.0.1")
    assert any(n.uid == ipu and n.label == "IpAddress" for n in batch.nodes)
    iu = uid.interface(DEV, "loopback0")
    assert (iu, ipu) in [(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "HAS_IP"]
    assert not [r for r in batch.rels if r.rel_type == "IN" and r.start_uid == ipu]


def test_canonical_mac_is_canonical_or_none():
    """The cross-collector MAC policy is the canonical 12-hex form or None."""
    assert canonical_mac("aabb.ccdd.ee01") == "aabbccddee01"
    assert canonical_mac("AA:BB:CC:DD:EE:01") == "aabbccddee01"
    assert canonical_mac("not-a-mac") is None
    assert canonical_mac("") is None
    assert canonical_mac(None) is None


def test_unparseable_neighbor_mac_becomes_none_not_the_raw_string():
    inter = {
        **INTER,
        "neighbors": [
            {
                "local_port": "Ethernet1/1",
                "name": "core1",
                "mac": "core1.example.com",  # a chassis-id that is a hostname, not a MAC
                "port": "Ethernet2/1",
                "proto": "lldp",
            }
        ],
    }
    batch = normalize_cisco(inter, source=SOURCE, scope=SCOPE, l3dom=L3DOM)
    port = next(n for n in batch.nodes if n.uid == uid.port(DEV, "Ethernet1/1"))
    assert "lldp_neighbor_mac" not in port.props
    assert port.props["lldp_neighbor_name"] == "core1"


def test_batch_is_coherent_no_dangling_endpoints():
    batch = _batch()
    node_keys = {(n.label, n.uid) for n in batch.nodes}
    for r in batch.rels:
        assert (r.start_label, r.start_uid) in node_keys, f"dangling start: {r}"
        assert (r.end_label, r.end_uid) in node_keys, f"dangling end: {r}"
    known_labels = {
        "Device",
        "Site",
        "Interface",
        "Port",
        "IpAddress",
        "Prefix",
        "VrfInstance",
        "RoutingDomain",
        "VlanInstance",
        "BridgeDomain",
        "RouteTarget",
    }
    assert {n.label for n in batch.nodes} <= known_labels


# --- vrf_rt_fields: shared by the IOS-XR/IOS-XE `show vrf ... detail` mappers ------------


class TestVrfRtFields:
    def test_no_detail_row_yields_the_empty_unknown_shape(self):
        assert vrf_rt_fields(None) == {"rd": None, "rt_import": [], "rt_export": []}

    def test_xr_not_set_sentinel_normalizes_to_none(self):
        row = {"rd": "not set", "rt_import": [], "rt_export": []}
        assert vrf_rt_fields(row)["rd"] is None

    def test_xe_bracketed_not_set_sentinel_normalizes_to_none(self):
        row = {"rd": "<not set>", "rt_import": [], "rt_export": []}
        assert vrf_rt_fields(row)["rd"] is None

    def test_a_real_rd_passes_through(self):
        row = {"rd": "65000:1", "rt_import": [], "rt_export": []}
        assert vrf_rt_fields(row)["rd"] == "65000:1"

    def test_rt_lists_are_deduped_and_sorted(self):
        row = {"rd": None, "rt_import": ["65000:200", "65000:100", "65000:100", ""], "rt_export": []}
        assert vrf_rt_fields(row)["rt_import"] == ["65000:100", "65000:200"]

    def test_missing_rt_keys_default_to_empty_lists(self):
        assert vrf_rt_fields({"rd": None})["rt_import"] == []
        assert vrf_rt_fields({"rd": None})["rt_export"] == []


# --- NAT: the shared `ip nat` grammar ----------------------------------------------------


class TestNatGrammar:
    def test_pool_netmask_and_prefix_length_spellings(self):
        nat = parse_nat_config(
            [
                "ip nat pool A 203.0.113.10 203.0.113.20 netmask 255.255.255.0",
                "ip nat pool B 10.99.0.0 10.99.0.255 prefix-length 24",
            ]
        )
        assert nat["pools"]["A"]["start"] == "203.0.113.10"
        assert nat["pools"]["A"]["cidr"] is None  # .10-.20 is not a whole block
        assert nat["pools"]["B"]["cidr"] == "10.99.0.0/24"

    def test_single_address_pool_has_no_cidr(self):
        nat = parse_nat_config(["ip nat pool ONE 203.0.113.7 203.0.113.7 prefix-length 24"])
        assert nat["pools"]["ONE"]["cidr"] is None  # one address has no network cidr

    def test_static_with_protocol_ports_and_vrf(self):
        [r] = parse_nat_config(["ip nat inside source static tcp 10.0.0.5 8080 203.0.113.5 80 vrf CUST"])[
            "rules"
        ]
        assert r["direction"] == "inside-source" and r["static"] is True
        assert r["protocol"] == "tcp"
        assert (r["local"], r["local_port"]) == ("10.0.0.5", 8080)
        assert (r["global"], r["global_port"]) == ("203.0.113.5", 80)
        assert r["vrf"] == "CUST"

    def test_static_network_form(self):
        [r] = parse_nat_config(["ip nat inside source static network 10.1.1.0 203.0.113.0 /24"])["rules"]
        assert r["network"] is True and r["prefixlen"] == 24
        assert r["local"] == "10.1.1.0" and r["global"] == "203.0.113.0"

    def test_outside_source_static_stores_global_first(self):
        # IOS writes the outside form global-first; the parse stores semantically
        [r] = parse_nat_config(["ip nat outside source static 198.51.100.9 10.5.5.9"])["rules"]
        assert r["direction"] == "outside-source"
        assert r["global"] == "198.51.100.9" and r["local"] == "10.5.5.9"

    def test_list_pool_interface_destination_and_route_map_forms(self):
        nat = parse_nat_config(
            [
                "ip nat inside source list ACL1 pool P1 overload",
                "ip nat inside source list 7 interface GigabitEthernet0/0 overload",
                "ip nat inside destination list DACL pool P2",
                "ip nat inside source route-map RM pool P1",
                "ip nat outside source list OACL pool P3",
            ]
        )
        forms = [(r["direction"], r.get("acl"), r.get("pool"), r.get("interface")) for r in nat["rules"]]
        assert forms == [
            ("inside-source", "ACL1", "P1", None),
            ("inside-source", "7", None, "GigabitEthernet0/0"),
            ("inside-destination", "DACL", "P2", None),
            ("inside-source", None, "P1", None),
            ("outside-source", "OACL", "P3", None),
        ]
        assert nat["rules"][3]["route_map"] == "RM"
        assert [r["overload"] for r in nat["rules"]] == [True, True, False, False, False]

    def test_unknown_trailing_tokens_are_tolerated(self):
        [r] = parse_nat_config(["ip nat inside source static 10.0.0.5 203.0.113.5 extendable no-alias"])[
            "rules"
        ]
        assert r["local"] == "10.0.0.5" and r["global"] == "203.0.113.5"

    def test_unknown_grammar_lines_are_dropped_not_fatal(self):
        nat = parse_nat_config(
            [
                "ip nat translation timeout 300",
                "ip nat inside source list ACL1 pool P1",
                "ip nat settings mode default",
            ]
        )
        assert len(nat["rules"]) == 1

    def test_interface_sub_blocks_carry_roles_top_level_bare_lines_do_not(self):
        nat = parse_nat_config(
            [
                "interface Ethernet1/1",
                "  ip nat outside",
                "interface Vlan10",
                "  ip nat inside",
                "feature nat",
                "  ip nat inside",  # indented under a non-interface line: no context
                "ip nat inside",  # bare at top level: not a role, not a rule
            ]
        )
        assert nat["if_roles"] == {"Ethernet1/1": "outside", "Vlan10": "inside"}
        assert nat["rules"] == []


class TestWildcardCidr:
    def test_wildcard_becomes_cidr(self):
        assert wildcard_cidr("10.0.0.0", "0.0.0.255") == "10.0.0.0/24"
        assert wildcard_cidr("10.0.0.0", "0.0.255.255") == "10.0.0.0/16"

    def test_bare_or_zero_wildcard_is_a_host(self):
        assert wildcard_cidr("10.0.0.9", None) == "10.0.0.9"
        assert wildcard_cidr("10.0.0.9", "0.0.0.0") == "10.0.0.9"  # noqa: S104 - an ACL wildcard

    def test_non_contiguous_wildcard_has_no_cidr(self):
        assert wildcard_cidr("10.0.0.0", "0.255.0.255") is None


class TestResolveAclSources:
    ACLS = {
        "MIXED": [
            {"action": "permit", "src": "10.1.0.0/16", "dst": "any"},
            {"action": "permit", "src": "10.2.2.2", "dst": "any"},
            {"action": "deny", "src": "10.1.9.0/24", "dst": "any"},
            {"action": "permit", "src": "any", "dst": "203.0.113.80"},
        ],
        "EMPTY": [],
    }

    def test_permit_sources_resolve_deny_makes_approximate(self):
        res = resolve_acl_sources(self.ACLS, "MIXED")
        assert res["targets"] == ["10.1.0.0/16", "10.2.2.2"]
        assert res["any"] is True  # the explicit `permit any` ACE
        assert res["approximate"] is True  # the deny ACE
        assert res["unresolved"] is False

    def test_destination_side_for_inside_destination_rules(self):
        res = resolve_acl_sources(self.ACLS, "MIXED", side="dst")
        assert res["targets"] == ["203.0.113.80"]

    def test_uncollected_acl_is_unresolved_and_approximate(self):
        res = resolve_acl_sources(self.ACLS, "NOPE")
        assert res == {"targets": [], "any": False, "approximate": True, "unresolved": True}
        assert resolve_acl_sources(None, "NOPE")["unresolved"] is True

    def test_collected_but_empty_acl_is_resolved(self):
        res = resolve_acl_sources(self.ACLS, "EMPTY")
        assert res["unresolved"] is False and res["approximate"] is False

    def test_unparseable_permit_side_marks_approximate(self):
        acls = {"A": [{"action": "permit", "src": None, "dst": None}]}
        assert resolve_acl_sources(acls, "A")["approximate"] is True


class TestParseAccessGroups:
    def test_bindings_in_config_order_across_interface_stanzas(self):
        lines = [
            "interface GigabitEthernet1/0/1",
            " description x",
            " ip access-group EDGE-IN in",
            "!",
            "interface Vlan10",
            " ip access-group MGMT-OUT out",
        ]
        assert parse_access_groups(lines) == [
            {"interface": "GigabitEthernet1/0/1", "direction": "in", "acl": "EDGE-IN"},
            {"interface": "Vlan10", "direction": "out", "acl": "MGMT-OUT"},
        ]

    def test_a_line_outside_any_interface_stanza_is_dropped(self):
        assert parse_access_groups(["ip access-group ORPHAN in"]) == []

    def test_a_non_access_group_sub_line_of_an_interface_is_ignored(self):
        lines = ["interface Vlan10", " ip address 10.0.0.1 255.255.255.0"]
        assert parse_access_groups(lines) == []

    def test_a_bang_line_does_not_end_the_current_interface_early(self):
        # Only a non-indented line ends the stanza.
        lines = ["interface Vlan10", " ip access-group MGMT-OUT out", "!"]
        assert parse_access_groups(lines) == [{"interface": "Vlan10", "direction": "out", "acl": "MGMT-OUT"}]


class TestAcePortSpec:
    def test_eq_and_range_become_a_port_or_a_range_spec(self):
        assert ace_port_spec("eq", 443) == ("443", None)
        assert ace_port_spec("range", 20, 21) == ("20-21", None)

    def test_lt_and_gt_become_the_bounded_complement(self):
        assert ace_port_spec("lt", 1024) == ("0-1023", None)
        assert ace_port_spec("gt", 1023) == ("1024-65535", None)

    def test_neq_is_not_expressible_as_a_single_spec(self):
        spec, why = ace_port_spec("neq", 80)
        assert spec is None and "neq" in why

    def test_a_port_keyword_with_no_number_is_not_expressible(self):
        spec, why = ace_port_spec("eq", "www")
        assert spec is None and "www" in why

    def test_no_operator_at_all_is_no_port_clause(self):
        assert ace_port_spec(None, None) == (None, None)

    def test_a_range_missing_its_end_is_not_expressible(self):
        spec, why = ace_port_spec("range", 20, None)
        assert spec is None and why

    def test_precedence_and_tos_name_themselves_not_an_unresolved_port(self):
        """`precedence` and `tos` share the operator column with the port
        operators."""
        spec, why = ace_port_spec("precedence", "routine")
        assert spec is None and "precedence" in why and "routine" in why
        spec, why = ace_port_spec("tos", "max-reliability")
        assert spec is None and "tos" in why.lower() and "max-reliability" in why


class TestAceQualifierReason:
    def test_no_qualifiers_is_none(self):
        assert ace_qualifier_reason([]) is None

    def test_names_every_qualifier_the_flow_tuple_has_no_dimension_for(self):
        reason = ace_qualifier_reason(["the TCP flags 'established'", "the ICMP type 'echo'"])
        assert "established" in reason and "echo" in reason


# --- Interface ACLs: acl_stage branches the family fixtures do not cover -----------------

_PERMIT_ANY_ACE = {
    "action": "permit",
    "src_any": True,
    "src": None,
    "src_opaque_reason": None,
    "dst_any": True,
    "dst": None,
    "dst_opaque_reason": None,
    "proto": None,
    "ports": None,
    "src_port": None,
    "svc_opaque_reason": None,
    "qualifier_reason": None,
}


def _acl_batch(acl: dict):
    return normalize_cisco({**INTER, "acl": acl}, source=SOURCE, scope=SCOPE, l3dom=L3DOM)


def test_acl_stage_absent_or_no_bindings_changes_nothing():
    base = {n.uid for n in _batch().nodes}
    assert {n.uid for n in _acl_batch({}).nodes} == base
    assert {n.uid for n in _acl_batch({"lists": {}, "bindings": []}).nodes} == base


def test_acl_stage_one_rulebase_per_acl_name_enforced_by_the_device():
    acl = {
        "lists": {"EDGE-IN": [_PERMIT_ANY_ACE]},
        "bindings": [{"interface": "Ethernet1/1", "direction": "in", "acl": "EDGE-IN"}],
    }
    batch = _acl_batch(acl)
    rb = next(n for n in batch.nodes if n.label == "FwRulebase")
    assert rb.uid == f"{SCOPE}:acl:edge-in~f89b1a37"
    # configured_revision is the digest of the reported entries the ENFORCES
    # edge records as installed
    props = dict(rb.props)
    revision = props.pop("configured_revision")
    assert props == {
        "name": "EDGE-IN",
        "kind": "access",
        "vendor": "cisco",
        "match_context": "interface-acl",
        "default_action": "deny",
        "af": 4,
    }
    assert (DEV, rb.uid) in {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ENFORCES"}
    (edge,) = [r for r in batch.rels if r.rel_type == "ENFORCES" and r.end_uid == rb.uid]
    assert edge.props["installed_revision"] == revision and edge.props["installed"] is True
    # the binding is the PROTECTED_BY edge, not a property of the rules
    rule = next(n for n in batch.nodes if n.label == "FwRule")
    assert "in_interface" not in rule.props
    assert "out_interface" not in rule.props


def test_acl_stage_same_list_bound_to_two_interfaces_mints_one_rulebase():
    acl = {
        "lists": {"SHARED": [_PERMIT_ANY_ACE]},
        "bindings": [
            {"interface": "Ethernet1/1", "direction": "in", "acl": "SHARED"},
            {"interface": "Vlan10", "direction": "out", "acl": "SHARED"},
        ],
    }
    batch = _acl_batch(acl)
    assert {n.uid for n in batch.nodes if n.label == "FwRulebase"} == {f"{SCOPE}:acl:shared~0e1d1edc"}
    assert len([n for n in batch.nodes if n.label == "FwRule"]) == 1


def test_acl_stage_a_binding_naming_an_unknown_interface_puts_no_interface_on_the_rule():
    acl = {
        "lists": {"X": []},
        "bindings": [{"interface": "GigabitEthernet9/9/9", "direction": "in", "acl": "X"}],
    }
    batch = _acl_batch(acl)
    rule = next(n for n in batch.nodes if n.label == "FwRule")
    assert "in_interface" not in rule.props
    assert not [r for r in batch.rels if r.rel_type == "PROTECTED_BY"]


def test_acl_stage_a_collected_but_empty_acl_mints_an_opaque_rule_not_a_confident_deny():
    """A list that printed its header and no ACE mints an opaque rule with the
    vendor's implicit-deny action."""
    acl = {
        "lists": {"EMPTY": []},
        "bindings": [{"interface": "Ethernet1/1", "direction": "in", "acl": "EMPTY"}],
    }
    batch = _acl_batch(acl)
    rule = next(n for n in batch.nodes if n.label == "FwRule")
    assert rule.props["action"] == "deny" and rule.props["src_any"] is False
    obj = next(n for n in batch.nodes if n.label == "NetObject")
    assert obj.props["opaque"] is True
    assert "EMPTY" in obj.props["opaque_reason"] and "not collected" not in obj.props["opaque_reason"]


def test_acl_stage_an_uncollected_acl_mints_an_opaque_rule_fail_visible():
    acl = {"lists": {}, "bindings": [{"interface": "Ethernet1/1", "direction": "in", "acl": "GHOST"}]}
    batch = _acl_batch(acl)
    rb = next(n for n in batch.nodes if n.label == "FwRulebase")
    obj = next(n for n in batch.nodes if n.label == "NetObject")
    assert obj.props["opaque"] is True and "GHOST" in obj.props["opaque_reason"]
    assert (DEV, rb.uid) in {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ENFORCES"}


def test_acl_stage_a_binding_with_no_direction_acl_name_or_interface_is_skipped():
    acl = {
        "lists": {"X": [_PERMIT_ANY_ACE]},
        "bindings": [
            {"interface": "Ethernet1/1", "direction": "sideways", "acl": "X"},
            {"interface": "Ethernet1/1", "direction": "in", "acl": ""},
            {"interface": "", "direction": "in", "acl": "X"},
        ],
    }
    assert not [n for n in _acl_batch(acl).nodes if n.label == "FwRulebase"]


# --- NAT: nat_stage branches the family fixtures do not cover ----------------------------


def _nat_batch(nat: dict):
    return normalize_cisco({**INTER, "nat": nat}, source=SOURCE, scope=SCOPE, l3dom=L3DOM)


def test_nat_stage_positions_statics_ahead_of_dynamic_rules_per_direction():
    """Cisco checks static translations before dynamic ones, whatever the
    configuration order. The running-config prints the list rule
    first; a host inside its ACL that also has a static mapping must be
    claimed by the static rule, so the static comes first by `position`,
    the order the NAT gate and the policy engine read as first match."""
    nat = parse_nat_config(
        [
            "ip nat pool P 203.0.113.10 203.0.113.20 netmask 255.255.255.0",
            "ip nat inside source list NAT-IN pool P overload",
            "ip nat outside source list OUT-IN pool P",
            "ip nat inside source static 10.10.10.5 203.0.113.5",
            "ip nat inside source static 10.10.10.6 203.0.113.6",
            "ip nat outside source static 198.51.100.9 10.5.5.9",
        ]
    )
    acls = {
        "NAT-IN": [{"action": "permit", "src": "10.10.10.0/24", "dst": "any"}],
        "OUT-IN": [{"action": "permit", "src": "198.51.100.0/24", "dst": "any"}],
    }
    batch = _nat_batch({**nat, "acls": acls})
    rules = {n.uid: n.props for n in batch.nodes if n.label == "NatRule"}
    inside = sorted(
        (p["position"], u, p["static"]) for u, p in rules.items() if p["direction"] == "inside-source"
    )
    # the uid keeps the configuration ordinal, the position the evaluation order
    assert inside == [
        (1, f"{SCOPE}:nat:inside-source:2", True),
        (2, f"{SCOPE}:nat:inside-source:3", True),
        (3, f"{SCOPE}:nat:inside-source:1", False),
    ]
    outside = sorted(
        (p["position"], u, p["static"]) for u, p in rules.items() if p["direction"] == "outside-source"
    )
    assert outside == [
        (1, f"{SCOPE}:nat:outside-source:2", True),
        (2, f"{SCOPE}:nat:outside-source:1", False),
    ]


def test_nat_stage_outside_source_is_dnat_side_and_swaps_the_edge_targets():
    nat = parse_nat_config(["ip nat outside source static 198.51.100.9 10.5.5.9"])
    batch = _nat_batch({**nat, "acls": {}})
    rb = next(n for n in batch.nodes if n.label == "FwRulebase")
    assert rb.uid == f"{SCOPE}:nat:outside-source"
    rule = next(n for n in batch.nodes if n.label == "NatRule")
    assert rule.uid == f"{SCOPE}:nat:outside-source:1"
    assert rule.props["kind"] == "dnat" and rule.props["direction"] == "outside-source"
    # it rewrites the source of outside-to-inside traffic: orig is the outside
    # global address, xlate the inside-local appearance; NAT targets are
    # routed addressing, anchored on the rule's VrfInstance uid (no `vrf` on
    # this rule: the device's default table)
    default_vrf = uid.vrf(DEV, "default")
    edges = {(r.rel_type, r.end_uid) for r in batch.rels if r.start_uid == rule.uid}
    assert ("ORIG_SRC", uid.ip(default_vrf, "198.51.100.9")) in edges
    assert ("XLATE_SRC", uid.ip(default_vrf, "10.5.5.9")) in edges
    assert rule.props["translation"] == "10.5.5.9"


def test_nat_stage_static_network_form_mints_prefixes():
    nat = parse_nat_config(["ip nat inside source static network 10.1.1.0 203.0.113.0 /24"])
    batch = _nat_batch({**nat, "acls": {}})
    rule = next(n for n in batch.nodes if n.label == "NatRule")
    default_vrf = uid.vrf(DEV, "default")
    edges = {(r.rel_type, r.end_uid) for r in batch.rels if r.start_uid == rule.uid}
    assert ("ORIG_SRC", uid.prefix(default_vrf, "10.1.1.0/24")) in edges
    assert ("XLATE_SRC", uid.prefix(default_vrf, "203.0.113.0/24")) in edges


def test_nat_stage_vrf_scoped_rule_lands_in_that_vrfs_domain():
    nat = parse_nat_config(["ip nat inside source static 10.0.0.5 203.0.113.5 vrf CUST"])
    batch = _nat_batch({**nat, "acls": {}})
    rule = next(n for n in batch.nodes if n.label == "NatRule")
    cust_vrf = uid.vrf(DEV, "CUST")
    edges = {(r.rel_type, r.end_uid) for r in batch.rels if r.start_uid == rule.uid}
    assert ("ORIG_SRC", uid.ip(cust_vrf, "10.0.0.5")) in edges
    assert ("XLATE_SRC", uid.ip(cust_vrf, "203.0.113.5")) in edges
    assert any(n.label == "VrfInstance" and n.props.get("name") == "CUST" for n in batch.nodes)


def test_nat_stage_uncollected_acl_rule_is_approximate_with_no_orig_edges():
    nat = parse_nat_config(
        [
            "ip nat pool P 10.99.0.0 10.99.0.255 prefix-length 24",
            "ip nat inside source list MISSING pool P",
        ]
    )
    batch = _nat_batch({**nat, "acls": {}})
    rule = next(n for n in batch.nodes if n.label == "NatRule")
    assert rule.props["approximate"] is True and rule.props["src_any"] is False
    assert not [r for r in batch.rels if r.start_uid == rule.uid and r.rel_type == "ORIG_SRC"]
    assert [r.end_uid for r in batch.rels if r.start_uid == rule.uid and r.rel_type == "XLATE_SRC"] == [
        uid.prefix(uid.vrf(DEV, "default"), "10.99.0.0/24")
    ]


def test_nat_stage_absent_or_empty_nat_key_changes_nothing():
    base = {n.uid for n in _batch().nodes}
    with_empty = {n.uid for n in _nat_batch({"if_roles": {}, "pools": {}, "rules": [], "acls": {}}).nodes}
    assert with_empty == base


def test_nat_stage_if_roles_merge_onto_existing_interfaces_and_skip_unknown_names():
    nat = {"if_roles": {"Ethernet1/1": "outside", "Ethernet9/9": "inside"}, "pools": {}, "rules": []}
    batch = _nat_batch(nat)
    eth = next(n for n in batch.nodes if n.uid == uid.interface(DEV, "Ethernet1/1"))
    assert eth.props["nat_role"] == "outside" and eth.props["kind"] == "phys"
    # an unknown interface name mints nothing
    assert not any("ethernet9-9" in n.uid for n in batch.nodes)


# bgp_stage: absent or empty "bgp"/"route_policies"/"prefix_lists" keys leave normalize() unchanged.


def test_bgp_stage_absent_or_empty_keys_change_nothing():
    base = {n.uid for n in _batch().nodes}
    empty_inter = {
        **INTER,
        "bgp": None,
        "bgp_sessions": [],
        "bgp_redistribute": [],
        "route_policies": [],
        "prefix_lists": [],
    }
    with_empty = {n.uid for n in normalize_cisco(empty_inter, source=SOURCE, scope=SCOPE, l3dom=L3DOM).nodes}
    assert with_empty == base
    assert not any(n.label in ("RoutingProcess", "BgpSession", "RoutePolicy") for n in _batch().nodes)


# --- cross-family contract: every family's parse() output satisfies the same
# intermediate shape, independent of which CLI dialect/transport produced it

_INTER_TOP_KEYS = {"device", "interfaces", "neighbors", "vlans", "vrfs", "rib", "mac_table", "arp"}
_INTER_DEVICE_KEYS = {"hostname", "serial", "platform", "os_version"}
_INTER_LIST_FIELDS = ("interfaces", "neighbors", "vlans", "vrfs", "rib", "mac_table", "arp")
_INTER_ENTRY_FIELDS = {
    "interfaces": {"name", "kind", "mac", "admin_up", "ips", "vlan"},
    "neighbors": {"local_port", "name", "mac", "port", "proto"},
    "vlans": {"vid"},
    "vrfs": {"name", "rd", "rt_import", "rt_export"},
    "rib": {"vrf", "prefix", "next_hop", "protocol", "metric"},
    "mac_table": {"vlan", "mac", "port_name"},
    "arp": {"vrf", "ip", "mac", "interface_name"},
}


def assert_inter_shape(inter: dict) -> None:
    """Validate `inter` against the cross-family intermediate-shape contract
    documented on `normalize_cisco`: required top-level keys, required
    `device` keys, list types for every collection field, and required
    per-entry fields for interfaces/neighbors/vlans/vrfs/rib/mac_table/arp.
    `vlans` entries require `vid` (`name` is optional: `normalize_cisco`
    hard-indexes `v["vid"]` and reads name with `.get`). `vrfs` entries are
    dicts requiring `name`/`rd`/`rt_import`/`rt_export`, one per named VRF
    the platform reports; the fallback global table is never in this list."""
    missing = _INTER_TOP_KEYS - inter.keys()
    assert not missing, f"intermediate shape missing top-level keys: {missing}"
    assert isinstance(inter["device"], dict), "device must be a dict"
    missing_device = _INTER_DEVICE_KEYS - inter["device"].keys()
    assert not missing_device, f"device missing keys: {missing_device}"
    for field in _INTER_LIST_FIELDS:
        assert isinstance(inter[field], list), f"{field} must be a list"
    for field, required in _INTER_ENTRY_FIELDS.items():
        for i, entry in enumerate(inter[field]):
            assert isinstance(entry, dict), f"{field}[{i}] must be a dict"
            missing_fields = required - entry.keys()
            assert not missing_fields, f"{field}[{i}] missing fields: {missing_fields}"


def test_nxos_parse_satisfies_inter_shape():
    assert_inter_shape(nxos.parse(NXOS_RAW))


def test_assert_inter_shape_rejects_a_vlans_entry_missing_vid():
    bad = {**INTER, "vlans": [{"name": "DATA"}]}  # no "vid"
    with pytest.raises(AssertionError, match=r"vlans.*missing fields"):
        assert_inter_shape(bad)


class TestParsedInterShape:
    def test_iosxe_parse_satisfies_inter_shape(self):
        assert_inter_shape(iosxe.parse(IOSXE_RAW))

    def test_iosxr_parse_satisfies_inter_shape(self):
        assert_inter_shape(iosxr.parse(IOSXR_RAW))


def test_cdp_neighbor_serial_lands_on_the_port_and_absent_serial_writes_nothing():
    """The reasoner's cable-from-neighbor-name rule joins `cdp_neighbor_serial`
    against the device uid: a Nexus far end's CDP device id carries it, every
    other far end's does not, and an absent one writes no prop."""
    inter = {
        **INTER,
        "neighbors": [
            {
                "local_port": "Eth1/1",
                "name": "core2.example.com",
                "serial": "ABC1234XYZ",
                "mac": None,
                "port": "Ethernet1/30",
                "proto": "cdp",
            },
            {"local_port": "Po1", "name": "access1", "mac": None, "port": "Gi1/0/24", "proto": "cdp"},
        ],
    }
    batch = normalize_cisco(inter, source=SOURCE, scope=SCOPE, l3dom=L3DOM)
    by_uid = {n.uid: n for n in batch.nodes}
    first = by_uid[uid.port(DEV, "Ethernet1/1")]
    assert first.props["cdp_neighbor_serial"] == "ABC1234XYZ"
    assert first.props["cdp_neighbor_name"] == "core2.example.com"
    second = by_uid[uid.port(DEV, "port-channel1")]
    assert second.props["cdp_neighbor_name"] == "access1"
    assert "cdp_neighbor_serial" not in second.props


@pytest.mark.parametrize(
    "value, expected",
    [
        ("core2.example.com(ABC1234XYZ)", ("core2.example.com", "ABC1234XYZ")),
        ("core2(ABC1234XYZ)", ("core2", "ABC1234XYZ")),
        ("access1.mgmt.example.com", ("access1.mgmt.example.com", None)),
        ("  edge1  ", ("edge1", None)),
        ("", (None, None)),
        (None, (None, None)),
    ],
)
def test_cdp_device_id_splits_name_and_serial(value, expected):
    assert cdp_device_id(value) == expected
