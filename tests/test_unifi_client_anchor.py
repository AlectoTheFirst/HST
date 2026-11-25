"""Client addresses of two UniFi consoles that each route their own networks
never fold onto one uid.

Every console that leaves the L2 fabric undeclared shares the default fabric,
so VLAN 1 at two branches is one BridgeDomain. A branch whose own gateway
routes its networks is a NAT island: its clients anchor on the prefix's
anchor, as its gateway address does, so 192.168.1.20 at two branches is two
addresses. A console with no gateway is routed by another router, and its
clients keep the bridge-domain anchor through which they join that router's
prefix.
"""

from __future__ import annotations

import copy
from typing import Any

from tests import test_unifi as tu

from hst.collectors.unifi import UnifiCollector, normalize_unifi
from hst.reasoner.containment import containment_pairs


def _with_gateway(n: int) -> dict[str, Any]:
    raw = copy.deepcopy(tu.RAW)
    raw["devices"].append(
        {
            "type": "udm",
            "mac": f"aa:bb:cc:00:0{n}:99",
            "name": f"gw-{n}",
            "model": "UDMPRO",
            "serial": f"UDM00{n}",
        }
    )
    return raw


def _batch(raw: dict[str, Any], branch: str):
    return normalize_unifi(
        raw,
        site_code=branch,
        l3dom=f"inventory:{branch}",
        unifi_site="default",
        partition=f"{branch}:default",
    )


def _addresses(batch) -> dict[str, dict[str, Any]]:
    return {n.uid: n.props for n in batch.nodes if n.label == "IpAddress"}


def _in_prefix(batch) -> set[tuple[str, str]]:
    return {
        (r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "IN" and r.start_uid.startswith("ip:")
    }


def test_two_gateway_consoles_keep_their_routed_clients_apart():
    a, b = _batch(_with_gateway(1), "branch-a"), _batch(_with_gateway(2), "branch-b")

    shared = set(_addresses(a)) & set(_addresses(b))

    # only the clients of the vlan-only network and of a VLAN with no network,
    # which another router routes, keep the shared bridge-domain anchor
    assert shared == {"ip:bd-vlan-fab0-50:192.168.50.9", "ip:bd-vlan-fab0-7:192.168.7.9"}
    # the bridge domains stay one per VLAN id in the default fabric
    assert {n.uid for n in a.nodes if n.label == "BridgeDomain"} == {
        n.uid for n in b.nodes if n.label == "BridgeDomain"
    }


def test_a_routed_client_anchors_on_its_prefix_anchor_and_joins_its_own_prefix():
    batch = _batch(_with_gateway(1), "branch-a")
    client = _addresses(batch)["ip:vrf-dev-gw-1-default:192.168.1.20"]

    assert client["anchor"] == "vrf:dev:gw-1:default"
    joined = ("ip:vrf-dev-gw-1-default:192.168.1.20", "pfx:vrf-dev-gw-1-default:192.168.1.0/24")
    assert joined in _in_prefix(batch)


def test_a_client_with_the_gateway_address_is_the_gateway_address_node():
    """Both mint one uid under one anchor, so the run's identity check passes."""
    batch = _batch(_with_gateway(1), "branch-a")
    gateway = {r.end_uid for r in batch.rels if r.rel_type == "HAS_IP" and r.start_label == "Interface"}
    client = {r.end_uid for r in batch.rels if r.rel_type == "HAS_IP" and r.start_label == "Endpoint"}

    assert "ip:vrf-dev-gw-1-default:192.168.1.1" in gateway & client


def test_a_console_without_a_gateway_keeps_the_bridge_domain_anchor():
    batch = _batch(tu.RAW, "branch-a")
    client = _addresses(batch)["ip:bd-vlan-fab0-30:192.168.30.50"]

    assert client["anchor"] == "bd:vlan:fab0:30"


def test_containment_joins_a_routed_client_to_its_console_prefix_only():
    """Two consoles with one subnet: each client is in its own console's prefix."""
    a, b = _batch(_with_gateway(1), "branch-a"), _batch(_with_gateway(2), "branch-b")
    addresses = [
        {"uid": u, "ip": p["ip"], "l3dom": p["l3dom"], "anchor": p["anchor"]}
        for batch in (a, b)
        for u, p in _addresses(batch).items()
        if u.endswith(":192.168.1.20")
    ]
    prefixes = [
        {"uid": n.uid, "cidr": n.props["cidr"], "l3dom": n.props["l3dom"], "anchor": n.props["anchor"]}
        for batch in (a, b)
        for n in batch.nodes
        if n.label == "Prefix" and n.props.get("cidr") == "192.168.1.0/24"
    ]

    assert containment_pairs(addresses, prefixes, []) == [
        {"ip": "ip:vrf-dev-gw-1-default:192.168.1.20", "pfx": "pfx:vrf-dev-gw-1-default:192.168.1.0/24"},
        {"ip": "ip:vrf-dev-gw-2-default:192.168.1.20", "pfx": "pfx:vrf-dev-gw-2-default:192.168.1.0/24"},
    ]


def test_the_anchor_change_bumps_the_normalization_version():
    assert UnifiCollector.NORMALIZATION_VERSIONS["client-address-anchor"] == "1"
