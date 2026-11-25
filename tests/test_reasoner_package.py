"""The reasoner package keeps the names that production code and tests read
from `hst.reasoner`."""

from __future__ import annotations

import importlib

import pytest

from hst import reasoner

# name -> the module of the package that defines it
USED_NAMES = {
    "ACTIVE_CIRCUIT_STATES": "_constants",
    "CLEAR": "_constants",
    "CLEAR_PROPS": "_constants",
    "ENDED_CIRCUIT_STATES": "_constants",
    "GATEWAY_ROLES": "_constants",
    "STATED_CABLE_SOURCES": "_constants",
    "RULES": "catalog",
    "FETCH_DEVICE_PORTS": "stated_cables",
    "FETCH_MAC_OWNERS": "stated_cables",
    "FETCH_STATED_CABLE_PORTS": "stated_cables",
    "STATED_CABLE_WRITE": "stated_cables",
    "_canonical_mac_or_none": "stated_cables",
    "resolve_stated_cables": "stated_cables",
    "FABRIC_PORT_ISSUE_WRITE": "fabric_ports",
    "FABRIC_PORT_RULE": "fabric_ports",
    "_fabric_port_matcher": "fabric_ports",
    "fabric_port_issues": "fabric_ports",
    "fabric_port_warnings": "fabric_ports",
    "resolve_fabric_port_bindings": "fabric_ports",
    "EDGE_DEVICE_RULE": "edge_devices",
    "EDGE_ON_WRITE": "edge_devices",
    "EDGE_REALIZED_WRITE": "edge_devices",
    "EDGE_SAME_AS_WRITE": "edge_devices",
    "FETCH_EDGE_BINDINGS": "edge_devices",
    "FETCH_EDGE_BINDINGS_REFUSED": "edge_devices",
    "FETCH_EDGE_CANDIDATES": "edge_devices",
    "FETCH_EDGE_DEVICES": "edge_devices",
    "FETCH_EDGE_INTERFACES": "edge_devices",
    "_run_edge_device_rule": "edge_devices",
    "check_edge_devices": "edge_devices",
    "edge_device_candidates": "edge_devices",
    "resolve_edge_device_bindings": "edge_devices",
    "FETCH_SHARED_ZSCALER_SCOPES": "zscaler",
    "FETCH_ZIA_ONLY_SITES": "zscaler",
    "FETCH_ZSCALER_ADDRESSES": "zscaler",
    "GLOBAL_ADDRESS_CONFIDENCE": "zscaler",
    "PRIVATE_ADDRESS_CONFIDENCE": "zscaler",
    "ZPA_ZIA_SAME_AS_RULE": "zscaler",
    "check_zscaler": "zscaler",
    "resolve_zpa_zia_ip_links": "zscaler",
    "CONTAINMENT_ADDRESSES": "containment",
    "CONTAINMENT_BD_MAP": "containment",
    "CONTAINMENT_PREFIXES": "containment",
    "CONTAINMENT_WRITE": "containment",
    "containment_pairs": "containment",
    "FETCH_BOUND_CIRCUITS": "vlan_stretch",
    "MacIndex": "vlan_stretch",
    "ONE_SIDED": "vlan_stretch",
    "PORT_BASED": "vlan_stretch",
    "STRETCHED": "vlan_stretch",
    "TRANSLATED": "vlan_stretch",
    "check_vlan_stretch": "vlan_stretch",
    "mac_rows_query": "vlan_stretch",
    "observed_mac_count": "vlan_stretch",
    "read_mac_rows": "vlan_stretch",
    "stretch_observations": "vlan_stretch",
    "stretch_warnings": "vlan_stretch",
    "FETCH_RUN_DEVICES": "arp_cables",
    "FETCH_SDWAN_ADDRESSES": "arp_cables",
    "derive_arp_cables": "arp_cables",
    "resolve_arp_cables": "arp_cables",
    "FETCH_DEVICE_ROLES": "device_roles",
    "SET_DEVICE_ROLES": "device_roles",
    "apply_device_roles": "device_roles",
    "run": "runner",
}


@pytest.mark.parametrize("name", sorted(USED_NAMES))
def test_the_package_exposes_the_name(name: str) -> None:
    module = importlib.import_module(f"hst.reasoner.{USED_NAMES[name]}")
    assert getattr(reasoner, name) is getattr(module, name)


def test_every_exposed_name_is_listed() -> None:
    assert set(reasoner.__all__) == set(USED_NAMES)
