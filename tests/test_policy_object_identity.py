"""A policy object is identified by its enforcing scope and its configured name.

For the collector output each vendor's unit tests build, no FwRulebase,
RoutePolicy or PbrPolicy carries an interface name of its device in its uid or
its name, and each one has an edge to what enforces it. The exceptions are
exact:

- a rulebase a zone pair binds (FROM_ZONE/TO_ZONE: a VyOS zone policy, a UniFi
  zone-pair rulebase) or a rule jumps to (JUMPS_TO) acts where that binding is,
  not device-wide, so it has no ENFORCES;
- a RoutePolicy carries its device in its uid (`rtpol:<device uid>:...`) and is
  linked to what applies it by FILTERED_BY or REFERENCES; one that nothing
  applies has no edge at all;
- an APIC PbrPolicy (vnsSvcRedirectPol) is linked to nothing that enforces it,
  because the service graph device selection that names it is not collected.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable
from typing import Any

import pytest
from tests import test_apic, test_checkpoint, test_iosxe, test_iosxr, test_nxos, test_unifi, test_vyos

from hst.core.model import Batch
from hst.core.normalize import iface_slug

POLICY_LABELS = ("FwRulebase", "RoutePolicy", "PbrPolicy")

BATCHES: dict[str, Callable[[], Batch]] = {
    "iosxe": lambda: test_iosxe._collector().normalize(test_iosxe.ACL_RAW),
    "nxos": lambda: test_nxos._collector().normalize(test_nxos.ACL_RAW),
    "iosxr": lambda: test_iosxr._collector().normalize(test_iosxr.RAW),
    "vyos": test_vyos._batch,
    "unifi-zone": lambda: test_unifi._gw_batch(
        firewall_zones=test_unifi.ZONES, firewall_policies=test_unifi.POLICIES
    ),
    "unifi-classic": lambda: test_unifi._gw_batch(
        firewall_rules=test_unifi.CLASSIC_RULES, firewall_groups=test_unifi.GROUPS
    ),
    "checkpoint": test_checkpoint._norm_cp,
    "apic": test_apic._norm,
}


def _policies(batch: Batch) -> list[Any]:
    return [n for n in batch.nodes if n.label in POLICY_LABELS]


def _tokens(text: str) -> set[str]:
    """The `:` and space separated segments of `text`, and their `/` separated
    parts: an interface name keeps its slashes, a DN is cut at them."""
    whole = {t for t in re.split(r"[:\s]+", text) if t}
    return whole | {p for t in whole for p in t.split("/") if p}


@pytest.mark.parametrize("vendor", sorted(BATCHES))
def test_every_vendor_fixture_carries_policy_objects(vendor):
    assert _policies(BATCHES[vendor]())


@pytest.mark.parametrize("vendor", sorted(BATCHES))
def test_no_policy_uid_or_name_embeds_an_interface_of_its_device(vendor):
    """Each uid and name is cut into its segments (`_tokens`),
    and none of them is the name of an interface of the batch or its uid slug.
    The segments of the batch scope and of the device uids are left out: they
    are the enforcing scope, and a UniFi site and a UniFi network can share a
    word."""
    batch = BATCHES[vendor]()
    names = {n.props["name"] for n in batch.nodes if n.label == "Interface" and n.props.get("name")}
    forbidden = names | {iface_slug(name) for name in names}
    scope = _tokens(batch.scope) | {t for n in batch.nodes if n.label == "Device" for t in _tokens(n.uid)}
    for node in _policies(batch):
        for text in (node.uid, str(node.props.get("name") or "")):
            hit = (_tokens(text) - scope) & forbidden
            assert not hit, f"{vendor}: {node.label} {text!r} names interface {sorted(hit)}"


def _exception(
    node: Any, incoming: dict[str, set[str]], outgoing: dict[str, set[str]], devices: set[str]
) -> bool:
    if node.label == "FwRulebase":
        return bool(outgoing[node.uid] & {"FROM_ZONE", "TO_ZONE"} or "JUMPS_TO" in incoming[node.uid])
    if node.label == "RoutePolicy":
        return any(node.uid.startswith(f"rtpol:{dev}:") for dev in devices)
    return node.label == "PbrPolicy" and node.uid.startswith("aci:")


@pytest.mark.parametrize("vendor", sorted(BATCHES))
def test_every_policy_has_an_edge_to_what_enforces_it(vendor):
    batch = BATCHES[vendor]()
    incoming: dict[str, set[str]] = defaultdict(set)
    outgoing: dict[str, set[str]] = defaultdict(set)
    enforcers: dict[str, set[str]] = defaultdict(set)
    for rel in batch.rels:
        incoming[rel.end_uid].add(rel.rel_type)
        outgoing[rel.start_uid].add(rel.rel_type)
        if rel.rel_type == "ENFORCES":
            enforcers[rel.end_uid].add(rel.start_label)
    devices = {n.uid for n in batch.nodes if n.label == "Device"}
    for node in _policies(batch):
        if _exception(node, incoming, outgoing, devices):
            continue
        assert enforcers[node.uid] - {"Interface"}, (
            f"{vendor}: {node.label} {node.uid!r} has no ENFORCES edge from its enforcing scope"
        )


def test_an_interface_bound_policy_has_an_edge_from_each_interface_with_its_direction():
    """The interface-bound policies of the fixtures: a Cisco interface ACL by
    PROTECTED_BY with a direction, a VyOS policy route by ENFORCES from the
    interfaces it is applied to (the ingress direction is implied)."""
    for vendor in ("iosxe", "nxos"):
        batch = BATCHES[vendor]()
        bound = [r for r in batch.rels if r.rel_type == "PROTECTED_BY"]
        assert bound
        assert all(r.start_label == "Interface" and r.props["direction"] in ("in", "out") for r in bound)
    vyos = BATCHES["vyos"]()
    pbr = {n.uid for n in vyos.nodes if n.label == "PbrPolicy"}
    assert pbr
    assert {r.end_uid for r in vyos.rels if r.rel_type == "ENFORCES" and r.start_label == "Interface"} == pbr
