"""The symbolic model reads a VyOS service port as the point tracer does."""

from __future__ import annotations

from typing import Any

import pytest

from hst.analysis_model.graph import GraphInventory
from hst.analysis_model.read import MaterializedTable
from hst.collectors.vyos import normalize_vyos
from hst.path.addrsets import _MATCH, _NO_MATCH, _UNKNOWN, _port_matches, _ports
from hst.policy.graph import GraphPolicyNormalizer
from hst.policy.ir import AllOf, AnyOf, Atom, ExecutionContext, Predicate, Unknown

VERSION = "Version:          VyOS 1.4.0\nHardware S/N:     0000"


def _inventory(batch) -> GraphInventory:
    nodes = {n.uid: {"id": n.uid, "labels": [n.label], "props": dict(n.props)} for n in batch.nodes}
    rels = [
        {
            "id": f"rel:{i}",
            "kind": r.rel_type,
            "start": r.start_uid,
            "end": r.end_uid,
            "props": {**r.key, **r.props},
        }
        for i, r in enumerate(batch.rels)
    ]
    return GraphInventory.from_tables(
        MaterializedTable("a" * 64, "nodes", tuple(nodes.values()), len(nodes), True, "b" * 64),
        MaterializedTable("a" * 64, "relationships", tuple(rels), len(rels), True, "c" * 64),
    )


def _batch(rules: dict[str, Any], groups: dict[str, Any] | None = None):
    fw: dict[str, Any] = {"ipv4": {"forward": {"filter": {"default-action": "drop", "rule": rules}}}}
    if groups:
        fw["group"] = groups
    cfg = {
        "system": {"host-name": "gw"},
        "interfaces": {"ethernet": {"eth0": {"address": ["203.0.113.2/30"]}}},
        "firewall": fw,
    }
    return normalize_vyos({"config": cfg, "version_text": VERSION, "links": []}, l3dom="dc1")


_RULES: dict[str, Any] = {
    "10": {"action": "accept", "protocol": "tcp", "destination": {"port": "443"}},
    "20": {"action": "accept", "protocol": "tcp", "destination": {"port": "1000-2000"}},
    "30": {"action": "accept", "protocol": "tcp_udp", "destination": {"port": "52217,53220,55265-55274"}},
    "40": {"action": "accept", "protocol": "tcp", "destination": {"port": "http"}},
    "50": {"action": "accept", "protocol": "tcp_udp", "destination": {"port": "53"}},
    "60": {"action": "accept", "protocol": "udp", "destination": {"group": {"port-group": "P"}}},
    "70": {"action": "accept", "protocol": "udp", "source": {"port": "67"}, "destination": {"port": "68"}},
}
_GROUPS = {"port-group": {"P": {"port": ["1900", "5353"]}}}

# rule -> (protocols, destination port ranges)
_EXPECTED: dict[str, tuple[set[int], set[tuple[int, int]]]] = {
    "10": ({6}, {(443, 443)}),
    "20": ({6}, {(1000, 2000)}),
    "30": ({6, 17}, {(52217, 52217), (53220, 53220), (55265, 55274)}),
    "40": ({6}, {(80, 80)}),
    "50": ({6, 17}, {(53, 53)}),
    "60": ({17}, {(1900, 1900), (5353, 5353)}),
    "70": ({17}, {(68, 68)}),
}


def _unknowns(predicate: Predicate) -> list[Unknown]:
    if isinstance(predicate, Unknown):
        return [predicate]
    if isinstance(predicate, (AllOf, AnyOf)):
        return [u for term in predicate.terms for u in _unknowns(term)]
    return []


def _atoms(predicate: Predicate, field: str) -> set[tuple[int, int]]:
    if isinstance(predicate, Atom):
        if predicate.field != field:
            return set()
        return {(predicate.value, predicate.other if predicate.other is not None else predicate.value)}
    if isinstance(predicate, (AllOf, AnyOf)):
        return {a for term in predicate.terms for a in _atoms(term, field)}
    return set()


def _services(batch) -> tuple[GraphInventory, dict[str, str]]:
    inventory = _inventory(batch)
    by_rule = {
        relation.start.rsplit(":", 1)[-1]: relation.end
        for (start, kind), relations in inventory.outgoing.items()
        if kind == "SVC"
        for relation in relations
    }
    return inventory, by_rule


def test_the_inventory_freezes_the_collected_port_list():
    inventory, services = _services(_batch(_RULES, _GROUPS))
    ports = inventory.nodes[services["30"]].props["ports"]
    assert isinstance(ports, tuple)
    assert ports == ("52217", "53220", "55265-55274")


@pytest.mark.parametrize("rule", sorted(_EXPECTED))
def test_a_vyos_service_object_reads_its_ports_and_protocol(rule):
    inventory, services = _services(_batch(_RULES, _GROUPS))
    normalizer = GraphPolicyNormalizer(
        inventory, ExecutionContext("estate", "authority", "domain", "gw", "vrf", 4)
    )
    predicate = normalizer._object(services[rule], "service")
    assert _unknowns(predicate) == []
    protocols, ports = _EXPECTED[rule]
    assert {low for low, _ in _atoms(predicate, "protocol")} == protocols
    assert _atoms(predicate, "destination_port") == ports


def test_the_source_port_of_a_vyos_service_reads_as_a_range():
    inventory, services = _services(_batch(_RULES, _GROUPS))
    normalizer = GraphPolicyNormalizer(
        inventory, ExecutionContext("estate", "authority", "domain", "gw", "vrf", 4)
    )
    assert _atoms(normalizer._object(services["70"], "service"), "source_port") == {(67, 67)}


def test_an_unreadable_port_stays_unknown():
    # a negated port the collector keeps verbatim and marks opaque
    batch = _batch({"10": {"action": "accept", "protocol": "tcp", "destination": {"port": "!80"}}})
    inventory, services = _services(batch)
    normalizer = GraphPolicyNormalizer(
        inventory, ExecutionContext("estate", "authority", "domain", "gw", "vrf", 4)
    )
    codes = {u.code for u in _unknowns(normalizer._object(services["10"], "service"))}
    assert "GRAPH_SERVICE_PORT_UNKNOWN" in codes


@pytest.mark.parametrize(
    "spec",
    [["443"], ["80", "443"], ["1000-2000"], ["52217", "53220", "55265-55274"], ["abc"], ["2000-1000"], []],
)
def test_a_tuple_port_spec_reads_as_the_list_the_tracer_passes(spec):
    try:
        expected: Any = _ports(spec)
    except ValueError as error:
        expected = type(error)
    try:
        actual: Any = _ports(tuple(spec))
    except ValueError as error:
        actual = type(error)
    assert actual == expected
    for port in (None, 0, 80, 443, 1500, 53220, 55270, 65535):
        assert _port_matches(tuple(spec), port) == _port_matches(spec, port)


def test_the_tracer_port_answers_do_not_change():
    assert _ports(["443"]) == [(0, 443, 443)]
    assert _ports("80,443") == [(0, 80, 80), (0, 443, 443)]
    assert _port_matches(["1000-2000"], 1500) == _MATCH
    assert _port_matches(["1000-2000"], 999) == _NO_MATCH
    assert _port_matches(["http"], 80) == _UNKNOWN
    with pytest.raises(ValueError):
        _ports(["abc"])


def test_a_frozen_member_with_no_port_is_not_decided_and_a_list_member_is_skipped():
    for spec in (("",), (" ",), (",",), ("", "81")):
        assert _port_matches(spec, 80) == _UNKNOWN, spec
    assert _port_matches(("", "80"), 80) == _MATCH
    assert _port_matches([""], 80) == _NO_MATCH
    assert _port_matches(["", "81"], 80) == _NO_MATCH
    assert _port_matches(["", "80"], 80) == _MATCH
    with pytest.raises(ValueError):
        _ports(("",))
