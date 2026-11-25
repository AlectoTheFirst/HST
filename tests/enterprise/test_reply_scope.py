"""The reply model is routed like the request, not over every route."""

import importlib
import ipaddress
import os
import random

import pytest

from hst.analysis_model.network import (
    _LongestMatch,
    normalize_network,
    normalize_reply_network,
    request_devices,
)
from hst.impact.evaluate import Interface, Member, Network, RequestSet, member
from hst.policy.ir import AllOf, AnyOf, Atom, Not
from hst.simul.rib import RibInput

from .test_network_compile import _Gates, _graph, _ivals

POOL = "198.51.100.7"


def _estate(ecmp_groups=11):
    """r1 (c1, the sources) and r2 (c2, the server) joined on 192.0.2.0/24;
    r3 (c3) holds the source NAT pool behind r2; r9 (c9) is unrelated and
    has `ecmp_groups` two-way equal-cost prefixes."""
    static = [
        {"context_uid": "c1", "prefix": "203.0.113.0/24", "next_hop": "192.0.2.2"},
        {"context_uid": "c2", "prefix": "10.0.0.0/24", "next_hop": "192.0.2.1"},
        {"context_uid": "c2", "prefix": "198.51.100.0/24", "next_hop": "203.0.113.3"},
    ]
    for group in range(ecmp_groups):
        for hop in ("172.16.0.2", "172.16.0.3"):
            static.append({"context_uid": "c9", "prefix": f"10.{100 + group}.0.0/16", "next_hop": hop})
    return Network(
        RibInput(
            contexts=[
                {"uid": "c1", "device_uid": "r1", "platform": "nxos"},
                {"uid": "c2", "device_uid": "r2", "platform": "nxos"},
                {"uid": "c3", "device_uid": "r3", "platform": "nxos"},
                {"uid": "c9", "device_uid": "r9", "platform": "nxos"},
            ],
            connected=[
                {"context_uid": "c1", "prefix": "10.0.0.0/24", "interface": "lan"},
                {"context_uid": "c1", "prefix": "192.0.2.0/24", "interface": "wan"},
                {"context_uid": "c2", "prefix": "192.0.2.0/24", "interface": "wan"},
                {"context_uid": "c2", "prefix": "203.0.113.0/24", "interface": "lan"},
                {"context_uid": "c3", "prefix": "203.0.113.0/24", "interface": "wan"},
                {"context_uid": "c3", "prefix": "198.51.100.0/24", "interface": "pool"},
                {"context_uid": "c9", "prefix": "172.16.0.0/24", "interface": "lan9"},
            ],
            static=static,
        ),
        (
            Interface("r1", "if:r1:lan", "lan", "c1", ("10.0.0.0/24",), ("10.0.0.1",)),
            Interface("r1", "if:r1:wan", "wan", "c1", ("192.0.2.0/24",), ("192.0.2.1",)),
            Interface("r2", "if:r2:wan", "wan", "c2", ("192.0.2.0/24",), ("192.0.2.2",)),
            Interface("r2", "if:r2:lan", "lan", "c2", ("203.0.113.0/24",), ("203.0.113.1",)),
            Interface("r3", "if:r3:wan", "wan", "c3", ("203.0.113.0/24",), ("203.0.113.3",)),
            Interface("r3", "if:r3:pool", "pool", "c3", ("198.51.100.0/24",), ("198.51.100.1",)),
            Interface("r9", "if:r9:lan", "lan9", "c9", ("172.16.0.0/24",), ("172.16.0.1",)),
        ),
        _Gates(),
    )


def _request():
    return RequestSet(
        "web",
        _ivals("10.0.0.10"),
        "server",
        (Member("server", _ivals("203.0.113.10")),),
        member("server"),
        source_context="c1",
        success="round-trip",
    )


def _delivery(network, request):
    forward = normalize_network(network, _graph(), request, request.members[0], "estate")
    return next(node.key for node in forward.nodes if node.key.location.startswith("delivery:c2:"))


def test_equal_cost_routes_off_the_reply_path_leave_the_reply_choices_complete():
    network, request = _estate(), _request()
    reply = normalize_reply_network(
        network, _graph(), request, request.members[0], "estate", (_delivery(network, request),)
    )

    assert reply.choices_complete is True
    assert [choice.uid for choice in reply.choices] == ["routing:only"]
    assert not any(node.key.location.startswith("routing:c9:") for node in reply.nodes)
    assert any(node.key.location.startswith("routing:c1:") for node in reply.nodes)


def test_the_reply_is_routed_toward_the_translated_source_too():
    network, request = _estate(ecmp_groups=0), _request()
    delivery = _delivery(network, request)
    pool = int(ipaddress.ip_address(POOL))

    plain = normalize_reply_network(network, _graph(), request, request.members[0], "estate", (delivery,))
    translated = normalize_reply_network(
        network, _graph(), request, request.members[0], "estate", (delivery,), destinations=((4, pool, pool),)
    )

    assert not any(node.key.location.startswith("routing:c3:") for node in plain.nodes)
    assert any(node.key.location.startswith("routing:c3:") for node in translated.nodes)


def test_a_reply_context_without_a_route_toward_the_reply_has_no_route_not_an_unknown():
    network = _estate(ecmp_groups=0)
    request = RequestSet(
        "web",
        _ivals("10.0.0.10"),
        "server",
        (Member("server", _ivals("203.0.113.10")),),
        member("server"),
        source_context="c1",
        success="round-trip",
    )
    delivery = _delivery(network, request)
    # r2 loses its route back to the sources
    stripped = Network(
        RibInput(
            contexts=network.routing.contexts,
            connected=network.routing.connected,
            static=[row for row in network.routing.static if row["context_uid"] != "c2"],
        ),
        network.interfaces,
        network.gates,
    )
    reply = normalize_reply_network(stripped, _graph(), request, request.members[0], "estate", (delivery,))
    entry = next(node for node in reply.nodes if node.key == reply.entries[0].key)

    assert entry.key.location == "routing:c2:ingress:if:r2:lan"
    assert entry.terminal is None and entry.edges == () and entry.complete is True


def test_request_devices_are_the_owners_of_the_forward_and_reply_contexts():
    network = _estate()

    assert request_devices(network, _request()) == frozenset({"r1", "r2"})


def _reference(row, rows):
    """The longest-match predicate of `row` by a quadratic scan of `rows`."""
    prefix = ipaddress.ip_network(str(row["prefix"]), strict=False)
    more_specific = []
    for candidate in rows:
        if candidate is row:
            continue
        other = ipaddress.ip_network(str(candidate["prefix"]), strict=False)
        contained = int(prefix.network_address) <= int(other.network_address) and int(
            other.broadcast_address
        ) <= int(prefix.broadcast_address)
        if other.version == prefix.version and other.prefixlen > prefix.prefixlen and contained:
            more_specific.append(
                Atom("destination_address", "range", int(other.network_address), int(other.broadcast_address))
            )
    selected = Atom(
        "destination_address", "range", int(prefix.network_address), int(prefix.broadcast_address)
    )
    return AllOf((selected, Not(AnyOf(tuple(more_specific))))) if more_specific else selected


def test_the_sorted_longest_match_index_gives_the_predicates_of_the_full_scan():
    generator = random.Random(33)
    rows = []
    for _ in range(400):
        if generator.random() < 0.8:
            length = generator.randint(0, 32)
            address = ipaddress.ip_address(generator.getrandbits(32) & 0xFF00FFFF)
            prefix = ipaddress.ip_network(f"{address}/{length}", strict=False)
        else:
            length = generator.randint(0, 128)
            prefix = ipaddress.ip_network(
                f"{ipaddress.IPv6Address(generator.getrandbits(128))}/{length}", strict=False
            )
        rows.append({"context_uid": "c", "prefix": str(prefix)})
    rows.extend(dict(row) for row in rows[:40])  # equal-cost duplicates
    index = _LongestMatch(rows)

    for row in rows:
        assert index.predicate(row) == _reference(row, rows)


def test_reply_destinations_are_the_translated_source_prefixes():
    if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
        importlib.import_module("dd.cudd")
    else:
        pytest.importorskip("dd.cudd", reason="native symbolic wheel required for this test")
    from hst.analysis_model.network_session import MAX_REPLY_PREFIXES, reply_destinations
    from hst.symbolic import HeaderSchema, SymbolicManager
    from hst.symbolic.predicates import ValueRange, header

    pool = int(ipaddress.ip_address("198.51.100.0"))
    with SymbolicManager(HeaderSchema(4)) as manager:
        assert reply_destinations(manager.empty(), 4) == ()
        packets = header(manager, {"source_address": [ValueRange(pool, pool + 255)]})
        assert reply_destinations(packets, 4) == ((4, pool, pool + 255),)
        # every second address: more prefixes than the cap, one spanning range
        scattered = manager.empty()
        for offset in range(0, 2 * (MAX_REPLY_PREFIXES + 1), 2):
            scattered = scattered.union(
                header(manager, {"source_address": [ValueRange(pool + offset, pool + offset)]})
            )
        assert reply_destinations(scattered, 4) == ((4, pool, pool + 2 * MAX_REPLY_PREFIXES),)
