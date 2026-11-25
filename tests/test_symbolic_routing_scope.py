"""A routing state of the symbolic model is incomplete only for a gap that can change
the route of a destination the model routes (`normalize_network`, `Network.incomplete`)."""

from __future__ import annotations

from dataclasses import replace

import pytest
from tests.enterprise import test_network_compile as nc

from hst.analysis_model.network import normalize_network
from hst.impact.evaluate import Member, RequestSet, member
from hst.simul import rib


def _row(prefix, next_hop, af):
    return {
        "prefix": prefix,
        "next_hop": next_hop,
        "interface": "wan",
        "protocol": "kernel",
        "metric": None,
        "prefixlen": int(prefix.split("/")[1]),
        "af": af,
    }


def network(extra=(), coverage="complete", drop=None, afs=None):
    """`nc._network` with an observed RIB that is the computed one, less the rows
    of `drop`, plus the rows `extra` of c1, read completely unless `coverage` says
    otherwise; `afs` the families the observations cover."""
    base = nc._network()
    observed: dict[str, list[dict]] = {}
    for row in rib.compute(base.routing).rib:
        if row["prefix"] != drop:
            observed.setdefault(str(row["context_uid"]), []).append(dict(row))
    observed["c1"].extend(extra)
    contexts = [
        {**context, **({"observed_rib_afs": afs} if afs is not None else {})}
        for context in base.routing.contexts
    ]
    routing = replace(
        base.routing,
        contexts=contexts,
        observed_rib=observed,
        rib_coverage=dict.fromkeys(("c1", "c2"), coverage),
    )
    return replace(base, routing=routing)


REQUEST = RequestSet(
    "web",
    nc._ivals("10.0.0.10"),
    "server",
    (Member("server", nc._ivals("203.0.113.10")),),
    member("server"),
    source_context="c1",
)


def _complete(net, **kwargs):
    model = normalize_network(net, nc._graph(), REQUEST, REQUEST.members[0], "estate", **kwargs)
    return {
        node.key.location: node.complete
        for node in model.nodes
        if node.key.location.startswith("routing:c1:")
    }


@pytest.mark.parametrize(
    "extra",
    [
        _row("::/0", "fe80::1", 6),
        _row("198.51.100.0/24", "192.0.2.9", 4),
        _row("0.0.0.0/0", "192.0.2.9", 4),
    ],
    ids=["ipv6-kernel-default", "ipv4-other-prefix", "ipv4-default-a-longer-route-wins"],
)
def test_a_gap_that_cannot_change_the_flows_route_leaves_the_routing_state_complete(extra):
    net = network(extra=[extra])
    # the context does hold the gap
    assert net.incomplete("c1")
    assert _complete(net) == {"routing:c1:ingress:none": True, "routing:c1:ingress:if:r1:lan": True}


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"extra": [_row("203.0.113.0/25", "192.0.2.9", 4)]}, "203.0.113.0/25"),
        ({"drop": "203.0.113.0/24"}, "203.0.113.0/24"),
        ({"coverage": "partial"}, "coverage for c1 is partial"),
        ({"afs": [6]}, "do not cover the requested address family"),
    ],
    ids=[
        "more-specific-route-uncalibrated",
        "flows-route-not-held",
        "table-read-partial",
        "family-not-observed",
    ],
)
def test_a_gap_that_can_change_the_flows_route_keeps_the_routing_state_incomplete(kwargs, reason):
    net = network(**kwargs)
    assert _complete(net) == {"routing:c1:ingress:none": False, "routing:c1:ingress:if:r1:lan": False}
    (detail,) = net.incomplete("c1", ((4, *nc._ivals("203.0.113.10")[0][1:]),))
    assert reason in detail


def test_a_model_of_every_route_counts_every_gap():
    net = network(extra=[_row("::/0", "fe80::1", 6)])
    assert set(_complete(net, _all_routes=True).values()) == {False}


def test_a_gap_on_the_route_toward_a_linked_tunnels_far_end_still_counts(monkeypatch):
    """A tunnel the model links to its far end (`_tunnel_targets`) is carried by
    the route toward that end, which no routing state asks for: a gap on that
    route counts as one on the flow's own."""
    from types import MappingProxyType

    from hst.analysis_model import network as netmod
    from hst.analysis_model.graph import GraphNode, GraphRelation

    nodes = {
        "t1": GraphNode("t1", frozenset({"Tunnel"}), MappingProxyType({})),
        "far": GraphNode("far", frozenset({"IpAddress"}), MappingProxyType({"ip": "198.51.100.2"})),
    }
    graph = nc._rebuild(
        nc._graph(), nodes, [GraphRelation("f1", "TERMINATES_ON", "t1", "far", MappingProxyType({}))]
    )
    gap = network(extra=[_row("198.51.100.0/24", "192.0.2.9", 4)])

    def complete(linked):
        monkeypatch.setattr(netmod, "_tunnel_targets", lambda *_a, **_k: dict.fromkeys(linked, None))
        model = normalize_network(gap, graph, REQUEST, REQUEST.members[0], "estate")
        return {node.complete for node in model.nodes if node.key.location.startswith("routing:c1:")}

    assert complete(()) == {True}
    assert complete(("t1",)) == {False}


def _oslo_mirrored():
    """The Oslo router (tests/test_symbolic_masquerade.py) with its configured
    static 192.0.2.0/25 via 10.18.99.1, which FRR does not install, and a
    complete mirrored RIB that holds what the device holds: no 192.0.2.0/25, and
    an IPv6 kernel default by a link-local next hop no collector models."""
    from tests.test_symbolic_masquerade import MAIN, _estate, oslo_network

    net = oslo_network(_estate(1))
    routing = net.routing
    routing.static.append({"context_uid": MAIN, "prefix": "192.0.2.0/25", "next_hop": "10.18.99.1"})
    observed: dict[str, list[dict]] = {}
    for row in rib.compute(routing).rib:
        if row["prefix"] != "192.0.2.0/25":
            observed.setdefault(str(row["context_uid"]), []).append(dict(row))
    observed[MAIN].append({**_row("::/0", "fe80::1", 6), "interface": "eth0"})
    routing = replace(
        routing,
        contexts=[{**context, "observed_rib_afs": [4, 6]} for context in routing.contexts],
        observed_rib=observed,
        rib_coverage=dict.fromkeys(observed, "complete"),
    )
    return replace(net, routing=routing)


@pytest.mark.parametrize(("destination", "complete"), [("192.0.2.180", True), ("192.0.2.10", False)])
def test_on_the_oslo_router_only_the_flow_the_uninstalled_route_covers_stays_incomplete(
    destination, complete
):
    from tests.test_symbolic_masquerade import MAIN, _estate, _inventory, oslo_request

    net = _oslo_mirrored()
    assert len(net.incomplete(MAIN)) == 2
    request = oslo_request(destination=destination)
    model = normalize_network(net, _inventory(_estate(1)), request, request.members[0], "estate")
    states = {node.complete for node in model.nodes if node.key.location.startswith(f"routing:{MAIN}:")}
    assert states == {complete}
