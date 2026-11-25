"""A BGP peer whose routes are not collected, on a router whose collected routing table is
complete (`Network.incomplete`, `rib._Run.observed_seeds`).

core1 has three eBGP sessions to Kubernetes nodes that are no collected devices, and the
router answers "No such neighbor or address family" to every per-neighbor route command.
Each session leaves a gap "what the peer supplies is not observed".

The router's own collected table is the evidence for the present state: what a peer sent
and the router installed is in it. With that table complete for the flow's family and
nothing in the request that can alter the routing of the context, such a gap does not hold
a flow back by itself. The per-prefix calibration decides: a prefix the collected
table has and the computed one lacks (the routes learned from the peer, while their paths
are not captured) stays not decided for that prefix only, and is never answered by the
default route. A table that is not complete, a family it does not cover, a change of the
routing, a failure scenario and a network with no collected table block the flow.

The router is the Oslo office of the demo estate (tests/test_symbolic_masquerade.py) with
three sessions of core1's shape. Everything here runs without the native backend; the walk
is in tests/enterprise/test_native_bgp_peer_supply.py.
"""

from __future__ import annotations

import importlib
import ipaddress
from dataclasses import replace

import pytest
from tests.enterprise import test_network_compile as nc
from tests.test_demo_enterprise_vyos import DEV, MAIN, _estate
from tests.test_impact_evaluate import graph  # noqa: F401 - the fixture the impact evaluator reads
from tests.test_symbolic_masquerade import oslo_network, oslo_request
from tests.test_symbolic_vyos_service_ports import _inventory

from hst.analysis_model.network import normalize_network
from hst.impact.evaluate import Network
from hst.results.words import FORBIDDEN_WORDS, _contains_word
from hst.simul import certainty, rib
from hst.simul.propagate import SimulationInput

ev = importlib.import_module("hst.impact.evaluate")

PROCESS = f"bgp:{DEV}:default"
PEERS = ("10.18.20.30", "10.18.20.35", "10.18.20.36")
SESSIONS = tuple(f"{PROCESS}~{peer}:default" for peer in PEERS)
# the prefixes the router learned from the peers, as its collected table has them
LEARNED = {"10.96.0.0/12": PEERS[0], "10.244.0.0/16": PEERS[1]}
INTERNET, INSIDE_LEARNED = "192.0.2.180", "10.96.0.10"
# the start of the reason a peer whose routes are not collected gives
PEER_TEXT = "BGP peer 10.18.20.3"
# The cases capture no direction, the accepted one and the received one.
CASES = ("none", "accepted", "received")


def _ivals(text: str) -> tuple[tuple[int, int, int], ...]:
    return nc._ivals(text)


def _rib_row(prefix: str, next_hop: str) -> dict:
    return {
        "prefix": prefix,
        "next_hop": next_hop,
        "next_hop_context_uid": None,
        "interface": "eth1.20",
        "protocol": "bgp",
        "discard": None,
        "metric": 0,
        "prefixlen": ipaddress.ip_network(prefix).prefixlen,
        "af": 4,
    }


def _path(session: str, prefix: str, next_hop: str, direction: str) -> dict:
    return {
        "device_uid": DEV,
        "context_uid": MAIN,
        "session_uid": session,
        "peer_ip": next_hop,
        "af": 4,
        "safi": "unicast",
        "direction": direction,
        "prefix": prefix,
        "prefixlen": ipaddress.ip_network(prefix).prefixlen,
        "next_hop": next_hop,
        "next_hop_context_uid": None,
        "as_path": "64513",
        "local_pref": 100,
        "med": None,
        "origin": "igp",
        "communities": None,
        "path_id": None,
        "best": None,
    }


def core1(
    case: str = "none",
    *,
    coverage: str | None = "complete",
    afs: list[int] | None = (4,),  # type: ignore[assignment]
    platform: str = "vyos-datacenter",
    base: Network | None = None,
) -> Network:
    """The router with three eBGP sessions to peers that are no collected devices, and
    a collected table that has its connected and static routes and the two learned
    prefixes. `case` is what the collection captured of the peers' routes; `coverage`
    the recorded outcome of the table read (None: no table at all); `afs` the families
    the table covers (None: the read does not say)."""
    net = base if base is not None else oslo_network(_estate(1))
    routing = net.routing
    context_platform = routing.contexts[0].get("platform") or platform
    observed: dict[str, list[dict]] = {}
    for row in rib.compute(routing).rib:
        observed.setdefault(str(row["context_uid"]), []).append(dict(row))
    context = str(routing.contexts[0]["uid"])
    observed[context].extend(_rib_row(prefix, hop) for prefix, hop in LEARNED.items())
    local = _local_address(net, context)
    sessions = [
        {
            "uid": uid,
            "process_uid": PROCESS,
            "local_asn": 64512,
            "peer_asn": 64513,
            "local_ip": local,
            "peer_ip": peer,
        }
        for uid, peer in zip(SESSIONS, PEERS, strict=True)
    ]
    bgp = SimulationInput(
        processes=[
            {
                "uid": PROCESS,
                "context_uid": context,
                "proto": "bgp",
                "asn": 64512,
                "router_id": local,
                "platform": platform if context_platform == "vyos" else context_platform,
            }
        ],
        sessions=sessions,
        platform=platform if context_platform == "vyos" else context_platform,
    )
    status: dict[tuple[str, str], str | None] = {
        (uid, direction): "not-captured"
        for uid in SESSIONS
        for direction in ("received", "accepted", "advertised")
    }
    paths: list[dict] = []
    if case != "none":
        for uid in SESSIONS:
            status[uid, case] = "complete"
        for prefix, hop in LEARNED.items():
            paths.append({**_path(SESSIONS[PEERS.index(hop)], prefix, hop, case), "context_uid": context})
    contexts = [
        {**c, **({"observed_rib_afs": list(afs)} if afs is not None else {"observed_rib_afs": None})}
        for c in routing.contexts
    ]
    changed = replace(
        routing,
        bgp=bgp,
        observed_paths=paths,
        direction_status=status,
        contexts=contexts,
        observed_rib=observed if coverage is not None else {},
        rib_coverage=dict.fromkeys(observed, coverage) if coverage is not None else {},
    )
    return replace(net, routing=changed)


def _local_address(net: Network, context: str) -> str:
    for interface in net.interfaces:
        if interface.context_uid == context and interface.name in ("eth1.20", "wan"):
            return interface.addresses[0]
    return "10.18.20.1"


def _reasons(net: Network, destination: str, context: str = MAIN) -> tuple[str, ...]:
    return net.incomplete(context, _ivals(destination))


def _states(net: Network, destination: str) -> list:
    request = oslo_request(destination=destination)
    model = normalize_network(net, _inventory(_estate(1)), request, request.members[0], "estate")
    return [node for node in model.nodes if node.key.location.startswith(f"routing:{MAIN}:")]


def _vocabulary(text: str) -> None:
    assert not [word for word in FORBIDDEN_WORDS if _contains_word(text.lower(), word)], text


# --- the gap is made with its cause ---------------------------------------------------------


@pytest.mark.parametrize("case", ["none", "accepted"])
def test_the_gap_of_a_peer_whose_routes_are_not_collected_names_its_cause(case):
    gaps = [g for g in core1(case).routes.gaps if g.get("session_uid") in SESSIONS]
    assert sorted(g["session_uid"] for g in gaps) == sorted(SESSIONS)
    assert {g["kind"] for g in gaps} == {rib.NOT_OBSERVED}
    assert {g["cause"] for g in gaps} == {certainty.PEER_SUPPLY}
    for gap in gaps:
        _vocabulary(gap["detail"])
        assert gap["detail"].startswith("BGP peer 10.18.20.3")
        assert f" on {DEV}: " in gap["detail"]
        assert "VRF" not in gap["detail"]


def test_with_the_received_routes_collected_there_is_no_gap():
    assert not [g for g in core1("received").routes.gaps if g.get("session_uid") in SESSIONS]


# --- 5. the calibration flags a collected route the computed table lacks, by its prefix -----


def test_a_learned_prefix_the_computed_table_lacks_is_flagged_for_its_own_prefix():
    net = core1("none")
    unverified = {str(item["prefix"]): item for item, _prefix in net._calibration.unverified.get(MAIN, ())}
    assert set(unverified) == set(LEARNED)
    for item in unverified.values():
        assert item["status"] == rib.NOT_OBSERVED
        _vocabulary(item["detail"])
    # nothing else of the context is unverified: the default route agrees
    assert {str(p) for p in net._calibration.validated[MAIN]} >= {"0.0.0.0/0", "10.18.10.0/24"}


@pytest.mark.parametrize("case", ["accepted", "received"])
def test_with_the_peers_routes_collected_the_learned_prefixes_agree(case):
    net = core1(case)
    assert not net._calibration.unverified.get(MAIN)
    assert {"10.96.0.0/12", "10.244.0.0/16"} <= {str(p) for p in net._calibration.validated[MAIN]}


def test_an_accepted_route_the_collected_table_lacks_is_flagged_for_its_own_prefix():
    """Case (b) with a learned prefix the accepted paths do not have: the computed table
    lacks it, and with the BGP input not marked incomplete it is a mismatch."""
    net = core1("accepted")
    routing = replace(
        net.routing,
        observed_paths=[p for p in net.routing.observed_paths if p["prefix"] != "10.244.0.0/16"],
    )
    net = replace(net, routing=routing)
    (item,) = (item for item, _p in net._calibration.unverified[MAIN])
    assert (item["prefix"], item["status"]) == ("10.244.0.0/16", rib.MISMATCH)
    assert _reasons(net, INTERNET) == ()
    (reason,) = _reasons(net, "10.244.1.1")
    assert "10.244.0.0/16" in reason


# --- 1. a flow to the internet ----------------------------------------------------------------


@pytest.mark.parametrize("case", CASES)
def test_a_flow_to_the_internet_is_decided(case):
    net = core1(case)
    assert _reasons(net, INTERNET) == ()
    states = _states(net, INTERNET)
    assert states and all(node.complete and not node.incomplete_reasons for node in states)


# --- 2. a flow into a learned prefix ------------------------------------------------------------


def test_with_no_path_collected_a_flow_into_a_learned_prefix_is_not_decided_and_names_it():
    net = core1("none")
    (reason,) = _reasons(net, INSIDE_LEARNED)
    assert "10.96.0.0/12" in reason and "bgp" in reason
    _vocabulary(reason)
    states = _states(net, INSIDE_LEARNED)
    assert states and not any(node.complete for node in states)
    for node in states:
        assert any("10.96.0.0/12" in text for text in node.incomplete_reasons)
    # the other learned prefix is not this flow's
    assert not any("10.244.0.0/16" in text for node in states for text in node.incomplete_reasons)


@pytest.mark.parametrize("case", ["accepted", "received"])
def test_with_the_peers_routes_collected_a_flow_into_a_learned_prefix_is_decided(case):
    """The computed table then has the learned route and it agrees with the collected one;
    the route of the flow is the BGP route, not the default route."""
    net = core1(case)
    assert _reasons(net, INSIDE_LEARNED) == ()
    (row,) = (r for r in net.routes.rib if r["context_uid"] == MAIN and r["prefix"] == "10.96.0.0/12")
    assert (row["protocol"], row["next_hop"]) == ("bgp", PEERS[0])
    assert all(node.complete for node in _states(net, INSIDE_LEARNED))


# --- 3. the collected table is not complete, or does not cover the family -----------------------


@pytest.mark.parametrize(
    "kwargs",
    [{"coverage": "partial"}, {"coverage": "failed"}, {"afs": [6]}, {"afs": None}, {"coverage": None}],
    ids=["partial", "failed", "family-not-covered", "families-not-recorded", "no-table"],
)
@pytest.mark.parametrize("case", ["none", "accepted"])
def test_without_a_complete_table_for_the_family_every_flow_stays_not_decided(case, kwargs):
    net = core1(case, **kwargs)
    for destination in (INTERNET, INSIDE_LEARNED):
        reasons = _reasons(net, destination)
        assert any(PEER_TEXT in text for text in reasons), reasons
        assert not any(node.complete for node in _states(net, destination))


def test_a_table_with_no_family_record_keeps_the_peer_gap():
    """The peer's gap blocks a context row with no `observed_rib_afs` key."""
    net = core1("none")
    contexts = [{k: v for k, v in c.items() if k != "observed_rib_afs"} for c in net.routing.contexts]
    net = replace(net, routing=replace(net.routing, contexts=contexts))
    assert any(PEER_TEXT in text for text in _reasons(net, INTERNET))


# --- 4. a request that can alter the routing of the context ------------------------------------


def _shut(net: Network) -> Network:
    from hst.simul.fw_overlay import ChangeSet, Intent

    return ev.apply(net, ChangeSet([Intent(rib.INTENT_BGP_SESSION_SHUT, {"session": SESSIONS[2]})]))


@pytest.mark.parametrize("case", ["none", "accepted"])
def test_a_change_of_a_session_keeps_the_context_not_decided(case):
    after = _shut(core1(case))
    assert MAIN in after.routing.superseded_contexts
    assert after.incomplete(MAIN, _ivals(INTERNET))
    assert not any(node.complete for node in _states(after, INTERNET))


def test_a_derived_network_whose_routing_input_differs_keeps_the_context_not_decided():
    net = core1("none")
    routing = replace(net.routing, static=[*net.routing.static])
    routing.static.append({"context_uid": MAIN, "prefix": "198.51.100.0/24", "next_hop": "203.0.113.201"})
    derived = replace(net, routing=routing, baseline=net, routing_parent=net)
    assert any(PEER_TEXT in text for text in _reasons(derived, INTERNET))


def test_a_failure_scenario_keeps_the_context_not_decided():
    """`assessment.resilience.apply_failures` derives the network with `replace` and the
    baseline set, also when the failure leaves every routing row as it was."""
    net = core1("none")
    failed = replace(net, baseline=net)
    assert failed.routing == net.routing
    assert any(PEER_TEXT in text for text in _reasons(failed, INTERNET))


def test_a_change_with_no_routing_intent_keeps_the_decided_answer():
    """A change of the firewall policy only (`evaluate.apply` with no routing intent) shares
    the baseline's routing input and its calculation: the flow to the internet stays decided
    on both sides of the comparison."""
    from hst.simul.fw_overlay import ChangeSet

    net = core1("none")
    after = ev.apply(net, ChangeSet([]))
    assert after.routing is net.routing
    assert _reasons(after, INTERNET) == ()
    (reason,) = _reasons(after, INSIDE_LEARNED)
    assert "10.96.0.0/12" in reason
    again = ev.apply(after, ChangeSet([]))
    assert _reasons(again, INTERNET) == ()
    # a failure on top of it blocks again
    assert any(PEER_TEXT in text for text in _reasons(replace(after, baseline=net), INTERNET))


# --- other vendors, and a network with no collected table ---------------------------------------


def test_an_nxos_router_with_an_external_peer_and_a_complete_table_gets_the_same_rule():
    base = nc._network()
    net = core1("none", base=base, afs=[4])
    context = "c1"
    assert any(g.get("cause") == certainty.PEER_SUPPLY for g in net.routes.gaps)
    assert net.incomplete(context, _ivals("203.0.113.10")) == ()
    (reason,) = net.incomplete(context, _ivals(INSIDE_LEARNED))
    assert "10.96.0.0/12" in reason
    partial = core1("none", base=base, afs=[4], coverage="partial")
    assert any(PEER_TEXT in text for text in partial.incomplete(context, _ivals("203.0.113.10")))


def test_a_network_with_no_collected_table_is_unchanged():
    """The peer's gap blocks every flow of a model with no `rib_coverage`."""
    net = core1("none", coverage=None, afs=None)
    assert not net.routing.rib_coverage
    reasons = _reasons(net, INTERNET)
    assert len([text for text in reasons if PEER_TEXT in text]) == len(SESSIONS)


def test_a_network_with_no_peer_gap_is_unchanged():
    net = oslo_network(_estate(1))
    assert net.incomplete(MAIN, _ivals(INTERNET)) == ()
    assert all(node.complete for node in _states(net, INTERNET))


# the impact evaluator reads the same rule


def _legacy(coverage: str = "complete"):
    """The estate of tests/test_impact_evaluate.py: R1 learns 203.0.113.0/24 from peer A,
    whose received routes are collected, and has peer B, whose routes are not collected
    and which is no device of the input. R1's collected table has its computed routes and
    198.51.100.0/24, learned from B."""
    from tests import test_impact_evaluate as ie

    routing = ie._routing(b_observed=False, fixed_boundary=False)
    observed: dict[str, list[dict]] = {}
    for row in ie._network(routing).routes.rib:
        observed.setdefault(str(row["context_uid"]), []).append(dict(row))
    observed[ie.VRF_R1].append({**_rib_row("198.51.100.0/24", "10.0.2.2"), "interface": "eth2"})
    routing = replace(
        routing,
        observed_rib=observed,
        rib_coverage=dict.fromkeys(observed, coverage),
        contexts=[{**c, "observed_rib_afs": [4]} for c in routing.contexts],
    )
    return ie, ie._network(routing)


@pytest.mark.usefixtures("graph")
def test_the_impact_evaluator_decides_a_flow_the_collected_table_answers():
    ie, net = _legacy()
    assert any(g.get("cause") == certainty.PEER_SUPPLY for g in net.routes.gaps)
    answer = ev.answer(net, ie._request())
    assert answer.lower == ie.CLIENTS
    assert answer.upper == ie.CLIENTS


@pytest.mark.usefixtures("graph")
def test_the_impact_evaluator_keeps_a_flow_into_a_learned_prefix_open():
    ie, net = _legacy()
    answer = ev.answer(net, ie._request(dst="198.51.100.10"))
    assert answer.lower != answer.upper


@pytest.mark.usefixtures("graph")
def test_the_impact_evaluator_keeps_every_flow_open_without_a_complete_table():
    ie, net = _legacy("partial")
    answer = ev.answer(net, ie._request())
    assert answer.lower != answer.upper


def test_a_firewall_change_that_misses_the_flow_leaves_both_sides_decided(request):
    """`evaluate.evaluate` as the impact assessment runs it: the after side is an overlay of
    `evaluate.apply` with no routing intent, and keeps the baseline's answer."""
    fake = request.getfixturevalue("graph")
    ie, net = _legacy()
    ie._firewall(fake, ie.B, "rb:b", [])
    impact = ev.evaluate(net, ie._changes(ie._deny_intent("rb:b", "198.51.100.77")), ie._request())
    assert impact.before.lower == impact.before.upper == ie.CLIENTS
    assert impact.after.lower == impact.after.upper == ie.CLIENTS


# --- the gaps around the peer's gap -------------------------------------------------------------


def test_a_family_marked_incomplete_for_another_reason_keeps_its_own_gap():
    """An OSPF process with no router id next to the peers' gaps: the context-wide gap of
    the OSPF input stays, so the context stays not decided."""
    net = core1("none")
    routing = replace(
        net.routing,
        ospf=[{"uid": "ospf:core1", "context_uid": MAIN, "router_id": None, "rows": []}],
    )
    net = replace(net, routing=routing)
    (fallback,) = (
        g
        for g in net.routes.gaps
        if g.get("context_uid") == MAIN and "incomplete ospf inputs" in str(g.get("detail"))
    )
    assert "cause" not in fallback
    assert fallback["detail"] in _reasons(net, INTERNET)


def test_a_peer_gap_carried_to_a_downstream_context_counts_there():
    """The gap of c1's external peer reaches c2 over the iBGP peering. c2's own table is
    complete, but what reaches it from c1 is not its collected table's to answer: the copy
    still counts in c2."""
    from hst.impact.evaluate import Interface

    def session(uid, process, local, peer, peer_asn=65001):
        return {
            "uid": uid,
            "process_uid": process,
            "local_asn": 65001,
            "peer_asn": peer_asn,
            "local_ip": local,
            "peer_ip": peer,
        }

    routing = rib.RibInput(
        contexts=[
            {"uid": "c1", "device_uid": "d1", "platform": "nxos", "observed_rib_afs": [4]},
            {"uid": "c2", "device_uid": "d2", "platform": "nxos", "observed_rib_afs": [4]},
        ],
        connected=[
            {"context_uid": "c1", "prefix": "10.0.12.0/30", "interface": "eth1"},
            {"context_uid": "c1", "prefix": "192.0.2.0/30", "interface": "eth0"},
            {"context_uid": "c2", "prefix": "10.0.12.0/30", "interface": "eth1"},
        ],
        static=[
            {"context_uid": "c1", "prefix": "0.0.0.0/0", "next_hop": "192.0.2.2"},
            {"context_uid": "c2", "prefix": "0.0.0.0/0", "next_hop": "10.0.12.1"},
        ],
        bgp=SimulationInput(
            processes=[
                {"uid": "p1", "context_uid": "c1", "proto": "bgp", "asn": 65001, "router_id": "10.0.12.1"},
                {"uid": "p2", "context_uid": "c2", "proto": "bgp", "asn": 65001, "router_id": "10.0.12.2"},
            ],
            sessions=[
                session("s12", "p1", "10.0.12.1", "10.0.12.2"),
                session("s21", "p2", "10.0.12.2", "10.0.12.1"),
                session("ext", "p1", "192.0.2.1", "192.0.2.2", peer_asn=65100),
            ],
            platform="nxos",
        ),
        direction_status={("ext", "received"): "not-captured", ("ext", "accepted"): "not-captured"},
        platform="nxos",
    )
    observed: dict[str, list[dict]] = {}
    for row in rib.compute(routing).rib:
        observed.setdefault(str(row["context_uid"]), []).append(dict(row))
    routing = replace(routing, observed_rib=observed, rib_coverage=dict.fromkeys(("c1", "c2"), "complete"))
    net = Network(
        routing,
        (
            Interface("d1", "if:d1:eth1", "eth1", "c1", ("10.0.12.0/30",), ("10.0.12.1",)),
            Interface("d1", "if:d1:eth0", "eth0", "c1", ("192.0.2.0/30",), ("192.0.2.1",)),
            Interface("d2", "if:d2:eth1", "eth1", "c2", ("10.0.12.0/30",), ("10.0.12.2",)),
        ),
        nc._Gates(),
    )
    copies = [g for g in net.routes.gaps if g.get("cause") == certainty.PEER_SUPPLY]
    assert {(g["context_uid"], g.get("origin_context_uid")) for g in copies} == {("c1", None), ("c2", "c1")}
    assert not any("BGP peer 192.0.2.2" in text for text in net.incomplete("c1", _ivals("8.8.8.8")))
    assert any("BGP peer 192.0.2.2" in text for text in net.incomplete("c2", _ivals("8.8.8.8")))


def test_a_peer_on_a_named_vrf_is_named_with_its_router_and_vrf():
    """A line of `missing_evidence` stands alone: it names the router, and the VRF when it
    is not the default one."""
    net = core1("none")
    contexts = [{**c, "name": "blue"} if c["uid"] == MAIN else c for c in net.routing.contexts]
    net = replace(net, routing=replace(net.routing, contexts=contexts))
    details = {g["detail"] for g in net.routes.gaps if g.get("cause") == certainty.PEER_SUPPLY}
    assert {d[: d.index(": ")] for d in details} == {f"BGP peer {peer} on {DEV} VRF blue" for peer in PEERS}


# the live shape with accepted tables and an ECMP prefix

ECMP = "10.10.10.1/32"


def core1_live() -> Network:
    """core1 as the live graph has it with the accepted tables collected: the process
    records maximum-paths 4 for eBGP and no policy requirement; 10.10.10.1/32 is accepted
    from .35 (best) and .36 (multipath, not best) with the same AS path and MED 0; .30's
    accepted table is complete and empty; the received direction is not captured; the
    collected table has the prefix by both next hops."""
    net = core1("accepted")
    routing = net.routing
    assert routing.bgp is not None
    process = {
        **routing.bgp.processes[0],
        "maximum_paths_ebgp_v4": 4,
        "multipath_config_recorded": True,
        "ebgp_requires_policy": False,
    }
    status = dict(routing.direction_status)
    for uid in SESSIONS:
        status[uid, "accepted"] = "complete"
    status[SESSIONS[0], "accepted"] = "complete-empty"
    paths = [
        {**_path(SESSIONS[1], ECMP, PEERS[1], "accepted"), "med": 0, "best": True},
        {**_path(SESSIONS[2], ECMP, PEERS[2], "accepted"), "med": 0, "best": False, "multipath": True},
    ]
    observed = {
        uid: [row for row in rows if row.get("protocol") != "bgp"]
        for uid, rows in routing.observed_rib.items()
    }
    observed[MAIN] += [_rib_row(ECMP, PEERS[1]), _rib_row(ECMP, PEERS[2])]
    return replace(
        net,
        routing=replace(
            routing,
            bgp=replace(routing.bgp, processes=[process]),
            observed_paths=paths,
            direction_status=status,
            observed_rib=observed,
        ),
    )


def test_live_shape_the_flow_to_the_internet_is_decided():
    net = core1_live()
    assert _reasons(net, INTERNET) == ()
    assert all(node.complete for node in _states(net, INTERNET))


def test_live_shape_the_flow_to_the_ecmp_prefix_is_not_decided_by_the_arrival_order_tie():
    """Both paths are installed and agree with the collected table, but which of the two
    is the best path the engine decides only by the arrival-order step (FRR's oldest-path
    rule for eBGP), which no collected table records: the prefix carries a
    history-dependent gap, and that alone holds the flow back. The peers' gaps do not."""
    net = core1_live()
    rows = sorted(r["next_hop"] for r in net.routes.rib if r["context_uid"] == MAIN and r["prefix"] == ECMP)
    assert rows == [PEERS[1], PEERS[2]]
    (item,) = (v for v in net.routes.validation if v["context_uid"] == MAIN and v["prefix"] == ECMP)
    assert item["status"] == rib.VALIDATED
    (gap,) = (g for g in net.routes.gaps if g.get("prefix") == ECMP)
    assert gap["kind"] == rib.HISTORY_DEPENDENT
    (reason,) = _reasons(net, "10.10.10.1")
    assert reason == gap["detail"]
    assert "not invariant across arrival histories" in reason
    assert not any(node.complete for node in _states(net, "10.10.10.1"))
