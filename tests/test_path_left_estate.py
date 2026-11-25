"""Where a trace leaves the estate."""

# ruff: noqa: F811

import copy
import importlib

import pytest
from tests.test_path_nat import _tunnel
from tests.test_path_reply_exit import _drop_all
from tests.test_path_trace import (  # noqa: F401
    GW,
    _route,
    _src_row,
    graph,
)

from hst import path
from hst.results.trace import leg_result, project_trace

tracemod = importlib.import_module("hst.path.trace")

UPLINK = tracemod._EGRESS_UPLINK_QUERY
GW6 = {**GW, "cidr": "fd00::/64"}
LAN = _route("10.0.0.0/24", egress="eth1", kind="ORIGINATES")
LAN6 = _route("fd00::/64", egress="eth1", kind="ORIGINATES")
ZONE_TEXT = 'the operator\'s site zone "internet" of block dc-edge'


def _uplinks(graph, rows):
    """Answer the uplink read from `rows`, keyed by egress uid."""
    read_one = graph.read_one

    def answer(query, **params):
        if query == UPLINK:
            return rows.get(params["u"])
        return read_one(query, **params)

    graph.read_one = answer


def _row(zone=None, block="dc-edge", link=None, kind=None, origin=None):
    """The uplink read's row: the interface's marks and its device's stamp."""
    return {
        "default_origin": origin,
        "link_uid": link,
        "link_name": "MPLS" if kind == "mpls" else ("DIA" if link else None),
        "link_kind": kind,
        "site_zone": zone,
        "site_block": block if zone else None,
    }


def _edge(graph, routes, row=None, egress="Gi0/0/0", src="10.0.0.5", dst="198.51.100.7", gw=GW, **kw):
    """One trace from `src` through r1, whose uplink read answers `row`."""
    graph.sources = [_src_row(ip=src)]
    graph.routes = {"vrf:main": routes}
    if row is not None:
        _uplinks(graph, {f"if:{egress}": row})
    return path.trace(None, src, dst, port=443, proto="tcp", gateways=[gw], reply=True, **kw)


def _ios_default():
    return [_route("0.0.0.0/0", egress="Gi0/0/0", next_hop="203.0.113.1"), LAN]


ZONE_EXIT = {
    "basis": "site-zone",
    "device_uid": "dev:r1",
    "device": "r1",
    "interface_uid": "if:Gi0/0/0",
    "interface": "Gi0/0/0",
    "next_hop": "203.0.113.1",
    "wan_link_uid": None,
    "wan_link": None,
    "site_block": "dc-edge",
}


# --- rule B: the operator's site zone "internet" ----------------------------------------------


def test_an_internet_edge_with_no_wan_link_leaves_the_estate_by_its_zone(graph):
    """The IOS-XE shape: `ip route 0.0.0.0 0.0.0.0 203.0.113.1` out of Gi0/0/0, no
    collector marks the interface; the device's zone is "internet"."""
    result = _edge(graph, _ios_default(), _row(zone="internet"))

    forward = result["forward"]
    leg = forward["legs"][0]
    assert leg["boundary"] is True and not leg["indeterminate"]
    assert leg["left_estate"] == ZONE_EXIT
    assert forward["left_estate"] == [ZONE_EXIT]
    assert forward["reach"] == "left_estate"
    assert leg_result(leg).answer == "true"
    # the answer rests on a declaration, and its prose names it
    assert not any("not held by any interface" in w for w in forward["warnings"])
    assert forward["notes"] == [
        f"10.0.0.5: 0.0.0.0/0 leaves by Gi0/0/0 toward next hop 203.0.113.1, the internet by {ZONE_TEXT}; "
        "the path leaves the twin at r1"
    ]
    assert forward["verdict"] == (
        "10.0.0.5 → 198.51.100.7:443/tcp: egress via Gi0/0/0 (0.0.0.0/0, main table) · leaves the estate "
        f"at r1 Gi0/0/0 to next hop 203.0.113.1 ({ZONE_TEXT})"
    )
    # the reply is derived and starts on the egress interface
    reply = result["reply"]
    assert not reply["verdict"].startswith("reply not derived"), reply["verdict"]
    first = reply["hops"][0]
    assert (first["stage"], first["uid"], first["note"]) == (
        "SRC_ENDPOINT",
        "if:Gi0/0/0",
        "reply origin: 198.51.100.7, outside the twin",
    )
    assert reply["legs"][0]["egress"] == "eth1"
    assert reply["reach"] == "destination" and reply["left_estate"] == []


def test_an_internet_edge_of_an_ipv6_default_leaves_by_its_zone(graph):
    routes = [_route("::/0", egress="Gi0/0/0", next_hop="2001:db8:18::1"), LAN6]
    result = _edge(graph, routes, _row(zone="internet"), src="fd00::5", dst="2001:db8:ff00::7", gw=GW6)

    assert result["forward"]["legs"][0]["left_estate"]["basis"] == "site-zone"
    assert result["forward"]["reach"] == "left_estate"


def _today(graph, routes, **kw):
    """The same scenario on a fresh fake graph."""
    from tests.test_path_trace import FakeGraph

    graph.__dict__.clear()
    graph.__dict__.update(FakeGraph().__dict__)
    assert "read_one" not in graph.__dict__
    return _edge(graph, routes, **kw)


@pytest.mark.parametrize(
    "row",
    [
        _row(),
        _row(zone="internal"),
        _row(zone="external"),
        {**_row(), "site_block": "dc-edge"},  # a block with no zone
    ],
    ids=["no-stamp", "internal", "external", "block-without-zone"],
)
@pytest.mark.parametrize(
    "routes",
    [
        _ios_default(),
        [_route("0.0.0.0/0", egress="Gi0/0/0"), LAN],
        [_route("198.51.100.0/24", egress="Gi0/0/0", next_hop="203.0.113.1"), LAN],
    ],
    ids=["next-hop-default", "interface-only-default", "specific-route"],
)
def test_a_device_not_stamped_internet_reads_as_a_run_with_no_uplink_row(graph, row, routes):
    stamped = _edge(graph, copy.deepcopy(routes), row)
    before = _today(graph, copy.deepcopy(routes))

    assert stamped == before
    forward = stamped["forward"]
    assert "left_estate" not in forward["legs"][0]
    assert forward["left_estate"] == []


def test_the_external_zone_with_a_default_to_an_outside_next_hop_is_no_exit(graph):
    """ "external" is the map's zone (outside the firewall), not an internet edge."""
    result = _edge(graph, _ios_default(), _row(zone="external"))

    forward = result["forward"]
    assert any("not held by any interface" in w for w in forward["warnings"])
    assert "left_estate" not in forward["legs"][0]
    assert forward["left_estate"] == [] and forward["reach"] is None
    assert result["reply"]["verdict"] == "reply not derived: the forward leg never confirmed delivery"
    assert result["reply"]["reach"] is None and result["reply"]["left_estate"] == []


def test_an_ipv6_flow_with_only_an_ipv4_default_is_no_exit_by_the_zone(graph):
    result = _edge(
        graph, [*_ios_default(), LAN6], _row(zone="internet"), src="fd00::5", dst="2001:db8:ff00::7", gw=GW6
    )

    forward = result["forward"]
    assert forward["legs"][0]["verdict"] == "no route found"
    assert "left_estate" not in forward["legs"][0]
    assert forward["left_estate"] == [] and forward["reach"] is None


def test_an_mpls_link_on_the_egress_outranks_the_zone(graph):
    result = _edge(graph, _ios_default(), _row(zone="internet", link="wan:r1:mpls", kind="mpls"))

    forward = result["forward"]
    assert any("not held by any interface" in w for w in forward["warnings"])
    assert "left_estate" not in forward["legs"][0]
    assert forward["reach"] is None
    assert result["reply"]["verdict"] == "reply not derived: the forward leg never confirmed delivery"


def test_a_more_specific_route_of_an_internet_edge_is_no_exit(graph):
    routes = [_route("198.51.100.0/24", egress="Gi0/0/0", next_hop="203.0.113.1"), LAN]
    result = _edge(graph, routes, _row(zone="internet"))

    forward = result["forward"]
    assert any("not held by any interface" in w for w in forward["warnings"])
    assert "left_estate" not in forward["legs"][0]
    assert forward["reach"] is None


def test_an_interface_only_default_of_an_internet_edge_leaves_by_its_zone(graph):
    result = _edge(graph, [_route("0.0.0.0/0", egress="Gi0/0/0"), LAN], _row(zone="internet"))

    forward = result["forward"]
    assert forward["legs"][0]["left_estate"] == {**ZONE_EXIT, "next_hop": None}
    assert forward["reach"] == "left_estate"
    assert forward["notes"] == [
        f"10.0.0.5: 0.0.0.0/0 leaves by Gi0/0/0 with no next hop in the graph, the internet by {ZONE_TEXT}; "
        "the path leaves the twin at r1"
    ]
    assert forward["warnings"] == []


def test_the_zone_is_read_from_the_run_pinned_device(graph):
    """The uplink read reaches the Device through the interface, in the pinned run."""
    assert "(i)-[don:ON]->(d:Device)" in UPLINK
    assert "d:Obj AND d.collection_ts = $snap" in UPLINK
    assert "d.site_zone AS site_zone, d.site_block AS site_block" in UPLINK


# --- the collected bases ----------------------------------------------------------------------


def test_a_collected_wan_link_is_the_wan_link_basis(graph):
    routes = [_route("0.0.0.0/0", egress="eth0", next_hop="203.0.113.1"), LAN]
    result = _edge(graph, routes, _row(link="wan:r1:eth0", kind="dia"), egress="eth0")

    forward = result["forward"]
    assert forward["legs"][0]["left_estate"] == {
        "basis": "wan-link",
        "device_uid": "dev:r1",
        "device": "r1",
        "interface_uid": "if:eth0",
        "interface": "eth0",
        "next_hop": "203.0.113.1",
        "wan_link_uid": "wan:r1:eth0",
        "wan_link": "DIA",
        "site_block": None,
    }
    assert forward["reach"] == "left_estate"
    assert forward["verdict"] == "10.0.0.5 → 198.51.100.7:443/tcp: egress via eth0 (0.0.0.0/0, main table)"
    assert forward["notes"] == [
        "10.0.0.5: 0.0.0.0/0 leaves by DIA toward next hop 203.0.113.1, beyond the collected uplink; "
        "the path leaves the twin at r1"
    ]
    assert forward["warnings"] == []
    assert result["reply"]["verdict"] == "reply: egress via eth1 (10.0.0.0/24, main table)"
    assert result["reply"]["hops"][0]["uid"] == "wan:r1:eth0"


def test_a_wan_link_outranks_the_zone(graph):
    routes = [_route("0.0.0.0/0", egress="eth0", next_hop="203.0.113.1"), LAN]
    result = _edge(graph, routes, _row(zone="internet", link="wan:r1:eth0", kind="dia"), egress="eth0")

    assert result["forward"]["legs"][0]["left_estate"]["basis"] == "wan-link"
    assert result["forward"]["legs"][0]["left_estate"]["site_block"] is None


def test_the_access_client_default_is_its_own_basis(graph):
    routes = [_route("0.0.0.0/0", egress="eth0", next_hop="203.0.113.1"), LAN]
    result = _edge(graph, routes, _row(origin="dhcp"), egress="eth0")

    exit_ = result["forward"]["legs"][0]["left_estate"]
    assert exit_["basis"] == "access-client-default" and exit_["wan_link_uid"] is None


def test_an_interface_only_default_by_a_drawn_wan_link_is_the_wan_link_basis(graph):
    graph.wan = {"uid": "wan:r1:eth0", "name": "DIA", "kind": "dia"}
    result = _edge(graph, [_route("0.0.0.0/0", egress="eth0"), LAN])

    exit_ = result["forward"]["legs"][0]["left_estate"]
    assert (exit_["basis"], exit_["wan_link_uid"], exit_["next_hop"]) == ("wan-link", "wan:r1:eth0", None)


def test_an_interface_only_default_by_an_mpls_link_carries_no_marker(graph):
    graph.wan = {"uid": "wan:r1:eth0", "name": "MPLS", "kind": "mpls"}
    result = _edge(graph, [_route("0.0.0.0/0", egress="eth0"), LAN])

    assert "left_estate" not in result["forward"]["legs"][0]
    assert result["forward"]["reach"] is None


def test_the_sdwan_direct_row_names_the_kind_of_its_link():
    trail = tracemod._Trail()
    route = {
        "cidr": "0.0.0.0/0",
        "kind": "SDWAN_DIRECT",
        "sdwan": {"link_uid": "wan:vc:1", "link_name": "isp-a", "link_kind": "mpls"},
    }
    wan = tracemod._default_route_wan_hop(None, trail, route, {"dev_uid": "dev:vc"})
    assert wan == {"uid": "wan:vc:1", "name": "isp-a", "kind": "mpls"}


# --- the carrier underlay ----------------------------------------------------------------------


def _carrier_exit(graph, zone):
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [_route("0.0.0.0/0", egress="wg0")],
        "vrf:wan": [_route("0.0.0.0/0", egress="Gi0/0/0", next_hop="198.51.100.1")],
    }
    graph.local_vrf = {"vrf_uid": "vrf:wan", "vrf_name": "default"}
    graph.iface_addrs = {"if:Gi0/0/0": "198.51.100.2"}
    _tunnel(graph)
    _uplinks(graph, {"if:Gi0/0/0": _row(zone=zone)})
    return path.trace(None, "10.0.0.5", "8.8.8.8", port=443, proto="tcp", gateways=[GW])


def test_a_carrier_that_leaves_by_an_internet_edge_carries_the_marker(graph):
    result = _carrier_exit(graph, "internet")

    leg = result["legs"][0]
    exit_ = {**ZONE_EXIT, "next_hop": "198.51.100.1"}
    assert leg["carrier"]["left_estate"] == exit_ and leg["left_estate"] == exit_
    assert result["left_estate"] == [exit_]
    assert result["reach"] == "left_estate"
    assert result["warnings"] == []


def test_a_carrier_out_of_an_unstamped_device_keeps_its_warned_gap(graph):
    result = _carrier_exit(graph, None)

    leg = result["legs"][0]
    assert "left_estate" not in leg and "left_estate" not in leg["carrier"]
    assert result["warnings"] == [
        "us-streaming: carrier next hop 198.51.100.1 is not held by any interface in the graph"
    ]
    assert result["left_estate"] == [] and result["reach"] is None


# --- reach --------------------------------------------------------------------------------------


def test_a_flow_delivered_inside_the_estate_reaches_its_destination(graph):
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.0.1.0/24", egress="eth2", kind="ORIGINATES")]}

    result = path.trace(None, "10.0.0.5", "10.0.1.9", gateways=[GW])

    assert result["reach"] == "destination"
    assert result["left_estate"] == []


def test_a_blocked_walk_has_no_reach(graph):
    _drop_all(graph)
    result = _edge(graph, _ios_default(), _row(zone="internet"))

    assert result["forward"]["legs"][0]["blocked"]
    assert result["forward"]["reach"] is None


def test_an_undecided_walk_has_no_reach_but_keeps_its_exit(graph):
    """The exit leaves the twin outside the asserted destination context: the walk
    is undecided, and only `reach` says nothing."""
    result = _edge(graph, _ios_default(), _row(zone="internet"), dst_context="vrf:other")

    forward = result["forward"]
    assert forward["indeterminate"] is True
    assert forward["left_estate"] == [ZONE_EXIT]
    assert forward["reach"] is None


def test_walk_reach_reads_each_candidate_path():
    ok = {"verdict": "egress via eth0", "blocked": False, "indeterminate": False}
    reach = tracemod._walk_reach
    assert reach([ok, ok], ["destination", "destination"], False) == "destination"
    assert reach([ok, ok], ["left_estate", "left_estate"], False) == "left_estate"
    assert reach([ok, ok], ["destination", "left_estate"], False) == "split"
    # an end the walk did not name, a not-decided walk, a blocked leg: no reach
    assert reach([ok, ok], ["destination", None], False) is None
    assert reach([ok], ["destination"], True) is None
    assert reach([ok, {**ok, "blocked": True}], ["destination", "destination"], False) is None
    assert reach([], [], False) is None


def test_merged_lanes_combine_each_parts_reach():
    def part(reach, exits=(), indeterminate=False):
        return {
            "hops": [],
            "legs": [{"lane": 0, "verdict": "x"}],
            "verdict": "v",
            "notes": [],
            "indeterminate": indeterminate,
            "boundary": False,
            "left_estate": list(exits),
            "reach": reach,
        }

    merge = tracemod._merge_lanes
    both = merge(
        [("a", "a", part("destination")), ("b", "b", part("left_estate", [ZONE_EXIT]))], [], truncated=False
    )
    assert both["reach"] == "split" and both["left_estate"] == [ZONE_EXIT]
    old = {k: v for k, v in part("destination").items() if k not in ("left_estate", "reach")}
    assert merge([("a", "a", part("destination")), ("b", "b", old)], [], truncated=False)["reach"] is None
    assert merge([("a", "a", part("destination", indeterminate=True))], [], truncated=False)["reach"] is None


# --- the projection ---------------------------------------------------------------------------


def test_the_projection_keeps_both_keys(graph):
    result = project_trace(_edge(graph, _ios_default(), _row(zone="internet")))

    assert result["forward"]["reach"] == "left_estate"
    assert result["forward"]["left_estate"] == [ZONE_EXIT]
    assert result["forward"]["legs"][0]["left_estate"] == ZONE_EXIT
    assert result["reply"]["reach"] == "destination"


def test_the_projection_clears_reach_on_a_walk_that_does_not_read_forwarded():
    walk = {
        "legs": [{"verdict": "egress via eth0", "blocked": False, "indeterminate": True}],
        "verdict": "x",
        "indeterminate": True,
        "left_estate": [ZONE_EXIT],
        "reach": "left_estate",
    }
    project_trace(walk)
    assert walk["reach"] is None and walk["left_estate"] == [ZONE_EXIT]


def test_a_stored_walk_without_the_keys_stays_without_them():
    walk = {
        "legs": [{"verdict": "egress via eth0", "blocked": False, "indeterminate": False}],
        "verdict": "x",
    }
    project_trace(walk)
    assert "reach" not in walk and "left_estate" not in walk


# --- the forward path the reply is compared with ------------------------------------------------


def _hop(uid, stage, rank, shared=False):
    return {"uid": uid, "kind": "Device", "stage": stage, "lane": 0, "shared": shared, "rank": rank}


def _forward_sequence(monkeypatch, hops, visits):
    """The forward sequence `_compose_bidirectional` hands the reply walk."""
    seen = []

    def walk(session, fleg, terminal, forward_sequence, *args, **kw):
        seen.append(forward_sequence)
        return {
            "hops": [],
            "legs": [],
            "verdict": "x",
            "notes": [],
            "warnings": [],
            "indeterminate": False,
            "boundary": False,
            "asymmetric": False,
            "comparison_notes": [],
            "destinations": [],
        }

    monkeypatch.setattr(tracemod, "_walk_reply_leg", walk)
    forward = {"legs": [{"lane": 0}], "hops": hops}
    capture = {"leg_terminals": [None], "leg_gate_states": [{}], "device_sequence": visits}
    tracemod._compose_bidirectional(None, forward, capture, [], [], None, max_hops=12)
    return seen[0]


def test_a_gateway_drawn_as_the_sources_attach_switch_starts_the_forward_path(monkeypatch):
    """The core's one hop is SRC_ATTACH."""
    hops = [_hop("dev:core", "SRC_ATTACH", 1, shared=True), _hop("dev:edge", "DEVICE", 5)]
    assert _forward_sequence(monkeypatch, hops, ["dev:core", "dev:edge"]) == ["dev:core", "dev:edge"]


def test_a_gateway_drawn_as_a_device_hop_is_not_counted_twice(monkeypatch):
    hops = [
        _hop("dev:sw", "SRC_ATTACH", 1, shared=True),
        _hop("dev:core", "DEVICE", 3),
        _hop("dev:edge", "DEVICE", 5),
    ]
    assert _forward_sequence(monkeypatch, hops, ["dev:core", "dev:edge"]) == ["dev:core", "dev:edge"]


def test_a_reply_home_by_another_device_is_asymmetric_against_that_path():
    forward = ["dev:core", "dev:edge"]
    asymmetric, notes = tracemod._reply_comparison(forward, {0: ["dev:edge", "dev:other"]}, {})
    assert asymmetric is True
    assert notes == [
        "asymmetric routing: the reply's own path (dev:edge → dev:other) does not match the forward "
        "path reversed (dev:edge → dev:core)"
    ]
    assert tracemod._reply_comparison(forward, {0: ["dev:edge", "dev:core"]}, {}) == (False, [])


# --- the words of the edge sentences --------------------------------------------------------------


def _added_sentences(result):
    """The sentences the estate's edge adds to an answer: the verdict's exit
    clause, and each note or warning that names the zone or the estate."""
    walk = result.get("forward", result)
    texts = [walk["verdict"].split(" · ", 1)[1]] if " · " in walk["verdict"] else []
    texts += [
        t for t in [*walk["notes"], *walk["warnings"]] if "the internet by" in t or "leaves the estate" in t
    ]
    return texts


@pytest.mark.parametrize(
    "exit_",
    [
        ZONE_EXIT,
        {**ZONE_EXIT, "next_hop": None, "site_block": None},
        {**ZONE_EXIT, "basis": "wan-link", "wan_link": "DIA", "site_block": None},
        {**ZONE_EXIT, "basis": "wan-link", "wan_link": None, "wan_link_uid": None, "site_block": None},
        {**ZONE_EXIT, "basis": "access-client-default", "site_block": None},
    ],
)
def test_the_exit_sentence_uses_only_result_words(exit_):
    from hst.results.words import FORBIDDEN_WORDS, _contains_word

    sentence = tracemod._exit_words(exit_).lower()
    assert not [w for w in FORBIDDEN_WORDS if _contains_word(sentence, w)], sentence


def test_the_sentences_of_each_zone_exit_use_only_result_words(graph):
    from tests.test_path_trace import FakeGraph

    from hst.results.words import FORBIDDEN_WORDS, _contains_word

    answers = [
        _edge(graph, _ios_default(), _row(zone="internet")),
        _edge(graph, [_route("0.0.0.0/0", egress="Gi0/0/0"), LAN], _row(zone="internet")),
    ]
    graph.__dict__.clear()
    graph.__dict__.update(FakeGraph().__dict__)
    answers.append(_carrier_exit(graph, "internet"))
    sentences = [s for answer in answers for s in _added_sentences(answer)]
    assert len(sentences) >= 5
    for sentence in sentences:
        assert not [w for w in FORBIDDEN_WORDS if _contains_word(sentence.lower(), w)], sentence


# --- a destination the estate serves is no exit ------------------------------------------------


def _estate(graph, cidrs, routed=()):
    """Answer the estate's served prefixes (`_ESTATE_PREFIXES_QUERY`) with `cidrs` (a cidr, or a
    whole row with the interface's edge facts) and the routes (`_ROUTED_PREFIXES_QUERY`) with
    `routed` (a cidr of r2's, or a (cidr, devices) pair), and count the reads."""
    from hst.core.ipenc import graph_prefix_keys

    read = graph.read
    graph.estate_reads = 0
    graph.routed_reads = []

    def meets(cidr, spans):
        lo, hi = graph_prefix_keys(cidr)
        return any(
            (lo in s["covering"] or s["lo"] <= lo <= s["hi"]) and hi >= s["lo"] and lo <= s["hi"]
            for s in spans
        )

    def answer(query, **params):
        if query == tracemod._ESTATE_PREFIXES_QUERY:
            graph.estate_reads += 1
            return [c if isinstance(c, dict) else {"cidr": c} for c in cidrs]
        if query == tracemod._ROUTED_PREFIXES_QUERY:
            graph.routed_reads.append(params["spans"])
            # the prefixes whose keys meet a span, as the Cypher selects them
            rows = [r if isinstance(r, tuple) else (r, ["dev:r2"]) for r in routed]
            return [{"cidr": c, "devices": d} for c, d in rows if meets(c, params["spans"])]
        return read(query, **params)

    graph.read = answer


ESTATE = ["10.0.0.0/24", "10.9.0.0/16", "fd00::/64", "2001:db8:9::/48"]
NEXT_HOP_BASES = {
    "site-zone": ("Gi0/0/0", _row(zone="internet")),
    "wan-link": ("Gi0/0/0", _row(link="wan:r1:gi0", kind="dia")),
    "access-client-default": ("Gi0/0/0", _row(origin="dhcp")),
}


def _estate_warning(dst, cidr, egress="Gi0/0/0", src="10.0.0.5", part=False):
    what = f"{dst} of the destination is" if part else f"the destination {dst} is"
    return (
        f"{src}: {what} an address of the estate, and r1 has no route to it other than the default "
        f"route {cidr} by {egress}"
    )


@pytest.mark.parametrize("basis", sorted(NEXT_HOP_BASES))
def test_an_address_of_the_estate_sent_to_the_edge_is_no_exit(graph, basis):
    """r1 has no route to 10.9.0.0/16, which another device of the estate serves, and sends it
    to its default route: a route missing on r1, not the internet, on every basis."""
    _egress, row = NEXT_HOP_BASES[basis]
    _estate(graph, ESTATE)
    result = _edge(graph, _ios_default(), row, dst="10.9.9.9")

    forward = result["forward"]
    leg = forward["legs"][0]
    assert "left_estate" not in leg and forward["left_estate"] == [] and forward["reach"] is None
    assert leg["boundary"] is True and not leg["indeterminate"]
    assert forward["warnings"] == [
        "10.0.0.5: next hop 203.0.113.1 is not held by any interface in the graph; "
        "the path leaves the twin at r1",
        _estate_warning("10.9.9.9", "0.0.0.0/0"),
    ]
    assert not any("beyond the collected uplink" in n or "the internet by" in n for n in forward["notes"])
    assert result["reply"]["verdict"] == "reply not derived: the forward leg never confirmed delivery"
    assert graph.estate_reads == 1


@pytest.mark.parametrize("basis", ["site-zone", "wan-link"])
def test_an_ipv6_address_of_the_estate_sent_to_the_edge_is_no_exit(graph, basis):
    _egress, row = NEXT_HOP_BASES[basis]
    _estate(graph, ESTATE)
    routes = [_route("::/0", egress="Gi0/0/0", next_hop="2001:db8:18::1"), LAN6]
    result = _edge(graph, routes, row, src="fd00::5", dst="2001:db8:9::9", gw=GW6)

    forward = result["forward"]
    assert "left_estate" not in forward["legs"][0] and forward["reach"] is None
    assert forward["warnings"][-1] == _estate_warning("2001:db8:9::9", "::/0", src="fd00::5")
    assert result["reply"]["verdict"] == "reply not derived: the forward leg never confirmed delivery"


def test_an_internet_address_beside_the_estate_leaves_by_the_edge(graph):
    """The estate's prefixes do not cover 198.51.100.7."""
    _estate(graph, ESTATE)
    result = _edge(graph, _ios_default(), _row(zone="internet"))

    assert result["forward"]["legs"][0]["left_estate"] == ZONE_EXIT
    assert result["forward"]["reach"] == "left_estate"
    assert graph.estate_reads == 1


def test_a_destination_prefix_partly_in_the_estate_is_no_exit_and_names_that_part(graph):
    """198.18.0.0/15 is one flow part on r1 (one route, the default): its upper half is served
    by the estate, its lower half is public. The marker needs every address of the part outside
    the estate, so the part reads as the unrecognized edge does: a warned boundary, no marker, no
    reply; the warning names the part that is the estate's."""
    _estate(graph, [*ESTATE, "198.19.0.0/16"])
    result = _edge(graph, _ios_default(), _row(zone="internet"), dst="198.18.0.0/15")

    forward = result["forward"]
    assert [leg.get("left_estate") for leg in forward["legs"]] == [None]
    assert forward["reach"] is None and forward["left_estate"] == []
    assert forward["warnings"][-1] == _estate_warning("198.19.0.0/16", "0.0.0.0/0", part=True)


def test_an_interface_only_default_to_an_address_of_the_estate_carries_no_marker(graph):
    """The interface-only exit keeps its note and its reply start, as every interface-only
    exit with no marker does; the marker is withheld and a warning names the fact."""
    _estate(graph, ESTATE)
    result = _edge(graph, [_route("0.0.0.0/0", egress="Gi0/0/0"), LAN], _row(zone="internet"), dst="10.9.9.9")

    forward = result["forward"]
    assert "left_estate" not in forward["legs"][0] and forward["reach"] is None
    # a warning is also in the notes, in order
    assert forward["notes"] == [
        _estate_warning("10.9.9.9", "0.0.0.0/0"),
        "10.0.0.5: 0.0.0.0/0 leaves by Gi0/0/0 with no next hop in the graph; the path leaves the twin at r1",
    ]
    assert forward["warnings"] == [_estate_warning("10.9.9.9", "0.0.0.0/0")]
    assert not result["reply"]["verdict"].startswith("reply not derived")


def test_an_interface_only_default_by_a_wan_link_to_an_address_of_the_estate_carries_no_marker(graph):
    graph.wan = {"uid": "wan:r1:eth0", "name": "DIA", "kind": "dia"}
    _estate(graph, ESTATE)
    result = _edge(graph, [_route("0.0.0.0/0", egress="eth0"), LAN], dst="10.9.9.9")

    assert "left_estate" not in result["forward"]["legs"][0]
    assert result["forward"]["warnings"] == [_estate_warning("10.9.9.9", "0.0.0.0/0", egress="eth0")]


def test_the_estate_wrapper_gives_no_exit_for_an_address_of_the_estate(graph):
    _estate(graph, ESTATE)
    _uplinks(graph, {"if:Gi0/0/0": _row(zone="internet")})
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": _ios_default()}
    route = _ios_default()[0]
    common = {
        "device_uid": "dev:r1",
        "device_name": "r1",
        "table_uid": "vrf:main",
        "route": route,
        "egress_uid": "if:Gi0/0/0",
        "egress_name": "Gi0/0/0",
    }
    from hst.path.addrsets import _intervals

    assert tracemod.estate_exit(None, **common) == ZONE_EXIT
    assert tracemod.estate_exit(None, **common, destinations=_intervals(["198.51.100.7"])) == ZONE_EXIT
    assert tracemod.estate_exit(None, **common, destinations=_intervals(["10.9.9.9"])) is None


def test_the_estate_is_its_served_and_routed_prefixes_and_private_space_never_a_default():
    from hst.path.addrsets import _intervals, _merge

    private = list(tracemod.NOT_INTERNET)
    assert tracemod.estate_prefixes([]) == tuple(_merge(_intervals(private)))
    held = tracemod.estate_prefixes(
        ["198.18.0.0/16", "0.0.0.0/0", "::/0", "x"], routed=["203.0.113.0/26", "0.0.0.0/0", "::/0", "y"]
    )
    assert held == tuple(_merge(_intervals(["198.18.0.0/16", "203.0.113.0/26", *private])))
    # a call with the served prefixes only
    assert tracemod.estate_prefixes(["198.18.0.0/16"]) == tuple(
        _merge(_intervals(["198.18.0.0/16", *private]))
    )


def test_private_space_has_no_documentation_range():
    from hst.path.addrsets import _intersect, _intervals

    docs = _intervals(["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"])
    assert _intersect(docs, list(tracemod.estate_prefixes([]))) == []


def test_the_estate_warning_uses_only_result_words(graph):
    from hst.results.words import FORBIDDEN_WORDS, _contains_word

    _estate(graph, [*ESTATE, "198.19.0.0/16"])
    sentences = [
        _edge(graph, _ios_default(), _row(zone="internet"), dst="198.18.0.0/15")["forward"]["warnings"][-1],
        _estate_warning("10.9.9.9", "0.0.0.0/0"),
    ]
    for sentence in sentences:
        assert not [w for w in FORBIDDEN_WORDS if _contains_word(sentence.lower(), w)], sentence


# --- private space and the routes of other devices ----------------------------------------------


def _private_warning(dst, cidr, src="10.0.0.5"):
    return (
        f"{src}: the destination {dst} is a private address that no device of the estate serves, and r1 "
        f"has no route to it other than the default route {cidr} by Gi0/0/0"
    )


@pytest.mark.parametrize("basis", sorted(NEXT_HOP_BASES))
def test_a_private_address_no_device_serves_is_no_exit(graph, basis):
    """172.20.1.1 is private space no interface of the estate serves and no device routes: it is
    never on the internet, so the default route to it is a route missing on r1."""
    _egress, row = NEXT_HOP_BASES[basis]
    _estate(graph, ESTATE)
    result = _edge(graph, _ios_default(), row, dst="172.20.1.1")

    forward = result["forward"]
    assert "left_estate" not in forward["legs"][0] and forward["reach"] is None
    assert forward["warnings"][-1] == _private_warning("172.20.1.1", "0.0.0.0/0")
    assert result["reply"]["verdict"] == "reply not derived: the forward leg never confirmed delivery"


@pytest.mark.parametrize("basis", ["site-zone", "wan-link"])
def test_a_unique_local_ipv6_address_no_device_serves_is_no_exit(graph, basis):
    _egress, row = NEXT_HOP_BASES[basis]
    _estate(graph, ESTATE)
    routes = [_route("::/0", egress="Gi0/0/0", next_hop="2001:db8:18::1"), LAN6]
    result = _edge(graph, routes, row, src="fd00::5", dst="fd12:3456::9", gw=GW6)

    forward = result["forward"]
    assert "left_estate" not in forward["legs"][0] and forward["reach"] is None
    assert forward["warnings"][-1] == _private_warning("fd12:3456::9", "::/0", src="fd00::5")


@pytest.mark.parametrize("basis", sorted(NEXT_HOP_BASES))
def test_a_public_address_another_device_routes_is_no_exit(graph, basis):
    """r2 has a static 203.0.113.0/26 (a partner's network): the estate routes 203.0.113.9 by
    another device, so r1's default route to it is a route missing on r1, not the internet."""
    _egress, row = NEXT_HOP_BASES[basis]
    _estate(graph, ESTATE, routed=["0.0.0.0/0", "203.0.113.0/26"])
    result = _edge(graph, _ios_default(), row, dst="203.0.113.9")

    forward = result["forward"]
    assert "left_estate" not in forward["legs"][0] and forward["reach"] is None
    assert forward["warnings"][-1] == (
        "10.0.0.5: another device of the estate has a route to the destination 203.0.113.9, and r1 has no "
        "route to it other than the default route 0.0.0.0/0 by Gi0/0/0"
    )
    # one bounded read: the distinct network keys of the 33 prefix lengths over 203.0.113.9
    # (an exact index seek), and the address itself as the range
    (spans,) = graph.routed_reads
    assert len(spans) == 1 and spans[0]["lo"] == spans[0]["hi"] == "4:cb007109"
    assert {"4:00000000", "4:cb007100", "4:cb007109"} <= set(spans[0]["covering"])
    assert len(spans[0]["covering"]) <= 33


def test_a_public_address_outside_every_route_leaves_by_the_edge(graph):
    _estate(graph, ESTATE, routed=["0.0.0.0/0", "203.0.113.0/26"])
    result = _edge(graph, _ios_default(), _row(zone="internet"))

    assert result["forward"]["legs"][0]["left_estate"] == ZONE_EXIT
    assert result["forward"]["reach"] == "left_estate"


def test_the_private_and_routed_warnings_use_only_result_words():
    from hst.results.words import FORBIDDEN_WORDS, _contains_word

    sentences = [
        _private_warning("172.20.1.1", "0.0.0.0/0"),
        "10.0.0.5: another device of the estate has a route to the destination 203.0.113.9, and r1 has no "
        "route to it other than the default route 0.0.0.0/0 by Gi0/0/0",
    ]
    for sentence in sentences:
        assert not [w for w in FORBIDDEN_WORDS if _contains_word(sentence.lower(), w)], sentence


# --- an uplink's provider prefix is not the estate's ---------------------------------------------


def _served(cidr, if_uid, **facts):
    """One served-prefix row of `_ESTATE_PREFIXES_QUERY`: the interface's edge facts."""
    return {
        "cidr": cidr,
        "if_uid": if_uid,
        "if_name": if_uid.rsplit(":", 1)[-1],
        "default_origin": facts.get("origin"),
        "link_kinds": facts.get("links", []),
        "site_zone": facts.get("zone"),
        "defaults": facts.get("defaults", []),
    }


# Two collected sites with DHCP uplinks: r1 (site A) leases in 203.0.113.0/24 behind a WAN link;
# r2 (site B) leases in 198.51.100.0/24 by its access client. Each uplink's subnet has GATEWAY_FOR
# (the reasoner's gateway-from-router-interface rule) and a connected route on its router.
TWO_SITES = [
    "10.0.0.0/24",
    "10.1.0.0/24",
    _served(
        "203.0.113.0/24",
        "if:r1:eth0",
        links=["dia"],
        defaults=[{"cidr": "0.0.0.0/0", "next_hop": "203.0.113.1"}],
    ),
    _served(
        "198.51.100.0/24",
        "if:r2:eth0",
        origin="dhcp",
        defaults=[{"cidr": "0.0.0.0/0", "next_hop": "198.51.100.1"}],
    ),
]
TWO_SITES_ROUTED = [
    ("203.0.113.0/24", ["dev:r1"]),
    ("198.51.100.0/24", ["dev:r2"]),
    ("10.1.0.0/24", ["dev:r2"]),
]


def _to_site_b(graph, estate):
    """A host at site A to site B's public address 198.51.100.7 (a port forward on r2)."""
    if estate:
        _estate(graph, TWO_SITES, routed=TWO_SITES_ROUTED)
    routes = [_route("0.0.0.0/0", egress="eth0", next_hop="203.0.113.1"), LAN]
    return _edge(graph, routes, _row(link="wan:r1:eth0", kind="dia"), egress="eth0")


def test_a_flow_to_another_collected_sites_public_address_leaves_by_the_wan_link(graph):
    """B's public address is in B's provider subnet, which r2's uplink serves."""
    from tests.test_path_trace import FakeGraph

    result = _to_site_b(graph, estate=True)
    forward = result["forward"]
    assert forward["legs"][0]["left_estate"]["basis"] == "wan-link"
    assert forward["reach"] == "left_estate" and forward["warnings"] == []
    assert not result["reply"]["verdict"].startswith("reply not derived")
    graph.__dict__.clear()
    graph.__dict__.update(FakeGraph().__dict__)
    assert result == _to_site_b(graph, estate=False)


def _tunnel_to_site_b(graph, estate):
    """A WireGuard tunnel from r1 to site B's public address 198.51.100.9; the carrier leaves by
    r1's uplink Gi0/0/0 (a WAN link) to the provider's gateway 203.0.113.1."""
    if estate:
        _estate(graph, TWO_SITES, routed=TWO_SITES_ROUTED)
    graph.sources = [_src_row()]
    graph.routes = {
        "vrf:main": [_route("0.0.0.0/0", egress="wg0")],
        "vrf:wan": [_route("0.0.0.0/0", egress="Gi0/0/0", next_hop="203.0.113.1")],
    }
    graph.local_vrf = {"vrf_uid": "vrf:wan", "vrf_name": "default"}
    graph.iface_addrs = {"if:Gi0/0/0": "203.0.113.2"}
    _tunnel(graph, endpoint="198.51.100.9")
    _uplinks(graph, {"if:Gi0/0/0": _row(link="wan:r1:gi0", kind="dia")})
    return path.trace(None, "10.0.0.5", "10.1.0.5", port=443, proto="tcp", gateways=[GW])


def test_a_tunnel_between_two_collected_dhcp_sites_reads_as_with_no_estate_rows(graph):
    from tests.test_path_trace import FakeGraph

    result = _tunnel_to_site_b(graph, estate=True)
    carrier = result["legs"][0]["carrier"]
    assert result["warnings"] == []
    assert "us-streaming: carrier next hop 203.0.113.1 is beyond the collected uplink DIA" in result["notes"]
    assert carrier["left_estate"]["basis"] == "wan-link"
    graph.__dict__.clear()
    graph.__dict__.update(FakeGraph().__dict__)
    assert result == _tunnel_to_site_b(graph, estate=False)


V4_DEFAULT = {"cidr": "0.0.0.0/0", "next_hop": "198.51.100.1", "interface": None}
V6_DEFAULT = {"cidr": "::/0", "next_hop": "2001:db8:51::1", "interface": None}


@pytest.mark.parametrize(
    ("row", "uplink"),
    [
        (_served("198.51.100.0/24", "if:r2:eth0", links=["dia"], defaults=[V4_DEFAULT]), True),
        # no default route of the device is known (a side-store-only table): the WAN link decides
        (_served("198.51.100.0/24", "if:r2:eth0", links=["dia"]), True),
        (_served("198.51.100.0/24", "if:r2:eth0", links=["mpls"], defaults=[V4_DEFAULT]), False),
        # the first link by uid counts, as the exit rule reads it
        (_served("198.51.100.0/24", "if:r2:eth0", links=["mpls", "dia"], defaults=[V4_DEFAULT]), False),
        (_served("198.51.100.0/24", "if:r2:eth0", origin="dhcp", defaults=[V4_DEFAULT]), True),
        # the access client's mark is itself an IPv4 default by the interface: an uplink for its
        # prefixes of both families, whatever default of another family the graph has
        (_served("2001:db8:51::/64", "if:r2:eth0", origin="dhcp", defaults=[V6_DEFAULT]), True),
        (_served("198.51.100.0/24", "if:r2:Gi0", zone="internet", defaults=[V4_DEFAULT]), True),
        (
            _served(
                "198.51.100.0/24",
                "if:r2:Gi0",
                zone="internet",
                defaults=[{"cidr": "0.0.0.0/0", "next_hop": None, "interface": "Gi0"}],
            ),
            True,
        ),
        (
            _served(
                "10.1.0.0/24",
                "if:r2:Gi1",
                zone="internet",
                defaults=[{"cidr": "0.0.0.0/0", "next_hop": "198.51.100.1", "interface": "Gi0"}],
            ),
            False,
        ),
        (_served("198.51.100.0/24", "if:r2:Gi0", zone="external", defaults=[V4_DEFAULT]), False),
        (_served("10.1.0.0/24", "if:r2:eth1"), False),
        # an MPLS link outranks the zone, as `_site_zone_exit` reads it
        (
            _served("198.51.100.0/24", "if:r2:Gi0", zone="internet", links=["mpls"], defaults=[V4_DEFAULT]),
            False,
        ),
        # a next hop a collected interface has is no exit, so no uplink
        (
            _served("198.51.100.0/24", "if:r2:Gi0", zone="internet", defaults=[{**V4_DEFAULT, "held": True}]),
            False,
        ),
        (
            _served("198.51.100.0/24", "if:r2:eth0", links=["dia"], defaults=[{**V4_DEFAULT, "held": True}]),
            False,
        ),
        # a link-local next hop that no interface on the link has is the provider's router
        (
            _served(
                "169.254.0.0/16",
                "if:r2:Gi0",
                zone="internet",
                defaults=[{"cidr": "0.0.0.0/0", "next_hop": "169.254.0.1"}],
            ),
            True,
        ),
    ],
    ids=[
        "wan-link",
        "wan-link-no-default",
        "mpls",
        "mpls-first",
        "access-client",
        "access-client-ipv6",
        "zone-next-hop",
        "zone-interface",
        "zone-lan",
        "external",
        "lan",
        "zone-mpls",
        "zone-held-next-hop",
        "wan-link-held-next-hop",
        "zone-link-local",
    ],
)
def test_an_interface_is_an_uplink_by_the_tracers_own_rule(row, uplink):
    assert tracemod._uplink_interface(row) is uplink


def test_the_shared_rule_leaves_the_uplinks_out_of_served_and_routed_but_not_out_of_private_space():
    from hst.path.addrsets import _intervals, _merge

    private = list(tracemod.NOT_INTERNET)
    held = tracemod.estate_prefixes(
        ["198.51.100.0/24", "10.1.0.0/24", "100.64.0.0/22"],
        routed=["198.51.100.0/24", "203.0.113.0/26"],
        uplinks=["198.51.100.0/24", "100.64.0.0/22"],
    )
    assert held == tuple(_merge(_intervals(["10.1.0.0/24", "203.0.113.0/26", *private])))


def test_a_route_in_another_table_of_the_same_device_is_named_as_a_device_of_the_estate(graph):
    """r1's policy table routes 203.0.113.0/26: the estate has a route, on r1 itself."""
    _estate(graph, ESTATE, routed=[("203.0.113.0/26", ["dev:r1"])])
    result = _edge(graph, _ios_default(), _row(zone="internet"), dst="203.0.113.9")

    forward = result["forward"]
    assert "left_estate" not in forward["legs"][0] and forward["reach"] is None
    assert forward["warnings"][-1] == (
        "10.0.0.5: a device of the estate has a route to the destination 203.0.113.9, and r1 has no "
        "route to it other than the default route 0.0.0.0/0 by Gi0/0/0"
    )


def test_the_uplink_decision_and_the_exit_rule_agree_on_every_case():
    """One predicate: for each fact shape, `_uplink_interface` sees an uplink exactly when
    `exit_basis` names a basis for its default route, or for the access client's own IPv4
    default that the mark states (a next hop, by the interface)."""
    for links in ([], ["dia"], ["mpls"], ["mpls", "dia"], ["dia", "mpls"]):
        for origin in (None, "dhcp"):
            for zone in (None, "external", "internet"):
                for hop in ("198.51.100.1", None):
                    for cidr, af in (("0.0.0.0/0", 4), ("::/0", 6)):
                        default = {"cidr": cidr, "next_hop": hop, "interface": "Gi0"}
                        row = _served("198.51.100.0/24", "if:r2:Gi0", links=links, origin=origin, zone=zone)
                        row["defaults"] = [default]
                        basis = tracemod.exit_basis(
                            link_kinds=links,
                            default_origin=origin,
                            site_zone=zone,
                            family=af,
                            next_hop=bool(hop),
                        )
                        client = tracemod.exit_basis(
                            link_kinds=links, default_origin=origin, site_zone=zone, family=4, next_hop=True
                        )
                        expected = basis is not None or (bool(origin) and client is not None)
                        assert tracemod._uplink_interface(row) is expected, (
                            links,
                            origin,
                            zone,
                            hop,
                            cidr,
                        )


def test_the_hubs_mpls_pe_ce_address_is_the_estates_not_an_internet_exit(graph):
    """The hub's default route points at the PE (62.1.1.1, in the PE-CE /30)."""
    hub = _served(
        "62.1.1.0/30",
        "if:hub:Gi0/1",
        links=["mpls"],
        zone="internet",
        defaults=[
            {"cidr": "0.0.0.0/0", "next_hop": "62.1.1.1"},
            {"cidr": "0.0.0.0/0", "next_hop": "203.0.113.1"},
        ],
    )
    assert tracemod._uplink_interface(hub) is False
    _estate(graph, [*ESTATE, hub])
    result = _edge(graph, _ios_default(), _row(zone="internet"), dst="62.1.1.1")

    forward = result["forward"]
    assert "left_estate" not in forward["legs"][0] and forward["reach"] is None
    assert forward["warnings"][-1] == _estate_warning("62.1.1.1", "0.0.0.0/0")
    assert result["reply"]["verdict"] == "reply not derived: the forward leg never confirmed delivery"


def test_a_prefix_whose_default_next_hop_a_collected_interface_has_stays_the_estates(graph):
    """r2's Gi0 is in zone internet, but its default route goes to 62.2.2.1, which another
    collected interface has: no exit by Gi0, so 62.2.2.0/29 is the estate's."""
    r2 = _served(
        "62.2.2.0/29",
        "if:r2:Gi0",
        zone="internet",
        defaults=[{"cidr": "0.0.0.0/0", "next_hop": "62.2.2.1", "held": True}],
    )
    _estate(graph, [*ESTATE, r2])
    result = _edge(graph, _ios_default(), _row(zone="internet"), dst="62.2.2.5")

    forward = result["forward"]
    assert "left_estate" not in forward["legs"][0] and forward["reach"] is None
    assert forward["warnings"][-1] == _estate_warning("62.2.2.5", "0.0.0.0/0")


# --- the uplink decision: every table of the device, per interface, link-local -------------------


def _iface(if_name, cidrs, **facts):
    """One interface's row for `_uplink_interface`, all its served prefixes at once."""
    row = _served(cidrs[0], f"if:r1:{if_name}", **facts)
    row["if_name"] = if_name
    row["cidrs"] = list(cidrs)
    return row


PPPOE_V4 = {"cidr": "0.0.0.0/0", "next_hop": None, "interface": "pppoe0"}
PPPOE_V6 = {"cidr": "::/0", "next_hop": "fe80::1", "interface": "pppoe0", "held": False}


@pytest.mark.parametrize(
    ("row", "uplink"),
    [
        # a default only in a policy table of the device (OWNED_BY, no interface in it) is read
        (
            _iface(
                "eth1",
                ["84.10.0.8/29"],
                links=["static"],
                defaults=[{"cidr": "0.0.0.0/0", "next_hop": "84.10.0.9"}],
            ),
            True,
        ),
        # a standby uplink whose default (a higher distance) is in the graph
        (
            _iface(
                "eth1",
                ["192.0.2.0/29"],
                links=["dia"],
                defaults=[
                    {"cidr": "0.0.0.0/0", "next_hop": "203.0.113.1", "interface": "eth0"},
                    {"cidr": "0.0.0.0/0", "next_hop": "192.0.2.1", "interface": "eth1"},
                ],
            ),
            True,
        ),
        # a second WAN link by which no default route of the device leaves
        (
            _iface(
                "eth1",
                ["192.0.2.0/29"],
                links=["dia"],
                defaults=[{"cidr": "0.0.0.0/0", "next_hop": "203.0.113.1", "interface": "eth0"}],
            ),
            False,
        ),
        # no default route of the device in the graph (a side-store-only table): link and mark decide
        (_iface("eth1", ["84.10.0.8/29"], links=["dia"]), True),
        (_iface("eth1", ["84.10.0.8/29"], origin="dhcp"), True),
        (_iface("eth1", ["84.10.0.8/29"], links=["mpls"]), False),
        (_iface("eth1", ["84.10.0.8/29"], zone="internet"), False),
        # a link-local IPv6 default on a WAN link, a marked interface, a zone-internet device
        (
            _iface("eth0", ["2001:db8:1::/64"], links=["dia"], defaults=[{**PPPOE_V6, "interface": "eth0"}]),
            True,
        ),
        (
            _iface("eth0", ["2001:db8:1::/64"], origin="dhcp", defaults=[{**PPPOE_V6, "interface": "eth0"}]),
            True,
        ),
        (
            _iface(
                "eth0", ["2001:db8:1::/64"], zone="internet", defaults=[{**PPPOE_V6, "interface": "eth0"}]
            ),
            True,
        ),
        # a link-local next hop an interface on the same link has is the estate's own router
        (
            _iface(
                "eth0",
                ["2001:db8:1::/64"],
                links=["dia"],
                defaults=[{**PPPOE_V6, "interface": "eth0", "held": True}],
            ),
            False,
        ),
        # the owner's router: PPPoE with a dia link, an IPv4 interface-only default and an IPv6
        # default by a link-local next hop; its prefixes of both families are the provider's
        (
            _iface(
                "pppoe0", ["100.64.5.1/32", "2001:db8:5::/64"], links=["dia"], defaults=[PPPOE_V4, PPPOE_V6]
            ),
            True,
        ),
        # either family makes the interface an uplink: the IPv4 default alone, by the served prefix
        (
            _iface(
                "eth0",
                ["198.51.100.0/24", "2001:db8:51::/64"],
                links=["dia"],
                defaults=[{"cidr": "0.0.0.0/0", "next_hop": "198.51.100.1"}],
            ),
            True,
        ),
    ],
    ids=[
        "policy-table-default",
        "standby-uplink",
        "second-link-no-default",
        "no-default-wan-link",
        "no-default-mark",
        "no-default-mpls",
        "no-default-zone-only",
        "link-local-wan-link",
        "link-local-mark",
        "link-local-zone",
        "link-local-on-link-held",
        "owner-pppoe",
        "either-family",
    ],
)
def test_an_interface_is_an_uplink_by_a_default_route_of_any_table_and_family(row, uplink):
    assert tracemod._uplink_interface(row) is uplink


def test_the_served_read_takes_the_defaults_of_every_table_of_the_device():
    """The policy tables a device OWNS have no interface IN_VRF to them; their defaults count."""
    query = tracemod._ESTATE_PREFIXES_QUERY
    # each device once, its tables found from it: its interfaces' tables and the ones it owns
    assert "MATCH (d:Device:Obj)\nWHERE d.collection_ts = $snap" in query
    assert "MATCH (d)<-[ow:OWNED_BY]-(v:VrfInstance)" in query
    assert "MATCH (d)<-[dv:ON]-(:Interface)-[iv:IN_VRF]->(v:VrfInstance)" in query
    # the default routes once, from the default prefixes by their indexed first address
    assert "dp.lo_key IN ['4:00000000', '6:" in query
    # a link-local next hop is held only by an interface on the egress interface's link
    assert "WHERE eg.name = x.interface AND ia.ip = x.next_hop" in query


def test_both_families_of_an_uplink_interface_are_the_providers(graph):
    """r2's eth0 is an uplink by its IPv4 default: its IPv6 /64 is the provider's too, so r1's
    internet edge sends 2001:db8:51::9 out of the estate, as an internet address."""
    eth0 = [
        _served(
            "198.51.100.0/24",
            "if:r2:eth0",
            links=["dia"],
            defaults=[{"cidr": "0.0.0.0/0", "next_hop": "198.51.100.1"}],
        ),
        _served(
            "2001:db8:51::/64",
            "if:r2:eth0",
            links=["dia"],
            defaults=[{"cidr": "0.0.0.0/0", "next_hop": "198.51.100.1"}],
        ),
    ]
    _estate(graph, [*ESTATE, *eth0], routed=[("2001:db8:51::/64", ["dev:r2"])])
    routes = [_route("::/0", egress="Gi0/0/0", next_hop="2001:db8:18::1"), LAN6]
    result = _edge(graph, routes, _row(zone="internet"), src="fd00::5", dst="2001:db8:51::9", gw=GW6)

    forward = result["forward"]
    assert forward["legs"][0]["left_estate"]["basis"] == "site-zone"
    assert forward["reach"] == "left_estate" and forward["warnings"] == []
