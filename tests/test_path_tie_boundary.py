import importlib

import pytest
from tests.test_impact_evaluate import Graph, _deny, _firewall
from tests.test_path_trace import GW, _route, _src_row

from hst import path
from hst.core.mtu import MtuRequest
from hst.path import mtu_topology
from hst.path.gates import _Trail

tracemod = importlib.import_module("hst.path.trace")

DST = "10.99.0.7"
PORT, PROTO = 443, "tcp"


@pytest.fixture()
def graph(monkeypatch):
    g = Graph()
    monkeypatch.setattr(path, "_read", lambda session, query, **p: g.read(query, **p))
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: g.read_one(query, **p))
    return g


def _qualified(result):
    return bool(result.get("indeterminate")) or any("tie" in w for w in result["warnings"])


def _verdicts(result):
    return sorted(ll["verdict"] for ll in result["legs"])


# --- the gateway tie ----------------------------------------------------------------------


def _gateway_tie(graph, permitting, denying):
    """Two gateways for the source prefix in one context: `permitting` accepts
    the flow by default action, `denying` drops it by rule."""
    graph.sources = [_src_row()]
    graph.routes = {"vrf:main": [_route("10.99.0.0/24", egress="eth0")]}
    _firewall(graph, permitting, f"rb:{permitting}", [], "accept")
    _firewall(graph, denying, f"rb:{denying}", [_deny(DST)], "accept")
    return [
        {**GW, "dev_uid": permitting, "dev_name": permitting, "if_uid": f"if:{permitting}"},
        {**GW, "dev_uid": denying, "dev_name": denying, "if_uid": f"if:{denying}"},
    ]


def test_a_gateway_tie_with_differing_outcomes_is_never_an_unqualified_answer(graph):
    first = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=_gateway_tie(graph, "dev:a", "dev:b"))
    second = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=_gateway_tie(graph, "dev:b", "dev:a"))

    assert not first["legs"][0]["blocked"] and second["legs"][0]["blocked"]
    assert _qualified(first) and _qualified(second)


def test_a_gateway_tie_with_equivalent_candidates_stays_determinate(graph):
    gws = _gateway_tie(graph, "dev:a", "dev:b")
    _firewall(graph, "dev:b", "rb:dev:b", [], "accept")

    first = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=gws)
    second = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=list(reversed(gws)))

    assert not first["indeterminate"] and not second["indeterminate"]
    assert _verdicts(first) == _verdicts(second)
    assert not first["legs"][0]["blocked"] and not second["legs"][0]["blocked"]


# --- the next-hop tie ---------------------------------------------------------------------


def _next_hop_tie(graph, permitting, denying):
    """r1 (the gateway) routes the destination via 10.0.12.2, which two
    devices hold in one forwarding context; each device serves the
    destination on a connected interface and carries its own rulebase."""
    graph.sources = [_src_row()]
    graph.default_tables = {GW["if_uid"]: {"uid": "vrf:r1"}}
    graph.routes = {"vrf:r1": [_route("10.99.0.0/24", egress="eth0", next_hop="10.0.12.2")]}
    graph.next_hop_devs = {"10.0.12.2": []}
    graph.contexts = {
        "vrf:r1": {"name": "default", "is_global": True},
        "vrf:pair": {"name": "default", "is_global": True},
    }
    for dev in (permitting, denying):
        graph.default_tables[f"if:{dev}-eth0"] = {"uid": f"vrf:{dev}"}
        graph.routes[f"vrf:{dev}"] = [_route("10.99.0.0/24", egress=f"{dev}-eth5")]
        graph.next_hop_devs["10.0.12.2"].append(
            {
                "dev_uid": dev,
                "dev_name": dev,
                "if_uid": f"if:{dev}-eth0",
                "if_name": "eth0",
                "anchor": "vrf:pair",
            }
        )
    _firewall(graph, permitting, f"rb:{permitting}", [], "accept")
    _firewall(graph, denying, f"rb:{denying}", [_deny(DST)], "accept")


def test_a_next_hop_tie_with_differing_outcomes_must_not_flip_an_unqualified_answer(graph):
    _next_hop_tie(graph, "dev:a", "dev:b")
    first = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=[GW])
    _next_hop_tie(graph, "dev:b", "dev:a")
    second = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=[GW])

    assert (_qualified(first) and _qualified(second)) or _verdicts(first) == _verdicts(second)


def test_a_next_hop_tie_with_differing_outcomes_names_the_tie(graph):
    _next_hop_tie(graph, "dev:a", "dev:b")
    first = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=[GW])
    _next_hop_tie(graph, "dev:b", "dev:a")
    second = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=[GW])

    assert not first["legs"][0]["blocked"] and second["legs"][0]["blocked"]
    for result in (first, second):
        assert any("2 interfaces hold next hop 10.0.12.2" in n for n in result["notes"])


def test_a_next_hop_tie_with_equivalent_candidates_stays_determinate(graph):
    _next_hop_tie(graph, "dev:a", "dev:b")
    _firewall(graph, "dev:b", "rb:dev:b", [], "accept")
    first = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=[GW])
    _next_hop_tie(graph, "dev:b", "dev:a")
    _firewall(graph, "dev:a", "rb:dev:a", [], "accept")
    second = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=[GW])

    assert not first["indeterminate"] and not second["indeterminate"]
    assert _verdicts(first) == _verdicts(second)
    assert not first["legs"][0]["blocked"] and not second["legs"][0]["blocked"]


_DIFFERENT = (
    "10.0.0.5: the trace through dev:b eth0 and the trace through dev:a eth0 answer differently "
    "for next hop 10.0.12.2, and no record names the device that forwards"
)


def test_a_next_hop_tie_with_differing_outcomes_is_indeterminate_in_both_uid_orders(graph):
    _next_hop_tie(graph, "dev:a", "dev:b")
    first = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=[GW])
    _next_hop_tie(graph, "dev:b", "dev:a")
    second = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=[GW])

    for result in (first, second):
        assert result["indeterminate"]
        assert [ll["indeterminate_reason"] for ll in result["legs"]] == [_DIFFERENT]
        assert _DIFFERENT in result["warnings"]


def test_a_next_hop_tie_draws_only_the_owner_with_the_lowest_uid(graph):
    _next_hop_tie(graph, "dev:a", "dev:b")
    result = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=[GW])

    devices = [h["label"] for h in result["hops"] if h["kind"] == "Device"]
    assert "dev:a" in devices and "dev:b" not in devices
    assert len(result["legs"]) == 1


def test_a_next_hop_tie_with_equivalent_candidates_adds_no_warning(graph):
    _next_hop_tie(graph, "dev:a", "dev:b")
    _firewall(graph, "dev:b", "rb:dev:b", [], "accept")
    result = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=[GW])

    assert not any("next hop 10.0.12.2" in w for w in result["warnings"])
    assert "indeterminate_reason" not in result["legs"][0]


def _third_owner(graph, dev):
    """`dev` holds the next hop of `_next_hop_tie` as well and accepts the flow."""
    graph.default_tables[f"if:{dev}-eth0"] = {"uid": f"vrf:{dev}"}
    graph.routes[f"vrf:{dev}"] = [_route("10.99.0.0/24", egress=f"{dev}-eth5")]
    graph.next_hop_devs["10.0.12.2"].append(
        {"dev_uid": dev, "dev_name": dev, "if_uid": f"if:{dev}-eth0", "if_name": "eth0", "anchor": "vrf:pair"}
    )
    _firewall(graph, dev, f"rb:{dev}", [], "accept")


def test_the_third_of_three_tied_owners_with_another_outcome_makes_the_answer_indeterminate(graph):
    _next_hop_tie(graph, "dev:a", "dev:c")
    _third_owner(graph, "dev:b")
    result = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=[GW])

    assert result["indeterminate"]
    assert (
        "the trace through dev:c eth0 and the trace through dev:a eth0 answer differently"
        in (result["legs"][0]["indeterminate_reason"])
    )


def test_three_tied_owners_with_one_outcome_stay_determinate(graph):
    _next_hop_tie(graph, "dev:a", "dev:c")
    _firewall(graph, "dev:c", "rb:dev:c", [], "accept")
    _third_owner(graph, "dev:b")
    result = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=[GW])

    assert not result["indeterminate"]
    assert any("3 interfaces hold next hop 10.0.12.2" in n for n in result["notes"])


def test_a_tied_owner_past_the_cap_makes_the_answer_indeterminate(graph, monkeypatch):
    monkeypatch.setattr(tracemod, "_TIE_PROBE_CAP", 0)
    _next_hop_tie(graph, "dev:a", "dev:b")
    _firewall(graph, "dev:b", "rb:dev:b", [], "accept")
    result = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=[GW])

    assert result["indeterminate"]
    assert result["legs"][0]["indeterminate_reason"] == (
        "10.0.0.5: the trace did not follow dev:b eth0 for next hop 10.0.12.2 after 0 tied next hops, "
        "and no record names the device that forwards"
    )


def test_a_tied_owner_is_walked_once_per_trace(graph, monkeypatch):
    _next_hop_tie(graph, "dev:a", "dev:b")
    _firewall(graph, "dev:b", "rb:dev:b", [], "accept")
    walked = []
    device_stage = tracemod._device_stage

    def counted(session, trail, gw, *args, **kwargs):
        walked.append(gw["dev_uid"])
        return device_stage(session, trail, gw, *args, **kwargs)

    monkeypatch.setattr(tracemod, "_device_stage", counted)
    path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=[GW])

    assert sorted(walked) == ["dev:a", "dev:b", GW["dev_uid"]]


def test_no_mtu_site_is_recorded_inside_not_capturing():
    capture = mtu_topology.Capture(MtuRequest(mode="inventory"), 4)
    token = mtu_topology._SCOPE.set(capture)
    try:
        with mtu_topology.not_capturing():
            assert not mtu_topology.capturing()
            mtu_topology.crossing(_Trail(), "if:x", enforcement="l3")
        assert mtu_topology.capturing()
    finally:
        mtu_topology._SCOPE.reset(token)

    assert capture.stages == []


def _second_tie(graph, permitting, denying):
    """Both owners of `_next_hop_tie` route the destination via 10.0.23.2, which
    two more devices hold in one forwarding context."""
    for dev in ("dev:a", "dev:b"):
        _firewall(graph, dev, f"rb:{dev}", [], "accept")
        graph.routes[f"vrf:{dev}"] = [_route("10.99.0.0/24", egress=f"{dev}-eth5", next_hop="10.0.23.2")]
        graph.contexts[f"vrf:{dev}"] = {"name": "default", "is_global": True}
    graph.contexts["vrf:pair2"] = {"name": "default", "is_global": True}
    graph.next_hop_devs["10.0.23.2"] = []
    for dev in (permitting, denying):
        graph.default_tables[f"if:{dev}-eth0"] = {"uid": f"vrf:{dev}"}
        graph.routes[f"vrf:{dev}"] = [_route("10.99.0.0/24", egress=f"{dev}-eth5")]
        graph.next_hop_devs["10.0.23.2"].append(
            {
                "dev_uid": dev,
                "dev_name": dev,
                "if_uid": f"if:{dev}-eth0",
                "if_name": "eth0",
                "anchor": "vrf:pair2",
            }
        )
    _firewall(graph, permitting, f"rb:{permitting}", [], "accept")
    _firewall(graph, denying, f"rb:{denying}", [_deny(DST)], "accept")


def test_two_ties_in_a_row_with_equivalent_candidates_stay_determinate(graph):
    _next_hop_tie(graph, "dev:a", "dev:b")
    _second_tie(graph, "dev:c", "dev:d")
    _firewall(graph, "dev:d", "rb:dev:d", [], "accept")
    result = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=[GW])

    assert not result["indeterminate"]
    assert result["legs"][0]["verdict"] == "egress via dev:c-eth5"
    assert [h["label"] for h in result["hops"] if h["kind"] == "Device"] == ["r1", "dev:a", "dev:c"]


def test_a_second_tie_with_differing_outcomes_is_indeterminate_in_both_uid_orders(graph):
    _next_hop_tie(graph, "dev:a", "dev:b")
    _second_tie(graph, "dev:c", "dev:d")
    first = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=[GW])
    _second_tie(graph, "dev:d", "dev:c")
    second = path.trace(None, "10.0.0.5", DST, PORT, PROTO, gateways=[GW])

    assert not first["legs"][0]["blocked"] and second["legs"][0]["blocked"]
    for result in (first, second):
        assert result["indeterminate"]
        assert (
            "the trace through dev:d eth0 and the trace through dev:c eth0 answer differently"
            in (result["legs"][0]["indeterminate_reason"])
        )
