"""Where the tracer reads a route as the estate's edge (`path.trace.estate_exit`), the part is
forwarded out of the estate and passes (`HOLDS`)."""

# ruff: noqa: F811

import importlib
from dataclasses import replace

import pytest
from tests import test_impact_evaluate as estate
from tests.test_impact_evaluate import graph  # noqa: F401

from hst.assessment import evaluation, package
from hst.path.gates import sdwan

ev = estate.ev
tracemod = importlib.import_module("hst.path.trace")
fw_overlay_read = importlib.import_module("hst.app.fw_overlay_read")

INTERNET = "198.51.100.7"
NEXT_HOP = estate._static("0.0.0.0/0", "192.0.2.2")
IFACE_ONLY = {**estate._static("0.0.0.0/0", None), "interface": "eth3"}
WAN_IF = "if:r1-eth3"


def _row(zone=None, block="dc-edge", link=None, kind=None, origin=None):
    """The tracer's uplink read for the egress interface: its marks and its
    device's site zone stamp."""
    return {
        "default_origin": origin,
        "link_uid": link,
        "link_name": "MPLS" if kind == "mpls" else ("DIA" if link else None),
        "link_kind": kind,
        "site_zone": zone,
        "site_block": block if zone else None,
    }


def _answers(graph, uplink=None, boundary=None):
    """Answer the tracer's uplink read, the device's name and the SD-WAN boundary read."""
    read_one = graph.read_one

    def answer(query, **params):
        if query == tracemod._EGRESS_UPLINK_QUERY:
            return uplink if params.get("u") == WAN_IF else None
        if query == ev._DEVICE_NAME_QUERY:
            return {"name": "r1"} if params.get("dev") == estate.R1 else None
        if query == sdwan._BOUNDARY_QUERY:
            return boundary
        return read_one(query, **params)

    graph.read_one = answer


def _network(static, extra=()):
    """The estate with a WAN interface eth3 on r1; `extra` adds a far LAN
    (prefixes the estate holds on another device, with no route on r1)."""
    inp = estate._routing(bgp=False, static=[static])
    inp = replace(inp, connected=[*inp.connected, estate._connected(estate.VRF_R1, "192.0.2.0/30", "eth3")])
    wan = ev.Interface(estate.R1, WAN_IF, "eth3", estate.VRF_R1, ("192.0.2.0/30",), ("192.0.2.1",))
    far = tuple(
        ev.Interface(estate.B, f"if:b-far{n}", f"far{n}", estate.VRF_B, (prefix,), ())
        for n, prefix in enumerate(extra)
    )
    return estate._network(routing=inp, interfaces=(*estate._interfaces(), wan, *far))


def _answer(static, success="forward"):
    return ev.answer(_network(static), replace(estate._request(dst=INTERNET), success=success))


def _exit(basis, next_hop="192.0.2.2", link=None, block=None):
    return {
        "basis": basis,
        "device_uid": estate.R1,
        "device": "r1",
        "interface_uid": WAN_IF,
        "interface": "eth3",
        "next_hop": next_hop,
        "wan_link_uid": "wan:1" if link else None,
        "wan_link": link,
        "site_block": block,
    }


def _terminal(answer):
    explanation = estate._only(answer)
    return explanation, explanation.steps[-1]


def _shape(answer):
    """Everything of an answer apart from the `left_estate` step key."""
    out = []
    for name, member in answer.members.items():
        for e in member.explanations:
            steps = [
                (
                    s.device_uid,
                    s.stage,
                    s.kind,
                    s.detail,
                    s.unknown,
                    {k: v for k, v in s.data.items() if k != "left_estate"},
                )
                for s in e.steps
            ]
            out.append((name, e.outcome, e.request, tuple(steps), e.missing))
    return answer.lower, answer.upper, out


# --- the walk ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("static", "uplink", "wan", "expected"),
    [
        pytest.param(
            NEXT_HOP, _row(link="wan:1", kind="dia"), None, _exit("wan-link", link="DIA"), id="wan-link"
        ),
        pytest.param(NEXT_HOP, _row(origin=True), None, _exit("access-client-default"), id="access-default"),
        pytest.param(
            NEXT_HOP, _row(zone="internet"), None, _exit("site-zone", block="dc-edge"), id="zone-next-hop"
        ),
        pytest.param(
            IFACE_ONLY,
            None,
            {"uid": "wan:1", "name": "DIA", "kind": "dia"},
            _exit("wan-link", next_hop=None, link="DIA"),
            id="iface-only-wan-link",
        ),
        pytest.param(
            IFACE_ONLY,
            _row(zone="internet"),
            None,
            _exit("site-zone", next_hop=None, block="dc-edge"),
            id="zone-iface",
        ),
    ],
)
def test_an_edge_the_tracer_reads_passes_with_its_marker(graph, static, uplink, wan, expected):
    _answers(graph)
    graph.wan = None
    plain = _answer(static)
    _answers(graph, uplink)
    graph.wan = wan
    marked = _answer(static)

    explanation, step = _terminal(marked)
    assert explanation.outcome == ev.HOLDS
    assert (step.stage, step.kind) == ("forwarding", "left-estate")
    assert step.data["left_estate"] == expected
    assert explanation.missing == ()
    assert marked.lower and marked.lower == marked.upper
    # with no recognized edge the same route is not decided
    assert _terminal(plain)[0].outcome == ev.NOT_ESTABLISHED
    assert "left_estate" not in _terminal(plain)[1].data


@pytest.mark.parametrize("static", [NEXT_HOP, IFACE_ONLY], ids=["next-hop", "iface-only"])
def test_a_destination_the_estate_holds_is_no_internet_and_stays_undecided(graph, static):
    """A destination inside a prefix an interface of the estate serves, that
    this device sends by its default route, is a route missing here."""
    _answers(graph, _row(zone="internet"))
    answer = ev.answer(_network(static), estate._request(dst="198.18.0.1"))
    held = ev.answer(_network(static, extra=("198.18.0.0/24",)), estate._request(dst="198.18.0.1"))
    assert _terminal(answer)[0].outcome == ev.HOLDS
    explanation, step = _terminal(held)
    assert explanation.outcome == ev.NOT_ESTABLISHED
    assert step.kind in ("unowned", "beyond-interface")
    assert "left_estate" not in step.data


@pytest.mark.parametrize(
    ("static", "uplink", "boundary"),
    [
        pytest.param(NEXT_HOP, None, None, id="no-mark"),
        pytest.param(NEXT_HOP, _row(zone="external"), None, id="zone-external"),
        pytest.param(NEXT_HOP, _row(zone="internal"), None, id="zone-internal"),
        pytest.param(
            NEXT_HOP, _row(zone="internet", link="wan:m", kind="mpls"), None, id="mpls-outranks-zone"
        ),
        pytest.param(NEXT_HOP, _row(link="wan:m", kind="mpls"), None, id="mpls"),
        pytest.param(IFACE_ONLY, _row(zone="external"), None, id="iface-zone-external"),
        pytest.param(IFACE_ONLY, _row(origin=True), None, id="iface-access-origin"),
        pytest.param(NEXT_HOP, _row(link="wan:1", kind="dia"), {"boundary_uid": "fb:1"}, id="sdwan-edge"),
    ],
)
def test_any_other_end_reads_as_an_unmarked_end(graph, static, uplink, boundary):
    _answers(graph)
    graph.wan = None
    plain = _answer(static)
    _answers(graph, uplink, boundary)
    marked = _answer(static)

    assert _terminal(marked)[1].data == _terminal(plain)[1].data
    assert _shape(marked) == _shape(plain)


def test_a_next_hop_the_graph_holds_is_no_edge_even_when_the_model_lacks_it(graph):
    """The tracer's own owner read decides, not the model's interface list:
    a collected device the model left out is not "outside the estate"."""
    _answers(graph, _row(link="wan:1", kind="dia"))
    graph.next_hop_devs["192.0.2.2"] = {
        "dev_uid": "dev:isp-ce",
        "dev_name": "ce",
        "if_uid": "if:ce-0",
        "if_name": "ge0",
        "l3dom": None,
        "anchor": estate.VRF_R1,
    }
    explanation, step = _terminal(_answer(NEXT_HOP))

    assert explanation.outcome == ev.NOT_ESTABLISHED
    assert step.kind == "unowned"
    assert "left_estate" not in step.data


def test_an_unheld_link_local_next_hop_is_no_edge(graph):
    """The tracer reads a link-local next hop no collected interface on the
    egress link holds as undecided, not as the estate's edge."""
    _answers(graph, _row(link="wan:1", kind="dia"))
    found = tracemod.estate_exit(
        None,
        device_uid=estate.R1,
        device_name="r1",
        table_uid=estate.VRF_R1,
        route={"cidr": "::/0", "next_hop": "fe80::1", "kind": "FIB"},
        egress_uid=WAN_IF,
        egress_name="eth3",
    )
    assert found is None
    # the same route to a global next hop is the edge
    assert tracemod.estate_exit(
        None,
        device_uid=estate.R1,
        device_name="r1",
        table_uid=estate.VRF_R1,
        route={"cidr": "::/0", "next_hop": "2001:db8::1", "kind": "FIB"},
        egress_uid=WAN_IF,
        egress_name="eth3",
    ) == {**_exit("wan-link", link="DIA"), "next_hop": "2001:db8::1"}


def test_both_sides_of_a_change_name_the_edge_and_the_comparison_is_unchanged(graph):
    """The after side reads through the change set's overlay session; the
    marker reaches it, and the comparison is that of an unmarked run."""
    request = estate._request(dst=INTERNET)
    _answers(graph)
    plain = ev.evaluate(_network(NEXT_HOP), estate._changes(), request)
    _answers(graph, _row(link="wan:1", kind="dia"))
    marked = ev.evaluate(_network(NEXT_HOP), estate._changes(), request)

    for side in (marked.before, marked.after):
        assert _terminal(side)[1].data["left_estate"] == _exit("wan-link", link="DIA")
        assert _terminal(side)[0].outcome == ev.HOLDS
    # both sides pass at the edge: the change gains and loses nothing
    assert not (marked.proven_loss or marked.possible_loss or marked.proven_gain or marked.possible_gain)
    assert _shape(marked.after) == _shape(marked.before)
    assert _terminal(plain.after)[0].outcome == ev.NOT_ESTABLISHED


def test_a_destination_inside_the_estate_keeps_its_proof(graph):
    _answers(graph, _row(zone="internet"))
    answer = ev.answer(estate._network(), estate._request())

    explanation = estate._only(answer)
    assert explanation.outcome == ev.HOLDS
    assert not any("left_estate" in s.data for s in explanation.steps)


@pytest.mark.parametrize("static", [NEXT_HOP, IFACE_ONLY], ids=["next-hop", "iface-only"])
def test_a_round_trip_walks_its_reply_from_the_edge_and_names_it(graph, static):
    """The reply starts on the egress interface, as at an interface-only
    delivery, and is walked back; the forward step names the edge."""
    _answers(graph, _row(zone="internet"))
    answer = _answer(static, success="round-trip")

    explanations = answer.members["app"].explanations
    assert explanations and all(e.outcome == ev.HOLDS for e in explanations)
    for e in explanations:
        edge = [i for i, s in enumerate(e.steps) if "left_estate" in s.data]
        assert [e.steps[i].kind for i in edge] == ["left-estate"]
        # the reply was walked after the edge, not assumed
        assert len(e.steps) > edge[0] + 1


# --- the row -----------------------------------------------------------------------------


def test_the_row_carries_the_exits_and_one_sentence(graph):
    _answers(graph, _row(zone="internet"))
    row = evaluation._evidence(_answer(NEXT_HOP), "before")[0]

    assert row["outcome"] == ev.HOLDS
    assert row["left_estate"] == [_exit("site-zone", block="dc-edge")]
    assert row["left_estate_note"] == (
        "the last hop is outside the estate: r1 eth3 to next hop 192.0.2.2 "
        '(the operator\'s site zone "internet" of block dc-edge)'
    )
    assert row["missing"] == []


@pytest.mark.parametrize(
    ("uplink", "wan", "static", "words"),
    [
        (
            _row(link="wan:1", kind="dia"),
            None,
            NEXT_HOP,
            "r1 eth3 to next hop 192.0.2.2 (a collected WAN link DIA)",
        ),
        (_row(origin=True), None, NEXT_HOP, "r1 eth3 to next hop 192.0.2.2 (the access client's default)"),
        (
            None,
            {"uid": "wan:1", "name": "DIA", "kind": "dia"},
            IFACE_ONLY,
            "r1 eth3 with no next hop (a collected WAN link DIA)",
        ),
    ],
)
def test_the_sentence_names_each_basis(graph, uplink, wan, static, words):
    _answers(graph, uplink)
    graph.wan = wan
    row = evaluation._evidence(_answer(static), "after")[0]

    assert row["left_estate_note"] == f"the last hop is outside the estate: {words}"


def test_a_row_with_no_edge_has_neither_key(graph):
    _answers(graph)
    rows = evaluation._evidence(_answer(NEXT_HOP), "before") + evaluation._evidence(
        ev.answer(estate._network(), estate._request()), "after"
    )

    assert rows
    assert not any({"left_estate", "left_estate_note"} & set(row) for row in rows)


# --- stored rows -------------------------------------------------------------------------


def test_a_replay_does_not_read_the_left_estate_keys_on_one_side_alone_as_a_change():
    stored = {"evidence": {"items": [{"outcome": "not-established", "missing": ["x"]}]}}
    replayed = {
        "evidence": {
            "items": [
                {
                    "outcome": "not-established",
                    "missing": ["x"],
                    "left_estate": [_exit("wan-link", link="DIA")],
                    "left_estate_note": "the last hop is outside the estate: r1 eth3",
                }
            ]
        }
    }

    left, right = package._align(stored, replayed)
    assert left == right == stored
    # the same keys on both sides are compared as they are
    other = {"evidence": {"items": [{**replayed["evidence"]["items"][0], "left_estate": []}]}}
    left, right = package._align(replayed, other)
    assert left != right
    # and the answer itself still counts
    changed = {"evidence": {"items": [{**replayed["evidence"]["items"][0], "outcome": "holds"}]}}
    left, right = package._align(stored, changed)
    assert left != right


# --- change simulation -------------------------------------------------------------------


def test_a_flow_side_passes_where_the_trace_ends(monkeypatch):
    exits = [_exit("wan-link", link="DIA")]
    trace = {"verdict": "forwarded", "legs": [], "warnings": [], "reach": "left_estate", "left_estate": exits}

    side = fw_overlay_read._flow_summary(trace)
    assert side["reach"] == "left_estate"
    assert side["left_estate"] == exits

    old = {k: v for k, v in trace.items() if k not in ("reach", "left_estate")}
    before = fw_overlay_read._flow_summary(old)
    assert set(side) - set(before) == {"reach", "left_estate"}
    assert {k: v for k, v in side.items() if k not in ("reach", "left_estate")} == before
