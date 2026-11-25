"""The next-hop pick over a first-hop redundancy group: the members hold one
virtual address in one context each (a Cisco member anchors its addresses on
its own VrfInstance), and the `HAS_IP` edge marks carry the protocol, the
group and the member's state. Same seams as test_path_multihop."""

# ruff: noqa: F811

from tests.test_path_multihop import R2_IF, _two_routers
from tests.test_path_trace import GW, graph  # noqa: F401

from hst import path

# The member that sorts last by uid is the one forwarding.
STANDBY = {**R2_IF, "anchor": "vrf:r2", "fhrp": "hsrp", "fhrp_group": 20, "fhrp_state": "standby"}
ACTIVE = {
    "dev_uid": "dev:zz-r2b",
    "dev_name": "r2b",
    "if_uid": "if:r2b-e0",
    "if_name": "r2b-e0",
    "anchor": "vrf:r2b",
    "fhrp": "hsrp",
    "fhrp_group": 20,
    "fhrp_state": "active",
}


def _pair(graph, *rows):
    _two_routers(graph)
    graph.default_tables["if:r2b-e0"] = {"uid": "vrf:r2b"}
    graph.contexts["vrf:r2b"] = {"name": "default", "is_global": True}
    graph.routes["vrf:r2b"] = [
        dict(r, egress_uid="if:r2b-eth5", egress_name="r2b-eth5") for r in graph.routes["vrf:r2"]
    ]
    graph.next_hop_devs["10.0.12.2"] = list(rows)


def test_the_active_member_is_traced_and_the_note_names_the_basis(graph):
    _pair(graph, STANDBY, ACTIVE)
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    assert not result.get("indeterminate")
    kinds = [(h["kind"], h["label"]) for h in result["hops"]]
    assert ("Device", "r2b") in kinds
    assert ("Device", "r2") not in kinds
    assert any("2 interfaces hold next hop 10.0.12.2 in one hsrp group 20" in n for n in result["notes"])
    assert any("traced via r2b r2b-e0 (hsrp active member)" in n for n in result["notes"])


def test_the_vrrp_master_is_the_forwarding_member(graph):
    _pair(
        graph,
        {**STANDBY, "fhrp": "vrrp", "fhrp_state": "backup"},
        {**ACTIVE, "fhrp": "vrrp", "fhrp_state": "master"},
    )
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    kinds = [(h["kind"], h["label"]) for h in result["hops"]]
    assert ("Device", "r2b") in kinds
    assert any("(vrrp master member)" in n for n in result["notes"])


def test_the_pick_does_not_depend_on_row_order(graph):
    _pair(graph, ACTIVE, STANDBY)
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    assert ("Device", "r2b") in [(h["kind"], h["label"]) for h in result["hops"]]


def test_without_a_recorded_state_the_lowest_uid_answers(graph):
    _pair(graph, {**STANDBY, "fhrp_state": None}, {**ACTIVE, "fhrp_state": None})
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    assert not result.get("indeterminate")
    kinds = [(h["kind"], h["label"]) for h in result["hops"]]
    assert ("Device", "r2") in kinds
    assert any("traced via r2 r2-eth0 (lowest uid)" in n for n in result["notes"])


def test_two_members_both_claiming_the_active_role_fail_closed(graph):
    """Two active members of one group number on one address are two folded groups."""
    _pair(graph, {**STANDBY, "fhrp_state": "active"}, ACTIVE)
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    assert result["indeterminate"]
    assert any("next hop 10.0.12.2 is owned in 2 forwarding contexts" in w for w in result["warnings"])
    kinds = [(h["kind"], h["label"]) for h in result["hops"]]
    assert ("Device", "r2b") not in kinds and ("Device", "r2") not in kinds


def test_rows_of_different_groups_in_different_contexts_stay_ambiguous(graph):
    """The group mark only folds contexts together for one group: two groups
    with one virtual address in two contexts is duplicated addressing."""
    _pair(graph, STANDBY, {**ACTIVE, "fhrp_group": 21})
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    assert result["indeterminate"]
    assert any("owned in 2 forwarding contexts" in w for w in result["warnings"])


def test_a_pair_in_one_context_keeps_the_forwarding_context_wording(graph):
    _pair(graph, STANDBY, {**ACTIVE, "anchor": "vrf:r2"})
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])
    assert ("Device", "r2b") in [(h["kind"], h["label"]) for h in result["hops"]]
    assert any("in one forwarding context" in n and "(hsrp active member)" in n for n in result["notes"])


def test_the_query_projects_the_edge_marks():
    from hst.path.gates.routing import _NEXT_HOP_DEVICE_QUERY

    assert "h.fhrp AS fhrp" in _NEXT_HOP_DEVICE_QUERY
    assert "h.group AS fhrp_group" in _NEXT_HOP_DEVICE_QUERY
    assert "h.state AS fhrp_state" in _NEXT_HOP_DEVICE_QUERY


def test_without_a_recorded_state_a_member_in_an_unrelated_vrf_makes_the_answer_indeterminate(graph):
    _pair(graph, {**STANDBY, "fhrp_state": None}, {**ACTIVE, "fhrp_state": None})
    graph.contexts["vrf:r1"] = {"name": "A", "is_global": False}
    graph.contexts["vrf:r2"] = {"name": "A", "is_global": False}
    graph.contexts["vrf:r2b"] = {"name": "B", "is_global": False}
    result = path.trace(None, "10.0.0.5", "10.99.0.7", gateways=[GW])

    assert result["indeterminate"]
    assert ("Device", "r2") in [(h["kind"], h["label"]) for h in result["hops"]]
    assert result["legs"][0]["indeterminate_reason"] == (
        "10.0.0.5: the trace through r2b r2b-e0 and the trace through r2 r2-eth0 answer differently "
        "for next hop 10.0.12.2, and no record names the device that forwards"
    )
