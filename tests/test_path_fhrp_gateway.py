"""Initial source gateway selection for a VLAN stretched across two routers."""

import importlib

import pytest
from tests.test_path_trace import GW, FakeGraph, _route, _src_row

from hst import path

trace_module = importlib.import_module("hst.path.trace")

FR2 = {**GW, "anchor": "vrf:fr2:wan", "l3dom": "inventory:acme-emea:wan", "dev_name": "FR2"}
FR6 = {
    **FR2,
    "anchor": "vrf:fr6:wan",
    "if_uid": "if:fr6-vlan",
    "if_name": "Vlan20",
    "dev_uid": "dev:zz-fr6",
    "dev_name": "FR6",
}
STANDBY = {
    "if_uid": FR2["if_uid"],
    "group_uid": "fhrp:hsrp:wan:10.0.0.1",
    "vip": "10.0.0.1",
    "fhrp": "hsrp",
    "fhrp_group": 20,
    "fhrp_state": "standby",
}
ACTIVE = {**STANDBY, "if_uid": FR6["if_uid"], "fhrp_state": "active"}


@pytest.fixture
def estate(monkeypatch):
    graph = FakeGraph()
    graph.fhrp = [STANDBY.copy(), ACTIVE.copy()]
    graph.fhrp_reads = []
    graph.default_tables = {
        FR2["if_uid"]: {"uid": FR2["anchor"]},
        FR6["if_uid"]: {"uid": FR6["anchor"]},
    }
    graph.routes = {
        FR2["anchor"]: [_route("0.0.0.0/0", egress="fr2-uplink", next_hop="192.0.2.2")],
        FR6["anchor"]: [_route("0.0.0.0/0", egress="fr6-uplink", next_hop="192.0.2.6")],
    }

    def read(session, query, **params):
        if query == trace_module._GATEWAY_FHRP_QUERY:
            graph.fhrp_reads.append(params)
            return [r for r in graph.fhrp if r["if_uid"] in params["interfaces"]]
        return graph.read(query, **params)

    monkeypatch.setattr(path, "_read", read)
    monkeypatch.setattr(path, "_read_one", lambda session, query, **p: graph.read_one(query, **p))
    return graph


def run_trace(**kwargs):
    return path.trace(None, "10.0.0.5/32", "203.0.113.5", gateways=[FR2, FR6], **kwargs)


def assert_unresolved(result, reason):
    assert result["indeterminate"] is True
    assert result["legs"] == []
    assert reason in result["verdict"]
    assert not any(h["kind"] == "Device" for h in result["hops"])


def test_32_uses_hsrp_active_router_and_its_own_next_hop(estate):
    result = run_trace()
    assert {h["uid"] for h in result["hops"] if h["kind"] == "Device"} == {FR6["dev_uid"]}
    assert {leg["egress"] for leg in result["legs"]} == {"fr6-uplink"}
    assert estate.next_hop_lookups == ["192.0.2.6"]
    assert any("HSRP group 20 VIP 10.0.0.1: active member FR6" in n for n in result["notes"])
    assert "ambiguous_domains" not in result


def test_snapshot_with_failover_uses_fr2_routes(estate):
    estate.fhrp = [{**STANDBY, "fhrp_state": "active"}, {**ACTIVE, "fhrp_state": "standby"}]
    result = run_trace()
    assert {leg["egress"] for leg in result["legs"]} == {"fr2-uplink"}
    assert estate.next_hop_lookups == ["192.0.2.2"]


def test_vrrp_master_is_also_selected(estate):
    estate.fhrp = [
        {**STANDBY, "fhrp": "vrrp", "fhrp_state": "backup"},
        {**ACTIVE, "fhrp": "vrrp", "fhrp_state": "master"},
    ]
    result = run_trace()
    assert {leg["egress"] for leg in result["legs"]} == {"fr6-uplink"}
    assert any("VRRP group 20 VIP 10.0.0.1: master member FR6" in n for n in result["notes"])


@pytest.mark.parametrize("state", [None, "", "unknown"])
def test_missing_member_state_does_not_guess(estate, state):
    estate.fhrp[0]["fhrp_state"] = state
    assert_unresolved(run_trace(), "missing or conflicting member state")


@pytest.mark.parametrize("state,count", [("standby", 0), ("active", 2)])
def test_no_active_or_two_active_members_do_not_guess(estate, state, count):
    estate.fhrp = [{**r, "fhrp_state": state} for r in estate.fhrp]
    assert_unresolved(run_trace(), f"has {count} active members recorded")


def test_conflicting_observations_for_one_member_do_not_guess(estate):
    estate.fhrp.append({**ACTIVE, "fhrp_state": "standby"})
    assert_unresolved(run_trace(), "missing or conflicting member state")


@pytest.mark.parametrize(
    "field,value", [("group_uid", "fhrp:other"), ("vip", "10.0.0.2"), ("fhrp_group", 21)]
)
def test_distinct_groups_are_not_merged_by_vrf_label(estate, field, value):
    estate.fhrp[1][field] = value
    assert_unresolved(run_trace(), "multiple redundancy groups or virtual IPs")


def test_multiple_groups_on_same_interfaces_need_source_gateway(estate):
    estate.fhrp.extend(
        [{**r, "group_uid": "fhrp:second", "vip": "10.0.0.2", "fhrp_group": 21} for r in estate.fhrp]
    )
    assert_unresolved(run_trace(), "multiple redundancy groups or virtual IPs")


def test_missing_peer_membership_does_not_hide_other_router(estate):
    estate.fhrp = [ACTIVE]
    assert_unresolved(run_trace(), "not every gateway candidate has recorded membership")


@pytest.mark.parametrize("field", ["group_uid", "fhrp_group"])
def test_incomplete_group_identity_does_not_guess(estate, field):
    estate.fhrp = [{**r, field: None} for r in estate.fhrp]
    assert_unresolved(run_trace(), "redundancy group membership is incomplete")


def test_no_fhrp_evidence_keeps_existing_context_ambiguity(estate):
    estate.fhrp = []
    assert_unresolved(run_trace(), "matches gateway prefixes in 2 isolated L3 domains")


def test_unrelated_virtual_address_does_not_resolve_source_gateway(estate):
    estate.fhrp = [{**r, "vip": "10.1.0.1"} for r in estate.fhrp]
    assert_unresolved(run_trace(), "matches gateway prefixes in 2 isolated L3 domains")


def test_explicit_source_context_can_trace_standby_router(estate):
    result = run_trace(src_context=FR2["anchor"])
    assert {leg["egress"] for leg in result["legs"]} == {"fr2-uplink"}
    assert estate.fhrp_reads == []


def test_group_on_disjoint_segments_is_not_a_shared_gateway(estate):
    estate.iface_segments = {FR2["if_uid"]: ["bd:fr2"], FR6["if_uid"]: ["bd:fr6"]}
    assert_unresolved(run_trace(), "different recorded L2 segments")


def test_stretched_segment_accepts_shared_or_extends_reachable_domain(estate):
    estate.iface_segments = {FR2["if_uid"]: ["bd:fr2", "bd:fr6"], FR6["if_uid"]: ["bd:fr6", "bd:fr2"]}
    assert {leg["egress"] for leg in run_trace()["legs"]} == {"fr6-uplink"}


def test_endpoint_on_shared_segment_uses_active_gateway(estate):
    estate.sources = [{**_src_row(), "anchor": "bd:stretched", "seg_uid": "bd:stretched"}]
    estate.iface_segments = {FR2["if_uid"]: ["bd:stretched"], FR6["if_uid"]: ["bd:stretched"]}
    result = path.trace(None, "10.0.0.5", "203.0.113.5", gateways=[FR2, FR6])
    assert {leg["egress"] for leg in result["legs"]} == {"fr6-uplink"}
