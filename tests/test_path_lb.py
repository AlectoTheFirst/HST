"""The load balancer stage's own building blocks: VIP proto/port claims,
member-region partitioning, and snat_mode resolution."""

# ruff: noqa: F811

from tests.test_path_trace import GW, graph  # noqa: F401

from hst.core.config import Settings
from hst.path.addrsets import _MATCH, _NO_MATCH, _UNKNOWN
from hst.path.gates import lb


def _vs(**kw):
    base = {
        "uid": "ns:dc1-ns01:lbvs:web-443",
        "name": "web-443",
        "kind": "lb",
        "proto": "tcp",
        "port": 443,
        "snat_mode": None,
    }
    base.update(kw)
    return base


def _member(**kw):
    base = {
        "uid": "ns:dc1-ns01:sg:web/10.0.10.5:8443",
        "name": None,
        "pool_uid": "ns:dc1-ns01:sg:web",
        "pool_name": "web",
        "port": 8443,
        "state": "up",
        "ip": "10.0.10.5",
    }
    base.update(kw)
    return base


# --- _vip_claims: the D-LB2 three-valued proto/port match -------------------------------


def test_vip_claims_matches_proto_and_port():
    assert lb._vip_claims(_vs(), "tcp", 443) == _MATCH


def test_vip_claims_no_match_on_wrong_proto():
    assert lb._vip_claims(_vs(proto="udp"), "tcp", 443) == _NO_MATCH


def test_vip_claims_no_match_on_wrong_port():
    assert lb._vip_claims(_vs(port=8080), "tcp", 443) == _NO_MATCH


def test_vip_claims_unknown_when_flow_carries_no_port():
    assert lb._vip_claims(_vs(), "tcp", None) == _UNKNOWN


def test_vip_claims_matches_when_vs_carries_no_proto():
    """An unset VS.proto constrains nothing."""
    assert lb._vip_claims(_vs(proto=None), "tcp", 443) == _MATCH


# --- _vip_supported: the kinds this stage evaluates --------------------------------------


def test_vip_supported_kinds():
    for kind in ("lb", "alb", "nlb", "azlb", "appgw", None):
        assert lb._vip_supported(_vs(kind=kind))


def test_vip_unsupported_kinds():
    for kind in ("gslb", "cs"):
        assert not lb._vip_supported(_vs(kind=kind))


# --- _member_regions: D-LB3 ---------------------------------------------------------------


def test_member_regions_one_healthy_member():
    regions = lb._member_regions([_member()])
    assert regions == lb.LbRegions([_member()], False, None)


def test_member_regions_skips_a_down_member():
    up = _member(uid="m:up", ip="10.0.10.5", state="up")
    down = _member(uid="m:down", ip="10.0.10.6", state="down")
    regions = lb._member_regions([up, down])
    assert regions.members == [up]
    assert not regions.collapsed


def test_member_regions_collapses_when_no_member_carries_state():
    """Not-collected health is distinct from every member being explicitly
    down: neither can be fanned into per-member legs (D-LB3)."""
    members = [_member(uid="m:a", state=None), _member(uid="m:b", ip="10.0.10.6", state=None)]
    regions = lb._member_regions(members)
    assert regions.members == []
    assert regions.collapsed
    assert "m:a" in regions.note or "10.0.10.5" in regions.note


def test_member_regions_follows_up_to_the_cap_and_reports_the_surplus():
    """Over the cap the pool is not collapsed and not truncated silently: the
    first `cap` members are followed and the rest are counted as surplus, for
    the caller to draw as one indeterminate leg naming the cap."""
    members = [_member(uid=f"m:{i}", ip=f"10.0.10.{i}", state="up") for i in range(5)]
    regions = lb._member_regions(members, cap=3)
    assert regions.members == members[:3]
    assert not regions.collapsed
    assert regions.surplus == 2
    assert "3-member cap" in regions.note
    assert "lb_member_cap" in regions.note
    assert "10.0.10.3" in regions.note and "10.0.10.4" in regions.note


def test_member_regions_cap_defaults_to_the_setting():
    """The pool fan-out has its own cap, below path_region_cap."""
    cap = Settings().lb_member_cap
    assert cap == 8
    assert cap < Settings().path_region_cap
    members = [_member(uid=f"m:{i}", ip=f"10.0.10.{i}", state="up") for i in range(cap + 1)]
    regions = lb._member_regions(members)
    assert len(regions.members) == cap
    assert regions.surplus == 1


def test_member_regions_collapses_when_every_member_is_down():
    members = [_member(uid="m:a", state="down"), _member(uid="m:b", ip="10.0.10.6", state="down")]
    regions = lb._member_regions(members)
    assert regions.members == []
    assert regions.collapsed


def test_member_regions_empty_pool():
    regions = lb._member_regions([])
    assert regions == lb.LbRegions([], True, "the pool has no members")


# --- _vip_bindings: the two GATE_BINDINGS patterns, read as one query --------------------


def test_vip_bindings_found(graph):
    vs_row = _vs()
    graph.vip[("10.0.30.10", GW["dev_uid"])] = vs_row
    assert lb._vip_bindings(None, "10.0.30.10", GW["dev_uid"]) == [vs_row]


def test_vip_bindings_returns_every_vserver_on_the_address(graph):
    """Two vservers on one VIP is the ordinary appliance shape: the query
    returns both and the caller's proto/port match picks between them."""
    web80 = _vs(uid="ns:dc1-ns01:lbvs:web-80", name="web-80", port=80)
    web443 = _vs()
    graph.vip[("10.0.30.10", GW["dev_uid"])] = [web80, web443]
    assert lb._vip_bindings(None, "10.0.30.10", GW["dev_uid"]) == [web80, web443]


def test_vip_bindings_not_found(graph):
    assert lb._vip_bindings(None, "10.0.30.10", GW["dev_uid"]) == []


def test_vip_binding_query_scopes_the_address_node_to_this_snapshot():
    """The VIP's own IpAddress node supplies the instance the flow terminates
    on, so it carries the same retirement and snapshot guard every other
    IpAddress read in this module carries."""
    assert "NOT vip:Retired" in lb._VIP_BINDING_QUERY
    assert "vip.collection_ts = $snap" in lb._VIP_BINDING_QUERY


# --- _pool_members ------------------------------------------------------------------------


def test_pool_members_reads_by_virtualservice_uid(graph):
    members = [_member()]
    graph.pool_members[_vs()["uid"]] = members
    assert lb._pool_members(None, _vs()["uid"]) == members


# --- _lb_snat: D-LB4 ------------------------------------------------------------------------

CLIENT_SRC = [(4, 0x0A000005, 0x0A000005)]  # 10.0.0.5/32, in the interval encoding


def test_lb_snat_snat_from_resolved(graph):
    vs_row = _vs(snat_mode="snat_from")
    graph.snat_from[vs_row["uid"]] = {"ip": "10.0.30.99"}
    src, note, indeterminate = lb._lb_snat(None, vs_row, GW["dev_uid"], "10.0.10.5", CLIENT_SRC)
    assert not indeterminate
    assert "10.0.30.99" in note
    from hst.path.addrsets import _to_cidrs

    assert _to_cidrs(src) == ["10.0.30.99/32"]


def test_lb_snat_snat_from_uncollected_is_indeterminate(graph):
    vs_row = _vs(snat_mode="snat_from")
    src, note, indeterminate = lb._lb_snat(None, vs_row, GW["dev_uid"], "10.0.10.5", CLIENT_SRC)
    assert indeterminate
    assert src == CLIENT_SRC
    assert "no SNAT_FROM address" in note


def test_lb_snat_snip_resolved_on_member_subnet(graph):
    vs_row = _vs(snat_mode="snip")
    graph.snip_candidates[GW["dev_uid"]] = [
        {"ip": "10.0.10.1", "if_uid": "if:snip0", "if_name": "snip0", "cidr": "10.0.10.0/24"}
    ]
    src, note, indeterminate = lb._lb_snat(None, vs_row, GW["dev_uid"], "10.0.10.5", CLIENT_SRC)
    assert not indeterminate
    assert "10.0.10.1" in note and "SNIP" in note
    from hst.path.addrsets import _to_cidrs

    assert _to_cidrs(src) == ["10.0.10.1/32"]


def test_lb_snat_snip_no_matching_subnet_is_indeterminate(graph):
    vs_row = _vs(snat_mode="snip")
    graph.snip_candidates[GW["dev_uid"]] = [
        {"ip": "192.168.1.1", "if_uid": "if:x", "if_name": "x", "cidr": "192.168.1.0/24"}
    ]
    src, _note, indeterminate = lb._lb_snat(None, vs_row, GW["dev_uid"], "10.0.10.5", CLIENT_SRC)
    assert indeterminate
    assert src == CLIENT_SRC


def test_lb_snat_automap_reads_distinctly_from_snip(graph):
    vs_row = _vs(snat_mode="automap")
    graph.snip_candidates[GW["dev_uid"]] = [
        {"ip": "10.0.10.1", "if_uid": "if:snip0", "if_name": "snip0", "cidr": "10.0.10.0/24"}
    ]
    _src, note, indeterminate = lb._lb_snat(None, vs_row, GW["dev_uid"], "10.0.10.5", CLIENT_SRC)
    assert not indeterminate
    assert "automap" in note.lower()


def test_lb_snat_none_preserves_client_source(graph):
    vs_row = _vs(snat_mode="none")
    src, note, indeterminate = lb._lb_snat(None, vs_row, GW["dev_uid"], "10.0.10.5", CLIENT_SRC)
    assert not indeterminate
    assert src == CLIENT_SRC
    assert "no SNAT" in note


def test_lb_snat_absent_is_indeterminate_and_names_nothing_fabricated(graph):
    """Absent isn't fine, distinct from an unrecognized-but-present string
    (labels.py's own 'unknown is fine, absent is not' doctrine)."""
    vs_row = _vs(snat_mode=None)
    src, note, indeterminate = lb._lb_snat(None, vs_row, GW["dev_uid"], "10.0.10.5", CLIENT_SRC)
    assert indeterminate
    assert src == CLIENT_SRC
    assert "no snat_mode" in note


def test_lb_snat_unrecognized_value_is_indeterminate_and_names_it(graph):
    vs_row = _vs(snat_mode="reencrypt-vip")
    src, note, indeterminate = lb._lb_snat(None, vs_row, GW["dev_uid"], "10.0.10.5", CLIENT_SRC)
    assert indeterminate
    assert src == CLIENT_SRC
    assert "reencrypt-vip" in note
