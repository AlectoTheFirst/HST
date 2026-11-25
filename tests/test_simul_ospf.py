"""The OSPF calculation over a fixture link-state database."""

import copy
import ipaddress
import random

import pytest

from hst.simul import ospf, platforms
from hst.simul.errors import ErrorSink

AREA_0 = "0.0.0.0"  # noqa: S104 - an OSPF area id
AREA_1 = "0.0.0.1"
DEFAULT_ROUTE = "0.0.0.0/0"
ZERO = "0.0.0.0"  # noqa: S104 - a zero link-state id or forwarding address
R1, R2, R3, R4 = "10.255.0.1", "10.255.0.2", "10.255.0.3", "10.255.0.4"
CTX = "vrf:dev-r1:default"
MASK_24, MASK_30, MASK_32 = "255.255.255.0", "255.255.255.252", "255.255.255.255"


def _lsa(lsa_type, lsid, adv_router, area=AREA_0, **over):
    row = {
        "process": "1",
        "area": area,
        "lsa_type": lsa_type,
        "lsid": lsid,
        "adv_router": adv_router,
        "seq": 0x80000001,
        "age": 100,
        "metric": None,
        "links": None,
        "attached_routers": None,
        "mask": None,
        "forwarding_address": None,
        "metric_type": None,
    }
    row.update(over)
    return row


def _link(link_type, link_id, link_data, metric):
    return {"link_type": link_type, "link_id": link_id, "link_data": link_data, "metric": metric}


def _p2p(neighbor, own_address, metric):
    return _link("point-to-point", neighbor, own_address, metric)


def _stub(network, mask, metric):
    return _link("stub", network, mask, metric)


def _transit(dr_address, own_address, metric):
    return _link("transit", dr_address, own_address, metric)


def _router(rid, links, area=AREA_0):
    return _lsa("router", rid, rid, area, links=links)


def _network(dr_address, dr_rid, mask, attached, area=AREA_0):
    return _lsa("network", dr_address, dr_rid, area, mask=mask, attached_routers=attached)


def _summary(network, mask, metric, adv_router, area=AREA_0):
    return _lsa("summary", network, adv_router, area, mask=mask, metric=metric)


def _asbr_summary(asbr, metric, adv_router, area=AREA_0):
    return _lsa("asbr-summary", asbr, adv_router, area, metric=metric)


def _external(
    network, mask, metric, adv_router, metric_type=2, forwarding_address=None, lsa_type="external", area=None
):
    return _lsa(
        lsa_type,
        network,
        adv_router,
        area,
        mask=mask,
        metric=metric,
        metric_type=metric_type,
        forwarding_address=forwarding_address,
    )


def _single_area():
    return [
        _router(
            R1,
            [
                _p2p(R2, "10.0.12.1", 10),
                _stub("10.0.12.0", MASK_30, 10),
                _p2p(R3, "10.0.13.1", 20),
                _stub("10.0.13.0", MASK_30, 20),
                _stub(R1, MASK_32, 1),
            ],
        ),
        _router(
            R2,
            [
                _p2p(R1, "10.0.12.2", 10),
                _stub("10.0.12.0", MASK_30, 10),
                _transit("10.0.23.3", "10.0.23.2", 10),
                _stub(R2, MASK_32, 1),
            ],
        ),
        _router(
            R3,
            [
                _p2p(R1, "10.0.13.3", 20),
                _stub("10.0.13.0", MASK_30, 20),
                _transit("10.0.23.3", "10.0.23.3", 10),
                _stub(R3, MASK_32, 1),
                _stub("192.168.3.0", MASK_24, 5),
            ],
        ),
        _network("10.0.23.3", R3, MASK_24, [R2, R3]),
    ]


def _rib(prefix, next_hop, metric, protocol="ospf-1"):
    return {
        "prefix": prefix,
        "next_hop": next_hop,
        "next_hop_context_uid": None,
        "interface": "Ethernet1/1",
        "protocol": protocol,
        "discard": None,
        "metric": metric,
        "prefixlen": ipaddress.ip_network(prefix).prefixlen,
        "af": 4,
    }


def _observed_single_area():
    return [
        _rib("10.0.12.0/30", "10.0.12.1", 0, "direct"),
        _rib("10.0.13.0/30", "10.0.13.1", 0, "direct"),
        _rib("10.255.0.1/32", R1, 0, "local"),
        _rib("10.0.23.0/24", "10.0.12.2", 20),
        _rib("10.255.0.2/32", "10.0.12.2", 11),
        _rib("10.255.0.3/32", "10.0.12.2", 21),
        _rib("10.255.0.3/32", "10.0.13.3", 21),
        _rib("192.168.3.0/24", "10.0.12.2", 25),
        _rib("192.168.3.0/24", "10.0.13.3", 25),
    ]


def _calculate(rows, root=R1, platform="nxos", area_types=None):
    errors = ErrorSink()
    model = ospf.LsdbModel.from_rows(rows, area_types=area_types, errors=errors)
    return ospf.calculate(model, root, platform=platform, errors=errors)


def _by_prefix(calc):
    return {r.prefix: r for r in calc.routes}


# --- intra-area ------------------------------------------------------------


def test_a_single_area_reproduces_the_observed_rib_rows():
    calc = _calculate(_single_area())
    assert calc.model_errors == []
    assert calc.gaps == []
    assert calc.area_border_router is False
    assert [(r.prefix, r.path_type, r.metric, r.next_hops) for r in calc.routes] == [
        ("10.0.23.0/24", "intra-area", 20, ("10.0.12.2",)),
        ("10.255.0.2/32", "intra-area", 11, ("10.0.12.2",)),
        ("10.255.0.3/32", "intra-area", 21, ("10.0.12.2", "10.0.13.3")),
        ("192.168.3.0/24", "intra-area", 25, ("10.0.12.2", "10.0.13.3")),
    ]
    assert calc.router_costs == {(AREA_0, R2): 10, (AREA_0, R3): 20}

    errors = ErrorSink()
    report = ospf.validate(calc, _observed_single_area(), process="1", errors=errors)
    assert [(row["prefix"], row["status"]) for row in report] == [
        ("10.0.23.0/24", "validated"),
        ("10.255.0.2/32", "validated"),
        ("10.255.0.3/32", "validated"),
        ("192.168.3.0/24", "validated"),
    ]
    assert errors.as_dicts() == []


def test_rib_rows_carry_one_row_per_next_hop_with_the_platform_admin_distance():
    rows = ospf.rib_rows(CTX, _calculate(_single_area()), platform="nxos")
    assert [(r["prefix"], r["next_hop"]) for r in rows] == [
        ("10.0.23.0/24", "10.0.12.2"),
        ("10.255.0.2/32", "10.0.12.2"),
        ("10.255.0.3/32", "10.0.12.2"),
        ("10.255.0.3/32", "10.0.13.3"),
        ("192.168.3.0/24", "10.0.12.2"),
        ("192.168.3.0/24", "10.0.13.3"),
    ]
    assert rows[0] == {
        "context_uid": CTX,
        "prefix": "10.0.23.0/24",
        "next_hop": "10.0.12.2",
        "protocol": "ospf",
        "metric": 20,
        "admin": 110,
        "path_type": "intra-area",
        "area": AREA_0,
        "advertising_router": None,
        "forward_metric": None,
    }


def test_the_calculating_routers_own_subnets_are_not_ospf_routes():
    """R2 and R3 advertise the point-to-point subnets as stub links too. The
    main RIB holds those as connected routes, so the calculation does not
    offer them, whatever cost a neighbor advertises them at."""
    prefixes = set(_by_prefix(_calculate(_single_area())))
    assert not prefixes & {"10.0.12.0/30", "10.0.13.0/30", "10.255.0.1/32"}


# --- inter-area ------------------------------------------------------------


def _two_areas():
    """R2 becomes the area border router: it has a second router LSA in area
    1, where R4 hangs off it, and originates summary LSAs both ways."""
    return [
        *_single_area(),
        _router(
            R2,
            [_p2p(R4, "10.1.24.2", 10), _stub("10.1.24.0", MASK_30, 10), _stub("10.1.0.0", MASK_24, 10)],
            AREA_1,
        ),
        _router(
            R4, [_p2p(R2, "10.1.24.4", 10), _stub("10.1.24.0", MASK_30, 10), _stub(R4, MASK_32, 1)], AREA_1
        ),
        # into the backbone
        _summary("10.1.0.0", MASK_24, 10, R2),
        _summary("10.1.24.0", MASK_30, 10, R2),
        _summary(R4, MASK_32, 11, R2),
        # a summary for a prefix R1 already reaches intra-area, at a lower metric
        _summary("192.168.3.0", MASK_24, 1, R2),
        # into area 1
        _summary(R1, MASK_32, 11, R2, AREA_1),
        _summary("10.0.23.0", MASK_24, 10, R2, AREA_1),
        # a summary in area 1 from another border router
        _summary("172.16.0.0", MASK_24, 5, R4, AREA_1),
    ]


def test_two_areas_with_one_border_router_yield_inter_area_routes_with_summed_metrics():
    calc = _calculate(_two_areas())
    assert calc.model_errors == []
    assert calc.gaps == []
    routes = _by_prefix(calc)
    assert (routes["10.1.0.0/24"].path_type, routes["10.1.0.0/24"].metric) == ("inter-area", 20)
    assert routes["10.1.0.0/24"].next_hops == ("10.0.12.2",)
    assert routes["10.1.0.0/24"].advertising_router == R2
    assert (routes["10.1.24.0/30"].metric, routes["10.255.0.4/32"].metric) == (20, 21)
    assert routes["10.255.0.4/32"].next_hops == ("10.0.12.2",)
    assert (routes["192.168.3.0/24"].path_type, routes["192.168.3.0/24"].metric) == ("intra-area", 25), (
        "an intra-area path is always preferred over an inter-area one (RFC 2328 16.2 step 5)"
    )
    assert "172.16.0.0/24" not in routes, "R1 is in the backbone only and never sees area 1's summaries"


def test_the_border_router_examines_backbone_summaries_only():
    """RFC 2328 16.2: a router with active attachments to more than one area
    considers only the backbone's summary LSAs. From R2, the area-1 summary
    another border router originates yields nothing; R2's own summaries are
    skipped as self-originated; both areas' intra-area routes are present."""
    calc = _calculate(_two_areas(), root=R2)
    assert calc.model_errors == []
    assert calc.area_border_router is True
    routes = _by_prefix(calc)
    assert "172.16.0.0/24" not in routes
    assert (routes["10.255.0.1/32"].metric, routes["10.255.0.1/32"].next_hops) == (11, ("10.0.12.1",))
    assert (routes["10.255.0.4/32"].area, routes["10.255.0.4/32"].next_hops) == (AREA_1, ("10.1.24.4",))
    assert routes["10.0.13.0/30"].next_hops == ("10.0.12.1", "10.0.23.3"), "two equal-cost paths at 30"
    assert routes["10.0.13.0/30"].metric == 30


def test_a_stub_area_default_comes_from_the_border_routers_summary():
    rows = [
        _router(
            R4, [_p2p(R2, "10.1.24.4", 10), _stub("10.1.24.0", MASK_30, 10), _stub(R4, MASK_32, 1)], AREA_1
        ),
        _router(R2, [_p2p(R4, "10.1.24.2", 10), _stub("10.1.24.0", MASK_30, 10)], AREA_1),
        _summary(ZERO, ZERO, 1, R2, AREA_1),
        _summary(R1, MASK_32, 11, R2, AREA_1),
    ]
    calc = _calculate(rows, root=R4, area_types={AREA_1: "stub"})
    assert calc.model_errors == []
    assert [(r.prefix, r.path_type, r.metric, r.next_hops) for r in calc.routes] == [
        (DEFAULT_ROUTE, "inter-area", 11, ("10.1.24.2",)),
        ("10.255.0.1/32", "inter-area", 21, ("10.1.24.2",)),
    ]


# --- externals -------------------------------------------------------------


def test_a_type_1_external_beats_a_type_2_whatever_the_cost():
    rows = [
        *_single_area(),
        _external("203.0.113.0", MASK_24, 20, R3, metric_type=2),
        _external("203.0.113.0", MASK_24, 100, R2, metric_type=1),
    ]
    route = _by_prefix(_calculate(rows))["203.0.113.0/24"]
    assert (route.path_type, route.metric, route.forward_metric) == ("external-1", 110, 10)
    assert (route.next_hops, route.advertising_router) == (("10.0.12.2",), R2)


def test_type_2_externals_tie_on_the_lsa_metric_and_break_on_the_forward_metric():
    rows = [
        *_single_area(),
        _external("203.0.113.0", MASK_24, 20, R3, metric_type=2),
        _external("203.0.113.0", MASK_24, 20, R2, metric_type=2),
    ]
    route = _by_prefix(_calculate(rows))["203.0.113.0/24"]
    assert (route.path_type, route.metric, route.forward_metric) == ("external-2", 20, 10)
    assert (route.next_hops, route.advertising_router) == (("10.0.12.2",), R2)

    # the cheaper LSA metric wins first, whatever the forward metric
    rows[-1]["metric"] = 30
    route = _by_prefix(_calculate(rows))["203.0.113.0/24"]
    assert (route.metric, route.forward_metric, route.advertising_router) == (20, 20, R3)
    assert route.next_hops == ("10.0.12.2", "10.0.13.3"), "the path to R3 is the equal-cost pair"


def test_a_forwarding_address_resolves_through_the_computed_routes():
    rows = [
        *_single_area(),
        _external("198.51.100.0", MASK_24, 20, R2, forwarding_address="192.168.3.10"),
        # on the calculating router's own subnet: the forwarding address is the next hop
        _external("198.51.101.0", MASK_24, 20, R3, forwarding_address="10.0.12.2"),
        # covered by no intra- or inter-area route: the LSA is unusable
        _external("198.51.102.0", MASK_24, 20, R2, forwarding_address="172.31.0.1"),
    ]
    routes = _by_prefix(_calculate(rows))
    via_lan = routes["198.51.100.0/24"]
    assert (via_lan.metric, via_lan.forward_metric, via_lan.next_hops) == (20, 25, ("10.0.12.2", "10.0.13.3"))
    on_link = routes["198.51.101.0/24"]
    assert (on_link.forward_metric, on_link.next_hops) == (10, ("10.0.12.2",))
    assert "198.51.102.0/24" not in routes


def test_rfc_1583_compatibility_decides_the_path_to_the_asbr():
    """RFC 2328 16.4.1: without RFC 1583 compatibility an intra-area path to
    the ASBR through a non-backbone area outranks a cheaper path through the
    backbone. R2 reaches the ASBR X at cost 50 inside area 1 and at cost 15
    through R1's ASBR-summary in the backbone."""
    asbr = "10.255.0.9"
    rows = [
        r for r in _two_areas() if not (r["lsa_type"] == "router" and r["lsid"] == R2 and r["area"] == AREA_1)
    ]
    rows += [
        _router(
            R2,
            [
                _p2p(R4, "10.1.24.2", 10),
                _stub("10.1.24.0", MASK_30, 10),
                _p2p(asbr, "10.1.29.2", 50),
                _stub("10.1.29.0", MASK_30, 50),
            ],
            AREA_1,
        ),
        _router(asbr, [_p2p(R2, "10.1.29.9", 50), _stub("10.1.29.0", MASK_30, 50)], AREA_1),
        _asbr_summary(asbr, 5, R1),
        _external("203.0.113.0", MASK_24, 20, asbr),
    ]
    rfc2328 = _by_prefix(_calculate(rows, root=R2, platform="nxos"))["203.0.113.0/24"]
    assert (rfc2328.metric, rfc2328.forward_metric, rfc2328.next_hops) == (20, 50, ("10.1.29.9",))
    rfc1583 = _by_prefix(_calculate(rows, root=R2, platform="iosxe"))["203.0.113.0/24"]
    assert (rfc1583.metric, rfc1583.forward_metric, rfc1583.next_hops) == (20, 15, ("10.0.12.1",))


def test_nssa_type_7_externals_and_the_nssa_default():
    """R4 inside the not-so-stubby area 1: the border router R2's type 7
    default and type 7 external are routes to R2; R4's own type 7 is skipped
    as self-originated; the area is an NSSA by the evidence alone."""
    rows = [
        _router(
            R4, [_p2p(R2, "10.1.24.4", 10), _stub("10.1.24.0", MASK_30, 10), _stub(R4, MASK_32, 1)], AREA_1
        ),
        _router(R2, [_p2p(R4, "10.1.24.2", 10), _stub("10.1.24.0", MASK_30, 10)], AREA_1),
        _summary(R1, MASK_32, 11, R2, AREA_1),
        _external(ZERO, ZERO, 1, R2, lsa_type="nssa-external", area=AREA_1),
        _external(
            "198.51.100.0", MASK_24, 30, R2, forwarding_address=ZERO, lsa_type="nssa-external", area=AREA_1
        ),
        _external(
            "203.0.113.0",
            MASK_24,
            20,
            R4,
            forwarding_address="10.1.24.4",
            lsa_type="nssa-external",
            area=AREA_1,
        ),
    ]
    errors = ErrorSink()
    model = ospf.LsdbModel.from_rows(rows, errors=errors)
    assert model.area_type(AREA_1) == "nssa"
    calc = ospf.calculate(model, R4, platform="nxos", errors=errors)
    assert calc.model_errors == []
    assert [
        (r.prefix, r.path_type, r.metric, r.forward_metric, r.next_hops, r.lsa_type) for r in calc.routes
    ] == [
        (DEFAULT_ROUTE, "external-2", 1, 10, ("10.1.24.2",), "nssa-external"),
        ("10.255.0.1/32", "inter-area", 21, None, ("10.1.24.2",), "summary"),
        ("198.51.100.0/24", "external-2", 30, 10, ("10.1.24.2",), "nssa-external"),
    ]


# --- changes ---------------------------------------------------------------


def test_a_cost_change_moves_the_next_hop():
    rows = _single_area()
    before = copy.deepcopy(rows)
    errors = ErrorSink()
    observed = ospf.LsdbModel.from_rows(rows, errors=errors)
    changed = observed.with_interface_cost(R1, "10.0.12.1", 40, errors)
    route = _by_prefix(ospf.calculate(changed, R1, platform="nxos", errors=errors))["10.255.0.2/32"]
    assert (route.metric, route.next_hops) == (31, ("10.0.13.3",)), (
        "R2 is now cheaper through R3 and the segment"
    )
    assert errors.as_dicts() == []
    # the observed model and the observed rows are unchanged
    assert _by_prefix(ospf.calculate(observed, R1, platform="nxos"))["10.255.0.2/32"].next_hops == (
        "10.0.12.2",
    )
    assert rows == before


def test_an_adjacency_loss_removes_the_routes_through_it():
    rows = _single_area()
    before = copy.deepcopy(rows)
    errors = ErrorSink()
    observed = ospf.LsdbModel.from_rows(rows, errors=errors)
    calc = ospf.calculate(observed.without_adjacency(R1, R2, errors), R1, platform="nxos", errors=errors)
    assert errors.as_dicts() == []
    assert calc.gaps == []
    assert [(r.prefix, r.metric, r.next_hops) for r in calc.routes] == [
        ("10.0.23.0/24", 30, ("10.0.13.3",)),
        ("10.255.0.2/32", 31, ("10.0.13.3",)),
        ("10.255.0.3/32", 21, ("10.0.13.3",)),
        ("192.168.3.0/24", 25, ("10.0.13.3",)),
    ]
    assert rows == before


def test_an_adjacency_loss_on_a_transit_network_leaves_the_segment_as_stubs():
    """R2 loses its adjacency to the designated router R3: R2 leaves the
    network LSA, which then has no second router and is withdrawn, and both
    advertise the segment as a stub. R3 is reachable only directly."""
    errors = ErrorSink()
    observed = ospf.LsdbModel.from_rows(_single_area(), errors=errors)
    calc = ospf.calculate(observed.without_adjacency(R2, R3, errors), R1, platform="nxos", errors=errors)
    assert errors.as_dicts() == []
    routes = _by_prefix(calc)
    assert (routes["10.0.23.0/24"].metric, routes["10.0.23.0/24"].next_hops) == (20, ("10.0.12.2",))
    assert routes["10.255.0.3/32"].next_hops == ("10.0.13.3",)
    assert routes["192.168.3.0/24"].next_hops == ("10.0.13.3",)


def test_an_interface_moving_area_takes_its_prefix_out_of_the_old_area():
    errors = ErrorSink()
    observed = ospf.LsdbModel.from_rows(_single_area(), errors=errors)
    moved = observed.with_interface_in_area(R3, "192.168.3.1", AREA_1, errors)
    calc = ospf.calculate(moved, R1, platform="nxos", errors=errors)
    assert errors.as_dicts() == []
    assert calc.gaps == []
    assert "192.168.3.0/24" not in _by_prefix(calc), "R1 has no presence in area 1 and no summary reaches it"
    assert _by_prefix(calc)["10.255.0.3/32"].next_hops == ("10.0.12.2", "10.0.13.3")


def test_a_change_that_touches_nothing_is_reported():
    errors = ErrorSink()
    observed = ospf.LsdbModel.from_rows(_single_area(), errors=errors)
    observed.with_interface_cost(R1, "10.9.9.9", 5, errors)
    assert [e["kind"] for e in errors.as_dicts()] == ["ospf-change-no-effect"]


# --- gaps and validation ---------------------------------------------------


def test_a_missing_lsa_is_a_named_gap_and_never_a_mismatch():
    rows = [r for r in _single_area() if not (r["lsa_type"] == "router" and r["lsid"] == R3)]
    calc = _calculate(rows)
    assert calc.model_errors == []
    assert calc.gaps == [
        {
            "kind": "not-observed",
            "lsa_type": "router",
            "lsid": R3,
            "area": AREA_0,
            "detail": (
                f"router LSA {R3} in area {AREA_0} is not in the observed database: "
                f"named by a point-to-point link of router {R1}"
            ),
        }
    ]
    assert [r.prefix for r in calc.routes] == ["10.0.23.0/24", "10.255.0.2/32"]

    errors = ErrorSink()
    report = ospf.validate(calc, _observed_single_area(), process="1", errors=errors)
    assert [(row["prefix"], row["status"]) for row in report] == [
        ("10.0.23.0/24", "validated"),
        ("10.255.0.2/32", "validated"),
        ("10.255.0.3/32", "not-observed"),
        ("192.168.3.0/24", "not-observed"),
    ]
    assert errors.as_dicts() == []


def test_a_database_without_the_calculating_router_yields_nothing_but_a_gap():
    calc = _calculate(_single_area(), root="10.255.0.99")
    assert calc.routes == []
    assert [(g["lsa_type"], g["lsid"], g["area"]) for g in calc.gaps] == [("router", "10.255.0.99", None)]


def test_a_mismatch_is_a_model_error():
    observed = _observed_single_area()
    for row in observed:
        if row["prefix"] == "10.255.0.2/32":
            row["metric"] = 12
    errors = ErrorSink()
    report = ospf.validate(_calculate(_single_area()), observed, process="1", errors=errors)
    statuses = {row["prefix"]: row["status"] for row in report}
    assert statuses["10.255.0.2/32"] == "mismatch"
    assert [(e["kind"], e["subject"]) for e in errors.as_dicts()] == [
        ("ospf-route-mismatch", "10.255.0.2/32")
    ]


def test_a_prefix_the_device_installed_from_another_protocol_is_not_observed():
    observed = [r for r in _observed_single_area() if r["prefix"] != "10.255.0.2/32"]
    observed.append(_rib("10.255.0.2/32", "10.0.12.2", 0, "static"))
    errors = ErrorSink()
    report = ospf.validate(_calculate(_single_area()), observed, process="1", errors=errors)
    row = next(r for r in report if r["prefix"] == "10.255.0.2/32")
    assert row["status"] == "not-observed"
    assert "static" in row["detail"]
    assert errors.as_dicts() == []


def test_an_observed_ospf_route_the_complete_database_does_not_produce_is_a_mismatch():
    observed = [*_observed_single_area(), _rib("10.99.0.0/24", "10.0.12.2", 40)]
    errors = ErrorSink()
    report = ospf.validate(_calculate(_single_area()), observed, process="1", errors=errors)
    assert next(r["status"] for r in report if r["prefix"] == "10.99.0.0/24") == "mismatch"
    assert [e["subject"] for e in errors.as_dicts()] == ["10.99.0.0/24"]


def test_an_lsa_outside_the_vocabulary_is_reported_and_left_out():
    rows = [*_single_area(), _lsa("opaque-area", "1.0.0.1", R2)]
    calc = _calculate(rows)
    assert [e["kind"] for e in calc.model_errors] == ["unknown-lsa-type"]
    assert len(calc.routes) == 4


# --- determinism -----------------------------------------------------------


def test_the_calculation_is_deterministic():
    rows = [
        *_two_areas(),
        _external("203.0.113.0", MASK_24, 20, R3),
        _external("203.0.113.0", MASK_24, 20, R2),
        _external("198.51.100.0", MASK_24, 20, R2, forwarding_address="192.168.3.10"),
    ]
    reference = _calculate(rows)
    for seed in range(5):
        shuffled = list(rows)
        random.Random(seed).shuffle(shuffled)
        again = _calculate(shuffled)
        assert again.routes == reference.routes
        assert again.gaps == reference.gaps
        assert ospf.rib_rows(CTX, again) == ospf.rib_rows(CTX, reference)
    assert _calculate(rows).routes == reference.routes


# --- platform defaults -----------------------------------------------------


@pytest.mark.parametrize(
    "platform",
    [platforms.IOSXE, platforms.NXOS, platforms.IOSXR, platforms.FRR_TRADITIONAL, platforms.FRR_DATACENTER],
)
def test_the_ospf_administrative_distance_is_110_everywhere(platform):
    assert platforms.ospf_admin_distance(platform) == 110


@pytest.mark.parametrize(
    ("platform", "mbps", "rfc1583"),
    [
        (platforms.IOSXE, 100, True),
        (platforms.NXOS, 40_000, False),
        (platforms.IOSXR, 100, False),
        (platforms.FRR_TRADITIONAL, 100, False),
        (platforms.FRR_DATACENTER, 100, False),
    ],
)
def test_reference_bandwidth_and_rfc_1583_defaults_per_platform(platform, mbps, rfc1583):
    assert platforms.ospf_reference_bandwidth_mbps(platform) == mbps
    assert platforms.ospf_rfc1583_compatible(platform) is rfc1583


@pytest.mark.parametrize(
    ("platform", "kbps", "cost"),
    [
        (platforms.IOSXE, 1_544, 64),  # a T1 on IOS: 100 Mb/s over 1.544 Mb/s, truncated
        (platforms.IOSXE, 1_000_000, 1),  # a gigabit link costs 1 under a 100 Mb/s reference
        (platforms.NXOS, 10_000_000, 4),  # 40 Gb/s over 10 Gb/s
        (platforms.IOSXE, 60_000, 1),  # 1.67, truncated
        (platforms.FRR_TRADITIONAL, 60_000, 2),  # 1.67, rounded
        (platforms.IOSXE, 1, 65_535),  # clamped to the 16-bit link metric
    ],
)
def test_interface_cost_from_bandwidth(platform, kbps, cost):
    assert platforms.ospf_interface_cost(platform, kbps) == cost


def test_an_unknown_platform_takes_iosxe_defaults_and_is_reported():
    errors = ErrorSink()
    model = ospf.LsdbModel.from_rows(_single_area(), errors=errors)
    ospf.calculate(model, R1, platform="junos", errors=errors)
    assert [e["kind"] for e in errors.as_dicts()] == ["unknown-platform"]
