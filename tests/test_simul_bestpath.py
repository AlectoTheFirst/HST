"""Best-path ordering, session-type derivation, and the gap-13 platform defaults."""

import pytest

from hst.simul import bestpath, platforms
from hst.simul.errors import ErrorSink
from hst.simul.route import Route


def _route(**kwargs):
    return Route(prefix="10.0.0.0/24", **kwargs)


def _preferred(a, b):
    """Which of two routes wins, asserted in both argument orders."""
    forward = bestpath.compare_routes(a, b)
    assert forward == -bestpath.compare_routes(b, a)
    return a if forward > 0 else (b if forward < 0 else None)


# --- session type ----------------------------------------------------------


def test_session_type_is_derived_from_the_two_as_numbers():
    assert bestpath.session_type({"local_asn": 65001, "peer_asn": 65002}) == "ebgp"
    assert bestpath.session_type({"local_asn": 65001, "peer_asn": 65001}) == "ibgp"


def test_session_type_accepts_the_schema_string_form():
    assert bestpath.session_type({"local_asn": "65001", "peer_asn": "65002"}) == "ebgp"


# --- no policy attached ----------------------------------------------------


@pytest.mark.parametrize(
    ("platform", "ebgp_permits"),
    [
        (platforms.IOSXE, True),
        (platforms.NXOS, True),
        (platforms.IOSXR, False),
        (platforms.FRR_TRADITIONAL, False),
        (platforms.FRR_DATACENTER, True),
    ],
)
def test_gap_13_no_policy_default_per_platform(platform, ebgp_permits):
    """IOS-XR and FRR's `traditional` profile drop eBGP routes with no policy
    attached; IOS-XE, NX-OS and FRR's `datacenter` profile permit."""
    assert platforms.no_policy_permits(platform, "ebgp") is ebgp_permits
    assert platforms.no_policy_permits(platform, "ibgp") is True, "iBGP is never subject to it"


def test_a_bare_vyos_platform_is_reported_as_unresolved():
    """The FRR defaults profile flips the eBGP answer, and the platform `vyos`
    names no profile."""
    errors = ErrorSink()
    platforms.normalize("vyos", errors)
    assert "unresolved-platform-profile" in {e.kind for e in errors.errors}


def test_an_unknown_platform_is_reported():
    errors = ErrorSink()
    assert platforms.normalize("junos", errors) == platforms.IOSXE
    assert "unknown-platform" in {e.kind for e in errors.errors}


def test_a_session_with_no_policy_takes_the_platform_default():
    session = {"uid": "s1", "local_asn": 65001, "peer_asn": 65002}
    route = _route()
    kwargs = {"policies": {}, "prefix_lists": {}, "errors": ErrorSink()}
    assert (
        bestpath.apply_attached_policy(route, session, direction="in", platform=platforms.IOSXE, **kwargs)
        is route
    )
    assert (
        bestpath.apply_attached_policy(route, session, direction="in", platform=platforms.IOSXR, **kwargs)
        is None
    )


# --- undefined neighbour attachments ---------------------------------------


def test_an_undefined_neighbor_route_map_denies_the_direction():
    """An IOS-XE or NX-OS neighbour `route-map` in or out with an undefined name
    denies all routes in that direction."""
    session = {
        "uid": "s1",
        "local_asn": 65001,
        "peer_asn": 65002,
        "import_policy_name": "ABSENT",
        "import_policy_kind": "route-map",
    }
    errors = ErrorSink()
    assert (
        bestpath.apply_attached_policy(
            _route(),
            session,
            direction="in",
            platform=platforms.IOSXE,
            policies={},
            prefix_lists={},
            errors=errors,
        )
        is None
    )
    assert "undefined-neighbor-route-map" in {e.kind for e in errors.errors}


def test_an_undefined_neighbor_prefix_list_out_imposes_no_filter_on_nxos():
    """An undefined NX-OS neighbour `prefix-list` out accepts everything."""
    session = {
        "uid": "s1",
        "local_asn": 65001,
        "peer_asn": 65002,
        "export_policy_name": "ABSENT",
        "export_policy_kind": "prefix-list",
    }
    errors = ErrorSink()
    route = _route()
    assert (
        bestpath.apply_attached_policy(
            route,
            session,
            direction="out",
            platform=platforms.NXOS,
            policies={},
            prefix_lists={},
            errors=errors,
        )
        is route
    )
    assert "undefined-neighbor-prefix-list" in {e.kind for e in errors.errors}


# --- neighbour filter-list and a prefix-list beside a route-map --------------


def _compiled(platform):
    from hst.simul.compile import compile_policies

    return compile_policies(
        [
            {
                "name": "RM",
                "kind": "route-map",
                "entries": [{"seq": 10, "kind": "clause", "action": "permit"}],
            },
            {
                "name": "PL",
                "kind": "prefix-list",
                "entries": [
                    {"seq": 5, "action": "permit", "prefix": "10.9.0.0/16", "min_len": 16, "max_len": 24}
                ],
            },
        ],
        platform,
        ErrorSink(),
    )


@pytest.mark.parametrize("direction", ["in", "out"])
def test_a_neighbor_filter_list_denies_the_direction_and_is_reported(direction):
    """An AS-path filter-list is not evaluated: the direction fails closed,
    whatever else is attached, and the session is named."""
    prefix = "import" if direction == "in" else "export"
    session = {"uid": "s1", "local_asn": 65001, "peer_asn": 65002, f"{prefix}_filter_list_name": "AS-IN"}
    errors = ErrorSink()
    assert (
        bestpath.apply_attached_policy(
            _route(),
            session,
            direction=direction,
            platform=platforms.NXOS,
            policies={},
            prefix_lists={},
            errors=errors,
        )
        is None
    )
    assert [(e.kind, e.subject) for e in errors.errors] == [("neighbor-filter-list-not-modeled", "s1")]


def test_a_prefix_list_beside_a_route_map_filters_before_the_route_map_runs():
    policies, prefix_lists = _compiled(platforms.NXOS)
    session = {
        "uid": "s1",
        "local_asn": 65001,
        "peer_asn": 65002,
        "import_policy_name": "RM",
        "import_policy_kind": "route-map",
        "import_prefix_list_name": "PL",
    }
    kwargs = {"policies": policies, "prefix_lists": prefix_lists, "errors": ErrorSink()}
    denied = Route(prefix="10.0.0.0/24")
    permitted = Route(prefix="10.9.1.0/24")
    assert (
        bestpath.apply_attached_policy(denied, session, direction="in", platform=platforms.NXOS, **kwargs)
        is None
    )
    assert (
        bestpath.apply_attached_policy(permitted, session, direction="in", platform=platforms.NXOS, **kwargs)
        is not None
    )


# --- comparator, one case per level ----------------------------------------


def test_weight_wins_first():
    assert _preferred(_route(weight=100), _route(weight=0, local_pref=500)).weight == 100


def test_local_preference_beats_as_path_length():
    high = _route(local_pref=200, as_path=(1, 2, 3))
    low = _route(local_pref=100, as_path=(1,))
    assert _preferred(high, low) is high


def test_local_origination_is_compared_after_local_preference():
    """A locally originated route ranks after local preference and before AS-path length."""
    local = _route(origin_mechanism="network", as_path=(1, 2, 3))
    learned = _route(origin_mechanism="learned", as_path=(1,))
    assert _preferred(local, learned) is local, "local origination outranks a shorter path"

    # local preference outranks it
    learned_high_pref = _route(origin_mechanism="learned", local_pref=200)
    local_low_pref = _route(origin_mechanism="network", local_pref=100)
    assert _preferred(learned_high_pref, local_low_pref) is learned_high_pref

    # weight outranks local preference
    weighted_learned = _route(origin_mechanism="learned", weight=50)
    assert _preferred(weighted_learned, _route(origin_mechanism="network")) is weighted_learned


def test_a_network_originated_route_ranks_above_an_aggregate():
    """Within local origination, network and redistribute rank above aggregate."""
    network = _route(origin_mechanism="network")
    aggregate = _route(origin_mechanism="aggregate")
    assert _preferred(network, aggregate) is network
    assert _preferred(aggregate, _route(origin_mechanism="learned")) is aggregate


def test_shorter_as_path_wins():
    short = _route(as_path=(1,))
    assert _preferred(short, _route(as_path=(1, 2))) is short


def test_origin_type_ranks_igp_over_egp_over_incomplete():
    igp = _route(origin="igp")
    egp = _route(origin="egp")
    incomplete = _route(origin="incomplete")
    assert _preferred(igp, egp) is igp
    assert _preferred(egp, incomplete) is egp


def test_ebgp_beats_ibgp():
    ebgp = _route(protocol="bgp")
    assert _preferred(ebgp, _route(protocol="ibgp")) is ebgp


def test_lower_med_wins_within_the_same_neighbouring_as():
    low = _route(as_path=(65002, 3), med=10)
    high = _route(as_path=(65002, 4), med=50)
    assert _preferred(low, high) is low


def test_med_is_not_compared_across_different_neighbouring_ases():
    a = _route(as_path=(65002, 3), med=50)
    b = _route(as_path=(65003, 4), med=10)
    assert _preferred(a, b) is None, "the MED step is skipped, and nothing else separates them"


def test_med_is_compared_before_ebgp_over_ibgp():
    """Every vendor compares MED (same neighbouring AS) before it prefers
    an eBGP path, so the iBGP path with the lower MED is the best path."""
    ebgp = _route(protocol="bgp", as_path=(65002,), med=100)
    ibgp = _route(protocol="ibgp", as_path=(65002,), med=50)
    assert _preferred(ebgp, ibgp) is ibgp


def test_ebgp_beats_ibgp_when_the_med_step_does_not_separate_them():
    ebgp = _route(protocol="bgp", as_path=(65002,), med=50)
    ibgp = _route(protocol="ibgp", as_path=(65003,), med=10)
    assert _preferred(ebgp, ibgp) is ebgp, "different neighbouring ASes: the MED step is skipped"


def test_always_compare_med_compares_across_neighbouring_ases():
    a = _route(as_path=(65002, 3), med=50)
    b = _route(as_path=(65003, 4), med=10)
    assert bestpath.compare_preference(a, b, always_compare_med=True) < 0
    assert bestpath.compare_preference(b, a, always_compare_med=True) > 0
    assert bestpath.best_path([a, b], always_compare_med=True) is b
    assert bestpath.compare_preference(a, b) == 0


def test_a_missing_med_compares_as_zero_which_is_best():
    """`missing-as-worst` is off by default on every in-scope platform."""
    missing = _route(as_path=(65002,), med=None)
    explicit = _route(as_path=(65002,), med=10)
    assert _preferred(missing, explicit) is missing
    assert missing.effective_med == 0


def test_lower_igp_cost_to_the_next_hop_wins():
    near = _route(as_path=(65002,), igp_cost=5)
    far = _route(as_path=(65002,), igp_cost=50)
    assert _preferred(near, far) is near


def test_the_igp_cost_step_is_skipped_when_a_cost_is_unknown():
    assert _preferred(_route(igp_cost=5), _route(igp_cost=None)) is None


def test_arrival_order_breaks_a_tie_between_two_ebgp_routes():
    """Earlier arrival wins, and only for protocol BGP."""
    early = _route(arrival=1, originator_ip="10.0.0.9")
    late = _route(arrival=2, originator_ip="10.0.0.1")
    assert _preferred(early, late) is early


def test_a_lower_originator_id_breaks_a_tie():
    low = _route(protocol="ibgp", originator_ip="10.0.0.1")
    high = _route(protocol="ibgp", originator_ip="10.0.0.9")
    assert _preferred(low, high) is low


def test_originator_id_is_compared_whatever_the_tie_breaker_says():
    """The originator id comparison runs for every `tie_breaker` value."""
    low = _route(protocol="ibgp", originator_ip="10.0.0.1")
    high = _route(protocol="ibgp", originator_ip="10.0.0.9")
    assert bestpath.compare_routes(low, high, tie_breaker="cluster-list-length") > 0


def test_a_shorter_cluster_list_breaks_a_tie():
    short = _route(protocol="ibgp", originator_ip="10.0.0.1", cluster_list=("1.1.1.1",))
    long = _route(protocol="ibgp", originator_ip="10.0.0.1", cluster_list=("1.1.1.1", "2.2.2.2"))
    assert _preferred(short, long) is short


def test_received_from_compares_neighbour_ip_then_subtype_then_interface():
    lower_ip = _route(protocol="ibgp", originator_ip="10.0.0.1", received_from_ip="10.0.0.1")
    higher_ip = _route(protocol="ibgp", originator_ip="10.0.0.1", received_from_ip="10.0.0.9")
    assert _preferred(lower_ip, higher_ip) is lower_ip

    interface = _route(
        protocol="ibgp",
        originator_ip="10.0.0.1",
        received_from_kind="interface",
        received_from_interface="Ethernet1/1",
    )
    by_ip = _route(protocol="ibgp", originator_ip="10.0.0.1", received_from_kind="ip")
    assert _preferred(interface, by_ip) is interface


def test_no_path_id_beats_any_path_id():
    none = _route(protocol="ibgp", originator_ip="10.0.0.1", path_id=None)
    some = _route(protocol="ibgp", originator_ip="10.0.0.1", path_id=1)
    assert _preferred(none, some) is none
    lower = _route(protocol="ibgp", originator_ip="10.0.0.1", path_id=1)
    higher = _route(protocol="ibgp", originator_ip="10.0.0.1", path_id=2)
    assert _preferred(lower, higher) is lower


def test_best_path_picks_the_single_winner_from_a_candidate_set():
    routes = [
        _route(as_path=(1, 2, 3)),
        _route(as_path=(1,), local_pref=50),
        _route(as_path=(1, 2)),
    ]
    # The low-local-preference route loses on local preference despite its short path; the
    # remaining two are separated by AS-path length.
    assert bestpath.best_path(routes).as_path == (1, 2)


def test_best_path_of_nothing_is_nothing():
    assert bestpath.best_path([]) is None


# --- import and export rewrites --------------------------------------------


def _session(**kwargs):
    base = {"uid": "s1", "local_asn": 65001, "peer_asn": 65002, "local_ip": "10.0.0.1", "peer_ip": "10.0.0.2"}
    base.update(kwargs)
    return base


def test_import_rejects_a_route_whose_as_path_holds_the_local_as():
    """The AS-path loop check."""
    session = _session()
    assert (
        bestpath.import_route(
            _route(as_path=(65002, 65001)),
            session,
            platform=platforms.IOSXE,
            local_asn=65001,
            policies={},
            prefix_lists={},
            errors=ErrorSink(),
        )
        is None
    )


def test_allowas_in_lets_the_local_as_through():
    session = _session(allow_local_as_in=True)
    assert (
        bestpath.import_route(
            _route(as_path=(65002, 65001)),
            session,
            platform=platforms.IOSXE,
            local_asn=65001,
            policies={},
            prefix_lists={},
            errors=ErrorSink(),
        )
        is not None
    )


def test_import_tags_the_route_with_the_session_protocol_and_admin_distance():
    imported = bestpath.import_route(
        _route(as_path=(65002,)),
        _session(),
        platform=platforms.IOSXE,
        local_asn=65001,
        policies={},
        prefix_lists={},
        errors=ErrorSink(),
    )
    assert imported.protocol == "bgp"
    assert imported.admin == bestpath.DEFAULT_EBGP_ADMIN
    assert imported.received_from_ip == "10.0.0.2"
    assert imported.origin_mechanism == "learned"

    ibgp = bestpath.import_route(
        _route(as_path=(65002,)),
        _session(peer_asn=65001),
        platform=platforms.IOSXE,
        local_asn=65001,
        policies={},
        prefix_lists={},
        errors=ErrorSink(),
    )
    assert ibgp.protocol == "ibgp"
    assert ibgp.admin == bestpath.DEFAULT_IBGP_ADMIN


def test_ebgp_export_prepends_the_local_as_and_resets_the_transitive_attributes():
    """MED cleared, weight cleared, local preference reset,
    tag cleared, local AS prepended, next hop set to the local session IP."""
    exported = bestpath.export_route(
        _route(as_path=(65003,), med=42, weight=100, local_pref=250, tag=9),
        _session(),
        platform=platforms.IOSXE,
        local_asn=65001,
        local_router_id="10.255.0.1",
        policies={},
        prefix_lists={},
        errors=ErrorSink(),
    )
    assert exported.as_path == (65001, 65003)
    assert exported.med == 0
    assert exported.weight == 0
    assert exported.local_pref == 100
    assert exported.tag is None
    assert exported.next_hop == "10.0.0.1"
    assert exported.originator_ip == "10.255.0.1"


def test_ibgp_export_preserves_med_and_local_preference():
    """`advertiseUnchangedMed` and `advertiseUnchangedLocalPref` are both true for
    iBGP."""
    exported = bestpath.export_route(
        _route(as_path=(65003,), med=42, local_pref=250, origin_mechanism="network"),
        _session(peer_asn=65001),
        platform=platforms.IOSXE,
        local_asn=65001,
        local_router_id="10.255.0.1",
        policies={},
        prefix_lists={},
        errors=ErrorSink(),
    )
    assert exported.med == 42
    assert exported.local_pref == 250
    assert exported.as_path == (65003,), "iBGP export does not prepend"


def test_export_drops_a_route_carrying_no_advertise():
    assert (
        bestpath.export_route(
            _route(communities=frozenset({"no-advertise"})),
            _session(),
            platform=platforms.IOSXE,
            local_asn=65001,
            local_router_id="10.255.0.1",
            policies={},
            prefix_lists={},
            errors=ErrorSink(),
        )
        is None
    )


def test_ebgp_export_drops_a_route_carrying_no_export():
    assert (
        bestpath.export_route(
            _route(communities=frozenset({"no-export"}), as_path=(65003,)),
            _session(),
            platform=platforms.IOSXE,
            local_asn=65001,
            local_router_id="10.255.0.1",
            policies={},
            prefix_lists={},
            errors=ErrorSink(),
        )
        is None
    )


def test_ebgp_export_does_not_send_a_route_back_to_its_own_first_as():
    """The export applies `AllowRemoteAsOutMode.EXCEPT_FIRST`."""
    assert (
        bestpath.export_route(
            _route(as_path=(65002, 65004)),
            _session(),
            platform=platforms.IOSXE,
            local_asn=65001,
            local_router_id="10.255.0.1",
            policies={},
            prefix_lists={},
            errors=ErrorSink(),
        )
        is None
    )


def test_ibgp_export_drops_a_learned_route_that_is_not_reflectable():
    """An iBGP-learned route is not passed to another iBGP peer
    unless route reflection makes it eligible."""
    route = _route(protocol="ibgp", as_path=(65003,))
    assert (
        bestpath.export_route(
            route,
            _session(peer_asn=65001),
            platform=platforms.IOSXE,
            local_asn=65001,
            local_router_id="10.255.0.1",
            policies={},
            prefix_lists={},
            errors=ErrorSink(),
            sending_session={"uid": "s0", "local_asn": 65001, "peer_asn": 65001},
        )
        is None
    )


def test_ibgp_export_carries_an_ebgp_learned_route():
    """A best path from the local BGP RIB is exported to
    every iBGP peer regardless of reflection. The drop only applies to
    a route that is itself iBGP-sourced and not reflectable (below)."""
    learned = bestpath.import_route(
        _route(as_path=(65003,)),
        _session(local_asn=65001, peer_asn=65002),
        platform=platforms.IOSXE,
        local_asn=65001,
        policies={},
        prefix_lists={},
        errors=ErrorSink(),
    )
    assert learned.protocol == "bgp"
    assert learned.is_locally_originated is False

    exported = bestpath.export_route(
        learned,
        _session(peer_asn=65001),
        platform=platforms.IOSXE,
        local_asn=65001,
        local_router_id="10.255.0.1",
        policies={},
        prefix_lists={},
        errors=ErrorSink(),
        sending_session={"uid": "s0", "local_asn": 65001, "peer_asn": 65001},
    )
    assert exported is not None


def test_a_reflector_appends_its_cluster_id_when_reflecting_to_a_client():
    route = _route(protocol="ibgp", as_path=(65003,), originator_ip="10.255.0.9")
    exported = bestpath.export_route(
        route,
        _session(peer_asn=65001, route_reflector_client=True, cluster_id="1.1.1.1"),
        platform=platforms.IOSXE,
        local_asn=65001,
        local_router_id="10.255.0.1",
        policies={},
        prefix_lists={},
        errors=ErrorSink(),
        sending_session={"uid": "s0", "local_asn": 65001, "peer_asn": 65001},
    )
    assert exported is not None
    assert exported.cluster_list == ("1.1.1.1",)
    assert exported.originator_ip == "10.255.0.9", "the originator is preserved on iBGP"


def _reflect(route, **session):
    return bestpath.export_route(
        route,
        _session(peer_asn=65001, route_reflector_client=True, **session),
        platform=platforms.IOSXE,
        local_asn=65001,
        local_router_id="10.255.0.1",
        policies={},
        prefix_lists={},
        errors=ErrorSink(),
        sending_session={"uid": "s0", "local_asn": 65001, "peer_asn": 65001},
    )


def test_a_reflector_with_no_configured_cluster_id_appends_its_router_id():
    """With no `cluster-id` the reflector's cluster id is its router id,
    so the cluster list still records the reflection."""
    exported = _reflect(_route(protocol="ibgp", as_path=(65003,), originator_ip="10.255.0.9"))
    assert exported is not None
    assert exported.cluster_list == ("10.255.0.1",)


def test_a_route_is_not_reflected_to_a_reflector_whose_cluster_it_has_passed():
    """A receiving reflector drops a route whose cluster list holds its
    cluster id, so the sender does not send it."""
    looped = _route(protocol="ibgp", as_path=(65003,), originator_ip="10.255.0.9", cluster_list=("10.9.9.9",))
    assert _reflect(looped, peer_cluster_ids=["10.9.9.9"]) is None
    assert _reflect(looped, peer_cluster_ids=["10.8.8.8"]) is not None


def test_a_route_that_is_not_reflected_still_reaches_a_reflector_in_the_same_cluster():
    """Two reflectors of one cluster: the one that learned a route over eBGP
    sends it to the other, since it adds no cluster id to a route it does not
    reflect; a reflected route would carry the shared id and is not sent."""
    learned = _route(as_path=(65003,))
    assert _reflect(learned, cluster_id="10.9.9.9", peer_cluster_ids=["10.9.9.9"]) is not None
    reflected = _route(protocol="ibgp", as_path=(65003,), originator_ip="10.255.0.9")
    assert _reflect(reflected, cluster_id="10.9.9.9", peer_cluster_ids=["10.9.9.9"]) is None


# --- next-hop-self on an iBGP export ----------------------------------------


def _ibgp_export(route, *, next_hop_self=None, client=False, sending=None):
    session = _session(peer_asn=65001, route_reflector_client=client, cluster_id="1.1.1.1")
    if next_hop_self:
        session["next_hop_self"] = next_hop_self
    return bestpath.export_route(
        route,
        session,
        platform=platforms.IOSXE,
        local_asn=65001,
        local_router_id="10.255.0.1",
        policies={},
        prefix_lists={},
        errors=ErrorSink(),
        sending_session=sending,
    )


def test_an_ibgp_export_keeps_the_external_next_hop_without_next_hop_self():
    learned = _route(as_path=(65003,), next_hop="192.0.2.1")
    assert _ibgp_export(learned).next_hop == "192.0.2.1"


@pytest.mark.parametrize("mode", ["ebgp", "all"])
def test_next_hop_self_rewrites_an_ebgp_learned_route_to_the_local_address(mode):
    learned = _route(as_path=(65003,), next_hop="192.0.2.1")
    assert _ibgp_export(learned, next_hop_self=mode).next_hop == "10.0.0.1"


def test_plain_next_hop_self_leaves_a_reflected_route_alone_and_all_rewrites_it():
    reflected = _route(protocol="ibgp", as_path=(65003,), next_hop="192.0.2.1", originator_ip="10.255.0.9")
    sending = {"uid": "s0", "local_asn": 65001, "peer_asn": 65001}
    plain = _ibgp_export(reflected, next_hop_self="ebgp", client=True, sending=sending)
    assert plain is not None
    assert plain.next_hop == "192.0.2.1"
    everything = _ibgp_export(reflected, next_hop_self="all", client=True, sending=sending)
    assert everything is not None
    assert everything.next_hop == "10.0.0.1"


def test_an_export_policy_next_hop_wins_over_next_hop_self():
    exported = bestpath._post_export(
        _route(as_path=(65003,), next_hop="198.51.100.9"),
        _session(peer_asn=65001, next_hop_self="all"),
        stype=bestpath.IBGP,
        local_asn=65001,
        local_ip="10.0.0.1",
        original_next_hop="192.0.2.1",
        policy_set_next_hop=True,
        reflecting=False,
    )
    assert exported.next_hop == "198.51.100.9"
