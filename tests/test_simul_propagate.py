"""Propagation to a fixed point, and the provider's output shape."""

from hst.simul import bestpath, compute_route_delta
from hst.simul.propagate import MAX_ROUNDS


def _process(uid, context_uid, asn, router_id, platform="iosxe"):
    return {
        "uid": uid,
        "context_uid": context_uid,
        "proto": "bgp",
        "asn": asn,
        "router_id": router_id,
        "platform": platform,
    }


def _session(uid, process_uid, local_asn, peer_asn, local_ip, peer_ip, **kwargs):
    return {
        "uid": uid,
        "process_uid": process_uid,
        "local_asn": local_asn,
        "peer_asn": peer_asn,
        "local_ip": local_ip,
        "peer_ip": peer_ip,
        **kwargs,
    }


PREFIX_LIST = {
    "name": "PL_BLOCKED",
    "kind": "prefix-list",
    "entries": [
        {
            "seq": 5,
            "action": "permit",
            "prefix": "192.168.20.0/24",
            "min_len": 24,
            "max_len": 24,
        }
    ],
}

# A route-map that denies 192.168.20.0/24 and permits everything else.
EXPORT_MAP = {
    "name": "RM_OUT",
    "kind": "route-map",
    "entries": [
        {"seq": 10, "kind": "clause", "action": "deny", "match_prefix_lists": ["PL_BLOCKED"]},
        {"seq": 20, "kind": "clause", "action": "permit"},
    ],
}


def _two_router_estate(export_policy_on_b=True):
    b_session = _session("sess:b", "proc:b", 65002, 65001, "10.0.0.2", "10.0.0.1")
    if export_policy_on_b:
        b_session["export_policy_name"] = "RM_OUT"
        b_session["export_policy_kind"] = "route-map"
    return {
        "processes": [
            _process("proc:a", "vrf:dev-a:default", 65001, "10.255.0.1"),
            _process("proc:b", "vrf:dev-b:default", 65002, "10.255.0.2"),
        ],
        "sessions": [
            _session("sess:a", "proc:a", 65001, 65002, "10.0.0.1", "10.0.0.2"),
            b_session,
        ],
        "policies": [PREFIX_LIST, EXPORT_MAP],
        "local_routes": [
            {"process_uid": "proc:a", "prefix": "192.168.10.0/24"},
            {"process_uid": "proc:b", "prefix": "192.168.20.0/24"},
            {"process_uid": "proc:b", "prefix": "192.168.30.0/24"},
        ],
    }


def test_two_router_propagation_with_an_export_policy_filtering_one_prefix():
    delta = compute_route_delta(**_two_router_estate())
    assert delta.model_errors == []
    rows = {(r["context_uid"], r["prefix"]): r for r in delta.rib}

    assert sorted(rows) == [
        ("vrf:dev-a:default", "192.168.10.0/24"),
        ("vrf:dev-a:default", "192.168.30.0/24"),
        ("vrf:dev-b:default", "192.168.10.0/24"),
        ("vrf:dev-b:default", "192.168.20.0/24"),
        ("vrf:dev-b:default", "192.168.30.0/24"),
    ], "B's outbound route-map denies 192.168.20.0/24, so A never holds it"

    learned = rows[("vrf:dev-a:default", "192.168.30.0/24")]
    assert learned == {
        "context_uid": "vrf:dev-a:default",
        "prefix": "192.168.30.0/24",
        "next_hop": "10.0.0.2",
        "protocol": "bgp",
        "metric": 0,
        "local_pref": 100,
        # `advertiseUnchangedMed()` is true for a locally originated route.
        "med": None,
        "weight": 0,
        "as_path": [65002],
        "origin": "igp",
        "origin_mechanism": "learned",
        "session_protocol": "bgp",
        "admin": 20,
        "communities": [],
        "originator_ip": "10.255.0.2",
        "cluster_list": [],
        "tag": None,
    }

    originated = rows[("vrf:dev-a:default", "192.168.10.0/24")]
    assert originated["origin_mechanism"] == "network"
    assert originated["weight"] == 32768, "IOS's default weight for a local route"
    assert originated["as_path"] == []

    on_b = rows[("vrf:dev-b:default", "192.168.10.0/24")]
    assert on_b["as_path"] == [65001]
    assert on_b["next_hop"] == "10.0.0.1"


def test_removing_the_export_policy_lets_the_filtered_prefix_through():
    """The same estate with nothing attached: IOS-XE permits by default,
    so all three prefixes are present on both sides."""
    delta = compute_route_delta(**_two_router_estate(export_policy_on_b=False))
    assert delta.model_errors == []
    prefixes = sorted({r["prefix"] for r in delta.rib if r["context_uid"] == "vrf:dev-a:default"})
    assert prefixes == ["192.168.10.0/24", "192.168.20.0/24", "192.168.30.0/24"]


def test_the_same_estate_on_iosxr_drops_everything_without_a_policy():
    """IOS-XR discards eBGP routes in both directions with no
    route-policy attached, so only the locally originated routes remain."""
    estate = _two_router_estate(export_policy_on_b=False)
    for process in estate["processes"]:
        process["platform"] = "iosxr"
    delta = compute_route_delta(**estate)
    assert sorted((r["context_uid"], r["prefix"]) for r in delta.rib) == [
        ("vrf:dev-a:default", "192.168.10.0/24"),
        ("vrf:dev-b:default", "192.168.20.0/24"),
        ("vrf:dev-b:default", "192.168.30.0/24"),
    ]


def test_the_run_is_deterministic():
    estate = _two_router_estate()
    assert compute_route_delta(**estate).rib == compute_route_delta(**estate).rib


def test_a_stable_estate_settles_in_at_most_three_rounds():
    delta = compute_route_delta(**_two_router_estate())
    assert delta.model_errors == []
    assert delta.rounds <= 3


def test_an_oscillation_reports_no_fixed_point(monkeypatch):
    """A winner that flips every round never settles."""
    real_best_path = bestpath.best_path
    consultations = {"count": 0}

    def flapping_best_path(routes, **kwargs):
        best = real_best_path(routes, **kwargs)
        # B consults its own candidates for 192.168.30.0/24 once per round. On
        # every other consultation the winner carries a different origin, so
        # A receives a changed path in every round.
        if best is not None and best.prefix == "192.168.30.0/24" and best.is_locally_originated:
            consultations["count"] += 1
            if consultations["count"] % 2 == 0:
                return best.with_(origin="egp")
        return best

    monkeypatch.setattr(bestpath, "best_path", flapping_best_path)
    delta = compute_route_delta(**_two_router_estate())
    assert "no-routing-fixed-point" in {e["kind"] for e in delta.model_errors}
    assert delta.rounds == MAX_ROUNDS


def test_an_unpaired_session_is_reported_as_missing_input():
    estate = _two_router_estate()
    estate["sessions"] = [estate["sessions"][0]]
    delta = compute_route_delta(**estate)
    assert "unpaired-bgp-session" in {e["kind"] for e in delta.model_errors}


def test_model_errors_travel_with_the_prediction():
    """A dangling reference reaches the caller in the same object as the rows."""
    estate = _two_router_estate()
    estate["sessions"][0]["import_policy_name"] = "ABSENT"
    estate["sessions"][0]["import_policy_kind"] = "route-map"
    delta = compute_route_delta(**estate)
    assert "undefined-neighbor-route-map" in {e["kind"] for e in delta.model_errors}
    assert not [r for r in delta.rib if r["context_uid"] == "vrf:dev-a:default" and r["as_path"]], (
        "an undefined inbound route-map denies every route in that direction"
    )


def test_a_shut_session_carries_nothing():
    estate = _two_router_estate()
    estate["sessions"][1]["state"] = "shutdown"
    delta = compute_route_delta(**estate)
    a_rows = sorted(r["prefix"] for r in delta.rib if r["context_uid"] == "vrf:dev-a:default")
    assert a_rows == ["192.168.10.0/24"]


def test_a_route_originated_on_one_side_is_not_looped_back():
    """The AS-path loop check at import stops A's own prefix returning."""
    delta = compute_route_delta(**_two_router_estate())
    a_rows = [r for r in delta.rib if r["context_uid"] == "vrf:dev-a:default"]
    own = [r for r in a_rows if r["prefix"] == "192.168.10.0/24"]
    assert len(own) == 1 and own[0]["origin_mechanism"] == "network"


def test_summary_only_aggregate_holds_its_more_specifics_back_from_advertisement():
    """B originates two /24s and a `summary-only` /16 over them. A receives
    the /16 only; the /24s stay in B's own table, and the delta names each
    suppressed advertisement with the aggregate that caused it."""
    estate = _two_router_estate(export_policy_on_b=False)
    estate["local_routes"] = [
        {"process_uid": "proc:a", "prefix": "192.168.10.0/24"},
        {"process_uid": "proc:b", "prefix": "172.16.20.0/24"},
        {"process_uid": "proc:b", "prefix": "172.16.30.0/24"},
        {
            "process_uid": "proc:b",
            "prefix": "172.16.0.0/16",
            "origin_mechanism": "aggregate",
            "summary_only": True,
        },
    ]
    delta = compute_route_delta(**estate)
    assert delta.model_errors == []
    rows = {(r["context_uid"], r["prefix"]) for r in delta.rib}

    assert rows == {
        ("vrf:dev-a:default", "192.168.10.0/24"),
        ("vrf:dev-a:default", "172.16.0.0/16"),
        ("vrf:dev-b:default", "192.168.10.0/24"),
        ("vrf:dev-b:default", "172.16.0.0/16"),
        ("vrf:dev-b:default", "172.16.20.0/24"),
        ("vrf:dev-b:default", "172.16.30.0/24"),
    }
    assert delta.suppressed == [
        {
            "process_uid": "proc:b",
            "context_uid": "vrf:dev-b:default",
            "session_uid": "sess:b",
            "prefix": "172.16.20.0/24",
            "aggregate": "172.16.0.0/16",
        },
        {
            "process_uid": "proc:b",
            "context_uid": "vrf:dev-b:default",
            "session_uid": "sess:b",
            "prefix": "172.16.30.0/24",
            "aggregate": "172.16.0.0/16",
        },
    ]


def test_an_aggregate_without_summary_only_advertises_its_more_specifics():
    estate = _two_router_estate(export_policy_on_b=False)
    estate["local_routes"] = [
        {"process_uid": "proc:b", "prefix": "172.16.20.0/24"},
        {"process_uid": "proc:b", "prefix": "172.16.0.0/16", "origin_mechanism": "aggregate"},
    ]
    delta = compute_route_delta(**estate)
    on_a = {r["prefix"] for r in delta.rib if r["context_uid"] == "vrf:dev-a:default"}
    assert on_a == {"172.16.0.0/16", "172.16.20.0/24"}
    assert delta.suppressed == []


def test_a_reflector_computes_each_best_path_once_per_round_not_once_per_session(monkeypatch):
    """A route reflector with 20 clients exports one best path per prefix to
    every client. The best path is computed once per prefix per round, so the
    calls stay below one per predicted row per round."""
    processes = [_process("rr", "vrf:rr", 65000, "10.0.0.1")]
    sessions, local = [], []
    for i in range(20):
        client, address = f"cl{i:02d}", f"10.1.0.{i + 1}"
        processes.append(_process(client, f"vrf:{client}", 65000, address))
        sessions.append(
            _session(f"s:rr:{client}", "rr", 65000, 65000, "10.0.0.1", address, route_reflector_client=True)
        )
        sessions.append(_session(f"s:{client}:rr", client, 65000, 65000, address, "10.0.0.1"))
        local.append({"process_uid": client, "prefix": f"172.16.{i}.0/24", "next_hop": address})
    real_best_path = bestpath.best_path
    calls = {"count": 0}

    def counting_best_path(routes, **kwargs):
        calls["count"] += 1
        return real_best_path(routes, **kwargs)

    monkeypatch.setattr(bestpath, "best_path", counting_best_path)
    delta = compute_route_delta(processes=processes, sessions=sessions, local_routes=local)
    assert len(delta.rib) == 21 * 20
    assert calls["count"] <= delta.rounds * len(delta.rib)


# --- route-reflector-client not recorded ------------------------------------------------
#
# A route reflector RR with two clients C1 and C2. C1 originates 172.16.1.0/24;
# RR reflects it to C2 only when its sessions say the two are clients.


def _reflector_estate(rr_flag):
    extra = {} if rr_flag is None else {"route_reflector_client": rr_flag}
    return {
        "processes": [
            _process("rr", "vrf:rr", 65000, "10.0.0.1"),
            _process("c1", "vrf:c1", 65000, "10.0.0.2"),
            _process("c2", "vrf:c2", 65000, "10.0.0.3"),
        ],
        "sessions": [
            _session("s:rr:c1", "rr", 65000, 65000, "10.0.0.1", "10.0.0.2", **extra),
            _session("s:rr:c2", "rr", 65000, 65000, "10.0.0.1", "10.0.0.3", **extra),
            _session("s:c1:rr", "c1", 65000, 65000, "10.0.0.2", "10.0.0.1", route_reflector_client=False),
            _session("s:c2:rr", "c2", 65000, 65000, "10.0.0.3", "10.0.0.1", route_reflector_client=False),
        ],
        "local_routes": [{"process_uid": "c1", "prefix": "172.16.1.0/24", "next_hop": "10.0.0.2"}],
    }


def _on(delta, context_uid):
    return {r["prefix"] for r in delta.rib if r["context_uid"] == context_uid}


def test_a_reflector_whose_sessions_record_the_client_setting_reflects_without_error():
    delta = compute_route_delta(**_reflector_estate(True))
    assert "172.16.1.0/24" in _on(delta, "vrf:c2")
    assert delta.model_errors == []


def test_a_reflector_whose_sessions_state_no_clients_reflects_nothing_without_error():
    delta = compute_route_delta(**_reflector_estate(False))
    assert "172.16.1.0/24" not in _on(delta, "vrf:c2")
    assert delta.model_errors == []


def test_an_ibgp_process_whose_sessions_do_not_record_the_client_setting_is_reported():
    """The setting absent is unknown."""
    delta = compute_route_delta(**_reflector_estate(None))
    errors = [e for e in delta.model_errors if e["kind"] == "bgp-reflection-unknown"]
    assert [e["subject"] for e in errors] == ["rr"]
    assert "s:rr:c1" in errors[0]["detail"] and "s:rr:c2" in errors[0]["detail"]


def test_a_single_ibgp_session_never_reflects_and_is_not_reported():
    estate = _reflector_estate(None)
    estate["sessions"] = [s for s in estate["sessions"] if s["uid"] in ("s:rr:c1", "s:c1:rr")]
    estate["processes"] = estate["processes"][:2]
    delta = compute_route_delta(**estate)
    assert delta.model_errors == []


def _device_policies(device_uid, blocked):
    """One device's own `PL_BLOCKED` and `RM_OUT`: the names every device of a
    templated estate defines, with content of its own."""
    return [
        {
            "uid": f"rtpol:{device_uid}:prefix-list:PL_BLOCKED",
            "device_uid": device_uid,
            "name": "PL_BLOCKED",
            "kind": "prefix-list",
            "entries": [{"seq": 5, "action": "permit", "prefix": blocked, "min_len": 24, "max_len": 24}],
        },
        {
            "uid": f"rtpol:{device_uid}:route-map:RM_OUT",
            "device_uid": device_uid,
            "name": "RM_OUT",
            "kind": "route-map",
            "entries": [
                {"seq": 10, "kind": "clause", "action": "deny", "match_prefix_lists": ["PL_BLOCKED"]},
                {"seq": 20, "kind": "clause", "action": "permit"},
            ],
        },
    ]


def test_route_policies_of_one_name_on_two_devices_are_evaluated_each_on_its_own_device():
    """Both devices export through a route-map `RM_OUT` that calls a
    prefix-list `PL_BLOCKED`, and each device's own content decides: A blocks
    10.1.0.0/24 and B blocks 10.2.0.0/24."""
    estate = {
        "processes": [
            {**_process("proc:a", "vrf:a", 65001, "10.255.0.1"), "device_uid": "dev:a"},
            {**_process("proc:b", "vrf:b", 65002, "10.255.0.2"), "device_uid": "dev:b"},
        ],
        "sessions": [
            _session("sess:a", "proc:a", 65001, 65002, "10.0.0.1", "10.0.0.2", export_policy_name="RM_OUT"),
            _session("sess:b", "proc:b", 65002, 65001, "10.0.0.2", "10.0.0.1", export_policy_name="RM_OUT"),
        ],
        "policies": [
            *_device_policies("dev:a", "10.1.0.0/24"),
            *_device_policies("dev:b", "10.2.0.0/24"),
        ],
        "local_routes": [
            {"process_uid": "proc:a", "prefix": "10.1.0.0/24"},
            {"process_uid": "proc:a", "prefix": "10.1.1.0/24"},
            {"process_uid": "proc:b", "prefix": "10.2.0.0/24"},
            {"process_uid": "proc:b", "prefix": "10.2.1.0/24"},
        ],
    }

    delta = compute_route_delta(**estate)

    assert delta.model_errors == []
    held = {(r["context_uid"], r["prefix"]) for r in delta.rib}
    assert held == {
        ("vrf:a", "10.1.0.0/24"),
        ("vrf:a", "10.1.1.0/24"),
        ("vrf:a", "10.2.1.0/24"),
        ("vrf:b", "10.2.0.0/24"),
        ("vrf:b", "10.2.1.0/24"),
        ("vrf:b", "10.1.1.0/24"),
    }


def test_route_policies_of_one_name_in_two_virtual_systems_of_one_gateway_are_two_policies():
    """Two Check Point virtual systems of one gateway both export
    through a route map `RM_OUT` of their own; each policy row states its
    routing context. Each virtual system evaluates its own: VS1 blocks
    10.1.0.0/24, VS2 blocks 10.2.1.0/24."""

    def scoped(policies, context):
        return [{**p, "context_uid": context, "uid": f"{p['uid']}:{context}"} for p in policies]

    estate = {
        "processes": [
            {**_process("proc:vs1", "vrf:gw:vs1", 65001, "10.255.0.1"), "device_uid": "dev:gw"},
            {**_process("proc:vs2", "vrf:gw:vs2", 65001, "10.255.0.2"), "device_uid": "dev:gw"},
            {**_process("proc:a", "vrf:a", 65002, "10.255.0.3"), "device_uid": "dev:a"},
            {**_process("proc:b", "vrf:b", 65003, "10.255.0.4"), "device_uid": "dev:b"},
        ],
        "sessions": [
            _session("s:vs1", "proc:vs1", 65001, 65002, "10.0.1.1", "10.0.1.2", export_policy_name="RM_OUT"),
            _session("s:a", "proc:a", 65002, 65001, "10.0.1.2", "10.0.1.1"),
            _session("s:vs2", "proc:vs2", 65001, 65003, "10.0.2.1", "10.0.2.2", export_policy_name="RM_OUT"),
            _session("s:b", "proc:b", 65003, 65001, "10.0.2.2", "10.0.2.1"),
        ],
        "policies": [
            *scoped(_device_policies("dev:gw", "10.1.0.0/24"), "vrf:gw:vs1"),
            *scoped(_device_policies("dev:gw", "10.2.1.0/24"), "vrf:gw:vs2"),
        ],
        "local_routes": [
            {"process_uid": "proc:vs1", "prefix": "10.1.0.0/24"},
            {"process_uid": "proc:vs1", "prefix": "10.1.1.0/24"},
            {"process_uid": "proc:vs2", "prefix": "10.2.0.0/24"},
            {"process_uid": "proc:vs2", "prefix": "10.2.1.0/24"},
        ],
    }

    delta = compute_route_delta(**estate)

    assert delta.model_errors == []
    held = {(r["context_uid"], r["prefix"]) for r in delta.rib}
    assert {prefix for context, prefix in held if context == "vrf:a"} == {"10.1.1.0/24"}
    assert {prefix for context, prefix in held if context == "vrf:b"} == {"10.2.0.0/24"}


def test_policies_that_name_no_device_stay_one_name_keyed_input():
    """An input that states no owner keeps one namespace of policy names."""
    delta = compute_route_delta(**_two_router_estate())
    assert delta.model_errors == []
