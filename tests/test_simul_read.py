"""The graph read behind provider 2 (`hst.app.simul_read`)."""

import pytest
from tests.support.cputime import cpu_time

from hst import path as pathmod
from hst.app import simul_read
from hst.simul import proof
from hst.simul.errors import ErrorSink


class _Graph:
    """A fake `path._read`: one canned answer per query, keyed by a fragment."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, session, query, **params):
        self.calls.append((query, params))
        for fragment, rows in self.answers.items():
            if fragment in query:
                return rows(params) if callable(rows) else rows
        return []


def _install(monkeypatch, answers):
    graph = _Graph(answers)
    monkeypatch.setattr(pathmod, "_read", graph)
    return graph


# Two routers, one eBGP peering, one prefix originated on each side.
PROC_A = {
    "uid": "rp:a",
    "props": {"uid": "rp:a", "proto": "bgp", "asn": 65001, "router_id": "10.0.0.1"},
    "context_uid": "vrf:a:default",
    "platforms": ["iosxe"],
    "vendors": ["cisco"],
}
PROC_B = {
    "uid": "rp:b",
    "props": {"uid": "rp:b", "proto": "bgp", "asn": 65002, "router_id": "10.0.0.2"},
    "context_uid": "vrf:b:default",
    "platforms": ["iosxe"],
    "vendors": ["cisco"],
}
SESS_A = {
    "uid": "bgp:a:1",
    "process_uid": "rp:a",
    "props": {"uid": "bgp:a:1", "local_asn": 65001, "peer_asn": 65002, "peer_ip": "192.0.2.2"},
}
SESS_B = {
    "uid": "bgp:b:1",
    "process_uid": "rp:b",
    "props": {"uid": "bgp:b:1", "local_asn": 65002, "peer_asn": 65001, "peer_ip": "192.0.2.1"},
}
ADDRESSES = [
    {"process_uid": "rp:a", "ip": "192.0.2.1"},
    {"process_uid": "rp:b", "ip": "192.0.2.2"},
]


def _two_router_answers(**overrides):
    answers = {
        "(d:Device:Obj {uid: $dev, collection_ts: $snap})": [{"uid": "rp:a"}],
        "far.uid AS uid": [{"uid": "rp:b"}],
        "collect(DISTINCT d.platform)": [PROC_A, PROC_B],
        "properties(b) AS props": [SESS_A, SESS_B],
        "ip.ip AS ip": ADDRESSES,
        "og.proto AS proto": [
            {"process_uid": "rp:a", "prefix": "10.1.0.0/24", "proto": "connected"},
            {"process_uid": "rp:b", "prefix": "10.2.0.0/24", "proto": "aggregate"},
        ],
        "collect(properties(e)) AS entries": [],
    }
    answers.update(overrides)
    return answers


def test_scope_requires_exactly_one_of_device_or_vrf():
    with pytest.raises(ValueError):
        simul_read.read_simulation_input(object())
    with pytest.raises(ValueError):
        simul_read.read_simulation_input(object(), device="d", vrf="v")


def test_empty_scope_reports_no_bgp_process_in_scope(monkeypatch):
    _install(monkeypatch, {})
    result = simul_read.read_simulation_input(object(), device="dev:x")
    assert result.processes == []
    assert [e["kind"] for e in result.errors.as_dicts()] == ["no-bgp-process-in-scope"]


def test_device_scope_widens_by_one_peering_hop(monkeypatch):
    graph = _install(monkeypatch, _two_router_answers())
    result = simul_read.read_simulation_input(object(), device="dev:a")

    assert [p["uid"] for p in result.processes] == ["rp:a", "rp:b"]
    # The far-end process is fetched.
    procs = next(p["procs"] for q, p in graph.calls if "collect(DISTINCT d.platform)" in q)
    assert procs == ["rp:a", "rp:b"]


def test_context_uid_comes_from_the_in_vrf_edge(monkeypatch):
    _install(monkeypatch, _two_router_answers())
    result = simul_read.read_simulation_input(object(), device="dev:a")
    assert {p["uid"]: p["context_uid"] for p in result.processes} == {
        "rp:a": "vrf:a:default",
        "rp:b": "vrf:b:default",
    }


def test_local_ip_is_derived_from_the_far_end_and_mirrors(monkeypatch):
    _install(monkeypatch, _two_router_answers())
    result = simul_read.read_simulation_input(object(), device="dev:a")
    by_uid = {s["uid"]: s for s in result.sessions}

    # No collector writes local_ip; it is the far end's peer_ip. The engine
    # pairs on the mirrored tuple, so both directions must line up.
    assert by_uid["bgp:a:1"]["local_ip"] == "192.0.2.1"
    assert by_uid["bgp:b:1"]["local_ip"] == "192.0.2.2"
    a, b = by_uid["bgp:a:1"], by_uid["bgp:b:1"]
    assert (a["local_ip"], a["peer_ip"]) == (b["peer_ip"], b["local_ip"])


def test_peer_router_id_is_filled_from_the_far_process(monkeypatch):
    _install(monkeypatch, _two_router_answers())
    result = simul_read.read_simulation_input(object(), device="dev:a")
    by_uid = {s["uid"]: s for s in result.sessions}
    assert by_uid["bgp:a:1"]["peer_router_id"] == "10.0.0.2"
    assert by_uid["bgp:b:1"]["peer_router_id"] == "10.0.0.1"


def test_peer_cluster_ids_are_the_far_reflectors_cluster_ids(monkeypatch):
    """The far process reflects to a client and states its cluster id
    on one session; its router id is the cluster id of the client session that
    states none. A process that reflects nothing and states none has none."""
    reflector = {**SESS_B, "props": {**SESS_B["props"], "route_reflector_client": True}}
    other = {
        "uid": "bgp:b:2",
        "process_uid": "rp:b",
        "props": {"uid": "bgp:b:2", "local_asn": 65002, "peer_asn": 65003, "peer_ip": "198.51.100.9"},
    }
    configured = {**other, "props": {**other["props"], "cluster_id": "10.9.9.9"}}
    _install(monkeypatch, _two_router_answers(**{"properties(b) AS props": [SESS_A, reflector, configured]}))
    result = simul_read.read_simulation_input(object(), device="dev:a")
    by_uid = {s["uid"]: s for s in result.sessions}
    assert by_uid["bgp:a:1"]["peer_cluster_ids"] == ["10.0.0.2", "10.9.9.9"]
    assert "peer_cluster_ids" not in by_uid["bgp:b:1"]


def test_a_neighbor_written_as_no_session_is_reported_on_its_process(monkeypatch):
    """A collector names the neighbors it wrote no session for on the
    process; the read reports them with an uncertain kind."""
    gapped = {
        **PROC_A,
        "props": {**PROC_A["props"], "session_gaps": ["neighbor 10.0.0.4 has no resolvable remote-as"]},
    }
    _install(monkeypatch, _two_router_answers(**{"collect(DISTINCT d.platform)": [gapped, PROC_B]}))
    result = simul_read.read_simulation_input(object(), device="dev:a")
    errors = [e for e in result.errors.as_dicts() if e["kind"] == "bgp-session-not-recorded"]
    assert len(errors) == 1
    assert "neighbor 10.0.0.4 has no resolvable remote-as" in errors[0]["detail"]
    assert "bgp-session-not-recorded" in proof.UNCERTAIN_KINDS


def test_unpairable_session_keeps_local_ip_unset(monkeypatch):
    # An eBGP peer outside the estate: nothing owns 198.51.100.9, so no far end.
    lone = {
        "uid": "bgp:a:2",
        "process_uid": "rp:a",
        "props": {"uid": "bgp:a:2", "local_asn": 65001, "peer_asn": 65099, "peer_ip": "198.51.100.9"},
    }
    _install(
        monkeypatch,
        _two_router_answers(**{"properties(b) AS props": [SESS_A, SESS_B, lone]}),
    )
    result = simul_read.read_simulation_input(object(), device="dev:a")
    outside = next(s for s in result.sessions if s["uid"] == "bgp:a:2")
    assert "local_ip" not in outside


def test_ambiguous_pairing_is_reported_and_resolved_deterministically(monkeypatch):
    # rp:a and rp:b peer over two address pairs
    sess_a2 = {
        "uid": "bgp:a:2",
        "process_uid": "rp:a",
        "props": {"uid": "bgp:a:2", "local_asn": 65001, "peer_asn": 65002, "peer_ip": "192.0.2.4"},
    }
    sess_b2 = {
        "uid": "bgp:b:2",
        "process_uid": "rp:b",
        "props": {"uid": "bgp:b:2", "local_asn": 65002, "peer_asn": 65001, "peer_ip": "192.0.2.3"},
    }
    answers = _two_router_answers(
        **{
            "properties(b) AS props": [SESS_A, sess_a2, SESS_B, sess_b2],
            "ip.ip AS ip": [
                {"process_uid": "rp:a", "ip": "192.0.2.1"},
                {"process_uid": "rp:a", "ip": "192.0.2.3"},
                {"process_uid": "rp:b", "ip": "192.0.2.2"},
                {"process_uid": "rp:b", "ip": "192.0.2.4"},
            ],
        }
    )
    _install(monkeypatch, answers)
    result = simul_read.read_simulation_input(object(), device="dev:a")

    kinds = [e["kind"] for e in result.errors.as_dicts()]
    assert "ambiguous-session-pairing" in kinds
    by_uid = {s["uid"]: s for s in result.sessions}
    assert by_uid["bgp:a:1"]["local_ip"] == "192.0.2.1"
    assert by_uid["bgp:a:2"]["local_ip"] == "192.0.2.1"


def test_undefined_policy_name_reaches_the_engine_as_a_name(monkeypatch):
    # import_policy_name is set with no FILTERED_BY edge behind it
    filtered = dict(SESS_A)
    filtered["props"] = {
        **SESS_A["props"],
        "import_policy_name": "RM_MISSING",
        "import_policy_kind": "route-map",
    }
    _install(
        monkeypatch,
        _two_router_answers(**{"properties(b) AS props": [filtered, SESS_B]}),
    )
    result = simul_read.read_simulation_input(object(), device="dev:a")
    session = next(s for s in result.sessions if s["uid"] == "bgp:a:1")

    assert session["import_policy_name"] == "RM_MISSING"
    assert session["import_policy_kind"] == "route-map"
    assert result.policies == []


def test_no_query_reads_learned_route(monkeypatch):
    graph = _install(monkeypatch, _two_router_answers())
    simul_read.read_simulation_input(object(), device="dev:a")
    # LEARNED_ROUTE.next_hop is a RIB next hop, never a peer.
    assert not any("LEARNED_ROUTE" in q or "next_hop" in q for q, _ in graph.calls)


def test_policy_entries_are_sorted_by_seq(monkeypatch):
    # compile_policies reads entries[0]["kind"] unsorted to pick the conversion shape.
    policy_rows = [
        {
            "uid": "rp-pol:a",
            "name": "RM_OUT",
            "kind": "route-map",
            "entries": [
                {"seq": 20, "kind": "clause", "action": "permit"},
                {"seq": 10, "kind": "clause", "action": "deny"},
            ],
        }
    ]
    _install(
        monkeypatch,
        _two_router_answers(**{"collect(properties(e)) AS entries": policy_rows}),
    )
    result = simul_read.read_simulation_input(object(), device="dev:a")
    assert [e["seq"] for e in result.policies[0]["entries"]] == [10, 20]


def test_colliding_policy_names_are_reported_and_first_by_uid_wins(monkeypatch):
    policy_rows = [
        {"uid": "rp-pol:b", "name": "RM_IN", "kind": "route-map", "entries": []},
        {"uid": "rp-pol:a", "name": "RM_IN", "kind": "route-map", "entries": []},
    ]
    _install(
        monkeypatch,
        _two_router_answers(**{"collect(properties(e)) AS entries": policy_rows}),
    )
    result = simul_read.read_simulation_input(object(), device="dev:a")

    assert [p["uid"] for p in result.policies] == ["rp-pol:a"]
    assert "ambiguous-policy-name" in [e["kind"] for e in result.errors.as_dicts()]


class _OspfCoverage:
    """An OSPF reader that answers the coverage questions: the device's outcome,
    the contexts' recorded outcomes and the contexts the device holds rows for."""

    def __init__(self, device, recorded=None, held=()):
        self.device, self.recorded, self.held = device, recorded or {}, set(held)

    def coverage(self, device_uid):
        return self.device

    def context_coverage(self, context_uid):
        return self.recorded.get(context_uid)

    def contexts_with_rows(self, device_uid):
        return self.held


ROW = {"lsa_type": "router"}


def test_a_vrf_the_run_did_not_read_is_not_observed_whatever_the_device_outcome_is():
    """The device's default VRF was read (`complete`, rows), the process
    in VRF TENANT was not, and the answer for TENANT is not `complete`."""
    source = _OspfCoverage("complete", {"vrf:t": "not-captured"}, held={"vrf:d"})
    assert simul_read._ospf_coverage(source, "dev:a", "vrf:t", []) == "not-observed"
    assert simul_read._ospf_coverage(source, "dev:a", "vrf:d", [ROW]) == "complete"


def test_a_context_with_no_rows_beside_a_context_with_rows_is_not_observed():
    """A snapshot that records no context outcome is judged on the rows: a
    database that was read holds at least its own router LSA."""
    source = _OspfCoverage("complete", held={"vrf:d"})
    assert simul_read._ospf_coverage(source, "dev:a", "vrf:t", []) == "not-observed"


def test_a_device_whose_every_database_is_empty_stays_complete_empty():
    source = _OspfCoverage("complete-empty")
    assert simul_read._ospf_coverage(source, "dev:a", "vrf:t", []) == "complete-empty"


def test_a_context_recorded_read_and_empty_is_complete_empty():
    source = _OspfCoverage("complete", {"vrf:t": "complete-empty"}, held={"vrf:d"})
    assert simul_read._ospf_coverage(source, "dev:a", "vrf:t", []) == "complete-empty"


def test_a_device_outcome_that_is_not_complete_is_kept():
    source = _OspfCoverage("failed", {"vrf:t": "complete"}, held={"vrf:d"})
    assert simul_read._ospf_coverage(source, "dev:a", "vrf:t", [ROW]) == "failed"


def test_a_context_with_no_rows_and_no_recorded_outcome_is_not_observed():
    source = _OspfCoverage(None)
    assert simul_read._ospf_coverage(source, "dev:a", "vrf:t", []) == "not-observed"
    assert simul_read._ospf_coverage(source, "dev:a", "vrf:t", [ROW]) is None


def test_the_session_read_leaves_out_sessions_that_carry_no_ipv4_unicast():
    """An EVPN-only or IPv6-only session carries none of the IPv4 routes
    the engine propagates."""
    assert "b.afi_safi IS NULL OR 'ipv4-unicast' IN b.afi_safi" in simul_read._SESSIONS


def test_a_policy_name_two_devices_define_keeps_both_each_on_its_own_device(monkeypatch):
    """A templated estate gives every branch a `LOCAL-NETS` of its own.
    Each policy row names the device of the process that reached it, both
    policies are kept, and no name collision is reported."""
    proc_a = {**PROC_A, "device_uids": ["dev:a"]}
    proc_b = {**PROC_B, "device_uids": ["dev:b"]}
    policy_rows = [
        {
            "uid": "rtpol:dev:a:route-map:LOCAL-NETS",
            "name": "LOCAL-NETS",
            "kind": "route-map",
            "process_uid": "rp:a",
            "entries": [],
        },
        {
            "uid": "rtpol:dev:b:route-map:LOCAL-NETS",
            "name": "LOCAL-NETS",
            "kind": "route-map",
            "process_uid": "rp:b",
            "entries": [],
        },
    ]
    _install(
        monkeypatch,
        _two_router_answers(
            **{
                "collect(DISTINCT d.platform)": [proc_a, proc_b],
                "collect(properties(e)) AS entries": policy_rows,
            }
        ),
    )

    result = simul_read.read_simulation_input(object(), device="dev:a")

    assert {p["uid"]: p["device_uid"] for p in result.policies} == {
        "rtpol:dev:a:route-map:LOCAL-NETS": "dev:a",
        "rtpol:dev:b:route-map:LOCAL-NETS": "dev:b",
    }
    assert {p["uid"]: p["device_uid"] for p in result.processes} == {"rp:a": "dev:a", "rp:b": "dev:b"}
    assert "ambiguous-policy-name" not in [e["kind"] for e in result.errors.as_dicts()]


def test_a_policy_two_processes_of_one_device_reached_is_one_policy(monkeypatch):
    proc_a = {**PROC_A, "device_uids": ["dev:a"]}
    proc_b = {**PROC_B, "device_uids": ["dev:a"]}
    policy_rows = [
        {
            "uid": "rtpol:dev:a:route-map:RM",
            "name": "RM",
            "kind": "route-map",
            "process_uid": "rp:a",
            "entries": [],
        },
        {
            "uid": "rtpol:dev:a:route-map:RM",
            "name": "RM",
            "kind": "route-map",
            "process_uid": "rp:b",
            "entries": [],
        },
    ]
    _install(
        monkeypatch,
        _two_router_answers(
            **{
                "collect(DISTINCT d.platform)": [proc_a, proc_b],
                "collect(properties(e)) AS entries": policy_rows,
            }
        ),
    )

    result = simul_read.read_simulation_input(object(), device="dev:a")

    assert [p["uid"] for p in result.policies] == ["rtpol:dev:a:route-map:RM"]
    assert "ambiguous-policy-name" not in [e["kind"] for e in result.errors.as_dicts()]


def test_a_process_on_a_shared_context_names_no_device_and_keeps_the_collision_report(monkeypatch):
    """A process whose context spans devices owns no policy scope, so two
    policies of one name it reached are still one collision."""
    shared = {**PROC_A, "device_uids": ["dev:a", "dev:b"]}
    policy_rows = [
        {
            "uid": "rtpol:dev:a:route-map:RM",
            "name": "RM",
            "kind": "route-map",
            "process_uid": "rp:a",
            "entries": [],
        },
        {
            "uid": "rtpol:dev:b:route-map:RM",
            "name": "RM",
            "kind": "route-map",
            "process_uid": "rp:a",
            "entries": [],
        },
    ]
    _install(
        monkeypatch,
        _two_router_answers(
            **{
                "collect(DISTINCT d.platform)": [shared, PROC_B],
                "collect(properties(e)) AS entries": policy_rows,
            }
        ),
    )

    result = simul_read.read_simulation_input(object(), device="dev:a")

    assert "device_uid" not in result.processes[0]
    assert "ambiguous-policy-name" in [e["kind"] for e in result.errors.as_dicts()]


def test_originates_proto_maps_onto_the_engines_origin_mechanism(monkeypatch):
    _install(monkeypatch, _two_router_answers())
    result = simul_read.read_simulation_input(object(), device="dev:a")
    assert result.local_routes == [
        {
            "process_uid": "rp:a",
            "prefix": "10.1.0.0/24",
            "origin_mechanism": "network",
            "src_protocol": "connected",
        },
        {
            "process_uid": "rp:b",
            "prefix": "10.2.0.0/24",
            "origin_mechanism": "aggregate",
            "src_protocol": "aggregate",
            "intent": True,
        },
    ]
    assert "origination-not-recorded" in [e["kind"] for e in result.errors.as_dicts()]


def test_vyos_platform_is_refined_from_ebgp_requires_policy(monkeypatch):
    # A bare "vyos" is an unresolved gap-13 profile to the engine.
    traditional = {
        **PROC_A,
        "props": {**PROC_A["props"], "ebgp_requires_policy": True},
        "platforms": ["vyos"],
        "vendors": ["vyos"],
    }
    datacenter = {
        **PROC_B,
        "props": {**PROC_B["props"], "ebgp_requires_policy": False},
        "platforms": ["vyos"],
        "vendors": ["vyos"],
    }
    _install(
        monkeypatch,
        _two_router_answers(**{"collect(DISTINCT d.platform)": [traditional, datacenter]}),
    )
    result = simul_read.read_simulation_input(object(), device="dev:a")
    assert [p["platform"] for p in result.processes] == ["vyos-traditional", "vyos-datacenter"]


def test_platform_falls_back_to_vendor_then_is_omitted(monkeypatch):
    no_platform = {**PROC_A, "platforms": [None], "vendors": ["cisco_ios"]}
    nothing = {**PROC_B, "platforms": [], "vendors": []}
    _install(
        monkeypatch,
        _two_router_answers(**{"collect(DISTINCT d.platform)": [no_platform, nothing]}),
    )
    result = simul_read.read_simulation_input(object(), device="dev:a")
    assert result.processes[0]["platform"] == "cisco_ios"
    # Nothing recorded: the engine falls back to the run's own `platform`.
    assert "platform" not in result.processes[1]


def test_vrf_scope_uses_the_vrf_seed_query(monkeypatch):
    graph = _install(
        monkeypatch,
        _two_router_answers(**{"(v:VrfInstance:Obj {uid: $vrf, collection_ts: $snap})": [{"uid": "rp:a"}]}),
    )
    result = simul_read.read_simulation_input(object(), vrf="vrf:a:default")
    assert [p["uid"] for p in result.processes] == ["rp:a", "rp:b"]
    assert any("$vrf" in q for q, _ in graph.calls)


def test_every_query_excludes_retired_nodes(monkeypatch):
    graph = _install(monkeypatch, _two_router_answers())
    simul_read.read_simulation_input(object(), device="dev:a")
    assert graph.calls
    for query, _ in graph.calls:
        assert "NOT " in query and ":Retired" in query


def test_end_to_end_delta_merges_read_errors_with_engine_errors(monkeypatch):
    _install(monkeypatch, {})
    delta = simul_read.compute_route_delta(object(), device="dev:x")
    assert delta.rib == []
    assert delta.model_errors[0]["kind"] == "no-bgp-process-in-scope"


def test_end_to_end_delta_predicts_rows_keyed_by_context_uid(monkeypatch):
    _install(monkeypatch, _two_router_answers())
    delta = simul_read.compute_route_delta(object(), device="dev:a")

    contexts = {row["context_uid"] for row in delta.rib}
    assert contexts == {"vrf:a:default", "vrf:b:default"}
    # Each side keeps its own prefix and learns the other's across the peering.
    assert {(r["context_uid"], r["prefix"]) for r in delta.rib} == {
        ("vrf:a:default", "10.1.0.0/24"),
        ("vrf:a:default", "10.2.0.0/24"),
        ("vrf:b:default", "10.1.0.0/24"),
        ("vrf:b:default", "10.2.0.0/24"),
    }


def test_aggregate_attribute_map_reaches_the_engine_as_the_rows_route_map(monkeypatch):
    # An unresolved attribute-map travels as the raw name the ORIGINATES edge recorded.
    _install(
        monkeypatch,
        _two_router_answers(
            **{
                "og.proto AS proto": [
                    {
                        "process_uid": "rp:a",
                        "prefix": "10.1.0.0/24",
                        "proto": "aggregate",
                        "origin_props": {"attribute_map": "RM_AGG"},
                        "origin_policy_name": "RM_AGG",
                    },
                    {
                        "process_uid": "rp:b",
                        "prefix": "10.2.0.0/24",
                        "proto": "aggregate",
                        "origin_props": {"attribute_map": "RM_GHOST"},
                        "origin_policy_name": None,
                    },
                ]
            }
        ),
    )
    result = simul_read.read_simulation_input(object(), device="dev:a")
    assert [(row["prefix"], row["route_map"]) for row in result.local_routes] == [
        ("10.1.0.0/24", "RM_AGG"),
        ("10.2.0.0/24", "RM_GHOST"),
    ]


def test_pairing_a_hub_with_many_spokes_does_not_scan_every_session():
    """One hub process peers with 5000 spokes. Each session finds its far end
    by address, not by scanning every other process's sessions."""
    addresses = {"rp:hub": {"10.0.0.1"}}
    sessions = []
    for i in range(5000):
        spoke, address = f"rp:{i:04d}", f"10.1.{i // 250}.{i % 250 + 1}"
        addresses[spoke] = {address}
        sessions.append({"uid": f"hub:{i:04d}", "process_uid": "rp:hub", "peer_ip": address})
        sessions.append({"uid": f"spoke:{i:04d}", "process_uid": spoke, "peer_ip": "10.0.0.1"})
    with cpu_time() as spent:
        simul_read._pair_local_ips(sessions, addresses, {}, ErrorSink())
    assert spent.seconds < 1.0
    by_uid = {s["uid"]: s for s in sessions}
    assert by_uid["hub:0007"]["local_ip"] == "10.0.0.1"
    assert by_uid["spoke:0007"]["local_ip"] == "10.1.0.8"


def test_a_community_list_and_an_as_path_list_of_one_name_are_two_policies(monkeypatch):
    """IOS numbers both kinds of list, so `ip community-list 7` and
    `ip as-path access-list 7` on one device are two policies; each list kind
    is its own namespace and neither is dropped as a collision."""
    policy_rows = [
        {"uid": "rp-pol:cl", "name": "7", "kind": "community-list", "entries": []},
        {"uid": "rp-pol:ap", "name": "7", "kind": "as-path-list", "entries": []},
        {"uid": "rp-pol:rm", "name": "7", "kind": "route-map", "entries": []},
    ]
    _install(
        monkeypatch,
        _two_router_answers(**{"collect(properties(e)) AS entries": policy_rows}),
    )
    result = simul_read.read_simulation_input(object(), device="dev:a")

    assert sorted(p["uid"] for p in result.policies) == ["rp-pol:ap", "rp-pol:cl", "rp-pol:rm"]
    collisions = [e["detail"] for e in result.errors.as_dicts() if e["kind"] == "ambiguous-policy-name"]
    assert not any(
        len({uid for uid in ("rp-pol:cl", "rp-pol:ap", "rp-pol:rm") if uid in detail}) > 1
        for detail in collisions
    )


def test_provider_rows_resting_on_a_colliding_policy_name_are_not_established(monkeypatch):
    """Two RoutePolicy nodes of one name in one namespace (here the
    processes name no device, as for a context owned by none) keep only the
    first by uid. The provider path's rows for the context that attaches the
    name must say they are not established; the other context's rows, which
    attach nothing, stay plain."""
    sess_a = {
        **SESS_A,
        "props": {**SESS_A["props"], "import_policy_name": "RM_IN", "import_policy_kind": "route-map"},
    }
    policy_rows = [
        {"uid": "rtpol:x:RM_IN", "name": "RM_IN", "kind": "route-map", "process_uid": "rp:a", "entries": []},
        {"uid": "rtpol:y:RM_IN", "name": "RM_IN", "kind": "route-map", "process_uid": "rp:a", "entries": []},
    ]
    _install(
        monkeypatch,
        _two_router_answers(
            **{"properties(b) AS props": [sess_a, SESS_B], "collect(properties(e)) AS entries": policy_rows}
        ),
    )
    graph_input = simul_read.read_simulation_input(object(), device="dev:a")
    assert simul_read.ambiguous_contexts(graph_input) == {"vrf:a:default": ["RM_IN"]}

    delta = simul_read.compute_route_delta(object(), device="dev:a")
    rows_a = [r for r in delta.rib if r["context_uid"] == "vrf:a:default"]
    rows_b = [r for r in delta.rib if r["context_uid"] == "vrf:b:default"]
    assert rows_a and rows_b
    assert all("ambiguous-policy-name" in r["not_established_because"] for r in rows_a)
    assert all("not_established_because" not in r for r in rows_b)

    # the agent's prediction tool builds its delta with the provider directly;
    # its rows, and the baseline's, carry the same marking
    from hst.app.agent.tools import route_prediction

    prediction = route_prediction(object(), "dev:a", [], baseline=True)
    for computed in (prediction.delta, prediction.baseline):
        tool_a = [r for r in computed.rib if r["context_uid"] == "vrf:a:default"]
        tool_b = [r for r in computed.rib if r["context_uid"] == "vrf:b:default"]
        assert tool_a and tool_b
        assert all("ambiguous-policy-name" in r["not_established_because"] for r in tool_a)
        assert all("not_established_because" not in r for r in tool_b)


def test_a_colliding_list_name_marks_every_process_of_its_namespace():
    """A list name no process attaches (a prefix list used inside entries)
    counts for every process of the namespace the collision is in."""
    graph_input = simul_read.GraphInput(
        processes=[
            {"uid": "rp:a", "context_uid": "vrf:a", "device_uid": "dev:a"},
            {"uid": "rp:b", "context_uid": "vrf:b", "device_uid": "dev:b"},
        ],
        ambiguous_policies={("dev:a", "", "PL")},
    )
    assert simul_read.ambiguous_contexts(graph_input) == {"vrf:a": ["PL"]}


def _two_virtual_systems():
    """The collector's graph for one Check Point gateway with two virtual
    systems (VS 7 and VS 8), each exporting to 192.0.2.2 through a route map
    `out` of its own, as `normalize_checkpoint_gateway` writes it, and the
    rows the read's queries answer with for it."""
    import copy

    from tests.enterprise.test_checkpoint_gateway_integration import _config
    from tests.test_vsx_operational import capture

    from hst.collectors.checkpoint_gateway import normalize_checkpoint_gateway

    raw = capture()
    second = copy.deepcopy(raw["contexts"]["7"])
    second["vsid"] = 8
    second["interfaces"][1]["addr_info"] = [{"local": "198.51.100.1", "prefixlen": 24}]
    raw["contexts"]["8"] = second
    raw["vsx stat -v"] += "\n8 | S other | policy | 12Sep2026 | Trust"
    for vsid, action in (("7", "allow"), ("8", "restrict")):
        raw["contexts"][vsid]["bgp_config"] = (
            "set bgp external remote-as 65002 peer 192.0.2.2 export-routemap out preference 10 on"
        )
        raw["contexts"][vsid]["bgp_routemaps"] = (
            f"set routemap out id 10 on\nset routemap out id 10 {action}\n"
        )
    batch = normalize_checkpoint_gateway(raw, _config())
    props: dict = {}
    for node in batch.nodes:
        props.setdefault(node.uid, {"uid": node.uid}).update(node.props)
    labels = {node.uid: node.label for node in batch.nodes}
    edges: dict = {}
    for rel in batch.rels:
        edges.setdefault((rel.rel_type, rel.start_uid), []).append(rel.end_uid)
    processes = sorted(uid for uid, label in labels.items() if label == "RoutingProcess")
    sessions = []
    policies = []
    process_rows = []
    for process in processes:
        context = edges[("IN_VRF", process)][0]
        process_rows.append(
            {
                "uid": process,
                "props": props[process],
                "context_uid": context,
                "platforms": ["checkpoint-gaia"],
                "vendors": ["checkpoint"],
                "device_uids": edges[("OWNED_BY", context)],
            }
        )
        for session in edges.get(("HAS", process), ()):
            sessions.append({"uid": session, "process_uid": process, "props": props[session]})
            pending = list(edges.get(("FILTERED_BY", session), ()))
            while pending:
                policy = pending.pop()
                pending.extend(edges.get(("REFERENCES", policy), ()))
                policies.append(
                    {
                        "uid": policy,
                        "name": props[policy]["name"],
                        "kind": props[policy]["kind"],
                        "context_uid": props[policy].get("context_uid"),
                        "process_uid": process,
                        "entries": [props[e] for e in edges.get(("HAS_RULE", policy), ())],
                    }
                )
    device = process_rows[0]["device_uids"][0]
    return device, process_rows, sessions, policies


def _vsx_answers(process_rows, sessions, policies):
    return {
        "(d:Device:Obj {uid: $dev, collection_ts: $snap})": [{"uid": p["uid"]} for p in process_rows],
        "collect(DISTINCT d.platform)": process_rows,
        "properties(b) AS props": sessions,
        "collect(properties(e)) AS entries": policies,
    }


def test_two_virtual_systems_of_one_gateway_keep_a_route_map_name_each(monkeypatch):
    """Both virtual systems of one gateway define `out` (and the chain
    `192.0.2.2:out`). Each RoutePolicy node states its routing context, so
    each virtual system keeps its own: four policies, no collision, and no
    context whose rows are marked."""
    device, process_rows, sessions, policies = _two_virtual_systems()
    assert len({p["context_uid"] for p in process_rows}) == 2
    assert {p["device_uids"][0] for p in process_rows} == {device}
    _install(monkeypatch, _vsx_answers(process_rows, sessions, policies))

    result = simul_read.read_simulation_input(object(), device=device)

    contexts = {p["context_uid"] for p in process_rows}
    assert sorted((p["name"], p["context_uid"]) for p in result.policies) == sorted(
        (name, context) for name in ("192.0.2.2:out", "out") for context in contexts
    )
    assert {p["device_uid"] for p in result.processes} == {device}
    kinds = [e["kind"] for e in result.errors.as_dicts()]
    assert "ambiguous-policy-name" not in kinds
    assert "policy-context-ambiguous" not in kinds
    assert simul_read.ambiguous_contexts(result) == {}

    # each virtual system's own `out` decides: VS 7 allows, VS 8 restricts
    from hst.simul.compile import (
        compile_policies,
        context_namespaces,
        resolving_namespace,
        scoped_policies,
    )
    from hst.simul.policy import Environment, call
    from hst.simul.route import Route

    namespaces = context_namespaces(result.policies)
    accepted = {}
    for process in result.processes:
        namespace = resolving_namespace(namespaces, process["device_uid"], process["context_uid"])
        errors = ErrorSink()
        compiled, _ = compile_policies(scoped_policies(result.policies, namespace), "checkpoint-gaia", errors)
        assert not errors.errors
        route = Route("10.0.0.0/24", src_protocol="static")
        env = Environment(route, route, policies=compiled, peer_as=65002)
        accepted[process["context_uid"]] = call(compiled["192.0.2.2:out"], env).boolean_value
    assert sorted(accepted.values()) == [False, True]


def test_a_single_virtual_system_keeps_device_keyed_policy_rows(monkeypatch):
    """A gateway whose policies no other context of it names again needs no
    context to tell them apart."""
    device, process_rows, sessions, policies = _two_virtual_systems()
    only = process_rows[0]
    _install(
        monkeypatch,
        _vsx_answers(
            [only],
            [s for s in sessions if s["process_uid"] == only["uid"]],
            [p for p in policies if p["process_uid"] == only["uid"]],
        ),
    )

    result = simul_read.read_simulation_input(object(), device=device)

    assert sorted(p["name"] for p in result.policies) == ["192.0.2.2:out", "out"]
    assert all(set(p) == {"uid", "name", "kind", "entries", "device_uid"} for p in result.policies)
    assert [e for e in result.errors.as_dicts() if "polic" in e["kind"]] == []


def test_a_route_map_name_two_nodes_define_in_one_virtual_system_is_not_decided_there(monkeypatch):
    """A second `out` node in VS 7's own context is a collision in that
    context only: VS 7's rows are marked, VS 8's are not."""
    device, process_rows, sessions, policies = _two_virtual_systems()
    first = next(p for p in policies if p["name"] == "out")
    extra = {**first, "uid": first["uid"] + ":copy"}
    _install(monkeypatch, _vsx_answers(process_rows, sessions, [*policies, extra]))

    result = simul_read.read_simulation_input(object(), device=device)

    assert "ambiguous-policy-name" in [e["kind"] for e in result.errors.as_dicts()]
    assert simul_read.ambiguous_contexts(result) == {first["context_uid"]: ["out"]}


def test_a_route_map_one_virtual_system_reached_in_another_is_not_decided(monkeypatch):
    """A process that reached a policy defined in another virtual system's
    context: the engine does not find it under the process's name, so the
    read names the process (`policy-context-ambiguous`) and marks its context,
    never the policy of the first context by uid."""
    device, process_rows, sessions, policies = _two_virtual_systems()
    own, other = process_rows
    foreign = next(p for p in policies if p["name"] == "out" and p["process_uid"] == own["uid"])
    _install(
        monkeypatch,
        _vsx_answers(process_rows, sessions, [*policies, {**foreign, "process_uid": other["uid"]}]),
    )

    result = simul_read.read_simulation_input(object(), device=device)

    faults = [e for e in result.errors.as_dicts() if e["kind"] == "policy-context-ambiguous"]
    assert [e["subject"] for e in faults] == [other["uid"]]
    assert "not decided" in faults[0]["detail"]
    assert other["context_uid"] in simul_read.ambiguous_contexts(result)
