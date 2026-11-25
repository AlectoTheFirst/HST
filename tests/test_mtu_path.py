"""Synthetic traversal integration, isolated from rendered hop order."""

from importlib import import_module
from types import SimpleNamespace

import pytest
from tests.test_mtu_contract import observation
from tests.test_mtu_snapshot import row
from tests.test_path_trace import GW, FakeGraph, _script_l2_trunk, _src_row

import hst.path as path
from hst.core.mtu import MtuRequest, MtuStage
from hst.path.gates import Stage, _Trail
from hst.path.mtu import constraint_budget
from hst.path.mtu_topology import (
    MAX_STAGES,
    TOPOLOGY_QUERY,
    boundary,
    connection_scope,
    crossing,
    expand_stages,
    mtu_request,
    trace_scope,
)

trace_module = import_module("hst.path.trace")


def graph_reads(monkeypatch, observations=()):
    calls = []

    def read(session, query, **params):
        calls.append((query, params))
        if "HAS_MTU" in query:
            return [row(o) for o in observations if o.subject_uid in params["subject_uids"]]
        return []

    monkeypatch.setattr(path, "_read", read)
    return calls


def test_no_enabled_request_does_not_capture_or_read(monkeypatch):
    calls = graph_reads(monkeypatch)

    @trace_scope()
    def walk(session):
        crossing(_Trail(), "if:a", enforcement="l3")
        return {"hops": []}

    assert walk(SimpleNamespace(cts=42)) == {"hops": []}
    assert not calls


def test_direct_crossing_limit_survives_missing_path(monkeypatch):
    graph_reads(monkeypatch, [observation(subject_uid="if:a")])

    @trace_scope()
    def walk(session):
        crossing(_Trail(), "if:a", enforcement="l3")
        crossing(_Trail(), None, enforcement="destination", direction="rx")
        return {"hops": []}

    with mtu_request(MtuRequest(mode="unfragmented", ip_packet_bytes=1501), 4):
        result = walk(SimpleNamespace(cts=42))["mtu"]
    assert result["outcome"] == "fail"
    assert result["known_ceiling_bytes"] == 1500
    assert result["guaranteed_bytes"] is None
    assert "MTU_ENDPOINT_UNKNOWN" in result["coverage"]["gaps"]
    assert walk(SimpleNamespace(cts=42)) == {"hops": []}


def test_lag_collapse_retains_every_raw_crossing_as_possible(monkeypatch):
    graph_reads(monkeypatch)

    @trace_scope()
    def walk(session):
        trail = _Trail()
        trace_module._draw_l2_chain(
            trail,
            session,
            [
                {"uid": "p:1", "is_port": True, "lag": "lag:x", "label": "p1", "dev": "d"},
                {"uid": "p:2", "is_port": True, "lag": "lag:x", "label": "p2", "dev": "d"},
            ],
            None,
            stage=Stage.L2_FABRIC,
        )
        return {"hops": trail.hops}

    with mtu_request(MtuRequest(mode="inventory"), 4):
        result = walk(SimpleNamespace(cts=42))
    assert len(result["hops"]) == 1
    stages = result["mtu"]["stages"]
    assert len(stages) == 4
    assert all(s["selection"] == "possible" for s in stages)
    assert {s["egress_subject_uid"] or s["ingress_subject_uid"] for s in stages} == {"p:1", "p:2"}


def _stages_by_subject(result):
    grouped: dict[str, list] = {}
    for s in result["mtu"]["stages"]:
        grouped.setdefault(s["egress_subject_uid"] or s["ingress_subject_uid"], []).append(s)
    return grouped


def _iface_segment_reads(bds, observations):
    def read(session, query, **params):
        if "HAS_MTU" in query:
            return [row(o) for o in observations if o.subject_uid in params["subject_uids"]]
        if "(v:VlanInstance)-[rz:REALIZES]" in query:
            return [{"uid": u} for u in bds]
        return []

    return read


def test_l2_chain_tag_depth_converts_the_frame_ceiling_by_carriage(monkeypatch):
    """A port's carriage of the flow's bridge domain states the tag depth (mtu-l2-path-coverage rule 1)."""
    frame = {
        "profile_id": "ethernet_frame_including_fcs",
        "metric": "l2_max_frame_bytes",
        "bound_kind": "ceiling",
        "enforcement": "l2",
        "direction": "both",
        "tag_accounting": "extra_allowance",
        "tag_allowance_bytes": 4,
    }
    observations = [
        observation(1518, subject_uid="p:access", **frame),
        observation(1518, subject_uid="p:trunk", **frame),
        observation(1518, subject_uid="p:unrecorded", **frame),
    ]
    monkeypatch.setattr(path, "_read", _iface_segment_reads(["bd:vlan:fab0:10"], observations))

    @trace_scope()
    def walk(session):
        trail = _Trail()
        trace_module._draw_l2_chain(
            trail,
            session,
            [
                {
                    "uid": "p:access",
                    "is_port": True,
                    "label": "access",
                    "dev": "sw",
                    "native_bds": ["bd:vlan:fab0:10"],
                    "tagged_bds": [],
                    "conn_source": "unifi",
                },
                {
                    "uid": "p:trunk",
                    "is_port": True,
                    "label": "trunk",
                    "dev": "sw",
                    "native_bds": [],
                    "tagged_bds": ["bd:vlan:fab0:10"],
                    "conn_source": "unifi",
                },
                {
                    "uid": "p:unrecorded",
                    "is_port": True,
                    "label": "unrecorded",
                    "dev": "sw",
                    "native_bds": [],
                    "tagged_bds": [],
                    "conn_source": "unifi",
                },
            ],
            "if:gw",
            stage=Stage.L2_FABRIC,
        )
        return {}

    with mtu_request(MtuRequest(mode="inventory"), 4):
        result = walk(SimpleNamespace(cts=42))
    by_subject = _stages_by_subject(result)

    access_stage = MtuStage.model_validate(by_subject["p:access"][0])
    assert access_stage.context.tag_depth == 0
    (constraint,) = access_stage.constraints
    assert constraint_budget(constraint, access_stage) == (1504, [])

    trunk_stage = MtuStage.model_validate(by_subject["p:trunk"][0])
    assert trunk_stage.context.tag_depth == 1
    (constraint,) = trunk_stage.constraints
    assert constraint_budget(constraint, trunk_stage) == (1500, [])

    unrecorded_stage = MtuStage.model_validate(by_subject["p:unrecorded"][0])
    assert unrecorded_stage.context.tag_depth is None
    (constraint,) = unrecorded_stage.constraints
    budget, gaps = constraint_budget(constraint, unrecorded_stage)
    assert budget is None
    assert "MTU_SEMANTICS_UNKNOWN" in gaps


def test_l2_chain_stated_cabling_is_eligible_on_every_hop(monkeypatch):
    graph_reads(monkeypatch)

    @trace_scope()
    def walk(session):
        trail = _Trail()
        trace_module._draw_l2_chain(
            trail,
            session,
            [
                {"uid": "p:1", "is_port": True, "label": "p1", "dev": "sw1", "conn_source": "unifi"},
                {"uid": "p:2", "is_port": True, "label": "p2", "dev": "sw2", "conn_source": "nautobot-cable"},
            ],
            None,
            stage=Stage.L2_FABRIC,
        )
        return {}

    with mtu_request(MtuRequest(mode="inventory"), 4):
        result = walk(SimpleNamespace(cts=42))
    stages = result["mtu"]["stages"]
    assert len(stages) == 4
    assert all(s["selection"] == "eligible" for s in stages)


def test_l2_chain_unifi_uplink_record_is_eligible_like_a_directly_stated_cable(monkeypatch):
    graph_reads(monkeypatch)

    @trace_scope()
    def walk(session):
        trail = _Trail()
        trace_module._draw_l2_chain(
            trail,
            session,
            [
                {"uid": "p:1", "is_port": True, "label": "p1", "dev": "sw1", "conn_source": "unifi-uplink"},
                {"uid": "p:2", "is_port": True, "label": "p2", "dev": "sw2", "conn_source": "reasoner"},
            ],
            None,
            stage=Stage.L2_FABRIC,
        )
        return {}

    with mtu_request(MtuRequest(mode="inventory"), 4):
        result = walk(SimpleNamespace(cts=42))
    by_subject = _stages_by_subject(result)
    assert all(s["selection"] == "eligible" for s in by_subject["p:1"])
    assert all(s["selection"] == "possible" for s in by_subject["p:2"])


def test_l2_chain_unifi_lldp_record_is_eligible_like_a_directly_stated_cable(monkeypatch):
    graph_reads(monkeypatch)

    @trace_scope()
    def walk(session):
        trail = _Trail()
        trace_module._draw_l2_chain(
            trail,
            session,
            [
                {"uid": "p:1", "is_port": True, "label": "p1", "dev": "sw1", "conn_source": "unifi-lldp"},
                {"uid": "p:2", "is_port": True, "label": "p2", "dev": "sw2", "conn_source": "reasoner"},
            ],
            None,
            stage=Stage.L2_FABRIC,
        )
        return {}

    with mtu_request(MtuRequest(mode="inventory"), 4):
        result = walk(SimpleNamespace(cts=42))
    by_subject = _stages_by_subject(result)
    assert all(s["selection"] == "eligible" for s in by_subject["p:1"])
    assert all(s["selection"] == "possible" for s in by_subject["p:2"])


def test_l2_chain_a_reasoner_inferred_link_is_possible_on_that_hop_only(monkeypatch):
    graph_reads(monkeypatch)

    @trace_scope()
    def walk(session):
        trail = _Trail()
        trace_module._draw_l2_chain(
            trail,
            session,
            [
                {"uid": "p:1", "is_port": True, "label": "p1", "dev": "sw1", "conn_source": "unifi"},
                {"uid": "p:2", "is_port": True, "label": "p2", "dev": "sw2", "conn_source": "reasoner"},
            ],
            None,
            stage=Stage.L2_FABRIC,
        )
        return {}

    with mtu_request(MtuRequest(mode="inventory"), 4):
        result = walk(SimpleNamespace(cts=42))
    by_subject = _stages_by_subject(result)
    assert all(s["selection"] == "eligible" for s in by_subject["p:1"])
    assert all(s["selection"] == "possible" for s in by_subject["p:2"])


def test_l2_chain_possible_from_the_fork_onward(monkeypatch):
    """The walk finds two L2 paths to choose between at the second hop."""
    graph_reads(monkeypatch)

    @trace_scope()
    def walk(session):
        trail = _Trail()
        trace_module._draw_l2_chain(
            trail,
            session,
            [
                {"uid": "p:1", "is_port": True, "label": "p1", "dev": "sw1", "conn_source": "unifi"},
                {
                    "uid": "p:2",
                    "is_port": True,
                    "label": "p2",
                    "dev": "sw2",
                    "conn_source": "unifi",
                    "forked": True,
                },
                {"uid": "p:3", "is_port": True, "label": "p3", "dev": "sw3", "conn_source": "unifi"},
            ],
            None,
            stage=Stage.L2_FABRIC,
        )
        return {}

    with mtu_request(MtuRequest(mode="inventory"), 4):
        result = walk(SimpleNamespace(cts=42))
    by_subject = _stages_by_subject(result)
    assert all(s["selection"] == "eligible" for s in by_subject["p:1"])
    assert all(s["selection"] == "possible" for s in by_subject["p:2"])
    assert all(s["selection"] == "possible" for s in by_subject["p:3"])


def test_independent_reply_has_own_length(monkeypatch):
    graph_reads(monkeypatch, [observation(subject_uid="if:a")])

    @trace_scope(reverse=True)
    def walk(session):
        crossing(_Trail(), "if:a", enforcement="l3")
        return {}

    with mtu_request(MtuRequest(mode="packet", ip_packet_bytes=1500, reply_ip_packet_bytes=1400), 4):
        result = walk(SimpleNamespace(cts=42))["mtu"]
    assert result["direction"] == "reverse"
    assert result["requested_bytes"] == 1400


def test_public_off_plain_and_enabled_early_unknown(monkeypatch):
    fake = FakeGraph()
    monkeypatch.setattr(path, "_read", lambda s, q, **p: fake.read(q, **p))
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: fake.read_one(q, **p))
    args = (SimpleNamespace(cts=42), "10.0.0.5", "192.0.2.1")
    plain = path.trace(*args, gateways=[GW])
    assert path.trace(*args, gateways=[GW], mtu={"mode": "off"}) == plain
    enabled = path.trace(*args, gateways=[GW], mtu={"mode": "inventory"})
    assert enabled["mtu"]["coverage"]["complete"] is False
    assert enabled["mtu"]["known_ceiling_bytes"] is None


def test_public_actual_source_crossing_and_af_validation(monkeypatch):
    fake = FakeGraph()
    fake.sources = [_src_row()]
    monkeypatch.setattr(path, "_read", lambda s, q, **p: fake.read(q, **p))
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: fake.read_one(q, **p))
    result = path.trace(
        SimpleNamespace(cts=42),
        "10.0.0.5",
        "192.0.2.1",
        gateways=[GW],
        mtu={"mode": "unfragmented", "ip_packet_bytes": 1500},
    )
    assert result["mtu"]["stages"]
    with pytest.raises(ValueError, match="address family"):
        path.trace(SimpleNamespace(cts=42), "10.0.0.5", "2001:db8::1", mtu={"mode": "inventory"})


def test_expansion_drops_inactive_and_preserves_unknown_members(monkeypatch):
    from tests.test_mtu_budget import stage

    def read(session, query, **params):
        assert query == TOPOLOGY_QUERY
        return [
            {
                "subject_uid": "if:a",
                "subject": {},
                "carrier_uid": "lag:a",
                "carrier_is_lag": True,
                "member_uid": f"p:{i}",
                "eligible": eligible,
            }
            for i, eligible in enumerate([True, False, None])
        ]

    monkeypatch.setattr(path, "_read", read)
    result = expand_stages(SimpleNamespace(cts=42), [stage(egress_subject_uid="if:a")])
    assert len(result) == 3
    assert result[1].selection == "eligible"
    assert result[2].selection == "possible"
    assert result[1].candidate_set_id == result[2].candidate_set_id
    assert "r.collection_ts=$snap" in TOPOLOGY_QUERY


# --- MTU_PATH_COVERAGE_INCOMPLETE clears only where evidence establishes coverage --------


def test_resolved_eligible_ceiling_stage_clears_the_coverage_gap(monkeypatch):
    graph_reads(monkeypatch, [observation(subject_uid="if:a")])

    @trace_scope()
    def walk(session):
        crossing(_Trail(), "if:a", enforcement="l3")
        return {}

    with mtu_request(MtuRequest(mode="inventory"), 4):
        result = walk(SimpleNamespace(cts=42))["mtu"]
    (stage,) = result["stages"]
    assert stage["selection"] == "eligible"
    assert stage["applicability"] == "applicable"
    assert stage["coverage"]["constraints_complete"] is True
    assert "MTU_PATH_COVERAGE_INCOMPLETE" not in stage["coverage"]["gaps"]


def test_possible_stage_keeps_the_coverage_gap(monkeypatch):
    graph_reads(monkeypatch, [observation(subject_uid="if:a")])

    @trace_scope()
    def walk(session):
        crossing(_Trail(), "if:a", enforcement="l3", possible=True)
        return {}

    with mtu_request(MtuRequest(mode="inventory"), 4):
        result = walk(SimpleNamespace(cts=42))["mtu"]
    (stage,) = result["stages"]
    assert stage["selection"] == "possible"
    assert "MTU_PATH_COVERAGE_INCOMPLETE" in stage["coverage"]["gaps"]


def test_truncated_capture_keeps_every_coverage_gap(monkeypatch):
    graph_reads(monkeypatch, [observation(subject_uid="if:a")])

    @trace_scope()
    def walk(session):
        for _ in range(MAX_STAGES + 1):
            crossing(_Trail(), "if:a", enforcement="l3")
        return {}

    with mtu_request(MtuRequest(mode="inventory"), 4):
        result = walk(SimpleNamespace(cts=42))["mtu"]
    assert result["coverage"]["truncated"] is True
    assert result["stages"]
    assert all("MTU_PATH_COVERAGE_INCOMPLETE" in s["coverage"]["gaps"] for s in result["stages"])


def test_source_stage_without_constraints_keeps_the_coverage_gap(monkeypatch):
    graph_reads(monkeypatch, [])

    @trace_scope()
    def walk(session):
        crossing(_Trail(), "if:client", enforcement="source")
        return {}

    with mtu_request(MtuRequest(mode="inventory"), 4):
        result = walk(SimpleNamespace(cts=42))["mtu"]
    (stage,) = result["stages"]
    assert stage["constraints"] == []
    assert "MTU_ENDPOINT_UNKNOWN" in stage["coverage"]["gaps"]
    assert "MTU_PATH_COVERAGE_INCOMPLETE" in stage["coverage"]["gaps"]


def test_boundary_stage_keeps_the_coverage_gap(monkeypatch):
    graph_reads(monkeypatch, [])

    @trace_scope()
    def walk(session):
        boundary(_Trail())
        return {}

    with mtu_request(MtuRequest(mode="inventory"), 4):
        result = walk(SimpleNamespace(cts=42))["mtu"]
    (stage,) = result["stages"]
    assert stage["egress_subject_uid"] is None
    assert stage["ingress_subject_uid"] is None
    assert stage["enforcement"] == "unknown"
    assert stage["selection"] == "possible"
    assert "MTU_PATH_COVERAGE_INCOMPLETE" in stage["coverage"]["gaps"]


def test_candidate_in_an_incomplete_set_keeps_the_coverage_gap(monkeypatch):
    obs = [
        observation(subject_uid="p:1", enforcement="l2"),
        observation(subject_uid="p:2", enforcement="l2"),
    ]
    by_subject: dict[str, list] = {}
    for o in obs:
        by_subject.setdefault(o.subject_uid, []).append(o)

    def read(session, query, **params):
        if "HAS_MTU" in query:
            return [row(o) for subject in params["subject_uids"] for o in by_subject.get(subject, [])]
        if query == TOPOLOGY_QUERY:
            return [
                {
                    "subject_uid": "if:a",
                    "subject": {},
                    "carrier_uid": "lag:a",
                    "carrier_is_lag": True,
                    "member_uid": f"p:{i}",
                    "eligible": eligible,
                }
                for i, eligible in [(1, True), (2, None)]
            ]
        return []

    monkeypatch.setattr(path, "_read", read)

    @trace_scope()
    def walk(session):
        crossing(_Trail(), "if:a", enforcement="l2")
        return {}

    with mtu_request(MtuRequest(mode="inventory"), 4):
        result = walk(SimpleNamespace(cts=42))["mtu"]
    by_uid = {s["egress_subject_uid"]: s for s in result["stages"]}
    assert by_uid["p:1"]["selection"] == "eligible"
    assert by_uid["p:2"]["selection"] == "possible"
    assert by_uid["p:1"]["coverage"]["candidate_set_complete"] is False
    assert "MTU_PATH_COVERAGE_INCOMPLETE" in by_uid["p:1"]["coverage"]["gaps"]
    assert "MTU_PATH_COVERAGE_INCOMPLETE" in by_uid["p:2"]["coverage"]["gaps"]


def test_only_a_lower_bound_keeps_the_coverage_gap(monkeypatch):
    graph_reads(monkeypatch, [observation(subject_uid="if:a", bound_kind="acceptance_lower_bound")])

    @trace_scope()
    def walk(session):
        crossing(_Trail(), "if:a", enforcement="l3")
        return {}

    with mtu_request(MtuRequest(mode="inventory"), 4):
        result = walk(SimpleNamespace(cts=42))["mtu"]
    (stage,) = result["stages"]
    assert stage["constraints"]
    assert all(c["bound_kind"] != "ceiling" for c in stage["constraints"])
    assert "MTU_PATH_COVERAGE_INCOMPLETE" in stage["coverage"]["gaps"]


def test_backend_connection_identity_is_separate(monkeypatch):
    graph_reads(monkeypatch)

    @connection_scope
    def backend():
        crossing(_Trail(), "if:back", enforcement="l3")

    @trace_scope()
    def walk(session):
        crossing(_Trail(), "if:front", enforcement="l3")
        backend()
        return {}

    with mtu_request(MtuRequest(mode="inventory"), 4):
        result = walk(SimpleNamespace(cts=42))["mtu"]
    assert len(result["connections"]) == 2
    assert any(c["stages"][0]["connection_reset"] for c in result["connections"])


# --- _gateway_walk: a missing L2 chain is an unresolved crossing, not a drop ----------
#

_L2_SRC = _src_row(ip="10.0.0.5") | {
    "ep_uid": "ep:a",
    "ep_name": "laptop-a",
    "att_uid": "port:sw1-p1",
    "att_is_port": True,
    "att_name": "Port 1",
    "sw_uid": "dev:sw1",
    "sw_name": "sw1",
}


def _mtu_gateway_walk_trace(monkeypatch, fake: FakeGraph) -> dict:
    monkeypatch.setattr(path, "_read", lambda s, q, **p: fake.read(q, **p))
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: fake.read_one(q, **p))
    return path.trace(
        SimpleNamespace(cts=42),
        "10.0.0.5",
        "192.0.2.1",
        gateways=[GW],
        mtu={"mode": "packet", "ip_packet_bytes": 1300, "ipv4_df": True},
    )


def _unresolved_l2_stages(mtu_result: dict) -> list[dict]:
    return [s for s in mtu_result["stages"] if s["enforcement"] == "l2" and s["selection"] == "unknown"]


def test_gateway_walk_missing_l2_chain_records_an_unresolved_crossing(monkeypatch):
    """No cable chain connects the client's attachment and the gateway's uplink port."""
    fake = FakeGraph()
    fake.sources = [_L2_SRC]
    _script_l2_trunk(fake)  # scripts the trunk but no chain for (dev:sw1, port:sw2-p1)

    result = _mtu_gateway_walk_trace(monkeypatch, fake)
    mtu_result = result["mtu"]

    assert mtu_result["outcome"] != "fits_known_limits"
    unresolved = _unresolved_l2_stages(mtu_result)
    assert unresolved
    assert unresolved[0]["egress_subject_uid"] is None
    assert unresolved[0]["ingress_subject_uid"] is None
    assert "MTU_PATH_COVERAGE_INCOMPLETE" in unresolved[0]["coverage"]["gaps"]
    assert any("dev:sw1" in n and "port:sw2-p1" in n for n in result["notes"])


def test_gateway_walk_unknown_source_attachment_records_an_unresolved_crossing(monkeypatch):
    """The physical attachment of the source host is not resolved."""
    fake = FakeGraph()
    fake.sources = [_src_row(ip="10.0.0.5")]  # att_uid is None by construction
    _script_l2_trunk(fake)

    result = _mtu_gateway_walk_trace(monkeypatch, fake)
    mtu_result = result["mtu"]

    assert mtu_result["outcome"] != "fits_known_limits"
    unresolved = _unresolved_l2_stages(mtu_result)
    assert unresolved


def test_gateway_walk_svi_gateway_with_no_chain_records_an_unresolved_crossing(monkeypatch):
    """No trunk row resolves a switch port for the gateway interface (an SVI)."""
    fake = FakeGraph()
    fake.sources = [_L2_SRC]  # no trunk scripted: both trunk rows answer None

    result = _mtu_gateway_walk_trace(monkeypatch, fake)
    mtu_result = result["mtu"]

    assert mtu_result["outcome"] != "fits_known_limits"
    unresolved = _unresolved_l2_stages(mtu_result)
    assert unresolved
    assert "MTU_PATH_COVERAGE_INCOMPLETE" in unresolved[0]["coverage"]["gaps"]
    assert any("dev:sw1" in n and GW["dev_uid"] in n for n in result["warnings"])


def test_gateway_walk_prefix_source_with_no_chain_is_unaffected(monkeypatch):
    fake = FakeGraph()
    _script_l2_trunk(fake)
    monkeypatch.setattr(path, "_read", lambda s, q, **p: fake.read(q, **p))
    monkeypatch.setattr(path, "_read_one", lambda s, q, **p: fake.read_one(q, **p))

    result = path.trace(
        SimpleNamespace(cts=42),
        "10.0.0.0/24",
        "192.0.2.1",
        gateways=[GW],
        mtu={"mode": "packet", "ip_packet_bytes": 1300, "ipv4_df": True},
    )
    mtu_result = result["mtu"]
    assert not _unresolved_l2_stages(mtu_result)
