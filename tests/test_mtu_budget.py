"""Real boundary outcomes for complete, partial and alternative MTU paths."""

import pytest

from hst.core.mtu import MtuConstraint, MtuContext, MtuCoverage, MtuRequest, MtuStage
from hst.path.mtu import evaluate_stage, evaluate_stages


def stage(value=1500, **changes):
    constraint = MtuConstraint(
        subject_uid="if:a",
        enforcement_key="ip",
        enforcement="l3",
        metric="ipv4_mtu_bytes",
        direction="tx",
        af=4,
        bound_kind="ceiling",
        value_bytes=value,
        evidence_uids=["mtu:a"],
        evidence_quality=["observed"],
    )
    fields = {
        "stage_id": "a",
        "egress_subject_uid": "if:a",
        "enforcement": "l3",
        "context": MtuContext(af=4, tag_depth=0),
        "constraints": [constraint],
        "selection": "selected",
        "coverage": MtuCoverage(
            complete=True, candidate_set_complete=True, constraints_complete=True, exact_path_known=True
        ),
    }
    fields.update(changes)
    return MtuStage(**fields)


def request(size=1500, **changes):
    return MtuRequest(mode=changes.pop("mode", "unfragmented"), ip_packet_bytes=size, **changes)


def test_exact_boundary_and_one_byte_above():
    assert evaluate_stage(stage(), request()).outcome == "pass"
    result = evaluate_stage(stage(), request(1501))
    assert result.outcome == "fail"
    assert result.findings[0].deficit_bytes == 1


def test_known_limit_is_not_a_guarantee_across_unknown_stretch():
    missing = stage(stage_id="missing", constraints=[], coverage=MtuCoverage())
    result = evaluate_stages([stage(), missing], request())
    assert result.outcome == "unknown"
    assert result.known_ceiling_bytes == 1500
    assert result.guaranteed_bytes is None


def test_local_deficit_is_provable_even_with_unknown_other_stage():
    missing = stage(stage_id="missing", constraints=[], coverage=MtuCoverage())
    result = evaluate_stages([stage(), missing], request(9000))
    assert result.outcome == "fail"
    assert result.guaranteed_bytes is None


def test_acceptance_lower_bound_does_not_prove_rejection_above_it():
    receiving = stage()
    receiving.constraints[0].bound_kind = "acceptance_lower_bound"
    receiving.constraints[0].direction = "rx"
    receiving.context.direction = "rx"
    assert evaluate_stage(receiving, request()).outcome == "pass"
    larger = evaluate_stage(receiving, request(1501))
    assert larger.outcome == "unknown"
    assert larger.known_ceiling_bytes is None
    assert larger.guaranteed_bytes == 1500


def test_canonical_tagged_frame_conversion():
    tagged = stage()
    tagged.constraints[0].metric = "l2_max_frame_bytes"
    tagged.constraints[0].value_bytes = 1514
    tagged.context.tag_depth = 1
    assert evaluate_stage(tagged, request(1496)).outcome == "pass"
    assert evaluate_stage(tagged, request(1497)).outcome == "fail"
    tagged.context.tag_depth = None
    assert evaluate_stage(tagged, request()).outcome == "unknown"


@pytest.mark.parametrize(
    ("df", "outcome"), [(True, "fail"), (False, "fragmentation_required"), (None, "conditional")]
)
def test_ipv4_packet_fragmentation_outcomes(df, outcome):
    assert evaluate_stage(stage(), request(1501, mode="packet", ipv4_df=df)).outcome == outcome


def rx_stage(value=1500, af=4, **changes):
    """An entry-side interface ceiling: the same bound_kind as an exit ceiling,
    but the stage's own context direction is "rx"."""
    constraint = MtuConstraint(
        subject_uid="if:a",
        enforcement_key="ip",
        enforcement="l3",
        metric=f"ipv{af}_mtu_bytes",
        direction="both",
        af=af,
        bound_kind="ceiling",
        value_bytes=value,
        evidence_uids=["mtu:a"],
        evidence_quality=["observed"],
    )
    fields = {
        "stage_id": "entry",
        "ingress_subject_uid": "if:a",
        "enforcement": "l3",
        "context": MtuContext(af=af, direction="rx", tag_depth=0),
        "constraints": [constraint],
        "selection": "selected",
        "coverage": MtuCoverage(
            complete=True, candidate_set_complete=True, constraints_complete=True, exact_path_known=True
        ),
    }
    fields.update(changes)
    return MtuStage(**fields)


@pytest.mark.parametrize("df", [True, False, None])
def test_rx_entry_ceiling_deficit_fails_in_every_df_state(df):
    # A 9000-byte packet against a 1500 entry-interface ceiling is dropped at
    # the entry to that interface regardless of DF; no fragmentation and no
    # ICMP feedback belong to an entry-side deficit.
    result = evaluate_stage(rx_stage(), request(9000, mode="packet", ipv4_df=df))
    assert result.outcome == "fail"
    assert result.outcome != "fragmentation_required"
    assert "MTU_FRAGMENTATION_UNMODELED" not in result.coverage.gaps
    assert result.feedback == []
    deficit = next(f for f in result.findings if f.code == "MTU_CAPACITY_DEFICIT")
    assert deficit.detail == (
        "Requested complete IP packet exceeds the entry interface MTU; "
        "the interface drops it in every DF state."
    )


def test_rx_entry_ceiling_deficit_fails_for_ipv6_too():
    result = evaluate_stage(rx_stage(af=6), request(9000, mode="packet"))
    assert result.outcome == "fail"
    assert "MTU_FRAGMENTATION_UNMODELED" not in result.coverage.gaps
    assert result.feedback == []
    deficit = next(f for f in result.findings if f.code == "MTU_CAPACITY_DEFICIT")
    assert "entry interface MTU" in deficit.detail


@pytest.mark.parametrize(
    ("df", "outcome"), [(True, "fail"), (False, "fragmentation_required"), (None, "conditional")]
)
def test_tx_exit_ceiling_fragmentation_outcomes_follow_df(df, outcome):
    result = evaluate_stage(stage(1492), request(1500, mode="packet", ipv4_df=df))
    assert result.outcome == outcome
    deficit = next(f for f in result.findings if f.code == "MTU_CAPACITY_DEFICIT")
    assert deficit.detail == "Requested complete IP packet exceeds this stage's normalized budget."


def test_l2_does_not_fragment_and_possible_cable_does_not_prove_drop():
    assert (
        evaluate_stage(stage(enforcement="l2"), request(1501, mode="packet", ipv4_df=False)).outcome == "fail"
    )
    possible = evaluate_stage(stage(selection="possible"), request(9000))
    assert possible.outcome == "unknown"
    assert possible.findings[0].severity == "risk"


def test_exit_fragmentation_reaches_the_next_hops_matching_entry_ceiling():
    # A router's egress and the next hop's ingress share one link and one MTU.
    exit_stage = stage(1500, stage_id="exit", depth=0)
    entry_stage = rx_stage(1500, stage_id="entry", depth=1)
    for df, outcome, gap in (
        (True, "fail", None),
        (False, "fragmentation_required", "MTU_FRAGMENTATION_UNMODELED"),
        (None, "conditional", None),
    ):
        result = evaluate_stages([exit_stage, entry_stage], request(1501, mode="packet", ipv4_df=df))
        assert result.outcome == outcome
        assert (gap in result.coverage.gaps) is (gap is not None)
        if df is not True:
            assert not any(f.stage_ids == ["entry"] for f in result.findings)


def test_exit_fragmentation_fails_a_smaller_next_entry():
    exit_stage = stage(1500, stage_id="exit", depth=0)
    smaller_entry = rx_stage(1300, stage_id="entry", depth=1)
    result = evaluate_stages([exit_stage, smaller_entry], request(1501, mode="packet", ipv4_df=False))
    assert result.outcome == "fail"
    entry_deficit = next(f for f in result.findings if f.stage_ids == ["entry"])
    assert entry_deficit.severity == "failure"
    assert "entry interface MTU" in entry_deficit.detail


def test_exit_fragmentation_reaches_a_candidate_entrys_matching_ceiling():
    # mtu_topology.expand_stages clones a stage per LAG member.
    exit_stage = stage(1500, stage_id="exit", depth=0)
    member_entries = [
        rx_stage(1514, stage_id=member, depth=1, candidate_id=member, candidate_set_id="po1")
        for member in ("m1", "m2")
    ]
    for member_stage in member_entries:
        member_stage.constraints[0].metric = "l2_max_frame_bytes"
    result = evaluate_stages([exit_stage, *member_entries], request(1501, mode="packet", ipv4_df=False))
    assert result.outcome == "fragmentation_required"
    assert "MTU_FRAGMENTATION_UNMODELED" in result.coverage.gaps
    assert not any(f.stage_ids in (["m1"], ["m2"]) for f in result.findings)


def test_a_candidates_own_fragmentation_does_not_thread_into_the_shared_trunk():
    # Only a trunk stage produces a threaded update.
    member_exits = [
        stage(1500, stage_id=member, depth=0, candidate_id=member, candidate_set_id="po1")
        for member in ("m1", "m2")
    ]
    trunk_entry = rx_stage(1500, stage_id="entry", depth=1)
    result = evaluate_stages([*member_exits, trunk_entry], request(1501, mode="packet", ipv4_df=False))
    assert any(f.stage_ids == ["entry"] for f in result.findings)


def test_distinct_proxy_connections_never_share_one_path_ceiling():
    result = evaluate_stages([stage(), stage(9000, connection_id="backend")], request())
    assert len(result.connections) == 2
    assert result.known_ceiling_bytes is None
    assert {p.guaranteed_bytes for p in result.connections} == {1500, 9000}


def test_alternatives_preserve_different_outcomes_and_guaranteed_minimum():
    result = evaluate_stages(
        [
            stage(candidate_id="small", selection="eligible"),
            stage(9000, candidate_id="large", selection="eligible", stage_id="b"),
        ],
        request(9000),
    )
    assert result.outcome == "conditional"
    assert result.guaranteed_bytes == 1500
    assert result.known_ceiling_bytes == 9000
    assert {p.outcome for p in result.candidates} == {"pass", "fail"}


def test_all_missing_and_off_inventory_modes():
    assert evaluate_stages([], request()).outcome == "unknown"
    assert evaluate_stages([stage()], MtuRequest()).outcome == "not_assessed"
    result = evaluate_stages([stage()], MtuRequest(mode="inventory"))
    assert result.outcome == "not_assessed"
    assert result.known_ceiling_bytes == 1500


def test_unobserved_alternative_cannot_prove_all_candidate_failure():
    incomplete = MtuCoverage(complete=False, candidate_set_complete=False, constraints_complete=True)
    result = evaluate_stages([stage(candidate_id="known", coverage=incomplete)], request(9000))
    assert result.outcome == "unknown"
    assert result.known_ceiling_bytes is None
    assert result.guaranteed_bytes is None


def test_unmatched_direction_or_class_cannot_supply_a_guarantee():
    wrong = stage()
    wrong.constraints[0].direction = "rx"
    assert evaluate_stage(wrong, request()).guaranteed_bytes is None
    wrong.constraints[0].direction = "tx"
    wrong.constraints[0].traffic_class = "jumbo"
    assert evaluate_stage(wrong, request()).guaranteed_bytes is None


def test_zero_budget_is_a_proven_deficit_not_missing_data():
    exhausted = stage()
    exhausted.constraints[0].metric = "l2_max_frame_bytes"
    exhausted.constraints[0].value_bytes = 14
    result = evaluate_stage(exhausted, request(20))
    assert result.known_ceiling_bytes == 0
    assert result.outcome == "fail"


def test_an_unrelated_svi_does_not_limit_pure_bridging():
    svi = stage(1500, stage_id="unrelated-svi", applicability="not_applicable")
    result = evaluate_stages([stage(9000), svi], request(9000))
    assert result.outcome == "pass"
    assert result.known_ceiling_bytes == 9000


# --- Lane fold: each lane is judged like its own path, then the lanes fold ------------------
#
# A lane is a route alternative or flow partition of one connection.


def test_two_failing_lanes_with_df_set_both_fail():
    lanes = [stage(1400, lane="0", stage_id="lane0"), stage(1400, lane="1", stage_id="lane1")]
    result = evaluate_stages(lanes, request(1500, mode="packet", ipv4_df=True))
    assert result.outcome == "fail"
    assert {lane.outcome for lane in result.lanes} == {"fail"}
    assert all(f.severity == "failure" for lane in result.lanes for f in lane.findings)
    assert all(f.severity == "failure" for f in result.findings if f.code == "MTU_CAPACITY_DEFICIT")


def test_two_failing_lanes_with_df_cleared_both_need_fragmentation():
    lanes = [stage(1400, lane="0", stage_id="lane0"), stage(1400, lane="1", stage_id="lane1")]
    result = evaluate_stages(lanes, request(1500, mode="packet", ipv4_df=False))
    assert result.outcome == "fragmentation_required"
    assert {lane.outcome for lane in result.lanes} == {"fragmentation_required"}


def test_two_failing_lanes_with_df_unstated_are_conditional():
    lanes = [stage(1400, lane="0", stage_id="lane0"), stage(1400, lane="1", stage_id="lane1")]
    result = evaluate_stages(lanes, request(1500, mode="packet", ipv4_df=None))
    assert result.outcome == "conditional"
    assert {lane.outcome for lane in result.lanes} == {"conditional"}


def test_two_failing_ipv6_lanes_both_fail():
    def ipv6_stage(**changes):
        point = stage(1400, **changes)
        point.context.af = 6
        point.constraints[0].metric = "ipv6_mtu_bytes"
        point.constraints[0].af = 6
        return point

    lanes = [ipv6_stage(lane="0", stage_id="lane0"), ipv6_stage(lane="1", stage_id="lane1")]
    result = evaluate_stages(lanes, request(1500, mode="packet"))
    assert result.outcome == "fail"
    assert {lane.outcome for lane in result.lanes} == {"fail"}


def test_one_lane_deficit_one_lane_pass_is_conditional_with_no_guarantee():
    # The deficit lane's path coverage is incomplete.
    deficit_coverage = MtuCoverage(
        candidate_set_complete=True, constraints_complete=True, exact_path_known=True
    )
    lanes = [
        stage(1400, lane="0", stage_id="lane0", coverage=deficit_coverage),
        stage(1500, lane="1", stage_id="lane1"),
    ]
    result = evaluate_stages(lanes, request(1500, mode="packet", ipv4_df=True))
    assert result.outcome == "conditional"
    assert result.guaranteed_bytes is None
    deficit_findings = [f for f in result.findings if f.code == "MTU_CAPACITY_DEFICIT"]
    assert deficit_findings and all(f.severity == "risk" for f in deficit_findings)
    by_lane = {lane.lane: lane for lane in result.lanes}
    assert by_lane["0"].outcome == "fail"
    assert all(f.severity == "failure" for f in by_lane["0"].findings)
    assert by_lane["1"].outcome == "pass"


def test_one_lane_deficit_one_lane_with_no_constraints_is_unknown():
    lanes = [
        stage(1400, lane="0", stage_id="lane0"),
        stage(lane="1", stage_id="lane1", constraints=[], coverage=MtuCoverage()),
    ]
    result = evaluate_stages(lanes, request(1500, mode="packet", ipv4_df=True))
    assert result.outcome == "unknown"
    deficit_findings = [f for f in result.findings if f.code == "MTU_CAPACITY_DEFICIT"]
    assert deficit_findings and all(f.severity == "risk" for f in deficit_findings)
    by_lane = {lane.lane: lane for lane in result.lanes}
    assert by_lane["0"].outcome == "fail"
    assert all(f.severity == "failure" for f in by_lane["0"].findings)


def test_tunnel_lane_fails_while_l3_lane_needs_fragmentation_and_connection_is_conditional():
    tunnel = stage(1300, lane="0", stage_id="lane0", enforcement="tunnel")
    tunnel.constraints[0].enforcement = "tunnel"
    l3_deficit = stage(1400, lane="1", stage_id="lane1")
    result = evaluate_stages([tunnel, l3_deficit], request(1500, mode="packet", ipv4_df=False))
    by_lane = {lane.lane: lane for lane in result.lanes}
    assert by_lane["0"].outcome == "fail"
    assert by_lane["1"].outcome == "fragmentation_required"
    assert result.outcome == "conditional"


def test_two_passing_lanes_guarantee_the_smaller_lane_ceiling():
    lanes = [stage(1500, lane="0", stage_id="lane0"), stage(9000, lane="1", stage_id="lane1")]
    result = evaluate_stages(lanes, request(1500, mode="packet", ipv4_df=True))
    assert result.outcome == "pass"
    assert result.guaranteed_bytes == 1500
    assert {lane.outcome for lane in result.lanes} == {"pass"}


# --- fits_known_limits: distinct from pass, and how it folds -----------------------------


def endpoint_stage(kind="source", **changes):
    """A source/destination endpoint stage as capture leaves it."""
    fields = {
        "stage_id": f"{kind}-endpoint",
        "enforcement": kind,
        "context": MtuContext(af=4),
        "selection": "eligible",
        "egress_subject_uid": "if:client" if kind == "source" else None,
        "ingress_subject_uid": "if:server" if kind == "destination" else None,
        "constraints": [],
        "coverage": MtuCoverage(gaps=["MTU_ENDPOINT_UNKNOWN"]),
    }
    fields.update(changes)
    return MtuStage(**fields)


def fits_stage(value=1500, **changes):
    """A device stage that Part 1 resolves does not reach "pass" on its own."""
    fields = {"coverage": MtuCoverage(candidate_set_complete=True, constraints_complete=True)}
    fields.update(changes)
    return stage(value, **fields)


def test_single_lane_fits_known_limits_with_only_a_source_gap():
    lanes = [endpoint_stage("source"), fits_stage(1500, stage_id="device")]
    result = evaluate_stages(lanes, request(1300, mode="packet", ipv4_df=True))
    assert result.outcome == "fits_known_limits"
    assert result.coverage.uncovered == ["source-endpoint"]
    assert result.coverage.gaps and "MTU_ENDPOINT_UNKNOWN" in result.coverage.gaps
    assert result.coverage.complete is False
    assert result.guaranteed_bytes is None


def test_lane_with_an_incomplete_device_stage_stays_unknown():
    incomplete = fits_stage(
        1500,
        stage_id="device",
        coverage=MtuCoverage(
            candidate_set_complete=True, constraints_complete=True, gaps=["MTU_PATH_COVERAGE_INCOMPLETE"]
        ),
    )
    lanes = [endpoint_stage("source"), incomplete]
    result = evaluate_stages(lanes, request(1300, mode="packet", ipv4_df=True))
    assert result.outcome == "unknown"
    assert result.coverage.uncovered == []


def test_fold_lane_fits_with_lane_fits_gives_fits():
    lanes = [
        endpoint_stage("source", stage_id="source0", lane="0"),
        fits_stage(1500, stage_id="device0", lane="0"),
        endpoint_stage("source", stage_id="source1", lane="1"),
        fits_stage(1500, stage_id="device1", lane="1"),
    ]
    result = evaluate_stages(lanes, request(1300, mode="packet", ipv4_df=True))
    assert {lane.outcome for lane in result.lanes} == {"fits_known_limits"}
    assert result.outcome == "fits_known_limits"
    assert result.coverage.uncovered == ["source-endpoint"]


def test_fold_lane_fits_with_lane_pass_gives_fits():
    # A guarantee needs every lane.
    lanes = [
        endpoint_stage("source", stage_id="source0", lane="0"),
        fits_stage(1500, stage_id="device0", lane="0"),
        stage(1500, lane="1", stage_id="lane1"),
    ]
    result = evaluate_stages(lanes, request(1300, mode="packet", ipv4_df=True))
    by_lane = {lane.lane: lane for lane in result.lanes}
    assert by_lane["0"].outcome == "fits_known_limits"
    assert by_lane["1"].outcome == "pass"
    assert result.outcome == "fits_known_limits"
    assert result.guaranteed_bytes is None


def test_fold_lane_fits_with_lane_fail_gives_conditional():
    lanes = [
        endpoint_stage("source", stage_id="source0", lane="0"),
        fits_stage(1500, stage_id="device0", lane="0"),
        stage(1400, lane="1", stage_id="lane1"),
    ]
    result = evaluate_stages(lanes, request(1500, mode="packet", ipv4_df=True))
    by_lane = {lane.lane: lane for lane in result.lanes}
    assert by_lane["0"].outcome == "fits_known_limits"
    assert by_lane["1"].outcome == "fail"
    assert result.outcome == "conditional"


def test_fold_lane_fits_with_lane_fragmentation_required_gives_conditional():
    lanes = [
        endpoint_stage("source", stage_id="source0", lane="0"),
        fits_stage(1500, stage_id="device0", lane="0"),
        stage(1400, lane="1", stage_id="lane1"),
    ]
    result = evaluate_stages(lanes, request(1500, mode="packet", ipv4_df=False))
    by_lane = {lane.lane: lane for lane in result.lanes}
    assert by_lane["0"].outcome == "fits_known_limits"
    assert by_lane["1"].outcome == "fragmentation_required"
    assert result.outcome == "conditional"


def test_fold_lane_fits_with_lane_unknown_gives_unknown():
    lanes = [
        endpoint_stage("source", stage_id="source0", lane="0"),
        fits_stage(1500, stage_id="device0", lane="0"),
        stage(lane="1", stage_id="lane1", constraints=[], coverage=MtuCoverage()),
    ]
    result = evaluate_stages(lanes, request(1300, mode="packet", ipv4_df=True))
    by_lane = {lane.lane: lane for lane in result.lanes}
    assert by_lane["0"].outcome == "fits_known_limits"
    assert by_lane["1"].outcome == "unknown"
    assert result.outcome == "unknown"


def test_multi_connection_fold_pass_and_fits_gives_fits():
    conn_a = stage(1500, stage_id="a", connection_id="original")
    conn_b = [
        endpoint_stage("source", stage_id="source-b", connection_id="b"),
        fits_stage(1500, stage_id="device-b", connection_id="b"),
    ]
    result = evaluate_stages([conn_a, *conn_b], request(1300, mode="packet", ipv4_df=True))
    assert len(result.connections) == 2
    by_connection = {c.connection_id: c for c in result.connections}
    assert by_connection["original"].outcome == "pass"
    assert by_connection["b"].outcome == "fits_known_limits"
    assert result.outcome == "fits_known_limits"
