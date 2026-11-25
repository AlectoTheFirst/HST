"""Packet size semantics, independent connection lengths and serial alternatives."""

import pytest
from pydantic import ValidationError

from hst.core.mtu import MtuRequest
from hst.path.mtu import evaluate_stage, evaluate_stages
from hst.path.mtu_feedback import MtuPacketShape, request_for_connection
from test_mtu_budget import request, stage


@pytest.mark.parametrize("df", [True, False, None])
def test_aci_no_fragmentation_drops_oversize_for_every_df_value(df):
    result = evaluate_stage(stage(fragmentation_supported=False), request(1600, mode="packet", ipv4_df=df))
    assert result.outcome == "fail"
    assert any("does not support IPv4 fragmentation" in f.detail for f in result.findings)
    assert "MTU_FRAGMENTATION_UNMODELED" not in result.coverage.gaps


def test_ipv4_fragmentation_supported_does_not_promise_fragment_delivery():
    result = evaluate_stage(stage(fragmentation_supported=True), request(1600, mode="packet", ipv4_df=False))
    assert result.outcome == "fragmentation_required"
    assert not result.coverage.complete
    assert "MTU_FRAGMENTATION_UNMODELED" in result.coverage.gaps
    assert not result.feedback


def test_ipv6_packet_drop_keeps_feedback_unknown_until_error_route_is_evaluated():
    point = stage()
    point.context.af = 6
    point.constraints[0].metric = "ipv6_mtu_bytes"
    point.constraints[0].af = 6
    result = evaluate_stage(point, request(1600, mode="packet"))
    assert result.outcome == "fail"
    assert result.feedback[0].outcome == "unknown"
    assert result.feedback[0].gaps == ["MTU_PMTUD_FEEDBACK_UNKNOWN"]


def test_l2_constraint_inside_routed_stage_cannot_fragment_or_generate_ptb():
    point = stage()
    point.constraints[0].enforcement = "l2"
    point.constraints[0].metric = "l2_max_frame_bytes"
    point.constraints[0].value_bytes = 1514
    result = evaluate_stage(point, request(1600, mode="packet", ipv4_df=False))
    assert result.outcome == "fail"
    assert not result.feedback


def test_reverse_packet_size_is_independent_and_does_not_inherit_df():
    req = MtuRequest(mode="packet", ip_packet_bytes=9000, reply_ip_packet_bytes=1400, ipv4_df=True)
    result = evaluate_stages(
        [stage(stage_id="forward", direction="forward"), stage(stage_id="reverse", direction="reverse")], req
    )
    directions = {leg.direction: leg for leg in result.connections}
    assert directions["forward"].requested_bytes == 9000
    assert directions["forward"].outcome == "fail"
    assert directions["reverse"].requested_bytes == 1400
    assert directions["reverse"].outcome == "pass"
    selected, gaps = request_for_connection(req, direction="reverse")
    assert selected.ipv4_df is None and not gaps


def test_unstated_reply_and_proxy_packet_are_unknown_while_inventory_is_retained():
    result = evaluate_stages(
        [
            stage(stage_id="front"),
            stage(9000, stage_id="backend", connection_id="backend", connection_reset=True),
            stage(stage_id="reply", direction="reverse"),
        ],
        request(),
    )
    legs = {(leg.connection_id, leg.direction): leg for leg in result.connections}
    assert legs["original", "forward"].outcome == "pass"
    for key in [("backend", "forward"), ("original", "reverse")]:
        assert legs[key].outcome == "unknown" and legs[key].requested_bytes is None
        assert legs[key].known_ceiling_bytes is not None
        assert "MTU_LENGTH_UNSUPPORTED" in legs[key].coverage.gaps


def test_explicit_proxy_length_and_ordinary_nat_have_distinct_behavior():
    req = request(9000, mode="packet", ipv4_df=True)
    ordinary, gaps = request_for_connection(req)
    assert ordinary.ip_packet_bytes == 9000 and ordinary.ipv4_df is True and not gaps
    proxy, gaps = request_for_connection(req, connection_reset=True, explicit_ip_packet_bytes=1400)
    assert proxy.ip_packet_bytes == 1400 and proxy.ipv4_df is None and not gaps


def test_serial_lags_expand_both_sets_in_every_candidate():
    points = [
        stage(
            value,
            stage_id=f"{bundle}-{member}",
            candidate_set_id=bundle,
            candidate_id=member,
            selection="eligible",
        )
        for bundle, limits in [("first", [1500, 9000]), ("second", [1400, 8000])]
        for member, value in zip(["a", "b"], limits, strict=True)
    ]
    result = evaluate_stages(points, request(1400))
    assert len(result.candidates) == 4
    assert all(len(candidate.stages) == 2 for candidate in result.candidates)
    assert sorted(candidate.known_ceiling_bytes for candidate in result.candidates) == [
        1400,
        1400,
        1500,
        8000,
    ]
    assert result.known_ceiling_bytes == 8000
    assert result.guaranteed_bytes == 1400
    assert result.outcome == "pass"


def test_candidate_expansion_is_bounded_and_cannot_certify_truncated_paths():
    points = [
        stage(
            1500,
            stage_id=f"{bundle}-{member}",
            candidate_set_id=f"lag:{bundle}",
            candidate_id=f"member:{member}",
            selection="eligible",
        )
        for bundle in range(8)
        for member in range(2)
    ]
    result = evaluate_stages(points, request(1400))
    assert len(result.candidates) == 128
    assert result.coverage.truncated and not result.coverage.candidate_set_complete
    assert result.guaranteed_bytes is None and result.known_ceiling_bytes is None
    assert result.outcome == "unknown"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"af": 4, "ip_packet_bytes": 30, "ip_header_bytes": 20, "transport_header_bytes": 20},
        {"af": 4, "ip_packet_bytes": 1500, "ip_header_bytes": 22},
        {"af": 6, "ip_packet_bytes": 65576, "ip_header_bytes": 40},
        {"af": 6, "ip_packet_bytes": 1500, "ip_header_bytes": 44},
        {"af": 4, "ip_packet_bytes": 1500, "ip_header_bytes": 20, "non_initial_fragment": True},
    ],
)
def test_unsupported_or_impossible_packet_shapes_are_rejected(kwargs):
    with pytest.raises(ValidationError):
        MtuPacketShape(**kwargs)


def test_ipv6_ordinary_maximum_counts_its_base_header():
    assert MtuPacketShape(af=6, ip_packet_bytes=65575, ip_header_bytes=40).ip_packet_bytes == 65575
