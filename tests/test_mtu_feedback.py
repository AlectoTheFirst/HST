"""Typed PMTUD errors require their own policy, quote and state evidence."""

import pytest
from pydantic import ValidationError

from hst.core.mtu import MtuPacketDescriptor
from hst.path.mtu import evaluate_stage
from hst.path.mtu_feedback import (
    MtuFeedbackHop,
    MtuQuotedFlow,
    build_feedback_packet,
    evaluate_feedback,
    feedback_findings,
)
from test_mtu_budget import request, stage


def quoted(af=4):
    return MtuQuotedFlow(
        af=af,
        source_ip="192.0.2.10" if af == 4 else "2001:db8::10",
        destination_ip="198.51.100.20" if af == 4 else "2001:db8:1::20",
        protocol=6,
        source_port=12345,
        destination_port=443,
    )


def packet(af=4):
    point = stage()
    point.context.af = af
    point.constraints[0].metric = f"ipv{af}_mtu_bytes"
    point.constraints[0].af = af
    req = request(1600, mode="packet", ipv4_df=True if af == 4 else None)
    return build_feedback_packet(
        point,
        req,
        evaluate_stage(point, req),
        router_ip="192.0.2.1" if af == 4 else "2001:db8::1",
        quoted_flow=quoted(af),
    )


def hop(**changes):
    fields = {
        "stage_id": "error-router",
        "route_outcome": "permitted",
        "policy_outcome": "permitted",
        "icmp_type_code_complete": True,
        "quoted_flow_complete": True,
        "evidence_uids": ["rule:error"],
    }
    fields.update(changes)
    return MtuFeedbackHop(**fields)


@pytest.mark.parametrize(("af", "icmp_type", "code"), [(4, 3, 4), (6, 2, 0)])
def test_feedback_packet_quotes_specific_connection_and_returns_to_sender(af, icmp_type, code):
    error = packet(af)
    assert isinstance(error, MtuPacketDescriptor)
    assert (error.icmp_type, error.icmp_code) == (icmp_type, code)
    assert error.destination_ip == quoted(af).source_ip
    assert error.advertised_mtu_bytes == 1500


def test_l2_drop_cannot_invent_a_router_error():
    point = stage(enforcement="l2")
    req = request(1600, mode="packet", ipv4_df=True)
    assert (
        build_feedback_packet(
            point, req, evaluate_stage(point, req), router_ip="192.0.2.1", quoted_flow=quoted()
        )
        is None
    )


def test_permitted_feedback_needs_error_generation_and_complete_route():
    error = packet()
    assert evaluate_feedback(error, [hop()], path_complete=True).outcome == "unknown"
    permitted = evaluate_feedback(error, [hop()], path_complete=True, generation="modeled")
    assert permitted.outcome == "permitted" and not permitted.gaps
    assert evaluate_feedback(error, [hop()], generation="modeled").outcome == "unknown"


@pytest.mark.parametrize(
    "changes",
    [
        {"icmp_type_code_complete": False},
        {"quoted_flow_complete": False},
        {"stateful": True},
        {"route_outcome": "unknown"},
        {"policy_outcome": "unknown"},
    ],
)
def test_bare_icmp_or_established_reply_permission_does_not_prove_ptb_permission(changes):
    result = evaluate_feedback(packet(), [hop(**changes)], path_complete=True, generation="modeled")
    assert result.outcome == "unknown"
    assert result.gaps == ["MTU_PMTUD_FEEDBACK_UNKNOWN"]


def test_supported_related_state_evidence_can_permit_exact_icmp_error():
    stateful = hop(stateful=True, related_state_complete=True)
    assert (
        evaluate_feedback(packet(), [stateful], path_complete=True, generation="modeled").outcome
        == "permitted"
    )


def test_local_proven_feedback_block_survives_unknown_other_hop_as_risk_not_outage():
    result = evaluate_feedback(packet(), [hop(policy_outcome="blocked"), hop(route_outcome="unknown")])
    assert result.outcome == "blocked"
    findings = feedback_findings(result, stage_id="limit")
    assert findings[0].code == "MTU_PMTUD_BLACKHOLE_RISK" and findings[0].severity == "risk"


def test_wrong_error_type_quote_connection_or_malformed_quote_is_unknown():
    error = packet()
    for change in [{"icmp_type": 8}, {"connection_id": "other"}, {"quoted_flow_json": "{"}]:
        bad = error.model_copy(update=change)
        assert evaluate_feedback(bad, [hop()], path_complete=True, generation="modeled").outcome == "unknown"


def test_nat64_quote_is_rejected_without_explicit_family_transform():
    point = stage()
    req = request(1600, mode="packet", ipv4_df=True)
    with pytest.raises(ValueError, match="connection and AF"):
        build_feedback_packet(
            point, req, evaluate_stage(point, req), router_ip="192.0.2.1", quoted_flow=quoted(6)
        )


def test_invalid_quoted_address_family_is_rejected():
    with pytest.raises(ValidationError):
        MtuQuotedFlow(af=6, source_ip="192.0.2.10", destination_ip="2001:db8::20", protocol=6)
