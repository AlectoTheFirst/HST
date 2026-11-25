import json

import pytest
from pydantic import ValidationError

from hst.core.model import Batch, NodeRecord, RelRecord
from hst.core.mtu import MtuContext, MtuPolicyApplication, MtuRequest, MtuResult, mtu_fingerprint
from hst.core.mtu_profiles import observation_from_raw, observation_records
from hst.core.mtu_read import resolve_constraints


def observation(value=1500, **extra):
    fields = {
        "subject_uid": "dev:synthetic/if/eth0",
        "source": "synthetic",
        "source_target": "fixture",
        "source_field": "ip_mtu",
        "raw_value": value,
        "profile_id": "ip_packet",
        "metric": "ipv4_mtu_bytes",
        "direction": "tx",
        "bound_kind": "ceiling",
        "enforcement": "l3",
        "assertion_kind": "operational",
    }
    fields.update(extra)
    return observation_from_raw(**fields)


@pytest.mark.parametrize("raw", [None, True, 1500.0, "inherit", -1, 0, "1500 bytes"])
def test_ambiguous_values_remain_raw(raw):
    obs = observation(raw)
    assert json.loads(obs.raw_value_json) == raw
    assert obs.normalized_value is None
    assert obs.gaps == ["MTU_SEMANTICS_UNKNOWN"]


def test_identity_is_value_version_independent_but_source_scoped():
    first = observation()
    changed = observation(9000, collector_version="2", profile_version="2")
    assert first.uid == changed.uid
    assert first.uid != observation(source_target="other").uid
    assert first.uid != observation(direction="rx").uid
    assert mtu_fingerprint(first.model_dump()) != mtu_fingerprint(changed.model_dump())


def test_frame_profiles_and_explicit_payload_tag_allowance():
    assert observation("1500").normalized_value == 1500
    frame = observation(
        1518, profile_id="ethernet_frame_including_fcs", metric="l2_max_frame_bytes", enforcement="l2"
    )
    assert frame.normalized_value == 1514
    assert frame.normalized_value - 14 == observation().normalized_value
    for depth in (0, 1, 2):
        payload = observation(
            1500,
            profile_id="ethernet_payload",
            metric="l2_max_frame_bytes",
            tag_depth=depth,
            tag_accounting="extra_allowance",
            tag_allowance_bytes=4 * depth,
            enforcement="l2",
        )
        assert payload.normalized_value == 1514 + 4 * depth
    ambiguous = observation(1500, profile_id="ethernet_payload", metric="l2_max_frame_bytes")
    assert ambiguous.normalized_value is None


def test_receive_guarantee_is_not_rejection_limit():
    obs = observation(direction="rx", bound_kind="acceptance_lower_bound")
    resolved = resolve_constraints([obs], MtuContext(af=4, direction="rx"))
    assert resolved.constraints[0].bound_kind == "acceptance_lower_bound"
    assert resolved.constraints[0].value_bytes == 1500


def test_override_operational_drift_and_independent_constraint():
    default = observation(
        1500, subject_uid="dev:synthetic", source_field="system", scope="device", assertion_kind="configured"
    )
    explicit = observation(9000, assertion_kind="configured")
    actual = observation(8500)
    physical = observation(8000, source_field="fabric", enforcement_key="fabric")
    applications = [
        MtuPolicyApplication(
            observation_uid=default.uid,
            subject_uid=explicit.subject_uid,
            enforcement_key="interface",
            precedence=-1,
            profile_id="synthetic-explicit",
            evidence_uids=[default.uid],
        )
    ]
    result = resolve_constraints(
        [default, explicit, actual, physical], MtuContext(af=4), applications=applications
    )
    assert {c.value_bytes for c in result.constraints} == {8000, 8500}
    assert [c.value_bytes for c in result.configured] == [9000]
    assert result.findings[0].code == "MTU_POLICY_DRIFT"
    assert len(result.observations) == 4


def test_equal_authority_conflict_and_intent_does_not_override():
    result = resolve_constraints(
        [observation(), observation(9000, source="other"), observation(9200, assertion_kind="intent")],
        MtuContext(af=4),
    )
    assert result.constraints[0].value_bytes is None
    assert "MTU_SOURCE_CONFLICT" in result.gaps
    assert result.intent[0].value_bytes == 9200


def test_missing_class_preserves_alternatives_and_unknown_scope():
    result = resolve_constraints(
        [observation(1500, traffic_class="default"), observation(9000, traffic_class="jumbo")],
        MtuContext(af=4),
    )
    assert {c.value_bytes for c in result.constraints} == {1500, 9000}
    assert "MTU_CLASS_UNKNOWN" in result.gaps
    unresolved = resolve_constraints([observation(scope="fabric")], MtuContext(af=4))
    assert not unresolved.constraints
    assert "MTU_POLICY_UNRESOLVED" in unresolved.gaps


def test_graph_properties_scalar_and_endpoint_validation():
    obs = observation()
    node, rel = observation_records("Interface", obs)
    Batch(source="synthetic", scope="fixture", nodes=[node], rels=[rel]).validate_registry()
    assert all(not isinstance(v, dict) for v in node.props.values())
    invalid = RelRecord(
        type="HAS_MTU",
        start_label="Prefix",
        start_uid="pfx:fixture",
        end_label="MtuObservation",
        end_uid=obs.uid,
    )
    with pytest.raises(ValueError, match="HAS_MTU endpoints"):
        Batch(source="synthetic", scope="fixture", rels=[invalid]).validate_registry()
    with pytest.raises(ValueError):
        observation_records("Prefix", obs)
    assert NodeRecord(label="MtuObservation", uid=obs.uid, props=obs.graph_props()).uid == obs.uid


@pytest.mark.parametrize(
    "mtu_request",
    [
        {"mode": "packet"},
        {"mode": "inventory", "ip_packet_bytes": 1500},
        {"mode": "unfragmented", "ip_packet_bytes": True},
        {"mode": "packet", "ip_packet_bytes": 1500.0},
    ],
)
def test_invalid_request_rejected(mtu_request):
    with pytest.raises(ValidationError):
        MtuRequest(**mtu_request)


def test_address_family_lengths_and_off_default():
    assert MtuRequest().mode == "off"
    assert MtuResult().outcome == "not_assessed"
    MtuRequest(mode="packet", ip_packet_bytes=65575).validate_af(6)
    for length in (39, 65576):
        with pytest.raises(ValueError):
            MtuRequest(mode="packet", ip_packet_bytes=length).validate_af(6)
    with pytest.raises(ValueError):
        MtuRequest(mode="packet", ip_packet_bytes=65536).validate_af(4)
    with pytest.raises(ValueError):
        MtuRequest(mode="packet", ip_packet_bytes=1500, ipv4_df=True).validate_af(6)


def test_frame_extra_tags_are_counted_exactly_once():
    for depth in (1, 2):
        obs = observation(
            1514,
            metric="l2_max_frame_bytes",
            profile_id="ethernet_frame_excluding_fcs",
            tag_depth=depth,
            tag_accounting="extra_allowance",
            tag_allowance_bytes=4 * depth,
        )
        assert obs.normalized_value == 1514 + 4 * depth


def test_unknown_direction_cannot_supply_applicable_limit():
    obs = observation(direction="unknown")
    result = resolve_constraints([obs], MtuContext(af=4))
    assert result.constraints[0].value_bytes is None
    assert "MTU_SEMANTICS_UNKNOWN" in result.gaps


def test_lag_identity_uses_shared_interface_slug():
    from hst.core import uid
    from hst.core.normalize import iface_slug

    assert uid.lag("dev:synthetic", "Port-channel10") == f"dev:synthetic/lag/{iface_slug('Port-channel10')}"
