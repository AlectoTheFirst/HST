"""A normalized local inherit assertion retains its policy dependencies."""

from tests.test_mtu_contract import observation

from hst.core.mtu import MtuContext
from hst.core.mtu_profiles import observation_from_raw
from hst.core.mtu_read import resolve_constraints


def test_local_inheritance_keeps_policy_reference_and_dependency_evidence():
    obs = observation(
        assertion_kind="configured",
        resolution_state="inherited",
        policy_ref="policy:fabric-default",
        dependency_uids=["mtu:fabric"],
    )
    result = resolve_constraints([obs], MtuContext(af=4, enforcement="l3"))
    constraint = result.constraints[0]
    assert "inherited" in constraint.evidence_quality
    assert constraint.inherited_from == ["policy:fabric-default"]
    assert constraint.evidence_uids == sorted([obs.uid, "mtu:fabric"])


def _raw_field(subject_uid, source_field="port_table.jumbo", raw_value=True):
    """A preserved raw field (mtu_import.py's `preserve_raw_mtu_fields`)."""
    return observation_from_raw(
        subject_uid=subject_uid,
        source="unifi",
        source_target="fixture",
        source_field=source_field,
        raw_value=raw_value,
        assertion_kind="configured",
        enforcement="unknown",
    )


def test_a_preserved_raw_field_yields_no_constraint_beside_a_resolved_sibling():
    resolved = observation(
        1518,
        metric="l2_max_frame_bytes",
        bound_kind="ceiling",
        enforcement="l2",
        profile_id="ethernet_frame_including_fcs",
    )
    raw = _raw_field(resolved.subject_uid)
    assert raw.metric == "unknown" and raw.bound_kind == "unknown"
    result = resolve_constraints([resolved, raw], MtuContext(af=4, enforcement="l2", direction="tx"))
    assert len(result.constraints) == 1
    assert result.constraints[0].value_bytes == 1514
    assert "MTU_SEMANTICS_UNKNOWN" not in result.gaps
    # The raw field stays in the evidence set; only its promotion to a
    # constraint is suppressed.
    assert raw in result.observations
    assert resolved in result.observations


def test_a_preserved_raw_field_alone_yields_the_unknown_constraint():
    raw = _raw_field("dev:synthetic/if/eth0")
    result = resolve_constraints([raw], MtuContext(af=4, enforcement="l2", direction="tx"))
    assert len(result.constraints) == 1
    assert result.constraints[0].bound_kind == "unknown"
    assert "MTU_SEMANTICS_UNKNOWN" in result.gaps


def test_a_preserved_raw_field_for_a_different_context_stands_alone():
    resolved = observation(
        1518,
        metric="l2_max_frame_bytes",
        bound_kind="ceiling",
        enforcement="l2",
        direction="rx",
        profile_id="ethernet_frame_including_fcs",
    )
    raw = _raw_field(resolved.subject_uid)
    result = resolve_constraints([resolved, raw], MtuContext(af=4, enforcement="l2", direction="tx"))
    assert len(result.constraints) == 1
    assert result.constraints[0].bound_kind == "unknown"
    assert "MTU_SEMANTICS_UNKNOWN" in result.gaps


def test_a_preserved_raw_field_stands_when_the_only_sibling_has_a_different_tag_depth():
    """The pre-pass that finds a "resolving" sibling applies the tag_depth filter of the grouped loop."""
    resolved = observation(
        1518,
        metric="l2_max_frame_bytes",
        bound_kind="ceiling",
        enforcement="l2",
        profile_id="ethernet_frame_including_fcs",
        tag_depth=0,
    )
    raw = _raw_field(resolved.subject_uid)
    context = MtuContext(af=4, enforcement="l2", direction="tx", tag_depth=1)
    result = resolve_constraints([resolved, raw], context)
    assert len(result.constraints) == 1
    assert result.constraints[0].bound_kind == "unknown"
    assert "MTU_SEMANTICS_UNKNOWN" in result.gaps


def test_a_preserved_raw_field_stands_when_the_only_sibling_has_a_different_traffic_class():
    resolved = observation(
        1518,
        metric="l2_max_frame_bytes",
        bound_kind="ceiling",
        enforcement="l2",
        profile_id="ethernet_frame_including_fcs",
        traffic_class="data",
    )
    raw = _raw_field(resolved.subject_uid)
    context = MtuContext(af=4, enforcement="l2", direction="tx", traffic_class="voice")
    result = resolve_constraints([resolved, raw], context)
    assert len(result.constraints) == 1
    assert result.constraints[0].bound_kind == "unknown"
    assert "MTU_SEMANTICS_UNKNOWN" in result.gaps


def test_a_preserved_raw_field_is_suppressed_when_the_sibling_matches_tag_depth_and_traffic_class():
    resolved = observation(
        1518,
        metric="l2_max_frame_bytes",
        bound_kind="ceiling",
        enforcement="l2",
        profile_id="ethernet_frame_including_fcs",
        tag_depth=0,
        traffic_class="voice",
    )
    raw = _raw_field(resolved.subject_uid)
    context = MtuContext(af=4, enforcement="l2", direction="tx", tag_depth=0, traffic_class="voice")
    result = resolve_constraints([resolved, raw], context)
    assert len(result.constraints) == 1
    assert result.constraints[0].value_bytes == 1514
    assert "MTU_SEMANTICS_UNKNOWN" not in result.gaps
