from datetime import UTC, datetime, timedelta

from hst.analysis_model.evidence import (
    CaptureOutcome,
    ClockQuality,
    ConsistencyMode,
    EvidencePolicy,
    EvidenceWindow,
    GapCode,
    RevisionEvidence,
    evaluate_evidence,
)

NOW = datetime(2026, 9, 12, 10, tzinfo=UTC)


def window(**changes):
    values = {
        "subject": "vsx-a",
        "source": "checkpoint-a",
        "section": "access",
        "capture_start": NOW - timedelta(seconds=20),
        "capture_end": NOW - timedelta(seconds=10),
        "observation_time": NOW - timedelta(seconds=10),
        "outcome": CaptureOutcome.COMPLETE,
        "clock_quality": ClockQuality.TRUSTED,
        "revision": RevisionEvidence("r1", "r1", ("raw:1",)),
        "revision_required": True,
        "revision_scope": "estate-a/domain-a/vsx-a/package-a",
        "producer_ids": ("table:1",),
    }
    return EvidenceWindow(**(values | changes))


def codes(result):
    return [gap.code for gap in result.gaps]


def test_age_uses_saved_analysis_time_and_original_observation_not_manifest_time():
    old = window(observation_time=NOW - timedelta(seconds=3_601))
    result = evaluate_evidence((old,), EvidencePolicy(), analysis_time=NOW)
    assert GapCode.STALE_EVIDENCE in codes(result)
    replay = evaluate_evidence((old,), EvidencePolicy(), analysis_time=NOW - timedelta(seconds=2))
    assert GapCode.STALE_EVIDENCE not in codes(replay)


def test_partial_legacy_future_and_clock_quality_are_typed_gaps():
    result = evaluate_evidence(
        (
            window(outcome=CaptureOutcome.PARTIAL, clock_quality=ClockQuality.UNCERTAIN),
            window(section="nat", outcome=CaptureOutcome.LEGACY, observation_time=None),
            window(section="objects", observation_time=NOW + timedelta(seconds=1)),
        ),
        EvidencePolicy(),
        analysis_time=NOW,
    )
    assert {
        GapCode.PARTIAL_EVIDENCE,
        GapCode.LEGACY_METADATA_MISSING,
        GapCode.FUTURE_OBSERVATION,
    } <= set(codes(result))
    assert GapCode.CLOCK_QUALITY_UNCERTAIN in codes(result)


def test_missing_and_contradictory_installed_revisions_remain_typed_gaps():
    result = evaluate_evidence(
        (
            window(outcome=CaptureOutcome.MISSING, observation_time=None, revision=RevisionEvidence()),
            window(revision=RevisionEvidence("r1", "installed-a")),
            window(source="checkpoint-b", revision=RevisionEvidence("r1", "installed-b")),
        ),
        EvidencePolicy(),
        analysis_time=NOW,
    )
    assert GapCode.NOT_COLLECTED in codes(result)
    assert GapCode.INSTALLED_REVISION_MISSING in codes(result)
    assert GapCode.CONTRADICTORY_INSTALLED_REVISION in codes(result)


def test_missing_capture_window_is_unknown_even_when_observation_is_complete_and_trusted():
    result = evaluate_evidence(
        (window(capture_start=None, capture_end=None),), EvidencePolicy(), analysis_time=NOW
    )
    assert GapCode.LEGACY_METADATA_MISSING in codes(result)


def test_ordinary_rib_observation_does_not_require_policy_installation_revision():
    result = evaluate_evidence(
        (
            window(
                section="rib",
                revision=RevisionEvidence(),
                revision_required=False,
                revision_scope="",
            ),
        ),
        EvidencePolicy(),
        analysis_time=NOW,
    )
    assert GapCode.INSTALLED_REVISION_MISSING not in codes(result)


def test_contradictions_use_explicit_qualified_scope_without_cross_context_collision():
    other_context = window(
        subject="vsx-b",
        source="checkpoint-b",
        revision=RevisionEvidence("r1", "installed-b"),
        revision_scope="estate-a/domain-a/vsx-b/package-a",
    )
    result = evaluate_evidence((window(), other_context), EvidencePolicy(), analysis_time=NOW)
    assert GapCode.CONTRADICTORY_INSTALLED_REVISION not in codes(result)


def test_invalid_mode_and_window_enums_are_rejected_without_silencing_skew():
    import pytest

    with pytest.raises(ValueError):
        EvidencePolicy(consistency_mode="not-a-mode")
    with pytest.raises(ValueError):
        window(outcome="not-an-outcome")
    with pytest.raises(ValueError):
        window(clock_quality="not-a-clock")
    with pytest.raises(ValueError):
        from hst.analysis_model.evidence import EvidenceGap

        EvidenceGap("not-a-gap", "vsx-a", "checkpoint-a", "access")


def test_bounded_window_reports_skew_and_mismatch_survives_with_skew_possible():
    mismatch = window(revision=RevisionEvidence("configured", "installed"))
    late = window(
        section="nat",
        capture_start=NOW + timedelta(seconds=601),
        capture_end=NOW + timedelta(seconds=602),
        observation_time=NOW + timedelta(seconds=602),
    )
    result = evaluate_evidence((mismatch, late), EvidencePolicy(max_skew_s=300), analysis_time=NOW)
    mismatch_codes = {gap.code for gap in result.gaps if gap.section == "access"}
    assert GapCode.INSTALLED_REVISION_MISMATCH in mismatch_codes
    assert GapCode.EXCESSIVE_SKEW in mismatch_codes
    skew = next(gap for gap in result.gaps if gap.section == "access" and gap.code == GapCode.EXCESSIVE_SKEW)
    assert GapCode.SKEW_POSSIBLE in skew.related_codes


def test_stable_window_assumption_must_be_declared_and_does_not_erase_mismatch():
    mismatch = window(revision=RevisionEvidence("configured", "installed"))
    later = window(section="nat", observation_time=NOW + timedelta(seconds=601))
    policy = EvidencePolicy(
        consistency_mode=ConsistencyMode.STABLE_WINDOW_ASSUMPTION,
        stable_window_assumption="policy state stable during collection",
    )
    result = evaluate_evidence((mismatch, later), policy, analysis_time=NOW)
    assert GapCode.INSTALLED_REVISION_MISMATCH in codes(result)
    assert GapCode.EXCESSIVE_SKEW not in codes(result)
