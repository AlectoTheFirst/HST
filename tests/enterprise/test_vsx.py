from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from hst.analysis_model.evidence import (
    CaptureOutcome,
    ClockQuality,
    EvidencePolicy,
    EvidenceWindow,
    RevisionEvidence,
)
from hst.core.firewall_context import (
    FailureScope,
    FirewallAuthority,
    FirewallInstance,
    FirewallPlacement,
    GatewayCaptureEnvelope,
    GatewayCaptureSection,
    InterfaceContext,
    PhysicalAppliance,
    QualifiedVsid,
    StateSyncObservation,
    VrfContext,
)
from hst.core.firewall_read import (
    InstallationExpectation,
    InstallationObservation,
    installation_predicate,
)
from hst.policy.ir import Constant, Unknown

NOW = datetime(2026, 9, 12, 10, tzinfo=UTC)
MANIFEST = "a" * 64


def _instance(*, estate: str = "estate-a", domain: str = "domain-a") -> FirewallInstance:
    return FirewallInstance.authoritative(FirewallAuthority(estate, "mgmt-uid", domain), "vs-object-7")


def _window(
    *,
    installed: str = "rev-4",
    outcome: CaptureOutcome = CaptureOutcome.COMPLETE,
    observed: datetime = NOW,
    producer: str = "capture-1",
) -> EvidenceWindow:
    return EvidenceWindow(
        subject="policy-uid",
        source="gateway-source",
        section="policy-installation",
        capture_start=observed - timedelta(seconds=2),
        capture_end=observed,
        observation_time=observed,
        outcome=outcome,
        clock_quality=ClockQuality.TRUSTED,
        revision=RevisionEvidence("rev-4", installed, (producer,)),
        revision_required=True,
        revision_scope="authority/domain/instance/context",
    )


def _expectation(instance: FirewallInstance) -> InstallationExpectation:
    return InstallationExpectation(
        instance.uid,
        "policy-uid",
        "rev-4",
        MANIFEST,
        "authority/domain/instance/context",
        "context-uid",
    )


def _observation(instance: FirewallInstance, window: EvidenceWindow) -> InstallationObservation:
    return InstallationObservation(instance.uid, "policy-uid", "context-uid", MANIFEST, window)


def test_authoritative_namespace_and_local_names_never_collide() -> None:
    first = _instance()
    assert first.uid != _instance(estate="estate-b").uid
    assert first.uid != _instance(domain="domain-b").uid

    appliance_a = PhysicalAppliance("estate-a", "gateway-authority", "member-a")
    appliance_b = PhysicalAppliance("estate-a", "gateway-authority", "member-b")
    vsid_a = QualifiedVsid(appliance_a, "observation-1", 7)
    vsid_b = QualifiedVsid(appliance_b, "observation-1", 7)
    assert vsid_a != vsid_b
    assert (
        InterfaceContext(first.uid, "interface-object-uid").uid
        != InterfaceContext(_instance(domain="domain-b").uid, "interface-object-uid").uid
    )
    assert (
        VrfContext(first.uid, "vrf-object-uid").uid
        != VrfContext(_instance(domain="domain-b").uid, "vrf-object-uid").uid
    )


def test_cluster_placement_changes_retain_logical_identity_and_failure_scope() -> None:
    instance = _instance()
    appliance_a = PhysicalAppliance("estate-a", "gateway-authority", "member-a")
    appliance_b = PhysicalAppliance("estate-a", "gateway-authority", "member-b")
    before = FirewallPlacement(instance.uid, appliance_a, "snapshot-a")
    after = FirewallPlacement(instance.uid, appliance_b, "snapshot-b")
    assert before.instance_uid == after.instance_uid == instance.uid
    assert FailureScope("physical-appliance", appliance_a.appliance_uid) != FailureScope(
        "logical-firewall", instance.uid
    )
    with pytest.raises(ValueError, match="distinct execution locations"):
        StateSyncObservation(
            instance.uid,
            instance.uid,
            "member-a",
            "member-a",
            "binding-1",
            "connection",
            "bidirectional",
            "synchronized",
            "snapshot-a",
            "sync-capture-1",
        )


def test_capture_envelope_rejects_cross_vs_sections() -> None:
    instance = _instance()
    appliance = PhysicalAppliance("estate-a", "gateway-authority", "member-a")
    selected = QualifiedVsid(appliance, "observation-1", 7)
    other = QualifiedVsid(appliance, "observation-1", 8)
    with pytest.raises(ValueError, match="mixed selected shell VS contexts"):
        GatewayCaptureEnvelope(
            appliance,
            "observation-1",
            instance.uid,
            selected,
            (GatewayCaptureSection("interfaces", instance.uid, other, "capture-1"),),
        )


@pytest.mark.parametrize(
    ("observations", "code"),
    [
        ((), "INSTALLATION_NOT_OBSERVED"),
        ((_window(outcome=CaptureOutcome.PARTIAL),), "PARTIAL_EVIDENCE"),
        ((_window(observed=NOW - timedelta(hours=2)),), "STALE_EVIDENCE"),
        ((_window(installed="rev-3"),), "INSTALLED_REVISION_MISMATCH"),
        (
            (_window(producer="capture-1"), _window(installed="rev-5", producer="capture-2")),
            "CONTRADICTORY_INSTALLED_REVISION",
        ),
    ],
)
def test_missing_stale_partial_and_conflicting_installations_are_unknown(
    observations: tuple[EvidenceWindow, ...], code: str
) -> None:
    instance = _instance()
    predicate = installation_predicate(
        _expectation(instance),
        tuple(_observation(instance, window) for window in observations),
        analysis_time=NOW,
        evidence_policy=EvidencePolicy(max_age_s=3600),
    )
    assert isinstance(predicate, Unknown)
    assert predicate.code == code


def test_only_complete_matching_authoritative_installation_is_true() -> None:
    instance = _instance()
    observation = _observation(instance, _window())
    assert installation_predicate(
        _expectation(instance),
        (observation,),
        analysis_time=NOW,
        evidence_policy=EvidencePolicy(),
    ) == Constant(True)
    mismatched = replace(observation, context_uid="another-context")
    predicate = installation_predicate(
        _expectation(instance),
        (mismatched,),
        analysis_time=NOW,
        evidence_policy=EvidencePolicy(),
    )
    assert isinstance(predicate, Unknown)
    assert predicate.code == "INSTALLATION_CONTEXT_MISMATCH"
