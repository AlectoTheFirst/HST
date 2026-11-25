"""Firewall policy installations checked against their evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from hst.analysis_model.evidence import (
    CaptureOutcome,
    EvidencePolicy,
    EvidenceWindow,
    GapCode,
    evaluate_evidence,
)
from hst.policy.ir import Constant, Predicate, Unknown


def _identity(value: str, field: str) -> None:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{field} must be a nonempty canonical string")


def _manifest(value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("manifest_digest must be a pinned lowercase SHA-256 digest")


@dataclass(frozen=True, slots=True)
class InstallationExpectation:
    firewall_instance_uid: str
    policy_uid: str
    configured_revision: str
    manifest_digest: str
    revision_scope: str
    context_uid: str

    def __post_init__(self) -> None:
        for field in (
            "firewall_instance_uid",
            "policy_uid",
            "configured_revision",
            "revision_scope",
            "context_uid",
        ):
            _identity(getattr(self, field), field)
        _manifest(self.manifest_digest)


@dataclass(frozen=True, slots=True)
class InstallationObservation:
    firewall_instance_uid: str
    policy_uid: str
    context_uid: str
    manifest_digest: str
    evidence: EvidenceWindow

    def __post_init__(self) -> None:
        for field in ("firewall_instance_uid", "policy_uid", "context_uid"):
            _identity(getattr(self, field), field)
        _manifest(self.manifest_digest)
        if not self.evidence.revision_required:
            raise ValueError("installation observation must require revision evidence")
        if not self.evidence.evidence_ids:
            raise ValueError("installation observation requires pinned producer evidence IDs")


def _unknown(code: str, expected: InstallationExpectation, evidence: tuple[str, ...] = ()) -> Unknown:
    return Unknown(code, expected.policy_uid, tuple(sorted(set(evidence))))


def installation_predicate(
    expected: InstallationExpectation,
    observations: tuple[InstallationObservation, ...],
    *,
    analysis_time: datetime,
    evidence_policy: EvidencePolicy,
) -> Predicate:
    candidates = tuple(
        observation
        for observation in observations
        if observation.firewall_instance_uid == expected.firewall_instance_uid
        and observation.policy_uid == expected.policy_uid
    )
    if not candidates:
        return _unknown("INSTALLATION_NOT_OBSERVED", expected)

    evidence_ids = tuple(uid for item in candidates for uid in item.evidence.evidence_ids)
    if any(item.evidence.subject != expected.policy_uid for item in candidates):
        return _unknown("INSTALLATION_SUBJECT_MISMATCH", expected, evidence_ids)
    if any(item.context_uid != expected.context_uid for item in candidates):
        return _unknown("INSTALLATION_CONTEXT_MISMATCH", expected, evidence_ids)
    if any(item.manifest_digest != expected.manifest_digest for item in candidates):
        return _unknown("INSTALLATION_MANIFEST_MISMATCH", expected, evidence_ids)
    if any(item.evidence.revision_scope != expected.revision_scope for item in candidates):
        return _unknown("INSTALLATION_AUTHORITY_MISMATCH", expected, evidence_ids)

    evaluation = evaluate_evidence(
        tuple(item.evidence for item in candidates), evidence_policy, analysis_time=analysis_time
    )
    if evaluation.gaps:
        gap = sorted(evaluation.gaps, key=lambda item: (item.code.value, item.subject))[0]
        return _unknown(gap.code.name, expected, evidence_ids)
    if any(item.evidence.outcome != CaptureOutcome.COMPLETE for item in candidates):
        return _unknown(GapCode.PARTIAL_EVIDENCE.name, expected, evidence_ids)
    if any(
        item.evidence.revision.configured_revision != expected.configured_revision
        or item.evidence.revision.installed_revision != expected.configured_revision
        for item in candidates
    ):
        return _unknown(GapCode.INSTALLED_REVISION_MISMATCH.name, expected, evidence_ids)
    return Constant(True)
