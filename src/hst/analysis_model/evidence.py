"""Immutable temporal evidence policy for compiled analysis inputs."""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType

from hst.symbolic import PacketSet


class ConsistencyMode(StrEnum):
    BOUNDED_WINDOW = "bounded-window"
    STABLE_WINDOW_ASSUMPTION = "stable-window-assumption"


class CaptureOutcome(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    MISSING = "missing"
    FAILED = "failed"
    LEGACY = "legacy"


class ClockQuality(StrEnum):
    TRUSTED = "trusted"
    UNCERTAIN = "uncertain"
    UNKNOWN = "unknown"


class GapCode(StrEnum):
    UNSUPPORTED_SEMANTICS = "unsupported-semantics"
    NOT_COLLECTED = "not-collected"
    PARTIAL_EVIDENCE = "partial-evidence"
    STALE_EVIDENCE = "stale-evidence"
    FUTURE_OBSERVATION = "future-observation"
    CLOCK_QUALITY_UNCERTAIN = "clock-quality-uncertain"
    EXCESSIVE_SKEW = "excessive-skew"
    SKEW_POSSIBLE = "skew-possible"
    INSTALLED_REVISION_MISSING = "installed-revision-missing"
    INSTALLED_REVISION_MISMATCH = "installed-revision-mismatch"
    CONTRADICTORY_INSTALLED_REVISION = "contradictory-installed-revision"
    LEGACY_METADATA_MISSING = "legacy-metadata-missing"
    EXECUTION_LIMIT = "execution-limit"


class ScopeKind(StrEnum):
    EXACT = "exact"
    CONSERVATIVE = "conservative"


def _utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value.astimezone(UTC)


def _identity(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{field_name} must be a nonempty canonical string")


@dataclass(frozen=True, slots=True)
class EvidencePolicy:
    max_age_s: int = 3_600
    max_skew_s: int = 300
    consistency_mode: ConsistencyMode = ConsistencyMode.BOUNDED_WINDOW
    stable_window_assumption: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "consistency_mode", ConsistencyMode(self.consistency_mode))
        for name in ("max_age_s", "max_skew_s"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        if self.consistency_mode == ConsistencyMode.STABLE_WINDOW_ASSUMPTION:
            _identity(self.stable_window_assumption, "stable_window_assumption")
        elif self.stable_window_assumption:
            raise ValueError("stable_window_assumption requires stable-window-assumption mode")


@dataclass(frozen=True, slots=True)
class RevisionEvidence:
    configured_revision: str = ""
    installed_revision: str = ""
    producer_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("configured_revision", "installed_revision"):
            value = getattr(self, name)
            if value:
                _identity(value, name)
        object.__setattr__(self, "producer_ids", tuple(self.producer_ids))
        for producer_id in self.producer_ids:
            _identity(producer_id, "producer_id")


@dataclass(frozen=True, slots=True)
class EvidenceWindow:
    subject: str
    source: str
    section: str
    capture_start: datetime | None
    capture_end: datetime | None
    observation_time: datetime | None
    outcome: CaptureOutcome
    clock_quality: ClockQuality = ClockQuality.UNKNOWN
    address_family: int | None = None
    vrf: str = ""
    revision: RevisionEvidence = field(default_factory=RevisionEvidence)
    revision_required: bool = False
    revision_scope: str = ""
    producer_ids: tuple[str, ...] = ()
    clock_source: str = ""
    clock_assumption: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "outcome", CaptureOutcome(self.outcome))
        object.__setattr__(self, "clock_quality", ClockQuality(self.clock_quality))
        for name in ("subject", "source", "section"):
            _identity(getattr(self, name), name)
        if self.vrf:
            _identity(self.vrf, "vrf")
        if type(self.revision_required) is not bool:
            raise TypeError("revision_required must be an explicit boolean")
        if self.revision_required or self.revision_scope:
            _identity(self.revision_scope, "revision_scope")
        if self.address_family not in (None, 4, 6):
            raise ValueError("address_family must be 4, 6, or None")
        for name in ("capture_start", "capture_end", "observation_time"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _utc(value, name))
        if (
            self.capture_start is not None
            and self.capture_end is not None
            and self.capture_end < self.capture_start
        ):
            raise ValueError("capture_end precedes capture_start")
        if self.outcome == CaptureOutcome.COMPLETE and self.observation_time is None:
            raise ValueError("complete evidence requires its original observation_time")
        object.__setattr__(self, "producer_ids", tuple(self.producer_ids))
        for producer_id in self.producer_ids:
            _identity(producer_id, "producer_id")
        if self.clock_source:
            _identity(self.clock_source, "clock_source")
        if self.clock_assumption and not self.clock_assumption.strip():
            raise ValueError("clock_assumption must be empty or nonblank")

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        return self.producer_ids + self.revision.producer_ids

    @property
    def interval(self) -> tuple[datetime, datetime] | None:
        values = tuple(
            value
            for value in (self.capture_start, self.capture_end, self.observation_time)
            if value is not None
        )
        return (min(values), max(values)) if values else None


@dataclass(frozen=True, slots=True)
class CollectionRecipe:
    """A recipe already resolved from registered read operations by the caller."""

    id: str
    source: str
    subject: str
    section: str
    operations: tuple[str, ...]
    permission: str

    def __post_init__(self) -> None:
        for name in ("id", "source", "subject", "section", "permission"):
            _identity(getattr(self, name), name)
        object.__setattr__(self, "operations", tuple(self.operations))
        if not self.operations:
            raise ValueError("a collection recipe needs an actual read operation")


@dataclass(frozen=True, slots=True)
class EvidenceGap:
    code: GapCode
    subject: str
    source: str
    section: str
    address_family: int | None = None
    vrf: str = ""
    observed_interval: tuple[datetime, datetime] | None = None
    outcome: CaptureOutcome | None = None
    evidence_ids: tuple[str, ...] = ()
    detail: str = ""
    related_codes: tuple[GapCode, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", GapCode(self.code))
        if self.outcome is not None:
            object.__setattr__(self, "outcome", CaptureOutcome(self.outcome))
        for name in ("subject", "source", "section"):
            _identity(getattr(self, name), name)
        if self.vrf:
            _identity(self.vrf, "vrf")
        if self.address_family not in (None, 4, 6):
            raise ValueError("address_family must be 4, 6, or None")
        if self.observed_interval is not None:
            start, end = (_utc(value, "observed_interval") for value in self.observed_interval)
            if end < start:
                raise ValueError("observed_interval ends before it starts")
            object.__setattr__(self, "observed_interval", (start, end))
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))
        object.__setattr__(self, "related_codes", tuple(GapCode(code) for code in self.related_codes))


@dataclass(frozen=True, slots=True)
class ScopedEvidenceGap:
    gap: EvidenceGap
    packets: PacketSet
    scope_kind: ScopeKind
    recipe: CollectionRecipe | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope_kind", ScopeKind(self.scope_kind))


@dataclass(frozen=True, slots=True)
class EvidenceEvaluation:
    analysis_time: datetime
    policy: EvidencePolicy
    windows: tuple[EvidenceWindow, ...]
    gaps: tuple[EvidenceGap, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "analysis_time", _utc(self.analysis_time, "analysis_time"))
        object.__setattr__(self, "windows", tuple(self.windows))
        object.__setattr__(self, "gaps", tuple(self.gaps))


def _gap(
    window: EvidenceWindow, code: GapCode, detail: str = "", *, related: Sequence[GapCode] = ()
) -> EvidenceGap:
    return EvidenceGap(
        code=code,
        subject=window.subject,
        source=window.source,
        section=window.section,
        address_family=window.address_family,
        vrf=window.vrf,
        observed_interval=window.interval,
        outcome=window.outcome,
        evidence_ids=window.evidence_ids,
        detail=detail,
        related_codes=tuple(related),
    )


def evaluate_evidence(
    windows: Sequence[EvidenceWindow], policy: EvidencePolicy, *, analysis_time: datetime
) -> EvidenceEvaluation:
    """Assess pinned observations by their original observation times."""

    saved_time = _utc(analysis_time, "analysis_time")
    frozen_windows = tuple(windows)
    gaps: list[EvidenceGap] = []
    installed_by_scope: dict[str, set[str]] = {}
    interval_values: list[datetime] = []
    for window in frozen_windows:
        if window.outcome in {CaptureOutcome.MISSING, CaptureOutcome.FAILED}:
            gaps.append(_gap(window, GapCode.NOT_COLLECTED))
        elif window.outcome == CaptureOutcome.PARTIAL:
            gaps.append(_gap(window, GapCode.PARTIAL_EVIDENCE))
        elif window.outcome == CaptureOutcome.LEGACY:
            gaps.append(_gap(window, GapCode.LEGACY_METADATA_MISSING))
        if window.capture_start is None or window.capture_end is None:
            gaps.append(_gap(window, GapCode.LEGACY_METADATA_MISSING, "capture window is absent"))
        if window.clock_quality != ClockQuality.TRUSTED:
            gaps.append(_gap(window, GapCode.CLOCK_QUALITY_UNCERTAIN))
        if window.observation_time is None:
            gaps.append(_gap(window, GapCode.LEGACY_METADATA_MISSING, "original observation time is absent"))
        else:
            age = saved_time - window.observation_time
            if age < timedelta(0):
                gaps.append(_gap(window, GapCode.FUTURE_OBSERVATION))
            elif age > timedelta(seconds=policy.max_age_s):
                gaps.append(_gap(window, GapCode.STALE_EVIDENCE))
        if window.revision_required:
            if not window.revision.configured_revision or not window.revision.installed_revision:
                gaps.append(_gap(window, GapCode.INSTALLED_REVISION_MISSING))
            elif window.revision.configured_revision != window.revision.installed_revision:
                gaps.append(_gap(window, GapCode.INSTALLED_REVISION_MISMATCH))
            if window.revision.installed_revision:
                installed_by_scope.setdefault(window.revision_scope, set()).add(
                    window.revision.installed_revision
                )
        if window.interval is not None:
            interval_values.extend(window.interval)
    if interval_values and max(interval_values) - min(interval_values) > timedelta(seconds=policy.max_skew_s):
        for window in frozen_windows:
            has_mismatch = (
                window.revision_required
                and window.revision.configured_revision
                and window.revision.installed_revision
                and window.revision.configured_revision != window.revision.installed_revision
            )
            related = (GapCode.SKEW_POSSIBLE,) if has_mismatch else ()
            if policy.consistency_mode == ConsistencyMode.BOUNDED_WINDOW:
                gaps.append(_gap(window, GapCode.EXCESSIVE_SKEW, related=related))
            elif related:
                gaps.append(_gap(window, GapCode.SKEW_POSSIBLE))
    for scope, revisions in installed_by_scope.items():
        if len(revisions) > 1:
            for window in frozen_windows:
                if window.revision_required and window.revision_scope == scope:
                    gaps.append(_gap(window, GapCode.CONTRADICTORY_INSTALLED_REVISION))
    return EvidenceEvaluation(saved_time, policy, frozen_windows, tuple(gaps))


def scope_evidence(
    evaluation: EvidenceEvaluation, refs: Collection[tuple[str, str, str, int | None, str]]
) -> EvidenceEvaluation:
    """The evaluation of only the windows that `refs` lists, each as (source,
    subject, section, address family, vrf).

    A model is judged on the windows its own nodes depend on."""
    kept = tuple(
        window
        for window in evaluation.windows
        if (window.source, window.subject, window.section, window.address_family, window.vrf) in refs
    )
    return evaluate_evidence(kept, evaluation.policy, analysis_time=evaluation.analysis_time)


def project_gaps(
    gaps: Sequence[EvidenceGap],
    request_universe: PacketSet,
    *,
    exact_scopes: Mapping[EvidenceGap, PacketSet] | None = None,
    conservative_scopes: Mapping[EvidenceGap, PacketSet] | None = None,
    recipes: Sequence[CollectionRecipe] = (),
    permissions: frozenset[str] = frozenset(),
) -> tuple[ScopedEvidenceGap, ...]:
    """Attach exact or explicit conservative packet scopes and authorized recipes.

    `project_gaps` looks up no permissions or recipes.  The integration boundary must
    pass both from its pinned authorization and registered collector capability.
    """

    exact = MappingProxyType(dict(exact_scopes or {}))
    conservative = MappingProxyType(dict(conservative_scopes or {}))
    result: list[ScopedEvidenceGap] = []
    for gap in gaps:
        if gap in exact:
            packets, kind = exact[gap], ScopeKind.EXACT
        elif gap in conservative:
            packets, kind = conservative[gap], ScopeKind.CONSERVATIVE
        else:
            packets, kind = request_universe, ScopeKind.CONSERVATIVE
        request_universe.manager._assert_sets(packets)
        if not packets.subtract(request_universe).is_empty():
            raise ValueError("gap scope must be within request_universe")
        recipe = next(
            (
                candidate
                for candidate in recipes
                if candidate.source == gap.source
                and candidate.subject == gap.subject
                and candidate.section == gap.section
                and candidate.permission in permissions
            ),
            None,
        )
        result.append(ScopedEvidenceGap(gap, packets, kind, recipe))
    return tuple(result)
