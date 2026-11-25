"""Batched reads of MTU evidence from a pinned snapshot, and policy resolution."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from typing import Any

from pydantic import Field, ValidationError

from .mtu import (
    MTU_CONTRACT_VERSION,
    MTU_NORMALIZATION_VERSION,
    MtuConstraint,
    MtuContext,
    MtuFinding,
    MtuGapCode,
    MtuModel,
    MtuObservation,
    MtuPolicyApplication,
    MtuResolution,
)
from .mtu_profiles import PROFILE_IDS, PROFILE_VERSION, observation_from_raw

MTU_QUERY = """
UNWIND $subject_uids AS subject_uid
MATCH (s:Obj {uid: subject_uid, collection_ts: $snap})
WHERE NOT s:Retired AND s._retired_at IS NULL
OPTIONAL MATCH (s)-[r:HAS_MTU]->(o:MtuObservation {collection_ts: $snap})
WHERE r.collection_ts = $snap AND r._retired_at IS NULL
  AND NOT o:Retired AND o._retired_at IS NULL AND o.subject_uid = s.uid
RETURN s.uid AS subject_uid, s.mtu AS legacy_mtu,
       o.uid AS observation_uid, properties(o) AS observation
ORDER BY subject_uid, observation_uid
LIMIT $row_limit
"""


class MtuEvidenceSet(MtuModel):
    snapshot_key: int | None = None
    by_subject: dict[str, list[MtuObservation]] = Field(default_factory=dict)
    gaps: list[MtuGapCode] = Field(default_factory=list)
    unresolved_subjects: list[str] = Field(default_factory=list)
    carried_observation_uids: list[str] = Field(default_factory=list)
    # The loader metadata of each observation, by observation uid.
    provenance: dict[str, dict[str, Any]] = Field(default_factory=dict)
    truncated: bool = False
    query_count: int = 0


def read_mtu(
    session: Any,
    subject_uids: Iterable[str],
    *,
    batch_size: int = 256,
    max_subjects: int = 4096,
    max_observations: int = 16384,
) -> MtuEvidenceSet:
    """Read the MTU observations of the supplied subjects only.

    A caller reuses the returned set within one request. An unpinned session issues no query.
    """
    if not 1 <= batch_size <= 4096 or max_subjects < 1 or max_observations < 1:
        raise ValueError("MTU read budgets must be positive; batch size must be <=4096")
    subjects: set[str] = set()
    overflow = False
    for subject in subject_uids:
        subjects.add(subject)
        if len(subjects) > max_subjects:
            overflow = True
            break
    ordered = sorted(subjects)[:max_subjects]
    result = MtuEvidenceSet(by_subject={s: [] for s in ordered}, truncated=overflow)
    cts = getattr(session, "cts", None)
    if type(cts) is not int:
        result.gaps = ["MTU_SNAPSHOT_UNPINNED"]
        result.unresolved_subjects = ordered
        return result
    result.snapshot_key = cts
    import hst.path as path

    seen: set[str] = set()
    observed_count = 0
    for start in range(0, len(ordered), batch_size):
        chunk = ordered[start : start + batch_size]
        remaining = max_observations - observed_count
        if remaining <= 0:
            result.truncated = True
            break
        rows = path._read(session, MTU_QUERY, subject_uids=chunk, row_limit=remaining + 1)
        result.query_count += 1
        if len(rows) > remaining:
            result.truncated = True
            rows = rows[:remaining]
        for row in rows:
            subject = row.get("subject_uid")
            if subject not in chunk:
                continue
            props = row.get("observation")
            if props:
                if (
                    props.get("collection_ts") != cts
                    or props.get("_retired_at") is not None
                    or props.get("subject_uid") != subject
                ):
                    continue
                obs_uid = row.get("observation_uid")
                try:
                    obs = MtuObservation.model_validate(
                        {k: v for k, v in props.items() if k in MtuObservation.model_fields}
                    )
                except (ValidationError, ValueError):
                    result.gaps.append("MTU_SEMANTICS_UNKNOWN")
                    continue
                if obs.uid != obs_uid:
                    result.gaps.append("MTU_SOURCE_CONFLICT")
                    continue
                if obs.uid in seen:
                    continue
                seen.add(obs.uid)
                result.by_subject[subject].append(obs)
                observed_count += 1
                result.provenance[obs.uid] = {
                    k: props[k]
                    for k in ("collection_ts", "collected_at", "carried", "_run_id", "_sources")
                    if k in props
                }
                if props.get("carried"):
                    result.carried_observation_uids.append(obs.uid)
            elif row.get("legacy_mtu") is not None:
                # The `legacy_mtu` scalar becomes an observation with the profile `unknown`.
                obs = observation_from_raw(
                    subject_uid=subject,
                    source="legacy",
                    source_target=subject,
                    source_field="mtu",
                    raw_value=row["legacy_mtu"],
                    assertion_kind="configured",
                    enforcement="unknown",
                )
                if obs.uid not in seen:
                    seen.add(obs.uid)
                    result.by_subject[subject].append(obs)
                    observed_count += 1
        if result.truncated and len(rows) >= remaining:
            break
    result.unresolved_subjects = [s for s in ordered if not result.by_subject[s]]
    if result.unresolved_subjects:
        result.gaps.append("MTU_NOT_CAPTURED")
    if result.truncated:
        result.gaps.append("MTU_PATH_COVERAGE_INCOMPLETE")
    result.gaps = sorted(set(result.gaps))
    return result


def _constraint(observations: Sequence[MtuObservation], subject: str, slot: str) -> MtuConstraint:
    first = observations[0]
    values = {o.normalized_value for o in observations}
    conflict = len(values) > 1
    ambiguous = any(o.direction == "unknown" for o in observations)
    gaps = {g for o in observations for g in o.gaps}
    if ambiguous:
        gaps.add("MTU_SEMANTICS_UNKNOWN")
    if conflict:
        gaps.add("MTU_SOURCE_CONFLICT")
    return MtuConstraint(
        subject_uid=subject,
        enforcement_key=slot,
        enforcement=first.enforcement,
        metric=first.metric,
        direction=first.direction,
        af=first.af,
        bound_kind=first.bound_kind,
        value_bytes=None if conflict or ambiguous else first.normalized_value,
        traffic_class=first.traffic_class,
        tag_depth=first.tag_depth,
        tag_accounting=first.tag_accounting,
        tag_allowance_bytes=first.tag_allowance_bytes,
        evidence_uids=sorted({u for o in observations for u in [o.uid, *o.dependency_uids]}),
        evidence_quality=sorted(
            {o.assertion_kind for o in observations}
            | {
                "inherited"
                for o in observations
                if o.subject_uid != subject or o.resolution_state == "inherited"
            }
        ),
        inherited_from=sorted(
            {o.subject_uid for o in observations if o.subject_uid != subject}
            | {o.policy_ref for o in observations if o.resolution_state == "inherited" and o.policy_ref}
        ),
        gaps=sorted(gaps),
    )


def resolve_constraints(
    observations: Sequence[MtuObservation],
    context: MtuContext,
    *,
    applications: Sequence[MtuPolicyApplication] = (),
) -> MtuResolution:
    """Resolve the observations to constraints. Enforcement slots and assertion
    kinds resolve separately.

    An application assigns a policy observation to a subject and a slot. The
    largest precedence wins within that slot and assertion kind. A policy scope
    observation without an application stays unresolved
    (`MTU_POLICY_UNRESOLVED`).
    """
    result = MtuResolution(observations=sorted(observations, key=lambda o: o.uid))
    apps: dict[str, list[MtuPolicyApplication]] = defaultdict(list)
    for app in applications:
        if app.profile_id == "unknown":
            result.gaps.append("MTU_POLICY_UNRESOLVED")
            continue
        apps[app.observation_uid].append(app)
    # A preserved raw field (mtu_import.py `preserve_raw_mtu_fields`) is skipped for a subject that
    # has another observation resolving for this context.
    resolving_subjects: set[str] = set()
    for obs in result.observations:
        if obs.metric == "unknown" or obs.bound_kind == "unknown":
            continue
        if (
            obs.contract_version != MTU_CONTRACT_VERSION
            or obs.normalization_version != MTU_NORMALIZATION_VERSION
            or obs.profile_version != PROFILE_VERSION
            or obs.profile_id not in PROFILE_IDS
        ):
            continue
        # These filters match the tag_depth and traffic_class filters of the grouped loop below.
        if obs.tag_depth is not None and context.tag_depth is not None and obs.tag_depth != context.tag_depth:
            continue
        if obs.af is not None and obs.af != context.af:
            continue
        if obs.direction not in {context.direction, "both", "unknown"}:
            continue
        if context.enforcement != "unknown" and obs.enforcement not in {context.enforcement, "unknown"}:
            continue
        if obs.traffic_class is not None and context.traffic_class not in {None, obs.traffic_class}:
            continue
        resolving_subjects.add(obs.subject_uid)
    grouped: dict[tuple[Any, ...], list[tuple[int, MtuObservation]]] = defaultdict(list)
    for obs in result.observations:
        if (
            obs.contract_version != MTU_CONTRACT_VERSION
            or obs.normalization_version != MTU_NORMALIZATION_VERSION
            or obs.profile_version != PROFILE_VERSION
            or obs.profile_id not in PROFILE_IDS
        ):
            result.gaps.append("MTU_SEMANTICS_UNKNOWN")
            continue
        # The constraint keeps a stated tag depth. A known context depth that
        # differs excludes the observation.
        if obs.tag_depth is not None and context.tag_depth is not None and obs.tag_depth != context.tag_depth:
            result.gaps.append("MTU_SEMANTICS_UNKNOWN")
            continue
        if obs.af is not None and obs.af != context.af:
            continue
        if obs.direction not in {context.direction, "both", "unknown"}:
            continue
        if context.enforcement != "unknown" and obs.enforcement not in {context.enforcement, "unknown"}:
            continue
        if (obs.metric == "unknown" or obs.bound_kind == "unknown") and obs.subject_uid in resolving_subjects:
            continue
        if obs.traffic_class is not None and context.traffic_class not in {None, obs.traffic_class}:
            continue
        if obs.traffic_class is not None and context.traffic_class is None:
            result.gaps.append("MTU_CLASS_UNKNOWN")
        if obs.direction == "unknown":
            result.gaps.append("MTU_SEMANTICS_UNKNOWN")
        if obs.scope != "interface" and obs.uid not in apps and obs.enforcement != "path":
            result.gaps.append("MTU_POLICY_UNRESOLVED")
            continue
        targets = [(a.subject_uid, a.enforcement_key, a.precedence) for a in apps.get(obs.uid, [])]
        if not targets:
            targets = [(obs.subject_uid, obs.enforcement_key, 0)]
        for subject, slot, precedence in targets:
            key = (
                subject,
                slot,
                obs.metric,
                context.direction,
                obs.af,
                obs.bound_kind,
                obs.traffic_class,
                obs.enforcement,
                obs.tag_depth,
                obs.assertion_kind,
            )
            grouped[key].append((precedence, obs))
    resolved: dict[tuple[Any, ...], dict[str, MtuConstraint]] = defaultdict(dict)
    # An intent constraint whose observations all have a `source` of
    # `"intent:<kind>"` is a change-simulation restatement
    # (`hst.simul.fw_overlay._restate_mtu_row`). It is the constraint of the key
    # when the key has no operational and no configured constraint.
    simulated: dict[tuple[Any, ...], MtuConstraint] = {}
    for key, rows in sorted(grouped.items(), key=lambda item: repr(item[0])):
        highest = max(precedence for precedence, _ in rows)
        chosen = {o.uid: o for precedence, o in rows if precedence == highest}
        observations = list(chosen.values())
        constraint = _constraint(observations, key[0], key[1])
        result.gaps.extend(constraint.gaps)
        resolved[key[:-1]][key[-1]] = constraint
        if key[-1] == "intent" and all(o.source.startswith("intent:") for o in observations):
            simulated[key[:-1]] = constraint
    for key, categories in resolved.items():
        for kind, field in (
            ("configured", result.configured),
            ("intent", result.intent),
            ("hardware_max", result.hardware),
            ("measurement", result.measurements),
        ):
            if kind in categories:
                field.append(categories[kind])
        actual = categories.get("operational") or categories.get("configured") or simulated.get(key)
        if actual is not None:
            result.constraints.append(actual)
        cfg, oper = categories.get("configured"), categories.get("operational")
        if cfg is not None and oper is not None and cfg.value_bytes != oper.value_bytes:
            result.findings.append(
                MtuFinding(
                    code="MTU_POLICY_DRIFT",
                    severity="risk",
                    detail="Configured and operational MTU differ",
                    subject_uids=[key[0]],
                    evidence_uids=sorted(set(cfg.evidence_uids + oper.evidence_uids)),
                    observed_bytes=oper.value_bytes,
                    required_bytes=cfg.value_bytes,
                    af=context.af,
                )
            )
    if not result.constraints:
        result.gaps.append("MTU_NOT_CAPTURED")
    result.gaps = sorted(set(result.gaps))
    return result
