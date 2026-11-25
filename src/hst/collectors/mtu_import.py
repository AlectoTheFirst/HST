"""Bounded explicit MTU imports and raw-field preservation for unverified sources."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Annotated, Any, Literal

from pydantic import Field, StrictInt, model_validator

from hst.core.mtu import MtuModel, MtuObservation, canonical_json
from hst.core.mtu_profiles import emit_observation, observation_from_raw

from .util import GraphBuilder

MAX_IMPORT_BYTES = 1024 * 1024
MAX_IMPORT_ROWS = 512
IMPORT_VERSION = 1
IMPORT_SUBJECT_LABELS = Literal[
    "Endpoint", "Interface", "Port", "Pnic", "Vnic", "Dvs", "DvPortgroup", "Tunnel"
]


class ImportedMtu(MtuModel):
    subject_label: IMPORT_SUBJECT_LABELS
    subject_uid: str = Field(min_length=3, max_length=1024)
    source: str = Field(min_length=1, max_length=256)
    evidence_ref: str = Field(min_length=1, max_length=2048)
    observed_at_ms: Annotated[StrictInt, Field(ge=0)]
    raw_value: StrictInt | str
    basis: Literal[
        "ip_packet", "ethernet_frame_excluding_fcs", "ethernet_frame_including_fcs", "ethernet_payload"
    ]
    metric: Literal["ipv4_mtu_bytes", "ipv6_mtu_bytes", "l2_max_frame_bytes"]
    direction: Literal["tx", "rx", "both"]
    bound_kind: Literal["ceiling", "acceptance_lower_bound"]
    authority: Literal["intent", "configured", "operational"] = "intent"
    tag_depth: Annotated[StrictInt, Field(ge=0, le=8)] | None = None
    tag_accounting: Literal["included", "extra_allowance", "unknown"] = "unknown"
    tag_allowance_bytes: Annotated[StrictInt, Field(ge=0)] | None = None

    @model_validator(mode="after")
    def explicit_identity(self) -> ImportedMtu:
        if not self.subject_uid.strip() or self.subject_uid != self.subject_uid.strip():
            raise ValueError("MTU subject UID must be explicit and contain no surrounding whitespace")
        if ":" not in self.subject_uid or any(c.isspace() for c in self.subject_uid):
            raise ValueError("MTU subject UID must be a graph UID, not a hostname or address")
        obs = self.observation("validation")
        if obs.normalized_value is None:
            raise ValueError("MTU import value/basis/metric/tag accounting cannot be normalized")
        return self

    def observation(self, import_source: str) -> MtuObservation:
        return observation_from_raw(
            subject_uid=self.subject_uid,
            source=f"manual:{import_source}",
            source_target=self.source,
            source_field="import.mtu",
            raw_value=self.raw_value,
            profile_id=self.basis,
            metric=self.metric,
            direction=self.direction,
            bound_kind=self.bound_kind,
            enforcement="l2" if self.metric == "l2_max_frame_bytes" else "l3",
            enforcement_key="imported-interface",
            assertion_kind=self.authority,
            observed_at_ms=self.observed_at_ms,
            raw_evidence_ref=self.evidence_ref,
            collector_version="2",
            tag_depth=self.tag_depth,
            tag_accounting=self.tag_accounting,
            tag_allowance_bytes=self.tag_allowance_bytes,
            selector_json=canonical_json(
                {
                    "version": 1,
                    "evidence_origin": "operator_import",
                    "declared_authority": self.authority,
                    "source_verified": False,
                }
            ),
        )


class MtuImport(MtuModel):
    version: Literal[1] = IMPORT_VERSION
    observations: list[ImportedMtu] = Field(default_factory=list, max_length=MAX_IMPORT_ROWS)

    @model_validator(mode="after")
    def unique_assertions(self) -> MtuImport:
        labels: dict[str, str] = {}
        identities: set[str] = set()
        for row in self.observations:
            label = labels.setdefault(row.subject_uid, row.subject_label)
            if label != row.subject_label:
                raise ValueError(f"ambiguous subject label for {row.subject_uid}")
            ident = row.observation("validation").uid
            if ident in identities:
                raise ValueError(f"duplicate MTU assertion for {row.subject_uid}")
            identities.add(ident)
        return self


def parse_mtu_import(text: str) -> MtuImport:
    if len(text.encode()) > MAX_IMPORT_BYTES:
        raise ValueError("MTU import exceeds 1 MiB")
    return MtuImport.model_validate(json.loads(text)) if text.strip() else MtuImport()


SUBJECT_QUERY = """
UNWIND $subjects AS subject
MATCH (n:Obj {uid: subject.uid, collection_ts: $snap})
WHERE subject.label IN labels(n) AND NOT n:Retired AND n._retired_at IS NULL
RETURN n.uid AS uid, subject.label AS label
"""


def validate_import_subjects(
    session: Any, imported: MtuImport, snapshot_key: int | None
) -> list[dict[str, str]]:
    """Check in a read transaction that the snapshot holds every subject of
    the import. No subject is created."""
    if not imported.observations:
        return []
    if type(snapshot_key) is not int:
        raise ValueError("MTU import requires a published snapshot containing its subjects")
    subjects = sorted({(r.subject_uid, r.subject_label) for r in imported.observations})
    requested = [{"uid": uid_, "label": label} for uid_, label in subjects]
    rows = session.execute_read(
        lambda tx: tx.run(SUBJECT_QUERY, subjects=requested, snap=snapshot_key).data()
    )
    actual = [(r["uid"], r["label"]) for r in rows]
    missing = set(subjects) - set(actual)
    if missing or len(actual) != len(set(actual)):
        detail = ", ".join(f"{label} {uid_}" for uid_, label in sorted(missing))
        raise ValueError(f"MTU import has missing or ambiguous subjects in snapshot {snapshot_key}: {detail}")
    return requested


def emit_import(b: GraphBuilder, imported: MtuImport, import_source: str) -> None:
    for row in imported.observations:
        emit_observation(b, row.subject_label, row.observation(import_source))


def preserve_raw_mtu_fields(
    b: GraphBuilder,
    label: str,
    subject: str,
    record: Mapping[str, Any],
    *,
    source: str,
    target: str,
    path: str,
    authority: Literal["intent", "configured", "operational"],
    fields: Sequence[str] | None = None,
) -> int:
    count = 0
    names = (
        fields
        if fields is not None
        else sorted(k for k in record if "mtu" in k.lower() or "jumbo" in k.lower())
    )
    for name in names:
        if name not in record or not isinstance(record[name], (str, int, float, bool, type(None))):
            continue
        emit_observation(
            b,
            label,
            observation_from_raw(
                subject_uid=subject,
                source=source,
                source_target=target,
                source_field=f"{path}.{name}",
                raw_value=record[name],
                assertion_kind=authority,
                enforcement="unknown",
                raw_evidence_ref=f"{path}.{name}",
                collector_version="2",
            ),
        )
        count += 1
    return count
