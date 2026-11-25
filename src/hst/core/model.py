"""Typed records exchanged between collectors and the loader.

Collectors normalize raw API payloads into a `Batch` of `NodeRecord`/`RelRecord`.
The loader validates every record against the label/relationship registry before
anything is written to Neo4j. Invalid records fail at validation time.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .labels import MTU_SUBJECT_LABELS, check_identity, validate_label, validate_props, validate_rel

# Rel key names are interpolated into the MERGE pattern by loader.rel_upsert_query.
_KEY_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _check_reserved(props: dict[str, Any]) -> dict[str, Any]:
    """Reject a payload prop named `uid` or with a `_` prefix. The loader owns these keys."""
    bad = sorted(k for k in props if k == "uid" or k.startswith("_"))
    if bad:
        raise ValueError(
            f"reserved prop keys not allowed: {bad} (`uid` and `_`-prefixed keys are loader-owned)"
        )
    return props


class NodeRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str
    uid: str
    props: dict[str, Any] = Field(default_factory=dict)

    _validate_props = field_validator("props")(_check_reserved)


class RelRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    rel_type: str = Field(alias="type")
    start_label: str
    start_uid: str
    end_label: str
    end_uid: str
    # The MERGE pattern includes these props. They distinguish 2 relationships of
    # one type between the same pair of nodes.
    key: dict[str, Any] = Field(default_factory=dict)
    props: dict[str, Any] = Field(default_factory=dict)

    _validate_props = field_validator("props", "key")(_check_reserved)

    @model_validator(mode="before")
    @classmethod
    def _expand_ends(cls, data: Any) -> Any:
        """Accept `start` and `end` as [label, uid] pairs."""
        if isinstance(data, dict):
            for side in ("start", "end"):
                v = data.pop(side, None)
                if v is not None:
                    label, uid_ = v
                    data.setdefault(f"{side}_label", label)
                    data.setdefault(f"{side}_uid", uid_)
        return data


SectionStatus = Literal[
    "ok",
    "empty",
    "unsupported",
    "unauthorized",
    "malformed",
    "partial",
    "failed",
    "unknown",
]

# The statuses that mean a section was not collected for a reason the device
# owner has to act on.
DEGRADING_SECTION_STATUSES: tuple[SectionStatus, ...] = ("failed", "unauthorized", "malformed")


class SectionOutcome(BaseModel):
    """The outcome of one section of the collection of a device.

    A section is the part of the device state that one command returns.

    `status` is one of the `SectionStatus` values. `detail` holds the failure
    text of the device. `row_count` is the count of records that the section
    parsed to. It is null for a section without rows and on every status that
    produced no records.
    """

    model_config = ConfigDict(extra="forbid")

    status: SectionStatus = "unknown"
    detail: str = ""
    row_count: int | None = None


def section_verdict(
    sections: Mapping[str, SectionOutcome], authoritative: Iterable[str] = ()
) -> Literal["ok", "partial", "failed"]:
    """Roll one device's section outcomes up into its collection verdict.

    Any degrading status on an authoritative section (failed, unauthorized or
    malformed) fails the device.

    A degrading status on any other section makes the collection `partial`.
    """
    required = set(authoritative)
    verdict: Literal["ok", "partial", "failed"] = "ok"
    for name, outcome in sorted(sections.items()):
        if outcome.status not in DEGRADING_SECTION_STATUSES:
            continue
        if name in required:
            return "failed"
        verdict = "partial"
    return verdict


TableStatus = Literal[
    "complete",
    "complete-empty",
    "partial",
    "failed",
    "unchanged",
    # The device does not have the feature that this table reads, for example
    # an OSPF link-state database on a device with no OSPF process.
    "unsupported",
    # The run did not capture this table or this direction of it. The capture
    # is switched off for the source, or the platform cannot expose the input
    # (a BGP received table with no soft reconfiguration inbound).
    "not-captured",
]

# The table statuses that mean the side store does not hold this run's rows for
# the table.
DEGRADING_TABLE_STATUSES: tuple[TableStatus, ...] = ("failed", "partial")


class TableOutcome(BaseModel):
    """The outcome of one expected side-store table of the collection of a device.

    The model has the fields of `SectionOutcome` (a status, the failure text
    of the writer and the row count) and the file that holds the rows. A table
    is `complete` when its rows were written, `complete-empty` when the
    collector produced no rows and no file exists, `failed` when the write
    raised, `unchanged` when the fetch matched the previous payload and no
    load ran, `partial` when only a part of the rows was written,
    `unsupported` when the device does not have the feature of the table (an
    OSPF link-state database on a device with no OSPF process), and
    `not-captured` when the run asked the device for none of it.

    `path` is the side-store file relative to the data directory. It is empty
    on every status that wrote no file.

    The snapshot manifest fills in `observed_ms` and `parser_version`
    (core/manifest.py `DeviceEntry`). `observed_ms` is the fetch start of the
    payload that holds the rows of the table. `parser_version` is the
    `PARSER_VERSION` of the collector at that fetch. Both are null on the
    outcome that the loader returns (`load_payload`) and on an outcome of a
    manifest before schema version 3.
    """

    model_config = ConfigDict(extra="forbid")

    status: TableStatus = "complete"
    detail: str = ""
    row_count: int | None = None
    path: str = ""
    observed_ms: int | None = None
    parser_version: str | None = None


def table_verdict(tables: Mapping[str, TableOutcome]) -> Literal["ok", "partial"]:
    """Roll one device's table outcomes up into its side-store verdict."""
    for outcome in tables.values():
        if outcome.status in DEGRADING_TABLE_STATUSES:
            return "partial"
    return "ok"


class Batch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str  # e.g. "apic"
    scope: str  # retirement partition, e.g. "apic:fab1"
    nodes: list[NodeRecord] = Field(default_factory=list)
    rels: list[RelRecord] = Field(default_factory=list)
    # The outcome of each section of the payload, by section name. The map is
    # empty for a collector that reports no per-section outcomes. A section
    # without a recorded outcome has the status `unknown`.
    sections: dict[str, SectionOutcome] = Field(default_factory=dict)
    # The points that normalization could not settle from the payload and its
    # configuration. Each warning is a full sentence with the name of the
    # device. The load copies the warnings to the run manifest
    # (`RunManifest.warnings`) and the run copies them to `warnings` of the
    # snapshot manifest.
    warnings: list[str] = Field(default_factory=list)

    def validate_registry(self) -> None:
        errors: list[str] = []
        # Identity is checked before the registry errors are reported.
        identities: dict[str, dict[str, Any]] = {}
        for n in self.nodes:
            check_identity(identities, n.label, n.uid, n.props)
            try:
                validate_label(n.label)
                validate_props(n.label, n.props)
            except ValueError as e:
                errors.append(f"{e} (node {n.uid})")
        mtu_subjects = {n.uid: n.props.get("subject_uid") for n in self.nodes if n.label == "MtuObservation"}
        for r in self.rels:
            if (
                r.rel_type == "HAS_MTU"
                and r.end_uid in mtu_subjects
                and mtu_subjects[r.end_uid] != r.start_uid
            ):
                errors.append(f"HAS_MTU subject disagrees with observation: {r.end_uid}")
            if r.rel_type == "HAS_MTU" and (
                r.start_label not in MTU_SUBJECT_LABELS or r.end_label != "MtuObservation"
            ):
                errors.append(f"invalid HAS_MTU endpoints: {r.start_label} -> {r.end_label}")
            for check, value in (
                (validate_rel, r.rel_type),
                (validate_label, r.start_label),
                (validate_label, r.end_label),
            ):
                try:
                    check(value)
                except ValueError as e:
                    errors.append(f"{e} (rel {r.rel_type} {r.start_uid} -> {r.end_uid})")
            for k in r.key:
                if not _KEY_NAME.match(k):
                    errors.append(
                        f"invalid rel key name {k!r}: a key name must match [A-Za-z_][A-Za-z0-9_]* "
                        f"(rel {r.rel_type} {r.start_uid} -> {r.end_uid})"
                    )
        if errors:
            uniq = sorted(set(errors))
            raise ValueError("batch failed registry validation:\n  " + "\n  ".join(uniq))


class RunManifest(BaseModel):
    run_id: str
    source: str
    scope: str
    started: str = ""
    finished: str = ""
    finished_ms: int = 0
    nodes_upserted: int = 0
    nodes_created: int = 0
    nodes_revived: int = 0
    rels_upserted: int = 0
    rels_created: int = 0
    rels_revived: int = 0
    rels_dropped_missing_endpoint: int = 0
    nodes_retired: int = 0
    rels_retired: int = 0
    retirement_skipped: bool = False
    rel_retirement_skipped: bool = False
    errors: list[str] = Field(default_factory=list)
    # The section outcomes of the batch that this load wrote.
    sections: dict[str, SectionOutcome] = Field(default_factory=dict)
    # The warnings of the batch (`Batch.warnings`). The run records them in its
    # snapshot manifest.
    warnings: list[str] = Field(default_factory=list)
    # One entry per side-store table that the collector declares.
    # `collectors/base.py load_payload` fills the map after the graph load
    # returns. The map is empty on the manifest that the loader returns.
    tables: dict[str, TableOutcome] = Field(default_factory=dict)
    # `graph_sha` is the digest of the normalized batch that the load read
    # (`collectors/base.py graph_sha`). It is empty on a manifest that no
    # normalization produced. `graph_unchanged` is true when that digest
    # matched the digest on record. The load then wrote only the shared and
    # anchored objects of the batch (`collectors/base.py _shared_part`) and the
    # counters count those objects. The carry brings the other objects of the
    # device forward.
    graph_sha: str = Field(default="", exclude=True)
    graph_unchanged: bool = Field(default=False, exclude=True)
