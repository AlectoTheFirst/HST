"""Pure conversions of MTU values between byte coordinates, one per profile."""

from __future__ import annotations

from typing import Any, Protocol

from . import uid
from .model import NodeRecord, RelRecord
from .mtu import MtuObservation, canonical_json

PROFILE_VERSION = "1"
PROFILE_IDS = frozenset(
    {
        "unknown",
        "ip_packet",
        "ethernet_frame_excluding_fcs",
        "ethernet_frame_including_fcs",
        "ethernet_payload",
    }
)


class ObservationBuilder(Protocol):
    def node(self, label: str, uid_: str, **props: Any) -> str: ...
    def rel(
        self, rtype: str, start_label: str, start_uid: str, end_label: str, end_uid: str, **props: Any
    ) -> None: ...


def _profile_normalize(
    *,
    profile_id: str,
    metric: str,
    value: int,
    tag_accounting: str,
    tag_allowance_bytes: int | None,
    tag_depth: int | None,
) -> tuple[int | None, bool]:
    """Convert the integer `value` to `normalized_value` with the byte-coordinate
    rules of one profile. Return the converted value and whether the profile
    accepted the input.
    """
    if profile_id == "ip_packet":
        ok = metric in {"ipv4_mtu_bytes", "ipv6_mtu_bytes", "path_pmtu_bytes"}
        return (value if ok else None), ok
    if profile_id in {"ethernet_frame_excluding_fcs", "ethernet_frame_including_fcs"}:
        ok = metric == "l2_max_frame_bytes"
        out = value - 4 if profile_id == "ethernet_frame_including_fcs" else value
        if tag_accounting == "extra_allowance":
            allowance_ok = type(tag_allowance_bytes) is int and tag_allowance_bytes >= 0
            ok = ok and allowance_ok
            if ok and isinstance(tag_allowance_bytes, int):
                out += tag_allowance_bytes
        if isinstance(tag_depth, int) and tag_depth > 0:
            ok = ok and tag_accounting in {"included", "extra_allowance"}
        ok = ok and out >= 14
        return (out if ok else None), ok
    if profile_id == "ethernet_payload":
        # A stated payload limit already has the requested coordinate. Only
        # conversion to a full frame requires MAC/FCS/tag accounting.
        if metric == "l2_payload_mtu_bytes":
            return value, True
        ok = (
            metric == "l2_max_frame_bytes"
            and type(tag_depth) is int
            and tag_depth >= 0
            and tag_accounting in {"included", "extra_allowance"}
            and type(tag_allowance_bytes) is int
            and tag_allowance_bytes >= 0
        )
        out = value
        if ok and isinstance(tag_allowance_bytes, int):
            out += 14 + (tag_allowance_bytes if tag_accounting == "extra_allowance" else 0)
        return (out if ok else None), ok
    return None, False


def restate_ip_bytes(observation: MtuObservation, *, ip_bytes: int) -> tuple[str, int | None]:
    """Return the `(raw_value_json, normalized_value)` of this observation for
    an interface IP MTU of `ip_bytes`. The values use the `profile_id`, the
    `metric` and the tag accounting of the observation.
    """
    profile_id = observation.profile_id
    if profile_id == "ip_packet":
        raw_value = ip_bytes
    elif profile_id == "ethernet_frame_excluding_fcs":
        raw_value = ip_bytes + 14
    elif profile_id == "ethernet_frame_including_fcs":
        raw_value = ip_bytes + 14 + 4
    elif profile_id == "ethernet_payload":
        raw_value = ip_bytes
    else:
        raise ValueError(f"MTU profile {profile_id!r} cannot be restated from an interface MTU value")
    normalized_value, _ok = _profile_normalize(
        profile_id=profile_id,
        metric=observation.metric,
        value=raw_value,
        tag_accounting=observation.tag_accounting,
        tag_allowance_bytes=observation.tag_allowance_bytes,
        tag_depth=observation.tag_depth,
    )
    return canonical_json(raw_value), normalized_value


def observation_from_raw(
    *,
    subject_uid: str,
    source: str,
    source_field: str,
    raw_value: str | int | float | bool | None,
    profile_id: str = "unknown",
    **evidence: Any,
) -> MtuObservation:
    """Build an observation from a raw scalar.

    A malformed scalar is kept in `raw_value_json`. `normalized_value` is set
    only when the profile accepts the value. `bound_kind` stays as the caller
    passes it.
    """
    fields = dict(evidence)
    fields.update(
        subject_uid=subject_uid,
        source=source,
        source_field=source_field,
        profile_id=profile_id,
        profile_version=fields.get("profile_version", PROFILE_VERSION),
        raw_value_json=canonical_json(raw_value),
    )
    fields.setdefault("metric", "unknown")
    fields.setdefault("direction", "unknown")
    fields.setdefault("scope", "interface")
    fields.setdefault("enforcement_key", "interface")
    fields.setdefault("resolution_state", "explicit")
    fields.setdefault("bound_kind", "unknown")
    if fields["metric"] == "ipv4_mtu_bytes":
        fields.setdefault("af", 4)
    elif fields["metric"] == "ipv6_mtu_bytes":
        fields.setdefault("af", 6)
    fields["uid"] = uid.mtu_observation(
        subject_uid,
        source,
        fields.get("source_target", ""),
        source_field,
        fields["metric"],
        fields["direction"],
        fields["scope"],
        fields["assertion_kind"],
        traffic_class=fields.get("traffic_class"),
        policy_ref=fields.get("policy_ref"),
        enforcement_key=fields["enforcement_key"],
    )
    fields["raw_basis"] = profile_id if profile_id in PROFILE_IDS else "unknown"
    value: int | None = None
    if type(raw_value) is int:
        value = raw_value
    elif isinstance(raw_value, str) and raw_value.strip().isascii() and raw_value.strip().isdigit():
        value = int(raw_value.strip())
    valid = value is not None and 0 < value <= 2**31 - 1
    valid = valid and fields["profile_version"] == PROFILE_VERSION
    metric = fields["metric"]
    if fields.get("raw_units", "bytes") != "bytes" or fields["bound_kind"] == "unknown":
        valid = False
    if fields["resolution_state"] in {"unknown", "unsupported", "conflict"}:
        valid = False
    normalized: int | None = None
    if valid and value is not None:
        normalized, ok = _profile_normalize(
            profile_id=profile_id,
            metric=metric,
            value=value,
            tag_accounting=fields.get("tag_accounting", "unknown"),
            tag_allowance_bytes=fields.get("tag_allowance_bytes"),
            tag_depth=fields.get("tag_depth"),
        )
        valid = valid and ok
    if valid:
        fields["normalized_value"] = normalized
    else:
        fields["normalized_value"] = None
        if fields["resolution_state"] not in {"unsupported", "conflict"}:
            fields["resolution_state"] = "unknown"
        fields["gaps"] = sorted({*fields.get("gaps", []), "MTU_SEMANTICS_UNKNOWN"})
    return MtuObservation.model_validate(fields)


def observation_records(
    subject_label: str,
    observation: MtuObservation,
) -> tuple[NodeRecord, RelRecord]:
    from .labels import MTU_SUBJECT_LABELS

    if subject_label not in MTU_SUBJECT_LABELS:
        raise ValueError(f"{subject_label} cannot own MTU evidence")
    return (
        NodeRecord(label="MtuObservation", uid=observation.uid, props=observation.graph_props()),
        RelRecord(
            type="HAS_MTU",
            start_label=subject_label,
            start_uid=observation.subject_uid,
            end_label="MtuObservation",
            end_uid=observation.uid,
        ),
    )


def emit_observation(
    builder: ObservationBuilder,
    subject_label: str,
    observation: MtuObservation,
) -> str:
    node, rel = observation_records(subject_label, observation)
    builder.node(node.label, node.uid, **node.props)
    builder.rel(rel.rel_type, rel.start_label, rel.start_uid, rel.end_label, rel.end_uid)
    return node.uid
