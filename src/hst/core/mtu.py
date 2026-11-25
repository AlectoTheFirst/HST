"""Versioned MTU evidence and evaluation contracts, independent of graph reads."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, model_validator

MTU_CONTRACT_VERSION = "1"
MTU_NORMALIZATION_VERSION = "1"
MTU_EVALUATION_VERSION = "1"
Bytes = Annotated[StrictInt, Field(gt=0)]
BudgetBytes = Annotated[StrictInt, Field(ge=0)]
AddressFamily = Literal[4, 6]
MtuMetric = Literal[
    "l2_max_frame_bytes",
    "l2_payload_mtu_bytes",
    "ipv4_mtu_bytes",
    "ipv6_mtu_bytes",
    "path_pmtu_bytes",
    "unknown",
]
MtuDirection = Literal["tx", "rx", "both", "unknown"]
MtuEnforcement = Literal[
    "l2", "l3", "source", "destination", "tunnel", "fabric", "control_plane", "path", "unknown"
]
MtuBoundKind = Literal["ceiling", "acceptance_lower_bound", "unknown"]
MtuOutcome = Literal[
    "not_assessed", "pass", "fail", "unknown", "fragmentation_required", "conditional", "fits_known_limits"
]
# A stable code for a part of the path that the twin does not cover. The part
# is a source or destination endpoint without evidence in the twin, or the
# path beyond the boundary of the twin. The path is beyond the boundary when
# the destination is not modeled or when the trace ends at an egress toward an
# unknown next hop.
MtuUncoveredCode = Literal["source-endpoint", "destination-endpoint", "path-beyond-twin"]
MtuGapCode = Literal[
    "MTU_NOT_CAPTURED",
    "MTU_SEMANTICS_UNKNOWN",
    "MTU_SOURCE_CONFLICT",
    "MTU_POLICY_UNRESOLVED",
    "MTU_ENDPOINT_UNKNOWN",
    "MTU_RECEIVE_LIMIT_UNKNOWN",
    "MTU_ENCAP_UNKNOWN",
    "MTU_PATH_COVERAGE_INCOMPLETE",
    "MTU_FRAGMENTATION_UNMODELED",
    "MTU_PMTUD_FEEDBACK_UNKNOWN",
    "MTU_EVIDENCE_STALE",
    "MTU_CLASS_UNKNOWN",
    "MTU_SNAPSHOT_UNPINNED",
    "MTU_LENGTH_UNSUPPORTED",
]
MtuFindingCode = Literal[
    "MTU_NORMALIZED_DIFFERENCE",
    "MTU_CAPACITY_DEFICIT",
    "MTU_POLICY_DRIFT",
    "MTU_ADJACENCY_DISCREPANCY",
    "MTU_LAG_INCONSISTENCY",
    "MTU_PMTUD_BLACKHOLE_RISK",
]


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def mtu_fingerprint(*values: Any) -> str:
    """Return the identity of an evaluation.

    The inputs are JSON values and include the request and the observation versions.
    """
    return hashlib.sha256(
        canonical_json(
            {
                "contract": MTU_CONTRACT_VERSION,
                "normalization": MTU_NORMALIZATION_VERSION,
                "evaluation": MTU_EVALUATION_VERSION,
                "inputs": values,
            }
        ).encode()
    ).hexdigest()


class MtuModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class MtuObservation(MtuModel):
    uid: str
    contract_version: str = MTU_CONTRACT_VERSION
    normalization_version: str = MTU_NORMALIZATION_VERSION
    subject_uid: str
    source: str
    source_target: str
    source_field: str
    raw_value_json: str
    raw_basis: Literal[
        "ip_packet",
        "ethernet_frame_excluding_fcs",
        "ethernet_frame_including_fcs",
        "ethernet_payload",
        "unknown",
    ] = "unknown"
    raw_units: str = "bytes"
    metric: MtuMetric = "unknown"
    normalized_value: Bytes | None = None
    direction: MtuDirection = "unknown"
    bound_kind: MtuBoundKind = "unknown"
    af: AddressFamily | None = None
    enforcement: MtuEnforcement = "unknown"
    # Resolution keeps one constraint per enforcement slot and takes no minimum across slots.
    enforcement_key: str = "interface"
    traffic_class: str | None = None
    assertion_kind: Literal["configured", "operational", "intent", "hardware_max", "measurement"]
    resolution_state: Literal[
        "explicit", "inherited", "profile_default", "unknown", "unsupported", "conflict"
    ] = "unknown"
    policy_ref: str | None = None
    scope: str = "interface"
    # The selector is canonical JSON of at most 4096 characters with `version` 1.
    # It holds no property map.
    selector_json: str = '{"version":1}'
    profile_id: str = "unknown"
    profile_version: str = "1"
    collector_version: str = "unknown"
    raw_evidence_ref: str = ""
    observed_at_ms: Annotated[StrictInt, Field(ge=0)] | None = None
    dependency_uids: list[str] = Field(default_factory=list)
    tag_accounting: Literal["included", "extra_allowance", "unknown"] = "unknown"
    tag_depth: Annotated[StrictInt, Field(ge=0, le=8)] | None = None
    tag_allowance_bytes: Annotated[StrictInt, Field(ge=0)] | None = None
    gaps: list[MtuGapCode] = Field(default_factory=list)

    @model_validator(mode="after")
    def valid_observation(self) -> MtuObservation:
        for name in ("uid", "subject_uid", "source", "source_target", "source_field", "enforcement_key"):
            if not getattr(self, name).strip():
                raise ValueError(f"{name} must be nonempty")
        raw = json.loads(self.raw_value_json)
        if isinstance(raw, (dict, list)):
            raise ValueError("raw MTU must be a scalar")
        selector = json.loads(self.selector_json)
        if not isinstance(selector, dict) or selector.get("version") != 1:
            raise ValueError("selector_json needs version 1")
        if len(self.selector_json) > 4096 or len(self.raw_value_json) > 4096:
            raise ValueError("MTU evidence exceeds bounded JSON size")
        if self.normalized_value is not None and (
            self.metric == "unknown"
            or self.bound_kind == "unknown"
            or self.raw_basis == "unknown"
            or self.resolution_state in {"unknown", "unsupported", "conflict"}
        ):
            raise ValueError("normalized MTU requires known basis, metric, bound and resolution")
        if self.metric == "ipv4_mtu_bytes" and self.af != 4:
            raise ValueError("IPv4 MTU requires af=4")
        if self.metric == "ipv6_mtu_bytes" and self.af != 6:
            raise ValueError("IPv6 MTU requires af=6")
        if self.metric == "path_pmtu_bytes" and (
            self.assertion_kind != "measurement" or self.enforcement != "path"
        ):
            raise ValueError("measured PMTU belongs to a measured path")
        return self

    def graph_props(self) -> dict[str, Any]:
        """Return the fields as Neo4j scalar and array properties, without `uid` and without
        null values. The loader adds the collection timestamps."""
        return self.model_dump(exclude={"uid"}, exclude_none=True)


class MtuRequest(MtuModel):
    mode: Literal["off", "inventory", "unfragmented", "packet"] = "off"
    ip_packet_bytes: Bytes | None = None
    ipv4_df: StrictBool | None = None
    reply_ip_packet_bytes: Bytes | None = None
    traffic_class: str | None = None

    @model_validator(mode="after")
    def valid_mode(self) -> MtuRequest:
        if self.mode in {"unfragmented", "packet"} and self.ip_packet_bytes is None:
            raise ValueError("MTU size modes require complete IP packet bytes")
        if self.mode in {"off", "inventory"} and (
            self.ip_packet_bytes is not None
            or self.reply_ip_packet_bytes is not None
            or self.ipv4_df is not None
        ):
            raise ValueError("off/inventory MTU modes do not accept packet sizes or DF")
        if self.mode == "off" and self.traffic_class is not None:
            raise ValueError("off mode does not accept traffic class")
        return self

    def validate_af(self, af: AddressFamily) -> MtuRequest:
        """Validate the request against the address family `af`.

        Each entry point, forks included, calls it after the flow family is resolved.
        """
        if af not in (4, 6):
            raise ValueError("MTU address family must be 4 or 6")
        if af == 6 and self.ipv4_df is not None:
            raise ValueError("IPv4 DF is invalid for IPv6 traffic")
        low, high = (20, 65535) if af == 4 else (40, 65575)
        for value in (self.ip_packet_bytes, self.reply_ip_packet_bytes):
            if value is not None and not low <= value <= high:
                raise ValueError(f"IPv{af} packet length must be {low}..{high}; jumbograms unsupported")
        return self


class MtuContext(MtuModel):
    af: AddressFamily
    direction: Literal["tx", "rx"] = "tx"
    enforcement: MtuEnforcement = "unknown"
    traffic_class: str | None = None
    tag_depth: Annotated[StrictInt, Field(ge=0, le=8)] | None = None


class MtuCoverage(MtuModel):
    complete: bool = False
    candidate_set_complete: bool = False
    constraints_complete: bool = False
    exact_path_known: bool = False
    truncated: bool = False
    gaps: list[MtuGapCode] = Field(default_factory=list)
    unresolved_subjects: list[str] = Field(default_factory=list)
    # The sorted codes of the parts that the twin does not cover. A lane or a
    # connection with the outcome "fits_known_limits" holds them. A connection
    # with the outcome "conditional" holds the union of the codes of its lanes.
    # The list is empty for "pass" and "unknown".
    uncovered: list[MtuUncoveredCode] = Field(default_factory=list)


class MtuFinding(MtuModel):
    code: MtuFindingCode | MtuGapCode
    severity: Literal["info", "risk", "failure", "gap"] = "gap"
    detail: str
    subject_uids: list[str] = Field(default_factory=list)
    stage_ids: list[str] = Field(default_factory=list)
    evidence_uids: list[str] = Field(default_factory=list)
    af: AddressFamily | None = None
    direction: Literal["forward", "reverse"] | None = None
    observed_bytes: Bytes | None = None
    required_bytes: Bytes | None = None
    deficit_bytes: Bytes | None = None
    scope: str | None = None


class MtuConstraint(MtuModel):
    subject_uid: str
    enforcement_key: str
    enforcement: MtuEnforcement
    metric: MtuMetric
    direction: MtuDirection
    af: AddressFamily | None = None
    bound_kind: MtuBoundKind
    value_bytes: Bytes | None = None
    traffic_class: str | None = None
    tag_depth: Annotated[StrictInt, Field(ge=0, le=8)] | None = None
    tag_accounting: Literal["included", "extra_allowance", "unknown"] = "unknown"
    tag_allowance_bytes: Annotated[StrictInt, Field(ge=0)] | None = None
    evidence_uids: list[str] = Field(default_factory=list)
    evidence_quality: list[str] = Field(default_factory=list)
    inherited_from: list[str] = Field(default_factory=list)
    gaps: list[MtuGapCode] = Field(default_factory=list)


class MtuPolicyApplication(MtuModel):
    """The application of a policy observation to a subject and an enforcement slot,
    proved by a platform adapter."""

    observation_uid: str
    subject_uid: str
    enforcement_key: str
    precedence: StrictInt
    profile_id: str
    evidence_uids: list[str] = Field(min_length=1)


class MtuResolution(MtuModel):
    constraints: list[MtuConstraint] = Field(default_factory=list)
    configured: list[MtuConstraint] = Field(default_factory=list)
    intent: list[MtuConstraint] = Field(default_factory=list)
    hardware: list[MtuConstraint] = Field(default_factory=list)
    measurements: list[MtuConstraint] = Field(default_factory=list)
    observations: list[MtuObservation] = Field(default_factory=list)
    findings: list[MtuFinding] = Field(default_factory=list)
    gaps: list[MtuGapCode] = Field(default_factory=list)


class MtuEncapsulation(MtuModel):
    kind: Literal["vxlan", "gre", "wireguard", "ipsec", "vlan", "pppoe", "mpls", "macsec", "unknown"]
    operation: Literal["encapsulate", "decapsulate"] = "encapsulate"
    profile_id: str = "unknown"
    outer_af: AddressFamily | None = None
    parameters_json: str = '{"version":1}'
    # For the kind `ipsec`, `proposal_basis` holds how the governing ESP
    # proposal was chosen among the proposals of an esp-group ("single",
    # "equal-overhead-of-<n>", "largest-overhead-of-<n>"). `esp_encryption` and
    # `esp_hash` hold the encryption and the hash of that proposal. The 3
    # fields are unset for every other kind.
    proposal_basis: str | None = None
    esp_encryption: str | None = None
    esp_hash: str | None = None
    evidence_uids: list[str] = Field(default_factory=list)


class MtuStage(MtuModel):
    stage_id: str
    connection_id: str = "original"
    direction: Literal["forward", "reverse"] = "forward"
    lane: str = "forward"
    region: str = ""
    depth: Annotated[StrictInt, Field(ge=0)] = 0
    enforcement: MtuEnforcement = "unknown"
    applicability: Literal["applicable", "not_applicable", "unknown"] = "applicable"
    ingress_subject_uid: str | None = None
    egress_subject_uid: str | None = None
    peer_subject_uid: str | None = None
    context: MtuContext
    constraints: list[MtuConstraint] = Field(default_factory=list)
    coverage: MtuCoverage = Field(default_factory=MtuCoverage)
    encapsulation: list[MtuEncapsulation] = Field(default_factory=list)
    candidate_set_id: str | None = None
    candidate_id: str | None = None
    selection: Literal["selected", "eligible", "possible", "unknown"] = "unknown"
    connection_reset: bool = False
    # None means that the IPv4 fragmentation support of the stage is not known.
    fragmentation_supported: StrictBool | None = None


class MtuResult(MtuModel):
    contract_version: str = MTU_CONTRACT_VERSION
    evaluation_version: str = MTU_EVALUATION_VERSION
    mode: Literal["off", "inventory", "unfragmented", "packet"] = "off"
    af: AddressFamily | None = None
    direction: Literal["forward", "reverse"] = "forward"
    connection_id: str = "original"
    # A lane is one route alternative or flow partition of a connection.
    lane: str | None = None
    requested_bytes: Bytes | None = None
    outcome: MtuOutcome = "not_assessed"
    known_ceiling_bytes: BudgetBytes | None = None
    guaranteed_bytes: BudgetBytes | None = None
    coverage: MtuCoverage = Field(default_factory=MtuCoverage)
    evidence_quality: list[str] = Field(default_factory=list)
    bottleneck_stage_ids: list[str] = Field(default_factory=list)
    findings: list[MtuFinding] = Field(default_factory=list)
    unresolved_subjects: list[str] = Field(default_factory=list)
    stages: list[MtuStage] = Field(default_factory=list)
    candidates: list[MtuResult] = Field(default_factory=list)
    lanes: list[MtuResult] = Field(default_factory=list)
    connections: list[MtuResult] = Field(default_factory=list)
    fingerprint: str | None = None
    feedback: list[MtuFeedback] = Field(default_factory=list)
    observations: list[MtuObservation] = Field(default_factory=list)
    observation_provenance: dict[str, dict[str, Any]] = Field(default_factory=dict)


class MtuPacketDescriptor(MtuModel):
    """One ICMP error with the flow that it quotes (`quoted_flow_json`)."""

    af: AddressFamily
    source_ip: str
    destination_ip: str
    icmp_type: Annotated[StrictInt, Field(ge=0, le=255)]
    icmp_code: Annotated[StrictInt, Field(ge=0, le=255)]
    quoted_flow_json: str
    connection_id: str
    advertised_mtu_bytes: Bytes | None = None


class MtuFeedback(MtuModel):
    outcome: Literal["not_assessed", "permitted", "blocked", "unknown"] = "not_assessed"
    packet: MtuPacketDescriptor | None = None
    evidence_uids: list[str] = Field(default_factory=list)
    gaps: list[MtuGapCode] = Field(default_factory=list)


MtuResult.model_rebuild()
