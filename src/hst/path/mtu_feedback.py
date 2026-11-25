"""Packet and ICMP-error semantics independent of ordinary reverse traffic.

No function here probes a device or calls the firewall engine with an invented
'established' TCP state. Feedback is permitted only with explicit coverage from a
typed error/quoted-flow policy adapter.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Sequence
from typing import Annotated, Literal

from pydantic import Field, StrictBool, StrictInt, model_validator

from hst.core.mtu import (
    AddressFamily,
    Bytes,
    MtuFeedback,
    MtuFinding,
    MtuGapCode,
    MtuModel,
    MtuPacketDescriptor,
    MtuRequest,
    MtuResult,
    MtuStage,
    canonical_json,
    mtu_fingerprint,
)


class MtuQuotedFlow(MtuModel):
    """Identity of the rejected packet at the rejecting router, after NAT.

    A before-NAT quote does not match after-NAT connection state.
    """

    version: Literal[1] = 1
    af: AddressFamily
    source_ip: str
    destination_ip: str
    protocol: Annotated[StrictInt, Field(ge=0, le=255)]
    source_port: Annotated[StrictInt, Field(ge=0, le=65535)] | None = None
    destination_port: Annotated[StrictInt, Field(ge=0, le=65535)] | None = None
    connection_id: str = "original"

    @model_validator(mode="after")
    def validate_flow(self) -> MtuQuotedFlow:
        if not self.connection_id.strip():
            raise ValueError("quoted flow needs a connection identity")
        for address in (self.source_ip, self.destination_ip):
            if ipaddress.ip_address(address).version != self.af:
                raise ValueError("quoted addresses must match the quoted address family")
        if self.protocol not in {6, 17} and (
            self.source_port is not None or self.destination_port is not None
        ):
            raise ValueError("ports are supported only for quoted TCP/UDP")
        return self


class MtuFeedbackHop(MtuModel):
    """Evidence for the path of one ICMP error, separate from the data-flow reply.

    related_state_complete is required only for stateful evaluation. A verified
    stateless rule can be complete without any simulated connection state.
    """

    stage_id: str
    route_outcome: Literal["permitted", "blocked", "unknown"] = "unknown"
    policy_outcome: Literal["permitted", "blocked", "unknown"] = "unknown"
    icmp_type_code_complete: StrictBool = False
    quoted_flow_complete: StrictBool = False
    stateful: StrictBool = False
    related_state_complete: StrictBool = False
    evidence_uids: list[str] = Field(default_factory=list)

    @property
    def policy_complete(self) -> bool:
        return (
            self.icmp_type_code_complete
            and self.quoted_flow_complete
            and (not self.stateful or self.related_state_complete)
        )


class MtuPacketShape(MtuModel):
    """The lengths of one IP packet and its headers. Jumbograms and non-initial fragments are refused."""

    af: AddressFamily
    ip_packet_bytes: Bytes
    ip_header_bytes: Annotated[StrictInt, Field(ge=20)]
    transport_header_bytes: Annotated[StrictInt, Field(ge=0)] = 0
    non_initial_fragment: StrictBool = False

    @model_validator(mode="after")
    def validate_shape(self) -> MtuPacketShape:
        MtuRequest(mode="packet", ip_packet_bytes=self.ip_packet_bytes).validate_af(self.af)
        if self.non_initial_fragment:
            raise ValueError("forwarding non-initial fragments is not modeled")
        if self.af == 4 and (not 20 <= self.ip_header_bytes <= 60 or self.ip_header_bytes % 4):
            raise ValueError("IPv4 header length must be 20..60 bytes in four-byte words")
        if self.af == 6 and (self.ip_header_bytes < 40 or (self.ip_header_bytes - 40) % 8):
            raise ValueError("supported IPv6 extension-header lengths use eight-byte units")
        if self.ip_header_bytes + self.transport_header_bytes > self.ip_packet_bytes:
            raise ValueError("complete IP packet is shorter than its specified headers")
        return self


def request_for_connection(
    request: MtuRequest,
    *,
    direction: Literal["forward", "reverse"] = "forward",
    connection_reset: bool = False,
    explicit_ip_packet_bytes: int | None = None,
) -> tuple[MtuRequest | None, list[MtuGapCode]]:
    """The request for one connection leg. A proxy-originated packet and a reply
    do not inherit an unstated size.

    With a result of None, the caller keeps the inventory evidence and marks the
    original size mode unknown. Ordinary same-family NAT passes
    connection_reset=False.
    """
    if request.mode in {"off", "inventory"}:
        return request.model_copy(deep=True), []
    length = explicit_ip_packet_bytes
    if length is None and not connection_reset:
        length = request.reply_ip_packet_bytes if direction == "reverse" else request.ip_packet_bytes
    if length is None:
        return None, ["MTU_LENGTH_UNSUPPORTED"]
    # IPv4 DF belongs to the stated original packet. Neither the reverse packet
    # nor a proxy's independently originated packet inherits that bit.
    df = request.ipv4_df if direction == "forward" and not connection_reset else None
    return MtuRequest(
        mode=request.mode, ip_packet_bytes=length, ipv4_df=df, traffic_class=request.traffic_class
    ), []


def qualify_packet_result(
    result: MtuResult,
    stage: MtuStage,
    request: MtuRequest,
    *,
    deficit_enforcements: set[str] | None = None,
) -> MtuResult:
    """Qualify a pure byte deficit with its actual packet enforcement point."""
    if request.mode != "packet" or not any(f.code == "MTU_CAPACITY_DEFICIT" for f in result.findings):
        return result
    if stage.applicability != "applicable" or stage.selection not in {"selected", "eligible"}:
        return result
    changed = result.model_copy(deep=True)
    # An entry-side (rx) deficit is a drop in every DF state.
    routing = (
        stage.enforcement == "l3"
        and stage.context.direction != "rx"
        and (deficit_enforcements is None or deficit_enforcements == {"l3"})
    )
    if not routing:
        changed.outcome = "fail"
        changed.coverage.gaps = [g for g in changed.coverage.gaps if g != "MTU_FRAGMENTATION_UNMODELED"]
        return changed
    if stage.context.af == 4 and stage.fragmentation_supported is False:
        changed.outcome = "fail"
        changed.coverage.gaps = [g for g in changed.coverage.gaps if g != "MTU_FRAGMENTATION_UNMODELED"]
        changed.findings.append(
            MtuFinding(
                code="MTU_CAPACITY_DEFICIT",
                severity="failure",
                detail="This routed stage does not support IPv4 fragmentation.",
                stage_ids=[stage.stage_id],
                af=4,
                direction=stage.direction,
            )
        )
    elif stage.context.af == 4 and request.ipv4_df is False:
        # The outcome does not model fragment forwarding or reassembly.
        changed.outcome = "fragmentation_required"
        changed.coverage.complete = False
        changed.coverage.gaps = sorted({*changed.coverage.gaps, "MTU_FRAGMENTATION_UNMODELED"})
    elif stage.context.af == 4 and request.ipv4_df is None:
        changed.outcome = "conditional"
    else:
        changed.outcome = "fail"
    # No router source address or quoted-flow route is known here.
    if stage.context.af == 6 or request.ipv4_df is not False:
        changed.feedback = [MtuFeedback(outcome="unknown", gaps=["MTU_PMTUD_FEEDBACK_UNKNOWN"])]
    changed.fingerprint = mtu_fingerprint(
        result.fingerprint, stage.fragmentation_supported, [f.model_dump() for f in changed.feedback]
    )
    return changed


def build_feedback_packet(
    stage: MtuStage,
    request: MtuRequest,
    result: MtuResult,
    *,
    router_ip: str,
    quoted_flow: MtuQuotedFlow,
    advertised_mtu_bytes: int | None = None,
) -> MtuPacketDescriptor | None:
    """Build a candidate PTB/error only for a proven routed IP-MTU deficit.

    An outer-tunnel error quotes the outer carrier flow.
    """
    request.validate_af(stage.context.af)
    if stage.enforcement != "l3" or stage.applicability != "applicable" or stage.selection != "selected":
        return None
    # An entry-side interface drop never fragments or generates ICMP feedback.
    if stage.context.direction == "rx":
        return None
    if request.mode != "packet" or result.outcome not in {"fail", "conditional"}:
        return None
    deficits = [f for f in result.findings if f.code == "MTU_CAPACITY_DEFICIT"]
    if not deficits:
        return None
    # A stage with any non-L3 constraint has no known L3 feedback source.
    if not stage.constraints or any(c.enforcement != "l3" for c in stage.constraints):
        return None
    if stage.context.af == 4 and request.ipv4_df is not True:
        return None
    if quoted_flow.af != stage.context.af or quoted_flow.connection_id != stage.connection_id:
        raise ValueError("feedback quote must describe this rejecting stage's connection and AF")
    router = ipaddress.ip_address(router_ip)
    if router.version != stage.context.af:
        raise ValueError("feedback router address must match the packet family")
    # An encapsulated stage does not advertise its inner-packet budget as the outer IP MTU.
    if advertised_mtu_bytes is None and not stage.encapsulation:
        advertised_mtu_bytes = result.known_ceiling_bytes or None
    return MtuPacketDescriptor(
        af=stage.context.af,
        source_ip=str(router),
        destination_ip=quoted_flow.source_ip,
        icmp_type=3 if stage.context.af == 4 else 2,
        icmp_code=4 if stage.context.af == 4 else 0,
        quoted_flow_json=canonical_json(quoted_flow.model_dump()),
        connection_id=stage.connection_id,
        advertised_mtu_bytes=advertised_mtu_bytes,
    )


def evaluate_feedback(
    packet: MtuPacketDescriptor,
    hops: Sequence[MtuFeedbackHop],
    *,
    path_complete: bool = False,
    generation: Literal["modeled", "observed", "unknown", "suppressed"] = "unknown",
) -> MtuFeedback:
    """Evaluate the exact error path with quote/type/state-aware evidence.

    A modeled permit is separate from measured PMTU, sender PMTUD/PLPMTUD
    capability and ordinary reverse TCP/UDP delivery.
    """
    if len(packet.quoted_flow_json) > 4096:
        return MtuFeedback(outcome="unknown", packet=packet, gaps=["MTU_PMTUD_FEEDBACK_UNKNOWN"])
    try:
        flow = MtuQuotedFlow.model_validate(json.loads(packet.quoted_flow_json))
        router = ipaddress.ip_address(packet.source_ip)
        target = ipaddress.ip_address(packet.destination_ip)
    except (ValueError, TypeError):
        return MtuFeedback(outcome="unknown", packet=packet, gaps=["MTU_PMTUD_FEEDBACK_UNKNOWN"])
    expected = (3, 4) if packet.af == 4 else (2, 0)
    valid = (
        (packet.icmp_type, packet.icmp_code) == expected
        and router.version == packet.af
        and target.version == packet.af
        and flow.af == packet.af
        and str(target) == str(ipaddress.ip_address(flow.source_ip))
        and flow.connection_id == packet.connection_id
    )
    evidence = sorted({e for hop in hops for e in hop.evidence_uids})
    if not valid:
        return MtuFeedback(
            outcome="unknown", packet=packet, evidence_uids=evidence, gaps=["MTU_PMTUD_FEEDBACK_UNKNOWN"]
        )
    if generation == "suppressed" or any(
        bool(hop.evidence_uids)
        and (hop.route_outcome == "blocked" or (hop.policy_outcome == "blocked" and hop.policy_complete))
        for hop in hops
    ):
        return MtuFeedback(outcome="blocked", packet=packet, evidence_uids=evidence)
    if (
        path_complete
        and bool(hops)
        and generation in {"modeled", "observed"}
        and all(
            h.route_outcome == h.policy_outcome == "permitted" and h.policy_complete and bool(h.evidence_uids)
            for h in hops
        )
    ):
        return MtuFeedback(outcome="permitted", packet=packet, evidence_uids=evidence)
    return MtuFeedback(
        outcome="unknown", packet=packet, evidence_uids=evidence, gaps=["MTU_PMTUD_FEEDBACK_UNKNOWN"]
    )


def feedback_findings(feedback: MtuFeedback, *, stage_id: str) -> list[MtuFinding]:
    if feedback.outcome != "blocked":
        return []
    return [
        MtuFinding(
            code="MTU_PMTUD_BLACKHOLE_RISK",
            severity="risk",
            detail="The modeled MTU error cannot reach the sender; sender recovery capability is unverified.",
            stage_ids=[stage_id],
            evidence_uids=feedback.evidence_uids,
            af=feedback.packet.af if feedback.packet else None,
        )
    ]
