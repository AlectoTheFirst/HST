"""MTU capture at traversal sites, with request-local snapshot evidence."""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
from typing import Any

from hst.core.mtu import (
    AddressFamily,
    MtuEncapsulation,
    MtuGapCode,
    MtuRequest,
    MtuStage,
    canonical_json,
    mtu_fingerprint,
)
from hst.core.mtu_read import read_mtu, resolve_constraints

from .mtu import evaluate_stages
from .mtu_encap import PROFILES, carrier_af, inner_budget

_REQUEST: ContextVar[tuple[MtuRequest, int] | None] = ContextVar("mtu_request", default=None)
_SCOPE: ContextVar[Capture | None] = ContextVar("mtu_capture", default=None)
MAX_STAGES = 2048


@dataclass
class Capture:
    request: MtuRequest
    af: int
    direction: str = "forward"
    connection_id: str = "original"
    stages: list[MtuStage] = field(default_factory=list)
    truncated: bool = False


@contextmanager
def mtu_request(request: MtuRequest, af: int) -> Iterator[None]:
    request.validate_af(af)  # type: ignore[arg-type]
    token = _REQUEST.set((request, af))
    try:
        yield
    finally:
        _REQUEST.reset(token)


def crossing(
    trail: Any,
    subject_uid: str | None,
    *,
    enforcement: str,
    direction: str = "tx",
    possible: bool = False,
    region: str | None = None,
    tag_depth: int | None = None,
) -> None:
    """Record an enforcement site before rendering collapses hops."""
    capture = _SCOPE.get()
    if capture is None:
        return
    if len(capture.stages) >= MAX_STAGES:
        capture.truncated = True
        return
    position = len(capture.stages)
    capture.stages.append(
        MtuStage.model_validate(
            {
                "stage_id": mtu_fingerprint(
                    capture.connection_id, capture.direction, position, subject_uid, trail.depth, trail.lane
                )[:24],
                "connection_id": capture.connection_id,
                "connection_reset": capture.connection_id != "original",
                "direction": capture.direction,
                "lane": "shared" if trail.shared else str(trail.lane),
                "depth": trail.depth,
                "region": region or "all",
                "enforcement": enforcement,
                "egress_subject_uid": subject_uid if direction == "tx" else None,
                "ingress_subject_uid": subject_uid if direction == "rx" else None,
                "selection": "possible" if possible else "eligible",
                "applicability": "applicable" if subject_uid else "unknown",
                "context": {
                    "af": capture.af,
                    "direction": direction,
                    "enforcement": enforcement,
                    "traffic_class": capture.request.traffic_class,
                    "tag_depth": tag_depth,
                },
                "coverage": {
                    "gaps": ["MTU_PATH_COVERAGE_INCOMPLETE"],
                    "unresolved_subjects": [] if subject_uid else ["unresolved-crossing"],
                },
            }
        )
    )


def capturing() -> bool:
    """Whether a trace is recording MTU enforcement sites."""
    return _SCOPE.get() is not None


@contextmanager
def not_capturing() -> Iterator[None]:
    """No MTU enforcement site is recorded inside the block."""
    token = _SCOPE.set(None)
    try:
        yield
    finally:
        _SCOPE.reset(token)


def boundary(trail: Any, *, connection_reset: bool = False) -> None:
    crossing(trail, None, enforcement="unknown", possible=True)
    capture = _SCOPE.get()
    if capture and capture.stages:
        capture.stages[-1].connection_reset = connection_reset
        if connection_reset:
            capture.stages[-1].coverage.gaps.append("MTU_LENGTH_UNSUPPORTED")


def unresolved_crossing(trail: Any, *, enforcement: str) -> None:
    """A crossing the trace could not resolve, as a stage with `selection: "unknown"`."""
    crossing(trail, None, enforcement=enforcement)
    capture = _SCOPE.get()
    if capture and capture.stages:
        capture.stages[-1].selection = "unknown"


def _candidate_set_completeness(stages: list[MtuStage]) -> dict[str, bool]:
    """A candidate set is complete when every member is "eligible" and the
    topology read was not truncated.

    It runs before `_finish` overwrites `coverage.truncated`.
    """
    groups: dict[str, list[MtuStage]] = {}
    for stage in stages:
        if stage.candidate_set_id is not None:
            groups.setdefault(stage.candidate_set_id, []).append(stage)
    return {
        set_id: all(s.selection == "eligible" for s in members)
        and not any(s.coverage.truncated for s in members)
        for set_id, members in groups.items()
    }


def _finish(session: Any, capture: Capture, result: dict[str, Any]) -> dict[str, Any]:
    capture.stages = expand_stages(session, capture.stages)
    candidate_set_complete = _candidate_set_completeness(capture.stages)
    subjects = {u for s in capture.stages for u in (s.ingress_subject_uid, s.egress_subject_uid) if u}
    evidence = read_mtu(session, subjects)
    resolution_findings = []
    for stage in capture.stages:
        subject = stage.egress_subject_uid or stage.ingress_subject_uid
        observations = evidence.by_subject.get(subject or "", [])
        # A host netdevice limit applies to that host's source/destination crossing.
        context = stage.context
        if stage.enforcement in {"source", "destination"}:
            context = context.model_copy(update={"enforcement": "unknown"})
        if stage.encapsulation:
            # The evidence of a carrier crossing is in the tunnel's outer family.
            carrier_family, carrier_gaps = carrier_af(stage.encapsulation, original_af=stage.context.af)
            if carrier_family is not None and not carrier_gaps:
                context = context.model_copy(update={"af": carrier_family})
        resolved = resolve_constraints(observations, context)
        stage.constraints = resolved.constraints
        resolution_findings.extend(resolved.findings)
        stage.coverage.constraints_complete = bool(resolved.constraints) and not resolved.gaps
        # MTU_NOT_CAPTURED applies only to a stage whose own subject is unresolved.
        subject_evidence_gaps: list[MtuGapCode] = [g for g in evidence.gaps if g != "MTU_NOT_CAPTURED"]
        if subject in evidence.unresolved_subjects:
            subject_evidence_gaps.append("MTU_NOT_CAPTURED")
        stage.coverage.gaps = sorted(set(stage.coverage.gaps + resolved.gaps + subject_evidence_gaps))
        stage.coverage.truncated = capture.truncated or evidence.truncated
        if subject in evidence.unresolved_subjects:
            stage.coverage.unresolved_subjects.append(subject)
        if stage.enforcement in {"source", "destination"} and not resolved.constraints:
            stage.coverage.gaps.append("MTU_ENDPOINT_UNKNOWN")
        if stage.context.direction == "rx" and not resolved.constraints:
            stage.coverage.gaps.append("MTU_RECEIVE_LIMIT_UNKNOWN")
        if stage.candidate_set_id is not None:
            stage.coverage.candidate_set_complete = candidate_set_complete.get(stage.candidate_set_id, False)
        has_ceiling = any(c.bound_kind == "ceiling" and c.value_bytes is not None for c in stage.constraints)
        if (
            subject is not None
            and stage.coverage.constraints_complete
            and has_ceiling
            and stage.selection in {"selected", "eligible"}
            and stage.applicability == "applicable"
            and (stage.candidate_set_id is None or stage.coverage.candidate_set_complete)
            and not capture.truncated
            and not evidence.truncated
        ):
            stage.coverage.gaps = [g for g in stage.coverage.gaps if g != "MTU_PATH_COVERAGE_INCOMPLETE"]
    # Shared source stages apply to every lane of the connection.
    shared = [s for s in capture.stages if s.lane == "shared"]
    lanes = sorted({s.lane for s in capture.stages if s.lane != "shared"}) or ["0"]
    stages = [s for s in capture.stages if s.lane != "shared"]
    # Each lane keeps the selection and coverage of its own stages.
    for lane in lanes:
        stages.extend(
            s.model_copy(update={"lane": lane, "stage_id": mtu_fingerprint(s.stage_id, lane)[:24]})
            for s in shared
        )
    value = evaluate_stages(stages, capture.request)
    unique_findings = {f.model_dump_json(): f for f in [*value.findings, *resolution_findings]}
    value.findings = [unique_findings[key] for key in sorted(unique_findings)]
    value.observation_provenance = evidence.provenance
    value.observations = sorted((o for obs in evidence.by_subject.values() for o in obs), key=lambda o: o.uid)
    value.coverage.truncated |= capture.truncated or evidence.truncated
    value.fingerprint = mtu_fingerprint(
        value.model_dump(mode="json"),
        evidence.model_dump(mode="json"),
        capture.request.model_dump(mode="json"),
    )
    result["mtu"] = value.model_dump(mode="json")
    return result


def trace_scope(*, reverse: bool = False) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Keep source interpretations and independently routed replies separate."""

    def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(fn)
        def wrapped(session: Any, *args: Any, **kwargs: Any) -> Any:
            current = _REQUEST.get()
            if current is None:
                return fn(session, *args, **kwargs)
            request, af = current
            if reverse:
                request = request.model_copy(
                    update={"ip_packet_bytes": request.reply_ip_packet_bytes, "ipv4_df": None}
                )
            capture = Capture(request, af, "reverse" if reverse else "forward")
            token = _SCOPE.set(capture)
            try:
                result = fn(session, *args, **kwargs)
                return _finish(session, capture, result)
            finally:
                _SCOPE.reset(token)

        return wrapped

    return decorate


def ensure_result(result: dict[str, Any], request: MtuRequest) -> dict[str, Any]:
    """Add an unresolved MTU result to a result that has none."""
    if "mtu" not in result and "forward" not in result:
        value = evaluate_stages([], request)
        result["mtu"] = value.model_dump(mode="json")
    return result


def connection_scope(fn: Callable[..., Any]) -> Callable[..., Any]:
    """A load balancer backend originates a separate packet-size domain."""

    @wraps(fn)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        capture = _SCOPE.get()
        if capture is None:
            return fn(*args, **kwargs)
        previous = capture.connection_id
        capture.connection_id = f"{previous}/backend/{len(capture.stages)}"
        try:
            return fn(*args, **kwargs)
        finally:
            capture.connection_id = previous

    return wrapped


# The ICV length that ESP appends for each hash of a VyOS esp-group proposal
# whose cipher is not an AEAD mode. The sources are RFC 4868 SS2.3 (HMAC-SHA-2
# truncation), RFC 2404 (HMAC-SHA-1-96) and RFC 2403 (HMAC-MD5-96).
_ESP_HASH_ICV_BYTES: dict[str, int] = {"sha1": 12, "sha256": 16, "sha384": 24, "sha512": 32, "md5": 12}
# The ICV length of an AES-GCM ESP proposal, keyed by the trailing bit count
# of the proposal name (RFC 4106 SS5). The explicit IV is 8 bytes (RFC 4106 SS5).
_ESP_GCM_ICV_BYTES: dict[str, int] = {"64": 8, "96": 12, "128": 16}


def _outer_af(tunnel: dict[str, Any]) -> AddressFamily | None:
    """The carrier address family from the local address, else the endpoint address, or None."""
    for key in ("local_address", "endpoint"):
        addr = tunnel.get(key)
        if not isinstance(addr, str) or not addr:
            continue
        try:
            return 6 if ipaddress.ip_address(addr.split("/")[0]).version == 6 else 4
        except ValueError:
            continue
    return None


def _tunnel_label(tunnel: dict[str, Any]) -> str:
    return str(tunnel.get("name") or tunnel.get("uid") or "tunnel")


def _wireguard_params(tunnel: dict[str, Any], header: int) -> tuple[dict[str, Any] | None, str | None]:
    mtu = tunnel.get("tunnel_mtu")
    if isinstance(mtu, int) and mtu > 0:
        # Linux caps the padded ciphertext at the MTU of the wg interface
        # (wireguard(8)). Below that MTU, WireGuard pads the plaintext to a
        # multiple of 16 bytes for ChaCha20-Poly1305.
        return {"outer_header_bytes": header, "padding_mode": "linux_mtu_cap", "inner_mtu_bytes": mtu}, None
    return {"outer_header_bytes": header, "padding_mode": "multiple_16", "inner_mtu_bytes": None}, None


def _gre_params(tunnel: dict[str, Any], header: int) -> tuple[dict[str, Any] | None, str | None]:
    key, checksum, sequence = tunnel.get("gre_key"), tunnel.get("gre_checksum"), tunnel.get("gre_sequence")
    if key is None or checksum is None or sequence is None:
        return None, f"GRE key/checksum/sequence flags not collected for tunnel {_tunnel_label(tunnel)}"
    return {
        "outer_header_bytes": header,
        "checksum": bool(checksum),
        "key": bool(key),
        "sequence": bool(sequence),
        "routing": False,
        "payload_kind": "ip",
    }, None


def _vxlan_params(tunnel: dict[str, Any], header: int) -> tuple[dict[str, Any] | None, str | None]:
    return {
        "outer_header_bytes": header,
        "retained_inner_tags": 0,
        # IEEE 802.3 minimum frame length (64 bytes) minus the 4-byte FCS (RFC 7348 SS5).
        "inner_min_frame_bytes": 60,
    }, None


def _ipsec_params(tunnel: dict[str, Any], header: int) -> tuple[dict[str, Any] | None, str | None]:
    label = _tunnel_label(tunnel)
    encryption, hash_name = tunnel.get("esp_encryption"), tunnel.get("esp_hash")
    if not encryption:
        return None, f"IPsec proposal not collected for tunnel {label}"
    mode = tunnel.get("esp_mode") or "tunnel"
    if mode not in ("tunnel", "transport"):
        return None, f"unrecognized IPsec mode {mode!r} for tunnel {label}"
    if "gcm" in encryption:
        cipher, iv = "aes_gcm", 8
        icv = _ESP_GCM_ICV_BYTES.get(encryption.rsplit("gcm", 1)[-1])
        if icv is None:
            return None, f"unsupported ESP cipher {encryption!r} for tunnel {label}"
    elif encryption.startswith("aes"):
        cipher, iv = "aes_cbc", 16  # The CBC IV length equals the AES block size (RFC 3602 SS2).
        if not hash_name:
            return None, f"IPsec hash not collected for tunnel {label}"
        icv = _ESP_HASH_ICV_BYTES.get(hash_name)
        if icv is None:
            return None, f"unsupported ESP hash {hash_name!r} for tunnel {label}"
    else:
        return None, f"unsupported ESP cipher {encryption!r} for tunnel {label}"
    return {
        "outer_header_bytes": header,
        "mode": mode,
        "cipher": cipher,
        "iv_bytes": iv,
        "icv_bytes": icv,
        "nat_t": str(tunnel.get("endpoint_port")) == "4500",
        "tfc_padding_bytes": 0,
    }, None


def _esp_overhead(
    encryption: str | None, hash_name: str | None, *, mode: str, nat_t: bool, header: int, af: AddressFamily
) -> int | None:
    """ESP overhead in bytes that one proposal adds to a 1500-byte packet, or
    None for an unsupported cipher/hash combination."""
    if not encryption:
        return None
    if "gcm" in encryption:
        cipher, iv = "aes_gcm", 8
        icv = _ESP_GCM_ICV_BYTES.get(encryption.rsplit("gcm", 1)[-1])
    elif encryption.startswith("aes") and hash_name:
        cipher, iv = "aes_cbc", 16
        icv = _ESP_HASH_ICV_BYTES.get(hash_name)
    else:
        return None
    if icv is None:
        return None
    payload = {
        "version": 1,
        "options_complete": True,
        "outer_header_bytes": header,
        "mode": mode,
        "cipher": cipher,
        "iv_bytes": iv,
        "icv_bytes": icv,
        "nat_t": nat_t,
        "tfc_padding_bytes": 0,
    }
    encap = MtuEncapsulation(
        kind="ipsec",
        operation="encapsulate",
        profile_id=PROFILES["ipsec"],
        outer_af=af,
        parameters_json=canonical_json(payload),
    )
    budget, gaps = inner_budget(1500, [encap], original_af=af)
    if gaps or budget is None:
        return None
    return 1500 - budget


def _resolve_esp_proposal(
    tunnel: dict[str, Any], header: int, af: AddressFamily
) -> tuple[dict[str, Any], str]:
    """Choose which esp-group proposal governs this tunnel's inner IP budget.

    `esp_proposals` (canonical JSON, set only when the collector saw every
    proposal in the bound esp-group) lists the proposals in ascending
    proposal-number order. Without usable `esp_proposals`, `esp_encryption`/
    `esp_hash` govern with basis `"single"`. A proposal that `_esp_overhead`
    cannot size is not ranked. With no ranked proposal, the lowest-numbered
    proposal governs with basis `"unranked-of-<n>"`, `n` the proposal count.
    Among ranked proposals of equal overhead, the lowest-numbered one governs
    with basis `"single"` or `"equal-overhead-of-<n>"`. Otherwise the
    largest-overhead one governs with basis `"largest-overhead-of-<n>"`. In
    these bases, `n` is the ranked count. Returns a tunnel dict with the
    chosen proposal's `esp_encryption`/`esp_hash`, and the basis."""
    raw = tunnel.get("esp_proposals")
    proposals: list[dict[str, Any]] = []
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = None
        if isinstance(parsed, list):
            proposals = [p for p in parsed if isinstance(p, dict)]
    if not proposals:
        return tunnel, "single"
    mode = tunnel.get("esp_mode") or "tunnel"
    nat_t = str(tunnel.get("endpoint_port")) == "4500"
    ranked: list[tuple[dict[str, Any], int]] = []
    for p in proposals:
        overhead = _esp_overhead(
            p.get("encryption"), p.get("hash"), mode=mode, nat_t=nat_t, header=header, af=af
        )
        if overhead is not None:
            ranked.append((p, overhead))
    if not ranked:
        first = proposals[0]
        basis = f"unranked-of-{len(proposals)}"
        return {**tunnel, "esp_encryption": first.get("encryption"), "esp_hash": first.get("hash")}, basis
    chosen, basis = ranked[0][0], "single"
    if len(ranked) > 1:
        overheads = [overhead for _, overhead in ranked]
        if len(set(overheads)) == 1:
            basis = f"equal-overhead-of-{len(ranked)}"
        else:
            largest = max(overheads)
            chosen = next(p for p, overhead in ranked if overhead == largest)
            basis = f"largest-overhead-of-{len(ranked)}"
    return {**tunnel, "esp_encryption": chosen.get("encryption"), "esp_hash": chosen.get("hash")}, basis


_PARAM_BUILDERS: dict[str, Callable[[dict[str, Any], int], tuple[dict[str, Any] | None, str | None]]] = {
    "wireguard": _wireguard_params,
    "gre": _gre_params,
    "vxlan": _vxlan_params,
    "ipsec": _ipsec_params,
}


def build_carrier_stack(tunnel: dict[str, Any] | None) -> tuple[list[MtuEncapsulation], str | None]:
    """A one-item encapsulation stack for a carrier crossing, built only from the
    fields the twin collected for this Tunnel.

    Returns the stack and None, or an empty stack and a detail text about the
    field that is missing or unsupported.
    """
    if not tunnel or not tunnel.get("encap"):
        return [], "no tunnel evidence collected for this carrier crossing"
    kind = tunnel["encap"]
    builder = _PARAM_BUILDERS.get(kind)
    if builder is None:
        return [], f"{kind!r} has no supported encapsulation profile"
    af = _outer_af(tunnel)
    if af is None:
        return [], f"outer address family not established for tunnel {_tunnel_label(tunnel)}"
    header = 20 if af == 4 else 40
    proposal_basis: str | None = None
    if kind == "ipsec":
        tunnel, proposal_basis = _resolve_esp_proposal(tunnel, header, af)
    params, missing = builder(tunnel, header)
    if missing or params is None:
        return [], missing or f"{kind!r} carrier options are not modeled"
    payload = {"version": 1, "options_complete": True, **params}
    evidence_uids = sorted({u for u in (tunnel.get("uid"), tunnel.get("interface_uid")) if u})
    return [
        MtuEncapsulation(
            kind=kind,
            operation="encapsulate",
            profile_id=PROFILES[kind],
            outer_af=af,
            parameters_json=canonical_json(payload),
            evidence_uids=evidence_uids,
            proposal_basis=proposal_basis,
            esp_encryption=tunnel.get("esp_encryption") if kind == "ipsec" else None,
            esp_hash=tunnel.get("esp_hash") if kind == "ipsec" else None,
        )
    ], None


def carrier_crossing(trail: Any, subject_uid: str | None, *, tunnel: dict[str, Any] | None = None) -> None:
    """The outer carrier crossing, with the encapsulation stack that
    `build_carrier_stack` builds from the tunnel options."""
    crossing(trail, subject_uid, enforcement="l3")
    capture = _SCOPE.get()
    if not capture or not capture.stages:
        return
    stack, detail = build_carrier_stack(tunnel)
    if detail:
        # The kind "unknown" makes inner_budget return None (MTU_ENCAP_UNKNOWN).
        capture.stages[-1].encapsulation = [MtuEncapsulation(kind="unknown")]
        capture.stages[-1].coverage.gaps.append("MTU_ENCAP_UNKNOWN")
        trail.warn(detail)
    else:
        capture.stages[-1].encapsulation = stack


TOPOLOGY_QUERY = """
UNWIND $subject_uids AS u
MATCH (s:Obj {uid:u, collection_ts:$snap})
WHERE NOT s:Retired AND s._retired_at IS NULL
OPTIONAL MATCH (s)-[r:REALIZED_BY|BOUND_TO]->(p)
WHERE (p:Port OR p:Lag) AND p.collection_ts=$snap AND NOT p:Retired
  AND p._retired_at IS NULL AND r.collection_ts=$snap AND r._retired_at IS NULL
OPTIONAL MATCH (m:Port)-[mr:MEMBER_OF]->(p:Lag)
WHERE m.collection_ts=$snap AND NOT m:Retired AND m._retired_at IS NULL
  AND mr.collection_ts=$snap AND mr._retired_at IS NULL
RETURN s.uid AS subject_uid, properties(s) AS subject,
       p.uid AS carrier_uid, p:Lag AS carrier_is_lag,
       m.uid AS member_uid, mr.eligible AS eligible
ORDER BY subject_uid, carrier_uid, member_uid
LIMIT $row_limit
"""


def _tag_depth_from_name(name: Any) -> int | None:
    """The VLAN tag depth of an interface name, from the count of its dots.

    One dot is a single tag (VyOS `eth0.10`, IOS-XE/XR `Gi0/0/0/0.20`). Two
    dots are a VyOS QinQ vif-s/vif-c pair (`eth0.100.200`). A name without a
    dot is untagged. The depth is capped at 8."""
    if not isinstance(name, str) or not name:
        return None
    return min(name.count("."), 8)


def expand_stages(session: Any, stages: list[MtuStage]) -> list[MtuStage]:
    """Expand each stage along its REALIZED_BY and BOUND_TO edges to ports and
    LAG members.

    For a LAG carrier, a member with `eligible` true is `eligible` and any
    other target is `possible`. A member with `eligible` false is left out.
    All relationships and endpoints must be present in the same pinned
    snapshot. A session without a pinned run returns the stages unchanged.

    The read is bounded to 4096 subjects and 8192 rows. A cut sets
    `coverage.truncated` on every stage.
    """
    if type(getattr(session, "cts", None)) is not int:
        return stages
    import hst.path as path

    subjects = sorted({u for s in stages for u in (s.egress_subject_uid, s.ingress_subject_uid) if u})
    rows: list[dict[str, Any]] = []
    for start in range(0, min(len(subjects), 4096), 256):
        rows.extend(
            path._read(session, TOPOLOGY_QUERY, subject_uids=subjects[start : start + 256], row_limit=8193)
        )
        if len(rows) > 8192:
            break
    truncated = len(rows) > 8192 or len(subjects) > 4096
    by_subject: dict[str, list[dict[str, Any]]] = {}
    for row in rows[:8192]:
        by_subject.setdefault(row["subject_uid"], []).append(row)
    expanded = list(stages)
    for stage in stages:
        subject = stage.egress_subject_uid or stage.ingress_subject_uid
        stage.coverage.truncated |= truncated
        seen: set[str] = set()
        for row in by_subject.get(subject or "", []):
            properties = row.get("subject") or {}
            if (
                hasattr(stage, "fragmentation_supported")
                and properties.get("ip_fragmentation") == "unsupported"
            ):
                stage.fragmentation_supported = False
            member = row.get("member_uid")
            carrier = row.get("carrier_uid")
            if member and row.get("eligible") is False:
                continue
            target = member or carrier
            if not target or target in seen:
                continue
            seen.add(target)
            if len(expanded) >= MAX_STAGES:
                stage.coverage.truncated = True
                break
            clone = stage.model_copy(deep=True)
            clone.stage_id = mtu_fingerprint(stage.stage_id, target)[:24]
            clone.enforcement = "l2"
            clone.context.enforcement = "l2"
            clone.egress_subject_uid = target if clone.context.direction == "tx" else None
            clone.ingress_subject_uid = target if clone.context.direction == "rx" else None
            if clone.context.tag_depth is None:
                clone.context.tag_depth = _tag_depth_from_name(properties.get("name"))
            if row.get("carrier_is_lag"):
                clone.selection = "eligible" if member and row.get("eligible") is True else "possible"
                clone.candidate_set_id = f"{stage.stage_id}:{carrier}"
                clone.candidate_id = target
            expanded.append(clone)
    return expanded
