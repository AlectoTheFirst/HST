"""Explicit normalized network inputs without live graph handles or vendor defaults."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, fields, is_dataclass, replace
from datetime import datetime
from typing import Literal

from hst.policy.ir import Constant, ExecutionContext, Policy, Predicate

from .evidence import EvidenceEvaluation

Terminal = Literal["permit", "deny", "no_route", "unknown"]
ALWAYS = Constant(True)
# One `left_estate` object of the tracer (`hst.path.trace.estate_exit`) as
# its (key, value) pairs in the tracer's key order. The pairs are hashable,
# and `dict()` returns the object.
ExitRecord = tuple[tuple[str, str | None], ...]
# A field that a model fingerprint leaves out while it is empty.
_OMIT_EMPTY = {"fingerprint": "omit-empty"}


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    source: str
    subject: str
    section: str
    address_family: int | None = None
    vrf: str = ""


@dataclass(frozen=True, slots=True)
class StateKey:
    location: str
    context: ExecutionContext
    stage: str = "forward"
    tunnel_stack: tuple[str, ...] = ()
    binding_scope: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.location or not self.stage:
            raise ValueError("location and stage are required")
        object.__setattr__(self, "tunnel_stack", tuple(self.tunnel_stack))
        object.__setattr__(self, "binding_scope", tuple(self.binding_scope))


@dataclass(frozen=True, slots=True)
class ChoiceAssignment:
    """One complete joint assignment, supplied by the normalized model producer."""

    uid: str
    bindings: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        value = tuple(sorted(tuple(pair) for pair in self.bindings))
        if not self.uid or any(not scope or not choice for scope, choice in value):
            raise ValueError("choice identities cannot be empty")
        if len({scope for scope, _ in value}) != len(value):
            raise ValueError("one assignment per choice scope is required")
        object.__setattr__(self, "bindings", value)


@dataclass(frozen=True, slots=True)
class RangeRewriteSpec:
    field: str
    source_low: int
    source_high: int
    target_low: int


@dataclass(frozen=True, slots=True)
class EdgeSpec:
    uid: str
    target: StateKey
    predicate: Predicate = ALWAYS
    rewrites: tuple[tuple[str, int], ...] = ()
    choices: tuple[tuple[str, str], ...] = ()
    evidence: tuple[str, ...] = ()
    ranges: tuple[RangeRewriteSpec, ...] = ()

    def __post_init__(self) -> None:
        if not self.uid:
            raise ValueError("edge identity is required")
        for name in ("rewrites", "choices"):
            value = tuple(sorted(tuple(pair) for pair in getattr(self, name)))
            if len({key for key, _ in value}) != len(value):
                raise ValueError(f"duplicate {name} keys")
            object.__setattr__(self, name, value)
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "ranges", tuple(self.ranges))


@dataclass(frozen=True, slots=True)
class NodeSpec:
    key: StateKey
    edges: tuple[EdgeSpec, ...] = ()
    terminal: Terminal | None = None
    policy: Policy | None = None
    complete: bool = True
    evidence: tuple[EvidenceRef, ...] = ()
    policy_bank: Literal["current", "original"] = "current"
    # The `left_estate` objects of the tracer for a terminal where the path
    # leaves the estate at its edge. No outcome reads them.
    left_estate: tuple[ExitRecord, ...] = field(default=(), metadata=_OMIT_EMPTY)
    # Why an incomplete node is incomplete (`Network.incomplete` of a routing
    # state). No outcome reads it.
    incomplete_reasons: tuple[str, ...] = field(default=(), metadata=_OMIT_EMPTY)
    # The uids of the source NAT edges of this node whose source port the
    # device picks (a masquerade that the model keeps decided). The reply
    # model checks no state before the device reads that port.
    free_source_ports: tuple[str, ...] = field(default=(), metadata=_OMIT_EMPTY)

    def __post_init__(self) -> None:
        object.__setattr__(self, "edges", tuple(self.edges))
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "left_estate", tuple(self.left_estate))
        object.__setattr__(self, "incomplete_reasons", tuple(self.incomplete_reasons))
        object.__setattr__(self, "free_source_ports", tuple(self.free_source_ports))
        if not set(self.free_source_ports) <= {edge.uid for edge in self.edges}:
            raise ValueError("a free source port names an edge of the node")
        if self.left_estate and self.terminal is None:
            raise ValueError("only a terminal leaves the estate")
        if self.incomplete_reasons and self.complete:
            raise ValueError("only an incomplete node has a reason to be incomplete")
        if type(self.complete) is not bool:
            raise ValueError("node completeness must be an explicit boolean")
        if self.terminal not in {None, "permit", "deny", "no_route", "unknown"}:
            raise ValueError("invalid terminal outcome")
        if self.terminal is not None and self.edges:
            raise ValueError("a terminal node cannot also forward")
        if len({edge.uid for edge in self.edges}) != len(self.edges):
            raise ValueError("edge identities must be unique within a node")
        if self.policy is not None and self.policy.context != self.key.context:
            raise ValueError("policy binding crosses execution contexts")
        if self.policy_bank not in {"current", "original"}:
            raise ValueError("policy bank must be current or original")


@dataclass(frozen=True, slots=True)
class EntrySpec:
    key: StateKey
    predicate: Predicate = ALWAYS
    choices: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        value = tuple(sorted(tuple(pair) for pair in self.choices))
        if len({scope for scope, _ in value}) != len(value):
            raise ValueError("duplicate entry choice scopes")
        object.__setattr__(self, "choices", value)


@dataclass(frozen=True, slots=True)
class ModelInput:
    manifest_digest: str
    nodes: tuple[NodeSpec, ...]
    entries: tuple[EntrySpec, ...]
    choices: tuple[ChoiceAssignment, ...]
    choices_complete: bool
    schema_version: int = 1
    evidence: EvidenceEvaluation | None = None

    def __post_init__(self) -> None:
        if len(self.manifest_digest) != 64 or any(c not in "0123456789abcdef" for c in self.manifest_digest):
            raise ValueError("a pinned lowercase SHA-256 manifest digest is required")
        for name in ("nodes", "entries", "choices"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        if type(self.choices_complete) is not bool:
            raise ValueError("choice completeness must be an explicit boolean")
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError("unsupported model input schema")
        if len({node.key for node in self.nodes}) != len(self.nodes):
            raise ValueError("duplicate qualified node identity")
        if len({choice.uid for choice in self.choices}) != len(self.choices):
            raise ValueError("duplicate joint choice identity")
        if len({choice.bindings for choice in self.choices}) != len(self.choices):
            raise ValueError("duplicate joint choice assignments")
        scopes = {scope for node in self.nodes for edge in node.edges for scope, _ in edge.choices}
        scopes.update(scope for entry in self.entries for scope, _ in entry.choices)
        for choice in self.choices:
            if not scopes <= dict(choice.bindings).keys():
                raise ValueError("joint choices must assign every referenced scope")


def semantic_fingerprint(model: ModelInput) -> str:
    """Stable typed content identity, independent of input node/edge row order."""

    # Rule order inside policy dataclasses is significant.
    nodes = tuple(
        sorted(
            (replace(node, edges=tuple(sorted(node.edges, key=lambda e: e.uid))) for node in model.nodes),
            key=lambda n: repr(n.key),
        )
    )
    normalized = replace(
        model,
        nodes=nodes,
        entries=tuple(sorted(model.entries, key=repr)),
        choices=tuple(sorted(model.choices, key=lambda c: c.uid)),
    )
    return semantic_value_fingerprint(normalized)


def semantic_value_fingerprint(value: object) -> str:
    """Stable digest for one immutable normalized-model value."""

    def encode(item: object) -> object:
        if isinstance(item, datetime):
            return item.isoformat()
        if isinstance(item, NodeSpec):
            item = replace(item, edges=tuple(sorted(item.edges, key=lambda edge: edge.uid)))
        if is_dataclass(item) and not isinstance(item, type):
            return {
                "type": type(item).__name__,
                **{
                    field.name: encode(getattr(item, field.name))
                    for field in fields(item)
                    if not (field.metadata == _OMIT_EMPTY and not getattr(item, field.name))
                },
            }
        if isinstance(item, (tuple, list)):
            return [encode(child) for child in item]
        if isinstance(item, frozenset):
            return sorted(item)
        return item

    payload = json.dumps(encode(value), sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(payload.encode()).hexdigest()


def evidence_dependency_fingerprints(
    evidence: EvidenceEvaluation | None,
) -> tuple[str, dict[EvidenceRef, str]]:
    """Digest evidence once, partitioned by the exact dependency reference."""
    if evidence is None:
        return semantic_value_fingerprint(None), {}
    buckets: dict[EvidenceRef, list[object]] = {}
    for window in evidence.windows:
        window_ref = EvidenceRef(
            window.source,
            window.subject,
            window.section,
            window.address_family,
            window.vrf,
        )
        buckets.setdefault(window_ref, []).append(window)
    for gap in evidence.gaps:
        gap_ref = EvidenceRef(
            gap.source,
            gap.subject,
            gap.section,
            gap.address_family,
            gap.vrf,
        )
        buckets.setdefault(gap_ref, []).append(gap)
    global_digest = semantic_value_fingerprint((evidence.analysis_time, evidence.policy))
    return global_digest, {
        bucket_ref: semantic_value_fingerprint(tuple(values)) for bucket_ref, values in buckets.items()
    }
