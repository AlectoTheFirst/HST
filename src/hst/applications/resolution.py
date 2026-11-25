"""Deterministic application resolution and requirement compilation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Protocol

from fastapi import HTTPException

from hst import path as pathmod
from hst.applications.models import (
    BusinessApplicationDefinition,
    Connection,
    DestinationCondition,
    InventoryReference,
)
from hst.applications.yaml_format import definition_digest
from hst.assessment.evaluation import RequestBody, _request_from_body

MAX_RESOLVED_ADDRESSES = 10_000


@dataclass(frozen=True)
class AddressBinding:
    address: str
    context: str | None = None
    object_uid: str | None = None


@dataclass(frozen=True)
class InventoryCandidate:
    uid: str
    kind: str
    addresses: tuple[AddressBinding, ...] = ()
    evidence: tuple[str, ...] = ()
    complete: bool = True


class InventoryReader(Protocol):
    def resolve(self, reference: InventoryReference, snapshot: dict) -> list[InventoryCandidate]: ...


class StaticInventoryReader:
    def __init__(self, candidates: dict[str, list[InventoryCandidate]]) -> None:
        self.candidates = candidates

    def resolve(self, reference: InventoryReference, snapshot: dict) -> list[InventoryCandidate]:
        return list(self.candidates.get(reference.uid, []))


_GRAPH_REFERENCE = """
MATCH (n:Obj {uid:$uid, collection_ts:$snap}) WHERE NOT n:Retired
OPTIONAL MATCH (n)-[address_rel:HAS_IP|RESOLVES_TO]->(address:Obj)
WHERE address_rel.collection_ts = $snap AND address_rel._retired_at IS NULL
 AND address.collection_ts = $snap AND NOT address:Retired
OPTIONAL MATCH (n)-[context_rel:IN_VRF]->(context:VrfInstance)
WHERE context_rel.collection_ts = $snap AND context_rel._retired_at IS NULL
 AND context.collection_ts = $snap AND NOT context:Retired
WITH n, [b IN collect(DISTINCT {
 address:coalesce(address.ip,address.cidr,address.prefix,n.ip,n.cidr,n.prefix),
 context:context.uid}) WHERE b.address IS NOT NULL] AS all_bindings
RETURN n.uid AS uid, labels(n) AS labels, all_bindings[0..10001] AS bindings,
 size(all_bindings) AS binding_count,
 coalesce(n.evidence_reference,n.raw_evidence_ref) AS evidence
"""

# Graph label to inventory reference kind.
LABEL_KIND = {
    "Device": "device",
    "Interface": "interface",
    "IpAddress": "ip",
    "Prefix": "network",
    "DnsRecord": "dns",
    "ServiceRequirement": "service_requirement",
    "VrfInstance": "vrf",
    "IdentityGroup": "identity",
    "ZpaAppSegment": "segment",
}


class GraphInventoryReader:
    """The lookup of a UID in the pinned graph snapshot."""

    def __init__(self, session: object, snapshot_cts: int) -> None:
        self.session = session
        self.snapshot_cts = snapshot_cts

    def resolve(self, reference: InventoryReference, snapshot: dict) -> list[InventoryCandidate]:
        rows = pathmod._read(self.session, _GRAPH_REFERENCE, uid=reference.uid, snap=self.snapshot_cts)
        candidates = []
        for row in rows:
            kind = next((LABEL_KIND[label] for label in row["labels"] if label in LABEL_KIND), "unsupported")
            bindings = tuple(
                sorted(
                    (
                        AddressBinding(str(value["address"]), value.get("context"), row["uid"])
                        for value in row.get("bindings", [])
                        if value.get("address") is not None
                    ),
                    key=lambda item: (item.context or "", item.address, item.object_uid or ""),
                )
            )
            candidates.append(
                InventoryCandidate(
                    uid=row["uid"],
                    kind=kind,
                    addresses=bindings,
                    evidence=(str(row["evidence"]),) if row.get("evidence") else (),
                    complete=int(row.get("binding_count", 0)) <= len(bindings),
                )
            )
        return candidates


@dataclass(frozen=True)
class ResolutionIssue:
    code: str
    path: str
    detail: str
    severity: str = "error"


@dataclass
class ResolvedMember:
    id: str
    bindings: list[AddressBinding] = field(default_factory=list)
    inventory_uid: str | None = None
    evidence: list[str] = field(default_factory=list)


def resolve_application(
    definition: BusinessApplicationDefinition,
    *,
    revision: int,
    snapshot: dict,
    reader: InventoryReader,
    service_ids: list[str] | None = None,
    connection_ids: list[str] | None = None,
) -> dict:
    identity = str(snapshot.get("snapshot") or snapshot.get("collection_ts") or "")
    if not identity or identity == "latest":
        raise ValueError("application resolution requires a pinned snapshot identity")
    services = {service.id: service for service in definition.services}
    connections = {connection.id: connection for connection in definition.connections}
    selected: list[str] = []
    for service_id in service_ids or []:
        if service_id not in services:
            raise ValueError(f"unknown service {service_id}")
        selected.extend(services[service_id].connection_ids)
    selected.extend(connection_ids or [])
    if not service_ids and not connection_ids:
        selected = [connection.id for connection in definition.connections]
    selected = list(dict.fromkeys(selected))
    unknown = [identifier for identifier in selected if identifier not in connections]
    if unknown:
        raise ValueError(f"unknown connections: {', '.join(unknown)}")

    groups = {group.id: group for group in definition.groups}
    resolved_groups: dict[str, dict[str, ResolvedMember]] = {}
    group_issues: dict[str, list[ResolutionIssue]] = {}
    resolved_address_count = 0
    for group_id in dict.fromkeys(
        endpoint
        for identifier in selected
        for endpoint in (connections[identifier].source, connections[identifier].destination)
    ):
        members: dict[str, ResolvedMember] = {}
        issues: list[ResolutionIssue] = []
        for member in groups[group_id].members:
            path = f"groups.{group_id}.members.{member.id}"
            if member.address is not None:
                members[member.id] = ResolvedMember(
                    id=member.id,
                    bindings=[AddressBinding(member.address, member.context)],
                )
                continue
            if member.placeholder is not None:
                # A connection that uses the group of a placeholder member stays unresolved.
                issues.append(
                    ResolutionIssue(
                        "member-placeholder",
                        path,
                        f"unbound placeholder ({member.placeholder.status})",
                    )
                )
                members[member.id] = ResolvedMember(id=member.id)
                continue
            reference = member.inventory
            if reference is None:
                raise ValueError(f"{path} has no address source")
            candidates = reader.resolve(reference, snapshot)
            if not candidates:
                issues.append(
                    ResolutionIssue(
                        "inventory-not-found",
                        path,
                        f"{reference.uid} was not found at snapshot {identity}",
                    )
                )
                members[member.id] = ResolvedMember(id=member.id, inventory_uid=reference.uid)
                continue
            if len(candidates) > 1:
                issues.append(
                    ResolutionIssue(
                        "inventory-ambiguous",
                        path,
                        f"{reference.uid} resolved to {len(candidates)} objects",
                    )
                )
                members[member.id] = ResolvedMember(id=member.id, inventory_uid=reference.uid)
                continue
            candidate = candidates[0]
            if candidate.kind != reference.kind:
                issues.append(
                    ResolutionIssue(
                        "inventory-kind-mismatch",
                        path,
                        f"expected {reference.kind}, found {candidate.kind}",
                    )
                )
            bindings = sorted(
                [binding for binding in candidate.addresses if reference.context in {None, binding.context}],
                key=lambda item: (item.context or "", item.address, item.object_uid or ""),
            )
            if not candidate.complete:
                issues.append(
                    ResolutionIssue(
                        "inventory-read-incomplete",
                        path,
                        f"{reference.uid} exceeded the {MAX_RESOLVED_ADDRESSES}-address read bound",
                    )
                )
            resolved_address_count += len(bindings)
            if resolved_address_count > MAX_RESOLVED_ADDRESSES:
                raise ValueError(f"resolved scope exceeds {MAX_RESOLVED_ADDRESSES} addresses")
            if not bindings:
                issues.append(
                    ResolutionIssue(
                        "inventory-address-unavailable",
                        path,
                        "the referenced object has no address in the requested context",
                    )
                )
            members[member.id] = ResolvedMember(
                id=member.id,
                bindings=bindings,
                inventory_uid=candidate.uid,
                evidence=sorted(candidate.evidence),
            )
        resolved_groups[group_id] = members
        group_issues[group_id] = issues

    resolved_connections = []
    all_issues: list[ResolutionIssue] = []
    if not selected:
        all_issues.append(
            ResolutionIssue(
                "no-connections-selected",
                "selection.connection_ids",
                "no connection is selected or associated with the selected services",
            )
        )
    for identifier in selected:
        connection = connections[identifier]
        issues = [*group_issues[connection.source], *group_issues[connection.destination]]
        request, compile_issues = _compile_connection(connection, groups, resolved_groups)
        issues.extend(compile_issues)
        all_issues.extend(issues)
        owner_service_id: str | None = next(
            (service.id for service in definition.services if identifier in service.connection_ids), None
        )
        resolved_connections.append(
            {
                "id": identifier,
                "service_id": owner_service_id,
                "readiness": "ready" if request is not None and not issues else "unresolved",
                "request": request.model_dump(mode="json", exclude_none=True) if request else None,
                "issues": [asdict(issue) for issue in issues],
            }
        )
    groups_document = {
        group_id: {
            member_id: {
                "bindings": [asdict(binding) for binding in member.bindings],
                "inventory_uid": member.inventory_uid,
                "evidence": member.evidence,
            }
            for member_id, member in members.items()
        }
        for group_id, members in resolved_groups.items()
    }
    total = sum(len(member.bindings) for members in resolved_groups.values() for member in members.values())
    if total > MAX_RESOLVED_ADDRESSES:
        raise ValueError(f"resolved scope exceeds {MAX_RESOLVED_ADDRESSES} addresses")
    document = {
        "schema_version": 1,
        "application": {
            "id": definition.id,
            "revision": revision,
            "digest": definition_digest(definition),
        },
        "snapshot": snapshot,
        "selection": {"service_ids": service_ids or [], "connection_ids": selected},
        "groups": groups_document,
        "connections": resolved_connections,
        "issues": [asdict(issue) for issue in _deduplicate_issues(all_issues)],
        "ready": bool(resolved_connections)
        and all(connection["readiness"] == "ready" for connection in resolved_connections),
    }
    document["digest"] = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    return document


def _compile_connection(
    connection: Connection,
    groups: dict,
    resolved: dict[str, dict[str, ResolvedMember]],
) -> tuple[RequestBody | None, list[ResolutionIssue]]:
    issues: list[ResolutionIssue] = []
    source_context = connection.source_context.vrf if connection.source_context else None
    destination_context = connection.destination_context.vrf if connection.destination_context else None
    source_bindings = [
        binding
        for member in resolved[connection.source].values()
        for binding in member.bindings
        if source_context in {None, binding.context}
    ]
    context_values = {binding.context for binding in source_bindings}
    if source_context is None and len(context_values) > 1:
        issues.append(
            ResolutionIssue(
                "source-context-ambiguous",
                f"connections.{connection.id}.source_context",
                "source addresses occupy multiple contexts; select one explicitly",
            )
        )
    effective_source_context = (
        source_context if source_context is not None else next(iter(context_values), None)
    )
    members = []
    destination_context_values: set[str | None] = set()
    for member in groups[connection.destination].members:
        bindings = [
            binding
            for binding in resolved[connection.destination][member.id].bindings
            if destination_context in {None, binding.context}
        ]
        destination_context_values.update(binding.context for binding in bindings)
        if bindings:
            members.append(
                {
                    "name": member.id,
                    "addresses": sorted({binding.address for binding in bindings}),
                    "proto": connection.protocol,
                    "port": _ports(connection.destination_ports),
                    "source_port": _ports(connection.source_ports),
                }
            )
    if destination_context is None and len(destination_context_values) > 1:
        issues.append(
            ResolutionIssue(
                "destination-context-ambiguous",
                f"connections.{connection.id}.destination_context",
                "destination addresses occupy multiple contexts; select one explicitly",
            )
        )
    effective_destination_context = (
        destination_context
        if destination_context is not None
        else next(iter(destination_context_values), None)
    )
    if not source_bindings:
        issues.append(
            ResolutionIssue(
                "source-empty", f"connections.{connection.id}.source", "source group resolved to no addresses"
            )
        )
    if not members:
        issues.append(
            ResolutionIssue(
                "destination-empty",
                f"connections.{connection.id}.destination",
                "destination group resolved to no addresses",
            )
        )
    if issues:
        return None, _deduplicate_issues(issues)
    context = connection.source_context
    try:
        request = RequestBody.model_validate(
            {
                "name": connection.name,
                "destination": groups[connection.destination].name,
                "sources": sorted({binding.address for binding in source_bindings}),
                "members": members,
                "condition": _condition_document(connection.destination_condition),
                "proto": connection.protocol,
                "port": _ports(connection.destination_ports),
                "source_port": _ports(connection.source_ports),
                "success": connection.success,
                "source_context": effective_source_context,
                "source_device_uid": context.device_uid if context else None,
                "identity_uid": context.identity_uid if context else None,
                "segment_uid": context.segment_uid if context else None,
                "ingress_interface_uid": context.ingress_interface_uid if context else None,
                "destination_context": effective_destination_context,
                "header_constraints": connection.header_constraints,
                "mtu": connection.mtu.model_dump(mode="json") if connection.mtu else None,
            }
        )
    except ValueError as exc:
        return None, [ResolutionIssue("requirement-invalid", f"connections.{connection.id}", str(exc))]
    try:
        # `_request_from_body` builds the request set of the engine. It refuses, for
        # example, a connection whose source and destination share no address family.
        _request_from_body(request)
    except HTTPException as exc:
        return None, [ResolutionIssue("requirement-invalid", f"connections.{connection.id}", str(exc.detail))]
    return request, []


def _condition_document(condition: DestinationCondition) -> dict[str, object]:
    if condition.kind == "member":
        return {"kind": "member", "member": condition.member}
    value: dict[str, object] = {
        "kind": condition.kind,
        "parts": [_condition_document(part) for part in condition.parts],
    }
    if condition.n is not None:
        value["n"] = condition.n
    return value


def _ports(values: list[int | str] | None) -> str | None:
    return ",".join(str(value) for value in values) if values else None


def _deduplicate_issues(issues: list[ResolutionIssue]) -> list[ResolutionIssue]:
    return list({(issue.code, issue.path, issue.detail): issue for issue in issues}.values())
