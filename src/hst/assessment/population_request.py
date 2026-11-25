"""Bind source-population declarations to a pinned assessment request."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from hst import path as pathmod
from hst.core import manifest

from .populations import (
    InventorySnapshot,
    PopulationArtifact,
    PopulationError,
    PopulationSelector,
    materialize_population,
    replay_population,
)


class PopulationBindingError(ValueError):
    pass


MAX_POPULATION_CIDRS = 50_000


@dataclass(frozen=True, slots=True)
class BoundPopulationRequest:
    """The request document persisted with the immutable population result."""

    request: dict[str, Any]
    artifact: PopulationArtifact


_IPAM_QUERY = """
MATCH (ip:IpAddress:Obj)
WHERE NOT ip:Retired AND ip.collection_ts = $snap AND ip.population_source = 'nautobot'
RETURN ip.nautobot_id AS id, ip.ip AS address, ip.vrf_id AS vrf_id,
       ip.namespace_id AS namespace_id, ip.role_id AS role_id, ip.location_id AS location_id,
       ip.tag_ids AS tag_ids
ORDER BY id LIMIT 1000001
"""

_POPULATION_CONTEXT_QUERY = """
MATCH (ip:IpAddress:Obj)-[iv:IN_VRF]->(declared:VrfInstance)
WHERE NOT ip:Retired AND NOT declared:Retired AND iv._retired_at IS NULL
  AND ip.collection_ts = $snap
  AND ip.population_source = 'nautobot'
  AND ip.vrf_id = $vrf_id AND coalesce(ip.namespace_id, '') = $namespace_id
OPTIONAL MATCH (declared)-[:SAME_AS*0..4]-(resolved:VrfInstance)
WHERE NOT resolved:Retired
RETURN collect(DISTINCT coalesce(resolved.uid, declared.uid)) AS contexts
"""


def pinned_inventory(settings: Any, session: Any, snapshot: Any) -> InventorySnapshot:
    """Build population evidence from the graph rows of one published snapshot."""
    if snapshot.cts is None or snapshot.manifest is None:
        raise PopulationBindingError("population binding requires a published pinned snapshot")
    rows = pathmod._read(session, _IPAM_QUERY, snap=snapshot.cts)
    if len(rows) > 1_000_000:
        raise PopulationBindingError("population inventory exceeds the bounded graph read")
    addresses = tuple(
        {
            "id": row.get("id"),
            "address": row.get("address"),
            "vrf_id": row.get("vrf_id"),
            "namespace_id": row.get("namespace_id"),
            "role_id": row.get("role_id"),
            "location_id": row.get("location_id"),
            "tag_ids": row.get("tag_ids") or (),
            "object_type": "ip_address",
        }
        for row in rows
        if isinstance(row, Mapping)
    )
    kinds = {source.name: source.type for source in snapshot.manifest.sources}
    statuses = [
        entry.sections.get("ipam:addresses").status
        for entry in snapshot.manifest.devices
        if kinds.get(entry.source) == "nautobot" and entry.sections.get("ipam:addresses") is not None
    ]
    status = "complete" if statuses and all(value in {"ok", "empty"} for value in statuses) else "incomplete"
    return InventorySnapshot(manifest.digest_of(settings, snapshot.cts), "nautobot", status, addresses)


def bind_pinned_request(
    settings: Any, session: Any, snapshot: Any, request: Mapping[str, Any]
) -> dict[str, Any]:
    """Bind the population selector of a request, or validate its saved artifact.

    Submission and direct evaluation call this function.
    """
    if request.get("population_artifact") is not None:
        value = replay_bound_request(request).request
    elif request.get("population") is None:
        return dict(request)
    else:
        value = bind_request_population(request, pinned_inventory(settings, session, snapshot)).request
    _validate_pinned_context(session, snapshot, value)
    return value


def bind_request_population(
    request: Mapping[str, Any], snapshot: InventorySnapshot
) -> BoundPopulationRequest:
    """Resolve one submitted selector once and replace it with its artifact."""
    value = deepcopy(dict(request))
    if value.get("population_artifact") is not None:
        raise PopulationBindingError("submitted request already carries a population artifact")
    declaration = value.get("population")
    if not isinstance(declaration, Mapping):
        raise PopulationBindingError("population binding requires a population selector")
    try:
        selector = PopulationSelector(**dict(declaration))
        artifact = materialize_population(selector, snapshot)
    except (PopulationError, TypeError) as exc:
        raise PopulationBindingError(str(exc)) from exc
    if value.get("sources"):
        raise PopulationBindingError("a population selector cannot be combined with literal request sources")
    if selector.kind == "nautobot" and not isinstance(value.get("source_context"), str):
        raise PopulationBindingError("a Nautobot population requires an explicit qualified source_context")
    scopes = {member[1] for member in artifact.members}
    if len(scopes) > 1:
        raise PopulationBindingError(
            "a request source population spans qualified VRFs; bind one routing context per request"
        )
    if len(artifact.members) > MAX_POPULATION_CIDRS:
        raise PopulationBindingError("population artifact exceeds the 50,000-CIDR durable request limit")
    value["sources"] = [member[3] for member in artifact.members]
    record = artifact.as_record()
    value["population"] = record["selector"]
    value["population_artifact"] = record
    value["population_complete"] = artifact.complete
    value["population_gaps"] = list(artifact.gaps)
    value["population_scope"] = next(iter(scopes), "")
    return BoundPopulationRequest(value, artifact)


def replay_bound_request(request: Mapping[str, Any]) -> BoundPopulationRequest:
    """Validate a saved artifact and return its original source population."""
    value = deepcopy(dict(request))
    record = value.get("population_artifact")
    if not isinstance(record, Mapping):
        raise PopulationBindingError("saved request has no population artifact")
    try:
        artifact = replay_population(PopulationArtifact.from_record(record))
    except PopulationError as exc:
        raise PopulationBindingError(str(exc)) from exc
    if value.get("population") != artifact.as_record()["selector"]:
        raise PopulationBindingError("saved population selector does not match its artifact")
    if list(value.get("sources") or []) != [member[3] for member in artifact.members]:
        raise PopulationBindingError("saved request sources do not match its population artifact")
    if value.get("population_complete") is not artifact.complete or value.get("population_gaps") != list(
        artifact.gaps
    ):
        raise PopulationBindingError("saved request population completeness does not match its artifact")
    scopes = {member[1] for member in artifact.members}
    if value.get("population_scope") != next(iter(scopes), ""):
        raise PopulationBindingError("saved request population scope does not match its artifact")
    return BoundPopulationRequest(value, artifact)


def validate_population_scope(request: Mapping[str, Any], qualified_scope: str) -> None:
    """Require the adapter's graph-resolved source scope to equal saved IPAM scope."""
    saved = request.get("population_scope")
    if saved is None:
        return
    if not isinstance(saved, str) or not saved or saved != qualified_scope:
        raise PopulationBindingError("population scope does not match the resolved routing context")


def _validate_pinned_context(session: Any, snapshot: Any, request: Mapping[str, Any]) -> None:
    """Check that the pinned graph maps the saved IPAM scope to `source_context`."""
    scope = request.get("population_scope")
    if scope is None:
        return
    context = request.get("source_context")
    if not isinstance(scope, str) or not isinstance(context, str):
        raise PopulationBindingError("population needs an explicit graph-qualified source_context")
    if not scope.startswith("nautobot:"):
        raise PopulationBindingError("population has an unsupported qualified scope")
    _, namespace_id, vrf_id = scope.split(":", 2)
    rows = pathmod._read(
        session,
        _POPULATION_CONTEXT_QUERY,
        snap=snapshot.cts,
        vrf_id=vrf_id,
        namespace_id=namespace_id,
    )
    contexts = {str(value) for row in rows for value in row.get("contexts", ()) if isinstance(value, str)}
    if not contexts:
        raise PopulationBindingError("pinned graph has no verified Nautobot VRF/namespace context mapping")
    if context not in contexts:
        raise PopulationBindingError("population scope does not match the pinned graph source_context")
