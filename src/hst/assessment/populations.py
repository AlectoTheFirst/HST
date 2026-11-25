"""Pinned, materialized source populations for symbolic assessments."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from types import MappingProxyType
from typing import Any, Literal


class PopulationError(ValueError):
    pass


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_Network = IPv4Network | IPv6Network


@dataclass(frozen=True, slots=True)
class PopulationSelector:
    """A selector evaluated once against one captured inventory snapshot."""

    kind: Literal["manual", "nautobot"]
    vrf_id: str | None = None
    role_id: str | None = None
    tag_ids: tuple[str, ...] = ()
    namespace_id: str | None = None
    location_id: str | None = None
    object_uids: tuple[str, ...] = ()
    prefixes: tuple[str, ...] = ()
    literals: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in {"manual", "nautobot"}:
            raise PopulationError(f"unsupported population selector kind: {self.kind!r}")
        object.__setattr__(self, "tag_ids", tuple(sorted(set(self.tag_ids))))
        object.__setattr__(self, "object_uids", tuple(sorted(set(self.object_uids))))
        object.__setattr__(self, "prefixes", tuple(sorted({str(value) for value in self.prefixes})))
        object.__setattr__(self, "literals", tuple(str(value) for value in self.literals))
        for prefix in self.prefixes:
            try:
                ip_network(prefix, strict=False)
            except ValueError as exc:
                raise PopulationError(f"invalid population prefix: {prefix!r}") from exc
        inventory_fields = (
            self.vrf_id,
            self.role_id,
            self.tag_ids,
            self.namespace_id,
            self.location_id,
            self.object_uids,
            self.prefixes,
        )
        if self.kind == "manual":
            if not self.literals or any(inventory_fields):
                raise PopulationError("manual population needs literals and no inventory selectors")
        elif self.literals or not any(inventory_fields):
            raise PopulationError("Nautobot population needs at least one inventory selector")


@dataclass(frozen=True, slots=True)
class InventorySnapshot:
    manifest_digest: str
    source: str
    status: str
    addresses: tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if not _DIGEST.fullmatch(self.manifest_digest):
            raise PopulationError("inventory snapshot requires lowercase SHA-256 manifest digest")
        object.__setattr__(
            self,
            "addresses",
            tuple(
                MappingProxyType({str(key): _freeze(value) for key, value in row.items()})
                for row in self.addresses
            ),
        )


@dataclass(frozen=True, slots=True)
class PopulationArtifact:
    selector: PopulationSelector
    manifest_digest: str
    # (source-qualified object uid, qualified VRF, address family, CIDR)
    members: tuple[tuple[str, str, int, str], ...]
    complete: bool
    gaps: tuple[str, ...]
    digest: str
    version: int = 1

    def __post_init__(self) -> None:
        if self.version != 1:
            raise PopulationError(f"unsupported population artifact version: {self.version}")
        if not _DIGEST.fullmatch(self.manifest_digest) or not _DIGEST.fullmatch(self.digest):
            raise PopulationError("population artifact needs lowercase SHA-256 digests")
        values: set[tuple[str, str, int, str]] = set()
        for member in self.members:
            if len(member) != 4:
                raise PopulationError("population artifact member is malformed")
            origin, vrf, family, cidr = member
            if (
                not isinstance(origin, str)
                or not isinstance(vrf, str)
                or family not in {4, 6}
                or not isinstance(cidr, str)
            ):
                raise PopulationError("population artifact member is malformed")
            values.add((origin, vrf, family, cidr))
        normalized = tuple(sorted(values))
        for _, _, family, value in normalized:
            network = ip_network(value, strict=False)
            if network.version != family:
                raise PopulationError("population artifact member has wrong address family")
        object.__setattr__(self, "members", normalized)
        object.__setattr__(self, "gaps", tuple(sorted(set(self.gaps))))
        if self.digest != _artifact_digest(
            self.selector, self.manifest_digest, normalized, self.complete, self.gaps, self.version
        ):
            raise PopulationError("population artifact digest does not match contents")

    @property
    def address_count(self) -> int:
        """The count of addresses in the union of the members, per qualified VRF and family."""
        by_scope: dict[tuple[str, int], list[_Network]] = {}
        for _, vrf, family, value in self.members:
            by_scope.setdefault((vrf, family), []).append(ip_network(value, strict=False))
        return sum(_union_count(values) for values in by_scope.values())

    def as_record(self) -> dict[str, Any]:
        """The artifact as a JSON-safe record with its digest."""
        return {
            "version": self.version,
            "selector": asdict(self.selector),
            "manifest_digest": self.manifest_digest,
            "members": [list(member) for member in self.members],
            "complete": self.complete,
            "gaps": list(self.gaps),
            "digest": self.digest,
        }

    @classmethod
    def from_record(cls, value: Mapping[str, Any]) -> PopulationArtifact:
        try:
            selector = PopulationSelector(**dict(value["selector"]))
            members = tuple(tuple(member) for member in value["members"])
            return cls(
                selector,
                str(value["manifest_digest"]),
                members,
                bool(value["complete"]),
                tuple(str(gap) for gap in value["gaps"]),
                str(value["digest"]),
                int(value["version"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PopulationError("population artifact record is malformed") from exc


def materialize_population(selector: PopulationSelector, snapshot: InventorySnapshot) -> PopulationArtifact:
    gaps: list[str] = []
    members: dict[tuple[str, int, str], str] = {}
    if selector.kind == "manual":
        for ordinal, literal in enumerate(selector.literals):
            value = ip_network(literal, strict=False)
            members[("manual", value.version, str(value))] = f"manual:{ordinal}"
    else:
        if snapshot.source != "nautobot":
            gaps.append("INVENTORY_SOURCE_MISMATCH")
        if snapshot.status not in {"complete", "complete-empty"}:
            gaps.append("INVENTORY_NOT_COMPLETE")
        for row in snapshot.addresses:
            if not _matches(selector, row):
                continue
            try:
                value = _row_network(row)
            except ValueError:
                gaps.append("INVENTORY_ADDRESS_UNPARSED")
                continue
            vrf = str(row.get("vrf_id") or "")
            namespace = str(row.get("namespace_id") or "")
            object_id = str(row.get("id") or row.get("object_uid") or "")
            if not vrf:
                gaps.append("INVENTORY_VRF_MISSING")
                continue
            if not object_id:
                gaps.append("INVENTORY_OBJECT_ID_MISSING")
                continue
            key = (f"nautobot:{namespace}:{vrf}", value.version, str(value))
            origin = f"nautobot:{namespace}:{object_id}"
            members[key] = min(origin, members.get(key, origin))
    values = tuple(
        sorted((origin, scope, family, value) for (scope, family, value), origin in members.items())
    )
    gap_values = tuple(sorted(set(gaps)))
    complete = not gap_values
    return PopulationArtifact(
        selector=selector,
        manifest_digest=snapshot.manifest_digest,
        members=values,
        complete=complete,
        gaps=gap_values,
        digest=_artifact_digest(selector, snapshot.manifest_digest, values, complete, gap_values, 1),
    )


def replay_population(artifact: PopulationArtifact) -> PopulationArtifact:
    """Validate a saved artifact and return it. The constructor checks its digest."""
    return PopulationArtifact(
        artifact.selector,
        artifact.manifest_digest,
        artifact.members,
        artifact.complete,
        artifact.gaps,
        artifact.digest,
        artifact.version,
    )


def _row_network(row: Mapping[str, Any]) -> _Network:
    raw = str(row.get("address") or row.get("prefix") or "")
    if not raw:
        raise ValueError("missing address")
    kind = str(row.get("object_type") or row.get("type") or "ip_address").lower()
    if kind in {"prefix", "ipam.prefix"}:
        return ip_network(raw, strict=False)
    return ip_network(ip_address(raw.split("/", 1)[0]))


def _matches(selector: PopulationSelector, row: Mapping[str, Any]) -> bool:
    if selector.vrf_id and str(row.get("vrf_id")) != selector.vrf_id:
        return False
    if selector.role_id and str(row.get("role_id")) != selector.role_id:
        return False
    if selector.namespace_id and str(row.get("namespace_id")) != selector.namespace_id:
        return False
    if selector.location_id and str(row.get("location_id")) != selector.location_id:
        return False
    object_id = str(row.get("id") or row.get("object_uid") or "")
    if selector.object_uids and object_id not in selector.object_uids:
        return False
    try:
        value = _row_network(row)
    except ValueError:
        return False
    if selector.prefixes and not any(
        value.version == selected.version
        and int(value.network_address) >= int(selected.network_address)
        and int(value.broadcast_address) <= int(selected.broadcast_address)
        for prefix in selector.prefixes
        for selected in (ip_network(prefix, strict=False),)
    ):
        return False
    tags = {str(item) for item in row.get("tag_ids") or ()}
    return not selector.tag_ids or set(selector.tag_ids) <= tags


def _union_count(networks: list[_Network]) -> int:
    """Count the addresses in the union of CIDRs of one family from their merged ranges."""
    ranges = sorted((int(network.network_address), int(network.broadcast_address)) for network in networks)
    total = 0
    current_start: int | None = None
    current_end: int | None = None
    for start, end in ranges:
        if current_start is None:
            current_start, current_end = start, end
            continue
        if current_end is None:
            raise PopulationError("address union lost its current range")
        if start > current_end + 1:
            total += current_end - current_start + 1
            current_start, current_end = start, end
        else:
            current_end = max(current_end, end)
    if current_start is None:
        return total
    if current_end is None:
        raise PopulationError("address union lacks its final range")
    return total + current_end - current_start + 1


def _artifact_digest(
    selector: PopulationSelector,
    manifest_digest: str,
    members: tuple[tuple[str, str, int, str], ...],
    complete: bool,
    gaps: tuple[str, ...],
    version: int,
) -> str:
    payload = {
        "version": version,
        "selector": asdict(selector),
        "manifest": manifest_digest,
        "members": members,
        "complete": complete,
        "gaps": gaps,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return tuple(sorted((str(key), _freeze(item)) for key, item in value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value
