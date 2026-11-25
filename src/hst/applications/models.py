"""The models of the Business Application schema, versions 1 and 2."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from typing import Annotated, Any, Literal
from typing import Protocol as TypingProtocol

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    model_validator,
)
from pydantic.config import JsonDict

from hst.core.mtu import MtuRequest

Identifier = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{0,62}$")]
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]

# The routes use these path segments under /api/business-applications/ for
# POST .../validate and for the generation routes under .../generations. A new
# revision cannot take one of them as its application id. A stored definition
# is read back without this check.
RESERVED_APPLICATION_IDS = frozenset({"generations", "validate"})
# The validation context key that marks a document as the input of a new
# revision. `parse_application_source` sets it, and it turns on the reserved
# id check.
NEW_REVISION = "new_revision"


def check_application_id(value: str) -> str:
    """Return `value`, or raise `ValueError` for a reserved application id."""
    if value in RESERVED_APPLICATION_IDS:
        raise ValueError(f"{value} is a reserved application id")
    return value


def _unreserved(value: str, info: ValidationInfo) -> str:
    if isinstance(info.context, dict) and info.context.get(NEW_REVISION):
        check_application_id(value)
    return value


ApplicationIdentifier = Annotated[Identifier, AfterValidator(_unreserved)]

MAX_SERVICES = 200
MAX_GROUPS = 500
MAX_CONNECTIONS = 1000
MAX_MEMBERS = 2000
MAX_ASSOCIATIONS = 1000


InventoryKind = Literal[
    "device", "interface", "ip", "network", "dns", "service_requirement", "vrf", "identity", "segment"
]

# The JSON Schema form of the 2 placeholder rules of
# `BusinessApplicationDefinition.valid_references`. A document with a placeholder
# member states schema_version 2 and has the state `draft`. The inner `properties`
# makes an explicit `placeholder: null` count as no placeholder, as it does in the model.
_PLACEHOLDER_RULE: JsonDict = {
    "if": {
        "required": ["groups"],
        "properties": {
            "groups": {
                "contains": {
                    "required": ["members"],
                    "properties": {
                        "members": {
                            "contains": {
                                "required": ["placeholder"],
                                "properties": {"placeholder": {"type": "object"}},
                            }
                        }
                    },
                }
            }
        },
    },
    "then": {
        "required": ["schema_version"],
        "properties": {"schema_version": {"const": 2}, "state": {"const": "draft"}},
    },
}


class ApplicationModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class InventoryReference(ApplicationModel):
    kind: InventoryKind
    uid: str = Field(min_length=1, max_length=500)
    role: Literal["source", "destination", "component", "shared"] = "component"
    context: str | None = Field(default=None, min_length=1, max_length=500)


class Placeholder(ApplicationModel):
    """Schema version 2. A described object that is not bound to inventory yet."""

    # the phrase from the description
    text: str = Field(min_length=1, max_length=500)
    expected_kind: InventoryKind | None = None
    status: Literal["unresolved", "ambiguous"] = "unresolved"
    # the uids seen in lookups
    candidates: list[str] = Field(default_factory=list, max_length=20)
    note: str | None = Field(default=None, max_length=1000)


class GroupMember(ApplicationModel):
    id: Identifier
    name: Name | None = None
    address: str | None = Field(default=None, max_length=200)
    inventory: InventoryReference | None = None
    context: str | None = Field(default=None, min_length=1, max_length=500)
    placeholder: Placeholder | None = None

    @model_validator(mode="after")
    def one_source(self) -> GroupMember:
        sources = (self.address, self.inventory, self.placeholder)
        if sum(source is not None for source in sources) != 1:
            raise ValueError("state exactly one literal address, inventory reference or placeholder")
        if self.address is not None:
            try:
                self.address = str(
                    ipaddress.ip_network(self.address, strict=False)
                    if "/" in self.address
                    else ipaddress.ip_address(self.address)
                )
            except ValueError as exc:
                raise ValueError("address must be an IPv4/IPv6 address or prefix") from exc
        return self


class ComponentGroup(ApplicationModel):
    id: Identifier
    name: Name
    description: str | None = Field(default=None, max_length=2000)
    members: list[GroupMember] = Field(default_factory=list, max_length=MAX_MEMBERS)

    @model_validator(mode="after")
    def unique_members(self) -> ComponentGroup:
        _unique(self.members, "component member")
        return self


class ServiceComponentRole(ApplicationModel):
    group_id: Identifier
    role: Literal["client", "endpoint", "dependency", "component"]


class ApplicationService(ApplicationModel):
    id: Identifier
    name: Name
    description: str | None = Field(default=None, max_length=2000)
    connection_ids: list[Identifier] = Field(default_factory=list, max_length=MAX_ASSOCIATIONS)
    component_roles: list[ServiceComponentRole] = Field(default_factory=list, max_length=MAX_ASSOCIATIONS)

    @model_validator(mode="after")
    def unique_associations(self) -> ApplicationService:
        if len(set(self.connection_ids)) != len(self.connection_ids):
            raise ValueError("connection_ids must be unique")
        roles = [(entry.group_id, entry.role) for entry in self.component_roles]
        if len(set(roles)) != len(roles):
            raise ValueError("component role associations must be unique")
        return self


class DestinationCondition(ApplicationModel):
    kind: Literal["member", "and", "or", "threshold"]
    member: Identifier | None = None
    n: int | None = Field(default=None, ge=1)
    parts: list[DestinationCondition] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def valid_shape(self) -> DestinationCondition:
        if self.kind == "member":
            if self.member is None or self.parts or self.n is not None:
                raise ValueError("member conditions require only member")
        elif not self.parts or self.member is not None:
            raise ValueError(f"{self.kind} conditions require nonempty parts and no member")
        elif self.kind == "threshold":
            if self.n is None or self.n > len(self.parts):
                raise ValueError("threshold conditions require n within the number of parts")
        elif self.n is not None:
            raise ValueError("only threshold conditions accept n")
        return self


DestinationCondition.model_rebuild()


class EndpointContext(ApplicationModel):
    vrf: str | None = Field(default=None, min_length=1, max_length=500)
    device_uid: str | None = Field(default=None, min_length=1, max_length=500)
    identity_uid: str | None = Field(default=None, min_length=1, max_length=500)
    segment_uid: str | None = Field(default=None, min_length=1, max_length=500)
    ingress_interface_uid: str | None = Field(default=None, min_length=1, max_length=500)


class TraceProvenance(ApplicationModel):
    trace_id: str = Field(min_length=1, max_length=500)
    snapshot: str = Field(min_length=1, max_length=200)
    captured_fields: list[str] = Field(min_length=1, max_length=50)


Port = int | Annotated[str, StringConstraints(pattern=r"^[0-9]{1,5}(?:-[0-9]{1,5})?$")]


class Connection(ApplicationModel):
    id: Identifier
    name: Name
    description: str | None = Field(default=None, max_length=2000)
    source: Identifier
    destination: Identifier
    protocol: str | None = Field(default=None, min_length=1, max_length=50)
    destination_ports: list[Port] | None = Field(default=None, min_length=1, max_length=100)
    source_ports: list[Port] | None = Field(default=None, min_length=1, max_length=100)
    success: Literal["forward", "round-trip", "session"] = "forward"
    destination_condition: DestinationCondition
    source_context: EndpointContext | None = None
    destination_context: EndpointContext | None = None
    header_constraints: dict[str, list[tuple[int, int]]] = Field(default_factory=dict, max_length=7)
    mtu: MtuRequest | None = None
    provenance: TraceProvenance | None = None

    @model_validator(mode="after")
    def valid_ports(self) -> Connection:
        for field in ("destination_ports", "source_ports"):
            for value in getattr(self, field) or []:
                lo, hi = _port_range(value)
                if not 0 <= lo <= hi <= 65535:
                    raise ValueError(f"{field} values must be within 0..65535")
        return self


class BusinessApplicationDefinition(ApplicationModel):
    model_config = ConfigDict(extra="forbid", json_schema_extra=_PLACEHOLDER_RULE)

    schema_version: Literal[1, 2] = 1
    kind: Literal["BusinessApplication"] = "BusinessApplication"
    id: ApplicationIdentifier
    name: Name
    description: str | None = Field(default=None, max_length=4000)
    owner: str | None = Field(default=None, max_length=500)
    environment: str | None = Field(default=None, max_length=200)
    state: Literal["draft", "ready"] = "draft"
    services: list[ApplicationService] = Field(default_factory=list, max_length=MAX_SERVICES)
    groups: list[ComponentGroup] = Field(default_factory=list, max_length=MAX_GROUPS)
    connections: list[Connection] = Field(default_factory=list, max_length=MAX_CONNECTIONS)

    @model_validator(mode="after")
    def valid_references(self) -> BusinessApplicationDefinition:
        _unique(self.services, "service")
        _unique(self.groups, "group")
        _unique(self.connections, "connection")
        if sum(len(group.members) for group in self.groups) > MAX_MEMBERS:
            raise ValueError(f"an application supports at most {MAX_MEMBERS} group members")
        groups = {group.id: group for group in self.groups}
        connections = {connection.id: connection for connection in self.connections}
        assigned: set[str] = set()
        for service in self.services:
            for identifier in service.connection_ids:
                if identifier not in connections:
                    raise ValueError(f"service {service.id} references unknown connection {identifier}")
                if identifier in assigned:
                    raise ValueError(f"connection {identifier} is assigned to more than one service")
                assigned.add(identifier)
            for role in service.component_roles:
                if role.group_id not in groups:
                    raise ValueError(f"service {service.id} references unknown group {role.group_id}")
        for connection in self.connections:
            if connection.source not in groups:
                raise ValueError(
                    f"connection {connection.id} references unknown source group {connection.source}"
                )
            if connection.destination not in groups:
                raise ValueError(
                    f"connection {connection.id} references unknown destination group "
                    f"{connection.destination}"
                )
            member_ids = {member.id for member in groups[connection.destination].members}
            for member in _condition_members(connection.destination_condition):
                if member not in member_ids:
                    raise ValueError(
                        f"connection {connection.id} condition references unknown destination member {member}"
                    )
        placeholders = [
            f"groups.{group.id}.members.{member.id}"
            for group in self.groups
            for member in group.members
            if member.placeholder is not None
        ]
        if placeholders and self.schema_version < 2:
            raise ValueError("placeholder members require schema_version 2")
        if placeholders and self.state == "ready":
            raise ValueError(f"state ready is blocked by placeholders: {', '.join(placeholders)}")
        return self


class BusinessApplicationPatch(ApplicationModel):
    """Keyed merge input. Omitted fields/entities retain the current revision."""

    schema_version: Literal[1, 2] = 1
    kind: Literal["BusinessApplication"] = "BusinessApplication"
    id: ApplicationIdentifier
    name: Name | None = None
    description: str | None = None
    owner: str | None = None
    environment: str | None = None
    state: Literal["draft", "ready"] | None = None
    services: list[ApplicationService] | None = Field(default=None, max_length=MAX_SERVICES)
    groups: list[ComponentGroup] | None = Field(default=None, max_length=MAX_GROUPS)
    connections: list[Connection] | None = Field(default=None, max_length=MAX_CONNECTIONS)

    @model_validator(mode="after")
    def unique_patch_entities(self) -> BusinessApplicationPatch:
        for values, noun in (
            (self.services, "service"),
            (self.groups, "group"),
            (self.connections, "connection"),
        ):
            if values is not None:
                _unique(values, noun)
        return self


def stored_definition(document: Mapping[str, Any]) -> BusinessApplicationDefinition:
    """Read a definition the store holds."""
    return BusinessApplicationDefinition.model_validate(upgraded_document(document))


def upgraded_document(document: Mapping[str, Any]) -> dict[str, Any]:
    """A stored definition in the current shape. The document is not validated.

    The function drops `choice_scope` from each stored connection."""
    connections = document.get("connections")
    if not (
        isinstance(connections, list)
        and any(isinstance(item, dict) and "choice_scope" in item for item in connections)
    ):
        return dict(document)
    return {
        **document,
        "connections": [
            {key: value for key, value in item.items() if key != "choice_scope"}
            if isinstance(item, dict)
            else item
            for item in connections
        ],
    }


class RemovalSet(ApplicationModel):
    services: list[Identifier] = Field(default_factory=list, max_length=MAX_SERVICES)
    groups: list[Identifier] = Field(default_factory=list, max_length=MAX_GROUPS)
    connections: list[Identifier] = Field(default_factory=list, max_length=MAX_CONNECTIONS)
    members: dict[Identifier, list[Identifier]] = Field(default_factory=dict, max_length=MAX_GROUPS)


class _Identified(TypingProtocol):
    id: str


def _unique(values: Sequence[_Identified], noun: str) -> None:
    identifiers = [value.id for value in values]
    duplicates = sorted({identifier for identifier in identifiers if identifiers.count(identifier) > 1})
    if duplicates:
        raise ValueError(f"duplicate {noun} ids: {', '.join(duplicates)}")


def _condition_members(condition: DestinationCondition) -> list[str]:
    if condition.kind == "member":
        return [condition.member] if condition.member else []
    return [member for part in condition.parts for member in _condition_members(part)]


def _port_range(value: Port) -> tuple[int, int]:
    if isinstance(value, int):
        return value, value
    parts = value.split("-", 1)
    return int(parts[0]), int(parts[-1])
