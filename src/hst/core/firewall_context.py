from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal

from hst.policy.ir import ExecutionContext


def _identity(value: str, field: str) -> None:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{field} must be a nonempty canonical string")


def _uid(kind: str, *parts: str) -> str:
    for index, part in enumerate(parts):
        _identity(part, f"identity part {index}")
    digest = hashlib.sha256("\0".join((kind, *parts)).encode()).hexdigest()[:32]
    return f"{kind}:{digest}"


@dataclass(frozen=True, slots=True)
class FirewallAuthority:
    estate: str
    authority: str
    domain: str

    def __post_init__(self) -> None:
        for field in ("estate", "authority", "domain"):
            _identity(getattr(self, field), field)


@dataclass(frozen=True, slots=True)
class FirewallInstance:
    scope: FirewallAuthority
    gateway_object_uid: str
    uid: str

    @classmethod
    def authoritative(cls, scope: FirewallAuthority, gateway_object_uid: str) -> FirewallInstance:
        _identity(gateway_object_uid, "gateway_object_uid")
        return cls(
            scope,
            gateway_object_uid,
            _uid(
                "firewall-instance",
                scope.estate,
                scope.authority,
                scope.domain,
                gateway_object_uid,
            ),
        )

    def __post_init__(self) -> None:
        _identity(self.gateway_object_uid, "gateway_object_uid")
        expected = _uid(
            "firewall-instance",
            self.scope.estate,
            self.scope.authority,
            self.scope.domain,
            self.gateway_object_uid,
        )
        if self.uid != expected:
            raise ValueError("firewall instance UID does not match its authoritative identity")

    def execution_context(self, vrf_uid: str, address_family: Literal[4, 6]) -> ExecutionContext:
        return ExecutionContext(
            self.scope.estate,
            self.scope.authority,
            self.scope.domain,
            self.uid,
            vrf_uid,
            address_family,
        )


@dataclass(frozen=True, slots=True)
class PhysicalAppliance:
    estate: str
    authority: str
    appliance_uid: str

    def __post_init__(self) -> None:
        for field in ("estate", "authority", "appliance_uid"):
            _identity(getattr(self, field), field)


@dataclass(frozen=True, slots=True)
class FirewallPlacement:
    instance_uid: str
    appliance: PhysicalAppliance
    observation_uid: str

    def __post_init__(self) -> None:
        _identity(self.instance_uid, "instance_uid")
        _identity(self.observation_uid, "observation_uid")


@dataclass(frozen=True, slots=True)
class QualifiedVsid:
    """A VS number, local to one appliance in one observation."""

    appliance: PhysicalAppliance
    observation_uid: str
    value: int

    def __post_init__(self) -> None:
        _identity(self.observation_uid, "observation_uid")
        if type(self.value) is not int or self.value < 0:
            raise ValueError("VSID must be a nonnegative integer")


@dataclass(frozen=True, slots=True)
class InterfaceContext:
    instance_uid: str
    interface_uid: str

    def __post_init__(self) -> None:
        _identity(self.instance_uid, "instance_uid")
        _identity(self.interface_uid, "interface_uid")

    @property
    def uid(self) -> str:
        return _uid("firewall-interface-context", self.instance_uid, self.interface_uid)


@dataclass(frozen=True, slots=True)
class VrfContext:
    instance_uid: str
    vrf_uid: str

    def __post_init__(self) -> None:
        _identity(self.instance_uid, "instance_uid")
        _identity(self.vrf_uid, "vrf_uid")

    @property
    def uid(self) -> str:
        return _uid("firewall-vrf-context", self.instance_uid, self.vrf_uid)


@dataclass(frozen=True, slots=True)
class FailureScope:
    kind: Literal["physical-appliance", "logical-firewall"]
    uid: str

    def __post_init__(self) -> None:
        if self.kind not in {"physical-appliance", "logical-firewall"}:
            raise ValueError("unsupported firewall failure scope")
        _identity(self.uid, "uid")


@dataclass(frozen=True, slots=True)
class StateSyncObservation:
    """The observed state synchronization of one binding."""

    origin_instance_uid: str
    peer_instance_uid: str
    origin_location_uid: str
    peer_location_uid: str
    binding_uid: str
    state_kind: Literal["connection", "nat"]
    direction: Literal["origin-to-peer", "peer-to-origin", "bidirectional"]
    health: Literal["synchronized", "unsynchronized", "unknown"]
    observation_uid: str
    evidence_uid: str

    def __post_init__(self) -> None:
        for field in (
            "origin_instance_uid",
            "peer_instance_uid",
            "origin_location_uid",
            "peer_location_uid",
            "binding_uid",
            "observation_uid",
            "evidence_uid",
        ):
            _identity(getattr(self, field), field)
        if self.origin_location_uid == self.peer_location_uid:
            raise ValueError("state synchronization requires distinct execution locations")
        if self.state_kind not in {"connection", "nat"}:
            raise ValueError("unsupported synchronized state kind")
        if self.direction not in {"origin-to-peer", "peer-to-origin", "bidirectional"}:
            raise ValueError("unsupported synchronization direction")
        if self.health not in {"synchronized", "unsynchronized", "unknown"}:
            raise ValueError("synchronization health must be explicit")


@dataclass(frozen=True, slots=True)
class GatewayCaptureSection:
    section: str
    selected_instance_uid: str
    selected_vsid: QualifiedVsid
    evidence_uid: str

    def __post_init__(self) -> None:
        for field in ("section", "selected_instance_uid", "evidence_uid"):
            _identity(getattr(self, field), field)


@dataclass(frozen=True, slots=True)
class GatewayCaptureEnvelope:
    """The sections captured in one shell selection.

    Each section has the instance and the VSID of the envelope."""

    appliance: PhysicalAppliance
    observation_uid: str
    instance_uid: str
    selected_vsid: QualifiedVsid
    sections: tuple[GatewayCaptureSection, ...]

    def __post_init__(self) -> None:
        _identity(self.observation_uid, "observation_uid")
        _identity(self.instance_uid, "instance_uid")
        object.__setattr__(self, "sections", tuple(self.sections))
        if not self.sections:
            raise ValueError("capture envelope requires at least one section")
        if self.selected_vsid.appliance != self.appliance:
            raise ValueError("selected VSID belongs to another appliance")
        if self.selected_vsid.observation_uid != self.observation_uid:
            raise ValueError("selected VSID belongs to another observation")
        for section in self.sections:
            if section.selected_instance_uid != self.instance_uid:
                raise ValueError("mixed logical firewall contexts in capture envelope")
            if section.selected_vsid != self.selected_vsid:
                raise ValueError("mixed selected shell VS contexts in capture envelope")
