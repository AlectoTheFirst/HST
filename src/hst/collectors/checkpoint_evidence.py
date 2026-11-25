"""Validated supplemental VSX observations from management/runtime exports."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, model_validator


class EvidenceModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class InterfaceRef(EvidenceModel):
    vsid: int = Field(ge=0)
    interface: str = Field(min_length=1)


class WarpLink(EvidenceModel):
    a: InterfaceRef
    b: InterfaceRef
    evidence_uid: str = Field(min_length=1)


class BridgeGroup(EvidenceModel):
    vsid: int = Field(ge=0)
    name: str = Field(min_length=1)
    interfaces: tuple[str, ...] = Field(min_length=2)
    evidence_uid: str = Field(min_length=1)


class Installation(EvidenceModel):
    """One observed policy installation on a virtual system.

    `configured_revision` and `installed_revision` use the form in which the management
    collector records the `configured_revision` of a rulebase (checkpoint.py
    `_policy_revision`). The form is "{posix}|{last-modifier}" of the meta-info
    last-modify-time of the package. The path gates and the analysis model treat a
    binding as installed only when the installed revision equals that configured
    revision. A revision in another form leaves every binding approximate.
    """

    vsid: int = Field(ge=0)
    gateway_object_uid: str = Field(min_length=1)
    authority: str = Field(min_length=1)
    rulebase_uid: str = Field(min_length=1)
    configured_revision: str = Field(min_length=1)
    installed_revision: str = Field(min_length=1)
    complete: bool
    policy_name: str = Field(min_length=1)
    installed_at_raw: str = Field(min_length=1)
    evidence_uid: str = Field(min_length=1)
    address_family: Literal[4, 6]
    ingress_interface: str
    egress_interface: str


class Session(EvidenceModel):
    vsid: int = Field(ge=0)
    binding_uid: str = Field(min_length=1)
    protocol: Literal["tcp", "udp", "icmp", "icmpv6"]
    observed_at: datetime
    expires_at: datetime
    original_source: IPvAnyAddress
    original_destination: IPvAnyAddress
    translated_source: IPvAnyAddress
    translated_destination: IPvAnyAddress
    original_source_port: int = Field(ge=0, le=65535)
    original_destination_port: int = Field(ge=0, le=65535)
    translated_source_port: int = Field(ge=0, le=65535)
    translated_destination_port: int = Field(ge=0, le=65535)
    evidence_uid: str = Field(min_length=1)
    synchronized_members: tuple[str, ...] = ()

    @model_validator(mode="after")
    def consistent(self):
        addresses = (
            self.original_source,
            self.original_destination,
            self.translated_source,
            self.translated_destination,
        )
        if len({a.version for a in addresses}) != 1:
            raise ValueError("mixed address families in runtime NAT binding")
        if self.observed_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("runtime evidence timestamps require a timezone")
        if self.expires_at <= self.observed_at:
            raise ValueError("runtime binding expires before observation")
        return self


class VsxEvidence(EvidenceModel):
    version: Literal[1]
    appliance_uid: str = Field(min_length=1)
    observation_uid: str = Field(min_length=1)
    warp_links: tuple[WarpLink, ...] = ()
    bridge_groups: tuple[BridgeGroup, ...] = ()
    installations: tuple[Installation, ...] = ()
    sessions: tuple[Session, ...] = ()


def read_evidence(path: str, appliance: str, observation: str) -> dict[str, Any]:
    with Path(path).open("rb") as stream:
        data = stream.read(32 * 1024 * 1024 + 1)
    if len(data) > 32 * 1024 * 1024:
        raise ValueError("VSX evidence exceeds 32 MiB")
    model = VsxEvidence.model_validate(json.loads(data))
    if model.appliance_uid != appliance or model.observation_uid != observation:
        raise ValueError("VSX evidence belongs to another appliance or observation")
    return {**model.model_dump(mode="json"), "sha256": hashlib.sha256(data).hexdigest()}


def installations_for(
    evidence: dict[str, Any],
    *,
    vsid: int,
    authority: str,
    gateway: str,
    observed: list[dict[str, str]],
    interfaces: dict[str, str],
) -> tuple[list[dict[str, Any]], list[str]]:
    result, gaps = [], []
    model = VsxEvidence.model_validate({k: v for k, v in evidence.items() if k != "sha256"})
    for item in model.installations:
        if item.vsid != vsid:
            continue
        if item.authority != authority or item.gateway_object_uid != gateway:
            gaps.append(f"VS {vsid}: installation authority/target mismatch")
            continue
        matches = [
            row
            for row in observed
            if row["policy_name"] == item.policy_name and row["installed_at_raw"] == item.installed_at_raw
        ]
        if not matches:
            gaps.append(f"VS {vsid}: management installation has no matching gateway observation")
            continue
        if any(
            name != "*" and name not in interfaces for name in (item.ingress_interface, item.egress_interface)
        ):
            gaps.append(f"VS {vsid}: installation references an unobserved interface")
            continue
        complete = item.complete and item.installed_revision == item.configured_revision
        if not complete:
            gaps.append(f"VS {vsid}: installed/configured revision differs or policy capture is incomplete")
        result.append(
            {
                **item.model_dump(),
                "complete": complete,
                "ingress_interface_uid": interfaces.get(item.ingress_interface, "*"),
                "egress_interface_uid": interfaces.get(item.egress_interface, "*"),
            }
        )
    return result, gaps


def sessions_for(evidence: dict[str, Any], vsid: int) -> str:
    model = VsxEvidence.model_validate({k: v for k, v in evidence.items() if k != "sha256"})
    now = datetime.now(UTC)
    return json.dumps(
        [
            item.model_dump(mode="json")
            for item in model.sessions
            if item.vsid == vsid and item.observed_at <= now < item.expires_at
        ]
    )
