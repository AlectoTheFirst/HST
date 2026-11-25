"""The Check Point profile `checkpoint-r81.20-filter-v1` and the field sets of its rule and object types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class CheckpointProfile:
    management_release: str
    gateway_release: str
    api_version: str
    version: str = "checkpoint-r81.20-filter-v1"

    def __post_init__(self) -> None:
        if (self.management_release, self.gateway_release, self.api_version, self.version) != (
            "R81.20",
            "R81.20",
            "1.9",
            "checkpoint-r81.20-filter-v1",
        ):
            raise ValueError("unqualified Check Point profile; explicit release/profile support is required")


@dataclass(frozen=True, slots=True)
class FieldAudit:
    subject: str
    field: str
    classification: Literal["supported", "metadata", "unsupported", "unclassified"]
    reason: str


METADATA = frozenset(
    {"uid", "name", "type", "domain", "folder", "meta-info", "comments", "color", "icon", "tags", "read-only"}
)
RULE_FIELDS = frozenset(
    {
        "source",
        "destination",
        "service",
        "source-negate",
        "destination-negate",
        "service-negate",
        "enabled",
        "action",
        "inline-layer",
        "install-on",
        "rule-number",
        "implied",
    }
)
CONTEXT_FIELDS = frozenset({"time", "vpn", "content", "content-direction", "user-check", "action-settings"})
OBJECT_FIELDS = {
    "CpmiAnyObject": frozenset(),
    "RulebaseAction": frozenset(),
    "host": frozenset({"ipv4-address", "ipv6-address"}),
    "network": frozenset({"subnet4", "mask-length4", "subnet6", "mask-length6", "subnet-mask"}),
    "address-range": frozenset(
        {"ipv4-address-first", "ipv4-address-last", "ipv6-address-first", "ipv6-address-last"}
    ),
    "group": frozenset({"members"}),
    "group-with-exclusion": frozenset({"include", "except"}),
    "service-group": frozenset({"members"}),
    "service-tcp": frozenset({"port", "source-port", "protocol", "match-by-protocol-signature"}),
    "service-udp": frozenset({"port", "source-port", "protocol", "match-by-protocol-signature"}),
    "service-icmp": frozenset({"icmp-type", "icmp-code", "strata-unconstrained-icmp-fields"}),
    "service-icmp6": frozenset({"icmp-type", "icmp-code", "strata-unconstrained-icmp-fields"}),
}

OBJECT_STAGE_METADATA = frozenset(
    {
        "nat-settings",
        "session-timeout",
        "use-default-session-timeout",
        "keep-connections-open-after-policy-installation",
        "sync-connections-on-cluster",
        "aggressive-aging",
        "groups",
    }
)
