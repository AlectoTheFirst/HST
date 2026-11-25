"""The role code is a whole letter token of the short hostname."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from .normalize import normalize_hostname

# The role values that a collector writes on every device that it reaches.
GENERIC_ROLES = frozenset({"router", "unknown"})

# The forwarding function of each design tier (core.labels.DEVICE_ROLES).
TIER_ROLES: dict[str, str] = {
    "core": "router",
    "distribution": "router",
    "access": "switch",
    "internet-edge": "router",
    "wan-edge": "router",
    "sdwan-hub": "sdwan-hub",
    "sdwan-edge": "sdwan-edge",
    "wireless": "controller",
    "access-point": "ap",
    "firewall": "firewall",
    "leaf": "leaf",
    "spine": "spine",
}

# The tier of a role that a collector reported. It replaces the tier of the
# hostname token. An RTS that VeloCloud reports as a hub has the tier sdwan-hub.
ROLE_TIERS: dict[str, str] = {
    "sdwan-hub": "sdwan-hub",
    "sdwan-edge": "sdwan-edge",
    "firewall": "firewall",
    "leaf": "leaf",
    "spine": "spine",
}

# The default naming standard maps each hostname token to a tier.
# Settings.hostname_tier_tokens replaces it for an estate with other names.
DEFAULT_TIER_TOKENS: dict[str, str] = {
    "swc": "core",
    "swd": "distribution",
    "swa": "access",
    "rti": "internet-edge",
    "rtw": "wan-edge",
    "rth": "sdwan-hub",
    "rts": "sdwan-edge",
    "wlc": "wireless",
    "ap": "access-point",
    "fw": "firewall",
    "vs": "firewall",
}

_TOKEN = re.compile(r"[a-z]+")


@dataclass(frozen=True)
class Classification:
    role: str
    basis: str
    tier: str | None


def tier_from_hostname(hostname: str | None, tokens: Mapping[str, str]) -> str | None:
    """Return the tier of the short hostname, or None when no token matches or
    the tokens map to 2 or more tiers."""
    if not hostname:
        return None
    short = normalize_hostname(hostname).short
    tiers = {tokens[token] for token in _TOKEN.findall(short) if token in tokens}
    return tiers.pop() if len(tiers) == 1 else None


def classify(
    hostname: str | None,
    reported: str | None,
    has_fhrp: bool,
    tokens: Mapping[str, str],
    has_routing: bool = False,
) -> Classification:
    """Return the role, its basis and the tier of one device.

    `reported` is the role that the collector wrote. `has_fhrp` is whether an
    interface of the device is a member of an FHRP group. `has_routing` is
    whether the device holds a routing-protocol adjacency."""
    reported = reported or "unknown"
    tier = tier_from_hostname(hostname, tokens)
    if reported not in GENERIC_ROLES:
        return Classification(reported, "collector", ROLE_TIERS.get(reported, tier))
    if tier is None:
        return Classification(reported, "default", None)
    role = TIER_ROLES[tier]
    if role == "switch" and (has_fhrp or has_routing):
        return Classification("router", "evidence", tier)
    return Classification(role, "hostname", tier)
