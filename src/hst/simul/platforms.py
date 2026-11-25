"""Defaults keyed by platform.

The module holds the no-policy eBGP default, the route-map conversion shape,
the OSPF defaults, the administrative distances and the redistribution
defaults.

The key is the source kind of the collector (`iosxe`, `iosxr`, `nxos`, `vyos`).
`collectors/base.py` registers a collector under the same string.

FRR has no collector source kind. VyOS runs FRR, and the no-policy eBGP
default of FRR depends on the active defaults profile. A bare `vyos` platform
is reported as a named model error and uses permit.
"""

from __future__ import annotations

from .errors import ErrorSink

GAIA = "checkpoint-gaia"
IOSXE = "iosxe"
IOSXR = "iosxr"
NXOS = "nxos"
FRR_TRADITIONAL = "frr-traditional"
FRR_DATACENTER = "frr-datacenter"

_ALIASES = {
    "ios-xe": IOSXE,
    "ios": IOSXE,
    "cisco_ios": IOSXE,
    "ios-xr": IOSXR,
    "cisco_xr": IOSXR,
    "nx-os": NXOS,
    "nexus": NXOS,
    "vyos-traditional": FRR_TRADITIONAL,
    "vyos-datacenter": FRR_DATACENTER,
    "frr": FRR_TRADITIONAL,
}

KNOWN = frozenset({IOSXE, IOSXR, NXOS, FRR_TRADITIONAL, FRR_DATACENTER, GAIA})

# True when an eBGP peer without a policy in a direction drops the routes of
# that direction. An iBGP peer has the restriction on Gaia only.
_EBGP_REQUIRES_POLICY = {
    GAIA: True,
    IOSXE: False,
    NXOS: False,
    IOSXR: True,
    FRR_TRADITIONAL: True,
    FRR_DATACENTER: False,
}


# The count of equal BGP paths that a process installs without a configured
# `maximum-paths`. The count is 1 on IOS-XE, NX-OS and IOS-XR. FRR and Gaia
# have no value.
BGP_MAXIMUM_PATHS: dict[str, int] = {IOSXE: 1, NXOS: 1, IOSXR: 1}


def bgp_maximum_paths(platform: str) -> int | None:
    """The default `maximum-paths` of a platform, or None when not recorded."""
    return BGP_MAXIMUM_PATHS.get(platform)


def known(platform: str | None) -> str | None:
    """The `KNOWN` name of a platform string, or None when the string resolves to no known platform."""
    raw = (platform or "").strip().lower()
    resolved = _ALIASES.get(raw, raw)
    return resolved if resolved in KNOWN else None


def normalize(platform: str | None, errors: ErrorSink) -> str:
    """Map a caller's platform string onto one of `KNOWN`.

    An unrecognised platform is reported and treated as IOS-XE.
    """
    resolved = known(platform)
    if resolved is not None:
        return resolved
    if (platform or "").strip().lower() == "vyos":
        errors.report(
            "unresolved-platform-profile",
            "VyOS runs FRR, whose no-policy eBGP default depends on the active "
            "defaults profile; no profile was supplied, "
            "so permit-by-default was applied. Pass 'vyos-traditional' or "
            "'vyos-datacenter'.",
            "vyos",
        )
        return IOSXE
    errors.report(
        "unknown-platform",
        f"platform {platform!r} has no recorded BGP default profile; permit-by-default was applied",
        platform,
    )
    return IOSXE


def ebgp_requires_policy(platform: str) -> bool:
    """Whether an eBGP peer without a policy in a direction drops the routes of that direction."""
    return _EBGP_REQUIRES_POLICY.get(platform, False)


def no_policy_permits(platform: str, session_type: str) -> bool:
    """Whether a peer without a policy in a direction permits the routes of that direction."""
    if platform == GAIA:
        return False
    if session_type == "ibgp":
        return True
    return not ebgp_requires_policy(platform)


def route_map_flavor(platform: str) -> str:
    """The conversion shape of a `kind="clause"` policy.

    IOS-XE nests the clauses as `If`s, or compiles one sub-policy per clause
    when a clause has `continue`. NX-OS partitions the map into intervals at
    the continue targets and returns through `callInContext`. A matched clause
    exits on IOS-XE and returns on NX-OS.
    """
    return NXOS if platform == NXOS else IOSXE


# --- OSPF defaults, read by simul/ospf.py ----------------------------------
#
# The values are from the vendor documentation. The two FRR profiles have the
# same OSPF defaults.
#
#   administrative distance   110 on every platform of this module.
#   reference bandwidth       `auto-cost reference-bandwidth` is 100 Mb/s on
#                             IOS-XE and IOS-XR and 40 Gb/s on NX-OS. The FRR
#                             manual states 100 Mb/s. FRRouting/frr issue 15455
#                             records that the code constant of FRR and its
#                             interface-speed unit disagree with that figure.
#   RFC 1583 compatibility    IOS-XE has `compatible rfc1583` on by default.
#                             Its external-route preference is the cost-only
#                             rule of RFC 1583. NX-OS, IOS-XR and FRR follow
#                             RFC 2328 section 16.4.1 by default. An intra-area
#                             path to the ASBR through a non-backbone area
#                             beats every other path to it.
#   interface cost rounding   The cost is reference / bandwidth. Cisco
#                             truncates the quotient. FRR rounds it
#                             (ospf_interface.c adds 0.5 before the integer
#                             conversion).

_OSPF_ADMIN_DISTANCE = {
    IOSXE: 110,
    NXOS: 110,
    IOSXR: 110,
    FRR_TRADITIONAL: 110,
    FRR_DATACENTER: 110,
}

_OSPF_REFERENCE_BANDWIDTH_MBPS = {
    IOSXE: 100,
    NXOS: 40_000,
    IOSXR: 100,
    FRR_TRADITIONAL: 100,
    FRR_DATACENTER: 100,
}

_OSPF_RFC1583_COMPATIBLE = {
    IOSXE: True,
    NXOS: False,
    IOSXR: False,
    FRR_TRADITIONAL: False,
    FRR_DATACENTER: False,
}

_OSPF_COST_ROUNDS = {
    IOSXE: False,
    NXOS: False,
    IOSXR: False,
    FRR_TRADITIONAL: True,
    FRR_DATACENTER: True,
}

# The metric of a link is a 16-bit field (RFC 2328 A.4.2).
OSPF_MAX_LINK_COST = 65_535


def ospf_admin_distance(platform: str) -> int:
    """The administrative distance of an OSPF route in the main RIB."""
    return _OSPF_ADMIN_DISTANCE.get(platform, 110)


def ospf_reference_bandwidth_mbps(platform: str) -> int:
    """The `auto-cost reference-bandwidth` default, in megabits per second."""
    return _OSPF_REFERENCE_BANDWIDTH_MBPS.get(platform, 100)


def ospf_rfc1583_compatible(platform: str) -> bool:
    """Whether the external-route preference follows RFC 1583 (cost only).

    False selects RFC 2328 section 16.4.1 (intra-area non-backbone paths to the
    ASBR first).
    """
    return _OSPF_RFC1583_COMPATIBLE.get(platform, True)


def ospf_interface_cost(platform: str, bandwidth_kbps: int) -> int:
    """The cost of an interface without an explicit `ip ospf cost`.

    The cost is the reference bandwidth divided by the interface bandwidth,
    limited to the range 1 to 65535. `bandwidth_kbps` is the interface
    bandwidth in kilobits per second.
    """
    reference_kbps = ospf_reference_bandwidth_mbps(platform) * 1000
    if bandwidth_kbps <= 0:
        return OSPF_MAX_LINK_COST
    quotient = reference_kbps / bandwidth_kbps
    cost = int(quotient + 0.5) if _OSPF_COST_ROUNDS.get(platform, False) else int(quotient)
    return max(1, min(OSPF_MAX_LINK_COST, cost))


# --- administrative distances, read by simul/rib.py -------------------------
#
# The values are from the vendor documentation. IOS-XE, NX-OS, IOS-XR and FRR
# have connected 0, static 1, eBGP 20, OSPF 110 and iBGP 200.
# `ospf_admin_distance` returns the same OSPF value.

CONNECTED = "connected"
STATIC = "static"
OSPF = "ospf"
EBGP = "ebgp"
IBGP = "ibgp"
# A BGP route that the router originates (network, redistribute, aggregate).
# The distance is 200 on IOS-XE, IOS-XR and FRR and 220 on NX-OS
# (`distance 20 200 220`).
LOCAL_BGP = "local-bgp"

_ADMIN_DISTANCE: dict[str, dict[str, int]] = {
    platform: {CONNECTED: 0, STATIC: 1, EBGP: 20, OSPF: 110, IBGP: 200, LOCAL_BGP: 200}
    for platform in (IOSXE, NXOS, IOSXR, FRR_TRADITIONAL, FRR_DATACENTER)
}
_ADMIN_DISTANCE[NXOS][LOCAL_BGP] = 220

# The distance of a protocol that is not in the table. It ranks below every protocol in the table.
UNKNOWN_ADMIN_DISTANCE = 255


def admin_distance(platform: str, protocol: str) -> int:
    """The administrative distance of a route of `protocol` in the main RIB on `platform`.

    `protocol` is `connected`, `static`, `ebgp`, `ospf`, `ibgp` or `local-bgp`.
    """
    return _ADMIN_DISTANCE.get(platform, _ADMIN_DISTANCE[IOSXE]).get(protocol, UNKNOWN_ADMIN_DISTANCE)


# --- redistribution defaults --------------------------------------------------
#
# On IOS-XE a `redistribute ... route-map` with an undefined map redistributes
# nothing. IOS-XR redistributes unfiltered with a warning. NX-OS omits the
# route-map conjunct when the map is not defined. The bgpd of FRR applies a
# missing route-map as a deny.
_REDISTRIBUTE_UNDEFINED_PERMITS = {
    IOSXE: False,
    NXOS: True,
    IOSXR: True,
    FRR_TRADITIONAL: False,
    FRR_DATACENTER: False,
}

# The OSPF routes that `redistribute ospf` without a `match` clause offers to
# BGP. IOS-XE offers internal routes only. NX-OS, IOS-XR and FRR offer every
# OSPF route.
_REDISTRIBUTE_OSPF_INTERNAL_ONLY = {
    IOSXE: True,
    NXOS: False,
    IOSXR: False,
    FRR_TRADITIONAL: False,
    FRR_DATACENTER: False,
}

# The metric of a route redistributed into OSPF when the route-map sets none.
# Cisco IOS documents 1 for BGP and 20 for every other source (Cisco,
# "Redistributing Routing Protocols", Document ID 8606). NX-OS, IOS-XR and FRR
# document 20 for every source (their `default-metric` defaults).
_OSPF_REDISTRIBUTE_METRIC: dict[str, dict[str, int]] = {
    IOSXE: {"bgp": 1},
    NXOS: {},
    IOSXR: {},
    FRR_TRADITIONAL: {},
    FRR_DATACENTER: {},
}
OSPF_REDISTRIBUTE_DEFAULT_METRIC = 20


# Whether `redistribute` into BGP leaves out a default route (0.0.0.0/0, ::/0)
# when the process has no `default-information originate`. IOS-XE adds
# NOT_DEFAULT_ROUTE to every redistribution. NX-OS excludes the default route
# from every clause. The IOS-XR BGP command reference requires
# `default-information originate` too.
_REDISTRIBUTE_EXCLUDES_DEFAULT: dict[str, bool] = {IOSXE: True, NXOS: True, IOSXR: True}


def redistribute_excludes_default(platform: str) -> bool | None:
    """Whether a default route is left out of a BGP redistribution unless
    `default-information originate` is configured, or None when the platform's
    behavior is not established."""
    return _REDISTRIBUTE_EXCLUDES_DEFAULT.get(platform)


def redistribute_undefined_permits(platform: str) -> bool:
    """Whether a redistribution whose route-map is undefined proceeds
    unfiltered (True) or does not occur at all (False)."""
    return _REDISTRIBUTE_UNDEFINED_PERMITS.get(platform, False)


def redistribute_ospf_internal_only(platform: str) -> bool:
    """Whether `redistribute ospf` with no match clause offers internal
    (intra-area and inter-area) routes only."""
    return _REDISTRIBUTE_OSPF_INTERNAL_ONLY.get(platform, False)


def ospf_redistribute_metric(platform: str, source_protocol: str) -> int:
    """The metric an external route takes when redistributed into OSPF from
    `source_protocol` and the route-map sets none."""
    return _OSPF_REDISTRIBUTE_METRIC.get(platform, {}).get(source_protocol, OSPF_REDISTRIBUTE_DEFAULT_METRIC)
