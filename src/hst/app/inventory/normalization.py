"""Legacy normalization freeze and parity helper."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from typing import Any, Literal

from hst.app.sources import RESOLVER_VERSION, backfill_routing_scope, resolve_normalization
from hst.app.store import Site, Source
from hst.core import Settings

Sensitivity = Literal["identity", "label"]

# The v1 resolver places a row without a `site_code` at the site "home"
# (app/sources.py `resolve_normalization`). The v1 backfill pins the same literal
# (app/sources.py `backfill_routing_scope`).
IMPLICIT_SITE = "home"

# The v2 fallback routing namespace of a connection whose collector reads the
# legacy routing scope.
V2_NAMESPACE_PREFIX = "inventory:"


@dataclass(frozen=True)
class Classification:
    sensitivity: Sensitivity
    evidence: str


@dataclass(frozen=True)
class FrozenValue:
    """One frozen normalization value.

    `value` is the result of the v1 resolver. `origin` is the level that gave the value.
    `sensitivity` is the classification of the field for the collector of the row."""

    value: str | None
    # site_code: "group" | "implicit"
    # routing_scope: "group" | "site" | "site_code" | "source" | "backfill"
    # l2fabric: "group" | "application" | "backfill"
    # l3dom alias: "absent" | "alias-inert" | "alias-effective"
    origin: str
    sensitivity: Sensitivity
    evidence: str


@dataclass(frozen=True)
class FrozenNormalization:
    source_key: str
    collector_type: str
    resolver_version: str
    site_code: FrozenValue
    routing_scope: FrozenValue
    l3dom_alias: FrozenValue
    l2fabric: FrozenValue
    # The keys that the v1 cycle backfill pinned into the config of the row before the
    # resolver ran (app/runs_exec.py `_prepare_all`). The tuple is empty for a row that
    # states both keys.
    backfill_pinned: tuple[str, ...]
    reads_routing_scope: bool
    # The v2 fallback routing namespace of this source as a new
    # connection, or None when its collector has a native qualified context.
    v2_namespace: str | None
    # Digest of the inputs the freeze was computed from.
    input_digest: str

    def as_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["backfill_pinned"] = list(self.backfill_pinned)
        return out


# --- per-collector classification ------------------------------------------------

_BASE_SCOPE = (
    "collectors/base.py:131-133 effective_routing_scope = routing_scope or site_code; "
    "app/sources.py:56 resolves routing_scope from the group, the site param, then the site code"
)
_BASE_FABRIC = (
    "collectors/base.py:117-121 l2fabric field; core/config.py:50-56 l2fabric_of(source, explicit); "
    "app/sources.py:59 resolves l2fabric from the group, then the application fabric table"
)
_CONTEXT_ONLY = (
    "the collector never reads the value; collectors/base.py:365-372 records it in the "
    "raw_sha normalization context only, which changes the skip fingerprint, never a uid"
)
_L3DOMAIN_LABEL = (
    "core/l3domain.py:1-21 resolve() output is grouping and display only; "
    "collectors/util.py:209-211 VrfDomains.add uses it for the declared RoutingDomain node"
)


def _cls(sensitivity: Sensitivity, evidence: str) -> Classification:
    return Classification(sensitivity, evidence)


# The classification of each field of each collector. The table has every registered
# collector. `test_inventory_routing_identity.py` compares the keys of the table with the
# registry.
CLASSIFICATION: dict[str, dict[str, Classification]] = {
    "apic": {
        "site_code": _cls(
            "identity", f"{_BASE_SCOPE}; apic.py:334 l3dom=effective_routing_scope, see routing_scope"
        ),
        "routing_scope": _cls(
            "identity",
            "apic.py:334 l3dom=self.config.effective_routing_scope; "
            "apic.py:394,414 DomainPolicy(scope=l3dom) "
            "resolves each Ctx to `<scope>:<ctx dn>`; apic.py:618 Prefix anchor=dom and apic.py:795 "
            "uid.ip(dom, addr) embed that resolved domain in endpoint address uids",
        ),
        "l2fabric": _cls("label", f"{_CONTEXT_ONLY}; apic.py normalize_apic takes no l2fabric"),
        "l3dom": _cls(
            "label", "base.py:73 alias of routing_scope, inert once app/sources.py:56 writes routing_scope"
        ),
    },
    "checkpoint": {
        "site_code": _cls(
            "label", f"{_CONTEXT_ONLY}; checkpoint.py:604-610 scope_of(host, domain) takes no site"
        ),
        "routing_scope": _cls(
            "label", f"{_CONTEXT_ONLY}; checkpoint.py normalize_checkpoint writes no VrfInstance"
        ),
        "l2fabric": _cls("label", f"{_CONTEXT_ONLY}; checkpoint.py writes no bridging node"),
        "l3dom": _cls("label", "base.py:73 alias of routing_scope, inert"),
    },
    "checkpoint_gateway": {
        "site_code": _cls(
            "label", f"{_CONTEXT_ONLY}; identity is authority/domain/appliance (checkpoint_identity.py)"
        ),
        "routing_scope": _cls(
            "label",
            f"{_CONTEXT_ONLY}; checkpoint_gateway.py:868-872 VrfContext uids hash the "
            "FirewallInstance uid and "
            "the device-qualified vrf name, never the routing scope",
        ),
        "l2fabric": _cls(
            "identity",
            "checkpoint_gateway.py:463-469 l2fabric_of(source_name, l2fabric) passed to normalize; "
            "checkpoint_topology.py:84 uid.bridge_domain(fabric, vid)",
        ),
        "l3dom": _cls("label", "base.py:73 alias of routing_scope, inert"),
    },
    "equinix": {
        "site_code": _cls(
            "label", f"{_CONTEXT_ONLY}; equinix.py:410-412 sites come from the IBX map, not site_code"
        ),
        "routing_scope": _cls(
            "label", f"{_CONTEXT_ONLY}; equinix.py:364-370 normalize_equinix takes no scope"
        ),
        "l2fabric": _cls("label", f"{_CONTEXT_ONLY}; equinix.py normalize_equinix takes no l2fabric"),
        "l3dom": _cls("label", "base.py:73 alias of routing_scope, inert"),
    },
    "iosxe": {
        "site_code": _cls("label", f"{_BASE_SCOPE}; see routing_scope"),
        "routing_scope": _cls(
            "label",
            "cli_collector.py:392 l3dom=effective_routing_scope; "
            "cisco_common.py:144 DomainPolicy(scope=l3dom); "
            "cisco_common.py:1499,1774 IpAddress uids anchor on the VrfInstance uid or the collector scope, "
            f"l3dom is a display prop only; {_L3DOMAIN_LABEL}",
        ),
        "l2fabric": _cls(
            "identity",
            "cli_collector.py:394-399 l2fabric_of(source_name, l2fabric); cisco_common.py:316,2006 "
            "uid.bridge_domain(l2fabric, vid)",
        ),
        "l3dom": _cls("label", "base.py:73 alias of routing_scope, inert"),
    },
    "iosxr": {
        "site_code": _cls("label", f"{_BASE_SCOPE}; see routing_scope"),
        "routing_scope": _cls(
            "label",
            "cli_collector.py:392 l3dom=effective_routing_scope; "
            "cisco_common.py:144 DomainPolicy(scope=l3dom); "
            f"cisco_common.py:1499,1774 uids anchor on the VrfInstance uid or the scope; {_L3DOMAIN_LABEL}",
        ),
        "l2fabric": _cls(
            "identity",
            "cli_collector.py:394-399 l2fabric_of(source_name, l2fabric); cisco_common.py:316,2006 "
            "uid.bridge_domain(l2fabric, vid)",
        ),
        "l3dom": _cls("label", "base.py:73 alias of routing_scope, inert"),
    },
    "manual": {
        "site_code": _cls("identity", f"{_BASE_SCOPE}; see routing_scope"),
        "routing_scope": _cls(
            "identity",
            "manual.py:27-33 _manual_dom resolves the bare scope from effective_routing_scope; "
            "manual.py:152-160 uid.ip(dom, mgmt_ip) embeds it in the management address uid "
            "(source-scoped endpoint addressing)",
        ),
        "l2fabric": _cls("label", f"{_CONTEXT_ONLY}; manual.py never reads l2fabric"),
        "l3dom": _cls("label", "base.py:73 alias of routing_scope, inert"),
    },
    "nautobot": {
        "site_code": _cls("label", f"{_CONTEXT_ONLY}; nautobot.py:166-177 never reads site_code"),
        "routing_scope": _cls(
            "label", f"{_CONTEXT_ONLY}; nautobot.py:387-393 VrfInstance anchors on namespace and vrf id"
        ),
        "l2fabric": _cls("label", f"{_CONTEXT_ONLY}; nautobot.py never reads l2fabric"),
        "l3dom": _cls("label", "base.py:73 alias of routing_scope, inert"),
    },
    "ndo": {
        "site_code": _cls("label", f"{_CONTEXT_ONLY}; ndo.py never reads site_code"),
        "routing_scope": _cls("label", f"{_CONTEXT_ONLY}; ndo.py never reads routing_scope"),
        "l2fabric": _cls("label", f"{_CONTEXT_ONLY}; ndo.py never reads l2fabric"),
        "l3dom": _cls("label", "base.py:73 alias of routing_scope, inert"),
    },
    "netscaler": {
        "site_code": _cls("identity", f"{_BASE_SCOPE}; see routing_scope"),
        "routing_scope": _cls(
            "identity",
            "netscaler.py:220 l3dom=self.config.l3dom or self.config.effective_routing_scope; "
            "netscaler.py:248-255 anchor = l3dom or scope_name and uid.ip(anchor, addr) for every "
            "VIP, pool member and SNAT address",
        ),
        "l2fabric": _cls("label", f"{_CONTEXT_ONLY}; netscaler.py never reads l2fabric"),
        "l3dom": _cls(
            "identity",
            "netscaler.py:125-129 declares its own l3dom field beside the base alias; netscaler.py:220,248 "
            "the field, when set, is the IpAddress anchor ahead of the routing scope",
        ),
    },
    "nxos": {
        "site_code": _cls("label", f"{_BASE_SCOPE}; see routing_scope"),
        "routing_scope": _cls(
            "label",
            "cli_collector.py:392 l3dom=effective_routing_scope; "
            "cisco_common.py:144 DomainPolicy(scope=l3dom); "
            f"nxos.py:2364,2393 Prefix uids anchor on the VrfInstance uid; {_L3DOMAIN_LABEL}",
        ),
        "l2fabric": _cls(
            "identity",
            "cli_collector.py:394-399,419-422 l2fabric_of(source_name, l2fabric); cisco_common.py:316,2006 "
            "uid.bridge_domain(l2fabric, vid)",
        ),
        "l3dom": _cls("label", "base.py:73 alias of routing_scope, inert"),
    },
    "unifi": {
        "site_code": _cls(
            "identity",
            f"{_BASE_SCOPE}; see routing_scope. unifi.py keys SSID and endpoint uids by the source "
            "partition, not the site code",
        ),
        "routing_scope": _cls(
            "identity",
            "unifi.py:1141 l3dom=effective_routing_scope; unifi.py:100 _dom resolves the bare scope; "
            "unifi.py:609-611 ip_anchor = seg or dom and uid.ip(ip_anchor, ip); unifi.py:806-811,1011-1016 "
            "uid.prefix(dom, ...) and uid.ip(dom, ...) for source-scoped endpoint addressing",
        ),
        "l2fabric": _cls(
            "identity",
            "unifi.py:1144 l2fabric_of(source_name, l2fabric); "
            "unifi.py:449,603 uid.bridge_domain(l2fabric, vid)",
        ),
        "l3dom": _cls("label", "base.py:73 alias of routing_scope, inert"),
    },
    "velocloud": {
        "site_code": _cls("label", f"{_CONTEXT_ONLY}; velocloud.py never reads site_code"),
        "routing_scope": _cls(
            "label",
            f"{_CONTEXT_ONLY}; velocloud.py:640-645 DomainPolicy scope is the orchestrator scope plus the "
            "enterprise logicalId, never routing_scope",
        ),
        "l2fabric": _cls("label", f"{_CONTEXT_ONLY}; velocloud.py never reads l2fabric"),
        "l3dom": _cls("label", "base.py:73 alias of routing_scope, inert"),
    },
    "vyos": {
        "site_code": _cls("identity", f"{_BASE_SCOPE}; see routing_scope"),
        "routing_scope": _cls(
            "identity",
            "vyos.py:3370 l3dom=effective_routing_scope; vyos.py:322 DomainPolicy(scope=l3dom), the global "
            "table resolves to the bare scope; vyos.py:1579-1584,2024-2030,2267-2272 uid.prefix(l3dom, ...) "
            "and uid.ip(l3dom, ...) embed that resolved domain in policy-object address uids",
        ),
        "l2fabric": _cls(
            "identity",
            "vyos.py:3371 l2fabric_of(source_name, l2fabric); vyos.py:862 uid.bridge_domain(l2fabric, vid)",
        ),
        "l3dom": _cls("label", "base.py:73 alias of routing_scope, inert"),
    },
    "zia": {
        "site_code": _cls("label", f"{_CONTEXT_ONLY}; zia.py:143-255 never reads site_code"),
        "routing_scope": _cls("label", f"{_CONTEXT_ONLY}; zia.py never reads routing_scope"),
        "l2fabric": _cls("label", f"{_CONTEXT_ONLY}; zia.py never reads l2fabric"),
        "l3dom": _cls("label", "base.py:73 alias of routing_scope, inert"),
    },
    "zpa": {
        "site_code": _cls("label", f"{_CONTEXT_ONLY}; zpa.py never reads site_code"),
        "routing_scope": _cls("label", f"{_CONTEXT_ONLY}; zpa.py never reads routing_scope"),
        "l2fabric": _cls("label", f"{_CONTEXT_ONLY}; zpa.py never reads l2fabric"),
        "l3dom": _cls("label", "base.py:73 alias of routing_scope, inert"),
    },
}

# Collectors that read `effective_routing_scope` (apic.py, cli_collector.py for
# iosxe, iosxr and nxos, manual.py, netscaler.py, unifi.py, vyos.py).
READS_ROUTING_SCOPE: frozenset[str] = frozenset(
    {"apic", "iosxe", "iosxr", "manual", "netscaler", "nxos", "unifi", "vyos"}
)

# The one collector whose own `l3dom` field makes the legacy alias effective
# (netscaler.py).
ALIAS_EFFECTIVE: frozenset[str] = frozenset({"netscaler"})

_UNKNOWN = Classification(
    "label", "collector type not in the registry at the baseline; nothing reads the value"
)


def classification(collector_type: str, field: str) -> Classification:
    return CLASSIFICATION.get(collector_type, {}).get(field, _UNKNOWN)


def v2_namespace(source_key: str, collector_type: str) -> str | None:
    """Return the fallback routing namespace of a new connection under resolver v2.

    The namespace is `inventory:<immutable source key>` when the collector reads the legacy
    routing scope. It is None when the collector has a native qualified context."""
    if collector_type not in READS_ROUTING_SCOPE:
        return None
    return f"{V2_NAMESPACE_PREFIX}{source_key}"


def backfilled_config(row: Source, settings: Settings) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Return the config of the row after the v1 once-only key backfill, and the keys that it pinned.

    The rules are those of the backfill in app/runs_exec.py `_prepare_all`. The backfill pins
    only an absent key. An explicit null means inherit and stays. `routing_scope` gets the
    result of `app/sources.py backfill_routing_scope`. That result is the site code of the row
    or the implicit site, and null for a controller row without a site code. `l2fabric` gets
    the value of the application fabric table."""
    config = dict(row.config)
    pinned: list[str] = []
    if "routing_scope" not in config or "l2fabric" not in config:
        if "routing_scope" not in config:
            config["routing_scope"] = backfill_routing_scope(row)
            pinned.append("routing_scope")
        if "l2fabric" not in config:
            config["l2fabric"] = settings.l2fabric_of(row.name)
            pinned.append("l2fabric")
    return config, tuple(pinned)


def input_digest(row: Source, sites: Mapping[str, Site], settings: Settings) -> str:
    """Return the digest of the inputs of the freeze.

    The inputs are the resolver version, the name, the type and the non-secret config of the
    row, the params of the site that the row names or of the implicit site, and the fabric
    table. The frozen values must be recomputed when the digest differs between a dry run and
    an apply."""
    site_code = row.config.get("site_code") or IMPLICIT_SITE
    site = sites.get(site_code)
    material = {
        "resolver_version": RESOLVER_VERSION,
        "name": row.name,
        "type": row.type,
        "config": row.config,
        "site": {"code": site_code, "params": (site.params if site is not None else None)},
        "l2_fabrics": settings.l2_fabrics or {},
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def freeze_legacy_normalization(
    row: Source, sites: Mapping[str, Site], settings: Settings
) -> FrozenNormalization:
    """The v1 effective normalization of one source row.

    The function runs the v1 backfill and then the v1 resolver
    (`app/sources.py resolve_normalization`) on the row. The origins are those of the
    resolver. A key that the backfill pinned to a value has the origin `backfill`.

    `l3dom_alias` holds the legacy `l3dom` key of the row. For NetScaler the key is a field of
    the collector and the effective IpAddress anchor, and its origin is `alias-effective`. For
    every other collector the key is inert after resolution, and its origin is `alias-inert`.
    """
    config, pinned = backfilled_config(row, settings)
    resolved_row = replace(row, config=config)
    effective, origins = resolve_normalization(resolved_row, settings, sites=dict(sites))
    kind = row.type

    site_value = str(effective["site_code"])
    site_origin = "group" if row.config.get("site_code") else "implicit"
    site_cls = classification(kind, "site_code")

    scope_value = str(effective["routing_scope"])
    scope_origin = origins["routing_scope"]
    if scope_origin == "group" and "routing_scope" in pinned:
        scope_origin = "backfill"
    scope_cls = classification(kind, "routing_scope")

    fabric_value = str(effective["l2fabric"])
    fabric_origin = origins["l2fabric"]
    if fabric_origin == "group" and "l2fabric" in pinned:
        fabric_origin = "backfill"
    fabric_cls = classification(kind, "l2fabric")

    alias_raw = row.config.get("l3dom")
    alias_cls = classification(kind, "l3dom")
    if alias_raw in (None, ""):
        alias = FrozenValue(None, "absent", alias_cls.sensitivity, alias_cls.evidence)
    elif kind in ALIAS_EFFECTIVE:
        alias = FrozenValue(str(alias_raw), "alias-effective", alias_cls.sensitivity, alias_cls.evidence)
    else:
        alias = FrozenValue(str(alias_raw), "alias-inert", alias_cls.sensitivity, alias_cls.evidence)

    return FrozenNormalization(
        source_key=row.name,
        collector_type=kind,
        resolver_version=RESOLVER_VERSION,
        site_code=FrozenValue(site_value, site_origin, site_cls.sensitivity, site_cls.evidence),
        routing_scope=FrozenValue(scope_value, scope_origin, scope_cls.sensitivity, scope_cls.evidence),
        l3dom_alias=alias,
        l2fabric=FrozenValue(fabric_value, fabric_origin, fabric_cls.sensitivity, fabric_cls.evidence),
        backfill_pinned=pinned,
        reads_routing_scope=kind in READS_ROUTING_SCOPE,
        v2_namespace=v2_namespace(row.name, kind),
        input_digest=input_digest(row, sites, settings),
    )


def effective_identity_anchor(frozen: FrozenNormalization) -> str | None:
    """Return the string that a collector embeds in source-scoped address uids, or None.

    The string is the `l3dom` field of a NetScaler row when the field is set (netscaler.py).
    Otherwise it is the resolved routing scope of a collector for which the scope is identity.
    The result is None for every other collector."""
    if not frozen.reads_routing_scope:
        return None
    if frozen.l3dom_alias.origin == "alias-effective" and frozen.l3dom_alias.value:
        return frozen.l3dom_alias.value
    if frozen.routing_scope.sensitivity != "identity":
        return None
    return frozen.routing_scope.value
