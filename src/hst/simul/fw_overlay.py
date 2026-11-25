"""The policy change overlay applies a proposed change set to the rows of a pinned read.

The overlay rewrites the rows of the reads listed under "row rewriting" in
memory for one call.

`path.session._read` passes the rows of each read to the `overlay(query,
params, rows)` hook of the session object. The overlaid rows are in the shape
that the queries in `hst.path.gates` return.

An intent kind has the form `<schema object>.<verb>`. The policy kinds:

    fw_rule.add            a FwRule that does not exist yet, on one FwRulebase
    fw_rule.remove          an existing FwRule taken out of its rulebase
    fw_rule.modify          an existing FwRule's action, addresses or service
    nat_rule.add            a NatRule that does not exist yet, on one device
    nat_rule.remove         an existing NatRule taken out
    nat_rule.modify         an existing NatRule's columns
    zone.add_interface      an Interface joins a Zone
    zone.remove_interface   an Interface leaves a Zone

A change set holds any number of these, across any number of rulebases, applied
in the order given.

A `fw_rule.add` can state `device` in place of `rulebase`.
`hst.app.fw_overlay_read` derives the rulebases it means before the set is
parsed. `fw_rule.remove` and `fw_rule.modify` require a rulebase.

A match value is an address, a prefix, a range, an explicit `any`, a
`NetObject` by uid or name, or an `SvcObject` by uid or name. A `NetObject`
group is resolved through its `MEMBER_OF` edges to a depth of `_GROUP_DEPTH`.
A zone-scoped proposal (`from_zone`/`to_zone`) is expanded into one row per
interface the zone contains, all at the same position.

The overlay does not express the following:

  * A new `FwRulebase`, `Zone`, `NetObject` or `SvcObject`. Every intent
    addresses objects the snapshot holds.
  * `(FwRule)-[:FROM_ZONE|TO_ZONE]->(Zone)` as the match condition of a
    collected rule, or a modification of that condition.
    `gates.firewall._RULEBASE_RULES` does not read those edges.
  * A rule with the action `redirect-layer`. The tracer does not evaluate the
    `JUMPS_TO` chain.
  * A change on a device that the change set does not name.

The caller computes route consequences from `denied_directions()`. It returns
the addresses that the change set stops traffic being sent to and the
addresses that it stops traffic being accepted from.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from hst.core.mtu import MtuObservation, canonical_json
from hst.core.mtu_profiles import restate_ip_bytes
from hst.path.addrsets import _intervals
from hst.path.gates.nat import _nat_rule_kind
from hst.path.verdict import DENY_ACTIONS, PERMIT_ACTIONS
from hst.results.trace import leg_result
from hst.simul.errors import ErrorSink

# --- the catalog ----------------------------------------------------------
from hst.simul.intents import (
    FW_KINDS as FW_KINDS,
)
from hst.simul.intents import (
    INTERFACE_KINDS as INTERFACE_KINDS,
)
from hst.simul.intents import (
    NAT_KINDS as NAT_KINDS,
)
from hst.simul.intents import (
    OVERLAY_KINDS as INTENT_KINDS,
)
from hst.simul.intents import (
    ROUTING_KINDS as ROUTING_KINDS,
)
from hst.simul.intents import (
    ZONE_KINDS as ZONE_KINDS,
)

# The actions a proposed rule can take.
PROPOSABLE_ACTIONS: frozenset[str] = PERMIT_ACTIONS | DENY_ACTIONS

# The NAT kinds that the direction resolution of the tracer reads (`_nat_rule_kind`).
PROPOSABLE_NAT_KINDS: frozenset[str] = frozenset({"snat", "dnat", "static"})

# How deep a `MEMBER_OF` chain is followed out of a NetObject group.
_GROUP_DEPTH = 16


class ProposalError(ValueError):
    """A change set that cannot be applied at all.

    A fault is an unknown intent kind, an action or NAT kind outside the
    proposable sets, a match value that is neither an address nor an object in
    the snapshot, or a rule named for removal that the rulebase does not hold.
    """


# --- what the graph supplies ----------------------------------------------


@dataclass
class Catalog:
    """The snapshot's policy objects, as plain dicts.

    `hst.app.fw_overlay_read` fills it. The keys are uids. A lookup also
    matches the `name` of an object.

    `net_objects[uid]` is `{"name", "addrs": [spec, ...], "members": [uid, ...],
    "opaque", "opaque_reason"}`. `svc_objects[uid]` is `{"name", "protos": [...],
    "ports": [...], "src_port", "members": [uid, ...], "opaque", "opaque_reason"}`.
    `opaque` is true when the collector could not state the object as
    addresses, or as a protocol and port.
    `zones[uid]` is `{"name", "default_action", "default_action_unknown",
    "established_default_unknown", "intra_zone_filtering", "intra_zone_action",
    "interfaces": [interface name, ...]}`.

    `interfaces[uid]` holds the facts of one Interface that the validation and
    the overlay of `interface.set_mtu` read, as `{"uid", "name", "device_uid",
    "vendor", "platform", "os_version", "device_sources", "parent_interface_uid",
    "parent_source_command", "port_uid", "observations": [MtuObservation, ...],
    "parent_uid", "configured_tag_depth"}`. `device_sources` is the Device's
    own `_sources` list of configured source names, or `None` when the read did
    not populate it. A key absent from this dict is an interface `read_catalog`
    was not asked about.

    `source_kinds` maps the name of each configured source of the twin to its
    collector kind (`hst.app.store.Source.name` to `.type`, for example
    `{"vyos-lts-1": "vyos", "unifi1": "unifi"}`). It is `None` when the caller
    has no sources configuration.
    """

    net_objects: dict[str, dict[str, Any]] = field(default_factory=dict)
    svc_objects: dict[str, dict[str, Any]] = field(default_factory=dict)
    zones: dict[str, dict[str, Any]] = field(default_factory=dict)
    interfaces: dict[str, dict[str, Any]] = field(default_factory=dict)
    source_kinds: dict[str, str] | None = None

    def _lookup(self, table: dict[str, dict[str, Any]], token: str) -> tuple[str, dict[str, Any]] | None:
        """One object by uid, else by name. A name shared by two objects
        resolves to the first by uid."""
        if token in table:
            return token, table[token]
        matches = sorted(uid for uid, obj in table.items() if str(obj.get("name") or "") == token)
        return (matches[0], table[matches[0]]) if matches else None

    def net_object(self, token: str) -> dict[str, Any] | None:
        found = self._lookup(self.net_objects, token)
        return found[1] if found else None

    def svc_object(self, token: str) -> dict[str, Any] | None:
        found = self._lookup(self.svc_objects, token)
        return found[1] if found else None

    def zone(self, token: str) -> dict[str, Any] | None:
        found = self._lookup(self.zones, token)
        return found[1] if found else None

    def zone_uid(self, token: str) -> str:
        """Return the uid of the zone that a uid or name token matches. Return
        the token when the catalog holds no such zone."""
        found = self._lookup(self.zones, token)
        return found[0] if found else token

    def interface(self, uid: str) -> dict[str, Any] | None:
        return self.interfaces.get(uid)

    def net_addresses(self, token: str) -> list[str]:
        """Return every address spec of a NetObject and of the members of its groups.

        The walk follows nested groups to a depth of `_GROUP_DEPTH` and visits
        each object once. It returns the addresses found within that depth.
        `net_gaps` reports a group that nests deeper.
        """
        seen: set[str] = set()
        out: list[str] = []

        def walk(uid: str, depth: int) -> None:
            if depth > _GROUP_DEPTH or uid in seen:
                return
            seen.add(uid)
            obj = self.net_objects.get(uid)
            if obj is None:
                return
            out.extend(str(a) for a in obj.get("addrs") or () if a)
            for member in obj.get("members") or ():
                walk(str(member), depth + 1)

        found = self._lookup(self.net_objects, token)
        if found is None:
            return []
        walk(found[0], 0)
        return out

    def net_gaps(self, token: str) -> list[str]:
        """Return the reasons why `net_addresses` does not return every address
        of a NetObject. A reason is an opaque object (an FQDN or a dynamic
        object), a member that the catalog does not hold, or nesting deeper
        than `_GROUP_DEPTH`."""
        seen: set[str] = set()
        out: list[str] = []

        def walk(uid: str, depth: int) -> None:
            if uid in seen:
                return
            seen.add(uid)
            if depth > _GROUP_DEPTH:
                out.append(f"it nests groups deeper than {_GROUP_DEPTH} levels")
                return
            obj = self.net_objects.get(uid)
            if obj is None:
                out.append(f"member {uid!r} is not in this snapshot")
                return
            if obj.get("opaque"):
                out.append(f"{obj.get('name') or uid!r} is {_why_opaque(obj)}")
            for member in obj.get("members") or ():
                walk(str(member), depth + 1)

        found = self._lookup(self.net_objects, token)
        if found is not None:
            walk(found[0], 0)
        return out

    def svc_pairs(self, token: str) -> tuple[list[tuple[str | None, str | None, str | None]], list[str]]:
        """Return the (protocol, port, source port) tuples of a SvcObject and of
        the members of its groups, and the reasons why the tuples are incomplete.

        A service-group holds no protocol or port. It is read through the
        `MEMBER_OF` edges from its members. The second list gets a reason for
        an opaque member, a member that the catalog does not hold, a member
        that states no protocol or port, a member scoped to a source port
        alone, and nesting deeper than `_GROUP_DEPTH`.
        """
        seen: set[str] = set()
        pairs: list[tuple[str | None, str | None, str | None]] = []
        gaps: list[str] = []

        def walk(uid: str, depth: int) -> None:
            if uid in seen:
                return
            seen.add(uid)
            if depth > _GROUP_DEPTH:
                gaps.append(f"it nests groups deeper than {_GROUP_DEPTH} levels")
                return
            obj = self.svc_objects.get(uid)
            if obj is None:
                gaps.append(f"member {uid!r} is not an SvcObject in this snapshot")
                return
            label = obj.get("name") or uid
            if obj.get("opaque"):
                gaps.append(f"{label!r} is {_why_opaque(obj)}")
            members = obj.get("members") or ()
            for member in members:
                walk(str(member), depth + 1)
            src = obj.get("src_port") or None
            own = _service_pairs(
                [str(p) for p in obj.get("protos") or () if p], [str(p) for p in obj.get("ports") or () if p]
            )
            if own:
                pairs.extend((proto, port, src) for proto, port in own)
            elif not members:
                gaps.append(
                    f"{label!r} is scoped to a source port only"
                    if src
                    else f"{label!r} states no protocol or port"
                )

        found = self._lookup(self.svc_objects, token)
        if found is not None:
            walk(found[0], 0)
        return pairs, gaps


def _why_opaque(obj: Mapping[str, Any]) -> str:
    return f"opaque ({obj['opaque_reason']})" if obj.get("opaque_reason") else "opaque"


# --- match values ---------------------------------------------------------


def _texts(value: Any) -> tuple[str, ...]:
    """Return the field of a caller as a tuple of strings. The field is one
    string or a list."""
    if value in (None, "", (), []):
        return ()
    items = [value] if isinstance(value, str) else list(value)
    return tuple(str(v).strip() for v in items if str(v).strip())


def _address_side(label: str, value: Any, catalog: Catalog) -> tuple[list[str], bool]:
    """Return the literal specs of one side of the address match of a rule, and
    whether the side is any.

    A token that parses as an address, prefix or range is used as it stands.
    Any other token is a `NetObject` by uid or by name and is flattened. A
    token that does not resolve in full raises `ProposalError`.
    """
    specs = _texts(value)
    if not specs or [s.lower() for s in specs] == ["any"]:
        return [], True
    if any(s.lower() == "any" for s in specs):
        raise ProposalError(f"{label} mixes 'any' with specific values")
    out: list[str] = []
    for token in specs:
        if _intervals([token]):
            out.append(token)
            continue
        resolved = catalog.net_addresses(token)
        gaps = catalog.net_gaps(token)
        if gaps:
            raise ProposalError(
                f"{label} value {token!r} does not resolve to all the addresses it names in this "
                f"snapshot: {'; '.join(dict.fromkeys(gaps))}"
            )
        if not resolved:
            known = catalog.net_object(token)
            if known is None:
                raise ProposalError(
                    f"{label} value {token!r} is neither an address, prefix or range nor a "
                    "NetObject in this snapshot"
                )
            raise ProposalError(
                f"{label} value {token!r} is a NetObject that resolves to no address in this "
                "snapshot (an empty group, an FQDN or a dynamic object)"
            )
        out.extend(resolved)
    return out, False


def _service_pairs(protos: list[str], ports: list[str]) -> list[tuple[str | None, str | None]]:
    """One service's stated protocols and ports as explicit (protocol, port) pairs.

    Protocols and ports stated together give one pair for each protocol on
    each port. A protocol stated with no port pairs with None. A port stated
    with no protocol pairs with None. None leaves that dimension of the pair
    unconstrained.
    """
    if protos and ports:
        return [(p, q) for p in protos for q in ports]
    if protos:
        return [(p, None) for p in protos]
    return [(None, q) for q in ports]


def _service(
    protocols: Any, ports: Any, services: Any, catalog: Catalog
) -> tuple[list[str | None], list[str | None], list[str | None]]:
    """Return the service match of a rule as 3 parallel lists: protocols, ports
    and source ports.

    `protos[i]`, `ports[i]` and `src_ports[i]` describe the same service
    member, as in a collected row of `firewall._RULEBASE_RULES`. The gate zips
    the columns into per-member pairs.

    The literal protocols and ports give pairs through `_service_pairs`. Each
    referenced `SvcObject` gives the pairs of its own protocols and ports. A
    service-group gives the pairs of its members (`Catalog.svc_pairs`). An
    object that does not resolve to protocols and ports in full raises
    `ProposalError`.
    """
    protos: list[str | None] = []
    port_specs: list[str | None] = []
    src_ports: list[str | None] = []

    def add(pairs: Iterable[tuple[str | None, str | None, str | None]]) -> None:
        for proto, port, src in pairs:
            protos.append(proto)
            port_specs.append(port)
            src_ports.append(src)

    add((proto, port, None) for proto, port in _service_pairs(list(_texts(protocols)), list(_texts(ports))))
    for token in _texts(services):
        if catalog.svc_object(token) is None:
            raise ProposalError(f"service {token!r} is not an SvcObject in this snapshot")
        pairs, gaps = catalog.svc_pairs(token)
        if gaps or not pairs:
            raise ProposalError(
                f"service {token!r} does not resolve to protocols and ports in this snapshot: "
                f"{'; '.join(dict.fromkeys(gaps)) or 'it names none'}"
            )
        add(pairs)
    return protos, port_specs, src_ports


# --- interface.set_mtu -----------------------------------------------------
#
# Platform validation runs against `catalog.interfaces`.
# `hst.app.fw_overlay_read.read_catalog` reads these facts from the Device of
# each named interface and from the MTU evidence read (`hst.core.mtu_read`).
# A platform that is not resolved or not recognised is refused. VyOS records
# the parent link as `parent_subject_uid` and `configured_tag_depth` in the
# `selector_json` of an observation (`hst.collectors.vyos`). The Cisco
# platforms record it as the property `parent_interface_uid` of the Interface
# node (`hst.collectors.cisco_common`).

MTU_MIN_BYTES = 68
MTU_MAX_BYTES = 65535

# Vendors and platform prefixes with no writable interface MTU model in the twin.
_NO_MTU_MODEL_VENDORS = frozenset({"ubiquiti", "checkpoint"})
_NO_MTU_MODEL_PLATFORM_PREFIXES = (
    "unifi-",  # hst/collectors/unifi.py sets platform=f"unifi-{type}"
    "apic",  # hst/collectors/apic.py sets platform "apic" for a controller
    "aci",  # the prefix of the platforms "aci-leaf" and "aci-spine"
    "netscaler",
    "citrix",
    "zia",
    "zscaler",
    "nautobot",
)
# hst/collectors/netscaler.py creates no Device node. Its Interface node has
# this value in `mtu_source` (`_netscaler_mtu`).
_NETSCALER_MTU_SOURCE = "NITRO Interface"

# Collector kinds that observe an interface's own MTU. Validation requires one
# of the Device's `_sources` to map, by kind, to one of these
# (`Catalog.source_kinds`).
_DEVICE_MTU_COLLECTOR_SOURCES = frozenset({"vyos", "iosxe", "iosxr", "nxos"})


def _platform_kind(fact: Mapping[str, Any] | None) -> str:
    """The platform family `interface.set_mtu` validates against: `"vyos"`,
    `"iosxe"`, `"iosxr"`, `"nxos"`, `"no_mtu_model"` (a recognised platform
    with no writable MTU model) or `"unknown"`.

    The family is read from `Device.vendor` and `Device.platform`. The
    collectors write `vendor="vyos"`/`platform="vyos"`
    (`vyos.py`), `platform="iosxe"`/`"iosxr"`/`"nxos"` (`cisco_common.py`,
    `iosxe.py`, `iosxr.py`, `nxos.py`), `platform=f"unifi-{type}"`,
    `vendor="ubiquiti"` (`unifi.py`), `platform in {"apic","aci-leaf",
    "aci-spine"}` (`apic.py`), `vendor="checkpoint"`/`platform="checkpoint"`
    (`checkpoint.py`). NetScaler creates no Device node. It is recognised by
    `Interface.mtu_source` (`_NETSCALER_MTU_SOURCE`).
    """
    if not fact:
        return "unknown"
    if str(fact.get("mtu_source") or "") == _NETSCALER_MTU_SOURCE:
        return "no_mtu_model"
    vendor = str(fact.get("vendor") or "").strip().lower()
    platform = str(fact.get("platform") or "").strip().lower()
    if vendor == "vyos" or platform == "vyos":
        return "vyos"
    if platform == "iosxe":
        return "iosxe"
    if platform == "iosxr":
        return "iosxr"
    if platform == "nxos":
        return "nxos"
    if vendor in _NO_MTU_MODEL_VENDORS or any(
        platform.startswith(p) or vendor.startswith(p) for p in _NO_MTU_MODEL_PLATFORM_PREFIXES
    ):
        return "no_mtu_model"
    return "unknown"


def _interface_mtu_bytes(observations: Sequence[Any], af: int) -> int | None:
    """Return the current MTU of the interface for one address family.

    The value is from an interface-scoped observation of the `ip_packet`
    profile with the assertion kind configured or operational. A configured
    observation takes precedence.
    """
    metric = f"ipv{af}_mtu_bytes"
    by_kind: dict[str, int] = {}
    for obs in observations:
        if (
            getattr(obs, "scope", None) == "interface"
            and getattr(obs, "profile_id", None) == "ip_packet"
            and getattr(obs, "metric", None) == metric
            and getattr(obs, "assertion_kind", None) in ("configured", "operational")
            and getattr(obs, "normalized_value", None) is not None
        ):
            by_kind.setdefault(obs.assertion_kind, obs.normalized_value)
    return by_kind.get("configured", by_kind.get("operational"))


def _mtu_afs(index: int, params: Mapping[str, Any]) -> tuple[int, ...]:
    af = params.get("af")
    if af in (None, ""):
        return (4, 6)
    if str(af) not in ("4", "6"):
        raise ProposalError(f'intent {index} (interface.set_mtu) af must be "4" or "6"')
    return (int(str(af)),)


def _mtu_prescan(intents: Sequence[Mapping[str, Any]]) -> dict[str, dict[int, int]]:
    """Map each interface uid to `{af: mtu}` for every well-formed
    `interface.set_mtu` intent in the set.

    The map is built before the validation of each intent. `_parent_ceiling_ok`
    reads it to find a parent that the same change set raises, in any intent
    order. A malformed entry is skipped.
    """
    out: dict[str, dict[int, int]] = {}
    for raw in intents:
        if str(raw.get("kind", "")).strip() != "interface.set_mtu":
            continue
        params = raw.get("params") or {}
        iface = params.get("interface")
        mtu_raw = params.get("mtu")
        if mtu_raw is None:
            continue
        try:
            mtu = int(mtu_raw)
        except (TypeError, ValueError):
            continue
        af_raw = params.get("af")
        if af_raw in (None, ""):
            afs: tuple[int, ...] = (4, 6)
        elif str(af_raw) in ("4", "6"):
            afs = (int(str(af_raw)),)
        else:
            continue
        if not iface:
            continue
        slot = out.setdefault(str(iface), {})
        for af in afs:
            slot[af] = mtu
    return out


def _parent_ceiling_ok(
    index: int,
    iface: str,
    parent_uid: str,
    af: int,
    mtu: int,
    catalog: Catalog,
    prescan: Mapping[str, Mapping[int, int]],
) -> None:
    """Refuse `mtu` on `iface` for address family `af` when it exceeds the
    parent's current MTU, unless this same change set raises the parent to at
    least `mtu` for that family too."""
    raised_to = prescan.get(parent_uid, {}).get(af)
    if raised_to is not None and raised_to >= mtu:
        return
    parent_fact = catalog.interface(parent_uid) or {}
    parent_mtu = _interface_mtu_bytes(parent_fact.get("observations") or (), af)
    if parent_mtu is None:
        raise ProposalError(
            f"intent {index} (interface.set_mtu) names {iface!r}: its parent {parent_uid!r}'s current "
            f"ipv{af} MTU is not known in this snapshot"
        )
    if mtu > parent_mtu:
        raise ProposalError(
            f"intent {index} (interface.set_mtu) sets {iface!r} to {mtu} (ipv{af}), above its parent "
            f"{parent_uid!r}'s MTU of {parent_mtu}; raise the parent's MTU to at least {mtu} in the same "
            "change, or lower this value"
        )


def _validate_interface_set_mtu(
    index: int,
    params: Mapping[str, Any],
    catalog: Catalog,
    prescan: Mapping[str, Mapping[int, int]],
) -> None:
    iface = params.get("interface")
    if not iface:
        raise ProposalError(f"intent {index} (interface.set_mtu) needs an interface")
    if params.get("mtu") is None:
        raise ProposalError(f"intent {index} (interface.set_mtu) needs an mtu")
    mtu = _int_param(params, "mtu")
    if not (MTU_MIN_BYTES <= mtu <= MTU_MAX_BYTES):
        raise ProposalError(
            f"intent {index} (interface.set_mtu) needs an mtu between {MTU_MIN_BYTES} and "
            f"{MTU_MAX_BYTES}; got {mtu}"
        )
    afs = _mtu_afs(index, params)
    iface = str(iface)

    fact = catalog.interface(iface)
    if fact is None:
        raise ProposalError(f"intent {index} (interface.set_mtu) names {iface!r}, not in this snapshot")
    kind = _platform_kind(fact)
    if kind == "no_mtu_model":
        raise ProposalError(
            f"intent {index} (interface.set_mtu) names {iface!r}: no MTU intent for this platform"
        )
    if kind == "unknown":
        raise ProposalError(f"intent {index} (interface.set_mtu) names {iface!r}: unknown platform")

    device_sources = fact.get("device_sources")
    if device_sources and catalog.source_kinds is not None:
        kinds = {catalog.source_kinds.get(name) for name in device_sources}
        if not (kinds & _DEVICE_MTU_COLLECTOR_SOURCES):
            raise ProposalError(
                f"intent {index} (interface.set_mtu) names {iface!r}: no collected MTU evidence for this "
                "device; the twin holds it from Nautobot only"
            )

    if kind == "iosxe":
        parent_uid = fact.get("parent_interface_uid")
        if parent_uid:
            raise ProposalError(
                f"intent {index} (interface.set_mtu) names {iface!r}, a subinterface; IOS-XE has no MTU "
                f"of its own for a subinterface; set it on the parent interface {parent_uid!r}"
            )
        return  # a parent/physical interface accepts any in-range value

    if kind in ("iosxr", "nxos"):
        parent_uid = fact.get("parent_interface_uid")
        if not parent_uid:
            return  # a parent/physical interface accepts any in-range value
        for af in afs:
            _parent_ceiling_ok(index, iface, str(parent_uid), af, mtu, catalog, prescan)
        return

    # vyos
    parent_uid = fact.get("parent_uid")
    tag_depth = fact.get("configured_tag_depth")
    is_vif = bool(parent_uid) or tag_depth in (1, 2)
    if not is_vif:
        return  # a physical ethernet interface accepts any in-range value
    if not parent_uid:
        raise ProposalError(
            f"intent {index} (interface.set_mtu) names {iface!r}, a vif whose parent this snapshot does "
            "not resolve"
        )
    for af in afs:
        _parent_ceiling_ok(index, iface, str(parent_uid), af, mtu, catalog, prescan)


def _zone_interfaces(label: str, token: Any, catalog: Catalog) -> list[str | None]:
    """The interface names a zone contains, as rule scoping values.

    `[None]` is returned for no zone. It gives one rule row that matches any
    interface of the flow. A zone with no interface recorded raises
    `ProposalError`.
    """
    if token in (None, ""):
        return [None]
    zone = catalog.zone(str(token))
    if zone is None:
        raise ProposalError(f"{label} {token!r} is not a Zone in this snapshot")
    names = [str(n) for n in zone.get("interfaces") or () if n]
    if not names:
        raise ProposalError(f"{label} {token!r} contains no Interface in this snapshot")
    return list(names)


# --- intents --------------------------------------------------------------


@dataclass(frozen=True)
class Intent:
    """One typed change, addressed to schema uids. `params` is the mapping of
    the caller, unchanged."""

    kind: str
    params: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "params": dict(self.params)}


def _int_param(params: Mapping[str, Any], name: str) -> int:
    try:
        return int(params[name])
    except KeyError as exc:
        raise ProposalError(f"{name} is required") from exc
    except (TypeError, ValueError) as exc:
        raise ProposalError(f"{name} {params[name]!r} is not a number") from exc


def _fw_rule_rows(intent: Intent, catalog: Catalog, ordinal: int) -> list[dict[str, Any]]:
    """A `fw_rule.add` as rule rows.

    The rule gives one row per (from-zone interface, to-zone interface) pair.
    A rule that is not zone-scoped gives one row. Every address spec goes into
    the `*_cidrs` column.
    """
    params = intent.params
    action = str(params.get("action", "")).strip().lower()
    if action not in PROPOSABLE_ACTIONS:
        raise ProposalError(
            f"action {params.get('action')!r} is not a proposable firewall action; use one of "
            f"{', '.join(sorted(PROPOSABLE_ACTIONS))}"
        )
    src, src_any = _address_side("source", params.get("source"), catalog)
    dst, dst_any = _address_side("destination", params.get("destination"), catalog)
    protos, ports, src_ports = _service(
        params.get("protocols"), params.get("ports"), params.get("services"), catalog
    )
    in_ifs = _zone_interfaces("from_zone", params.get("from_zone"), catalog)
    out_ifs = _zone_interfaces("to_zone", params.get("to_zone"), catalog)
    if params.get("in_interface"):
        in_ifs = [str(params["in_interface"])]
    if params.get("out_interface"):
        out_ifs = [str(params["out_interface"])]
    position = _int_param(params, "position")
    base_uid = str(params.get("uid") or f"fw:rule:proposed:{ordinal}")
    name = params.get("name")

    rows: list[dict[str, Any]] = []
    for i, in_if in enumerate(in_ifs):
        for j, out_if in enumerate(out_ifs):
            suffix = "" if len(in_ifs) * len(out_ifs) == 1 else f":{i}:{j}"
            rows.append(
                {
                    "uid": f"{base_uid}{suffix}",
                    "pos": position,
                    "action": action,
                    "name": name,
                    "out_if": out_if,
                    "in_if": in_if,
                    "src_any": src_any,
                    "dst_any": dst_any,
                    "svc_any": not (protos or ports),
                    "src_cidrs": list(src),
                    "src_ips": [],
                    "dst_cidrs": list(dst),
                    "dst_ips": [],
                    "protos": list(protos),
                    "ports": list(ports),
                    "src_ports": list(src_ports),
                    "svc_src_port": any(src_ports),
                    "src_ranges": [],
                    "dst_ranges": [],
                    "src_obj_count": 0,
                    "dst_obj_count": 0,
                    "svc_obj_count": 0,
                    "src_opaque": False,
                    "dst_opaque": False,
                    "svc_opaque": False,
                    "src_negate": False,
                    "dst_negate": False,
                    "svc_negate": False,
                }
            )
    return rows


# The columns of a `_NAT_RULES_QUERY` row, with the values of a rule that
# states nothing.
_NAT_ROW_DEFAULTS: dict[str, Any] = {
    "rb_uid": None,
    "rb_name": None,
    "approximate": False,
    # The Automatic NAT marker of Check Point. A proposal states its direction
    # in `kind`.
    "auto_generated": None,
    # True when an address column refers to an object, resolved or not.
    "orig_src_present": False,
    "orig_dst_present": False,
    "xlate_src_present": False,
    "xlate_dst_present": False,
    "uid": None,
    "pos": None,
    "kind": None,
    "method": None,
    "enabled": True,
    "exclude": False,
    "translation": None,
    "translation_port": None,
    "direction": None,
    "static_flag": False,
    "orig_src_raw": None,
    "orig_dst_raw": None,
    "orig_src_port": None,
    "orig_dst_port": None,
    "orig_port": None,
    "xlate_port": None,
    "protocol": None,
    "in_if": None,
    "out_if": None,
    "translation_interface": None,
    "xlate_src_original": False,
    "xlate_dst_original": False,
    "rule_approximate": False,
    "orig_src_addrs": [],
    "orig_dst_addrs": [],
    "xlate_src_addrs": [],
    "xlate_dst_addrs": [],
    # True when the object of a column was resolved only in part. The address
    # side of a proposal is resolved or explicitly any.
    "orig_src_opaque": False,
    "orig_dst_opaque": False,
    "xlate_src_opaque": False,
    "xlate_dst_opaque": False,
}

# The `nat_rule.add` params that map straight onto a row column.
_NAT_PARAM_COLUMNS = {
    "method": "method",
    "translation": "translation",
    "translation_port": "translation_port",
    "direction": "direction",
    "protocol": "protocol",
    "in_interface": "in_if",
    "out_interface": "out_if",
    "orig_src_port": "orig_src_port",
    "orig_dst_port": "orig_dst_port",
    "orig_port": "orig_port",
    "xlate_port": "xlate_port",
}


def _nat_rule_row(intent: Intent, catalog: Catalog, ordinal: int) -> dict[str, Any]:
    """A `nat_rule.add` as one `_NAT_RULES_QUERY` row.

    The address columns take the resolved edge lists (`*_addrs`).
    """
    params = intent.params
    kind = str(params.get("kind", "")).strip().lower()
    if kind not in PROPOSABLE_NAT_KINDS:
        raise ProposalError(
            f"NAT kind {params.get('kind')!r} is not proposable; use one of "
            f"{', '.join(sorted(PROPOSABLE_NAT_KINDS))}"
        )
    row = dict(_NAT_ROW_DEFAULTS)
    row["uid"] = str(params.get("uid") or f"nat:rule:proposed:{ordinal}")
    row["pos"] = _int_param(params, "position")
    row["kind"] = kind
    row["static_flag"] = kind == "static"
    row["exclude"] = bool(params.get("exclude"))
    row["rb_uid"] = params.get("rulebase")
    row["rb_name"] = params.get("rulebase_name") or params.get("rulebase")
    for param, column in _NAT_PARAM_COLUMNS.items():
        if params.get(param) not in (None, ""):
            row[column] = params[param]
    for param, column in (
        ("orig_src", "orig_src_addrs"),
        ("orig_dst", "orig_dst_addrs"),
        ("xlate_src", "xlate_src_addrs"),
        ("xlate_dst", "xlate_dst_addrs"),
    ):
        specs, is_any = _address_side(param, params.get(param), catalog)
        row[column] = [] if is_any else specs
        row[f"{param}_present"] = not is_any
    return row


# The `nat_rule.modify` params that change a rule beside `_NAT_PARAM_COLUMNS`.
_NAT_MODIFY_FIELDS = ("enabled", "kind", "exclude", "orig_src", "orig_dst", "xlate_src", "xlate_dst")


def _translation_side(kind: str) -> str:
    """Return the translated column that `gates.nat._nat_row_sets` fills from
    the raw `translation` string of a rule. The column is the source for snat
    and the destination for dnat and static."""
    return "xlate_src" if kind == "snat" else "xlate_dst"


def _apply_nat_modify(row: dict[str, Any], changes: Mapping[str, Any], catalog: Catalog) -> dict[str, Any]:
    """Apply a `nat_rule.modify` to one collected NatRule row.

    Only the stated fields change. A modification that states no field raises
    `ProposalError`. A modification of the position raises `ProposalError`. A
    rule moves by a remove and an add.

    `_nat_match_set` reads the raw config string of a rule before its resolved
    edges. A restated original column clears its `orig_*_raw` string. A
    restated translated column clears the raw `translation` when the kind of
    the rule, before or after the change, reads the translation into that
    column and the change does not state `translation`. A change of kind that
    moves the raw translation to the other translated column must restate that
    column.
    """
    if "position" in changes:
        raise ProposalError("a NAT rule is moved by a remove and an add, not by a modify of its position")
    merged = dict(row)
    touched = False
    for param, column in _NAT_PARAM_COLUMNS.items():
        if param in changes:
            merged[column] = changes[param]
            touched = True
    if "enabled" in changes:
        merged["enabled"] = bool(changes["enabled"])
        touched = True
    if "exclude" in changes:
        merged["exclude"] = bool(changes["exclude"])
        touched = True
    before = _nat_rule_kind(row)
    if "kind" in changes:
        kind = str(changes["kind"] or "").strip().lower()
        if kind not in PROPOSABLE_NAT_KINDS:
            raise ProposalError(
                f"NAT kind {changes['kind']!r} is not proposable; use one of "
                f"{', '.join(sorted(PROPOSABLE_NAT_KINDS))}"
            )
        side = _translation_side(kind)
        if row.get("translation") and side != _translation_side(before) and side not in changes:
            raise ProposalError(
                f"changing the kind of NAT rule {row.get('uid')!r} from {before} to {kind} moves its "
                f"translation {row['translation']!r} to the other side; restate {side}"
            )
        merged["kind"], merged["static_flag"] = kind, kind == "static"
        touched = True
    raw_side = _translation_side(merged["kind"] if "kind" in changes else before)
    for param, column in (
        ("orig_src", "orig_src_addrs"),
        ("orig_dst", "orig_dst_addrs"),
        ("xlate_src", "xlate_src_addrs"),
        ("xlate_dst", "xlate_dst_addrs"),
    ):
        if param not in changes:
            continue
        specs, is_any = _address_side(param, changes[param], catalog)
        merged[column] = [] if is_any else specs
        merged[f"{param}_opaque"] = False
        merged[f"{param}_present"] = not is_any
        if param in ("orig_src", "orig_dst"):
            merged[f"{param}_raw"] = None
        elif (param == raw_side or param == _translation_side(before)) and "translation" not in changes:
            merged["translation"] = None
        touched = True
    if not touched:
        raise ProposalError("a modify intent must state at least one field to change")
    return merged


def parse_intents(intents: Sequence[Mapping[str, Any]], catalog: Catalog) -> list[Intent]:
    """Validate a change set. Every fault raises `ProposalError`.

    An intent kind outside the catalog is refused by name.
    """
    out: list[Intent] = []
    mtu_prescan = _mtu_prescan(intents)
    for index, raw in enumerate(intents):
        kind = str(raw.get("kind", "")).strip()
        if kind not in INTENT_KINDS:
            raise ProposalError(
                f"intent {index} has kind {kind!r}, which the policy overlay does not "
                f"express; the catalog is {', '.join(sorted(INTENT_KINDS))}"
            )
        params = dict(raw.get("params") or {})
        intent = Intent(kind=kind, params=params)
        # A malformed intent is refused here, before any read.
        if kind == "fw_rule.add":
            if not params.get("rulebase"):
                raise ProposalError(
                    f"intent {index} ({kind}) needs a rulebase, or a device for the rulebase to "
                    "be derived from"
                )
            _fw_rule_rows(intent, catalog, index)
        elif kind == "nat_rule.add":
            if not params.get("device"):
                raise ProposalError(f"intent {index} ({kind}) needs a device")
            _nat_rule_row(intent, catalog, index)
        elif kind in ("fw_rule.remove", "fw_rule.modify"):
            if not params.get("rulebase") or not params.get("rule"):
                raise ProposalError(f"intent {index} ({kind}) needs a rulebase and a rule uid")
        elif kind in ("nat_rule.remove", "nat_rule.modify"):
            if not params.get("device") or not params.get("rule"):
                raise ProposalError(f"intent {index} ({kind}) needs a device and a rule uid")
            if kind == "nat_rule.modify":
                # The 2 checks of `_apply_nat_modify`, made before any read.
                if "position" in params:
                    raise ProposalError(
                        f"intent {index} ({kind}): a NAT rule is moved by a remove and an add, "
                        "not by a modify of its position"
                    )
                if not any(p in params for p in (*_NAT_PARAM_COLUMNS, *_NAT_MODIFY_FIELDS)):
                    raise ProposalError(f"intent {index} ({kind}) must state at least one field to change")
        elif kind == "bgp_session.shut":
            if not params.get("session"):
                raise ProposalError(f"intent {index} ({kind}) needs a session (a BgpSession uid)")
        elif kind == "ospf.interface_cost":
            if not params.get("router_id") or not params.get("address") or params.get("cost") is None:
                raise ProposalError(
                    f"intent {index} ({kind}) needs a router_id, the interface address and a cost"
                )
            if _int_param(params, "cost") < 1:
                raise ProposalError(f"intent {index} ({kind}) needs a cost of at least 1")
        elif kind == "ospf.adjacency_down":
            if not params.get("router_a") or not params.get("router_b"):
                raise ProposalError(f"intent {index} ({kind}) needs router_a and router_b (router ids)")
        elif kind == "interface.set_mtu":
            _validate_interface_set_mtu(index, params, catalog, mtu_prescan)
        else:  # zone.add_interface / zone.remove_interface
            if not params.get("zone") or not params.get("interface"):
                raise ProposalError(f"intent {index} ({kind}) needs a zone and an interface")
            if catalog.zone(str(params["zone"])) is None:
                raise ProposalError(f"intent {index} names zone {params['zone']!r}, not in this snapshot")
        out.append(intent)
    return out


# --- row rewriting --------------------------------------------------------

# A fragment of the query text identifies each read that the overlay rewrites.
# A query with none of these fragments is returned untouched. The rule read
# and the local-zone context read are matched by the whole query constant
# (`_gate_queries`).
_Q_NAT_RULES = "MATCH (rb)-[hr:HAS_RULE]->(n:NatRule)"
_Q_ZONE_PAIR = "MATCH (rb:FwRulebase)-[fz:FROM_ZONE]->(src), (rb)-[tz:TO_ZONE]->(dst)"
_Q_INGRESS_ZONE = "RETURN z.name AS name"
# The route read of the tracer (`hst.path.trace._ROUTES_QUERY`). `route_rows`
# replaces its rows for a change set with a routing intent.
_Q_ROUTES = "[r:STATIC_ROUTE|LEARNED_ROUTE|ORIGINATES]->(p:Prefix)"
# The MTU evidence read (`hst.core.mtu_read.MTU_QUERY`).
_Q_MTU = "-[r:HAS_MTU]->(o:MtuObservation {collection_ts: $snap})"


def _gate_queries() -> tuple[frozenset[str], str]:
    """Return the rule queries of the gates and the query of the local-zone
    context read."""
    from hst.path.gates.firewall import _RULEBASE_RULES
    from hst.path.gates.local_zone import _LOCAL_RULES_QUERY, _LOCAL_ZONE_CONTEXT_QUERY

    return frozenset({_RULEBASE_RULES, _LOCAL_RULES_QUERY}), _LOCAL_ZONE_CONTEXT_QUERY


def _insert_by_position(rows: list[dict[str, Any]], new: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Place new rows in an ordered rule list, ahead of the first collected rule
    at or after their position.

    The collected rules keep the positions they were read with.
    """
    if not new:
        return rows
    want = new[0].get("pos")
    for index, rule in enumerate(rows):
        pos = rule.get("pos")
        if pos is None or want is None or int(pos) >= int(want):
            return rows[:index] + [dict(n) for n in new] + rows[index:]
    return rows + [dict(n) for n in new]


def _apply_modify(row: dict[str, Any], changes: Mapping[str, Any], catalog: Catalog) -> dict[str, Any]:
    """Apply a `fw_rule.modify` to one collected rule row.

    Only the stated fields change. A modification that states nothing is
    refused.
    """
    out = dict(row)
    touched = False
    if "action" in changes:
        action = str(changes["action"]).strip().lower()
        if action not in PROPOSABLE_ACTIONS:
            raise ProposalError(f"action {changes['action']!r} is not a proposable firewall action")
        out["action"] = action
        touched = True
    if "enabled" in changes:
        if not changes["enabled"]:
            return {}
        touched = True
    for side, prefix in (("source", "src"), ("destination", "dst")):
        if side in changes:
            specs, is_any = _address_side(side, changes[side], catalog)
            out[f"{prefix}_any"] = is_any
            out[f"{prefix}_cidrs"] = list(specs)
            out[f"{prefix}_ips"] = []
            out[f"{prefix}_ranges"] = []
            # A restated side drops the collected row's opacity and negation signals.
            out[f"{prefix}_obj_count"] = 0
            out[f"{prefix}_opaque"] = False
            out[f"{prefix}_opaque_reasons"] = []
            out[f"{prefix}_negate"] = False
            touched = True
    if any(k in changes for k in ("protocols", "ports", "services")):
        protos, ports, src_ports = _service(
            changes.get("protocols"), changes.get("ports"), changes.get("services"), catalog
        )
        out["protos"] = protos
        out["ports"] = ports
        out["src_ports"] = src_ports
        out["svc_src_port"] = any(src_ports)
        out["svc_any"] = not (protos or ports)
        out["svc_obj_count"] = 0
        out["svc_opaque"] = False
        out["svc_opaque_reasons"] = []
        out["svc_negate"] = False
        touched = True
    if not touched:
        raise ProposalError("a modify intent must state at least one field to change")
    return out


@dataclass(frozen=True)
class DeniedAddresses:
    """The two address sets a change set denies, kept apart by direction.

    `to_specs` are the addresses the change stops traffic being sent to,
    `from_specs` the addresses it stops traffic being accepted from. The specs
    are the literal values the intents state (an address, a prefix, a range, or
    the addresses a NetObject resolved to). `to_set` and `from_set` are the
    same values as merged intervals.
    """

    to_specs: list[str] = field(default_factory=list)
    from_specs: list[str] = field(default_factory=list)

    @property
    def to_set(self) -> list[tuple[int, int, int]]:
        return _intervals(list(self.to_specs))

    @property
    def from_set(self) -> list[tuple[int, int, int]]:
        return _intervals(list(self.from_specs))

    def any_denied(self) -> bool:
        return bool(self.to_specs or self.from_specs)


# The zone an interface sits in, and the rulebases bound to a zone pair.
ZONE_OF_INTERFACE = """
MATCH (:Interface:Obj {uid: $iface, collection_ts: $snap})<-[c:CONTAINS]-(z:Zone:Obj)
WHERE NOT z:Retired AND c._retired_at IS NULL AND z.collection_ts = $snap
RETURN z.uid AS uid, z.name AS name
ORDER BY z.name LIMIT 1"""

# The rows replace the zone-pair rows of the tracer for a flow whose zone
# membership the change moves. The query returns every column that the gate
# reads from a zone-pair row.
ZONE_PAIR_RULEBASES = """
MATCH (src:Zone:Obj {uid: $src, collection_ts: $snap}), (dst:Zone:Obj {uid: $dst, collection_ts: $snap})
MATCH (rb:FwRulebase)-[fz:FROM_ZONE]->(src), (rb)-[tz:TO_ZONE]->(dst)
WHERE NOT rb:Retired AND NOT src:Retired AND NOT dst:Retired
  AND fz._retired_at IS NULL AND tz._retired_at IS NULL
  AND rb.collection_ts = $snap
RETURN rb.uid AS rb_uid, rb.name AS rb_name, rb.af AS af, rb.default_action AS default_action,
       rb.default_action_unknown AS default_action_unknown,
       rb.global_state_policy AS global_state_policy, rb.state_policy_basis AS state_policy_basis,
       rb.established_default_unknown AS established_default_unknown,
       src.name AS src_zone, dst.name AS dst_zone, dst.default_action AS zone_default,
       dst.default_action_unknown AS zone_default_unknown,
       dst.established_default_unknown AS zone_established_default_unknown
ORDER BY rb.uid"""


@dataclass
class ZoneMembership:
    """The zone-membership changes of the set, keyed by interface.

    `moved_in` maps an interface to the zone that it joins. `moved_out` maps an
    interface to the zones that it leaves. The schema allows an interface in
    more than one zone. The tracer takes the first zone by name. A move sets
    the effective zone for the pair lookup.
    """

    moved_in: dict[str, str] = field(default_factory=dict)
    moved_out: dict[str, set[str]] = field(default_factory=dict)

    def touches(self, interface: Any) -> bool:
        return bool(interface) and (interface in self.moved_in or interface in self.moved_out)


@dataclass
class ChangeSet:
    """A parsed change set, and the row rewriting it performs.

    `path.session._read` passes every read to `rewrite(query, params, rows)`.
    `rewrite` depends on its arguments, the parsed intents and the callables
    that the caller supplies. A zone move needs 2 of them:
    `zone_of(interface_uid) -> zone uid | None` and `pair_rows(src_zone_uid,
    dst_zone_uid) -> rows` in the shape the zone-pair query returns.
    """

    intents: list[Intent]
    catalog: Catalog = field(default_factory=Catalog)
    zone_of: Callable[[str], str | None] | None = None
    pair_rows: Callable[[str, str], list[dict[str, Any]]] | None = None
    # `(table_uid, collected rows) -> rows` for the route read of the tracer.
    # It returns the after-FIB of the routing calculation for a table that the
    # calculation covers, and the collected rows for any other table.
    # `hst.app.fw_overlay_read` supplies it for a change set with a routing
    # intent. None leaves the read unchanged.
    route_rows: Callable[[str, list[dict[str, Any]]], list[dict[str, Any]]] | None = None
    errors: ErrorSink = field(default_factory=ErrorSink)
    membership: ZoneMembership = field(init=False, default_factory=ZoneMembership)

    def __post_init__(self) -> None:
        self.membership = ZoneMembership()
        for intent in self.intents:
            if intent.kind == "zone.add_interface":
                self.membership.moved_in[str(intent.params["interface"])] = str(intent.params["zone"])
            elif intent.kind == "zone.remove_interface":
                self.membership.moved_out.setdefault(str(intent.params["interface"]), set()).add(
                    str(intent.params["zone"])
                )

    # -- firewall rules

    def _rewrite_fw_rules(self, rulebase: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = [dict(r) for r in rows]
        for index, intent in enumerate(self.intents):
            if intent.kind not in FW_KINDS or str(intent.params.get("rulebase")) != rulebase:
                continue
            if intent.kind == "fw_rule.add":
                out = _insert_by_position(out, _fw_rule_rows(intent, self.catalog, index))
                continue
            target = str(intent.params["rule"])
            hit = [r for r in out if str(r.get("uid")) == target]
            if not hit:
                raise ProposalError(
                    f"rulebase {rulebase} holds no enabled FwRule {target!r} in this snapshot"
                )
            if intent.kind == "fw_rule.remove":
                out = [r for r in out if str(r.get("uid")) != target]
            else:
                # `_apply_modify` returns an empty dict for a rule that the
                # modification disables. A disabled rule leaves the list.
                changed = _apply_modify(hit[0], intent.params, self.catalog)
                rebuilt = []
                for rule in out:
                    if str(rule.get("uid")) != target:
                        rebuilt.append(rule)
                    elif changed:
                        rebuilt.append(changed)
                out = rebuilt
        return out

    # -- NAT rules

    def _rewrite_nat_rules(self, device: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = [dict(r) for r in rows]
        for index, intent in enumerate(self.intents):
            if intent.kind not in NAT_KINDS or str(intent.params.get("device")) != device:
                continue
            if intent.kind == "nat_rule.add":
                new = _nat_rule_row(intent, self.catalog, index)
                if new["rb_uid"] is None and out:
                    # A proposal with no rulebase joins the rulebase of the
                    # first collected row.
                    new["rb_uid"], new["rb_name"] = out[0]["rb_uid"], out[0]["rb_name"]
                # The rule takes the address family of its rulebase (VyOS `nat`
                # or `nat66`) when the collected rows of the rulebase state
                # exactly one family.
                families = {r.get("af") for r in out if r.get("rb_uid") == new["rb_uid"]} & {4, 6}
                if new.get("af") is None and len(families) == 1:
                    new["af"] = families.pop()
                out = _insert_by_position(out, [new])
                continue
            target = str(intent.params["rule"])
            hit = [r for r in out if str(r.get("uid")) == target]
            if not hit:
                raise ProposalError(f"device {device} enforces no NatRule {target!r} in this snapshot")
            if intent.kind == "nat_rule.remove":
                out = [r for r in out if str(r.get("uid")) != target]
            else:
                merged = _apply_nat_modify(hit[0], intent.params, self.catalog)
                out = [merged if str(r.get("uid")) == target else r for r in out]
        return out

    # -- zones

    def _effective_zone(self, interface: str | None, fallback: str | None) -> str | None:
        if not interface:
            return fallback
        if interface in self.membership.moved_in:
            return self.membership.moved_in[interface]
        left = self.membership.moved_out.get(interface)
        if left and fallback in left:
            return None
        return fallback

    def _rewrite_zone_pair(self, in_if: Any, out_if: Any, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not (self.membership.touches(in_if) or self.membership.touches(out_if)):
            return rows
        if self.zone_of is None or self.pair_rows is None:
            self.errors.report(
                "zone-move-not-resolvable",
                "a zone-membership change was proposed but no zone lookup was supplied, so "
                "the zone pair governing this flow was read as collected",
                in_if or out_if,
            )
            return rows
        src = self._effective_zone(in_if, self.zone_of(in_if) if in_if else None)
        dst = self._effective_zone(out_if, self.zone_of(out_if) if out_if else None)
        if not src or not dst:
            # The flow crosses no zone pair under the change. With no zone-pair
            # row the tracer reads the device-wide rulebases, as VyOS does for
            # an interface in no zone.
            return []
        return self.pair_rows(src, dst)

    def _rewrite_ingress_zone(self, in_if: Any, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not self.membership.touches(in_if) or in_if is None:
            return rows
        collected = str(rows[0]["name"]) if rows else None
        moved_in = self.membership.moved_in.get(in_if)
        if moved_in:
            zone = self.catalog.zone(moved_in)
            row: dict[str, Any] = {"name": str(zone["name"]) if zone else moved_in}
            if zone is not None:
                default_action = zone.get("default_action")
                if default_action is not None:
                    row["default_action"] = default_action
                # The other columns of the zone read of the tracer
                # (`gates.firewall._ZONE_OF_INTERFACE`).
                for column in (
                    "default_action_unknown",
                    "established_default_unknown",
                    "intra_zone_filtering",
                    "intra_zone_action",
                ):
                    value = zone.get(column)
                    if value is not None:
                        row[column] = value
            return [row]
        left = self.membership.moved_out.get(in_if) or set()
        if collected and any(collected == str((self.catalog.zone(z) or {}).get("name") or z) for z in left):
            return []
        return rows

    def _rewrite_local_zone_context(
        self, params: Mapping[str, Any], rows: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Return the (interface, zone) rows of the local-zone gate with the
        zone moves applied.

        A joined zone replaces the zones of the interface, as in
        `_effective_zone`. A left zone is dropped. An interface that joins a
        zone keeps no row when its name is not known, and the error sink gets
        `zone-move-not-resolvable`.
        """
        touched = [
            str(i)
            for i in dict.fromkeys((params.get("in_if"), params.get("out_if")))
            if i and self.membership.touches(i)
        ]
        if not touched:
            return rows
        out = list(rows)
        for interface in touched:
            collected = [r for r in out if r.get("if_uid") == interface]
            out = [r for r in out if r.get("if_uid") != interface]
            moved_in = self.membership.moved_in.get(interface)
            if moved_in:
                zone = self.catalog.zone(moved_in)
                name = next((r.get("if_name") for r in collected if r.get("if_name")), None) or (
                    self.catalog.interface(interface) or {}
                ).get("name")
                if name is None:
                    self.errors.report(
                        "zone-move-not-resolvable",
                        "an interface joins a zone but its name was not collected, so the "
                        "local-zone binding of the interface is not known",
                        interface,
                    )
                    continue
                out.append(
                    {
                        "if_uid": interface,
                        "if_name": name,
                        "zone_uid": self.catalog.zone_uid(moved_in),
                        "zone_name": str(zone["name"]) if zone else moved_in,
                    }
                )
                continue
            left = {self.catalog.zone_uid(token) for token in self.membership.moved_out.get(interface, ())}
            out.extend(r for r in collected if r.get("zone_uid") not in left)
        return sorted(out, key=lambda r: (str(r.get("if_uid")), str(r.get("zone_uid"))))

    # -- MTU evidence

    def _mtu_intent_map(self) -> dict[str, dict[int, int]]:
        """Map each changed interface uid to `{af: mtu}`, from the intents that
        `parse_intents` validated."""
        out: dict[str, dict[int, int]] = {}
        for intent in self.intents:
            if intent.kind != "interface.set_mtu":
                continue
            iface = str(intent.params["interface"])
            mtu = int(intent.params["mtu"])
            af_raw = intent.params.get("af")
            afs = (4, 6) if af_raw in (None, "") else (int(str(af_raw)),)
            slot = out.setdefault(iface, {})
            for af in afs:
                slot[af] = mtu
        return out

    def _restate_mtu_row(
        self, obs: Mapping[str, Any], afs: Mapping[int, int], *, source_iface: str
    ) -> dict[str, Any] | None:
        """Return one MTU_QUERY observation dict restated with the interface
        MTU in `afs`.

        Return `None` for an observation of another scope, assertion kind,
        direction, metric or address family, for an operator import, and for a
        profile that `restate_ip_bytes` rejects.
        """
        if obs.get("scope", "interface") != "interface":
            return None
        if obs.get("assertion_kind") not in ("configured", "operational"):
            return None
        if str(obs.get("source") or "").startswith("manual:"):
            return None  # an intent does not restate an operator import
        if obs.get("direction") != "both":
            # The intent restates a bidirectional ceiling only.
            return None
        metric = obs.get("metric")
        if metric in ("ipv4_mtu_bytes", "ipv6_mtu_bytes"):
            af = 4 if metric == "ipv4_mtu_bytes" else 6
            if af not in afs:
                return None
            new_bytes = afs[af]
        elif metric in {"l2_max_frame_bytes", "l2_payload_mtu_bytes"}:
            # These metrics have no address family. The frame ceiling of the
            # interface takes the stated value only when the intent covers
            # both families (the default).
            if len(afs) < 2:
                return None
            new_bytes = next(iter(afs.values()))
        else:
            return None
        try:
            # `obs` is `properties(o)` from the graph, plus `uid` and
            # `collection_ts`. These 2 keys are not model fields.
            # `hst.core.mtu_read.read_mtu` applies the same filter.
            observation = MtuObservation.model_validate(
                {k: v for k, v in obs.items() if k in MtuObservation.model_fields}
            )
        except Exception:
            return None
        try:
            raw_value_json, normalized_value = restate_ip_bytes(observation, ip_bytes=new_bytes)
        except ValueError:
            return None
        try:
            selector = json.loads(observation.selector_json)
        except (TypeError, ValueError):
            selector = {"version": 1}
        if not isinstance(selector, dict):
            selector = {"version": 1}
        selector["intent"] = {"kind": "interface.set_mtu", "interface": source_iface, "mtu": new_bytes}
        restated = dict(obs)
        restated.update(
            raw_value_json=raw_value_json,
            normalized_value=normalized_value,
            assertion_kind="intent",
            resolution_state="explicit",
            source="intent:interface.set_mtu",
            raw_evidence_ref="intent",
            selector_json=canonical_json(selector),
            gaps=[],
        )
        return restated

    def _derived_mtu_target(
        self, obs: Mapping[str, Any], targets: Mapping[str, Mapping[int, int]]
    ) -> tuple[str, Mapping[int, int]] | None:
        """Return the changed parent interface that the observation derives
        from, with its `{af: mtu}`.

        The parent is `derived_from_subject_uid` in the `selector_json` of the
        observation. `hst.collectors.vyos` and `hst.collectors.cisco_common`
        record it. Return `None` when the parent is not a changed interface.
        """
        selector_json = obs.get("selector_json")
        if not isinstance(selector_json, str):
            return None
        try:
            selector = json.loads(selector_json)
        except (TypeError, ValueError):
            return None
        if not isinstance(selector, dict):
            return None
        parent = selector.get("derived_from_subject_uid")
        if parent and str(parent) in targets:
            return str(parent), targets[str(parent)]
        return None

    def _rewrite_mtu(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        targets = self._mtu_intent_map()
        if not targets:
            return rows
        # The Port that holds the frame-ceiling row of a changed ethernet
        # interface. The catalog has it as `port_uid`, read from `REALIZED_BY`.
        port_targets: dict[str, tuple[str, dict[int, int]]] = {}
        for iface, afs in targets.items():
            port_uid = (self.catalog.interface(iface) or {}).get("port_uid")
            if port_uid:
                port_targets[str(port_uid)] = (iface, afs)
        legacy: dict[str, int] = {iface: max(afs.values()) for iface, afs in targets.items()}

        out: list[dict[str, Any]] = []
        for row in rows:
            subject = str(row["subject_uid"]) if row.get("subject_uid") is not None else None
            new_row = dict(row)
            obs = row.get("observation")
            if isinstance(obs, dict):
                if subject in targets:
                    restated = self._restate_mtu_row(obs, targets[subject], source_iface=subject)
                elif subject in port_targets:
                    port_iface, port_afs = port_targets[subject]
                    restated = self._restate_mtu_row(obs, port_afs, source_iface=port_iface)
                else:
                    derived = self._derived_mtu_target(obs, targets)
                    restated = (
                        self._restate_mtu_row(obs, derived[1], source_iface=derived[0])
                        if derived is not None
                        else None
                    )
                if restated is not None:
                    new_row["observation"] = restated
            if subject in legacy:
                new_row["legacy_mtu"] = legacy[subject]
            out.append(new_row)
        return out

    def mtu_subjects(self) -> set[str]:
        """Return every subject uid that the `interface.set_mtu` intents of this
        change set restate directly.

        The subjects are each changed interface and its Port when the catalog
        has a `port_uid` for it. The Port holds the frame-ceiling row of an
        ethernet interface. A subinterface that derives from a changed parent
        is not in the set.
        """
        subjects: set[str] = set()
        for intent in self.intents:
            if intent.kind != "interface.set_mtu":
                continue
            iface = str(intent.params["interface"])
            subjects.add(iface)
            port_uid = (self.catalog.interface(iface) or {}).get("port_uid")
            if port_uid:
                subjects.add(str(port_uid))
        return subjects

    # -- the hook

    def rewrite(self, query: str, params: Mapping[str, Any], rows: Any) -> Any:
        """The `path.session._read` overlay hook. A query this set does not
        change returns its rows untouched, by identity."""
        listed = list(rows)
        rule_queries, local_zone_context = _gate_queries()
        if query in rule_queries:
            return self._rewrite_fw_rules(str(params.get("rb")), listed)
        if query == local_zone_context:
            return self._rewrite_local_zone_context(params, listed)
        if _Q_NAT_RULES in query:
            return self._rewrite_nat_rules(str(params.get("dev")), listed)
        if _Q_ZONE_PAIR in query:
            return self._rewrite_zone_pair(params.get("in_if"), params.get("out_if"), listed)
        if _Q_INGRESS_ZONE in query:
            return self._rewrite_ingress_zone(params.get("in_if"), listed)
        if _Q_ROUTES in query and self.route_rows is not None and params.get("vrf"):
            return self.route_rows(str(params["vrf"]), listed)
        if _Q_MTU in query:
            return self._rewrite_mtu(listed)
        return rows

    # -- what the set denies, for the route consequence

    def denied_directions(self) -> DeniedAddresses:
        """The address sets the change set newly denies, kept apart by direction.

        `to_specs` is the destination side of a deny (traffic the change stops
        being sent to those addresses), `from_specs` the source side. A side
        stated as `any` contributes nothing.

        Only `fw_rule.add` with a deny action contributes.

        The service, the rule position and shadowing by another rule in the
        rulebase are not read.
        """
        to_specs: list[str] = []
        from_specs: list[str] = []
        for intent in self.intents:
            if intent.kind != "fw_rule.add":
                continue
            if str(intent.params.get("action", "")).strip().lower() not in DENY_ACTIONS:
                continue
            dst, dst_any = _address_side("destination", intent.params.get("destination"), self.catalog)
            if not dst_any:
                to_specs.extend(dst)
            src, src_any = _address_side("source", intent.params.get("source"), self.catalog)
            if not src_any:
                from_specs.extend(src)
        return DeniedAddresses(to_specs=to_specs, from_specs=from_specs)

    def unevaluated_for_routing(self) -> list[Intent]:
        """The intents in this set whose effect on a route `denied_directions()`
        does not evaluate.

        `denied_directions()` derives the routing follow-on from `fw_rule.add`
        deny intents alone.
        """
        gap_kinds = (FW_KINDS - {"fw_rule.add"}) | NAT_KINDS | ZONE_KINDS
        return [intent for intent in self.intents if intent.kind in gap_kinds]

    def denied_sets(self) -> list[tuple[int, int, int]]:
        """The destination address set the change set newly denies.

        Only the destination side of a `fw_rule.add` with a deny action is in
        the set. The routing follow-on reads the set to find the peerings and
        next hops that the change stops traffic to. A `fw_rule.modify` and a
        `fw_rule.remove` are not in the set. The trace comparison covers them.
        """
        specs: list[str] = []
        for intent in self.intents:
            if intent.kind != "fw_rule.add":
                continue
            if str(intent.params.get("action", "")).strip().lower() not in DENY_ACTIONS:
                continue
            side, is_any = _address_side("destination", intent.params.get("destination"), self.catalog)
            if is_any:
                continue
            specs.extend(side)
        return _intervals(specs)

    def changed_rulebases(self) -> set[str]:
        """The rulebases this change set rewrites, by uid.

        A path is only decided by the change where the rulebase that decided it
        is one of these. A NAT or zone intent names no rulebase.
        """
        return {
            str(intent.params["rulebase"])
            for intent in self.intents
            if intent.kind in FW_KINDS and intent.params.get("rulebase")
        }


# --- path rows ------------------------------------------------------------
#
# A trace returns one leg per path that it walked and one prose line for all
# legs (`_combined_verdict` in `hst.path.trace`). `path_rows` returns one row
# per leg with the destination, the egress interface, the next hop, the blocked
# state and the rule that decided the path.
#
# `compare_paths` puts paths that share both outcomes, an egress and a note on
# one group row with the path count. It lists at most `_MAX_PATH_GROUPS` groups
# and returns the count of all groups.

# The count of group rows that one flow lists, and the count of destinations
# and of next hops that one group lists. The counts returned beside the lists
# cover all members.
_MAX_PATH_GROUPS = 8
_MAX_PATH_SAMPLE = 4


def _mtu_stage_subjects(mtu: Mapping[str, Any]) -> dict[str, str]:
    """Map each stage_id to its subject uid, over the `stages` of one
    `MtuResult` and of every nested lane, connection and candidate result.

    `hst.path.mtu._merge_path` and `_merge_lanes` fold a trace with 2 or more
    lanes or interpretations into `.lanes` and `.connections`. Each of those is
    an `MtuResult` with its own `stages`.
    """
    out: dict[str, str] = {}
    for stage in mtu.get("stages") or ():
        subject = stage.get("egress_subject_uid") or stage.get("ingress_subject_uid")
        stage_id = stage.get("stage_id")
        if stage_id and subject:
            out[str(stage_id)] = str(subject)
    for key in ("lanes", "connections", "candidates"):
        for nested in mtu.get(key) or ():
            if isinstance(nested, Mapping):
                out.update(_mtu_stage_subjects(nested))
    return out


def _mtu_side(mtu: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Return the bounded MTU view of the top-level `mtu` result of one trace,
    a JSON-shaped `hst.core.mtu.MtuResult`.

    The view holds the outcome, the known ceiling, the subjects of the
    bottleneck stages and the codes in `coverage.uncovered`.
    `coverage.uncovered` is set on a `fits_known_limits` outcome, and on a
    `conditional` outcome where the endpoint gaps of a fits lane survive the
    fold. The return value is `None` when the flow had no MTU request.

    A path that crosses a proxy, for example the SNIP/DNAT hop of a NetScaler,
    splits into 2 `connections`. Each connection is an `MtuResult` with its own
    `known_ceiling_bytes`, `bottleneck_stage_ids`, `coverage` and `stages`.
    The top-level result folds only `outcome` and leaves its own copies of
    those 4 fields empty. When `connections` is non-empty, the known ceiling
    is the minimum across the connections, or `None` when no connection has
    one. The bottleneck is the union of the bottleneck subjects of every
    connection. The stage ids of a connection are resolved against the stages
    of that connection. `uncovered` is the sorted union of the coverage gaps
    of every connection. `outcome` is the top-level value.
    """
    if not mtu:
        return None
    connections = [c for c in (mtu.get("connections") or ()) if isinstance(c, Mapping)]
    if connections:
        ceilings = [c["known_ceiling_bytes"] for c in connections if c.get("known_ceiling_bytes") is not None]
        bottleneck: set[str] = set()
        uncovered: set[str] = set()
        for conn in connections:
            conn_subjects = _mtu_stage_subjects(conn)
            bottleneck.update(
                conn_subjects[s] for s in conn.get("bottleneck_stage_ids") or () if s in conn_subjects
            )
            uncovered.update((conn.get("coverage") or {}).get("uncovered") or ())
        return {
            "outcome": mtu.get("outcome"),
            "known_ceiling_bytes": min(ceilings) if ceilings else None,
            "bottleneck": sorted(bottleneck),
            "uncovered": sorted(uncovered),
        }
    stage_subjects = _mtu_stage_subjects(mtu)
    bottleneck_ids = sorted(
        {stage_subjects[s] for s in mtu.get("bottleneck_stage_ids") or () if s in stage_subjects}
    )
    coverage = mtu.get("coverage") or {}
    return {
        "outcome": mtu.get("outcome"),
        "known_ceiling_bytes": mtu.get("known_ceiling_bytes"),
        "bottleneck": bottleneck_ids,
        "uncovered": list(coverage.get("uncovered") or ()),
    }


def _path_note(row: Mapping[str, Any], changed: set[str]) -> str | None:
    """Return the note for a path that is not blocked.

    The note states that the change does not rewrite the rulebase that decided
    the path, or that no rulebase decided it (intra-zone traffic, or a device
    with no rulebase bound in the snapshot). Return `None` for a blocked path
    and for a path that a changed rulebase decided.
    """
    if row.get("blocked"):
        return None
    rulebase = row.get("rulebase")
    if rulebase and str(rulebase) in changed:
        return None
    if rulebase:
        return f"decided by {rulebase}, which this change does not alter"
    return "no rulebase decided this path in the snapshot, so no rulebase this change alters governs it"


def path_rows(
    legs: Sequence[Mapping[str, Any]],
    changed_rulebases: set[str] | None = None,
    *,
    mtu: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return one row per leg that the tracer walked, in the order of the tracer.

    `destination` is the `dst_label` of the leg, the part of the destination
    set that the leg covers when the set spans 2 or more routes. Without a
    `dst_label` it is the matched prefix. Every row has its next hop.

    `mtu` is the top-level `mtu` result of the trace, one `MtuResult` per flow.
    With `mtu`, every row of the flow has the same `mtu_outcome`,
    `mtu_known_ceiling_bytes`, `mtu_bottleneck` (the subject uids of the
    bottleneck stages) and `mtu_uncovered` (`coverage.uncovered`). `mtu` is
    `None` for a flow with no MTU request.
    """
    changed = changed_rulebases or set()
    mtu_side = _mtu_side(mtu)
    rows: list[dict[str, Any]] = []
    for leg in legs:
        row: dict[str, Any] = {
            "destination": leg.get("dst_label") or leg.get("cidr"),
            "route_prefix": leg.get("cidr"),
            "egress": leg.get("egress"),
            "next_hop": leg.get("next_hop"),
            "table": leg.get("table"),
            "blocked": bool(leg.get("blocked")),
            "indeterminate": bool(leg.get("indeterminate")),
            "decided_by": leg.get("firewall"),
            "rulebase": leg.get("fw_uid"),
            "detail": leg.get("verdict"),
            "result": leg_result(leg).model_dump(mode="json"),
        }
        row["changed_rulebase_applies"] = bool(row["rulebase"] and str(row["rulebase"]) in changed)
        note = _path_note(row, changed)
        if note:
            row["note"] = note
        if mtu_side is not None:
            row["mtu_outcome"] = mtu_side["outcome"]
            row["mtu_known_ceiling_bytes"] = mtu_side["known_ceiling_bytes"]
            row["mtu_bottleneck"] = mtu_side["bottleneck"]
            row["mtu_uncovered"] = mtu_side["uncovered"]
        rows.append(row)
    return rows


def _path_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    """Return the key that pairs a row of the before trace with a row of the
    after trace. The outcome is not in the key."""
    return (row.get("destination"), row.get("egress"), row.get("next_hop"), row.get("table"))


def _group_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    """Return the key that puts 2 compared paths on one group row. The key
    holds the outcome before, the outcome after, the egress interface and the
    note."""
    return (
        _state(row.get("before")),
        _state(row.get("after")),
        row.get("egress"),
        row.get("note"),
    )


def _state(side: Mapping[str, Any] | None) -> tuple[Any, ...]:
    """Return the tuple that compares the outcome of 2 sides.

    The tuple holds the firewall fields, `mtu_outcome` and the bottleneck
    subjects. A path with the same firewall verdict and a different MTU
    outcome or bottleneck counts as changed.
    """
    if side is None:
        return ("absent",)
    return (
        bool(side.get("blocked")),
        bool(side.get("indeterminate")),
        side.get("decided_by"),
        side.get("rulebase"),
        side.get("mtu_outcome"),
        tuple(side.get("mtu_bottleneck") or ()),
    )


def _side(row: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    side: dict[str, Any] = {
        "blocked": bool(row.get("blocked")),
        "indeterminate": bool(row.get("indeterminate")),
        "decided_by": row.get("decided_by"),
        "rulebase": row.get("rulebase"),
        "detail": row.get("detail"),
        "result": row.get("result"),
    }
    if "mtu_outcome" in row:
        side["mtu_outcome"] = row.get("mtu_outcome")
        side["mtu_known_ceiling_bytes"] = row.get("mtu_known_ceiling_bytes")
        side["mtu_bottleneck"] = list(row.get("mtu_bottleneck") or ())
        side["mtu_uncovered"] = list(row.get("mtu_uncovered") or ())
    return side


def _mtu_group_side(side: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Return the `mtu_before` or `mtu_after` of one group, the MTU view of the
    `before` or `after` `PathSide` of its first path. Return `None` when the
    side has no MTU result.
    """
    if side is None or "mtu_outcome" not in side:
        return None
    return {
        "outcome": side.get("mtu_outcome"),
        "known_ceiling_bytes": side.get("mtu_known_ceiling_bytes"),
        "bottleneck": list(side.get("mtu_bottleneck") or ()),
        "uncovered": list(side.get("mtu_uncovered") or ()),
    }


def _sample(values: Sequence[Any]) -> tuple[list[Any], int]:
    seen: list[Any] = []
    for value in values:
        if value is not None and value not in seen:
            seen.append(value)
    return seen[:_MAX_PATH_SAMPLE], len(seen)


def pair_paths(
    before: Sequence[Mapping[str, Any]], after: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    """Return the paths of one flow, each before row paired with its after row.
    The list is not grouped and not capped.

    Paths are paired on destination, egress, next hop and routing table. A
    path that only one side has gives a row with the other side `None`.
    """
    left = {_path_key(r): r for r in before}
    right = {_path_key(r): r for r in after}
    keys = list(left) + [k for k in right if k not in left]
    return [
        {
            "destination": (left.get(k) or right[k]).get("destination"),
            "route_prefix": (left.get(k) or right[k]).get("route_prefix"),
            "egress": (left.get(k) or right[k]).get("egress"),
            "next_hop": (left.get(k) or right[k]).get("next_hop"),
            "table": (left.get(k) or right[k]).get("table"),
            "before": _side(left.get(k)),
            "after": _side(right.get(k)),
            "changed": _state(_side(left.get(k))) != _state(_side(right.get(k))),
            "note": (right.get(k) or left[k]).get("note"),
        }
        for k in keys
    ]


def compare_paths(before: Sequence[Mapping[str, Any]], after: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Return the paths of one flow, before beside after, grouped and counted.

    `pair_paths` pairs the rows. Paths that share both outcomes, the egress
    and the note form one group row. The row has the path count, a sample of
    at most `_MAX_PATH_SAMPLE` destinations and next hops, and the count of
    all destinations and of all next hops. The list holds at most
    `_MAX_PATH_GROUPS` groups. `group_count` is the count of all groups.
    """
    paired = pair_paths(before, after)

    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for row in paired:
        groups.setdefault(_group_key(row), []).append(row)
    listed: list[dict[str, Any]] = []
    for members in list(groups.values())[:_MAX_PATH_GROUPS]:
        head = members[0]
        destinations, destination_count = _sample([m["destination"] for m in members])
        next_hops, next_hop_count = _sample([m["next_hop"] for m in members])
        group: dict[str, Any] = {
            "path_count": len(members),
            "destinations": destinations,
            "destination_count": destination_count,
            "next_hops": next_hops,
            "next_hop_count": next_hop_count,
            "egress": head["egress"],
            "before": head["before"],
            "after": head["after"],
            "changed": _state(head["before"]) != _state(head["after"]),
            "sample_truncated": destination_count > len(destinations) or next_hop_count > len(next_hops),
        }
        if head.get("note"):
            group["note"] = head["note"]
        mtu_before = _mtu_group_side(head["before"])
        if mtu_before is not None:
            group["mtu_before"] = mtu_before
        mtu_after = _mtu_group_side(head["after"])
        if mtu_after is not None:
            group["mtu_after"] = mtu_after
        listed.append(group)
    return {
        "groups": listed,
        "group_count": len(groups),
        "truncated": len(groups) > len(listed),
        "path_count_before": len(before),
        "path_count_after": len(after),
        "blocked_before": sum(1 for r in before if r.get("blocked")),
        "blocked_after": sum(1 for r in after if r.get("blocked")),
        "indeterminate_after": sum(1 for r in after if r.get("indeterminate")),
        "changed": sum(1 for r in paired if _state(r["before"]) != _state(r["after"])),
    }
