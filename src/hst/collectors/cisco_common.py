"""Shared normalize core for the Cisco CLI trio (NX-OS, IOS-XE, IOS-XR)."""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import logging
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from hst.core import debug_capture, uid
from hst.core.config import DEFAULT_L2_FABRIC
from hst.core.identity import DeviceResolver, MemoryResolver, chassis_serial, resolve_chassis
from hst.core.l3domain import DEFAULT_VRF, DomainPolicy
from hst.core.model import Batch
from hst.core.mtu import MTU_NORMALIZATION_VERSION, canonical_json
from hst.core.mtu_profiles import emit_observation, observation_from_raw
from hst.core.normalize import IfNameResolver, iface_slug

from . import streams
from .cisco_bgp import (
    emit_bgp_peer,
    expand_dynamic_neighbors,
    observed_peer_router_id,
    peer_network,
    reflector_client,
    session_gap,
)
from .util import GraphBuilder, VrfDomains, bgp_multipath_props, canonical_mac, connected_address, lpm_columns

logger = logging.getLogger(__name__)

_PORT_KINDS = {"phys", "lag", "mgmt"}


def device_uid(
    inter: dict, scope: str, resolver: DeviceResolver | None = None, target_host: str | None = None
) -> str:
    """Return the Device uid of a payload.

    `normalize_cisco` and the `side_tables()` of each family collector use it.
    The registry resolves the chassis serial, or the ref
    (`fallback_device_uid`) when the box reports no serial. `resolver` is the
    registry of the collector (`Collector.identity`). None resolves in memory.
    `target_host` is the address that the collector reached the box at. It
    names a new uid when the box reports no hostname (`mint_name`). A
    placeholder serial counts as no serial. A serial that another device holds
    in this run resolves by the ref (`resolve_chassis`)."""
    d = inter.get("device") or {}
    serial = chassis_serial(d.get("serial"))
    if serial is None:
        return fallback_device_uid(inter, scope, resolver, target_host)
    return resolve_chassis(
        resolver or MemoryResolver(),
        serial,
        ("ref", f"{scope}:{d.get('hostname') or 'unknown'}"),
        mint_name(d, target_host),
    )


def fallback_device_uid(
    inter: dict, source: str, resolver: DeviceResolver | None = None, target_host: str | None = None
) -> str:
    """Return the Device uid of a Device without a serial.

    The registry keys the Device by `<source>:<hostname>`."""
    d = inter.get("device") or {}
    hostname = d.get("hostname")
    return (resolver or MemoryResolver()).resolve_device(
        "ref", f"{source}:{hostname or 'unknown'}", mint_name(d, target_host)
    )


def mint_name(device: dict, target_host: str | None) -> str | None:
    """Return the name for a new Device uid.

    The name is the hostname that the box reports, else the host that the
    collector reached the box at."""
    hostname = device.get("hostname")
    if hostname and hostname != "unknown":
        return hostname
    return target_host or hostname


@debug_capture.traced
def normalize_cisco(
    inter: dict[str, Any],
    *,
    source: str,
    scope: str,
    l3dom: str,
    l2fabric: str = DEFAULT_L2_FABRIC,
    group_scope: str | None = None,
    resolver: DeviceResolver | None = None,
    target_host: str | None = None,
) -> Batch:
    """Turn the cross-family intermediate shape into the twin.

    inter = {
      "device": {"hostname", "serial", "platform", "os_version"},
      "interfaces": [{"name", "kind", "mac", "admin_up", "ips": [{"ip",
                      "prefixlen", "vrf"}], "vlan"}],
      "neighbors": [{"local_port", "name", "mac", "port", "proto",
                     "serial": optional}],
      "vlans": [{"vid", "name"}],
      "vlan_ports": optional, {vid: [port names]},
      "vrfs": [{"name", "rd", "rt_import", "rt_export"}, ...],
      "nat": optional, {"if_roles": {ifname: "inside"|"outside"},
                          "pools": {name: {"start", "end", "cidr"|None}},
                          "rules": [config-ordered dicts from parse_nat_config],
                          "acls": {name: [{"action", "src", "dst"}]}},
      "acl": optional, {"lists": {name: [ACE dicts, see `acl_stage`]},
                          "bindings": [{"interface", "direction", "acl",
                                        optional "family"}]},
      "xr_route_policies" / "xr_prefix_lists" / "xr_community_lists" /
             "xr_as_path_lists": optional, [{"name", "kind" ("rpl" |
             "prefix-list" | "community-list" | "as-path-list"), "entries":
             [RoutePolicyEntry/PrefixListEntry/MatchListEntry field-dicts incl.
             "seq"]}],
      "xr_bgp" / "xr_bgp_sessions" / "xr_bgp_redistribute": optional,
             {"asn", "router_id"} / [BgpSession field-dicts] /
             [{"protocol", "policy_name"}],
      "ospf": optional, {"processes": [{"process", "vrf", "router_id",
                           "areas": [{"area_id", "type"}],
                           "redistribute": [{"protocol", "route_map"}]}],
                           "interfaces": [{"process", "vrf", "name", "area",
                           "cost", "network_type", "passive"}],
                           "adjacencies": [{"process", "vrf", "area",
                           "local_interface", "neighbor_router_id",
                           "neighbor_ip", "state"}],
                           "lsdb": [LSA dicts, see `ospf_side_rows`]},
      "routing": optional, {"bgp": {"asn", "router_id", "neighbors": [...],
                              "redistribute": [...]} | None,
                              "prefix_lists": {name: [entry dict, ...]},
                              "route_maps": {name: [clause dict, ...]}},
      "fhrp": optional, [{"interface", "kind": "hsrp"|"vrrp", "group", "vip",
                            "priority", "state", "virtual_mac"}],
      "vpc": optional, NX-OS only, {"domain", "role", "peer_link",
             "peer_status"},
      "rib" / "mac_table" / "arp": side-store only,
    }

    A family that does not collect an optional key omits it.

    `neighbors[].serial` is the chassis serial of the far end when its CDP
    device id holds one (NX-OS `<host>(<serial>)`).

    `vlan_ports` is the trunk membership that the platform states (NX-OS
    `show vlan` member lists and the trunk table, `nxos.parse_vlan_ports`).
    `carriage_stage` reads it and writes `(Port)-[:CARRIES]->(VlanInstance)`.

    `vrfs` holds one entry per named VRF that the platform reports. The global
    table is absent from the list. "rd" is the route distinguisher or None.
    "rt_import" and "rt_export" are deduplicated lists of route-target values.
    They are empty when the platform or the collector does not capture them.

    `nat_stage` reads `nat`.

    `acl` holds the interface access lists and the filter bindings that put a
    list on an interface (`parse_access_groups`, `parse_vlan_filters`).
    `acl_stage` reads it. A box with no filter binding has no `acl` key.

    `bgp_stage` reads the `xr_*` keys and reads each absent key as empty.

    `ospf_stage` reads `ospf` for the graph objects. `ospf_side_rows` reads it
    for the `ospf_lsdb` side-store table. A device with no OSPF feature has no
    `ospf` key.

    `routing_stage` reads `routing`.

    `fhrp` holds one row per first-hop redundancy group per member interface.
    `fhrp_stage` reads it. `state` is the role of the member as the platform
    reports it, lowercased (`active`/`standby` for HSRP, `master`/`backup` for
    VRRP), or None. A box with no group configured has no `fhrp` key.

    `vpc` holds the vPC domain membership of the box. `vpc_stage` reads it. A
    box without `feature vpc` has no `vpc` key.

    `rib`, `mac_table` and `arp` go to the side store and never enter the
    batch.

    `group_scope` is the identity scope of every device of one group source
    (the name of the source row), or `scope` for a collector built without a
    source row.

    `resolver` is the device identity registry (`Collector.identity`) that
    gives the Device uid (`device_uid`). None resolves in memory.
    `target_host` is the address that the collector reached the box at
    (`mint_name`).
    """
    b = GraphBuilder()
    dev = _device_stage(b, inter, scope=scope, resolver=resolver, target_host=target_host)

    policy = DomainPolicy(scope=l3dom)
    vrfs = VrfDomains(b, dev, policy, lambda name: uid.vrf(dev, name))
    _register_vrfs(vrfs, inter)

    port_uids, iface_uids = _interface_stage(b, inter, dev=dev, scope=scope, l2fabric=l2fabric, vrfs=vrfs)
    # fhrp_stage runs after _interface_stage. The virtual address copies its
    # prefix length and VRF from the address of the member interface.
    fhrp_stage(b, inter, dev=dev, iface_uids=iface_uids, vrfs=vrfs)
    vpc_stage(b, inter, dev=dev, group_scope=group_scope or scope)
    _mtu_stage(b, inter, dev=dev, source=source, scope=scope, ports=port_uids, interfaces=iface_uids)

    # The VLAN name database writes a VlanInstance node for each VLAN, with or
    # without a bound interface.
    for v in inter.get("vlans") or []:
        b.node("VlanInstance", uid.vlan(scope, v["vid"]), vid=v["vid"], name=v.get("name"))

    _neighbor_stage(b, inter, port_uids)

    carriage_stage(b, inter, port_uids=port_uids, scope=scope)

    routing_stage(b, inter, dev=dev, source=source, vrfs=vrfs)

    nat_stage(
        b,
        inter,
        dev=dev,
        scope=scope,
        domain_for=lambda name: _domain_for(vrfs, name),
        vrf_node=lambda name: _vrf_node(vrfs, name),
        iface_uids=iface_uids,
    )

    acl_stage(b, inter, dev=dev, scope=scope)

    bgp_stage(b, inter, dev=dev, vrfs=vrfs)

    ospf_stage(b, inter, dev=dev, vrfs=vrfs, iface_uids=iface_uids)

    return b.batch(source, scope)


def _device_stage(
    b: GraphBuilder,
    inter: dict[str, Any],
    *,
    scope: str,
    resolver: DeviceResolver | None = None,
    target_host: str | None = None,
) -> str:
    """Write the Device node and return the device uid.

    The stage writes no Site and no LOCATED_IN. core/cycle.py
    `apply_site_assignments` writes the site of a device from the assignment
    of the operator."""
    d = inter.get("device") or {}
    # A box that reports no hostname gets an empty `identities` list.
    host = mint_name(d, target_host) or "unknown"
    named = d.get("hostname") not in (None, "", "unknown")
    serial = chassis_serial(d.get("serial"))
    dev = device_uid(inter, scope, resolver, target_host)
    # reasoner.py's gateway-from-router-interface rule keys on `role`.
    b.node(
        "Device",
        dev,
        hostname=host,
        platform=d.get("platform"),
        vendor="cisco",
        role="router",
        os_version=d.get("os_version"),
        serial=serial,
        identities=[host] if named else [],
    )
    return dev


def _vrf_node(vrfs: VrfDomains, name: str) -> str:
    if not name:
        # An empty name is the global table.
        return vrfs.add(DEFAULT_VRF, is_global=True)
    return vrfs.add(name)


def _domain_for(vrfs: VrfDomains, name: str) -> str:
    _vrf_node(vrfs, name)  # ensure the VRF and its domain exist
    return vrfs.domains[name or DEFAULT_VRF]


def _register_vrfs(vrfs: VrfDomains, inter: dict[str, Any]) -> None:
    # Every named VRF is registered before the interface loop (VrfDomains.add keeps the first call).
    for v in inter.get("vrfs") or []:
        vrfs.add(
            v["name"],
            rd=v["rd"],
            rt_import=tuple(v["rt_import"]),
            rt_export=tuple(v["rt_export"]),
            is_global=True if v["name"] == DEFAULT_VRF else None,
        )


def _interface_stage(
    b: GraphBuilder,
    inter: dict[str, Any],
    *,
    dev: str,
    scope: str,
    l2fabric: str,
    vrfs: VrfDomains,
) -> tuple[dict[str, str], dict[str, str]]:
    """Interfaces with their Ports (phys/lag), VLAN bindings and addresses.

    Returns (port_uids, iface_uids), both keyed by iface_slug of the name."""
    port_uids: dict[str, str] = {}
    iface_uids: dict[str, str] = {}
    for ifc in inter.get("interfaces") or []:
        name = ifc["name"]
        kind = ifc.get("kind")
        iu = uid.interface(dev, name)
        # NAT config can abbreviate the names that the interface table spells in full.
        iface_uids[iface_slug(name)] = iu
        mac = canonical_mac(ifc.get("mac"))
        b.node(
            "Interface",
            iu,
            name=name,
            kind=kind,
            mac=mac,
            admin_up=ifc.get("admin_up"),
            description=ifc.get("description"),
        )
        if ifc.get("oper_status"):
            b.node("Interface", iu, oper_status=ifc["oper_status"])
        if ifc.get("mtu_parent_name"):
            b.node(
                "Interface",
                iu,
                parent_interface_uid=uid.interface(dev, ifc["mtu_parent_name"]),
                parent_source_command=ifc["mtu_parent_source"],
            )
        b.rel("ON", "Interface", iu, "Device", dev)

        # An interface of a kind in _PORT_KINDS also gets a Port.
        if kind in _PORT_KINDS:
            pu = b.node(
                "Port",
                uid.port(dev, name),
                name=name,
                mac=mac,
                kind=kind,
                speed_mbps=ifc.get("speed_mbps"),
                duplex=ifc.get("duplex"),
                speed_source=ifc.get("speed_source"),
                bandwidth_kbit=ifc.get("bandwidth_kbit"),
                # The fabric-port-from-description rule of the reasoner reads
                # the Equinix port name and the cable id from the description.
                description=ifc.get("description"),
            )
            # The LLDP/CDP table spells a port differently from the interface table ("Tw1/0/1").
            port_uids[iface_slug(name)] = pu
            b.rel("ON", "Port", pu, "Device", dev)
            b.rel("REALIZED_BY", "Interface", iu, "Port", pu)

        vid = ifc.get("vlan")
        if vid is not None:
            vu = b.node("VlanInstance", uid.vlan(scope, vid), vid=vid)
            seg = b.node("BridgeDomain", uid.bridge_domain(l2fabric, vid))
            b.rel("REALIZES", "VlanInstance", vu, "BridgeDomain", seg)
            b.rel("BOUND_TO", "Interface", iu, "VlanInstance", vu)

        seen_vrfs: set[str] = set()
        for a in ifc.get("ips") or []:
            vname = a.get("vrf") or ""
            vru = _vrf_node(vrfs, vname)
            ipu, _ = connected_address(
                b, f"{a['ip']}/{a['prefixlen']}", anchor=vru, dom=_domain_for(vrfs, vname), vrf_uid=vru
            )
            b.rel("HAS_IP", "Interface", iu, "IpAddress", ipu)
            if vname not in seen_vrfs:
                seen_vrfs.add(vname)
                b.rel("IN_VRF", "Interface", iu, "VrfInstance", vru)
    return port_uids, iface_uids


# --- first-hop redundancy (HSRP/VRRP) and vPC ------------------------------------------
#
# Every member interface of a first-hop group holds the virtual address. The
# stage writes the address as a `HAS_IP` on each member, with the protocol, the
# group number and the state of the member. The next-hop resolver finds the
# device for the address in the same way as for the address of an interface,
# and the state lets it prefer the active member. The address joins the
# connected `Prefix` of the member. Its prefix length and VRF are copied from
# the address of the member interface in the same family and have no default.
# A row whose member has no address in the family is skipped
# (`annotate_fhrp_sections`).

FHRP_ACTIVE_STATES: dict[str, str] = {"hsrp": "active", "vrrp": "master"}


def _fhrp_state(value: Any) -> str | None:
    """Return the role of the member as the platform reports it, lowercased,
    without a parenthesised qualifier.

    NX-OS text output renders a transitional state as `Active(...)`."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    return text.split("(", 1)[0].strip() or None


def ifname_resolver(device_ifnames: Iterable[str]) -> IfNameResolver:
    """The resolver of the names a command prints against `device_ifnames`, the
    device's own interface table (`IfNameResolver`)."""
    return IfNameResolver(device_ifnames)


def canonical_ifname(device_ifnames: Iterable[str], raw: str | None) -> str | None:
    """Return `raw`, an interface name that a command printed, as the interface
    table of the device spells it.

    The function returns `raw` itself when the table has no unique match."""
    return IfNameResolver(device_ifnames)(raw)


def inter_ifnames(inter: dict[str, Any]) -> IfNameResolver:
    """The resolver over the interface table of an intermediate shape."""
    return IfNameResolver(i["name"] for i in inter.get("interfaces") or [] if i.get("name"))


def resolve_fhrp(inter: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    """Return the FHRP rows that can join the twin and the skip reasons per
    protocol.

    Each returned row holds the `prefixlen` and the `vrf` of the address of its
    member interface in the family of the virtual address.
    """
    by_name = {i["name"]: i for i in inter.get("interfaces") or [] if i.get("name")}
    resolve = inter_ifnames(inter)
    resolved: list[dict[str, Any]] = []
    skipped: dict[str, list[str]] = {}
    for row in inter.get("fhrp") or []:
        kind = str(row.get("kind") or "").lower()
        name = row.get("interface")
        vip = row.get("vip")
        label = f"{kind or 'fhrp'} group {row.get('group')} on {name}"
        try:
            af = ipaddress.ip_address(str(vip)).version
        except ValueError:
            skipped.setdefault(kind, []).append(f"{label}: virtual address {vip!r} is not an address")
            continue
        ifc = by_name.get(str(resolve(str(name)))) if name else None
        if ifc is None:
            skipped.setdefault(kind, []).append(f"{label}: the interface table has no such interface")
            continue
        own = next(
            (
                a
                for a in ifc.get("ips") or []
                if _af_of(str(a.get("ip"))) == af and a.get("prefixlen") is not None
            ),
            None,
        )
        if own is None:
            skipped.setdefault(kind, []).append(
                f"{label}: the interface holds no IPv{af} address of its own, so the prefix "
                f"length of virtual address {vip} is unknown"
            )
            continue
        resolved.append(
            {
                **row,
                "interface": ifc["name"],
                "kind": kind,
                "af": af,
                "prefixlen": int(own["prefixlen"]),
                "vrf": own.get("vrf") or "",
            }
        )
    return resolved, skipped


def fhrp_stage(
    b: GraphBuilder,
    inter: dict[str, Any],
    *,
    dev: str,
    iface_uids: dict[str, str],
    vrfs: VrfDomains,
) -> None:
    """`FhrpGroup` nodes and the virtual-address edges,
    one row of `inter["fhrp"]` at a time."""
    resolved, _ = resolve_fhrp(inter)
    for row in resolved:
        iu = iface_uids.get(iface_slug(str(row["interface"])))
        if iu is None:  # pragma: no cover - resolve_fhrp already dropped the row
            continue
        kind, vip = row["kind"], str(row["vip"])
        vname = row["vrf"]
        vru = _vrf_node(vrfs, vname)
        dom = _domain_for(vrfs, vname)
        ipu, _ = connected_address(b, f"{vip}/{row['prefixlen']}", anchor=vru, dom=dom, vrf_uid=vru)
        state = _fhrp_state(row.get("state"))
        group = row.get("group")
        b.rel("HAS_IP", "Interface", iu, "IpAddress", ipu, fhrp=kind, group=group, state=state)
        gu = b.node(
            "FhrpGroup",
            uid.fhrp(kind, dom, vip),
            kind=kind,
            group_id=group,
            vip=vip,
            af=row["af"],
            virtual_mac=canonical_mac(row.get("virtual_mac")),
        )
        b.rel("MEMBER_OF", "Interface", iu, "FhrpGroup", gu, priority=row.get("priority"), state=state)
        b.rel("HAS_IP", "FhrpGroup", gu, "IpAddress", ipu)


def annotate_fhrp_sections(
    sections: dict[str, Any], inter: dict[str, Any], names: dict[str, str]
) -> dict[str, Any]:
    """Return the section outcomes with each FHRP row that the stage could not
    place added to the detail of its protocol section.

    `names` maps a protocol to a section name. Only a section with status `ok`
    gets the reasons."""
    _, skipped = resolve_fhrp(inter)
    out = dict(sections)
    for kind, reasons in skipped.items():
        name = names.get(kind)
        outcome = out.get(name) if name else None
        if outcome is None or outcome.status != "ok":
            continue
        detail = "; ".join([*filter(None, [outcome.detail]), *reasons])
        out[name] = outcome.model_copy(update={"detail": detail})
    return out


def vpc_stage(b: GraphBuilder, inter: dict[str, Any], *, dev: str, group_scope: str) -> None:
    """Write the vPC domain of the box as a `RedundancyGroup kind=vpc` and its
    `(Device)-[:MEMBER_OF {role, peer_link, peer_status}]->` edge.

    Both peers derive the uid from the scope of the group source and the
    domain id. Their batches merge on one node. The map and impact views read
    the node."""
    vpc = inter.get("vpc")
    if not vpc or vpc.get("domain") is None:
        return
    domain = str(vpc["domain"])
    gu = b.node(
        "RedundancyGroup",
        uid.rgrp("vpc", group_scope, domain),
        kind="vpc",
        name=f"vpc-domain-{domain}",
        domain_id=domain,
    )
    b.rel(
        "MEMBER_OF",
        "Device",
        dev,
        "RedundancyGroup",
        gu,
        role=vpc.get("role"),
        peer_link=vpc.get("peer_link"),
        peer_status=vpc.get("peer_status"),
    )


def _neighbor_stage(b: GraphBuilder, inter: dict[str, Any], port_uids: dict[str, str]) -> None:
    # a neighbor on a local_port that resolved to no Port node is skipped
    resolve = inter_ifnames(inter)
    for n in inter.get("neighbors") or []:
        local = n.get("local_port")
        pu = port_uids.get(resolve.slug(local)) if local else None
        if pu is None:
            continue
        proto = n["proto"]
        # The cable-from-neighbor-name rule of the reasoner joins the name and
        # the serial against the Devices of all runs. The cable-from-lldp-record
        # rule joins the MAC. `b.node` drops a None value. A row without a
        # serial writes no serial property.
        b.node(
            "Port",
            pu,
            **{
                f"{proto}_neighbor_name": n.get("name"),
                f"{proto}_neighbor_mac": canonical_mac(n.get("mac")),
                f"{proto}_neighbor_port": n.get("port"),
                f"{proto}_neighbor_serial": chassis_serial(n.get("serial")),
            },
        )


def carriage_stage(b: GraphBuilder, inter: dict[str, Any], *, port_uids: dict[str, str], scope: str) -> None:
    """Write `(Port)-[:CARRIES]->(VlanInstance)` for each port in the member
    list of a VLAN.
    """
    resolve = inter_ifnames(inter)
    for vid, ports in (inter.get("vlan_ports") or {}).items():
        for name in ports or []:
            pu = port_uids.get(resolve.slug(name)) if name else None
            if pu is None:
                continue
            vu = b.node("VlanInstance", uid.vlan(scope, int(vid)), vid=int(vid))
            b.rel("CARRIES", "Port", pu, "VlanInstance", vu)


# --- BGP / route-policy: graph stage ----------------
#
# `bgp_stage` reads the "xr_bgp"/"xr_bgp_sessions"/"xr_bgp_redistribute"/
# "xr_route_policies"/"xr_prefix_lists" keys that the docstring of
# `normalize_cisco` defines.


def _aggregate_origins(
    b: GraphBuilder,
    *,
    vru: str,
    rp_uid: str,
    aggregates: list[Any],
    l3dom: str | None,
    policy_uid_for: Any,
) -> None:
    """One `ORIGINATES {proto: aggregate}` edge per recorded aggregate, with
    its options as edge properties, and a `FILTERED_BY {redistribute,
    aggregate}` edge to the attribute policy when `policy_uid_for(name)`
    resolves it."""
    for item in aggregates:
        recorded = item if isinstance(item, dict) else {"prefix": item}
        cidr = recorded.get("prefix")
        if not cidr:
            continue
        # An aggregate equal to a connected prefix keeps the connected kind.
        # The ORIGINATES edge holds the aggregate origination.
        pu = uid.prefix(vru, cidr)
        prefix = b.node(
            "Prefix",
            pu,
            cidr=cidr,
            af=ipaddress.ip_network(cidr, strict=False).version,
            kind=None if b.props("Prefix", pu) else "aggregate",
            anchor=vru,
            l3dom=l3dom,
        )
        attribute_map = recorded.get("attribute_map")
        b.rel(
            "ORIGINATES",
            "VrfInstance",
            vru,
            "Prefix",
            prefix,
            key={"proto": "aggregate"},
            proto="aggregate",
            summary_only=recorded.get("summary_only", False),
            as_set=recorded.get("as_set", False),
            attribute_map=attribute_map,
            unsupported_options=recorded.get("unsupported_options", []),
        )
        if not attribute_map:
            continue
        target = policy_uid_for(attribute_map)
        if target:
            b.rel(
                "FILTERED_BY",
                "RoutingProcess",
                rp_uid,
                "RoutePolicy",
                target,
                key={"direction": "redistribute", "protocol": "aggregate"},
                direction="redistribute",
                protocol="aggregate",
            )
        else:
            logger.warning(
                "%s: aggregate %s names undefined attribute policy %r; raw name kept, no FILTERED_BY edge",
                rp_uid,
                cidr,
                attribute_map,
            )


def match_list_stage(b: GraphBuilder, lists: list[dict[str, Any]], *, dev: str) -> dict[tuple[str, str], str]:
    """Write one `RoutePolicy` (kind `community-list` or `as-path-list`) for
    each community list and AS-path list, with a `MatchListEntry` per line.

    A `MatchListEntry` holds `seq`, `action`, `match_type` and `value`.
    simul/matchlist.py defines the meaning of each `match_type`. The function
    returns a map of `(kind, name)` to the RoutePolicy uid for the REFERENCES
    pass. IOS-XE, NX-OS and IOS-XR use it."""
    out: dict[tuple[str, str], str] = {}
    for ml in lists:
        pu = b.node(
            "RoutePolicy", uid.route_policy(dev, ml["kind"], ml["name"]), name=ml["name"], kind=ml["kind"]
        )
        out[(ml["kind"], ml["name"])] = pu
        for entry in ml["entries"]:
            eu = uid.match_list_entry(pu, entry["seq"])
            b.node(
                "MatchListEntry",
                eu,
                seq=entry["seq"],
                action=entry["action"],
                match_type=entry["match_type"],
                value=entry.get("value"),
            )
            b.rel("HAS_RULE", "RoutePolicy", pu, "MatchListEntry", eu)
    return out


# Each RoutePolicyEntry property and the kind of RoutePolicy that each name in it refers to.
LIST_REFERENCE_KEYS = (
    ("match_community_lists", "community-list"),
    ("match_as_path_lists", "as-path-list"),
    ("set_comm_list_delete", "community-list"),
)


def list_references(entry: dict[str, Any]) -> list[tuple[str, str]]:
    """`(kind, name)` for every community list and AS-path list a policy entry
    names, in a match or in `set comm-list delete`, without repeats."""
    out: list[tuple[str, str]] = []
    for key, kind in LIST_REFERENCE_KEYS:
        value = entry.get(key)
        for name in [value] if isinstance(value, str) else value or []:
            if name and (kind, name) not in out:
                out.append((kind, name))
    return out


def bgp_stage(b: GraphBuilder, inter: dict[str, Any], *, dev: str, vrfs: VrfDomains) -> None:
    """Write RoutePolicy, RoutePolicyEntry and PrefixListEntry nodes, then
    RoutingProcess and BgpSession nodes, then the REFERENCES and FILTERED_BY
    edges between them.

    A name that does not resolve to a `RoutePolicy` node in the same batch gets
    a warning and no edge. Without the `"xr_bgp"`, `"xr_route_policies"` and
    `"xr_prefix_lists"` keys (nxos.py, iosxe.py), the stage writes nothing."""
    route_policies = inter.get("xr_route_policies") or []
    prefix_lists = inter.get("xr_prefix_lists") or []
    match_lists = [*(inter.get("xr_community_lists") or []), *(inter.get("xr_as_path_lists") or [])]

    # Pass 1 writes every RoutePolicy with its entries and collects the uid set
    # that the REFERENCES and FILTERED_BY resolution checks names against.
    policy_uids: set[str] = set(match_list_stage(b, match_lists, dev=dev).values())
    for rp in route_policies:
        pu = uid.route_policy(dev, rp["kind"], rp["name"])
        b.node("RoutePolicy", pu, name=rp["name"], kind=rp["kind"])
        policy_uids.add(pu)
        for entry in rp["entries"]:
            eu = uid.route_policy_entry(pu, entry["seq"])
            b.node("RoutePolicyEntry", eu, **entry)
            b.rel("HAS_RULE", "RoutePolicy", pu, "RoutePolicyEntry", eu)

    for pl in prefix_lists:
        pu = uid.route_policy(dev, pl["kind"], pl["name"])
        b.node("RoutePolicy", pu, name=pl["name"], kind=pl["kind"])
        policy_uids.add(pu)
        for entry in pl["entries"]:
            eu = uid.prefix_list_entry(pu, entry["seq"])
            b.node("PrefixListEntry", eu, **entry)
            b.rel("HAS_RULE", "RoutePolicy", pu, "PrefixListEntry", eu)

    # Pass 2: REFERENCES from each RoutePolicyEntry's match/call clauses.
    for rp in route_policies:
        pu = uid.route_policy(dev, rp["kind"], rp["name"])
        for entry in rp["entries"]:
            eu = uid.route_policy_entry(pu, entry["seq"])
            for name in entry.get("match_prefix_lists") or []:
                target = uid.route_policy(dev, "prefix-list", name)
                if target in policy_uids:
                    b.rel(
                        "REFERENCES",
                        "RoutePolicyEntry",
                        eu,
                        "RoutePolicy",
                        target,
                        key={"kind": "prefix-list"},
                        kind="prefix-list",
                    )
                else:
                    logger.warning(
                        "iosxr: route-policy %r entry %d references undefined prefix-set/prefix-list %r",
                        rp["name"],
                        entry["seq"],
                        name,
                    )
            for kind, name in list_references(entry):
                target = uid.route_policy(dev, kind, name)
                if target in policy_uids:
                    b.rel(
                        "REFERENCES",
                        "RoutePolicyEntry",
                        eu,
                        "RoutePolicy",
                        target,
                        key={"kind": kind},
                        kind=kind,
                    )
                else:
                    logger.warning(
                        "iosxr: route-policy %r entry %d references undefined %s %r",
                        rp["name"],
                        entry["seq"],
                        kind,
                        name,
                    )
            calls = [entry["calls_policy"]] if entry.get("calls_policy") else []
            for called in dict.fromkeys([*calls, *(entry.get("match_policies") or [])]):
                target = uid.route_policy(dev, "rpl", called)
                if target in policy_uids:
                    b.rel(
                        "REFERENCES",
                        "RoutePolicyEntry",
                        eu,
                        "RoutePolicy",
                        target,
                        key={"kind": "call"},
                        kind="call",
                    )
                else:
                    logger.warning(
                        "iosxr: route-policy %r entry %d applies undefined route-policy %r",
                        rp["name"],
                        entry["seq"],
                        called,
                    )

    bgp = inter.get("xr_bgp")
    if bgp is None:
        return

    processes = inter.get("xr_bgp_processes") or [
        {
            **bgp,
            "vrf": DEFAULT_VRF,
            "sessions": inter.get("xr_bgp_sessions") or [],
            "redistribute": inter.get("xr_bgp_redistribute") or [],
        }
    ]
    for process in processes:
        vrf_name = process.get("vrf") or DEFAULT_VRF
        vru = vrfs.add(vrf_name, is_global=vrf_name == DEFAULT_VRF)
        rp_uid = uid.routing_process(dev, vrf_name, "bgp")
        b.node(
            "RoutingProcess",
            rp_uid,
            proto="bgp",
            asn=process["asn"],
            router_id=process.get("router_id"),
            # The property is set only when configured. An absent property is
            # the default, gated MED.
            always_compare_med=True if process.get("always_compare_med") else None,
            **bgp_multipath_props(process.get("maximum_paths") or {}, bool(process.get("multipath_relax"))),
            default_information_originate_afs=process.get("default_information_originate_afs") or None,
            redistribute_protocols=sorted({r["protocol"] for r in process.get("redistribute") or []}),
            origin_config_recorded=True,
            origin_afs=[4, 6],
            origin_context_gaps=list(process.get("origin_context_gaps") or []),
        )
        b.rel("IN_VRF", "RoutingProcess", rp_uid, "VrfInstance", vru)
        for item in process.get("networks") or []:
            cidr = item["prefix"]
            # A network statement for a connected subnet keeps the connected
            # kind. The gateway rule of reasoner/catalog.py reads the kind.
            pu = uid.prefix(vru, cidr)
            prefix = b.node(
                "Prefix",
                pu,
                cidr=cidr,
                af=ipaddress.ip_network(cidr, strict=False).version,
                kind=None if b.props("Prefix", pu) else "bgp-network",
                anchor=vru,
                l3dom=vrfs.domains.get(vrf_name),
            )
            policy_name = item.get("policy_name")
            b.rel(
                "ORIGINATES",
                "VrfInstance",
                vru,
                "Prefix",
                prefix,
                key={"proto": "network"},
                proto="network",
                route_map=policy_name,
            )
            if policy_name:
                target = uid.route_policy(dev, "rpl", policy_name)
                if target in policy_uids:
                    b.rel(
                        "FILTERED_BY",
                        "RoutingProcess",
                        rp_uid,
                        "RoutePolicy",
                        target,
                        key={"direction": "redistribute", "protocol": "network"},
                        direction="redistribute",
                        protocol="network",
                    )
        _aggregate_origins(
            b,
            vru=vru,
            rp_uid=rp_uid,
            aggregates=process.get("aggregates") or [],
            l3dom=vrfs.domains.get(vrf_name),
            policy_uid_for=lambda name: (
                target if (target := uid.route_policy(dev, "rpl", name)) in policy_uids else None
            ),
        )

        session_gaps: list[str] = []
        for sess in expand_dynamic_neighbors(
            process.get("sessions") or [],
            (inter.get("bgp_observed") or {}).get("sessions") or [],
            vrf_name,
            as_key="peer_asn",
            report_missing=True,
        ):
            if sess.get("peer_asn") is None and peer_network(sess["peer_ip"]) is None:
                # The process records the skipped session in `session_gaps`.
                # app/simul_read.py reports each gap as an unrecorded session.
                gap = session_gap(sess)
                logger.warning("iosxr: %s %s; skipped", rp_uid, gap)
                session_gaps.append(gap)
                continue
            peer_label, su = emit_bgp_peer(
                b,
                rp_uid,
                vrf_name,
                peer_ip=sess["peer_ip"],
                local_asn=sess["local_asn"],
                peer_asn=sess["peer_asn"],
                afi_safi=sess.get("afi_safi") or [],
                state=sess.get("state"),
                **{k: sess[k] for k in ("dynamic_range", "observed_state", "inheritance_gaps") if k in sess},
                import_policy_name=sess.get("import_policy_name"),
                import_policy_kind=sess.get("import_policy_kind"),
                export_policy_name=sess.get("export_policy_name"),
                export_policy_kind=sess.get("export_policy_kind"),
                route_reflector_client=reflector_client(sess),
                cluster_id=sess.get("cluster_id") or process.get("cluster_id"),
                peer_router_id=observed_peer_router_id(inter.get("bgp_observed"), vrf_name, sess["peer_ip"]),
            )
            for direction, name, kind in (
                ("in", sess.get("import_policy_name"), sess.get("import_policy_kind")),
                ("out", sess.get("export_policy_name"), sess.get("export_policy_kind")),
            ):
                if not name:
                    continue
                target = uid.route_policy(dev, kind, name)
                if target in policy_uids:
                    b.rel(
                        "FILTERED_BY",
                        peer_label,
                        su,
                        "RoutePolicy",
                        target,
                        key={"direction": direction},
                        direction=direction,
                    )
                else:
                    logger.warning(
                        "iosxr: neighbor %s %sbound route-policy %r is not defined",
                        sess["peer_ip"],
                        direction,
                        name,
                    )
        if session_gaps:
            b.node("RoutingProcess", rp_uid, session_gaps=session_gaps)

        for r in process.get("redistribute") or []:
            name = r.get("policy_name")
            if not name:
                continue
            target = uid.route_policy(dev, "rpl", name)
            if target in policy_uids:
                b.rel(
                    "FILTERED_BY",
                    "RoutingProcess",
                    rp_uid,
                    "RoutePolicy",
                    target,
                    key={"direction": "redistribute", "protocol": r["protocol"]},
                    direction="redistribute",
                    protocol=r["protocol"],
                )
            else:
                logger.warning("iosxr: redistribute %s route-policy %r is not defined", r["protocol"], name)


# --- OSPF: shared graph stage ----------------------------
#
# The stage writes these labels of core/labels.py: a `RoutingProcess` with proto
# "ospf", an `OspfArea` per area of the process, `IN_AREA` from each `Interface`
# that the process runs on, and an `OspfAdjacency` per neighbor. The link-state
# database goes to the `ospf_lsdb` side-store table as one row per LSA
# (`ospf_side_rows`).

# The `redistribute` protocols that an OSPF process can name. The OSPF config
# parser of each family reads them (`nxos.parse_ospf_config`).
OSPF_REDIST_PROTOCOLS: tuple[str, ...] = ("bgp", "direct", "static", "rip", "eigrp", "isis", "ospf")


def _defined_route_policies(inter: dict[str, Any]) -> dict[str, str]:
    """Map each policy name to the `kind` of its definition.

    The intermediate shape holds route-policy definitions in 3 keys: `bgp`
    for NX-OS, `routing` for IOS-XE and `xr_route_policies` for IOS-XR.
    """
    kinds: dict[str, str] = {}
    for name in (inter.get("bgp") or {}).get("route_maps") or {}:
        kinds[name] = "route-map"
    for name in (inter.get("routing") or {}).get("route_maps") or {}:
        kinds[name] = "route-map"
    for rp in inter.get("xr_route_policies") or []:
        kinds[rp["name"]] = rp["kind"]
    return kinds


def _ospf_process(
    b: GraphBuilder, proc: dict[str, Any], *, dev: str, vname: str, inter: dict[str, Any]
) -> str:
    """The `RoutingProcess` node for one OSPF process, its areas, and the
    redistribution statements it names. Returns the process uid."""
    # The uid holds the process id. IOS runs more than one OSPF process in one
    # VRF.
    process = proc.get("process")
    rpu = uid.routing_process(dev, vname, f"ospf-{process}" if process else "ospf")
    b.node(
        "RoutingProcess",
        rpu,
        proto="ospf",
        process_id=proc.get("process"),
        router_id=proc.get("router_id"),
        # The property is set only when the statement is configured.
        default_information_originate=True if proc.get("default_information_originate") else None,
        default_information_originate_always=True
        if proc.get("default_information_originate_always")
        else None,
    )
    for area in proc.get("areas") or []:
        au = uid.ospf_area(rpu, area["area_id"])
        b.node("OspfArea", au, area_id=area["area_id"], type=area.get("type"))
        b.rel("HAS", "RoutingProcess", rpu, "OspfArea", au)

    kinds = _defined_route_policies(inter)
    for r in proc.get("redistribute") or []:
        protocol, name = r["protocol"], r.get("route_map")
        if not name:
            continue
        # The process holds the raw name whether or not the name resolves. A
        # raw name without a FILTERED_BY edge marks an attached policy that is
        # undefined.
        b.node("RoutingProcess", rpu, **{f"redist_{protocol}_route_map": name})
        kind = kinds.get(name)
        if kind is None:
            logger.warning(
                "ospf: %s redistribute %s names undefined route-policy %r; raw name kept, no edge",
                rpu,
                protocol,
                name,
            )
            continue
        b.rel(
            "FILTERED_BY",
            "RoutingProcess",
            rpu,
            "RoutePolicy",
            uid.route_policy(dev, kind, name),
            key={"direction": "redistribute", "protocol": protocol},
            direction="redistribute",
            protocol=protocol,
        )
    return rpu


def ospf_stage(
    b: GraphBuilder,
    inter: dict[str, Any],
    *,
    dev: str,
    vrfs: VrfDomains,
    iface_uids: dict[str, str],
) -> None:
    """Write RoutingProcess, OspfArea and OspfAdjacency nodes from the optional
    `inter["ospf"]`, and the `IN_AREA` edges from the interfaces that the
    process runs on.

    Without an `ospf` key the stage writes nothing. A platform whose collector
    does not read OSPF and a device with no OSPF feature have no `ospf` key.
    """
    ospf = inter.get("ospf") or {}
    processes = ospf.get("processes") or []
    if not processes:
        return
    resolve = inter_ifnames(inter)

    proc_uids: dict[tuple[str, str], str] = {}
    for proc in processes:
        vname = proc.get("vrf") or DEFAULT_VRF
        vru = _vrf_node(vrfs, "" if vname == DEFAULT_VRF else vname)
        rpu = _ospf_process(b, proc, dev=dev, vname=vname, inter=inter)
        b.rel("IN_VRF", "RoutingProcess", rpu, "VrfInstance", vru)
        proc_uids[(proc.get("process") or "", vname)] = rpu

    def _process_of(row: dict[str, Any], what: str) -> str | None:
        key = (row.get("process") or "", row.get("vrf") or DEFAULT_VRF)
        rpu = proc_uids.get(key)
        if rpu is None:
            logger.warning("ospf: %s names process %r, which the process table never listed", what, key)
        return rpu

    for ifc in ospf.get("interfaces") or []:
        name = ifc.get("name")
        iu = iface_uids.get(resolve.slug(name)) if name else None
        rpu = _process_of(ifc, f"interface {name!r}")
        if iu is None or rpu is None:
            if rpu is not None:
                logger.warning("ospf: interface %r is not in the interface table; no IN_AREA edge", name)
            continue
        au = uid.ospf_area(rpu, ifc["area"])
        b.node("OspfArea", au, area_id=ifc["area"])
        b.rel(
            "IN_AREA",
            "Interface",
            iu,
            "OspfArea",
            au,
            cost=ifc.get("cost"),
            network_type=ifc.get("network_type"),
            passive=ifc.get("passive"),
        )

    for adj in ospf.get("adjacencies") or []:
        name = adj.get("local_interface")
        iu = iface_uids.get(resolve.slug(name)) if name else None
        rpu = _process_of(adj, f"adjacency on {name!r}")
        rid = adj.get("neighbor_router_id")
        if iu is None or rpu is None or not rid:
            if rpu is not None and iu is None:
                logger.warning("ospf: adjacency on %r has no Interface node; skipped", name)
            continue
        adju = uid.ospf_adjacency(rpu, iu, rid)
        b.node(
            "OspfAdjacency",
            adju,
            state=adj.get("state"),
            area=adj.get("area"),
            neighbor_router_id=rid,
            neighbor_ip=adj.get("neighbor_ip"),
            local_interface=name,
        )
        b.rel("HAS", "RoutingProcess", rpu, "OspfAdjacency", adju)
        b.rel("ENDPOINT", "OspfAdjacency", adju, "Interface", iu)


# --- BGP / route-policy: shared graph stage (IOS-XE) -----------------------------------


def routing_stage(b: GraphBuilder, inter: dict[str, Any], *, dev: str, source: str, vrfs: VrfDomains) -> None:
    """Write RoutingProcess, BgpSession, RoutePolicy, RoutePolicyEntry and
    PrefixListEntry nodes from the optional `inter["routing"]`.

    Without a `routing` key (no BGP, prefix-list or route-map config captured)
    the stage writes nothing. A route-map match clause, a `redistribute` line or
    a neighbor policy attachment gets a REFERENCES or FILTERED_BY edge only when
    a `RoutePolicy` of the matching kind and name exists in the same batch. A
    node property always holds the raw name.
    """
    routing = inter.get("routing")
    if not routing:
        return

    policy_uids: dict[tuple[str, str], str] = match_list_stage(
        b, [*(routing.get("community_lists") or []), *(routing.get("as_path_lists") or [])], dev=dev
    )
    dangling: list[str] = []

    for name, entries in (routing.get("prefix_lists") or {}).items():
        pol = b.node("RoutePolicy", uid.route_policy(dev, "prefix-list", name), name=name, kind="prefix-list")
        policy_uids[("prefix-list", name)] = pol
        for e in entries:
            base_len = int(e["prefix"].split("/", 1)[1])
            max_bits = 128 if ":" in e["prefix"] else 32
            # `eq` takes precedence over `ge` and `le` when a line has both. The
            # vendor applies `eq` last in its field assignment order. With `le`
            # alone, the minimum length is the length of the prefix. A line
            # with none of the 3 matches the configured length only.
            if e.get("eq") is not None:
                min_len = max_len = e["eq"]
            elif e.get("ge") is None and e.get("le") is None:
                min_len = max_len = base_len
            else:
                min_len = e["ge"] if e.get("ge") is not None else base_len
                max_len = e["le"] if e.get("le") is not None else max_bits
            entry_uid = uid.prefix_list_entry(pol, e["seq"])
            b.node(
                "PrefixListEntry",
                entry_uid,
                seq=e["seq"],
                action=e["action"],
                prefix=e["prefix"],
                ge=e.get("ge"),
                le=e.get("le"),
                eq=e.get("eq"),
                min_len=min_len,
                max_len=max_len,
            )
            b.rel("HAS_RULE", "RoutePolicy", pol, "PrefixListEntry", entry_uid)

    for name, clauses in (routing.get("route_maps") or {}).items():
        pol = b.node("RoutePolicy", uid.route_policy(dev, "route-map", name), name=name, kind="route-map")
        policy_uids[("route-map", name)] = pol
        for c in clauses:
            entry_uid = uid.route_policy_entry(pol, c["seq"])
            b.node(
                "RoutePolicyEntry",
                entry_uid,
                seq=c["seq"],
                kind="clause",
                action=c["action"],
                continues=c["continues"],
                continue_seq=c.get("continue_seq"),
                match_prefix_lists=c.get("match_prefix_lists") or [],
                match_as_path_lists=c.get("match_as_path_lists") or [],
                match_community_lists=c.get("match_community_lists") or [],
                match_tags=c.get("match_tags") or [],
                match_metric=c.get("match_metric"),
                match_protocols=c.get("match_protocols") or [],
                match_unsupported=c.get("match_unsupported") or None,
                set_unsupported=c.get("set_unsupported") or None,
                set_local_pref=c.get("set_local_pref"),
                set_metric=c.get("set_metric"),
                set_origin=c.get("set_origin"),
                set_tag=c.get("set_tag"),
                set_weight=c.get("set_weight"),
                set_next_hop=c.get("set_next_hop"),
                set_as_path_prepend=c.get("set_as_path_prepend") or [],
                set_communities=c.get("set_communities") or [],
                set_communities_additive=c.get("set_communities_additive"),
                set_comm_list_delete=c.get("set_comm_list_delete"),
            )
            b.rel("HAS_RULE", "RoutePolicy", pol, "RoutePolicyEntry", entry_uid)
            for pl_name in c.get("match_prefix_lists") or []:
                target = policy_uids.get(("prefix-list", pl_name))
                if target:
                    b.rel(
                        "REFERENCES",
                        "RoutePolicyEntry",
                        entry_uid,
                        "RoutePolicy",
                        target,
                        key={"kind": "prefix-list"},
                    )
                else:
                    dangling.append(f"route-map {name} seq {c['seq']}: prefix-list {pl_name!r} not captured")
            for kind, list_name in list_references(c):
                target = policy_uids.get((kind, list_name))
                if target:
                    b.rel(
                        "REFERENCES",
                        "RoutePolicyEntry",
                        entry_uid,
                        "RoutePolicy",
                        target,
                        key={"kind": kind},
                    )
                else:
                    dangling.append(f"route-map {name} seq {c['seq']}: {kind} {list_name!r} not captured")

    bgp = routing.get("bgp")
    if bgp:
        for bgp_process in bgp.get("processes") or [bgp]:
            vrf_name = bgp_process.get("vrf") or DEFAULT_VRF
            vru = _vrf_node(vrfs, vrf_name)
            proc = b.node(
                "RoutingProcess",
                uid.routing_process(dev, vrf_name, "bgp"),
                proto="bgp",
                asn=bgp_process["asn"],
                router_id=bgp_process.get("router_id"),
                # The property is set only when configured. An absent property
                # is the default, gated MED.
                always_compare_med=True if bgp_process.get("always_compare_med") else None,
                **bgp_multipath_props(
                    bgp_process.get("maximum_paths") or {}, bool(bgp_process.get("multipath_relax"))
                ),
                default_information_originate_afs=bgp_process.get("default_information_originate_afs")
                or None,
                redistribute_protocols=sorted({r["protocol"] for r in bgp_process.get("redistribute") or []}),
                origin_config_recorded=True,
                # An absent address family is not configured.
                origin_afs=[4, 6],
                origin_context_gaps=[
                    *(
                        item.get("raw") or "network"
                        for item in bgp_process.get("networks") or []
                        if isinstance(item, dict) and not item.get("prefix")
                    ),
                    *(
                        f"aggregate-address {item.get('raw') or 'unknown'} has no parseable prefix"
                        for item in bgp_process.get("aggregates") or []
                        if isinstance(item, dict) and not item.get("prefix")
                    ),
                    *(bgp_process.get("origin_context_gaps") or []),
                ],
            )
            b.rel("IN_VRF", "RoutingProcess", proc, "VrfInstance", vru)
            for item in bgp_process.get("networks") or []:
                cidr = item["prefix"] if isinstance(item, dict) else item
                if not cidr:
                    continue
                # A network statement for a connected subnet keeps the
                # connected kind. The gateway rule of reasoner/catalog.py reads
                # the kind.
                pu = uid.prefix(vru, cidr)
                prefix = b.node(
                    "Prefix",
                    pu,
                    cidr=cidr,
                    af=ipaddress.ip_network(cidr, strict=False).version,
                    kind=None if b.props("Prefix", pu) else "bgp-network",
                    anchor=vru,
                    l3dom=vrfs.domains.get(vrf_name),
                )
                route_map = item.get("route_map") if isinstance(item, dict) else None
                b.rel(
                    "ORIGINATES",
                    "VrfInstance",
                    vru,
                    "Prefix",
                    prefix,
                    key={"proto": "network"},
                    proto="network",
                    route_map=route_map,
                )
                if route_map:
                    target = policy_uids.get(("route-map", route_map))
                    if target:
                        b.rel(
                            "FILTERED_BY",
                            "RoutingProcess",
                            proc,
                            "RoutePolicy",
                            target,
                            key={"direction": "redistribute", "protocol": "network"},
                        )
            _aggregate_origins(
                b,
                vru=vru,
                rp_uid=proc,
                aggregates=bgp_process.get("aggregates") or [],
                l3dom=vrfs.domains.get(vrf_name),
                policy_uid_for=lambda name: policy_uids.get(("route-map", name)),
            )

            for r in bgp_process.get("redistribute") or []:
                route_map = r.get("route_map")
                if not route_map:
                    continue
                target = policy_uids.get(("route-map", route_map))
                if target:
                    b.rel(
                        "FILTERED_BY",
                        "RoutingProcess",
                        proc,
                        "RoutePolicy",
                        target,
                        key={"direction": "redistribute", "protocol": r["protocol"]},
                    )
                else:
                    dangling.append(f"redistribute {r['protocol']}: route-map {route_map!r} not captured")

            session_gaps: list[str] = []
            for n in expand_dynamic_neighbors(
                bgp_process.get("neighbors") or [],
                (inter.get("bgp_observed") or {}).get("sessions") or [],
                vrf_name,
                report_missing=True,
            ):
                remote_as = n.get("remote_as")
                if remote_as is None and peer_network(n["peer_ip"]) is None:
                    gap = session_gap(n)
                    logger.warning("%s: %s %s; skipped", source, proc, gap)
                    session_gaps.append(gap)
                    continue
                peer_ip = n["peer_ip"]
                # A route-map is the session policy of its direction. A lone
                # prefix-list is the policy when there is no route-map. IOS also
                # applies a prefix-list attached beside the route-map. The
                # session keeps it as `<direction>_prefix_list_name`, and the
                # engine applies it first.
                import_name = n.get("route_map_in") or n.get("prefix_list_in")
                import_kind = (
                    "route-map"
                    if n.get("route_map_in")
                    else ("prefix-list" if n.get("prefix_list_in") else None)
                )
                export_name = n.get("route_map_out") or n.get("prefix_list_out")
                export_kind = (
                    "route-map"
                    if n.get("route_map_out")
                    else ("prefix-list" if n.get("prefix_list_out") else None)
                )
                beside = {
                    direction: n.get(f"prefix_list_{direction}") if n.get(f"route_map_{direction}") else None
                    for direction in ("in", "out")
                }
                peer_label, sess = emit_bgp_peer(
                    b,
                    proc,
                    vrf_name,
                    peer_ip=peer_ip,
                    local_asn=bgp_process["asn"],
                    peer_asn=remote_as,
                    state="shutdown" if n.get("shutdown") else None,
                    **{
                        k: n[k]
                        for k in (
                            "dynamic_range",
                            "observed_state",
                            "peer_group",
                            "inheritance_gaps",
                            "next_hop_self",
                        )
                        if k in n
                    },
                    import_policy_name=import_name,
                    import_policy_kind=import_kind,
                    export_policy_name=export_name,
                    export_policy_kind=export_kind,
                    import_prefix_list_name=beside["in"],
                    export_prefix_list_name=beside["out"],
                    import_filter_list_name=n.get("filter_list_in"),
                    export_filter_list_name=n.get("filter_list_out"),
                    route_reflector_client=reflector_client(n),
                    cluster_id=n.get("cluster_id") or bgp_process.get("cluster_id"),
                    peer_router_id=observed_peer_router_id(inter.get("bgp_observed"), vrf_name, peer_ip),
                )
                for direction, name, kind in (
                    ("in", import_name, import_kind),
                    ("out", export_name, export_kind),
                    # A prefix list beside a route-map has its own direction key.
                    # The `in` and `out` edges hold only the session policy.
                    ("in-prefix-list", beside["in"], "prefix-list"),
                    ("out-prefix-list", beside["out"], "prefix-list"),
                ):
                    if not name:
                        continue
                    target = policy_uids.get((kind, name))
                    if target:
                        b.rel(
                            "FILTERED_BY",
                            peer_label,
                            sess,
                            "RoutePolicy",
                            target,
                            key={"direction": direction},
                        )
                    else:
                        dangling.append(f"neighbor {peer_ip} {direction}: {kind} {name!r} not captured")
            if session_gaps:
                b.node("RoutingProcess", proc, session_gaps=session_gaps)
    if dangling:
        logger.warning(
            "%s: %d dangling route-policy reference(s): %s", source, len(dangling), "; ".join(dangling)
        )


# --- NAT: shared config grammar and graph stage (NX-OS, IOS-XE) ------------------------
#
# NX-OS and IOS-XE use the same `ip nat ...` grammar. NX-OS also accepts the
# `prefix-length` spelling and puts interface roles in `interface` sub-blocks
# of `show running-config nat`.

_NAT_POOL_RE = re.compile(
    r"^ip nat pool (?P<name>\S+) (?P<start>\S+) (?P<end>\S+)"
    r" (?:netmask (?P<netmask>\S+)|prefix-length (?P<plen>\d+))"
)


def _pool_cidr(start: str, end: str) -> str | None:
    """Return the CIDR of the pool when start..end spans one whole block of
    more than one address, else None."""
    try:
        nets = list(ipaddress.summarize_address_range(ipaddress.ip_address(start), ipaddress.ip_address(end)))
    except ValueError:
        return None
    if len(nets) != 1 or nets[0].prefixlen >= nets[0].max_prefixlen:
        return None
    return str(nets[0])


def wildcard_cidr(network: str, wildcard: str | None) -> str | None:
    """Return the CIDR of an IOS ACL `network wildcard` pair.

    A bare network or a zero wildcard is a host. A non-contiguous wildcard
    returns None."""
    if not wildcard or wildcard == "0.0.0.0":  # noqa: S104 - an ACL wildcard
        return network
    try:
        mask = ipaddress.ip_address(int(ipaddress.ip_address(wildcard)) ^ 0xFFFFFFFF)
        return str(ipaddress.ip_network(f"{network}/{mask}", strict=False))
    except ValueError:
        return None


def _nat_rule(side: str, body: list[str]) -> dict | None:
    """One `ip nat (inside|outside) ...` rule line, tokenized past the side
    word. Returns None for a line that is not a rule. Unknown trailing tokens are ignored."""
    rule = {
        "direction": None,
        "static": False,
        "network": False,
        "prefixlen": None,
        "protocol": None,
        "local": None,
        "local_port": None,
        "global": None,
        "global_port": None,
        "acl": None,
        "pool": None,
        "interface": None,
        "overload": False,
        "route_map": None,
        "vrf": None,
    }
    if not body:
        return None
    what, rest = body[0], body[1:]
    if what == "destination":
        if side != "inside" or len(rest) < 4 or rest[0] != "list" or rest[2] != "pool":
            return None
        rule.update(direction="inside-destination", acl=rest[1], pool=rest[3])
        return rule
    if what != "source" or not rest:
        return None
    rule["direction"] = f"{side}-source"
    form, rest = rest[0], rest[1:]
    if form == "static":
        rule["static"] = True
        if rest and rest[0] in ("tcp", "udp"):
            rule["protocol"] = rest[0]
            rest = rest[1:]
        if rest and rest[0] == "network":
            rule["network"] = True
            rest = rest[1:]
        addrs: list[str | None] = []
        ports: list[int | None] = []
        while rest and len(addrs) < 2:
            tok = rest.pop(0)
            if tok.startswith("/"):
                rule["prefixlen"] = int(tok[1:])
                continue
            if tok == "interface" and rest:
                # In `static [tcp|udp] L [LP] interface <name> [GP]`, the
                # global side is the address of the interface.
                rule["interface"] = rest.pop(0)
                addrs.append(None)
            else:
                addrs.append(tok)
            ports.append(int(rest.pop(0)) if rule["protocol"] and rest and rest[0].isdigit() else None)
        if len(addrs) < 2:
            return None
        # IOS writes the inside form local-first and the outside form
        # global-first. The rule stores the addresses under `local` and `global`.
        first, second = ("local", "global") if side == "inside" else ("global", "local")
        if rule["interface"] and (addrs[0] is None or side != "inside"):
            return None  # only the global side of an inside rule names an interface
        rule[first], rule[second] = addrs
        rule[f"{first}_port"], rule[f"{second}_port"] = ports
        if rest and rest[0].startswith("/"):
            rule["prefixlen"] = int(rest.pop(0)[1:])
    elif form in ("list", "route-map"):
        if len(rest) < 3:
            return None
        rule["acl" if form == "list" else "route_map"] = rest[0]
        if rest[1] == "pool":
            rule["pool"] = rest[2]
        elif rest[1] == "interface":
            rule["interface"] = rest[2]
        else:
            return None
        rest = rest[3:]
    else:
        return None
    rule["overload"] = "overload" in rest
    if "vrf" in rest:
        idx = rest.index("vrf")
        if idx + 1 < len(rest):
            rule["vrf"] = rest[idx + 1]
    return rule


@debug_capture.traced
def parse_nat_config(lines: list[str]) -> dict[str, Any]:
    """Parse `ip nat ...` running-config lines into the intermediate `nat`
    shape (`if_roles`, `pools`, `rules`).

    The caller adds `acls`. The parser reads the IOS-XE flat
    `| include ^ip nat` extract and the NX-OS `show running-config nat`. The
    `interface` sub-blocks of the NX-OS output hold the bare
    `ip nat inside|outside` role lines. The rules keep the config order."""
    if_roles: dict[str, str] = {}
    pools: dict[str, dict] = {}
    rules: list[dict] = []
    current_if: str | None = None
    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped:
            continue
        indented = raw_line[:1].isspace()
        if not indented:
            current_if = None
        if stripped.startswith("interface "):
            current_if = stripped.split(None, 1)[1]
            continue
        if not stripped.startswith("ip nat "):
            continue
        m = _NAT_POOL_RE.match(stripped)
        if m:
            plen = m["plen"]
            if plen is None:
                try:
                    plen = ipaddress.ip_network(f"0.0.0.0/{m['netmask']}").prefixlen
                except ValueError:
                    plen = None
            pools[m["name"]] = {
                "start": m["start"],
                "end": m["end"],
                "prefixlen": int(plen) if plen is not None else None,
                "cidr": _pool_cidr(m["start"], m["end"]),
            }
            continue
        tokens = stripped.split()
        side, body = tokens[2], tokens[3:]
        if side not in ("inside", "outside"):
            continue
        if not body:
            if current_if:
                if_roles[current_if] = side
            continue
        rule = _nat_rule(side, body)
        if rule:
            rules.append(rule)
    return {"if_roles": if_roles, "pools": pools, "rules": rules}


def resolve_acl_sources(
    acl_records: dict[str, list[dict]] | None, acl_name: str, *, side: str = "src"
) -> dict[str, Any]:
    """Resolve a NAT rule's match ACL to concrete addresses.

    `acl_records` is {name: [{"action", "src", "dst"}]} with each side "any",
    a bare ip (host), a cidr, or None (unresolvable ACE). Only permit ACEs
    match traffic into the translation. A deny ACE exempts traffic, adds no
    edge and marks the resolution approximate."""
    records = (acl_records or {}).get(acl_name)
    if records is None:
        return {"targets": [], "any": False, "approximate": True, "unresolved": True}
    targets: list[str] = []
    any_flag = False
    approximate = False
    for ace in records:
        if ace.get("action") != "permit":
            approximate = True
            continue
        val = ace.get(side)
        if val == "any":
            any_flag = True
        elif val:
            targets.append(val)
        else:
            approximate = True
    return {"targets": targets, "any": any_flag, "approximate": approximate, "unresolved": False}


def _nat_target(
    b: GraphBuilder, rel: str, nu: str, dom: str, value: str, *, vrf_uid: str, **prefix_props: Any
) -> None:
    """Write an ORIG_* or XLATE_* edge to a Prefix (cidr) or an IpAddress (bare
    address).

    The node is anchored on the VrfInstance of the rule (`vrf_uid`)."""
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            pu = b.node(
                "Prefix",
                uid.prefix(vrf_uid, str(net)),
                cidr=str(net),
                af=net.version,
                l3dom=dom,
                anchor=vrf_uid,
                **prefix_props,
            )
            b.rel(rel, "NatRule", nu, "Prefix", pu)
        else:
            af = ipaddress.ip_address(value).version
            ipu = b.node("IpAddress", uid.ip(vrf_uid, value), ip=value, af=af, l3dom=dom, anchor=vrf_uid)
            b.rel(rel, "NatRule", nu, "IpAddress", ipu)
    except ValueError:
        return


def _interface_v4(inter: dict[str, Any], resolve: IfNameResolver, name: str) -> str | None:
    """The one IPv4 address of the interface `name` in the interface table,
    or None when the interface is not there or holds none or more than one."""
    slug = resolve.slug(name)
    addrs = {
        ip["ip"]
        for ifc in inter.get("interfaces") or []
        if ifc.get("name") and resolve.slug(ifc["name"]) == slug
        for ip in ifc.get("ips") or []
        if ip.get("ip") and ":" not in str(ip["ip"])
    }
    return next(iter(addrs)) if len(addrs) == 1 else None


def nat_stage(
    b: GraphBuilder, inter: dict[str, Any], *, dev: str, scope: str, domain_for, vrf_node, iface_uids
) -> None:
    """Write FwRulebase and NatRule nodes and their address edges from the
    intermediate `nat` shape, and merge `nat_role` onto the Interface nodes."""
    nat = inter.get("nat") or {}
    resolve = inter_ifnames(inter)
    for ifname, role in (nat.get("if_roles") or {}).items():
        iu = iface_uids.get(resolve.slug(ifname))
        if iu:
            b.node("Interface", iu, nat_role=role)

    pools = nat.get("pools") or {}
    acls = nat.get("acls") or {}
    rulebases: dict[str, str] = {}
    ordinals: dict[str, int] = {}
    rules = nat.get("rules") or []
    # Cisco checks the static translations of a direction before its dynamic
    # rules, whatever order the configuration prints them in. `position` is
    # the evaluation order, with statics first and configuration order within
    # each class. The NAT gate and the policy engine read `position` as first
    # match. The uid keeps the configuration ordinal.
    statics: dict[str, int] = {}
    for r in rules:
        if r.get("static"):
            statics[r["direction"]] = statics.get(r["direction"], 0) + 1
    evaluated: dict[tuple[str, bool], int] = {}
    for r in rules:
        direction = r["direction"]
        rb = rulebases.get(direction)
        if rb is None:
            rb = b.node(
                "FwRulebase", f"{scope}:nat:{direction}", name=f"nat-{direction}", kind="nat", vendor="cisco"
            )
            b.rel("ENFORCES", "Device", dev, "FwRulebase", rb)
            rulebases[direction] = rb
        ordinals[direction] = ordinal = ordinals.get(direction, 0) + 1
        is_static = bool(r.get("static"))
        evaluated[direction, is_static] = rank = evaluated.get((direction, is_static), 0) + 1
        pos = rank if is_static else statics.get(direction, 0) + rank
        dom = domain_for(r.get("vrf") or "")
        vru = vrf_node(r.get("vrf") or "")
        # An outside-source rule rewrites the source of traffic from outside to
        # inside. On the return path it rewrites the destination. Its kind is dnat.
        kind = "snat" if direction == "inside-source" else "dnat"
        orig_rel = "ORIG_DST" if direction == "inside-destination" else "ORIG_SRC"
        xlate_rel = "XLATE_DST" if direction == "inside-destination" else "XLATE_SRC"

        approximate = bool(r.get("route_map"))
        src_any: bool | None = None
        translation: str | None = None
        orig_targets: list[str] = []
        xlate_target: str | None = None
        pool = pools.get(r["pool"]) if r.get("pool") else None

        if r.get("static") and r.get("interface"):
            # The global side is the address of the interface in the interface
            # table. Without a single IPv4 address on the interface, the rule
            # has no public side, and the NAT gate marks its flows opaque.
            orig_targets = [r["local"]]
            xlate_target = translation = _interface_v4(inter, resolve, r["interface"])
            if translation is None:
                translation, approximate = "interface", True
        elif r.get("static"):
            plen = r.get("prefixlen")
            orig, xlate = (
                (r["local"], r["global"]) if direction != "outside-source" else (r["global"], r["local"])
            )
            if r.get("network") and plen is not None:
                orig = str(ipaddress.ip_network(f"{orig}/{plen}", strict=False))
                xlate = str(ipaddress.ip_network(f"{xlate}/{plen}", strict=False))
            orig_targets = [orig]
            xlate_target = translation = xlate
        elif r.get("acl"):
            res = resolve_acl_sources(acls, r["acl"], side="dst" if orig_rel == "ORIG_DST" else "src")
            approximate = approximate or res["approximate"]
            src_any = res["any"]
            orig_targets = res["targets"]

        if r.get("interface") and not r.get("static"):
            # Interface overload is masquerade. The translated address is the
            # address of the egress interface. The rule gets no XLATE edge.
            translation = "interface"
        elif pool and not r.get("static"):
            xlate_target = translation = pool["cidr"] or pool["start"]

        orig_port = r.get("local_port") if direction != "outside-source" else r.get("global_port")
        translation_port = r.get("global_port") if direction != "outside-source" else r.get("local_port")
        nu = b.node(
            "NatRule",
            f"{scope}:nat:{direction}:{ordinal}",
            position=pos,
            direction=direction,
            kind=kind,
            static=bool(r.get("static")),
            overload=bool(r.get("overload")),
            translation=translation,
            translation_interface=r.get("interface"),
            translation_port=translation_port,
            orig_port=orig_port,
            protocol=r.get("protocol"),
            match_acl=r.get("acl"),
            match_route_map=r.get("route_map"),
            pool=r.get("pool"),
            pool_start=pool["start"] if pool else None,
            pool_end=pool["end"] if pool else None,
            src_any=src_any,
            approximate=approximate,
        )
        b.rel("HAS_RULE", "FwRulebase", rb, "NatRule", nu)
        # The collector does not read a route-map match. The rule gets
        # match_route_map and approximate and no address edges.
        if r.get("route_map"):
            continue
        for t in orig_targets:
            _nat_target(b, orig_rel, nu, dom, t, vrf_uid=vru)
        if xlate_target:
            props = {"kind": "nat-pool"} if pool and not r.get("static") else {}
            _nat_target(b, xlate_rel, nu, dom, xlate_target, vrf_uid=vru, **props)


# --- Interface ACLs: access-group bindings and the filter rulebase stage ---------------
#
# `ip access-group <name> in|out` binds one access list to one interface in one
# direction. Each access list a device binds becomes one FwRulebase (kind='access',
# match_context='interface-acl'), and every binding is an edge
# (Interface)-[:PROTECTED_BY {direction}]->(FwRulebase).
#
# `default_action='deny'` is written unconditionally (the implicit deny of Cisco).
#
# The ACE shape the two families produce, one dict per ACE in list order:
#   {"action": "permit"|"deny",
#    "src_any": bool, "src": <cidr|ip|None>, "src_opaque_reason": str|None,
#    "dst_any": bool, "dst": <cidr|ip|None>, "dst_opaque_reason": str|None,
#    "proto": str|None, "ports": str|None, "src_port": str|None,
#    "svc_opaque_reason": str|None, "qualifier_reason": str|None,
#    "states": list[str]|None (present only for an `established` ACE),
#    "icmp_type": str (present only for an ACE that names an ICMP type),
#    "unmodeled_fields": list[str] (present only for an ACE whose record holds a
#    field outside the allow-list of the family, each named in `qualifier_reason`),
#    "src_opaque_note" / "dst_opaque_note" / "svc_opaque_note" / "qualifier_note": str
#    (present only beside a reason)}
# `proto=None` with no port spec is "every protocol" (the `ip` keyword). The rule
# gets `svc_any` for it. Every "_reason" field holds the text that the leg note
# prints. The "_note" beside it is the short form that the firewall table lists
# (queries.py `firewall`). `established` is in `states`.

#
# Beside `ip access-group`, an interface binds a filter as a port ACL (NX-OS
# `ip port access-group`, `ipv6 port traffic-filter`, `mac port access-group`), an
# IPv6 filter (`ipv6 traffic-filter`), a MAC access list (`mac access-group`), or the
# IOS-XR `ipv4|ipv6 access-group <name> ingress|egress`, and a VLAN access map filters
# whole VLANs (`vlan filter <map> vlan-list <ids>`, global config). Each is a binding
# of its own family (`_ACL_FAMILIES`).
_ACCESS_GROUP_RE = re.compile(
    r"^(?P<af>ip|ipv4|ipv6|mac) (?P<port>port )?(?:access-group|traffic-filter) "
    r"(?:common (?P<common>\S+) )?(?P<acl>\S+)(?: (?P<direction>in|out|ingress|egress))?"
    r"(?:(?: hardware-count| interface-statistics| compress level \d+)*)\s*$"
)
# A line that binds any filter to the interface, whether the grammar reads it or not.
_FILTER_BINDING_RE = re.compile(r"^(?:ip|ipv4|ipv6|mac) (?:port )?(?:access-group|traffic-filter)\b")
# In the IOS-XE zone-based firewall, an interface that is a zone member passes only
# the traffic that the inspect policy of a zone-pair allows, and no traffic between
# a member and a non-member. The collector does not read zones, zone-pairs and
# inspect policies. The membership is bound as its own family, and the placeholder
# rule of the family names the gap.
_ZONE_MEMBER_RE = re.compile(r"^zone-member security (?P<zone>\S+)\s*$")
_VLAN_FILTER_RE = re.compile(r"^vlan filter (?P<map>\S+) vlan-list (?P<vlans>[^\s,]*(?:\s*,\s*[^\s,]*)*)\s*$")
_DIRECTIONS = {"in": "in", "out": "out", "ingress": "in", "egress": "out"}
_INTERFACE_STANZA_RE = re.compile(r"^interface (?P<name>\S.*?)\s*$")

# Maps a binding family to (rulebase uid segment, rulebase af, the reason that the
# gate cannot read the entries of a list of the family). The IPv4 family reads
# `acl["lists"]`. The lists of every other family are not collected or not modeled.
# The rulebase of such a family holds the opaque placeholder rule with the reason.
# An af of None judges flows of both families, as the gate does for a rulebase
# with no family.
_ACL_FAMILIES: dict[str, tuple[str, int | None, str | None]] = {
    "ipv4": ("acl", 4, None),
    "ipv6": ("acl6", 6, "IPv6 access lists are not collected"),
    "mac": ("macacl", None, "MAC access lists are not modeled"),
    "vlan-map": ("vacl", None, "VLAN access maps are not modeled"),
    "common": (
        "aclcommon",
        None,
        "a common access list is applied before the interface access list, which is not modeled",
    ),
    "unparsed": ("aclline", None, "this interface filter binding could not be read"),
    "zone": (
        "zbfw",
        None,
        "the interface is a member of a zone-based firewall zone, whose zone-pair inspect "
        "policies are not modeled",
    ),
}

_UNCOLLECTED_ACL_REASON = "the access list this interface is bound to was not collected"
_EMPTY_ACL_REASON = "the access list collected no entries"
_UNREAD_ACE_SIDE_REASON = "the address on this ACE could not be read"


@debug_capture.traced
def parse_access_groups(lines: list[str]) -> list[dict[str, str]]:
    """Parse interface running-config into the filter bindings of each interface.

    Returns [{"interface", "direction", "acl"}] in config order, with a
    "family" key (`_ACL_FAMILIES`) on every binding that is not an IPv4 access
    list.

    An IOS-XR direction (ingress, egress) is read as in and out. An NX-OS
    `mac port access-group` names no direction and filters inbound. An IOS-XR
    binding with a `common` access list is one binding of the "common" family.
    The device applies the common list before the interface list. A filter
    binding line that the grammar does not read is one "unparsed" binding per
    direction with the line as its name. An IOS-XE `zone-member security <zone>`
    line is one "zone" binding per direction named after the zone. The parser
    drops any other line.
    """
    out: list[dict[str, str]] = []
    current: str | None = None
    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("!"):
            continue
        if not raw_line[:1].isspace():
            m = _INTERFACE_STANZA_RE.match(stripped)
            current = m["name"] if m else None
            continue
        if current is None:
            continue
        line = " ".join(stripped.split())
        if zm := _ZONE_MEMBER_RE.match(line):
            out.extend(
                {"interface": current, "direction": side, "acl": zm["zone"], "family": "zone"}
                for side in ("in", "out")
            )
            continue
        if not _FILTER_BINDING_RE.match(stripped):
            continue
        out.extend(_filter_bindings(current, line))
    return out


def _filter_bindings(interface: str, line: str) -> list[dict[str, str]]:
    """The bindings one interface filter line makes (`parse_access_groups`)."""
    m = _ACCESS_GROUP_RE.match(line)
    acl, direction, common = (m["acl"], m["direction"], m["common"]) if m else (None, None, None)
    if m and common and direction is None and acl in _DIRECTIONS:
        # `ipv4 access-group common <name> ingress` binds a common list alone.
        acl, direction = common, acl
    if m and direction is None and m["af"] == "mac" and m["port"]:
        direction = "in"
    if not m or direction is None or acl in _DIRECTIONS:
        return [
            {"interface": interface, "direction": side, "acl": line, "family": "unparsed"}
            for side in ("in", "out")
        ]
    binding = {"interface": interface, "direction": _DIRECTIONS[direction], "acl": acl}
    if common:
        # The binding name holds both lists in the order that the device applies them.
        binding.update(acl=common if acl == common else f"{common} {acl}", family="common")
    elif m["af"] == "ipv6":
        binding["family"] = "ipv6"
    elif m["af"] == "mac":
        binding["family"] = "mac"
    return [binding]


def _vlan_ids(spec: str) -> list[int] | None:
    """The VLAN ids of a `vlan-list` ("10,20-22"), or None for one that does not
    read as ids and ranges between 1 and 4094."""
    ids: list[int] = []
    for part in spec.replace(" ", "").split(","):
        lo, _sep, hi = part.partition("-")
        if not lo.isdigit() or (hi and not hi.isdigit()):
            return None
        first, last = int(lo), int(hi or lo)
        if not 1 <= first <= last <= 4094:
            return None
        ids.extend(range(first, last + 1))
    return ids


@debug_capture.traced
def parse_vlan_filters(lines: list[str]) -> list[dict[str, str]]:
    """Parse global `vlan filter <map> vlan-list <ids>` lines into "vlan-map"
    bindings.

    A VLAN access map filters every packet of the VLANs that it names, routed
    or bridged. The parser binds it to the interface of each VLAN (`Vlan<id>`)
    in both directions. A VLAN interface that the device did not report stays
    on the rulebase as an unreported binding (`acl_stage`). A line whose VLAN
    list does not parse gets no binding and a log warning.
    """
    out: list[dict[str, str]] = []
    for raw_line in lines:
        m = _VLAN_FILTER_RE.match(raw_line.strip())
        if not m:
            continue
        ids = _vlan_ids(m["vlans"])
        if ids is None:
            logger.warning("vlan filter %s: VLAN list %r does not read; not bound", m["map"], m["vlans"])
            continue
        out.extend(
            {"interface": f"Vlan{vid}", "direction": side, "acl": m["map"], "family": "vlan-map"}
            for vid in ids
            for side in ("in", "out")
        )
    return out


# The port keywords that an ACE prints in place of a number. IOS, IOS-XE and NX-OS
# show a well-known port by its name (`eq bgp`, `eq domain`, `range ftp-data ftp`).
# The names come from 2 lists, one per protocol. The lists are the TCP and UDP port
# names of the Cisco IOS Security Command Reference (`permit`, extended IP ACL).
# NX-OS prints the same names. IOS-XE adds the TCP names drip and msrpc. A keyword
# resolves only against the table of the protocol of its ACE. Most names exist for
# one protocol only (`www`, `snmp`). 3 numbers have a different name per protocol.
# 512 is exec on TCP and biff on UDP, 513 is login and who, and 514 is cmd and
# syslog. Without a protocol, only the names that both tables map to the same
# number resolve. A name in neither table stays opaque.
_TCP_PORT_KEYWORDS: dict[str, int] = {
    "bgp": 179,
    "chargen": 19,
    "cmd": 514,
    "daytime": 13,
    "discard": 9,
    "domain": 53,
    "drip": 3949,
    "echo": 7,
    "exec": 512,
    "finger": 79,
    "ftp": 21,
    "ftp-data": 20,
    "gopher": 70,
    "hostname": 101,
    "ident": 113,
    "irc": 194,
    "klogin": 543,
    "kshell": 544,
    "login": 513,
    "lpd": 515,
    "msrpc": 135,
    "nntp": 119,
    "pim-auto-rp": 496,
    "pop2": 109,
    "pop3": 110,
    "smtp": 25,
    "sunrpc": 111,
    "tacacs": 49,
    "talk": 517,
    "telnet": 23,
    "time": 37,
    "uucp": 540,
    "whois": 43,
    "www": 80,
}
_UDP_PORT_KEYWORDS: dict[str, int] = {
    "biff": 512,
    "bootpc": 68,
    "bootps": 67,
    "discard": 9,
    "dnsix": 195,
    "domain": 53,
    "echo": 7,
    "isakmp": 500,
    "mobile-ip": 434,
    "nameserver": 42,
    "netbios-dgm": 138,
    "netbios-ns": 137,
    "netbios-ss": 139,
    "non500-isakmp": 4500,
    "ntp": 123,
    "pim-auto-rp": 496,
    "rip": 520,
    "snmp": 161,
    "snmptrap": 162,
    "sunrpc": 111,
    "syslog": 514,
    "tacacs": 49,
    "talk": 517,
    "tftp": 69,
    "time": 37,
    "who": 513,
    "xdmcp": 177,
}


def ace_port_keyword(keyword: Any, proto: Any = None) -> int | None:
    """The port number of a Cisco ACE port keyword under the ACE's protocol, or None."""
    name = str(keyword).strip().lower()
    p = str(proto or "").strip().lower()
    if p == "tcp":
        return _TCP_PORT_KEYWORDS.get(name)
    if p == "udp":
        return _UDP_PORT_KEYWORDS.get(name)
    tcp, udp = _TCP_PORT_KEYWORDS.get(name), _UDP_PORT_KEYWORDS.get(name)
    return tcp if tcp is not None and tcp == udp else None


def _port_number(value: Any, proto: Any = None) -> int | None:
    try:
        n = int(str(value))
    except (TypeError, ValueError):
        return ace_port_keyword(value, proto) if value is not None else None
    return n if 0 <= n <= 65535 else None


def ace_port_spec(
    op: Any, port: Any, port_end: Any = None, *, proto: Any = None
) -> tuple[str | None, str | None]:
    """Return the `SvcObject.ports` spec and an opaque reason for an ACE port clause.

    The function is `ace_port_clause` without the short note."""
    spec, reason, _ = ace_port_clause(op, port, port_end, proto=proto)
    return spec, reason


def ace_port_clause(
    op: Any, port: Any, port_end: Any = None, *, proto: Any = None
) -> tuple[str | None, str | None, str | None]:
    """Return the `SvcObject.ports` spec, an opaque reason and its short note for an ACE port clause.

    The port comparison of the gate reads a comma-separated list of numbers
    and `lo-hi` ranges. `eq`, `range`, `lt` and `gt` map onto it. A port
    keyword (`eq www`) is read through the keyword table of the ACE protocol
    (`ace_port_keyword`). `neq` and a keyword the table does not hold return a
    reason and no spec.

    `precedence` and `tos` return a reason naming precedence or ToS.
    """
    if not op:
        return None, None, None
    op = str(op).strip().lower()
    if op == "precedence":
        return (
            None,
            f"the rule matches on IP precedence {str(port)!r}, which is not a port",
            f"precedence {port}",
        )
    if op == "tos":
        return None, f"the rule matches on ToS {str(port)!r}, which is not a port", f"tos {port}"
    if op == "range":
        lo, hi = _port_number(port, proto), _port_number(port_end, proto)
        if lo is None or hi is None:
            return (
                None,
                f"the port range {port} {port_end} does not name two port numbers",
                f"port range {' '.join(str(x) for x in (port, port_end) if x is not None)} unknown",
            )
        return f"{lo}-{hi}", None, None
    lo = _port_number(port, proto)
    if lo is None:
        return (
            None,
            f"the port keyword {str(port)!r} was not resolved to a port number",
            f"port keyword {port} unknown",
        )
    if op == "eq":
        return str(lo), None, None
    if op == "lt":
        return (f"0-{lo - 1}", None, None) if lo > 0 else (None, "'lt 0' names no port", "lt 0")
    if op == "gt":
        return (
            (f"{lo + 1}-65535", None, None) if lo < 65535 else (None, "'gt 65535' names no port", "gt 65535")
        )
    return None, f"the port operator {op!r} does not express a port set", f"{op} {lo}"


def ace_qualifier_reason(qualifiers: list[str]) -> str | None:
    """Return the reason line for ACE keywords outside the traced flow tuple.

    A trace models a new flow whose tuple is (source set, destination set,
    destination port, protocol). A TCP flag list, an ICMP type and a time-range
    each narrow a rule along a dimension outside the tuple. The trace can
    neither apply nor skip a rule that the addresses and the service otherwise
    match.
    """
    if not qualifiers:
        return None
    return f"the rule matches on {', '.join(qualifiers)}, which the traced flow does not state"


def ace_qualifiers(
    *,
    tcp_flags: Sequence[str] = (),
    icmp_type: Any = None,
    time_range: Any = None,
    unmodeled: Sequence[str] = (),
) -> dict[str, Any]:
    """The qualifier fields of one ACE in the shared shape, for both families.

    `qualifier_reason` is the sentence of the trace (`ace_qualifier_reason`).
    `qualifier_note` is the short form that the firewall table lists.
    `icmp_type` keeps the ICMP type as data on the service. `qualifier_note`
    is present only beside a reason, and `icmp_type` only for an ICMP type. An
    ICMP type alone gives an empty note beside its reason.

    `unmodeled` names the fields of the ACE record of the family that are
    outside its allow-list (`unmodeled_ace_fields`). Each field joins the
    reason. `unmodeled_fields` holds the names and is present only when there
    is one.
    """
    flags = " ".join(tcp_flags)
    qualifiers, notes = [], []
    if flags:
        qualifiers.append(f"the TCP flags {flags!r}")
        notes.append(f"tcp flags {flags}")
    if icmp_type:
        qualifiers.append(f"the ICMP type {icmp_type!r}")
    if time_range:
        qualifiers.append(f"the time-range {time_range!r}")
        notes.append(f"time-range {time_range}")
    for name in unmodeled:
        qualifiers.append(f"the field {name!r}")
        notes.append(f"field {name}")
    reason = ace_qualifier_reason(qualifiers)
    out: dict[str, Any] = {"qualifier_reason": reason}
    if reason:
        out["qualifier_note"] = "; ".join(notes)
    if icmp_type:
        out["icmp_type"] = str(icmp_type)
    if unmodeled:
        out["unmodeled_fields"] = list(unmodeled)
    return out


def unmodeled_ace_fields(record: Mapping[str, Any], known: frozenset[str]) -> list[str]:
    """Return the names of the fields of one ACE record that are outside the
    allow-list of the family and hold a value.
    """
    return sorted(str(k) for k, v in record.items() if k not in known and v not in (None, "", [], {}))


def _acl_address(b: GraphBuilder, scope: str, obj_uid: str, value: str, side: str) -> None:
    """Write the RESOLVES_TO edge of one ACE side, or mark the NetObject
    opaque when the address does not parse."""
    l3dom = f"l3dom:unresolved:{scope}"
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            target = b.node(
                "Prefix",
                uid.prefix(scope, str(net)),
                cidr=str(net),
                af=net.version,
                anchor=scope,
                l3dom=l3dom,
            )
            b.rel("RESOLVES_TO", "NetObject", obj_uid, "Prefix", target)
        else:
            addr = ipaddress.ip_address(value)
            target = b.node(
                "IpAddress", uid.ip(scope, value), ip=value, af=addr.version, anchor=scope, l3dom=l3dom
            )
            b.rel("RESOLVES_TO", "NetObject", obj_uid, "IpAddress", target)
    except ValueError:
        b.node(
            "NetObject",
            obj_uid,
            opaque=True,
            opaque_reason=f"the ACE address {value!r} could not be parsed",
            opaque_note=f"{side} address {value} unparseable",
        )


def _acl_rule_side(b: GraphBuilder, scope: str, rule_uid: str, ace: dict[str, Any], side: str) -> None:
    """Write the SRC or DST NetObject of one ACE, with its address or its
    opacity.

    A side that the collector did not resolve (an object-group, a
    non-contiguous wildcard) gets an opaque NetObject with the reason on it. A
    rule that references an opaque object evaluates as indeterminate and names
    the reason. The note beside the reason is its short form for the firewall
    table and names the side.
    """
    value = ace.get(side)
    obj_uid = b.node(
        "NetObject",
        f"{rule_uid}:{side}",
        name=value or ace.get(f"{side}_opaque_reason") or side,
        kind="inline",
    )
    if value:
        _acl_address(b, scope, obj_uid, value, side)
    else:
        reason = ace.get(f"{side}_opaque_reason")
        b.node(
            "NetObject",
            obj_uid,
            opaque=True,
            opaque_reason=reason or _UNREAD_ACE_SIDE_REASON,
            opaque_note=f"{side} {ace.get(f'{side}_opaque_note') or reason or 'address unread'}",
        )
    b.rel("SRC" if side == "src" else "DST", "FwRule", rule_uid, "NetObject", obj_uid)


def _acl_rule(b: GraphBuilder, rb: str, scope: str, position: int, ace: dict[str, Any]) -> None:
    """Write one FwRule for one ACE under its rulebase, with its address and service edges."""
    rule_uid = f"{rb}:{position}"
    proto = ace.get("proto")
    ports = ace.get("ports")
    src_port = ace.get("src_port")
    svc_reason = (
        "; ".join(dict.fromkeys(x for x in (ace.get("svc_opaque_reason"), ace.get("qualifier_reason")) if x))
        or None
    )
    # The short form of the same reasons for the firewall table. A reason with no
    # note beside it is its own short form. On an ICMP rule only, the service name
    # shows the ICMP type and the note leaves it out. The IOS template can read the
    # second port of `eq www 443` as an ICMP type, and the note then names it.
    icmp_type = ace.get("icmp_type") if str(proto or "").lower() in _ICMP_PROTOCOLS else None
    stray_icmp = f"icmp type {ace['icmp_type']}" if ace.get("icmp_type") and not icmp_type else None
    svc_note = "; ".join(
        dict.fromkeys(
            x
            for x in (
                _ace_note(ace, "svc_opaque_reason", "svc_opaque_note"),
                _ace_note(ace, "qualifier_reason", "qualifier_note"),
                stray_icmp,
            )
            if x
        )
    )
    ru = b.node(
        "FwRule",
        rule_uid,
        position=position,
        action=ace.get("action"),
        enabled=True,
        src_any=bool(ace.get("src_any")),
        dst_any=bool(ace.get("dst_any")),
        # the `ip` keyword with no port clause is every protocol on every port
        svc_any=not (proto or ports or src_port or svc_reason),
        states=ace.get("states") or [],
        unmodeled_fields=list(ace.get("unmodeled_fields") or ()),
    )
    b.rel("HAS_RULE", "FwRulebase", rb, "FwRule", ru)
    for side in ("src", "dst"):
        if not ace.get(f"{side}_any"):
            _acl_rule_side(b, scope, ru, ace, side)
    if proto or ports or src_port or svc_reason:
        # The firewall table shows the name. The name is <proto>/<ports> with an
        # optional source port after it, or the ICMP type that the rule matches.
        name = (
            f"icmp {icmp_type}"
            if icmp_type
            else f"{proto or 'any'}/{ports or 'any'}" + (f" src {src_port}" if src_port else "")
        )
        su = b.node(
            "SvcObject",
            f"{rule_uid}:svc",
            name=name,
            proto=proto,
            ports=ports,
            src_port=src_port,
            # Each rule has its own SvcObject with its own ICMP type.
            icmp_type=icmp_type,
            opaque=True if svc_reason else None,
            opaque_reason=svc_reason,
            opaque_note=svc_note if svc_reason else None,
        )
        b.rel("SVC", "FwRule", ru, "SvcObject", su)


# The protocol values of an ACE that can name an ICMP type, as keyword or number.
_ICMP_PROTOCOLS = {"icmp", "1"}


def _ace_note(ace: dict[str, Any], reason_key: str, note_key: str) -> str | None:
    """Return the short note beside one reason of an ACE.

    The note is the note that the family wrote, else the reason itself. The
    function returns None when there is no reason."""
    if not ace.get(reason_key):
        return None
    note = ace.get(note_key)
    return ace[reason_key] if note is None else note


def _acl_placeholder_rule(
    b: GraphBuilder, rb: str, acl_name: str, *, collected: bool, reason: str | None = None
) -> None:
    """Write the single rule of a rulebase whose access list has no ACE.

    A list that printed its header and no ACE, and a list that was not
    collected, each get an opaque rule with action "deny" that names the case.
    `reason` is the reason of a family of lists whose entries are not read at
    all (`_ACL_FAMILIES`). A given `reason` replaces both cases.
    """
    rule_uid = f"{rb}:1"
    ru = b.node(
        "FwRule",
        rule_uid,
        position=1,
        action="deny",
        enabled=True,
        src_any=False,
        dst_any=True,
        svc_any=True,
    )
    b.rel("HAS_RULE", "FwRulebase", rb, "FwRule", ru)
    note = reason or ("ACL empty" if collected else "ACL not collected")
    reason = reason or (_EMPTY_ACL_REASON if collected else _UNCOLLECTED_ACL_REASON)
    obj_uid = b.node(
        "NetObject",
        f"{rule_uid}:src",
        name=acl_name,
        kind="inline",
        opaque=True,
        opaque_reason=f"{reason} ({acl_name})",
        opaque_note=note,
    )
    b.rel("SRC", "FwRule", ru, "NetObject", obj_uid)


def acl_stage(b: GraphBuilder, inter: dict[str, Any], *, dev: str, scope: str) -> None:
    """Write one FwRulebase per bound access list from the intermediate `acl`
    shape.

    The device ENFORCES each rulebase. Each interface that the list is bound to
    is PROTECTED_BY the rulebase in the direction of the binding.

    `inter["acl"]` is {"lists": {name: [ace, ...]}, "bindings": [{"interface",
    "direction", "acl", optional "family"}]}. A list that is collected but
    bound nowhere gets no rulebase.

    A binding names its family (`_ACL_FAMILIES`), IPv4 when it names none. The
    stage writes one rulebase per family and list name. An IPv4 and an IPv6
    list that share a name are 2 rulebases. Only the IPv4 family reads
    `lists`. The rulebase of any other family holds the opaque placeholder rule
    with the reason that its entries cannot be read.

    The uid segment of the name is `uid.exact_slug`. Cisco ACL names are case
    sensitive, and `WEB-IN` and `web-in` are 2 rulebases.
    """
    acl = inter.get("acl") or {}
    bindings = acl.get("bindings") or []
    if not bindings:
        return
    lists = acl.get("lists") or {}
    resolve = inter_ifnames(inter)
    if_names = {i["name"] for i in inter.get("interfaces") or []}
    reported_numbers = {_number_of(name) for name in if_names} - {None}
    # Maps (family, access list name) to its bindings, in config order and once each.
    # A binding is (the interface node name or None when the device did not report
    # the interface, the config spelling, the direction).
    bound: dict[tuple[str, str], list[tuple[str | None, str, str]]] = {}
    seen: set[tuple[str, str, str, str]] = set()
    for binding in bindings:
        direction = binding.get("direction")
        acl_name = binding.get("acl")
        bound_to = binding.get("interface")
        family = binding.get("family") or "ipv4"
        if direction not in ("in", "out") or not acl_name or not bound_to:
            continue
        if family not in _ACL_FAMILIES:
            # A family unknown to the stage becomes the "unparsed" family.
            family = "unparsed"
        # The config spells the interface as the operator typed it. The resolver
        # matches it to the name that the device reported.
        resolved = str(resolve(bound_to))
        key = (family, acl_name, iface_slug(resolved), direction)
        if key in seen:
            continue
        seen.add(key)
        bound.setdefault((family, acl_name), []).append(
            (resolved if resolved in if_names else None, bound_to, direction)
        )
    for (family, acl_name), acl_bindings in bound.items():
        segment, af, reason = _ACL_FAMILIES[family]
        rb_uid = f"{scope}:{segment}:{uid.exact_slug(acl_name)}"
        # A binding to an interface that the device did not report stays on the
        # rulebase as "<interface> <direction>".
        unreported = [f"{spelled} {direction}" for name, spelled, direction in acl_bindings if name is None]
        # The analysis model rules an unreported binding out for a packet whose
        # interface the graph names otherwise. A spelling that shares its number with
        # a reported interface can be an abbreviation that the resolver could not
        # settle. The model does not rule such a binding out.
        uncertain = any(
            _number_of(spelled) in reported_numbers for name, spelled, _d in acl_bindings if name is None
        )
        _acl_rulebase(
            b,
            rb_uid,
            scope,
            dev,
            acl_name,
            lists.get(acl_name) if family == "ipv4" else None,
            unreported,
            af=af,
            unread_reason=reason,
            unreported_uncertain=uncertain,
        )
        for name, _spelled, direction in acl_bindings:
            if name is None:
                continue
            # The edge key holds the direction. A list bound in and out on one
            # interface gets 2 edges.
            b.rel(
                "PROTECTED_BY",
                "Interface",
                uid.interface(dev, name),
                "FwRulebase",
                rb_uid,
                key={"direction": direction},
                direction=direction,
            )


_IFNUM_RE = re.compile(r"^\s*[A-Za-z-]+\s*(?P<num>[0-9].*?)\s*$")


def _number_of(name: str) -> str | None:
    """Return the interface number of a name, lowercased (`Gi1/0/2` gives
    `1/0/2`), or None for a name without one.

    `IfNameResolver` matches abbreviations by the same key."""
    m = _IFNUM_RE.match(name)
    return m["num"].lower() if m else None


def _acl_rulebase(
    b: GraphBuilder,
    rb_uid: str,
    scope: str,
    dev: str,
    acl_name: str,
    aces: list[dict[str, Any]] | None,
    unreported: list[str],
    *,
    af: int | None = 4,
    unread_reason: str | None = None,
    unreported_uncertain: bool = False,
) -> None:
    """Write the FwRulebase of one access list, the ENFORCES edge from the device and the rules.

    The device filters with the access list that it reported. The ENFORCES
    edge records that installation for the analysis model
    (analysis_model/network.py `_bindings`). The installation has the
    revision of the reported entries and applies in every context and on both
    interfaces. The PROTECTED_BY edges hold the interface binding. The edge is
    installed when the entries were collected and read. Its coverage is
    complete only when, in addition, every binding names an interface that
    the device reported. A list that is partial only for unreported bindings
    is proven on a packet whose interfaces are elsewhere
    (`_unreported_elsewhere`). `unreported_uncertain` (an unreported spelling
    that can abbreviate a reported interface) or an unread list sets installed
    to False, and the installation stays unproven.

    `unread_reason` is set for a family whose entries are not read. The
    rulebase then holds only the opaque placeholder rule with that reason."""
    revision = hashlib.sha256(canonical_json({"acl": acl_name, "aces": aces}).encode()).hexdigest()
    read = aces is not None and unread_reason is None
    complete = read and not unreported
    rb = b.node(
        "FwRulebase",
        rb_uid,
        name=acl_name,
        kind="access",
        vendor="cisco",
        match_context="interface-acl",
        default_action="deny",
        # `show ip access-lists` is the v4 table. An IPv4 list judges only v4
        # flows, and an IPv6 list only v6 flows. A MAC list or a VLAN map filters
        # both and has no family.
        af=af,
        unreported_bindings=unreported or None,
        configured_revision=revision,
    )
    b.rel(
        "ENFORCES",
        "Device",
        dev,
        "FwRulebase",
        rb,
        installed=read and not unreported_uncertain,
        coverage="complete" if complete else "partial",
        installed_revision=revision,
        context_uid="*",
        ingress_interface_uid="*",
        egress_interface_uid="*",
        address_family=af,
    )
    if unread_reason is not None:
        _acl_placeholder_rule(b, rb, acl_name, collected=False, reason=unread_reason)
        return
    if not aces:
        _acl_placeholder_rule(b, rb, acl_name, collected=aces is not None)
        return
    for position, ace in enumerate(aces, start=1):
        _acl_rule(b, rb, scope, position, ace)


def _af_of(addr: str) -> int | None:
    """Return the address family (4 or 6) of a bare address, or None for an unparseable one."""
    try:
        return ipaddress.ip_address(addr).version
    except ValueError:
        return None


@debug_capture.traced
def side_rows(
    inter: dict[str, Any], device_uid: str, *, l2fabric: str = DEFAULT_L2_FABRIC
) -> dict[str, Sequence[dict[str, Any]]]:
    """Map `rib`, `mac_table` and `arp` of the intermediate shape to the
    side-store column contract and stamp every row with `device_uid`.

    `l2fabric` must be the value passed to `normalize_cisco` for the table of
    the device.

    `rib`, `mac` and `arp` are `streams.MappedRows` views over the
    intermediate lists. Each row is built when it is read. A row that cannot be
    built surfaces as `streams.RowMappingError` while the view is read. The
    context and bridge-domain uids repeat across rows and are built once per
    VRF and per VLAN.

    A family that also reads OSPF gets the `ospf_lsdb` table. A family that
    does not read OSPF gets the 3 tables and no `ospf_lsdb` key
    (`ospf_side_rows`)."""
    contexts: dict[str, str] = {}
    bridge_domains: dict[Any, str] = {}
    # Route and ARP output abbreviate interface names on some platforms
    # (NX-OS `Eth1/1`). The path stage matches the names against `Interface.name`.
    if_name = inter_ifnames(inter)

    def context_uid(vrf: str) -> str:
        # This must equal the uid of the VrfInstance node that normalize_cisco emits.
        name = vrf or DEFAULT_VRF
        found = contexts.get(name)
        if found is None:
            found = contexts[name] = uid.vrf(device_uid, name)
        return found

    def rib(r: dict[str, Any]) -> dict[str, Any]:
        # A route out of Null0 (a summary, the `via 0.0.0.0, Null0` of a BGP
        # aggregate, a blackhole static) is a discard route. The device drops the
        # traffic that it matches, and the row has no next hop.
        discard = "blackhole" if is_null_interface(r.get("interface")) else None
        next_hop_vrf = r.get("next_hop_vrf")
        return {
            "device_uid": device_uid,
            "vrf": r["vrf"],
            "context_uid": context_uid(r["vrf"]),
            "prefix": r["prefix"],
            "next_hop": None if discard else r.get("next_hop"),
            # The table that the next hop of a leaked route resolves in. IOS
            # names the global table `default`, and `global` is read as the
            # same table.
            "next_hop_context_uid": (
                context_uid(DEFAULT_VRF if next_hop_vrf == "global" else next_hop_vrf)
                if next_hop_vrf
                else None
            ),
            "interface": if_name(r.get("interface")),
            "protocol": r["protocol"],
            "discard": discard,
            "metric": r["metric"],
            **lpm_columns(r["prefix"]),
        }

    def mac(m: dict[str, Any]) -> dict[str, Any]:
        vlan = m["vlan"]
        bridge_domain = bridge_domains.get(vlan)
        if bridge_domain is None:
            bridge_domain = bridge_domains[vlan] = uid.bridge_domain(l2fabric, vlan)
        return {
            "device_uid": device_uid,
            "vlan": vlan,
            "mac": m["mac"],
            "port_name": if_name(m["port_name"]),
            "bridge_domain_uid": bridge_domain,
        }

    def arp(a: dict[str, Any]) -> dict[str, Any]:
        return {
            "device_uid": device_uid,
            "vrf": a["vrf"],
            # The context uid uses the same fallback and VrfInstance uid formula as `rib`.
            "context_uid": context_uid(a["vrf"]),
            "ip": a["ip"],
            "mac": a["mac"],
            "interface_name": if_name(a["interface_name"]),
            "af": _af_of(a["ip"]),
        }

    return {
        "rib": streams.MappedRows(inter.get("rib") or [], rib),
        "mac": streams.MappedRows(inter.get("mac_table") or [], mac),
        "arp": streams.MappedRows(inter.get("arp") or [], arp),
        **ospf_side_rows(inter, device_uid),
    }


# The LSA names in the `lsa_type` column of the `ospf_lsdb` table, in protocol
# order. The names are the OSPF names. A platform that prints the numeric type
# and a platform that prints a word get the same value (core/sidestore.py).
OSPF_LSA_TYPES: tuple[str, ...] = (
    "router",
    "network",
    "summary",
    "asbr-summary",
    "external",
    "nssa-external",
)


def ospf_side_rows(inter: dict[str, Any], device_uid: str) -> dict[str, list[dict]]:
    """Map `inter["ospf"]["lsdb"]` to the `ospf_lsdb` side-store column
    contract.

    Every row gets `device_uid` and the `context_uid` of the VrfInstance that
    the process runs in, by the formula of `rib`. The function returns no
    `ospf_lsdb` key when the intermediate shape has no `ospf` key.

    The parse decides the column values. The function maps names and fills the
    columns that an LSA type does not use with None. An `lsa_type` outside
    `OSPF_LSA_TYPES` is kept as the parse produced it.
    """
    if inter.get("ospf") is None:
        return {}
    rows = []
    for lsa in (inter.get("ospf") or {}).get("lsdb") or []:
        rows.append(
            {
                "device_uid": device_uid,
                # The context uid uses the same fallback and VrfInstance uid formula as `rib`.
                "context_uid": uid.vrf(device_uid, lsa.get("vrf") or DEFAULT_VRF),
                "process": lsa.get("process"),
                "area": lsa.get("area"),
                "lsa_type": lsa.get("lsa_type"),
                "lsid": lsa.get("lsid"),
                "adv_router": lsa.get("adv_router"),
                "seq": lsa.get("seq"),
                "age": lsa.get("age"),
                "metric": lsa.get("metric"),
                "links": lsa.get("links"),
                "attached_routers": lsa.get("attached_routers"),
                "mask": lsa.get("mask"),
                "forwarding_address": lsa.get("forwarding_address"),
                "metric_type": lsa.get("metric_type"),
            }
        )
    return {"ospf_lsdb": rows}


# --- OSPF: shared text parsing for the TextFSM families (IOS-XE, IOS-XR) --------------
#
# No live IOS-XE or IOS-XR capture confirms the classic Cisco OSPF display text
# below. One parser serves both families.
#
# On IOS-XE, the router and network LSA bodies go through the ntc-templates
# `cisco_ios_show_ip_ospf_database_router` and `_network` templates. `iosxe.py`
# groups their flat per-link and per-attached-router records into one row per
# LSA. ntc-templates has no template for the summary, asbr-summary, external or
# nssa-external LSA body of either family, or for the router or network body of
# IOS-XR. `ospf_lsa_detail_rows` parses all of those bodies.

# Maps the `Network Type` word that IOS-XE and IOS-XR print in `show ip ospf
# interface` and `show ospf interface` to the protocol names. `_OSPF_NETWORK_TYPES`
# of `nxos.py` maps the JSON form of the field to the same names. An unmapped value
# is kept lowercased.
OSPF_TEXT_NETWORK_TYPES: dict[str, str] = {
    "BROADCAST": "broadcast",
    "POINT_TO_POINT": "point-to-point",
    "NON_BROADCAST": "nbma",
    "POINT_TO_MULTIPOINT": "point-to-multipoint",
    "LOOPBACK": "loopback",
}


def ospf_area_id(value: str | None) -> str | None:
    """Return an OSPF area id in dotted form. Area 0 and 0.0.0.0 give the same id."""
    if value is None or value == "":
        return None
    text = value.strip()
    if text.isdigit():
        with contextlib.suppress(ValueError):
            return str(ipaddress.IPv4Address(int(text)))
    return text


_OSPF_PROC_RE = re.compile(r'^\s*Routing Process "ospf (?P<process>\S+)" with ID (?P<rid>\S+)')
# IOS prints the line under the header of a VRF process that runs without
# `capability vrf-lite`. With `capability vrf-lite` the line is absent
# (`stamp_ospf_vrfs`).
_OSPF_PROC_VRF_RE = re.compile(r"^\s*Connected to MPLS VPN Superbackbone, VRF (?P<vrf>\S+)")
_OSPF_AREA_BACKBONE_RE = re.compile(r"^\s*Area BACKBONE\((?P<aid>[\d.]+)\)")
_OSPF_AREA_RE = re.compile(r"^\s*Area (?P<aid>[\d.]+)\s*$")
_OSPF_STUB_AREA_RE = re.compile(r"^\s*It is a stub area")
_OSPF_NSSA_AREA_RE = re.compile(r"^\s*It is a NSSA area")


@debug_capture.traced
def parse_ospf_process_text(text: str) -> list[dict[str, Any]]:
    """Parse `show ip ospf` (IOS-XE) or `show ospf` (IOS-XR) into one entry per
    process.

    An entry is `{"process", "router_id", "areas": [{"area_id", "type"}],
    "redistribute"}`. Each process of the box prints its own "Routing Process
    ..." header, and a box with more than one process yields one entry per
    header. A process whose block names its VRF (`Connected to MPLS VPN
    Superbackbone, VRF <name>`) gets `vrf`. `stamp_ospf_vrfs` finds the VRF of
    the others."""
    processes: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    current_area: dict[str, Any] | None = None
    for line in text.splitlines():
        if m := _OSPF_PROC_RE.match(line):
            current = {"process": m["process"], "router_id": m["rid"], "areas": [], "redistribute": []}
            processes.append(current)
            current_area = None
            continue
        if current is None:
            continue
        if m := _OSPF_PROC_VRF_RE.match(line):
            current["vrf"] = m["vrf"]
            continue
        if m := _OSPF_AREA_BACKBONE_RE.match(line) or _OSPF_AREA_RE.match(line):
            current_area = {"area_id": ospf_area_id(m["aid"]), "type": "normal"}
            current["areas"].append(current_area)
            continue
        if current_area is not None:
            if _OSPF_STUB_AREA_RE.match(line):
                current_area["type"] = "stub"
            elif _OSPF_NSSA_AREA_RE.match(line):
                current_area["type"] = "nssa"
    return processes


_OSPF_IF_HDR_RE = re.compile(r"^(?P<name>\S+) is (?:up|administratively down|down)\b")
_OSPF_IF_AREA_RE = re.compile(r"Internet Address \S+, Area (?P<area>[\d.]+)")
_OSPF_IF_PROC_RE = re.compile(
    r"Process ID (?P<process>\S+), Router ID \S+, Network Type (?P<nt>\S+), Cost:\s*(?P<cost>\d+)"
)
_OSPF_IF_PASSIVE_RE = re.compile(r"No Hellos \(Passive interface\)")


@debug_capture.traced
def parse_ospf_interface_text(text: str) -> list[dict[str, Any]]:
    """Parse `show ip ospf interface` (IOS-XE) or `show ospf interface`
    (IOS-XR) into `[{"process", "name", "area", "cost", "network_type",
    "passive"}]`, one entry per interface header.

    A header with no `Internet Address ..., Area ...` line under it is not
    running OSPF and is dropped."""
    out: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    def flush() -> None:
        if current is not None and current["area"] is not None:
            out.append(current)

    for line in text.splitlines():
        if m := _OSPF_IF_HDR_RE.match(line):
            flush()
            current = {
                "process": None,
                "name": m["name"],
                "area": None,
                "cost": None,
                "network_type": None,
                "passive": False,
            }
            continue
        if current is None:
            continue
        if m := _OSPF_IF_AREA_RE.search(line):
            current["area"] = ospf_area_id(m["area"])
        elif m := _OSPF_IF_PROC_RE.search(line):
            current["process"] = m["process"]
            current["cost"] = int(m["cost"])
            current["network_type"] = OSPF_TEXT_NETWORK_TYPES.get(m["nt"], m["nt"].lower())
        elif _OSPF_IF_PASSIVE_RE.search(line):
            current["passive"] = True
    flush()
    return out


@debug_capture.traced
def ospf_adjacency_rows_from_neighbor_records(
    records: list[dict[str, Any]], *, process: str | None, area_by_if: dict[str, str]
) -> list[dict[str, Any]]:
    """Map the records of the ntc-templates `cisco_ios_show_ip_ospf_neighbor`
    and `cisco_xr_show_ospf_neighbor` templates to `[{"process", "area",
    "local_interface", "neighbor_router_id", "neighbor_ip", "state"}]`.

    Both templates use the same field names (`neighbor_id`, `state`,
    `ip_address`, `interface`). The neighbor table does not state the area.
    `area_by_if` maps each interface of the OSPF interface table to its area."""
    out = []
    for r in records:
        name = r.get("interface")
        rid = r.get("neighbor_id")
        if not name or not rid:
            continue
        out.append(
            {
                "process": process,
                "area": area_by_if.get(name),
                "local_interface": name,
                "neighbor_router_id": rid,
                "neighbor_ip": r.get("ip_address"),
                "state": r.get("state"),
            }
        )
    return out


_OSPF_DB_HDR_RE = re.compile(r"OSPF Router with ID \((?P<rid>\S+)\) \(Process ID (?P<pid>\S+)\)")
_OSPF_DB_AREA_HDR_RE = re.compile(r"Link States\s*\(Area (?P<area>[\d.]+)\)")
_OSPF_LS_AGE_RE = re.compile(r"^\s*LS age:\s*(?P<age>\d+)")
_OSPF_LS_ID_RE = re.compile(r"^\s*Link State ID:\s*(?P<lsid>\S+)")
_OSPF_LS_ADV_RE = re.compile(r"^\s*Advertising Router:\s*(?P<adv>\S+)")
_OSPF_LS_SEQ_RE = re.compile(r"^\s*LS Seq Number:\s*(?P<seq>\S+)")
_OSPF_LINK_CONNECTED_RE = re.compile(r"^\s*Link connected to:\s*(?P<desc>.+)$")
_OSPF_LINK_ID_RE = re.compile(
    r"^\s*\(Link ID\)\s*(?:Network/subnet number|Designated Router address|Neighboring Router ID):"
    r"\s*(?P<id>\S+)"
)
_OSPF_LINK_DATA_RE = re.compile(
    r"^\s*\(Link Data\)\s*(?:Network Mask|Router Interface address):\s*(?P<data>\S+)"
)
_OSPF_TOS0_METRIC_RE = re.compile(r"^\s*TOS 0 Metrics:\s*(?P<metric>\d+)")
_OSPF_ATTACHED_ROUTER_RE = re.compile(r"^\s*Attached Router:\s*(?P<rid>\S+)")
_OSPF_NETWORK_MASK_RE = re.compile(r"^\s*Network Mask:\s*/?(?P<mask>\S+)")
_OSPF_METRIC_TOS_LINE_RE = re.compile(r"^\s*TOS:\s*\d+\s+Metric:\s*(?P<metric>\d+)")
_OSPF_METRIC_TYPE_RE = re.compile(r"^\s*Metric Type:\s*(?P<mtype>\d)")
_OSPF_METRIC_LINE_RE = re.compile(r"^\s*Metric:\s*(?P<metric>\d+)\s*$")
_OSPF_FORWARDING_ADDR_RE = re.compile(r"^\s*Forward(?:ing)? Address:\s*(?P<addr>\S+)")

# Maps a link-connected-to description phrase to the link type of the schema
# (RFC 2328 A.4.2 numbering, the names of `_OSPF_LINK_TYPES` in `nxos.py`). The
# phrase "another Router" has no entry. `ospf_text_link_type` maps a phrase with
# "router" that matches neither entry to point-to-point.
_OSPF_LINK_TYPE_PHRASES: tuple[tuple[str, str], ...] = (
    ("transit network", "transit"),
    ("stub network", "stub"),
)


def ospf_text_link_type(desc: str) -> str:
    """Return the link type of the "Link connected to: <desc>" phrase of a router LSA."""
    lowered = desc.lower()
    for phrase, word in _OSPF_LINK_TYPE_PHRASES:
        if phrase in lowered:
            return word
    if "router" in lowered:
        return "point-to-point"
    return lowered


def _ospf_text_mask(raw: str | None) -> str | None:
    """Return a network mask as a dotted quad.

    The input is the "/24" prefix-length form that `show ... database
    summary|external|nssa-external detail` prints, with the leading slash
    stripped by `_OSPF_NETWORK_MASK_RE`, or the dotted form of an IOS release."""
    if raw is None:
        return None
    if raw.isdigit():
        length = int(raw)
        if not 0 <= length <= 32:
            return None
        bits = (0xFFFFFFFF << (32 - length)) & 0xFFFFFFFF if length else 0
        return ".".join(str((bits >> (8 * i)) & 0xFF) for i in (3, 2, 1, 0))
    return raw


@debug_capture.traced
def ospf_lsa_detail_rows(text: str, *, default_type: str) -> list[dict[str, Any]]:
    """Parse `show ip ospf database <type> detail` (IOS-XE) or `show ospf
    database <type> detail` (IOS-XR) into LSA rows in the `ospf_lsdb` column
    contract (the shape of `ospf_side_rows`).

    The parser reads every LSA type. IOS-XE uses it for the 4 types that have
    no ntc-templates template (summary, asbr-summary, external,
    nssa-external). IOS-XR has no database template and uses it for all 6
    types.

    `area` is `None` for an AS-external LSA. An NSSA-external LSA names its area
    ("NSSA-External Link States (Area <id>)").
    """
    rows: list[dict[str, Any]] = []
    area: str | None = None
    process: str | None = None
    current: dict[str, Any] | None = None
    current_link: dict[str, Any] | None = None

    def flush_link() -> None:
        nonlocal current_link
        if current_link is not None and current is not None and current["links"] is not None:
            current["links"].append(current_link)
        current_link = None

    def flush() -> None:
        nonlocal current
        flush_link()
        if current is not None:
            rows.append(current)
        current = None

    for line in text.splitlines():
        if m := _OSPF_DB_HDR_RE.search(line):
            process = m["pid"]
            continue
        if "Link States" in line:
            m = _OSPF_DB_AREA_HDR_RE.search(line)
            area = ospf_area_id(m["area"]) if m else None
            continue
        if m := _OSPF_LS_AGE_RE.match(line):
            flush()
            current = {
                "process": process,
                "area": area,
                "lsa_type": default_type,
                "lsid": None,
                "adv_router": None,
                "seq": None,
                "age": int(m["age"]),
                "metric": None,
                "links": [] if default_type == "router" else None,
                "attached_routers": [] if default_type == "network" else None,
                "mask": None,
                "forwarding_address": None,
                "metric_type": None,
            }
            continue
        if current is None:
            continue
        if m := _OSPF_LS_ID_RE.match(line):
            current["lsid"] = m["lsid"]
        elif m := _OSPF_LS_ADV_RE.match(line):
            current["adv_router"] = m["adv"]
        elif m := _OSPF_LS_SEQ_RE.match(line):
            try:
                current["seq"] = int(m["seq"], 16)
            except ValueError:
                current["seq"] = None
        elif m := _OSPF_LINK_CONNECTED_RE.match(line):
            flush_link()
            current_link = {
                "link_type": ospf_text_link_type(m["desc"]),
                "link_id": None,
                "link_data": None,
                "metric": None,
            }
        elif current_link is not None and (m := _OSPF_LINK_ID_RE.match(line)):
            current_link["link_id"] = m["id"]
        elif current_link is not None and (m := _OSPF_LINK_DATA_RE.match(line)):
            current_link["link_data"] = m["data"]
        elif current_link is not None and (m := _OSPF_TOS0_METRIC_RE.match(line)):
            current_link["metric"] = int(m["metric"])
        elif m := _OSPF_ATTACHED_ROUTER_RE.match(line):
            if current["attached_routers"] is not None:
                current["attached_routers"].append(m["rid"])
        elif m := _OSPF_NETWORK_MASK_RE.match(line):
            current["mask"] = _ospf_text_mask(m["mask"])
        elif m := _OSPF_METRIC_TOS_LINE_RE.match(line):
            current["metric"] = int(m["metric"])
        elif m := _OSPF_METRIC_TYPE_RE.match(line):
            current["metric_type"] = int(m["mtype"])
        elif m := _OSPF_METRIC_LINE_RE.match(line):
            current["metric"] = int(m["metric"])
        elif m := _OSPF_FORWARDING_ADDR_RE.match(line):
            current["forwarding_address"] = m["addr"]
    flush()
    return rows


_ROUTER_OSPF_RE = re.compile(r"^router ospf (\S+)\s*$")
_OSPF_ROUTER_ID_RE = re.compile(r"^router-id (\S+)\s*$")
_OSPF_DEFAULT_ORIGINATE_RE = re.compile(r"^default-information originate(?:\s+(?P<options>.*))?$")
_OSPF_REDIST_LINE_RE = re.compile(
    r"^redistribute\s+(?P<proto>" + "|".join(OSPF_REDIST_PROTOCOLS) + r")(?:\s+\S+)?"
    r"\s+route-(?:map|policy)\s+(?P<name>\S+)\s*$"
)


@debug_capture.traced
def parse_ospf_redistribute_config(text: str) -> dict[str, dict[str, Any]]:
    """Parse `show running-config | section ^router ospf` (IOS-XE) or `show
    running-config router ospf` (IOS-XR) into `{process: {"router_id",
    "redistribute": [{"protocol", "route_map"}]}}`.

    `_OSPF_REDIST_LINE_RE` reads the `redistribute <proto> [...]
    route-map|route-policy <name>` line of both families. The field is
    `route_map` for both keywords (docstring of `normalize_cisco`).
    `_ospf_process` resolves the name through `_defined_route_policies`
    against the policy table of the platform (`routing.route_maps` on IOS-XE,
    `xr_route_policies` on IOS-XR). A `redistribute` line without a route-map
    or route-policy is not recorded. A `default-information originate` line
    adds the fields of `ospf_default_originate`. The output holds no VRF."""
    out: dict[str, dict[str, Any]] = {}
    current: dict[str, Any] | None = None
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped == "!":
            continue
        if m := _ROUTER_OSPF_RE.match(stripped):
            current = out.setdefault(m.group(1), {"router_id": None, "redistribute": []})
            continue
        if current is None:
            continue
        if m := _OSPF_ROUTER_ID_RE.match(stripped):
            current["router_id"] = m.group(1)
        elif m := _OSPF_REDIST_LINE_RE.match(stripped):
            current["redistribute"].append({"protocol": m["proto"], "route_map": m["name"]})
        elif m := _OSPF_DEFAULT_ORIGINATE_RE.match(stripped):
            current.update(ospf_default_originate(m["options"]))
    return out


def ospf_default_originate(options: str | None) -> dict[str, bool]:
    """Return the process fields that a `default-information originate
    [always] [...]` line sets.

    `default_information_originate` is always set. With `always`, the default
    LSA does not depend on a default route in the main RIB, and
    `default_information_originate_always` is set."""
    out = {"default_information_originate": True}
    if "always" in (options or "").split():
        out["default_information_originate_always"] = True
    return out


# --- record mappers shared by the TextFSM families (IOS-XE, IOS-XR) --------------------

# The one-letter codes of the `show ip route` legend. `expand_protocol` maps a
# code by its first letter.
_PROTOCOL = {
    "l": "local",
    "c": "connected",
    "s": "static",
    "r": "rip",
    "m": "mobile",
    "b": "bgp",
    "d": "eigrp",
    "o": "ospf",
    "i": "isis",
}


def expand_protocol(code: str | None) -> str | None:
    if not code:
        return None
    return _PROTOCOL.get(code[0].lower(), code.lower())


def interface_kind(name: str, *, lag_prefix: str, svi: bool = False) -> str:
    """Return the kind of an interface from its name.

    `lag_prefix` and `svi` hold the platform differences. A dotted name is a
    subinterface whatever the kind of its parent."""
    if "." in name:
        return "subif"
    n = name.lower()
    if svi and n.startswith("vlan"):
        return "svi"
    if n.startswith("loopback"):
        return "loopback"
    if n.startswith(lag_prefix):
        return "lag"
    return "phys"


@debug_capture.traced
def if_vrf_map(
    vrf_rows: list[dict[str, Any]], *, vrf_key: str, device_ifnames: Iterable[str] = ()
) -> dict[str, str]:
    """Map each interface slug to its non-default VRF name from the per-VRF
    `interfaces` list of a `show vrf` variant.

    `show vrf` prints the members abbreviated (Gi1/0/2, Vl10, Fi1/0/1).
    `show interfaces` and `show ip arp` spell them in full. Each member is
    resolved against `device_ifnames`, the interface table of the device,
    before it is slugged. `vrf_of` looks a name up with the same resolution.
    An interface absent from every list is in the default VRF. The family
    docstrings define the use of "" and of the literal "default"."""
    resolve = IfNameResolver(device_ifnames)
    out: dict[str, str] = {}
    for row in vrf_rows:
        for ifname in row.get("interfaces") or []:
            out[resolve.slug(ifname)] = row[vrf_key]
    return out


def vrf_of(vrf_by_if: dict[str, str], resolve: IfNameResolver, ifname: str | None, default: str) -> str:
    """Return the VRF that `if_vrf_map` assigned to the interface a command names, or `default`."""
    return vrf_by_if.get(resolve.slug(ifname), default)


def stamp_ospf_vrfs(ospf: dict[str, Any] | None, vrf_by_if: dict[str, str], resolve: IfNameResolver) -> None:
    """Give each OSPF process of the intermediate `ospf` shape its VRF, and
    copy it onto the interface, adjacency and LSA rows of the process.

    A process keeps the VRF that its own block names. Otherwise it takes the
    VRF of the interfaces that it runs on, when they all are in one VRF. A VRF
    process with `capability vrf-lite` prints no VRF line. A process with no
    VRF is in the default VRF. The adjacency table has no process column. An
    adjacency takes the process of its local interface when the interface
    table names one."""
    if not ospf:
        return
    interfaces = ospf.get("interfaces") or []
    seen: dict[str, set[str]] = {}
    for ifc in interfaces:
        if ifc.get("process") and ifc.get("name"):
            seen.setdefault(ifc["process"], set()).add(vrf_of(vrf_by_if, resolve, ifc["name"], ""))
    vrfs: dict[str, str] = {}
    for proc in ospf.get("processes") or []:
        found = seen.get(proc.get("process") or "", set())
        vrf = proc.get("vrf") or (next(iter(found)) if len(found) == 1 else "")
        proc["vrf"] = vrf or None
        vrfs[proc.get("process") or ""] = vrf
    process_by_if = {
        resolve.slug(i["name"]): i["process"] for i in interfaces if i.get("name") and i.get("process")
    }
    for adj in ospf.get("adjacencies") or []:
        name = adj.get("local_interface")
        adj["process"] = (
            process_by_if.get(resolve.slug(name), adj.get("process")) if name else adj.get("process")
        )
    for row in (*interfaces, *(ospf.get("adjacencies") or []), *(ospf.get("lsdb") or [])):
        row["vrf"] = vrfs.get(row.get("process") or "") or None


def vrf_rt_fields(row: dict[str, Any] | None) -> dict[str, Any]:
    """`rd`/`rt_import`/`rt_export` from a parsed `show vrf ... detail` row.
    "not set" (XR) and "<not set>" (XE) normalize to None."""
    if row is None:
        return {"rd": None, "rt_import": [], "rt_export": []}
    rd = row.get("rd")
    return {
        "rd": rd if rd and rd not in ("not set", "<not set>") else None,
        "rt_import": sorted({r for r in row.get("rt_import") or [] if r}),
        "rt_export": sorted({r for r in row.get("rt_export") or [] if r}),
    }


@debug_capture.traced
def lldp_neighbor_rows(lldp_rows: list[dict[str, Any]], *, name_key: str) -> list[dict]:
    return [
        {
            "local_port": (r.get("local_interface") or "").strip(),
            "name": r.get(name_key) or None,
            "mac": canonical_mac(r.get("chassis_id")),
            "port": (r.get("neighbor_port_id") or "").strip(),
            "proto": "lldp",
        }
        for r in lldp_rows
    ]


# A Nexus far end sends its CDP device id as `<hostname>(<serial>)`, with the
# chassis serial in parentheses. The name can have a domain suffix. Every other
# platform sends the hostname without parentheses, with or without the domain.
_CDP_DEVICE_ID_RE = re.compile(r"^(?P<name>[^()]+?)\s*\((?P<serial>[^()]+)\)\s*$")


def cdp_device_id(value: Any) -> tuple[str | None, str | None]:
    """(name, serial) from a CDP device id. The serial is the `serial`
    property of the Device and a key of the device identity registry. A Nexus
    neighbor that this run also collected is matched by the serial. Every
    other far end gives the name alone."""
    if not isinstance(value, str) or not value.strip():
        return None, None
    m = _CDP_DEVICE_ID_RE.match(value.strip())
    if m is None:
        return value.strip(), None
    return m.group("name").strip(), m.group("serial").strip() or None


@debug_capture.traced
def cdp_neighbor_rows(
    cdp_rows: list[dict[str, Any]], *, name_keys: tuple[str, ...] = ("neighbor_name",)
) -> list[dict]:
    rows = []
    for r in cdp_rows:
        name, serial = cdp_device_id(next((r[k] for k in name_keys if r.get(k)), None))
        row = {
            "local_port": (r.get("local_interface") or "").strip(),
            "name": name,
            "mac": None,
            "port": (r.get("neighbor_interface") or "").strip(),
            "proto": "cdp",
        }
        if serial:
            row["serial"] = serial
        rows.append(row)
    return rows


@debug_capture.traced
def fhrp_rows(
    records: list[dict[str, Any]],
    *,
    kind: str,
    priority_key: str,
    vip_key: str,
    interface_key: str = "interface",
    group_key: str = "group",
    state_key: str = "state",
) -> list[dict]:
    """Map the TextFSM records of an IOS-family FHRP summary (`show standby
    brief`, `show vrrp brief`, `show hsrp`) to the `fhrp` rows of the
    intermediate shape.

    The call site passes the column names of the template. Interface names
    arrive abbreviated (`Vl10`, `Gi0/0/0/0`) and stay as printed.
    `resolve_fhrp` resolves them against the interface table of the device.
    The summary forms hold no virtual MAC."""
    rows = []
    for rec in records:
        name, vip = rec.get(interface_key), rec.get(vip_key)
        if not name or not vip:
            continue
        rows.append(
            {
                "interface": str(name).strip(),
                "kind": kind,
                "group": _int_or_none(rec.get(group_key)),
                "vip": str(vip),
                "priority": _int_or_none(rec.get(priority_key)),
                "state": rec.get(state_key) or None,
                "virtual_mac": None,
            }
        )
    return rows


def _int_or_none(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def rib_row(
    r: dict[str, Any], *, next_hop_key: str, interface_key: str, next_hop_vrf_key: str | None = None
) -> dict[str, Any] | None:
    """Map one TextFSM route record to one `rib` row of the intermediate shape.

    The call site passes the field names of the template. The family parsers
    pass the function to `cli_parse.parse(row=)`. Each record becomes its row
    as it is parsed, and the record list of a full table never exists.

    `next_hop_vrf` is the VRF that the next hop of a leaked route resolves in,
    as the device prints it (IOS `via 10.0.0.1 (default)`, IOS-XR `(nexthop in
    vrf default)`), or None for a next hop in the VRF of the route. The IOS-XR
    template reads the IOS-XR form into the interface column as `vrf <name>`.
    It reads the next hop of an interface route as the word `connected`. The
    function moves the VRF to `next_hop_vrf` and drops the word `connected`.

    A backup path (IOS-XR LFA or PIC, marked `(!)`, read into `backup`) does
    not forward until the primary path fails, and gives None. The caller drops
    it, and the path is not an equal-cost path of the route."""
    if r.get("backup"):
        return None
    next_hop = r.get(next_hop_key) or None
    if next_hop == "connected":
        next_hop = None
    next_hop_vrf = (r.get(next_hop_vrf_key) or None) if next_hop_vrf_key else None
    interface = r.get(interface_key) or None
    if interface and interface.startswith("vrf "):
        next_hop_vrf, interface = interface[len("vrf ") :], None
    return {
        "vrf": r.get("vrf") or "default",
        "prefix": f"{r['network']}/{r['prefix_length']}",
        "next_hop": next_hop,
        "next_hop_vrf": next_hop_vrf,
        "interface": interface,
        "protocol": expand_protocol(r.get("protocol")),
        "metric": int(r["metric"]) if r.get("metric") else None,
    }


@debug_capture.traced
def rib_rows(
    route_rows: list[dict[str, Any]],
    *,
    next_hop_key: str,
    interface_key: str,
    next_hop_vrf_key: str | None = None,
) -> list[dict]:
    rows = (
        rib_row(r, next_hop_key=next_hop_key, interface_key=interface_key, next_hop_vrf_key=next_hop_vrf_key)
        for r in route_rows
    )
    return [row for row in rows if row is not None]


def is_null_interface(name: Any) -> bool:
    """Whether a route's egress is the null interface (`Null0`, any case and
    spacing), the one a Cisco summary, aggregate or blackhole static drops
    traffic through."""
    return isinstance(name, str) and name.replace(" ", "").lower() == "null0"


def arp_row(r: dict[str, Any], vrf_by_if: dict[str, str], resolve: IfNameResolver) -> dict[str, Any]:
    """Map one TextFSM ARP record to one `arp` row of the intermediate shape.

    The VRF comes from the interface-to-VRF map (`if_vrf_map`) through
    `resolve`, the resolver of the interface table of the device. The parser
    builds the row at the parse site, as for `rib_row`."""
    return {
        "vrf": vrf_of(vrf_by_if, resolve, r.get("interface"), "default"),
        "ip": r["ip_address"],
        "mac": canonical_mac(r.get("mac_address")),
        "interface_name": r.get("interface"),
    }


@debug_capture.traced
def arp_rows(records: list[dict[str, Any]], vrf_by_if: dict[str, str], resolve: IfNameResolver) -> list[dict]:
    return [arp_row(r, vrf_by_if, resolve) for r in records]


# The MTU adapters read documented field coordinates and use no vendor-wide
# numeric defaults.
# The words that an IOS-XE or IOS-XR routing table prints even when it holds no
# route, such as its legend, its gateway line and a VRF heading. An answer to the
# RIB command that parsed to no rows and holds none of them is not an empty
# table (`cli_collector.Section.empty_answer`).
RIB_EMPTY_ANSWER: tuple[str, ...] = (
    "Codes:",
    "Gateway of last resort",
    "Routing Table:",
    "VRF:",
    "No matching routes",
    "Network not in table",
)
MTU_COMMANDS = {
    "iosxe": {
        "ipv4": "show ip interface",
        "ipv6": "show ipv6 interface",
        "system": "show system mtu",
        "members": "show etherchannel summary",
    },
    "iosxr": {
        "ipv4": "show ipv4 interface",
        "ipv6": "show ipv6 interface",
        "config": "show running-config interface",
        "members": "show bundle",
    },
    "nxos": {
        "media": "show interface",
        "ipv4": "show ip interface",
        "ipv6": "show ipv6 interface",
        "system": "show running-config all | i jumbomtu",
        "qos": "show policy-map system type network-qos",
        "queuing": "show queuing interface",
        "members": "show port-channel summary",
    },
}
# The MTU reads that every release of a family has. They are the running-config
# extracts. A refusal of one of them is a permission that the credential lacks
# (`cli_collector.classify_command_failure`).
MTU_ALWAYS_PRESENT: dict[str, frozenset[str]] = {
    family: frozenset(command for command in commands.values() if command.startswith("show running-config"))
    for family, commands in MTU_COMMANDS.items()
}
_MTU_HEADER = re.compile(r"^([A-Za-z][\w./:-]*)(?: is |, Interface status:)")
# A new entry requires documentary coordinate evidence and a versioned fixture.
_MTU_MEDIA_PROFILES = {
    ("iosxe", "C9300-24T", "17.3.4a"),
    ("iosxr", "R-IOSXRV9000-CC", "7.3.2"),
}


def _nxos_payload_mtu_profile(model: Any, release: Any) -> bool:
    """Return whether the model and release have the documented semantics of
    the interface payload MTU and the system and QoS MTU parameters.

    The N9K 10.5(x) QoS guide states that network-QoS MTU only sizes
    no-drop buffers. Interface MTU excludes Ethernet headers. System jumbo
    is a selectable preset. The verified platform is C93360YC-FX2.
    """
    return (
        isinstance(model, str)
        and isinstance(release, str)
        and re.fullmatch(
            r"(?:Nexus\s*9000\s+)?(?:N9K-)?C93360YC-FX2(?:\s+chassis)?",
            model.strip(),
            re.IGNORECASE,
        )
        is not None
        and re.fullmatch(r"10\.5\(\d+\)[A-Za-z]?", release.strip()) is not None
    )


def mtu_interface_fields(row: dict[str, Any]) -> dict[str, Any]:
    """Preserve installed TextFSM fields including the coordinate evidence."""
    return {
        "media_mtu": row.get("mtu"),
        "hardware_type": row.get("hardware_type"),
        "encapsulation": row.get("encapsulation"),
        "oper_status": row.get("link_status"),
        "vlan_id": row.get("vlan_id"),
        "vlan_id_inner": row.get("vlan_id_inner"),
        "vlan_id_outer": row.get("vlan_id_outer"),
    }


def _mtu_entry(
    command: str, field: str, value: Any, *, af: int | None = None, configured: bool = False, **extra: Any
) -> dict[str, Any]:
    return {
        "source_field": f"{command}:{field}",
        "raw_evidence_ref": command,
        "raw_value": value,
        "profile_id": "ip_packet" if af else "unknown",
        "metric": f"ipv{af}_mtu_bytes" if af else "l2_max_frame_bytes",
        "direction": "both",
        "bound_kind": "ceiling" if af else "unknown",
        "enforcement": "l3" if af else "l2",
        "enforcement_key": "protocol" if af else "media",
        "assertion_kind": "configured" if configured else "operational",
        **extra,
    }


@debug_capture.traced
def parse_mtu(raw: dict[str, Any], inter: dict[str, Any], *, family: str, config_command: str) -> None:
    """Join optional command evidence only to interfaces present in inventory.

    Media, protocol, config and policy observations stay separate. An answer
    in an unknown format gets the status partial or malformed in
    `mtu_sections`. Neither a media limit nor an interface being up proves an
    active aggregate member or an exact MRU.
    """
    from .cli_collector import effective_outcomes

    commands = MTU_COMMANDS[family]
    # A refusal recorded `ok` with its banner as the answer reads as the refusal.
    recorded = effective_outcomes(raw, {}, MTU_ALWAYS_PRESENT[family])
    interfaces = {iface_slug(i["name"]): i for i in inter.get("interfaces", [])}
    resolve = inter_ifnames(inter)
    observations: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    malformed: set[str] = set()
    unmatched: set[str] = set()
    device = inter.get("device") or {}
    nxos_payload_profile = family == "nxos" and _nxos_payload_mtu_profile(
        inter.get("mtu_model", device.get("model")), device.get("os_version")
    )
    inter["mtu_qos_buffer_only"] = nxos_payload_profile
    inter["mtu_system_jumbo_preset"] = nxos_payload_profile

    def usable(command: str) -> str:
        outcome = recorded.get(command)
        if outcome and outcome.status not in {"ok", "empty"}:
            return ""
        body = raw.get(command)
        return body if isinstance(body, str) else ""

    def add(name: str | None, entry: dict[str, Any]) -> None:
        command = entry["raw_evidence_ref"]
        counts[command] = counts.get(command, 0) + 1
        value = entry["raw_value"]
        # Zero is a well-formed answer and no limit: NX-OS states `MTU 0 bytes`
        # for a port-channel with no operational member. The observation keeps
        # it, and `observation_from_raw` gives it no normalized value.
        if not (type(value) is int and 0 <= value < 2**31) and not (
            isinstance(value, str) and value.isascii() and value.isdigit() and int(value) < 2**31
        ):
            malformed.add(command)
        # Buffer sizing and the selectable jumbo preset do not limit forwarding
        # on their own. Their raw values are counted and validated but give no
        # observation. The explicit per-port MTUs give the applied limit,
        # including the jumbo selection.
        if nxos_payload_profile and command in {commands.get("qos"), commands.get("system")}:
            return
        if name is not None:
            ifc = interfaces.get(resolve.slug(name))
            if ifc is None:
                unmatched.add(command)
                return
            entry["interface"] = ifc["name"]
            if (
                nxos_payload_profile
                and ifc.get("kind") in _PORT_KINDS
                and re.fullmatch(
                    r"(?:Eth(?:ernet)?\d+(?:/\d+)+|(?:Port-channel|Po)\d+|mgmt\d+)",
                    ifc["name"],
                    re.IGNORECASE,
                )
                and entry["source_field"]
                in {
                    "show interface | json:eth_mtu",
                    "show interface:MTU",
                    f"{config_command}:media mtu",
                }
            ):
                entry.update(
                    profile_id="ethernet_payload",
                    metric="l2_payload_mtu_bytes",
                    bound_kind="ceiling",
                )
        observations.append(entry)

    media_command = "show interfaces" if family != "nxos" else commands["media"]
    media_profile = (
        family,
        inter.get("mtu_model", device.get("model")),
        device.get("os_version"),
    ) in _MTU_MEDIA_PROFILES
    for ifc in interfaces.values():
        if family == "nxos" and usable("show interface | json"):
            for field, raw_value in ifc.get("mtu_raw_fields", {}).items():
                add(ifc["name"], _mtu_entry("show interface | json", field, raw_value))
        value = ifc.get("media_mtu")
        if value not in (None, "") and usable(media_command):
            entry = _mtu_entry(media_command, "MTU", value)
            # ARPA explicitly establishes an untagged Ethernet representation.
            # IOS-XR includes the MAC header. IOS excludes it. The tag allowance
            # on parent ports is a separate, unverified context.
            ethernet = "ethernet" in (ifc.get("hardware_type") or "").lower()
            if (
                media_profile
                and ethernet
                and "." not in ifc["name"]
                and (ifc.get("encapsulation") or "").strip().upper() == "ARPA"
            ):
                entry.update(
                    profile_id="ethernet_frame_excluding_fcs" if family == "iosxr" else "ethernet_payload",
                    bound_kind="ceiling",
                    tag_depth=0,
                    tag_accounting="included",
                    tag_allowance_bytes=0,
                )
            add(ifc["name"], entry)

    for role in ("media", "ipv4", "ipv6"):
        command = commands.get(role)
        if command is None:
            continue
        name = None
        for line in usable(command).splitlines():
            header = _MTU_HEADER.match(line)
            if header:
                name = header[1]
            if name is None:
                continue
            if role == "media":
                match = re.match(r"\s+MTU (\S+) bytes", line)
                if match:
                    add(name, _mtu_entry(command, "MTU", match[1]))
                continue
            af = 4 if role == "ipv4" else 6
            # On IOS-XR the first number is the media MTU. The value in
            # parentheses is the IP MTU.
            pattern = (
                r"\bMTU is \S+ \((\S+) is available to (?:IP|IPv6)\)"
                if family == "iosxr"
                else r"\b(?:IPv6 MTU:|IP MTU:|MTU is)\s+(\S+)"
            )
            match = re.search(pattern, line)
            if match:
                add(
                    name,
                    _mtu_entry(command, "available_to_ip" if family == "iosxr" else "MTU", match[1], af=af),
                )

    name = None
    memberships: list[dict[str, Any]] = []
    for line in usable(config_command).splitlines():
        match = re.match(r"^interface\s+(\S+)\s*$", line)
        if match:
            name = match[1]
            ifc = interfaces.get(resolve.slug(name))
            parent = interfaces.get(resolve.slug(name.rsplit(".", 1)[0])) if "." in name else None
            if ifc is not None and parent is not None:
                ifc["mtu_parent_name"] = parent["name"]
                ifc["mtu_parent_source"] = config_command
        elif line and not line[0].isspace():
            name = None
        if name is None:
            continue
        tag = re.fullmatch(r"\s+(?:encapsulation dot1[Qq]|dot1q vlan) (\d+)(?: second-dot1q (\d+))?\s*", line)
        if tag and resolve.slug(name) in interfaces:
            interfaces[resolve.slug(name)]["mtu_tag_depth"] = 2 if tag[2] else 1
        match = re.fullmatch(r"\s+(?:(ip|ipv4|ipv6) )?mtu (\S+)\s*", line)
        if match:
            protocol = match[1]
            af = 6 if protocol == "ipv6" else 4 if protocol else None
            add(
                name,
                _mtu_entry(config_command, f"{protocol or 'media'} mtu", match[2], af=af, configured=True),
            )
        member = re.fullmatch(r"\s+(?:channel-group|bundle id) (\d+)(?: mode (\S+))?\s*", line)
        if member:
            memberships.append(
                {
                    "member": resolve(name),
                    "aggregate": resolve(
                        f"{'Bundle-Ether' if family == 'iosxr' else 'Port-channel'}{member[1]}"
                    ),
                    "status": "configured",
                    "eligible": None,
                    "source": config_command,
                }
            )

    for role in ("system", "qos"):
        command = commands.get(role)
        if command is None:
            continue
        policy = None
        traffic_class = None
        for line in usable(command).splitlines():
            if role == "system":
                match = re.search(
                    r"(?:system jumbomtu|System (?:Jumbo )?MTU size is|System MTU:)\s+(\S+)",
                    line,
                    re.IGNORECASE,
                )
            else:
                policy_match = re.search(
                    r"(?:Service-policy(?: \([^)]*\))?:|policy-map type network-qos)\s*(\S+)",
                    line,
                    re.IGNORECASE,
                )
                class_match = re.search(
                    r"(?:Class-map(?: \([^)]*\))?:|class type network-qos)\s*(\S+)", line, re.IGNORECASE
                )
                if policy_match:
                    policy, traffic_class = policy_match[1], None
                if class_match:
                    traffic_class = class_match[1]
                match = re.search(r"\bmtu[ :]+(\S+)", line, re.IGNORECASE)
            if match:
                add(
                    None,
                    _mtu_entry(
                        command,
                        role,
                        match[1],
                        configured=True,
                        scope="system_policy",
                        policy_ref=policy or role,
                        traffic_class=traffic_class,
                        enforcement_key=role,
                        gaps=["MTU_POLICY_UNRESOLVED"],
                    ),
                )

    if family == "nxos":
        command = commands["queuing"]
        name, traffic_class, direction = None, None, "unknown"
        for line in usable(command).splitlines():
            header = re.match(r"\s*(\S+) queuing information:", line)
            if header:
                name, traffic_class, direction = header[1], None, "unknown"
            if "TX Queuing" in line:
                direction, traffic_class = "tx", None
            elif "RX Queuing" in line:
                direction, traffic_class = "rx", None
            class_match = re.match(r"\s*qos-group\s+(\d+)\s*$", line)
            if class_match:
                traffic_class = f"qos-group:{class_match[1]}"
            match = re.search(r"HW MTU:\s+(\S+)(?: \((\S+) configured\))?", line)
            if match and name:
                add(
                    name,
                    _mtu_entry(
                        command,
                        "HW MTU",
                        match[1],
                        direction=direction,
                        traffic_class=traffic_class,
                        enforcement_key="queue",
                    ),
                )
                if match[2]:
                    add(
                        name,
                        _mtu_entry(
                            command,
                            "configured MTU",
                            match[2],
                            configured=True,
                            direction=direction,
                            traffic_class=traffic_class,
                            enforcement_key="queue",
                        ),
                    )
            direct = re.search(r"HW MTU of (\S+)\s*:\s+(\S+) bytes", line)
            if direct:
                add(
                    direct[1],
                    _mtu_entry(command, "HW MTU", direct[2], direction="unknown", enforcement_key="queue"),
                )

    member_command = commands["members"]
    members_text = usable(member_command)
    aggregate = None
    aggregate_up: bool | None = None
    for line in members_text.splitlines():
        if family == "iosxr":
            match = re.match(r"\s*Bundle-Ether\s*(\d+)\s*$", line)
            if match:
                aggregate, aggregate_up = f"Bundle-Ether{match[1]}", None
            elif line.strip().startswith("Bundle-"):
                aggregate = None
            state = re.match(r"\s+Status:\s+(.+?)\s*$", line)
            if state:
                aggregate_up = state[1] == "Up"
            # Foreign mLACP members are not ports of the local device.
            member = re.match(r"\s*(\S+\d[\w./]*)\s+Local\s+(\S+)\b", line)
            found = [(member[1], member[2])] if member else []
        else:
            match = re.match(r"\s*\d+\s+(Po\d+)\((\w+)\)", line)
            if match:
                aggregate, aggregate_up = match[1], "U" in match[2]
                line = line[match.end() :]
            elif line.strip() and not line[0].isspace():
                aggregate = None
            found = re.findall(r"([A-Za-z][\w/.-]*\d[\w/.-]*)\(([A-Za-z]+)\)", line)
        if aggregate:
            for member_name, status in found:
                eligible = (
                    (status == "Active" and aggregate_up is True)
                    if family == "iosxr"
                    else (status == "P" and aggregate_up is True)
                )
                known = status in (
                    {"Active", "Standby", "Configured", "Detached", "Negotiating"}
                    if family == "iosxr"
                    else {"P", "D", "H", "I", "s", "r", "M", "w"}
                )
                memberships.append(
                    {
                        "member": resolve(member_name),
                        "aggregate": resolve(aggregate),
                        "status": status,
                        "eligible": eligible if known else None,
                        "source": member_command,
                    }
                )
                counts[member_command] = counts.get(member_command, 0) + 1
                if resolve.slug(member_name) not in interfaces or resolve.slug(aggregate) not in interfaces:
                    unmatched.add(member_command)

    inter["mtu_observations"] = observations
    inter["mtu_memberships"] = memberships
    inter["mtu_counts"] = counts
    inter["mtu_malformed_commands"] = malformed
    inter["mtu_unmatched_commands"] = unmatched


def mtu_sections(raw: dict[str, Any], inter: dict[str, Any], *, family: str) -> dict:
    """Return the MTU section outcome of each command role.

    SectionStatus has no not-captured value. A command that was not captured
    gets the status unknown with the detail MTU_NOT_CAPTURED."""
    from hst.core.model import SectionOutcome

    from .cli_collector import effective_outcomes

    recorded = effective_outcomes(raw, inter, MTU_ALWAYS_PRESENT[family])
    result = {}
    for role, command in MTU_COMMANDS[family].items():
        outcome = recorded.get(command)
        if outcome is not None and outcome.status != "ok":
            result[f"mtu_{role}"] = outcome
        elif command not in raw:
            result[f"mtu_{role}"] = SectionOutcome(status="unknown", detail="MTU_NOT_CAPTURED")
        elif outcome is None:
            result[f"mtu_{role}"] = SectionOutcome(status="unknown", detail="capture outcome not recorded")
        else:
            count = inter.get("mtu_counts", {}).get(command, 0)
            body = raw.get(command)
            if not isinstance(body, str) or command in inter.get("mtu_malformed_commands", set()):
                status = "malformed"
            elif not body.strip():
                status = "empty"
            elif command in inter.get("mtu_unmatched_commands", set()):
                status = "partial"
            elif count:
                status = "ok"
            else:
                # A nonempty interface table without protocol MTU can be valid
                # (protocol disabled), but it does not establish MTU coverage.
                status = "partial"
            detail = (
                "Network-QoS MTU sizes no-drop buffers; not a forwarding MTU limit. Raw capture retained."
                if role == "qos" and inter.get("mtu_qos_buffer_only") and status == "ok"
                else ""
            )
            if role == "system" and inter.get("mtu_system_jumbo_preset") and status == "ok":
                detail = (
                    "System jumbo is a selectable preset; applied MTU is recorded per port. "
                    "Raw capture retained."
                )
            result[f"mtu_{role}"] = SectionOutcome(status=status, row_count=count, detail=detail)
    return result


async def capture_mtu(
    session: Any, raw: dict[str, Any], *, family: str, check: Callable[[], None] | None = None
) -> None:
    """Run the opt-in read-only MTU commands.

    Each refusal is recorded as an outcome and leaves an empty answer.
    `check`, the stop check of the collector (`Collector.check_stop`), is
    called before each command, outside the refusal handling."""
    from . import ssh
    from .base import RAW_OUTCOMES_KEY
    from .cli_collector import classify_command_failure

    outcomes = raw.setdefault(RAW_OUTCOMES_KEY, {})
    for command in MTU_COMMANDS[family].values():
        if check is not None:
            check()
        try:
            raw[command] = await session.run(command)
            outcomes[command] = {"status": "ok"}
        except ssh.CommandFailed as exc:
            raw[command] = ""
            status, detail = classify_command_failure(
                exc, command=command, always_present=MTU_ALWAYS_PRESENT[family]
            )
            outcomes[command] = {"status": status, "detail": detail}


async def capture_match_lists(
    session: Any, raw: dict[str, Any], commands: Sequence[str], *, check: Callable[[], None] | None = None
) -> None:
    """Read the community-list and AS-path-list commands that a family derived
    from the policy text of this fetch.

    Each command is optional. A refusal is recorded under `RAW_OUTCOMES_KEY`
    with the text of the device and leaves an empty answer. `check` is the
    stop check of the collector and is called before each command."""
    from . import ssh
    from .base import RAW_OUTCOMES_KEY
    from .cli_collector import classify_command_failure

    outcomes = raw.setdefault(RAW_OUTCOMES_KEY, {})
    for command in commands:
        if check is not None:
            check()
        try:
            raw[command] = await session.run(command)
            outcomes[command] = {"status": "ok"}
        except ssh.CommandFailed as exc:
            raw[command] = ""
            status, detail = classify_command_failure(exc)
            outcomes[command] = {"status": status, "detail": detail}


def _mtu_stage(
    b: GraphBuilder,
    inter: dict[str, Any],
    *,
    dev: str,
    source: str,
    scope: str,
    ports: dict[str, str],
    interfaces: dict[str, str],
) -> None:
    interface_rows = {iface_slug(i["name"]): i for i in inter.get("interfaces", [])}
    # A subinterface's own explicit config MTU does not derive from the parent.
    own_config_names: set[str] = set()
    for record in inter.get("mtu_observations", []):
        rec_name = record.get("interface")
        if (
            not rec_name
            or record.get("assertion_kind") != "configured"
            or record.get("enforcement_key") == "queue"
        ):
            continue
        parent_source = interface_rows.get(iface_slug(rec_name), {}).get("mtu_parent_source")
        if parent_source is not None and record.get("raw_evidence_ref") == parent_source:
            own_config_names.add(iface_slug(rec_name))
    for record in inter.get("mtu_observations", []):
        entry = dict(record)
        name = entry.pop("interface", None)
        subject = interfaces.get(iface_slug(name)) if name else dev
        if subject is None:
            continue
        label = "Interface" if name else "Device"
        # Media evidence belongs to the physical/aggregate port when available.
        if name and entry["enforcement"] == "l2" and iface_slug(name) in ports:
            label, subject = "Port", ports[iface_slug(name)]
        # The MTU observations of a subinterface without its own config MTU
        # derive from the observations of its parent. `derived_from_subject_uid`
        # records the link on the observation.
        parent_name = (
            interface_rows.get(iface_slug(name), {}).get("mtu_parent_name")
            if name and iface_slug(name) not in own_config_names
            else None
        )
        parent_uid = interfaces.get(iface_slug(parent_name)) if parent_name else None
        selector: dict[str, Any] = {
            "version": 1,
            "platform": (inter.get("device") or {}).get("platform"),
            "os_version": (inter.get("device") or {}).get("os_version"),
            "model": inter.get("mtu_model", (inter.get("device") or {}).get("model")),
            "validation": "documented_synthetic_fixture_only"
            if entry["profile_id"] != "unknown"
            else "semantics_unverified",
            "interface_kind": interface_rows.get(iface_slug(name), {}).get("kind") if name else None,
            "encapsulation": interface_rows.get(iface_slug(name), {}).get("encapsulation") if name else None,
            "configured_tag_depth": interface_rows.get(iface_slug(name), {}).get("mtu_tag_depth")
            if name
            else None,
        }
        if parent_uid:
            selector["derived_from_subject_uid"] = parent_uid
        entry["selector_json"] = canonical_json(selector)
        emit_observation(
            b,
            label,
            observation_from_raw(
                subject_uid=subject,
                source=source,
                source_target=scope,
                collector_version=f"mtu-{MTU_NORMALIZATION_VERSION}",
                **entry,
            ),
        )

    # Operational membership supersedes configuration only for the same pair.
    members = {}
    for row in inter.get("mtu_memberships", []):
        key = iface_slug(row["member"]), iface_slug(row["aggregate"])
        members[key] = row
    for (member, aggregate), row in members.items():
        pu, iu = ports.get(member), interfaces.get(aggregate)
        if pu is None or iu is None:
            continue
        lu = uid.lag(dev, row["aggregate"])
        b.node("Lag", lu, name=row["aggregate"])
        b.rel("ON", "Lag", lu, "Device", dev)
        b.rel("REALIZED_BY", "Interface", iu, "Lag", lu)
        props = {
            "state": row["status"],
            "source_command": row["source"],
            "assertion_kind": "configured" if row["status"] == "configured" else "operational",
        }
        if row["eligible"] is not None:
            props["eligible"] = row["eligible"]
        b.rel("MEMBER_OF", "Port", pu, "Lag", lu, **props)
