"""The collector reads the Network application behind the UniFi OS proxy with a local admin account."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import ssl
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any, ClassVar

import httpx
from pydantic import Field, field_validator

from hst.core import uid
from hst.core.config import DEFAULT_L2_FABRIC
from hst.core.identity import DeviceResolver, MemoryResolver, chassis_serial, resolve_chassis
from hst.core.l3domain import DomainPolicy, Vrf
from hst.core.l3domain import resolve as l3d_resolve
from hst.core.model import Batch, SectionOutcome
from hst.core.mtu import MTU_NORMALIZATION_VERSION, canonical_json
from hst.core.mtu_profiles import emit_observation, observation_from_raw

from . import http
from .auth import TlsConfig, UserPassword
from .base import Collector, SourceConfig, register
from .mtu_import import preserve_raw_mtu_fields
from .util import GraphBuilder, VrfDomains, canonical_mac, connected_address

logger = logging.getLogger(__name__)

ROLE = {"usw": "switch", "uap": "ap", "ugw": "gateway", "udm": "gateway", "uxg": "gateway"}

# The maximum frame size of a UniFi device is 1518 bytes with jumbo frames off and
# 9216 bytes with jumbo frames on.
_UNIFI_JUMBO_FRAME_BYTES_INCLUDING_FCS = {False: 1518, True: 9216}

_POLICY_ACTION = {"ALLOW": "accept", "BLOCK": "drop", "REJECT": "reject"}

# ADDRv4 and ADDRv6 stand for the gateway's own address on the network.
_NETCONF_ADDRESS_TYPES = {"NETV4", "NETV6"}
_NETCONF_GATEWAY_TYPES = {"ADDRV4", "ADDRV6"}

_CLASSIC_STATE_FLAGS = (
    ("state_new", "new"),
    ("state_established", "established"),
    ("state_related", "related"),
    ("state_invalid", "invalid"),
)

# A classic ruleset name has 3 parts. The first part is the network family
# (LAN, WAN or GUEST). The second part is the optional IPv6 marker. The third
# part is the direction. IN and OUT apply on the forwarding path where the
# packet enters or leaves a network of the family. LOCAL applies to the
# traffic that the family sends to the gateway itself.
_CLASSIC_RULESET_RE = re.compile(r"(?i)^(LAN|WAN|GUEST)(v6)?_(IN|OUT|LOCAL)$")

# A LAN or GUEST ruleset binds the gateway interfaces of the networks with
# this purpose. The WAN interface is not collected. No networkconf of purpose
# wan holds the uplink address of the gateway. A WAN ruleset reports its
# binding by name in `unreported_bindings`.
_CLASSIC_FAMILY_PURPOSE = {"LAN": "corporate", "GUEST": "guest"}

# The default action of the gateway for a packet that no listed rule of a
# ruleset matches. WAN_IN and WAN_LOCAL default to drop. The controller places
# accepts for port forwards and for the services of the gateway ahead of that
# drop, and rest/firewallrule does not return them. The GUEST rulesets hold
# the predefined guest isolation rules, and rest/firewallrule does not return
# them. The defaults of these rulesets are recorded as unknown.
_CLASSIC_DEFAULTS = {
    ("LAN", "IN"): "accept",
    ("LAN", "OUT"): "accept",
    ("LAN", "LOCAL"): "accept",
    ("WAN", "OUT"): "accept",
}

# Any other field makes the rule undecided.
_CLASSIC_RULE_KEYS = frozenset(
    {
        "_id",
        "action",
        "dst_address",
        "dst_firewallgroup_ids",
        "dst_networkconf_id",
        "dst_networkconf_type",
        "dst_port",
        "enabled",
        "icmp_typename",
        "icmpv6_typename",
        "ipsec",
        "name",
        "protocol",
        "protocol_match_excepted",
        "rule_index",
        "ruleset",
        "src_address",
        "src_firewallgroup_ids",
        "src_mac_address",
        "src_networkconf_id",
        "src_networkconf_type",
        "src_port",
        *(flag for flag, _state in _CLASSIC_STATE_FLAGS),
    }
)

# A schedule is read by its `mode` alone.
_POLICY_KEYS = frozenset(
    {
        "_id",
        "action",
        "connection_state_type",
        "connection_states",
        "destination",
        "enabled",
        "icmp_typename",
        "icmp_v6_typename",
        "index",
        "ip_version",
        "match_ip_sec",
        "match_opposite_protocol",
        "name",
        "protocol",
        "schedule",
        "source",
    }
)
_POLICY_SIDE_KEYS = frozenset(
    {
        "ip_group_id",
        "ips",
        "match_opposite_ips",
        "match_opposite_networks",
        "match_opposite_ports",
        "matching_target",
        "matching_target_type",
        "network_id",
        "network_ids",
        "port",
        "port_group_id",
        "port_matching_type",
        "zone_id",
    }
)


def _unmodeled_fields(
    item: dict[str, Any],
    keys: frozenset[str],
    sides: tuple[str, ...] = (),
    side_keys: frozenset[str] = frozenset(),
) -> list[str]:
    """The names of the fields of a rule or policy outside its allow-list. A
    side field has its side as a prefix ("source ip_group_id")."""
    out = sorted(str(k) for k in item if k not in keys)
    for side in sides:
        value = item.get(side)
        if isinstance(value, dict):
            out += [f"{side} {k}" for k in sorted(map(str, value)) if k not in side_keys]
    return out


def normalize_unifi(
    raw: dict[str, Any],
    *,
    site_code: str,
    l3dom: str,
    unifi_site: str,
    include_clients: bool = True,
    l2fabric: str = DEFAULT_L2_FABRIC,
    resolver: DeviceResolver | None = None,
    partition: str = "",
) -> Batch:
    """`partition` namespaces the controller-local uids and the batch scope."""
    partition = partition or unifi_site
    b = GraphBuilder()
    # UniFi devices have no VRFs. Every address is in the global table. The
    # global table resolves to the bare scope.
    _dom = l3d_resolve(Vrf(device=f"unifi:{unifi_site}"), DomainPolicy(scope=l3dom))
    mac_to_dev = _device_stage(b, raw, unifi_site, resolver or MemoryResolver())
    port_by_mac_idx = _port_stage(b, raw, mac_to_dev)
    gw_duid, vrf_uid, gw_uids = _gateway_stage(b, raw, mac_to_dev, unifi_site, l3dom)
    ha_group = _gateway_group(b, partition, gw_uids)
    net_by_id = _network_stage(b, raw, partition, l2fabric, _dom, gw_duid, vrf_uid, routed=bool(gw_uids))
    _carriage_stage(b, raw, port_by_mac_idx, net_by_id)
    _zone_firewall(b, raw, partition, _dom, net_by_id)
    _classic_firewall(b, raw, partition, _dom, gw_duid, net_by_id, ha_group=ha_group)
    _wlan_stage(b, raw, partition, net_by_id)
    if include_clients:
        _client_stage(b, raw, partition, l2fabric, _dom, mac_to_dev, port_by_mac_idx, net_by_id)

    count = 0
    for record in raw.get("devices", []):
        mac = canonical_mac(record.get("mac"))
        subject = mac_to_dev.get(mac) if mac else None
        if not subject:
            continue
        count += preserve_raw_mtu_fields(
            b,
            "Device",
            subject,
            record,
            source="unifi",
            target=unifi_site,
            path="device",
            authority="configured",
        )
        for port in record.get("port_table") or []:
            port_uid = (
                port_by_mac_idx.get((mac, int(port["port_idx"])))
                if port.get("port_idx") is not None
                else None
            )
            if port_uid:
                count += preserve_raw_mtu_fields(
                    b,
                    "Port",
                    port_uid,
                    port,
                    source="unifi",
                    target=unifi_site,
                    path="port_table",
                    authority="configured",
                )
    frame_count = _l2_frame_stage(b, raw, unifi_site, port_by_mac_idx)
    count += frame_count
    batch = b.batch("unifi", f"unifi:{partition}")
    batch.sections["mtu"] = SectionOutcome(
        status="partial" if count else "unsupported",
        row_count=count,
        detail=(
            "per-port l2_max_frame_bytes ceiling from the device jumbo-frame flag "
            "(documented untagged/jumbo byte basis); remaining raw controller "
            "MTU/jumbo fields preserved without a numeric byte basis or host "
            "receive evidence"
            if frame_count
            else "raw controller MTU/jumbo fields only; no validated numeric "
            "byte basis or host receive evidence"
        ),
    )
    return batch


def _device_stage(
    b: GraphBuilder, raw: dict[str, Any], unifi_site: str, resolver: DeviceResolver
) -> dict[str, str]:
    """Writes the UniFi devices (switches, APs, gateways) and returns a map of
    canonical MAC to Device uid. The registry resolves the serial. For a device
    that reports no serial or a placeholder, the registry resolves the chassis
    MAC (`resolve_chassis`)."""
    mac_to_dev: dict[str, str] = {}
    for d in raw.get("devices", []):
        mac = canonical_mac(d.get("mac"))
        if mac is None:
            continue
        serial = chassis_serial(d.get("serial")) or mac
        name = (d.get("name") or "").strip()
        duid = resolve_chassis(resolver, serial, ("serial", mac), name or None)
        mac_to_dev[mac] = duid
        b.node(
            "Device",
            duid,
            hostname=name.lower() or None,
            # The reasoner's stated-cable rules resolve a UniFi neighbor by this MAC
            # (FETCH_MAC_OWNERS).
            mac=mac,
            platform=f"unifi-{d.get('type', 'unknown')}",
            # Device.role is required (core/labels.py).
            role=ROLE.get(d.get("type", ""), d.get("type")) or "unknown",
            vendor="ubiquiti",
            model=d.get("model"),
            serial=serial,
            mgmt_ip=d.get("ip"),
            os_version=d.get("version"),
            identities=sorted({x for x in (name, d.get("mac")) if x}),
            # The site id of the controller. An operator binds it to a Site.
            reported_location=unifi_site,
            reported_location_name=unifi_site,
        )
    return mac_to_dev


def _unifi_speed_mbps(up: Any, raw_speed: Any) -> int | None:
    """Speeds are in Mbit/s."""
    if not up:
        return None
    return raw_speed if isinstance(raw_speed, int | float) and raw_speed else None


def _unifi_duplex(up: Any, speed_mbps: int | None, full_duplex: Any) -> str | None:
    if not up or speed_mbps is None:
        return None
    if full_duplex is True:
        return "full"
    if full_duplex is False:
        return "half"
    return None


def _port_stage(
    b: GraphBuilder, raw: dict[str, Any], mac_to_dev: dict[str, str]
) -> dict[tuple[str, int], str]:
    """Writes the ports, the LLDP hints of each port and the uplink cabling
    between UniFi devices. Returns a map of (device MAC, port index) to Port uid."""
    # An AP without a port table gets one synthetic uplink port as the endpoint of its cabling.
    port_by_mac_idx: dict[tuple[str, int], str] = {}
    # `seen` holds the neighbor MACs that each port reports. `lldp` holds the LLDP entries of
    # each port. The uplink records are checked against both.
    seen: dict[str, set[str]] = {}
    lldp: dict[str, list[tuple[str, Any]]] = {}
    for d in raw.get("devices", []):
        mac = canonical_mac(d.get("mac"))
        if mac is None:
            continue
        duid = mac_to_dev[mac]
        table = d.get("port_table") or []
        synthetic_ap_port = not table and d.get("type") == "uap"
        if synthetic_ap_port:
            table = [{"port_idx": 0, "name": "eth0"}]
        for p in table:
            idx = p.get("port_idx")
            if idx is None:
                continue
            puid = f"{duid}/port/port{idx}"
            port_by_mac_idx[(mac, int(idx))] = puid
            if synthetic_ap_port:
                # The synthetic port is up while the AP is adopted and connected (`state` 1).
                port_up = bool(d.get("adopted")) and d.get("state") == 1
                uplink = d.get("uplink") or {}
                speed_mbps = _unifi_speed_mbps(port_up, uplink.get("speed"))
                duplex = _unifi_duplex(port_up, speed_mbps, uplink.get("full_duplex"))
                speed_source = "unifi:uplink.speed" if speed_mbps is not None else None
            else:
                port_up = p.get("up")
                speed_mbps = _unifi_speed_mbps(port_up, p.get("speed"))
                duplex = _unifi_duplex(port_up, speed_mbps, p.get("full_duplex"))
                speed_source = (
                    "unifi:port_table.speed" if speed_mbps is not None or duplex is not None else None
                )
            b.node(
                "Port",
                puid,
                name=p.get("name") or f"Port {idx}",
                speed_mbps=speed_mbps,
                duplex=duplex,
                speed_source=speed_source,
                poe=p.get("port_poe"),
                oper="up" if port_up else "down",
            )
            b.rel("ON", "Port", puid, "Device", duid)
            lc = p.get("last_connection") or {}
            lc_mac = canonical_mac(lc.get("mac"))
            if lc_mac and lc.get("connected"):
                b.node("Port", puid, last_conn_mac=lc_mac)
                seen.setdefault(puid, set()).add(lc_mac)

    for d in raw.get("devices", []):
        mac = canonical_mac(d.get("mac"))
        if mac is None:
            continue
        entries = list(d.get("lldp_table") or [])
        for p in d.get("port_table") or []:
            entries += [{**e, "local_port_idx": p.get("port_idx")} for e in (p.get("lldp_table") or [])]
        for e in entries:
            idx, nmac = e.get("local_port_idx"), canonical_mac(e.get("chassis_id"))
            if idx is None or nmac is None:
                continue
            puid = port_by_mac_idx.get((mac, int(idx)))
            if puid:
                b.node("Port", puid, lldp_neighbor_mac=nmac, lldp_neighbor_port=e.get("port_id"))
                seen.setdefault(puid, set()).add(nmac)
                lldp.setdefault(puid, []).append((nmac, e.get("port_id")))

    # A record that the port facts contradict is not used.
    for d in raw.get("devices", []):
        mac = canonical_mac(d.get("mac"))
        up = d.get("uplink") or {}
        rmac = canonical_mac(up.get("uplink_mac"))
        if mac is None or rmac is None:
            continue
        idx = int(up.get("port_idx", 0) or 0)
        local = port_by_mac_idx.get((mac, idx))
        if local is None:
            idx, local = 0, port_by_mac_idx.get((mac, 0))
        remote_idx = up.get("uplink_remote_port")
        remote = port_by_mac_idx.get((rmac, int(remote_idx))) if remote_idx is not None else None
        if local:
            reason = _uplink_contradiction(local, remote, mac, rmac, idx, seen, lldp)
            if reason:
                logger.warning(
                    "unifi: the controller's uplink record of %s (port %s to %s port %s) "
                    "contradicts the switch neighbor data: %s; the record is not used",
                    d.get("name") or mac,
                    idx,
                    up.get("uplink_device_name") or rmac,
                    remote_idx,
                    reason,
                    extra={"event": "unifi.uplink_contradicted"},
                )
                continue
            b.node("Port", local, uplink_mac=rmac, uplink_remote_port=remote_idx)
        if local and remote:
            a, z = sorted((local, remote))
            b.rel("CONNECTED_TO", "Port", a, "Port", z, key={"source": "unifi"})
    return port_by_mac_idx


# A UniFi LLDP port id with a port index, such as "Port 20".
_PORT_INDEX_RE = re.compile(r"(?i)^(?:local\s+)?port\s*(\d+)$")


def _uplink_contradiction(
    local: str,
    remote: str | None,
    mac: str,
    rmac: str,
    idx: int,
    seen: dict[str, set[str]],
    lldp: dict[str, list[tuple[str, Any]]],
) -> str | None:
    """The reason that the port facts contradict the uplink record of one
    device, or None.

    `seen` holds the neighbor MACs that each port reports (connected
    last_connection and LLDP chassis). `lldp` holds the LLDP entries of each
    port. A port with no facts contradicts no record. The local port
    contradicts the record when it reports neighbors without `rmac`. The far
    UniFi port contradicts the record when it reports neighbors without this
    device, or when its LLDP entry for this device has another port index."""
    own = seen.get(local, set())
    if own and rmac not in own:
        return f"port {idx} sees {', '.join(sorted(own))}"
    if remote is None:
        return None
    far = seen.get(remote, set())
    if far and mac not in far:
        return f"the far port sees {', '.join(sorted(far))}"
    for nmac, port_id in lldp.get(remote, []):
        m = _PORT_INDEX_RE.match(str(port_id or "").strip())
        if nmac == mac and m and int(m.group(1)) != idx:
            return f"the far port names {port_id} of this device over LLDP"
    return None


def _l2_frame_stage(
    b: GraphBuilder,
    raw: dict[str, Any],
    unifi_site: str,
    port_by_mac_idx: dict[tuple[str, int], str],
) -> int:
    """`port_table.jumbo` is kept raw only (`preserve_raw_mtu_fields`)."""
    count = 0
    for record in raw.get("devices", []):
        mac = canonical_mac(record.get("mac"))
        if mac is None:
            continue
        jumbo = record.get("jumboframe_enabled")
        if type(jumbo) is not bool:
            continue
        frame = _UNIFI_JUMBO_FRAME_BYTES_INCLUDING_FCS[jumbo]
        # The 1518 ceiling has room for one 802.1Q tag, and the 9216 ceiling has none.
        allowance = not jumbo
        for port in record.get("port_table") or []:
            idx = port.get("port_idx")
            if idx is None:
                continue
            port_uid = port_by_mac_idx.get((mac, int(idx)))
            if not port_uid:
                continue
            fields: dict[str, Any] = {
                "subject_uid": port_uid,
                "source": "unifi",
                "source_target": unifi_site,
                "source_field": "device.jumboframe_enabled",
                "raw_value": frame,
                "profile_id": "ethernet_frame_including_fcs",
                "metric": "l2_max_frame_bytes",
                "direction": "both",
                "bound_kind": "ceiling",
                "enforcement": "l2",
                "enforcement_key": "netdevice",
                "assertion_kind": "configured",
                "resolution_state": "explicit",
                "collector_version": MTU_NORMALIZATION_VERSION,
                "raw_evidence_ref": "stat/device:jumboframe_enabled",
                "selector_json": canonical_json(
                    {
                        "version": 1,
                        "source_profile": "unifi_jumboframe_enabled_v1",
                        "profile_validation": "documentation_only",
                        "jumboframe_enabled": jumbo,
                        "port_table_jumbo_is_authoritative": False,
                    }
                ),
            }
            if allowance:
                fields["tag_accounting"] = "extra_allowance"
                fields["tag_allowance_bytes"] = 4
            emit_observation(b, "Port", observation_from_raw(**fields))
            count += 1
    return count


def _gateway_stage(
    b: GraphBuilder, raw: dict[str, Any], mac_to_dev: dict[str, str], unifi_site: str, l3dom: str
) -> tuple[str | None, str | None, list[str]]:
    """Returns (gateway Device uid, its default VrfInstance uid, every
    gateway-role Device uid). The first 2 are None unless the payload has
    exactly one gateway."""
    gw_uids = sorted(
        {
            mac_to_dev[m]
            for d in raw.get("devices", [])
            if (m := canonical_mac(d.get("mac"))) in mac_to_dev
            and (ROLE.get(d.get("type", ""), d.get("type")) or "unknown") == "gateway"
        }
    )
    gw_duid = gw_uids[0] if len(gw_uids) == 1 else None
    vrf_uid: str | None = None
    if gw_duid:
        vrfs = VrfDomains(
            b,
            f"unifi:{unifi_site}",
            DomainPolicy(scope=l3dom),
            lambda name: uid.vrf(gw_duid, name),
            owner_device_uid=gw_duid,
        )
        vrf_uid = vrfs.add("default", is_global=True)
    return gw_duid, vrf_uid, gw_uids


def _gateway_group(b: GraphBuilder, partition: str, gw_uids: list[str]) -> str | None:
    """The classic rulebases are bound to the group (path/gates/firewall.py)."""
    if len(gw_uids) < 2:
        return None
    group = b.node(
        "RedundancyGroup",
        uid.rgrp("unifi-ha", partition, "gateway"),
        kind="unifi-ha",
        name="gateway HA",
    )
    for gw in gw_uids:
        b.rel("MEMBER_OF", "Device", gw, "RedundancyGroup", group)
    return group


def gateway_count(raw: dict[str, Any]) -> int:
    """The count of distinct MACs of gateway-role devices in the payload."""
    return len(
        {
            mac
            for d in raw.get("devices") or []
            if (mac := canonical_mac(d.get("mac")))
            and (ROLE.get(d.get("type", ""), d.get("type")) or "unknown") == "gateway"
        }
    )


def policy_gaps(raw: dict[str, Any]) -> list[str]:
    gaps: list[str] = []
    count = gateway_count(raw)
    if count != 1 and (raw.get("firewall_rules") or raw.get("firewall_policies")):
        gaps.append(f"{count} gateway devices; zone membership is not bound to an interface")
    zone_ids = {z.get("_id") for z in raw.get("firewall_zones") or [] if isinstance(z, dict)}
    lost = sum(
        1
        for p in raw.get("firewall_policies") or []
        if isinstance(p, dict)
        and (
            (p.get("source") or {}).get("zone_id") not in zone_ids
            or (p.get("destination") or {}).get("zone_id") not in zone_ids
        )
    )
    if lost:
        gaps.append(f"{lost} zone policies name zones that were not collected")
    rules = [r for r in raw.get("firewall_rules") or [] if isinstance(r, dict)]
    if rules and READ_PATHS["firewall_groups"] in (raw.get("refused_reads") or ()):
        gaps.append("the firewall group read was refused (400 or 404) while classic rules were read")
    # A classic rule that refers to a group outside the payload is opaque on that side.
    group_ids = {g.get("_id") for g in raw.get("firewall_groups") or [] if isinstance(g, dict)}
    unresolved = sum(
        1
        for r in rules
        if any(
            gid not in group_ids
            for gid in (r.get("src_firewallgroup_ids") or []) + (r.get("dst_firewallgroup_ids") or [])
        )
    )
    if unresolved:
        gaps.append(f"{unresolved} classic firewall rules name firewall groups that were not collected")
    return gaps


def _network_stage(
    b: GraphBuilder,
    raw: dict[str, Any],
    unifi_site: str,
    l2fabric: str,
    dom: str,
    gw_duid: str | None,
    vrf_uid: str | None,
    *,
    routed: bool = False,
) -> dict[str, dict[str, Any]]:
    """Writes the VLAN instance, the L2 segment, the prefix and the gateway
    address of each VLAN network.

    `routed` is true when the console has a gateway. The gateway routes every
    network with a subnet.

    Returns a map of network _id to {vuid, seg, prefix, net, iface, purpose,
    if_name, ip_anchor} for the later stages."""
    net_by_id: dict[str, dict[str, Any]] = {}
    for n in raw.get("networks", []):
        if n.get("purpose") not in ("corporate", "guest", "vlan-only") or n.get("enabled") is False:
            continue
        vid = int(n.get("vlan") or 1)
        vuid = uid.vlan(f"unifi:{unifi_site}", vid)
        seg = uid.bridge_domain(l2fabric, vid)
        guest = n.get("purpose") == "guest"
        b.node("VlanInstance", vuid, vid=vid, name=n.get("name"))
        b.node("BridgeDomain", seg, name=n.get("name"), security_class="guest" if guest else None)
        b.rel("REALIZES", "VlanInstance", vuid, "BridgeDomain", seg)
        # `_classic_firewall` uses `purpose` and `if_name` to place the gateway
        # interface of the network in a classic ruleset family.
        info: dict[str, Any] = {
            "vuid": vuid,
            "seg": seg,
            "prefix": None,
            "net": None,
            "iface": None,
            "purpose": n.get("purpose"),
            "if_name": n.get("name") or f"br{vid}",
            "ip_anchor": None,
        }
        if n.get("ip_subnet"):
            iface_uid: str | None = None
            if gw_duid:
                iface_uid = uid.interface(gw_duid, f"br{vid}")
                b.node("Interface", iface_uid, name=info["if_name"], kind="svi")
                b.rel("ON", "Interface", iface_uid, "Device", gw_duid)
                b.rel("IN_VRF", "Interface", iface_uid, "VrfInstance", vrf_uid)
                info["iface"] = iface_uid
            # Without one gateway, routed addressing anchors on the domain string `dom`.
            gw_ip, pfx = connected_address(
                b,
                n["ip_subnet"],
                anchor=vrf_uid or dom,
                dom=dom,
                vrf_uid=vrf_uid,
                prefix_props={"name": n.get("name"), "security_class": "guest" if guest else None},
            )
            if iface_uid:
                b.rel("HAS_IP", "Interface", iface_uid, "IpAddress", gw_ip)
            # The address of the gateway on the network. `_netconf_object` uses
            # it for an ADDRv4/ADDRv6 rule side.
            info["gw_ip"] = gw_ip
            info["gw_af"] = ipaddress.ip_interface(n["ip_subnet"]).version
            if pfx:
                info["prefix"], info["net"] = pfx, ipaddress.ip_interface(n["ip_subnet"]).network
            # The gateway of the console owns this subnet. Its clients and the
            # gateway address take the anchor of the subnet prefix. The bridge
            # domain of the clients is in the shared default fabric. 2 consoles
            # that reuse a VLAN and a subnet behind their own NAT share this
            # bridge domain. Another router routes a console with no gateway.
            # The clients of such a console join the prefix of that router
            # through the bridge domain.
            if routed:
                info["ip_anchor"] = vrf_uid or dom
        net_by_id[n.get("_id")] = info
    return net_by_id


def _carriage_stage(
    b: GraphBuilder,
    raw: dict[str, Any],
    port_by_mac_idx: dict[tuple[str, int], str],
    net_by_id: dict[str, dict[str, Any]],
) -> None:
    # The carriage layers are the port_overrides entry, the assigned port profile,
    # then the port_table entry.
    profiles = {p.get("_id"): p for p in raw.get("port_profiles") or []}
    for d in raw.get("devices", []):
        mac = canonical_mac(d.get("mac"))
        if mac is None:
            continue
        overrides = {
            int(o["port_idx"]): o
            for o in d.get("port_overrides") or []
            if isinstance(o, dict) and o.get("port_idx") is not None
        }
        for p in d.get("port_table") or []:
            idx = p.get("port_idx")
            puid = port_by_mac_idx.get((mac, int(idx))) if idx is not None else None
            if not puid:
                continue
            override = overrides.get(int(idx)) or {}
            profile_id = override.get("portconf_id") or p.get("portconf_id")
            if _states_carriage(override):
                src = override
            elif profile_id:
                src = profiles.get(profile_id) or {}
            else:
                src = p
            carried: dict[str, bool] = {}  # The key is a VLAN uid. The value is the native flag.
            fwd = src.get("forward")
            if fwd == "disabled":
                # The port forwards no network. This includes its native network.
                continue
            native_id = src.get("native_networkconf_id")
            if native_id in net_by_id:
                carried[net_by_id[native_id]["vuid"]] = True
            # `tagged_vlan_mgmt` (Network 8.x) holds the tagged networks where it is present.
            mgmt = src.get("tagged_vlan_mgmt")
            mode = {"block_all": "native", "auto": "all", "custom": "customize"}.get(mgmt, fwd)
            if mode == "all":
                tagged_ids: list[str] = [i for i in net_by_id if i != native_id]
            elif mode == "customize":
                explicit = src.get("tagged_networkconf_ids")
                if explicit is not None:
                    tagged_ids = [i for i in explicit if i in net_by_id and i != native_id]
                else:
                    # Without an explicit list, customize carries every network that is not excluded.
                    excluded = set(src.get("excluded_networkconf_ids") or [])
                    tagged_ids = [i for i in net_by_id if i not in excluded and i != native_id]
            else:
                tagged_ids = []  # The mode is "native" or block_all, or the entry has no carriage data.
            for nid in tagged_ids:
                carried.setdefault(net_by_id[nid]["vuid"], False)
            for vuid, native in sorted(carried.items()):
                b.rel("CARRIES", "Port", puid, "VlanInstance", vuid, native=native)


def _states_carriage(entry: dict[str, Any]) -> bool:
    """Whether a port entry states which networks the port carries."""
    return any(entry.get(key) is not None for key in ("forward", "tagged_vlan_mgmt", "native_networkconf_id"))


def _wlan_stage(
    b: GraphBuilder, raw: dict[str, Any], partition: str, net_by_id: dict[str, dict[str, Any]]
) -> None:
    """An SSID is keyed by the source partition and the controller's WLAN id."""
    for w in raw.get("wlans", []):
        suid = f"ssid:unifi:{partition}:{uid.exact_slug(str(w.get('_id') or w.get('name') or ''))}"
        b.node("Ssid", suid, name=w.get("name"), security=w.get("security"), enabled=w.get("enabled", True))
        info = net_by_id.get(w.get("networkconf_id"))
        if info:
            b.rel("BRIDGED_TO", "Ssid", suid, "VlanInstance", info["vuid"])


def _epoch_ms(value: Any) -> int | None:
    """Converts an epoch-seconds time of the controller to epoch milliseconds.
    The graph holds every time in epoch milliseconds. Returns None for a value
    that is not a positive number."""
    if isinstance(value, bool) or not isinstance(value, int | float) or value <= 0:
        return None
    return int(value * 1000)


def _client_stage(
    b: GraphBuilder,
    raw: dict[str, Any],
    partition: str,
    l2fabric: str,
    dom: str,
    mac_to_dev: dict[str, str],
    port_by_mac_idx: dict[tuple[str, int], str],
    net_by_id: dict[str, dict[str, Any]],
) -> None:
    """Writes the client endpoints with their segment membership, addressing
    and attachment point."""
    # A row with a malformed ip or sw_port is skipped whole, with a warning.
    skipped = 0
    for c in raw.get("clients", []):
        mac = canonical_mac(c.get("mac"))
        if mac is None:
            continue
        client_id = c.get("_id") or c.get("mac")
        ip = c.get("ip")
        ip_af: int | None = None
        if ip:
            try:
                ip_af = ipaddress.ip_address(ip).version
            except ValueError:
                logger.warning("unifi: skipping client %s: malformed ip %r", client_id, ip)
                skipped += 1
                continue
        sw_port: int | None = None
        if c.get("is_wired") and c.get("sw_port"):
            try:
                sw_port = int(c["sw_port"])
            except (TypeError, ValueError):
                logger.warning("unifi: skipping client %s: malformed sw_port %r", client_id, c["sw_port"])
                skipped += 1
                continue
        # The uid is keyed by the source partition. The site code is the same
        # for every controller row that sets none.
        euid = f"ep:unifi:{partition}:{uid.norm_mac(mac)}"
        b.node(
            "Endpoint",
            euid,
            mac=mac,
            kind="client",
            name=c.get("name") or c.get("hostname"),
            wired=bool(c.get("is_wired")),
            # `oui` is the vendor of the MAC OUI as the controller reports it.
            # `last_seen` is the time the controller last saw the client
            # (stat/sta `last_seen`, epoch seconds).
            oui=c.get("oui") or None,
            last_seen=_epoch_ms(c.get("last_seen")),
        )
        info = net_by_id.get(c.get("network_id"))
        seg = info["seg"] if info else None
        if seg is None:
            # A vlan-only network leaves network_id null.
            try:
                vid = int(c.get("vlan") or 0)
            except (TypeError, ValueError):
                vid = 0
            if 0 < vid < 4095:
                seg = b.node("BridgeDomain", uid.bridge_domain(l2fabric, vid))
        if seg:
            b.rel("IN", "Endpoint", euid, "BridgeDomain", seg)
        if ip:
            # The address anchors on the anchor of the prefix when the gateway
            # of the console routes the network of the client. Otherwise it
            # anchors on the L2 segment of the client, or on the domain string
            # `dom` when no segment is resolved.
            ip_anchor = (info or {}).get("ip_anchor") or seg or dom
            ipu = b.node("IpAddress", uid.ip(ip_anchor, ip), ip=ip, af=ip_af, l3dom=dom, anchor=ip_anchor)
            b.rel("HAS_IP", "Endpoint", euid, "IpAddress", ipu)
            home = _containing(net_by_id.values(), ip, prefer=info)
            if home:
                b.rel("IN", "IpAddress", ipu, "Prefix", home["prefix"])
        if c.get("is_wired"):
            swmac = canonical_mac(c.get("sw_mac"))
            puid = port_by_mac_idx.get((swmac, sw_port)) if swmac and sw_port else None
            if puid:
                b.rel("ATTACHED", "Endpoint", euid, "Port", puid)
        else:
            apuid = mac_to_dev.get(canonical_mac(c.get("ap_mac")) or "")
            if apuid:
                b.rel("ATTACHED", "Endpoint", euid, "Device", apuid, ssid=c.get("essid"))
    if skipped:
        logger.warning(
            "unifi: skipped %d of %d client rows as malformed", skipped, len(raw.get("clients", []))
        )


def _firewall_revision(raw: dict[str, Any]) -> str:
    """The revision of the firewall configuration that the controller
    returned. It is a digest of the rules, groups, zone policies and zones.
    The controller programs the gateway from this configuration. The rulebases
    record the digest as their configured revision and as their installed
    revision."""
    payload = {
        key: raw.get(key)
        for key in ("firewall_rules", "firewall_groups", "firewall_policies", "firewall_zones")
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def _installed(revision: str) -> dict[str, Any]:
    """`established_default_unknown` means that the gateway's predefined
    established/related rules sit behind the listed rules."""
    return {
        "installed": True,
        "coverage": "complete",
        "installed_revision": revision,
        "configured_revision": revision,
        "established_default_unknown": True,
    }


def _zone_firewall(b: GraphBuilder, raw: dict[str, Any], unifi_site: str, dom: str, net_by_id: dict) -> None:
    """Each (source zone, destination zone) pair has one FwRulebase."""
    # Zones and zone-pair rulebases are keyed by the controller's zone id.
    zones = {z["_id"]: z for z in raw.get("firewall_zones") or [] if z.get("_id")}
    zone_uid: dict[str, str] = {}
    installed = _installed(_firewall_revision(raw))
    for zid, z in zones.items():
        # A flow that no zone policy matches is undecided.
        zu = b.node(
            "Zone",
            f"unifi:{unifi_site}:zone:{uid.exact_slug(str(zid))}",
            name=z.get("name"),
            default_action_unknown=True,
            **installed,
        )
        zone_uid[zid] = zu
        for nid in z.get("network_ids") or []:
            info = net_by_id.get(nid) or {}
            if info.get("iface"):
                b.rel("CONTAINS", "Zone", zu, "Interface", info["iface"])

    def side_ips(side: dict, net_by_id: dict) -> tuple[bool, list[str], str | None]:
        """Returns (any, cidrs/addrs, opaque_reason)."""
        target = str(side.get("matching_target") or "ANY").upper()
        if target == "ANY":
            return True, [], None
        if target == "IP":
            # An IP group (matching_target_type OBJECT, `ip_group_id`) is not
            # collected. Inline ips beside an IP group can be a part of its
            # members.
            kind = side.get("matching_target_type")
            if side.get("ip_group_id") or str(kind or "SPECIFIC").upper() != "SPECIFIC":
                return (
                    False,
                    [],
                    f"matching_target 'IP' references an IP group (matching_target_type {kind!r}, "
                    f"ip_group_id {side.get('ip_group_id')!r}), which is not collected",
                )
            ips = [str(a) for a in side.get("ips") or []]
            if not ips:
                return (
                    False,
                    [],
                    f"matching_target 'IP' lists no inline ips (matching_target_type {kind!r})",
                )
            return False, ips, None
        if target == "NETWORK":
            nids = side.get("network_ids")
            if nids is None:
                nid = side.get("network_id")
                nids = [nid] if nid is not None else []
            if not nids:
                return False, [], "matching_target 'NETWORK' names no network_id/network_ids"
            cidrs: list[str] = []
            for nid in nids:
                info = net_by_id.get(nid)
                if info is None:
                    return (
                        False,
                        [],
                        f"network {nid!r} referenced by the rule is not among the collected networks",
                    )
                net = info.get("net")
                if net is None:
                    return (
                        False,
                        [],
                        f"network {nid!r} referenced by the rule is collected but has no prefix (unrouted)",
                    )
                cidrs.append(str(net))
            return False, cidrs, None
        return False, [], f"matching_target {target!r} is not modeled as an address set"

    def side_negate(side: dict) -> bool:
        """True when a side matches everything except its listed targets. The
        flag is `match_opposite_ips` for the target IP and
        `match_opposite_networks` for the target NETWORK."""
        target = str(side.get("matching_target") or "ANY").upper()
        if target == "IP":
            return bool(side.get("match_opposite_ips"))
        if target == "NETWORK":
            return bool(side.get("match_opposite_networks"))
        return False

    # A policy scoped to one address family goes into the rulebase of that
    # family alone. A zone pair that holds such a policy gets a second rulebase
    # for IPv6, like `ipv6-name` beside `name` in vyos.py. The gate takes the
    # rulebase of the family of the flow, or the rulebase with no family when
    # the pair has none for that family. The first rulebase serves IPv4 flows.
    split_pairs = {
        ((p.get("source") or {}).get("zone_id"), (p.get("destination") or {}).get("zone_id"))
        for p in raw.get("firewall_policies") or []
        if str(p.get("ip_version") or "BOTH").upper() in ("IPV4", "IPV6")
    }
    pair_rb: dict[tuple[str, str, int | None], str] = {}
    policies = [p for p in raw.get("firewall_policies") or [] if p.get("enabled", True)]
    for p in sorted(policies, key=lambda p: int(p.get("index") or 0)):
        src, dst = p.get("source") or {}, p.get("destination") or {}
        sz, dz = src.get("zone_id"), dst.get("zone_id")
        if sz not in zone_uid or dz not in zone_uid:
            continue
        # Both rulebases of a split pair exist even when every policy of the
        # pair has one family. This keeps an IPv6 flow out of the rulebase
        # with no family.
        families: tuple[int | None, ...] = (None, 6) if (sz, dz) in split_pairs else (None,)
        for af in families:
            if (sz, dz, af) not in pair_rb:
                sname = zones[sz].get("name") or sz
                dname = zones[dz].get("name") or dz
                rb = b.node(
                    "FwRulebase",
                    f"unifi:{unifi_site}:fw:zone:{uid.exact_slug(str(sz))}:{uid.exact_slug(str(dz))}"
                    + (":ipv6" if af else ""),
                    name=f"{sname}-{dname}" + (" (IPv6)" if af else ""),
                    kind="zone",
                    vendor="ubiquiti",
                    match_context="zone-pair",
                    af=af,
                    # The policies of a zone pair have no default action.
                    default_action_unknown=True,
                    **installed,
                )
                b.rel("FROM_ZONE", "FwRulebase", rb, "Zone", zone_uid[sz])
                b.rel("TO_ZONE", "FwRulebase", rb, "Zone", zone_uid[dz])
                pair_rb[(sz, dz, af)] = rb
        ip_version = str(p.get("ip_version") or "BOTH").upper()
        if len(families) > 1:
            families = {"IPV4": (None,), "IPV6": (6,)}.get(ip_version, families)
        for af in families:
            rb = pair_rb[(sz, dz, af)]
            _zone_policy_rule(
                b,
                unifi_site,
                dom,
                rb,
                p,
                (*side_ips(src, net_by_id), side_negate(src)),
                (*side_ips(dst, net_by_id), side_negate(dst)),
            )


def _zone_policy_rule(
    b: GraphBuilder,
    unifi_site: str,
    dom: str,
    rb: str,
    p: dict[str, Any],
    src_side: tuple[bool, list[str], str | None, bool],
    dst_side: tuple[bool, list[str], str | None, bool],
) -> None:
    """A schedule, an ICMP type or an IPsec match goes to `states_opaque`."""
    src, dst = p.get("source") or {}, p.get("destination") or {}
    src_any, src_ips, src_opaque, src_negate = src_side
    dst_any, dst_ips, dst_opaque, dst_negate = dst_side
    unmodeled: list[str] = []
    cst = str(p.get("connection_state_type") or "ALL").upper()
    states: list[str] = []
    if cst == "RESPOND_ONLY":
        states = ["established", "related"]
    elif cst == "CUSTOM":
        states = sorted({str(s).lower() for s in p.get("connection_states") or []})
        if not states:
            unmodeled.append("a custom connection state list that names no state")
    elif cst != "ALL":
        unmodeled.append(f"connection_state_type {cst!r}")
    if str((p.get("schedule") or {}).get("mode") or "ALWAYS").upper() != "ALWAYS":
        unmodeled.append("a schedule")
    for key in ("icmp_typename", "icmp_v6_typename"):
        if str(p.get(key) or "ANY").upper() != "ANY":
            unmodeled.append(f"ICMP type {p[key]!r}")
    if p.get("match_ip_sec"):
        unmodeled.append("IPsec")
    fields = _unmodeled_fields(p, _POLICY_KEYS, ("source", "destination"), _POLICY_SIDE_KEYS)
    unmodeled += [f"the field {name!r}" for name in fields]
    proto = str(p.get("protocol") or "all").lower()
    svc_reasons: list[str] = []
    port, src_port = None, None
    for side, label in ((dst, "destination"), (src, "source")):
        if side.get("match_opposite_ports"):
            svc_reasons.append(f"the policy matches every {label} port except the ones it lists")
        matching = str(side.get("port_matching_type") or "SPECIFIC").upper()
        # A side with a port group id and no matching type is a port group.
        if matching == "OBJECT" or (matching != "ANY" and side.get("port_group_id")):
            svc_reasons.append(f"the {label} port is a port group, which is not collected")
        elif matching != "ANY" and side.get("port"):
            if side is dst:
                port = str(dst["port"])
            else:
                src_port = str(src["port"])
    excepted = bool(p.get("match_opposite_protocol"))
    ru = b.node(
        "FwRule",
        f"{rb}:{p['_id']}",
        position=int(p.get("index") or 0),
        action=_POLICY_ACTION.get(
            str(p.get("action") or "").upper(),
            str(p.get("action") or "").lower() or None,
        ),
        name=p.get("name"),
        enabled=True,
        rule_uid=p["_id"],
        src_any=src_any,
        dst_any=dst_any,
        src_negate=src_negate,
        dst_negate=dst_negate,
        svc_any=proto == "all" and not excepted and not port and not src_port and not svc_reasons,
        # The list is explicitly empty when the policy has no state. The empty
        # list overwrites the states of an earlier write.
        states=states,
        states_opaque=bool(unmodeled),
        states_opaque_reason=(
            "the policy also matches on " + ", ".join(unmodeled) + ", which is not modeled"
            if unmodeled
            else None
        ),
        # The list is explicitly empty when every field is modeled. The empty
        # list overwrites the list of an earlier write.
        unmodeled_fields=fields,
    )
    b.rel("HAS_RULE", "FwRulebase", rb, "FwRule", ru)
    for rel, any_, addrs, opaque_reason in (
        ("SRC", src_any, src_ips, src_opaque),
        ("DST", dst_any, dst_ips, dst_opaque),
    ):
        if not any_ and not addrs and opaque_reason is None:
            opaque_reason = "the side is not Any and lists no address"
        if opaque_reason is not None:
            # The uid of the opaque NetObject holds the rule and the side.
            ou = b.node(
                "NetObject",
                f"{ru}:{rel.lower()}:opaque",
                name=f"{rel.lower()} side (opaque)",
                kind="opaque",
                opaque=True,
                opaque_reason=opaque_reason,
            )
            b.rel(rel, "FwRule", ru, "NetObject", ou)
            continue
        for a in addrs:
            b.rel(rel, "FwRule", ru, "NetObject", _addr_object(b, unifi_site, a, dom))
    if svc_reasons:
        # The opaque SvcObject is the only service of the rule.
        su = b.node(
            "SvcObject",
            f"{ru}:svc:opaque",
            name="service (opaque)",
            opaque=True,
            opaque_reason="; ".join(svc_reasons),
        )
        b.rel("SVC", "FwRule", ru, "SvcObject", su)
    elif proto != "all" or excepted or port or src_port:
        su = _svc_object(b, unifi_site, proto, excepted=excepted, ports=port, src_port=src_port)
        b.rel("SVC", "FwRule", ru, "SvcObject", su)


def _svc_object(
    b: GraphBuilder,
    unifi_site: str,
    proto: str,
    *,
    excepted: bool = False,
    ports: str | None = None,
    src_port: str | None = None,
) -> str:
    """The uid includes the protocol, the destination ports and the source ports."""
    sp = f"!{proto}" if excepted else (None if proto == "all" else proto)
    key = f"{'not-' if excepted else ''}{proto}-{ports or 'any'}" + (f"-src{src_port}" if src_port else "")
    name = f"{'!' if excepted else ''}{proto}/{ports or 'any'}" + (f" src {src_port}" if src_port else "")
    return b.node(
        "SvcObject",
        f"unifi:{unifi_site}:svc:{key}",
        name=name,
        proto=sp,
        ports=ports or None,
        src_port=src_port or None,
    )


def _classic_scope(
    ruleset: str, net_by_id: dict[str, dict[str, Any]], *, predefined: bool = False
) -> dict[str, Any]:
    """`default_action` is None where it is not known (`_CLASSIC_DEFAULTS`)."""
    m = _CLASSIC_RULESET_RE.match(ruleset)
    if m is None:
        return {
            "match_context": "device",
            "chain": None,
            "default_action": None,
            "approximate": True,
            "bound": [],
            "unreported": [],
        }
    family, way = m.group(1).upper(), m.group(3).upper()
    default = None if predefined else _CLASSIC_DEFAULTS.get((family, way))
    if way == "LOCAL":
        return {
            "match_context": "device",
            "chain": "input",
            "default_action": default,
            "approximate": True,
            "bound": [],
            "unreported": [],
        }
    direction = way.lower()
    bound: list[tuple[str, str]] = []
    unreported: list[str] = []
    if family == "WAN":
        unreported.append(f"wan {direction}")
    else:
        for info in net_by_id.values():
            if info.get("purpose") != _CLASSIC_FAMILY_PURPOSE[family] or info.get("net") is None:
                continue
            if info.get("iface"):
                bound.append((info["iface"], direction))
            else:
                unreported.append(f"{info['if_name']} {direction}")
    return {
        "match_context": "interface-acl",
        "chain": "forward",
        "default_action": default,
        "approximate": False,
        "bound": bound,
        "unreported": sorted(unreported),
    }


def _classic_firewall(
    b: GraphBuilder,
    raw: dict[str, Any],
    unifi_site: str,
    dom: str,
    gw_duid: str | None,
    net_by_id: dict[str, dict[str, Any]],
    *,
    ha_group: str | None = None,
) -> None:
    """An empty state list means every state."""
    # Groups are keyed by the controller's group id.
    groups = {g["_id"]: g for g in raw.get("firewall_groups") or [] if g.get("_id")}
    emitted: dict[str, str] = {}

    def net_group(gid: str) -> str | None:
        g = groups.get(gid)
        if not g or g.get("group_type") not in ("address-group", "ipv6-address-group"):
            return None
        if gid not in emitted:
            gu = b.node(
                "NetObject",
                f"unifi:{unifi_site}:grp:{uid.exact_slug(str(gid))}",
                name=g.get("name"),
                kind="group",
            )
            for m in g.get("group_members") or []:
                m = str(m)
                if "/" in m:
                    pu = b.node(
                        "Prefix", uid.prefix(dom, m), cidr=m, af=6 if ":" in m else 4, l3dom=dom, anchor=dom
                    )
                    b.rel("RESOLVES_TO", "NetObject", gu, "Prefix", pu)
                else:
                    ipu = b.node(
                        "IpAddress", uid.ip(dom, m), ip=m, af=6 if ":" in m else 4, l3dom=dom, anchor=dom
                    )
                    b.rel("RESOLVES_TO", "NetObject", gu, "IpAddress", ipu)
            emitted[gid] = gu
        return emitted[gid]

    def unresolved_group(gid: str, rule_id: str, side: str) -> str | None:
        """Returns None for an address group or a port group in the payload.
        Returns an opaque NetObject for every other group id."""
        kind = (groups.get(gid) or {}).get("group_type")
        if kind in ("address-group", "ipv6-address-group", "port-group"):
            return None
        reason = (
            f"firewall group {gid!r} referenced by the rule is not among the collected groups"
            if kind is None
            else f"firewall group {gid!r} has the type {kind!r}, which is not modeled"
        )
        return b.node(
            "NetObject",
            f"unifi:{unifi_site}:grp:{uid.exact_slug(str(gid))}:rule:{uid.slug(rule_id)}:{side}",
            name=f"group:{gid}",
            kind="group",
            opaque=True,
            opaque_reason=reason,
        )

    def port_group(gid: str) -> str | None:
        g = groups.get(gid)
        if not g or g.get("group_type") != "port-group":
            return None
        return b.node(
            "SvcObject",
            f"unifi:{unifi_site}:svc:grp:{uid.exact_slug(str(gid))}",
            name=g.get("name"),
            kind="group",
            ports=[str(m) for m in g.get("group_members") or []],
        )

    def port_members(gids: list[str]) -> list[str]:
        """The ports of every port group among `gids`."""
        return [
            str(m)
            for gid in gids
            if (groups.get(gid) or {}).get("group_type") == "port-group"
            for m in groups[gid].get("group_members") or []
        ]

    by_ruleset: dict[str, list[dict]] = {}
    for r in raw.get("firewall_rules") or []:
        by_ruleset.setdefault(str(r.get("ruleset") or "UNKNOWN"), []).append(r)

    installed = _installed(_firewall_revision(raw))
    # For an isolated network and for a network without internet access, the
    # controller places predefined drops ahead of the listed rules. The rule
    # read does not return these drops. No ruleset default is known while such
    # a network is configured.
    predefined = any(
        n.get("network_isolation_enabled") is True or n.get("internet_access_enabled") is False
        for n in raw.get("networks") or []
        if isinstance(n, dict) and n.get("enabled") is not False
    )
    owner = ("Device", gw_duid) if gw_duid else ("RedundancyGroup", ha_group) if ha_group else None
    for ruleset, rules in sorted(by_ruleset.items()):
        scope = _classic_scope(ruleset, net_by_id, predefined=predefined)
        # The name of a v6 ruleset holds `v6`, such as WANv6_IN and LANv6_IN.
        af = 6 if "v6" in ruleset.lower() else 4
        acl = scope["match_context"] == "interface-acl"
        rb = b.node(
            "FwRulebase",
            f"unifi:{unifi_site}:fw:{uid.slug(ruleset)}",
            name=ruleset,
            kind="access",
            vendor="ubiquiti",
            match_context=scope["match_context"],
            chain=scope["chain"],
            af=af,
            default_action=scope["default_action"],
            default_action_unknown=scope["default_action"] is None,
            unreported_bindings=scope["unreported"] or None,
            configured_revision=installed["configured_revision"],
            established_default_unknown=True,
        )
        if owner:
            # The coverage of an IN or OUT ruleset is complete only when every binding
            # is an interface that the graph holds.
            b.rel(
                "ENFORCES",
                owner[0],
                owner[1],
                "FwRulebase",
                rb,
                approximate=scope["approximate"],
                installed=True,
                coverage="partial" if acl and scope["unreported"] else "complete",
                installed_revision=installed["installed_revision"],
                context_uid="*",
                address_family=af,
                **({"ingress_interface_uid": "*", "egress_interface_uid": "*"} if acl else {}),
            )
        for iface, direction in scope["bound"]:
            # The edge is keyed by direction, like the edge of cisco_common.acl_stage.
            b.rel(
                "PROTECTED_BY",
                "Interface",
                iface,
                "FwRulebase",
                rb,
                key={"direction": direction},
                direction=direction,
            )
        for r in sorted(rules, key=lambda r: int(r.get("rule_index") or 0)):
            src_objs = [gu for gid in r.get("src_firewallgroup_ids") or [] if (gu := net_group(gid))]
            dst_objs = [gu for gid in r.get("dst_firewallgroup_ids") or [] if (gu := net_group(gid))]
            svc_objs = [su for gid in r.get("dst_firewallgroup_ids") or [] if (su := port_group(gid))]
            src_objs += [
                ou
                for gid in r.get("src_firewallgroup_ids") or []
                if (ou := unresolved_group(gid, str(r["_id"]), "src"))
            ]
            dst_objs += [
                ou
                for gid in r.get("dst_firewallgroup_ids") or []
                if (ou := unresolved_group(gid, str(r["_id"]), "dst"))
            ]
            if r.get("src_address"):
                src_objs.append(_addr_object(b, unifi_site, str(r["src_address"]), dom))
            if r.get("dst_address"):
                dst_objs.append(_addr_object(b, unifi_site, str(r["dst_address"]), dom))
            if r.get("src_networkconf_id"):
                src_objs.append(
                    _netconf_object(
                        b,
                        unifi_site,
                        net_by_id,
                        str(r["src_networkconf_id"]),
                        r.get("src_networkconf_type"),
                        str(r["_id"]),
                        "src",
                        combo=bool(src_objs),
                    )
                )
            if r.get("dst_networkconf_id"):
                dst_objs.append(
                    _netconf_object(
                        b,
                        unifi_site,
                        net_by_id,
                        str(r["dst_networkconf_id"]),
                        r.get("dst_networkconf_type"),
                        str(r["_id"]),
                        "dst",
                        combo=bool(dst_objs),
                    )
                )
            proto = str(r.get("protocol") or "all").lower()
            port = r.get("dst_port")
            excepted = bool(r.get("protocol_match_excepted"))
            src_ports = ([str(r["src_port"])] if r.get("src_port") else []) + port_members(
                r.get("src_firewallgroup_ids") or []
            )
            if excepted or src_ports or (svc_objs and proto != "all"):
                # The rule gets its own SvcObject in place of the shared port
                # group. The shared port group holds neither the protocol nor
                # a source port. A tcp rule on a port group must not match udp
                # on the ports of the group.
                dst_ports = ([str(port)] if port else []) + port_members(r.get("dst_firewallgroup_ids") or [])
                svc_objs = [
                    _svc_object(
                        b,
                        unifi_site,
                        proto,
                        excepted=excepted,
                        ports=",".join(dst_ports) or None,
                        src_port=",".join(src_ports) or None,
                    )
                ]
            elif not svc_objs and (proto != "all" or port):
                svc_objs = [_svc_object(b, unifi_site, proto, ports=str(port) if port else None)]
            unmodeled = [
                label
                for key, label in (
                    ("src_mac_address", "a source MAC address"),
                    ("icmp_typename", "an ICMP type"),
                    ("icmpv6_typename", "an ICMPv6 type"),
                    ("ipsec", "IPsec"),
                )
                if str(r.get(key) or "").lower() not in ("", "any")
            ]
            fields = _unmodeled_fields(r, _CLASSIC_RULE_KEYS)
            unmodeled += [f"the field {name!r}" for name in fields]
            ru = b.node(
                "FwRule",
                f"{rb}:{r['_id']}",
                position=int(r.get("rule_index") or 0),
                action=str(r.get("action") or "").lower() or None,
                name=r.get("name"),
                enabled=bool(r.get("enabled", True)),
                rule_uid=r["_id"],
                src_any=not src_objs,
                dst_any=not dst_objs,
                svc_any=not svc_objs,
                # The list is explicitly empty when no state flag is set. The
                # empty list overwrites the states of an earlier write.
                states=[state for flag, state in _CLASSIC_STATE_FLAGS if r.get(flag) is True],
                states_opaque=bool(unmodeled),
                states_opaque_reason=(
                    "the rule also matches on " + ", ".join(unmodeled) + ", which is not modeled"
                    if unmodeled
                    else None
                ),
                # The list is explicitly empty when every field is modeled. The
                # empty list overwrites the list of an earlier write.
                unmodeled_fields=fields,
            )
            b.rel("HAS_RULE", "FwRulebase", rb, "FwRule", ru)
            for gu in src_objs:
                b.rel("SRC", "FwRule", ru, "NetObject", gu)
            for gu in dst_objs:
                b.rel("DST", "FwRule", ru, "NetObject", gu)
            for su in svc_objs:
                b.rel("SVC", "FwRule", ru, "SvcObject", su)


def _netconf_object(
    b: GraphBuilder,
    unifi_site: str,
    net_by_id: dict[str, dict[str, Any]],
    nid: str,
    ntype: Any,
    rule_id: str,
    side: str,
    *,
    combo: bool,
) -> str:
    """The NetObject is always emitted, resolved or opaque."""
    if combo:
        return b.node(
            "NetObject",
            f"unifi:{unifi_site}:net:{uid.slug(nid)}:rule:{uid.slug(rule_id)}:{side}",
            name=f"network:{nid}",
            kind="network",
            opaque=True,
            opaque_reason=(
                f"network {nid!r} is combined with a group or address scope on the same "
                "side; intersection semantics are unconfirmed"
            ),
        )
    if str(ntype or "").upper() in _NETCONF_GATEWAY_TYPES:
        af = 6 if str(ntype).upper() == "ADDRV6" else 4
        gw_info = net_by_id.get(nid)
        if gw_info is not None and gw_info.get("gw_ip") and gw_info.get("gw_af") == af:
            ou = b.node(
                "NetObject",
                f"unifi:{unifi_site}:net:{uid.slug(nid)}:gw{af}",
                name=f"gateway:{nid}",
                kind="host",
            )
            b.rel("RESOLVES_TO", "NetObject", ou, "IpAddress", gw_info["gw_ip"])
            return ou
        if gw_info is None:
            why = "the network is not among the collected networks"
        elif af == 6:
            why = "the network states no IPv6 gateway address"
        else:
            why = "the network states no subnet"
        return b.node(
            "NetObject",
            f"unifi:{unifi_site}:net:{uid.slug(nid)}:rule:{uid.slug(rule_id)}:{side}",
            name=f"network:{nid}",
            kind="network",
            opaque=True,
            opaque_reason=(
                f"network scope type {ntype!r} names the gateway address of network {nid!r}, "
                f"which is not known: {why}"
            ),
        )
    if ntype is not None and str(ntype).upper() not in _NETCONF_ADDRESS_TYPES:
        return b.node(
            "NetObject",
            f"unifi:{unifi_site}:net:{uid.slug(nid)}:rule:{uid.slug(rule_id)}:{side}",
            name=f"network:{nid}",
            kind="network",
            opaque=True,
            opaque_reason=f"network scope type {ntype!r} is not modeled as an address set",
        )
    ou = b.node(
        "NetObject",
        f"unifi:{unifi_site}:net:{uid.slug(nid)}",
        name=f"network:{nid}",
        kind="network",
    )
    info = net_by_id.get(nid)
    if info is None:
        b.node(
            "NetObject",
            ou,
            opaque=True,
            opaque_reason=f"network {nid!r} referenced by the rule is not among the collected networks",
        )
        return ou
    if info.get("prefix") is None:
        b.node(
            "NetObject",
            ou,
            opaque=True,
            opaque_reason=f"network {nid!r} referenced by the rule is collected but has no prefix (unrouted)",
        )
        return ou
    b.rel("RESOLVES_TO", "NetObject", ou, "Prefix", info["prefix"])
    return ou


def _addr_object(b: GraphBuilder, unifi_site: str, addr: str, dom: str) -> str:
    ou = b.node(
        "NetObject",
        f"unifi:{unifi_site}:addr:{uid.slug(addr)}",
        name=addr,
        kind="cidr" if "/" in addr else "host",
    )
    if "/" in addr:
        pu = b.node(
            "Prefix", uid.prefix(dom, addr), cidr=addr, af=6 if ":" in addr else 4, l3dom=dom, anchor=dom
        )
        b.rel("RESOLVES_TO", "NetObject", ou, "Prefix", pu)
    else:
        ipu = b.node(
            "IpAddress", uid.ip(dom, addr), ip=addr, af=6 if ":" in addr else 4, l3dom=dom, anchor=dom
        )
        b.rel("RESOLVES_TO", "NetObject", ou, "IpAddress", ipu)
    return ou


def _containing(infos, ip: str, prefer=None):
    addr = ipaddress.ip_address(ip)
    if prefer and prefer.get("net") and addr in prefer["net"]:
        return prefer
    for info in infos:
        if info.get("net") and addr in info["net"]:
            return info
    return None


def _transport(config: UnifiConfig) -> httpx.BaseTransport | None:
    """A test replaces this function. None selects the default transport of httpx."""
    return None


class CertificatePinMismatch(ssl.SSLCertVerificationError):
    """The console presented a certificate other than the pinned certificate
    of the source (`UnifiConfig.tls_fingerprint_sha256`). The exception is
    raised during the TLS handshake. No request and no login password is sent
    on that connection."""

    def __str__(self) -> str:
        # SSLError renders its args as a tuple
        return str(self.args[0]) if self.args else ""


def _check_pin(context: ssl.SSLContext, der: bytes | None) -> None:
    want = getattr(context, "pinned_sha256", "")
    got = hashlib.sha256(der).hexdigest() if der else ""
    if got != want:
        raise CertificatePinMismatch(
            f"the console presented a certificate with SHA-256 fingerprint {got or 'none'}, "
            f"not the pinned {want}; no request was sent"
        )


class _PinnedSocket(ssl.SSLSocket):
    def do_handshake(self, block: bool = False) -> None:
        super().do_handshake(block)
        _check_pin(self.context, self.getpeercert(binary_form=True))


class _PinnedObject(ssl.SSLObject):
    def do_handshake(self) -> None:
        super().do_handshake()
        _check_pin(self.context, self.getpeercert(binary_form=True))


class _PinnedContext(ssl.SSLContext):
    """A TLS client context that accepts exactly one certificate by its
    SHA-256 fingerprint. The check runs when the handshake of each connection
    completes. httpcore opens every connection of the client through
    `wrap_socket` or `wrap_bio`. The check runs on every connection that
    sends the login and the reads, including reconnects."""

    sslsocket_class = _PinnedSocket
    sslobject_class = _PinnedObject
    pinned_sha256 = ""


def _pinned_transport(config: UnifiConfig) -> httpx.HTTPTransport:
    """The chain and the name of the console certificate are not checked."""
    context = _PinnedContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.pinned_sha256 = config.tls_fingerprint_sha256
    if config.tls.client_cert is not None:
        http._load_client_cert(
            context, config.tls.client_cert.cert, config.tls.client_cert.key.get_secret_value()
        )
    return httpx.HTTPTransport(verify=context)


@contextmanager
def _pin_failure(url: str) -> Iterator[None]:
    """Raises `CertificatePinMismatch` for a pin mismatch that httpx reports as
    a ConnectError."""
    try:
        yield
    except httpx.ConnectError as exc:
        cause: BaseException | None = exc
        while cause is not None and not isinstance(cause, CertificatePinMismatch):
            cause = cause.__cause__ or cause.__context__
        if cause is None:
            raise
        raise CertificatePinMismatch(f"{url}: {cause}") from exc


def client_mac_rows(
    raw: dict[str, Any], *, unifi_site: str, l2fabric: str, resolver: DeviceResolver
) -> list[dict[str, Any]]:
    """The wired clients of the payload as side-store `mac` rows. A row holds
    the switch that reports the client, the port, the client MAC and its VLAN.
    The port name is `port<idx>`, the name segment of the Port uid that
    `_port_stage` writes. The VLAN is the VLAN of the network of the client,
    or its VLAN tag, in the order of `_client_stage`. A client on no collected
    switch port has no row. A client with a malformed port has no row. A
    wireless client has no row."""
    mac_to_dev = _device_stage(GraphBuilder(), raw, unifi_site, resolver)
    ports = {
        (mac, int(p["port_idx"]))
        for d in raw.get("devices") or []
        if isinstance(d, dict) and (mac := canonical_mac(d.get("mac")))
        for p in d.get("port_table") or []
        if isinstance(p, dict) and isinstance(p.get("port_idx"), int)
    }
    vid_by_net = {
        n.get("_id"): int(n.get("vlan") or 1)
        for n in raw.get("networks") or []
        if isinstance(n, dict)
        and n.get("purpose") in ("corporate", "guest", "vlan-only")
        and n.get("enabled") is not False
    }
    rows: list[dict[str, Any]] = []
    for c in raw.get("clients") or []:
        if not isinstance(c, dict) or not c.get("is_wired") or not c.get("sw_port"):
            continue
        mac, sw_mac = canonical_mac(c.get("mac")), canonical_mac(c.get("sw_mac"))
        try:
            port = int(c["sw_port"])
        except (TypeError, ValueError):
            continue
        if mac is None or sw_mac is None or (sw_mac, port) not in ports:
            continue
        vid: int | None = vid_by_net.get(c.get("network_id"))
        if vid is None:
            try:
                vid = int(c.get("vlan") or 0)
            except (TypeError, ValueError):
                vid = 0
            vid = vid if 0 < vid < 4095 else None
        rows.append(
            {
                "device_uid": mac_to_dev[sw_mac],
                "vlan": vid,
                "mac": mac,
                "port_name": f"port{port}",
                "bridge_domain_uid": uid.bridge_domain(l2fabric, vid) if vid else None,
            }
        )
    return rows


READ_PATHS = {
    "devices": "stat/device",
    "networks": "rest/networkconf",
    "port_profiles": "rest/portconf",
    "wlans": "rest/wlanconf",
    "clients": "stat/sta",
    "firewall_rules": "rest/firewallrule",
    "firewall_groups": "rest/firewallgroup",
    "firewall_zones": "firewall/zones",
    "firewall_policies": "firewall-policies",
}


class UnifiConfig(SourceConfig):
    url: str  # e.g. https://192.168.1.2 (UniFi OS console)
    auth: UserPassword
    # The site id is interpolated into every request path.
    site: str = Field(default="default", pattern=r"^[A-Za-z0-9_-]{1,32}$")
    tls: TlsConfig = TlsConfig()
    # False keeps the wired clients as side-store `mac` rows.
    include_clients: bool = True
    # The SHA-256 fingerprint of the DER bytes of the console certificate, in
    # hex. Colons are allowed. When it is set, every connection of the source
    # accepts only that certificate, and `tls.verify` and `tls.ca_bundle` are
    # not used (`_pinned_transport`). A different certificate fails the source
    # before the login is sent. When it is empty, TLS follows `tls`.
    tls_fingerprint_sha256: str = ""

    @field_validator("tls_fingerprint_sha256")
    @classmethod
    def _fingerprint_hex(cls, value: str) -> str:
        digest = re.sub(r"[\s:]", "", value).lower()
        if digest and not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("tls_fingerprint_sha256 must be a SHA-256 digest: 64 hex digits, colons allowed")
        return digest


@register
class UnifiCollector(Collector):
    name = "unifi"
    ConfigModel = UnifiConfig
    KIND = "orchestrator"
    PARSER_VERSION = "4"
    NORMALIZATION_VERSIONS: ClassVar[dict[str, str]] = {
        "mtu": MTU_NORMALIZATION_VERSION,
        "firewall": "4",
        "policy-binding": "2",
        # The port VLAN carriage comes from the port override when it has
        # carriage fields, else from the assigned profile, else from the
        # port_table entry. The carriage reads tagged_vlan_mgmt.
        "port-carriage": "1",
        # A placeholder serial identifies no chassis. When 2 devices report
        # one serial in one run, the later device is keyed by its ref.
        "serial": "1",
        # The address of a client on a network that the gateway of the console
        # routes anchors on the anchor of the prefix.
        "client-address-anchor": "1",
    }

    def __init__(self, config: UnifiConfig, settings):
        super().__init__(config, settings)
        self.scope = f"unifi:{self.partition}"

    @property
    def partition(self) -> str:
        """The partition is the source row and the site, such as `branch-a:default`."""
        c = self.config
        return f"{uid.slug(c.source_name)}:{c.site}" if c.source_name else c.site

    def _login(self, client: httpx.Client) -> None:
        c = self.config
        client.post(
            "/api/auth/login",
            json={"username": c.auth.username, "password": c.auth.password.get_secret_value()},
        ).raise_for_status()

    def _client(self) -> httpx.Client:
        c = self.config
        transport = _transport(c)
        if transport is None and c.tls_fingerprint_sha256:
            transport = _pinned_transport(c)
        with _pin_failure(c.url):
            return http.logged_in_client(c.url, c.tls, self._login, timeout=30, transport=transport)

    def probe(self) -> str:
        # The client of `http.logged_in_client` raises when it is entered as a context manager.
        client = self._client()
        try:
            return f"login ok: {self.config.auth.username} at {self.config.url}"
        finally:
            client.close()

    def fetch(self) -> dict[str, Any]:
        c = self.config
        client = self._client()
        try:

            def get(path: str):
                with _pin_failure(c.url):
                    resp = client.get(f"/proxy/network/api/s/{c.site}/{path}")
                resp.raise_for_status()
                payload = resp.json()
                return payload.get("data", payload)

            def get_v2(path: str):
                with _pin_failure(c.url):
                    resp = client.get(f"/proxy/network/v2/api/site/{c.site}/{path}")
                resp.raise_for_status()
                payload = resp.json()
                return payload.get("data", payload) if isinstance(payload, dict) else payload

            refused: list[str] = []

            def get_opt(fn, path: str):
                # a controller answers 400 or 404 for the firewall family it lacks
                try:
                    return fn(path)
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code in (400, 404):
                        refused.append(path)
                        return []
                    raise

            payload = {
                "devices": get(READ_PATHS["devices"]),
                "networks": get(READ_PATHS["networks"]),
                # The port profiles hold the VLAN carriage of each port for the
                # bridge-domain audit. A site with only a gateway can lack the
                # model.
                "port_profiles": get_opt(get, READ_PATHS["port_profiles"]),
                "wlans": get(READ_PATHS["wlans"]),
                "clients": get(READ_PATHS["clients"]),
                "firewall_rules": get_opt(get, READ_PATHS["firewall_rules"]),
                "firewall_groups": get_opt(get, READ_PATHS["firewall_groups"]),
                "firewall_zones": get_opt(get_v2, READ_PATHS["firewall_zones"]),
                "firewall_policies": get_opt(get_v2, READ_PATHS["firewall_policies"]),
            }
            payload["refused_reads"] = refused
            return payload
        finally:
            client.close()

    def side_tables(self, raw: dict[str, Any]) -> dict[str, Sequence[dict[str, Any]]]:
        c = self.config
        if c.include_clients:
            return {}
        return {
            "mac": client_mac_rows(
                raw,
                unifi_site=c.site,
                l2fabric=self.settings.l2fabric_of(c.source_name, c.l2fabric),
                resolver=self.identity,
            )
        }

    def normalize(self, raw: dict[str, Any]) -> Batch:
        c = self.config
        l2fabric = self.settings.l2fabric_of(c.source_name, c.l2fabric)
        batch = normalize_unifi(
            raw,
            site_code=c.site_code,
            l3dom=c.effective_routing_scope,
            unifi_site=c.site,
            include_clients=c.include_clients,
            l2fabric=l2fabric,
            resolver=self.identity,
            partition=self.partition,
        )
        # A client address that no gateway of this console routes anchors on the bridge
        # domain of its VLAN.
        if l2fabric == DEFAULT_L2_FABRIC:
            shared_prefix = uid.bridge_domain(l2fabric, 0).rsplit(":", 1)[0] + ":"
            shared = sum(
                1
                for n in batch.nodes
                if n.label == "IpAddress" and str(n.props.get("anchor") or "").startswith(shared_prefix)
            )
            if shared:
                batch.warnings.append(
                    f"unifi {c.site}: {shared} client addresses anchor on a VLAN of the default L2 "
                    f"fabric {l2fabric!r} (no gateway of this console routes them), so another source "
                    "that reuses the VLAN id and the address shares their nodes; declare an L2_FABRICS "
                    "entry for this source if it is a separate branch"
                )
        policy_keys = (
            "firewall_rules",
            "firewall_groups",
            "firewall_zones",
            "firewall_policies",
        )
        rows = sum(len(raw.get(name) or ()) for name in policy_keys)
        gaps = policy_gaps(raw) if rows else []
        if gaps:
            batch.sections["policy"] = SectionOutcome(
                status="partial", row_count=rows, detail="; ".join(gaps)
            )
            batch.warnings.extend(f"unifi {self.config.site}: {gap}" for gap in gaps)
        else:
            batch.sections["policy"] = SectionOutcome(status="ok" if rows else "empty", row_count=rows)
        return batch
