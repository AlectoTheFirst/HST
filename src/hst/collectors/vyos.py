"""VLAN subinterfaces emit the same L2Segment uids as the UniFi collector (l2seg:<site>:vlan<vid>)."""

from __future__ import annotations

import functools
import hashlib
import ipaddress
import json
import logging
import math
import re
from collections.abc import Callable, Iterable, Iterator, Sequence
from typing import Any, ClassVar, NamedTuple

from hst.core import debug_capture, uid
from hst.core.config import DEFAULT_L2_FABRIC
from hst.core.identity import DeviceResolver, MemoryResolver, placeholder_serial, resolve_chassis
from hst.core.ipenc import prefix_bounds
from hst.core.l3domain import DEFAULT_VRF, DomainPolicy
from hst.core.manifest import BGP_ROUTES_TABLE, BGP_SESSIONS_TABLE, OSPF_LSDB_TABLE, bgp_direction_key
from hst.core.model import Batch, SectionOutcome, TableOutcome
from hst.core.mtu import MTU_NORMALIZATION_VERSION, canonical_json
from hst.core.mtu_profiles import emit_observation, observation_from_raw
from hst.core.normalize import iface_slug

from . import streams
from .base import RAW_OUTCOMES_KEY, CollectionStopped, register
from .cisco_bgp import neighbor_key, router_id_or_none
from .cisco_common import list_references, match_list_stage, ospf_default_originate, ospf_stage
from .cli_collector import (
    SshCliCollector,
    SshSourceConfig,
    classify_command_failure,
    effective_outcomes,
)
from .util import (
    GraphBuilder,
    OverlayEnd,
    VrfDomains,
    as_int,
    bgp_multipath_props,
    canonical_mac,
    connected_address,
    listify,
    lpm_columns,
    overlay_connection,
    parse_cluster_id,
)

logger = logging.getLogger(__name__)

# The PATH of a non-interactive SSH exec has no sbin directory.
_IP_PATH = "PATH=/usr/sbin:/sbin:/usr/bin:/bin"

# A read failure becomes `unknown` inside the script.
_LINK_SPEED_SCRIPT = (
    "for i in /sys/class/net/*; do "
    'n=$(basename "$i"); '
    's=$(cat "$i/speed" 2>/dev/null || echo unknown); '
    'd=$(cat "$i/duplex" 2>/dev/null || echo unknown); '
    'echo "$n $s $d"; '
    "done"
)

# The read commands. Evidence collection guidance uses the same commands.
READ_COMMANDS = {
    "config": "show configuration json",
    "version": "show version",
    "links": f"{_IP_PATH} ip -j link show",
    "addrs": f"{_IP_PATH} ip -j addr show",
    "routes": f'{_IP_PATH} vtysh -c "show ip route vrf all json"',
    "routes6": f'{_IP_PATH} vtysh -c "show ipv6 route vrf all json"',
    "link_speeds": f"{_IP_PATH} sh -c '{_LINK_SPEED_SCRIPT}'",
    # `neigh` holds the ARP and IPv6 neighbor tables of every interface.
    "neigh": f"{_IP_PATH} ip -j neigh show",
}


def _af(addr: str) -> int:
    """Return the address family (4 or 6) of an address literal.

    The function reads config strings that `ipaddress` does not parse, such as
    ranges, group members and NAT translations.
    """
    return 6 if ":" in addr else 4


_IF_KIND = {
    "ethernet": "phys",
    "loopback": "loopback",
    "wireguard": "wireguard",
    "bridge": "bridge",
    "bonding": "lag",
    "pppoe": "pppoe",
    "tunnel": "tunnel",
}

# The IP protocol of the carrier (IPv6 next header) for each tunnel encapsulation.
# The IP-in-IP kinds are numbers. The inner family sets the number (4 for IPv4
# inside, 41 for IPv6 inside), whatever the family of the carrier. In
# /etc/protocols, "ipip" is 94. `ipip6` is IPv4 in IPv6 (DS-Lite).
_TUNNEL_CARRIER_PROTO = {
    "gre": "gre",
    "gre-bridge": "gre",
    "ip6gre": "gre",
    "ipip": "4",
    "ipip6": "4",
    "sit": "41",
    "ip6ip6": "41",
}


def _looks_like_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _ipsec_esp_groups(cfg: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """`proposals` is in ascending proposal-number order."""
    groups: dict[str, dict[str, Any]] = {}
    for name, group in (((cfg.get("vpn") or {}).get("ipsec") or {}).get("esp-group") or {}).items():
        proposals = group.get("proposal") or {}
        ordered = [proposals[num] or {} for num in sorted(proposals, key=lambda n: (len(n), n))]
        chosen: dict[str, Any] = ordered[0] if ordered else {}
        groups[name] = {
            "encryption": chosen.get("encryption"),
            "hash": chosen.get("hash"),
            "mode": group.get("mode"),
            "proposals": [{"encryption": p.get("encryption"), "hash": p.get("hash")} for p in ordered],
        }
    return groups


def _ipsec_vti_peers(cfg: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The vti-scoped esp-group takes precedence over `default-esp-group`."""
    peers: dict[str, dict[str, Any]] = {}
    for peer_key, peer in (
        (((cfg.get("vpn") or {}).get("ipsec") or {}).get("site-to-site") or {}).get("peer", {}).items()
    ):
        vti = peer.get("vti") or {}
        bind = vti.get("bind")
        if not isinstance(bind, str):
            continue
        remote = peer.get("remote-address") or (peer_key if _looks_like_address(peer_key) else None)
        peers[bind] = {
            "local": peer.get("local-address"),
            "remote": remote,
            "esp_group": vti.get("esp-group") or peer.get("default-esp-group"),
        }
    return peers


def device_uid(
    version_text: str, host: str, source_name: str = "", resolver: DeviceResolver | None = None
) -> str:
    """`normalize_vyos` and `VyosCollector.side_tables` both derive this uid."""
    return resolve_chassis(
        resolver or MemoryResolver(), _serial(version_text), ("ref", f"{source_name or 'vyos'}:{host}"), host
    )


def local_namespace(dev: str) -> str:
    """The namespace is the name part of the Device uid, `edge` for `dev:edge`."""
    return dev.removeprefix("dev:")


def normalize_vyos(
    raw: dict[str, Any],
    *,
    l3dom: str,
    l2fabric: str = DEFAULT_L2_FABRIC,
    rib_graph_max_routes: int = 1000,
    source_name: str = "",
    rib: Callable[[], _RibRead] | None = None,
    resolver: DeviceResolver | None = None,
    scope: str = "",
) -> Batch:
    """Return the batch of one VyOS payload.

    `scope` is the retirement partition of the batch. The collector passes its
    own `scope` (`vyos:<host>`, the configured host). A run names the partition
    of the device by that string before any payload is read, to carry the
    device forward when its load is skipped or fails. The objects of the load
    must have the same scope. Without `scope`, the scope is built from the uid
    namespace of the device (`local_namespace`).

    `rib` returns the RIB of the payload as `_read_rib` reads it. The collector
    passes the read that its load already holds. A load decodes each RIB answer
    once. Without `rib`, the answers are read here when a stage first needs them.

    `resolver` is the device identity registry (`Collector.identity`) that
    gives the Device uid (`device_uid`). With None, the uid resolves in memory.
    """
    cfg = raw.get("config") or {}
    b = GraphBuilder()
    rib_of = rib if rib is not None else functools.cache(functools.partial(_read_rib, raw))

    dev, host = _device_stage(b, cfg, raw.get("version_text") or "", source_name, resolver)
    # The policy stages below take the namespace in their `host` argument.
    ns = local_namespace(dev)
    vrfs = _vrf_stage(b, cfg, dev, l3dom)
    if_uids, if_vrf = _interface_stage(b, raw, cfg, dev, host, l2fabric, vrfs, rib_of)
    _static_uplinks(b, cfg, dev, if_uids, if_vrf)
    _mtu_stage(b, raw, cfg, dev, source_name or host, if_uids)
    vrf = vrfs.uids[DEFAULT_VRF]

    # Global-scope objects below resolve in the default VRF's domain.
    default_dom = vrfs.domains[DEFAULT_VRF]

    _firewall(b, cfg, dev, ns, default_dom, if_uids, if_vrf)
    _legacy_firewall(b, cfg, dev, ns, host)
    _legacy_policy_route(b, cfg, dev, ns, if_uids)
    _nat(b, cfg, dev, ns, default_dom)

    table_uids = _route_stage(
        b, cfg, dev, vrfs, if_uids, rib_graph_max_routes, rib_of, _rib_sections_read(raw, rib_of())
    )

    # `policy prefix-list` and `policy route-map` are global config. They are
    # built once and indexed by name before any BGP process resolves an
    # attachment.
    pl_uids, rm_uids = _policy_stage(b, cfg, dev)
    peers = summary_peers(raw.get(BGP_SUMMARY_COMMAND))
    observed_as = {key: asn for key, asn in peers.items() if asn is not None}
    default_bgp = (cfg.get("protocols") or {}).get("bgp")
    peer_rids = neighbor_router_ids(raw.get(BGP_NEIGHBORS_COMMAND))
    _bgp_stage(
        b, default_bgp, dev, DEFAULT_VRF, vrf, default_dom, pl_uids, rm_uids, observed_as, peer_rids, peers
    )
    for vname, vnode in ((cfg.get("vrf") or {}).get("name") or {}).items():
        vbgp = ((vnode or {}).get("protocols") or {}).get("bgp")
        if vbgp:
            _bgp_stage(
                b,
                vbgp,
                dev,
                vname,
                vrfs.uids[vname],
                vrfs.domains[vname],
                pl_uids,
                rm_uids,
                observed_as,
                peer_rids,
                peers,
            )
    # VyOS 1.3 spells the BGP of a VRF `protocols vrf <name> bgp <asn>`. The
    # module does not read it and writes its process with a session gap (`_bgp_stage`).
    for vname, vnode in (((cfg.get("protocols") or {}).get("vrf")) or {}).items():
        vbgp = (vnode or {}).get("bgp") if isinstance(vnode, dict) else None
        if isinstance(vbgp, dict) and vname in vrfs.uids:
            _bgp_stage(b, vbgp, dev, vname, vrfs.uids[vname], vrfs.domains[vname], pl_uids, rm_uids)

    ospf = _parse_ospf(raw, cfg)
    if ospf is not None:
        # `iface_uids` is keyed by `iface_slug`.
        ospf_stage(
            b,
            {"ospf": ospf},
            dev=dev,
            vrfs=vrfs,
            iface_uids={iface_slug(name): iu for name, iu in if_uids.items()},
        )

    _pbr(b, cfg, dev, ns, default_dom, if_uids, vrf, table_uids)

    dhcp = ((cfg.get("service") or {}).get("dhcp-server") or {}).get("shared-network-name") or {}
    for net in dhcp.values():
        for spfx in net.get("subnet") or {}:
            # A DHCP-served subnet is routed addressing of the default table.
            b.node("Prefix", uid.prefix(vrf, spfx), cidr=spfx, af=4, l3dom=default_dom, anchor=vrf, dhcp=True)

    return b.batch("vyos", scope or f"vyos:{ns}")


def _device_stage(
    b: GraphBuilder,
    cfg: dict[str, Any],
    version_text: str,
    source_name: str = "",
    resolver: DeviceResolver | None = None,
) -> tuple[str, str]:
    """Write the router Device and return (device uid, hostname).

    The stage writes no Site and no LOCATED_IN. core/cycle.py
    `apply_site_assignments` writes the site of a device."""
    host = (cfg.get("system") or {}).get("host-name", "vyos")
    serial = _serial(version_text)
    dev = device_uid(version_text, host, source_name, resolver)
    version = _first(re.search(r"Version:\s*VyOS\s*(\S+)", version_text))

    b.node(
        "Device",
        dev,
        hostname=host,
        platform="vyos",
        role="router",
        vendor="vyos",
        serial=serial,
        os_version=version,
        identities=[host],
    )
    return dev, host


# The keys of the VyOS 1.3 configuration paths that this module does not read.
_LEGACY_FIREWALL_KEYS = ("name", "ipv6-name")
_LEGACY_STATIC_KEYS = ("interface-route", "interface-route6")
_LEGACY_VERSION = re.compile(r"Version:\s*VyOS\s*(\d+)\.(\d+)")


def _legacy_interface_paths(cfg: dict[str, Any], key: str) -> list[str]:
    """Return every `interfaces <kind> <name> [vif ...] <key>` path that the config holds.

    These paths are the VyOS 1.3 per-interface firewall and policy-route
    bindings. VyOS 1.4 holds them under the firewall and policy trees."""
    found: list[str] = []

    def walk(node: Any, path: str) -> None:
        if not isinstance(node, dict):
            return
        if key in node:
            found.append(f"{path} {key}")
        for vif_key in ("vif", "vif-s", "vif-c"):
            for vid, child in (node.get(vif_key) or {}).items():
                walk(child, f"{path} {vif_key} {vid}")

    for kind, members in (cfg.get("interfaces") or {}).items():
        if isinstance(members, dict):
            for name, node in members.items():
                walk(node, f"interfaces {kind} {name}")
    return found


def legacy_firewall_unread(cfg: dict[str, Any]) -> list[str]:
    """Return the VyOS 1.3 firewall configuration that this module does not read.

    The parts are the top-level `firewall name` and `firewall ipv6-name`
    rulesets, `zone-policy` and the per-interface `firewall in|out|local`
    bindings."""
    fw = cfg.get("firewall") or {}
    unread = [f"firewall {key}" for key in _LEGACY_FIREWALL_KEYS if key in fw]
    if "zone-policy" in cfg:
        unread.append("zone-policy")
    unread.extend(_legacy_interface_paths(cfg, "firewall"))
    return unread


def legacy_unread(cfg: dict[str, Any], version_text: str) -> list[str]:
    """Return every part of a VyOS 1.3 configuration that this module does not read.

    The module reads the 1.4 and 1.5 configuration model. The list is empty
    for a 1.4 or later configuration."""
    unread = legacy_firewall_unread(cfg)
    unread.extend(_legacy_interface_paths(cfg, "policy"))
    protocols = cfg.get("protocols") or {}
    if any(str(key).isdigit() for key in (protocols.get("bgp") or {})):
        unread.append("protocols bgp <asn>")
    static = protocols.get("static") or {}
    unread.extend(f"protocols static {key}" for key in _LEGACY_STATIC_KEYS if key in static)
    if "vrf" in protocols:
        unread.append("protocols vrf")
    m = _LEGACY_VERSION.search(version_text or "")
    if m and (int(m.group(1)), int(m.group(2))) < (1, 4):
        unread.append(f"VyOS {m.group(1)}.{m.group(2)} configuration model")
    return unread


def _legacy_firewall(b: GraphBuilder, cfg: dict[str, Any], dev: str, ns: str, host: str) -> None:
    """The rulebase has no rule and no recorded default action."""
    unread = legacy_firewall_unread(cfg)
    if not unread:
        return
    rb = b.node(
        "FwRulebase",
        f"vyos:{ns}:fw:unread-legacy",
        name="unread VyOS 1.3 firewall",
        kind="access",
        vendor="vyos",
        chain="forward",
        match_context="device",
        default_action_unknown=True,
    )
    b.rel("ENFORCES", "Device", dev, "FwRulebase", rb)
    logger.warning("vyos %s: VyOS 1.3 firewall configuration not read: %s", host, ", ".join(unread))


def _legacy_policy_bindings(cfg: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return (interface name, `policy` node) for every VyOS 1.3 `interfaces
    <kind> <name> [vif ...] policy` binding.

    The interface name is the name that `_interface_stage` gives the interface.
    """
    found: list[tuple[str, dict[str, Any]]] = []

    def walk(node: Any, name: str) -> None:
        if not isinstance(node, dict):
            return
        if isinstance(node.get("policy"), dict):
            found.append((name, node["policy"]))
        for vid, child in (node.get("vif") or {}).items():
            walk(child, f"{name}.{vid}")
        for svid, child in (node.get("vif-s") or {}).items():
            walk(child, f"{name}.{svid}")
            for cvid, grandchild in ((child or {}).get("vif-c") or {}).items():
                walk(grandchild, f"{name}.{svid}.{cvid}")

    for members in (cfg.get("interfaces") or {}).values():
        if isinstance(members, dict):
            for name, node in members.items():
                walk(node, str(name))
    return found


def _legacy_policy_route(
    b: GraphBuilder, cfg: dict[str, Any], dev: str, ns: str, if_uids: dict[str, str]
) -> None:
    """The policy's one rule matches every flow and cannot be decided."""
    for ifname, policy in _legacy_policy_bindings(cfg):
        if ifname not in if_uids:
            continue
        names = ", ".join(f"{key} {value}" for key, value in sorted(policy.items()))
        pu = b.node(
            "PbrPolicy",
            f"vyos:{ns}:pbr:unread-legacy:{ifname}",
            name=f"unread VyOS 1.3 policy on {ifname}",
            vendor="vyos",
        )
        b.rel("ENFORCES", "Device", dev, "PbrPolicy", pu)
        b.rel("ENFORCES", "Interface", if_uids[ifname], "PbrPolicy", pu)
        ru = b.node(
            "FwRule",
            f"{pu}:1",
            position=1,
            action="route",
            enabled=True,
            rule_uid=f"pbr:unread-legacy:{ifname}:1",
            states_opaque=True,
            states_opaque_reason=f"the VyOS 1.3 binding policy {names} on {ifname} is not read",
        )
        b.rel("HAS_RULE", "PbrPolicy", pu, "FwRule", ru)


def _vrf_stage(b: GraphBuilder, cfg: dict[str, Any], dev: str, l3dom: str) -> VrfDomains:
    # `l3dom` is the scope that those VRFs resolve within (core/l3domain.py).
    policy = DomainPolicy(scope=l3dom)
    vrfs = VrfDomains(b, dev, policy, lambda name: f"vrf:{dev}:{uid.slug(name)}")
    # `vrfs.add` writes the VrfInstance and the L3Domain it realizes, once per name.
    vrfs.add(DEFAULT_VRF, is_global=True)
    for vname, vnode in ((cfg.get("vrf") or {}).get("name") or {}).items():
        vrfs.add(vname, table=(vnode or {}).get("table"))
    return vrfs


_REMOTE_AS_SYMBOLIC = {"auto", "external", "internal"}


def _neighbor_leaf(bgp_cfg: dict[str, Any], neighbor: dict[str, Any], *path: str) -> Any:
    """Return one setting of a BGP neighbor as FRR applies it.

    The value is the value of the neighbor, or else the value of its
    peer-group. The inheritance is per leaf. A member that sets only
    `address-family ipv4-unicast soft-reconfiguration inbound` still takes the
    route-map of the group under that address family."""

    def dig(node: Any) -> Any:
        for key in path:
            if not isinstance(node, dict):
                return None
            node = node.get(key)
        return node

    own = dig(neighbor)
    group = neighbor.get("peer-group")
    if own is not None or not group:
        return own
    return dig(((bgp_cfg.get("peer-group") or {}).get(str(group))) or {})


def _neighbor_remote_as(
    bgp_cfg: dict[str, Any], neighbor: dict[str, Any], observed: int | None = None
) -> int | None:
    """Return the peer ASN of the neighbor, or None when this module cannot state it.

    The remote-as is the value of the neighbor or of its peer-group
    (`_neighbor_leaf`). `internal` is the ASN of the process. For `external`
    and `auto`, the peer ASN comes from the OPEN message of the peer, and the
    function returns the ASN that the BGP summary reports for the peer
    (`observed`, `summary_remote_as`). `external` accepts only an ASN other
    than the ASN of the process, as FRR does. Both give None when the summary
    reports no ASN."""
    raw = _neighbor_leaf(bgp_cfg, neighbor, "remote-as")
    local = bgp_cfg.get("system-as") or bgp_cfg.get("local-as")
    if raw == "internal":
        raw = local
    elif raw in ("external", "auto"):
        if observed is None or (raw == "external" and str(observed) == str(local)):
            return None
        return observed
    if not raw or raw in _REMOTE_AS_SYMBOLIC:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def neighbor_router_ids(text: Any) -> dict[tuple[str, str], str]:
    """Map (vrf, peer address) to the `remoteRouterId` that `show ip bgp vrf
    all neighbors json` reports for each peer.

    FRR keys the answer by VRF name with the peers beneath, or by peer address
    for the default VRF. A peer entry has `remoteRouterId` or `remoteAs`. A
    peer with no identifier or with 0.0.0.0 (a session that never opened) is
    left out. An answer that is absent or does not decode gives an empty map."""
    if not isinstance(text, str) or _blank_answer(text):
        return {}
    try:
        payload = json.loads(text)
    except ValueError:
        return {}
    out: dict[tuple[str, str], str] = {}
    if not isinstance(payload, dict):
        return out

    def is_peer(entry: Any) -> bool:
        return isinstance(entry, dict) and ("remoteRouterId" in entry or "remoteAs" in entry)

    def take(vrf_name: str, peers: dict[str, Any]) -> None:
        for peer_ip, entry in peers.items():
            if is_peer(entry) and (rid := router_id_or_none(entry.get("remoteRouterId"))):
                out.setdefault(neighbor_key(vrf_name, str(peer_ip)), rid)

    take(DEFAULT_VRF, payload)
    for vrf_name, peers in payload.items():
        if isinstance(peers, dict) and not is_peer(peers):
            take(str(vrf_name), peers)
    return out


def summary_peers(text: Any) -> dict[tuple[str, str], int | None]:
    """Map (vrf, peer address) to the remote ASN that `show bgp vrf all summary
    json` reports for each peer of every address family.

    The ASN is None for a peer whose ASN FRR has not learned (FRR reports 0).
    A summary that is absent or does not decode gives an empty map. A dynamic
    peer of a listen range is listed like any other peer (`bgp_neighbors`)."""
    if not isinstance(text, str) or _blank_answer(text):
        return {}
    try:
        payload = json.loads(text)
    except ValueError:
        return {}
    out: dict[tuple[str, str], int | None] = {}
    if not isinstance(payload, dict):
        return out
    for vrf_name, vrf_payload in payload.items():
        if not isinstance(vrf_payload, dict):
            continue
        for fam in vrf_payload.values():
            peers = fam.get("peers") if isinstance(fam, dict) else None
            if not isinstance(peers, dict):
                continue
            for peer_ip, p in peers.items():
                asn = p.get("remoteAs") if isinstance(p, dict) else None
                key = (str(vrf_name), str(peer_ip))
                if isinstance(asn, int) and not isinstance(asn, bool) and asn > 0:
                    out[key] = out.get(key) or asn
                else:
                    out.setdefault(key, None)
    return out


def summary_remote_as(text: Any) -> dict[tuple[str, str], int]:
    """Map (vrf, peer address) to the remote ASN of each peer of `summary_peers`
    that has an ASN.

    The map serves the neighbors whose remote-as is `external` or `auto`
    (`_neighbor_remote_as`)."""
    return {key: asn for key, asn in summary_peers(text).items() if asn is not None}


# The key of the listen range that accepted a dynamic peer, in its `bgp_neighbors` entry.
_DYNAMIC_RANGE = "_dynamic_range"


def _listen_ranges(
    bgp_cfg: dict[str, Any],
) -> list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, Any]]:
    """Return each `listen range <prefix> peer-group <group>` as (range, group)."""
    out = []
    for prefix, node in (((bgp_cfg.get("listen") or {}).get("range")) or {}).items():
        try:
            net = ipaddress.ip_network(str(prefix), strict=False)
        except ValueError:
            continue
        out.append((net, (node if isinstance(node, dict) else {}).get("peer-group")))
    return out


def bgp_neighbors(
    bgp_cfg: dict[str, Any], vrf_name: str, peers: Iterable[tuple[str, str]] = ()
) -> dict[str, dict[str, Any]]:
    """Return the neighbors of one BGP process.

    The neighbors are each configured `neighbor`, then each peer that the
    summary lists for this VRF (`peers`, `summary_peers`), that no neighbor
    names, and that exactly one `listen range` holds. Such a dynamic peer is a
    member of the peer-group of the range. It takes the remote-as and the
    policies of the group (`_neighbor_leaf`) and holds the range under
    `_DYNAMIC_RANGE`. A peer in 2 ranges is left out with a warning, as in
    `cisco_bgp.expand_dynamic_neighbors`."""
    out: dict[str, dict[str, Any]] = {
        str(peer): (node if isinstance(node, dict) else {})
        for peer, node in (bgp_cfg.get("neighbor") or {}).items()
    }
    ranges = _listen_ranges(bgp_cfg)
    if not ranges:
        return out
    for peer_vrf, peer in peers:
        if peer_vrf != vrf_name or peer in out:
            continue
        try:
            address = ipaddress.ip_address(peer)
        except ValueError:
            continue
        holding = [(net, group) for net, group in ranges if address.version == net.version and address in net]
        if len(holding) != 1:
            if holding:
                logger.warning(
                    "vyos: bgp dynamic peer %s in VRF %s is in several listen ranges; skipped", peer, vrf_name
                )
            continue
        net, group = holding[0]
        entry: dict[str, Any] = {_DYNAMIC_RANGE: str(net)}
        if group:
            entry["peer-group"] = group
        out[peer] = entry
    return out


def _prefix_list_range(prefix: str | None, ge: str | None, le: str | None) -> tuple[int | None, int | None]:
    """The bounds follow FRR's `prefix_list_entry_match` (`lib/plist.c`)."""
    if not prefix:
        return None, None
    plen = int(prefix.split("/", 1)[1])
    max_bits = 128 if _af(prefix) == 6 else 32
    if not ge and not le:
        return plen, plen
    return (int(ge) if ge else plen), (int(le) if le else max_bits)


# The `match` paths of a route-map rule `_policy_stage` reads into match_* fields.
_READ_MATCH_PATHS = {
    ("ip", "address", "prefix-list"),
    ("as-path",),
    ("community", "community-list"),
    ("tag",),
    ("metric",),
}
# The `set` paths that `_policy_stage` reads into set_* fields. The
# community-list delete has 2 spellings, VyOS 1.4 `set community delete <list>`
# and VyOS 1.3 `set comm-list comm-list <list>` with `delete`.
_READ_SET_PATHS = {
    ("local-preference",),
    ("metric",),
    ("as-path", "prepend"),
    ("community", "add"),
    ("community", "replace"),
    ("community", "delete"),
    ("comm-list", "comm-list"),
    ("comm-list", "delete"),
}


def _unread_lines(tree: dict[str, Any], keyword: str, read: set[tuple[str, ...]]) -> list[str]:
    """Return every leaf of the `match` or `set` tree of a rule outside `read`
    as `<keyword> <path> <value>` text.

    The lines fill `match_unsupported` and `set_unsupported` of the rule.
    """
    out: list[str] = []

    def walk(node: Any, path: tuple[str, ...]) -> None:
        if path in read:
            return
        if isinstance(node, dict) and node:
            for key in sorted(node):
                walk(node[key], (*path, key))
            return
        if not path:
            return
        text = " ".join((keyword, *path))
        values = [] if isinstance(node, dict) else listify(node)
        if values:
            out.extend(f"{text} {v}" for v in values)
        else:
            out.append(text)

    walk(tree, ())
    return out


def _unread_match_lines(match: dict[str, Any]) -> list[str]:
    return _unread_lines(match, "match", _READ_MATCH_PATHS)


def _int_or_none(value: Any) -> int | None:
    text = str(value).strip() if value is not None else ""
    return int(text) if text.isdigit() else None


def _match_lists(policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Return `policy community-list` and `policy as-path-list` as
    `[{"name", "kind", "entries"}]`.

    FRR matches the `regex` of a VyOS list as an expanded regular expression,
    against the communities of a route as one string or against its AS path
    (simul/matchlist.py)."""
    out: list[dict[str, Any]] = []
    for key, kind in (("community-list", "community-list"), ("as-path-list", "as-path-list")):
        for name, node in (policy.get(key) or {}).items():
            entries = []
            for seqs, rule in sorted(((node or {}).get("rule") or {}).items(), key=lambda kv: int(kv[0])):
                rule = rule or {}
                regex = rule.get("regex")
                entries.append(
                    {
                        "seq": int(seqs),
                        "action": rule.get("action"),
                        "match_type": "expanded" if regex is not None else "unsupported",
                        "value": str(regex) if regex is not None else None,
                    }
                )
            out.append({"name": name, "kind": kind, "entries": entries})
    return out


def _policy_stage(b: GraphBuilder, cfg: dict[str, Any], dev: str) -> tuple[dict[str, str], dict[str, str]]:
    """Every RoutePolicy node is minted before any entry is processed."""
    policy = cfg.get("policy") or {}
    prefix_lists = policy.get("prefix-list") or {}
    route_maps = policy.get("route-map") or {}
    list_uids = match_list_stage(b, _match_lists(policy), dev=dev)

    pl_uids = {
        name: b.node("RoutePolicy", uid.route_policy(dev, "prefix-list", name), name=name, kind="prefix-list")
        for name in prefix_lists
    }
    rm_uids = {
        name: b.node("RoutePolicy", uid.route_policy(dev, "route-map", name), name=name, kind="route-map")
        for name in route_maps
    }

    for name, pl in prefix_lists.items():
        pu = pl_uids[name]
        for seqs, rule in sorted((pl.get("rule") or {}).items(), key=lambda kv: int(kv[0])):
            seq = int(seqs)
            prefix = rule.get("prefix")
            ge, le = rule.get("ge"), rule.get("le")
            min_len, max_len = _prefix_list_range(prefix, ge, le)
            eu = uid.prefix_list_entry(pu, seq)
            b.node(
                "PrefixListEntry",
                eu,
                seq=seq,
                action=rule.get("action"),
                prefix=prefix,
                ge=ge,
                le=le,
                min_len=min_len,
                max_len=max_len,
            )
            b.rel("HAS_RULE", "RoutePolicy", pu, "PrefixListEntry", eu)

    for name, rm in route_maps.items():
        pu = rm_uids[name]
        for seqs, rule in sorted((rm.get("rule") or {}).items(), key=lambda kv: int(kv[0])):
            seq = int(seqs)
            eu = uid.route_policy_entry(pu, seq)
            match = rule.get("match") or {}
            set_ = rule.get("set") or {}
            pl_names = listify(((match.get("ip") or {}).get("address") or {}).get("prefix-list"))
            as_path_names = listify(match.get("as-path"))
            community_names = listify((match.get("community") or {}).get("community-list"))
            comm_set = set_.get("community") or {}
            comm_add, comm_replace = comm_set.get("add"), comm_set.get("replace")
            communities = listify(comm_add if comm_add is not None else comm_replace)
            comm_list = set_.get("comm-list") or {}
            comm_delete = comm_set.get("delete") or (
                comm_list.get("comm-list") if "delete" in comm_list else None
            )
            set_unsupported = _unread_lines(set_, "set", _READ_SET_PATHS)
            if comm_list and "delete" not in comm_list:
                set_unsupported.append(f"set comm-list comm-list {comm_list.get('comm-list')}")
            local_pref = set_.get("local-preference")
            if local_pref is not None and _int_or_none(local_pref) is None:
                set_unsupported.append(f"set local-preference {local_pref}")
                local_pref = None
            metric = set_.get("metric")
            if metric is not None and _int_or_none(metric) is None:
                set_unsupported.append(f"set metric {metric}")
                metric = None
            prepend = [t for v in listify((set_.get("as-path") or {}).get("prepend")) for t in str(v).split()]
            if not all(t.isdigit() for t in prepend):
                set_unsupported.append("set as-path prepend " + " ".join(prepend))
                prepend = []
            tags = [t for t in (_int_or_none(v) for v in listify(match.get("tag"))) if t is not None]
            match_unsupported = _unread_match_lines(match)
            if len(tags) != len(listify(match.get("tag"))):
                match_unsupported.append(f"match tag {match.get('tag')}")
            match_metric = _int_or_none(match.get("metric"))
            if match.get("metric") is not None and match_metric is None:
                match_unsupported.append(f"match metric {match['metric']}")
            call = rule.get("call")
            continue_raw = rule.get("continue")
            b.node(
                "RoutePolicyEntry",
                eu,
                seq=seq,
                kind="clause",
                action=rule.get("action"),
                continues=continue_raw is not None,
                continue_seq=int(continue_raw) if continue_raw not in (None, "") else None,
                match_prefix_lists=pl_names or None,
                match_as_path_lists=as_path_names or None,
                match_community_lists=community_names or None,
                match_tags=tags or None,
                match_metric=match_metric,
                match_unsupported=match_unsupported or None,
                set_unsupported=set_unsupported or None,
                set_local_pref=local_pref,
                set_metric=metric,
                set_as_path_prepend=prepend or None,
                set_communities=communities or None,
                set_communities_additive=(comm_add is not None) if communities else None,
                set_comm_list_delete=comm_delete,
                calls_policy=call,
            )
            b.rel("HAS_RULE", "RoutePolicy", pu, "RoutePolicyEntry", eu)
            refs = {
                "match_community_lists": community_names,
                "match_as_path_lists": as_path_names,
                "set_comm_list_delete": comm_delete,
            }
            for list_kind, list_name in list_references(refs):
                target = list_uids.get((list_kind, list_name))
                if target:
                    b.rel("REFERENCES", "RoutePolicyEntry", eu, "RoutePolicy", target, kind=list_kind)
                else:
                    logger.warning(
                        "vyos: route-map %r rule %s: undefined %s %r referenced",
                        name,
                        seq,
                        list_kind,
                        list_name,
                    )
            for pln in pl_names:
                target = pl_uids.get(pln)
                if target:
                    b.rel("REFERENCES", "RoutePolicyEntry", eu, "RoutePolicy", target, kind="prefix-list")
                else:
                    logger.warning(
                        "vyos: route-map %r rule %s: undefined prefix-list %r referenced", name, seq, pln
                    )
            if call:
                target = rm_uids.get(call)
                if target:
                    b.rel("REFERENCES", "RoutePolicyEntry", eu, "RoutePolicy", target, kind="call")
                else:
                    logger.warning("vyos: route-map %r rule %s: call to undefined policy %r", name, seq, call)

    return pl_uids, rm_uids


def _next_hop_self(neighbor: dict[str, Any], group: dict[str, Any] | None) -> str | None:
    """Return the `address-family ipv4-unicast nexthop-self [force]` setting of
    the neighbor, or of its peer group when the neighbor sets none.

    The value is `all` with `force` (reflected routes too), `ebgp` without
    `force`, and None when neither configures it."""
    for node in (neighbor, group):
        setting = (((node or {}).get("address-family") or {}).get("ipv4-unicast") or {}).get("nexthop-self")
        if setting is not None:
            return "all" if "force" in (setting or {}) else "ebgp"
    return None


def _bgp_stage(
    b: GraphBuilder,
    bgp_cfg: dict[str, Any] | None,
    dev: str,
    vrf_name: str,
    vrf_uid: str,
    l3dom: str,
    pl_uids: dict[str, str],
    rm_uids: dict[str, str],
    observed_as: dict[tuple[str, str], int] | None = None,
    peer_rids: dict[tuple[str, str], str] | None = None,
    peers: Iterable[tuple[str, str]] = (),
) -> None:
    """A neighbor with no resolvable peer_asn is skipped with a warning."""
    if not bgp_cfg:
        return
    asn_raw = bgp_cfg.get("system-as") or bgp_cfg.get("local-as")
    legacy_asn = next((str(key) for key in bgp_cfg if str(key).isdigit()), None)
    if not asn_raw and legacy_asn is not None:
        # VyOS 1.3 `protocols bgp <asn>` gets its ASN and a session gap.
        ru = uid.routing_process(dev, vrf_name, "bgp")
        b.node(
            "RoutingProcess",
            ru,
            proto="bgp",
            asn=int(legacy_asn),
            session_gaps=[
                f"VyOS 1.3 'protocols bgp {legacy_asn}' configuration not read: "
                "its neighbors, policies and networks are unknown"
            ],
        )
        b.rel("IN_VRF", "RoutingProcess", ru, "VrfInstance", vrf_uid)
        logger.warning("vyos: VyOS 1.3 protocols bgp %s on vrf %r not read", legacy_asn, vrf_name)
        return
    if not asn_raw:
        logger.warning("vyos: protocols bgp on vrf %r has no system-as/local-as; skipping", vrf_name)
        return
    asn = int(asn_raw)
    params = bgp_cfg.get("parameters") or {}
    address_families = bgp_cfg.get("address-family") or {}
    unicast = [
        (4, address_families.get("ipv4-unicast") or {}),
        (6, address_families.get("ipv6-unicast") or {}),
    ]
    redistribute = sorted(
        {str(protocol) for _af, family in unicast for protocol in (family.get("redistribute") or {})}
    )
    ru = uid.routing_process(dev, vrf_name, "bgp")
    b.node(
        "RoutingProcess",
        ru,
        proto="bgp",
        asn=asn,
        router_id=params.get("router-id"),
        # The no-policy eBGP default is permit on VyOS unless the device opts into RFC 8212 enforcement here.
        ebgp_requires_policy="ebgp-requires-policy" in params,
        redistribute_protocols=redistribute,
        # `parameters always-compare-med` compares the MED across neighbouring
        # ASes (FRR `bgp always-compare-med`).
        always_compare_med=True if "always-compare-med" in params else None,
        # The multipath settings come from `address-family <family> maximum-paths
        # ebgp|ibgp N` and `parameters bestpath as-path multipath-relax` (FRR
        # `maximum-paths`, `bgp bestpath as-path multipath-relax`).
        **bgp_multipath_props(
            {
                f"{kind}_v{family_af}": count
                for family_af, family in unicast
                for kind, value in ((family.get("maximum-paths") or {}).items())
                if kind in ("ebgp", "ibgp") and (count := as_int(value)) is not None and count >= 1
            },
            "multipath-relax" in ((params.get("bestpath") or {}).get("as-path") or {}),
        ),
        origin_config_recorded=True,
        origin_afs=[4, 6],
        # VyOS documents an absent `network-import-check` as disabled. A network
        # is advertised without a RIB route unless the parameter is configured.
        network_import_check="network-import-check" in params,
    )
    b.rel("IN_VRF", "RoutingProcess", ru, "VrfInstance", vrf_uid)

    def configured_prefixes(value: Any) -> list[str]:
        if isinstance(value, dict):
            return [str(prefix) for prefix in value]
        return [str(prefix) for prefix in listify(value)]

    for _family_af, family in unicast:
        for cidr in configured_prefixes(family.get("network") or {}):
            net = ipaddress.ip_network(cidr, strict=False)
            # A connected subnet keeps its connected kind. The ORIGINATES edge
            # holds the origination, keyed by proto beside the connected edge.
            pu = uid.prefix(vrf_uid, str(net))
            b.node(
                "Prefix",
                pu,
                cidr=str(net),
                af=net.version,
                kind=None if b.props("Prefix", pu) else "bgp-network",
                anchor=vrf_uid,
                l3dom=l3dom,
            )
            b.rel(
                "ORIGINATES", "VrfInstance", vrf_uid, "Prefix", pu, key={"proto": "network"}, proto="network"
            )
        for cidr in configured_prefixes(family.get("aggregate-address") or {}):
            net = ipaddress.ip_network(cidr, strict=False)
            # A connected subnet keeps its connected kind. The ORIGINATES edge
            # holds the origination, keyed by proto beside the connected edge.
            pu = uid.prefix(vrf_uid, str(net))
            b.node(
                "Prefix",
                pu,
                cidr=str(net),
                af=net.version,
                kind=None if b.props("Prefix", pu) else "aggregate",
                anchor=vrf_uid,
                l3dom=l3dom,
            )
            b.rel(
                "ORIGINATES",
                "VrfInstance",
                vrf_uid,
                "Prefix",
                pu,
                key={"proto": "aggregate"},
                proto="aggregate",
            )

    # The configured neighbors that get no BgpSession. The process holds them
    # as session gaps.
    session_gaps: list[str] = []
    for net, group_name in _listen_ranges(bgp_cfg):
        # A BgpPeerRange is the passive definition, as the Cisco collectors
        # write it (`cisco_bgp.emit_bgp_peer`).
        range_uid = b.node(
            "BgpPeerRange",
            uid.bgp_peer_range(ru, str(net), vrf_name),
            prefix=str(net),
            local_asn=asn,
            peer_group=group_name,
        )
        b.rel("HAS", "RoutingProcess", ru, "BgpPeerRange", range_uid)
    for peer_ip, neighbor in bgp_neighbors(bgp_cfg, vrf_name, peers).items():
        remote_as = _neighbor_remote_as(bgp_cfg, neighbor, (observed_as or {}).get((vrf_name, peer_ip)))
        if remote_as is None:
            logger.warning(
                "vyos: bgp neighbor %r on vrf %r has no resolvable remote-as (%r); skipping",
                peer_ip,
                vrf_name,
                _neighbor_leaf(bgp_cfg, neighbor, "remote-as"),
            )
            session_gaps.append(f"neighbor {peer_ip} has no resolvable remote-as")
            continue

        su = uid.bgp_session(ru, peer_ip, vrf_name)
        # A member takes every address family and policy that its peer-group
        # states and the member does not (`_neighbor_leaf`).
        group = (bgp_cfg.get("peer-group") or {}).get(str(neighbor.get("peer-group") or "")) or {}
        afs = list(
            dict.fromkeys([*(neighbor.get("address-family") or {}), *(group.get("address-family") or {})])
        )

        def policy(kind: str, direction: str, neighbor: dict[str, Any] = neighbor) -> Any:
            return _neighbor_leaf(bgp_cfg, neighbor, "address-family", "ipv4-unicast", kind, direction)

        # The peer-group that the neighbor names. Two settings are also read from
        # it, route-reflector-client and an AS-path filter-list.
        group_name = neighbor.get("peer-group")
        ipv4u = (neighbor.get("address-family") or {}).get("ipv4-unicast") or {}
        group_ipv4u = (group.get("address-family") or {}).get("ipv4-unicast") or {}
        flist = {**(group_ipv4u.get("filter-list") or {}), **(ipv4u.get("filter-list") or {})}
        if "route-reflector-client" in ipv4u or "route-reflector-client" in group_ipv4u:
            reflector_client: bool | None = True
        else:
            # An undefined peer-group could state the setting. The value is None.
            defined = str(group_name) in (bgp_cfg.get("peer-group") or {})
            reflector_client = None if group_name and not defined else False

        dynamic_range = neighbor.get(_DYNAMIC_RANGE)
        session_props: dict[str, Any] = {
            "local_asn": asn,
            "peer_asn": remote_as,
            "peer_ip": peer_ip,
            # The listen range that accepted a dynamic peer.
            "dynamic_range": dynamic_range,
            "afi_safi": afs or None,
            "peer_group": neighbor.get("peer-group"),
            "route_reflector_client": reflector_client,
            # `parameters cluster-id`, the process's cluster id when it reflects
            "cluster_id": parse_cluster_id(params.get("cluster-id")),
            # The router id of the peer as `show ip bgp vrf all neighbors json`
            # reports it, or None.
            "peer_router_id": (peer_rids or {}).get(neighbor_key(vrf_name, peer_ip)),
            # An AS-path filter-list. The engine does not evaluate it.
            "import_filter_list_name": flist.get("import"),
            "export_filter_list_name": flist.get("export"),
            "next_hop_self": _next_hop_self(
                neighbor, (bgp_cfg.get("peer-group") or {}).get(neighbor.get("peer-group"))
            ),
        }
        filtered_by: dict[str, str] = {}
        for direction in ("import", "export"):
            rm_name, pl_name = policy("route-map", direction), policy("prefix-list", direction)
            name = kind = target = None
            if rm_name:
                # A prefix-list beside a route-map is kept as `<direction>_prefix_list_name`.
                name, kind, target = rm_name, "route-map", rm_uids.get(rm_name)
                if target is None:
                    logger.warning(
                        "vyos: bgp neighbor %r %s route-map %r is undefined", peer_ip, direction, rm_name
                    )
                if pl_name:
                    session_props[f"{direction}_prefix_list_name"] = pl_name
                    if pl_target := pl_uids.get(pl_name):
                        filtered_by[f"{direction}-prefix-list"] = pl_target
                    else:
                        logger.warning(
                            "vyos: bgp neighbor %r %s prefix-list %r is undefined",
                            peer_ip,
                            direction,
                            pl_name,
                        )
            elif pl_name:
                name, kind, target = pl_name, "prefix-list", pl_uids.get(pl_name)
                if target is None:
                    logger.warning(
                        "vyos: bgp neighbor %r %s prefix-list %r is undefined", peer_ip, direction, pl_name
                    )
            session_props[f"{direction}_policy_name"] = name
            session_props[f"{direction}_policy_kind"] = kind
            if target:
                filtered_by[direction] = target

        b.node("BgpSession", su, **session_props)
        b.rel("HAS", "RoutingProcess", ru, "BgpSession", su)
        if dynamic_range:
            b.rel(
                "MEMBER_OF", "BgpSession", su, "BgpPeerRange", uid.bgp_peer_range(ru, dynamic_range, vrf_name)
            )
        # The address is anchored on the session's own VRF.
        peer_uid = b.node(
            "IpAddress", uid.ip(vrf_uid, peer_ip), ip=peer_ip, af=_af(peer_ip), l3dom=l3dom, anchor=vrf_uid
        )
        b.rel("ENDPOINT", "BgpSession", su, "IpAddress", peer_uid)
        for direction, target in filtered_by.items():
            # A prefix-list beside the route-map has its own key. The
            # `direction: 'in'` edge stays the session policy.
            d = direction.replace("import", "in").replace("export", "out")
            b.rel(
                "FILTERED_BY",
                "BgpSession",
                su,
                "RoutePolicy",
                target,
                key={"direction": d},
                direction=d,
            )
    if session_gaps:
        b.node("RoutingProcess", ru, session_gaps=session_gaps)


def _carrier_egress_interface(
    rib: _RibRead, target: ipaddress.IPv4Address | ipaddress.IPv6Address
) -> str | None:
    """Return the egress interface of the longest main-table prefix that holds
    `target`, or None.

    The main table has the label "main" or "254".
    """
    index = rib.egress_index
    if not index.get(_INDEXED):
        index.update(_egress_index(rib.entries))
    address = int(target)
    width = target.max_prefixlen
    for plen in range(width, -1, -1):
        by_network = index.get((target.version, plen))
        if by_network:
            network = address >> (width - plen) << (width - plen)
            if (egress := by_network.get(network)) is not None:
                return egress
    return None


# The key that marks a built `_RibRead.egress_index` (`_carrier_egress_interface`).
_INDEXED = (0, -1)


def _egress_index(entries: Iterable[_RibEntry]) -> dict[tuple[int, int], dict[int, str]]:
    """The first row of a prefix in listing order wins."""
    index: dict[tuple[int, int], dict[int, str]] = {_INDEXED: {}}
    for row in entries:
        if row.table not in ("main", "254") or not row.interface:
            continue
        try:
            net = ipaddress.ip_network(row.cidr)
        except ValueError:
            continue
        if net.version != row.af:
            continue
        index.setdefault((net.version, net.prefixlen), {}).setdefault(
            int(net.network_address), str(row.interface)
        )
    return index


def _interface_address_of_family(
    cfg: dict[str, Any], raw: dict[str, Any], ifname: str, af: int
) -> str | None:
    """The configured address wins over the operationally learned one."""
    for members in (cfg.get("interfaces") or {}).values():
        node = (members or {}).get(ifname)
        if node is None:
            continue
        for a in listify(node.get("address")):
            if a in ("dhcp", "dhcpv6"):
                continue
            try:
                iface = ipaddress.ip_interface(a)
            except ValueError:
                continue
            if iface.version == af:
                return str(iface.ip)
    for link in raw.get("addrs") or []:
        if link.get("ifname") != ifname:
            continue
        for ai in link.get("addr_info") or []:
            if ai.get("scope") in ("link", "host") or ai.get("temporary") or ai.get("mngtmpaddr"):
                continue
            ip = ai.get("local")
            if not ip:
                continue
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr.version == af:
                return ip
    return None


def _derive_wireguard_local_address(
    raw: dict[str, Any], cfg: dict[str, Any], endpoint: str | None, rib: Callable[[], _RibRead]
) -> str | None:
    if not endpoint:
        return None
    try:
        target = ipaddress.ip_address(endpoint)
    except ValueError:
        return None
    egress = _carrier_egress_interface(rib(), target)
    if not egress:
        return None
    return _interface_address_of_family(cfg, raw, egress, target.version)


def _sysfs_speed_mbps(value: str) -> int | None:
    """The speed is in Mbit/s."""
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed > 0 else None


def _sysfs_duplex(value: str) -> str | None:
    return value if value in ("full", "half") else None


def _parse_link_speeds(raw_value: Any) -> list[tuple[str, int | None, str | None]]:
    """The payload holds one `<ifname> <speed> <duplex>` line per interface."""
    if not isinstance(raw_value, str):
        return []
    rows: list[tuple[str, int | None, str | None]] = []
    for line in raw_value.splitlines():
        parts = line.split()
        if not parts:
            continue
        name = parts[0]
        speed_field = parts[1] if len(parts) > 1 else "unknown"
        duplex_field = parts[2] if len(parts) > 2 else "unknown"
        rows.append((name, _sysfs_speed_mbps(speed_field), _sysfs_duplex(duplex_field)))
    return rows


def _vyos_configured_speed_mbps(value: Any) -> int | None:
    """Return the fixed speed in Mbit/s of `interfaces ethernet <if> speed`.

    A numeric string fixes the speed. `auto`, the default, gives None.
    """
    if not isinstance(value, str):
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _vyos_configured_duplex(value: Any) -> str | None:
    """Return the fixed duplex of `interfaces ethernet <if> duplex`.

    `full` and `half` fix the duplex. `auto`, the default, gives None.
    """
    return value if value in ("full", "half") else None


def _tunnel_connection(
    b: GraphBuilder,
    technology: str,
    tunnel: str,
    *,
    dev: str,
    host: str,
    ifname: str,
    if_uid: str,
    local: Any,
    remote: Any,
    vrf_uid: str,
    l3dom: str,
    peer: str | None = None,
    local_port: Any = None,
    remote_port: Any = None,
    key: Any = None,
) -> str | None:
    """Write the `OverlayConnection` that one VyOS tunnel realizes and return
    its uid, or None.

    The far end of a VyOS tunnel is an address. With the local and the remote
    address known, the connection key is the 2 addresses, with the WireGuard
    ports when both are configured. The far router computes the same key from
    its own configuration, and the 2 ends of one tunnel write one connection.
    When `remote` is an address, the far end is an `IpAddress` in the local
    default table, the table that routes the outer packet. Without one of the
    2 addresses, the key of the near end is the uid of the local tunnel
    interface, and the name holds the interface. A tunnel with neither a
    remote address nor a peer name has no connection. `key` is a GRE key. Both
    ends configure it alike, and it tells apart 2 tunnels between the same 2
    addresses."""
    try:
        far_ip = str(ipaddress.ip_address(str(remote))) if remote else None
    except ValueError:
        far_ip = None
    if local and remote:
        near_key, far_key = str(local), str(remote)
        if local_port not in (None, "") and remote_port not in (None, ""):
            near_key, far_key = f"{near_key}:{local_port}", f"{far_key}:{remote_port}"
        if key not in (None, ""):
            near_key, far_key = f"{near_key}~key{key}", f"{far_key}~key{key}"
        name = f"{host} to {remote}"
    elif remote or peer:
        near_key, far_key = if_uid, str(remote or peer)
        name = f"{host} {ifname} to {remote or peer}"
    else:
        return None
    far_uid = None
    if far_ip:
        far_uid = b.node(
            "IpAddress", uid.ip(vrf_uid, far_ip), ip=far_ip, af=_af(far_ip), l3dom=l3dom, anchor=vrf_uid
        )
    return overlay_connection(
        b,
        technology,
        (
            OverlayEnd(near_key, "Device", dev, "peer", reported=True),
            OverlayEnd(far_key, "IpAddress" if far_uid else None, far_uid, "peer"),
        ),
        [tunnel],
        name=name,
    )


def _member_names(node: Any) -> list[str]:
    """Return the interfaces that `member interface` names under a bond or a bridge.

    Under a bond, the value is a multi leaf (a list, or a str for one name).
    Under a bridge, the value is a tag node (a mapping).
    """
    members = ((node if isinstance(node, dict) else {}).get("member") or {}).get("interface")
    if isinstance(members, dict):
        return [str(name) for name in members]
    return [str(name) for name in listify(members)]


def _vlan_id(value: Any) -> int | None:
    vid = as_int(value)
    return vid if vid is not None and 1 <= vid <= 4094 else None


def _allowed_vlans(value: Any, existing: set[int]) -> set[int]:
    """Return the VLAN ids that the `allowed-vlan` values of a bridge member
    name (`10`, `20-30`) and that the bridge has as a vif.

    As with an NX-OS trunk range (`nxos.expand_vlan_list`), a range holds only
    the VLANs that exist on the device."""
    out: set[int] = set()
    for item in listify(value):
        lo_text, _, hi_text = str(item).partition("-")
        lo, hi = _vlan_id(lo_text), _vlan_id(hi_text or lo_text)
        if lo is not None and hi is not None and lo <= hi:
            out.update(vid for vid in existing if lo <= vid <= hi)
    return out


def _membership_stage(
    b: GraphBuilder, cfg: dict[str, Any], dev: str, l2fabric: str, if_uids: dict[str, str]
) -> None:
    """Write bond and bridge membership.

    A bond is a Lag that realizes its interface, with a configured MEMBER_OF
    from each member Port, as the Cisco collectors write it (`cisco_common` mtu
    memberships). The Lag also realizes each vif of the bond, and each member
    Port CARRIES the VLAN of the vif, as the Port under an ethernet vif does. A
    bridge member CARRIES its `native-vlan` natively and its `allowed-vlan`
    tagged, limited to the VLANs that the bridge has a vif for. A member that
    is a bond CARRIES them on each member Port. A bridge with no VLAN settings
    writes no membership."""
    interfaces = cfg.get("interfaces") or {}
    eth_ports = set(interfaces.get("ethernet") or {})
    ports_of: dict[str, list[str]] = {}
    for name, node in (interfaces.get("bonding") or {}).items():
        node = node if isinstance(node, dict) else {}
        members = [m for m in _member_names(node) if m in eth_ports]
        ports_of[name] = members
        lu = b.node("Lag", uid.lag(dev, name), name=name, mode=node.get("mode"))
        b.rel("ON", "Lag", lu, "Device", dev)
        b.rel("REALIZED_BY", "Interface", if_uids[name], "Lag", lu)
        for member in members:
            b.rel(
                "MEMBER_OF",
                "Port",
                uid.port(dev, member),
                "Lag",
                lu,
                state="configured",
                assertion_kind="configured",
            )
        for vid in node.get("vif") or {}:
            b.rel("REALIZED_BY", "Interface", if_uids[f"{name}.{vid}"], "Lag", lu)
            for member in members:
                b.rel(
                    "CARRIES",
                    "Port",
                    uid.port(dev, member),
                    "VlanInstance",
                    uid.vlan(dev, int(vid)),
                    native=False,
                )

    for node in (interfaces.get("bridge") or {}).values():
        node = node if isinstance(node, dict) else {}
        existing = {vid for v in node.get("vif") or {} if (vid := _vlan_id(v)) is not None}
        members = ((node.get("member") or {}).get("interface")) or {}
        for member in _member_names(node):
            options = members.get(member) if isinstance(members, dict) else None
            options = options if isinstance(options, dict) else {}
            ports = [member] if member in eth_ports else ports_of.get(member, [])
            native = _vlan_id(options.get("native-vlan"))
            carried = [(vid, False) for vid in sorted(_allowed_vlans(options.get("allowed-vlan"), existing))]
            if native is not None:
                carried.append((native, True))
            for vid, is_native in carried:
                vu = b.node("VlanInstance", uid.vlan(dev, vid), vid=vid)
                seg = b.node("BridgeDomain", uid.bridge_domain(l2fabric, vid))
                b.rel("REALIZES", "VlanInstance", vu, "BridgeDomain", seg)
                for port in ports:
                    b.rel("CARRIES", "Port", uid.port(dev, port), "VlanInstance", vu, native=is_native)


def _interface_stage(
    b: GraphBuilder,
    raw: dict[str, Any],
    cfg: dict[str, Any],
    dev: str,
    host: str,
    l2fabric: str,
    vrfs: VrfDomains,
    rib: Callable[[], _RibRead],
) -> tuple[dict[str, str], dict[str, str]]:
    """Write the ports and interfaces (VLAN subinterfaces included) with their
    configured and operational addresses, the interface MACs, the tunnels and
    the WanLinks of dynamic uplinks.

    Return a map of interface name to Interface uid and a map of interface
    name to VRF name. `rib` is read only for a WireGuard peer whose local
    address is derived."""
    vrf_uids, domain_of = vrfs.uids, vrfs.domains
    vrf = vrf_uids[DEFAULT_VRF]
    esp_groups = _ipsec_esp_groups(cfg)
    vti_peers = _ipsec_vti_peers(cfg)

    configured_ips: set[tuple[str, str]] = set()

    def add_address(if_uid: str, addr: str, origin: str = "configured", vrf_name: str = DEFAULT_VRF) -> bool:
        """Returns True when the address is a dynamic placeholder."""
        if addr in ("dhcp", "dhcpv6"):
            return True
        # Two VRFs with the same subnet stay two nodes.
        dom_name = domain_of.get(vrf_name, domain_of[DEFAULT_VRF])
        vrf_uid = vrf_uids.get(vrf_name, vrf_uids[DEFAULT_VRF])
        ipu, _ = connected_address(
            b, addr, anchor=vrf_uid, dom=dom_name, vrf_uid=vrf_uid, ip_props={"origin": origin}
        )
        b.rel("HAS_IP", "Interface", if_uid, "IpAddress", ipu)
        return False

    if_uids: dict[str, str] = {}
    if_vrf: dict[str, str] = {}

    def add_interface(name: str, node: dict, kind: str, port: str | None = None):
        iu = uid.interface(dev, name)
        if_uids[name] = iu
        b.node("Interface", iu, name=name, kind=kind, description=node.get("description"))
        b.rel("ON", "Interface", iu, "Device", dev)
        if port:
            b.rel("REALIZED_BY", "Interface", iu, "Port", port)
        # `set interfaces ethernet eth1 vrf RED`. Without `vrf`, the interface is in the global table.
        vrf_name = node.get("vrf") or DEFAULT_VRF
        if vrf_name not in vrf_uids:
            vrfs.add(vrf_name)
        if_vrf[name] = vrf_name

        dynamic = False
        addrs = listify(node.get("address"))
        # The access client installs these defaults outside `protocols static`.
        access_default = None
        if kind == "pppoe" and "no-default-route" not in node and node.get("default-route") != "none":
            access_default = "pppoe"
        elif "dhcp" in addrs and "no-default-route" not in (node.get("dhcp-options") or {}):
            access_default = "dhcp"
        b.node("Interface", iu, ipv4_default_origin=access_default)
        for a in addrs:
            dynamic = add_address(iu, a, vrf_name=vrf_name) or dynamic
            if a not in ("dhcp", "dhcpv6"):
                configured_ips.add((name, str(ipaddress.ip_interface(a).ip)))
        if addrs or access_default:
            b.rel("IN_VRF", "Interface", iu, "VrfInstance", vrf_uids[vrf_name])
        return iu, dynamic

    for iftype, members in (cfg.get("interfaces") or {}).items():
        kind = _IF_KIND.get(iftype, iftype)
        for name, node in (members or {}).items():
            port = None
            if iftype == "ethernet":
                port = b.node(
                    "Port",
                    uid.port(dev, name),
                    name=name,
                    speed_configured_mbps=_vyos_configured_speed_mbps(node.get("speed")),
                    duplex_configured=_vyos_configured_duplex(node.get("duplex")),
                )
                b.rel("ON", "Port", port, "Device", dev)
            iu, dynamic = add_interface(name, node, kind, port)
            if dynamic or iftype == "pppoe":
                wl = b.node(
                    "WanLink",
                    f"wan:{local_namespace(dev)}:{name}",
                    kind="dia",
                    name=node.get("description") or name,
                )
                b.rel("HAS_LINK", "Device", dev, "WanLink", wl)
                # The WanLink is ON the interface that the link leaves the router by.
                # The impact read uses it to tell a tunnel over this link from a
                # second circuit.
                b.rel("ON", "WanLink", wl, "Interface", iu)
            for vid, vnode in (node.get("vif") or {}).items():
                # A vif is realized by the same physical port as its parent.
                viu, _ = add_interface(f"{name}.{vid}", vnode, "subif", port)
                vu = b.node("VlanInstance", uid.vlan(dev, int(vid)), vid=int(vid))
                seg = b.node("BridgeDomain", uid.bridge_domain(l2fabric, int(vid)))
                b.rel("REALIZES", "VlanInstance", vu, "BridgeDomain", seg)
                b.rel("BOUND_TO", "Interface", viu, "VlanInstance", vu)
                if port:
                    b.rel("CARRIES", "Port", port, "VlanInstance", vu, native=False)
            # Both QinQ layers are realized by the one physical port underneath.
            for svid, snode in (node.get("vif-s") or {}).items():
                sname = f"{name}.{svid}"
                add_interface(sname, snode, "subif", port)
                for cvid, cnode in (snode.get("vif-c") or {}).items():
                    add_interface(f"{sname}.{cvid}", cnode, "subif", port)
            if iftype == "wireguard":
                for pname, peer in (node.get("peer") or {}).items():
                    configured_local = node.get("source-address")
                    if configured_local:
                        local_address, local_source = configured_local, "configured"
                    else:
                        local_address = _derive_wireguard_local_address(raw, cfg, peer.get("address"), rib)
                        local_source = "derived:egress" if local_address else None
                    tu = b.node(
                        "Tunnel",
                        # VyOS scopes a peer name to its interface, and
                        # names are case-sensitive. Peer `hq` of wg0 and peer
                        # `hq` of wg1 are 2 tunnels.
                        f"tun:wireguard:{dev}~{iface_slug(name)}~{uid.exact_slug(pname)}",
                        encap="wireguard",
                        name=pname,
                        endpoint=peer.get("address"),
                        endpoint_port=peer.get("port"),
                        carrier_proto="udp",
                        local_address=local_address,
                        local_address_source=local_source,
                        allowed_ips=listify(peer.get("allowed-ips")),
                        # The tunnel interface's own Linux MTU.
                        tunnel_mtu=_tunnel_operational_or_configured_mtu(raw, node, name),
                    )
                    b.rel("ENDPOINT", "Tunnel", tu, "Interface", if_uids[name])
                    _tunnel_connection(
                        b,
                        "wireguard",
                        tu,
                        dev=dev,
                        host=host,
                        ifname=name,
                        if_uid=if_uids[name],
                        local=local_address,
                        remote=peer.get("address"),
                        vrf_uid=vrf,
                        l3dom=domain_of[DEFAULT_VRF],
                        peer=pname,
                        local_port=node.get("port"),
                        remote_port=peer.get("port"),
                    )
            elif iftype == "tunnel" or iftype == "vti":
                esp: dict[str, Any] = {}
                local_source: str | None = None
                gre_key: Any = None
                if iftype == "vti":
                    encap, carrier_proto = "ipsec", "esp"
                    peer_info = vti_peers.get(name) or {}
                    remote = peer_info.get("remote")
                    local = peer_info.get("local")
                    esp = esp_groups.get(peer_info.get("esp_group") or "") or {}
                else:
                    encap = node.get("encapsulation")
                    carrier_proto = _TUNNEL_CARRIER_PROTO.get(encap or "")
                    # A 1.4/1.5 config has only the `remote` and `source-address` keys.
                    remote = node.get("remote") or node.get("remote-ip")
                    local = node.get("source-address") or node.get("local-ip")
                    if local:
                        local_source = "configured"
                    elif node.get("source-interface"):
                        # A tunnel bound to an interface with no source address
                        # sends from the address of that interface.
                        local = _interface_address_of_family(
                            cfg, raw, str(node["source-interface"]), _af(str(remote)) if remote else 4
                        )
                        local_source = "derived:source-interface" if local else None
                    gre_key = ((node.get("parameters") or {}).get("ip") or {}).get("key")
                if encap:
                    props: dict[str, Any] = {
                        "encap": encap,
                        "endpoint": remote,
                        "local_address": local,
                        "local_address_source": local_source,
                        "carrier_proto": carrier_proto,
                    }
                    if encap in ("gre", "gre-bridge"):
                        # VyOS's tunnel interface exposes only `parameters ip key`.
                        props["gre_key"] = bool(gre_key)
                        props["gre_checksum"] = False
                        props["gre_sequence"] = False
                    if iftype == "vti" and esp:
                        props["esp_encryption"] = esp.get("encryption")
                        props["esp_hash"] = esp.get("hash")
                        props["esp_mode"] = esp.get("mode") or "tunnel"
                        props["esp_proposals"] = canonical_json(esp.get("proposals") or [])
                    if local and remote:
                        # Both ends compute this uid from their own
                        # configuration. The GRE key tells apart 2 tunnels
                        # between the same 2 addresses.
                        tu_uid = uid.tunnel(encap, local, remote) + (f"~key{gre_key}" if gre_key else "")
                    else:
                        # Without both ends, the addresses do not identify a tunnel.
                        tu_uid = f"tun:{uid.slug(encap)}:{dev}~{iface_slug(name)}"
                    tu = b.node("Tunnel", tu_uid, **props)
                    b.rel("ENDPOINT", "Tunnel", tu, "Interface", if_uids[name])
                    _tunnel_connection(
                        b,
                        encap,
                        tu,
                        dev=dev,
                        host=host,
                        ifname=name,
                        if_uid=if_uids[name],
                        local=local,
                        remote=remote,
                        vrf_uid=vrf,
                        l3dom=domain_of[DEFAULT_VRF],
                        key=gre_key,
                    )
            elif iftype == "vxlan":
                remote = node.get("remote")
                group = node.get("group")
                local = node.get("source-address")
                tu = b.node(
                    "Tunnel",
                    uid.tunnel("vxlan", local or "", remote or group or ""),
                    encap="vxlan",
                    endpoint=remote or group,
                    local_address=local,
                    carrier_proto="udp",
                )
                b.rel("ENDPOINT", "Tunnel", tu, "Interface", if_uids[name])
                # A multicast group is the far end of a VTEP that floods to the group.
                _tunnel_connection(
                    b,
                    "vxlan",
                    tu,
                    dev=dev,
                    host=host,
                    ifname=name,
                    if_uid=if_uids[name],
                    local=local,
                    remote=remote or group,
                    vrf_uid=vrf,
                    l3dom=domain_of[DEFAULT_VRF],
                )

    _membership_stage(b, cfg, dev, l2fabric, if_uids)

    # Operationally assigned addresses from `ip -j addr show`.
    for link in raw.get("addrs") or []:
        name = link.get("ifname")
        iu = if_uids.get(name)
        if not iu:
            continue  # The config is the inventory of interfaces.
        added = False
        link_local: set[str] = set()
        for ai in link.get("addr_info") or []:
            ip = ai.get("local")
            plen = ai.get("prefixlen")
            if not ip or plen is None:
                continue
            # A route learned over the link names an IPv6 link-local address
            # as its next hop (OSPFv3, BGP over link-local, a router
            # advertisement). The address repeats across links. The interface
            # holds it in `ipv6_link_local`, and the trace finds the neighbour
            # on the egress link by it. No IpAddress node is written for it.
            if ai.get("scope") == "link" and ai.get("family") == "inet6":
                link_local.add(str(ip).split("%", 1)[0])
            # Link-local and host addresses are not reachable prefixes.
            if ai.get("scope") in ("link", "host"):
                continue
            # RFC 4941 privacy addresses are not written.
            if ai.get("temporary") or ai.get("mngtmpaddr"):
                continue
            if (name, ip) in configured_ips:
                continue
            try:
                add_address(iu, f"{ip}/{plen}", origin="dynamic", vrf_name=if_vrf.get(name, DEFAULT_VRF))
            except ValueError:
                continue
            added = True
        if link_local:
            b.node("Interface", iu, ipv6_link_local=sorted(link_local))
        if added:
            b.rel("IN_VRF", "Interface", iu, "VrfInstance", vrf_uids.get(if_vrf.get(name, DEFAULT_VRF), vrf))

    # Interface MACs from `ip -j link show` are the join key of the cabling reasoner.
    # A bond gives every member its own MAC and keeps the hardware MAC in
    # `permaddr`. The shared MAC stays on the interface of the bond.
    eth_ports = set((cfg.get("interfaces") or {}).get("ethernet") or {})
    for link in _mtu_link_rows(raw):
        name, mac = link.get("ifname"), link.get("permaddr") or link.get("address")
        if not name or not mac or name not in if_uids:
            continue
        try:
            nmac = uid.norm_mac(mac)
        except ValueError:
            continue
        b.node("Interface", if_uids[name], mac=nmac)
        if name in eth_ports:
            b.node("Port", uid.port(dev, name), mac=nmac)

    # Operational link speed and duplex from sysfs (`link_speeds`), on the Port nodes.
    for name, speed_mbps, duplex in _parse_link_speeds(raw.get("link_speeds")):
        if name not in eth_ports:
            continue
        props: dict[str, Any] = {"speed_mbps": speed_mbps, "duplex": duplex}
        if speed_mbps is not None or duplex is not None:
            props["speed_source"] = f"vyos:/sys/class/net/{name}/speed"
        b.node("Port", uid.port(dev, name), **props)
    return if_uids, if_vrf


def _mtu_link_rows(raw: dict[str, Any]) -> list[dict[str, Any]]:
    value = raw.get("links")
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def _tunnel_operational_or_configured_mtu(raw: dict[str, Any], node: dict[str, Any], name: str) -> int | None:
    """Return the operational MTU of the WireGuard interface from `ip -j link`,
    or the configured MTU when the operational read has none."""
    for link in _mtu_link_rows(raw):
        if link.get("ifname") == name:
            value = link.get("mtu")
            if isinstance(value, int):
                return value
            break
    configured = node.get("mtu")
    if isinstance(configured, int):
        return configured
    if isinstance(configured, str) and configured.strip().isdigit():
        return int(configured.strip())
    return None


def _emit_port_frame_ceiling(
    b: GraphBuilder,
    dev: str,
    source: str,
    name: str,
    link: dict[str, Any],
    *,
    failed: bool,
    conflict: bool,
) -> None:
    """The frame size is the Linux netdevice MTU plus 14 bytes of Ethernet header."""
    value = link.get("mtu")
    mtu = value if isinstance(value, int) else None
    ok = mtu is not None and not failed
    frame = mtu + 14 if ok else None
    gaps = []
    if not ok:
        gaps.append("MTU_NOT_CAPTURED")
    if conflict:
        gaps.append("MTU_SOURCE_CONFLICT")
    emit_observation(
        b,
        "Port",
        observation_from_raw(
            subject_uid=uid.port(dev, name),
            source=f"vyos:{source}",
            source_target=dev,
            source_field=f"links.ifname={name}.mtu",
            raw_value=frame,
            profile_id="ethernet_frame_excluding_fcs",
            metric="l2_max_frame_bytes",
            direction="both",
            bound_kind="ceiling",
            enforcement="l2",
            enforcement_key="netdevice",
            assertion_kind="operational",
            resolution_state="conflict" if conflict else "unknown" if not ok else "explicit",
            collector_version=MTU_NORMALIZATION_VERSION,
            raw_evidence_ref="ip -j link show",
            tag_accounting="extra_allowance",
            tag_allowance_bytes=4,
            selector_json=canonical_json(
                {
                    "version": 1,
                    "source_profile": "vyos_linux_netdevice_frame_v1",
                    "profile_validation": "documentation_only",
                    "derivation": "mtu_plus_ethernet_header",
                }
            ),
            gaps=gaps,
        ),
    )


def _mtu_stage(
    b: GraphBuilder,
    raw: dict[str, Any],
    cfg: dict[str, Any],
    dev: str,
    source: str,
    if_uids: dict[str, str],
) -> None:
    """Netdevice MTU excludes link headers for all IP families."""
    configured: dict[str, tuple[dict[str, Any], str, str, str | None]] = {}
    for kind, members in (cfg.get("interfaces") or {}).items():
        for name, node in (members or {}).items():
            configured[name] = (node, kind, f"config.interfaces.{kind}.{name}.mtu", None)
            for vid, child in (node.get("vif") or {}).items():
                child_name = f"{name}.{vid}"
                configured[child_name] = (
                    child,
                    "subif",
                    f"config.interfaces.{kind}.{name}.vif.{vid}.mtu",
                    name,
                )

            for svid, snode in (node.get("vif-s") or {}).items():
                sname = f"{name}.{svid}"
                prefix = f"config.interfaces.{kind}.{name}.vif-s.{svid}"
                configured[sname] = (snode, "subif", f"{prefix}.mtu", name)
                for cvid, cnode in (snode.get("vif-c") or {}).items():
                    configured[f"{sname}.{cvid}"] = (cnode, "subif", f"{prefix}.vif-c.{cvid}.mtu", sname)

    rows: dict[str, list[dict[str, Any]]] = {}
    for row in _mtu_link_rows(raw):
        name = row.get("ifname")
        if isinstance(name, str):
            rows.setdefault(name, []).append(row)
    outcomes = effective_outcomes(raw, {})

    def reference(value: Any) -> str | None:
        return if_uids.get(value) if isinstance(value, str) else None

    for name, subject in if_uids.items():
        node, kind, field, parent = configured[name]
        candidates = rows.get(name, [])
        link = candidates[0] if len(candidates) == 1 else {}
        # More than one row for one kernel name is a conflict.
        conflict = len(candidates) > 1
        # A parent in a foreign namespace (`link_index`/`link_netnsid`) is not resolved.
        foreign_parent = "link_netnsid" in link or "link_index" in link
        operational_parent = reference(link.get("link")) if not foreign_parent else None
        parent_uid = None if foreign_parent else operational_parent or reference(parent)
        master_uid = reference(link.get("master"))
        members = (node.get("member") or {}).get("interface") or []
        member_names = list(members) if isinstance(members, dict) else listify(members)
        configured_members = sorted({if_uids[m] for m in member_names if isinstance(m, str) and m in if_uids})
        selector = {
            "version": 1,
            "source_profile": "vyos_linux_netdevice_v1",
            "profile_validation": "documentation_only",
            "interface_kind": kind,
            "configured_tag_depth": 2 if ".vif-c." in field else 1 if parent else None,
            "qinq_carriage_unmodeled": ".vif-s." in field,
            "parent_subject_uid": parent_uid,
            "configured_parent_subject_uid": reference(parent),
            "operational_parent_subject_uid": operational_parent,
            "parent_namespace": "external_unresolved" if foreign_parent else "local",
            "master_subject_uid": master_uid,
            "configured_member_uids": configured_members[:16],
            "member_list_truncated": len(configured_members) > 16,
            "member_eligibility": "unknown",
            "parent_resolution": "resolved" if parent_uid else "not_captured",
        }
        info = link.get("linkinfo")
        if isinstance(info, dict) and isinstance(info.get("info_kind"), str):
            selector["kernel_link_kind"] = info["info_kind"][:64]
        for key in ("operstate", "link_type"):
            if isinstance(link.get(key), str):
                selector[key] = link[key][:64]

        def emit(
            value: Any,
            assertion: str,
            source_field: str,
            context: dict[str, Any],
            *,
            ambiguous: bool = False,
            subject: str = subject,
            kind: str = kind,
        ):
            state = outcomes.get("config" if assertion == "configured" else "links")
            legacy_error = assertion == "operational" and bool(raw.get("links_error"))
            failed = (state is not None and state.status != "ok") or legacy_error
            missing = value is None
            scalar = (
                value
                if isinstance(value, (str, int, float, bool)) or value is None
                else canonical_json(value)
            )
            if isinstance(scalar, float) and not math.isfinite(scalar):
                scalar = str(scalar)
            # A string value is cut to 512 characters.
            if isinstance(scalar, str):
                scalar = scalar[:512]
            gaps = []
            if failed or missing:
                gaps.append("MTU_NOT_CAPTURED")
            if ambiguous:
                gaps.append("MTU_SOURCE_CONFLICT")
            if context["member_list_truncated"] or context["qinq_carriage_unmodeled"]:
                gaps.append("MTU_PATH_COVERAGE_INCOMPLETE")
            if context["parent_namespace"] == "external_unresolved":
                gaps.append("MTU_PATH_COVERAGE_INCOMPLETE")
            context = {
                **context,
                "section_outcome": state.status
                if state
                else "legacy_failed"
                if legacy_error
                else "legacy_unrecorded",
                "command": READ_COMMANDS["config" if assertion == "configured" else "links"],
            }
            for af in (4, 6):
                # An interface MTU caps the frame size in both directions.
                obs = observation_from_raw(
                    subject_uid=subject,
                    source=f"vyos:{source}",
                    source_target=dev,
                    source_field=source_field,
                    raw_value=scalar,
                    profile_id="ip_packet",
                    metric=f"ipv{af}_mtu_bytes",
                    direction="both",
                    bound_kind="ceiling",
                    enforcement="tunnel" if kind in {"wireguard", "tunnel", "vti", "vxlan"} else "l3",
                    enforcement_key="netdevice",
                    assertion_kind=assertion,
                    resolution_state="conflict" if ambiguous else "unknown" if failed else "explicit",
                    collector_version=MTU_NORMALIZATION_VERSION,
                    raw_evidence_ref=source_field,
                    selector_json=canonical_json(context),
                    gaps=gaps,
                )
                emit_observation(b, "Interface", obs)
            # No read establishes the IPv6 protocol limit.
            if assertion == "operational":
                emit_observation(
                    b,
                    "Interface",
                    observation_from_raw(
                        subject_uid=subject,
                        source=f"vyos:{source}",
                        source_target=dev,
                        source_field="ipv6_protocol_mtu:not_captured",
                        raw_value=None,
                        metric="ipv6_mtu_bytes",
                        direction="tx",
                        bound_kind="ceiling",
                        enforcement="l3",
                        enforcement_key="ipv6_protocol",
                        assertion_kind="operational",
                        collector_version=MTU_NORMALIZATION_VERSION,
                        selector_json=canonical_json(context),
                        gaps=["MTU_NOT_CAPTURED"],
                    ),
                )

        if "mtu" in node:
            emit(node["mtu"], "configured", field, selector)
        if "mtu" in link or conflict or "links" in outcomes or "links_error" in raw:
            emit(link.get("mtu"), "operational", f"links.ifname={name}.mtu", selector, ambiguous=conflict)

        if kind == "ethernet":
            links_state = outcomes.get("links")
            links_failed = (links_state is not None and links_state.status != "ok") or bool(
                raw.get("links_error")
            )
            _emit_port_frame_ceiling(b, dev, source, name, link, failed=links_failed, conflict=conflict)


def _route_stage(
    b: GraphBuilder,
    cfg: dict[str, Any],
    dev: str,
    vrfs: VrfDomains,
    if_uids: dict[str, str],
    rib_graph_max_routes: int,
    rib: Callable[[], _RibRead],
    rib_read: frozenset[str] = frozenset(),
) -> dict[str, str]:
    """Write the static routes (main table, policy tables, per VRF) and the
    learned routes of the FRR RIB.

    Return a map of policy-table number to VrfInstance uid for `_pbr`.

    `rib_read` names the RIB sections whose read succeeded
    (`_rib_sections_read`). Each VrfInstance of the device gets `rib_mirrored`.
    True means that the graph holds the whole RIB of that table. The tracer
    then reads a forwarding static there without `rib_confirmed` as not
    installed. The value is True only when 5 conditions hold. Every read that
    feeds the table succeeded and has a shape that the read knows (`routes`
    and `routes6`, or the 2 reads of a declared policy table). No row of those
    reads is filed under another table, and no row of another read is filed
    under this table. The table holds at most `rib_graph_max_routes` rows.
    Every family that the configuration routes statically in the table has at
    least one row there. Every `static` row of the table for a prefix that the
    configuration declares was folded onto its config static.

    Every other VrfInstance is written False. The load merges properties, and
    False replaces a value that an earlier load wrote."""
    vrf_uids, domain_of = vrfs.uids, vrfs.domains
    vrf = vrf_uids[DEFAULT_VRF]
    default_dom = domain_of[DEFAULT_VRF]

    # Static routes of the main table and of the policy tables (`protocols static
    # table N`). Each table is its own routing instance, and PBR rules redirect
    # into the policy tables. `route6` is the IPv6 tree with the layout of `route`.
    static = (cfg.get("protocols") or {}).get("static") or {}
    static_seen: set[tuple[str, str, str | None, str | None]] = set()
    _static_routes(b, default_dom, vrf, if_uids, static.get("route"), static_seen, vrf_uid_of=vrf_uids)
    _static_routes(b, default_dom, vrf, if_uids, static.get("route6"), static_seen, vrf_uid_of=vrf_uids)
    table_uids: dict[str, str] = {}
    for tnum, t in (static.get("table") or {}).items():
        tu = b.node("VrfInstance", f"vrf:{dev}:table{tnum}", name=f"table{tnum}", kind="policy-table")
        b.rel("OWNED_BY", "VrfInstance", tu, "Device", dev)
        table_uids[str(tnum)] = tu
        _static_routes(b, default_dom, tu, if_uids, (t or {}).get("route"), static_seen, vrf_uid_of=vrf_uids)
        _static_routes(b, default_dom, tu, if_uids, (t or {}).get("route6"), static_seen, vrf_uid_of=vrf_uids)

    # Routes inside a VRF resolve in that VRF's domain.
    for vname, vnode in ((cfg.get("vrf") or {}).get("name") or {}).items():
        vstatic = ((vnode or {}).get("protocols") or {}).get("static") or {}
        _static_routes(
            b,
            domain_of[vname],
            vrf_uids[vname],
            if_uids,
            vstatic.get("route"),
            static_seen,
            vrf_uid_of=vrf_uids,
        )
        _static_routes(
            b,
            domain_of[vname],
            vrf_uids[vname],
            if_uids,
            vstatic.get("route6"),
            static_seen,
            vrf_uid_of=vrf_uids,
        )

    # The FRR RIB holds every learned route that the config does not show (the
    # PPPoE/DHCP default, protocol-installed routes). Its tables map onto the
    # VrfInstance nodes of the config. The learned and the static routes of a
    # table share one VrfInstance.
    vrf_tables = {
        str((vnode or {}).get("table")): vname
        for vname, vnode in ((cfg.get("vrf") or {}).get("name") or {}).items()
        if (vnode or {}).get("table")
    }

    def table_vrf(label: str) -> tuple[str, str] | None:
        if label in ("main", "254"):
            return vrf, default_dom
        # VyOS never populates kernel table 253 ("default").
        if label in ("default", "253"):
            return None
        if label in vrf_tables:
            name = vrf_tables[label]
            return vrf_uids[name], domain_of[name]
        if label not in table_uids:
            table_uids[label] = b.node(
                "VrfInstance", f"vrf:{dev}:table{label}", name=f"table{label}", kind="policy-table"
            )
            b.rel("OWNED_BY", "VrfInstance", table_uids[label], "Device", dev)
        return table_uids[label], default_dom

    declared = frozenset(table_uids)
    read = rib()
    unfolded = _learned_routes(
        b, read, if_uids, table_vrf, static_seen, rib_graph_max_routes, vrf_uid_of=vrf_uids
    )
    sections = read.sections or {}

    def sources(label: str) -> tuple[str, str]:
        # The reads that hold the rows of a table. A declared policy table has
        # its own 2 reads. Every other table has the `vrf all` answer of each family.
        if label in declared:
            return f"routes_table_{label}", f"routes6_table_{label}"
        return "routes", "routes6"

    mirrored: set[str] = set()
    partial: set[str] = set(unfolded)
    # The rows of each (VrfInstance, family) that the reads of the table hold.
    held: dict[tuple[str, int], int] = {}
    for name, counts in sections.items():
        for (label, af), n in (counts or {}).items():
            target = table_vrf(label)
            if target is None:
                continue
            if name in sources(label):
                held[target[0], af] = held.get((target[0], af), 0) + n
                continue
            # The row is filed under a table that its read does not feed. A row
            # of a policy table without its `table` field reads as `main`.
            # Neither the table that holds the row nor the table of its read is whole.
            partial.add(target[0])
            own = name.partition("_table_")[2]
            if own in declared:
                partial.add(table_uids[own])
    for label in [*read.table_rows, *(t for t in declared if t not in read.table_rows)]:
        target = table_vrf(label)
        if target is None:
            continue
        if read.table_rows.get(label, 0) > rib_graph_max_routes or not all(
            s in rib_read and sections.get(s) is not None for s in sources(label)
        ):
            partial.add(target[0])
        else:
            mirrored.add(target[0])
    # A table is partial when the configuration routes a family statically in
    # it and the reads hold no row of that family there. An empty answer of FRR
    # reads the same as a dropped answer.
    for vrf_uid, cidr, gw, ifname in static_seen:
        if (gw is not None or ifname is not None) and not held.get((vrf_uid, 6 if ":" in cidr else 4)):
            partial.add(vrf_uid)
    for vrf_uid in {*vrf_uids.values(), *table_uids.values()}:
        b.node("VrfInstance", vrf_uid, rib_mirrored=vrf_uid in mirrored and vrf_uid not in partial)
    return table_uids


def _rib_sections_read(raw: dict[str, Any], rib: _RibRead) -> frozenset[str]:
    """Return the sections of `raw` whose read succeeded.

    A read succeeded when the fetch recorded `ok` and the answer decoded
    (`section_outcomes`). A payload with no recorded outcomes has no such
    section and mirrors no table in full."""
    return frozenset(
        name
        for name, outcome in effective_outcomes(raw, {}).items()
        if outcome.status == "ok" and name not in rib.failures
    )


# The interface types that a statically addressed uplink can have, with their
# vifs. A tunnel, a WireGuard or a loopback interface is no WAN link of the estate.
_UPLINK_IFTYPES = ("ethernet", "bonding", "bridge")

# Addresses that do not point outside the estate: RFC 1918, CGNAT, ULA,
# link-local, loopback, unspecified ("this network"), multicast and reserved.
# The documentation ranges count as public, as the fixtures use them.
_INTERNAL_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/127",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


def _outside_address(ip: Any) -> bool:
    """Return whether `ip` is in none of `_INTERNAL_NETS`.

    An IPv4-mapped IPv6 address is read as its IPv4 address.
    """
    mapped = getattr(ip, "ipv4_mapped", None)
    ip = mapped or ip
    return not any(ip.version == net.version and ip in net for net in _INTERNAL_NETS)


def _static_uplinks(
    b: GraphBuilder, cfg: dict[str, Any], dev: str, if_uids: dict[str, str], if_vrf: dict[str, str]
) -> None:
    """The next hop of an uplink is an address outside `_INTERNAL_NETS`."""
    nodes: dict[str, dict[str, Any]] = {}
    for iftype in _UPLINK_IFTYPES:
        for name, node in ((cfg.get("interfaces") or {}).get(iftype) or {}).items():
            node = node if isinstance(node, dict) else {}
            nodes[str(name)] = node
            for vid, vnode in (node.get("vif") or {}).items():
                nodes[f"{name}.{vid}"] = vnode if isinstance(vnode, dict) else {}
    owned: dict[str, list[Any]] = {}
    for name, node in nodes.items():
        for addr in listify(node.get("address")):
            try:
                owned.setdefault(name, []).append(ipaddress.ip_interface(addr))
            except ValueError:
                continue

    def outside_by(name: str, af: int) -> bool:
        # The interface holds an address of the family outside the estate.
        return any(a.version == af and _outside_address(a.ip) for a in owned.get(name, []))

    static = (cfg.get("protocols") or {}).get("static") or {}
    uplinks: list[str] = []
    for tree, default, af in (("route", "0.0.0.0/0", 4), ("route6", "::/0", 6)):
        route = (static.get(tree) or {}).get(default)
        if not isinstance(route, dict):
            continue
        for distance, kind, value, opts in _static_forms(route):
            if distance != 1 or opts.get("vrf") or opts.get("next-hop-vrf"):
                continue
            if kind == "interface":
                names = [value] if outside_by(value, af) else []
            elif kind == "next-hop":
                try:
                    gw = ipaddress.ip_address(value)
                except ValueError:
                    continue
                named = opts.get("interface") if isinstance(opts.get("interface"), str) else None
                if gw.is_link_local:
                    # For a link-local gateway, the address of the named interface decides.
                    names = [named] if named is not None and outside_by(named, af) else []
                elif not _outside_address(gw):
                    names = []
                elif named is not None:
                    names = [named] if any(gw in a.network for a in owned.get(named, [])) else []
                else:
                    names = [n for n, addrs in owned.items() if any(gw in a.network for a in addrs)]
            else:
                continue
            if len(names) == 1 and names[0] not in uplinks:
                uplinks.append(names[0])
    for name in uplinks:
        if name not in nodes or name not in if_uids or if_vrf.get(name, DEFAULT_VRF) != DEFAULT_VRF:
            continue
        wl = f"wan:{local_namespace(dev)}:{name}"
        if b.props("WanLink", wl):
            continue
        b.node("WanLink", wl, kind="static", name=nodes[name].get("description") or name)
        b.rel("HAS_LINK", "Device", dev, "WanLink", wl)
        b.rel("ON", "WanLink", wl, "Interface", if_uids[name])


def _serial(version_text: str) -> str | None:
    """The value is read on the `Hardware S/N:` line only."""
    m = re.search(r"^Hardware S/N:[ \t]*([^\r\n]*)", version_text, re.M)
    if not m:
        return None
    value = m.group(1).strip()
    return None if placeholder_serial(value) else value


def _first(match: re.Match | None) -> str | None:
    return match.group(1) if match else None


# Any other service name marks the SvcObject opaque.
_WELL_KNOWN_PORTS = {
    "ftp-data": "20",
    "ftp": "21",
    "ssh": "22",
    "telnet": "23",
    "smtp": "25",
    "domain": "53",
    "bootps": "67",
    "bootpc": "68",
    "tftp": "69",
    "http": "80",
    "www": "80",
    "pop3": "110",
    "ntp": "123",
    "netbios-ns": "137",
    "netbios-ssn": "139",
    "imap": "143",
    "snmp": "161",
    "snmp-trap": "162",
    "ldap": "389",
    "https": "443",
    "microsoft-ds": "445",
    "syslog": "514",
    "submission": "587",
    "ldaps": "636",
    "imaps": "993",
    "pop3s": "995",
    "openvpn": "1194",
    "mysql": "3306",
    "rdp": "3389",
    "postgresql": "5432",
    "sip": "5060",
    "mdns": "5353",
}

_FW_STATES = ("established", "related", "new", "invalid")


def _numeric_port(token: str) -> bool:
    """A half-written range (`80-`) is unresolvable."""
    if token.isdigit():
        return True
    lo, sep, hi = token.partition("-")
    return bool(sep) and lo.isdigit() and hi.isdigit()


def _port_spec(spec: Any) -> str | None:
    """Return a port spec as one comma-joined string, or None when it names nothing.

    VyOS writes a spec as a string or as a list of strings. Both forms give
    one string, and a value in a uid or a display name is deterministic.
    """
    if spec in (None, "", []):
        return None
    parts = spec if isinstance(spec, list) else [spec]
    return ",".join(t for t in (str(p).strip() for p in parts) if t) or None


def _resolve_ports(spec: Any) -> tuple[list[str] | None, str | None]:
    """A token that is not a number, a range or a known name is kept verbatim and reported as a reason."""
    if spec in (None, "", []):
        return None, None
    tokens: list[str] = []
    reasons: list[str] = []
    for part in spec if isinstance(spec, list) else [spec]:
        for raw in str(part).split(","):
            token = raw.strip()
            if not token:
                continue
            resolved = _WELL_KNOWN_PORTS.get(token.lower())
            tokens.append(resolved or token)
            if resolved or _numeric_port(token):
                continue
            if token.startswith("!"):
                # The matcher has no negation for a port.
                reasons.append(f"negated port spec is not modelled: {token!r}")
            elif any(c.isalpha() for c in token):
                reasons.append(f"unknown service name: {token!r}")
            else:
                reasons.append(f"port spec not understood: {token!r}")
    return tokens or None, "; ".join(dict.fromkeys(reasons)) or None


def _rule_states(value: Any) -> tuple[list[str] | None, str | None]:
    """The result is sorted."""
    if value in (None, "", {}, []):
        return None, None
    if isinstance(value, list):
        names = [str(v).strip().lower() for v in value]
    elif isinstance(value, dict):
        names = []
        for key, leaf in value.items():
            name = str(key).strip().lower()
            if leaf == "disable":
                continue
            if leaf == "enable" or leaf in ({}, None, ""):
                names.append(name)
            else:
                return None, f"connection state {name!r} carries an unreadable value {leaf!r}"
    else:
        return None, f"the connection state clause is neither a list nor a set of leaves: {value!r}"
    unknown = sorted({n for n in names if n not in _FW_STATES})
    if unknown:
        return None, f"connection states this collector does not model: {', '.join(unknown)}"
    return sorted(set(names)) or None, None


# Every other rule key makes the rule undecided (`_unmodelled_match`).
_RULE_KEYS = frozenset(
    {
        "action",
        "add-address-to-group",
        "description",
        "destination",
        "disable",
        "inbound-interface",
        "jump-target",
        "log",
        "log-options",
        "offload-target",
        "outbound-interface",
        "protocol",
        "queue",
        "queue-options",
        "source",
        "state",
        "synproxy",
    }
)
# `set` is the PBR action (`set table`).
_PBR_RULE_KEYS = _RULE_KEYS | {"set"}
# The keys that a rule side matches on. fqdn, geoip, mac-address, address-mask
# and the domain, mac, interface and dynamic address groups are not modelled.
_SIDE_KEYS = frozenset({"address", "group", "port"})
_SIDE_GROUP_KEYS = frozenset({"address-group", "ipv6-address-group", "ipv6-network-group", "network-group"})
# A source port group is named as unmodelled.
_SIDE_GROUP_KEYS_OF = {
    "source": _SIDE_GROUP_KEYS,
    "destination": _SIDE_GROUP_KEYS | {"port-group"},
}
# The firewall group that a side reference resolves against, by uid infix.
_GROUP_KEY_OF_INFIX = {
    "addr": "address-group",
    "addr6": "ipv6-address-group",
    "net": "network-group",
    "net6": "ipv6-network-group",
}


def _unmodelled_match(rule: dict, rule_keys: frozenset[str] = _RULE_KEYS) -> list[str]:
    """The match clauses of a rule this collector does not model, by name."""
    out = sorted(k for k in rule if k not in rule_keys)
    for name in ("source", "destination"):
        side = rule.get(name)
        if not isinstance(side, dict):
            continue
        out += [f"{name} {k}" for k in sorted(side) if k not in _SIDE_KEYS]
        grp = side.get("group")
        if isinstance(grp, dict):
            out += [f"{name} group {k}" for k in sorted(grp) if k not in _SIDE_GROUP_KEYS_OF[name]]
    return out


def _negated(value: Any) -> tuple[bool, Any]:
    """Return (negated, value without the '!') for a rule-side match value.

    VyOS reads a leading '!' on an address and on every group reference as
    "not". The '!' is stripped before any uid is minted. `!10.0.0.0/8`
    resolves to the same object as `10.0.0.0/8`, and the rule holds the
    negation.
    """
    if isinstance(value, str) and value.startswith("!"):
        return True, value[1:].strip()
    return False, value


def _group_members(groups: dict, cfg_key: str, name: str, leaf: str) -> tuple[list[str], str | None]:
    """An include that names an undefined group is reported as a reason."""
    out: list[str] = []
    missing: list[str] = []
    seen: set[str] = set()
    stack = [name]
    while stack:
        gname = stack.pop()
        if gname in seen:  # an include cycle adds nothing new
            continue
        seen.add(gname)
        g = (groups.get(cfg_key) or {}).get(gname)
        if not isinstance(g, dict):
            missing.append(gname)
            continue
        out += listify(g.get(leaf))
        stack += [str(i) for i in listify(g.get("include"))]
    reason = f"{cfg_key} {', '.join(sorted(missing))} is not defined" if missing else None
    return list(dict.fromkeys(out)), reason


def _port_group_ports(groups: dict, ref: str) -> tuple[list[str] | None, str | None]:
    """A reference that cannot be read keeps a token that no port equals."""
    negated, name = _negated(ref)
    if negated:
        # The service object pairs the protocol with the ports, and a negation
        # would also negate the protocol. The spec is reported, as `!80` is.
        return [ref], f"negated port group is not modelled: {ref!r}"
    members, missing = _group_members(groups, "port-group", name, "port")
    ports, why = _resolve_ports(members)
    if missing and not ports:
        return [f"port-group:{name}"], missing
    return ports, "; ".join(x for x in (missing, why) if x) or None


def _side_negation(negs: set[bool], side: str) -> tuple[bool, str | None]:
    """Return (negate flag, reason that the side cannot be read) from the
    polarities that `_match_side` returns.

    VyOS ANDs the address constraints of one side. When every constraint is
    negated, the side is the negation of their union, and the gate reads the
    negate flag. A side that mixes negated and plain constraints has no such
    form.
    """
    if negs == {True, False}:
        return False, f"the {side} side mixes negated and plain address matches"
    return negs == {True}, None


def _match_side(
    b: GraphBuilder,
    host: str,
    l3dom: str,
    rule_uid: str,
    rel: str,
    side: dict | None,
    v6: bool = False,
    groups: dict | None = None,
) -> set[bool]:
    # `v6` selects the group namespace.
    negs: set[bool] = set()
    if not side:
        return negs
    grp = side.get("group") or {}
    addr_infix, net_infix = ("addr6", "net6") if v6 else ("addr", "net")
    addr_keys = ("address-group", "ipv6-address-group") if v6 else ("address-group",)
    net_keys = ("network-group", "ipv6-network-group") if v6 else ("network-group",)
    for keys, infix in ((addr_keys, addr_infix), (net_keys, net_infix)):
        for key in keys:
            if not grp.get(key):
                continue
            negated, gname = _negated(grp[key])
            negs.add(negated)
            gu = f"vyos:{host}:grp:{infix}:{gname}"
            cfg_key = _GROUP_KEY_OF_INFIX[infix]
            if groups is not None and gname not in (groups.get(cfg_key) or {}):
                b.node(
                    "NetObject",
                    gu,
                    name=gname,
                    kind="group",
                    opaque=True,
                    opaque_reason=f"{cfg_key} {gname} is not defined",
                )
            b.rel(rel, "FwRule", rule_uid, "NetObject", gu)
    negated, addr = _negated(side.get("address"))
    if addr:
        negs.add(negated)
        nu = b.node(
            "NetObject",
            # `slug` folds ':' and '/' alike. A v6 host and a v6 prefix with the
            # same digits would share one object, and `exact_slug` keeps them
            # apart. A v4 address has no such pair and keeps its slug.
            f"vyos:{host}:obj:{uid.exact_slug(addr) if ':' in addr else uid.slug(addr)}",
            name=addr,
            kind="inline",
            ranges=[addr] if "-" in addr else None,
        )
        if "-" in addr:  # a range has no single node to resolve to
            b.rel(rel, "FwRule", rule_uid, "NetObject", nu)
            return negs
        if "/" in addr:
            target = b.node(
                "Prefix", uid.prefix(l3dom, addr), cidr=addr, af=_af(addr), l3dom=l3dom, anchor=l3dom
            )
            b.rel("RESOLVES_TO", "NetObject", nu, "Prefix", target)
        else:
            target = b.node(
                "IpAddress", uid.ip(l3dom, addr), ip=addr, af=_af(addr), l3dom=l3dom, anchor=l3dom
            )
            b.rel("RESOLVES_TO", "NetObject", nu, "IpAddress", target)
        b.rel(rel, "FwRule", rule_uid, "NetObject", nu)
    return negs


def _static_routes(
    b: GraphBuilder,
    l3dom: str,
    vrf_uid: str,
    if_uids: dict[str, str],
    routes: dict | None,
    seen: set[tuple[str, str, str | None, str | None]] | None = None,
    vrf_uid_of: dict[str, str] | None = None,
) -> None:
    # `seen` collects (vrf_uid, cidr, next_hop, interface).
    for pfx, route in (routes or {}).items():
        pu = b.node("Prefix", uid.prefix(vrf_uid, pfx), cidr=pfx, af=_af(pfx), l3dom=l3dom, anchor=vrf_uid)
        # Zebra installs the forms of the lowest distance.
        forms = _static_forms(route)
        best = min((distance for distance, *_rest in forms), default=None)
        for distance, kind, value, opts in forms:
            if distance != best:
                continue
            if kind == "discard":
                b.rel(
                    "STATIC_ROUTE",
                    "VrfInstance",
                    vrf_uid,
                    "Prefix",
                    pu,
                    key={"discard": value},
                    discard=value,
                    distance=distance,
                )
                if seen is not None:
                    seen.add((vrf_uid, pfx, None, None))
            elif kind == "next-hop":
                # VyOS 1.3 spells the leak `next-hop-vrf`. VyOS 1.4 and later spell it `vrf`.
                nhv = opts.get("next-hop-vrf") or opts.get("vrf")
                nh_vrf = (vrf_uid_of or {}).get(nhv) if isinstance(nhv, str) else None
                # `next-hop X interface Y` states the egress that an IPv6
                # link-local next hop needs. The edge holds it as `rib_interface`,
                # because `interface` is the key of this relationship
                # (`_confirm_static_route`).
                nh_if = opts.get("interface") if isinstance(opts.get("interface"), str) else None
                b.rel(
                    "STATIC_ROUTE",
                    "VrfInstance",
                    vrf_uid,
                    "Prefix",
                    pu,
                    key={"next_hop": value},
                    next_hop=value,
                    next_hop_vrf=nh_vrf if nh_vrf != vrf_uid else None,
                    rib_interface=nh_if,
                    distance=distance,
                )
                if nh_if in if_uids:
                    b.rel("VIA", "Prefix", pu, "Interface", if_uids[nh_if], key={"vrf": vrf_uid}, vrf=vrf_uid)
                b.node(
                    "IpAddress", uid.ip(vrf_uid, value), ip=value, af=_af(value), l3dom=l3dom, anchor=vrf_uid
                )
                if seen is not None:
                    seen.add((vrf_uid, pfx, value, None))
            else:
                # `interface X vrf V` leaks the route out of an interface of
                # VRF V (1.4 and later). V is the context of the interface.
                ifv = opts.get("next-hop-vrf") or opts.get("vrf")
                if_vrf = (vrf_uid_of or {}).get(ifv) if isinstance(ifv, str) else None
                b.rel(
                    "STATIC_ROUTE",
                    "VrfInstance",
                    vrf_uid,
                    "Prefix",
                    pu,
                    key={"interface": value},
                    interface=value,
                    next_hop_vrf=if_vrf if if_vrf != vrf_uid else None,
                    # For `dhcp-interface X`, the next hop is the router that the
                    # DHCP lease on X names. The configuration does not hold it.
                    via_dhcp=True if kind == "dhcp-interface" else None,
                    distance=distance,
                )
                if value in if_uids:
                    b.rel("VIA", "Prefix", pu, "Interface", if_uids[value], key={"vrf": vrf_uid}, vrf=vrf_uid)
                if seen is not None:
                    seen.add((vrf_uid, pfx, None, value))


def _static_forms(route: dict) -> list[tuple[int, str, str, dict]]:
    """Return (distance, kind, value, options) of every enabled form of one
    static route node.

    The kinds are `discard` (blackhole or reject), `next-hop`, `interface` and
    `dhcp-interface`. `dhcp-interface` is a leaf that names the interface whose
    DHCP lease gives the next hop. It has no distance of its own and installs
    at the default.

    The static distance of VyOS defaults to 1, the FRR default, on every form
    (`distance` under `blackhole`, `reject` and each next hop or interface).
    A distance that is not a number reads as the default."""

    def distance(opts: Any) -> int:
        try:
            return int((opts if isinstance(opts, dict) else {}).get("distance") or 1)
        except (TypeError, ValueError):
            return 1

    forms: list[tuple[int, str, str, dict]] = []
    for discard in ("blackhole", "reject"):
        if discard in route:
            forms.append((distance(route[discard]), "discard", discard, {}))
            break  # Blackhole wins.
    for kind in ("next-hop", "interface"):
        for value, opts in (route.get(kind) or {}).items():
            opts = opts if isinstance(opts, dict) else {}
            if "disable" not in opts:
                forms.append((distance(opts), kind, str(value), opts))
    dhcp = route.get("dhcp-interface")
    if isinstance(dhcp, str) and dhcp:
        forms.append((1, "dhcp-interface", dhcp, {}))
    return forms


def _route_prefix_count(listing: Any) -> int:
    """Return the count of prefixes in one `show ip route ... json` listing
    ({vrf: {prefix: [...]}}).

    The count is 0 for the `[]` that a failed read leaves."""
    if not isinstance(listing, dict):
        return 0
    return sum(len(by_prefix) for by_prefix in listing.values() if isinstance(by_prefix, dict))


def section_outcomes(raw: dict[str, Any], rib: _RibRead | None = None) -> dict[str, SectionOutcome]:
    """A payload with no recorded outcomes reads `unknown` for every section."""
    recorded = effective_outcomes(raw, {})
    rib = rib if rib is not None else _read_rib(raw)
    for name, failure in rib.failures.items():
        current = recorded.get(name)
        if current is None or current.status == "ok":
            recorded[name] = failure
    sections: dict[str, SectionOutcome] = {}

    def add(name: str, *, rows: int | None = None, present: bool = True) -> None:
        outcome = recorded.get(name)
        if outcome is None:
            sections[name] = SectionOutcome(status="unknown")
        elif outcome.status != "ok":
            sections[name] = outcome
        elif rows is None:
            sections[name] = SectionOutcome(status="ok" if present else "empty")
        else:
            sections[name] = SectionOutcome(status="ok" if rows else "empty", row_count=rows)

    add("config", present=bool(raw.get("config")))
    unread = legacy_unread(raw.get("config") or {}, str(raw.get("version_text") or ""))
    if unread and sections["config"].status == "ok":
        sections["config"] = SectionOutcome(
            status="partial", detail="VyOS 1.3 configuration not read: " + ", ".join(unread)
        )
    add("version", present=bool(str(raw.get("version_text") or "").strip()))
    for key in ("links", "addrs"):
        value = raw.get(key)
        add(key, rows=len(value) if isinstance(value, list) else 0)
    # A payload sealed without the neighbor read has no `neigh` section.
    if "neigh" in raw:
        value = raw["neigh"]
        add("neigh", rows=len(value) if isinstance(value, list) else 0)
    # A missing key or a failed read yields no rows.
    add("link_speeds", rows=len(_parse_link_speeds(raw.get("link_speeds"))))
    for key in ("routes", "routes6"):
        add(key, rows=rib.prefixes.get(key, 0))
        tables = raw.get(f"{key}_tables")
        if isinstance(tables, dict):
            for number in tables:
                name = f"{key}_table_{number}"
                add(name, rows=rib.prefixes.get(name, 0))
    # A read that the fetch rejected leaves an outcome with no listing beside it.
    for name, outcome in recorded.items():
        sections.setdefault(name, outcome)
    return sections


class _RibEntry(NamedTuple):
    """One row of the FRR RIB (`_rib_entries`).

    The row is a prefix that FRR installed and selected, with one of the
    nexthops that it forwards over. `table` is the label of the routing table
    of the row ("main", the number of a policy table, the table number of a
    VRF). `af` is the address family of the prefix. `next_hop_vrf` is the
    per-nexthop `vrf` field of FRR. `discard` names a drop. `drop` is the kind
    that the nexthop flags of FRR state (`_nexthop_discard`). A row that names
    neither a next hop nor an interface is a blackhole when no flag names
    another kind.
    """

    table: str
    cidr: str
    af: int
    next_hop: Any
    interface: Any
    next_hop_vrf: Any
    protocol: str | None
    metric: Any
    drop: str | None = None

    @property
    def discard(self) -> str | None:
        if self.drop:
            return self.drop
        return "blackhole" if not self.next_hop and not self.interface else None


def _nexthop_discard(nh: dict[str, Any]) -> str | None:
    """Return the discard kind that the FRR JSON states for one nexthop, or
    None for a nexthop that forwards.

    The kinds are the words of the static-route path (`_static_routes`,
    blackhole and reject) and `prohibit` for an admin-prohibited nexthop. FRR
    prints a blackhole-type nexthop as `unreachable` with one of `blackhole`,
    `reject` or `admin-prohibited`."""
    if nh.get("reject"):
        return "reject"
    if nh.get("admin-prohibited") or nh.get("prohibit"):
        return "prohibit"
    if nh.get("blackhole") or nh.get("unreachable"):
        return "blackhole"
    return None


class _RibRead(NamedTuple):
    """The rows that one load reads from the RIB answers of a payload (`_read_rib`).

    `entries` holds every row in the order that FRR listed them. `table_rows`
    counts the rows per table label, in the order of first appearance. The
    graph mirror applies its threshold to this count. `prefixes` holds the
    `_route_prefix_count` of each answer by section name (`section_outcomes`).
    `failures` holds the outcome of each answer that did not decode, by the
    name under which the fetch records the outcome of the command.
    `egress_index` is the longest-prefix index of the main table. The
    WireGuard carrier lookup builds it on its first call
    (`_carrier_egress_interface`). `sections` counts the rows of each answer
    by (table label, family), by section name. The value is None for an
    answer whose shape the read does not know, and `rib_mirrored` of
    `_route_stage` then does not read the table as whole.
    """

    entries: list[_RibEntry]
    table_rows: dict[str, int]
    prefixes: dict[str, int]
    failures: dict[str, SectionOutcome]
    egress_index: dict[tuple[int, int], dict[int, str]]
    sections: dict[str, dict[tuple[str, int], int] | None] | None = None


# An IPv4 prefix as `str(ipaddress.ip_network(...))` writes it. The 4 octets
# and the prefix length have no leading zero.
_OCTET = "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
_CANONICAL_V4 = re.compile(rf"{_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET}/(3[0-2]|[12][0-9]|[0-9])")


def _rib_cidr(prefix: Any, af: int) -> str | None:
    """None when the key is of the other family or `ip_network` rejects it."""
    if type(prefix) is str:
        match = _CANONICAL_V4.fullmatch(prefix)
        if match is not None:
            a, b, c, d, length = (int(group) for group in match.groups())
            if af != 4 or ((a << 24) | (b << 16) | (c << 8) | d) & ((1 << (32 - length)) - 1):
                return None
            return prefix
    try:
        net = ipaddress.ip_network(prefix)
    except ValueError:
        return None
    return str(net) if net.version == af else None


def _rib_entries(items: Iterable[tuple[Any, Any]], af: int, shared: dict[Any, Any]) -> Iterator[_RibEntry]:
    """The function returns one row per (prefix, nexthop)."""
    share = shared.setdefault

    def one(value: Any) -> Any:
        # Only an exact str or int is shared. True == 1 == 1.0, and a row must
        # keep the type that the JSON of the device gave.
        return share(value, value) if type(value) is str or type(value) is int else value

    for prefix, routes in items:
        cidr = _rib_cidr(prefix, af)
        if cidr is None:
            continue
        for route in routes or []:
            if not (route.get("installed") and route.get("selected")):
                continue
            if route.get("protocol") == "local":
                continue
            hops = [n for n in route.get("nexthops") or [] if n.get("fib")] or [
                n for n in route.get("nexthops") or [] if n.get("active")
            ]
            if not hops:
                continue
            table = str(route.get("table") or "main")
            if table in ("default", "253"):
                continue
            table = one(table)
            protocol = one(str(route["protocol"])) if route.get("protocol") else None
            metric = one(route.get("metric"))
            for nh in hops:
                drop = _nexthop_discard(nh)
                if drop is not None:
                    # A drop forwards nowhere. A stray next hop or interface on
                    # it must not make the row a forwarding route.
                    yield _RibEntry(table, cidr, af, None, None, None, protocol, metric, one(drop))
                    continue
                yield _RibEntry(
                    table,
                    cidr,
                    af,
                    one(nh.get("ip")),
                    one(nh.get("interfaceName")),
                    one(nh.get("vrf")),
                    protocol,
                    metric,
                )


def _rib_answer(value: Any) -> tuple[Any, SectionOutcome | None]:
    """Every str is read as the text FRR printed."""
    if not isinstance(value, str):
        return value, None
    try:
        return json.loads(value), None
    except ValueError as exc:
        return [], SectionOutcome(status="malformed", detail=str(exc))
    except RecursionError as exc:
        status, detail = classify_command_failure(exc)
        return [], SectionOutcome(status=status, detail=detail)


class _ObjectScan:
    """A JSON text read one object member at a time.

    `members` yields each key of the object at the read position and leaves
    the position at the value of the key. The caller reads the value
    (`value`) or descends into it (`members`) before it asks for the next key.
    Only the values that the caller decodes are built as trees. A malformed
    text raises `json.JSONDecodeError`."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0

    def _skip(self) -> None:
        self.pos = _JSON_WHITESPACE.match(self.text, self.pos).end()  # type: ignore[union-attr]

    def at(self, char: str) -> bool:
        self._skip()
        return self.text.startswith(char, self.pos)

    def _take(self, char: str, message: str) -> None:
        if not self.at(char):
            raise json.JSONDecodeError(message, self.text, self.pos)
        self.pos += 1

    def value(self) -> Any:
        self._skip()
        value, self.pos = _DECODER.raw_decode(self.text, self.pos)
        return value

    def members(self) -> Iterator[str]:
        self._take("{", "Expecting '{'")
        if self.at("}"):
            self.pos += 1
            return
        while True:
            if not self.at('"'):
                raise json.JSONDecodeError(
                    "Expecting property name enclosed in double quotes", self.text, self.pos
                )
            key = self.value()
            self._take(":", "Expecting ':' delimiter")
            yield key
            if self.at(","):
                self.pos += 1
            else:
                self._take("}", "Expecting ',' delimiter")
                return

    def end(self) -> None:
        self._skip()
        if self.pos != len(self.text):
            raise json.JSONDecodeError("Extra data", self.text, self.pos)


def _rib_items(text: str, nested: bool, odd: list[Any] | None = None) -> Iterator[tuple[Any, Any]]:
    """Yield (prefix, [route, ...]) of one RIB answer that is a JSON object.

    The routes of each prefix are decoded on their own. With `nested`, the
    answer is the `vrf all` answer, {vrf: {prefix: [...]}}. A VRF whose value
    is not an object has no items, and `odd` gets its name. Without `nested`,
    the answer is the {prefix: [...]} of one policy table."""
    scan = _ObjectScan(text)
    for key in scan.members():
        if not nested:
            yield key, scan.value()
        elif scan.at("{"):
            for prefix in scan.members():
                yield prefix, scan.value()
        else:
            scan.value()
            if odd is not None:
                odd.append(key)
    scan.end()


def _rib_rows(
    value: Any, af: int, nested: bool, shared: dict[Any, Any], odd: list[Any] | None = None
) -> tuple[list[_RibEntry], int, SectionOutcome | None]:
    """Return the rows of one RIB answer (`_rib_entries`), its prefix count as
    `_route_prefix_count` states it, and the outcome of the read when the read
    failed.

    An answer that is the text of a JSON object is read one prefix at a time
    (`_rib_items`). Besides the rows, a load holds the decoded routes of one
    prefix at a time. A full table decoded whole costs about 2 KB per prefix.
    Any other answer, and an answer that the incremental read rejects, is read
    whole by `_rib_answer`, which states the outcome that `json.loads` gives.
    An answer that `json.loads` rejects gives no rows.

    `odd`, when given, collects the parts of the answer that do not have the
    shape read here. These parts are an answer that is not an object, a VRF
    that is not an object, and a prefix whose value is not a list of routes."""
    if isinstance(value, str) and value.startswith("{", _JSON_WHITESPACE.match(value).end()):  # type: ignore[union-attr]
        rows: list[_RibEntry] = []
        count = 0
        try:
            for prefix, routes in _rib_items(value, nested, odd):
                if odd is not None and not isinstance(routes, list):
                    odd.append(prefix)
                if nested:
                    count += 1
                elif isinstance(routes, dict):
                    count += len(routes)
                rows.extend(_rib_entries(((prefix, routes),), af, shared))
        except (ValueError, RecursionError):
            if odd is not None:
                odd.clear()
        else:
            return rows, count, None
    answer, failure = _rib_answer(value)
    listings = (answer.values() if nested else (answer,)) if isinstance(answer, dict) else ()
    if odd is not None:
        if not isinstance(answer, dict):
            odd.append(None)
        for listing in listings:
            if not isinstance(listing, dict):
                odd.append(None)
            else:
                odd.extend(k for k, v in listing.items() if not isinstance(v, list))
    items = (item for listing in listings if isinstance(listing, dict) for item in listing.items())
    return list(_rib_entries(items, af, shared)), _route_prefix_count(answer), failure


def _read_rib_answer(
    section: str, value: Any, af: int, nested: bool, shared: dict[Any, Any], odd: list[Any] | None = None
) -> tuple[list[_RibEntry], int, SectionOutcome | None]:
    """Return `_rib_rows` of the answer whose outcome the fetch records under
    `section`, read as one debug-capture step.

    The fetch records `ok` for every answer that the device gave. The `begin`
    record of a capture does not show an answer that does not read. The end
    record of the step holds the outcome, and the section and its outcome are
    logged, as a TextFSM failure on an optional Cisco command is
    (`cli_parse.parse`). The `command` detail of the step is `section`
    (`routes6`, `routes_table_100`), and the open-step line of the capture
    shows it. The arguments of the log line are strings with no exception
    attached. No handler keeps a traceback whose frames hold the answer text.
    """
    with debug_capture.step(
        "vyos.rib_answer", command=section, chars=len(value) if isinstance(value, str) else None
    ) as out:
        rows, count, failure = _rib_rows(value, af, nested, shared, odd)
        out["prefixes"] = count
        if failure is not None:
            out["error"] = f"{section}: {failure.status}: {failure.detail}"
            logger.warning(
                "vyos: %s: %s: %s; continuing without its routes", section, failure.status, failure.detail
            )
    return rows, count, failure


def _table_outcome_key(key: str, number: Any) -> str:
    """Return the name under which the fetch records the outcome of a policy
    table read.

    The name holds the table number as the integer that the command was built
    from."""
    try:
        return f"{key}_table_{int(number)}"
    except (TypeError, ValueError):
        return f"{key}_table_{number}"


def _read_rib(raw: dict[str, Any]) -> _RibRead:
    """Read every RIB answer of `raw` once.

    The order of the rows is `routes` (every VRF), its policy tables,
    `routes6` and its policy tables. Each answer is read one prefix at a time
    (`_rib_rows`), counted for its section and turned into rows
    (`_rib_entries`). Besides the rows that it keeps, a load holds the decoded
    routes of one prefix at a time. The graph mirror (`_learned_routes`), the
    side table (`VyosCollector.side_tables`) and the WireGuard carrier lookup
    (`_carrier_egress_interface`) read the rows. Nothing reads the decoded
    trees again. The decode and the count of each answer is one debug-capture
    step (`_read_rib_answer`).
    """
    entries: list[_RibEntry] = []
    table_rows: dict[str, int] = {}
    prefixes: dict[str, int] = {}
    failures: dict[str, SectionOutcome] = {}
    sections: dict[str, dict[tuple[str, int], int] | None] = {}
    shared: dict[Any, Any] = {}

    def take(rows: list[_RibEntry], section: str, odd: list[Any]) -> None:
        counts: dict[tuple[str, int], int] = {}
        for entry in rows:
            entries.append(entry)
            table_rows[entry.table] = table_rows.get(entry.table, 0) + 1
            counts[entry.table, entry.af] = counts.get((entry.table, entry.af), 0) + 1
        sections[section] = None if odd else counts

    for key, af in (("routes", 4), ("routes6", 6)):
        odd: list[Any] = []
        rows, prefixes[key], failure = _read_rib_answer(key, raw.get(key), af, True, shared, odd)
        if failure is not None:
            failures[key] = failure
        take(rows, key, odd)
        tables = raw.get(f"{key}_tables")
        if not isinstance(tables, dict):
            continue
        for number, listing in tables.items():
            name = _table_outcome_key(key, number)
            odd = []
            rows, count, failure = _read_rib_answer(name, listing, af, False, shared, odd)
            prefixes[f"{key}_table_{number}"] = count
            if failure is not None:
                failures[name] = failure
            take(rows, f"{key}_table_{number}", odd)
    return _RibRead(entries, table_rows, prefixes, failures, {}, sections)


def _confirm_static_route(
    b: GraphBuilder,
    vrf_uid: str,
    dom: str,
    if_uids: dict[str, str],
    row: _RibEntry,
    *,
    by_next_hop: bool,
    vrf_uid_of: dict[str, str] | None = None,
) -> None:
    """The egress interface of the RIB row is written as `rib_interface`."""
    gw, ifname, cidr = row.next_hop, row.interface, row.cidr
    nh_vrf = (vrf_uid_of or {}).get(row.next_hop_vrf) if row.next_hop_vrf else None
    pu = b.node("Prefix", uid.prefix(vrf_uid, cidr), cidr=cidr, af=row.af, l3dom=dom, anchor=vrf_uid)
    b.rel(
        "STATIC_ROUTE",
        "VrfInstance",
        vrf_uid,
        "Prefix",
        pu,
        key={"next_hop": gw} if by_next_hop else {"interface": ifname},
        rib_confirmed=True,
        # Only the next-hop form is missing an interface.
        rib_interface=ifname if by_next_hop else None,
        next_hop_vrf=nh_vrf if nh_vrf != vrf_uid else None,
    )
    if by_next_hop and ifname in if_uids:
        b.rel("VIA", "Prefix", pu, "Interface", if_uids[ifname], key={"vrf": vrf_uid}, vrf=vrf_uid)


def _learned_routes(
    b: GraphBuilder,
    rib: _RibRead,
    if_uids: dict[str, str],
    table_vrf,
    static_seen: set[tuple[str, str, str | None, str | None]],
    max_routes: int,
    vrf_uid_of: dict[str, str] | None = None,
) -> set[str]:
    """Write the learned routes of each table with at most `max_routes` rows.

    A larger table stays in the side store only. Return the uids of the
    VrfInstances that have a `static` row for a declared prefix that was not
    folded onto its config static.
    """
    declared: set[tuple[str, str]] = set()
    for vrf_uid, cidr, _gw, _ifname in static_seen:
        try:
            declared.add((vrf_uid, str(ipaddress.ip_network(cidr, strict=False))))
        except ValueError:
            declared.add((vrf_uid, cidr))
    unfolded: set[str] = set()
    mirrored: dict[str, list[_RibEntry]] = {
        table: [] for table, count in rib.table_rows.items() if count <= max_routes
    }
    if mirrored:
        for entry in rib.entries:
            rows = mirrored.get(entry.table)
            if rows is not None:
                rows.append(entry)
    for table, count in rib.table_rows.items():
        target = table_vrf(table)
        if target is None or count > max_routes:
            continue
        vrf_uid, dom = target
        for row in mirrored[table]:
            if row.protocol == "connected":
                # The prefix is an ORIGINATES edge of the interface address.
                continue
            gw, ifname, cidr = row.next_hop, row.interface, row.cidr
            # Only a row that holds a next hop or an egress interface is folded onto the config static.
            by_next_hop = gw is not None and (vrf_uid, cidr, gw, None) in static_seen
            by_interface = ifname is not None and (vrf_uid, cidr, None, ifname) in static_seen
            if by_next_hop or by_interface:
                _confirm_static_route(
                    b, vrf_uid, dom, if_uids, row, by_next_hop=by_next_hop, vrf_uid_of=vrf_uid_of
                )
                continue
            if (vrf_uid, cidr, gw, None) in static_seen or (vrf_uid, cidr, None, ifname) in static_seen:
                # The config declares this route, and the row adds nothing to fold.
                continue
            if row.protocol == "static" and (vrf_uid, cidr) in declared:
                unfolded.add(vrf_uid)
            pu = b.node("Prefix", uid.prefix(vrf_uid, cidr), cidr=cidr, af=row.af, l3dom=dom, anchor=vrf_uid)
            # The key of the edge is one synthetic field, `via`.
            nhv = row.next_hop_vrf
            nh_vrf = (vrf_uid_of or {}).get(nhv) if nhv else None
            b.rel(
                "LEARNED_ROUTE",
                "VrfInstance",
                vrf_uid,
                "Prefix",
                pu,
                key={"via": f"{gw or ''}|{ifname or ''}"},
                next_hop=gw,
                interface=ifname,
                protocol=row.protocol,
                metric=row.metric,
                next_hop_vrf=nh_vrf if nh_vrf != vrf_uid else None,
                # The tracer reads `discard` as BLOCKED.
                discard=row.discard,
            )
            if gw:
                b.node("IpAddress", uid.ip(vrf_uid, gw), ip=gw, af=_af(gw), l3dom=dom, anchor=vrf_uid)
            if ifname in if_uids:
                b.rel("VIA", "Prefix", pu, "Interface", if_uids[ifname], key={"vrf": vrf_uid}, vrf=vrf_uid)
    return unfolded


def _pbr(
    b: GraphBuilder,
    cfg: dict,
    dev: str,
    host: str,
    l3dom: str,
    if_uids: dict[str, str],
    main_vrf: str,
    table_uids: dict[str, str],
) -> None:
    # `l3dom` is a resolved L3 domain (core/l3domain.py).
    """Each interface that a policy is applied to ENFORCES it."""
    groups = (cfg.get("firewall") or {}).get("group") or {}
    for tree, v6 in (("route", False), ("route6", True)):
        prefix = "pbr:ipv6" if v6 else "pbr"
        for name, pol in (((cfg.get("policy") or {}).get(tree)) or {}).items():
            # `af` is the family that the policy applies to. The PBR stage lets a
            # `policy route` claim no IPv6 flow and a `policy route6` no IPv4 flow.
            pu = b.node(
                "PbrPolicy", f"vyos:{host}:{prefix}:{name}", name=name, vendor="vyos", af=6 if v6 else 4
            )
            b.rel("ENFORCES", "Device", dev, "PbrPolicy", pu)
            for ifname in listify(pol.get("interface")):
                if ifname in if_uids:
                    b.rel("ENFORCES", "Interface", if_uids[ifname], "PbrPolicy", pu)
            for num, rule in sorted((pol.get("rule") or {}).items(), key=lambda kv: int(kv[0])):
                ru = b.node(
                    "FwRule",
                    f"vyos:{host}:{prefix}:{name}:{num}",
                    position=int(num),
                    action="route",
                    name=rule.get("description"),
                    enabled="disable" not in rule,
                    rule_uid=f"{prefix}:{name}:{num}",
                )
                b.rel("HAS_RULE", "PbrPolicy", pu, "FwRule", ru)
                src_negate, src_mixed = _side_negation(
                    _match_side(b, host, l3dom, ru, "SRC", rule.get("source"), v6, groups), "source"
                )
                dst_negate, dst_mixed = _side_negation(
                    _match_side(b, host, l3dom, ru, "DST", rule.get("destination"), v6, groups), "destination"
                )
                # `_firewall` reads a clause that it cannot evaluate in the same
                # way. The PBR stage reads such a rule as a rule that it cannot decide.
                states, states_reason = _rule_states(rule.get("state"))
                unread = _unmodelled_match(rule, _PBR_RULE_KEYS)
                match_reason = "; ".join(
                    x
                    for x in (
                        states_reason,
                        states and f"the rule matches only connection states {', '.join(states)}",
                        src_mixed,
                        dst_mixed,
                        unread and f"the rule also matches on {', '.join(unread)}, which is not modelled",
                    )
                    if x
                )
                b.node(
                    "FwRule",
                    ru,
                    states_opaque=True if match_reason else None,
                    states_opaque_reason=match_reason or None,
                    src_negate=True if src_negate else None,
                    dst_negate=True if dst_negate else None,
                )
                # The `prefix` (`pbr`/`pbr:ipv6`) stays in the SvcObject uid.
                proto = rule.get("protocol")
                port = (rule.get("destination") or {}).get("port")
                src_port = _port_spec((rule.get("source") or {}).get("port"))
                src_suffix = f"-src{src_port}" if src_port else ""
                src_label = f" src {src_port}" if src_port else ""
                pgrp = ((rule.get("destination") or {}).get("group") or {}).get("port-group")
                if pgrp:
                    grp_ports, why = _port_group_ports(groups, pgrp)
                    su = b.node(
                        "SvcObject",
                        f"vyos:{host}:svc:{prefix}:{proto or 'any'}:grp:{pgrp}{src_suffix}",
                        name=f"{proto or 'any'}/{pgrp}{src_label}",
                        proto=proto,
                        ports=grp_ports,
                        src_port=src_port,
                        opaque=True if why else None,
                        opaque_reason=why,
                    )
                    b.rel("SVC", "FwRule", ru, "SvcObject", su)
                elif proto or port or src_port:
                    ports, why = _resolve_ports(port)
                    su = b.node(
                        "SvcObject",
                        f"vyos:{host}:svc:{prefix}:{proto or 'any'}-{port or 'any'}{src_suffix}",
                        name=f"{proto or 'any'}/{port or 'any'}{src_label}",
                        proto=proto,
                        ports=ports,
                        src_port=src_port,
                        opaque=True if why else None,
                        opaque_reason=why,
                    )
                    b.rel("SVC", "FwRule", ru, "SvcObject", su)
                table = str((rule.get("set") or {}).get("table") or "")
                if table:
                    target = main_vrf if table == "main" else table_uids.get(table)
                    if target:
                        b.rel("REDIRECTS_VIA", "FwRule", ru, "VrfInstance", target, table=table)


def _firewall(
    b: GraphBuilder,
    cfg: dict,
    dev: str,
    host: str,
    l3dom: str,
    if_uids: dict[str, str],
    if_vrf: dict[str, str] | None = None,
) -> None:
    # `l3dom` is a resolved L3 domain (core/l3domain.py).
    fw = cfg.get("firewall") or {}
    groups = fw.get("group") or {}

    for cfg_key, infix in (("address-group", "addr"), ("ipv6-address-group", "addr6")):
        for gname in groups.get(cfg_key) or {}:
            addrs, missing = _group_members(groups, cfg_key, gname, "address")
            # A range such as `10.0.0.5-10.0.0.9` has no IpAddress node. It stays on
            # the object, where matching can expand it.
            ranges = [a for a in addrs if "-" in a]
            gu = b.node(
                "NetObject",
                f"vyos:{host}:grp:{infix}:{gname}",
                name=gname,
                kind="group",
                ranges=ranges or None,
                opaque=True if missing else None,
                opaque_reason=missing,
            )
            for a in addrs:
                if "-" in a:
                    continue
                ipu = b.node("IpAddress", uid.ip(l3dom, a), ip=a, af=_af(a), l3dom=l3dom, anchor=l3dom)
                b.rel("RESOLVES_TO", "NetObject", gu, "IpAddress", ipu)
    for cfg_key, infix in (("network-group", "net"), ("ipv6-network-group", "net6")):
        for gname in groups.get(cfg_key) or {}:
            nets, missing = _group_members(groups, cfg_key, gname, "network")
            gu = b.node(
                "NetObject",
                f"vyos:{host}:grp:{infix}:{gname}",
                name=gname,
                kind="group",
                opaque=True if missing else None,
                opaque_reason=missing,
            )
            for n in nets:
                pu = b.node("Prefix", uid.prefix(l3dom, n), cidr=n, af=_af(n), l3dom=l3dom, anchor=l3dom)
                b.rel("RESOLVES_TO", "NetObject", gu, "Prefix", pu)
    for gname in groups.get("port-group") or {}:
        grp_ports, grp_reason = _port_group_ports(groups, gname)
        b.node(
            "SvcObject",
            f"vyos:{host}:svc:grp:{gname}",
            name=gname,
            kind="group",
            ports=grp_ports,
            opaque=True if grp_reason else None,
            opaque_reason=grp_reason,
        )

    # The state-policy is kept on the rulebase and is not applied as a verdict.
    state_policy = (fw.get("global-options") or {}).get("state-policy") or {}
    global_state_policy = (
        sorted(f"{k}={(v or {}).get('action')}" for k, v in state_policy.items() if (v or {}).get("action"))
        or None
    )
    defined_rulesets: set[str] = set()
    # VyOS applies its running configuration, which the collector read. Every
    # ruleset is installed at the revision of that firewall configuration
    # (analysis_model/network.py `_bindings`). The forward, input and output
    # filters apply in every VRF. A device-wide binding names every context and
    # both interfaces as "*".
    revision = hashlib.sha256(canonical_json(fw).encode()).hexdigest()
    installed = {"installed": True, "coverage": "complete", "installed_revision": revision}

    def add_ruleset(base: str, name: str, rs: dict, v6: bool = False, chain: str | None = None) -> None:
        defined_rulesets.add(base)

        def named(target: Any) -> str:
            # The uid of the named ruleset of this family that a jump names.
            return f"vyos:{host}:fw:ipv6:{target}" if v6 else f"vyos:{host}:fw:{target}"

        default_jump = rs.get("default-jump-target") if rs.get("default-action") == "jump" else None
        b.node(
            "FwRulebase",
            base,
            name=name,
            kind="access",
            vendor="vyos",
            af=6 if v6 else 4,
            chain=chain,
            match_context="device" if chain else None,
            default_action=rs.get("default-action"),
            # An absent default-action is no recorded drop. VyOS models the
            # chain default. At the gate, the marker tells "the config did not
            # set one" apart from "the vendor has no such concept".
            default_action_unknown=rs.get("default-action") is None,
            # An empty value lets a refresh clear it.
            default_jump_target=named(default_jump) if default_jump else "",
            global_state_policy=global_state_policy,
            configured_revision=revision,
            **installed,
        )
        # A named ruleset gets no ENFORCES.
        if chain:
            b.rel(
                "ENFORCES",
                "Device",
                dev,
                "FwRulebase",
                base,
                **installed,
                context_uid="*",
                ingress_interface_uid="*",
                egress_interface_uid="*",
                address_family=6 if v6 else 4,
            )

        def addr_free(side: dict | None) -> bool:
            # The vendor's implicit Any is written explicitly.
            side = side or {}
            grp = side.get("group") or {}
            return not (
                side.get("address")
                or grp.get("address-group")
                or grp.get("network-group")
                or grp.get("ipv6-address-group")
                or grp.get("ipv6-network-group")
            )

        for num, rule in sorted((rs.get("rule") or {}).items(), key=lambda kv: int(kv[0])):
            states, states_reason = _rule_states(rule.get("state"))
            ru = f"{base}:{num}"
            src_negate, src_mixed = _side_negation(
                _match_side(b, host, l3dom, ru, "SRC", rule.get("source"), v6, groups), "source"
            )
            dst_negate, dst_mixed = _side_negation(
                _match_side(b, host, l3dom, ru, "DST", rule.get("destination"), v6, groups), "destination"
            )
            # A clause that the gate cannot evaluate narrows the match of the
            # rule. The rule is undecided for a flow that its addresses and
            # service match, and skipped with confidence for a flow that they
            # miss. The gate reads `states_opaque` for this. The sides stay as
            # written. An opaque object would also make a known address miss
            # undecided.
            unread = _unmodelled_match(rule)
            match_reason = "; ".join(
                x
                for x in (
                    states_reason,
                    src_mixed,
                    dst_mixed,
                    unread and f"the rule also matches on {', '.join(unread)}, which is not modelled",
                )
                if x
            )
            ru = b.node(
                "FwRule",
                f"{base}:{num}",
                position=int(num),
                action=rule.get("action"),
                # The gate reads the target's rules in the rule's place (gates/firewall.py `_expand_jumps`).
                jump_target=(
                    named(rule["jump-target"])
                    if rule.get("action") == "jump" and rule.get("jump-target")
                    else ""
                ),
                name=rule.get("description"),
                enabled="disable" not in rule,
                rule_uid=f"{name}:{num}",
                src_any=addr_free(rule.get("source")),
                dst_any=addr_free(rule.get("destination")),
                # The scope form is kept as written.
                out_interface=(rule.get("outbound-interface") or {}).get("name"),
                in_interface=(rule.get("inbound-interface") or {}).get("name"),
                # An absent scope is written as an explicit empty string.
                out_interface_group=(rule.get("outbound-interface") or {}).get("group") or "",
                in_interface_group=(rule.get("inbound-interface") or {}).get("group") or "",
                # The list is empty when the rule names no state.
                states=states or [],
                states_opaque=True if match_reason else None,
                states_opaque_reason=match_reason or None,
                src_negate=True if src_negate else None,
                dst_negate=True if dst_negate else None,
            )
            b.rel("HAS_RULE", "FwRulebase", base, "FwRule", ru)
            # `protocol !tcp` is kept verbatim. The path matcher reads the leading
            # '!' as an operator and needs no list of every other protocol name.
            proto = rule.get("protocol")
            port = (rule.get("destination") or {}).get("port")
            # The source port spec is a property of its own.
            src_port = _port_spec((rule.get("source") or {}).get("port"))
            # The source port is part of the identity. Two rules that agree on
            # protocol and destination port and differ in the source port are
            # two services, in the display name and in the uid.
            src_suffix = f"-src{src_port}" if src_port else ""
            src_label = f" src {src_port}" if src_port else ""
            pgrp = ((rule.get("destination") or {}).get("group") or {}).get("port-group")
            if pgrp:
                grp_ports, why = _port_group_ports(groups, pgrp)
                su = b.node(
                    "SvcObject",
                    f"vyos:{host}:svc:{proto or 'any'}:grp:{pgrp}{src_suffix}",
                    name=f"{proto or 'any'}/{pgrp}{src_label}",
                    proto=proto,
                    ports=grp_ports,
                    src_port=src_port,
                    opaque=True if why else None,
                    opaque_reason=why,
                )
                b.rel("SVC", "FwRule", ru, "SvcObject", su)
            elif proto or port or src_port:
                ports, why = _resolve_ports(port)
                su = b.node(
                    "SvcObject",
                    f"vyos:{host}:svc:{proto or 'any'}-{port or 'any'}{src_suffix}",
                    name=f"{proto or 'any'}/{port or 'any'}{src_label}",
                    proto=proto,
                    ports=ports,
                    src_port=src_port,
                    opaque=True if why else None,
                    opaque_reason=why,
                )
                b.rel("SVC", "FwRule", ru, "SvcObject", su)

    ip4 = fw.get("ipv4") or {}
    for name, rs in (ip4.get("name") or {}).items():
        add_ruleset(f"vyos:{host}:fw:{name}", name, rs)
    for chain in ("forward", "input", "output"):
        rs = (ip4.get(chain) or {}).get("filter")
        if rs:
            add_ruleset(f"vyos:{host}:fw:ipv4-{chain}", f"ipv4-{chain}", rs, chain=chain)

    # Named v6 rulesets get their own uid namespace (`fw:ipv6:<name>`).
    ip6 = fw.get("ipv6") or {}
    for name, rs in (ip6.get("name") or {}).items():
        add_ruleset(f"vyos:{host}:fw:ipv6:{name}", name, rs, v6=True)
    for chain in ("forward", "input", "output"):
        rs = (ip6.get(chain) or {}).get("filter")
        if rs:
            add_ruleset(f"vyos:{host}:fw:ipv6-{chain}", f"ipv6-{chain}", rs, v6=True, chain=chain)

    for zname, z in (fw.get("zone") or {}).items():
        # `intra-zone-filtering` decides traffic between two interfaces of this
        # zone, by an `action` or by a ruleset bound below as the pair (Z, Z).
        # Every zone holds `intra_zone_filtering`. The gate tells a zone that
        # states none from a graph that never recorded it.
        izf = z.get("intra-zone-filtering")
        zu = b.node(
            "Zone",
            f"vyos:{host}:zone:{zname}",
            name=zname,
            # `local-zone` can decode to an empty mapping or string.
            local_zone="local-zone" in z,
            intra_zone_filtering=izf is not None,
            intra_zone_action=(izf or {}).get("action") if isinstance(izf, dict) else None,
            default_action=z.get("default-action"),
            # The gate reads this marker, as the chain default above, to tell an
            # unconfigured zone default from a recorded drop.
            default_action_unknown=z.get("default-action") is None,
            configured_revision=revision,
            **installed,
        )
        b.rel("OWNED_BY", "Zone", zu, "Device", dev)
        # VyOS 1.4 names the interfaces of a zone directly (`zone Z interface
        # eth1`) and accepts VRF names there. VyOS 1.5 holds them under `member`,
        # as `member interface` (where `eth*` is a wildcard) and `member vrf`.
        # The gate finds a zone with no interface for no leg.
        member = z.get("member") or {}
        names = [str(n) for n in listify(z.get("interface")) + listify(member.get("interface"))]
        known_vrfs = set((if_vrf or {}).values())
        vrf_names = {str(v) for v in listify(member.get("vrf"))}
        vrf_names |= {n for n in names if n in known_vrfs and n not in if_uids}
        members = [
            ifname
            for n in names
            for ifname in if_uids
            if (ifname.startswith(n[:-1]) if n.endswith("*") else ifname == n)
        ]
        members += [ifname for ifname, vname in (if_vrf or {}).items() if vname in vrf_names]
        for ifname in dict.fromkeys(members):
            if ifname in if_uids:
                b.rel("CONTAINS", "Zone", zu, "Interface", if_uids[ifname])

    # `zone Z from X firewall name RS`: RS governs traffic from zone X to zone Z.
    # The direction determines which rulebase applies to a given flow.
    # `ipv6-name` binds the v6 ruleset for the same pair.
    for zname, z in (fw.get("zone") or {}).items():
        to_uid = f"vyos:{host}:zone:{zname}"
        pairs = dict(z.get("from") or {})
        # `intra-zone-filtering firewall name RS` governs traffic within the
        # zone as the pair (Z, Z). The zone-pair read of the gate joins it as
        # any other pair.
        izf = z.get("intra-zone-filtering")
        if isinstance(izf, dict) and izf.get("firewall"):
            pairs[zname] = {"firewall": izf["firewall"]}
        for from_zone, spec in pairs.items():
            firewall = spec.get("firewall") or {}
            rulebases = []
            if firewall.get("name"):
                rulebases.append(f"vyos:{host}:fw:{firewall['name']}")
            if firewall.get("ipv6-name"):
                rulebases.append(f"vyos:{host}:fw:ipv6:{firewall['ipv6-name']}")
            for rb in rulebases:
                if rb in defined_rulesets:
                    b.node("FwRulebase", rb, match_context="zone-pair")
                b.rel("FROM_ZONE", "FwRulebase", rb, "Zone", f"vyos:{host}:zone:{from_zone}")
                b.rel("TO_ZONE", "FwRulebase", rb, "Zone", to_uid)


def _nat_iface(rule: dict, key: str) -> str | None:
    """Return the interface name of `inbound-interface` or `outbound-interface`.

    VyOS 1.3 writes a bare string. VyOS 1.4 and later write `{"name": ...}`.
    """
    val = rule.get(key)
    if isinstance(val, dict):
        return val.get("name")
    return val


def _nat_side_groups(
    b: GraphBuilder,
    host: str,
    nat_uid: str,
    rel: str,
    name: str,
    side: dict,
    groups: dict,
    v6: bool,
) -> tuple[str | None, list[str]]:
    """Returns (port spec, reasons the side's scope is not modelled)."""
    grp = side.get("group") or {}
    if not isinstance(grp, dict):
        return None, []
    reasons: list[str] = []
    port_spec: str | None = None
    address_keys = {"address-group": "addr", "network-group": "net"}
    if v6:
        address_keys = {
            "address-group": "addr6",
            "ipv6-address-group": "addr6",
            "network-group": "net6",
            "ipv6-network-group": "net6",
        }
    address_constraints = 1 if side.get("address") or side.get("prefix") else 0
    for key, value in grp.items():
        if key in address_keys:
            address_constraints += 1
            negated, gname = _negated(value)
            if negated:
                reasons.append(f"the rule's {name} group {key} {value} is negated, which is not modeled")
                continue
            infix = address_keys[key]
            gu = f"vyos:{host}:grp:{infix}:{gname}"
            cfg_key = _GROUP_KEY_OF_INFIX[infix]
            if gname not in (groups.get(cfg_key) or {}):
                b.node(
                    "NetObject",
                    gu,
                    name=gname,
                    kind="group",
                    opaque=True,
                    opaque_reason=f"{cfg_key} {gname} is not defined",
                )
            b.rel(rel, "NatRule", nat_uid, "NetObject", gu)
        elif key == "port-group":
            ports, why = _port_group_ports(groups, str(value))
            if why or not ports:
                reasons.append(
                    f"the rule's {name} port-group {value} is not resolved: {why or 'it lists no port'}"
                )
            elif side.get("port"):
                reasons.append(f"the rule's {name} matches on both a port and port-group {value}")
            else:
                port_spec = ",".join(ports)
        else:
            reasons.append(f"the rule's {name} group {key} {value} is not modeled")
    if address_constraints > 1:
        reasons.append(f"the rule's {name} matches on more than one address constraint")
    return port_spec, reasons


def _nat(b: GraphBuilder, cfg: dict, dev: str, host: str, l3dom: str) -> None:
    # `l3dom` is a resolved L3 domain (core/l3domain.py).
    groups = (cfg.get("firewall") or {}).get("group") or {}

    def side(nat_uid: str, rel: str, addr: str | None) -> None:
        # Ranges and negated addresses stay on the rule's raw-match properties.
        if not addr or addr == "masquerade" or "-" in addr or addr.startswith("!"):
            return
        if "/" in addr:
            target = b.node(
                "Prefix", uid.prefix(l3dom, addr), cidr=addr, af=_af(addr), l3dom=l3dom, anchor=l3dom
            )
            b.rel(rel, "NatRule", nat_uid, "Prefix", target)
        else:
            target = b.node(
                "IpAddress", uid.ip(l3dom, addr), ip=addr, af=_af(addr), l3dom=l3dom, anchor=l3dom
            )
            b.rel(rel, "NatRule", nat_uid, "IpAddress", target)

    # `nat66` is the IPv6 tree with the shape of `nat` (source and destination
    # rules, translation address, masquerade). The tree name is part of the
    # rulebase uid, and the two trees never collide. `static` is the 1.4
    # one-to-one tree. It is bidirectional, its rules have kind="static", and
    # the engine applies them in both stages.
    for tree in ("nat", "nat66"):
        nat = cfg.get(tree) or {}
        directions = [("source", "snat"), ("destination", "dnat")]
        if tree == "nat":
            directions.append(("static", "static"))
        for direction, kind in directions:
            rules = (nat.get(direction) or {}).get("rule") or {}
            if not rules:
                continue
            rb = b.node(
                "FwRulebase",
                f"vyos:{host}:{tree}:{direction}",
                name=f"{tree}-{direction}",
                kind="nat",
                vendor="vyos",
            )
            b.rel("ENFORCES", "Device", dev, "FwRulebase", rb)
            for num, rule in sorted(rules.items(), key=lambda kv: int(kv[0])):
                trans = rule.get("translation") or {}
                src, dst = rule.get("source") or {}, rule.get("destination") or {}
                nat_uid = f"{rb}:{num}"
                src_group_port, unscoped = _nat_side_groups(
                    b, host, nat_uid, "ORIG_SRC", "source", src, groups, tree == "nat66"
                )
                dst_group_port, dst_unscoped = _nat_side_groups(
                    b, host, nat_uid, "ORIG_DST", "destination", dst, groups, tree == "nat66"
                )
                unscoped += dst_unscoped
                # This module does not resolve an interface group.
                for key in ("inbound-interface", "outbound-interface"):
                    bound = rule.get(key)
                    if isinstance(bound, dict) and bound.get("group"):
                        unscoped.append(f"the rule's {key} group {bound['group']} is not collected")
                nu = b.node(
                    "NatRule",
                    nat_uid,
                    position=int(num),
                    kind=kind,
                    name=rule.get("description"),
                    translation=trans.get("address") or trans.get("prefix"),
                    translation_port=trans.get("port"),
                    # The path engine parses the match tuple (cidr, single address, range).
                    orig_src=src.get("address") or src.get("prefix"),
                    orig_dst=dst.get("address") or dst.get("prefix"),
                    orig_src_port=src.get("port") or src_group_port,
                    orig_dst_port=dst.get("port") or dst_group_port,
                    protocol=rule.get("protocol"),
                    in_if=_nat_iface(rule, "inbound-interface"),
                    out_if=_nat_iface(rule, "outbound-interface"),
                    # With a scope that the NAT engine cannot evaluate, the
                    # rule claims the flows that the rest of its match covers,
                    # as undecided. Without such a scope, the rule has False
                    # and an empty reason. The SET of the loader only adds, and
                    # a refresh must clear both.
                    approximate=bool(unscoped),
                    approximate_reason="; ".join(unscoped),
                    # `exclude` claims the flow without translating it.
                    exclude="exclude" in rule,
                    enabled="disable" not in rule,
                    # The family of the rule. `nat` is IPv4, and `nat66` is IPv6.
                    af=6 if tree == "nat66" else 4,
                )
                b.rel("HAS_RULE", "FwRulebase", rb, "NatRule", nu)
                side(nu, "ORIG_SRC", src.get("address") or src.get("prefix"))
                side(nu, "ORIG_DST", dst.get("address") or dst.get("prefix"))
                if kind == "snat":
                    side(nu, "XLATE_SRC", trans.get("address") or trans.get("prefix"))
                else:
                    side(nu, "XLATE_DST", trans.get("address") or trans.get("prefix"))


# --- OSPF: FRR via vtysh, per VRF --------------------------------------------
# The JSON field names come from the FRR documentation and are not confirmed against a
# live capture.

_OSPF_SUBCOMMANDS: tuple[tuple[str, str], ...] = (
    ("process", ""),
    ("interfaces", "interface"),
    ("neighbors", "neighbor"),
    ("lsdb_router", "database router"),
    ("lsdb_network", "database network"),
    ("lsdb_summary", "database summary"),
    ("lsdb_asbr_summary", "database asbr-summary"),
    ("lsdb_external", "database external"),
    ("lsdb_nssa_external", "database nssa-external"),
)

_LSA_WRAPPER: dict[str, str] = {
    "router": "routerLinkStates",
    "network": "networkLinkStates",
    "summary": "summaryLinkStates",
    "asbr-summary": "asbrSummaryLinkStates",
    "nssa-external": "nssaExternalLinkStates",
}

# The FRR network-type words (`show ip ospf interface json`), mapped onto the
# protocol names of the shared schema.
_FRR_NETWORK_TYPES: dict[str, str] = {
    "pointopoint": "point-to-point",
    "point-to-point": "point-to-point",
    "broadcast": "broadcast",
    "nbma": "nbma",
    "pointomultipoint": "point-to-multipoint",
    "point-to-multipoint": "point-to-multipoint",
    "loopback": "loopback",
    "virtuallink": "virtual",
    "virtual-link": "virtual",
}


def _ospf_vrf_names(cfg: dict[str, Any]) -> list[str]:
    """A bare `protocols ospf` stanza reads as `{}` in `show configuration json`."""
    names = []
    if (cfg.get("protocols") or {}).get("ospf") is not None:
        names.append("")
    for vname, vnode in ((cfg.get("vrf") or {}).get("name") or {}).items():
        if ((vnode or {}).get("protocols") or {}).get("ospf") is not None:
            names.append(vname)
    return names


def _ospf_cfg_for(cfg: dict[str, Any], vrf_name: str) -> dict[str, Any]:
    if not vrf_name:
        return (cfg.get("protocols") or {}).get("ospf") or {}
    vnode = ((cfg.get("vrf") or {}).get("name") or {}).get(vrf_name) or {}
    return ((vnode or {}).get("protocols") or {}).get("ospf") or {}


def _ospf_command(sub: str, vrf_name: str) -> str:
    """Return one `vtysh -c "show ip ospf ..."` command.

    An empty `vrf_name` runs the bare command (the default VRF). A named VRF
    inserts "vrf <name>" after "ospf", as the FRR grammar has it (`show ip
    ospf [vrf NAME] ...`)."""
    parts = ["show", "ip", "ospf"]
    if vrf_name:
        parts += ["vrf", vrf_name]
    if sub:
        parts += sub.split()
    parts.append("json")
    return f'{_IP_PATH} vtysh -c "{" ".join(parts)}"'


def _ospf_raw_key(vrf_name: str, sub_key: str) -> str:
    return f"ospf_{vrf_name or 'default'}_{sub_key}"


def _ospf_redistribute(cfg: dict[str, Any], vrf_name: str) -> list[dict[str, Any]]:
    ospf_cfg = _ospf_cfg_for(cfg, vrf_name)
    return [
        {"protocol": proto, "route_map": (node or {}).get("route-map")}
        for proto, node in (ospf_cfg.get("redistribute") or {}).items()
    ]


def _ospf_default_originate(cfg: dict[str, Any], vrf_name: str) -> dict[str, bool]:
    """Return `protocols ospf default-information originate [always]` as the
    process fields that `cisco_common.ospf_default_originate` names, or an
    empty dict when the setting is absent."""
    originate = (_ospf_cfg_for(cfg, vrf_name).get("default-information") or {}).get("originate")
    if originate is None:
        return {}
    return ospf_default_originate("always" if "always" in (originate or {}) else None)


def _ospf_int(value: Any) -> int | None:
    """Return an OSPF numeric column as an int.

    vtysh prints a JSON int, a decimal string, or the hex form of an LSA
    sequence number ("0x80000005")."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def _ospf_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in ("true", "yes", "1"):
        return True
    if text in ("false", "no", "0", ""):
        return False
    return None


def _ospf_metric_type(value: Any) -> int | None:
    """Return the external metric type, 1 or 2 (the E bit of the LSA).

    FRR prints the type as "E1" or "E2".
    """
    if value is None:
        return None
    digits = re.search(r"[12]", str(value))
    return int(digits.group()) if digits else None


def _ospf_frr_state(value: Any) -> str | None:
    """Return the state word of an FRR neighbor state.

    FRR appends the DR/BDR role to the state ("Full/DR"). The `state` column
    of the schema holds the state word.
    """
    if not value:
        return None
    return str(value).split("/", 1)[0].strip().upper() or None


def _ospf_process_of(payload: dict[str, Any]) -> dict[str, Any]:
    """Return {router_id, areas} from the bare `show ip ospf [vrf NAME] json` payload."""
    areas = []
    for area_id, area in (payload.get("areas") or {}).items():
        if _ospf_bool(area.get("nssa")):
            kind = "nssa"
        elif _ospf_bool(area.get("stub")):
            kind = "stub"
        else:
            kind = "normal"
        areas.append({"area_id": area_id, "type": kind})
    return {"router_id": payload.get("routerId"), "areas": areas}


def _ospf_area_id(value: Any) -> str | None:
    """Return the area id of an area that FRR names.

    `ospf_area_desc_string` prints a stub or NSSA area with its type after
    the id (`0.0.0.1 [Stub]`). The area ids of the process have no type.
    """
    return str(value or "").split(" ", 1)[0] or None


def _ospf_interfaces_of(payload: dict[str, Any], vrf_name: str) -> list[dict[str, Any]]:
    out = []
    for name, row in (payload.get("interfaces") or {}).items():
        area = _ospf_area_id(row.get("area"))
        if not area:
            continue
        raw_type = str(row.get("networkType") or "").strip().lower()
        out.append(
            {
                "process": "",
                "vrf": vrf_name,
                "name": name,
                "area": area,
                "cost": _ospf_int(row.get("cost")),
                "network_type": _FRR_NETWORK_TYPES.get(raw_type, raw_type or None),
                "passive": _ospf_bool(row.get("timerPassiveIface")),
            }
        )
    return out


def _ospf_adjacencies_of(
    payload: dict[str, Any], vrf_name: str, area_by_if: dict[str, str | None]
) -> list[dict[str, Any]]:
    out = []
    for rid, entries in (payload.get("neighbors") or {}).items():
        rows = entries if isinstance(entries, list) else [entries]
        for row in rows:
            if not isinstance(row, dict):
                continue
            iface_field = str(row.get("ifaceName") or "")
            name = iface_field.split(":", 1)[0].strip() or None
            if not name:
                continue
            out.append(
                {
                    "process": "",
                    "vrf": vrf_name,
                    "area": area_by_if.get(name),
                    "local_interface": name,
                    "neighbor_router_id": str(rid),
                    "neighbor_ip": row.get("address"),
                    "state": _ospf_frr_state(row.get("nbrState")),
                }
            )
    return out


def _ospf_lsa_links(lsa: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "link_type": str(link.get("linkType") or "").strip().lower() or None,
            "link_id": link.get("linkId"),
            "link_data": link.get("linkData"),
            "metric": _ospf_int(link.get("metric")),
        }
        for link in lsa.get("routerLinks") or []
    ]


def _ospf_attached_routers(lsa: dict[str, Any]) -> list[str]:
    return [str(r) for r in lsa.get("attachedRouters") or [] if r]


def _ospf_lsa_row(lsa: dict[str, Any], *, vrf: str, area: str | None, lsa_type: str) -> dict[str, Any]:
    return {
        "process": "",
        "vrf": vrf,
        "area": area,
        "lsa_type": lsa_type,
        "lsid": lsa.get("lsId"),
        "adv_router": lsa.get("advertisedRouter"),
        "seq": _ospf_int(lsa.get("lsaSeqNumber")),
        "age": _ospf_int(lsa.get("lsaAge")),
        "metric": None if lsa_type in ("router", "network") else _ospf_int(lsa.get("metric")),
        "links": _ospf_lsa_links(lsa) if lsa_type == "router" else None,
        "attached_routers": (_ospf_attached_routers(lsa) if lsa_type == "network" else None),
        "mask": lsa.get("networkMask"),
        "forwarding_address": lsa.get("forwardAddress"),
        "metric_type": _ospf_metric_type(lsa.get("metricType")),
    }


def _ospf_lsdb_of(raw: dict[str, Any], vrf_name: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key, lsa_type in (
        ("lsdb_router", "router"),
        ("lsdb_network", "network"),
        ("lsdb_summary", "summary"),
        ("lsdb_asbr_summary", "asbr-summary"),
        ("lsdb_external", "external"),
        ("lsdb_nssa_external", "nssa-external"),
    ):
        payload = raw.get(_ospf_raw_key(vrf_name, key))
        if not isinstance(payload, dict):
            continue
        if lsa_type == "external":
            # An AS-external LSA is flooded in the whole domain and has no area.
            for lsa in payload.get("asExternalLinkStates") or []:
                rows.append(_ospf_lsa_row(lsa, vrf=vrf_name, area=None, lsa_type=lsa_type))
            continue
        wrapper = payload.get(_LSA_WRAPPER[lsa_type]) or {}
        for area_id, entries in (wrapper.get("areas") or {}).items():
            for lsa in entries or []:
                rows.append(_ospf_lsa_row(lsa, vrf=vrf_name, area=_ospf_area_id(area_id), lsa_type=lsa_type))
    return rows


def _parse_ospf(raw: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any] | None:
    """None when no VRF has a `protocols ospf` stanza configured."""
    vrf_names = _ospf_vrf_names(cfg)
    if not vrf_names:
        return None

    def _get(vname: str, key: str) -> dict[str, Any]:
        value = raw.get(_ospf_raw_key(vname, key))
        return value if isinstance(value, dict) else {}

    processes, interfaces, adjacencies, lsdb = [], [], [], []
    for vname in vrf_names:
        proc = _ospf_process_of(_get(vname, "process"))
        proc["process"] = ""
        proc["vrf"] = vname
        proc["redistribute"] = _ospf_redistribute(cfg, vname)
        proc.update(_ospf_default_originate(cfg, vname))
        processes.append(proc)

        ifs = _ospf_interfaces_of(_get(vname, "interfaces"), vname)
        interfaces.extend(ifs)
        area_by_if = {i["name"]: i["area"] for i in ifs}

        adjacencies.extend(_ospf_adjacencies_of(_get(vname, "neighbors"), vname, area_by_if))
        lsdb.extend(_ospf_lsdb_of(raw, vname))

    return {"processes": processes, "interfaces": interfaces, "adjacencies": adjacencies, "lsdb": lsdb}


def _ospf_lsdb_rows(ospf: dict[str, Any], device_uid: str) -> list[dict[str, Any]]:
    """This collector's per-VRF uid is `f"vrf:{dev}:{uid.slug(name)}"`."""
    return [
        {
            "device_uid": device_uid,
            "context_uid": f"vrf:{device_uid}:{uid.slug(lsa.get('vrf') or DEFAULT_VRF)}",
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
        for lsa in ospf.get("lsdb") or []
    ]


# --- BGP session and path observations: the FRR `vtysh ... json` capture ----------------
# Without a family FRR answers for IPv6 unicast.

BGP_SUMMARY_COMMAND = f'{_IP_PATH} vtysh -c "show bgp vrf all summary json"'

# The neighbor detail of every VRF. It is the one command that states the
# router identifier of the peer (`remoteRouterId`, `neighbor_router_ids`).
BGP_NEIGHBORS_COMMAND = f'{_IP_PATH} vtysh -c "show ip bgp vrf all neighbors json"'

# The three directions of a session map to the per-neighbor command keyword of
# FRR, the top-level JSON key of the answer, and the RIB and policy stage of
# the rows. `received` needs soft reconfiguration inbound on the neighbor.
# Without it, FRR does not keep the pre-policy table and says so, and the
# direction is recorded as `not-captured`.
BGP_DIRECTION_KEYWORDS: dict[str, str] = {
    "received": "received-routes",
    "accepted": "routes",
    "advertised": "advertised-routes",
}
_FRR_ROUTE_TABLE_KEYS: dict[str, str] = {
    "received": "receivedRoutes",
    "accepted": "routes",
    "advertised": "advertisedRoutes",
}
BGP_RIB_TYPES: dict[str, str] = {
    "received": "adj-rib-in",
    "accepted": "loc-rib",
    "advertised": "adj-rib-out",
}
BGP_POLICY_STAGES: dict[str, str] = {
    "received": "pre-import",
    "accepted": "post-import",
    "advertised": "post-export",
}

# The sub-family of every observed row is ipv4-unicast.
BGP_SAFI = "unicast"


def bgp_route_command(vrf_name: str, peer_ip: str, direction: str) -> str:
    """Return the per-neighbor path command for one direction.

    The command is `vtysh -c "show bgp [vrf <vrf>] ipv4 unicast neighbors
    <peer> received-routes|routes|advertised-routes json"`. The VRF clause is
    absent for the default table, as in `nxos.bgp_route_command`. The VRF
    clause comes before the family, as the FRR grammar has it."""
    scope = "" if not vrf_name or vrf_name == DEFAULT_VRF else f"vrf {vrf_name} "
    keyword = BGP_DIRECTION_KEYWORDS[direction]
    return f'{_IP_PATH} vtysh -c "show bgp {scope}ipv4 unicast neighbors {peer_ip} {keyword} json"'


def legacy_bgp_route_command(vrf_name: str, peer_ip: str, direction: str) -> str:
    """FRR answers this command for IPv6 unicast."""
    scope = "" if not vrf_name or vrf_name == DEFAULT_VRF else f"vrf {vrf_name} "
    keyword = BGP_DIRECTION_KEYWORDS[direction]
    return f'{_IP_PATH} vtysh -c "show bgp {scope}neighbors {peer_ip} {keyword} json"'


def _stored_route_command(
    raw: dict[str, Any], vrf_name: str, peer_ip: str, direction: str
) -> tuple[str, bool]:
    """A payload fetched without the family clause holds `legacy_bgp_route_command`."""
    command = bgp_route_command(vrf_name, peer_ip, direction)
    if command not in raw:
        legacy = legacy_bgp_route_command(vrf_name, peer_ip, direction)
        if legacy in raw:
            return legacy, True
    return command, False


def bgp_capture_targets(
    cfg: dict[str, Any],
    observed_as: dict[tuple[str, str], int] | None = None,
    peers: Iterable[tuple[str, str]] = (),
) -> list[tuple[str, str]]:
    """The pairs are in configuration order and without duplicates."""
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(vrf_name: str, bgp_cfg: dict[str, Any] | None) -> None:
        if not bgp_cfg:
            return
        for peer_ip, neighbor in bgp_neighbors(bgp_cfg, vrf_name, peers).items():
            if _neighbor_remote_as(bgp_cfg, neighbor, (observed_as or {}).get((vrf_name, peer_ip))) is None:
                continue
            key = (vrf_name, peer_ip)
            if key not in seen:
                seen.add(key)
                out.append(key)

    add(DEFAULT_VRF, (cfg.get("protocols") or {}).get("bgp"))
    for vname, vnode in ((cfg.get("vrf") or {}).get("name") or {}).items():
        add(vname, ((vnode or {}).get("protocols") or {}).get("bgp"))
    return out


def parse_bgp_summary(text: str) -> list[dict[str, Any]]:
    """`established_since_ms` and `capabilities` stay null."""
    if _blank_answer(text):
        return []
    try:
        payload = json.loads(text)
    except ValueError:
        return []
    return _summary_sessions(payload)


def _summary_sessions(payload: Any) -> list[dict[str, Any]]:
    """The session records of one decoded summary (`parse_bgp_summary`)."""
    if not isinstance(payload, dict):
        return []
    out: list[dict[str, Any]] = []
    for vrf_name, vrf_payload in payload.items():
        if not isinstance(vrf_payload, dict):
            continue
        fam = vrf_payload.get("ipv4Unicast")
        if not isinstance(fam, dict):
            continue
        peers = fam.get("peers")
        if not isinstance(peers, dict):
            continue
        for peer_ip, p in peers.items():
            if not isinstance(p, dict):
                continue
            out.append(
                {
                    "vrf": vrf_name,
                    "peer_ip": peer_ip,
                    "state": p.get("state"),
                    "established_since_ms": None,
                    "prefixes_received": p.get("pfxRcd"),
                    "prefixes_advertised": p.get("pfxSnt"),
                    "capabilities": None,
                }
            )
    return out


def _bgp_communities(value: Any) -> str | None:
    if isinstance(value, list):
        joined = " ".join(str(v) for v in value if v not in (None, ""))
        return joined or None
    text = str(value).strip() if value not in (None, "") else ""
    return text or None


def _bgp_best(path: dict[str, Any], direction: str) -> bool | None:
    """None for the received direction."""
    if direction == "received":
        return None
    value = path.get("bestpath")
    return None if value is None else bool(value)


def parse_bgp_paths(
    text: str, *, vrf: str, peer_ip: str, direction: str, legacy: bool = False
) -> list[dict[str, Any]]:
    """`legacy` reads the answer of a command without the family clause."""
    return list(_bgp_path_rows(text, vrf=vrf, peer_ip=peer_ip, direction=direction, legacy=legacy))


def _bgp_path_rows(
    text: Any, *, vrf: str, peer_ip: str, direction: str, legacy: bool = False
) -> Iterator[dict[str, Any]]:
    """Yield the records that `parse_bgp_paths` returns, one at a time.

    A blank answer, an answer that is not JSON and an answer that is not a
    JSON object yield none. The decoded tree lives as long as the iteration."""
    if _blank_answer(text):
        return
    try:
        payload = json.loads(text)
    except ValueError:
        return
    if not isinstance(payload, dict):
        return
    read = _iter_bgp_paths if legacy else _iter_frr_paths
    yield from read(payload, vrf=vrf, peer_ip=peer_ip, direction=direction)


def _frr_next_hop(path: dict[str, Any]) -> Any:
    """Return the next hop of one path.

    The value is the used entry of `nexthops`, else its first entry, else the
    `nextHop` of the adj forms."""
    nexthops = [h for h in (path.get("nexthops") or []) if isinstance(h, dict)]
    if nexthops:
        used = next((h.get("ip") for h in nexthops if h.get("used")), None)
        return used if used is not None else nexthops[0].get("ip")
    value = path.get("nextHop")
    return value if isinstance(value, str) and value else None


def _frr_as_path(path: dict[str, Any]) -> str | None:
    """Return the AS path of one path.

    The value is `aspath.string` (or `aspath` as a string), else `path`, the
    string that both brief forms print."""
    aspath = path.get("aspath")
    if isinstance(aspath, dict):
        aspath = aspath.get("string")
    if isinstance(aspath, str) and aspath:
        return aspath
    value = path.get("path")
    return value if isinstance(value, str) and value else None


def _frr_best(path: dict[str, Any], direction: str) -> bool | None:
    """Return whether FRR marked this path best, from the FRR keys.

    The value is None for the received direction, as in `_bgp_best`. That
    direction is read before the decision process runs. For the accepted
    direction (`routes`), `bestpath` is a boolean (the brief form) or an
    object with `overall` (the detail form). FRR prints the key on the best
    path only, and a path without it is no best path. For the advertised
    direction, the adj form prints `best`. When it prints neither `best` nor
    `bestpath`, the value is None.
    """
    if direction == "received":
        return None
    value = path.get("bestpath")
    if isinstance(value, dict):
        overall = value.get("overall")
        return None if overall is None else bool(overall)
    if value is not None:
        return bool(value)
    if direction == "advertised":
        best = path.get("best")
        return None if best is None else bool(best)
    return False


def _iter_frr_paths(
    payload: dict[str, Any], *, vrf: str, peer_ip: str, direction: str
) -> Iterator[dict[str, Any]]:
    """Yield the path records of one decoded path table in the FRR shapes.

    A prefix maps to an array of path objects (`routes`) or to one object
    (`advertisedRoutes`, `receivedRoutes`). An entry of neither shape yields
    nothing. `_route_table_problem` makes the direction fail on such an entry."""
    table = payload.get(_FRR_ROUTE_TABLE_KEYS[direction])
    if not isinstance(table, dict):
        return
    for prefix, value in table.items():
        paths = [value] if isinstance(value, dict) else value if isinstance(value, list) else []
        for idx, path in enumerate(paths):
            if not isinstance(path, dict):
                continue
            yield {
                "vrf": vrf,
                "peer_ip": peer_ip,
                "direction": direction,
                "prefix": prefix,
                "path_id": str(idx),
                "next_hop": _frr_next_hop(path),
                "as_path": _frr_as_path(path),
                "local_pref": as_int(path.get("locPrf")),
                "med": as_int(path.get("metric")),
                "origin": path.get("origin"),
                "communities": _bgp_communities(path.get("communityList")),
                "best": _frr_best(path, direction),
            }


# The top-level counter of each direction that states the number of printed
# prefixes. `numRoutes` is the counter of `routes`. `totalPrefixCounter` is the
# counter of the adj forms.
_FRR_PREFIX_COUNTERS: dict[str, str] = {
    "received": "totalPrefixCounter",
    "accepted": "numRoutes",
    "advertised": "totalPrefixCounter",
}


def _ipv4_prefix(prefix: Any) -> bool:
    """Whether a table key is an IPv4 prefix, the family the command asks for."""
    try:
        return ipaddress.ip_network(prefix).version == 4
    except (TypeError, ValueError):
        return False


def _route_table_problem(payload: dict[str, Any], direction: str) -> str | None:
    """Return why one decoded answer, which is a JSON object and no warning, is
    no route table that this collector can read whole, or None when it is one.

    A table is read whole when the table key of the direction is an object,
    every key of it is an IPv4 prefix, every value is a path object or a
    non-empty array of path objects, and the prefix counter of the answer, if
    the answer states one, is the number of printed prefixes. An empty table
    must have the form that FRR prints, the key with an empty object and, for
    the adj forms, `totalPrefixCounter` 0.
    """
    key = _FRR_ROUTE_TABLE_KEYS[direction]
    table = payload.get(key)
    if table is None:
        if not payload:
            return f"the answer is an empty JSON object, with no {key} table"
        found = ", ".join(sorted(str(k) for k in payload)[:12])
        return f"the answer has no {key} table; its top-level keys are {found}"
    if not isinstance(table, dict):
        return f"the {key} table of the answer is not a JSON object"
    unread = 0
    for prefix, value in table.items():
        if not _ipv4_prefix(prefix):
            unread += 1
        elif isinstance(value, dict):
            continue
        elif not (isinstance(value, list) and value and all(isinstance(p, dict) for p in value)):
            unread += 1
    if unread:
        return f"{unread} of the {len(table)} prefixes of the {key} table could not be read"
    counter_key = _FRR_PREFIX_COUNTERS[direction]
    counter = payload.get(counter_key)
    if counter is None:
        if not table and direction != "accepted":
            return f"the {key} table is empty and the answer states no {counter_key}"
        return None
    stated = as_int(counter)
    if stated != len(table):
        return f"the answer states {counter_key} {counter} and its {key} table has {len(table)} prefixes"
    return None


def _iter_bgp_paths(
    payload: dict[str, Any], *, vrf: str, peer_ip: str, direction: str
) -> Iterator[dict[str, Any]]:
    """A prefix's value is read only as an array."""
    table = payload.get(_FRR_ROUTE_TABLE_KEYS[direction])
    if not isinstance(table, dict):
        return
    for prefix, paths in table.items():
        if not isinstance(paths, list):
            continue
        for idx, path in enumerate(paths):
            if not isinstance(path, dict):
                continue
            nexthops = [h for h in (path.get("nexthops") or []) if isinstance(h, dict)]
            used = next((h.get("ip") for h in nexthops if h.get("used")), None)
            next_hop = used if used is not None else (nexthops[0].get("ip") if nexthops else None)
            yield {
                "vrf": vrf,
                "peer_ip": peer_ip,
                "direction": direction,
                "prefix": prefix,
                "path_id": str(idx),
                "next_hop": next_hop,
                "as_path": (path.get("aspath") or {}).get("string") or None,
                "local_pref": as_int(path.get("locPrf")),
                "med": as_int(path.get("metric")),
                "origin": path.get("origin"),
                "communities": _bgp_communities(path.get("communityList")),
                "best": _bgp_best(path, direction),
            }


# The helpers below read an observation answer once. `_command_outcome` judges
# an answer as `str(text or "").strip()` reads it, and the parsers above decode
# it as it is. The helpers state the stripped reading in place, without the
# copy that `strip` makes of a full table, and decode the answer once for both.
#
# `\s` in a str pattern and `str.strip` share one definition of whitespace
# (`str.isspace`). The first `\S` is where the stripped text starts.
_NON_SPACE = re.compile(r"\S")
# Every character `str.splitlines` ends a line at ("\r\n" ends at its "\r").
_LINE_BREAK = re.compile("[\n\r\x0b\x0c\x1c-\x1e\x85\u2028\u2029]")
# The whitespace that JSON allows around a value and that `json.loads` skips.
# The pattern is the pattern of `json.decoder.WHITESPACE`.
_JSON_WHITESPACE = re.compile(r"[ \t\n\r]*")
_DECODER = json.JSONDecoder()

# The kinds are `empty`, `percent`, `not-json`, `not-object`, `warning`, `object` and `unread`.
CommandFacts = tuple[str, str]

# The value that `_read_answer` returns for an answer that `json.loads` does not decode.
_UNDECODED = object()


def _blank_answer(text: Any) -> bool:
    """`not str(text or "").strip()`, tested in place for a str."""
    if isinstance(text, str):
        return _NON_SPACE.search(text) is None
    return not str(text or "").strip()


def _content_span(text: str) -> tuple[int, int] | None:
    """Return `(start, end)` with `text[start:end] == text.strip()`, or None
    when the stripped text is empty.

    The function makes no copy of the text.
    """
    match = _NON_SPACE.search(text)
    if match is None:
        return None
    end = len(text)
    # The loop stops at `match.start()` at the latest, which is not whitespace.
    while text[end - 1].isspace():
        end -= 1
    return match.start(), end


def _first_line(text: str, start: int, end: int) -> str:
    """`text[start:end].splitlines()[0]` for a non-empty span, without
    splitting the span."""
    match = _LINE_BREAK.search(text, start, end)
    return text[start : match.start() if match else end]


def _decode_span(text: str, start: int, end: int) -> Any:
    """Return `json.loads(text[start:end])` for a span that `_content_span`
    returned, without the slice.

    The function raises ValueError wherever `json.loads` raises. The value
    cannot run past `end`. It ends on a character that is not whitespace, and
    everything from `end` on is whitespace. The text between the value and
    `end` must be JSON whitespace, or it is the extra data that `json.loads`
    rejects."""
    value, stop = _DECODER.raw_decode(text, start)
    if _JSON_WHITESPACE.match(text, stop, end).end() != end:
        raise json.JSONDecodeError("Extra data", text, stop)
    return value


def _payload_facts(payload: Any) -> CommandFacts:
    """The `CommandFacts` of an answer that decoded to `payload`."""
    if not isinstance(payload, dict):
        return "not-object", ""
    warning = payload.get("warning")
    if isinstance(warning, str) and warning:
        return "warning", warning
    return "object", ""


def _span_facts(text: str, start: int, end: int) -> CommandFacts:
    """The `CommandFacts` of the stripped answer `text[start:end]`."""
    if text[start] == "%":
        return "percent", _first_line(text, start, end).strip()
    try:
        payload = _decode_span(text, start, end)
    except ValueError:
        return "not-json", ""
    return _payload_facts(payload)


def _outcome_facts(text: Any) -> CommandFacts:
    """The `CommandFacts` of one answer, read as `str(text or "").strip()`
    reads it, without the copy."""
    if not isinstance(text, str):
        text = str(text or "")
    span = _content_span(text)
    if span is None:
        return "empty", ""
    return _span_facts(text, *span)


def _read_answer(text: str) -> tuple[CommandFacts, Any]:
    """Return the `CommandFacts` of one answer and the value that
    `json.loads(text)` decodes (`_UNDECODED` where it raises), from one decode.

    `_command_outcome` reads the answer stripped, and the parsers read it as it
    is. The two readings agree when the whitespace around the value is JSON
    whitespace, which `json.loads` skips. One `json.loads(text)` then serves
    both. `json.loads` rejects any other whitespace at an edge (a form feed, a
    no-break space, U+2028) and a leading `%`. The parsers read nothing from
    such an answer, and only the stripped reading is made.
    """
    span = _content_span(text)
    if span is None:
        return ("empty", ""), _UNDECODED
    start, end = span
    json_before = _JSON_WHITESPACE.match(text, 0, start).end() == start
    json_after = _JSON_WHITESPACE.match(text, end).end() == len(text)
    if text[start] == "%" or not (json_before and json_after):
        return _span_facts(text, start, end), _UNDECODED
    try:
        payload = json.loads(text)
    except ValueError:
        return ("not-json", ""), _UNDECODED
    return _payload_facts(payload), payload


def _summary_read(text: Any) -> tuple[CommandFacts, list[dict[str, Any]]]:
    """The summary's `CommandFacts` and `parse_bgp_summary(text)`, from one
    decode."""
    if not isinstance(text, str):
        return _outcome_facts(text), parse_bgp_summary(text)
    facts, payload = _read_answer(text)
    return facts, [] if payload is _UNDECODED else _summary_sessions(payload)


def _direction_read(
    text: Any, *, vrf: str, peer_ip: str, direction: str, legacy: bool = False
) -> tuple[CommandFacts, int]:
    """An answer that is not a whole route table is `unread`, with the reason and no record."""
    if legacy:
        if not isinstance(text, str):
            rows = _bgp_path_rows(text, vrf=vrf, peer_ip=peer_ip, direction=direction, legacy=True)
            return _outcome_facts(text), sum(1 for _ in rows)
        facts, payload = _read_answer(text)
        if not isinstance(payload, dict):
            return facts, 0
        rows = _iter_bgp_paths(payload, vrf=vrf, peer_ip=peer_ip, direction=direction)
        return facts, sum(1 for _ in rows)
    facts, payload = _read_answer(text if isinstance(text, str) else str(text or ""))
    if facts[0] == "empty":
        return ("unread", "the command printed nothing, which is no route table"), 0
    if facts[0] != "object" or not isinstance(payload, dict):
        return facts, 0
    problem = _route_table_problem(payload, direction)
    if problem is not None:
        return ("unread", problem), 0
    rows = _iter_frr_paths(payload, vrf=vrf, peer_ip=peer_ip, direction=direction)
    return facts, sum(1 for _ in rows)


def bgp_observed(raw: dict[str, Any]) -> dict[str, Any]:
    """A direction whose command is absent from the payload has no row count."""
    summary_facts, sessions = _summary_read(raw.get(BGP_SUMMARY_COMMAND) or "")
    parts: list[tuple[int, Callable[[], Iterable[dict[str, Any]]]]] = []
    directions: list[dict[str, Any]] = []
    command_facts: dict[str, CommandFacts] = {}
    cfg = raw.get("config") or {}
    peers = summary_peers(raw.get(BGP_SUMMARY_COMMAND))
    observed_as = {key: asn for key, asn in peers.items() if asn is not None}
    for vrf_name, peer_ip in bgp_capture_targets(cfg, observed_as, peers):
        for direction in BGP_DIRECTION_KEYWORDS:
            # A payload fetched without the family clause holds the legacy key.
            command, legacy = _stored_route_command(raw, vrf_name, peer_ip, direction)
            entry: dict[str, Any] = {
                "vrf": vrf_name,
                "peer_ip": peer_ip,
                "direction": direction,
                "command": command,
                "row_count": None,
            }
            if command in raw:
                text = raw[command]
                facts, count = _direction_read(
                    text, vrf=vrf_name, peer_ip=peer_ip, direction=direction, legacy=legacy
                )
                command_facts[command] = facts
                entry["row_count"] = count
                if count:
                    rows = functools.partial(
                        _bgp_path_rows,
                        text,
                        vrf=vrf_name,
                        peer_ip=peer_ip,
                        direction=direction,
                        legacy=legacy,
                    )
                    parts.append((count, rows))
            directions.append(entry)
    return {
        "sessions": sessions,
        "routes": streams.ChainRows(parts),
        "directions": directions,
        "summary_facts": summary_facts,
        "command_facts": command_facts,
    }


def _bgp_session_uid(device_uid: str, vrf_name: str, peer_ip: str) -> str:
    """Return the BgpSession uid that an observed row joins the graph through.

    The formula is the formula of `_bgp_stage`
    (`uid.bgp_session(uid.routing_process(dev, vname, "bgp"), peer_ip, vname)`).
    """
    return uid.bgp_session(uid.routing_process(device_uid, vrf_name, "bgp"), peer_ip, vrf_name)


def _bgp_context_uid(device_uid: str, vrf_name: str) -> str:
    """The formula is `f"vrf:{dev}:{uid.slug(name)}"`, as in `_vrf_stage`."""
    return f"vrf:{device_uid}:{uid.slug(vrf_name)}"


def bgp_side_rows(
    raw: dict[str, Any], device_uid: str, *, observed: dict[str, Any] | None = None
) -> dict[str, Sequence[dict[str, Any]]]:
    """The two uids of a row depend on its VRF and peer only."""
    if observed is None:
        observed = bgp_observed(raw)
    sessions = []
    for s in observed["sessions"]:
        vrf_name = s["vrf"] or DEFAULT_VRF
        sessions.append(
            {
                "device_uid": device_uid,
                "context_uid": _bgp_context_uid(device_uid, vrf_name),
                "session_uid": _bgp_session_uid(device_uid, vrf_name, s["peer_ip"]),
                "peer_ip": s["peer_ip"],
                "af": 4,
                "safi": BGP_SAFI,
                "state": s.get("state"),
                "established_since_ms": s.get("established_since_ms"),
                "prefixes_received": s.get("prefixes_received"),
                "prefixes_advertised": s.get("prefixes_advertised"),
                "capabilities": s.get("capabilities"),
            }
        )
    # Map (vrf, peer) to (context_uid, session_uid).
    session_uids: dict[tuple[Any, Any], tuple[str, str]] = {}

    def route_row(r: dict[str, Any]) -> dict[str, Any]:
        key = (r["vrf"], r["peer_ip"])
        uids = session_uids.get(key)
        if uids is None:
            vrf_name = r["vrf"] or DEFAULT_VRF
            uids = (
                _bgp_context_uid(device_uid, vrf_name),
                _bgp_session_uid(device_uid, vrf_name, r["peer_ip"]),
            )
            session_uids[key] = uids
        context_uid, session_uid = uids
        direction = r["direction"]
        return {
            "device_uid": device_uid,
            "context_uid": context_uid,
            "session_uid": session_uid,
            "peer_ip": r["peer_ip"],
            "safi": BGP_SAFI,
            "direction": direction,
            "rib_type": BGP_RIB_TYPES[direction],
            "policy_stage": BGP_POLICY_STAGES[direction],
            "path_id": r.get("path_id"),
            "prefix": r["prefix"],
            "next_hop": r.get("next_hop"),
            # This collector resolves a BGP next hop in the context of the
            # session. No VyOS or FRR command of this capture states another
            # context.
            "next_hop_context_uid": None,
            "as_path": r.get("as_path"),
            "local_pref": r.get("local_pref"),
            "med": r.get("med"),
            "origin": r.get("origin"),
            "communities": r.get("communities"),
            "best": r.get("best"),
            **lpm_columns(r["prefix"]),
        }

    routes = streams.MappedRows(observed["routes"], route_row)
    return {"bgp_sessions": sessions, "bgp_session_routes": routes}


# The reason that a run states for a BGP table or direction that it did not
# read, per capture setting. The text states what the run did and the setting
# that decided it.
_CAPTURE_REASONS: dict[str, str] = {
    "none": "the source's capture_bgp setting is none",
    "sessions": "the source's capture_bgp setting is sessions, which reads session state only",
}


def _command_outcome(
    text: Any, recorded: SectionOutcome | None, row_count: int | None, *, facts: CommandFacts | None = None
) -> TableOutcome:
    """A command that the device refused as unknown is `not-captured`."""
    if recorded is None:
        return TableOutcome(status="not-captured")
    if recorded.status == "unsupported":
        return TableOutcome(status="not-captured", detail=recorded.detail)
    if recorded.status != "ok":
        return TableOutcome(status="failed", detail=recorded.detail)
    kind, detail = _outcome_facts(text) if facts is None else facts
    if kind == "unread":
        return TableOutcome(status="failed", detail=detail)
    if kind == "empty":
        return TableOutcome(status="complete-empty", row_count=0)
    if kind == "percent":
        return TableOutcome(status="not-captured", detail=detail)
    if kind == "not-json":
        return TableOutcome(status="failed", detail="the command answered with text that is not JSON")
    if kind == "not-object":
        return TableOutcome(status="failed", detail="the command answered with JSON that is not an object")
    if kind == "warning":
        return TableOutcome(status="not-captured", detail=detail)
    count = row_count or 0
    if not count:
        return TableOutcome(status="complete-empty", row_count=0)
    return TableOutcome(status="complete", row_count=count)


def bgp_table_outcomes(
    raw: dict[str, Any], device_uid: str, *, capture: str, observed: dict[str, Any] | None = None
) -> dict[str, TableOutcome]:
    """Each session direction gets its own outcome, keyed by `manifest.bgp_direction_key`."""
    outcomes: dict[str, TableOutcome] = {}
    recorded = effective_outcomes(raw, {})
    if observed is None:
        observed = bgp_observed(raw)
    if capture in _CAPTURE_REASONS:
        detail = _CAPTURE_REASONS[capture]
        outcomes[BGP_ROUTES_TABLE] = TableOutcome(status="not-captured", detail=detail)
        if capture == "none":
            outcomes[BGP_SESSIONS_TABLE] = TableOutcome(status="not-captured", detail=detail)
    if capture != "none":
        # A refused summary command is stated here.
        state = _command_outcome(
            raw.get(BGP_SUMMARY_COMMAND),
            recorded.get(BGP_SUMMARY_COMMAND),
            len(observed["sessions"]),
            facts=observed.get("summary_facts"),
        )
        if state.status in ("not-captured", "failed"):
            outcomes[BGP_SESSIONS_TABLE] = state
    facts = observed.get("command_facts") or {}
    for entry in observed["directions"]:
        session_uid = _bgp_session_uid(device_uid, entry["vrf"] or DEFAULT_VRF, entry["peer_ip"])
        outcome = _command_outcome(
            raw.get(entry["command"]),
            recorded.get(entry["command"]),
            entry["row_count"],
            facts=facts.get(entry["command"]),
        )
        if outcome.status == "not-captured" and not outcome.detail and capture in _CAPTURE_REASONS:
            outcome = outcome.model_copy(update={"detail": _CAPTURE_REASONS[capture]})
        outcomes[bgp_direction_key(session_uid, entry["direction"])] = outcome
    return outcomes


def _interface_vrfs(cfg: dict[str, Any]) -> dict[str, str]:
    """Map each interface name to the VRF that its configuration binds it to,
    as `_interface_stage` reads it.

    Vifs and QinQ layers are included. An interface that names no VRF is in
    the default VRF and is left out."""
    out: dict[str, str] = {}

    def take(name: str, node: Any) -> None:
        if isinstance(node, dict) and node.get("vrf"):
            out[name] = str(node["vrf"])

    for members in (cfg.get("interfaces") or {}).values():
        for name, node in (members or {}).items() if isinstance(members, dict) else ():
            take(name, node)
            node = node if isinstance(node, dict) else {}
            for vid, vnode in (node.get("vif") or {}).items():
                take(f"{name}.{vid}", vnode)
            for svid, snode in (node.get("vif-s") or {}).items():
                take(f"{name}.{svid}", snode)
                for cvid, cnode in ((snode or {}).get("vif-c") or {}).items():
                    take(f"{name}.{svid}.{cvid}", cnode)
    return out


def neighbor_rows(raw: dict[str, Any], device_uid: str) -> list[dict[str, Any]]:
    """Return `ip -j neigh show` as `arp` side-table rows, in the shape that
    `checkpoint_gateway.gateway_neighbor_rows` writes from the same command.

    An entry that the kernel could not resolve (FAILED, INCOMPLETE) is no
    evidence that a host is attached. An entry with no link-layer address or
    no interface names no host. Neither is a row. A STALE entry is a valid
    neighbor and stays. The VRF of the row is the VRF that the configuration
    binds the interface to. Its `context_uid` is the VrfInstance uid of that
    VRF (`_vrf_stage`)."""
    entries = raw.get("neigh")
    if not isinstance(entries, list):
        return []
    vrf_of = _interface_vrfs(raw.get("config") or {})
    rows: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        state = entry.get("state") or ()
        states = {str(s).upper() for s in (state if isinstance(state, list) else [state])}
        if states & {"FAILED", "INCOMPLETE"}:
            continue
        try:
            address = ipaddress.ip_address(entry.get("dst") or "")
        except ValueError:
            continue
        mac = canonical_mac(entry.get("lladdr"))
        interface = entry.get("dev")
        if not mac or not isinstance(interface, str) or not interface:
            continue
        vrf_name = vrf_of.get(interface, DEFAULT_VRF)
        rows.append(
            {
                "device_uid": device_uid,
                "vrf": vrf_name,
                "context_uid": f"vrf:{device_uid}:{uid.slug(vrf_name)}",
                "ip": str(address),
                "mac": mac,
                "interface_name": interface,
                "af": address.version,
            }
        )
    return rows


class VyosConfig(SshSourceConfig):
    pass


@register
class VyosCollector(SshCliCollector):
    name = "vyos"
    ConfigModel = VyosConfig
    KIND = "group"
    # Device-local uids are namespaced by the Device uid.
    PARSER_VERSION = "2"
    NORMALIZATION_VERSIONS: ClassVar[dict[str, str]] = {
        "mtu": MTU_NORMALIZATION_VERSION,
        # VyOS 1.3 configuration is marked unread. A refusal recorded `ok`
        # reads as the refusal. The side tables are judged by their reads. A
        # VyOS 1.3 interface policy binding leaves the interface undecided.
        "read-failures": "2",
        "iface_uid": uid.IFACE_UID_VERSION,
        # Rulesets and zones hold installation evidence. Jump rules name their
        # target. NAT rules match their groups. Zones record
        # intra-zone-filtering and bind its ruleset as (Z, Z).
        "firewall": "3",
        # The forms of a static route hold their distance, and a floating form
        # is not written. The 1.4 `vrf` leak of a next hop or an interface and
        # the per-nexthop vrf of a folded RIB row are the next_hop_vrf of the
        # route. The interface of a next hop is its egress. `dhcp-interface`
        # routes are read.
        "static": "3",
        # Tunnels read the endpoint keys of VyOS 1.3 and later. A WireGuard
        # tunnel uid names its interface and the exact peer name.
        "tunnel": "2",
        # An interface keeps its IPv6 link-local addresses.
        "link_local": "1",
        # BGP neighbors inherit from their peer-group. Remote-as external and
        # auto take the ASN that the summary reports. BgpSession holds the
        # cluster id, and RoutingProcess holds the neighbors that get no
        # session. The dynamic peers of a listen range are sessions, and each
        # range is a BgpPeerRange.
        "bgp": "4",
        # Placeholder serials and an empty S/N name no chassis.
        "serial": "1",
        # BgpSession states route-reflector-client, a filter-list and a
        # prefix-list beside a route-map.
        "bgp_session_filters": "1",
        # RoutingProcess records maximum-paths and multipath-relax.
        "bgp_multipath": "1",
        # BgpSession holds the router id of the peer from the neighbor output.
        "bgp_peer_router_id": "1",
        # Bonds are Lags with their member Ports. Bridge members carry their
        # VLANs. The MAC of a bond member is its `permaddr`.
        "membership": "1",
        # PbrPolicy and NatRule hold the address family (`af`) of their tree.
        "family": "1",
        # VrfInstance records whether the graph holds its whole RIB (`rib_mirrored`).
        "rib_mirror": "1",
        # A statically addressed uplink that a main-table default route leaves
        # by gets a WanLink of kind `static`.
        "static_uplink": "1",
    }
    NORMALIZATION_OUTCOME_KEYS = ("config", "link_speeds", "links", "version")
    # `show version` holds the uptime, and the BGP summary holds the uptimes
    # and prefix counters of its sessions. Both differ on every fetch. Neither
    # key is volatile. The Device node (serial, OS version, uid) is built from
    # the version text, and the summary feeds the `bgp_sessions` side table.
    # The routing tables also differ on every fetch (the uptime of each route)
    # and are graph inputs (GRAPH_MIRRORED_TABLES). Every payload is
    # normalized, and the batch digest (`graph_sha`) skips the graph write of
    # an unchanged device.
    # The neighbor table is volatile. Its entries change state on every fetch,
    # it feeds only the `arp` side table, and a change in it must not make the
    # configuration of the device read as changed.
    VOLATILE_RAW_KEYS = ("neigh",)
    # `links` and `link_speeds` are graph-affecting keys.
    OBSERVATION_RAW_KEYS = ("routes", "routes6", "routes_tables", "routes6_tables", "neigh")
    # `normalize` mirrors the routing tables with at most `rib_graph_max_routes`
    # rows into the graph as LEARNED_ROUTE edges (`_learned_routes`). The
    # snapshot manifest records this per side-store file. No other collector
    # writes those edges or declares a mirrored table.
    GRAPH_MIRRORED_TABLES = ("rib",)
    AUTHORITATIVE_SECTIONS = ("config", "version")
    # `side_tables` reads these tables whatever `capture_bgp` says.
    SIDE_TABLES = ("rib", "arp", OSPF_LSDB_TABLE, BGP_ROUTES_TABLE, BGP_SESSIONS_TABLE)
    # No optional section of this collector exclusively owns a node label.
    SECTION_LABELS: ClassVar[dict[str, tuple[str, ...]]] = {
        "links": (),
        "addrs": (),
        "neigh": (),
        "link_speeds": (),
        "routes": (),
        "routes6": (),
    }
    # The fixed reads behind each table (`Collector.TABLE_SECTIONS`). The
    # per-policy-table RIB reads and the per-VRF OSPF reads join them per
    # payload (`table_feeds`).
    TABLE_SECTIONS: ClassVar[dict[str, tuple[str, ...]]] = {"rib": ("routes", "routes6"), "arp": ("neigh",)}

    def __init__(self, config: VyosConfig, settings):
        super().__init__(config, settings)
        self.scope = f"vyos:{config.host}"
        # The payload of the current load and what the load has read of it
        # (`_read`). `release_payload` drops it when the load ends.
        self._payload_read: _PayloadRead | None = None

    @staticmethod
    def _op_mode(command: str) -> str:
        # Op-mode commands ("show ...") are not available in the non-interactive
        # vbash of a plain exec. The wrapper loads them.
        if command.startswith("show "):
            return f"/opt/vyatta/bin/vyatta-op-cmd-wrapper {command}"
        return command

    def _ssh(self, command: str) -> str:
        return self._run(self._op_mode(command))

    def probe(self) -> str:
        first = self._ssh("show version").strip().splitlines()
        return first[0] if first else "connected (empty version output)"

    async def _afetch_over(self, s) -> dict[str, Any]:
        outcomes: dict[str, dict[str, Any]] = {}

        async def run(command: str) -> str:
            # The run checks its stop flag before each command (`SshCliCollector._afetch_over`).
            self.check_stop()
            return await s.run(self._op_mode(command))

        def as_text(text: str) -> str:
            return text

        async def run_optional(key: str, command: str, *, parse: Callable[[str], Any] = json.loads) -> Any:
            # An optional command that fails does not fail the fetch.
            try:
                value = parse(await run(command))
                if key == "links" and (
                    not isinstance(value, list) or any(not isinstance(row, dict) for row in value)
                ):
                    raise json.JSONDecodeError("ip-link response must be an array of objects", "", 0)
            except CollectionStopped:
                raise
            except (RuntimeError, json.JSONDecodeError) as exc:
                raw[f"{key}_error"] = f"{type(exc).__name__}: {exc}"
                if isinstance(exc, json.JSONDecodeError):
                    # The command ran and the box answered with something that
                    # is not the JSON the command promises.
                    outcomes[key] = {"status": "malformed", "detail": str(exc)}
                else:
                    status, detail = classify_command_failure(exc)
                    outcomes[key] = {"status": status, "detail": detail}
                logger.warning("[vyos] %r failed: %s", command, exc)
                return []
            outcomes[key] = {"status": "ok"}
            return value

        raw: dict[str, Any] = {
            "config": json.loads(await run(READ_COMMANDS["config"])),
            "version_text": await run(READ_COMMANDS["version"]),
        }
        outcomes["config"] = {"status": "ok"}
        outcomes["version"] = {"status": "ok"}
        raw["links"] = await run_optional("links", READ_COMMANDS["links"])
        raw["addrs"] = await run_optional("addrs", READ_COMMANDS["addrs"])
        # The ARP and IPv6 neighbor tables state which host answers at which
        # address behind which interface. They feed the `arp` side table.
        raw["neigh"] = await run_optional("neigh", READ_COMMANDS["neigh"])
        # `run_optional` gets the identity parse for the text output.
        raw["link_speeds"] = await run_optional("link_speeds", READ_COMMANDS["link_speeds"], parse=as_text)
        # A read that fails gives `[]`, and its outcome is recorded.
        raw["routes"] = await run_optional("routes", READ_COMMANDS["routes"], parse=as_text)
        raw["routes6"] = await run_optional("routes6", READ_COMMANDS["routes6"], parse=as_text)
        # `vrf all` does not list the policy tables.
        static = ((raw["config"].get("protocols") or {}).get("static") or {}).get("table") or {}
        for key, ip_word in (("routes", "ip"), ("routes6", "ipv6")):
            tables: dict[str, Any] = {}
            for t in static:
                # The table key must be a plain integer.
                try:
                    table_num = int(t)
                except ValueError:
                    raw[f"{key}_table_{t}_error"] = f"ValueError: non-numeric static table key {t!r}"
                    outcomes[f"{key}_table_{t}"] = {
                        "status": "malformed",
                        "detail": f"non-numeric static table key {t!r}",
                    }
                    logger.warning("[vyos] skipping non-numeric static table key %r", t)
                    continue
                tables[str(t)] = await run_optional(
                    f"{key}_table_{table_num}",
                    f'{_IP_PATH} vtysh -c "show {ip_word} route table {table_num} json"',
                    parse=as_text,
                )
            raw[f"{key}_tables"] = tables
        # FRR is asked only about a VRF with a `protocols ospf` stanza.
        for vname in _ospf_vrf_names(raw["config"]):
            for sub_key, sub in _OSPF_SUBCOMMANDS:
                key = _ospf_raw_key(vname, sub_key)
                raw[key] = await run_optional(key, _ospf_command(sub, vname))
        await self._afetch_bgp_observations(s, raw, outcomes)
        raw[RAW_OUTCOMES_KEY] = outcomes
        return raw

    async def _afetch_bgp_observations(self, s, raw: dict[str, Any], outcomes: dict[str, Any]) -> None:
        """A refusal is recorded under `outcomes`."""
        capture = self.config.capture_bgp
        if capture == "none":
            return
        await self._afetch_bgp_commands(s, raw, outcomes, [BGP_SUMMARY_COMMAND])
        await self._afetch_peer_router_ids(s, raw)
        if capture == "all":
            # The targets come after the summary. A neighbor whose remote-as is
            # `external` or `auto` is a target when the summary reports its ASN.
            # A dynamic peer of a listen range is a target once the summary
            # lists it.
            cfg = raw.get("config") or {}
            peers = summary_peers(raw.get(BGP_SUMMARY_COMMAND))
            observed_as = {key: asn for key, asn in peers.items() if asn is not None}
            commands = [
                bgp_route_command(vrf_name, peer_ip, d)
                for vrf_name, peer_ip in bgp_capture_targets(cfg, observed_as, peers)
                for d in BGP_DIRECTION_KEYWORDS
            ]
            await self._afetch_bgp_commands(s, raw, outcomes, commands)

    async def _afetch_peer_router_ids(self, s, raw: dict[str, Any]) -> None:
        """Read the neighbor detail that states the router id of each peer.

        When the device refuses the command, nothing is recorded for it, and
        the sessions state no `peer_router_id`."""
        self.check_stop()
        try:
            raw[BGP_NEIGHBORS_COMMAND] = await s.run(self._op_mode(BGP_NEIGHBORS_COMMAND))
        except RuntimeError as exc:
            logger.warning(
                "[vyos] %r failed (%s); sessions state no peer router id", BGP_NEIGHBORS_COMMAND, exc
            )

    async def _afetch_bgp_commands(
        self, s, raw: dict[str, Any], outcomes: dict[str, Any], commands: list[str]
    ) -> None:
        """Run each BGP command of `_afetch_bgp_observations`, recording a
        refusal under `outcomes` and continuing without it."""
        for cmd in commands:
            self.check_stop()
            try:
                raw[cmd] = await s.run(self._op_mode(cmd))
                outcomes[cmd] = {"status": "ok"}
            except RuntimeError as exc:
                logger.warning("[vyos] %r failed (%s); continuing without it", cmd, exc)
                raw[cmd] = "{}"
                status, detail = classify_command_failure(exc)
                outcomes[cmd] = {"status": status, "detail": detail}

    def _read(self, raw: dict[str, Any]) -> _PayloadRead:
        """Return what this load has read of `raw` (`_PayloadRead`).

        `normalize`, `side_tables` and `table_outcomes` read the same payload.
        One load decodes each RIB and BGP answer once, for the first of them
        that asks. The read holds a reference to the payload. Without the
        reference, a new payload at the address of a freed payload would get
        the old read."""
        read = self._payload_read
        if read is None or read.raw is not raw:
            read = self._payload_read = _PayloadRead(raw)
        return read

    def release_payload(self) -> None:
        """Drop the read of the payload that this collector last loaded, and
        the payload with it.

        A run keeps the collector of every unit until it publishes. Without
        this call, the RIB rows and answers of a device stay in memory until
        the run ends. The next load reads its payload again."""
        self._payload_read = None

    def sections(self, raw: dict[str, Any]) -> dict[str, SectionOutcome]:
        """Return what each read of this payload produced (`section_outcomes`).

        An observation-only load (`base.load_observations`) records the same
        sections as a full load and judges the side tables by them."""
        return section_outcomes(raw, self._read(raw).rib())

    def table_feeds(self, raw: dict[str, Any]) -> dict[str, tuple[str, ...]]:
        """Return the reads behind each table of this payload.

        The RIB stands on the global reads and on one read per configured
        policy table. The OSPF link-state database stands on the process and
        database reads of every VRF that runs OSPF."""
        rib = list(self.TABLE_SECTIONS["rib"])
        for key in ("routes", "routes6"):
            tables = raw.get(f"{key}_tables")
            if isinstance(tables, dict):
                rib.extend(f"{key}_table_{number}" for number in tables)
            # A policy table whose config key was no number was never read.
            prefix = f"{key}_table_"
            rib.extend(name for name in raw.get(RAW_OUTCOMES_KEY) or {} if str(name).startswith(prefix))
        ospf = [
            _ospf_raw_key(vname, sub_key)
            for vname in _ospf_vrf_names(raw.get("config") or {})
            for sub_key, _sub in _OSPF_SUBCOMMANDS
            if sub_key == "process" or sub_key.startswith("lsdb_")
        ]
        return {
            "rib": tuple(dict.fromkeys(rib)),
            "arp": self.TABLE_SECTIONS["arp"],
            OSPF_LSDB_TABLE: tuple(ospf),
        }

    def normalize(self, raw: dict[str, Any]) -> Batch:
        read = self._read(raw)
        batch = normalize_vyos(
            raw,
            l3dom=self.config.effective_routing_scope,
            l2fabric=self.settings.l2fabric_of(self.config.source_name, self.config.l2fabric),
            rib_graph_max_routes=self.settings.rib_graph_max_routes,
            source_name=self.config.source_name,
            rib=read.rib,
            resolver=self.identity,
            scope=self.scope,
        )
        batch.sections = self.sections(raw)
        return batch

    def _device_uid(self, raw: dict[str, Any]) -> str:
        """Return the Device node uid that the rows of this payload key on.

        `side_tables` uses the same formula for the RIB."""
        cfg = raw.get("config") or {}
        host = (cfg.get("system") or {}).get("host-name", "vyos")
        return device_uid(raw.get("version_text") or "", host, self.config.source_name, self.identity)

    def side_tables(self, raw: dict[str, Any]) -> dict[str, Sequence[dict[str, Any]]]:
        """This method writes every RIB table, whatever its size."""
        cfg = raw.get("config") or {}
        dev = self._device_uid(raw)
        read = self._read(raw)
        vrf_tables = {
            str((vnode or {}).get("table")): vname
            for vname, vnode in ((cfg.get("vrf") or {}).get("name") or {}).items()
            if (vnode or {}).get("table")
        }
        # The map holds every VRF name that this device has a context_uid for, main table included.
        context_uid_by_vrf = {DEFAULT_VRF: f"vrf:{dev}:{uid.slug(DEFAULT_VRF)}"}
        context_uid_by_vrf.update({vname: f"vrf:{dev}:{uid.slug(vname)}" for vname in vrf_tables.values()})
        # Map a table label to (vrf name, context_uid), once per table.
        contexts: dict[str, tuple[str, str]] = {}

        def context_of(table: str) -> tuple[str, str]:
            # context_uid is the uid of the VrfInstance node that normalize_vyos emits for this table.
            if table in ("main", "254"):
                vrf_name = DEFAULT_VRF
                context_uid = f"vrf:{dev}:{uid.slug(DEFAULT_VRF)}"
            elif table in vrf_tables:
                vrf_name = vrf_tables[table]
                context_uid = f"vrf:{dev}:{uid.slug(vrf_name)}"
            else:
                vrf_name = f"table{table}"
                context_uid = f"vrf:{dev}:table{table}"
            contexts[table] = (vrf_name, context_uid)
            return vrf_name, context_uid

        def rib_row(r: _RibEntry) -> dict[str, Any]:
            vrf_name, context_uid = contexts.get(r.table) or context_of(r.table)
            lo, hi, plen, af = prefix_bounds(r.cidr)
            nhv = r.next_hop_vrf
            return {
                "device_uid": dev,
                "vrf": vrf_name,
                "context_uid": context_uid,
                "prefix": r.cidr,
                "next_hop": r.next_hop,
                "next_hop_context_uid": context_uid_by_vrf.get(nhv) if nhv else None,
                "interface": r.interface,
                "protocol": r.protocol,
                "discard": r.discard,
                "metric": r.metric,
                "af": af,
                "prefixlen": plen,
                "lo": lo,
                "hi": hi,
            }

        ospf = _parse_ospf(raw, cfg)
        tables: dict[str, Sequence[dict[str, Any]]] = {
            "rib": streams.MappedRows(read.rib().entries, rib_row),
            "arp": neighbor_rows(raw, dev),
            **bgp_side_rows(raw, dev, observed=read.bgp()),
        }
        if ospf is not None:
            tables["ospf_lsdb"] = _ospf_lsdb_rows(ospf, dev)
        return tables

    def table_outcomes(self, raw: dict[str, Any]) -> dict[str, TableOutcome]:
        """`ospf_lsdb` is `unsupported` when no VRF on this device has a `protocols ospf` stanza."""
        cfg = raw.get("config") or {}
        outcomes: dict[str, TableOutcome] = {}
        if "neigh" not in raw:
            outcomes["arp"] = TableOutcome(
                status="not-captured", detail="the payload predates the neighbor table read"
            )
        if not _ospf_vrf_names(cfg):
            outcomes[OSPF_LSDB_TABLE] = TableOutcome(
                status="unsupported", detail="the device does not have the feature this table reads"
            )
        outcomes.update(
            bgp_table_outcomes(
                raw,
                self._device_uid(raw),
                capture=self.config.capture_bgp,
                observed=self._read(raw).bgp(),
            )
        )
        return outcomes


class _PayloadRead:
    """What one load reads of one VyOS payload.

    The load reads each part when a phase first asks for it and keeps it for
    the rest of the load. The parts are the RIB answers (`_read_rib`) and the
    BGP observation answers (`bgp_observed`). `VyosCollector._read` holds one
    per load, and `VyosCollector.release_payload` drops it."""

    def __init__(self, raw: dict[str, Any]) -> None:
        self.raw = raw
        self._rib: _RibRead | None = None
        self._bgp: dict[str, Any] | None = None

    def rib(self) -> _RibRead:
        if self._rib is None:
            self._rib = _read_rib(self.raw)
        return self._rib

    def bgp(self) -> dict[str, Any]:
        if self._bgp is None:
            self._bgp = bgp_observed(self.raw)
        return self._bgp
