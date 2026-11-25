"""The uid builders, which define the identity grammar of the graph.

A uid is a deterministic, readable path string with a namespace prefix. Every
namespace is distinct, and a uid is globally unique. The graph has a single
`Obj(uid)` uniqueness constraint and matches relationships without labels.

The device uid `dev:<name>` is minted once from the short hostname and kept in
the device identity registry (core/identity.py). A collector gets it from
`Collector.identity`, and every child uid embeds it.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

from .normalize import iface_slug

_SLUG_BAD = re.compile(r"[^a-z0-9._-]+")

# The version of the Interface and Port uid segment (`iface_slug`). A collector
# that mints those uids from the interface names of a device declares it in its
# NORMALIZATION_VERSIONS.
# 1: the '.' of a subinterface name folds to '-'.
# 2: the '.' of a subinterface name stays ('GigabitEthernet0/0.1' and
#    'GigabitEthernet0/0/1' are two uids).
IFACE_UID_VERSION = "2"
_SLUG_ALPHABET = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._-")


def slug(value: str) -> str:
    """Lowercase `value`, replace each space and each run of characters outside
    [a-z0-9._-] with '-', and strip '-' from both ends."""
    v = value.strip().lower().replace(" ", "-")
    v = _SLUG_BAD.sub("-", v)
    return v.strip("-")


def exact_slug(value: str) -> str:
    """`slug` for a case-sensitive configured name. 2 different names give 2
    different segments.

    A name that `slug` leaves unchanged (`101`, `edge-in`) is its own segment.
    Any other name (`EDGE-IN`, `Web In`) is its slug plus `~` and the first 8
    hex digits of the SHA-256 of the exact name. `WEB-IN` and `web-in` are 2
    segments. `~` is outside the slug alphabet, and a segment with a suffix
    does not equal a plain segment."""
    folded = slug(value)
    if folded == value:
        return folded
    return f"{folded}~{hashlib.sha256(value.encode()).hexdigest()[:8]}"


def anchor_slug(value: str) -> str:
    """`slug` for the anchor segment of `prefix`/`ip`, with letter case kept.

    A character of the slug alphabet `[a-z0-9._-]` stays as it is. An ASCII
    uppercase letter encodes as `~` plus its lowercase form.

    A space becomes `-`. A run of other characters folds to a single `-`, as
    in `slug`.
    """
    out: list[str] = []
    folded = False
    for ch in value.strip():
        if ch == " ":
            out.append("-")
            folded = False
        elif ch in _SLUG_ALPHABET:
            out.append(ch)
            folded = False
        elif "A" <= ch <= "Z":
            out.append(f"~{ch.lower()}")
            folded = False
        elif not folded:
            out.append("-")
            folded = True
    return "".join(out).strip("-")


def norm_mac(mac: str) -> str:
    """The canonical form of a MAC address, 12 lowercase hex characters without separators."""
    m = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(m) != 12:
        raise ValueError(f"not a mac address: {mac!r}")
    return m


# --- shared-reality objects (merged across sources) ------------------------------------


def site(code: str) -> str:
    return f"site:{slug(code)}"


def site_fold(code: str, known: Iterable[str]) -> str | None:
    """The code in `known`, other than `code` itself, that has the Site uid of
    `code` (`DC1` and `dc1`, `fra:1` and `fra-1`), or None. Codes are
    case-sensitive, and the graph holds one Site per uid. 2 such codes give
    one node."""
    uid = site(code)
    return next((other for other in sorted(known) if other != code and site(other) == uid), None)


def rack(site_code: str, name: str) -> str:
    return f"rack:{slug(site_code)}:{slug(name)}"


def provider(name: str) -> str:
    return f"provider:{slug(name)}"


def provider_network(kind: str, name: str) -> str:
    """One carrier network of one kind (`ProviderNetwork.kind`: mpls, internet,
    p2p). Shared across sources."""
    return f"pnet:{slug(kind)}:{slug(name)}"


def rgrp(kind: str, scope: str, name: str) -> str:
    return f"rgrp:{slug(kind)}:{slug(scope)}:{slug(name)}"


def fhrp(kind: str, domain: str, vip: str) -> str:
    """One first-hop redundancy group (`FhrpGroup`), the virtual address that
    one protocol (`hsrp`, `vrrp`) answers for inside one routing domain.

    `domain` is the name of the routing domain that the VRF of the member
    interface resolves to (`cisco_common._domain_for`, the string that
    `connected_address` stamps as `l3dom`). It is embedded through
    `anchor_slug`, as the anchor of `prefix` and `ip`. Every member of the
    group is collected as its own device in its own batch. Each batch derives
    the same uid from the same domain and the same virtual address, and the
    members merge on one node. The group number is a property and is not part
    of the uid. The domain separates 2 sites that reuse group 1. A group that
    is renumbered keeps its address and its node.
    """
    return f"fhrp:{slug(kind)}:{anchor_slug(domain)}:{vip}"


def port(device_uid: str, port_name: str) -> str:
    return f"{device_uid}/port/{iface_slug(port_name)}"


def interface(device_uid: str, if_name: str) -> str:
    return f"{device_uid}/if/{iface_slug(if_name)}"


def vlan(scope_uid: str, vid: int) -> str:
    return f"vlan:{scope_uid}:{int(vid)}"


def bridge_domain(fabric: str, vid: int) -> str:
    """A classic switched broadcast domain, which is one VLAN id within one
    declared fabric. The fabric is a twin-level
    declaration with a single-fabric default.
    Platform families with their own flood-domain object do not use this
    grammar."""
    return f"bd:vlan:{slug(fabric)}:{int(vid)}"


def l3dom(name: str) -> str:
    return f"l3dom:{slug(name)}"


def routing_domain(name: str) -> str:
    """RoutingDomain grouping node."""
    return f"rdom:{slug(name)}"


def vrf(scope_uid: str, name: str) -> str:
    return f"vrf:{scope_uid}:{name}"


def prefix(anchor: str, cidr: str) -> str:
    """`anchor` is the owning VrfInstance uid for routed/connected addressing,
    an l2seg uid for endpoint addressing, or a source-scoped domain string for
    policy objects and manual/DNS-style records.
    It is never parsed back out of the uid."""
    return f"pfx:{anchor_slug(anchor)}:{cidr}"


def ip(anchor: str, addr: str) -> str:
    """`anchor` is as in `prefix`."""
    return f"ip:{anchor_slug(anchor)}:{addr}"


def endpoint(scope: str, mac: str) -> str:
    return f"ep:{slug(scope)}:{norm_mac(mac)}"


def route_target(value: str) -> str:
    return f"rt:{value}"


def fc(device_uid: str, table_id: str) -> str:
    """A forwarding context, which is one routing table on one device.
    `table_id` is the native name of the platform for the table (vrf name,
    'default', 'inet.0', a cloud route-table id). It is unique within the
    device, is not normalized across platforms and is not parsed back out of
    the uid."""
    return f"fc:{device_uid}:{slug(table_id)}"


def routing_process(device_uid: str, vrf_name: str, proto: str) -> str:
    """The process of one routing protocol in one VRF of one device
    (`RoutingProcess.proto` equals `proto`, for example "bgp"). `device_uid` is
    embedded verbatim, as in `fc()`, and `vrf_name` is slugged. A device runs
    at most one process per protocol per VRF on every collected platform."""
    return f"rproc:{device_uid}:{slug(vrf_name)}:{slug(proto)}"


def bgp_session(local_uid: str, peer_ip: str, vrf_name: str) -> str:
    """`local_uid` is the uid of the owning `RoutingProcess` (`routing_process()`).
    The engine finds the parent process through the
    `(RoutingProcess)-[:HAS]->(BgpSession)` edge. The uid is not parsed to
    recover the process."""
    return f"bgp:{local_uid}~{peer_ip}:{vrf_name}"


def bgp_peer_range(local_uid: str, prefix: str, vrf_name: str) -> str:
    """A passive BGP definition, distinct from every session it accepts."""
    return f"bgprange:{local_uid}~{prefix}:{vrf_name}"


def ospf_area(process_uid: str, area_id: str) -> str:
    """One area of one OSPF process (`OspfArea`). `process_uid` is the uid of
    the owning `RoutingProcess` (`routing_process()` with proto "ospf"). The
    same area id under 2 processes or 2 VRFs is 2 nodes. `area_id` is embedded
    in the dotted form that the process reports, slugged."""
    return f"ospfarea:{process_uid}:{slug(area_id)}"


def ospf_adjacency(process_uid: str, local_if_uid: str, neighbor_router_id: str) -> str:
    """One OSPF adjacency (`OspfAdjacency`), identified by the local interface
    it forms over and the router id of the neighbor. 2 processes can see the
    same neighbor router id over different interfaces (parallel links). One
    interface can hold adjacencies with more than 1 neighbor on a broadcast
    segment. `local_if_uid` is embedded verbatim, as the local uid in
    `bgp_session()`, and is not parsed back out."""
    return f"ospfadj:{process_uid}:{local_if_uid}~{neighbor_router_id}"


def route_policy(device_uid: str, kind: str, name: str) -> str:
    """A route-map, an IOS-XR route-policy (RPL) or a prefix-list used as a
    policy container. The scope is the device, whose global config declares
    these objects. `kind` separates objects with the same name in different
    vendor namespaces (a route-map and a prefix-list can share a name). `name`
    is embedded verbatim."""
    return f"rtpol:{device_uid}:{slug(kind)}:{name}"


def route_policy_entry(policy_uid: str, seq: int) -> str:
    """One sequence-numbered clause of a route-map/RPL policy (`RoutePolicyEntry`). `seq` is
    the clause's own sequence number for IOS-XE/NX-OS, or a synthetic 1-based ordinal for
    IOS-XR RPL, which has no native numbering."""
    return f"{policy_uid}/clause/{int(seq)}"


def prefix_list_entry(policy_uid: str, seq: int) -> str:
    """One sequence-numbered line of a prefix-list/prefix-set (`PrefixListEntry`)."""
    return f"{policy_uid}/line/{int(seq)}"


def match_list_entry(policy_uid: str, seq: int) -> str:
    """One sequence-numbered line of a community list/community-set or an AS-path
    list/as-path-set (`MatchListEntry`). The kind of the owning RoutePolicy
    separates it from a prefix-list line."""
    return f"{policy_uid}/line/{int(seq)}"


def tunnel(encap: str, end_a: str, end_b: str) -> str:
    a, b = sorted((end_a, end_b))  # The sorted ends give one uid for both view directions.
    return f"tun:{slug(encap)}:{a}~{b}"


def overlay_connection(technology: str, end_a: str, end_b: str) -> str:
    """One `OverlayConnection`, the overlay connection between 2 ends over any
    links and in any direction. `end_a` and `end_b` are the end keys
    (`collectors/util.py` `OverlayEnd.key`, which is a node uid, a tunnel
    address or a local discriminator). The keys are sorted, and both sides
    give the same uid."""
    a, b = sorted((end_a, end_b))
    return f"oconn:{slug(technology)}:{a}~{b}"


def fabric(name: str) -> str:
    return f"fabric:{slug(name)}"


# --- source-native ids (owned by exactly one source, no merge problem) ------------------


def aci(fabric_name: str, dn: str) -> str:
    return f"aci:{slug(fabric_name)}:{dn}"  # The APIC DN is embedded verbatim, with its case.


def checkpoint(mgmt: str, domain: str, api_uid: str) -> str:
    return f"cp:{slug(mgmt)}:{slug(domain)}:{api_uid}"


def fortigate(serial: str, vdom: str, table: str, mkey: str) -> str:
    return f"fgt:{serial}:{vdom}:{table}:{mkey}"


def ndo(host: str, ref: str) -> str:
    return f"ndo:{slug(host).replace('.', '-')}:{ref}"  # ref is NDO's own id path, verbatim


def netscaler(rgrp_name: str, obj_type: str, name: str) -> str:
    return f"ns:{slug(rgrp_name)}:{slug(obj_type)}:{name}"


def velocloud(enterprise: str, obj_type: str, obj_id: str | int) -> str:
    return f"vco:{slug(enterprise)}:{slug(obj_type)}:{obj_id}"


def velocloud_far_edge(tunnel_uid: str) -> str | None:
    """The logicalId of the far edge a VeloCloud branch and hub `Tunnel` uid
    names (`vco:<ent>:path:<eid>:<lid>~link:<far eid>:<far lid>`), or None for
    any other uid."""
    if not tunnel_uid.startswith("vco:") or "~link:" not in tunnel_uid:
        return None
    return tunnel_uid.split("~link:", 1)[1].rsplit(":", 1)[0] or None


def names_far_device(tunnel_uid: str, device_uid: str | None) -> bool:
    """Whether `device_uid` is the far edge that a VeloCloud tunnel uid names.
    True for a tunnel whose uid names no far edge."""
    far = velocloud_far_edge(tunnel_uid)
    return far is None or (device_uid or "").endswith(f":edge:{far}")


def zia(org: str, obj_type: str, obj_id: str | int) -> str:
    return f"zia:{slug(org)}:{slug(obj_type)}:{obj_id}"


def zpa(customer: str, obj_type: str, obj_id: str | int) -> str:
    return f"zpa:{slug(customer)}:{slug(obj_type)}:{obj_id}"


def aws(arn: str) -> str:
    return f"aws:{arn}"


def azure(resource_id: str) -> str:
    return f"az:{resource_id.lower()}"


def vcenter(vc: str, moref: str) -> str:
    return f"vc:{slug(vc)}:{moref}"


def snow(sys_id: str) -> str:
    return f"snow:{sys_id}"


def dns(fqdn: str, rtype: str) -> str:
    return f"dns:{fqdn.rstrip('.').lower()}:{rtype.upper()}"


def equinix(obj_type: str, uuid: str) -> str:
    return f"eqx:{slug(obj_type)}:{uuid}"


def run(run_id: str) -> str:
    return f"run:{run_id}"


def mtu_observation(
    subject_uid: str,
    source: str,
    source_target: str,
    source_field: str,
    metric: str,
    direction: str,
    scope: str,
    assertion_kind: str,
    *,
    traffic_class: str | None = None,
    policy_ref: str | None = None,
    enforcement_key: str = "interface",
) -> str:
    """The stable identity of an assertion. Values, versions and timestamps are
    not part of the identity.

    The source target is required, also for a subject that collectors share.
    """
    import hashlib
    import json

    identity = [
        subject_uid,
        source,
        source_target,
        source_field,
        metric,
        direction,
        scope,
        assertion_kind,
        traffic_class,
        policy_ref,
        enforcement_key,
    ]
    digest = hashlib.sha256(json.dumps(identity, ensure_ascii=True, separators=(",", ":")).encode())
    return f"mtu:{digest.hexdigest()}"


def lag(device_uid: str, name: str) -> str:
    """A logical aggregate identity, distinct from its physical/member ports."""
    return f"{device_uid}/lag/{iface_slug(name)}"
