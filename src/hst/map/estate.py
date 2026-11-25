"""A synthetic estate for the HST benchmark.

The estate has sites with campus and data-center blocks, cabled ports, LAGs,
interfaces, VRFs, VLANs, prefixes, firewall rulebases and rules, BGP sessions,
tunnels and endpoints, at fixed per-device ratios. Every object derives from
`(seed, device, version)`. A device changes between 2 runs by taking the next
version.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

L3_TIERS = frozenset({"wan-edge", "firewall", "core", "distribution", "spine", "leaf"})
ROLE_OF = {
    "wan-edge": "router",
    "firewall": "firewall",
    "core": "switch",
    "distribution": "switch",
    "access": "switch",
    "spine": "switch",
    "leaf": "switch",
}
BASE_PORTS = {"access": 24, "leaf": 32}
SPARE_PORTS = 2
VLANS = 8
RULEBASES = 3
RULES = 100
NAT_RULES = 10
BGP_PEERS = 4
ENDPOINTS = 6
# The transports of the tunnels between 2 hubs, by pair. The pairs alternate between 3 tunnels
# of 2 transports and 1 tunnel.
TUNNEL_ENCAPS = (("ipsec", "ipsec", "gre"), ("ipsec",))


@dataclass(frozen=True)
class Spec:
    devices: int = 10_000
    seed: int = 1
    change_rate: float = 0.05
    orphan_share: float = 0.02
    port_edge_share: float = 0.9
    context_edge_share: float = 0.85
    unbound_share: float = 0.05
    transient_share: float = 0.005


def _unit(*parts: Any) -> float:
    digest = hashlib.blake2b(":".join(map(str, parts)).encode(), digest_size=8).digest()
    return int.from_bytes(digest, "big") / 2**64


@dataclass
class Device:
    index: int
    uid: str
    name: str
    tier: str
    site: str | None
    ports: int = 0
    group: str | None = None
    transient: bool = False
    used: int = 0

    def port(self) -> int:
        self.used += 1
        return self.used - 1


@dataclass
class Cable:
    a: Device
    a_port: int
    b: Device
    b_port: int


@dataclass
class Estate:
    spec: Spec
    devices: list[Device] = field(default_factory=list)
    cables: list[Cable] = field(default_factory=list)
    lags: list[tuple[Device, str, list[int]]] = field(default_factory=list)
    tunnels: list[tuple[Device, Device]] = field(default_factory=list)
    sites: list[str] = field(default_factory=list)


def build(spec: Spec) -> Estate:
    """The static topology with sites, devices by tier, cables, LAGs, groups and tunnels."""
    estate = Estate(spec)
    orphans = round(spec.devices * spec.orphan_share)
    budget = spec.devices - orphans
    s = 0
    hubs: list[Device] = []
    while budget > 0:
        dc = s % 8 == 0
        size = min(
            budget,
            60 + int(_unit(spec.seed, "site", s) * 140)
            if dc
            else 20 + int(_unit(spec.seed, "site", s) * 100),
        )
        code = f"s{s:04d}"
        estate.sites.append(code)
        before = len(estate.devices)
        _site(estate, code, max(size, 8), dc)
        budget -= len(estate.devices) - before
        wan = [d for d in estate.devices[before:] if d.tier == "wan-edge"]
        hubs.append(wan[0])
        s += 1
    for hub in hubs[1:]:
        estate.tunnels.append((hub, hubs[0]))
    for _ in range(orphans):
        _device(estate, "access", None)
    for d in estate.devices:
        d.ports = max(BASE_PORTS.get(d.tier, 0), d.used + SPARE_PORTS)
        d.transient = (
            d.tier == "access"
            and d.site is not None
            and _unit(spec.seed, "transient", d.index) < spec.transient_share
        )
    return estate


def _device(estate: Estate, tier: str, site: str | None) -> Device:
    i = len(estate.devices)
    device = Device(i, f"dev:b{i:05d}", f"b{i:05d}", tier, site)
    estate.devices.append(device)
    return device


def _cable(estate: Estate, a: Device, b: Device) -> tuple[int, int]:
    pa, pb = a.port(), b.port()
    estate.cables.append(Cable(a, pa, b, pb))
    return pa, pb


def _site(estate: Estate, code: str, size: int, dc: bool) -> None:
    wan = [_device(estate, "wan-edge", code) for _ in range(2)]
    fw = [_device(estate, "firewall", code) for _ in range(2)]
    for group, members in (("wan", wan), ("fw", fw)):
        for d in members:
            d.group = f"rgrp:{group}:{code}"
    for w, f in zip(wan, fw, strict=True):
        _cable(estate, f, w)
    if dc:
        spines = [_device(estate, "spine", code) for _ in range(2 if size < 100 else 4)]
        for sp, f in zip(spines, fw * 2, strict=False):
            _cable(estate, sp, f)
        for _ in range(size - 4 - len(spines)):
            leaf = _device(estate, "leaf", code)
            for sp in spines:
                _cable(estate, leaf, sp)
        return
    cores = [_device(estate, "core", code) for _ in range(2)]
    for c in cores:
        c.group = f"rgrp:core:{code}"
    for c, f in zip(cores, fw, strict=True):
        _cable(estate, c, f)
    _cable(estate, cores[0], cores[1])
    dists = [_device(estate, "distribution", code) for _ in range(max(2, (size // 25) * 2))]
    for d in dists:
        for k, c in enumerate(cores):
            ports = [_cable(estate, d, c)[0] for _ in range(2)]
            estate.lags.append((d, f"{d.uid}/lag/po{k + 1}", ports))
    for i in range(size - 6 - len(dists)):
        access = _device(estate, "access", code)
        _cable(estate, access, dists[i % len(dists)])
        _cable(estate, access, dists[(i + 1) % len(dists)])


def changed(spec: Spec, device: int, run: int) -> bool:
    return run > 0 and _unit(spec.seed, "change", run, device) < spec.change_rate


def version(spec: Spec, device: int, run: int) -> int:
    return sum(1 for k in range(1, run + 1) if changed(spec, device, k))


def present(estate: Estate, device: Device, run: int) -> bool:
    return not device.transient or (run + device.index) % 2 == 0


Row = dict[str, Any]


def _port_uid(device: Device, i: int) -> str:
    return f"{device.uid}/port/eth{i}"


def _if_uid(device: Device, i: int) -> str:
    return f"{device.uid}/if/eth{i}"


def device_objects(
    estate: Estate, device: Device, run: int
) -> tuple[list[tuple[str, Row]], list[tuple[str, str, str, Row]]]:
    """The nodes `(label, row)` and relationships `(type, start, end, props)` of one device at `run`."""
    spec = estate.spec
    v = version(spec, device.index, run)
    nodes: list[tuple[str, Row]] = []
    rels: list[tuple[str, str, str, Row]] = []
    d = device.uid
    nodes.append(
        (
            "Device",
            {
                "uid": d,
                "hostname": device.name,
                "role": ROLE_OF[device.tier],
                "tier": device.tier,
                "vendor": "bench",
                "model": f"m{v % 3}",
            },
        )
    )
    if device.site is not None:
        rels.append(("LOCATED_IN", d, f"site:{device.site}", {}))
    if device.group is not None:
        rels.append(("MEMBER_OF", d, device.group, {}))
    for i in range(device.ports):
        oper = "down" if (i + v) % 7 == 0 else "up"
        nodes.append(
            (
                "Port",
                {
                    "uid": _port_uid(device, i),
                    "name": f"Ethernet1/{i + 1}",
                    "speed_mbps": 10_000,
                    "oper_status": oper,
                },
            )
        )
        rels.append(("ON", _port_uid(device, i), d, {}))
    if device.tier in L3_TIERS:
        for name, rd in (("default", "65000:1"), ("corp", "65000:2")):
            nodes.append(("VrfInstance", {"uid": f"vrf:{d}:{name}", "name": name, "rd": rd}))
            rels.append(("OWNED_BY", f"vrf:{d}:{name}", d, {}))
        for i in range(device.used):
            iface = _if_uid(device, i)
            nodes.append(
                (
                    "Interface",
                    {"uid": iface, "name": f"Ethernet1/{i + 1}", "oper_status": "up", "admin_up": True},
                )
            )
            rels.append(("ON", iface, d, {}))
            if _unit(spec.seed, "port-edge", d, i) < spec.port_edge_share:
                rels.append(("REALIZED_BY", iface, _port_uid(device, i), {}))
            if _unit(spec.seed, "context-edge", d, i) < spec.context_edge_share:
                rels.append(("IN_VRF", iface, f"vrf:{d}:{'corp' if i % 2 else 'default'}", {}))
            addr = f"10.{device.index // 256}.{device.index % 256}.{2 * i}"
            nodes.append(("IpAddress", {"uid": f"ip:{d}:{addr}", "address": addr}))
            nodes.append(("Prefix", {"uid": f"pfx:{d}:{addr}/31", "cidr": f"{addr}/31"}))
            rels.append(("HAS_IP", iface, f"ip:{d}:{addr}", {}))
            rels.append(("IN", f"ip:{d}:{addr}", f"pfx:{d}:{addr}/31", {}))
    else:
        iface = f"{d}/if/mgmt0"
        nodes.append(("Interface", {"uid": iface, "name": "mgmt0", "oper_status": "up", "admin_up": True}))
        rels.append(("ON", iface, d, {}))
        vlans = VLANS + v % 2
        for vid in range(10, 10 + vlans):
            nodes.append(("VlanInstance", {"uid": f"vlan:{d}:{vid}", "vid": vid}))
        for i in range(2, device.ports):
            rels.append(("CARRIES", _port_uid(device, i), f"vlan:{d}:{10 + i % vlans}", {}))
        site = device.site or "orphan"
        for e in range(ENDPOINTS + v % 3):
            mac = f"02:00:{device.index // 256 % 256:02x}:{device.index % 256:02x}:00:{e:02x}"
            nodes.append(("Endpoint", {"uid": f"ep:{site}:{mac}", "mac": mac}))
            rels.append(("ATTACHED", f"ep:{site}:{mac}", _port_uid(device, 2 + e), {}))
    if device.tier == "firewall":
        bases = [f"fwrb:{d}:{k}" for k in range(RULEBASES)]
        if _unit(spec.seed, "unbound", d) < spec.unbound_share:
            bases.append(f"fwrb:{d}:orphan")
        for rb in bases:
            nodes.append(("FwRulebase", {"uid": rb, "kind": "access", "name": rb.rsplit(":", 1)[-1]}))
            if not rb.endswith(":orphan"):
                rels.append(("ENFORCES", d, rb, {}))
            for r in range(RULES + (v % 3) * 5):
                nodes.append(("FwRule", {"uid": f"{rb}:r{r}", "position": r, "action": "accept"}))
                rels.append(("HAS_RULE", rb, f"{rb}:r{r}", {}))
        nat = f"fwrb:{d}:nat"
        nodes.append(("FwRulebase", {"uid": nat, "kind": "nat", "name": "nat"}))
        rels.append(("ENFORCES", d, nat, {}))
        for r in range(NAT_RULES):
            nodes.append(("NatRule", {"uid": f"{nat}:n{r}", "kind": "snat"}))
            rels.append(("HAS_RULE", nat, f"{nat}:n{r}", {}))
    if device.tier == "wan-edge":
        proc = f"rproc:{d}:default:bgp"
        nodes.append(("RoutingProcess", {"uid": proc, "protocol": "bgp"}))
        rels.append(("IN_VRF", proc, f"vrf:{d}:default", {}))
        for p in range(BGP_PEERS):
            peer = f"bgp:{proc}~192.0.2.{p + 1}:default"
            nodes.append(("BgpSession", {"uid": peer, "peer_ip": f"192.0.2.{p + 1}", "state": "established"}))
            rels.append(("HAS", proc, peer, {}))
    return nodes, rels


def shared_objects(estate: Estate, run: int) -> tuple[list[tuple[str, Row]], list[tuple[str, str, str, Row]]]:
    """Sites, redundancy groups, cables, LAGs and tunnels at `run`."""
    nodes: list[tuple[str, Row]] = [
        ("Site", {"uid": f"site:{code}", "code": code, "name": code}) for code in estate.sites
    ]
    groups = sorted({d.group for d in estate.devices if d.group})
    nodes += [("RedundancyGroup", {"uid": g, "kind": g.split(":")[1], "name": g}) for g in groups]
    rels: list[tuple[str, str, str, Row]] = []
    for c in estate.cables:
        if present(estate, c.a, run) and present(estate, c.b, run):
            rels.append(
                ("CONNECTED_TO", _port_uid(c.a, c.a_port), _port_uid(c.b, c.b_port), {"source": "bench"})
            )
    for device, lag, ports in estate.lags:
        nodes.append(("Lag", {"uid": lag, "name": lag.rsplit("/", 1)[-1]}))
        rels.append(("ON", lag, device.uid, {}))
        rels += [("MEMBER_OF", _port_uid(device, p), lag, {}) for p in ports]
    for i, (a, b) in enumerate(estate.tunnels):
        for k, encap in enumerate(TUNNEL_ENCAPS[i % len(TUNNEL_ENCAPS)]):
            uid = f"tun:{encap}:{a.uid}~{b.uid}:{k}"
            nodes.append(("Tunnel", {"uid": uid, "encap": encap}))
            rels.append(("ENDPOINT", uid, a.uid, {}))
            rels.append(("TERMINATES_ON", uid, b.uid, {}))
    return nodes, rels


def run_objects(
    estate: Estate, run: int, chunk: int = 200
) -> Iterator[tuple[list[tuple[str, Row]], list[tuple[str, str, str, Row]]]]:
    """The objects of one run, a chunk of devices at a time, the shared objects first."""
    yield shared_objects(estate, run)
    alive = [d for d in estate.devices if present(estate, d, run)]
    for start in range(0, len(alive), chunk):
        nodes: list[tuple[str, Row]] = []
        rels: list[tuple[str, str, str, Row]] = []
        for device in alive[start : start + chunk]:
            n, r = device_objects(estate, device, run)
            nodes += n
            rels += r
        yield nodes, rels


def ratios(estate: Estate) -> dict[str, float]:
    """Per-device averages of the static topology, for the benchmark report."""
    n = max(1, len(estate.devices))
    return {
        "sites": len(estate.sites),
        "devices": len(estate.devices),
        "orphan_devices": sum(1 for d in estate.devices if d.site is None),
        "ports_per_device": sum(d.ports for d in estate.devices) / n,
        "cables_per_device": len(estate.cables) / n,
        "firewalls": sum(1 for d in estate.devices if d.tier == "firewall"),
        "max_site": max((sum(1 for d in estate.devices if d.site == s) for s in estate.sites), default=0),
        "tunnels": len(estate.tunnels),
        "lags": len(estate.lags),
        "rings": math.ceil(math.sqrt(len(estate.sites))),
    }
