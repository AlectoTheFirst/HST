"""The network segments of a drawing, one record per bridge domain, joined from
the VLAN, subnet and client rows that the topology route reads.

A segment is a `BridgeDomain` (uid `bd:vlan:<fabric>:<vid>` on a classic
estate, DN-keyed on ACI). Every source that states the VLAN joins on that uid.
UniFi joins from its networks and ports, VyOS and Cisco from their SVIs. A
segment record holds these fields.

- carriers: the drawn ports that carry the segment, per device, with the
  native ports and the access ports among them. An access port is a native
  port with no cable.
- gateways: the drawn interfaces that the graph attaches to the segment, one
  row per address of the interface on a connected prefix. The reasoner writes
  `(Interface)-[:ATTACHED_TO {basis}]->(BridgeDomain)`, and the row holds
  that basis. The basis is `svi`, `subif` (a VLAN subinterface such as a VyOS
  `eth0.10`) or `cable` (an untagged routed port, such as the `eth0` of a
  router cabled to the native VLAN of a UniFi switch port). The SVI bound to
  the VLAN on a drawn device also joins (`basis: svi`), once per interface,
  and the basis of the edge takes precedence. A segment with no gateway takes
  the prefixes of the addresses of its clients. A drawn interface on one of
  those prefixes that no segment holds is its gateway by the prefix alone
  (`basis: cidr`), when the interface is at a site of the devices of the
  segment and every such interface is in one routing domain. `routes` is true
  when the graph marks the interface GATEWAY_FOR the prefix.
- cidrs: the prefixes `IN` the bridge domain and the prefixes of the gateways.
  A segment without those takes the prefixes of the clients. `cidr_basis`
  holds the basis. IPv4 comes first, then IPv6, each in address order.
- clients: the count of client endpoints in the segment, and the count per
  attachment point. An attachment point is a port, or an access point and
  SSID.
- site: the site of the devices of the segment, when the drawing holds devices
  of more than one site. With no L2 fabric declared, VLAN 10 of every site is
  one bridge domain (core/config.py `DEFAULT_L2_FABRIC`). The record is kept
  per site, under the same `bd`.

A client endpoint is skipped when its MAC is the chassis MAC of a drawn
device, or when it attaches to a port that has a cable (`visible`).

The module reads no database and is deterministic. The same rows in any order
give the same records.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from hst.core import uid as uidmod


def norm_mac(value: Any) -> str | None:
    """The canonical form of a MAC (core/uid.py `norm_mac`), or None when it does not parse."""
    if not value:
        return None
    try:
        return uidmod.norm_mac(str(value))
    except ValueError:
        return None


def cabled_ports(cables: Iterable[Mapping[str, Any]]) -> set[tuple[str, str]]:
    """The (device, port) of every cable end in the topology route's cable rows."""
    out: set[tuple[str, str]] = set()
    for c in cables:
        for dev, port in ((c.get("a_dev"), c.get("a_port")), (c.get("b_dev"), c.get("b_port"))):
            if dev and port:
                out.add((str(dev), str(port)))
    return out


def device_macs(devices: Iterable[Mapping[str, Any]]) -> set[str]:
    """The canonical chassis MACs of the drawn devices that state one."""
    return {m for m in (norm_mac(d.get("mac")) for d in devices) if m}


def visible(row: Mapping[str, Any], macs: set[str], cabled: set[tuple[str, str]]) -> bool:
    """Whether a client row is drawn. A row is not drawn when its MAC is the MAC of a drawn
    device or when its port has a cable."""
    mac = norm_mac(row.get("mac"))
    if mac is not None and mac in macs:
        return False
    port = row.get("port")
    return not (port and (row.get("dev"), port) in cabled)


def segments(
    vlans: Iterable[Mapping[str, Any]],
    subnets: Iterable[Mapping[str, Any]],
    clients: Iterable[Mapping[str, Any]],
    cabled: set[tuple[str, str]],
    attached: Iterable[Mapping[str, Any]] = (),
    prefixes: Iterable[Mapping[str, Any]] = (),
    sites: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """One record per bridge domain of the drawing, ordered by VLAN id and uid.

    The arguments are rows of the topology route.

    - `vlans`: the per-device VLAN groups (dev, vid, name, segment, bd, ports,
      native, svi)
    - `subnets`: the per-address rows of the subnet read (dev, iface, ip, cidr,
      af, vrf, domain, fhrp)
    - `clients`: the client rows after `visible` (dev, port, ssid, bd, cidrs)
    - `cabled`: the cabled ports
    - `attached`: the rows of the attachment read, one per address of an
      attached interface on a connected prefix (dev, iface, bd, basis, vid,
      segment, ip, cidr, af, vrf, domain, fhrp). ip and cidr are null for an
      interface with no such address.
    - `prefixes`: the rows of the bridge-domain prefix read (bd, cidr)
    - `sites`: the site of each drawn device, by uid

    A VLAN group with no bridge domain joins no segment. A drawing of devices
    at more than one site holds one record per (bridge domain, site). A prefix
    of the bridge domain joins the records whose gateways or clients sit in
    it.
    """
    site_of = sites or {}
    split = len({code for code in site_of.values() if code}) > 1
    addresses: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for s in subnets:
        addresses.setdefault((s["dev"], s["iface"]), []).append(s)

    segs: dict[tuple[str, str | None], dict[str, Any]] = {}
    # The interfaces that a segment holds as a gateway by the graph. Such an
    # interface is not a gateway of another segment by the prefix alone.
    claimed: set[tuple[str, str]] = set()

    def seg_of(bd: str, dev: str | None) -> dict[str, Any]:
        site = site_of.get(dev) if split and dev else None
        return segs.setdefault(
            (bd, site),
            {
                "bd": bd,
                "site": site,
                "vid": None,
                "name": None,
                "carriers": {},
                "gateways": [],
                "held": set(),
                "cidrs": [],
                "cidr_basis": None,
                "clients": 0,
                "attachments": Counter(),
                "client_cidrs": Counter(),
                "prefixes": set(),
                "devices": set(),
            },
        )

    # The attachments of the graph are read first.
    seen: set[tuple[str, str, str, Any, Any]] = set()
    for a in sorted(attached, key=_attached_key):
        bd = a.get("bd")
        if not bd:
            continue
        key = (bd, a["dev"], a["iface"], a.get("ip"), a.get("cidr"))
        if key in seen:
            continue
        seen.add(key)
        seg = seg_of(bd, a["dev"])
        if seg["vid"] is None and a.get("vid") is not None:
            seg["vid"] = int(a["vid"])
        seg["name"] = seg["name"] or a.get("segment")
        seg["held"].add((a["dev"], a["iface"]))
        claimed.add((a["dev"], a["iface"]))
        row = a if a.get("ip") is not None else None
        seg["gateways"].append(_gateway(a["dev"], a["iface"], row, a.get("basis")))

    for v in sorted(vlans, key=lambda v: (v["dev"], int(v["vid"]))):
        bd = v.get("bd")
        if not bd:
            continue
        seg = seg_of(bd, v["dev"])
        if seg["vid"] is None:
            seg["vid"] = int(v["vid"])
        seg["name"] = seg["name"] or v.get("segment") or v.get("name")
        dev = v["dev"]
        if v.get("ports"):
            seg["devices"].add(dev)
            native = sorted(v.get("native") or [])
            seg["carriers"][dev] = {
                "dev": dev,
                "ports": sorted(v["ports"]),
                "native": native,
                "access": [p for p in native if (dev, p) not in cabled],
            }
        if v.get("svi"):
            claimed.add((dev, v["svi"]))
            if (dev, v["svi"]) in seg["held"]:
                continue
            seg["held"].add((dev, v["svi"]))
            rows = addresses.get((dev, v["svi"]), [])
            if not rows:
                seg["gateways"].append(_gateway(dev, v["svi"], None, "svi"))
            seg["gateways"].extend(_gateway(dev, v["svi"], r, "svi") for r in rows)

    for c in clients:
        bd = c.get("bd")
        if not bd:
            continue
        seg = seg_of(bd, c.get("dev"))
        seg["clients"] += 1
        if c.get("dev"):
            seg["devices"].add(c["dev"])
        seg["attachments"][(c.get("dev") or "", c.get("port") or "", c.get("ssid") or "")] += 1
        for cidr in c.get("cidrs") or []:
            seg["client_cidrs"][cidr] += 1

    for p in prefixes:
        if not p.get("cidr"):
            continue
        for (bd, _site), seg in segs.items():
            if bd != p.get("bd"):
                continue
            if not split or p["cidr"] in {g["cidr"] for g in seg["gateways"]} | set(seg["client_cidrs"]):
                seg["prefixes"].add(p["cidr"])

    # The segments are read in bridge-domain order. A segment claims the
    # interface that it takes by the prefix, and the first of 2 segments takes it.
    for seg in sorted(segs.values(), key=lambda s: (s["bd"], s["site"] or "")):
        mine = {g["cidr"] for g in seg["gateways"] if g["cidr"]} | seg["prefixes"]
        if mine:
            seg["cidrs"], seg["cidr_basis"] = _ordered(mine), "gateway"
            continue
        voted = set(seg["client_cidrs"])
        if not voted:
            continue
        seg["cidrs"], seg["cidr_basis"] = _ordered(voted), "clients"
        if seg["gateways"]:
            continue
        seg_sites = {site_of[d] for d in seg["devices"] if site_of.get(d)}
        held = sorted(
            key
            for key, rows in addresses.items()
            if key not in claimed
            and any(r["cidr"] in voted for r in rows)
            and (not seg_sites or site_of.get(key[0]) in seg_sites)
        )
        domains = {
            r.get("domain") or f"vrf:{r.get('vrf')}"
            for key in held
            for r in addresses[key]
            if r["cidr"] in voted
        }
        if len(domains) > 1:
            held = []
        for dev, iface in held:
            claimed.add((dev, iface))
            seg["gateways"].extend(_gateway(dev, iface, r, "cidr") for r in addresses[(dev, iface)])
        if held:
            seg["cidrs"] = _ordered({g["cidr"] for g in seg["gateways"] if g["cidr"]} | voted)

    out = []
    for seg in sorted(
        segs.values(), key=lambda s: (s["vid"] is None, s["vid"] or 0, s["bd"], s["site"] or "")
    ):
        seg["gateways"].sort(key=lambda g: (g["dev"], g["iface"], g["af"] or 0, g["ip"] or ""))
        out.append(
            {
                "bd": seg["bd"],
                "site": seg["site"],
                "vid": seg["vid"],
                "name": seg["name"],
                "cidrs": seg["cidrs"],
                "cidr_basis": seg["cidr_basis"],
                "gateways": seg["gateways"],
                "carriers": [seg["carriers"][d] for d in sorted(seg["carriers"])],
                "clients": seg["clients"],
                "attachments": [
                    {"dev": dev or None, "port": port or None, "ssid": ssid or None, "count": n}
                    for (dev, port, ssid), n in sorted(seg["attachments"].items())
                ],
            }
        )
    return out


def _attached_key(row: Mapping[str, Any]) -> tuple[str, ...]:
    """A total order of the attachment rows. The first of 2 duplicate rows is the same row for
    any input order."""
    return tuple(
        str(row.get(k) or "") for k in ("bd", "dev", "iface", "basis", "ip", "cidr", "vrf", "domain", "fhrp")
    )


def _ordered(cidrs: Iterable[str]) -> list[str]:
    """Return the cidrs with IPv4 first, then IPv6, each in address order. A cidr that does not
    parse comes last, ordered by its text."""

    def key(cidr: str) -> tuple[int, int, int, str]:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return (2, 0, 0, cidr)
        return (0 if net.version == 4 else 1, int(net.network_address), net.prefixlen, cidr)

    return sorted(set(cidrs), key=key)


def _gateway(dev: str, iface: str, row: Mapping[str, Any] | None, basis: str | None) -> dict[str, Any]:
    return {
        "dev": dev,
        "iface": iface,
        "ip": row["ip"] if row else None,
        "cidr": row["cidr"] if row else None,
        "af": row.get("af") if row else None,
        "vrf": row.get("vrf") if row else None,
        "domain": row.get("domain") if row else None,
        "fhrp": row.get("fhrp") if row else None,
        # Whether the graph marks the interface GATEWAY_FOR the prefix. A trace uses only such
        # a gateway. Null when the row has no `routes` value, as in a row with no address.
        "routes": row.get("routes") if row else None,
        "basis": basis,
    }
