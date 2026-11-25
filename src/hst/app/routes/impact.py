"""GET /api/impact returns the impact assessment of one device."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from hst import path as pathmod
from hst.app import simul_read as simul_read
from hst.app.auth import require_permission
from hst.app.routes.path import _requested_run
from hst.assessment.evaluation import (
    _GROUP_KIND_TO_CONDITION as _GROUP_KIND_TO_CONDITION,
)
from hst.assessment.evaluation import (
    _GROUP_QUERY as _GROUP_QUERY,
)
from hst.assessment.evaluation import (
    _MAX_GROUP_DEPTH as _MAX_GROUP_DEPTH,
)
from hst.assessment.evaluation import (
    _NETWORK_INTERFACES_QUERY as _NETWORK_INTERFACES_QUERY,
)
from hst.assessment.evaluation import (
    _REQUIREMENT_QUERY as _REQUIREMENT_QUERY,
)
from hst.assessment.evaluation import (
    _TRIAGE_PARTS as _TRIAGE_PARTS,
)
from hst.assessment.evaluation import (
    EVIDENCE_CAP as EVIDENCE_CAP,
)
from hst.assessment.evaluation import (
    MAX_INTENTS as MAX_INTENTS,
)
from hst.assessment.evaluation import (
    MAX_MEMBERS as MAX_MEMBERS,
)
from hst.assessment.evaluation import (
    MAX_SOURCES as MAX_SOURCES,
)
from hst.assessment.evaluation import (
    ConditionBody as ConditionBody,
)
from hst.assessment.evaluation import (
    EvaluateBody as EvaluateBody,
)
from hst.assessment.evaluation import (
    MemberBody as MemberBody,
)
from hst.assessment.evaluation import (
    RequestBody as RequestBody,
)
from hst.assessment.evaluation import (
    _address_bucket as _address_bucket,
)
from hst.assessment.evaluation import (
    _address_set as _address_set,
)
from hst.assessment.evaluation import (
    _change_set as _change_set,
)
from hst.assessment.evaluation import (
    _cidrs as _cidrs,
)
from hst.assessment.evaluation import (
    _condition_body as _condition_body,
)
from hst.assessment.evaluation import (
    _condition_from_body as _condition_from_body,
)
from hst.assessment.evaluation import (
    _condition_from_graph as _condition_from_graph,
)
from hst.assessment.evaluation import (
    _contexts_in_scope as _contexts_in_scope,
)
from hst.assessment.evaluation import (
    _evidence as _evidence,
)
from hst.assessment.evaluation import (
    _group_tree as _group_tree,
)
from hst.assessment.evaluation import (
    _member_rows as _member_rows,
)
from hst.assessment.evaluation import (
    _model_interfaces as _model_interfaces,
)
from hst.assessment.evaluation import (
    _outcome_counts as _outcome_counts,
)
from hst.assessment.evaluation import (
    _request_from_body as _request_from_body,
)
from hst.assessment.evaluation import (
    _request_from_requirement as _request_from_requirement,
)
from hst.assessment.evaluation import (
    _service_of as _service_of,
)
from hst.assessment.evaluation import (
    _steps as _steps,
)
from hst.assessment.evaluation import (
    _triage_body as _triage_body,
)
from hst.assessment.evaluation import (
    _triage_flags as _triage_flags,
)
from hst.assessment.evaluation import (
    evaluate_change as evaluate_change,
)
from hst.core import bgpsource as bgpsource
from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core import ospfsource as ospfsource
from hst.core import ribsource as ribsource
from hst.core import snapshot as snapshotmod
from hst.core.diff import DETAIL_CAP

router = APIRouter()
_session = dbmod.session  # Tests replace this name.

_DEVICE_QUERY = """
MATCH (d:Device:Obj {uid: $dev, collection_ts: $snap})
WHERE NOT d:Retired
RETURN d.uid AS uid, d.hostname AS hostname, d.role AS role,
       d.os_version AS software_version, d.platform AS platform,
       d.vendor AS vendor, d.model AS model
ORDER BY d.uid LIMIT 1"""

# GATEWAY_FOR starts at an svi Interface or at an FhrpGroup. MEMBER_OF*0..1 reaches
# the device through the svi Interface or through the member interface of the group.
# The query collects every gateway device of the prefix and keeps the row only
# when this device is one of them.
_GATEWAY_PREFIX_QUERY = """
MATCH (gw)-[g:GATEWAY_FOR]->(p:Prefix:Obj)
WHERE g._retired_at IS NULL AND NOT gw:Retired AND NOT p:Retired
  AND p.collection_ts = $snap
MATCH (gw)<-[m:MEMBER_OF*0..1]-(i:Interface)-[o:ON]->(d:Device)
WHERE o._retired_at IS NULL AND NOT i:Retired AND NOT d:Retired
  AND all(r IN m WHERE r._retired_at IS NULL)
WITH p, collect(DISTINCT d.uid) AS gateways
WHERE $dev IN gateways
RETURN p.uid AS uid, p.cidr AS cidr, p.kind AS kind, p.l3dom AS l3dom,
       [x IN gateways WHERE x <> $dev] AS other_devices
ORDER BY p.uid"""

# An endpoint attaches to an interface, a port or an AP device. A port can sit on a
# module. PART_OF*0..1 reaches the device that holds the port.
_ENDPOINT_QUERY = """
MATCH (ep:Endpoint:Obj)-[a:ATTACHED]->(att)
WHERE a._retired_at IS NULL AND NOT ep:Retired AND NOT att:Retired
  AND ep.collection_ts = $snap
OPTIONAL MATCH (att)-[o:ON]->(h)-[pf:PART_OF*0..1]->(hd:Device)
WHERE o._retired_at IS NULL AND NOT hd:Retired
  AND all(r IN pf WHERE r._retired_at IS NULL)
// collect drops nulls, so an attachment that resolves to no device drops out here
WITH ep, collect(DISTINCT coalesce(hd.uid, CASE WHEN att:Device THEN att.uid END)) AS devices
WHERE $dev IN devices
RETURN ep.uid AS uid, coalesce(ep.name, ep.hostname, ep.mac) AS name, ep.kind AS kind,
       [x IN devices WHERE x <> $dev] AS other_devices
ORDER BY ep.uid"""

_REDUNDANCY_QUERY = """
MATCH (d:Device:Obj {uid: $dev, collection_ts: $snap})-[m:MEMBER_OF]->(rg:RedundancyGroup)
WHERE m._retired_at IS NULL AND NOT d:Retired AND NOT rg:Retired
OPTIONAL MATCH (peer:Device)-[pm:MEMBER_OF]->(rg)
WHERE pm._retired_at IS NULL AND NOT peer:Retired AND peer.uid <> $dev
RETURN rg.uid AS uid, rg.kind AS kind, rg.name AS name, m.role AS role,
       collect(DISTINCT {uid: peer.uid, hostname: peer.hostname}) AS other_members
ORDER BY rg.uid"""

_INTERFACE_QUERY = """
MATCH (i:Interface)-[o:ON]->(d:Device:Obj {uid: $dev, collection_ts: $snap})
WHERE o._retired_at IS NULL AND NOT i:Retired AND NOT d:Retired
RETURN i.uid AS uid, i.name AS name, i.kind AS kind
ORDER BY i.uid"""

# With HAS_IP*0..1 the tunnel endpoint is the interface or an address that the interface holds.
_TUNNEL_QUERY = """
MATCH (t:Tunnel:Obj)-[e:ENDPOINT]->(x)
WHERE e._retired_at IS NULL AND NOT t:Retired AND NOT x:Retired
  AND t.collection_ts = $snap
MATCH (x)<-[hi:HAS_IP*0..1]-(i:Interface)-[o:ON]->(d:Device:Obj {uid: $dev, collection_ts: $snap})
WHERE o._retired_at IS NULL AND NOT i:Retired AND NOT d:Retired
  AND all(r IN hi WHERE r._retired_at IS NULL)
RETURN DISTINCT t.uid AS uid, t.encap AS encap, t.state AS state
ORDER BY t.uid"""

_BGP_QUERY = """
MATCH (b:BgpSession:Obj)-[e:ENDPOINT]->(ip:IpAddress)
WHERE e._retired_at IS NULL AND NOT b:Retired AND NOT ip:Retired
  AND b.collection_ts = $snap
MATCH (ip)<-[hi:HAS_IP]-(i:Interface)-[o:ON]->(d:Device:Obj {uid: $dev, collection_ts: $snap})
WHERE hi._retired_at IS NULL AND o._retired_at IS NULL AND NOT i:Retired AND NOT d:Retired
RETURN DISTINCT b.uid AS uid, b.local_ip AS local_ip, b.peer_ip AS peer_ip,
       b.peer_asn AS peer_asn, b.kind AS kind, b.state AS state
ORDER BY b.uid"""

_FHRP_QUERY = """
MATCH (i:Interface)-[o:ON]->(d:Device:Obj {uid: $dev, collection_ts: $snap})
WHERE o._retired_at IS NULL AND NOT i:Retired AND NOT d:Retired
MATCH (i)-[m:MEMBER_OF]->(g:FhrpGroup)
WHERE m._retired_at IS NULL AND NOT g:Retired
OPTIONAL MATCH (peer:Interface)-[pm:MEMBER_OF]->(g)
WHERE pm._retired_at IS NULL AND NOT peer:Retired AND peer.uid <> i.uid
OPTIONAL MATCH (peer)-[po:ON]->(pd:Device)
WHERE po._retired_at IS NULL AND NOT pd:Retired AND pd.uid <> $dev
RETURN g.uid AS uid, g.kind AS kind, g.group_id AS group_id, g.vip AS vip,
       collect(DISTINCT i.name) AS interfaces,
       collect(DISTINCT pd.uid) AS other_devices
ORDER BY g.uid"""

# The 3 circuit kinds that a link or tunnel loss question can name. Each query
# reports every device-to-circuit pair in the run. assess_link looks up the named
# uid in the merged result. The result gives the device that carries the circuit
# and the other circuits of that device.

# HAS_LINK starts at the device. The uid of the WanLink identifies the device.
# `under` is what the link leaves the device by. It holds the Interfaces that the
# link is ON and the Ports that they are REALIZED_BY. It is empty when the source
# records no ON edge.
_LINK_WANLINK_QUERY = """
MATCH (d:Device)-[hl:HAS_LINK]->(wl:WanLink:Obj)
WHERE hl._retired_at IS NULL AND NOT d:Retired AND NOT wl:Retired
  AND wl.collection_ts = $snap
OPTIONAL MATCH (wl)-[wo:ON]->(i:Interface)
WHERE wo._retired_at IS NULL AND NOT i:Retired
OPTIONAL MATCH (i)-[rb:REALIZED_BY]->(p:Port)
WHERE rb._retired_at IS NULL AND NOT p:Retired
RETURN d.uid AS dev, wl.uid AS link, collect(DISTINCT i.uid) + collect(DISTINCT p.uid) AS under"""

# CONNECTED_TO is undirected and has no uid. A cable is named by either of its 2
# Ports. The query reports the device of the Port as the carrier and, per cable, the
# Port and the device on the other end. `_port_leads_away` reads the other end. A
# WanLink of the far device leads away only when it does not leave by that Port.
_LINK_PORT_QUERY = """
MATCH (p:Port:Obj)-[o:ON]->(d:Device)
WHERE o._retired_at IS NULL AND NOT p:Retired AND NOT d:Retired
  AND p.collection_ts = $snap
MATCH (p)-[c:CONNECTED_TO]-(peer:Port)
WHERE c._retired_at IS NULL AND NOT peer:Retired
OPTIONAL MATCH (peer)-[po:ON]->(pd:Device)
WHERE po._retired_at IS NULL AND NOT pd:Retired AND pd.uid <> d.uid
RETURN d.uid AS dev, p.uid AS link, collect(DISTINCT [peer.uid, pd.uid]) AS far"""

# With HAS_IP*0..1 the tunnel endpoint is the interface or an address that the
# interface holds, as in _TUNNEL_QUERY. The device of the local end is the carrier.
# `under` holds that interface and the Port that it is REALIZED_BY.
_LINK_TUNNEL_QUERY = """
MATCH (t:Tunnel:Obj)-[e:ENDPOINT]->(x)
WHERE e._retired_at IS NULL AND NOT t:Retired AND NOT x:Retired
  AND t.collection_ts = $snap
MATCH (x)<-[hi:HAS_IP*0..1]-(i:Interface)-[o:ON]->(d:Device)
WHERE o._retired_at IS NULL AND NOT i:Retired AND NOT d:Retired
  AND all(r IN hi WHERE r._retired_at IS NULL)
OPTIONAL MATCH (i)-[rb:REALIZED_BY]->(p:Port)
WHERE rb._retired_at IS NULL AND NOT p:Retired
RETURN d.uid AS dev, t.uid AS link, collect(DISTINCT i.uid) + collect(DISTINCT p.uid) AS under"""

# A tunnel whose ENDPOINT is its own tunnel interface (wg0 of WireGuard) has no
# underlay at the endpoint. Its `local_address` is the address that the outer packet
# leaves from. The query reports every Interface of the device of the tunnel that
# holds that address at the run, with its Port and with the source of the address.
# `_Circuits.tunnel_local` is built from these rows.
_LINK_TUNNEL_LOCAL_QUERY = """
MATCH (t:Tunnel:Obj)-[e:ENDPOINT]->(x)
WHERE e._retired_at IS NULL AND NOT t:Retired AND NOT x:Retired
  AND t.collection_ts = $snap AND t.local_address IS NOT NULL
MATCH (x)<-[hi:HAS_IP*0..1]-(:Interface)-[o:ON]->(d:Device)
WHERE o._retired_at IS NULL AND NOT d:Retired
  AND all(r IN hi WHERE r._retired_at IS NULL)
MATCH (li:Interface:Obj {collection_ts: $snap})-[lo:ON]->(d)
WHERE lo._retired_at IS NULL AND NOT li:Retired
MATCH (li)-[h:HAS_IP]->(la:IpAddress)
WHERE h._retired_at IS NULL AND NOT la:Retired AND la.ip = t.local_address
OPTIONAL MATCH (li)-[rb:REALIZED_BY]->(p:Port)
WHERE rb._retired_at IS NULL AND NOT p:Retired
RETURN d.uid AS dev, t.uid AS link, t.local_address_source AS source,
       collect(DISTINCT [li.uid, p.uid]) AS local_ifs"""

# The local address names the interface that the tunnel leaves by only when the
# configuration states the address, or when the RIB of the run routes the outer
# packet out of it.
_TUNNEL_LOCAL_SOURCES = frozenset({"configured", "derived:egress"})


# An Equinix Fabric circuit named by its VirtualCircuit uid resolves to the link
# that the cable-from-fabric-circuit rule of the reasoner derived for it. The edge
# has `circuit_uid`. The assessment runs on the A-side port of that link.
_CIRCUIT_LINK_QUERY = """
MATCH (a:Port:Obj)-[c:CONNECTED_TO]->(z:Port)
WHERE c.circuit_uid = $link AND c._retired_at IS NULL AND NOT a:Retired AND NOT z:Retired
  AND a.collection_ts = $snap
RETURN a.uid AS a, z.uid AS z
ORDER BY a.uid, z.uid LIMIT 1"""

# The bridge domains that both device ports of a circuit carry. They are the VLANs
# that the circuit stretches under the default single-fabric identity.
_CIRCUIT_BRIDGE_DOMAINS_QUERY = """
MATCH (a:Port:Obj {uid: $a, collection_ts: $snap})-[ca:CARRIES]->(va:VlanInstance)
      -[ra:REALIZES]->(bd:BridgeDomain)
      <-[rz:REALIZES]-(vz:VlanInstance)<-[cz:CARRIES]-(z:Port:Obj {uid: $z, collection_ts: $snap})
WHERE ca._retired_at IS NULL AND ra._retired_at IS NULL AND rz._retired_at IS NULL
  AND cz._retired_at IS NULL AND NOT a:Retired AND NOT z:Retired
  AND NOT va:Retired AND NOT vz:Retired AND NOT bd:Retired
  AND bd.collection_ts = $snap
RETURN DISTINCT bd.uid AS uid, bd.name AS name, va.vid AS vid
ORDER BY bd.uid"""


def _bucket(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """One detail bucket with the complete count, the capped rows and the cap flag."""
    return {"count": len(rows), "items": rows[:DETAIL_CAP], "truncated": len(rows) > DETAIL_CAP}


def _single_homed(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The rows whose only recorded device is the one under assessment."""
    return [{k: v for k, v in r.items() if k != "other_devices"} for r in rows if not r["other_devices"]]


def assess(session: Any, dev_uid: str) -> dict[str, Any]:
    """The impact buckets for one device, read from the session's pinned run.

    The session must be pinned (`path.pinned`). `path._read` binds $snap from it.
    """
    identity = pathmod._read_one(session, _DEVICE_QUERY, dev=dev_uid)
    if identity is None:
        raise HTTPException(404, detail=f"no device {dev_uid} in this snapshot")

    prefixes = pathmod._read(session, _GATEWAY_PREFIX_QUERY, dev=dev_uid)
    endpoints = pathmod._read(session, _ENDPOINT_QUERY, dev=dev_uid)
    groups = pathmod._read(session, _REDUNDANCY_QUERY, dev=dev_uid)
    interfaces = pathmod._read(session, _INTERFACE_QUERY, dev=dev_uid)
    tunnels = pathmod._read(session, _TUNNEL_QUERY, dev=dev_uid)
    sessions = pathmod._read(session, _BGP_QUERY, dev=dev_uid)
    fhrp = pathmod._read(session, _FHRP_QUERY, dev=dev_uid)

    redundancy = []
    for row in groups:
        members = [m for m in row["other_members"] if m.get("uid")]
        redundancy.append(
            {
                "uid": row["uid"],
                "kind": row["kind"],
                "name": row["name"],
                "role": row["role"],
                "other_members": sorted(members, key=lambda m: m["uid"]),
                "has_other_members": bool(members),
            }
        )

    fhrp_rows = [
        {
            "uid": row["uid"],
            "kind": row["kind"],
            "group_id": row["group_id"],
            "vip": row["vip"],
            "interfaces": sorted(n for n in row["interfaces"] if n),
            "other_devices": sorted(u for u in row["other_devices"] if u),
        }
        for row in fhrp
    ]

    return {
        "device": identity,
        "run": cyclemod.run_status(session, getattr(session, "snapshot", None)),
        "single_homed_prefixes": _bucket(_single_homed(prefixes)),
        "single_homed_endpoints": _bucket(_single_homed(endpoints)),
        "gateway_prefixes": _bucket(prefixes),
        "attached_endpoints": _bucket(endpoints),
        "redundancy_groups": _bucket(redundancy),
        "interfaces": _bucket(interfaces),
        "tunnels": _bucket(tunnels),
        "bgp_sessions": _bucket(sessions),
        "fhrp_groups": _bucket(fhrp_rows),
    }


@dataclass
class _Circuits:
    """The recorded WAN links, tunnel endpoints and cabled ports of every device.
    Each has its underlay, the Interface and Port uids that it leaves the device by."""

    # A map from device uid and WanLink uid to the Interfaces that the link is ON and
    # their Ports. An empty set marks an underlay that is not recorded.
    wan: dict[str, dict[str, set[str]]]
    # A map from device uid and Tunnel uid to the local ENDPOINT Interface of the
    # tunnel and the Port of that Interface.
    tunnels: dict[str, dict[str, set[str]]]
    # A map from device uid and cabled Port uid to the (far Port, far device or None)
    # of each cable of the Port.
    ports: dict[str, dict[str, set[tuple[str, str | None]]]]
    # A map from device uid and Tunnel uid to the one Interface that holds the local
    # address of the tunnel, and the Port of that Interface. An entry exists only when
    # the address is known and exactly one Interface holds it.
    tunnel_local: dict[str, dict[str, set[str]]] = field(default_factory=dict)

    def carried(self) -> dict[str, set[str]]:
        """Every circuit of each device, of any kind."""
        out: dict[str, set[str]] = {}
        for kind in (self.wan, self.tunnels, self.ports):
            for dev, links in kind.items():
                out.setdefault(dev, set()).update(links)
        return out

    def _port_leads_away(self, dev: str, port: str) -> bool:
        """A cabled Port leads away when a device on the other end of it holds a
        WanLink that is recorded to leave that device by another Port or Interface than
        the far end of this cable. A far WanLink or Tunnel that leaves by the cable to
        this device runs through this device. A far WanLink whose underlay is not
        recorded is not shown to lead away. Any other Port can be a LAN port."""
        for far_port, far_dev in self.ports.get(dev, {}).get(port, ()):
            if far_dev is None or far_dev == dev:
                continue
            if any(under and far_port not in under for under in self.wan.get(far_dev, {}).values()):
                return True
        return False

    def _underlay(self, dev: str, link: str) -> set[str] | None:
        """What `link` leaves `dev` by, or None when the run does not record it. The
        underlay of a Tunnel is known only when one of the device's WanLinks, or one
        of its cabled Ports that leads away, leaves by the local endpoint of the
        Tunnel or by the one Interface that holds its local address (`tunnel_local`).
        An endpoint on the tunnel's own interface (wg0 of WireGuard) names no underlay.
        When the endpoint and the local address name different circuits, the underlay
        is not recorded."""
        if link in self.wan.get(dev, {}):
            return set(self.wan[dev][link]) or None
        if link in self.ports.get(dev, {}):
            return {link}
        carriers = [under for under in self.wan.get(dev, {}).values() if under]
        carriers += [{p} for p in self.ports.get(dev, {}) if self._port_leads_away(dev, p)]
        found = [
            set(seen)
            for seen in (self.tunnels.get(dev, {}).get(link), self.tunnel_local.get(dev, {}).get(link))
            if seen and any(seen & under for under in carriers)
        ]
        if len(found) == 2 and not found[0] & found[1]:
            return None
        return found[0] if found else None

    def _leads_away(self, dev: str, link: str) -> bool:
        """True for a WanLink and for a Tunnel. For a cabled Port, the result of `_port_leads_away`."""
        if link in self.wan.get(dev, {}) or link in self.tunnels.get(dev, {}):
            return True
        return self._port_leads_away(dev, link)

    def _not_parallel(self, dev: str, link: str, other: str) -> str | None:
        """The reason that `other` is no established second path for what `link`
        carries, or None when it is one. A circuit is a second path only when it leads
        away from the device, is shown not to run over `link`, and `link` is shown not
        to run over it."""
        if not self._leads_away(dev, other):
            return "not shown to lead away from the device"
        wans = self.wan.get(dev, {})
        if link in wans and other in wans:
            # 2 WanLinks are 2 circuits unless they share a recorded interface.
            if wans[link] & wans[other]:
                return "leaves the device by the same interface as the lost circuit"
            return None
        if link in self.tunnels.get(dev, {}) and other in self.tunnels[dev]:
            return None  # the loss of one overlay does not take down another
        mine, theirs = self._underlay(dev, link), self._underlay(dev, other)
        if mine is not None and theirs is not None:
            if not mine & theirs:
                return None
            if other in self.tunnels.get(dev, {}):
                return "runs over the lost circuit"
            return "carries the lost tunnel" if link in self.tunnels.get(dev, {}) else "shares its underlay"
        return "its underlay is not recorded, so it is not shown to be independent of the lost circuit"

    def judged(self, dev: str, link: str) -> tuple[list[str], dict[str, str]]:
        """The other circuits of `dev` that are a second path for what `link` carries,
        and the reason for every other circuit that is not one. No circuit is a second
        path when `link` does not lead away from the device."""
        others = sorted(self.carried()[dev] - {link})
        if not self._leads_away(dev, link):
            return [], dict.fromkeys(others, "the lost circuit is not shown to lead away from the device")
        reasons = {other: self._not_parallel(dev, link, other) for other in others}
        return [o for o, r in reasons.items() if r is None], {o: r for o, r in reasons.items() if r}

    def parallel(self, dev: str, link: str) -> list[str]:
        """The other circuits of `dev` that are a second path for what `link` carries."""
        return self.judged(dev, link)[0]


def _device_circuits(session: Any) -> _Circuits:
    """Every device's recorded WAN links, cabled ports and tunnel endpoints."""
    circuits = _Circuits({}, {}, {})
    for query, into in ((_LINK_WANLINK_QUERY, circuits.wan), (_LINK_TUNNEL_QUERY, circuits.tunnels)):
        for row in pathmod._read(session, query):
            into.setdefault(row["dev"], {}).setdefault(row["link"], set()).update(
                u for u in row.get("under") or () if u
            )
    for row in pathmod._read(session, _LINK_TUNNEL_LOCAL_QUERY):
        held = [pair for pair in row.get("local_ifs") or () if pair and pair[0]]
        if row.get("source") not in _TUNNEL_LOCAL_SOURCES or len({pair[0] for pair in held}) != 1:
            continue  # an unknown, guessed or ambiguous local address names no underlay
        circuits.tunnel_local.setdefault(row["dev"], {})[row["link"]] = {
            u for pair in held for u in pair if u
        }
    for row in pathmod._read(session, _LINK_PORT_QUERY):
        circuits.ports.setdefault(row["dev"], {}).setdefault(row["link"], set()).update(
            (far[0], far[1] if len(far) > 1 else None) for far in row.get("far") or () if far and far[0]
        )
    return circuits


def assess_link(session: Any, link_uid: str) -> dict[str, Any]:
    """The impact buckets for one link, WAN circuit or tunnel, read from the
    session's pinned run.

    The answer holds graph buckets, as in assess(). It reports the device that
    carries the named circuit. When the device has no established parallel circuit,
    it also reports the prefixes and endpoints single-homed to that device. No flow
    is traced with the circuit removed.

    A `VirtualCircuit` uid resolves to the `CONNECTED_TO` link the reasoner
    derived for it and is assessed as that link, from its A-side port. The
    answer then also names the circuit, its 2 device ports and the bridge
    domains that both ports carry. A circuit with no derived link (one end
    unbound) is not a link in this snapshot and answers 404.
    """
    inventory = _device_circuits(session)
    circuits = inventory.carried()
    circuit: dict[str, Any] | None = None
    if not any(link_uid in links for links in circuits.values()):
        ends = pathmod._read_one(session, _CIRCUIT_LINK_QUERY, link=link_uid)
        if ends and ends.get("a") and ends.get("z"):
            domains = pathmod._read(session, _CIRCUIT_BRIDGE_DOMAINS_QUERY, a=ends["a"], z=ends["z"])
            circuit = {
                "uid": link_uid,
                "ports": [ends["a"], ends["z"]],
                "bridge_domains": [dict(row) for row in domains],
            }
            link_uid = ends["a"]
    dev_uid = next((dev for dev, links in circuits.items() if link_uid in links), None)
    if dev_uid is None:
        raise HTTPException(404, detail=f"no link or tunnel {link_uid} in this snapshot")

    other_circuits = sorted(circuits[dev_uid] - {link_uid})
    parallel, not_parallel = inventory.judged(dev_uid, link_uid)
    parallel_path = "established" if parallel else ("not established" if other_circuits else "none")

    prefixes = pathmod._read(session, _GATEWAY_PREFIX_QUERY, dev=dev_uid)
    endpoints = pathmod._read(session, _ENDPOINT_QUERY, dev=dev_uid)
    # With an established parallel path, the loss of this circuit does not isolate
    # the device. No prefix or endpoint is then reported as single-homed. Another
    # circuit that is not shown to lead away from the device is no parallel path.
    single_homed_prefixes = [] if parallel else _single_homed(prefixes)
    single_homed_endpoints = [] if parallel else _single_homed(endpoints)

    return {
        "device": dev_uid,
        "link": link_uid,
        "circuit": circuit,
        "other_circuits": other_circuits,
        "parallel_circuits": parallel,
        "parallel_path": parallel_path,
        # Every other circuit that is no established parallel path, with the reason.
        "not_parallel": [{"uid": uid, "reason": not_parallel[uid]} for uid in sorted(not_parallel)],
        "run": cyclemod.run_status(session, getattr(session, "snapshot", None)),
        "single_homed_prefixes": _bucket(single_homed_prefixes),
        "single_homed_endpoints": _bucket(single_homed_endpoints),
    }


@router.get("/impact", dependencies=[Depends(require_permission("graph.read"))])
def get_impact(request: Request, device: str, snapshot: str | None = None) -> dict:
    """Impact buckets for excluding one device, computed from the pinned snapshot."""
    settings = request.app.state.settings
    with _session(settings) as s:
        snap = snapshotmod.resolve(s, settings, _requested_run(s, snapshot))
        body = assess(pathmod.pinned(s, snap), device)
        return {"snapshot": snap.snapshot_id, **body}


@router.get("/impact/link", dependencies=[Depends(require_permission("graph.read"))])
def get_link_impact(request: Request, link: str, snapshot: str | None = None) -> dict:
    """Impact buckets for losing one WanLink, cabled Port or Tunnel, computed from
    the pinned snapshot."""
    settings = request.app.state.settings
    with _session(settings) as s:
        snap = snapshotmod.resolve(s, settings, _requested_run(s, snapshot))
        body = assess_link(pathmod.pinned(s, snap), link)
        return {"snapshot": snap.snapshot_id, **body}


@router.post("/impact/evaluate", dependencies=[Depends(require_permission("graph.read"))])
def post_impact_evaluate(request: Request, body: EvaluateBody) -> dict:
    """The three outcomes of a change set against a request set, computed from the
    pinned snapshot."""
    from hst.assessment.direct import evaluate_request

    settings = request.app.state.settings
    with _session(settings) as s:
        snap = snapshotmod.resolve(s, settings, _requested_run(s, body.snapshot))
        answer = evaluate_request(
            settings,
            pathmod.pinned(s, snap),
            snap,
            intents=list(body.intents),
            requirement=body.requirement,
            request=body.request,
            mode=body.mode,
        )
        return {"snapshot": snap.snapshot_id, "run": cyclemod.run_status(s, snap), **answer}
