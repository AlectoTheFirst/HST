"""Symbolic tunnel encapsulation and decapsulation over collected graph facts."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Literal

import hst.path as _path

from ..addrsets import _intersect, _intervals, _ports, _protoset, _subtract
from ..state import FlowRegion, Rect

TunnelStatus = Literal["complete", "down", "denied", "unknown", "ambiguous", "indeterminate"]

_CANDIDATES = """
CALL {
  MATCH (t:Tunnel:Obj)-[ep:ENDPOINT]->(overlay:Interface {uid: $if_uid})
  WHERE ep._retired_at IS NULL AND NOT t:Retired AND NOT overlay:Retired
    AND overlay:Obj AND overlay.collection_ts = $snap
    AND t.collection_ts = $snap
  RETURN t, overlay, 'endpoint' AS binding_kind
  UNION
  MATCH (t:Tunnel:Obj)-[ep:ENDPOINT]->(lip:IpAddress)<-[has:HAS_IP]-(overlay:Interface {uid: $if_uid})
  WHERE ep._retired_at IS NULL AND has._retired_at IS NULL
    AND NOT t:Retired AND NOT lip:Retired AND NOT overlay:Retired
    AND overlay:Obj AND overlay.collection_ts = $snap
    AND t.collection_ts = $snap
  RETURN t, overlay, 'endpoint' AS binding_kind
  UNION
  MATCH (overlay:Interface {uid: $if_uid})-[has:HAS_IP]->(lip:IpAddress)
  WHERE overlay:Obj AND overlay.collection_ts = $snap
  MATCH (t:Tunnel:Obj {source_ip: lip.ip, collection_ts: $snap})
  WHERE has._retired_at IS NULL AND NOT lip:Retired AND NOT t:Retired
    AND t.collection_ts = $snap
  RETURN t, overlay, 'source-selector' AS binding_kind
}
OPTIONAL MATCH (overlay)-[on:ON]->(ld:Device)
WHERE on._retired_at IS NULL AND NOT ld:Retired
OPTIONAL MATCH (overlay)-[iv:IN_VRF]->(lc:VrfInstance)
WHERE iv._retired_at IS NULL AND NOT lc:Retired
OPTIONAL MATCH (local_underlay:Interface:Obj {collection_ts: $snap})-[lha:HAS_IP]->(local_ip:IpAddress)
WHERE lha._retired_at IS NULL AND NOT local_underlay:Retired AND NOT local_ip:Retired
  AND local_ip.ip = coalesce(t.local_address, t.source_ip)
  AND EXISTS {
    MATCH (local_underlay)-[luon:ON]->(ld)
    WHERE luon._retired_at IS NULL
  }
OPTIONAL MATCH (local_underlay)-[luiv:IN_VRF]->(luc:VrfInstance)
WHERE luiv._retired_at IS NULL AND NOT luc:Retired
OPTIONAL MATCH (t)-[term:TERMINATES_ON]->(term_ip:IpAddress)
WHERE term._retired_at IS NULL AND NOT term_ip:Retired
WITH t, overlay, binding_kind, ld, lc, local_underlay, luc, term_ip,
     coalesce(term_ip.ip, t.endpoint) AS remote_address
OPTIONAL MATCH (direct_underlay:Interface:Obj)-[rha:HAS_IP]->(remote_ip:IpAddress)
WHERE rha._retired_at IS NULL AND NOT direct_underlay:Retired AND NOT remote_ip:Retired
  AND remote_ip.ip = remote_address AND direct_underlay.collection_ts = $snap
// an address after NAT is held by the far WanLink, not by its interface: from
// the tunnel's own far node, and by the address only for a tunnel without one
OPTIONAL MATCH (nat_link:WanLink:Obj)-[nlh:HAS_IP]->(nat_ip:IpAddress)
WHERE direct_underlay IS NULL
  AND CASE WHEN term_ip IS NOT NULL THEN nat_ip = term_ip ELSE nat_ip.ip = remote_address END
  AND nat_link.collection_ts = $snap
  AND nlh._retired_at IS NULL AND NOT nat_link:Retired AND NOT nat_ip:Retired
OPTIONAL MATCH (nat_link)-[nlon:ON]->(nat_underlay:Interface)
WHERE nlon._retired_at IS NULL AND NOT nat_underlay:Retired
WITH t, overlay, binding_kind, ld, lc, local_underlay, luc, remote_address,
     coalesce(direct_underlay, nat_underlay) AS remote_underlay
OPTIONAL MATCH (remote_underlay)-[ron:ON]->(rd:Device)
WHERE ron._retired_at IS NULL AND NOT rd:Retired
OPTIONAL MATCH (remote_underlay)-[ruiv:IN_VRF]->(ruc:VrfInstance)
WHERE ruiv._retired_at IS NULL AND NOT ruc:Retired
OPTIONAL MATCH (peer:Tunnel)-[pep:ENDPOINT]->(remote_overlay:Interface)-[pon:ON]->(rd)
WHERE peer.uid <> t.uid AND pep._retired_at IS NULL AND pon._retired_at IS NULL
  AND NOT peer:Retired AND NOT remote_overlay:Retired
  AND ((peer.local_address = remote_address
        AND peer.endpoint = coalesce(t.local_address, t.source_ip))
       // behind NAT the two ends name different addresses; both halves of one
       // configured tunnel carry the same pair
       OR (t.pair IS NOT NULL AND peer.pair = t.pair))
  AND peer.encap = t.encap AND peer.carrier_proto = t.carrier_proto
OPTIONAL MATCH (remote_overlay)-[roiv:IN_VRF]->(roc:VrfInstance)
WHERE roiv._retired_at IS NULL AND NOT roc:Retired
RETURN t.uid AS tunnel_uid, t.name AS tunnel_name, t.encap AS encap,
       t.state AS state, coalesce(t.local_address, t.source_ip) AS local_address,
       remote_address, t.carrier_proto AS carrier_proto,
       t.endpoint_port AS carrier_port, t.local_port AS local_port,
       t.allowed_ips AS allowed_ips, binding_kind,
       overlay.uid AS local_interface_uid, ld.uid AS local_device_uid,
       lc.uid AS local_context_uid, local_underlay.uid AS local_underlay_interface_uid,
       luc.uid AS local_underlay_context_uid,
       remote_overlay.uid AS remote_interface_uid, rd.uid AS remote_device_uid,
       roc.uid AS remote_context_uid, remote_underlay.uid AS remote_underlay_interface_uid,
       ruc.uid AS remote_underlay_context_uid, peer.uid AS peer_tunnel_uid
ORDER BY tunnel_uid, remote_underlay_interface_uid, remote_interface_uid, peer_tunnel_uid"""


@dataclass(frozen=True, slots=True)
class TunnelLeg:
    tunnel_uid: str
    encap: str | None
    inner: FlowRegion
    outer: FlowRegion | None
    local_interface_uid: str | None
    local_device_uid: str | None
    local_context_uid: str | None
    local_underlay_interface_uid: str | None
    local_underlay_context_uid: str | None
    remote_interface_uid: str | None
    remote_device_uid: str | None
    remote_context_uid: str | None
    remote_underlay_interface_uid: str | None
    remote_underlay_context_uid: str | None
    peer_tunnel_uid: str | None
    status: TunnelStatus
    evidence: tuple[str, ...]

    @property
    def can_decapsulate(self) -> bool:
        return self.status == "complete" and self.peer_tunnel_uid is not None


def _outer(row: Mapping[str, Any]) -> FlowRegion | None:
    local, remote = row.get("local_address"), row.get("remote_address")
    proto = row.get("carrier_proto")
    if not local or not remote or not proto:
        return None
    if str(proto).lower() == "udp" and row.get("carrier_port") is None:
        return None
    try:
        src, dst = _intervals([str(local)]), _intervals([str(remote)])
        if not src or not dst or src[0][0] != dst[0][0]:
            return None
        protocols = _protoset([str(proto)])
        ports = _ports(row.get("carrier_port")) if row.get("carrier_port") is not None else None
        sports = _ports(row.get("local_port")) if row.get("local_port") is not None else None
    except ValueError:
        return None
    return FlowRegion.from_query(src, dst, protocols, ports, sports)


def _wireguard_regions(
    rows: Sequence[Mapping[str, Any]], inner: FlowRegion
) -> tuple[dict[int, FlowRegion], set[int], set[int], bool]:
    """Longest-prefix WireGuard peer selection for each inner rectangle."""
    parsed: dict[int, list[tuple[int, tuple[int, int, int]]]] = {}
    unknown: set[int] = set()
    all_known = True
    for index, row in enumerate(rows):
        if str(row.get("encap") or "").lower() != "wireguard":
            continue
        specs = row.get("allowed_ips")
        if specs is None:
            all_known = False
            unknown.add(index)
            continue
        entries = []
        try:
            for spec in specs:
                net = ipaddress.ip_network(str(spec), strict=False)
                entries.append((net.prefixlen, _intervals([str(net)])[0]))
        except (TypeError, ValueError, IndexError):
            all_known = False
            unknown.add(index)
            continue
        parsed[index] = entries

    selected: dict[int, list[Rect]] = {}
    ambiguous: set[int] = set()
    for index, entries in parsed.items():
        for prefixlen, allowed in entries:
            longer = [ival for other in parsed.values() for plen, ival in other if plen > prefixlen]
            equal_other = [
                ival
                for other_index, other in parsed.items()
                if other_index != index
                for plen, ival in other
                if plen == prefixlen
            ]
            for rect in inner.rects:
                dst = _intersect(list(rect.dst), [allowed])
                for claimed in longer:
                    dst = _subtract(dst, [claimed])
                if not dst:
                    continue
                if any(_intersect(dst, [other]) for other in equal_other):
                    ambiguous.add(index)
                selected.setdefault(index, []).append(replace(rect, dst=tuple(dst)))
    return (
        {index: FlowRegion(tuple(rects)) for index, rects in selected.items()},
        ambiguous,
        unknown,
        all_known,
    )


def build_carrier_legs(rows: Sequence[Mapping[str, Any]], inner: FlowRegion) -> tuple[TunnelLeg, ...]:
    """Build every candidate without choosing among competing graph facts."""
    wg_regions, wg_ambiguous, wg_unknown, wg_known = _wireguard_regions(rows, inner)
    active: dict[int, FlowRegion] = {}
    counts: dict[str, int] = {}
    for index, row in enumerate(rows):
        uid = str(row.get("tunnel_uid") or "")
        wireguard = str(row.get("encap") or "").lower() == "wireguard"
        selected_inner = wg_regions.get(index) if wireguard else inner
        if wireguard and selected_inner is None and index not in wg_unknown:
            continue
        if selected_inner is None:
            selected_inner = inner
        active[index] = selected_inner
        counts[uid] = counts.get(uid, 0) + 1
    candidates = len({str(rows[index].get("tunnel_uid") or "") for index in active})
    legs: list[TunnelLeg] = []
    for index, row in enumerate(rows):
        if index not in active:
            continue
        uid = str(row.get("tunnel_uid") or "")
        wireguard = str(row.get("encap") or "").lower() == "wireguard"
        selected_inner = active[index]
        evidence: list[str] = []
        outer = _outer(row)
        state = str(row.get("state") or "").strip().lower()
        reciprocal = bool(row.get("peer_tunnel_uid"))
        required = (
            "local_interface_uid",
            "local_device_uid",
            "local_context_uid",
            "local_underlay_interface_uid",
            "local_underlay_context_uid",
            "remote_underlay_interface_uid",
            "remote_underlay_context_uid",
            "remote_interface_uid",
            "remote_device_uid",
            "remote_context_uid",
        )
        missing = [name for name in required if not row.get(name)]
        if state in {"down", "disabled", "inactive"}:
            status: TunnelStatus = "down"
            evidence.append(f"tunnel {uid} is {state}")
        elif row.get("binding_kind") == "source-selector":
            status = "indeterminate"
            evidence.append("a source-address match does not prove which inner traffic selects this tunnel")
        elif wireguard and index in wg_unknown:
            status = "unknown"
            evidence.append("WireGuard allowed IPs were not collected, so peer selection is unknown")
        elif index in wg_ambiguous:
            status = "ambiguous"
            evidence.append("more than one WireGuard peer has the same longest allowed-IP match")
        elif (not wireguard and candidates > 1) or counts[uid] > 1:
            status = "ambiguous"
            evidence.append("more than one tunnel carrier or endpoint matches the egress interface")
        elif outer is None:
            status = "indeterminate"
            evidence.append("carrier local address, remote address, protocol or port is missing or invalid")
        elif missing:
            status = "indeterminate"
            evidence.append("the remote side of the tunnel is not modeled; missing " + ", ".join(missing))
        elif not reciprocal:
            status = "indeterminate"
            evidence.append("no reciprocal tunnel proves where the carrier decapsulates")
        elif state not in {"up", "established", "active"}:
            status = "unknown"
            evidence.append("tunnel operational state was not observed")
        else:
            status = "complete"
            evidence.append(f"{uid} encapsulates at {row['local_interface_uid']}")
            evidence.append(f"{row['peer_tunnel_uid']} decapsulates at {row['remote_interface_uid']}")
        legs.append(
            TunnelLeg(
                tunnel_uid=uid,
                encap=str(row["encap"]) if row.get("encap") else None,
                inner=selected_inner,
                outer=outer,
                local_interface_uid=row.get("local_interface_uid"),
                local_device_uid=row.get("local_device_uid"),
                local_context_uid=row.get("local_context_uid"),
                local_underlay_interface_uid=row.get("local_underlay_interface_uid"),
                local_underlay_context_uid=row.get("local_underlay_context_uid"),
                remote_interface_uid=row.get("remote_interface_uid"),
                remote_device_uid=row.get("remote_device_uid"),
                remote_context_uid=row.get("remote_context_uid"),
                remote_underlay_interface_uid=row.get("remote_underlay_interface_uid"),
                remote_underlay_context_uid=row.get("remote_underlay_context_uid"),
                peer_tunnel_uid=row.get("peer_tunnel_uid"),
                status=status,
                evidence=tuple(evidence),
            )
        )
    if not legs and rows and all(str(r.get("encap") or "").lower() == "wireguard" for r in rows) and wg_known:

        def common(name: str) -> Any:
            values = {row.get(name) for row in rows}
            return values.pop() if len(values) == 1 else None

        legs.append(
            TunnelLeg(
                tunnel_uid="",
                encap="wireguard",
                inner=inner,
                outer=None,
                local_interface_uid=common("local_interface_uid"),
                local_device_uid=common("local_device_uid"),
                local_context_uid=common("local_context_uid"),
                local_underlay_interface_uid=common("local_underlay_interface_uid"),
                local_underlay_context_uid=common("local_underlay_context_uid"),
                remote_interface_uid=None,
                remote_device_uid=None,
                remote_context_uid=None,
                remote_underlay_interface_uid=None,
                remote_underlay_context_uid=None,
                peer_tunnel_uid=None,
                status="denied",
                evidence=("no configured WireGuard peer allows the inner destination",),
            )
        )
    return tuple(legs)


def carrier_legs(session: Any, egress_if_uid: str, inner: FlowRegion) -> tuple[TunnelLeg, ...]:
    """Read all snapshot/overlay-aware candidates at an egress interface."""
    return build_carrier_legs(_path._read(session, _CANDIDATES, if_uid=egress_if_uid), inner)
