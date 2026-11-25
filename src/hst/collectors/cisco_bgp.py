"""Dynamic BGP ranges shared by the Cisco collectors."""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import re
from typing import Any

from hst.core import uid
from hst.core.l3domain import DEFAULT_VRF

from .util import GraphBuilder

logger = logging.getLogger(__name__)


def peer_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if "/" not in value:
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def expand_dynamic_neighbors(
    neighbors: list[dict[str, Any]],
    observed: list[dict[str, Any]],
    vrf: str,
    *,
    peer_key: str = "peer_ip",
    as_key: str = "remote_as",
    report_missing: bool = False,
) -> list[dict[str, Any]]:
    """Keep configured entries and append observed, unambiguous dynamic peers.

    Exact configured neighbors take precedence. No range is enumerated. The
    copies retain the range's already resolved policy/template fields.
    """
    ranges = [(n, net) for n in neighbors if (net := peer_network(n.get(peer_key) or "")) is not None]
    if not ranges:
        return neighbors
    result = list(neighbors)
    exact = set()
    for n in neighbors:
        with contextlib.suppress(ValueError):
            exact.add(ipaddress.ip_address(n.get(peer_key) or ""))
    peers: dict[str, list[dict[str, Any]]] = {}
    for row in observed:
        if (row.get("vrf") or DEFAULT_VRF) != (vrf or DEFAULT_VRF):
            continue
        try:
            address = ipaddress.ip_address(row.get("peer_ip") or "")
        except ValueError:
            continue
        if address not in exact:
            peers.setdefault(str(address), []).append(row)
    matched = set()
    for peer, observations in sorted(peers.items()):
        address = ipaddress.ip_address(peer)
        candidates = [(n, net) for n, net in ranges if address in net]
        if not candidates:
            continue
        if len(candidates) != 1:
            logger.warning(
                "bgp dynamic peer %s in VRF %s matches multiple ranges; policies unresolved", peer, vrf
            )
            continue
        n, net = candidates[0]
        if n.get("inheritance_gaps"):
            logger.warning(
                "bgp dynamic peer %s in VRF %s has unresolved template inheritance; skipped", peer, vrf
            )
            continue
        states = {r.get("state") for r in observations}
        asns = {r.get("peer_asn") for r in observations if r.get("peer_asn") is not None}
        if len(states) > 1 or len(asns) > 1:
            logger.warning("bgp dynamic peer %s in VRF %s has conflicting observations; skipped", peer, vrf)
            continue
        remote_as = n.get(as_key)
        observed_as = next(iter(asns), None)
        if remote_as is not None and observed_as is not None and remote_as != observed_as:
            logger.warning(
                "bgp dynamic peer %s in VRF %s disagrees with the range remote-as; skipped", peer, vrf
            )
            continue
        matched.add(str(net))
        result.append(
            {
                **n,
                peer_key: peer,
                as_key: remote_as if remote_as is not None else observed_as,
                "dynamic_range": str(net),
                "observed_state": next(iter(states)),
            }
        )
    for _, net in ranges:
        if report_missing and str(net) not in matched:
            logger.warning("bgp dynamic range %s in VRF %s has no unambiguous observed peers", net, vrf)
    return result


def inherit_peer_templates(neighbor, templates, visited=()):
    """Resolve captured peer/session/policy templates without inventing defaults.

    `peer_templates` holds `(kind, name, sequence)` references and `templates`
    maps `(kind, name)` to a template parsed as a neighbor. A field that the
    neighbor leaves unset takes the value of the template. A reference to a
    template that the capture does not hold, or a loop, adds an
    `inheritance_gaps` entry. NX-OS and IOS-XE use this function."""
    result = dict(neighbor)
    # Lower sequence peer-policy templates fill unset fields first, regardless
    # of the order their lines appeared in the capture.
    for reference in sorted(neighbor.get("peer_templates") or [], key=lambda ref: ref[2]):
        key = reference[:2]
        if key in visited or key not in templates:
            result.setdefault("inheritance_gaps", []).append(f"unresolved template {key[0]} {key[1]}")
            continue
        parent = inherit_peer_templates(templates[key], templates, (*visited, key))
        for field, value in parent.items():
            if field in {"peer_ip", "peer_templates"}:
                continue
            if (field == "remote_as" and result.get("remote_as_route_map")) or (
                field == "remote_as_route_map" and result.get("remote_as") is not None
            ):
                continue
            if field == "inheritance_gaps":
                result.setdefault(field, []).extend(value)
            elif field == "address_families":
                result[field] = list(dict.fromkeys([*(result.get(field) or []), *value]))
            elif result.get(field) in (None, False, []):
                result[field] = value
    return result


def session_gap(neighbor: dict[str, Any]) -> str:
    reason = f"neighbor {neighbor.get('peer_ip')} has no resolvable remote-as"
    gaps = neighbor.get("inheritance_gaps")
    return f"{reason} ({'; '.join(gaps)})" if gaps else reason


def reflector_client(neighbor: dict[str, Any]) -> bool | None:
    """The `route_reflector_client` value of a session.

    It is True when the neighbor, or a group or template that it inherits from, states
    `route-reflector-client`. It is False when none states it. It is None when an
    inheritance source of the neighbor is undefined."""
    if neighbor.get("route_reflector_client"):
        return True
    return None if neighbor.get("inheritance_gaps") else False


_NEIGHBOR_HEADER_RE = re.compile(r"^\s*BGP neighbor is (?P<peer>[^\s,]+)(?P<rest>.*)$", re.IGNORECASE)
_NEIGHBOR_VRF_RE = re.compile(r"\bvrf (?P<vrf>[^\s,]+)", re.IGNORECASE)
_REMOTE_ROUTER_ID_RE = re.compile(r"\bremote router id[:\s]+(?P<rid>[0-9.]+)", re.IGNORECASE)

PEER_ROUTER_IDS_MARKER = "_strata_peer_router_ids"


def router_id_or_none(value: Any) -> str | None:
    """A BGP router identifier as a dotted quad, or None when the value is absent, is
    not an IPv4 address or is 0.0.0.0. A session that never opened reports 0.0.0.0."""
    try:
        address = ipaddress.IPv4Address(str(value).strip())
    except ValueError:
        return None
    return None if int(address) == 0 else str(address)


def neighbor_key(vrf: str | None, peer_ip: str) -> tuple[str, str]:
    """The `(vrf, peer address)` key of `peer_router_ids`. The VRF is the name of the
    default VRF when none is stated. An IP address is in its canonical form."""
    try:
        peer_ip = str(ipaddress.ip_address(str(peer_ip).strip()))
    except ValueError:
        peer_ip = str(peer_ip).strip()
    name = vrf or DEFAULT_VRF
    return (DEFAULT_VRF if name.lower() == DEFAULT_VRF else name), peer_ip


def parse_neighbor_router_ids(*texts: str | None) -> dict[tuple[str, str], str]:
    """Parse `show bgp [vrf all|all] neighbors` text of IOS-XE and IOS-XR into
    {(vrf, peer ip): remote router id}.

    A neighbor block opens with `BGP neighbor is <ip>[, vrf <name>]`. The
    identifier of the peer is on its own line, `BGP version 4, remote router ID
    A.B.C.D` (IOS-XE) or `Remote router ID A.B.C.D` (IOS-XR). A block with no
    such line, or one stating 0.0.0.0, adds no entry. A neighbor listed more
    than once (one block per address family) keeps its first stated
    identifier. Text of several commands (the default VRF's and the VRFs')
    merges into one map."""
    out: dict[tuple[str, str], str] = {}
    for text in texts:
        key: tuple[str, str] | None = None
        for line in str(text or "").splitlines():
            header = _NEIGHBOR_HEADER_RE.match(line)
            if header:
                vrf = _NEIGHBOR_VRF_RE.search(header["rest"])
                key = neighbor_key(vrf["vrf"] if vrf else None, header["peer"])
                continue
            m = _REMOTE_ROUTER_ID_RE.search(line)
            if m and key is not None:
                rid = router_id_or_none(m["rid"])
                if rid:
                    out.setdefault(key, rid)
    return out


def observed_peer_router_id(observed: dict[str, Any] | None, vrf: str | None, peer_ip: str) -> str | None:
    """The remote router id of one session from the `peer_router_ids` of
    `parse_bgp_observations` (`nest_router_ids`), or None when the neighbor output
    states none."""
    vrf_name, peer = neighbor_key(vrf, peer_ip)
    return ((observed or {}).get("peer_router_ids") or {}).get(vrf_name, {}).get(peer)


def nest_router_ids(ids: dict[tuple[str, str], str]) -> dict[str, dict[str, str]]:
    """Return `{(vrf, peer): id}` as `{vrf: {peer: id}}`. The result of
    `parse_bgp_observations` holds this form as `peer_router_ids`."""
    nested: dict[str, dict[str, str]] = {}
    for (vrf, peer), rid in sorted(ids.items()):
        nested.setdefault(vrf, {})[peer] = rid
    return nested


def stamp_peer_router_ids(raw: dict[str, Any], ids: dict[tuple[str, str], str]) -> None:
    """Add the stated router ids to `raw` under `PEER_ROUTER_IDS_MARKER`.

    The change hash includes the marker. The neighbor output is volatile, and its
    counters change on every fetch."""
    if ids:
        raw[PEER_ROUTER_IDS_MARKER] = sorted([vrf, peer, rid] for (vrf, peer), rid in ids.items())


def emit_bgp_peer(b: GraphBuilder, process: str, vrf: str, *, peer_ip: str, **props: Any) -> tuple[str, str]:
    """Emit either a range definition or a concrete session, with its owner."""
    net = peer_network(peer_ip)
    if net is not None:
        props.pop("peer_router_id", None)
        label, peer_uid = "BgpPeerRange", uid.bgp_peer_range(process, str(net), vrf)
        b.node(label, peer_uid, prefix=str(net), **props)
    else:
        label, peer_uid = "BgpSession", uid.bgp_session(process, peer_ip, vrf)
        b.node(label, peer_uid, peer_ip=peer_ip, **props)
        if prefix := props.get("dynamic_range"):
            b.rel("MEMBER_OF", label, peer_uid, "BgpPeerRange", uid.bgp_peer_range(process, prefix, vrf))
    b.rel("HAS", "RoutingProcess", process, label, peer_uid)
    return label, peer_uid


def stamp_dynamic_observations(
    raw: dict[str, Any],
    processes: list[dict[str, Any]],
    observed: list[dict[str, Any]],
    *,
    peer_key: str = "peer_ip",
) -> None:
    """Make peer appearance/disappearance defeat the config-only skip.

    The marker is stored with the raw snapshot and ignored by parsers.
    """
    if any(peer_network(n.get(peer_key) or "") for p in processes for n in p.get("neighbors") or []):
        raw["_strata_dynamic_bgp"] = sorted(
            {
                (
                    r.get("vrf") or DEFAULT_VRF,
                    r["peer_ip"],
                    str(r.get("peer_asn") or ""),
                    r.get("state") or "",
                )
                for r in observed
            }
        )
