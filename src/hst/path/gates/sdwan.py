"""The SD-WAN forwarding boundary as a routing stage over collected facts.

A VeloCloud edge publishes no route table (the VCO APIv2 has none). The
stage derives the exits of a flow from these collected facts.

- The tunnels that `CARRIES` the segment the flow is routed in. Each tunnel
  has a far end (another edge's WAN address, or a gateway) and the kind of
  its WAN link.
- The BGP neighbors configured in that segment. Each neighbor is on a
  connected prefix.
- The connected prefixes of every other edge in the enterprise, per segment.
  A destination inside the LAN of a branch or of the hub selects the tunnel
  to that edge.

`candidate_routes` turns these facts into rows of the `_ROUTES_QUERY` shape,
one row per candidate. The egress of a row is the tunnel's own WAN interface
or the neighbor's connected interface. The trace walks every candidate. The
effective business policy marks the candidate it prefers (`preferred_for`).
The leg is marked as a candidate set.

The rules apply in this order.

1. A destination inside a connected prefix of exactly one other edge, in the
   same segment, takes the tunnels to that edge. When more than one edge
   holds a covering prefix (duplicate LAN space), the boundary selects no
   candidate.
2. On a branch, and on a hub with no route, the exits are the far edges whose
   Overlay Flow Control rows (the `rib` side table, `collectors/velocloud.py`
   `rib_rows`) cover the destination in the segment. The longest prefix wins,
   then the lowest cost. A tie keeps every edge in it. The orchestrator
   orders the preferred exits of a prefix by preference, and the row keeps
   the cost. The rank reads the cost as the preference. Only the tunnels to
   the chosen edges are candidates. When the exit comes only from a default
   route (prefix length 0), the candidates of the business policy are added.
   The edge prefers that secure route unless Secure Default Route Override is
   on, and the snapshot does not hold that setting.
3. On a hub (`Device.sdwan_role = "hub"`) the order is the longest static
   route of the segment (`SdwanStaticRoute`) that covers the destination,
   then the Overlay Flow Control exit of another edge (rule 2) for a prefix
   longer than the default, then the segment's BGP neighbors. The hub's LAN
   side is a router in the collected estate. The trace continues there with
   the routing gate.
4. On a branch, and on a hub with no route, the business policy decides for a
   destination that is not in any edge's LAN (the `edge2cloud` route action).
   The first rule by position that matches the flow wins. A rule before it
   that the trace cannot decide (an application, a host name, an interface,
   or an unstated port or protocol) keeps its own outcome beside the outcome
   of the winner. `backhaul` takes the tunnels to the first hub or hub
   cluster of the rule that a tunnel ends on. `gateway` takes the tunnels to
   the cloud gateways. `direct` takes the public WAN links. With no policy
   outcome (no rule matches, or the rule leaves the choice to the
   orchestrator) the candidates are the tunnels whose far end is a hub, else
   every tunnel in the segment, and the `direct` links of any rule. A gateway
   far end is a boundary of the carrier trace.

A static route wins against a LAN prefix (rule 1) or an Overlay Flow Control
exit (rule 2) with a longer prefix, or with an equal prefix when the static
route has `preferred` true (`_static_wins`).

On every boundary a candidate whose near or far end is on a hot standby or
backup-only WAN link is dropped when a candidate on an active link remains.
The orchestrator moves traffic to a standby link only when the active links
fail.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

import hst.path as _path
from hst.core import uid as uidmod
from hst.path.addrsets import _set_bounds

# The DSCP the trace states for the flow (`trace(dscp=...)`). None leaves a rule
# that matches on DSCP undecided, as an unstated port does.
_DSCP: ContextVar[int | None] = ContextVar("sdwan_flow_dscp", default=None)


@contextmanager
def flow_dscp(dscp: int | None) -> Iterator[None]:
    token = _DSCP.set(dscp)
    try:
        yield
    finally:
        _DSCP.reset(token)


_BOUNDARY_QUERY = """
MATCH (d:Device {uid: $dev})-[hb:HAS_BOUNDARY]->(fb:ForwardingBoundary)-[i:IN]->(seg:SdwanSegment)
WHERE d:Obj AND d.collection_ts = $snap
  AND hb._retired_at IS NULL AND i._retired_at IS NULL AND NOT fb:Retired AND NOT seg:Retired
  AND fb.collection_ts = $snap
MATCH (v:VrfInstance {uid: $vrf})
WHERE v:Obj AND v.collection_ts = $snap AND (v.table_id = seg.segment_id OR v.name = seg.name)
OPTIONAL MATCH (pol:SdwanBusinessPolicy)-[sv:STEERS_VIA]->(fb)
WHERE sv._retired_at IS NULL AND NOT pol:Retired
RETURN fb.uid AS boundary_uid, seg.uid AS segment_uid, seg.name AS segment_name, seg.segment_id AS segment_id,
       fb.candidate_set_complete AS complete, fb.unsupported_reason AS reason,
       collect(DISTINCT pol.uid) AS policy_uids, d.sdwan_role AS role
ORDER BY fb.uid LIMIT 1"""

_CANDIDATE_TUNNELS_QUERY = """
MATCH (t:Tunnel)-[c:CARRIES]->(seg:SdwanSegment {uid: $seg})
WHERE seg:Obj AND seg.collection_ts = $snap
  AND c._retired_at IS NULL AND NOT t:Retired AND t.collection_ts = $snap
MATCH (t)-[e:ENDPOINT]->(wif:Interface)-[on:ON]->(d:Device {uid: $dev})
WHERE d:Obj AND d.collection_ts = $snap
  AND e._retired_at IS NULL AND on._retired_at IS NULL AND NOT wif:Retired
OPTIONAL MATCH (t)-[tr:TERMINATES_ON]->(far)
WHERE tr._retired_at IS NULL AND NOT far:Retired
OPTIONAL MATCH (far)<-[fh:HAS_IP]-(:Interface)-[fon:ON]->(if_dev:Device)
WHERE far:IpAddress AND fh._retired_at IS NULL AND fon._retired_at IS NULL AND NOT if_dev:Retired
// an address after NAT is held by the far edge's WanLink, not by an interface
OPTIONAL MATCH (far)<-[flh:HAS_IP]-(:WanLink)<-[fhl:HAS_LINK]-(link_dev:Device)
WHERE far:IpAddress AND if_dev IS NULL AND flh._retired_at IS NULL AND fhl._retired_at IS NULL
  AND NOT link_dev:Retired
WITH t, wif, far, coalesce(if_dev, link_dev) AS fdev
// the far end's own WanLink, for its standby state
OPTIONAL MATCH (far)<-[fwh:HAS_IP]-(fw:WanLink)
WHERE far:IpAddress AND fwh._retired_at IS NULL AND NOT fw:Retired
OPTIONAL MATCH (wif)-[wh:HAS_IP]->(wip:IpAddress)<-[lh:HAS_IP]-(w:WanLink)
WHERE wh._retired_at IS NULL AND lh._retired_at IS NULL AND NOT w:Retired
OPTIONAL MATCH (pol:SdwanBusinessPolicy)-[sv:STEERS_VIA]->(w)
WHERE sv._retired_at IS NULL AND NOT pol:Retired
// a rule that backhauls to a hub steers onto the tunnels to it
OPTIONAL MATCH (tpol:SdwanBusinessPolicy)-[tsv:STEERS_VIA]->(t)
WHERE tsv._retired_at IS NULL AND NOT tpol:Retired
RETURN t.uid AS uid, t.name AS name, t.encap AS encap, t.state AS state, t.peer_type AS peer_type,
       wif.uid AS egress_uid, wif.name AS egress_name,
       far.uid AS far_uid, far.ip AS far_ip, far.name AS far_name,
       CASE WHEN far:SdwanGateway THEN 'SdwanGateway'
            WHEN far:IpAddress THEN 'IpAddress' ELSE NULL END AS far_kind,
       fdev.uid AS far_dev, fdev.hostname AS far_dev_name, fdev.sdwan_role AS far_role,
       fdev.hub_cluster_name AS far_cluster,
       w.uid AS link_uid, w.kind AS link_kind, w.name AS link_name,
       w.link_mode AS link_mode, w.backup_only AS backup_only, w.hot_standby AS hot_standby,
       fw.link_mode AS far_link_mode, fw.backup_only AS far_backup_only, fw.hot_standby AS far_hot_standby,
       collect(DISTINCT sv.application_class) + collect(DISTINCT tsv.application_class) AS preferred_for
ORDER BY t.uid"""

_BGP_NEIGHBORS_QUERY = """
MATCH (vrf:VrfInstance:Obj {uid: $vrf, collection_ts: $snap})<-[iv:IN_VRF]-(rp:RoutingProcess)
      -[h:HAS]->(s:BgpSession)
MATCH (s)-[e:ENDPOINT]->(peer:IpAddress)
WHERE vrf:Obj AND vrf.collection_ts = $snap
  AND iv._retired_at IS NULL AND h._retired_at IS NULL AND e._retired_at IS NULL
  AND NOT s:Retired AND NOT peer:Retired AND s.collection_ts = $snap
OPTIONAL MATCH (dev:Device {uid: $dev})<-[on:ON]-(i:Interface)-[hi:HAS_IP]->(:IpAddress)-[inp:IN]->(p:Prefix)
WHERE dev:Obj AND dev.collection_ts = $snap
  AND on._retired_at IS NULL AND hi._retired_at IS NULL AND inp._retired_at IS NULL
  AND NOT i:Retired AND NOT p:Retired
  AND EXISTS { MATCH (i)-[iv2:IN_VRF]->(:VrfInstance {uid: $vrf}) WHERE iv2._retired_at IS NULL }
RETURN s.uid AS uid, peer.ip AS peer_ip, s.peer_asn AS peer_asn,
       collect(DISTINCT {if_uid: i.uid, if_name: i.name, cidr: p.cidr, prefix_uid: p.uid}) AS connected
ORDER BY s.uid"""

_DIRECT_EXITS_QUERY = """
MATCH (dev:Device {uid: $dev})-[en:ENFORCES]->(pol:SdwanBusinessPolicy)-[sv:STEERS_VIA]->(w:WanLink)
WHERE dev:Obj AND dev.collection_ts = $snap
  AND sv.route_policy = 'direct' AND en._retired_at IS NULL AND sv._retired_at IS NULL
  AND NOT pol:Retired AND NOT w:Retired AND w.collection_ts = $snap
  // the exits of the boundary's own segment; an edge from before the segment
  // was recorded on it counts for every segment
  AND (sv.segment_id IS NULL OR sv.segment_id = $segment_id)
MATCH (w)-[won:ON]->(wif:Interface)
WHERE won._retired_at IS NULL AND NOT wif:Retired
OPTIONAL MATCH (wif)-[iv:IN_VRF]->(wv:VrfInstance)
WHERE iv._retired_at IS NULL AND NOT wv:Retired
RETURN wif.uid AS egress_uid, wif.name AS egress_name, wif.next_hop AS next_hop, wv.uid AS egress_vrf,
       w.uid AS link_uid, w.kind AS link_kind, w.name AS link_name,
       w.link_mode AS link_mode, w.backup_only AS backup_only, w.hot_standby AS hot_standby,
       collect(DISTINCT sv.application_class) AS direct_for
ORDER BY wif.uid"""

# The edge's business policy rules in the segment, in the order the edge reads
# them (`collectors/velocloud.py` `_policy_rules`).
_POLICY_RULES_QUERY = """
MATCH (dev:Device {uid: $dev})-[en:ENFORCES]->(pol:SdwanBusinessPolicy)-[hr:HAS_RULE]->(r:SdwanPolicyRule)
WHERE dev:Obj AND dev.collection_ts = $snap
  AND en._retired_at IS NULL AND hr._retired_at IS NULL AND NOT pol:Retired AND NOT r:Retired
  AND pol.collection_ts = $snap AND r.collection_ts = $snap
  AND (r.segment_id = $segment_id OR r.segment_name = $segment_name)
RETURN properties(r) AS rule
ORDER BY r.position"""

# The boundary's static routes (`collectors/velocloud.py` `_static_routes`),
# each with the interface of the edge whose name is the route's `interface`.
_STATIC_ROUTES_QUERY = """
MATCH (fb:ForwardingBoundary {uid: $boundary})-[hr:HAS_ROUTE]->(r:SdwanStaticRoute)
WHERE fb:Obj AND fb.collection_ts = $snap
  AND hr._retired_at IS NULL AND NOT r:Retired AND r.collection_ts = $snap
OPTIONAL MATCH (dev:Device {uid: $dev})<-[on:ON]-(i:Interface)
WHERE dev:Obj AND dev.collection_ts = $snap
  AND on._retired_at IS NULL AND NOT i:Retired AND i.name = r.interface
  AND i.collection_ts = $snap
RETURN r.uid AS uid, r.cidr AS cidr, r.next_hop AS next_hop, r.interface AS interface,
       r.cost AS cost, r.preferred AS preferred, r.advertise AS advertise,
       r.description AS description, i.uid AS egress_uid
ORDER BY r.uid"""

_FAR_PREFIXES_QUERY = """
MATCH (fdev:Device)<-[ob:OWNED_BY]-(v:VrfInstance)-[o:ORIGINATES]->(p:Prefix)
WHERE fdev.uid IN $devs AND fdev:Obj AND fdev.collection_ts = $snap AND fdev.platform = 'velocloud-edge'
  AND ob._retired_at IS NULL AND o._retired_at IS NULL AND NOT v:Retired AND NOT p:Retired
  AND p.collection_ts = $snap
  AND (v.table_id = $segment_id OR v.name = $segment_name)
RETURN fdev.uid AS far_dev, p.cidr AS cidr, p.uid AS prefix_uid"""

# The table each far edge holds for the segment. The Overlay Flow Control
# rows of the edge are keyed by that table (`rib_rows` writes
# `uid.vrf(edge, segment name)`).
_FAR_TABLES_QUERY = """
MATCH (far:Device)<-[ob:OWNED_BY]-(v:VrfInstance)
WHERE far.uid IN $devs AND far:Obj AND far.collection_ts = $snap AND far.platform = 'velocloud-edge'
  AND ob._retired_at IS NULL AND NOT v:Retired
  AND v.collection_ts = $snap
  AND (v.table_id = $segment_id OR v.name = $segment_name)
RETURN far.uid AS far_dev, v.uid AS vrf_uid, v.name AS vrf_name
ORDER BY far.uid, v.uid"""


def _covers(cidrs: list[str], dst_part: list[tuple[int, int, int]]) -> bool:
    """Whether every address of `dst_part` sits inside one of `cidrs`."""
    nets = []
    for cidr in cidrs:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    if not nets:
        return False
    for af, lo, hi in dst_part:
        first = ipaddress.ip_address(lo)
        last = ipaddress.ip_address(hi)
        if first.version != af:
            return False
        if not any(first in n and last in n for n in nets if n.version == af):
            return False
    return True


def route_exits(
    rib: Any | None, far_tables: list[dict[str, Any]], dst_part: list[tuple[int, int, int]]
) -> list[dict[str, Any]]:
    """The far edges whose `rib` rows cover every address of `dst_part`, one
    entry per edge. An entry holds the longest covering prefix of the edge
    and the lowest cost among the rows of that prefix. The rows are the
    Overlay Flow Control preferred exits the collector keeps. An exit that
    the orchestrator marks `UNREACHABLE`, filters, or holds only as eligible
    has no row. An absent edge is not evidence that the edge lacks the
    prefix."""
    if rib is None or not dst_part:
        return []
    af, lo, _ = dst_part[0]
    probe = str(ipaddress.IPv4Address(lo) if af == 4 else ipaddress.IPv6Address(lo))
    bounds = _set_bounds(dst_part)
    best: dict[str, dict[str, Any]] = {}
    for table in far_tables:
        rows = rib.lpm(table["far_dev"], table["vrf_uid"], probe, legacy_vrf=table.get("vrf_name"))
        rows = [r for r in rows if r.get("prefix") and _covers([str(r["prefix"])], dst_part)]
        if not rows and bounds is not None:
            # A narrower row can cover the first address only. The longest row
            # that covers the whole part is among the rows that overlap the part.
            wide = rib.overlapping(
                table["far_dev"], table["vrf_uid"], *bounds, -1, af, legacy_vrf=table.get("vrf_name")
            )
            wide = [r for r in wide if r.get("prefix") and _covers([str(r["prefix"])], dst_part)]
            if wide:
                longest = max(_prefixlen(r) for r in wide)
                rows = [r for r in wide if _prefixlen(r) == longest]
        if not rows:
            continue
        cidr = str(rows[0]["prefix"])
        costs = [int(r["metric"]) for r in rows if r.get("metric") is not None]
        found = {
            "far_dev": table["far_dev"],
            "cidr": cidr,
            "prefixlen": ipaddress.ip_network(cidr, strict=False).prefixlen,
            "metric": min(costs) if costs else None,
        }
        held = best.get(table["far_dev"])
        if held is None or _exit_rank(found) < _exit_rank(held):
            best[table["far_dev"]] = found
    return [best[dev] for dev in sorted(best)]


def _prefixlen(row: dict[str, Any]) -> int:
    return ipaddress.ip_network(str(row["prefix"]), strict=False).prefixlen


def _exit_rank(exit_: dict[str, Any]) -> tuple[int, float]:
    """The sort key of an exit. The longest prefix ranks first, then the
    lowest cost. An exit with no cost ranks last."""
    metric = exit_.get("metric")
    return (-int(exit_["prefixlen"]), float("inf") if metric is None else float(metric))


_PROTO_NUMBER = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "esp", "58": "icmpv6"}

# The match fields that the trace cannot decide from the flow. The
# orchestrator reads them from the traffic itself or from the LAN side.
_OPEN_MATCHES = (
    ("match_app_id", "application"),
    ("match_app_class_id", "application class"),
    ("match_hostname", "host name"),
    ("match_src_interface", "source interface"),
    ("match_dst_interface", "destination interface"),
    ("match_src_vlan", "source VLAN"),
    ("match_dst_vlan", "destination VLAN"),
)


def _part_in(cidr: str, part: list[tuple[int, int, int]]) -> str:
    """`yes` when every address of `part` is inside `cidr`, `no` when none
    is, `maybe` otherwise."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return "maybe"
    lo_net, hi_net = int(net.network_address), int(net.broadcast_address)
    inside = all(af == net.version and lo_net <= lo and hi <= hi_net for af, lo, hi in part)
    overlap = any(af == net.version and lo <= hi_net and lo_net <= hi for af, lo, hi in part)
    return "yes" if inside and part else "maybe" if overlap else "no"


def _in_ports(spec: Any, port: int) -> bool | None:
    """Whether `port` is in the port or the port range `spec`. None for a spec
    that is neither."""
    low, _, high = str(spec).partition("-")
    try:
        return int(low) <= port <= int(high or low)
    except ValueError:
        return None


def rule_verdict(rule: dict[str, Any], flow: dict[str, Any]) -> tuple[str, str]:
    """Whether one `SdwanPolicyRule` matches the flow (`yes`, `no` or
    `maybe`), and for `maybe` the fields the trace could not decide. The
    function has no side effects. `flow` holds `af`, `src` and `dst`
    (interval parts), `proto`, `port` and `src_port` (a scalar when stated)
    and `dscp`."""
    undecided: list[str] = []
    version = str(rule.get("match_ip_version") or "")
    if version in ("IPv4", "IPv6") and int(version[-1]) != flow["af"]:
        return "no", ""
    for key, part, label in (("match_src", flow["src"], "source"), ("match_dst", flow["dst"], "destination")):
        if rule.get(key):
            held = _part_in(str(rule[key]), part) if part else "maybe"
            if held == "no":
                return "no", ""
            if held == "maybe":
                undecided.append(label)
    if rule.get("match_proto"):
        proto = flow.get("proto")
        if isinstance(proto, str) and proto:
            want = _PROTO_NUMBER.get(str(rule["match_proto"]), str(rule["match_proto"])).lower()
            if _PROTO_NUMBER.get(proto, proto).lower() != want:
                return "no", ""
        else:
            undecided.append("protocol")
    for key, port, label in (
        ("match_dst_port", flow.get("port"), "port"),
        ("match_src_port", flow.get("src_port"), "source port"),
    ):
        if rule.get(key):
            in_range = _in_ports(rule[key], port) if isinstance(port, int) else None
            if in_range is False:
                return "no", ""
            if in_range is None:
                undecided.append(label)
    if rule.get("match_dscp") is not None:
        # an unstated DSCP is undecided, as an unstated port is
        if not flow.get("dscp_stated", True):
            undecided.append("DSCP")
        else:
            try:
                if int(rule["match_dscp"]) != flow["dscp"]:
                    return "no", ""
            except ValueError:
                undecided.append("DSCP")
    undecided += [label for key, label in _OPEN_MATCHES if rule.get(key) is not None]
    # The rule can exclude the flow on a match key that the collector does not map.
    undecided += [str(key) for key in rule.get("match_unmapped") or []]
    return ("maybe", ", ".join(undecided)) if undecided else ("yes", "")


def policy_outcomes(rules: list[dict[str, Any]], flow: dict[str, Any]) -> list[dict[str, Any]]:
    """The rules that can decide the flow, in position order. These are
    every rule the trace cannot decide, up to and with the first rule that
    matches. Each entry is the rule with `maybe` and, for a `maybe`,
    `undecided`. The function reads no graph."""
    out: list[dict[str, Any]] = []
    on_dscp = False
    for rule in sorted(rules, key=lambda r: int(r.get("position") or 0)):
        on_dscp = on_dscp or rule.get("match_dscp") is not None
        verdict, undecided = rule_verdict(rule, flow)
        if verdict == "no":
            continue
        out.append({**rule, "maybe": verdict == "maybe", "undecided": undecided})
        if verdict == "yes":
            break
    # `dscp_evaluated` is True when a rule evaluated up to the decision
    # matches on DSCP. An unstated DSCP changes the answer only in that case.
    for entry in out:
        entry["dscp_evaluated"] = on_dscp
    return out


def _names_hub(tunnel: dict[str, Any], name: str) -> bool:
    """Whether a backhaul reference `name` is the name of the tunnel's far
    edge or of its hub cluster. The orchestrator keeps a leading space that
    an operator typed. Both sides are compared stripped."""
    name = name.strip()
    return bool(name) and name in (
        str(tunnel.get("far_cluster") or "").strip(),
        str(tunnel.get("far_dev_name") or "").strip(),
    )


def _rule_label(rule: dict[str, Any]) -> str:
    return f"rule {rule.get('position')} {rule.get('name')!r}"


def _steer(
    outcomes: list[dict[str, Any]],
    tunnels: list[dict[str, Any]],
    direct: list[dict[str, Any]],
    flow: dict[str, Any],
    *,
    hub_only: bool = False,
    per_rule: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]] | None, str]:
    """The candidates the `edge2cloud` route actions of `outcomes` select,
    and the note. The candidates are None when no outcome selects a
    candidate, and the caller applies its own rule. When no outcome is
    decided, the flow may match none of them, and the candidates for no
    matching rule are added. `hub_only` (a hub that falls through to the
    branch rules) keeps a tunnel to a branch out of the auto and no-match
    candidates. `per_rule`, when given, receives one entry per evaluated rule
    with its position, name, verdict, undecided fields, action and the number
    of candidates it selects."""
    chosen: list[dict[str, Any]] = []
    phrases: list[str] = []
    left_open = False

    def add(rows: list[dict[str, Any]]) -> None:
        for row in rows:
            if all(row is not c for c in chosen):
                chosen.append(row)

    def selects(rows: list[dict[str, Any]]) -> None:
        add(rows)
        if per_rule is not None:
            per_rule[-1]["candidates"] = len(rows)

    hubs = [t for t in tunnels if t.get("far_role") == "hub"]
    for rule in outcomes:
        policy = str(rule.get("edge2cloud_route_policy") or "auto").lower()
        if per_rule is not None:
            per_rule.append(
                {
                    "position": rule.get("position"),
                    "name": rule.get("name"),
                    "verdict": "may match" if rule["maybe"] else "matches",
                    "undecided": rule.get("undecided") or "",
                    "action": policy,
                    "candidates": 0,
                }
            )
        label = _rule_label(rule)
        if rule["maybe"]:
            label += f" (may match: {rule['undecided']} not decided)"
        if policy == "backhaul":
            names = [str(n) for n in rule.get("edge2cloud_backhaul_hubs") or []]
            at = next((i for i, n in enumerate(names) if any(_names_hub(t, n) for t in hubs)), None)
            if at is None:
                shown = ", ".join(n.strip() for n in names) or "no hub"
                phrases.append(f"{label} backhauls to {shown}, and no tunnel ends there")
                continue
            selects([t for t in hubs if _names_hub(t, names[at])])
            rest = [n.strip() for n in names[at + 1 :]]
            backup = f" (then {', '.join(rest)} if it fails)" if rest else ""
            phrases.append(f"{label} backhauls to {names[at].strip()}{backup}")
        elif policy == "gateway":
            gateways = [t for t in tunnels if t.get("far_kind") == "SdwanGateway"]
            if not gateways:
                phrases.append(f"{label} sends the flow to the cloud gateways, and no tunnel ends on one")
                continue
            selects(gateways)
            phrases.append(f"{label} sends the flow to the cloud gateways")
        elif policy == "direct":
            if not direct:
                phrases.append(f"{label} sends the flow direct, and no public link is steered")
                continue
            selects(direct)
            phrases.append(f"{label} sends the flow direct")
        else:
            left_open = True
            phrases.append(f"{label} leaves the route to the orchestrator")
    pool = hubs if hub_only else (hubs or tunnels)
    if left_open:
        add(pool)
        add(direct)
    if outcomes and all(rule["maybe"] for rule in outcomes):
        add(pool)
        add(direct)
        if hubs:
            unmatched = "via the hub"
        elif pool:
            unmatched = "every tunnel is a candidate"
        elif direct:
            unmatched = "the direct links"
        else:
            unmatched = "no candidate"
        phrases.append(f"when no rule matches: {unmatched}")
    if not phrases:
        return None, ""
    on_dscp = any(rule.get("dscp_evaluated") for rule in outcomes or [])
    dscp = "" if flow.get("dscp_stated") or not on_dscp else "; the DSCP is not stated"
    why = "business policy " + "; ".join(phrases)
    if not chosen:
        return None, f"{why}, so the policy selects no candidate{dscp}"
    return chosen, why + dscp


# The most candidates one boundary draws.
MAX_CANDIDATES = 16


def _row_key(row: dict[str, Any]) -> str:
    return str(row.get("uid") or row.get("link_uid") or row.get("egress_uid") or "")


def _cap(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """`rows` cut to the `MAX_CANDIDATES` with the lowest uids, in their own
    order, and the number left out."""
    if len(rows) <= MAX_CANDIDATES:
        return rows, 0
    keep = {id(r) for r in sorted(rows, key=_row_key)[:MAX_CANDIDATES]}
    return [r for r in rows if id(r) in keep], len(rows) - MAX_CANDIDATES


def _on_standby(row: dict[str, Any]) -> bool:
    """True when either tunnel end is on a standby link. The ends are the
    near WanLink and the WanLink of the far end (`far_` columns)."""
    return any(
        str(row.get(f"{end}link_mode") or "").upper() == "HOTSTANDBY"
        or row.get(f"{end}backup_only") is True
        or row.get(f"{end}hot_standby") is True
        for end in ("", "far_")
    )


def _active_links(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """`rows` without the candidates on a standby link, and the names of
    those links, when a candidate on an active link remains. Otherwise the
    result is `rows` unchanged and no names."""
    standby = [r for r in rows if _on_standby(r)]
    if not standby or len(standby) == len(rows):
        return rows, []
    names = sorted({str(r.get("link_name") or r.get("egress_name") or r.get("uid")) for r in standby})
    return [r for r in rows if not _on_standby(r)], names


def _static_cover(
    statics: list[dict[str, Any]], dst_part: list[tuple[int, int, int]]
) -> list[dict[str, Any]]:
    """The longest of `statics` that covers every address of `dst_part`.
    Among the routes of that length the lowest `cost` wins, and ties are
    kept."""
    held = [r for r in statics if r.get("cidr") and _covers([str(r["cidr"])], dst_part)]
    if not held:
        return []
    length = max(_plen(r["cidr"]) for r in held)
    longest = [r for r in held if _plen(r["cidr"]) == length]
    costs = [r["cost"] for r in longest if isinstance(r.get("cost"), int)]
    if costs:
        low = min(costs)
        longest = [r for r in longest if r.get("cost") == low]
    return [{**r, "static_cidr": r["cidr"]} for r in longest]


def _plen(cidr: Any) -> int:
    return ipaddress.ip_network(str(cidr), strict=False).prefixlen


def _static_note(held: list[dict[str, Any]]) -> str:
    """Every drawn static route, with its next hop and interface."""
    parts = []
    for r in held:
        via = f" via {r['next_hop']}" if r.get("next_hop") else ""
        on = f" on {r['interface']}" if r.get("interface") else ""
        parts.append(f"{r['cidr']}{via}{on}")
    noun = "static route" if len(parts) == 1 else "static routes"
    verb = "covers" if len(parts) == 1 else "cover"
    return f"the segment's {noun} {', '.join(parts)} {verb} the destination"


def _static_wins(held: list[dict[str, Any]], overlay_len: int | None) -> bool:
    """Whether a static route wins against the overlay answer. The longer
    prefix wins. At equal length a static route wins when its `preferred` is
    true."""
    if not held:
        return False
    if overlay_len is None:
        return True
    length = _plen(held[0]["cidr"])
    return length > overlay_len or (length == overlay_len and held[0].get("preferred") is True)


def read_boundary(session: Any, dev_uid: str, vrf_uid: str | None) -> dict[str, Any] | None:
    """The ForwardingBoundary of `dev_uid` for the segment `vrf_uid` realizes,
    or None when the device is not an SD-WAN edge in that table."""
    if not vrf_uid:
        return None
    return _path._read_one(session, _BOUNDARY_QUERY, dev=dev_uid, vrf=vrf_uid)


def _one_row_per_tunnel(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One candidate row per tunnel. An address after NAT can be held by the WAN
    links of several edges, and the read returns a row for each edge. The row
    of the far edge in the tunnel uid wins, else the first row in read order."""
    by_uid: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_uid.setdefault(str(row["uid"]), []).append(row)
    out = []
    for uid_, group in by_uid.items():
        named = [r for r in group if uidmod.names_far_device(uid_, r.get("far_dev"))]
        out.append((named or group)[0])
    return out


def _exit_choice(
    exits: list[dict[str, Any]],
    tunnels: list[dict[str, Any]],
    lead: str,
    report: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], str]:
    """The tunnels to the edges whose exit ranks first (rule 2), and the note.
    `report`, when given, receives the exit `prefix`."""
    top = min(_exit_rank(e) for e in exits)
    chosen = {e["far_dev"]: e for e in exits if _exit_rank(e) == top}
    to_exit = [t for t in tunnels if t.get("far_dev") in chosen]
    names = ", ".join(sorted({str(t.get("far_dev_name") or t["far_dev"]) for t in to_exit}))
    first = next(iter(chosen.values()))
    if report is not None:
        report["prefix"] = first["cidr"]
    cost = f" at cost {first['metric']}" if first["metric"] is not None else ""
    why = f"{lead}the Overlay Flow Control table names {names} as the exit for {first['cidr']}{cost}"
    passed = len(exits) - len(chosen)
    if passed:
        why += f"; {passed} other edge(s) hold the destination with a shorter prefix or a higher cost"
    return to_exit, why


def rank_candidates(
    tunnels: list[dict[str, Any]],
    neighbors: list[dict[str, Any]],
    far_prefixes: list[dict[str, Any]],
    dst_part: list[tuple[int, int, int]],
    *,
    role: str | None,
    direct: list[dict[str, Any]] | None = None,
    route_exits: list[dict[str, Any]] | None = None,
    statics: list[dict[str, Any]] | None = None,
    policy: list[dict[str, Any]] | None = None,
    flow: dict[str, Any] | None = None,
    report: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], str]:
    """The candidate rows the boundary selects for `dst_part`, and the note
    with the rule that selected them. The function reads no graph.
    `route_exits` is the result of `route_exits()` for the far edges of
    `tunnels`, `statics` the boundary's static routes and `policy` the result
    of `policy_outcomes()` for the flow. `report`, when given, receives
    `prefix`, the prefix that decided rule 1 or rule 2. When the business
    policy is evaluated (rule 4), `report` also receives `rules`, with one
    entry per evaluated rule."""
    by_far: dict[str, list[str]] = {}
    for row in far_prefixes:
        by_far.setdefault(str(row["far_dev"]), []).append(str(row["cidr"]))
    holders = [dev for dev, cidrs in by_far.items() if _covers(cidrs, dst_part)]
    held = _static_cover(statics or [], dst_part)
    if len(holders) == 1:
        to_holder = [t for t in tunnels if t.get("far_dev") == holders[0]]
        if to_holder:
            lan = max((c for c in by_far[holders[0]] if _covers([c], dst_part)), key=_plen)
            lan_len = _plen(lan)
            if _static_wins(held, lan_len):
                return held, _static_note(held)
            if report is not None:
                report["prefix"] = lan
            return (
                to_holder,
                f"destination is inside a LAN prefix of {to_holder[0].get('far_dev_name') or holders[0]}",
            )
    if len(holders) > 1:
        names = ", ".join(sorted(holders))
        return [], f"destination is inside a LAN prefix of more than one edge ({names}); not resolved"
    lead = ""
    far_devs = {t.get("far_dev") for t in tunnels if t.get("far_dev")}
    exits = [e for e in route_exits or [] if e["far_dev"] in far_devs]
    if held:
        exit_len = max((_plen(e["cidr"]) for e in exits), default=None)
        if _static_wins(held, exit_len):
            return held, _static_note(held)
    if role == "hub":
        # an Overlay Flow Control exit of another edge for a prefix longer than
        # the default comes before the neighbor fallback (rule 2 on a hub)
        specific = [e for e in exits if int(e["prefixlen"]) > 0]
        if specific:
            return _exit_choice(specific, tunnels, "", report)
        if neighbors:
            return (
                neighbors,
                "no route of the hub covers the destination; next hop from the segment's BGP neighbor",
            )
        # A hub is also an edge. A flow that the hub's own routes do not cover
        # leaves by the branch rules and the business policy of the hub.
        lead = "no route of the hub covers the destination and the segment has no BGP neighbor; "
    if exits:
        chosen_exit, why = _exit_choice(exits, tunnels, lead, report)
        top = min(_exit_rank(e) for e in exits)
        if policy and int(top[0]) == 0:
            # The exit comes only from a default route. The edge prefers that
            # secure route over a business policy unless Secure Default Route
            # Override is on. The snapshot does not hold that setting, and both
            # answers are drawn as candidates.
            per_rule: list[dict[str, Any]] = []
            steered, steer_why = _steer(policy, tunnels, direct or [], flow or {}, per_rule=per_rule)
            if report is not None:
                report["rules"] = per_rule
            if steered:
                both = list(chosen_exit)
                both += [c for c in steered if all(c is not x for x in both)]
                return both, (
                    f"{why}; {steer_why}. The edge prefers the overlay default route over the business "
                    "policy unless Secure Default Route Override is on, and the snapshot does not hold "
                    "that setting"
                )
        return chosen_exit, why
    direct = direct or []
    unsteered = ""
    if policy:
        per_rule = []
        steered, why = _steer(policy, tunnels, direct, flow or {}, hub_only=bool(lead), per_rule=per_rule)
        if report is not None:
            report["rules"] = per_rule
        if steered:
            return steered, f"{lead}destination is not in any edge's LAN; {why}"
        if why:
            unsteered = f"; {why}"
    also = ("; the business policy sends some traffic direct" if direct else "") + unsteered
    hubs = [t for t in tunnels if t.get("far_role") == "hub"]
    if hubs:
        return hubs + direct, f"{lead}destination is not in any edge's LAN; via the hub{also}"
    if lead:
        # The other tunnels of a hub end on branches. A branch is no exit for
        # a flow that the hub's own routes do not cover.
        if direct:
            return direct, (
                f"{lead}destination is not in any edge's LAN and no tunnel ends on another hub; "
                f"the business policy sends some traffic direct{unsteered}"
            )
        return [], lead.removesuffix("; ") + unsteered
    if tunnels:
        return (
            tunnels + direct,
            f"{lead}destination is not in any edge's LAN and no tunnel ends on a hub; "
            f"every tunnel is a candidate{also}",
        )
    if direct:
        return direct, f"{lead}no tunnel carries this segment; the business policy sends some traffic direct"
    return [], f"{lead}no tunnel carries this segment"


def candidate_routes(
    session: Any,
    gw: dict[str, Any],
    vrf_uid: str | None,
    dst_part: list[tuple[int, int, int]],
    rib: Any | None = None,
    *,
    src_part: list[tuple[int, int, int]] | None = None,
    port: Any = None,
    proto: Any = None,
    src_port: Any = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]] | None:
    """The synthetic route rows the boundary yields for this flow part, in
    `_ROUTES_QUERY`'s shape, plus the boundary read for the credit and the
    notes. The result is None when the device has no boundary in this table.
    `rib` is the trace's side store with the Overlay Flow Control rows.
    `src_part`, `port`, `proto` and `src_port` are the flow the business
    policy matches. The DSCP comes from `flow_dscp`."""
    boundary = read_boundary(session, gw["dev_uid"], vrf_uid)
    if boundary is None:
        return None
    hub = boundary.get("role") == "hub"
    segment = {
        "segment_id": str(boundary.get("segment_id") or ""),
        "segment_name": boundary.get("segment_name"),
    }
    dscp = _DSCP.get()
    flow = {
        "af": dst_part[0][0] if dst_part else 4,
        "src": src_part or [],
        "dst": dst_part,
        "port": port,
        "proto": proto,
        "src_port": src_port,
        "dscp": 0 if dscp is None else dscp,
        "dscp_stated": dscp is not None,
    }
    statics = _path._read(session, _STATIC_ROUTES_QUERY, boundary=boundary["boundary_uid"], dev=gw["dev_uid"])
    tunnels = _one_row_per_tunnel(
        _path._read(session, _CANDIDATE_TUNNELS_QUERY, dev=gw["dev_uid"], seg=boundary["segment_uid"])
    )
    neighbors = _path._read(session, _BGP_NEIGHBORS_QUERY, dev=gw["dev_uid"], vrf=vrf_uid)
    # The branch rules apply on a hub only when no static route covers the
    # destination and the segment has no BGP neighbor.
    as_edge = not hub or not (_static_cover(statics, dst_part) or neighbors)
    rules = (
        [r["rule"] for r in _path._read(session, _POLICY_RULES_QUERY, dev=gw["dev_uid"], **segment)]
        if as_edge
        else []
    )
    far_devs = sorted({str(t["far_dev"]) for t in tunnels if t.get("far_dev")})
    far_prefixes = (
        _path._read(
            session,
            _FAR_PREFIXES_QUERY,
            devs=far_devs,
            segment_id=str(boundary.get("segment_id") or ""),
            segment_name=boundary.get("segment_name"),
        )
        if far_devs
        else []
    )
    direct = (
        _path._read(session, _DIRECT_EXITS_QUERY, dev=gw["dev_uid"], segment_id=segment["segment_id"])
        if as_edge
        else []
    )
    far_tables = (
        _path._read(
            session,
            _FAR_TABLES_QUERY,
            devs=far_devs,
            segment_id=str(boundary.get("segment_id") or ""),
            segment_name=boundary.get("segment_name"),
        )
        if far_devs and rib is not None
        else []
    )
    report: dict[str, Any] = {}
    chosen, why = rank_candidates(
        tunnels,
        neighbors,
        far_prefixes,
        dst_part,
        role=boundary.get("role"),
        direct=direct,
        route_exits=route_exits(rib, far_tables, dst_part),
        statics=statics,
        policy=policy_outcomes(rules, flow),
        flow=flow,
        report=report,
    )
    chosen, standby = _active_links(chosen)
    if standby:
        why += f"; the candidates on the standby link {', '.join(standby)} are not drawn"
    chosen, not_drawn = _cap(chosen)
    routes: list[dict[str, Any]] = []
    for row in chosen:
        if "static_cidr" in row:
            routes.append(
                {
                    "uid": None,
                    "cidr": row["static_cidr"],
                    "kind": "SDWAN_STATIC",
                    "next_hop": row.get("next_hop"),
                    "ifname": row.get("interface"),
                    "egress_uid": row.get("egress_uid"),
                    "egress_name": row.get("interface") if row.get("egress_uid") else None,
                    "derived": True,
                    "via_rt": None,
                    "rib": None,
                    "next_hop_vrf": None,
                    "discard": None,
                    "sdwan": {"static_route_uid": row.get("uid"), "description": row.get("description")},
                }
            )
        elif "direct_for" in row:
            # The route leaves the overlay through the WAN interface in its own
            # table, to the next hop of the WAN settings.
            routes.append(
                {
                    "uid": None,
                    "cidr": "0.0.0.0/0" if not dst_part or dst_part[0][0] == 4 else "::/0",
                    "kind": "SDWAN_DIRECT",
                    "next_hop": row.get("next_hop"),
                    "ifname": row.get("egress_name"),
                    "egress_uid": row.get("egress_uid"),
                    "egress_name": row.get("egress_name"),
                    "derived": True,
                    "via_rt": None,
                    "rib": None,
                    "next_hop_vrf": row.get("egress_vrf"),
                    "discard": None,
                    "sdwan": {
                        "segment_id": boundary.get("segment_id"),
                        "segment_name": boundary.get("segment_name"),
                        "link_uid": row.get("link_uid"),
                        "link_kind": row.get("link_kind"),
                        "link_name": row.get("link_name"),
                        "route_policy": "direct",
                        "preferred_for": sorted({a for a in row.get("direct_for") or [] if a}),
                    },
                }
            )
        elif "peer_ip" in row:
            connected = [
                c
                for c in row.get("connected") or []
                if c.get("cidr") and _covers([c["cidr"]], _host(row["peer_ip"]))
            ]
            egress = connected[0] if connected else {}
            routes.append(
                {
                    "uid": None,
                    "cidr": "0.0.0.0/0" if ":" not in row["peer_ip"] else "::/0",
                    "kind": "SDWAN_BGP",
                    "next_hop": row["peer_ip"],
                    "ifname": egress.get("if_name"),
                    "egress_uid": egress.get("if_uid"),
                    "egress_name": egress.get("if_name"),
                    "derived": True,
                    "via_rt": None,
                    "rib": None,
                    "next_hop_vrf": None,
                    "discard": None,
                    "sdwan": {"session_uid": row["uid"], "peer_asn": row.get("peer_asn")},
                }
            )
        else:
            routes.append(
                {
                    "uid": None,
                    "cidr": "0.0.0.0/0" if not dst_part or dst_part[0][0] == 4 else "::/0",
                    "kind": "SDWAN_TUNNEL",
                    "next_hop": None,
                    "ifname": row.get("egress_name"),
                    "egress_uid": row.get("egress_uid"),
                    "egress_name": row.get("egress_name"),
                    "derived": True,
                    "via_rt": None,
                    "rib": None,
                    "next_hop_vrf": None,
                    "discard": None,
                    "tunnel_uid": row["uid"],
                    "sdwan": {
                        "segment_id": boundary.get("segment_id"),
                        "segment_name": boundary.get("segment_name"),
                        "tunnel_uid": row["uid"],
                        "tunnel_name": row.get("name"),
                        "link_uid": row.get("link_uid"),
                        "link_kind": row.get("link_kind"),
                        "link_name": row.get("link_name"),
                        "far_kind": row.get("far_kind"),
                        "far_dev_name": row.get("far_dev_name"),
                        "far_role": row.get("far_role"),
                        "state": row.get("state"),
                        "preferred_for": sorted({a for a in row.get("preferred_for") or [] if a}),
                    },
                }
            )
    info = {**boundary, "why": why, "candidates": len(chosen), "not_drawn": not_drawn}
    if "rules" in report:
        info["rules"] = report["rules"]
    if "prefix" in report:
        info["prefix"] = report["prefix"]
    return routes, info


def _host(ip: str) -> list[tuple[int, int, int]]:
    addr = ipaddress.ip_address(ip)
    return [(addr.version, int(addr), int(addr))]
