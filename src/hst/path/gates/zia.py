"""The ZIA forwarding stage at the ZIA boundary of a traced tunnel.

A flow that leaves through a ZIA GRE or IPsec tunnel reaches the ZIA cloud,
where the forwarding rules decide, first match by `order`, whether it goes
to ZPA, direct, or is dropped. This module reads the location the tunnel
serves and the tenant's forwarding rules, and `forwarding_decision` walks the
rules for the inner flow.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

import hst.path as _path
from hst.path.addrsets import _intersect, _intervals, _subtract

Intervals = list[tuple[int, int, int]]

# The top-level location that uses the tunnel, its location groups, and its
# sublocations with their address ranges and groups.
_TUNNEL_LOCATION_QUERY = """
MATCH (t:Tunnel {uid: $tunnel})<-[u:USES]-(loc:ZiaLocation)
WHERE t:Obj AND t.collection_ts = $snap
  AND u._retired_at IS NULL AND NOT loc:Retired AND loc.collection_ts = $snap
OPTIONAL MATCH (loc)-[mo:MEMBER_OF]->(g:ZiaLocationGroup) WHERE mo._retired_at IS NULL AND NOT g:Retired
WITH loc, collect(DISTINCT g.uid) AS groups
OPTIONAL MATCH (sub:ZiaLocation)-[po:PART_OF]->(loc) WHERE po._retired_at IS NULL AND NOT sub:Retired
OPTIONAL MATCH (sub)-[smo:MEMBER_OF]->(sg:ZiaLocationGroup) WHERE smo._retired_at IS NULL AND NOT sg:Retired
WITH loc, groups, sub, collect(DISTINCT sg.uid) AS sub_groups
RETURN loc.uid AS uid, loc.name AS name, groups,
       collect(CASE WHEN sub IS NULL THEN null ELSE {uid: sub.uid, name: sub.name,
               address_ranges: sub.address_ranges, other: sub.other_sublocation, groups: sub_groups} END)
         AS sublocations
"""

# The tenant's forwarding rules and the collected locations and groups each names.
_TENANT_RULES_QUERY = """
MATCH (r:ZiaForwardingRule:Obj)
WHERE r.uid STARTS WITH $prefix AND NOT r:Retired AND r.collection_ts = $snap
OPTIONAL MATCH (r)-[a:APPLIES_TO]->(target) WHERE a._retired_at IS NULL AND NOT target:Retired
RETURN r.uid AS uid, r.name AS name, r.order AS order, r.forward_method AS method, r.enabled AS enabled,
       r.location_ids AS location_ids, r.location_group_ids AS location_group_ids,
       r.src_ips AS src_ips, r.dest_addresses AS dest_addresses, r.other_criteria AS other_criteria,
       collect(DISTINCT target.uid) AS targets
"""


@dataclass(frozen=True)
class ZiaDecision:
    """The result of the walk. It holds the first decided matching rule, or
    an undecided rule that stopped the walk (`reason`), or neither."""

    rule: dict[str, Any] | None = None
    undecided: dict[str, Any] | None = None
    reason: str = ""
    location: str | None = None


def tunnel_location(session: Any, tunnel_uid: str) -> dict[str, Any] | None:
    return _path._read_one(session, _TUNNEL_LOCATION_QUERY, tunnel=tunnel_uid)


def tenant_rules(session: Any, tunnel_uid: str) -> list[dict[str, Any]]:
    """The forwarding rules of the tunnel's own tenant, by the uid prefix `zia:<tenant>:`."""
    parts = tunnel_uid.split(":")
    if len(parts) < 3 or parts[0] != "zia":
        return []
    return list(_path._read(session, _TENANT_RULES_QUERY, prefix=f"zia:{parts[1]}:"))


def _flow_location(location: dict[str, Any], src: Intervals) -> tuple[dict[str, Any] | None, str]:
    """The location the flow comes from. It is the top-level location when
    that location has no sublocation. Otherwise it is the one sublocation
    whose ranges hold the whole source set, or the `other` sublocation when
    the source overlaps no range."""
    subs = [s for s in location.get("sublocations") or [] if s]
    if not subs:
        return {
            "uid": location["uid"],
            "name": location.get("name"),
            "groups": location.get("groups") or [],
        }, ""
    ranged = [s for s in subs if not s.get("other")]
    for sub in ranged:
        held = _intervals([str(r) for r in sub.get("address_ranges") or []])
        if held and not _subtract(src, held):
            return sub, ""
    overlaps = any(
        _intersect(src, _intervals([str(r) for r in s.get("address_ranges") or []])) for s in ranged
    )
    other = next((s for s in subs if s.get("other")), None)
    if not overlaps and other is not None:
        return other, ""
    return (
        None,
        f"the sublocation of the flow's source in {location.get('name') or location['uid']} "
        "is not determined",
    )


def _entries(values: list[Any] | None) -> tuple[Intervals, list[str]]:
    """The address entries as intervals, and the entries that are not an
    address, a CIDR or a range."""
    held: Intervals = []
    other: list[str] = []
    for value in values or []:
        text = str(value).strip()
        got = _intervals([text])
        if got:
            held = _intervals([*[_spec(i) for i in held], *[_spec(i) for i in got]])
        elif text:
            other.append(text)
    return held, other


def _spec(item: tuple[int, int, int]) -> str:
    _, lo, hi = item
    return f"{ipaddress.ip_address(lo)}-{ipaddress.ip_address(hi)}"


def _criterion(values: list[Any] | None, flow: Intervals, what: str) -> tuple[str, str]:
    """`match`, `miss` or `undecided` for one address criterion, with a reason."""
    if not values:
        return "match", ""
    held, other = _entries(values)
    if held and not _subtract(flow, held):
        return "match", ""
    if other:
        return "undecided", f"{what} names {', '.join(other)}, which the trace cannot compare"
    if not _intersect(flow, held):
        return "miss", ""
    return "undecided", f"{what} holds part of the flow"


def _order_key(rule: dict[str, Any]) -> tuple[int, int, str]:
    order = rule.get("order")
    if isinstance(order, int) and order >= 1:
        return (0, order, rule["uid"])
    return (1, 0, rule["uid"])


def forwarding_decision(
    location: dict[str, Any], rules: list[dict[str, Any]], src: Intervals, dst: Intervals
) -> ZiaDecision:
    """First match over the enabled rules, by `order` (1 or more, ascending,
    then the rest by uid). A decided match wins, a decided miss continues, and
    an undecided rule stops the walk. The function has no side effects."""
    flow_loc, why = _flow_location(location, src)
    if flow_loc is None:
        return ZiaDecision(reason=why, location=location.get("name"))
    scope_uids = {flow_loc["uid"], *(flow_loc.get("groups") or [])}
    parent = location["uid"] if flow_loc["uid"] != location["uid"] else None
    for rule in sorted(rules, key=_order_key):
        if rule.get("enabled") is False:
            continue
        targets = set(rule.get("targets") or [])
        named = len(rule.get("location_ids") or []) + len(rule.get("location_group_ids") or [])
        if (targets or named) and not targets & scope_uids:
            if parent and parent in targets:
                return ZiaDecision(
                    undecided=rule,
                    reason="the rule names the parent location of the flow's sublocation",
                    location=flow_loc.get("name"),
                )
            if named > len(targets):
                return ZiaDecision(
                    undecided=rule,
                    reason="the rule names a location or group that this run did not collect",
                    location=flow_loc.get("name"),
                )
            continue
        if rule.get("other_criteria"):
            return ZiaDecision(
                undecided=rule,
                reason=f"the rule also matches on {', '.join(rule['other_criteria'])}",
                location=flow_loc.get("name"),
            )
        states = [
            _criterion(rule.get("src_ips"), src, "the source criterion"),
            _criterion(rule.get("dest_addresses"), dst, "the destination criterion"),
        ]
        if any(state == "miss" for state, _ in states):
            continue
        undecided = [reason for state, reason in states if state == "undecided"]
        if undecided:
            return ZiaDecision(undecided=rule, reason="; ".join(undecided), location=flow_loc.get("name"))
        return ZiaDecision(rule=rule, location=flow_loc.get("name"))
    return ZiaDecision(location=flow_loc.get("name"))
