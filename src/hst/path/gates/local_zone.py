"""Strict router-local evaluation of explicitly identified zone policy."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import hst.path as _path

from ..addrsets import _size
from ..state import Effect, FlowRegion, Rect
from ..verdict import DENY, INDETERMINATE, classify_action
from .firewall import (
    _RULEBASE_RULES,
    _expand_jumps,
    _first_match_by_sport,
    _unknown_dims,
    _unstated_default,
)

_LOCAL_RULES_QUERY = _RULEBASE_RULES.replace(
    "MATCH (rb:FwRulebase {uid: $rb})-[hr:HAS_RULE]->(r:FwRule)\n"
    "WHERE rb:Obj AND rb.collection_ts = $snap\n"
    "  AND r.enabled AND NOT r:Retired AND hr._retired_at IS NULL\n"
    "  AND r.collection_ts = $snap",
    "MATCH (rb:FwRulebase {uid: $rb})-[hr:HAS_RULE]->(r:FwRule)\n"
    "WHERE rb:Obj AND rb.collection_ts = $snap AND r.collection_ts = $snap\n"
    "  AND r.enabled AND NOT rb:Retired AND NOT r:Retired\n"
    "  AND hr._retired_at IS NULL AND hr.collection_ts = $snap",
)

_LOCAL_ZONE_CONTEXT_QUERY = """
MATCH (i:Interface:Obj {collection_ts: $snap})-[on:ON]->(d:Device {uid: $dev})
MATCH (zone:Zone)-[contains:CONTAINS]->(i)
WHERE i.uid IN [$in_if, $out_if]
  AND NOT d:Retired AND NOT i:Retired AND NOT zone:Retired
  AND d:Obj AND d.collection_ts = $snap AND i.collection_ts = $snap AND zone.collection_ts = $snap
  AND on._retired_at IS NULL AND contains._retired_at IS NULL
  AND on.collection_ts = $snap
  AND contains.collection_ts = $snap
RETURN i.uid AS if_uid, i.name AS if_name,
       zone.uid AS zone_uid, zone.name AS zone_name
ORDER BY if_uid, zone_uid
"""

_OWNED_ZONES_QUERY = """
MATCH (zone:Zone)-[owned:OWNED_BY]->(d:Device {uid: $dev})
WHERE NOT d:Retired AND NOT zone:Retired
  AND d:Obj AND d.collection_ts = $snap AND zone.collection_ts = $snap
  AND owned._retired_at IS NULL
  AND owned.collection_ts = $snap
RETURN zone.uid AS zone_uid, zone.name AS zone_name,
       zone.local_zone AS local_zone,
       zone.default_action AS default_action,
       zone.default_action_unknown AS default_action_unknown
ORDER BY zone_uid
"""

_LOCAL_ZONE_RULEBASES_QUERY = """
MATCH (src:Zone:Obj {collection_ts: $snap})-[src_owned:OWNED_BY]->(d:Device {uid: $dev})
MATCH (dst:Zone)-[dst_owned:OWNED_BY]->(d)
MATCH (rb:FwRulebase)-[from:FROM_ZONE]->(src:Zone)
MATCH (rb)-[to:TO_ZONE]->(dst:Zone)
WHERE NOT d:Retired AND NOT rb:Retired AND NOT src:Retired AND NOT dst:Retired
  AND d:Obj AND d.collection_ts = $snap AND rb.collection_ts = $snap
  AND src.collection_ts = $snap AND dst.collection_ts = $snap
  AND src_owned._retired_at IS NULL AND dst_owned._retired_at IS NULL
  AND from._retired_at IS NULL AND to._retired_at IS NULL
  AND src_owned.collection_ts = $snap
  AND dst_owned.collection_ts = $snap
  AND from.collection_ts = $snap
  AND to.collection_ts = $snap
RETURN DISTINCT rb.uid AS rb_uid, rb.name AS rb_name, rb.af AS af,
       rb.default_action AS default_action,
       rb.default_action_unknown AS default_action_unknown,
       rb.global_state_policy AS global_state_policy,
       src.uid AS src_uid, src.name AS src_name,
       coalesce(src.local_zone, src.is_local) AS src_local,
       dst.uid AS dst_uid, dst.name AS dst_name,
       coalesce(dst.local_zone, dst.is_local) AS dst_local
ORDER BY rb_uid
"""


def _af(row: dict[str, Any]) -> int | None:
    value = row.get("af")
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@dataclass
class LocalZoneTransition:
    """An input/output-chain flow through an explicit local-zone pair."""

    session: Any
    device_uid: str
    in_if_uid: str | None
    out_if_uid: str | None
    chain: str
    conn_state: str = "new"
    considered_ids: list[str] = field(default_factory=list, init=False)
    excluded_ids: list[str] = field(default_factory=list, init=False)
    _zones: list[dict[str, Any]] | None = field(default=None, init=False)
    _owned_zones: list[dict[str, Any]] | None = field(default=None, init=False)
    _rulebases: list[dict[str, Any]] | None = field(default=None, init=False)

    @property
    def considered(self) -> list[str]:
        return list(dict.fromkeys([*self.considered_ids, *self.excluded_ids]))

    @property
    def excluded(self) -> list[str]:
        return list(self.excluded_ids)

    def _read(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        if self._zones is None:
            params = {
                "dev": self.device_uid,
                "in_if": self.in_if_uid or "",
                "out_if": self.out_if_uid or "",
            }
            self._zones = _path._read(self.session, _LOCAL_ZONE_CONTEXT_QUERY, **params)
            self._owned_zones = _path._read(self.session, _OWNED_ZONES_QUERY, dev=self.device_uid)
            self._rulebases = _path._read(self.session, _LOCAL_ZONE_RULEBASES_QUERY, dev=self.device_uid)
        return self._zones, self._owned_zones or [], self._rulebases or []

    def apply(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]:
        zones, owned_zones, rows = self._read()
        if self.chain not in {"input", "output"}:
            return [
                self._unknown(rect, "local-zone policy applies only to input or output flows")
                for rect in region
            ]
        if not owned_zones and not rows:
            return [(FlowRegion.single(rect), Effect("pass", "local-zone")) for rect in region]
        if not owned_zones:
            return [
                self._unknown(rect, "zone ownership and local-zone identity were not collected")
                for rect in region
            ]
        local_zones = [zone for zone in owned_zones if zone.get("local_zone") is True]
        unknown_markers = [zone for zone in owned_zones if zone.get("local_zone") is None]
        if not local_zones and not unknown_markers:
            return [(FlowRegion.single(rect), Effect("pass", "local-zone")) for rect in region]
        if unknown_markers:
            return [
                self._unknown(rect, "one or more owned zones lack a collected local-zone marker")
                for rect in region
            ]
        if len(local_zones) != 1:
            return [
                self._unknown(rect, "multiple explicit local-zone identities are owned by the device")
                for rect in region
            ]
        local_uid = local_zones[0]["zone_uid"]
        interface_uid = self.in_if_uid if self.chain == "input" else self.out_if_uid
        attached = {row["zone_uid"] for row in zones if row.get("if_uid") == interface_uid}
        if len(attached) != 1:
            reason = (
                "the local flow interface has no collected zone binding"
                if not attached
                else "the local flow interface has multiple zone identities"
            )
            return [self._unknown(rect, reason) for rect in region]
        attached_uid = next(iter(attached))
        interface_names = {row.get("if_name") for row in zones if row.get("if_uid") == interface_uid}
        if len(interface_names) > 1:
            return [
                self._unknown(rect, "the local flow interface has conflicting collected names")
                for rect in region
            ]
        interface_name = next(iter(interface_names), None)
        relevant_side = "src" if self.chain == "input" else "dst"
        local_side = "dst" if self.chain == "input" else "src"
        plausible = [row for row in rows if row.get(f"{relevant_side}_uid") == attached_uid]
        pair = [
            row
            for row in plausible
            if row.get(f"{local_side}_uid") == local_uid and row.get(f"{local_side}_local") is True
        ]
        out: list[tuple[FlowRegion, Effect]] = []
        for rect in region:
            candidates = [row for row in pair if _af(row) in (None, rect.af)]
            excluded = sorted({row["rb_uid"] for row in rows if row.get("rb_uid") and row not in candidates})
            self.excluded_ids = list(dict.fromkeys([*self.excluded_ids, *excluded]))
            if not candidates:
                destination_uid = local_uid if self.chain == "input" else attached_uid
                destination = next(
                    (zone for zone in owned_zones if zone.get("zone_uid") == destination_uid), None
                )
                if destination is None:
                    out.append(
                        self._unknown(rect, "the destination zone was not collected", excluded=excluded)
                    )
                elif self.chain == "output":
                    out.append(self._output_default(rect, owned_zones, attached_uid, local_uid, excluded))
                else:
                    out.append(self._zone_default(rect, destination, attached_uid, local_uid, excluded))
            elif len(candidates) > 1:
                ids = sorted(row["rb_uid"] for row in candidates)
                self.considered_ids = list(dict.fromkeys([*self.considered_ids, *ids]))
                out.append(
                    self._unknown(
                        rect,
                        "multiple local-zone rulebases govern this family",
                        rb_uids=ids,
                        excluded=excluded,
                    )
                )
            else:
                out.extend(self._evaluate(rect, candidates[0], excluded, interface_name))
        return out

    def _zone_default(
        self,
        rect: Rect,
        zone: dict[str, Any],
        attached_uid: str,
        local_uid: str,
        excluded: list[str],
    ) -> tuple[FlowRegion, Effect]:
        reason = None
        if not zone.get("default_action_unknown") and not zone.get("default_action"):
            _unstated_default(f"zone {zone.get('zone_uid')}")  # logs the contract violation
        if zone.get("default_action_unknown") or not zone.get("default_action"):
            action = INDETERMINATE
            reason = "the destination zone default action was not collected"
        else:
            action = classify_action(zone["default_action"])
        credits = list(dict.fromkeys(excluded))
        return (
            FlowRegion.single(rect),
            Effect(
                action,
                "local-zone",
                terminal=action == DENY,
                unknown=_unknown_dims(reason) if action == INDETERMINATE else frozenset(),
                reason=reason,
                data={
                    "by": "zone-default",
                    "recorded_action": zone.get("default_action"),
                    "zone_uid": zone.get("zone_uid"),
                    "src_zone_uid": attached_uid if self.chain == "input" else local_uid,
                    "dst_zone_uid": local_uid if self.chain == "input" else attached_uid,
                    "considered_ids": self.considered,
                    "excluded_ids": excluded,
                    "gate_credits": credits,
                },
            ),
        )

    def _output_default(
        self,
        rect: Rect,
        owned_zones: list[dict[str, Any]],
        attached_uid: str,
        local_uid: str,
        excluded: list[str],
    ) -> tuple[FlowRegion, Effect]:
        """The fall-through of a packet the device sends into a zone that binds
        no rule set from the local zone for its family. The zone whose
        default-action governs the packet, the local zone or the egress zone,
        is not established here. The answer is decided only where both
        recorded defaults give the same outcome."""
        local = next((z for z in owned_zones if z.get("zone_uid") == local_uid), None)
        egress = next((z for z in owned_zones if z.get("zone_uid") == attached_uid), None)
        if local is None or egress is None:
            return self._unknown(rect, "the destination zone was not collected", excluded=excluded)
        by_egress = self._zone_default(rect, egress, attached_uid, local_uid, excluded)
        by_local = self._zone_default(rect, local, attached_uid, local_uid, excluded)
        if by_egress[1].kind == by_local[1].kind:
            return by_egress
        reason = (
            "no rule set is bound from the local zone to this zone for the family, and the local "
            "zone's and this zone's recorded default actions differ or are not recorded"
        )
        effect = by_egress[1]
        return (
            by_egress[0],
            Effect(
                INDETERMINATE,
                "local-zone",
                unknown=_unknown_dims(reason),
                reason=reason,
                data=effect.data,
            ),
        )

    def _evaluate(
        self,
        rect: Rect,
        rb: dict[str, Any],
        excluded: list[str],
        interface_name: str | None,
    ) -> list[tuple[FlowRegion, Effect]]:
        if rb["rb_uid"] not in self.considered_ids:
            self.considered_ids.append(rb["rb_uid"])
        rules = _expand_jumps(
            self.session,
            _path._read(self.session, _LOCAL_RULES_QUERY, rb=rb["rb_uid"]),
            (rb["rb_uid"],),
            _LOCAL_RULES_QUERY,
        )
        skips: list[dict[str, Any]] = []
        # The interface of the chain's one side has a collected zone binding
        # (`apply`). A name that is None is unresolved, and a rule scoped to
        # that side is undecided.
        side = "out" if self.chain == "output" else "in"
        decided = _first_match_by_sport(
            rules,
            None if self.chain == "output" else interface_name,
            None if self.chain == "input" else interface_name,
            list(rect.src),
            list(rect.dst),
            rect.proto,
            None if rect.dport is None else list(rect.dport),
            rect.sport,
            skips,
            conn_state=self.conn_state,
            unresolved=frozenset({side}) if interface_name is None else frozenset(),
        )
        out: list[tuple[FlowRegion, Effect]] = []
        for sport, regions in decided:
            for rule, src, dst, proto, dport in regions:
                reason = (rule or {}).get("indeterminate_reason")
                if rule is None:
                    if not rb.get("default_action_unknown") and not rb.get("default_action"):
                        _unstated_default(f"rulebase {rb['rb_uid']}")  # logs the contract violation
                    if rb.get("default_action_unknown") or not rb.get("default_action"):
                        action = INDETERMINATE
                        reason = "the local-zone rulebase default action was not collected"
                    else:
                        action = classify_action(rb["default_action"])
                else:
                    action = classify_action(rule["action"])
                # The walk partitions the service dimensions only. A rule's
                # address hit decides the whole region it is returned with,
                # and the region keeps the rectangle's own addresses. A hit
                # smaller than the rectangle is undecided and marked partial.
                partial = _size(src) < _size(list(rect.src)) or _size(dst) < _size(list(rect.dst))
                if partial:
                    action = INDETERMINATE
                    reason = "the local-zone rule covers only part of the packet address region"
                sub = rect.narrow(
                    proto=proto,
                    dport=None if dport is None else tuple(dport),
                    sport=None if sport is None else tuple(sport),
                )
                data = {
                    "rb_uid": rb["rb_uid"],
                    "rb_name": rb.get("rb_name"),
                    "rule_uid": (rule or {}).get("uid"),
                    "rule_pos": (rule or {}).get("pos"),
                    "recorded_action": rb.get("default_action") if rule is None else rule.get("action"),
                    "rule_name": (rule or {}).get("name"),
                    "partial": partial,
                    "src_zone_uid": rb["src_uid"],
                    "dst_zone_uid": rb["dst_uid"],
                    "state_skips": skips,
                    "considered_ids": list(dict.fromkeys(self.considered_ids)),
                    "excluded_ids": excluded,
                    "gate_credits": list(dict.fromkeys([rb["rb_uid"], *excluded])),
                }
                out.append(
                    (
                        FlowRegion.single(sub),
                        Effect(
                            action,
                            "local-zone",
                            terminal=action == DENY,
                            unknown=_unknown_dims(reason) if action == INDETERMINATE else frozenset(),
                            reason=reason,
                            data=data,
                        ),
                    )
                )
        return out

    @staticmethod
    def _unknown(
        rect: Rect,
        reason: str,
        *,
        rb_uids: list[str] | None = None,
        excluded: list[str] | None = None,
    ) -> tuple[FlowRegion, Effect]:
        return (
            FlowRegion.single(rect),
            Effect(
                "indeterminate",
                "local-zone",
                reason=reason,
                data={
                    "rb_uids": rb_uids or [],
                    "excluded_ids": excluded or [],
                    "gate_credits": excluded or [],
                },
            ),
        )
