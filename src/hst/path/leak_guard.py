"""Leak guards. A leak guard is a drop rule that backs up a policy route into a tunnel.

A policy route (PbrPolicy) on a device sends a set of sources into a routing
table whose route for their destinations leaves through a tunnel interface.
If the policy route or the tunnel is not in effect, the normal table of the
device (the table of the ingress interface) routes the same flows. A drop,
deny or reject rule R is a leak guard for tunnel T when the 3 conditions hold.

1. A policy route rule of the same device sends sources that R matches into a
   table that routes the destinations into T, after the earlier rules of its
   policy have taken their part.
2. For those sources and destinations the normal table routes out an
   interface that the rulebase scope of R (zone pair, PROTECTED_BY binding or
   device-wide chain) and the interface scope of R cover, and R is the rule
   that decides those flows there.
3. R does not drop the flows on the egress of T.

The policy route acts before R, and R is not on the tunnel path. R applies
when the same traffic leaves by the normal route. When the normal route
leaves by an interface that the rulebase scope of R covers and R does not
match, that exit is reported in a guard gap. An exit that the rulebase scope
does not cover (for a LAN to WAN zone pair, an exit into zone LAN) is left
out.

Each finding is a record. It holds the rule, the tunnel, the policy routes,
the hosts, the exits of the rule, the exits it covers or does not cover, and
one line built by `hst.results.words`. The detail of the engine (routes,
tables, zones, object membership) is under `detail`.

Every step uses the readers of the trace engine. `gates.pbr` gives the policy
route rows and their first-match partition. `trace._family_routes`,
`gates.routing._route_partition` and the side-store lookup
`trace._rib_lookup` give the routes of a table and their longest-prefix
partition. `gates.firewall` gives the rule rows and the first match of the
firewall gate. A step whose answer is not settled (an egress that does not
resolve, equal-cost routes that disagree, a rule the gate leaves undecided)
makes the record not decided (`decided` false). The record lists what is
missing under `missing`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, cast

import hst.path as _path
from hst.results.words import Missing, covered_line, decided_first_line, not_covered_line

from . import netobjects
from .addrsets import _complement, _describe, _intervals, _merge, _rule_intervals_status, _size, _subtract
from .gates.firewall import _RULEBASE_RULES, _acl_governs_hop, _first_match, _net_side
from .gates.pbr import _DEVICE_PBR_POLICIES, POLICY_RULES, _default_table_uid, partition_rules
from .gates.routing import _connected_egress, _route_partition
from .trace import (
    _IFACE_BY_NAME_QUERY,
    _family_routes,
    _rib_gap,
    _rib_lookup,
    _runs_dynamic_routing,
    _vrf_name,
)
from .verdict import DENY, INDETERMINATE, classify_action

Ivals = list[tuple[int, int, int]]

# MAX_DEVICES caps the devices of one rulebase. MAX_PARTS caps the route parts
# of one table lookup. NEXT_HOP_DEPTH caps the next hops of one egress
# resolution. MAX_FINDINGS, MAX_NOTES and MAX_ADDRESSES cap the lists of one
# answer. A cap that cuts the analysis as a whole makes every record of the
# answer not decided.
MAX_DEVICES = 4
MAX_PARTS = 32
NEXT_HOP_DEPTH = 4
MAX_FINDINGS = 20
MAX_NOTES = 10
MAX_ADDRESSES = 50
# `_DEVICE_INTERFACES` reads MAX_INTERFACES + 1 rows to detect a cut.
MAX_INTERFACES = 256

_DEFAULT_ROUTES = ("0.0.0.0/0", "::/0")

# The scope of one rulebase. It holds the interfaces of the zones it binds
# (each with its device), the devices that enforce it, and its PROTECTED_BY
# bindings.
_RULEBASE_SCOPE = """
MATCH (rb:FwRulebase {uid: $rb})
WHERE NOT rb:Retired AND rb:Obj AND rb.collection_ts = $snap
OPTIONAL MATCH (rb)-[fz:FROM_ZONE]->(fzone:Zone)-[fc:CONTAINS]->(fi:Interface)-[fo:ON]->(fd:Device)
WHERE fz._retired_at IS NULL AND fc._retired_at IS NULL AND fo._retired_at IS NULL
  AND NOT fzone:Retired AND NOT fi:Retired AND NOT fd:Retired
WITH rb, [x IN collect(DISTINCT {uid: fi.uid, zone: fzone.name, device: fd.uid})
          WHERE x.uid IS NOT NULL] AS from_ifs
OPTIONAL MATCH (rb)-[tz:TO_ZONE]->(tzone:Zone)-[tc:CONTAINS]->(ti:Interface)-[tn:ON]->(td:Device)
WHERE tz._retired_at IS NULL AND tc._retired_at IS NULL AND tn._retired_at IS NULL
  AND NOT tzone:Retired AND NOT ti:Retired AND NOT td:Retired
WITH rb, from_ifs, [x IN collect(DISTINCT {uid: ti.uid, zone: tzone.name, device: td.uid})
                    WHERE x.uid IS NOT NULL] AS to_ifs
OPTIONAL MATCH (ed:Device)-[ee:ENFORCES]->(rb)
WHERE ee._retired_at IS NULL AND NOT ed:Retired
WITH rb, from_ifs, to_ifs, collect(DISTINCT ed.uid) AS direct
OPTIONAL MATCH (gd:Device)-[gm:MEMBER_OF]->(:RedundancyGroup)-[ge:ENFORCES]->(rb)
WHERE gm._retired_at IS NULL AND ge._retired_at IS NULL AND NOT gd:Retired
WITH rb, from_ifs, to_ifs, direct, collect(DISTINCT gd.uid) AS grouped
WITH rb, from_ifs, to_ifs, direct + grouped AS enforced
OPTIONAL MATCH (bi:Interface)-[pb:PROTECTED_BY]->(rb)
WHERE pb._retired_at IS NULL AND NOT bi:Retired
OPTIONAL MATCH (bi)-[bo:ON]->(bd:Device)
WHERE bo._retired_at IS NULL AND NOT bd:Retired
WITH rb, from_ifs, to_ifs, enforced,
     [x IN collect(DISTINCT {uid: bi.uid, name: bi.name, direction: pb.direction, device: bd.uid})
      WHERE x.uid IS NOT NULL] AS bindings
RETURN rb.name AS name, rb.af AS af, rb.chain AS chain, rb.kind AS kind, rb.match_context AS match_context,
       size([(rb)-[z:FROM_ZONE|TO_ZONE]->(:Zone) WHERE z._retired_at IS NULL | z]) > 0 AS zone_bound,
       from_ifs, to_ifs, enforced, bindings"""

# Every interface of one device, with its zones and the tunnels it is an
# endpoint of.
_DEVICE_INTERFACES = """
MATCH (i:Interface)-[o:ON]->(d:Device {uid: $dev})
WHERE d:Obj AND d.collection_ts = $snap
  AND NOT i:Retired AND o._retired_at IS NULL AND i.collection_ts = $snap
OPTIONAL MATCH (z:Zone)-[c:CONTAINS]->(i)
WHERE c._retired_at IS NULL AND NOT z:Retired
OPTIONAL MATCH (t:Tunnel)-[e:ENDPOINT]->(i)
WHERE e._retired_at IS NULL AND NOT t:Retired
RETURN i.uid AS uid, i.name AS name, i.description AS description,
       [x IN collect(DISTINCT z.name) WHERE x IS NOT NULL] AS zones,
       [x IN collect(DISTINCT {uid: t.uid, name: t.name}) WHERE x.uid IS NOT NULL] AS tunnels
ORDER BY uid LIMIT 257"""

# The names of the devices that enforce one rulebase.
_DEVICE_NAMES = """
MATCH (d:Device)
WHERE d.uid IN $uids AND NOT d:Retired AND d:Obj AND d.collection_ts = $snap
RETURN d.uid AS uid, coalesce(d.hostname, d.name) AS name
ORDER BY uid"""


@dataclass
class _Branch:
    """One tunnel leg of one policy route claim and what the normal route
    does with the same flows."""

    kind: str  # "guard" or "gap"
    decided: bool
    device: str
    tunnel_if: dict[str, Any]
    claim: dict[str, Any]
    ingress: dict[str, Any]
    sources: Ivals
    destinations: Ivals
    table: dict[str, Any]
    breakout: list[dict[str, Any]]
    reasons: list[Missing] = field(default_factory=list)


def _rule_side(rule: dict[str, Any], side: str, universe: Ivals) -> Ivals | None:
    """The addresses one side of the rule matches, or None when the gate
    cannot read them as an address set."""
    ivals, unparsed = _rule_intervals_status(
        rule.get(f"{side}_cidrs") or [], rule.get(f"{side}_ips") or [], rule.get(f"{side}_ranges") or []
    )
    if unparsed:
        return None
    hit, gap, _reason = _net_side(
        bool(rule.get(f"{side}_any")),
        rule.get(f"{side}_obj_count", 0),
        bool(rule.get(f"{side}_opaque")),
        bool(rule.get(f"{side}_negate")),
        rule.get(f"{side}_opaque_reasons") or [],
        ivals,
        universe,
    )
    if gap:
        return None
    return hit or []


def _iface(row: dict[str, Any] | None, uid: str | None = None) -> dict[str, Any]:
    if row is None:
        return {"uid": uid, "name": None}
    return {"uid": row.get("uid", uid), "name": row.get("name")}


def _service_text(group: dict[str, Any]) -> str:
    """The service part of the flows a policy route claim answers for."""
    protos, ports, sports = group.get("proto_subset"), group.get("port_subset"), group.get("sport_subset")
    if protos is None and ports is None and sports is None:
        return "any"
    parts = []
    if protos is not None:
        parts.append("protocols " + ", ".join(str(p) for p in sorted(protos)))
    for label, ivals in (("destination ports", ports), ("source ports", sports)):
        if ivals is not None:
            parts.append(
                label + " " + ", ".join(f"{lo}-{hi}" if lo != hi else str(lo) for _, lo, hi in ivals)
            )
    return "; ".join(parts)


class _Analysis:
    def __init__(
        self,
        session: Any,
        rule: dict[str, Any],
        rules: list[dict[str, Any]],
        scope: dict[str, Any],
        rib: Callable[[], Any] | None,
    ) -> None:
        self.session = session
        self.rule = rule
        self.rules = rules
        self.scope = scope
        self._rib_factory = rib
        self._rib: Any = None
        self.branches: list[_Branch] = []
        self.notes: list[str] = []
        self.interfaces: dict[str, dict[str, Any]] = {}
        self._legs: dict[Any, tuple[str, str | None]] = {}
        self._rib_gaps: dict[str, tuple[str, bool] | None] = {}
        self._dynamic: dict[str, bool] = {}
        # The reasons that cut the analysis as a whole. With a reason here,
        # every record is not decided.
        self.open: list[Missing] = []
        self.label = f"rule {rule.get('pos')}"

    # --- reads ------------------------------------------------------------------------

    def rib(self) -> Any:
        if self._rib is None and self._rib_factory is not None:
            self._rib = self._rib_factory()
        return self._rib

    def note(self, text: str) -> None:
        if text not in self.notes:
            self.notes.append(text)

    def open_reason(self, reason: Missing) -> None:
        if reason not in self.open:
            self.open.append(reason)

    def table(self, uid: str) -> dict[str, Any]:
        return {"uid": uid, "name": _vrf_name(self.session, uid)}

    def lookup(
        self, dev: str, table_uid: str, dst: Ivals
    ) -> tuple[list[tuple[Ivals, list[dict[str, Any]]]], tuple[Ivals, Missing] | None]:
        """The longest-prefix partition of `dst` in one table, as the trace
        computes it, and the destinations after the `MAX_PARTS` cap with the
        reason they are not evaluated."""
        routes = _family_routes(self.session, table_uid, dst)
        rib = self.rib()
        lookup = _rib_lookup(rib, dev, table_uid, _vrf_name(self.session, table_uid)) if rib else None
        parts = _route_partition(routes, dst, lookup, [], limit=MAX_PARTS)
        rest = _subtract(dst, _merge([i for part, _ in parts for i in part]))
        if not rest:
            return parts, None
        name = _vrf_name(self.session, table_uid) or table_uid
        text = f"the destinations past the first {MAX_PARTS} routes of table {name} are not evaluated"
        self.note(f"{text} ({_describe(rest)})")
        return parts, (
            rest,
            Missing(
                code="routes-not-evaluated", subject=f"table {name}", detail=f"{text}: {_describe(rest)}"
            ),
        )

    def rib_reason(self, dev: str, table_uid: str, winners: list[dict[str, Any]]) -> Missing | None:
        """The reason that the routes of one part are graph edges only, as the
        trace marks a leg (`trace._mark_rib_gap`).

        When the pinned run recorded the RIB table of the device and the table
        cannot answer, every part has the reason. When nothing is recorded, a
        part has the reason only if it has no route or a default route, and
        the side store is unavailable or a dynamic routing process runs in the
        table. None with no RIB reader or with a store that answered."""
        rib = self.rib()
        if rib is None:
            return None
        if dev not in self._rib_gaps:
            self._rib_gaps[dev] = _rib_gap(rib, dev)
        gap = self._rib_gaps[dev]
        if gap is None:
            return None
        why, recorded = gap
        if not recorded:
            if winners and not any(w.get("cidr") in _DEFAULT_ROUTES for w in winners):
                return None
            if getattr(rib, "available", True) is not False:
                if table_uid not in self._dynamic:
                    self._dynamic[table_uid] = _runs_dynamic_routing(self.session, table_uid)
                if not self._dynamic[table_uid]:
                    return None
        name = _vrf_name(self.session, table_uid) or table_uid
        return Missing(
            code="rib-not-consulted",
            subject=f"table {name}",
            detail=f"the RIB of the device is not consulted ({why}); its routes are graph edges only",
        )

    def egress(
        self, dev: str, table_uid: str, route: dict[str, Any], in_if: str, depth: int = 0
    ) -> dict[str, Any] | None:
        """The device interface that one route leaves by, resolved as in the
        trace. The sources are the interface of the route, the gateway
        interface of a connected prefix, and the route to its next hop. None
        when the route does not resolve to one interface."""
        if route.get("egress_uid"):
            return {"uid": route["egress_uid"], "name": route.get("egress_name")}
        if route.get("ifname"):
            named = _path._read_one(
                self.session, _IFACE_BY_NAME_QUERY, name=route["ifname"], dev=dev, vrf=table_uid
            )
            if named:
                return {"uid": named["uid"], "name": named["name"]}
        if route.get("uid"):
            found = _connected_egress(self.session, route["uid"], dev, in_if)
            if found and not found.get("remote"):
                return {"uid": found["uid"], "name": found.get("name")}
        next_hop = route.get("next_hop")
        if not next_hop or depth >= NEXT_HOP_DEPTH or not _intervals([next_hop]):
            return None
        target = route.get("next_hop_vrf") or table_uid
        parts, _cut = self.lookup(dev, target, _intervals([next_hop]))  # One address gives one part.
        winners = parts[0][1] if parts else []
        found_ifs = {
            str(e["uid"]): e
            for e in (self.egress(dev, target, w, in_if, depth + 1) for w in winners if not w.get("discard"))
            if e is not None
        }
        if len(found_ifs) == 1 and len(winners) == len([w for w in winners if not w.get("discard")]):
            return next(iter(found_ifs.values()))
        return None

    # --- the rule on one leg --------------------------------------------------------------

    def governs(self, dev: str, in_if: str, out_if: str, in_name: str | None, out_name: str | None) -> str:
        """Whether the rulebase of the rule governs the leg from `in_if` to
        `out_if`. Returns "governs", "excluded", or the reason it is not
        decided."""
        scope = self.scope
        if scope.get("zone_bound"):
            from_ifs = {x["uid"] for x in scope.get("from_ifs") or ()}
            to_ifs = {x["uid"] for x in scope.get("to_ifs") or ()}
            return "governs" if in_if in from_ifs and out_if in to_ifs else "excluded"
        bindings = [b for b in scope.get("bindings") or () if b.get("device") in (None, dev)]
        if bindings or scope.get("match_context") == "interface-acl":
            results = []
            for direction in ("in", "out"):
                names = sorted(
                    {str(b["name"]) for b in bindings if (b.get("direction") or "in") == direction}
                )
                if names:
                    results.append(_acl_governs_hop(direction, names, in_name, out_name))
            if "governs" in results:
                return "governs"
            return next((r for r in results if r != "excluded"), "excluded")
        if (
            dev in (scope.get("enforced") or ())
            and (scope.get("chain") or "forward") == "forward"
            and (scope.get("kind") or "access") == "access"
        ):
            return "governs"
        return "excluded"

    def covers(self, dev: str, in_if: str, out_if: str) -> bool:
        """Whether the rulebase scope of the rule covers traffic from `in_if` out `out_if`."""
        in_name = (self.interfaces.get(in_if) or {}).get("name")
        out_name = (self.interfaces.get(out_if) or {}).get("name")
        return self.governs(dev, in_if, out_if, in_name, out_name) != "excluded"

    def on_leg(self, dev: str, in_if: str, out_if: str, src: Ivals, dst: Ivals) -> tuple[str, str | None]:
        """What the rule does with these flows from `in_if` out `out_if`.

        The first item is "drops", "no" or "possible". With "no", the rule
        does not match the flows there, or an earlier rule decides them and
        the second item is that rule. With "possible", the second item is the
        reason it is not settled."""
        key = (dev, in_if, out_if, tuple(src), tuple(dst))
        if key in self._legs:
            return self._legs[key]
        in_name = (self.interfaces.get(in_if) or {}).get("name")
        out_name = (self.interfaces.get(out_if) or {}).get("name")
        answer: tuple[str, str | None]
        governed = self.governs(dev, in_if, out_if, in_name, out_name)
        match = (
            None
            if governed == "excluded"
            else _first_match(self.rules, in_name, out_name, src, dst, None, None)
        )
        if match is None:
            answer = ("no", None)
        else:
            decided, src_hit, dst_hit = cast("tuple[dict[str, Any], Ivals, Ivals]", match)
            partial = _size(src_hit) < _size(src) or _size(dst_hit) < _size(dst)
            if decided["uid"] != self.rule["uid"]:
                if classify_action(decided.get("action")) == INDETERMINATE:
                    answer = (
                        "possible",
                        f"rule {decided.get('pos')} comes first and is not decided: "
                        f"{decided.get('indeterminate_reason') or 'its action is not known'}",
                    )
                elif partial:
                    answer = ("possible", f"rule {decided.get('pos')} decides part of these flows first")
                else:
                    answer = ("no", f"rule {decided.get('pos')}")
            elif governed != "governs":
                answer = ("possible", governed)
            elif decided.get("indeterminate_reason"):
                answer = ("possible", str(decided["indeterminate_reason"]))
            elif partial:
                answer = ("possible", f"{self.label} matches only part of these flows")
            else:
                answer = ("drops", None)
        self._legs[key] = answer
        return answer

    # --- the analysis -------------------------------------------------------------------

    def device(self, dev: str, sources: Ivals, destinations: Ivals) -> None:
        pairs = [
            (str(row["pol_uid"]), str(row["if_uid"]))
            for row in _path._read(self.session, _DEVICE_PBR_POLICIES, dev=dev)
            if row.get("pol_uid") and row.get("if_uid")
        ]
        if not pairs:
            return
        rows = _path._read(self.session, _DEVICE_INTERFACES, dev=dev)
        if len(rows) > MAX_INTERFACES:
            self.open_reason(
                Missing(
                    code="analysis-cut",
                    subject=f"device {dev}",
                    detail=f"the device has more than {MAX_INTERFACES} interfaces; the others are not read",
                )
            )
        self.interfaces.update({str(row["uid"]): row for row in rows})
        by_policy: dict[str, list[dict[str, Any]]] = {}
        for row in _path._read(self.session, POLICY_RULES, pol_uids=sorted({pol for pol, _ in pairs})):
            if row.get("rule_uid"):
                by_policy.setdefault(str(row["pol_uid"]), []).append(row)
        for pol_uid, if_uid in sorted(set(pairs)):
            rows = by_policy.get(pol_uid)
            if not rows:
                continue
            default_uid = _default_table_uid(self.session, if_uid)
            groups = partition_rules(rows, sources, destinations, default_uid, service=(None, None, None))
            for group in groups:
                if not group.get("rule_uid") or not group.get("table_uid"):
                    continue
                if group["table_uid"] == default_uid:
                    continue
                if default_uid is None:
                    name = (self.interfaces.get(if_uid) or {}).get("name") or if_uid
                    self.note(
                        f"interface {name} names no routing table of its own, so its normal route "
                        "is not known"
                    )
                    continue
                self.claim(dev, if_uid, group, default_uid)

    def claim(self, dev: str, in_if: str, group: dict[str, Any], default_uid: str) -> None:
        """Find the parts of the destinations of one policy route claim that
        its table sends into a tunnel."""
        reasons: list[Missing] = []
        if group.get("opaque"):
            reasons.append(
                Missing(
                    code="policy-route-not-decided",
                    subject=f"policy route {group.get('pol_name')} rule {group.get('pos')}",
                    detail=str(group.get("opaque_reason") or "the policy route rule is not decided"),
                )
            )
        parts, cut = self.lookup(dev, group["table_uid"], group["dst"])
        if cut:
            # The cut destinations may go into a tunnel, and no record holds them.
            self.open_reason(cut[1])
        for part, winners in parts:
            # The RIB may send a part into a tunnel when the graph routes it
            # nowhere or to an interface without a tunnel.
            rib_missing = self.rib_reason(dev, group["table_uid"], winners)
            usable = [w for w in winners if not w.get("discard")]
            if not usable or len(usable) < len(winners):
                if rib_missing:
                    self.open_reason(rib_missing)
                continue
            egresses = [self.egress(dev, group["table_uid"], w, in_if) for w in usable]
            tunnels = {
                str(e["uid"]): e
                for e in egresses
                if e is not None and (self.interfaces.get(str(e["uid"])) or {}).get("tunnels")
            }
            if not tunnels:
                if rib_missing:
                    self.open_reason(rib_missing)
                continue
            part_reasons = list(reasons)
            if rib_missing:
                part_reasons.append(rib_missing)
            if len(tunnels) < len(usable):
                part_reasons.append(
                    Missing(
                        code="equal-cost-routes",
                        subject=f"table {group.get('table_name')}",
                        detail=f"routes {_describe(part)} by {len(usable)} equal-cost routes, not all of "
                        "them into the tunnel",
                    )
                )
            for tunnel_if in tunnels.values():
                self.tunnel_leg(dev, in_if, group, tunnel_if, part, default_uid, part_reasons)

    def tunnel_leg(
        self,
        dev: str,
        in_if: str,
        group: dict[str, Any],
        tunnel_if: dict[str, Any],
        dst: Ivals,
        default_uid: str,
        reasons: list[Missing],
    ) -> None:
        src = group["sources"]
        tunnel_uid = str(tunnel_if["uid"])
        tunnel_name = tunnel_if.get("name") or tunnel_uid
        state, why = self.on_leg(dev, in_if, tunnel_uid, src, dst)
        if state == "drops":
            self.note(
                f"{self.label} also drops these flows on the tunnel path out {tunnel_name}, so it does not "
                f"back up policy route {group.get('pol_name')} rule {group.get('pos')}"
            )
            return
        reasons = list(reasons)
        if state == "possible":
            reasons.append(
                Missing(
                    code="tunnel-path-not-decided",
                    subject=f"{self.label} on {tunnel_name}",
                    detail=f"the rule may also match the tunnel path: {why}",
                )
            )
        table = self.table(default_uid)
        claim = {
            "policy": {"uid": group.get("pol_uid"), "name": group.get("pol_name")},
            "rule": {
                "uid": group.get("rule_uid"),
                "position": group.get("pos"),
                "name": group.get("rule_name"),
            },
            "table": {"uid": group.get("table_uid"), "name": group.get("table_name")},
            "service": _service_text(group),
        }
        ingress = _iface(self.interfaces.get(in_if), in_if)
        parts, cut = self.lookup(dev, default_uid, dst)
        for part, winners in parts:
            rib_missing = self.rib_reason(dev, default_uid, winners)
            part_reasons = [*reasons, rib_missing] if rib_missing else reasons
            if not winners:
                if rib_missing:
                    # The RIB may hold a route that the graph lacks.
                    self.open_part(dev, src, part, tunnel_if, table, claim, ingress, part_reasons)
                    continue
                self.note(
                    f"table {table['name'] or default_uid} holds no route for {_describe(part)}; without the "
                    f"policy route these flows from {ingress['name'] or in_if} have no route"
                )
                continue
            if any(w.get("discard") for w in winners):
                if rib_missing:
                    self.open_part(dev, src, part, tunnel_if, table, claim, ingress, part_reasons)
                continue
            before = len(self.branches)
            self.normal_part(dev, in_if, src, part, winners, tunnel_if, table, claim, ingress, part_reasons)
            if rib_missing and len(self.branches) == before:
                self.open_part(dev, src, part, tunnel_if, table, claim, ingress, part_reasons)
        if cut:
            rest, reason = cut
            self.open_part(dev, src, rest, tunnel_if, table, claim, ingress, [*reasons, reason])

    def open_part(
        self,
        dev: str,
        src: Ivals,
        dst: Ivals,
        tunnel_if: dict[str, Any],
        table: dict[str, Any],
        claim: dict[str, Any],
        ingress: dict[str, Any],
        reasons: list[Missing],
    ) -> None:
        """Record a destination part whose normal exit is not known as a guard
        gap that is not decided. The gap has no exit and holds the reasons."""
        tunnel_uid = str(tunnel_if["uid"])
        row = self.interfaces.get(tunnel_uid) or {}
        self.branches.append(
            _Branch(
                kind="gap",
                decided=False,
                device=dev,
                tunnel_if={
                    **_iface(row or None, tunnel_uid),
                    "description": row.get("description"),
                    "tunnels": list(row.get("tunnels") or []),
                },
                claim=claim,
                ingress=ingress,
                sources=src,
                destinations=dst,
                table=table,
                breakout=[{"interface": None, "zones": [], "route": None, "next_hop": None}],
                reasons=list(reasons),
            )
        )

    def normal_part(
        self,
        dev: str,
        in_if: str,
        src: Ivals,
        dst: Ivals,
        winners: list[dict[str, Any]],
        tunnel_if: dict[str, Any],
        table: dict[str, Any],
        claim: dict[str, Any],
        ingress: dict[str, Any],
        reasons: list[Missing],
    ) -> None:
        """The normal routes of one destination part, and what the rule does
        on the interfaces they leave by."""
        tunnel_uid = str(tunnel_if["uid"])
        reasons = list(reasons)
        if len(winners) > 1:
            reasons.append(
                Missing(
                    code="equal-cost-routes",
                    subject=f"table {table['name']}",
                    detail=f"routes {_describe(dst)} by {len(winners)} equal-cost routes",
                )
            )
        dropped: list[dict[str, Any]] = []
        missed: list[dict[str, Any]] = []
        for route in winners:
            egress = self.egress(dev, table["uid"], route, in_if)
            if egress is None:
                via = f" via next hop {route['next_hop']}" if route.get("next_hop") else ""
                candidates = [
                    self.breakout(uid, route)
                    for uid in sorted(self.interfaces)
                    if uid not in (in_if, tunnel_uid) and self.on_leg(dev, in_if, uid, src, dst)[0] == "drops"
                ]
                subject = f"route {route['cidr']}{via} in table {table['name']}"
                if candidates:
                    names = ", ".join(str(c["interface"]["name"]) for c in candidates)
                    reasons.append(
                        Missing(
                            code="egress-not-resolved",
                            subject=subject,
                            detail=f"the route does not resolve to an interface; {self.label} drops these "
                            f"flows if they leave by {names}",
                        )
                    )
                    dropped.extend(candidates)
                else:
                    reasons.append(
                        Missing(
                            code="egress-not-resolved",
                            subject=subject,
                            detail=f"the route does not resolve to an interface, and {self.label} drops "
                            "these flows on no interface of the device",
                        )
                    )
                    missed.append(
                        {
                            "interface": None,
                            "zones": [],
                            "route": route["cidr"],
                            "next_hop": route.get("next_hop"),
                        }
                    )
                continue
            if str(egress["uid"]) in (in_if, tunnel_uid):
                continue
            if not self.covers(dev, in_if, str(egress["uid"])):
                # The rulebase scope does not cover this exit.
                continue
            state, why = self.on_leg(dev, in_if, str(egress["uid"]), src, dst)
            entry = self.breakout(str(egress["uid"]), route)
            if state == "no":
                if why:
                    entry["decided_by"] = why
                missed.append(entry)
                continue
            if why:
                reasons.append(Missing(code="rule-not-decided", subject=self.label, detail=why))
            dropped.append(entry)
        if not dropped and not missed:
            return
        decided = not reasons
        row = self.interfaces.get(tunnel_uid) or {}
        tunnel = {
            **_iface(row or None, tunnel_uid),
            "description": row.get("description"),
            "tunnels": list(row.get("tunnels") or []),
        }
        common: dict[str, Any] = {
            "device": dev,
            "tunnel_if": tunnel,
            "claim": claim,
            "ingress": ingress,
            "sources": src,
            "destinations": dst,
            "table": table,
        }
        if dropped and not missed:
            self.branches.append(
                _Branch(
                    kind="guard",
                    decided=decided,
                    breakout=dropped,
                    reasons=reasons,
                    **common,
                )
            )
            return
        if missed and not dropped:
            self.branches.append(
                _Branch(
                    kind="gap",
                    decided=decided,
                    breakout=missed,
                    reasons=reasons,
                    **common,
                )
            )
            return
        # The rule drops on some equal-cost routes only. The routes it does
        # not match give a gap. The guard on the other routes is not decided.
        names = ", ".join(str((m["interface"] or {}).get("name") or m["route"]) for m in missed)
        self.branches.append(
            _Branch(
                kind="guard",
                decided=False,
                breakout=dropped,
                reasons=[
                    *reasons,
                    Missing(
                        code="equal-cost-routes",
                        subject=f"table {table['name']}",
                        detail=f"the other equal-cost routes leave by {names}, which {self.label} does not "
                        "match",
                    ),
                ],
                **common,
            )
        )
        self.branches.append(
            _Branch(
                kind="gap",
                decided=decided,
                breakout=missed,
                reasons=reasons,
                **common,
            )
        )

    def breakout(self, uid: str, route: dict[str, Any]) -> dict[str, Any]:
        row = self.interfaces.get(uid)
        return {
            "interface": _iface(row, uid),
            "zones": list((row or {}).get("zones") or []),
            "route": route.get("cidr"),
            "next_hop": route.get("next_hop"),
        }

    # --- the answer ------------------------------------------------------------------------

    def findings(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        grouped: dict[tuple[str, str, str, bool], list[_Branch]] = {}
        for branch in self.branches:
            key = (branch.kind, branch.device, str(branch.tunnel_if["uid"]), branch.decided)
            grouped.setdefault(key, []).append(branch)
        rule_uids = sorted({str(b.claim["rule"]["uid"]) for b in self.branches})
        objects = netobjects.rule_side_objects(self.session, rule_uids) if rule_uids else {}
        guards: list[dict[str, Any]] = []
        gaps: list[dict[str, Any]] = []
        for (kind, dev, _tunnel, decided), branches in grouped.items():
            entry = self.finding(kind, dev, decided, branches, objects)
            (guards if kind == "guard" else gaps).append(entry)
        guards.sort(key=lambda e: (not e["decided"], str(e["tunnel"]["uid"])))
        gaps.sort(key=lambda e: (not e["decided"], str(e["tunnel"]["uid"])))
        for name, found in (("leak guards", guards), ("guard gaps", gaps)):
            if len(found) > MAX_FINDINGS:
                self.open_reason(
                    Missing(
                        code="analysis-cut",
                        subject=self.label,
                        detail=f"only the first {MAX_FINDINGS} of {len(found)} {name} are listed",
                    )
                )
        return guards[:MAX_FINDINGS], gaps[:MAX_FINDINGS]

    def finding(
        self,
        kind: str,
        dev: str,
        decided: bool,
        branches: list[_Branch],
        objects: dict[str, list[dict[str, Any]]],
    ) -> dict[str, Any]:
        """One record with the rule, the tunnel, the policy routes and hosts,
        the exits the rule covers or does not cover, and its line."""
        first = branches[0]
        routes: dict[tuple[Any, ...], dict[str, Any]] = {}
        sources: dict[str, dict[str, Any]] = {}
        breakout: dict[str, dict[str, Any]] = {}
        tables: dict[str, dict[str, Any]] = {}
        reasons: list[Missing] = []
        for b in branches:
            key = (b.claim["policy"]["uid"], b.claim["rule"]["uid"], b.ingress["uid"])
            routes.setdefault(key, {**b.claim, "ingress_interface": b.ingress})
            rule_uid = str(b.claim["rule"]["uid"])
            entries = netobjects.source_entries(
                objects.get(f"{rule_uid}:SRC", []), b.sources, str(b.claim["policy"]["uid"]), rule_uid
            ) or [{"address": n} for n in netobjects.networks(b.sources)]
            for item in entries:
                sources.setdefault(str(item["address"]), item)
            for out in b.breakout:
                breakout.setdefault(str((out["interface"] or {}).get("uid") or out["route"]), out)
            tables.setdefault(str(b.table["uid"]), b.table)
            reasons.extend(r for r in b.reasons if r not in reasons)
        source_set = _merge([i for b in branches for i in b.sources])
        destination_set = _merge([i for b in branches for i in b.destinations])
        destinations = netobjects.networks(destination_set)
        source_objects = list(
            {
                o["uid"]: {"uid": o["uid"], "name": o.get("name")}
                for b in branches
                for o in objects.get(f"{b.claim['rule']['uid']}:SRC", [])
                if any(item.get("object") == o["uid"] for item in sources.values())
            }.values()
        )
        hosts = list(sources)[:MAX_ADDRESSES]
        named = [out for out in breakout.values() if (out["interface"] or {}).get("name")]
        earlier: dict[str, set[str]] = {}
        for out in named:
            if out.get("decided_by"):
                earlier.setdefault(str(out["decided_by"]), set()).add(str(out["interface"]["name"]))
        exits = sorted({str(out["interface"]["name"]) for out in named if not out.get("decided_by")})
        covered = exits if kind == "guard" else []
        not_covered = exits if kind == "gap" else []
        position = self.rule.get("pos")
        parts = []
        if covered:
            parts.append(covered_line(covered, hosts, position))
        if not_covered:
            parts.append(not_covered_line(not_covered, hosts))
        parts.extend(decided_first_line(rule, sorted(names)) for rule, names in sorted(earlier.items()))
        tunnel_if = first.tunnel_if
        record: dict[str, Any] = {
            "kind": kind,
            "rule": self.rule["uid"],
            "device": dev,
            "tunnel": {
                "interface": tunnel_if["name"],
                "description": tunnel_if.get("description"),
                "uid": tunnel_if["uid"],
            },
            "policy_routes": list(dict.fromkeys(str(r["rule"]["uid"]) for r in routes.values())),
            "hosts": hosts,
            "host_objects": [str(o.get("name") or o["uid"]) for o in source_objects],
            "rule_exits": [str(self.rule["out_if"])] if self.rule.get("out_if") else [],
            "exits_covered": covered,
            "exits_not_covered": not_covered,
            "exits_decided_first": [
                {"rule": rule, "exits": sorted(names)} for rule, names in sorted(earlier.items())
            ],
            "decided": decided,
            "line": " ".join(parts),
            "detail": {
                "tunnels": tunnel_if.get("tunnels") or [],
                "policy_routes": list(routes.values()),
                "source_objects": source_objects,
                "sources": list(sources.values())[:MAX_ADDRESSES],
                "source_networks": netobjects.networks(source_set)[:MAX_ADDRESSES],
                "destinations": destinations[:MAX_ADDRESSES],
                "destinations_truncated": len(destinations) > MAX_ADDRESSES,
                "normal_tables": list(tables.values()),
                "breakout": list(breakout.values()),
            },
        }
        if not decided:
            record["missing"] = [m.model_dump(mode="json") for m in reasons[:MAX_NOTES]]
        return record


def _devices(scope: dict[str, Any]) -> list[str]:
    found = {x.get("device") for key in ("from_ifs", "to_ifs", "bindings") for x in scope.get(key) or ()}
    found.update(scope.get("enforced") or ())
    return sorted(str(d) for d in found if d)


def leak_guards(
    session: Any,
    rulebase_uid: str,
    rule_uid: str,
    af: int,
    rib: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    """The leak guard records of one rule.

    `leak_guards` holds the tunnels whose normal route leaves by an exit that
    the rule covers. `guard_gaps` holds the tunnels whose normal route leaves
    by an exit of the rulebase that the rule does not cover. The answer also
    has `notes`. Both lists are empty for a rule that does not drop, and for
    a rule whose devices have no policy route that steers into a tunnel.

    `rib` builds the side-store RIB reader of the route lookups. It is called
    once, when a lookup first needs the reader.

    A part whose RIB is not consulted, or whose routes or exits a cap cuts,
    is a guard gap that is not decided. A cap that cuts the analysis as a
    whole (devices, interfaces, the routes of the policy route table,
    findings) makes every record not decided. The answer has `missing`, the
    reasons, only in that case."""
    rules = _path._read(session, _RULEBASE_RULES, rb=rulebase_uid)
    rule = next((r for r in rules if r.get("uid") == rule_uid), None)
    empty: dict[str, Any] = {"leak_guards": [], "guard_gaps": [], "notes": []}
    if rule is None or classify_action(rule.get("action")) != DENY:
        return empty
    scope = _path._read_one(session, _RULEBASE_SCOPE, rb=rulebase_uid)
    if scope is None or scope.get("af") not in (None, af):
        return empty
    universe = _complement([], {af})
    sources, destinations = _rule_side(rule, "src", universe), _rule_side(rule, "dst", universe)
    if sources is None or destinations is None:
        return {
            **empty,
            "notes": [
                f"the addresses rule {rule.get('pos')} matches are not all modeled as address sets, so no "
                "leak guard is established for it"
            ],
        }
    if not sources or not destinations:
        return empty
    analysis = _Analysis(session, rule, rules, scope, rib)
    devices = _devices(scope)
    for dev in devices[:MAX_DEVICES]:
        analysis.device(dev, sources, destinations)
    if len(devices) > MAX_DEVICES:
        text = f"only the first {MAX_DEVICES} of {len(devices)} devices of the rulebase are analysed"
        analysis.note(text)
        analysis.open_reason(Missing(code="analysis-cut", subject=f"rule {rule.get('pos')}", detail=text))
    guards, gaps = analysis.findings()
    notes = analysis.notes
    if len(notes) > MAX_NOTES:
        notes = [*notes[: MAX_NOTES - 1], f"{len(notes) - MAX_NOTES + 1} more notes are not listed"]
    found: dict[str, Any] = {"leak_guards": guards, "guard_gaps": gaps, "notes": notes}
    if analysis.open:
        # The analysis is cut and no record is decided. `missing` of the
        # answer holds the reasons, also for an answer without a record.
        open_ = [m.model_dump(mode="json") for m in analysis.open]
        for record in (*guards, *gaps):
            record["decided"] = False
            own = [m for m in record.get("missing") or () if m not in open_]
            record["missing"] = [*open_, *own][:MAX_NOTES]
        found["missing"] = open_
    return found


def _written(ivals: Ivals, af: int) -> list[str] | str:
    found = netobjects.networks(ivals)
    return "any" if found == (["0.0.0.0/0"] if af == 4 else ["::/0"]) else found


def rule_facts(session: Any, rulebase_uid: str, rule_uid: str, af: int) -> dict[str, Any] | None:
    """The facts of one enabled rule for line 1 of a rule explanation.

    The facts are the action, the rulebase name and position, the device, the
    hosts and groups it matches, the destinations ("any" or the networks) and
    its exits. None when the rule is not an enabled rule of the rulebase or
    its addresses are not all modeled as address sets."""
    rules = _path._read(session, _RULEBASE_RULES, rb=rulebase_uid)
    rule = next((r for r in rules if r.get("uid") == rule_uid), None)
    scope = _path._read_one(session, _RULEBASE_SCOPE, rb=rulebase_uid)
    if rule is None or scope is None:
        return None
    universe = _complement([], {af})
    sources, destinations = _rule_side(rule, "src", universe), _rule_side(rule, "dst", universe)
    if sources is None or destinations is None:
        return None
    objects = netobjects.rule_side_objects(session, [rule_uid]).get(f"{rule_uid}:SRC", [])
    devices = _devices(scope)
    names = {str(row["uid"]): row.get("name") for row in _path._read(session, _DEVICE_NAMES, uids=devices)}
    return {
        "action": rule.get("action"),
        "hosts": _written(sources, af),
        "host_objects": [str(o["name"]) for o in objects if o.get("kind") == "group" and o.get("name")],
        "destinations": _written(destinations, af),
        "exits": [str(rule["out_if"])] if rule.get("out_if") else [],
        "device": (names.get(devices[0]) or devices[0]) if len(devices) == 1 else None,
        "rulebase": scope.get("name"),
        "position": rule.get("pos"),
    }
