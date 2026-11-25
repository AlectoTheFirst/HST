"""The ZPA brokered stage. Its identity and policy lookups precede any packet.

The lookups do not call into `trace.py`.

`_choose_segment` turns a caller-supplied uid or FQDN into the one
`ZpaAppSegment` uid to trace, or an undecided or blocked answer when several
segments list the FQDN.

`_segment_port_match` compares the requested port and proto with the
segment's own collected port ranges.

`_access_rule_match` reads the rules `FOR` a segment with their
`GRANTS|DENIES` edges and hands them to the first-match reader in
core/zpa_policy.py.

`_segment_resolution` walks a segment's `RESOLVES_TO` chain to a destination
address set.

`_connector_selection` and `_connector_address` pick a healthy connector
recorded via `SERVED_BY/USES/HAS` and read its own collected address.

The hop bookkeeping, the recursion into the connector's own device pipeline,
and the leg bookkeeping are in `trace.py`.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, NamedTuple

import hst.path as _path

from ...core import zpa_policy
from ..addrsets import _intersect, _intervals
from ..state import Effect, FlowRegion, Ivals, Rect

# --- segment reference resolution -------------------------------------------------------
# A caller supplies either a ZpaAppSegment uid directly, or one of the FQDNs
# the segment's own `domains` property lists.
# A uid matches one segment. Several segments can list a domain (ZPA accepts
# that when their ports differ). The query returns every one of them.
_SEGMENT_REF_QUERY = """
MATCH (seg:ZpaAppSegment:Obj)
WHERE NOT seg:Retired AND seg.collection_ts = $snap
  AND (seg.uid = $ref OR $ref IN coalesce(seg.domains, []))
RETURN seg.uid AS uid
ORDER BY seg.uid"""


# The properties of the segment and of its group that `zpa_policy.segment_state` reads.
_SEGMENT_STATE_QUERY = """
MATCH (seg:ZpaAppSegment {uid: $segment})
WHERE NOT seg:Retired AND seg:Obj AND seg.collection_ts = $snap
OPTIONAL MATCH (seg)-[m:MEMBER_OF]->(grp:ZpaSegmentGroup)
WHERE m._retired_at IS NULL AND NOT grp:Retired
RETURN seg.enabled AS enabled, seg.bypass_type AS bypass_type, grp.enabled AS group_enabled,
       true AS segment_state_row"""


def _segment_state(session: Any, segment_uid: str) -> str:
    """`zpa_policy.segment_state` of the segment in the pinned run."""
    return zpa_policy.segment_state(_path._read_one(session, _SEGMENT_STATE_QUERY, segment=segment_uid))


def _resolve_segment_refs(session: Any, ref: str) -> list[str]:
    """The ZpaAppSegment uids that match `ref`. The result is the one segment
    whose uid is `ref`, or else every segment that lists `ref` as a collected
    FQDN."""
    uids = [row["uid"] for row in _path._read(session, _SEGMENT_REF_QUERY, ref=ref)]
    return [ref] if ref in uids else uids


class SegmentChoice(NamedTuple):
    """The answer of `_choose_segment`. `uid` is the one segment to trace.
    `reason` is why no segment is traced. `blocking_uid` is set only when no
    segment that matches the reference can carry the flow."""

    uid: str | None
    reason: str | None
    blocking_uid: str | None


def _choose_segment(session: Any, ref: str, port: int | None, proto: str | None) -> SegmentChoice:
    """The segment a brokered trace follows for `ref`.

    One match is that segment. Its own state and ports are judged later.
    When several segments list the domain, the state and the published ports
    of each one are read. The flow is blocked if none can carry it (each
    disabled, or each publishing other ports). Otherwise the segment that ZPA
    brokers the flow through is not decided here, and the reason lists every
    segment."""
    uids = _resolve_segment_refs(session, ref)
    if not uids:
        return SegmentChoice(
            None, f"{ref}: no ZpaAppSegment matches this uid or a collected domain name", None
        )
    if len(uids) == 1:
        return SegmentChoice(uids[0], None, None)
    outcomes: list[str] = []
    open_ = False
    for uid in uids:
        state = _segment_state(session, uid)
        if state != "active":
            outcomes.append(zpa_policy.segment_state_reason(uid, state) or f"{uid}: {state}")
            open_ = open_ or state != "disabled"
            continue
        ports = _segment_port_match(session, uid, port, proto)
        if ports.matched or ports.indeterminate:
            open_ = True
            outcomes.append(ports.reason or f"{uid}: active and publishes the requested port")
        else:
            outcomes.append(ports.reason or f"{uid}: does not publish the requested port")
    listed = f"{ref} is listed by {len(uids)} segments ({', '.join(uids)})"
    if not open_:
        return SegmentChoice(
            None, f"{listed}, none of which carries this flow: " + "; ".join(outcomes), uids[0]
        )
    return SegmentChoice(
        None, f"{listed}; which one brokers this flow is not determined: " + "; ".join(outcomes), None
    )


# --- segment port ranges -----------------------------------------------------------------
# A segment publishes the ports it accepts. A broker does not intercept a
# flow to a port the segment does not publish. The request's port and proto
# are a dimension of the match.
# `collectors/zpa.py` stores `tcpPortRanges`/`udpPortRanges` verbatim, as the
# flattened from/to string pairs the API sends (`["443", "443"]`).
_SEGMENT_PORTS_QUERY = """
MATCH (seg:ZpaAppSegment {uid: $segment})
WHERE NOT seg:Retired AND seg:Obj AND seg.collection_ts = $snap
RETURN seg.tcp_port_ranges AS tcp, seg.udp_port_ranges AS udp"""


class PortMatch(NamedTuple):
    """The answer of `_segment_port_match`.

    `matched` False with `indeterminate` False is a decided no-match. The
    segment publishes ranges, and the requested port is outside every one of
    them. `indeterminate` True means the port could not be compared with the
    ranges.
    """

    matched: bool
    indeterminate: bool
    reason: str | None


def _port_ranges(flat: Any) -> list[tuple[int, int]] | None:
    """The from/to pairs a collected `*_port_ranges` property holds.

    The result is None when the value is not a list, has an odd number of
    entries, or has an entry that is not a number.
    """
    if not isinstance(flat, (list, tuple)) or len(flat) % 2 != 0:
        return None
    try:
        bounds = [int(str(v).strip()) for v in flat]
    except (TypeError, ValueError):
        return None
    return [(bounds[i], bounds[i + 1]) for i in range(0, len(bounds), 2)]


def _segment_port_match(session: Any, segment_uid: str, port: int | None, proto: str | None) -> PortMatch:
    """Whether `segment_uid` publishes `port` on `proto`.

    A call with no port or no proto is a match with no reason. Ranges that
    are not collected, or that are not readable as from/to pairs, are
    indeterminate, and the reason holds the segment uid. A port outside every
    collected range is a decided no-match, and the reason holds the segment
    uid and the port.
    """
    if port is None or not proto:
        return PortMatch(True, False, None)
    key = proto.strip().lower()
    if key not in ("tcp", "udp"):
        return PortMatch(
            False,
            True,
            f"{segment_uid} records port ranges for tcp and udp only; {proto} is not compared",
        )
    row = _path._read_one(session, _SEGMENT_PORTS_QUERY, segment=segment_uid)
    raw = (row or {}).get(key)
    if not raw:
        return PortMatch(False, True, f"{segment_uid} carries no collected {key} port ranges")
    ranges = _port_ranges(raw)
    if ranges is None:
        return PortMatch(
            False, True, f"{segment_uid}'s collected {key} port ranges are not readable as from/to pairs"
        )
    if any(lo <= port <= hi for lo, hi in ranges):
        return PortMatch(True, False, None)
    published = ", ".join(f"{lo}-{hi}" for lo, hi in ranges)
    return PortMatch(False, False, f"{segment_uid} does not publish {key}/{port} (published: {published})")


# --- identity group label ----------------------------------------------------------------
_IDENTITY_GROUP_QUERY = """
MATCH (i:IdentityGroup {uid: $identity})
WHERE NOT i:Retired AND i:Obj AND i.collection_ts = $snap
RETURN i.uid AS uid, i.name AS name"""


def _identity_group(session: Any, identity_uid: str) -> dict[str, Any] | None:
    return _path._read_one(session, _IDENTITY_GROUP_QUERY, identity=identity_uid)


# --- ZpaAccessRule first-match evaluator ------------------------------------------------
# The query returns every ZpaAccessRule that applies to the segment. A rule
# applies through a `FOR` edge to the segment or to its ZpaSegmentGroup
# (`MEMBER_OF`), or with `app_scope` `any` or `other` in the segment's `_scope`.
_ACCESS_RULE_QUERY = """
MATCH (seg:ZpaAppSegment {uid: $segment}) WHERE NOT seg:Retired AND seg:Obj AND seg.collection_ts = $snap
MATCH (r:ZpaAccessRule:Obj) WHERE NOT r:Retired AND r.collection_ts = $snap
WITH seg, r, EXISTS {
  MATCH (r)-[ef:FOR]->(target)
  WHERE ef._retired_at IS NULL AND NOT target:Retired AND target.collection_ts = $snap
    AND (
      target.uid = $segment
      OR EXISTS {
        MATCH (:ZpaAppSegment {uid: $segment})-[em:MEMBER_OF]->(target:ZpaSegmentGroup)
        WHERE em._retired_at IS NULL
      }
    )
} AS segment_named
WHERE segment_named OR (r.app_scope IN ['any', 'other'] AND r._scope = seg._scope)
OPTIONAL MATCH (r)-[eg:GRANTS|DENIES|APPLIES_TO]->(ig:IdentityGroup {uid: $identity})
WHERE ig:Obj AND ig.collection_ts = $snap AND eg._retired_at IS NULL
WITH r, segment_named, count(eg) > 0 AS identity_named
RETURN r.uid AS uid, r.name AS name, r.position AS position, r.action AS action,
       r.applies_to_all_identities AS applies_to_all_identities, r.conditions AS conditions,
       r.action_raw AS action_raw, r.operator AS operator, r.enabled AS enabled,
       r.disabled_raw AS disabled_raw, r.identity_scope AS identity_scope, r.app_scope AS app_scope,
       segment_named, identity_named
ORDER BY r.position, r.uid"""

# The rule shape check, the rule order and the first-match steps are in
# core/zpa_policy.py. trace.py imports the alias `_rule_label` from this module.
_rule_label = zpa_policy.rule_label


# The client forwarding rules that apply to the segment, in the shape of
# _ACCESS_RULE_QUERY. The query aliases `applies_to_all_identities` as
# `everyone`. The scripted test graph tells this query from the access rule
# query by that alias.
_FORWARDING_RULE_QUERY = """
MATCH (seg:ZpaAppSegment {uid: $segment}) WHERE NOT seg:Retired AND seg:Obj AND seg.collection_ts = $snap
MATCH (r:ZpaClientForwardingRule:Obj) WHERE NOT r:Retired AND r.collection_ts = $snap
WITH seg, r, EXISTS {
  MATCH (r)-[ef:FOR]->(target)
  WHERE ef._retired_at IS NULL AND NOT target:Retired
    AND (target.uid = $segment OR EXISTS {
      MATCH (:ZpaAppSegment {uid: $segment})-[em:MEMBER_OF]->(target:ZpaSegmentGroup)
      WHERE em._retired_at IS NULL
    })
} AS segment_named
WHERE segment_named OR (r.app_scope IN ['any', 'other'] AND r._scope = seg._scope)
OPTIONAL MATCH (r)-[ea:APPLIES_TO]->(ig:IdentityGroup {uid: $identity})
WHERE ig:Obj AND ig.collection_ts = $snap AND ea._retired_at IS NULL
WITH r, segment_named, count(ea) > 0 AS identity_named
RETURN r.uid AS uid, r.name AS name, r.position AS position, r.action AS action,
       r.applies_to_all_identities AS everyone, r.conditions AS conditions, r.action_raw AS action_raw,
       r.operator AS operator, r.enabled AS enabled, r.disabled_raw AS disabled_raw,
       r.identity_scope AS identity_scope, r.app_scope AS app_scope, segment_named, identity_named
ORDER BY r.position, r.uid"""


def _forwarding_match(session: Any, identity_uid: str, segment_uid: str) -> zpa_policy.ForwardingDecision:
    """The client forwarding decision for the identity and the segment."""
    rows = [
        {**r, "applies_to_all_identities": r.get("everyone")}
        for r in _path._read(session, _FORWARDING_RULE_QUERY, identity=identity_uid, segment=segment_uid)
    ]
    return zpa_policy.forwarding_decision(rows, identity_uid, segment_uid)


class AccessRuleDecision(NamedTuple):
    """`_access_rule_match`'s answer.

    `rule` is the winning row, drawn as the ACCESS_RULE hop whenever it is not
    None. `action` is
    "allow"/"deny" only when `indeterminate` is False.
    """

    rule: dict[str, Any] | None
    action: str | None
    indeterminate: bool
    reason: str | None


def _access_rule_match(session: Any, identity_uid: str, segment_uid: str) -> AccessRuleDecision:
    """First-match ZpaAccessRule evaluator. The winner has the lowest
    `position` among the enabled rules that apply to `segment_uid` and may
    match `identity_uid`. A rule applies through FOR (directly or via its
    ZpaSegmentGroup), or when its `app_scope` is `any` or `other` and it is in
    the segment's tenant.

    The steps and the reason texts are those of `zpa_policy.access_decision`.
    The result is indeterminate, with a reason, when no rule applies to the
    segment, when no rule matches this identity, when the winner is a negated,
    OR-joined, require_approval or unknown-disabled rule, when a candidate's
    position is not an integer, when several rules tie at the winning
    position, or when the winning rule's conditions have a shape that
    `zpa_policy` does not read.
    """
    rows = _path._read(session, _ACCESS_RULE_QUERY, identity=identity_uid, segment=segment_uid)
    decision = zpa_policy.access_decision(rows, identity_uid, segment_uid)
    return AccessRuleDecision(decision.rule, decision.action, decision.indeterminate, decision.reason)


# --- segment address resolution ---------------------------------------------------------
# One variable-length walk of at most 5 RESOLVES_TO hops from the
# ZpaAppSegment to an IpAddress or a Prefix. Every node between the two ends
# is a DnsRecord. `nodes(p)[1..-1]` is every node of the path except its two
# ends. It is empty for a segment that resolves directly to a Prefix.
_SEGMENT_RESOLUTION_QUERY = """
MATCH p = (sgm:ZpaAppSegment {uid: $segment})-[:RESOLVES_TO*1..5]->(resolved)
WHERE sgm:Obj AND sgm.collection_ts = $snap
  AND all(n IN nodes(p)[1..-1] WHERE n:DnsRecord AND NOT n:Retired)
  AND all(rel IN relationships(p) WHERE rel._retired_at IS NULL)
  AND (resolved:IpAddress OR resolved:Prefix)
  AND NOT resolved:Retired AND resolved.collection_ts = $snap
RETURN DISTINCT coalesce(resolved.ip, resolved.cidr) AS addr
ORDER BY addr"""


class SegmentResolution(NamedTuple):
    addresses: list[str]
    indeterminate: bool
    reason: str | None
    #: the domain entries no address was found for, when others resolved
    note: str | None = None


# The segment's own address entries and its FQDN entries, and the domains the
# RESOLVES_TO edges cover (an edge without `domain` covers every entry).
_SEGMENT_ENTRIES_QUERY = """
MATCH (seg:ZpaAppSegment {uid: $segment})
WHERE NOT seg:Retired AND seg:Obj AND seg.collection_ts = $snap
OPTIONAL MATCH (seg)-[r:RESOLVES_TO]->()
WHERE r._retired_at IS NULL
RETURN seg.ranges AS ranges, seg.domains AS domains, seg.opaque_reason AS opaque_reason,
       collect(r.domain) AS covered, count(r) AS edges"""


def _segment_resolution(session: Any, segment_uid: str) -> SegmentResolution:
    """The destination address set `segment_uid` resolves to via RESOLVES_TO.

    The result is indeterminate, with the segment uid in the reason, when
    the chain and the segment's own `ranges` give no address.
    """
    rows = _path._read(session, _SEGMENT_RESOLUTION_QUERY, segment=segment_uid)
    addrs = [r["addr"] for r in rows if r.get("addr")]
    entries = _path._read_one(session, _SEGMENT_ENTRIES_QUERY, segment=segment_uid) or {}
    addrs += [a for a in entries.get("ranges") or [] if a not in addrs]
    if not addrs:
        return SegmentResolution([], True, f"{segment_uid} has no RESOLVES_TO edge to a resolvable address")
    covered = set(entries.get("covered") or [])
    # collect() drops a null domain. An edge without `domain` covers every entry.
    every = (entries.get("edges") or 0) > len(entries.get("covered") or [])
    left = (
        []
        if every
        else [
            str(e)
            for e in entries.get("domains") or []
            if str(e) not in covered and not str(e).startswith("*") and not _is_address(str(e))
        ]
    )
    notes = []
    if left:
        notes.append(
            f"{segment_uid}: no address is recorded for {', '.join(left)}; the other destinations are walked"
        )
    if entries.get("opaque_reason"):
        notes.append(f"{segment_uid}: {entries['opaque_reason']}")
    return SegmentResolution(addrs, False, None, "; ".join(notes) or None)


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False
    return True


# --- connector selection -----------------------------------------------------------------
# `(ZpaAppSegment)-[:SERVED_BY]->(ZpaServerGroup)-[:USES]->(ZpaAppConnectorGroup)-[:HAS]->
# (ZpaAppConnector)`. The same connector can be on more than one such chain.
_CONNECTOR_QUERY = """
MATCH (sgm:ZpaAppSegment {uid: $segment})-[es:SERVED_BY]->(sg:ZpaServerGroup)
WHERE sgm:Obj AND sgm.collection_ts = $snap
  AND es._retired_at IS NULL AND NOT sg:Retired AND sg.collection_ts = $snap
MATCH (sg)-[eu:USES]->(cg:ZpaAppConnectorGroup)
WHERE eu._retired_at IS NULL AND NOT cg:Retired AND cg.collection_ts = $snap
MATCH (cg)-[eh:HAS]->(conn:ZpaAppConnector)
WHERE eh._retired_at IS NULL AND NOT conn:Retired AND conn.collection_ts = $snap
RETURN DISTINCT conn.uid AS uid, conn.name AS name, conn.health AS health, conn.enabled AS enabled,
       cg.uid AS group_uid, cg.enabled AS group_enabled, sg.uid AS server_group_uid,
       sg.enabled AS server_group_enabled
ORDER BY conn.uid"""

# The connector and server groups a winning access rule names (STEERS_VIA).
_RULE_STEERING_QUERY = """
MATCH (r:ZpaAccessRule {uid: $rule})-[e:STEERS_VIA]->(g)
WHERE r:Obj AND r.collection_ts = $snap AND e._retired_at IS NULL AND NOT g:Retired
  AND (g:ZpaAppConnectorGroup OR g:ZpaServerGroup)
RETURN g.uid AS steering_uid"""


def _connector_rows(session: Any, segment_uid: str, rule_uid: str | None = None) -> list[dict[str, Any]]:
    """The connectors that can serve the segment, once each. A connector in a
    disabled connector group or server group is left out. When the winning
    rule has STEERS_VIA groups, only the connectors in those groups stay."""
    rows = _path._read(session, _CONNECTOR_QUERY, segment=segment_uid)
    rows = [
        r for r in rows if r.get("group_enabled") is not False and r.get("server_group_enabled") is not False
    ]
    if rule_uid:
        named = {r["steering_uid"] for r in _path._read(session, _RULE_STEERING_QUERY, rule=rule_uid)}
        if named:
            rows = [r for r in rows if r.get("group_uid") in named or r.get("server_group_uid") in named]
    seen: dict[str, dict[str, Any]] = {}
    for r in rows:
        seen.setdefault(r["uid"], r)
    return list(seen.values())


# The ZpaAppConnector.health vocabulary.
# collectors/zpa.py writes `health` through CONNECTOR_HEALTH as `up` or `down`,
# and writes none for any other control channel status. The other words in
# these sets come from hand-built rows (fixtures and tests). A collected value
# outside this set is read as healthy. A connector with no collected health is
# not a candidate.
_UNHEALTHY_CONNECTOR_STATES = frozenset({"down", "unhealthy", "offline", "degraded"})
_STRICT_HEALTHY_CONNECTOR_STATES = frozenset({"up", "healthy"})
_STRICT_DOWN_CONNECTOR_STATES = frozenset({"down", "unhealthy"})


class ConnectorSelection(NamedTuple):
    """The answer of `_connector_selection`. An indistinguishable set of
    connectors collapses to one indeterminate leg.

    `alternates` are the other healthy candidates the pick passed over and
    `no_health` the candidates with no collected health.
    """

    chosen: dict[str, Any] | None
    collapsed: bool
    note: str | None
    alternates: tuple[dict[str, Any], ...]
    no_health: tuple[dict[str, Any], ...]
    #: True when every connector that could serve is disabled. `ZpaTransition`
    #: reads it as a deny whose reason lists the connectors.
    all_disabled: bool = False


def _connector_names(rows: list[dict[str, Any]]) -> str:
    return ", ".join(r.get("name") or r["uid"] for r in rows)


def _connector_selection(session: Any, segment_uid: str, rule_uid: str | None = None) -> ConnectorSelection:
    """The healthy connector to originate the flow from, or a collapse with a note.

    A candidate set where no connector has collected health collapses, and
    the note lists every candidate. Where a candidate has collected health,
    only the connectors that report healthy are candidates. Of more than one
    healthy connector the first by uid is chosen, and the rest are returned
    as alternates.
    """
    rows = _connector_rows(session, segment_uid, rule_uid)
    if not rows:
        return ConnectorSelection(
            None, True, f"no connector is recorded for {segment_uid} via SERVED_BY/USES/HAS", (), ()
        )
    # `enabled` is configuration. A disabled connector cannot serve with any
    # collected health.
    disabled = [r for r in rows if r.get("enabled") is False]
    rows = [r for r in rows if r.get("enabled") is not False]
    if not rows:
        return ConnectorSelection(
            None,
            True,
            f"every connector of {segment_uid} is disabled ({_connector_names(disabled)})",
            (),
            (),
            all_disabled=True,
        )
    no_health = tuple(r for r in rows if r.get("health") is None)
    if len(no_health) == len(rows):
        return ConnectorSelection(
            None,
            True,
            f"no connector of {segment_uid} carries collected health state ({_connector_names(rows)})",
            (),
            no_health,
        )
    healthy = [
        r
        for r in rows
        if r.get("health") is not None and str(r["health"]).strip().lower() not in _UNHEALTHY_CONNECTOR_STATES
    ]
    if not healthy:
        return ConnectorSelection(
            None,
            True,
            f"no connector of {segment_uid} reports healthy ({_connector_names(rows)})",
            (),
            no_health,
        )
    return ConnectorSelection(healthy[0], False, None, tuple(healthy[1:]), no_health)


# --- connector address --------------------------------------------------------------------
# The connector gets its address through RUNS_ON to a Vm or Instance. The
# address is the HAS_IP address of a Vnic or Nic of that host.
_CONNECTOR_ADDRESS_QUERY = """
MATCH (cn:ZpaAppConnector {uid: $connector})-[er:RUNS_ON]->(host)
WHERE cn:Obj AND cn.collection_ts = $snap
  AND er._retired_at IS NULL AND NOT host:Retired AND host.collection_ts = $snap
OPTIONAL MATCH (host)<-[eo:OF]-(nic)-[eh:HAS_IP]->(ip:IpAddress)
WHERE eo._retired_at IS NULL AND eh._retired_at IS NULL AND NOT ip:Retired
  AND ip.collection_ts = $snap
RETURN host.uid AS host_uid, ip.ip AS ip
ORDER BY ip.ip"""

# The reasoner's `zpa-zia-ip-same-as` link from the connector's own collected
# `private_ip` to a campus address. The query is read only when the caller
# asks for it and RUNS_ON gave no address.
_CONNECTOR_SAME_AS_ADDRESS_QUERY = """
MATCH (cn:ZpaAppConnector {uid: $connector})-[sa:SAME_AS {basis: 'private_ip'}]->(ip:IpAddress)
WHERE cn:Obj AND cn.collection_ts = $snap
  AND sa._retired_at IS NULL AND NOT ip:Retired AND ip.collection_ts = $snap
RETURN DISTINCT ip.ip AS ip, sa.confidence AS confidence
ORDER BY ip.ip"""


class ConnectorAddress(NamedTuple):
    """`_connector_address`'s answer.

    `alternates` are the connector's other collected addresses, in query
    order. `same_as_confidence` is set only when the address came from a
    `SAME_AS` link.
    """

    ip: str | None
    reason: str | None
    alternates: tuple[str, ...]
    same_as_confidence: float | None = None
    #: "private_ip" when the address is the connector's own collected
    #: private_ip. That address is used when no RUNS_ON target gives one.
    basis: str | None = None


# The connector's own collected private address.
_CONNECTOR_PRIVATE_IP_QUERY = """
MATCH (conn:ZpaAppConnector {uid: $connector})
WHERE NOT conn:Retired AND conn:Obj AND conn.collection_ts = $snap AND conn.private_ip IS NOT NULL
RETURN conn.private_ip AS private_ip"""


def _connector_address(session: Any, connector_uid: str, *, follow_same_as: bool = False) -> ConnectorAddress:
    """The connector's own collected address, or the reason it has none.

    With `follow_same_as`, a connector whose RUNS_ON target gives no address is
    read through its `SAME_AS` link. The link joins on the address value
    only. The caller handles an address that the campus holds in several
    forwarding contexts, as for a RUNS_ON address.
    """
    rows = _path._read(session, _CONNECTOR_ADDRESS_QUERY, connector=connector_uid)
    if follow_same_as and not any(r.get("ip") for r in rows):
        linked = _path._read(session, _CONNECTOR_SAME_AS_ADDRESS_QUERY, connector=connector_uid)
        if linked:
            return ConnectorAddress(
                str(linked[0]["ip"]),
                None,
                tuple(str(r["ip"]) for r in linked[1:]),
                linked[0].get("confidence"),
            )
    with_ip = [str(r["ip"]) for r in rows if r.get("ip")]
    if with_ip:
        return ConnectorAddress(with_ip[0], None, tuple(with_ip[1:]))
    own = _path._read_one(session, _CONNECTOR_PRIVATE_IP_QUERY, connector=connector_uid)
    if own and own.get("private_ip"):
        return ConnectorAddress(str(own["private_ip"]), None, (), basis="private_ip")
    if not rows:
        return ConnectorAddress(None, f"{connector_uid} has no RUNS_ON target and no private_ip", ())
    return ConnectorAddress(None, f"{connector_uid}'s RUNS_ON target carries no collected IP address", ())


# --- the brokered stage as a transition ---------------------------------------------

_PROTO_KEYS = {6: "tcp", 17: "udp"}


def _segment_port_regions(
    session: Any, segment_uid: str, rect: Rect
) -> tuple[list[Rect], list[Rect], str | None]:
    """`_segment_port_match` over one rectangle. The result is the parts that
    the segment publishes, the parts that it does not publish, and a reason
    when the ranges cannot be read. The published parts are one per protocol,
    as tcp and udp have separate ranges.

    A rectangle with no port or no protocol is returned whole as published. A
    protocol other than tcp or udp in the rectangle's set cannot be compared.
    It leaves the rectangle undecided, and the reason holds the protocol.
    """
    if rect.dport is None or rect.proto is None:
        return [rect], [], None
    others = sorted(rect.proto - set(_PROTO_KEYS))
    if others:
        return [], [], f"{segment_uid} records port ranges for tcp and udp only; {others[0]} is not compared"
    row = _path._read_one(session, _SEGMENT_PORTS_QUERY, segment=segment_uid)
    published: list[Rect] = []
    unpublished: list[Rect] = []
    for number in sorted(rect.proto):
        key = _PROTO_KEYS[number]
        raw = (row or {}).get(key)
        if not raw:
            return [], [], f"{segment_uid} carries no collected {key} port ranges"
        ranges = _port_ranges(raw)
        if ranges is None:
            return [], [], f"{segment_uid}'s collected {key} port ranges are not readable as from/to pairs"
        want: Ivals = tuple((0, lo, hi) for lo, hi in ranges)
        inside = tuple(_intersect(list(rect.dport), list(want)))
        one = rect.narrow(proto=frozenset({number}))
        if inside:
            published.append(one.narrow(dport=inside))
        for rest in one.subtract(one.narrow(dport=inside)) if inside else [one]:
            unpublished.append(rest)
    return published, unpublished, None


@dataclass
class ZpaTransition:
    """The ZPA brokered stage over a `FlowRegion`. The identity half runs
    first, then the broker half.

    The identity half applies the access policy. The segment's published
    ports decide whether the flow is brokered (`_segment_port_regions`). Then
    the first-match access rule for this identity and segment
    (`_access_rule_match`) permits or denies the flow. The broker half
    relates the permitted part to the connector-originated connection by
    `Rect.rewrite`, with the client's request as the origin. The source is
    the chosen connector's own address, the destination is the segment's
    resolved address set, and the source port is unset. Every dimension that
    cannot be decided is an `indeterminate` effect with the reason. A deny
    and an unpublished port are terminal effects whose `blocking_uid` is the
    object that decided.
    """

    session: Any
    identity_uid: str
    segment_uid: str
    all_connectors: bool = False

    def apply(self, region: FlowRegion) -> list[tuple[FlowRegion, Effect]]:
        out: list[tuple[FlowRegion, Effect]] = []
        for rect in region:
            if self.all_connectors and (rect.proto is None or rect.dport is None):
                out.append(
                    (
                        FlowRegion.single(rect),
                        Effect(
                            "indeterminate",
                            "zpa",
                            unknown=frozenset(d for d in ("proto", "dport") if getattr(rect, d) is None),
                            reason="strict segment service evaluation requires protocol and destination port",
                        ),
                    )
                )
                continue
            state = _segment_state(self.session, self.segment_uid)
            if state != "active":
                why = zpa_policy.segment_state_reason(self.segment_uid, state)
                if state == "disabled":
                    effect = Effect(
                        "deny", "zpa", terminal=True, reason=why, data={"blocking_uid": self.segment_uid}
                    )
                else:
                    effect = Effect("indeterminate", "zpa", reason=why)
                out.append((FlowRegion.single(rect), effect))
                continue
            published, unpublished, reason = _segment_port_regions(self.session, self.segment_uid, rect)
            if reason:
                out.append((FlowRegion.single(rect), Effect("indeterminate", "zpa", reason=reason)))
                continue
            for r in unpublished:
                out.append(
                    (
                        FlowRegion.single(r),
                        Effect(
                            "deny",
                            "zpa",
                            terminal=True,
                            reason=f"{self.segment_uid} does not publish this port",
                            data={"blocking_uid": self.segment_uid},
                        ),
                    )
                )
            if not published:
                continue
            forwarding = _forwarding_match(self.session, self.identity_uid, self.segment_uid)
            if not forwarding.go_on:
                reason = (
                    forwarding.reason or f"{self.segment_uid}: the client forwarding match is not determined"
                )
                for r in published:
                    out.append((FlowRegion.single(r), Effect("indeterminate", "zpa", reason=reason)))
                continue
            decision = _access_rule_match(self.session, self.identity_uid, self.segment_uid)
            for r in published:
                out.extend(self._broker(r, decision))
        return out

    def _broker(self, rect: Rect, decision: AccessRuleDecision) -> list[tuple[FlowRegion, Effect]]:
        unknown = frozenset(d for d in ("proto", "dport") if getattr(rect, d) is None)
        if decision.indeterminate or decision.rule is None:
            reason = decision.reason or f"{self.segment_uid}: the access rule match is not determined"
            return [(FlowRegion.single(rect), Effect("indeterminate", "zpa", unknown=unknown, reason=reason))]
        rule = decision.rule
        if decision.action == "deny":
            return [
                (
                    FlowRegion.single(rect),
                    Effect(
                        "deny",
                        "zpa",
                        terminal=True,
                        reason=f"{_rule_label(rule)}: denied",
                        data={"rule": rule, "blocking_uid": rule["uid"]},
                    ),
                )
            ]
        resolution = _segment_resolution(self.session, self.segment_uid)
        if resolution.indeterminate:
            reason = resolution.reason or f"{self.segment_uid}: destination address not determined"
            return [(FlowRegion.single(rect), Effect("indeterminate", "zpa", unknown=unknown, reason=reason))]
        if self.all_connectors:
            return self._broker_all(rect, rule, resolution.addresses, unknown)
        selection = _connector_selection(self.session, self.segment_uid, rule["uid"])
        if selection.all_disabled:
            return [
                (
                    FlowRegion.single(rect),
                    Effect(
                        "deny",
                        "zpa",
                        terminal=True,
                        reason=selection.note or f"every connector of {self.segment_uid} is disabled",
                        data={"rule": rule, "blocking_uid": self.segment_uid},
                    ),
                )
            ]
        if selection.collapsed or selection.chosen is None:
            reason = selection.note or f"{self.segment_uid}: no connector determined"
            return [(FlowRegion.single(rect), Effect("indeterminate", "zpa", unknown=unknown, reason=reason))]
        addr = _connector_address(self.session, selection.chosen["uid"])
        if not addr.ip:
            reason = addr.reason or f"{selection.chosen['uid']}: no collected address"
            return [(FlowRegion.single(rect), Effect("indeterminate", "zpa", unknown=unknown, reason=reason))]
        brokered = rect.rewrite(
            src=tuple(_intervals([addr.ip])), dst=tuple(_intervals(resolution.addresses)), sport=None
        )
        return [
            (
                FlowRegion.single(brokered),
                Effect(
                    "broker",
                    "zpa",
                    unknown=unknown,
                    data={"rule": rule, "connector": selection.chosen, "address": addr.ip},
                ),
            )
        ]

    def _broker_all(
        self,
        rect: Rect,
        rule: dict[str, Any],
        destinations: list[str],
        unknown: frozenset[str],
    ) -> list[tuple[FlowRegion, Effect]]:
        connectors = _connector_rows(self.session, self.segment_uid, rule.get("uid"))
        if not connectors:
            return [
                (
                    FlowRegion.single(rect),
                    Effect("indeterminate", "zpa", reason="no connector inventory is recorded"),
                )
            ]
        healthy = []
        unknown_health = []
        down = []
        disabled = []
        for connector in connectors:
            health = str(connector.get("health") or "").strip().lower()
            if connector.get("enabled") is False:
                disabled.append(connector)
            elif health in _STRICT_HEALTHY_CONNECTOR_STATES:
                healthy.append(connector)
            elif health in _STRICT_DOWN_CONNECTOR_STATES:
                down.append(connector)
            else:
                unknown_health.append(connector)
        if (down or disabled) and not healthy and not unknown_health:
            if disabled and not down:
                why = f"every connector of {self.segment_uid} is disabled ({_connector_names(disabled)})"
            elif down and not disabled:
                why = f"every recorded connector is down ({_connector_names(down)})"
            else:
                why = (
                    f"every recorded connector is down ({_connector_names(down)}) "
                    f"or disabled ({_connector_names(disabled)})"
                )
            return [
                (
                    FlowRegion.single(rect),
                    Effect("deny", "zpa", terminal=True, reason=why, data={"blocking_uid": self.segment_uid}),
                )
            ]
        out: list[tuple[FlowRegion, Effect]] = []
        for connector in unknown_health:
            out.append(
                (
                    FlowRegion.single(rect),
                    Effect(
                        "indeterminate",
                        "zpa",
                        unknown=unknown,
                        reason=f"{connector.get('name') or connector['uid']} health is not recognized",
                        data={"rule": rule, "connector": connector},
                    ),
                )
            )
        for connector in healthy:
            address = _connector_address(self.session, connector["uid"])
            addresses = ([address.ip] if address.ip else []) + list(address.alternates)
            if not addresses:
                out.append(
                    (
                        FlowRegion.single(rect),
                        Effect(
                            "indeterminate",
                            "zpa",
                            reason=address.reason,
                            data={"rule": rule, "connector": connector},
                        ),
                    )
                )
                continue
            for connector_ip in addresses:
                for destination in destinations:
                    brokered = rect.rewrite(
                        src=tuple(_intervals([connector_ip])),
                        dst=tuple(_intervals([destination])),
                        sport=None,
                    )
                    out.append(
                        (
                            FlowRegion.single(brokered),
                            Effect(
                                "broker",
                                "zpa",
                                unknown=unknown,
                                data={
                                    "rule": rule,
                                    "connector": connector,
                                    "address": connector_ip,
                                    "destination": destination,
                                },
                            ),
                        )
                    )
        return out
