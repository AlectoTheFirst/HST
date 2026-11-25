"""The address objects of firewall and policy route rules, read at one run.

A rule matches on NetObject nodes. A NetObject has RESOLVES_TO edges to the
IpAddress, Prefix and DnsRecord nodes of the closure of its members, and a
`ranges` property. The reads list the objects of each rule side and their
addresses. `source_entries` writes the part of the addresses inside an address
set as concrete addresses. An entry has the uid of the graph node that covers
it, if one does.

`policy_route_sources` (applications/generator_tools.py) and the leak guard
analysis of `policy_evaluate` (path/leak_guard.py) use them. The interval
arithmetic is `path.addrsets`.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from typing import Any

import hst.path as _path

from .addrsets import _intersect, _rule_intervals, _subtract, _to_cidrs

Ivals = list[tuple[int, int, int]]
# the address objects of each rule side, keyed `<rule uid>:SRC` or `<rule uid>:DST`
SideObjects = Mapping[str, Sequence[Mapping[str, Any]]]


def _alive(*names: str) -> str:
    return " AND ".join(f"{n}.collection_ts = $snap AND NOT {n}:Retired" for n in names)


def _current(*names: str) -> str:
    return " AND ".join(f"{n}.collection_ts = $snap AND {n}._retired_at IS NULL" for n in names)


# The 2 queries hold the run guard as literal text. The scan in
# tests/test_time_travel.py reads the query text.
#
# The IpAddress, Prefix and DnsRecord targets of each address object, and its
# `ranges`. A group has a RESOLVES_TO edge to each target of the closure of
# its members.
NET_OBJECTS = """
MATCH (o:NetObject)
WHERE o.uid IN $uids AND o:Obj AND o.collection_ts = $snap AND NOT o:Retired
OPTIONAL MATCH (o)-[r:RESOLVES_TO]->(t:Obj)
WHERE t.collection_ts = $snap AND NOT t:Retired AND r.collection_ts = $snap AND r._retired_at IS NULL
WITH o, [x IN collect(DISTINCT {uid: t.uid, labels: labels(t), ip: t.ip, cidr: t.cidr})
         WHERE x.uid IS NOT NULL] AS targets
RETURN o.uid AS uid, o.name AS name, o.kind AS kind, o.ranges AS ranges,
       coalesce(o.opaque, false) AS opaque, o.opaque_reason AS opaque_reason, targets
ORDER BY uid"""

# The address objects each rule matches on its source and destination side.
RULE_OBJECTS = """
MATCH (r:FwRule)-[e:SRC|DST]->(o:NetObject)
WHERE r.uid IN $rules AND r:Obj AND r.collection_ts = $snap AND NOT r:Retired
  AND o.collection_ts = $snap AND NOT o:Retired
  AND e.collection_ts = $snap AND e._retired_at IS NULL
RETURN r.uid AS rule_uid, type(e) AS side, o.uid AS uid
ORDER BY rule_uid, side, uid"""


def address(text: str) -> str:
    """`text` as a member address. A host address is written without its mask.
    A prefix is written as a prefix."""
    network = ipaddress.ip_network(text, strict=False)
    return str(network.network_address) if network.num_addresses == 1 else str(network)


def networks(intervals: Ivals) -> list[str]:
    """The smallest list of prefixes that covers an address interval set,
    each written as `address` writes it."""
    return [address(cidr) for cidr in _to_cidrs(intervals)]


def target_label(labels: list[str]) -> str | None:
    return next((label for label in ("IpAddress", "Prefix", "DnsRecord") if label in labels), None)


def target_intervals(target: Mapping[str, Any]) -> Ivals:
    """The addresses of one RESOLVES_TO target, read as the trace reads the
    `st.cidr`/`st.ip` columns of a rule row."""
    return _rule_intervals([target.get("cidr")], [target.get("ip")], [])


def range_intervals(spec: str) -> Ivals:
    return _rule_intervals([], [], [[spec]])


def side_intervals(row: Mapping[str, Any], side: str) -> Ivals:
    """A rule row's source (`src`) or destination (`dst`) set, as
    `partition_rules` reads it."""
    return _rule_intervals(
        row.get(f"{side}_cidrs") or [], row.get(f"{side}_ips") or [], row.get(f"{side}_ranges") or []
    )


def net_objects(session: Any, uids: list[str]) -> dict[str, dict[str, Any]]:
    """The address objects `uids`, each with its targets in uid order."""
    if not uids:
        return {}
    rows = _path._read(session, NET_OBJECTS, uids=sorted(set(uids)))
    return {
        str(row["uid"]): {**row, "targets": sorted(row.get("targets") or [], key=lambda t: str(t["uid"]))}
        for row in rows
    }


def rule_side_objects(session: Any, rule_uids: list[str]) -> dict[str, list[dict[str, Any]]]:
    """The address objects of each side of the rules `rule_uids`, keyed
    `<rule uid>:SRC` and `<rule uid>:DST`. An object the run does not hold
    is kept as its uid alone."""
    side_objects: dict[str, list[str]] = {}
    for row in _path._read(session, RULE_OBJECTS, rules=rule_uids) if rule_uids else []:
        side_objects.setdefault(f"{row['rule_uid']}:{row['side']}", []).append(str(row["uid"]))
    found = net_objects(session, [uid for uids in side_objects.values() for uid in uids])
    return {key: [found.get(uid, {"uid": uid}) for uid in uids] for key, uids in side_objects.items()}


def source_entries(
    objects: Sequence[Mapping[str, Any]], effective: Ivals, pol_uid: str, rule_uid: str
) -> list[dict[str, Any]]:
    """The concrete source addresses of a rule within `effective`, the source
    set that the rule decides after the earlier rules of its policy. An
    IpAddress or Prefix node wholly inside `effective` keeps its uid. The part
    of a node or of a range inside `effective` is written as the smallest list
    of prefixes, without a uid."""
    entries: dict[tuple[str, str | None], dict[str, Any]] = {}
    for obj in objects:
        for target in obj.get("targets") or []:
            own = target_intervals(target)
            inside = _intersect(own, effective)
            if not inside:
                continue
            written = address(str(target.get("ip") or target.get("cidr")))
            if not _subtract(own, effective):
                key = (written, target["uid"])
                entries.setdefault(
                    key,
                    {
                        "address": written,
                        "uid": target["uid"],
                        "label": target_label(list(target.get("labels") or [])),
                        "object": obj["uid"],
                        "chain": [
                            {"from": pol_uid, "rel": "HAS_RULE", "to": rule_uid},
                            {"from": rule_uid, "rel": "SRC", "to": obj["uid"]},
                            {"from": obj["uid"], "rel": "RESOLVES_TO", "to": target["uid"]},
                        ],
                    },
                )
                continue
            for network in networks(inside):
                entries.setdefault(
                    (network, None), {"address": network, "object": obj["uid"], "part_of": written}
                )
        for spec in obj.get("ranges") or []:
            for network in networks(_intersect(range_intervals(str(spec)), effective)):
                entries.setdefault((network, None), {"address": network, "object": obj["uid"], "range": spec})
    return list(entries.values())
