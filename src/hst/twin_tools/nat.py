"""The NAT lookup tool `policy_lookup_nat`.

The tool lists the NAT rules of one run whose original columns (source and
destination) or translated columns name an address. It reads every enabled
rule of the NAT rulebases, with the objects of its `ORIG_SRC`, `ORIG_DST`,
`XLATE_SRC` and `XLATE_DST` columns and the addresses those objects resolve
to, and matches the address in Python.

A column is read as the NAT gate of the path engine reads it. The raw
configured value, which can hold ranges and negation, is used when it parses
as addresses (`gates.nat._nat_match_set`). Otherwise the objects of the column
give its addresses. The translation value of a rule belongs to its
translated destination for a destination rule and to its translated source
for a source rule (`gates.nat._nat_rule_kind`). The translation of a static
rule belongs to its translated source when the rule has a translated-source
object, and to its translated destination otherwise, as in
`_nat_stage_rules` of the gate. A column that states no address (any, the
original packet, or the address of an interface in a masquerade or interface
overload rule) matches no address.

The match of a rule whose objects all resolve and which is not approximate is
decided. An opaque object, an object that resolves to no address, a column
value that is not an address, or an approximate rule or rulebase leaves the
match not decided, with a gap. A rule is also not decided when the address is
not in the resolved part of a column and that column holds an unresolved
object.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from hst import path as pathmod
from hst.app.ai.registry import ToolContext, ToolError, ToolRegistry
from hst.core import db as dbmod
from hst.results.words import Result, from_engine
from hst.twin_tools import selectors
from hst.twin_tools.envelope import (
    Call,
    Evidence,
    ItemEvidence,
    Missing,
    catalogue_spec,
    gap_list,
    jsonable,
    lookup_evidence,
    whole_result,
)

# Rules one call reads, and unresolved objects one item lists.
MAX_RULES = 10_000
MAX_UNRESOLVED = 20

_NAT_RULES = """
MATCH (rb:FwRulebase:Obj {kind: 'nat'})-[hr:HAS_RULE]->(n:NatRule)
WHERE NOT rb:Retired AND NOT n:Retired AND hr._retired_at IS NULL
  AND rb.collection_ts = $snap AND n.collection_ts = $snap
  AND coalesce(n.enabled, true)
  AND ($device IS NULL
    OR EXISTS {
      MATCH (:Device:Obj {uid: $device, collection_ts: $snap})-[e:ENFORCES]->(rb)
      WHERE e._retired_at IS NULL
    }
    OR EXISTS {
      MATCH (:Device:Obj {uid: $device, collection_ts: $snap})-[m:MEMBER_OF]->(g)-[e:ENFORCES]->(rb)
      WHERE m._retired_at IS NULL AND e._retired_at IS NULL AND NOT g:Retired
    })
OPTIONAL MATCH (owner)-[en:ENFORCES]->(rb)
WHERE en._retired_at IS NULL AND NOT owner:Retired AND owner.collection_ts = $snap
WITH rb, n, [uid IN collect(DISTINCT owner.uid) WHERE uid IS NOT NULL] AS enforced_by,
     any(x IN collect(coalesce(en.approximate, false)) WHERE x) AS binding_approximate
OPTIONAL MATCH (n)-[c:ORIG_SRC|ORIG_DST|XLATE_SRC|XLATE_DST]->(t)
WHERE c._retired_at IS NULL AND NOT t:Retired AND t.collection_ts = $snap
OPTIONAL MATCH (t)-[r:RESOLVES_TO]->(a)
WHERE t:NetObject AND r._retired_at IS NULL AND NOT a:Retired AND a.collection_ts = $snap
WITH rb, n, enforced_by, binding_approximate, c, t,
     [x IN collect(DISTINCT coalesce(a.cidr, a.ip)) WHERE x IS NOT NULL] AS resolved,
     count(CASE WHEN a IS NOT NULL AND a.cidr IS NULL AND a.ip IS NULL THEN 1 END) AS unresolvable
WITH rb, n, enforced_by, binding_approximate,
     collect(CASE WHEN t IS NOT NULL THEN {
       column: type(c), uid: t.uid, name: t.name, net_object: t:NetObject,
       address: coalesce(t.cidr, t.ip), ranges: t.ranges, opaque: coalesce(t.opaque, false),
       opaque_reason: t.opaque_reason, resolved: resolved, unresolvable: unresolvable
     } END) AS targets
RETURN rb.uid AS rulebase, rb.name AS rulebase_name,
       coalesce(rb.approximate, false) OR binding_approximate AS rulebase_approximate,
       enforced_by, n.uid AS uid, n.name AS name, n.position AS position, n.kind AS kind,
       n.method AS method, n.auto_generated AS auto_generated, coalesce(n.static, false) AS static_flag,
       n.direction AS direction, n.orig_src AS orig_src_raw, n.orig_dst AS orig_dst_raw,
       n.translation AS translation, n.orig_port AS orig_port, n.orig_dst_port AS orig_dst_port,
       n.xlate_port AS xlate_port, n.translation_port AS translation_port, n.protocol AS protocol,
       coalesce(n.exclude, false) AS exclude, coalesce(n.approximate, false) AS rule_approximate,
       targets
ORDER BY rulebase, position, uid
LIMIT 10001"""

_COLUMNS = {
    "ORIG_SRC": "orig_src",
    "ORIG_DST": "orig_dst",
    "XLATE_SRC": "xlate_src",
    "XLATE_DST": "xlate_dst",
}
# Configured column values that name no address: any, and a translation to
# the address of an interface (VyOS masquerade, Cisco interface overload).
_NO_ADDRESS_VALUES = frozenset({"any", "all", "masquerade", "interface"})
_SIDES = {"original": ("orig_src", "orig_dst"), "translated": ("xlate_src", "xlate_dst")}

# The gap of each reason for an undecided match, as (code, envelope gap kind).
OPAQUE = ("NAT_OBJECT_OPAQUE", "not-modeled")
UNRESOLVED = ("NAT_OBJECT_UNRESOLVED", "not-collected")
RULE_APPROXIMATE = ("NAT_RULE_APPROXIMATE", "unclassified")
RULEBASE_APPROXIMATE = ("NAT_RULEBASE_APPROXIMATE", "unclassified")


class NatLookupInput(selectors.PagedInput):
    """The NAT rules of one run that name an address."""

    address: str = Field(max_length=64, description="An IPv4 or IPv6 address.")
    side: Literal["original", "translated", "either"] = Field(
        default="either",
        description=(
            "original matches the original source and destination columns, translated the translated "
            "ones, either both."
        ),
    )
    port: int | None = Field(
        default=None,
        ge=0,
        le=65535,
        description=(
            "Only rules whose destination port on the matched side covers this port. A rule that states "
            "no port covers every port."
        ),
    )
    device: str | None = Field(
        default=None,
        min_length=1,
        max_length=512,
        description=(
            "Only the NAT rulebases this device, or a group it is a member of, enforces: a uid or a hostname."
        ),
    )


class NatLookupResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    address: str
    side: str
    device: str | None = None
    items: list[dict[str, Any]] = Field(
        description=(
            "per rule on this page: rule_uid, rulebase, position, kind, the four columns, port, matched_on, "
            "unresolved objects and evidence; evidence.result says whether the rule matches or the "
            "match is not decided"
        )
    )


@dataclass
class _Column:
    """One address column of a NAT rule."""

    intervals: list[tuple[int, int, int]] = field(default_factory=list)
    text: str | None = None
    unresolved: list[dict[str, Any]] = field(default_factory=list)


def _translated_column(row: dict[str, Any], targets: dict[str, list[dict[str, Any]]]) -> str:
    """The translated column a rule's translation value belongs to."""
    from hst.path.gates.nat import _nat_rule_kind

    kind = _nat_rule_kind(
        {**row, "xlate_dst_addrs": [t.get("address") for t in targets.get("xlate_dst", ())]}
    )
    if kind == "static":
        return "xlate_src" if targets.get("xlate_src") else "xlate_dst"
    return "xlate_dst" if kind == "dnat" else "xlate_src"


def _target(column: _Column, name: str, target: dict[str, Any], labels: list[str]) -> None:
    """Add one object to a column. The column gets the addresses of the object,
    or the reason why the object has none."""
    from hst.path.addrsets import _intervals

    subject = {"column": name, "uid": target.get("uid"), "name": target.get("name")}
    if target.get("net_object"):
        if target.get("opaque"):
            reason = target.get("opaque_reason") or "the object is not modeled as an address set"
            column.unresolved.append({**subject, "code": OPAQUE[0], "reason": reason})
            labels.append(str(target.get("name") or target.get("uid")))
            return
        values = [*(target.get("resolved") or ()), *(target.get("ranges") or ())]
        column.intervals.extend(_intervals([str(value) for value in values]))
        labels.extend(str(value) for value in values)
        if not values or target.get("unresolvable"):
            column.unresolved.append(
                {**subject, "code": UNRESOLVED[0], "reason": "the object resolves to no address"}
            )
            if not values:
                labels.append(str(target.get("name") or target.get("uid")))
        return
    address = target.get("address")
    found = _intervals([str(address)]) if address else []
    if not found:
        column.unresolved.append(
            {**subject, "code": UNRESOLVED[0], "reason": "the object carries no address"}
        )
        labels.append(str(target.get("name") or target.get("uid")))
        return
    column.intervals.extend(found)
    labels.append(str(address))


def columns(row: dict[str, Any]) -> dict[str, _Column]:
    """The four address columns of one NAT rule row."""
    from hst.path.gates.nat import _nat_match_set

    targets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for target in row.get("targets") or ():
        name = _COLUMNS.get(str(target.get("column")))
        if name is not None:
            targets[name].append(target)
    raw: dict[str, Any] = {"orig_src": row.get("orig_src_raw"), "orig_dst": row.get("orig_dst_raw")}
    if row.get("translation"):
        raw[_translated_column(row, targets)] = row["translation"]
    out: dict[str, _Column] = {}
    for name in ("orig_src", "orig_dst", "xlate_src", "xlate_dst"):
        column = _Column()
        value = raw.get(name)
        if value and str(value).strip().lower() in _NO_ADDRESS_VALUES:
            column.text = str(value)
            out[name] = column
            continue
        parsed = _nat_match_set(value, []) if value else []
        if parsed:
            column.intervals, column.text = parsed, str(value)
        else:
            labels: list[str] = []
            for target in targets.get(name, ()):
                _target(column, name, target, labels)
            if value and not targets.get(name):
                column.unresolved.append(
                    {
                        "column": name,
                        "uid": None,
                        "name": None,
                        "code": UNRESOLVED[0],
                        "reason": f"the configured value {str(value)!r} is not an address",
                    }
                )
                labels.append(str(value))
            column.text = ", ".join(dict.fromkeys(labels)) or None
        out[name] = column
    return out


def _holds(intervals: list[tuple[int, int, int]], address: tuple[int, int]) -> bool:
    family, value = address
    return any(af == family and low <= value <= high for af, low, high in intervals)


def _port_spec(row: dict[str, Any], side: str) -> Any:
    if side == "original":
        return row.get("orig_dst_port") or row.get("orig_port")
    return row.get("xlate_port") or row.get("translation_port")


def _kind(row: dict[str, Any], cols: dict[str, _Column]) -> str | None:
    from hst.path.gates.nat import _nat_rule_kind

    kind = _nat_rule_kind({**row, "xlate_dst_addrs": [text for text in [cols["xlate_dst"].text] if text]})
    return kind if kind in ("snat", "dnat", "static") else None


def match_rule(
    row: dict[str, Any], address: tuple[int, int], side: str, port: int | None
) -> dict[str, Any] | None:
    """The lookup item of one NAT rule row, or None when the rule does not
    name the address on the side asked."""
    from hst.path.addrsets import _MATCH, _port_matches

    cols = columns(row)
    found: tuple[str, str, list[str]] | None = None
    for name in ("original", "translated") if side == "either" else (side,):
        if port is not None and _port_matches(_port_spec(row, name), port) != _MATCH:
            continue
        held = [column for column in _SIDES[name] if _holds(cols[column].intervals, address)]
        maybe = [column for column in _SIDES[name] if column not in held and cols[column].unresolved]
        if held or maybe:
            candidate = (name, "resolved" if held else "unresolved", held or maybe)
            if found is None or (found[1] == "unresolved" and candidate[1] == "resolved"):
                found = candidate
    if found is None:
        return None
    matched_on, match, matched_columns = found
    spec = _port_spec(row, matched_on)
    unresolved = [item for name in cols for item in cols[name].unresolved]
    codes = [item["code"] for item in unresolved]
    if row.get("rule_approximate"):
        codes.append(RULE_APPROXIMATE[0])
    if row.get("rulebase_approximate"):
        codes.append(RULEBASE_APPROXIMATE[0])
    codes = list(dict.fromkeys(codes))
    decided = match == "resolved" and not codes
    return {
        "rule_uid": row["uid"],
        "name": row.get("name"),
        "rulebase": row.get("rulebase"),
        "rulebase_name": row.get("rulebase_name"),
        "enforced_by": list(row.get("enforced_by") or ()),
        "position": row.get("position"),
        "kind": _kind(row, cols),
        "exclude": bool(row.get("exclude")),
        "orig_src": cols["orig_src"].text,
        "orig_dst": cols["orig_dst"].text,
        "xlate_src": cols["xlate_src"].text,
        "xlate_dst": cols["xlate_dst"].text,
        "port": None if spec is None else str(spec),
        "protocol": row.get("protocol"),
        "matched_on": matched_on,
        "matched_columns": matched_columns,
        "unresolved": unresolved[:MAX_UNRESOLVED],
        "unresolved_truncated": len(unresolved) > MAX_UNRESOLVED,
        "evidence": ItemEvidence.of(
            _match_result(decided, row, unresolved, codes), basis="configured"
        ).model_dump(mode="json"),
    }


def _match_result(
    decided: bool, row: dict[str, Any], unresolved: list[dict[str, Any]], codes: list[str]
) -> Result:
    """The result of the statement "the NAT rule matches the flow".

    The statement holds when `decided` is true. Otherwise it is open on the
    objects that did not resolve and on an approximate rule or rulebase."""
    if decided:
        return from_engine("nat-rule-matches", "holds")
    open_on = [
        Missing(
            code=str(item["code"]),
            subject=str(item.get("uid") or row["uid"]),
            detail=f"{item.get('column')}: {item.get('reason')}",
        )
        for item in unresolved
    ]
    for code in codes:
        if code == RULE_APPROXIMATE[0]:
            open_on.append(Missing(code=code, subject=str(row["uid"]), detail="the rule is approximate"))
        elif code == RULEBASE_APPROXIMATE[0]:
            rulebase = str(row.get("rulebase") or "")
            open_on.append(Missing(code=code, subject=rulebase, detail="the rulebase is approximate"))
    return from_engine("nat-rule-matches", "not-established", missing=open_on[:50])


_GAP_KINDS = dict((OPAQUE, UNRESOLVED, RULE_APPROXIMATE, RULEBASE_APPROXIMATE))


def _gap_entries(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for item in items:
        for unresolved in item["unresolved"]:
            entries.append(
                {
                    "code": unresolved["code"],
                    "kind": _GAP_KINDS[unresolved["code"]],
                    "subject": unresolved.get("uid") or item["rule_uid"],
                    "detail": f"{item['rule_uid']} {unresolved['column']}: {unresolved['reason']}",
                }
            )
        for code in dict.fromkeys(m["code"] for m in item["evidence"]["result"]["missing"]):
            if code in (RULE_APPROXIMATE[0], RULEBASE_APPROXIMATE[0]):
                subject = item["rulebase"] if code == RULEBASE_APPROXIMATE[0] else item["rule_uid"]
                entries.append({"code": code, "kind": _GAP_KINDS[code], "subject": subject})
    return entries


def policy_lookup_nat(ctx: ToolContext, params: NatLookupInput) -> str:
    from hst.twin_tools.inventory import _resolve_device

    try:
        parsed = ipaddress.ip_address(params.address.strip())
    except ValueError as exc:
        raise ToolError(
            "invalid_argument", f"{params.address!r} is not an IP address: {exc}", field="address"
        ) from None
    address = (parsed.version, int(parsed))
    with dbmod.session(ctx.settings, access_mode="READ") as session:
        call = Call.open(ctx, "policy_lookup_nat", params, session)
        pinned = pathmod.pinned(session, call.snapshot)
        device_uid = None if params.device is None else _resolve_device(pinned, params.device)
        rows = jsonable(pathmod._read(pinned, _NAT_RULES, device=device_uid))
        unknowns = [
            "a column that states no address (any, the original packet, or the address of an interface) "
            "matches no address; such a rule can translate this address",
            "each rule is listed by its configuration; which flows a device hands to the NAT rulebase, and "
            "the order of its NAT stages, are not evaluated; reach_trace evaluates translation along a path",
        ]
        if len(rows) > MAX_RULES:
            rows = rows[:MAX_RULES]
            unknowns.append(f"only the first {MAX_RULES} NAT rules of the run are searched; name a device")
        items = [
            item
            for item in (match_rule(row, address, params.side, params.port) for row in rows)
            if item is not None
        ]
        for item in items:
            if device_uid is not None:
                item["device"] = device_uid
            else:
                item["device"] = item["enforced_by"][0] if len(item["enforced_by"]) == 1 else None
        taken, page = call.pager.take(items[call.pager.offset :], total=len(items))
        if items:
            gaps, gaps_truncated = gap_list(_gap_entries(items))
            evidence = Evidence(
                result=whole_result((item["evidence"]["result"] for item in items), unknowns=unknowns),
                gaps=gaps,
                gaps_truncated=gaps_truncated,
                unknowns=unknowns,
                absence="not_recorded",
            )
        else:
            evidence = lookup_evidence(0, unknowns)
        return call.finish(
            session,
            result={
                "address": str(parsed),
                "side": params.side,
                "port": params.port,
                "device": device_uid,
                "items": taken,
            },
            evidence=evidence,
            page=page,
            engine="hst.path.gates.nat",
            engine_function="hst.twin_tools.nat.match_rule",
            queries=[("fixed", "hst.twin_tools.nat._NAT_RULES")],
        )


def register(registry: ToolRegistry) -> None:
    registry.register(
        catalogue_spec(
            name="policy_lookup_nat",
            description=(
                "NAT rules of one run that name an address, by the original columns (source and "
                "destination), the translated columns, or either. Each item gives the rule, its rulebase "
                "and position, its kind (snat, dnat or static), the four address columns, the port, which "
                "side matched, and evidence.result: a rule whose objects all resolve matches; an opaque "
                "or unresolved object, or an approximate rule, leaves the match not decided, with the "
                "object named as missing. port "
                "keeps rules whose port covers it; device keeps the NAT rulebases a device enforces. A "
                "column that states no address matches nothing. Items page with the cursor."
            ),
            input_model=NatLookupInput,
            result_model=NatLookupResult,
            run=policy_lookup_nat,
        )
    )
