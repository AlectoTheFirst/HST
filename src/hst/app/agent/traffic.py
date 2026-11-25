"""Resolve a traffic question once and evaluate its entire symbolic request set.

The model chooses selectors. Resolution reads the pinned snapshot and refuses
an ambiguous or opaque population. The impact engine (`hst.impact.evaluate`)
returns the flow bounds in the coordinates of the request.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from hst import path
from hst.core import uid as uidmod
from hst.impact.evaluate import (
    GUARANTEED,
    GraphGates,
    Member,
    Network,
    RequestSet,
    Service,
    answer,
    member,
)
from hst.path.addrsets import _intervals, _ports, _protoset, _subtract, _to_cidrs
from hst.path.state import FlowRegion, Ivals, Rect, port_spec

MAX_SELECTORS = 128
MAX_CANDIDATES = 32
RESULT_CAP = 128
MAX_RESULT_CHARS = 100_000
RFC1918 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
# The buckets of one answer, in the order they are listed and paged.
BUCKETS = ("allowed", "denied", "not_established", "evidence")

# An app_group value: an application id, then optionally a slash and a group
# id, both in the identifier grammar of the application catalog.
_APP_GROUP = re.compile(r"^([a-z][a-z0-9-]{0,62})(?:/([a-z][a-z0-9-]{0,62}))?$")

# An ApplicationLookup returns the newest stored revision of one Business
# Application by its id, or None when the catalog has no such application.
# The revision has `definition` (the application document) and `revision`.
ApplicationLookup = Callable[[str], Any]


class AddressSelector(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal[
        "addresses", "rfc1918", "non-rfc1918", "group", "vlan", "bridge_domain", "site", "zone", "app_group"
    ]
    value: str | None = Field(default=None, max_length=512)
    addresses: list[str] = Field(default_factory=list, max_length=MAX_SELECTORS)
    exclude: list[str] = Field(default_factory=list, max_length=MAX_SELECTORS)
    context: str | None = Field(default=None, max_length=512, description="Exact VrfInstance uid")


_GROUPS = """
MATCH (n:NetObject:Obj)
WHERE NOT n:Retired AND n.collection_ts = $snap
  AND (n.uid = $value OR toLower(n.name) = toLower($value))
OPTIONAL MATCH (n)-[r:RESOLVES_TO]->(a)
WHERE r._retired_at IS NULL AND NOT a:Retired
  AND a.collection_ts = $snap
RETURN n.uid AS uid, n.name AS name, n.ranges AS ranges,
       n.opaque AS opaque, n.opaque_reason AS opaque_reason,
       collect(DISTINCT coalesce(a.cidr, a.ip)) AS addresses,
       count(CASE WHEN a IS NOT NULL AND a.cidr IS NULL AND a.ip IS NULL THEN 1 END) AS unresolved
ORDER BY CASE WHEN uid = $value THEN 0 ELSE 1 END, uid LIMIT 33"""

_NETWORKS = """
MATCH (bd:BridgeDomain:Obj)
WHERE NOT bd:Retired AND bd.collection_ts = $snap
  AND (($kind = 'bridge_domain' AND (bd.uid = $value OR toLower(bd.name) = toLower($value)))
    OR ($kind = 'vlan' AND EXISTS {
      MATCH (v:VlanInstance)-[r:REALIZES]->(bd)
      WHERE NOT v:Retired AND v.collection_ts = $snap
        AND r._retired_at IS NULL AND v.vid = $vid
    }))
RETURN bd.uid AS uid, bd.name AS name
ORDER BY CASE WHEN uid = $value THEN 0 ELSE 1 END, uid LIMIT 33"""

# The query reads recorded addressing and bindings only. A prefix is IN its
# bridge domain (the APIC collector, the reasoner). A snapshot with a schema
# before v0.31.0 holds the APIC relation as WITHIN.
_NETWORK_PREFIXES = """
CALL {
MATCH (p:Prefix)-[w:IN|WITHIN]->(bd:BridgeDomain:Obj {uid: $uid, collection_ts: $snap})
WHERE NOT p:Retired AND w._retired_at IS NULL
  AND p.collection_ts = $snap
OPTIONAL MATCH (bd)-[iv:IN_VRF]->(ctx:VrfInstance)
WHERE iv._retired_at IS NULL AND NOT ctx:Retired AND ctx.collection_ts = $snap
RETURN p.cidr AS cidr, ctx.uid AS context
UNION
MATCH (i:Interface:Obj {collection_ts: $snap})-[b:BOUND_TO]->(v:VlanInstance)
      -[r:REALIZES]->(:BridgeDomain:Obj {uid: $uid, collection_ts: $snap})
MATCH (i)-[h:HAS_IP]->(a:IpAddress)-[ip:IN]->(p:Prefix)
WHERE NOT i:Retired AND NOT v:Retired AND NOT a:Retired AND NOT p:Retired
  AND all(rel IN [b, r, h, ip] WHERE rel._retired_at IS NULL)
  AND i.collection_ts = $snap
  AND v.collection_ts = $snap
  AND a.collection_ts = $snap
  AND p.collection_ts = $snap
OPTIONAL MATCH (i)-[iv:IN_VRF]->(ctx:VrfInstance)
WHERE iv._retired_at IS NULL AND NOT ctx:Retired AND ctx.collection_ts = $snap
RETURN p.cidr AS cidr, ctx.uid AS context
}
RETURN cidr, context ORDER BY context, cidr LIMIT 129"""

# A site by uid, by code or by name. The code is also matched in its uid form.
_SITES = """
MATCH (s:Site:Obj)
WHERE NOT s:Retired AND (s:Meta OR s.collection_ts = $snap)
  AND (s.uid IN [$value, $slug] OR toLower(coalesce(s.code, '')) = toLower($value)
    OR toLower(coalesce(s.name, '')) = toLower($value))
RETURN s.uid AS uid, s.code AS code, s.name AS name
ORDER BY CASE WHEN uid IN [$value, $slug] THEN 0 ELSE 1 END, uid LIMIT 33"""

# The connected prefixes of the devices located at one site, the rows
# `app.routes.sites.site_prefixes` reads, with the VRF of each interface.
_SITE_PREFIXES = """
MATCH (d:Device:Obj)-[l:LOCATED_IN]->(:Site {uid: $uid})
WHERE NOT d:Retired AND l._retired_at IS NULL AND d.collection_ts = $snap
MATCH (i:Interface)-[o:ON]->(d)
MATCH (i)-[h:HAS_IP]->(a:IpAddress)-[ip:IN]->(p:Prefix)
WHERE NOT i:Retired AND NOT a:Retired AND NOT p:Retired AND p.kind = 'connected'
  AND all(rel IN [o, h, ip] WHERE rel._retired_at IS NULL)
  AND i.collection_ts = $snap
  AND a.collection_ts = $snap
  AND p.collection_ts = $snap
OPTIONAL MATCH (i)-[iv:IN_VRF]->(ctx:VrfInstance)
WHERE iv._retired_at IS NULL AND NOT ctx:Retired AND ctx.collection_ts = $snap
WITH DISTINCT p.cidr AS cidr, ctx.uid AS context
WHERE $context IS NULL OR context = $context
RETURN cidr, context ORDER BY context, cidr LIMIT 129"""

# A zone by uid or by name, with up to four devices its interfaces sit on.
_ZONES = """
MATCH (z:Zone:Obj)
WHERE NOT z:Retired AND z.collection_ts = $snap
  AND (z.uid = $value OR toLower(coalesce(z.name, '')) = toLower($value))
OPTIONAL MATCH (z)-[c:CONTAINS]->(i:Interface)-[o:ON]->(d:Device)
WHERE c._retired_at IS NULL AND o._retired_at IS NULL AND NOT i:Retired AND NOT d:Retired
  AND d.collection_ts = $snap
WITH z, collect(DISTINCT d.uid) AS devices
RETURN z.uid AS uid, z.name AS name, devices[0..4] AS devices
ORDER BY CASE WHEN uid = $value THEN 0 ELSE 1 END, uid LIMIT 33"""

# The prefixes of the addresses on the interfaces a zone contains, with the
# VRF of each interface.
_ZONE_PREFIXES = """
MATCH (:Zone:Obj {uid: $uid, collection_ts: $snap})-[c:CONTAINS]->(i:Interface:Obj)
      -[h:HAS_IP]->(a:IpAddress)-[ip:IN]->(p:Prefix)
WHERE NOT i:Retired AND NOT a:Retired AND NOT p:Retired
  AND all(rel IN [c, h, ip] WHERE rel._retired_at IS NULL)
  AND i.collection_ts = $snap
  AND a.collection_ts = $snap
  AND p.collection_ts = $snap
OPTIONAL MATCH (i)-[iv:IN_VRF]->(ctx:VrfInstance)
WHERE iv._retired_at IS NULL AND NOT ctx:Retired AND ctx.collection_ts = $snap
RETURN DISTINCT p.cidr AS cidr, ctx.uid AS context
ORDER BY context, cidr LIMIT 129"""


@dataclass
class Resolution:
    selector: AddressSelector
    addresses: Ivals = ()
    context: str | None = None
    candidates: list[dict[str, Any]] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    ambiguous: bool = False

    def body(self) -> dict[str, Any]:
        return {
            "selector": self.selector.model_dump(exclude_none=True),
            "addresses": _to_cidrs(list(self.addresses)),
            "context": self.context,
            "candidates": self.candidates[:MAX_CANDIDATES],
            "candidates_truncated": len(self.candidates) > MAX_CANDIDATES,
            "issues": self.issues,
        }


def _strict_addresses(specs: list[str]) -> Ivals:
    if len(specs) > MAX_SELECTORS:
        raise ValueError(f"address set exceeds {MAX_SELECTORS} recorded specifications")
    for spec in specs:
        if not _intervals([spec]):
            raise ValueError(f"invalid address, prefix or range: {spec!r}")
    return tuple(_intervals(specs))


def resolve(
    session: Any, selector: AddressSelector, *, applications: ApplicationLookup | None = None
) -> Resolution:
    """The address population of one selector in the pinned run.

    `applications` reads the Business Application catalog for an `app_group`
    selector.
    """
    result = Resolution(selector, context=selector.context)
    kind = selector.kind
    if kind != "addresses" and selector.addresses:
        raise ValueError("addresses can only accompany kind=addresses")
    if kind in {"addresses", "rfc1918", "non-rfc1918"} and selector.value is not None:
        raise ValueError(
            "value is only used for a group, VLAN, bridge domain, site, zone or application group"
        )
    excluded = _strict_addresses(selector.exclude)
    if kind == "addresses":
        if not selector.addresses:
            raise ValueError("kind=addresses requires at least one address, prefix or range")
        result.addresses = _strict_addresses(selector.addresses)
    elif kind in {"rfc1918", "non-rfc1918"}:
        private = _strict_addresses(list(RFC1918))
        result.addresses = (
            private if kind == "rfc1918" else tuple(_subtract(_intervals(["0.0.0.0/0"]), list(private)))
        )
    else:
        if not selector.value:
            raise ValueError(f"kind={kind} requires value")
        if kind == "group":
            candidates = path._read(session, _GROUPS, value=selector.value)
            exact = [r for r in candidates if r["uid"] == selector.value]
            candidates = exact or candidates
            result.candidates = [{"uid": r["uid"], "name": r.get("name")} for r in candidates]
            if len(candidates) != 1:
                result.ambiguous = len(candidates) > 1
                result.issues.append(
                    "address object is ambiguous" if candidates else "no address object is recorded"
                )
                return result
            row = candidates[0]
            if row.get("opaque") or row.get("unresolved"):
                result.issues.append(
                    row.get("opaque_reason") or "address object membership is not fully resolved"
                )
                return result
            result.addresses = _strict_addresses(
                list(row.get("addresses") or ()) + list(row.get("ranges") or ())
            )
            if not result.addresses:
                result.issues.append("the address object has no recorded address membership")
        elif kind == "site":
            if not _resolve_site(session, selector, result):
                return result
        elif kind == "app_group":
            if not _resolve_app_group(session, selector, result, applications):
                return result
        else:
            vid = None
            if kind == "zone":
                networks = path._read(session, _ZONES, value=selector.value)
                prefix_query = _ZONE_PREFIXES
            else:
                if kind == "vlan":
                    if not selector.value.isdigit() or not 1 <= int(selector.value) <= 4094:
                        raise ValueError("VLAN value must be a number from 1 to 4094")
                    vid = int(selector.value)
                networks = path._read(session, _NETWORKS, kind=kind, value=selector.value, vid=vid)
                prefix_query = _NETWORK_PREFIXES
            exact = [r for r in networks if r["uid"] == selector.value]
            networks = exact or networks
            if len(networks) > MAX_CANDIDATES:
                result.candidates = networks
                result.ambiguous = True
                result.issues.append(
                    "too many zones match; specify a zone uid"
                    if kind == "zone"
                    else "too many broadcast domains match; specify a bridge-domain uid"
                )
                return result
            for network in networks:
                rows = path._read(session, prefix_query, uid=network["uid"])
                if len(rows) > MAX_SELECTORS:
                    result.issues.append(
                        "network addressing exceeds the resolution limit; narrow the selector"
                    )
                    return result
                contexts = sorted({r.get("context") or "" for r in rows}) or [""]
                for context in contexts:
                    if selector.context and context != selector.context:
                        continue
                    prefixes = sorted(
                        {r["cidr"] for r in rows if (r.get("context") or "") == context and r.get("cidr")}
                    )
                    result.candidates.append({**network, "context": context or None, "addresses": prefixes})
            if len(result.candidates) != 1:
                result.ambiguous = len(result.candidates) > 1
                if not result.ambiguous:
                    result.issues.append("no network addressing is recorded for this selector")
                elif kind == "zone":
                    result.issues.append("zone has multiple zone or VRF interpretations; select one")
                else:
                    result.issues.append(
                        "network has multiple broadcast-domain or VRF interpretations; select one"
                    )
                return result
            chosen = result.candidates[0]
            result.context = chosen["context"]
            result.addresses = _strict_addresses(chosen["addresses"])
            if not result.addresses or not result.context:
                result.issues.append("the network's prefixes and forwarding context are not fully recorded")
    result.addresses = tuple(_subtract(list(result.addresses), list(excluded)))
    return result


def _resolve_site(session: Any, selector: AddressSelector, result: Resolution) -> bool:
    """The connected prefixes of the devices located at one site.

    A context in the selector narrows them to that context. Without a context
    the population holds the prefixes of every VRF of the site. Returns False
    after it adds an issue to `result`.
    """
    value = str(selector.value)
    slug = uidmod.site(value)
    sites = path._read(session, _SITES, value=value, slug=slug)
    sites = [r for r in sites if r["uid"] in (value, slug)] or sites
    result.candidates = [{"uid": r["uid"], "code": r.get("code"), "name": r.get("name")} for r in sites]
    if len(sites) != 1:
        result.ambiguous = len(sites) > 1
        result.issues.append(
            "more than one site matches; select one by uid" if sites else "no site is recorded"
        )
        return False
    rows = path._read(session, _SITE_PREFIXES, uid=sites[0]["uid"], context=selector.context)
    if len(rows) > MAX_SELECTORS:
        result.issues.append("site addressing exceeds the resolution limit; narrow the selector with context")
        return False
    result.candidates[0]["contexts"] = sorted({r["context"] for r in rows if r.get("context")})
    prefixes = sorted({r["cidr"] for r in rows if r.get("cidr")})
    if not prefixes:
        result.issues.append(
            "no connected prefix is recorded for this site"
            + (" in the selected context" if selector.context else "")
        )
        return False
    result.addresses = _strict_addresses(prefixes)
    return True


def _single_group(definition: Any, group: Any) -> Any:
    """`definition` reduced to `group` and one connection from the group to itself."""
    from hst.applications.models import Connection

    probe = Connection.model_validate(
        {
            "id": "group-members",
            "name": "group members",
            "source": group.id,
            "destination": group.id,
            "destination_condition": {"kind": "member", "member": group.members[0].id},
        }
    )
    return definition.model_copy(update={"groups": [group], "services": [], "connections": [probe]})


def _resolve_app_group(
    session: Any, selector: AddressSelector, result: Resolution, applications: ApplicationLookup | None
) -> bool:
    """The addresses of one Business Application group.

    `resolve_application` resolves them at the pinned run. The value is
    `<application id>/<group id>`. An application id alone selects the group
    of an application with 1 group. For an application with more groups it
    lists the groups as candidates. Returns False after it adds an issue to
    `result`.
    """
    from hst.applications.models import stored_definition
    from hst.applications.resolution import GraphInventoryReader, resolve_application

    match = _APP_GROUP.match(str(selector.value))
    if match is None:
        raise ValueError("kind=app_group takes value '<application id>/<group id>'")
    if applications is None:
        raise ValueError(
            "kind=app_group needs the Business Application catalog, which this caller does not read"
        )
    application_id, group_id = match.groups()
    item = applications(application_id)
    if item is None:
        result.issues.append(f"no Business Application {application_id} is in the catalog")
        return False
    definition = stored_definition(item.definition)
    groups = {group.id: group for group in definition.groups}
    if group_id is None and len(groups) == 1:
        group_id = next(iter(groups))
    result.candidates = [
        {
            "application": application_id,
            "group": group.id,
            "name": group.name,
            "value": f"{application_id}/{group.id}",
        }
        for group in definition.groups
        if group_id is None or group.id == group_id
    ]
    if group_id is None:
        result.ambiguous = len(groups) > 1
        result.issues.append(
            "the application declares more than one group; select one"
            if groups
            else f"application {application_id} declares no group"
        )
        return False
    group = groups.get(group_id)
    if group is None:
        result.issues.append(f"application {application_id} declares no group {group_id}")
        return False
    if not group.members:
        result.issues.append(f"group {group_id} of application {application_id} has no members")
        return False
    cts = getattr(session, "cts", None)
    if cts is None:
        result.issues.append("an application group resolves against a pinned run, and no run is published")
        return False
    try:
        document = resolve_application(
            _single_group(definition, group),
            revision=item.revision,
            snapshot={"snapshot": str(cts)},
            reader=GraphInventoryReader(session, cts),
        )
    except ValueError as exc:
        result.issues.append(str(exc))
        return False
    issues = [
        issue for issue in document["issues"] if str(issue.get("path", "")).startswith(f"groups.{group_id}.")
    ]
    if issues:
        result.issues.extend(f"{issue['path']}: {issue['code']}: {issue['detail']}" for issue in issues)
        return False
    bindings = [
        binding
        for member in document["groups"].get(group_id, {}).values()
        for binding in member["bindings"]
        if selector.context is None or binding.get("context") == selector.context
    ]
    contexts = sorted({binding.get("context") or "" for binding in bindings})
    if len(contexts) > 1:
        result.ambiguous = True
        result.candidates = [
            {
                "application": application_id,
                "group": group_id,
                "context": context or None,
                "addresses": sorted({b["address"] for b in bindings if (b.get("context") or "") == context}),
            }
            for context in contexts
        ]
        result.issues.append("the group's addresses sit in more than one context; select one with context")
        return False
    addresses = sorted({binding["address"] for binding in bindings})
    if not addresses:
        result.issues.append(
            "the group resolves to no address" + (" in the selected context" if selector.context else "")
        )
        return False
    if len(addresses) > MAX_SELECTORS:
        result.issues.append("application group addressing exceeds the resolution limit; narrow the selector")
        return False
    result.context = selector.context or contexts[0] or None
    result.addresses = _strict_addresses(addresses)
    return True


def _rect_body(rect: Rect) -> dict[str, Any]:
    return {
        "sources": _to_cidrs(list(rect.src)),
        "destinations": _to_cidrs(list(rect.dst)),
        "protocols": sorted(rect.proto) if rect.proto is not None else None,
        "destination_ports": port_spec(rect.dport),
        "source_ports": port_spec(rect.sport),
    }


def _bucket(region: FlowRegion, offset: int = 0) -> dict[str, Any]:
    """The rectangle count of `region`, and at most `RESULT_CAP` of its
    rectangles from `offset` on. `truncated` is true when more rectangles follow."""
    return {
        "count": len(region.rects),
        "items": [_rect_body(r) for r in region.rects[offset : offset + RESULT_CAP]],
        "truncated": len(region.rects) > offset + RESULT_CAP,
    }


def bounded_result(result: dict[str, Any]) -> dict[str, Any]:
    """Bound the JSON text of `result` to `MAX_RESULT_CHARS` characters.

    Each pass halves the `items` of the largest bucket. The counts stay. A
    result that is too long with no bucket items left is replaced by a
    `not_established` result.
    """
    while len(json.dumps(result, default=str)) > MAX_RESULT_CHARS:
        buckets = [
            result[k]
            for k in ("allowed", "denied", "not_established", "evidence")
            if isinstance(result.get(k), dict) and result[k].get("items")
        ]
        if not buckets:
            return {
                "snapshot": result.get("snapshot"),
                "status": "not_established",
                "coverage": {
                    "entire_request_evaluated": False,
                    "entire_request_decided": False,
                    "output_truncated": True,
                },
                "missing_evidence": ["result metadata exceeds the response limit; narrow the request"],
            }
        largest = max(buckets, key=lambda b: len(json.dumps(b["items"], default=str)))
        largest["items"] = largest["items"][: len(largest["items"]) // 2]
        largest["truncated"] = True
        result["coverage"]["output_truncated"] = True
    return result


def evaluate(
    network: Network,
    source: Resolution,
    destination: Resolution,
    service: Service,
    *,
    ingress_interface: str | None = None,
    checkpoint: Callable[[], bool | None] = lambda: None,
    offset: int = 0,
) -> dict[str, Any]:
    """One forward-direction answer, with disjoint buckets in request coordinates.

    Each bucket lists at most `RESULT_CAP` items from `offset` on, in family
    order. Counts cover the whole bucket.
    """
    source_families = {af for af, _, _ in source.addresses}
    destination_families = {af for af, _, _ in destination.addresses}
    families = sorted(source_families & destination_families)
    if not families:
        raise ValueError("source and destination have no common address family")
    results = []
    # The item count of each bucket in the earlier families. The offset skips these items first.
    before = dict.fromkeys(BUCKETS, 0)
    for af in families:
        family = _evaluate_family(
            network,
            replace(source, addresses=tuple(i for i in source.addresses if i[0] == af)),
            replace(destination, addresses=tuple(i for i in destination.addresses if i[0] == af)),
            service,
            ingress_interface=ingress_interface,
            checkpoint=checkpoint,
            offsets={name: max(0, offset - before[name]) for name in BUCKETS},
        )
        for name in BUCKETS:
            before[name] += family[name]["count"]
        results.append(family)
    result = results[0]
    for extra in results[1:]:
        for name in BUCKETS:
            bucket, other = result[name], extra[name]
            bucket["count"] += other["count"]
            bucket["items"] = (bucket["items"] + other["items"])[:RESULT_CAP]
            bucket["truncated"] = bucket["count"] > offset + len(bucket["items"])
        for name in ("missing_evidence", "assumptions", "gaps", "model_errors"):
            result[name].extend(item for item in extra[name] if item not in result[name])
    result["status"] = "partial" if result["not_established"]["count"] else "complete"
    result["coverage"]["entire_request_decided"] = result["status"] == "complete"
    result["coverage"]["output_truncated"] = any(
        result[name]["truncated"] for name in ("allowed", "denied", "not_established", "evidence")
    )
    result["family_scope"] = {
        "evaluated": families,
        "unpaired_source_families": sorted(source_families - destination_families),
        "unpaired_destination_families": sorted(destination_families - source_families),
        "meaning": "same-family source/destination pairs; no cross-family translation is inferred",
    }
    return result


def _evaluate_family(
    network: Network,
    source: Resolution,
    destination: Resolution,
    service: Service,
    *,
    ingress_interface: str | None,
    checkpoint: Callable[[], bool | None],
    offsets: dict[str, int],
) -> dict[str, Any]:
    checkpoint()
    request = RequestSet(
        "allowed traffic",
        source.addresses,
        "destination",
        (Member("destination", destination.addresses),),
        member("destination"),
        service,
        source_context=source.context,
        destination_context=destination.context,
        ingress_interface_uid=ingress_interface,
    )
    from hst.assessment.evaluation import _left_estate, _left_estate_note

    calculated = answer(network, request, GUARANTEED)
    bounds = calculated.members["destination"]
    allowed = bounds.lower
    denied = bounds.request.subtract(bounds.upper)
    unresolved = bounds.upper.subtract(bounds.lower)
    evidence = [
        {
            "request": _rect_body(e.request),
            "outcome": e.outcome,
            "missing": list(e.missing),
            "steps": [
                {
                    "device_uid": s.device_uid,
                    "stage": s.stage,
                    "kind": s.kind,
                    "detail": s.detail,
                    "unknown": list(s.unknown),
                }
                for s in e.steps
            ],
            # A part whose path leaves the estate has `left_estate` and
            # `left_estate_note`.
            **(
                {"left_estate": exits, "left_estate_note": _left_estate_note(exits)}
                if (exits := _left_estate(e))
                else {}
            ),
        }
        for e in bounds.explanations[offsets["evidence"] : offsets["evidence"] + RESULT_CAP]
    ]
    buckets = {
        "allowed": _bucket(allowed, offsets["allowed"]),
        "denied": _bucket(denied, offsets["denied"]),
        "not_established": _bucket(unresolved, offsets["not_established"]),
        "evidence": {
            "count": len(bounds.explanations),
            "items": evidence,
            "truncated": len(bounds.explanations) > offsets["evidence"] + RESULT_CAP,
        },
    }
    return {
        "status": "partial" if unresolved else "complete",
        "coverage": {
            "entire_request_evaluated": True,
            "entire_request_decided": not bool(unresolved),
            "output_truncated": any(b["truncated"] for b in buckets.values()),
        },
        **buckets,
        "missing_evidence": sorted({m for e in bounds.explanations for m in e.missing}),
        "assumptions": list(calculated.assumptions),
        "gaps": [dict(g) for g in calculated.gaps],
        "model_errors": [dict(e) for e in calculated.model_errors],
    }


def query(
    session: Any,
    *,
    source: dict[str, Any],
    destination: dict[str, Any],
    ports: str = "any",
    protocols: str = "any",
    source_ports: str = "any",
    ingress_interface: str | None = None,
    rib_source: Any = None,
    bgp_source: Any = None,
    ospf_source: Any = None,
    checkpoint: Callable[[], bool | None] = lambda: None,
    applications: ApplicationLookup | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    """Resolve both selectors and evaluate the request set between them.

    `applications` reads the Business Application catalog for an `app_group`
    selector. `offset` is where each bucket's listed items start (`evaluate`).
    """
    from hst.app import simul_read
    from hst.app.routes.impact import _model_interfaces
    from hst.assessment.evaluation import _context_domains

    checkpoint()
    src = resolve(session, AddressSelector(**source), applications=applications)
    dst = resolve(session, AddressSelector(**destination), applications=applications)
    service = Service(_protoset(protocols.split(",")), tuple(_ports(ports)), tuple(_ports(source_ports)))
    if not service.proto or not service.dport or not service.sport:
        raise ValueError("traffic queries require explicit service sets; use any for the full range")
    result: dict[str, Any] = {
        "scope": "snapshot forward reachability; not a live measurement or a return-path check",
        "mode": GUARANTEED,
        "plan": {
            "source": src.body(),
            "destination": dst.body(),
            "ports": ports,
            "protocols": protocols,
            "source_ports": source_ports,
            "ingress_interface": ingress_interface,
        },
    }
    if src.issues or dst.issues:
        return {
            **result,
            "status": "needs_clarification" if src.ambiguous or dst.ambiguous else "not_established",
            "coverage": {"entire_request_evaluated": False, "entire_request_decided": False},
            "missing_evidence": src.issues + dst.issues,
        }
    if not src.addresses or not dst.addresses:
        return {
            **result,
            "status": "empty",
            "coverage": {"entire_request_evaluated": True, "entire_request_decided": True},
            "reason": "the requested set is empty after exclusions",
        }
    if not ({af for af, _, _ in src.addresses} & {af for af, _, _ in dst.addresses}):
        raise ValueError("source and destination have no common address family")
    if checkpoint() is False:
        return {
            **result,
            "status": "not_established",
            "coverage": {"entire_request_evaluated": False, "entire_request_decided": False},
            "missing_evidence": ["time budget exhausted before the network calculation"],
        }
    interfaces = _model_interfaces(session)
    domains = _context_domains(session)
    graph_input = simul_read.read_rib_input(
        session,
        contexts=sorted({i.context_uid for i in interfaces if i.context_uid}),
        rib_source=rib_source,
        bgp_source=bgp_source,
        ospf_source=ospf_source,
    )
    checkpoint()
    evaluated = evaluate(
        Network(
            graph_input.input,
            interfaces,
            GraphGates(session),
            checkpoint=checkpoint,
            context_domains=domains,
        ),
        src,
        dst,
        service,
        ingress_interface=ingress_interface,
        checkpoint=checkpoint,
        offset=offset,
    )
    evaluated["model_errors"] = graph_input.errors.as_dicts() + evaluated["model_errors"]
    return {**result, **evaluated}
