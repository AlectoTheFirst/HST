"""The named choices at a pinned snapshot for the guided forms and the AI drafts.

A search result is a suggestion. A selection resolves a UID at the pinned snapshot.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from hst import path
from hst.assessment import evaluation as ev
from hst.assessment import service
from hst.core import db
from hst.core import snapshot as snapshotmod

KINDS = {
    "service": "ServiceRequirement",
    "device": "Device",
    "interface": "Interface",
    "rulebase": "FwRulebase",
    "link": "WanLink",
    "tunnel": "Tunnel",
    "domain": "FailureDomain",
}
_LABEL_KINDS = {label: kind for kind, label in KINDS.items()}

_OBJECTS = """
MATCH (n:Obj)
WHERE n.collection_ts = $snap AND NOT n:Retired
  AND any(label IN labels(n) WHERE label IN $labels)
  AND ($uid IS NULL OR n.uid = $uid)
  AND ($after IS NULL OR n.uid > $after)
  AND ($q = '' OR toLower(coalesce(n.name, '')) CONTAINS $q
       OR toLower(coalesce(n.hostname, '')) CONTAINS $q
       OR toLower(n.uid) CONTAINS $q
       OR EXISTS {
         MATCH p=(n)-[:ON|ENFORCES|PROTECTED_BY|HAS_LINK|ENDPOINT|MEMBER_OF|LOCATED_IN*1..3]-(related)
         WHERE related.collection_ts = $snap AND NOT related:Retired
           AND (related:Device OR related:Site)
           AND all(r IN relationships(p) WHERE r.collection_ts = $snap AND r._retired_at IS NULL)
           AND all(x IN nodes(p) WHERE x.collection_ts = $snap AND NOT x:Retired)
           AND (toLower(coalesce(related.name, '')) CONTAINS $q
                OR toLower(coalesce(related.hostname, '')) CONTAINS $q
                OR toLower(coalesce(related.code, '')) CONTAINS $q)
       })
RETURN n.uid AS uid, labels(n) AS labels,
       coalesce(n.name, n.hostname, n.uid) AS name,
       n.source AS source, n.kind AS domain_kind, n.origin AS origin,
       n.collector AS collector, n.evidence_reference AS evidence_reference,
       n.evidence_section AS evidence_section, n.evidence_host AS evidence_host,
       n.observed_ms AS observed_ms, n.valid_from_ms AS valid_from_ms,
       n.valid_until_ms AS valid_until_ms, n._sources AS sources
ORDER BY CASE WHEN $catalog THEN 0 WHEN n.uid IN $suggested THEN 0 ELSE 1 END,
         CASE WHEN $catalog THEN n.uid ELSE toLower(coalesce(n.name, n.hostname, n.uid)) END, n.uid
LIMIT $limit
"""

# The query follows the directed relationships of the schema from an object to
# the devices that own it.
_OWNERS = """
CALL {
 MATCH (n:Device:Obj) WHERE n.uid IN $uids AND n.collection_ts = $snap RETURN n, n AS d, [] AS rels
 UNION
 MATCH (n:Interface:Obj)-[r:ON]->(d:Device) WHERE n.uid IN $uids AND n.collection_ts = $snap
 RETURN n, d, [r] AS rels
 UNION
 MATCH (d:Device)-[r:ENFORCES]->(n:FwRulebase:Obj) WHERE n.uid IN $uids AND n.collection_ts = $snap
 RETURN n, d, [r] AS rels
 UNION
 MATCH (v:VrfInstance)-[r:ENFORCES]->(n:FwRulebase:Obj), (v)-[o:ON]->(d:Device)
 WHERE n.uid IN $uids AND n.collection_ts = $snap AND v.collection_ts = $snap AND NOT v:Retired
 RETURN n, d, [r,o] AS rels
 UNION
 MATCH (d:Device)-[m:MEMBER_OF]->(g:RedundancyGroup)-[r:ENFORCES]->(n:FwRulebase:Obj)
 WHERE n.uid IN $uids AND n.collection_ts = $snap AND g.collection_ts = $snap AND NOT g:Retired
 RETURN n, d, [m,r] AS rels
 UNION
 MATCH (i:Interface)-[r:PROTECTED_BY]->(n:FwRulebase:Obj), (i)-[o:ON]->(d:Device)
 WHERE n.uid IN $uids AND n.collection_ts = $snap AND i.collection_ts = $snap AND NOT i:Retired
 RETURN n, d, [r,o] AS rels
 UNION
 MATCH (d:Device)-[r:HAS_LINK]->(n:WanLink:Obj) WHERE n.uid IN $uids AND n.collection_ts = $snap
 RETURN n, d, [r] AS rels
 UNION
 MATCH (n:Obj)-[r:ENDPOINT]->(i:Interface)-[o:ON]->(d:Device)
 WHERE n.uid IN $uids AND n.collection_ts = $snap AND (n:WanLink OR n:Tunnel)
   AND i.collection_ts = $snap AND NOT i:Retired RETURN n, d, [r,o] AS rels
}
WITH n, d, rels
WHERE n.collection_ts = $snap AND d.collection_ts = $snap AND NOT n:Retired AND NOT d:Retired
 AND all(r IN rels WHERE r.collection_ts = $snap AND r._retired_at IS NULL)
OPTIONAL MATCH (d)-[located:LOCATED_IN]->(site:Site)
WHERE located.collection_ts = $snap AND located._retired_at IS NULL
 AND site.collection_ts = $snap AND NOT site:Retired
WITH n.uid AS uid, collect(DISTINCT {uid:d.uid, name:coalesce(d.hostname,d.name,d.uid),
 site:coalesce(site.name,site.code)}) AS owners
RETURN uid, owners[0..101] AS devices, size(owners) AS owner_count
"""

_DETAILS = """
MATCH (n:Obj) WHERE n.uid IN $uids AND n.collection_ts = $snap AND NOT n:Retired
OPTIONAL MATCH (n)-[ep:ENDPOINT]->(endpoint)
WHERE ep.collection_ts = $snap AND ep._retired_at IS NULL
 AND endpoint.collection_ts = $snap AND NOT endpoint:Retired
WITH n, collect(DISTINCT {uid:endpoint.uid, name:coalesce(endpoint.name,endpoint.ip,endpoint.uid),
 labels:labels(endpoint)}) AS endpoints
OPTIONAL MATCH (member)-[m:MEMBER_OF]->(n:FailureDomain)
WHERE m.collection_ts = $snap AND m._retired_at IS NULL
 AND member.collection_ts = $snap AND NOT member:Retired
WITH n, endpoints, collect(DISTINCT {uid:member.uid,name:coalesce(member.name,member.hostname,member.uid),
 labels:labels(member)}) AS members
OPTIONAL MATCH (n)-[iv:IN_VRF]->(v:VrfInstance)
WHERE iv.collection_ts = $snap AND iv._retired_at IS NULL
 AND v.collection_ts = $snap AND NOT v:Retired
WITH n,endpoints,members, collect(DISTINCT {uid:v.uid,name:coalesce(v.name,v.uid)}) AS contexts
OPTIONAL MATCH (n)-[hi:HAS_IP]->(ip:IpAddress)
WHERE hi.collection_ts = $snap AND hi._retired_at IS NULL
 AND ip.collection_ts = $snap AND NOT ip:Retired
WITH n,endpoints,members,contexts, collect(DISTINCT ip.ip) AS addresses
OPTIONAL MATCH (app:BusinessService)-[dependency:DEPENDS_ON]->(n:ServiceRequirement)
WHERE app.collection_ts = $snap AND NOT app:Retired
 AND dependency.collection_ts = $snap AND dependency._retired_at IS NULL
WITH n,endpoints,members,contexts,addresses,collect(DISTINCT app.name) AS applications
OPTIONAL MATCH (origin:Obj)
WHERE origin.uid IN [n.source_device_uid,n.source_context,n.identity_uid,n.segment_uid]
 AND origin.collection_ts = $snap AND NOT origin:Retired
OPTIONAL MATCH location_path=(origin)-[:ON|LOCATED_IN*0..2]->(location)
WHERE location.collection_ts = $snap AND NOT location:Retired
 AND (location:Site OR location:Device OR location:VrfInstance
      OR location:IdentityGroup OR location:ZpaAppSegment)
 AND all(r IN relationships(location_path) WHERE r.collection_ts = $snap AND r._retired_at IS NULL)
 AND all(x IN nodes(location_path) WHERE x.collection_ts = $snap AND NOT x:Retired)
WITH n,endpoints,members,contexts,addresses,applications,
 collect(DISTINCT coalesce(location.name,location.hostname,location.code)) AS origin_locations
OPTIONAL MATCH population_path=(n)-[:SRC]->(population)<-[:GATEWAY_FOR]-(iface:Interface)
 -[:ON]->(device:Device)-[:LOCATED_IN]->(site:Site)
WHERE all(r IN relationships(population_path) WHERE r.collection_ts = $snap AND r._retired_at IS NULL)
 AND all(x IN nodes(population_path) WHERE x.collection_ts = $snap AND NOT x:Retired)
WITH n,endpoints,members,contexts,addresses,applications,origin_locations,
 collect(DISTINCT coalesce(site.name,site.code)) AS population_locations
RETURN n.uid AS uid, endpoints[0..101] AS endpoints, size(endpoints) AS endpoint_count,
 members[0..101] AS members, size(members) AS member_count,
 contexts[0..101] AS contexts, size(contexts) AS context_count,
 addresses[0..101] AS addresses, size(addresses) AS address_count,
 applications[0..101] AS applications, size(applications) AS application_count,
 (origin_locations + population_locations)[0..101] AS locations,
 size(origin_locations) + size(population_locations) AS location_count
"""


def request_document(req: Any) -> dict[str, Any]:
    """Serialize the request of the evaluator as a document with all of its flow dimensions."""

    def service_fields(item: Any) -> dict:
        if item is None:
            return {}

        def ports(values: Any) -> str | None:
            return ",".join(str(lo) if lo == hi else f"{lo}-{hi}" for _, lo, hi in values) if values else None

        return {
            "proto": ",".join(str(p) for p in sorted(item.proto)) if item.proto is not None else None,
            "port": ports(item.dport),
            "source_port": ports(item.sport),
        }

    def condition_document(condition: Any) -> dict:
        value = ev._condition_body(condition)

        def normalize(node: dict) -> dict:
            return {
                **node,
                "kind": {"every": "and", "any-one": "or", "n-of-m": "threshold"}.get(
                    node["kind"], node["kind"]
                ),
                **({"parts": [normalize(part) for part in node["parts"]]} if "parts" in node else {}),
            }

        return normalize(value)

    return {
        "name": req.name,
        "destination": req.destination,
        "sources": ev._cidrs(req.sources),
        "members": [
            {"name": m.name, "addresses": ev._cidrs(m.addresses), **service_fields(m.service)}
            for m in req.members
        ],
        "condition": condition_document(req.condition),
        **service_fields(req.service),
        "success": req.success,
        "source_context": req.source_context,
        "source_device_uid": req.source_device_uid,
        "identity_uid": req.identity_uid,
        "segment_uid": req.segment_uid,
        **({"mtu": req.mtu.as_request().model_dump(mode="json")} if req.mtu is not None else {}),
    }


def _kind(labels: list[str]) -> str:
    return next((_LABEL_KINDS[label] for label in labels if label in _LABEL_KINDS), "unsupported")


def _suggested(dependencies: list[dict], snapshot: str) -> set[str]:
    return {
        str(ref["uid"])
        for ref in dependencies
        if ref.get("kind") == "graph-object" and ref.get("uid") and str(ref.get("snapshot")) == snapshot
    }


def _read_options(
    session: Any,
    kinds: list[str],
    q: str,
    uid: str | None,
    suggested: set[str],
    limit: int,
    *,
    after: str | None = None,
    catalog: bool = False,
) -> dict:
    rows = path._read(
        session,
        _OBJECTS,
        labels=[KINDS[k] for k in kinds],
        q=q.casefold(),
        uid=uid,
        suggested=sorted(suggested),
        limit=limit + 1,
        after=after,
        catalog=catalog,
    )
    truncated = len(rows) > limit
    rows = rows[:limit]
    uids = [row["uid"] for row in rows]
    owners = {row["uid"]: row for row in path._read(session, _OWNERS, uids=uids)} if uids else {}
    details = {row["uid"]: row for row in path._read(session, _DETAILS, uids=uids)} if uids else {}
    items = []
    for row in rows:
        identifier = row["uid"]
        kind = _kind(row["labels"])
        detail = details.get(identifier, {})
        devices = owners.get(identifier, {}).get("devices", [])
        devices = list({d["uid"]: d for d in devices if d.get("uid")}.values())
        item = {
            "uid": identifier,
            "name": row.get("name") or identifier,
            "kind": kind,
            "devices": devices,
            "selectable": True,
            "suggested": identifier in suggested,
            "addresses": detail.get("addresses", []),
            "interfaces": [
                e["uid"]
                for e in detail.get("endpoints", [])
                if e.get("uid") and "Interface" in e.get("labels", [])
            ],
            "members": [
                {"uid": m["uid"], "name": m.get("name") or m["uid"], "kind": _kind(m.get("labels", []))}
                for m in detail.get("members", [])
                if m.get("uid")
            ],
            "source": row.get("source"),
            "sources": row.get("sources") or [],
        }
        reasons = []
        if item["suggested"]:
            item["suggestion_reason"] = (
                "Read by this assessment's completed analysis at the selected snapshot; review relevance."
            )
        if len(devices) == 1:
            item.update(device=devices[0], device_uid=devices[0]["uid"], device_name=devices[0]["name"])
        sites = sorted({d["site"] for d in devices if d.get("site")})
        if sites:
            item["site"] = ", ".join(sites)
        contexts = [v for v in detail.get("contexts", []) if v.get("uid")]
        item["contexts"] = contexts
        if len(contexts) == 1:
            item["context"] = contexts[0]
        if kind == "rulebase":
            item["policy_kind"] = row.get("domain_kind")
            if row.get("domain_kind") in {"nat", "ips-profile"}:
                reasons.append("This policy family is not an access-rule repair target.")
        if kind in {"rulebase", "interface"} and not devices:
            reasons.append("No modeled device owner is recorded for this object.")
        if kind in {"link", "tunnel"}:
            endpoints = [e for e in detail.get("endpoints", []) if e.get("uid")]
            if not item["interfaces"] or any("Interface" not in e.get("labels", []) for e in endpoints):
                reasons.append("Failure modeling requires all recorded endpoints to resolve to interfaces.")
        if (
            any(
                detail.get(field, 0) > 100
                for field in ("endpoint_count", "member_count", "context_count", "address_count")
            )
            or owners.get(identifier, {}).get("owner_count", 0) > 100
        ):
            reasons.append(
                "Related objects exceed the guided selection bound; partial scope cannot be selected."
            )
        if kind == "domain":
            item.update(
                evidence_status="observed" if row.get("origin") == "observed" else "declared",
                valid_from_ms=row.get("valid_from_ms"),
                valid_until_ms=row.get("valid_until_ms"),
                evidence_refs=[row["evidence_reference"]] if row.get("evidence_reference") else [],
                provenance={
                    key: row.get(key)
                    for key in (
                        "source",
                        "collector",
                        "origin",
                        "observed_ms",
                        "evidence_section",
                        "evidence_host",
                    )
                },
                provenance_validated=False,
            )
            if not item["members"] or any(
                m["kind"] not in {"device", "interface", "link", "tunnel", "domain"} for m in item["members"]
            ):
                reasons.append("Domain membership is empty or includes unsupported failure objects.")
            if not row.get("source"):
                reasons.append("The domain has no recorded source.")
        if kind == "service":
            item.update(
                origin="graph",
                locations=sorted(set(detail.get("locations", []))),
                applications=sorted(set(detail.get("applications", []))),
                metadata_complete=detail.get("location_count", 0) <= 100
                and detail.get("application_count", 0) <= 100,
            )
            try:
                item["definition"] = request_document(ev._request_from_requirement(session, identifier))
                ev.RequestBody.model_validate(item["definition"])
                item["requirement_uid"] = identifier
            except (HTTPException, ValueError) as exc:
                reasons.append(str(exc.detail) if isinstance(exc, HTTPException) else str(exc))
        if reasons:
            item.update(selectable=False, disabled_reason=" ".join(reasons), reason=" ".join(reasons))
        items.append(item)
    return {
        "items": items,
        "truncated": truncated,
        **({"cursor": rows[-1]["uid"] if rows else None} if catalog else {}),
    }


def search_options(
    settings: Any,
    snapshot: str,
    kind: str = "all",
    q: str = "",
    uid: str | None = None,
    *,
    dependencies: list[dict] | None = None,
    limit: int = 50,
    destination: str = "",
    client: str = "",
    location: str = "",
    application: str = "",
    saved_requirements: list[dict] | None = None,
) -> dict:
    """Find named candidates or resolve one UID at a pinned snapshot."""
    if not isinstance(snapshot, str) or not snapshot.isdigit() or int(snapshot) < 1:
        raise ValueError("Select a published snapshot before choosing assessment objects.")
    if len(q) > 200 or (uid is not None and (not uid or len(uid) > 500)):
        raise ValueError("Search text or object UID exceeds its bound.")
    if not 1 <= limit <= 100:
        raise ValueError("Discovery limit must be between 1 and 100.")
    kinds = list(KINDS) if kind == "all" else list(dict.fromkeys(kind.split(",")))
    if not kinds or any(k not in KINDS for k in kinds):
        raise ValueError("Object kind must be one of: " + ", ".join(KINDS))
    if any(len(value) > 500 for value in (destination, client, location, application)):
        raise ValueError("Service clues must not exceed 500 characters.")
    if any((destination, client, location, application)) and kinds != ["service"]:
        raise ValueError("Traffic and application clues require kind=service.")
    reference = service.snapshot_reference(settings, snapshot)
    with db.session(settings) as raw:
        snap = snapshotmod.resolve(raw, settings, int(reference["snapshot"]))
        session = path.pinned(raw, snap)
        if kinds == ["service"] and uid is None:
            from hst.assessment.service_discovery import scan_services

            result = scan_services(
                session,
                q=q,
                destination=destination,
                client=client,
                location=location,
                application=application,
                limit=limit,
                saved_requirements=saved_requirements or [],
                read_page=lambda after, count: _read_options(
                    session, kinds, "", None, set(), count, after=after, catalog=True
                ),
            )
        else:
            result = _read_options(
                session, kinds, q, uid, _suggested(dependencies or [], str(snap.cts)), limit
            )
            if kinds == ["service"] and uid is not None and saved_requirements:
                from hst.assessment.service_discovery import _saved_items

                saved = _saved_items(session, [item for item in saved_requirements if item["id"] == uid])
                # A UID with 2 origins has 2 items. A caller selects an item by its origin.
                result["items"].extend(saved)
    return {
        "snapshot": reference["snapshot"],
        **result,
        "scope": "Named objects recorded at the selected snapshot",
    }
