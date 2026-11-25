"""Recorded address choices for authoring traffic when no saved service exists."""

from __future__ import annotations

import time
from typing import Any

from hst import path

_ADDRESSES = """
MATCH (address:Obj)
WHERE address.collection_ts = $snap AND NOT address:Retired
 AND (address:Prefix OR address:IpAddress) AND address.uid > $after
OPTIONAL MATCH (iface:Interface)-[binding:GATEWAY_FOR|HAS_IP]->(address)
WHERE iface.collection_ts = $snap AND NOT iface:Retired
 AND binding.collection_ts = $snap AND binding._retired_at IS NULL
OPTIONAL MATCH (iface)-[on:ON]->(device:Device)
WHERE device.collection_ts = $snap AND NOT device:Retired
 AND on.collection_ts = $snap AND on._retired_at IS NULL
OPTIONAL MATCH (iface)-[iv:IN_VRF]->(context:VrfInstance)
WHERE context.collection_ts = $snap AND NOT context:Retired
 AND iv.collection_ts = $snap AND iv._retired_at IS NULL
OPTIONAL MATCH (device)-[located:LOCATED_IN]->(site:Site)
WHERE site.collection_ts = $snap AND NOT site:Retired
 AND located.collection_ts = $snap AND located._retired_at IS NULL
WITH address, collect(DISTINCT {device_uid:device.uid,device_name:coalesce(device.hostname,device.name),
 context_uid:context.uid,context_name:context.name,site:coalesce(site.name,site.code)}) AS contexts
RETURN address.uid AS uid, coalesce(address.name,address.cidr,address.ip,address.uid) AS name,
 coalesce(address.cidr,address.ip) AS address, contexts[0..101] AS contexts,
 size(contexts) AS context_count
ORDER BY address.uid LIMIT $limit
"""


def address_choices(
    session: Any,
    *,
    destinations: list[Any],
    client: Any | None,
    location: str,
    max_records: int = 1000,
    limit: int = 100,
) -> dict:
    from hst.assessment.service_discovery import network

    choices = []
    after = ""
    scanned = 0
    complete = True
    started = time.monotonic()
    while scanned < max_records:
        if time.monotonic() - started > 20:
            complete = False
            break
        batch = min(100, max_records - scanned)
        rows = path._read(session, _ADDRESSES, after=after, limit=batch + 1)
        for row in rows[:batch]:
            parsed = network(row.get("address") or "")
            if parsed is None:
                continue
            contexts = [ctx for ctx in row.get("contexts", []) if ctx.get("device_uid")]
            locations = [
                ctx
                for ctx in contexts
                if not location
                or any(
                    location.casefold() in str(ctx.get(field) or "").casefold()
                    for field in ("site", "device_name", "context_name")
                )
            ]
            if row.get("context_count", 0) > 100:
                complete = False
            for role, clues in (
                ("client", [client] if client is not None else []),
                ("destination", destinations),
            ):
                if role == "client" and not (client is not None or location):
                    continue
                if role == "destination" and not destinations:
                    continue
                matched = [clue for clue in clues if clue.version == parsed.version and clue.overlaps(parsed)]
                if clues and not matched:
                    continue
                if role == "client" and location and not locations:
                    continue
                narrowed = (
                    sorted({str(clue if clue.prefixlen >= parsed.prefixlen else parsed) for clue in matched})
                    if matched
                    else [str(parsed)]
                )
                selected_contexts = locations if role == "client" else contexts
                option = {
                    "uid": row["uid"],
                    "name": row["name"],
                    "role": role,
                    "addresses": narrowed,
                    "match_reasons": ["Recorded address evidence; explicitly select the traffic to include."],
                    "contexts": selected_contexts,
                    "selectable": row.get("context_count", 0) <= 100,
                }
                sites = sorted({ctx["site"] for ctx in selected_contexts if ctx.get("site")})
                if sites:
                    option["site"] = ", ".join(sites)
                devices = {ctx["device_uid"]: ctx for ctx in selected_contexts}
                if len(devices) == 1:
                    ctx = next(iter(devices.values()))
                    option["device"] = {"uid": ctx["device_uid"], "name": ctx["device_name"]}
                vrfs = {
                    ctx["context_uid"]: ctx["context_name"]
                    for ctx in selected_contexts
                    if ctx.get("context_uid")
                }
                source_contexts = {
                    ctx.get("context_uid") or f"default:{ctx['device_uid']}" for ctx in selected_contexts
                }
                if role == "client" and len(source_contexts) > 1:
                    option["selectable"] = False
                    option["disabled_reason"] = (
                        "This address has multiple recorded forwarding contexts; narrow the source location."
                    )
                if len(vrfs) == 1:
                    identifier, name = next(iter(vrfs.items()))
                    option["context"] = {"uid": identifier, "name": name}
                if role == "client" and location:
                    option["match_reasons"].append(
                        f"Recorded client gateway or interface belongs to {location}."
                    )
                choices.append(option)
        scanned += min(len(rows), batch)
        if len(rows) <= batch:
            break
        cursor = rows[batch - 1]["uid"]
        if cursor <= after or scanned >= max_records:
            complete = False
            break
        after = cursor
    return {
        "items": choices[:limit],
        "complete": complete,
        "truncated": len(choices) > limit or not complete,
        "scanned": scanned,
    }
