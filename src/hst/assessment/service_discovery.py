"""Find exact service definitions from traffic clues without live DNS or fetches."""

from __future__ import annotations

import ipaddress
import json
import re
import time
from collections.abc import Callable
from copy import deepcopy
from typing import Any
from urllib.parse import urlsplit

from fastapi import HTTPException

from hst import path
from hst.assessment import evaluation as ev

PAGE_SIZE = 100
MAX_SERVICES = 1000
MAX_SECONDS = 20.0
MAX_BYTES = 16 * 1024 * 1024

_DNS = """
MATCH (d:DnsRecord:Obj)
WHERE d.collection_ts = $snap AND NOT d:Retired AND toLower(d.fqdn) IN [$hostname, $hostname + '.']
OPTIONAL MATCH p=(d)-[:RESOLVES_TO*0..8]->(answer)
WHERE all(x IN nodes(p) WHERE x.collection_ts = $snap AND NOT x:Retired)
 AND all(r IN relationships(p) WHERE r.collection_ts = $snap AND r._retired_at IS NULL)
WITH d, collect(DISTINCT answer.ip) AS addresses
RETURN d.uid AS uid, d.type AS type, d.values AS values, addresses[0..101] AS addresses,
 size(addresses) AS address_count LIMIT 101
"""
_HOSTS = """
MATCH (host:Obj)
WHERE host.collection_ts = $snap AND NOT host:Retired
 AND (toLower(host.hostname_fqdn) IN [$hostname, $hostname + '.']
      OR toLower(host.hostname) IN [$hostname, $hostname + '.'])
OPTIONAL MATCH (host)-[hi:HAS_IP]->(ip:IpAddress)
WHERE hi.collection_ts = $snap AND hi._retired_at IS NULL
 AND ip.collection_ts = $snap AND NOT ip:Retired
WITH host, collect(DISTINCT ip.ip) AS addresses
RETURN host.uid AS uid, host.ip AS ip, addresses[0..101] AS addresses,
 size(addresses) AS address_count LIMIT 101
"""
_SAVED_CONTEXTS = """
UNWIND $requests AS request
OPTIONAL MATCH (origin:Obj)
WHERE origin.uid IN request.origins AND origin.collection_ts = $snap AND NOT origin:Retired
OPTIONAL MATCH p=(origin)-[:ON|LOCATED_IN*0..2]->(location)
WHERE location.collection_ts = $snap AND NOT location:Retired
 AND (location:Device OR location:Site OR location:VrfInstance
      OR location:IdentityGroup OR location:ZpaAppSegment)
 AND all(r IN relationships(p) WHERE r.collection_ts = $snap AND r._retired_at IS NULL)
 AND all(x IN nodes(p) WHERE x.collection_ts = $snap AND NOT x:Retired)
WITH request.uid AS uid,
 collect(DISTINCT coalesce(location.name,location.hostname,location.code)) AS locations
RETURN uid, locations[0..101] AS locations, size(locations) AS location_count
"""


def network(value: str) -> Any | None:
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def destination_clue(value: str) -> tuple[str | None, Any | None, int | None, list[str]]:
    """Extract only an address or hostname and an explicitly stated URL port."""
    if not value.strip():
        return None, None, None, []
    direct = network(value)
    if direct is not None:
        return None, direct, None, []
    parsed = urlsplit(value if "://" in value else "//" + value)
    try:
        hostname, port = parsed.hostname, parsed.port
    except ValueError as exc:
        raise ValueError("Use a valid destination URL, hostname, IP address or prefix.") from exc
    if not hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("Use a destination hostname or URL without embedded credentials.")
    hostname = hostname.rstrip(".").casefold()
    address = network(hostname)
    if address is None and not re.fullmatch(r"[a-z0-9_.-]+", hostname):
        raise ValueError("Use a valid recorded destination hostname.")
    notes = []
    if parsed.path or parsed.query or parsed.fragment:
        notes.append("Only the URL host and explicit port are matched; URL paths are not modeled.")
    return None if address is not None else hostname, address, port, notes


def _host_addresses(session: Any, hostname: str) -> tuple[list[Any], bool, list[dict]]:
    rows = path._read(session, _DNS, hostname=hostname)
    hosts = path._read(session, _HOSTS, hostname=hostname)
    complete = len(rows) <= 100 and len(hosts) <= 100
    values: list[Any] = []
    choices: list[dict] = []
    for row in [*rows[:100], *hosts[:100]]:
        complete &= row.get("address_count", 0) <= 100
        candidates = [*row.get("addresses", []), row.get("ip")]
        if str(row.get("type", "")).upper() in {"A", "AAAA"}:
            stored = row.get("values") or []
            candidates.extend(stored if isinstance(stored, list) else [stored])
        recorded = []
        for value in candidates:
            if not isinstance(value, str):
                continue
            try:
                literal = ipaddress.ip_address(value)
                recorded.append(ipaddress.ip_network(literal))
            except ValueError:
                continue
        values.extend(recorded)
        if recorded:
            choices.append(
                {
                    "uid": row["uid"],
                    "name": hostname,
                    "role": "destination",
                    "addresses": sorted({str(value) for value in recorded}),
                    "selectable": complete,
                    "match_reasons": [f"Recorded hostname evidence resolves {hostname} to these addresses."],
                }
            )
    return list(dict.fromkeys(values)), complete, choices


def _overlaps(clues: list[Any], values: list[str]) -> bool:
    return any(
        clue.version == actual.version and clue.overlaps(actual)
        for clue in clues
        for value in values
        if (actual := network(value)) is not None
    )


def _port_matches(request: dict, port: int) -> bool:
    for member in request.get("members", []):
        raw = member.get("port") if member.get("port") is not None else request.get("port")
        if raw is None:
            continue  # An unspecified dimension is not recorded evidence for this URL port.
        try:
            ports = ev._ports(raw)
        except ValueError:
            continue
        if ports is not None and any(lo <= port <= hi for _, lo, hi in ports):
            return True
    return False


def _saved_items(session: Any, saved: list[dict]) -> list[dict]:
    items = []
    for value in saved[:MAX_SERVICES]:
        request = value.get("definition", {}).get("request")
        if not request:
            continue
        item = {
            "uid": value["id"],
            "name": value["title"],
            "kind": "service",
            "origin": "saved",
            "requirement_id": value["id"],
            "requirement_revision": value["revision"],
            "selectable": True,
            "locations": [],
            "applications": [],
            "metadata_complete": True,
        }
        try:
            ev._request_from_body(ev.RequestBody.model_validate(request))
            item["definition"] = deepcopy(request)
        except (ValueError, HTTPException) as exc:
            item.update(
                selectable=False,
                disabled_reason=str(exc.detail) if isinstance(exc, HTTPException) else str(exc),
            )
        for key in ("origin_requirement", "origin_snapshot"):
            if key in value.get("definition", {}):
                item[key] = value["definition"][key]
        items.append(item)
    requests = [
        {
            "uid": item["uid"],
            "origins": [
                item.get("definition", {}).get(key)
                for key in ("source_device_uid", "source_context", "identity_uid", "segment_uid")
            ],
        }
        for item in items
    ]
    if requests:
        contexts = {row["uid"]: row for row in path._read(session, _SAVED_CONTEXTS, requests=requests)}
        for item in items:
            data = contexts.get(item["uid"], {})
            item["locations"] = data.get("locations", [])
            item["metadata_complete"] = data.get("location_count", 0) <= 100
    return items


def scan_services(
    session: Any,
    *,
    read_page: Callable[[str | None, int], dict],
    q: str = "",
    destination: str = "",
    client: str = "",
    location: str = "",
    application: str = "",
    limit: int = 50,
    saved_requirements: list[dict] | None = None,
) -> dict:
    """Scan complete definitions in pages before applying address and name clues.

    The limits bound the work of the scan. The result and its facets report an
    unfinished scan. An unfinished scan supports no absence claim and no
    uniqueness claim.
    """
    hostname, destination_network, port, questions = destination_clue(destination)
    client_network = network(client) if client else None
    if client and client_network is None:
        raise ValueError("Use a client IP address or CIDR prefix.")
    destinations = [destination_network] if destination_network is not None else []
    dns_complete = True
    dns_choices: list[dict] = []
    if hostname:
        destinations, dns_complete, dns_choices = _host_addresses(session, hostname)
        if not destinations:
            questions.append(
                f"No recorded address evidence resolves {hostname} in this snapshot. "
                "Provide a destination IP or collect the missing hostname evidence."
            )
        if not dns_complete:
            questions.append(
                "Recorded hostname evidence exceeded its bound; the match list is not proven complete."
            )
    started = time.monotonic()
    catalog = []
    after = None
    complete = True
    used_bytes = 0
    scanned = 0
    while scanned < MAX_SERVICES:
        if time.monotonic() - started > MAX_SECONDS:
            complete = False
            break
        page = read_page(after, min(PAGE_SIZE, MAX_SERVICES - scanned))
        rows = page["items"]
        for row in rows:
            used_bytes += len(json.dumps(row).encode())
            if used_bytes > MAX_BYTES:
                complete = False
                break
            catalog.append(row)
        scanned += len(rows)
        if not complete or not page["truncated"]:
            break
        cursor = page.get("cursor")
        if not rows or cursor is None or (after is not None and cursor <= after):
            complete = False
            break
        after = cursor
        if scanned >= MAX_SERVICES:
            complete = False
    saved = saved_requirements or []
    catalog.extend(_saved_items(session, saved))
    saved_complete = len(saved) < MAX_SERVICES
    locations: set[str] = set()
    applications: set[str] = set()
    matches = []
    for original in catalog:
        item = dict(original)
        request = item.get("definition", {})
        item["locations"] = sorted(set(item.get("locations", [])))
        app_names = item.get("applications", [])
        item["applications"] = sorted(set(app_names or [request.get("destination") or item["name"]]))
        item["description"] = (
            f"{', '.join(request.get('sources', []))} to "
            f"{request.get('destination', item['name'])}; "
            f"{request.get('success', 'unspecified')} connectivity"
        )
        locations.update(item["locations"])
        applications.update(item["applications"])
        reasons = []
        if (
            q
            and q.casefold()
            not in " ".join(
                [item["name"], item["uid"], item["description"], *item["locations"], *item["applications"]]
            ).casefold()
        ):
            continue
        if destination:
            addresses = [a for member in request.get("members", []) for a in member.get("addresses", [])]
            if not destinations or not _overlaps(destinations, addresses):
                continue
            if port is not None and not any(
                _overlaps(destinations, member.get("addresses", []))
                and _port_matches({**request, "members": [member]}, port)
                for member in request.get("members", [])
            ):
                continue
            reasons.append(
                f"Recorded destination addresses overlap {destination_network or hostname}."
                + (f" The service includes destination port {port}." if port is not None else "")
            )
        if client_network is not None:
            if not _overlaps([client_network], request.get("sources", [])):
                continue
            reasons.append(f"Recorded client population overlaps {client_network}.")
        if location:
            if not any(location.casefold() in value.casefold() for value in item["locations"]):
                continue
            reasons.append(f"Recorded source location or context matches {location}.")
        if application:
            if not any(
                application.casefold() in value.casefold() for value in [item["name"], *item["applications"]]
            ):
                continue
            reasons.append(f"Recorded application or destination name matches {application}.")
        item["match_reasons"] = reasons or [
            "Browse this recorded service definition."
            if item.get("origin") != "saved"
            else "Browse this saved service revision."
        ]
        matches.append(item)
    matches.sort(key=lambda item: (item["name"].casefold(), item.get("origin", "graph"), item["uid"]))
    if not matches and any((destination, client, location, application, q)):
        questions.append(
            "No service definition matched all supplied clues. Refine one clue, browse applications "
            "or locations, or define the traffic manually."
        )
    if not complete or not saved_complete:
        questions.append(
            "The service catalog scan is incomplete; "
            "a missing match does not establish that no service exists."
        )
    metadata_complete = all(item.get("metadata_complete", True) for item in catalog)
    if not metadata_complete:
        questions.append(
            "Recorded location or application relationships exceed their bound; the grouping is incomplete."
        )
    traffic: dict[str, Any] = {"items": [], "complete": True, "truncated": False, "scanned": 0}
    if any((destination, client, location)):
        from hst.assessment.traffic_discovery import address_choices

        traffic = address_choices(
            session, destinations=destinations, client=client_network, location=location
        )
        if traffic["truncated"]:
            questions.append(
                "Recorded address choices are incomplete; narrow the clues before selecting traffic."
            )
    return {
        "traffic_options": [*dns_choices, *traffic["items"]],
        "traffic_options_truncated": traffic["truncated"] or not dns_complete,
        "items": matches[:limit],
        "truncated": len(matches) > limit or not complete or not saved_complete,
        "facets": {"locations": sorted(locations), "applications": sorted(applications)},
        "questions": questions,
        "catalog_complete": complete and saved_complete and metadata_complete and dns_complete,
        "saved_catalog_complete": saved_complete,
        "scanned": scanned,
        "saved_scanned": len(saved),
        "matched_count": len(matches),
    }
