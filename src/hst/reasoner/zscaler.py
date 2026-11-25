"""The zpa-zia-ip-same-as rule and the zscaler check."""

from __future__ import annotations

import ipaddress
from typing import Any

# The zpa-zia-ip-same-as rule.
#
# The private_ip of a connector, the address of a static AppServer and the
# source_ip of a ZIA tunnel are collected as string properties. No Zscaler
# answer holds the forwarding context of an IpAddress uid. The join is on the
# address value.

ZPA_ZIA_SAME_AS_RULE = "zpa-zia-ip-same-as"

GLOBAL_ADDRESS_CONFIDENCE = 0.8
PRIVATE_ADDRESS_CONFIDENCE = 0.6

FETCH_ZSCALER_ADDRESSES = """
CALL {
  MATCH (n:ZpaAppConnector:Obj) WHERE n.collection_ts = $cts RETURN n
  UNION
  MATCH (n:AppServer:Obj) WHERE n.collection_ts = $cts RETURN n
  UNION
  MATCH (n:Tunnel:Obj) WHERE n.collection_ts = $cts AND n.uid STARTS WITH 'zia:' RETURN n
}
WITH n WHERE NOT n:Retired
RETURN n.uid AS uid,
       CASE WHEN n:ZpaAppConnector THEN 'private_ip' WHEN n:AppServer THEN 'address'
            ELSE 'source_ip' END AS basis,
       CASE WHEN n:ZpaAppConnector THEN n.private_ip WHEN n:AppServer THEN n.address
            ELSE n.source_ip END AS ip
"""

FETCH_CAMPUS_ADDRESSES = """
MATCH (h)-[r:HAS_IP]->(ia:IpAddress:Obj)
WHERE ia.ip IN $ips AND r._retired_at IS NULL AND NOT h:Retired AND NOT ia:Retired
  AND ia.collection_ts = $cts
RETURN DISTINCT ia.uid AS uid, ia.ip AS ip
"""

ZPA_ZIA_SAME_AS_WRITE = """
UNWIND $rows AS e
MATCH (a:Obj {uid: e.a, collection_ts: $cts}) WHERE a.collection_ts = $cts
MATCH (b:IpAddress:Obj {uid: e.b, collection_ts: $cts}) WHERE b.collection_ts = $cts
MERGE (a)-[r:SAME_AS {source: 'reasoner', basis: e.basis}]->(b)
SET r.derived = true, r.rule = 'zpa-zia-ip-same-as', r.confidence = e.confidence,
    r._scope = 'reasoner', r.collection_ts = $cts, r.collected_at = $ts
RETURN count(*) AS n
"""


def _address(value: Any) -> str | None:
    """The canonical text of an IP address, or None for a host name or junk."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def resolve_zpa_zia_ip_links(
    zscaler: list[dict[str, Any]], campus: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """`SAME_AS` rows (`{"a", "b", "basis", "confidence"}`) from each Zscaler node
    (`{"uid", "basis", "ip"}`) to every campus `IpAddress` (`{"uid", "ip"}`) with the
    same address. The result has one row per campus match."""
    by_ip: dict[str, list[str]] = {}
    for row in campus:
        ip = _address(row.get("ip"))
        if ip:
            by_ip.setdefault(ip, []).append(row["uid"])
    rows: list[dict[str, Any]] = []
    for node in zscaler:
        ip = _address(node.get("ip"))
        if not ip:
            continue
        parsed = ipaddress.ip_address(ip)
        # An unspecified, loopback or link-local address does not identify one host.
        if parsed.is_unspecified or parsed.is_loopback or parsed.is_link_local:
            continue
        confidence = (
            GLOBAL_ADDRESS_CONFIDENCE if ipaddress.ip_address(ip).is_global else PRIVATE_ADDRESS_CONFIDENCE
        )
        for campus_uid in by_ip.get(ip, []):
            rows.append({"a": node["uid"], "b": campus_uid, "basis": node["basis"], "confidence": confidence})
    return sorted(rows, key=lambda r: (r["a"], r["b"]))


def _run_zpa_zia_same_as_rule(tx: Any, *, ts: int, cts: int) -> dict[str, Any]:
    zscaler = tx.run(FETCH_ZSCALER_ADDRESSES, cts=cts).data()
    ips = sorted({ip for row in zscaler if (ip := _address(row.get("ip")))})
    if not ips:
        return {"edges": 0}
    campus = tx.run(FETCH_CAMPUS_ADDRESSES, cts=cts, ips=ips).data()
    rows = resolve_zpa_zia_ip_links(zscaler, campus)
    if not rows:
        return {"edges": 0}
    result = tx.run(ZPA_ZIA_SAME_AS_WRITE, rows=rows, ts=ts, cts=cts).data()
    return {"edges": result[0]["n"] if result else 0}


# The zscaler check reports ZIA-only sites and shared Zscaler scopes.

FETCH_ZIA_ONLY_SITES = """
MATCH (loc:ZiaLocation:Obj)-[rp:REPRESENTS]->(s:Site)
WHERE NOT loc:Retired AND NOT s:Retired AND rp._retired_at IS NULL
  AND loc.collection_ts = $cts
  AND NOT EXISTS {
    MATCH (n)-[li:LOCATED_IN]->(s)
    WHERE NOT n:ZiaLocation AND NOT n:Retired AND li._retired_at IS NULL
      AND n.collection_ts = $cts
  }
RETURN s.code AS site, collect(DISTINCT loc.name) AS locations
ORDER BY site"""

FETCH_SHARED_ZSCALER_SCOPES = """
MATCH (r:CollectionRun)
WHERE r.snapshot_ts = $cts AND (r.scope STARTS WITH 'zia:' OR r.scope STARTS WITH 'zpa:')
WITH r.scope AS scope, count(DISTINCT r.uid) AS loads
WHERE loads > 1
RETURN scope, loads
ORDER BY scope"""

ZSCALER_SITE_WARNINGS = 20


def check_zscaler(session: Any, *, collection_ts: int) -> dict[str, Any]:
    """The `zscaler` check over one run. It only reads.

    Returns `{"sites": [...], "shared_scopes": [...], "warnings": [...]}`.
    `sites` holds the sites that only ZIA locations represent, with no device
    or port located in them. `shared_scopes` holds the Zscaler scopes that
    more than one load wrote in the run."""

    def reads(tx: Any) -> tuple[list[dict[str, Any]], ...]:
        return (
            tx.run(FETCH_ZIA_ONLY_SITES, cts=collection_ts).data(),
            tx.run(FETCH_SHARED_ZSCALER_SCOPES, cts=collection_ts).data(),
        )

    sites, shared = session.execute_read(reads)
    warnings = [
        f"ZIA site {row['site']}: only ZIA locations name it ({', '.join(sorted(row['locations']))}); "
        "no device or port is located in it in this run"
        for row in sites[:ZSCALER_SITE_WARNINGS]
    ]
    if len(sites) > ZSCALER_SITE_WARNINGS:
        warnings.append(f"{len(sites) - ZSCALER_SITE_WARNINGS} more ZIA site(s) that only ZIA locations name")
    warnings.extend(
        f"{row['loads']} sources write scope {row['scope']} in this run; objects with the same Zscaler id "
        "share one node"
        for row in shared
    )
    return {"sites": sites, "shared_scopes": shared, "warnings": warnings}
