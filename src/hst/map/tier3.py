"""Tier 3 holds the logical objects of one device at a warm run, read from the graph.

This module is the one module of the map that opens a graph session. The no-graph gate excludes it by name.
"""

from __future__ import annotations

from typing import Any

from hst.core import db as dbmod
from hst.core.config import Settings
from hst.core.labels import RESERVED_LABELS

from .tiers import bootstrap

_ROW = "x {.uid, .name, label: head([l IN labels(x) WHERE NOT l IN $reserved])}"


def _query(pattern: str) -> str:
    return bootstrap._ANCHOR + f"OPTIONAL MATCH {pattern}\nRETURN collect(DISTINCT {_ROW}) AS xs"


QUERIES: dict[str, list[str]] = {
    name: [_query(p) for p in paths] for name, paths in bootstrap.CATEGORIES.items()
}


# The interface facts at t of a port or interface uid, one row per node. A row holds the node, its device,
# its port across REALIZED_BY, every interface it realizes, and their contexts, addresses and LAG. The
# pattern comprehensions keep the planner on the seek when the index sample is stale.
INTERFACE = """MATCH (x:Obj) USING INDEX x:Obj(uid, collection_ts)
WHERE x.uid IN $uids AND x.collection_ts = $cts AND (x:Interface OR x:Port)
WITH x, head([(x)-[:ON]->(d:Device) | d.uid]) AS device, head([(x)-[:REALIZED_BY]->(rp:Port) | rp]) AS rp,
     [(ri:Interface)-[:REALIZED_BY]->(x) | ri] AS ris
WITH x, device, CASE WHEN x:Port THEN x ELSE rp END AS p, CASE WHEN x:Interface THEN [x] ELSE ris END AS ifs
UNWIND CASE WHEN ifs = [] THEN [null] ELSE ifs END AS i
OPTIONAL MATCH (i)-[:IN_VRF|IN_CONTEXT]->(c)
OPTIONAL MATCH (z:Zone)-[:CONTAINS]->(i)
OPTIONAL MATCH (i)-[:HAS_IP]->(a:IpAddress)
OPTIONAL MATCH (p)-[:MEMBER_OF]->(l:Lag)
RETURN x.uid AS uid, head([k IN labels(x) WHERE NOT k IN $reserved]) AS label, device,
       collect(DISTINCT properties(i)) AS interfaces, properties(p) AS port,
       collect(DISTINCT c.uid) + collect(DISTINCT z.uid) AS contexts,
       collect(DISTINCT a.uid) AS addresses, collect(DISTINCT l.uid) AS lags"""
_INTERNAL = frozenset({"collection_ts"})
DEVICE = """MATCH (d:Obj) USING INDEX d:Obj(uid, collection_ts)
WHERE d.uid IN $uids AND d.collection_ts = $cts AND d:Device
RETURN d.mac AS mac, d.serial AS serial"""


def queries() -> list[str]:
    return [q for qs in QUERIES.values() for q in qs] + [bootstrap.CONTEXTS, INTERFACE, DEVICE]


def read(session: Any, uid: str, cts: int) -> dict[str, Any]:
    """The objects of each count column for device `uid` at `cts`, its forwarding contexts and its tunnels."""
    params = {"uids": [uid], "cts": cts, "reserved": sorted(RESERVED_LABELS)}
    categories: dict[str, list[dict[str, Any]]] = {}
    for name, qs in QUERIES.items():
        found: dict[str, dict[str, Any]] = {}
        for query in qs:
            for record in session.run(query, **params).data():
                for row in record["xs"]:
                    if row.get("uid") is not None:
                        found.setdefault(row["uid"], row)
        categories[name] = [found[k] for k in sorted(found)]
    contexts = session.run(bootstrap.CONTEXTS, **params).data()
    tunnels: dict[str, dict[str, Any]] = {}
    for query in (bootstrap.TUNNELS_LOCAL, bootstrap.TUNNELS_FAR):
        for t in session.run(query, uids=[uid], cts=cts).data():
            row = {"uid": t["tunnel"], "encap": t.get("encap"), "other": t["other"]}
            tunnels.setdefault(t["tunnel"], row)
    return {
        "categories": categories,
        "tunnels": [tunnels[k] for k in sorted(tunnels)],
        "contexts": [
            {"uid": c["uid"], "name": c.get("name"), "kind": c.get("kind"), "rd": c.get("rd")}
            for c in contexts
        ],
    }


def device(settings: Settings, uid: str, cts: int) -> dict[str, Any]:
    with dbmod.session(settings) as s:
        return read(s, uid, cts)


def segment_clients(session: Any, device: str, bridge_domain: str | None, cts: int) -> list[dict[str, Any]]:
    """The clients of one segment with name, IP addresses, MAC, port and last seen, by name and MAC."""
    rows = session.run(bootstrap.SEGMENT_CLIENTS, device=device, bd=bridge_domain, cts=cts).data()
    return [
        {
            "uid": r["uid"],
            "name": r.get("name"),
            "ip": sorted(x for x in (r.get("ips") or []) if x),
            "mac": r.get("mac"),
            "port": r.get("port"),
            "last_seen_ts": r.get("last_seen_ts"),
        }
        for r in rows
    ]


def segment(settings: Settings, device: str, bridge_domain: str | None, cts: int) -> list[dict[str, Any]]:
    with dbmod.session(settings) as s:
        return segment_clients(s, device, bridge_domain, cts)


def _props(node: dict[str, Any] | None) -> dict[str, Any] | None:
    return None if node is None else {k: node[k] for k in sorted(node) if k not in _INTERNAL}


def interface(session: Any, uid: str, cts: int) -> dict[str, Any] | None:
    """The facts at `cts` of the port or interface `uid`, or None when the run holds no such node.

    A port keeps its own `name`. Its `interface` is the realized one of that name, else the first by name.
    """
    params = {"uids": [uid], "cts": cts, "reserved": sorted(RESERVED_LABELS)}
    record = session.run(INTERFACE, **params).single()
    if record is None:
        return None
    port = _props(record["port"])
    realized = sorted((_props(i) or {} for i in record["interfaces"]), key=lambda i: str(i.get("name", "")))
    if port is not None and port.get("uid") == record["uid"]:
        name = port.get("name") or (realized[0].get("name") if realized else None)
        interface = next((i for i in realized if i.get("name") == name), realized[0] if realized else None)
    else:
        interface = realized[0] if realized else None
        name = (interface or {}).get("name") or (port or {}).get("name")
    return {
        "uid": record["uid"],
        "label": record["label"],
        "device_uid": record["device"],
        "name": name,
        "interface": interface,
        "interfaces": [i["name"] for i in realized if i.get("name")],
        "port": port,
        "contexts": sorted(c for c in record["contexts"] if c),
        "addresses": sorted(record["addresses"]),
        "lags": sorted(record["lags"]),
    }


def interface_facts(settings: Settings, uid: str, cts: int) -> dict[str, Any] | None:
    with dbmod.session(settings) as s:
        return interface(s, uid, cts)


def device_ids(settings: Settings, uid: str, cts: int) -> dict[str, Any] | None:
    """The `mac` and `serial` of Device `uid` at `cts`, or None when the run holds no such device."""
    with dbmod.session(settings) as s:
        record = s.run(DEVICE, uids=[uid], cts=cts).single()
    return None if record is None else {"mac": record["mac"], "serial": record["serial"]}


def _device_payload(
    settings: Settings, key: str, device_uid: str, run_key: int
) -> tuple[dict[str, Any], int | None] | None:
    """The raw payload that provides Device `device_uid`'s state at `run_key`, and its fetch time.

    The run's manifest names the fetch (`effective_run`). Its raw payload is decrypted with the
    data-encryption key `key`. None when the manifest names no fetch for the device.
    """
    from hst.core import manifest, rawstore

    record = manifest.read(settings, run_key)
    entry = next((d for d in record.devices if device_uid in d.device_uids), None)
    if entry is None or entry.effective_run is None:
        return None
    raw = next((f for f in record.files if f.kind == "raw" and f.run_id == entry.effective_run), None)
    if raw is None:
        return None
    payload = rawstore.read(settings.hst_data_dir / raw.path, key)
    if not isinstance(payload, dict):
        return None
    head = entry.effective_run.split("-", 1)[0]
    return payload, int(head) if head.isdigit() else None


def interface_text(
    settings: Settings, key: str, device_uid: str, run_key: int, name: str
) -> dict[str, Any] | None:
    """`{command, fetched_ts, text}`: the redacted configuration of interface `name` at `run_key`.

    The payload is the one `_device_payload` reads. A UniFi payload holds every device of the
    controller. The identifiers of the graph Device select the device in it. None when the manifest names
    no fetch for the device or the payload holds no configuration for the interface.
    """
    from hst.core import debug_capture

    from . import interface_text as extract

    found_payload = _device_payload(settings, key, device_uid, run_key)
    if found_payload is None:
        return None
    payload, fetched = found_payload
    device = device_ids(settings, device_uid, run_key) if extract.is_unifi(payload) else None
    found = extract.section(payload, name, device)
    if found is None:
        return None
    command, text = found
    return {"command": command, "fetched_ts": fetched, "text": debug_capture.redact(text)}


def device_text(settings: Settings, key: str, device_uid: str, run_key: int) -> dict[str, Any] | None:
    """`{fetched_ts, sections}`: the redacted version, routing, ACL and NAT sections of Device
    `device_uid` at `run_key` (`interface_text.device_sections`), from the payload `_device_payload`
    reads. None when the manifest names no fetch for the device."""
    from hst.core import debug_capture

    from . import interface_text as extract

    found = _device_payload(settings, key, device_uid, run_key)
    if found is None:
        return None
    payload, fetched = found
    sections = [
        {**s, "parts": [{**p, "text": debug_capture.redact(p["text"])} for p in s["parts"]]}
        for s in extract.device_sections(payload)
    ]
    return {"fetched_ts": fetched, "sections": sections}
