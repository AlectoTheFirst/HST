"""The fabric-port-from-description rule."""

from __future__ import annotations

import re
from typing import Any

# An operator writes the name of the Equinix port and its cable id in the
# description of the switch port where the cross connect ends, for example
# `TO EQUINIX FABRIC - XX1-EXT-PRI-01 - CABLE ID : 21000001 - 10 GBPS`. The
# Fabric API states the same 2 values as the port `name` and the
# `crossConnectId` of each physical port (`FabricPort.cross_connect_ids`,
# without the `-A` suffix). The name is matched as a whole word without
# regard to case. `...-PRI-01` does not match `...-PRI-010`.

FABRIC_PORT_RULE = "fabric-port-from-description"

FETCH_FABRIC_PORTS = """
MATCH (fp:FabricPort:Obj)
WHERE NOT fp:Retired AND fp.collection_ts = $cts AND fp.name IS NOT NULL
RETURN fp.uid AS uid, fp.name AS name, fp.cross_connect_ids AS cross_connect_ids,
       fp.bound_port_uid AS bound_port_uid
"""

FETCH_DESCRIBED_PORTS = """
MATCH (p:Port:Obj)
WHERE NOT p:Retired AND p.collection_ts = $cts AND p.description IS NOT NULL
RETURN p.uid AS uid, p.description AS description
"""

FABRIC_PORT_WRITE = """
UNWIND $edges AS e
MATCH (fp:FabricPort:Obj {uid: e.fabric_port, collection_ts: $cts})
WHERE NOT fp:Retired
MATCH (p:Port:Obj {uid: e.port, collection_ts: $cts})
WHERE NOT p:Retired
MERGE (fp)-[r:REALIZED_BY {source: 'reasoner'}]->(p)
SET r.derived = true, r.rule = 'fabric-port-from-description', r.evidence = e.evidence,
    r._scope = 'reasoner', r.collection_ts = $cts, r.collected_at = $ts
RETURN count(*) AS n
"""

_CABLE_ID_RE = re.compile(r"\b(?:CABLE\s*ID|CCID)\s*:?\s*(\d+)", re.IGNORECASE)


_WORD_NAME = re.compile(r"[A-Za-z0-9-]+")


def _fabric_port_matcher(fabric_ports: list[dict[str, Any]]) -> Any:
    """A function from a description to the Fabric ports whose name is in it
    as a whole word, sorted by uid.

    A name of ASCII letters, digits and hyphens matches when it is one of the
    maximal runs of `[A-Za-z0-9-]` in the description. The function finds
    such a name with a dict lookup. Any other name uses a whole-word pattern
    that is compiled once."""
    by_word: dict[str, list[dict[str, Any]]] = {}
    patterns: list[tuple[re.Pattern[str], dict[str, Any]]] = []
    for fp in fabric_ports:
        name = fp.get("name")
        if not name:
            continue
        if _WORD_NAME.fullmatch(name) and name.isascii():
            by_word.setdefault(name.lower(), []).append(fp)
        else:
            patterns.append((re.compile(rf"(?<![A-Z0-9-]){re.escape(name)}(?![A-Z0-9-])", re.IGNORECASE), fp))

    def named(description: str) -> list[dict[str, Any]]:
        found = {
            fp["uid"]: fp for word in _WORD_NAME.findall(description) for fp in by_word.get(word.lower(), [])
        }
        for pattern, fp in patterns:
            if pattern.search(description):
                found[fp["uid"]] = fp
        return [found[uid] for uid in sorted(found)]

    return named


def resolve_fabric_port_bindings(
    fabric_ports: list[dict[str, Any]], ports: list[dict[str, Any]]
) -> dict[str, Any]:
    """The REALIZED_BY edges that the port descriptions state, as `{"edges":
    [{"fabric_port", "port", "evidence"}], "conflicts": [...], "ambiguous":
    [...]}`.

    `evidence` is `name+cable` when the cable id of the description is one of
    the cross-connect ids of the Fabric port, and `name` when the description
    states no cable id. A conflict row holds the Fabric port, the port and
    the 2 cable id sets. An ambiguous row holds the Fabric port or the port,
    and every candidate.

    A Fabric port that the operator bound, and a port that the operator bound
    a Fabric port to, are left to that binding. A port whose description has
    2 Fabric port names is ambiguous also when the operator bound one of them."""
    operator_targets = {fp["bound_port_uid"] for fp in fabric_ports if fp.get("bound_port_uid")}
    names_of = _fabric_port_matcher(fabric_ports)
    matches: dict[str, list[tuple[str, str]]] = {}
    conflicts: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []
    for port in sorted(ports, key=lambda p: p["uid"]):
        if port["uid"] in operator_targets:
            continue
        named = names_of(port.get("description") or "")
        text = port.get("description") or ""
        if not named:
            continue
        if len(named) > 1:
            ambiguous.append({"port": port["uid"], "fabric_ports": sorted(fp["uid"] for fp in named)})
            continue
        fp = named[0]
        if fp.get("bound_port_uid"):
            continue
        stated = set(_CABLE_ID_RE.findall(text))
        known = set(fp.get("cross_connect_ids") or [])
        if stated and not stated & known:
            conflicts.append(
                {
                    "fabric_port": fp["uid"],
                    "port": port["uid"],
                    "stated": sorted(stated),
                    "cross_connect_ids": sorted(known),
                }
            )
            continue
        matches.setdefault(fp["uid"], []).append((port["uid"], "name+cable" if stated else "name"))
    edges: list[dict[str, str]] = []
    for fabric_port, found in sorted(matches.items()):
        if len(found) > 1:
            ambiguous.append({"fabric_port": fabric_port, "ports": sorted(p for p, _ in found)})
            continue
        port_uid, evidence = found[0]
        edges.append({"fabric_port": fabric_port, "port": port_uid, "evidence": evidence})
    return {"edges": edges, "conflicts": conflicts, "ambiguous": ambiguous}


FABRIC_PORT_ISSUE_WRITE = """
UNWIND $issues AS e
MATCH (fp:FabricPort:Obj {uid: e.fabric_port, collection_ts: $cts})
WHERE NOT fp:Retired
SET fp.binding_issue = e.issue, fp.binding_ports = e.ports
RETURN count(*) AS n
"""


def fabric_port_issues(fabric_ports: list[dict[str, Any]], report: dict[str, Any]) -> list[dict[str, Any]]:
    """The issue of each Fabric port that has no operator binding, no derived
    edge and a row in `report`.

    The issue is `cable-conflict` (a description states a cable id that the
    Fabric port does not have), `several-ports` (more than one port
    description has its name) or `several-fabric-ports` (a port description
    has its name and the name of another Fabric port). A result row holds the
    first issue that applies and the sorted port uids of its report rows. The
    function is pure."""
    bound = {e["fabric_port"] for e in report["edges"]}
    out = []
    for fp in sorted(fabric_ports, key=lambda f: f["uid"]):
        uid = fp["uid"]
        if fp.get("bound_port_uid") or uid in bound:
            continue
        conflict = sorted(c["port"] for c in report["conflicts"] if c["fabric_port"] == uid)
        several = sorted(p for a in report["ambiguous"] if a.get("fabric_port") == uid for p in a["ports"])
        across = sorted(a["port"] for a in report["ambiguous"] if uid in (a.get("fabric_ports") or []))
        for issue, ports in (
            ("cable-conflict", conflict),
            ("several-ports", several),
            ("several-fabric-ports", across),
        ):
            if ports:
                out.append({"fabric_port": uid, "issue": issue, "ports": ports})
                break
    return out


def fabric_port_warnings(report: dict[str, Any]) -> list[str]:
    """One run warning per conflict and per ambiguous row of the report. The function is pure."""
    lines = []
    for c in report["conflicts"]:
        lines.append(
            f"{FABRIC_PORT_RULE}: port {c['port']} names Fabric port {c['fabric_port']} with cable id "
            f"{', '.join(c['stated'])}; the Fabric port has {', '.join(c['cross_connect_ids']) or 'none'}; "
            "no binding"
        )
    for a in report["ambiguous"]:
        if a.get("fabric_port"):
            lines.append(
                f"{FABRIC_PORT_RULE}: {len(a['ports'])} ports name Fabric port {a['fabric_port']} "
                f"({', '.join(a['ports'])}); no binding"
            )
        else:
            lines.append(
                f"{FABRIC_PORT_RULE}: port {a['port']} names {len(a['fabric_ports'])} Fabric ports "
                f"({', '.join(a['fabric_ports'])}); no binding"
            )
    return lines


def _run_fabric_port_rule(tx: Any, *, ts: int, cts: int) -> dict[str, Any]:
    fabric_ports = tx.run(FETCH_FABRIC_PORTS, cts=cts).data()
    report = resolve_fabric_port_bindings(fabric_ports, tx.run(FETCH_DESCRIBED_PORTS, cts=cts).data())
    edges = 0
    if report["edges"]:
        rows = tx.run(FABRIC_PORT_WRITE, edges=report["edges"], ts=ts, cts=cts).data()
        edges = rows[0]["n"] if rows else 0
    issues = fabric_port_issues(fabric_ports, report)
    if issues:
        tx.run(FABRIC_PORT_ISSUE_WRITE, issues=issues, cts=cts).consume()
    return {
        "edges": edges,
        "conflicts": len(report["conflicts"]),
        "ambiguous": len(report["ambiguous"]),
        "warnings": fabric_port_warnings(report),
    }
