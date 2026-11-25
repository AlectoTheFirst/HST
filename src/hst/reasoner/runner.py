"""`run()` clears the reasoner writes of the cycle and runs every rule."""

from __future__ import annotations

import time
from typing import Any

from hst.core.loader import CHUNK
from hst.reasoner._constants import (
    ACTIVE_CIRCUIT_STATES,
    CLEAR,
    CLEAR_PROPS,
    ENDED_CIRCUIT_STATES,
    GATEWAY_ROLES,
    STATED_CABLE_SOURCES,
)
from hst.reasoner.catalog import RULES
from hst.reasoner.containment import (
    CONTAINMENT_ADDRESSES,
    CONTAINMENT_BD_MAP,
    CONTAINMENT_PREFIXES,
    CONTAINMENT_WRITE,
    containment_pairs,
)
from hst.reasoner.edge_devices import EDGE_DEVICE_RULE, _run_edge_device_rule
from hst.reasoner.fabric_ports import FABRIC_PORT_RULE, _run_fabric_port_rule
from hst.reasoner.stated_cables import _run_stated_cable_rules
from hst.reasoner.zscaler import ZPA_ZIA_SAME_AS_RULE, _run_zpa_zia_same_as_rule


def run(session: Any, ts_ms: int | None = None, collection_ts: int | None = None) -> list[dict[str, Any]]:
    """Drop the cycle's reasoner-owned writes and rebuild them from its facts.

    `collection_ts` is the run to reason over. Without `collection_ts`, the
    run of the pointer is used. Before the first run exists, `ts` is the run
    key.

    Every step runs in a bounded transaction of its own. Each rule reads the
    edges that the rules before it committed.

    It is called only for a run that is not yet the run of the pointer. Every
    write is an idempotent MERGE, SET or DELETE.
    """
    ts = ts_ms if ts_ms is not None else int(time.time() * 1000)
    cts = collection_ts
    if cts is None:
        from hst.core import cycle as cyclemod

        cts = cyclemod.current_ts_or_none(session)
    if cts is None:
        cts = ts

    def clear(tx: Any) -> int:
        rows = tx.run(CLEAR, cts=cts, limit=CHUNK).data()
        return rows[0]["n"] if rows else 0

    def rule(tx: Any, query: str) -> list[dict[str, Any]]:
        return tx.run(
            query,
            ts=ts,
            cts=cts,
            gateway_roles=GATEWAY_ROLES,
            stated_cable_sources=STATED_CABLE_SOURCES,
            ended_circuit_states=ENDED_CIRCUIT_STATES,
            active_circuit_states=ACTIVE_CIRCUIT_STATES,
        ).data()

    def candidates(tx: Any) -> list[list[dict[str, Any]]]:
        return [
            tx.run(CONTAINMENT_ADDRESSES, cts=cts).data(),
            tx.run(CONTAINMENT_PREFIXES, cts=cts).data(),
            tx.run(CONTAINMENT_BD_MAP, cts=cts).data(),
        ]

    def write_containment(tx: Any, chunk: list[dict[str, str]]) -> int:
        rows = tx.run(CONTAINMENT_WRITE, pairs=chunk, ts=ts, cts=cts).data()
        return rows[0]["n"] if rows else 0

    # execute_write retries on DeadlockDetected.
    while session.execute_write(clear) >= CHUNK:
        pass
    session.execute_write(lambda tx: tx.run(CLEAR_PROPS, cts=cts).consume())
    results = []
    stated_cables: dict[str, dict[str, Any]] | None = None
    for name, query in RULES:
        if name == FABRIC_PORT_RULE:
            report = session.execute_write(lambda tx: _run_fabric_port_rule(tx, ts=ts, cts=cts))
            results.append({"rule": name, **report})
            continue
        if name == EDGE_DEVICE_RULE:
            report = session.execute_write(lambda tx: _run_edge_device_rule(tx, ts=ts, cts=cts))
            results.append({"rule": name, **report})
            continue
        if name == ZPA_ZIA_SAME_AS_RULE:
            report = session.execute_write(lambda tx: _run_zpa_zia_same_as_rule(tx, ts=ts, cts=cts))
            results.append({"rule": name, **report})
            continue
        if query is None:
            # cable-from-uplink-record, cable-from-lldp-record and
            # cable-from-neighbor-name are resolved together from one fetch
            # when the first of them is reached.
            if stated_cables is None:
                stated_cables = _run_stated_cable_rules(session, ts=ts, cts=cts)
            bucket = stated_cables[name]
            results.append({"rule": name, **bucket})
            continue
        rows = session.execute_write(lambda tx, q=query: rule(tx, q))
        row = rows[0] if rows else {}
        # Every rule query returns its edge count as `n`.
        result: dict[str, Any] = {"rule": name, "edges": row.get("n", 0)}
        result.update({k: v for k, v in row.items() if k != "n"})
        results.append(result)
    pairs = containment_pairs(*session.execute_read(candidates))
    edges = 0
    for i in range(0, len(pairs), CHUNK):
        edges += session.execute_write(lambda tx, chunk=pairs[i : i + CHUNK]: write_containment(tx, chunk))
    results.append({"rule": "address-containment", "edges": edges})
    return results
