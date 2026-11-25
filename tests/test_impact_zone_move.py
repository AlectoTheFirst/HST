from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException
from tests.support.query_text import unpinned

from hst import path as pathmod
from hst.impact.evaluate import GraphGates
from hst.simul.fw_overlay import Catalog, ChangeSet, parse_intents

ZONE_PAIR = "MATCH (rb:FwRulebase)-[fz:FROM_ZONE]->(src), (rb)-[tz:TO_ZONE]->(dst)"
ZONE_PAIR_READ = f"{ZONE_PAIR} RETURN rb"

CATALOG = Catalog(
    zones={
        "zone:lan": {"uid": "zone:lan", "name": "LAN", "interfaces": ["eth0"]},
        "zone:wan": {"uid": "zone:wan", "name": "WAN", "interfaces": ["eth1"]},
        "zone:dmz": {"uid": "zone:dmz", "name": "DMZ", "interfaces": []},
    }
)
MOVE = {"kind": "zone.add_interface", "params": {"zone": "zone:dmz", "interface": "if:eth1"}}


class _Tx:
    def __init__(self, session: "_Session") -> None:
        self._session = session

    def run(self, query: str, **params: Any) -> Any:
        self._session.reads.append((unpinned(query), params))
        rows = self._session.answer(unpinned(query), params)

        class _Result:
            def data(self) -> list[dict[str, Any]]:
                return rows

        return _Result()


class _Session:
    """The pinned session the engine's gates read: the collected zone of each
    interface, and the rulebases bound to each zone pair."""

    cts = 1

    def __init__(self) -> None:
        self.reads: list[tuple[str, dict[str, Any]]] = []

    def execute_read(self, work: Any, /) -> Any:
        return work(_Tx(self))

    def answer(self, query: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        if "(:Interface" in query and "CONTAINS" in query:
            return [{"uid": {"if:eth0": "zone:lan", "if:eth1": "zone:wan"}[params["iface"]], "name": "x"}]
        if ZONE_PAIR in query and "src" in params:
            return [{"rb_uid": f"fw:{params['src']}->{params['dst']}"}]
        if ZONE_PAIR in query:
            return [{"rb_uid": "fw:collected-pair"}]
        return []


def _changes() -> ChangeSet:
    return ChangeSet(intents=parse_intents([MOVE], CATALOG), catalog=CATALOG)


def test_the_after_session_installs_the_zone_lookups():
    changes = _changes()
    assert changes.zone_of is None and changes.pair_rows is None
    GraphGates(_Session()).with_changes(changes)
    assert changes.zone_of is not None and changes.pair_rows is not None


def test_a_flow_through_a_moved_interface_reads_the_pair_of_the_effective_zones():
    session = _Session()
    changes = _changes()
    gates = GraphGates(session).with_changes(changes)

    rows = pathmod._read(gates.session, ZONE_PAIR_READ, in_if="if:eth0", out_if="if:eth1")

    assert [r["rb_uid"] for r in rows] == ["fw:zone:lan->zone:dmz"]
    assert changes.errors.as_dicts() == []
    # an interface the change does not move keeps the collected pair
    untouched = pathmod._read(gates.session, ZONE_PAIR_READ, in_if="if:eth0", out_if="if:eth2")
    assert [r["rb_uid"] for r in untouched] == ["fw:collected-pair"]


def test_the_zone_lookups_see_the_graph_as_collected_and_share_the_read_cache():
    session = _Session()
    session._read_cache = {}  # type: ignore[attr-defined]
    changes = _changes()
    gates = GraphGates(session).with_changes(changes)
    assert gates.session._read_cache is session._read_cache

    for _ in range(3):
        pathmod._read(gates.session, ZONE_PAIR_READ, in_if="if:eth0", out_if="if:eth1")

    # one read per interface and one for the pair, however often the flow reads
    assert len([q for q, _p in session.reads if "CONTAINS" in q]) == 2
    assert len([q for q, _p in session.reads if q.endswith("RETURN rb")]) == 1


def test_an_inner_overlay_is_kept_when_the_zone_lookups_read():
    session = _Session()
    seen: list[str] = []

    def inner(query: str, params: dict[str, Any], rows: Any) -> Any:
        seen.append(query)
        return rows

    session.overlay = inner  # type: ignore[attr-defined]
    gates = GraphGates(session).with_changes(_changes())

    pathmod._read(gates.session, ZONE_PAIR_READ, in_if="if:eth0", out_if="if:eth1")

    # the flow's read, the zone of each of its two interfaces and the new pair,
    # each through it
    assert len(seen) == 4


def test_a_change_set_that_leaves_a_zone_move_unresolved_fails_closed(monkeypatch):
    from hst.assessment import evaluation

    class _Unresolved:
        intents: list[Any] = []

    def change_set(session: Any, intents: Any, errors: Any) -> Any:
        errors.report("zone-move-not-resolvable", "no zone lookup was supplied", "if:eth1")
        return _Unresolved()

    monkeypatch.setattr(evaluation, "_change_set", change_set)
    monkeypatch.setattr(evaluation, "evaluate_impact", lambda *a, **k: object())
    with pytest.raises(HTTPException) as raised:
        evaluation._evaluate_change(
            _Session(),
            intents=[MOVE],
            request=object(),  # type: ignore[arg-type]
            network=SimpleNamespace(interfaces=()),  # type: ignore[arg-type]
        )
    assert raised.value.status_code == 422
