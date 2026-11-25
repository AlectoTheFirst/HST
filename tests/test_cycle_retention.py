"""Graph retention counts device and refresh runs on their own (core/cycle.py `_partition`).

Each device or refresh run is a full copy of the graph and the scheduler builds
one every device_run_interval_s. These tests run
the real `prune` and `retained_runs` over a fake session that answers the run
listing and records the deletes.
"""

from __future__ import annotations

import pytest

from hst.core import Settings
from hst.core import cycle as cyclemod


class _Result:
    def __init__(self, rows):
        self.rows = rows

    def data(self):
        return self.rows

    def consume(self):
        return None


class _Tx:
    def __init__(self, session):
        self.session = session

    def run(self, query, **params):
        return self.session.run(query, **params)


class _Session:
    """CycleRun nodes as rows of cts, kind and state, and the keys that hold
    objects. Every statement a prune issues is answered; `events` records the
    deletes in order."""

    def __init__(self, runs, pointer, objects=None):
        self.runs = list(runs)
        self.pointer = pointer
        self.objects = {r["cts"] for r in runs} if objects is None else set(objects)
        self.events: list[tuple[str, int]] = []
        self.writes: list[tuple[str, dict]] = []

    @property
    def deleted(self) -> list[int]:
        return [cts for kind, cts in self.events if kind == "objects"]

    def run(self, query, **params):
        if "CyclePointer" in query:
            return _Result([{"current": self.pointer}])
        if "coalesce(c.state" in query and "ORDER BY c.cts DESC" in query:
            rows = [{"cts": r["cts"], "kind": r["kind"], "state": r.get("state", "built")} for r in self.runs]
            return _Result(sorted(rows, key=lambda r: -r["cts"]))
        if "MATCH (n:Obj) WHERE n.collection_ts < $below" in query:
            return _Result([{"cts": c} for c in sorted(self.objects) if c < params["below"]])
        if "MATCH (r:CollectionRun) WHERE r.snapshot_ts < $below" in query:
            return _Result([])
        if "-[r]->()" in query:
            self.events.append(("rels", params["cts"]))
            return _Result([])
        if "DETACH DELETE n" in query:
            self.events.append(("objects", params["cts"]))
            self.objects.discard(params["cts"])
            return _Result([])
        if "MATCH (r:CollectionRun {snapshot_ts" in query:
            self.events.append(("load", params["cts"]))
            return _Result([])
        if "MATCH (c:CycleRun {uid" in query and "DELETE c" in query:
            self.events.append(("node", int(params["uid"].split(":")[1])))
            self.runs = [r for r in self.runs if f"cycle:{r['cts']}" != params["uid"]]
            return _Result([])
        if "MERGE (c:Obj:CycleRun:Meta" in query:
            self.writes.append((query, params))
            return _Result([])
        raise AssertionError(query)

    def execute_read(self, fn):
        return fn(_Tx(self))

    def execute_write(self, fn):
        return fn(_Tx(self))


def _device_runs_after_one_cycle(count: int) -> list[dict]:
    """One bootstrap cycle, then `count` device runs chained off it, the
    collection mode a deployment that schedules no cycle runs in."""
    runs = [{"cts": 0, "kind": "full", "parent": None}]
    for i in range(1, count + 1):
        runs.append({"cts": i * 600_000, "kind": "device", "parent": (i - 1) * 600_000})
    return runs


def test_device_runs_chained_off_a_kept_cycle_are_capped_by_their_own_count():
    runs = _device_runs_after_one_cycle(7 * 144)
    session = _Session(runs, runs[-1]["cts"])

    victims = cyclemod.prune(session, cyclemod.Keep(30, device_runs=48))

    kept = cyclemod.retained_runs(session, cyclemod.Keep(30, device_runs=48))
    assert len(kept) == 49  # the bootstrap cycle and the newest 48 device runs
    assert kept[0] == runs[-1]["cts"] and kept[-1] == 0
    assert len(victims) == len(runs) - 49
    assert set(victims).isdisjoint(kept)


def test_a_second_prune_keeps_the_same_runs_after_the_first_cut_their_chain():
    """The first prune deletes the parents of the device runs it keeps; the
    second must not read the broken chain as a reason to delete them."""
    runs = _device_runs_after_one_cycle(200)
    session = _Session(runs, runs[-1]["cts"])
    keep = cyclemod.Keep(30, device_runs=48)
    cyclemod.prune(session, keep)
    first = cyclemod.retained_runs(session, keep)

    assert cyclemod.prune(session, keep) == []
    assert cyclemod.retained_runs(session, keep) == first
    assert len(first) == 49


def test_daily_cycles_keep_the_cycle_count_and_the_device_run_window_only():
    runs, prev, t = [], None, 0
    for _day in range(40):
        t += 1
        runs.append({"cts": t, "kind": "full", "parent": prev})
        prev = t
        for _ in range(143):
            t += 1
            runs.append({"cts": t, "kind": "device", "parent": prev})
            prev = t
    session = _Session(runs, prev)

    kept = cyclemod.retained_runs(session, cyclemod.Keep(30, device_runs=48))

    kinds = {r["cts"]: r["kind"] for r in runs}
    assert sum(1 for cts in kept if kinds[cts] == "full") == 30
    assert sum(1 for cts in kept if kinds[cts] == "device") == 48


def test_device_runs_older_than_the_oldest_kept_cycle_go_and_the_pointer_and_pins_stay():
    runs = [
        {"cts": 1000, "kind": "full", "parent": None},
        {"cts": 1100, "kind": "device", "parent": 1000},
        {"cts": 2000, "kind": "full", "parent": 1100},
        {"cts": 2100, "kind": "refresh", "parent": 2000},
        {"cts": 2200, "kind": "device", "parent": 2100},
        {"cts": 2300, "kind": "device", "parent": 2200},
    ]
    session = _Session(runs, 2300)

    victims = cyclemod.prune(session, cyclemod.Keep(1, device_runs=1), frozenset({1100}))

    # one cycle (2000) and one device run newer than it (2300, also the pointer);
    # 1100 is pinned; 2200 and 2100 are past the device-run count, 1000 past the cycle count
    assert victims == [2200, 2100, 1000]
    assert sorted(r["cts"] for r in session.runs) == [1100, 2000, 2300]


def test_a_bare_count_keeps_the_default_device_run_window():
    runs = _device_runs_after_one_cycle(cyclemod.KEEP_DEVICE_RUNS + 10)
    session = _Session(runs, runs[-1]["cts"])
    assert len(cyclemod.retained_runs(session, 30)) == cyclemod.KEEP_DEVICE_RUNS + 1


def test_the_scheduled_sweeps_take_the_device_run_count_from_the_retention_settings():
    pytest.importorskip("sqlalchemy")
    from hst.app import retention
    from hst.worker import maintenance

    settings = Settings(_env_file=None, cycle_keep_runs=30, cycle_keep_device_runs=48)
    assert maintenance._graph_keep(retention.merged(None, settings)) == cyclemod.Keep(30, 48)
    stored = {"cycle_keep_runs": 5, "cycle_keep_device_runs": 12}
    assert maintenance._graph_keep(retention.merged(stored, settings)) == cyclemod.Keep(5, 12)


def _aged(monkeypatch, now_ms: int) -> None:
    monkeypatch.setattr(cyclemod, "_now_ms", lambda: now_ms)


DAY = 24 * 3600 * 1000


def test_a_run_is_removed_node_first_then_relationships_then_objects():
    session = _Session([{"cts": 1, "kind": "full"}, {"cts": 2, "kind": "full"}], 2)

    assert cyclemod.prune(session, cyclemod.Keep(1)) == [1]

    assert session.events[:3] == [("node", 1), ("rels", 1), ("objects", 1)]


def test_a_prune_deletes_the_oldest_victims_first_and_only_max_victims():
    runs = [{"cts": i, "kind": "full"} for i in range(1, 6)]
    session = _Session(runs, 5)

    assert cyclemod.prune(session, cyclemod.Keep(1), max_victims=2) == [2, 1]
    assert cyclemod.prune(session, cyclemod.Keep(1), max_victims=2) == [4, 3]
    assert cyclemod.prune(session, cyclemod.Keep(1), max_victims=2) == []
    assert [r["cts"] for r in session.runs] == [5]


def test_a_building_run_is_not_counted_as_a_cycle_and_is_kept_while_a_build_can_write_it(monkeypatch):
    cur = 10 * DAY
    _aged(monkeypatch, cur + 1000)
    runs = [
        {"cts": cur - 5 * DAY, "kind": "full"},
        {"cts": cur, "kind": "full"},
        {"cts": cur + 500, "kind": "full", "state": "building"},
        {"cts": cur - 1000, "kind": "full", "state": "building"},
    ]
    session = _Session(runs, cur)

    kept = cyclemod.retained_runs(session, cyclemod.Keep(2))

    # both finished cycles are kept (a BUILDING one does not take a slot), and
    # the two BUILDING runs are young enough that a build may still write them
    assert sorted(kept) == sorted(r["cts"] for r in runs)
    assert cyclemod.prune(session, cyclemod.Keep(2)) == []


def test_a_building_run_nothing_finished_is_deleted_once_the_pointer_has_passed_it(monkeypatch):
    cur = 10 * DAY
    _aged(monkeypatch, cur + 2 * DAY)
    dead = cur - 3 * DAY
    runs = [{"cts": cur, "kind": "full"}, {"cts": dead, "kind": "full", "state": "building"}]
    session = _Session(runs, cur)

    assert cyclemod.prune(session, cyclemod.Keep(5)) == [dead]
    assert [r["cts"] for r in session.runs] == [cur]


def test_a_failed_build_with_no_run_node_is_found_by_its_objects_and_deleted(monkeypatch):
    cur = 10 * DAY
    _aged(monkeypatch, cur + 2 * DAY)
    orphan = cur - 3 * DAY
    session = _Session([{"cts": cur, "kind": "full"}], cur, objects={cur, orphan})

    assert cyclemod.orphan_runs(session) == [orphan]
    assert cyclemod.prune(session, cyclemod.Keep(5)) == [orphan]
    assert session.objects == {cur}
    assert cyclemod.prune(session, cyclemod.Keep(5)) == []


def test_objects_with_no_run_node_stay_while_they_are_newer_than_the_pointer_or_the_grace_period(monkeypatch):
    cur = 10 * DAY
    _aged(monkeypatch, cur + 1000)
    young = cur - 1000
    ahead = cur + 500
    session = _Session([{"cts": cur, "kind": "full"}], cur, objects={cur, young, ahead})

    assert cyclemod.orphan_runs(session) == []
    assert cyclemod.prune(session, cyclemod.Keep(5)) == []


def test_a_protected_run_with_no_run_node_is_not_deleted(monkeypatch):
    cur = 10 * DAY
    _aged(monkeypatch, cur + 2 * DAY)
    orphan = cur - 3 * DAY
    session = _Session([{"cts": cur, "kind": "full"}], cur, objects={cur, orphan})

    assert cyclemod.prune(session, cyclemod.Keep(5), frozenset({orphan})) == []


def test_there_are_no_orphans_before_the_first_pointer():
    session = _Session([], None, objects={1, 2})

    assert cyclemod.orphan_runs(session) == []


def test_begin_run_writes_the_node_as_building_and_the_cycle_meta_completes_it():
    session = _Session([], None)

    cyclemod.begin_run(session, 42, "device", 41)
    cyclemod.write_cycle_meta(
        session, 42, kind="device", parent=41, statuses={}, carried_from=None, nodes=0, rels=0, degraded=False
    )

    (_, begun), (_, finished) = session.writes[0], session.writes[-1]
    assert begun["props"]["state"] == cyclemod.STATE_BUILDING
    assert begun["props"]["kind"] == "device" and begun["props"]["parent"] == 41
    assert finished["props"]["state"] == cyclemod.STATE_BUILT


def test_begin_run_refuses_an_unknown_kind():
    with pytest.raises(ValueError):
        cyclemod.begin_run(_Session([], None), 1, "nightly", None)


def test_discard_run_removes_the_node_before_the_objects():
    session = _Session([{"cts": 7, "kind": "full", "state": "building"}], 3)

    cyclemod.discard_run(session, 7)

    assert session.events[0] == ("node", 7) and ("objects", 7) in session.events
