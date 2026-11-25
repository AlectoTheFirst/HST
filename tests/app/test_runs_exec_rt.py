"""The route-target derivations inside a cycle and inside a single-source refresh."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

import hst.app.runs_exec as runs_exec
from hst.app.store import Source
from hst.core import Settings
from hst.core.model import RunManifest

PREV = 1000  # the cycle the pointer names when a cycle starts
NEW = 2000  # the cycle execute_cycle mints and derives into


def _source(name: str) -> Source:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return Source(
        id=1,
        name=name,
        type=name,
        config={},
        secrets=b"",
        enabled=True,
        created_at=now,
        updated_at=now,
    )


def _prepared(*names: str) -> list[runs_exec.PreparedSource]:
    return [
        runs_exec.PreparedSource(_source(n), [runs_exec.PreparedDevice(None, object(), None)]) for n in names
    ]


class _Session:
    """Minimal Neo4j session/transaction protocol used while publishing."""

    def __enter__(self) -> _Session:
        return self

    def __exit__(self, *a: Any) -> bool:
        return False

    def execute_read(self, work: Any) -> Any:
        return work(self)

    def run(self, query: str, **params: Any) -> list[dict[str, Any]]:
        return []


class _Cycle:
    """Stands in for `core.cycle`."""

    def __init__(self, log: list[tuple[str, Any]], pointer: int | None) -> None:
        self.log = log
        self.pointer = pointer
        self.meta: dict[str, Any] | None = None

    def current_ts(self, s: Any) -> int | None:
        return self.pointer

    def new_collection_ts(self) -> int:
        return NEW

    def carry_forward(self, s: Any, prev: int, cts: int, sources: list[str], **kw: Any) -> dict[str, int]:
        self.log.append(("carry_forward", tuple(sources)))
        return {"nodes": 0, "rels": 0}

    def cycle_counts(self, s: Any, cts: int) -> dict[str, int]:
        self.log.append(("cycle_counts", cts))
        return {"nodes": 7, "rels": 9}

    def set_pointer(self, s: Any, cts: int) -> None:
        self.log.append(("set_pointer", cts))
        self.pointer = cts

    def apply_site_assignments(self, s: Any, assigned: Any, cts: int | None = None) -> int:
        self.log.append(("apply_site_assignments", cts))
        return 0

    def write_cycle_meta(self, s: Any, cts: int, **kw: Any) -> None:
        self.log.append(("write_cycle_meta", cts))
        self.meta = kw


class _Rt:
    """Stands in for `core.reasoner`."""

    def __init__(self, log: list[tuple[str, Any]], fail: str | None) -> None:
        self.log = log
        self.fail = fail

    def execute_rt_domains(
        self, session: Any, settings: Settings, collection_ts: int | None = None
    ) -> RunManifest:
        return self._record("rt-domains", collection_ts, nodes=2)

    def execute_link_speed(
        self, session: Any, settings: Settings, collection_ts: int | None = None
    ) -> RunManifest:
        return self._record("link-speed", collection_ts, rels=1)

    def _record(self, step: str, cts: int | None, *, nodes: int = 0, rels: int = 0) -> RunManifest:
        self.log.append((step, cts))
        if self.fail == step:
            raise RuntimeError("route-target derivation blew up")
        return RunManifest(
            run_id=f"reasoner-{step}-{cts}",
            source="reasoner",
            scope=step,
            nodes_upserted=nodes,
            nodes_created=nodes,
            rels_upserted=rels,
            rels_created=rels,
        )


class _Coll:
    def __init__(self, log: list[tuple[str, Any]]) -> None:
        self.log = log

    def execute(
        self, collector: Any, s: Any, *, collection_ts: int, source_name: str, on_write: Any = None
    ) -> RunManifest:
        self.log.append(("collect", source_name))
        return RunManifest(run_id=f"{source_name}-{collection_ts}", source=source_name, scope=source_name)


class _Rules:
    """Stands in for the cabling/gateway reasoner (`hst.reasoner`)."""

    def __init__(self, log: list[tuple[str, Any]]) -> None:
        self.log = log

    def run(self, s: Any, ts_ms: int | None = None, collection_ts: int | None = None) -> list[dict]:
        self.log.append(("rules", collection_ts))
        return [{"rule": "cable-from-lldp", "edges": 1}]


class _Rig:
    def __init__(self, log: list[tuple[str, Any]], cycle: _Cycle) -> None:
        self.log = log
        self.cycle = cycle

    @property
    def steps(self) -> list[str]:
        return [name for name, _ in self.log]

    def rt_calls(self) -> list[tuple[str, Any]]:
        return [entry for entry in self.log if entry[0] in ("rt-imports", "rt-domains", "link-speed")]


@pytest.fixture
def rig(monkeypatch):
    """Patch every seam `execute_cycle`/`execute_refresh` reach through, and return
    the shared call log."""

    def build(*, pointer: int | None = PREV, fail: str | None = None) -> _Rig:
        log: list[tuple[str, Any]] = []
        cycle = _Cycle(log, pointer)
        monkeypatch.setattr(runs_exec, "cycle", cycle)
        monkeypatch.setattr(runs_exec, "rt_reasoner", _Rt(log, fail))
        monkeypatch.setattr(runs_exec, "coll", _Coll(log))
        monkeypatch.setattr(runs_exec, "reasoner", _Rules(log))
        monkeypatch.setattr(runs_exec.dbmod, "session", lambda settings: _Session())
        return _Rig(log, cycle)

    return build


def _settings() -> Settings:
    return Settings(_env_file=None, hst_secret_key="runs-exec-rt-test-archive-key-32-bytes")


# --- the cycle ---------------------------------------------------------------------------


def test_a_cycle_derives_into_the_cycle_it_is_building(rig):
    r = rig()

    runs_exec.execute_cycle(_settings(), _prepared("vyos"), {"vyos"})

    assert r.rt_calls() == [("rt-domains", NEW), ("link-speed", NEW)]


def test_a_cycle_derives_after_the_rules_and_before_the_counts_and_the_switchover(rig):
    r = rig()

    runs_exec.execute_cycle(_settings(), _prepared("vyos"), {"vyos"})

    assert r.steps == [
        "collect",
        "rules",
        "rt-domains",
        "link-speed",
        "apply_site_assignments",
        "cycle_counts",
        "write_cycle_meta",
        "set_pointer",
    ]


def test_the_pointer_moves_last_and_nothing_follows_it(rig):
    r = rig()

    runs_exec.execute_cycle(_settings(), _prepared("vyos"), {"vyos"}, {"dev:1": "hq"})

    assert r.steps[-1] == "set_pointer"
    assert r.steps.index("apply_site_assignments") < r.steps.index("cycle_counts")
    assert r.steps.index("write_cycle_meta") < r.steps.index("set_pointer")


def test_a_cycle_summary_reports_both_derivations(rig):
    rig()

    summary, _, _, _ = runs_exec.execute_cycle(_settings(), _prepared("vyos"), {"vyos"})

    assert "rt-imports" not in summary
    assert "rt-domains: nodes 2 (+2, -0) · rels 0 (+0, -0)" in summary
    assert "link-speed: nodes 0 (+0, -0) · rels 1 (+1, -0)" in summary


@pytest.mark.parametrize("failing", ["rt-domains", "link-speed"])
def test_a_failing_derivation_fails_the_whole_cycle(rig, failing):
    r = rig(fail=failing)

    with pytest.raises(RuntimeError, match="route-target derivation blew up"):
        runs_exec.execute_cycle(_settings(), _prepared("vyos"), {"vyos"})

    assert "set_pointer" not in r.steps


def test_reasoner_owned_nodes_are_not_carried_forward(rig):
    r = rig()

    runs_exec.execute_cycle(_settings(), _prepared("vyos", "unifi"), {"vyos"})

    carried = next(args for name, args in r.log if name == "carry_forward")
    assert "reasoner" not in carried
    assert set(carried) == {"unifi"}


# --- the refresh -------------------------------------------------------------------------


def test_a_refresh_derives_into_the_new_run_it_is_building(rig):
    r = rig()

    runs_exec.execute_refresh(_settings(), _prepared("vyos"), "vyos")

    assert r.rt_calls() == [("rt-domains", NEW), ("link-speed", NEW)]


def test_a_refresh_runs_the_same_sequence_a_cycle_does(rig):
    """Carry the sources the press did not touch, derive, re-apply the site
    assignments, count, write the meta node, then move the pointer. The run is
    complete before anything can read it."""
    r = rig()

    runs_exec.execute_refresh(_settings(), _prepared("vyos", "unifi"), "vyos")

    assert r.steps == [
        "collect",
        "carry_forward",
        "rules",
        "rt-domains",
        "link-speed",
        "apply_site_assignments",
        "cycle_counts",
        "write_cycle_meta",
        "set_pointer",
    ]


def test_a_refresh_writes_a_refresh_kind_run_parented_on_the_previous_one(rig):
    r = rig()

    _, _, key, _ = runs_exec.execute_refresh(_settings(), _prepared("vyos", "unifi"), "vyos")

    assert key == NEW
    assert r.cycle.meta["kind"] == "refresh"
    assert r.cycle.meta["parent"] == PREV
    assert r.cycle.meta["statuses"] == {"vyos": "fresh", "unifi": "carried"}


def test_a_refresh_carries_every_source_it_did_not_press(rig):
    r = rig()

    runs_exec.execute_refresh(_settings(), _prepared("vyos", "unifi"), "vyos")

    carried = next(args for name, args in r.log if name == "carry_forward")
    assert set(carried) == {"unifi"}


def test_a_refresh_summary_reports_both_derivations(rig):
    rig()

    summary, _, _, _ = runs_exec.execute_refresh(_settings(), _prepared("vyos"), "vyos")

    assert "rt-imports" not in summary
    assert "rt-domains: nodes 2 (+2, -0) · rels 0 (+0, -0)" in summary
    assert "link-speed: nodes 0 (+0, -0) · rels 1 (+1, -0)" in summary


@pytest.mark.parametrize("failing", ["rt-domains", "link-speed"])
def test_a_failing_derivation_fails_the_refresh(rig, failing):
    r = rig(fail=failing)

    with pytest.raises(RuntimeError, match="route-target derivation blew up"):
        runs_exec.execute_refresh(_settings(), _prepared("vyos"), "vyos")

    assert "set_pointer" not in r.steps
    assert "write_cycle_meta" not in r.steps


def test_a_cold_start_refresh_falls_through_to_a_cycle_and_derives(rig):
    r = rig(pointer=None)

    runs_exec.execute_refresh(_settings(), _prepared("vyos"), "vyos")

    assert r.rt_calls() == [("rt-domains", NEW), ("link-speed", NEW)]
