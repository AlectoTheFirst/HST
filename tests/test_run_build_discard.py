"""A build is recorded before its first write and discarded when it does not publish."""

# ruff: noqa: F811

from __future__ import annotations

import threading
from typing import Any

import pytest
from tests.test_manifest import PREV, _Cycle, _prepared, rig  # noqa: F401  (pytest fixture)

from hst import collectors as coll
from hst.app import runs_exec
from hst.core import grapharchive, rawstore
from hst.core import manifest as manifestmod


class _BuildCycle(_Cycle):
    """The test rig's stub of `core.cycle`, with the two calls that record and discard a run."""

    def __init__(self, base: _Cycle) -> None:
        super().__init__(base.pointer, base.keys)
        self.begun: list[tuple[int, str, int | None]] = []
        self.discarded: list[int] = []

    def begin_run(self, s: Any, cts: int, kind: str, parent: int | None) -> None:
        self.steps.append("begin_run")
        self.begun.append((cts, kind, parent))

    def discard_run(self, s: Any, cts: int) -> None:
        self.steps.append("discard_run")
        self.discarded.append(cts)


@pytest.fixture
def built(monkeypatch, rig):
    def make(**kw: Any):
        settings, base = rig(**kw)
        cycle = _BuildCycle(base)
        monkeypatch.setattr(runs_exec, "cycle", cycle)
        return settings, cycle

    return make


def _fail_the_pointer_move(cycle: _BuildCycle) -> None:
    def boom(s: Any, cts: int) -> None:
        raise RuntimeError("pointer move refused")

    cycle.set_pointer = boom


def test_a_full_cycle_records_the_run_before_its_first_write_and_keeps_it(built):
    settings, cycle = built()

    runs_exec.execute_cycle(settings, [_prepared(settings, "edge", "r1")], {"edge"})

    assert cycle.begun == [(2_000, "full", PREV)]
    assert cycle.steps[0] == "begin_run"
    assert cycle.steps[-2:] == ["write_cycle_meta", "set_pointer"]
    assert cycle.discarded == []
    assert manifestmod.path_for(settings, 2_000).is_file()


def test_a_cycle_that_fails_before_the_pointer_moves_discards_the_run_and_its_manifest(built):
    settings, cycle = built()
    _fail_the_pointer_move(cycle)

    with pytest.raises(RuntimeError, match="pointer move refused"):
        runs_exec.execute_cycle(settings, [_prepared(settings, "edge", "r1")], {"edge"})

    assert cycle.discarded == [2_000]
    assert cycle.pointer == PREV
    # the manifest was written before the pointer moved; the next run must not chain to it
    assert not manifestmod.path_for(settings, 2_000).exists()
    assert not manifestmod.sig_path_for(settings, 2_000).exists()
    assert not grapharchive.path_for(settings, 2_000).exists()


def test_the_next_run_after_a_discarded_one_chains_to_the_last_published_manifest(built, monkeypatch):
    settings, cycle = built(keys=[2_000, 3_000])
    runs_exec.execute_cycle(settings, [_prepared(settings, "edge", "r1")], {"edge"})
    assert cycle.pointer == 2_000
    real = cycle.set_pointer
    _fail_the_pointer_move(cycle)
    cycle.keys.insert(0, 2_500)
    with pytest.raises(RuntimeError):
        runs_exec.execute_cycle(settings, [_prepared(settings, "edge", "r1")], {"edge"})
    cycle.set_pointer = real
    cycle.keys[:] = [3_000]

    runs_exec.execute_cycle(settings, [_prepared(settings, "edge", "r1")], {"edge"})

    second = manifestmod.read(settings, 3_000)
    assert second.previous is not None and second.previous.snapshot_key == 2_000


def test_a_cycle_stopped_after_the_build_discards_it(built):
    settings, cycle = built()
    stop = threading.Event()
    stop.set()

    with pytest.raises(RuntimeError):
        runs_exec.execute_cycle(settings, [_prepared(settings, "edge", "r1")], {"edge"}, stop=stop)

    assert cycle.discarded == [2_000]
    assert cycle.pointer == PREV


def test_a_cycle_whose_pointer_was_moved_keeps_its_run_when_a_later_step_fails(built):
    """A failure after the switchover must never delete a run readers already see."""
    settings, cycle = built()
    seen: list[int] = []
    real = cycle.set_pointer

    def move_then_fail(s: Any, cts: int) -> None:
        real(s, cts)
        seen.append(cts)
        raise RuntimeError("after the switchover")

    cycle.set_pointer = move_then_fail

    with pytest.raises(RuntimeError, match="after the switchover"):
        runs_exec.execute_cycle(settings, [_prepared(settings, "edge", "r1")], {"edge"})

    assert seen == [2_000] and cycle.pointer == 2_000
    assert cycle.discarded == []
    assert manifestmod.path_for(settings, 2_000).is_file()


def test_a_run_is_left_in_place_when_the_pointer_cannot_be_read(built):
    settings, cycle = built()
    _fail_the_pointer_move(cycle)
    reads = 0
    real = cycle.current_ts

    def current_ts(s: Any) -> int | None:
        nonlocal reads
        reads += 1
        if reads > 1:  # the build's own read of the parent works; the check afterwards does not
            raise ConnectionError("graph unreachable")
        return real(s)

    cycle.current_ts = current_ts

    with pytest.raises(RuntimeError, match="pointer move refused"):
        runs_exec.execute_cycle(settings, [_prepared(settings, "edge", "r1")], {"edge"})

    assert cycle.discarded == []


def test_a_discard_that_fails_does_not_hide_the_error_the_run_failed_with(built):
    settings, cycle = built()
    _fail_the_pointer_move(cycle)

    def broken(s: Any, cts: int) -> None:
        raise ConnectionError("graph unreachable")

    cycle.discard_run = broken

    with pytest.raises(RuntimeError, match="pointer move refused"):
        runs_exec.execute_cycle(settings, [_prepared(settings, "edge", "r1")], {"edge"})

    # the manifest is still removed
    assert not manifestmod.path_for(settings, 2_000).exists()


def test_a_refresh_records_its_run_and_discards_it_on_failure(built):
    settings, cycle = built(keys=[2_000])
    _fail_the_pointer_move(cycle)

    with pytest.raises(RuntimeError, match="pointer move refused"):
        runs_exec.execute_refresh(settings, [_prepared(settings, "edge", "r1")], "edge")

    assert cycle.begun == [(2_000, "refresh", PREV)]
    assert cycle.discarded == [2_000]
    assert not manifestmod.path_for(settings, 2_000).exists()


def test_a_device_run_records_its_run_and_discards_it_on_failure(built):
    settings, cycle = built(keys=[2_000])
    edge = _prepared(settings, "edge", "r1")
    coll.park(edge.units[0].collector, {"host": "r1"}, source_name="edge")
    _fail_the_pointer_move(cycle)

    with pytest.raises(RuntimeError, match="pointer move refused"):
        runs_exec.build_device_run(settings, [edge])

    assert cycle.begun == [(2_000, "device", PREV)]
    assert cycle.discarded == [2_000]
    assert not manifestmod.path_for(settings, 2_000).exists()
    # the parked payload is still there for the next device run to fold in
    assert rawstore.parked(settings.raw_dir)


def test_a_device_run_with_nothing_parked_begins_no_run(built):
    settings, cycle = built(keys=[2_000])

    runs_exec.build_device_run(settings, [_prepared(settings, "edge", "r1")])

    assert cycle.begun == [] and cycle.discarded == []
