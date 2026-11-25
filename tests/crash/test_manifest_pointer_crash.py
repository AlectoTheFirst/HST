"""Crash injection: the process dies after the manifest is on disk
and before `cycle.set_pointer` runs (core/manifest.py `_atomic_write`,
core/cycle.py `set_pointer`)."""

# ruff: noqa: F811 -- the imported `rig` fixture is shadowed by design in the test signature

from __future__ import annotations

import pytest
from tests.crash.injectors import SimulatedCrash, crash_after
from tests.test_manifest import PREV, _prepared, rig  # noqa: F401  (pytest fixture)

from hst.app import runs_exec
from hst.core import manifest as manifestmod


def test_a_crash_after_the_manifest_write_and_before_the_pointer_move(monkeypatch, rig):
    settings, cycle = rig(keys=[2_000, 3_000])
    edge = _prepared(settings, "edge", "r1")

    with pytest.MonkeyPatch.context() as mp:
        crash_after(mp, manifestmod, "_atomic_write")
        with pytest.raises(SimulatedCrash):
            runs_exec.execute_cycle(settings, [edge], {"edge"})

    assert manifestmod.path_for(settings, 2_000).is_file()
    orphan = manifestmod.read(settings, 2_000)
    assert orphan.snapshot_key == 2_000

    assert cycle.pointer == PREV
    assert "set_pointer" not in cycle.steps

    runs_exec.execute_cycle(settings, [edge], {"edge"})
    assert cycle.pointer == 3_000
    second = manifestmod.read(settings, 3_000)
    assert second.previous is not None
    assert second.previous.snapshot_key == 2_000
    assert second.previous.sha256 == manifestmod.digest_of(settings, 2_000)
    assert second.chain_index == orphan.chain_index + 1
