"""The HST sweep keeps a base for every cold run across a history prune (map/sweep.py)."""

from datetime import UTC, datetime
from pathlib import Path

from hst.map import markers, store, sweep, timeline
from hst.map.tiers.fold import TIER_TABLES
from hst.map.tiers.read import MAX_COMPOSE

HOUR_MS = 3_600_000
BASE_MS = int(datetime(2026, 1, 1, tzinfo=UTC).timestamp() * 1000)


def _run(dirs: tuple[Path, Path], key: int, parent: int | None, *, state: str) -> None:
    markers_dir, sidestore = dirs
    markers.write(
        markers_dir, {"key": key, "kind": "full", "parent": parent, "published_ts": key, "state": state}
    )
    for name in (*TIER_TABLES, *sweep.HISTORY_TABLES):
        path = store.table_path(sidestore, name, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"PAR1")


def _chain(dirs: tuple[Path, Path], states: list[str]) -> list[int]:
    keys, parent = [], None
    for i, state in enumerate(states):
        key = BASE_MS + i * HOUR_MS
        _run(dirs, key, parent, state=state)
        keys.append(key)
        parent = key
    return keys


def _composable(dirs: tuple[Path, Path]) -> tuple[int, int]:
    """(runs whose tiers compose, runs in the timeline): a run composes from its own
    files or from the nearest earlier run holding them, at most MAX_COMPOSE runs back."""
    chain = timeline.chain(dirs[0])
    held = [store.table_path(dirs[1], "render_t1", k).exists() for k in chain]
    ok = sum(1 for i in range(len(chain)) if any(held[max(0, i - MAX_COMPOSE) : i + 1]))
    return ok, len(chain)


def test_a_history_prune_followed_by_a_tier_prune_keeps_every_cold_run_composable(tmp_path, monkeypatch):
    monkeypatch.setattr(sweep, "_layout_in_force", lambda _sidestore, _newest: set())
    dirs = (tmp_path / "m", tmp_path / "s")
    _chain(dirs, ["cold"] * 170 + ["warm"] * 30)
    sweep.prune_tiers(dirs[1], dirs[0], checkpoint_every=30)
    assert _composable(dirs) == (200, 200)

    # the 35 oldest runs are past the period; run 35 composes from run 30, so 30 to 34 stay
    now = datetime.fromtimestamp((BASE_MS + 35 * HOUR_MS) / 1000, tz=UTC)
    _files, gone = sweep.prune_history(dirs[1], dirs[0], 0, now)
    assert len(gone) == 30
    sweep.prune_tiers(dirs[1], dirs[0], checkpoint_every=30)

    assert _composable(dirs) == (170, 170)


def test_a_tier_prune_after_the_oldest_markers_went_keeps_the_checkpoints_that_are_left(tmp_path):
    """The checkpoint at index 30 is at index 19 after the prune."""
    dirs = (tmp_path / "m", tmp_path / "s")
    keys = _chain(dirs, ["cold"] * 60 + ["warm"] * 5)
    sweep.prune_tiers(dirs[1], dirs[0], checkpoint_every=30)
    for key in keys[:11]:
        markers.path_for(dirs[0], key).unlink()
        for name in (*TIER_TABLES, *sweep.HISTORY_TABLES):
            store.table_path(dirs[1], name, key).unlink(missing_ok=True)

    sweep.prune_tiers(dirs[1], dirs[0], checkpoint_every=30)

    assert store.table_path(dirs[1], "render_t1", keys[30]).exists()
    chain = timeline.chain(dirs[0])
    held = [store.table_path(dirs[1], "render_t1", k).exists() for k in chain]
    assert all(any(held[max(0, i - MAX_COMPOSE) : i + 1]) for i in range(chain.index(keys[30]), len(chain)))


def test_a_history_prune_keeps_the_base_of_the_first_run_that_stays(tmp_path, monkeypatch):
    monkeypatch.setattr(sweep, "_layout_in_force", lambda _sidestore, _newest: set())
    dirs = (tmp_path / "m", tmp_path / "s")
    keys = _chain(dirs, ["cold"] * 12 + ["warm"])
    sweep.prune_tiers(dirs[1], dirs[0], checkpoint_every=4)  # bases at 0, 4 and 8

    # runs 0 to 5 are past the period; run 6 stays and composes from run 4
    now = datetime.fromtimestamp((keys[6] - 1) / 1000, tz=UTC)
    _files, gone = sweep.prune_history(dirs[1], dirs[0], 0, now)

    assert gone == keys[:4]
    assert _composable(dirs) == (9, 9)


def test_a_history_prune_never_deletes_a_marker_between_two_that_stay(tmp_path, monkeypatch):
    """A cycle the graph still keeps can sit among older device runs it pruned;
    deleting the cold runs after it would cut every later run out of the timeline."""
    monkeypatch.setattr(sweep, "_layout_in_force", lambda _sidestore, _newest: set())
    dirs = (tmp_path / "m", tmp_path / "s")
    keys = _chain(dirs, ["cold", "warm", "cold", "cold", "warm"])
    now = datetime.fromtimestamp((keys[-1] + 1) / 1000, tz=UTC)

    _files, gone = sweep.prune_history(dirs[1], dirs[0], 0, now)

    assert gone == keys[:1]
    assert timeline.chain(dirs[0]) == keys[1:]
