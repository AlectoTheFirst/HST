import asyncio
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from hst.map import events, markers, store
from hst.map.events import Event, LocalBus


def _marker(key: int, *, tiers_ready: bool = True, parent: int | None = None) -> dict[str, Any]:
    return {
        "key": key,
        "kind": "full",
        "parent": parent,
        "published_ts": key,
        "state": "warm",
        "tiers_ready": tiers_ready,
        "counts": {"added": 1, "removed": 0, "changed": 1},
        "replan_recommended": False,
        "layout_version": 1,
        "durations_ms": {"delta": 1, "attribution": 1, "fold": 1, "layout": 1, "write": 1},
        "peak_memory_bytes": 10,
        "schema_version": markers.SCHEMA_VERSION,
    }


def _table(sidestore: Path, name: str, key: int, rows: list[dict[str, Any]]) -> None:
    path = store.table_path(sidestore, name, key)
    path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(rows), path)


@pytest.fixture
def dirs(tmp_path: Path) -> tuple[Path, Path]:
    return tmp_path / "manifests", tmp_path / "sidestore"


DELTA_ROWS = [{"uid": "dev:a", "change": "added"}, {"uid": "dev:b", "change": "changed"}]
LAYOUT_ROWS = [{"uid": "dev:a", "u": 1, "v": 2}]


def _stored_run(dirs: tuple[Path, Path], key: int, parent: int | None = None) -> None:
    markers_dir, sidestore = dirs
    _table(sidestore, events.GRAPH_DELTA_TABLE, key, DELTA_ROWS)
    _table(sidestore, events.LAYOUT_TABLE, key, LAYOUT_ROWS)
    markers.write(markers_dir, _marker(key, parent=parent))


def _live(key: int, parent: int | None = None) -> list[Event]:
    marker = _marker(key, parent=parent)
    return [
        Event(events.RUN_PUBLISHED, key, 0, events.published_payload(marker)),
        Event(events.DELTA_RECORD, key, 1, DELTA_ROWS[0]),
        Event(events.DELTA_RECORD, key, 2, DELTA_ROWS[1]),
        Event(events.LAYOUT_CHANGED, key, 3, LAYOUT_ROWS[0]),
        Event(events.RUN_TIERS_READY, key, 4, events.tiers_ready_payload(marker)),
    ]


async def _take(stream: Any, n: int) -> list[Event]:
    out = []
    async for event in stream:
        out.append(event)
        if len(out) == n:
            break
    return out


def test_an_event_has_a_known_type_and_a_non_negative_seq() -> None:
    with pytest.raises(ValueError):
        Event("run.renamed", 1, 0, {})
    with pytest.raises(ValueError):
        Event(events.RUN_PUBLISHED, 1, -1, {})
    keys = list(Event(events.RUN_PUBLISHED, 1, 0, {}).as_dict())
    assert keys == ["type", "run_key", "seq", "ts", "payload"]


def test_seq_is_strictly_increasing_per_run_key(dirs: tuple[Path, Path]) -> None:
    bus = LocalBus(*dirs)
    bus.publish(Event(events.RUN_PUBLISHED, 100, 0, {}))
    bus.publish(Event(events.DELTA_RECORD, 100, 1, {}))
    bus.publish(Event(events.RUN_PUBLISHED, 200, 0, {}))
    with pytest.raises(ValueError):
        bus.publish(Event(events.DELTA_RECORD, 100, 1, {}))
    with pytest.raises(ValueError):
        bus.publish(Event(events.DELTA_RECORD, 200, 0, {}))
    bus.publish(Event(events.RUN_TIERS_READY, 100, 5, {}))


async def test_subscribe_delivers_the_wanted_types_in_publish_order(dirs: tuple[Path, Path]) -> None:
    bus = LocalBus(*dirs)
    task = asyncio.create_task(_take(bus.subscribe([events.RUN_PUBLISHED, events.RUN_TIERS_READY]), 2))
    await asyncio.sleep(0)
    for event in _live(100):
        bus.publish(event)
    got = await asyncio.wait_for(task, 1)
    assert [(e.type, e.seq) for e in got] == [(events.RUN_PUBLISHED, 0), (events.RUN_TIERS_READY, 4)]


async def test_publish_from_another_thread_reaches_the_subscriber(dirs: tuple[Path, Path]) -> None:
    bus = LocalBus(*dirs)
    task = asyncio.create_task(_take(bus.subscribe(events.TYPES), 5))
    await asyncio.sleep(0)

    def publish_all() -> None:
        for event in _live(100):
            bus.publish(event)

    await asyncio.to_thread(publish_all)
    assert await asyncio.wait_for(task, 1) == _live(100)


async def test_subscribe_since_replays_the_stored_events_after_the_position(dirs: tuple[Path, Path]) -> None:
    _stored_run(dirs, 100)
    _stored_run(dirs, 200, parent=100)
    bus = LocalBus(*dirs)
    task = asyncio.create_task(_take(bus.subscribe(events.TYPES, since=(200, 1)), 4))
    await asyncio.sleep(0.05)
    bus.publish(Event(events.RUN_PUBLISHED, 300, 0, {}))
    got = await asyncio.wait_for(task, 1)
    assert [e.position for e in got] == [(200, 2), (200, 3), (200, 4), (300, 0)]


async def test_subscribe_since_skips_a_live_event_it_already_replayed(dirs: tuple[Path, Path]) -> None:
    _stored_run(dirs, 200)
    bus = LocalBus(*dirs)
    stream = bus.subscribe([events.RUN_PUBLISHED, events.RUN_TIERS_READY], since=(200, 0))
    task = asyncio.create_task(_take(stream, 2))
    await asyncio.sleep(0.05)
    bus.publish(Event(events.RUN_TIERS_READY, 200, 4, {}))
    bus.publish(Event(events.RUN_PUBLISHED, 300, 0, {}))
    got = await asyncio.wait_for(task, 1)
    assert [e.position for e in got] == [(200, 4), (300, 0)]


def test_replay_equals_the_live_sequence(dirs: tuple[Path, Path]) -> None:
    _stored_run(dirs, 100)
    assert LocalBus(*dirs).replay(100) == _live(100)


def test_replay_of_some_types_keeps_the_seq_of_the_full_sequence(dirs: tuple[Path, Path]) -> None:
    _stored_run(dirs, 100)
    got = LocalBus(*dirs).replay(100, [events.RUN_TIERS_READY])
    assert [e.position for e in got] == [(100, 4)]


def test_replay_omits_tiers_ready_until_the_marker_says_so(dirs: tuple[Path, Path]) -> None:
    markers_dir, _ = dirs
    markers.write(markers_dir, _marker(100, tiers_ready=False))
    assert [e.type for e in LocalBus(*dirs).replay(100)] == [events.RUN_PUBLISHED]


def test_the_poll_sees_a_marker_written_by_another_process(dirs: tuple[Path, Path]) -> None:
    markers_dir, _ = dirs
    _stored_run(dirs, 100)
    bus = LocalBus(*dirs)
    script = (
        "import json, sys; from pathlib import Path; from hst.map import markers; "
        "markers.write(Path(sys.argv[1]), json.loads(sys.argv[2]))"
    )
    marker = json.dumps(_marker(200, parent=100))
    subprocess.run([sys.executable, "-c", script, str(markers_dir), marker], check=True)
    got = bus.poll_markers()
    assert [(e.type, e.position) for e in got] == [
        (events.RUN_PUBLISHED, (200, 0)),
        (events.RUN_TIERS_READY, (200, 1)),
    ]
    assert bus.poll_markers() == []


def test_the_poll_reports_tiers_ready_when_the_marker_heals(dirs: tuple[Path, Path]) -> None:
    markers_dir, _ = dirs
    bus = LocalBus(*dirs)
    markers.write(markers_dir, _marker(100, tiers_ready=False))
    assert [e.type for e in bus.poll_markers()] == [events.RUN_PUBLISHED]
    markers.write(markers_dir, _marker(100))
    assert [e.type for e in bus.poll_markers()] == [events.RUN_TIERS_READY]


def test_the_poll_skips_a_marker_the_process_published(dirs: tuple[Path, Path]) -> None:
    bus = LocalBus(*dirs)
    for event in _live(100):
        bus.publish(event)
    _stored_run(dirs, 100)
    assert bus.poll_markers() == []
