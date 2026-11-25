"""A run that is stopped ends a side-table write within one row group
(collectors/base.py `_write_side_tables`, core/sidestore.py `write_table`)."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from hst import collectors as coll
from hst.app.crypto import generate_key
from hst.collectors.base import CollectionStopped, Collector, SourceConfig
from hst.collectors.util import GraphBuilder
from hst.core import Settings

RUN_ID = "1700000000000-aaaaaaaa"
CTS = 1_700_000_000_000
GROUP = 10


class FakeSession:
    """Node upserts answered inline, every other statement accepted."""

    def execute_write(self, work):
        return work(self)

    def run(self, q, **p):
        class _Result:
            def data(self_inner):
                if "UNWIND $rows" in q and "MERGE (n" in q:
                    return [{"uid": r["uid"], "before": {}, "after": {**r["props"]}} for r in p["rows"]]
                return []

        return _Result()


class HostCfg(SourceConfig):
    host: str = ""


class RowCollector(Collector):
    """A device whose side tables are whatever the test hands it."""

    name = "nxos"
    ConfigModel = HostCfg
    SIDE_TABLES = ("arp", "mac")

    def __init__(self, settings: Settings, tables: Callable[[], dict[str, Any]]):
        super().__init__(HostCfg(host="r1", source_name="edge"), settings)
        self.scope = "nxos:r1"
        self._tables = tables
        self.stop = threading.Event()

    def fetch(self):
        return {"seen": 1}

    def normalize(self, raw):
        b = GraphBuilder()
        b.node("Device", "dev:r1", hostname="r1", role="router")
        return b.batch("edge", self.scope)

    def probe(self) -> str:
        return "ok"

    def side_tables(self, raw):
        return self._tables()


class LazyRows:
    """`count` ARP rows built as they are read, the way `streams.MappedRows`
    builds them. `on_row(i)` runs before row `i` is built."""

    def __init__(self, count: int, on_row: Callable[[int], None] = lambda i: None) -> None:
        self.count = count
        self.read = 0
        self._on_row = on_row

    def __len__(self) -> int:
        return self.count

    def __iter__(self) -> Iterator[dict[str, Any]]:
        for i in range(self.count):
            self._on_row(i)
            self.read += 1
            yield {
                "device_uid": "dev:r1",
                "vrf": "default",
                "ip": f"10.0.{i // 256}.{i % 256}",
                "mac": "00:00:5e:00:53:01",
                "af": 4,
            }


MAC = [{"device_uid": "dev:r1", "vlan": 10, "mac": "00:00:5e:00:53:01", "port_name": "Eth1/1"}]


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        hst_data_dir=tmp_path,
        hst_secret_key=generate_key(),
        sidestore_row_group_rows=GROUP,
    )


def _files(settings: Settings) -> list[str]:
    root = settings.sidestore_dir
    if not root.is_dir():
        return []
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())


def _load(collector: Collector, reported: list[Path]) -> Any:
    return coll.load_payload(
        collector,
        FakeSession(),
        {"seen": 1},
        collection_ts=CTS,
        run_id=RUN_ID,
        ts_ms=CTS,
        on_write=lambda path, _source, _ts: reported.append(path),
    )


def test_a_stop_during_a_table_ends_its_write_within_one_row_group(tmp_path):
    settings = _settings(tmp_path)
    collector: RowCollector

    def on_row(i: int) -> None:
        if i == 15:  # the operator's cancel lands in the second row group
            collector.stop.set()

    rows = LazyRows(100, on_row)
    collector = RowCollector(settings, lambda: {"arp": rows})
    reported: list[Path] = []

    with pytest.raises(CollectionStopped):
        _load(collector, reported)

    # the row group the stop landed in is finished, and no further one is read
    assert rows.read == 2 * GROUP
    assert _files(settings) == []
    assert reported == []


def test_a_stop_during_a_later_table_removes_the_tables_already_written(tmp_path):
    """The tables are written in name order: `arp` is complete on disk when the
    stop lands while `mac` is read, and is removed with it."""
    settings = _settings(tmp_path)
    collector: RowCollector

    def on_row(i: int) -> None:
        if i == 0:
            collector.stop.set()

    macs = [dict(MAC[0], mac=f"00:00:5e:00:54:{i:02x}") for i in range(3)]

    class LazyMac(LazyRows):
        def __iter__(self) -> Iterator[dict[str, Any]]:
            for i, row in enumerate(macs):
                self._on_row(i)
                self.read += 1
                yield row

    arp = LazyRows(5)
    mac = LazyMac(len(macs), on_row)
    collector = RowCollector(settings, lambda: {"arp": arp, "mac": mac})
    reported: list[Path] = []

    with pytest.raises(CollectionStopped):
        _load(collector, reported)

    assert arp.read == 5
    assert mac.read == len(macs)  # the first row group, read before the stop was seen
    assert _files(settings) == []
    assert reported == []


def test_a_stop_set_before_a_table_reads_none_of_its_rows(tmp_path):
    settings = _settings(tmp_path)
    rows = LazyRows(30)
    collector = RowCollector(settings, lambda: {"arp": rows})
    real = collector.table_outcomes

    def stop_then_state(raw):
        # set after the load's own check before the side tables
        collector.stop.set()
        return real(raw)

    collector.table_outcomes = stop_then_state  # type: ignore[method-assign]

    with pytest.raises(CollectionStopped):
        _load(collector, [])

    assert rows.read == 0
    assert _files(settings) == []


def test_a_flag_that_stays_down_writes_every_table(tmp_path):
    settings = _settings(tmp_path)
    rows = LazyRows(25)
    collector = RowCollector(settings, lambda: {"arp": rows, "mac": MAC})
    reported: list[Path] = []

    manifest = _load(collector, reported)

    assert {name: (o.status, o.row_count) for name, o in manifest.tables.items()} == {
        "arp": ("complete", 25),
        "mac": ("complete", 1),
    }
    assert len(reported) == 2
    assert not [name for name in _files(settings) if name.endswith(".tmp")]
