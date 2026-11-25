"""A side-table row the collector cannot build fails the device; a row the side
store cannot convert fails only its table (collectors/base.py
`_write_side_tables`)."""

from __future__ import annotations

import gc
import time
import weakref
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from hst import collectors as coll
from hst.app.crypto import dek, generate_key
from hst.collectors import streams
from hst.collectors.base import Collector, SourceConfig
from hst.collectors.util import GraphBuilder
from hst.core import Settings, debug_capture, rawstore
from hst.core.manifest import file_facts

RUN_ID = "1700000000000-aaaaaaaa"
CTS = 1_700_000_000_000


def _settings(tmp_path, **kw: Any) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key(), **kw)


class FakeSession:
    """Minimal SessionLike: MERGE-shaped node upserts answered inline, every
    other statement accepted and ignored."""

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


ARP = [
    {"device_uid": "dev:r1", "vrf": "default", "ip": "10.0.0.1", "mac": "00:00:5e:00:53:01", "af": 4},
    {"device_uid": "dev:r1", "vrf": "default", "ip": "10.0.0.2", "mac": "00:00:5e:00:53:02", "af": 4},
]
MAC = [{"device_uid": "dev:r1", "vlan": 10, "mac": "00:00:5e:00:53:01", "port_name": "Eth1/1"}]


def _unbuildable(record: dict[str, Any]) -> dict[str, Any]:
    # The mapping of a parsed record that lacks a field the parse expected.
    return {**record, "interface_name": record["interface"]}


def _load(collector: Collector, on_write: Callable[[Path, str, int], None] | None = None) -> Any:
    return coll.load_payload(
        collector, FakeSession(), {"seen": 1}, collection_ts=CTS, run_id=RUN_ID, ts_ms=CTS, on_write=on_write
    )


def _raised(collector: Collector, on_write: Callable[[Path, str, int], None] | None = None) -> BaseException:
    try:
        _load(collector, on_write)
    except Exception as exc:
        return exc
    raise AssertionError("the load did not raise")


def _parquet(settings: Settings) -> list[str]:
    root = settings.sidestore_dir
    if not root.is_dir():
        return []
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())


# --- a row that cannot be built fails the load -----------------------------------------


def test_a_row_view_that_cannot_build_a_row_fails_the_load_with_the_parse_error(tmp_path):
    """One-row row groups, so the first arp row is already in the file when the
    second cannot be built."""
    settings = _settings(tmp_path, sidestore_row_group_rows=1)

    def second_unbuildable(record: dict[str, Any]) -> dict[str, Any]:
        return _unbuildable(record) if record["ip"] == "10.0.0.2" else dict(record)

    collector = RowCollector(
        settings, lambda: {"arp": streams.MappedRows(ARP, second_unbuildable), "mac": MAC}
    )

    with pytest.raises(KeyError) as raised:
        _load(collector)

    assert type(raised.value) is KeyError
    assert raised.value.args == ("interface",)
    # The writer removes the partly written arp file, and the load stopped
    # there: the mac table after it was never written.
    assert _parquet(settings) == []


def test_it_fails_exactly_as_a_raising_side_tables_does(tmp_path):
    """The eager build of the same rows inside `side_tables` raised this
    exception from the load before any table was written."""
    settings = _settings(tmp_path)

    def eager() -> dict[str, Any]:
        return {"arp": [_unbuildable(r) for r in ARP]}

    with pytest.raises(KeyError) as eager_raised:
        _load(RowCollector(settings, eager))
    with pytest.raises(KeyError) as lazy_raised:
        _load(RowCollector(settings, lambda: {"arp": streams.MappedRows(ARP, _unbuildable)}))

    assert type(lazy_raised.value) is type(eager_raised.value)
    assert str(lazy_raised.value) == str(eager_raised.value)


def _chained(record: dict[str, Any]) -> dict[str, Any]:
    """A mapping that turns the missing field into its own error, `from` it."""
    try:
        return {**record, "interface_name": record["interface"]}
    except KeyError as exc:
        raise ValueError("vendor field missing") from exc


def _implicit(record: dict[str, Any]) -> dict[str, Any]:
    """The same error raised while the KeyError is handled, without `from`."""
    try:
        return {**record, "interface_name": record["interface"]}
    except KeyError:
        raise ValueError("vendor field missing")  # noqa: B904


@pytest.mark.parametrize("mapping", [_chained, _implicit], ids=["from", "implicit"])
def test_the_parse_error_keeps_the_cause_and_context_it_was_raised_with(tmp_path, mapping):
    eager = _raised(RowCollector(_settings(tmp_path / "eager"), lambda: {"arp": [mapping(r) for r in ARP]}))
    lazy = _raised(
        RowCollector(_settings(tmp_path / "view"), lambda: {"arp": streams.MappedRows(ARP, mapping)})
    )

    assert type(lazy) is type(eager) is ValueError
    assert repr(lazy.__context__) == repr(eager.__context__) == "KeyError('interface')"
    assert repr(lazy.__cause__) == repr(eager.__cause__)
    assert lazy.__suppress_context__ is eager.__suppress_context__


def test_a_later_table_that_cannot_be_built_leaves_no_table_written_or_reported(tmp_path, monkeypatch):
    """arp sorts before mac, so the view writes the whole arp table before a mac
    row fails. The eager build of the same mac rows fails before any table is
    written; the view's failure removes the arp file it wrote. Neither load
    reports a side-store file."""
    from hst.core import sidestore

    written: list[Path] = []
    write_table = sidestore.write_table

    def recording(*args: Any, **kwargs: Any) -> Path | None:
        path = write_table(*args, **kwargs)
        if path is not None:
            written.append(path)
        return path

    monkeypatch.setattr(sidestore, "write_table", recording)
    outcome = {}
    for name, mac in (
        ("eager", lambda: [_unbuildable(r) for r in MAC]),
        ("view", lambda: streams.MappedRows(MAC, _unbuildable)),
    ):
        settings = _settings(tmp_path / name)
        reported: list[Path] = []
        exc = _raised(
            RowCollector(settings, lambda mac=mac: {"arp": ARP, "mac": mac()}),
            lambda path, sha, size, reported=reported: reported.append(path),
        )
        outcome[name] = (type(exc), str(exc), reported, _parquet(settings))

    assert outcome["view"] == outcome["eager"] == (KeyError, "'interface'", [], [])
    assert [p.relative_to(tmp_path).as_posix() for p in written] == [
        f"view/sidestore/arp/edge/r1/{RUN_ID}.parquet"
    ]


def test_the_debug_capture_records_the_failure_against_the_table_writes(tmp_path):
    settings = _settings(tmp_path)
    debug_capture.set_switch(settings, "edge", until_ms=int(time.time() * 1000) + 60_000, by="otto")

    with pytest.raises(KeyError):
        _load(RowCollector(settings, lambda: {"arp": streams.MappedRows(ARP, _unbuildable)}))

    raw_path = rawstore.raw_path_of(settings.raw_dir, "edge", "r1", RUN_ID)
    records, unreadable = debug_capture.read_records(
        rawstore.sibling(raw_path, rawstore.DEBUG_SUFFIX), dek(settings)
    )
    assert unreadable == 0
    ends = {r["step"]: r for r in records if r["event"] == "end"}
    assert ends["side_tables"]["rows"] == {"arp": 2}
    assert "error" not in ends["side_tables"]
    assert ends["write_side_tables"]["error"] == "KeyError: 'interface'"
    assert records[-1]["event"] == "finish" and records[-1]["status"] == "error"


def test_a_failed_load_frees_its_rows_with_its_exception(tmp_path):
    """The re-raise leaves no reference cycle through the frame that wrote the tables."""

    class Records(list[dict[str, Any]]):
        """A list that can be weakly referenced."""

    sources: list[weakref.ref[Records]] = []

    def tables() -> dict[str, Any]:
        source = Records(ARP)
        sources.append(weakref.ref(source))
        return {"arp": streams.MappedRows(source, _unbuildable)}

    collector = RowCollector(_settings(tmp_path), tables)
    gc.collect()
    gc.disable()
    try:
        exc = _raised(collector)
        assert isinstance(exc, KeyError)
        assert sources[0]() is not None
        del exc
        assert sources[0]() is None
    finally:
        gc.enable()


def test_a_view_whose_length_disagrees_with_its_rows_fails_the_load(tmp_path):
    settings = _settings(tmp_path)
    short = streams.ChainRows([(len(ARP) + 1, lambda: iter(ARP))])
    collector = RowCollector(settings, lambda: {"arp": short})

    with pytest.raises(RuntimeError, match="ChainRows part 0 yielded 2 of its 3 row"):
        _load(collector)


def test_the_observations_only_load_fails_the_same_way(tmp_path):
    settings = _settings(tmp_path)
    collector = RowCollector(settings, lambda: {"arp": streams.MappedRows(ARP, _unbuildable)})

    with pytest.raises(KeyError):
        coll.load_observations(collector, {"seen": 1}, collection_ts=CTS, run_id=RUN_ID, ts_ms=CTS)


def test_execute_seals_the_payload_and_then_fails_the_load(tmp_path):
    """The raw file is written before the load, as for any other load failure."""
    settings = _settings(tmp_path)
    collector = RowCollector(settings, lambda: {"arp": streams.MappedRows(ARP, _unbuildable)})

    with pytest.raises(KeyError):
        coll.execute(collector, FakeSession(), collection_ts=CTS)

    assert len(rawstore.raw_files(settings.raw_dir, "edge", 10)) == 1


# --- a row the side store cannot convert fails its table -------------------------------


@pytest.mark.parametrize("lazy", [False, True], ids=["list", "view"])
def test_a_row_arrow_cannot_convert_fails_its_table_and_the_load_goes_on(tmp_path, lazy):
    settings = _settings(tmp_path)
    bad = [{**ARP[0], "af": "four"}]

    def tables() -> dict[str, Any]:
        return {"arp": streams.MappedRows(bad, dict) if lazy else bad, "mac": MAC}

    reported: list[Path] = []
    manifest = _load(RowCollector(settings, tables), lambda path, sha, size: reported.append(path))

    arp = manifest.tables["arp"]
    assert arp.status == "failed"
    assert arp.row_count == 1
    assert arp.detail.startswith(("ArrowInvalid", "ArrowTypeError"))
    assert manifest.tables["mac"].status == "complete"
    assert manifest.tables["mac"].row_count == 1
    assert _parquet(settings) == [f"mac/edge/r1/{RUN_ID}.parquet"]
    assert reported == [settings.sidestore_dir / "mac" / "edge" / "r1" / f"{RUN_ID}.parquet"]


def test_views_that_build_their_rows_write_the_tables_the_lists_write(tmp_path):
    settings = _settings(tmp_path)
    manifest = _load(
        RowCollector(
            settings, lambda: {"arp": streams.MappedRows(ARP, dict), "mac": streams.MappedRows(MAC, dict)}
        )
    )

    assert {name: (t.status, t.row_count) for name, t in manifest.tables.items()} == {
        "arp": ("complete", 2),
        "mac": ("complete", 1),
    }


def test_every_written_table_is_reported_once_with_the_digest_of_its_file(tmp_path):
    settings = _settings(tmp_path)
    debug_capture.set_switch(settings, "edge", until_ms=int(time.time() * 1000) + 60_000, by="otto")
    reported: list[tuple[Path, str, int]] = []

    manifest = _load(
        RowCollector(settings, lambda: {"arp": streams.MappedRows(ARP, dict), "mac": MAC}),
        lambda path, sha, size: reported.append((path, sha, size)),
    )

    assert [(p.relative_to(settings.sidestore_dir).as_posix(), sha, size) for p, sha, size in reported] == [
        (
            f"{table}/edge/r1/{RUN_ID}.parquet",
            *file_facts(settings.hst_data_dir / manifest.tables[table].path),
        )
        for table in ("arp", "mac")
    ]
    raw_path = rawstore.raw_path_of(settings.raw_dir, "edge", "r1", RUN_ID)
    records, _ = debug_capture.read_records(rawstore.sibling(raw_path, rawstore.DEBUG_SUFFIX), dek(settings))
    [end] = [r for r in records if r["event"] == "end" and r["step"] == "write_side_tables"]
    assert end["outcomes"] == {"arp": "complete", "mac": "complete"}
