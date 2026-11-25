"""The start-up load that fills the place table once per file."""

import asyncio
import logging
import zipfile
from pathlib import Path

from tests.app.fakes import FakeStore
from tests.app.test_geo_places import ROWS, _places

from hst.app import main as app_main
from hst.app.geo_places import SOURCE_SETTING_KEY, file_sha256, load_bundled, source_record


def _zip(tmp_path: Path, name: str = "allCountries.zip", rows: list[str] = ROWS) -> Path:
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("allCountries.txt", "\n".join(rows) + "\n")
    return path


async def test_a_table_with_no_recorded_file_is_loaded_and_the_file_recorded(tmp_path):
    store, path = FakeStore(), _zip(tmp_path)

    assert await load_bundled(store, path) == len(_places())
    assert store.geo_places == _places()
    record = (await store.get_setting(SOURCE_SETTING_KEY)).value
    assert record == {"sha256": file_sha256(path), "file": "allCountries.zip", "source": "bundled"}


async def test_the_same_file_is_not_loaded_twice(tmp_path):
    store, path = FakeStore(), _zip(tmp_path)
    await load_bundled(store, path)
    store.geo_places = []

    assert await load_bundled(store, path) is None
    assert store.geo_places == []


async def test_a_new_bundled_file_replaces_the_earlier_one(tmp_path):
    store = FakeStore()
    await load_bundled(store, _zip(tmp_path))
    newer = _zip(tmp_path / "..", "newer.zip", ROWS[:1])

    assert await load_bundled(store, newer) == 1
    assert (await store.get_setting(SOURCE_SETTING_KEY)).value["sha256"] == file_sha256(newer)


async def test_a_file_an_operator_loaded_is_kept(tmp_path):
    store, path = FakeStore(), _zip(tmp_path)
    operator_file = _zip(tmp_path / "..", "DE.zip", ROWS[:1])
    await store.put_setting(SOURCE_SETTING_KEY, source_record(operator_file, "operator"), b"")

    assert await load_bundled(store, path) is None
    assert not getattr(store, "geo_places", [])


async def test_a_missing_file_loads_nothing(tmp_path, caplog):
    store = FakeStore()

    assert await load_bundled(store, tmp_path / "absent.zip") is None
    assert await store.get_setting(SOURCE_SETTING_KEY) is None
    assert "absent.zip is not a file" in caplog.text


async def test_a_failed_start_up_load_is_logged_and_does_not_raise(caplog):
    async def failing(store, path):
        raise ValueError("broken file")

    with caplog.at_level(logging.ERROR):
        await app_main._load_places(FakeStore(), Path("x.zip"), failing)
    assert "the start-up load failed" in caplog.text


def test_the_cli_load_records_the_file_as_the_operator_s(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    import hst.cli as cli

    store, path = FakeStore(), _zip(tmp_path, "DE.zip")
    monkeypatch.setattr(cli, "_with_store", lambda fn: asyncio.run(fn(store)))

    result = CliRunner().invoke(cli.app, ["geo-places", "load", str(path)])

    assert result.exit_code == 0, result.output
    assert (asyncio.run(store.get_setting(SOURCE_SETTING_KEY))).value == source_record(path, "operator")
