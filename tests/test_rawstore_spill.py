"""`rawstore.spill`, `adopt`, `drop_spill` and `clear_spills`: a payload sealed
under `<raw_dir>/.spill/` before its load."""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from hst.app import crypto
from hst.app.crypto import decrypt, dek, generate_key
from hst.core import Settings, debug_capture, manifest, rawstore, reconcile, replay

RUN_ID = "1700000000000-aaaaaaaa"
SOURCE = "edge"
HOST = "r1.example.net"


def _settings(tmp_path: Path) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())


def _payload() -> dict[str, Any]:
    """Text that compresses at every level, and to a different size at 1 and 9."""
    lines = "\n".join(
        f"route 10.{i % 251}.{i % 97}.0/24 via 192.0.2.{i % 13} metric {i * 7 % 1009}" for i in range(4000)
    )
    return {
        "show ip route": lines,
        "show version": "Version 17.9",
        "_strata_outcomes": {"show ip route": "ok"},
    }


def _sealed_text(settings: Settings, path: Path) -> bytes:
    return gzip.decompress(decrypt(dek(settings), path.read_bytes()))


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _spill(settings: Settings, payload: Any, *, run_id: str = RUN_ID, host: str = HOST, **kw: Any):
    return rawstore.spill(settings.raw_dir, SOURCE, run_id, payload, host=host, key=dek(settings), **kw)


# --- the spill file ------------------------------------------------------------------------


def test_a_spill_is_a_private_file_under_the_spill_directory(tmp_path):
    settings = _settings(tmp_path)

    spilled = _spill(settings, _payload())

    spill_dir = settings.raw_dir / rawstore.SPILL_DIR
    assert spilled.path.parent == spill_dir
    assert spilled.path.name.startswith(f"{RUN_ID}-")
    assert spilled.path.name.endswith(rawstore.SPILL_SUFFIX)
    assert _mode(spilled.path) == 0o600
    assert _mode(spill_dir) == 0o700
    assert _mode(settings.raw_dir) == 0o700
    assert (spilled.run_id, spilled.fetch_ts_ms, spilled.source, spilled.host) == (
        RUN_ID,
        1_700_000_000_000,
        SOURCE,
        HOST,
    )
    assert spilled.final == rawstore.raw_path_of(settings.raw_dir, SOURCE, HOST, RUN_ID)


@pytest.mark.parametrize("level", [1, 9])
def test_a_spill_reads_back_as_the_json_the_raw_store_seals(tmp_path, level):
    settings = _settings(tmp_path)
    payload = _payload()

    spilled = _spill(settings, payload, level=level)

    assert _sealed_text(settings, spilled.path) == json.dumps(payload, default=str).encode()


def test_the_compression_level_reaches_the_spill(tmp_path):
    settings = _settings(tmp_path)
    fast = _spill(settings, _payload(), run_id="1700000000000-aaaaaaa1", level=1)
    small = _spill(settings, _payload(), run_id="1700000000000-aaaaaaa9", level=9)

    assert fast.path.stat().st_size != small.path.stat().st_size


def test_two_spills_of_one_run_id_keep_their_own_files(tmp_path):
    """Every source and host spills into one directory, and two fetches that
    start in the same millisecond can draw the same run id. Each spill keeps
    its own file, and each adopts its own payload."""
    settings = _settings(tmp_path)
    first = _spill(settings, {"host": "r1"}, host="r1")
    second = _spill(settings, {"host": "r2"}, host="r2")
    again = _spill(settings, {"host": "r1", "second": True}, host="r1")

    assert len({first.path, second.path, again.path}) == 3
    assert rawstore.read(rawstore.adopt(second), dek(settings)) == {"host": "r2"}
    assert rawstore.read(first.path, dek(settings)) == {"host": "r1"}
    assert rawstore.read(again.path, dek(settings)) == {"host": "r1", "second": True}


def test_a_spill_creates_no_source_or_host_directory(tmp_path):
    settings = _settings(tmp_path)

    _spill(settings, _payload())

    assert sorted(p.name for p in settings.raw_dir.iterdir()) == [rawstore.SPILL_DIR]


def test_a_malformed_run_id_is_refused(tmp_path):
    settings = _settings(tmp_path)

    with pytest.raises(ValueError, match="not a run id"):
        _spill(settings, _payload(), run_id="edge-1700000000000")

    assert not settings.raw_dir.exists()


def test_a_seal_that_fails_leaves_no_file(tmp_path, monkeypatch):
    settings = _settings(tmp_path)

    def failing(self, data: bytes) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(crypto.TokenWriter, "write", failing)

    with pytest.raises(OSError, match="disk full"):
        _spill(settings, _payload())

    assert list((settings.raw_dir / rawstore.SPILL_DIR).iterdir()) == []


# --- no reader lists one ------------------------------------------------------------------


def _readers(settings: Settings) -> dict[str, Any]:
    raw_dir = settings.raw_dir
    return {
        "raw_files": rawstore.raw_files(raw_dir, SOURCE, 100),
        "latest_path": rawstore.latest_path(raw_dir, SOURCE, HOST),
        "parked": rawstore.parked(raw_dir),
        "traces": rawstore.traces(raw_dir),
        "list_snapshots": replay.list_snapshots(raw_dir),
        "effective_runs": manifest.effective_runs(raw_dir, 2_000_000_000_000),
        "on_disk": reconcile._on_disk(settings),
        "capture_files": debug_capture.capture_files(raw_dir),
    }


def test_no_reader_lists_a_spill_or_the_temporary_file_of_one(tmp_path):
    """Every reader that walks the raw store, or iterates its children,
    answers the same with a spill file and a spill's temporary file present."""
    settings = _settings(tmp_path)
    key = dek(settings)
    joined = rawstore.write(settings.raw_dir, SOURCE, "1600000000000-bbbbbbbb", {"x": 1}, host=HOST, key=key)
    rawstore.mark_joined(joined, 1_600_000_000_000)
    rawstore.write(settings.raw_dir, SOURCE, "1600000000001-cccccccc", {"x": 2}, host=HOST, key=key)
    before = _readers(settings)
    assert before["raw_files"] and before["latest_path"] and before["parked"] and before["effective_runs"]

    _spill(settings, _payload())
    in_flight = settings.raw_dir / rawstore.SPILL_DIR / f"1700000000001-dddddddd{rawstore.TMP_SUFFIX}"
    in_flight.write_bytes(b"a partly written token")

    assert _readers(settings) == before


# --- adopt ---------------------------------------------------------------------------------


def test_adopt_moves_the_spill_to_the_raw_file_write_would_have_written(tmp_path):
    settings = _settings(tmp_path)
    payload = _payload()
    spilled = _spill(settings, payload)
    sealed = hashlib.sha256(spilled.path.read_bytes()).hexdigest()

    final = rawstore.adopt(spilled)

    assert final == rawstore.raw_path_of(settings.raw_dir, SOURCE, HOST, RUN_ID)
    assert final == spilled.final
    assert hashlib.sha256(final.read_bytes()).hexdigest() == sealed
    assert _mode(final) == 0o600
    assert _mode(final.parent) == 0o700
    assert _mode(final.parent.parent) == 0o700
    assert list((settings.raw_dir / rawstore.SPILL_DIR).iterdir()) == []
    assert rawstore.read(final, dek(settings)) == json.loads(json.dumps(payload, default=str))
    # the adopted file is a parked raw file like any other until it is joined
    assert [p.path for p in rawstore.parked(settings.raw_dir)] == [final]


def test_a_payload_with_no_host_adopts_into_the_source_directory(tmp_path):
    settings = _settings(tmp_path)
    spilled = _spill(settings, {"sites": ["hq"]}, host="")

    final = rawstore.adopt(spilled)

    assert final == settings.raw_dir / SOURCE / f"{RUN_ID}{rawstore.SUFFIX}"
    assert rawstore.latest_path(settings.raw_dir, SOURCE) == final


def test_adopt_of_a_missing_spill_raises_and_creates_no_raw_file(tmp_path):
    settings = _settings(tmp_path)
    spilled = _spill(settings, _payload())
    spilled.path.unlink()

    with pytest.raises(FileNotFoundError):
        rawstore.adopt(spilled)

    assert not spilled.final.exists()


# --- drop_spill ----------------------------------------------------------------------------


def test_drop_spill_removes_the_file_and_is_idempotent(tmp_path):
    settings = _settings(tmp_path)
    spilled = _spill(settings, _payload())

    rawstore.drop_spill(spilled)
    rawstore.drop_spill(spilled)

    assert not spilled.path.exists()
    assert (settings.raw_dir / rawstore.SPILL_DIR).is_dir()


def test_drop_spill_after_adopt_leaves_the_raw_file(tmp_path):
    settings = _settings(tmp_path)
    spilled = _spill(settings, _payload())
    final = rawstore.adopt(spilled)

    rawstore.drop_spill(spilled)

    assert final.is_file()


def test_drop_spill_logs_a_file_it_cannot_remove_and_does_not_raise(tmp_path, monkeypatch, caplog):
    settings = _settings(tmp_path)
    spilled = _spill(settings, _payload())

    def refusing(self: Path, missing_ok: bool = False) -> None:
        raise PermissionError(13, "Permission denied", str(self))

    with monkeypatch.context() as patched, caplog.at_level(logging.WARNING, logger=rawstore.logger.name):
        patched.setattr(Path, "unlink", refusing)
        rawstore.drop_spill(spilled)

    assert spilled.path.exists()
    assert any("could not remove raw spill file" in r.getMessage() for r in caplog.records)


# --- clear_spills --------------------------------------------------------------------------


def _aged(path: Path, seconds: float) -> Path:
    stamp = path.stat().st_mtime - seconds
    os.utime(path, (stamp, stamp))
    return path


def test_clear_spills_removes_spill_and_temporary_files_only(tmp_path):
    settings = _settings(tmp_path)
    spilled = _spill(settings, _payload())
    spill_dir = spilled.path.parent
    tmp = spill_dir / f"1700000000001-dddddddd{rawstore.TMP_SUFFIX}"
    tmp.write_bytes(b"partial")
    other = spill_dir / "notes.txt"
    other.write_text("not a spill")
    nested = spill_dir / f"1700000000002-eeeeeeee{rawstore.SPILL_SUFFIX}"
    nested.mkdir()

    removed = rawstore.clear_spills(settings.raw_dir)

    assert sorted(removed) == sorted([spilled.path, tmp])
    assert not spilled.path.exists() and not tmp.exists()
    assert other.exists() and nested.is_dir() and spill_dir.is_dir()


def test_clear_spills_before_a_time_keeps_younger_files(tmp_path):
    settings = _settings(tmp_path)
    old = _aged(_spill(settings, _payload(), run_id="1700000000000-aaaaaaa1").path, 3600)
    young = _spill(settings, _payload(), run_id="1700000000000-aaaaaaa2").path
    cutoff = young.stat().st_mtime - 60

    removed = rawstore.clear_spills(settings.raw_dir, before=cutoff)

    assert removed == [old]
    assert young.exists()


def test_clear_spills_of_a_store_with_no_spill_directory_creates_nothing(tmp_path):
    settings = _settings(tmp_path)

    assert rawstore.clear_spills(settings.raw_dir) == []
    assert not settings.raw_dir.exists()

    settings.raw_dir.mkdir()
    assert rawstore.clear_spills(settings.raw_dir) == []
    assert list(settings.raw_dir.iterdir()) == []


def test_clear_spills_logs_a_spill_path_it_cannot_list(tmp_path, caplog):
    settings = _settings(tmp_path)
    settings.raw_dir.mkdir()
    (settings.raw_dir / rawstore.SPILL_DIR).write_text("a file where the directory would be")

    with caplog.at_level(logging.WARNING, logger=rawstore.logger.name):
        assert rawstore.clear_spills(settings.raw_dir) == []

    assert any("could not list raw spill directory" in r.getMessage() for r in caplog.records)
