"""The index of the raw files no run has joined (core/rawstore.py `parked`): the
parked payloads are listed from one marker each, and not by reading the
directory of every device the store has ever kept."""

from __future__ import annotations

import contextlib
import shutil
from pathlib import Path

import pytest

from hst.app.crypto import dek, generate_key
from hst.core import rawstore
from hst.core.config import Settings


@pytest.fixture(autouse=True)
def _key(tmp_path, monkeypatch):
    global KEY
    KEY = dek(Settings(_env_file=None, hst_data_dir=tmp_path / "keys", hst_secret_key=generate_key()))


KEY = ""


def _run_id(n: int) -> str:
    return f"{1_790_000_000_000 + n}-abcdef{n:02d}"


def _estate(raw_dir: Path, devices: int, runs: int = 3) -> None:
    for d in range(devices):
        for r in range(runs):
            rawstore.write(raw_dir, "edge", _run_id(r), {"d": d}, host=f"h{d}", key=KEY)


def _settle_all_but(raw_dir: Path, keep: set[str]) -> None:
    for path in sorted(raw_dir.rglob(f"*{rawstore.SUFFIX}")):
        if path.parent.name not in keep:
            rawstore.mark_joined(path, 1)


def test_a_write_is_indexed_and_a_settle_removes_it(tmp_path):
    path = rawstore.write(tmp_path, "edge", _run_id(1), {"x": 1}, host="h1", key=KEY)
    marker = tmp_path / rawstore.PENDING_DIR / "edge" / "h1" / f"{_run_id(1)}{rawstore.PENDING_SUFFIX}"
    assert marker.is_file()
    assert [p.path for p in rawstore.parked(tmp_path)] == [path]

    rawstore.mark_joined(path, 5)

    assert not marker.exists()
    assert rawstore.parked(tmp_path) == []
    # a second settle finds it settled and leaves the index as it is
    with contextlib.suppress(FileExistsError):
        rawstore.mark_joined(path, 6)
    assert not marker.exists()


def test_a_superseded_payload_leaves_the_index(tmp_path):
    path = rawstore.write(tmp_path, "edge", _run_id(1), {"x": 1}, host="h1", key=KEY)
    rawstore.mark_superseded(path, 9)
    assert rawstore.parked(tmp_path) == []
    assert not list((tmp_path / rawstore.PENDING_DIR).rglob(f"*{rawstore.PENDING_SUFFIX}"))


def test_an_adopted_spill_is_indexed(tmp_path):
    spilled = rawstore.spill(tmp_path, "edge", _run_id(2), {"x": 1}, host="h1", key=KEY)
    assert rawstore.parked(tmp_path) == []

    final = rawstore.adopt(spilled)

    assert [p.path for p in rawstore.parked(tmp_path)] == [final]


def test_a_store_written_before_the_index_is_read_whole_once(tmp_path):
    _estate(tmp_path, devices=3, runs=2)
    _settle_all_but(tmp_path, {"h1"})
    shutil.rmtree(tmp_path / rawstore.PENDING_DIR)

    found = rawstore.parked(tmp_path)

    assert {(p.host, p.run_id) for p in found} == {("h1", _run_id(0)), ("h1", _run_id(1))}
    assert (tmp_path / rawstore.PENDING_DIR / rawstore.PENDING_BUILT).is_file()


def test_a_marker_whose_file_is_gone_is_dropped(tmp_path):
    path = rawstore.write(tmp_path, "edge", _run_id(1), {"x": 1}, host="h1", key=KEY)
    assert rawstore.parked(tmp_path)
    path.unlink()

    assert rawstore.parked(tmp_path) == []
    assert not list((tmp_path / rawstore.PENDING_DIR).rglob(f"*{rawstore.PENDING_SUFFIX}"))


def test_the_listing_reads_no_directory_of_a_device_that_has_nothing_parked(tmp_path, monkeypatch):
    _estate(tmp_path, devices=40, runs=5)
    _settle_all_but(tmp_path, {"h7"})
    rawstore.parked(tmp_path)
    listed: list[Path] = []
    real = Path.iterdir

    def spy(self):
        listed.append(self)
        return real(self)

    monkeypatch.setattr(Path, "iterdir", spy)

    found = rawstore.parked(tmp_path)

    assert {(p.host, p.run_id) for p in found} == {("h7", _run_id(r)) for r in range(5)}
    raw_leaves = {p for p in listed if rawstore.PENDING_DIR not in p.parts}
    assert raw_leaves == set()
    assert len(listed) <= 4


def test_the_effective_runs_of_the_devices_asked_for_read_only_their_directories(tmp_path, monkeypatch):
    """A snapshot's manifest asks for the run of each carried device, and the read of every
    directory of the store is the cost of the devices it does not ask for."""
    import os

    from hst.core import manifest

    _estate(tmp_path, devices=30, runs=4)
    for path in sorted(tmp_path.rglob(f"*{rawstore.SUFFIX}")):
        rawstore.mark_joined(path, 10 if path.name.startswith(_run_id(0)[:13]) else 20)
    scanned: list[str] = []
    real = os.scandir

    def spy(target):
        scanned.append(str(target))
        return real(target)

    monkeypatch.setattr(os, "scandir", spy)

    asked = manifest.effective_runs(tmp_path, 15, {("edge", "h3"), ("edge", "h9"), ("edge", "missing")})

    assert asked == {("edge", "h3"): _run_id(0), ("edge", "h9"): _run_id(0)}
    assert sorted(Path(p).name for p in scanned) == ["h3", "h9"]
    monkeypatch.undo()
    assert manifest.effective_runs(tmp_path, 15)[("edge", "h3")] == _run_id(0)
    assert len(manifest.effective_runs(tmp_path, 25)) == 30
