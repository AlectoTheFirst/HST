"""`execute` and `execute_observations` with `sealed=`: a payload the fetch
window sealed to a spill file (`collectors.base.spill`) loads exactly as the
same payload handed in as `raw=`.

The spill file is moved to the raw path `write` would have written, joined
and reported the same way, and the load reads the payload back from it. Every
artifact of the two paths is compared: the manifest, the raw text sealed, the
file list reported through `on_write` and each parquet file's layout. The
payloads are the Cisco golden cases at fixture and small scale and the VyOS
fixture cases (`tests/support/`): synthetic, nothing captured from real
infrastructure.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from tests.support import synthetic_vyos
from tests.support.synthetic_payloads import (
    COLLECTOR_HOST,
    COLLECTOR_SOURCE,
    SNAPSHOT_TS,
    case_payload,
    make_collector,
    make_settings,
    parquet_layout,
)
from tests.test_collector_execute import DevCollector, FakeSession, HostCfg

from hst import collectors as coll
from hst.app.crypto import decrypt, dek, generate_key
from hst.collectors import base as collectors_base
from hst.core import Settings, rawstore
from hst.core.model import RunManifest

FETCH_MS = 1_700_000_000_000
WINDOW = (FETCH_MS, FETCH_MS + 1_500)
NONCE = "aaaaaaaa"

CISCO_CASES = (
    *(
        f"{family}/fixture/{variant}"
        for family in ("iosxe", "iosxr", "nxos")
        for variant in ("plain", "unicode")
    ),
    *(f"{family}/small/plain" for family in ("iosxe", "iosxr", "nxos")),
)
VYOS_CASES = tuple(key for key in synthetic_vyos.CASES if key.startswith("fixture/"))

Written = list[tuple[Path, str, int]]


@pytest.fixture
def run_ids(monkeypatch) -> list[int | None]:
    """Every run id is `<fetch time>-<NONCE>`, so the two paths' artifacts
    compare as they stand, and the fetch time of every run id built is
    recorded: a sealed load must use the run id its spill was sealed under
    and build none of its own."""
    calls: list[int | None] = []

    def fixed(fetch_ts_ms: int | None = None) -> str:
        calls.append(fetch_ts_ms)
        return f"{fetch_ts_ms}-{NONCE}"

    monkeypatch.setattr(collectors_base, "new_run_id", fixed)
    return calls


def _payload(key: str) -> dict[str, Any]:
    if key.startswith("vyos:"):
        return synthetic_vyos.new_raw(synthetic_vyos.answers(key.removeprefix("vyos:")))
    return case_payload(key)


def _collector(key: str, settings: Settings) -> Any:
    if key.startswith("vyos:"):
        return synthetic_vyos.make_collector(settings)
    return make_collector(key.split("/")[0], settings)


def _load(
    key: str, data_dir: Path, *, sealed: bool, observations: bool = False
) -> tuple[Settings, RunManifest, Written]:
    """One load of case `key` into its own data directory, by `raw=` or by a
    spill of the same payload handed in as `sealed=`."""
    settings = make_settings(data_dir, hst_secret_key=generate_key())
    collector = _collector(key, settings)
    payload = _payload(key)
    written: Written = []
    kw: dict[str, Any] = {}
    if sealed:
        kw["sealed"] = coll.spill(collector, payload, source_name=COLLECTOR_SOURCE, fetch_ts_ms=FETCH_MS)
    else:
        kw["raw"] = payload
    del payload
    common: dict[str, Any] = {
        "collection_ts": SNAPSHOT_TS,
        "source_name": COLLECTOR_SOURCE,
        "on_write": lambda path, sha, size: written.append((path, sha, size)),
        "fetch_window": WINDOW,
    }
    if observations:
        manifest = coll.execute_observations(collector, **kw, **common)
    else:
        manifest = coll.execute(collector, FakeSession(), **kw, **common)
    return settings, manifest, written


def _artifacts(settings: Settings, manifest: RunManifest, written: Written) -> dict[str, Any]:
    """What one load left behind, in a form two data directories compare in."""
    base = settings.hst_data_dir
    for path, sha, size in written:
        data = path.read_bytes()
        assert (hashlib.sha256(data).hexdigest(), len(data)) == (sha, size), (
            f"{path} is not what was reported"
        )
    raw_path = written[0][0]
    text = gzip.decompress(decrypt(dek(settings), raw_path.read_bytes()))
    return {
        "manifest": manifest.model_dump(mode="json"),
        "written": [path.relative_to(base).as_posix() for path, _sha, _size in written],
        "raw_text_sha": hashlib.sha256(text).hexdigest(),
        "joined": json.loads(rawstore.sibling(raw_path, rawstore.META_SUFFIX).read_text()),
        "parquet": {
            table: parquet_layout(base / outcome.path)
            for table, outcome in manifest.tables.items()
            if outcome.path
        },
    }


def _no_spill_left(settings: Settings) -> bool:
    spill_dir = settings.raw_dir / rawstore.SPILL_DIR
    return not spill_dir.exists() or not any(spill_dir.iterdir())


# --- parity --------------------------------------------------------------------------------


@pytest.mark.parametrize("key", [*CISCO_CASES, *(f"vyos:{k}" for k in VYOS_CASES)])
def test_a_sealed_load_writes_what_a_raw_load_writes(tmp_path, run_ids, key):
    raw = _artifacts(*_load(key, tmp_path / "raw", sealed=False))
    settings, manifest, written = _load(key, tmp_path / "sealed", sealed=True)
    sealed = _artifacts(settings, manifest, written)

    assert sealed == raw
    assert manifest.run_id == f"{FETCH_MS}-{NONCE}"
    assert run_ids == [FETCH_MS, FETCH_MS], "the sealed load built a run id of its own"
    assert written[0][0] == rawstore.raw_path_of(
        settings.raw_dir, COLLECTOR_SOURCE, COLLECTOR_HOST, manifest.run_id
    )
    assert raw["joined"] == {"snapshot_ts": SNAPSHOT_TS}
    assert _no_spill_left(settings)


@pytest.mark.parametrize(
    "key", ["iosxe/fixture/plain", "iosxr/fixture/plain", "nxos/fixture/plain", "vyos:fixture/plain"]
)
def test_a_sealed_observation_publication_writes_what_a_raw_one_writes(tmp_path, run_ids, key):
    raw = _artifacts(*_load(key, tmp_path / "raw", sealed=False, observations=True))
    settings, manifest, written = _load(key, tmp_path / "sealed", sealed=True, observations=True)

    assert _artifacts(settings, manifest, written) == raw
    assert raw["parquet"], "the case writes no side-store table to compare"
    assert run_ids == [FETCH_MS, FETCH_MS]
    assert _no_spill_left(settings)


# --- the run identity and the join ----------------------------------------------------------


def _settings(tmp_path: Path) -> Settings:
    return Settings(_env_file=None, hst_data_dir=tmp_path, hst_secret_key=generate_key())


def _device(settings: Settings) -> DevCollector:
    return DevCollector(HostCfg(host="r1", source_name="edge"), settings)


def test_a_sealed_raw_file_is_named_for_its_fetch_time_and_joined_to_the_run(tmp_path):
    settings = _settings(tmp_path)
    collector = _device(settings)
    spilled = coll.spill(collector, {"seen": 1}, source_name="edge", fetch_ts_ms=FETCH_MS)

    manifest = coll.execute(
        collector,
        FakeSession(),
        sealed=spilled,
        collection_ts=SNAPSHOT_TS,
        source_name="edge",
        fetch_window=WINDOW,
    )

    (raw_path,) = (settings.raw_dir / "edge" / "r1").glob(f"*{rawstore.SUFFIX}")
    run_id = raw_path.name[: -len(rawstore.SUFFIX)]
    stamp, nonce = run_id.split("-")
    assert int(stamp) == FETCH_MS
    assert len(nonce) == 8 and int(nonce, 16) >= 0
    assert run_id == spilled.run_id == manifest.run_id
    assert json.loads(rawstore.sibling(raw_path, rawstore.META_SUFFIX).read_text()) == {
        "snapshot_ts": SNAPSHOT_TS
    }
    assert _no_spill_left(settings)


def test_a_sealed_load_with_no_collection_ts_joins_its_fetch_time(tmp_path):
    settings = _settings(tmp_path)
    collector = _device(settings)
    spilled = coll.spill(collector, {"seen": 1}, source_name="edge", fetch_ts_ms=FETCH_MS)

    coll.execute(collector, FakeSession(), sealed=spilled, source_name="edge")

    meta = rawstore.sibling(spilled.final, rawstore.META_SUFFIX)
    assert json.loads(meta.read_text()) == {"snapshot_ts": FETCH_MS}


def test_raw_and_sealed_together_are_refused_before_anything_is_written(tmp_path):
    settings = _settings(tmp_path)
    collector = _device(settings)
    handle = rawstore.Spilled(
        settings.raw_dir / rawstore.SPILL_DIR / f"{FETCH_MS}-{NONCE}{rawstore.SPILL_SUFFIX}",
        settings.raw_dir,
        "edge",
        "r1",
        f"{FETCH_MS}-{NONCE}",
        FETCH_MS,
    )

    with pytest.raises(TypeError, match="raw and sealed"):
        coll.execute(collector, FakeSession(), raw={"seen": 1}, sealed=handle, collection_ts=SNAPSHOT_TS)
    with pytest.raises(TypeError, match="raw and sealed"):
        coll.execute_observations(collector, raw={"seen": 1}, sealed=handle, collection_ts=SNAPSHOT_TS)
    with pytest.raises(TypeError, match="raw and sealed"):
        coll.execute_observations(collector, collection_ts=SNAPSHOT_TS)

    assert not settings.raw_dir.exists()


def test_a_spill_that_cannot_be_moved_is_removed_and_the_error_propagates(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    collector = _device(settings)
    spilled = coll.spill(collector, {"seen": 1}, source_name="edge", fetch_ts_ms=FETCH_MS)

    def cross_device(handle: rawstore.Spilled) -> Path:
        raise OSError(18, "Invalid cross-device link")

    monkeypatch.setattr(rawstore, "adopt", cross_device)

    with pytest.raises(OSError, match="cross-device"):
        coll.execute(collector, FakeSession(), sealed=spilled, collection_ts=SNAPSHOT_TS, source_name="edge")

    assert not spilled.path.exists()
    assert not spilled.final.exists()


def test_a_normalize_that_raises_leaves_the_raw_file_in_place_and_joined(tmp_path):
    class Failing(DevCollector):
        def normalize(self, raw: Any):
            raise RuntimeError("parser fault")

    settings = _settings(tmp_path)
    collector = Failing(HostCfg(host="r1", source_name="edge"), settings)
    spilled = coll.spill(collector, {"seen": 1}, source_name="edge", fetch_ts_ms=FETCH_MS)

    with pytest.raises(RuntimeError, match="parser fault"):
        coll.execute(collector, FakeSession(), sealed=spilled, collection_ts=SNAPSHOT_TS, source_name="edge")

    assert spilled.final.is_file()
    assert json.loads(rawstore.sibling(spilled.final, rawstore.META_SUFFIX).read_text()) == {
        "snapshot_ts": SNAPSHOT_TS
    }
    assert _no_spill_left(settings)


def test_a_read_back_that_fails_leaves_the_raw_file_joined_not_parked(tmp_path, monkeypatch):
    """The file is joined before it is read back, so a payload that cannot be
    read is never left for a device run to pick up as parked."""
    settings = _settings(tmp_path)
    collector = _device(settings)
    spilled = coll.spill(collector, {"seen": 1}, source_name="edge", fetch_ts_ms=FETCH_MS)

    def unreadable(path: Path, key: str) -> Any:
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(rawstore, "read", unreadable)

    with pytest.raises(OSError, match="Input/output"):
        coll.execute(collector, FakeSession(), sealed=spilled, collection_ts=SNAPSHOT_TS, source_name="edge")

    assert spilled.final.is_file()
    assert rawstore.parked(settings.raw_dir) == []
