"""One small IOS-XE device through `execute`, held to the golden artifacts, and
three devices after it that leave nothing behind.

`execute` is the whole of one device's collection below the fetch: it seals
the payload in the raw store, normalizes and loads it, and writes its
side-store tables. Every artifact of that path must be the golden one of the
same payload (`tests/support/stream_golden.json` and its overlays): the change
hashes a run stores for the device, the JSON the raw file seals, each parquet
file's rows, row groups and schema, and the section and table outcomes the
manifest reports. A run keeps every device's collector until it publishes, so
a load must also leave nothing behind on it: neither the payload nor anything
built from it.

The payloads are the small IOS-XE golden case and two more of its size
(`tests/support/synthetic_payloads.py`): synthetic, nothing captured from real
infrastructure. `tests/perf/test_device_d_memory.py` holds the same path to
the peak model at a tenth of a full-table device, with the helpers below.
"""

from __future__ import annotations

import gc
import gzip
import hashlib
import json
import sys
import tracemalloc
import weakref
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from tests.support.synthetic_payloads import (
    ADDED_SINCE_BASE,
    COLLECTOR_HOST,
    COLLECTOR_SOURCE,
    RUN_ID,
    SCALES,
    SNAPSHOT_TS,
    base_spelling,
    case_payload,
    fixture_raw,
    held_mac_statement,
    iosxe_payload,
    load_golden,
    make_collector,
    make_settings,
    outcomes_json,
    parquet_layout,
    payload_sha,
    raw_json_sha,
    split_case,
    without_added_sections,
)
from tests.test_cisco_rib_volatility import base_digests, hash_as_base_record
from tests.test_collector_execute import FakeSession

from hst import collectors as coll
from hst.app.crypto import decrypt, dek, generate_key
from hst.collectors import base as collectors_base
from hst.collectors.base import obs_sha, raw_sha
from hst.core import Settings, rawstore
from hst.core.manifest import sidestore_row_facts
from hst.core.model import RunManifest

CASE = "iosxe/small/plain"
GOLDEN = load_golden()

# The golden run id is `<fetch time>-<nonce>`. `execute` stamps the run id from
# the start of the fetch window it is handed, and `golden_run_id` supplies the
# nonce, so the load runs under the golden run id.
_FETCH_MS, _NONCE = RUN_ID.split("-")
FETCH_WINDOW = (int(_FETCH_MS), int(_FETCH_MS))

# What three devices loaded one after another may leave traced once the last
# one returns.
RESIDUE_BYTES = 5_000_000

# (path, sha256, size) of one file `execute` reports through `on_write`.
Written = tuple[Path, str, int]


class WatchedPayload(dict[str, Any]):
    """A payload a weak reference can watch: a plain dict cannot be one's
    referent, a subclass can."""


def _references(texts: list[str]) -> list[int]:
    """The reference count of each text, read the same way every time so that
    two readings compare."""
    return [sys.getrefcount(text) for text in texts]


def _holders(text: str, own: list[str]) -> str:
    """The types of the objects the garbage collector tracks that refer to
    `text`, besides the list `own`."""
    kinds = sorted({type(holder).__name__ for holder in gc.get_referrers(text) if holder is not own})
    return ", ".join(kinds) or "nothing the garbage collector tracks"


class WatchedTexts:
    """A str cannot be the referent of a weak reference."""

    def __init__(self, payload: Mapping[str, Any]) -> None:
        shared = {id(text) for text in fixture_raw("iosxe").values()}
        self.commands = [
            command
            for command, text in payload.items()
            if isinstance(text, str) and text and id(text) not in shared
        ]
        self._texts: list[str] = [payload[command] for command in self.commands]
        self._held = _references(self._texts)

    def kept(self) -> list[str]:
        """The payload must be dropped and collected before the call."""
        now = _references(self._texts)
        return [
            f"{self.commands[index]!r} ({_holders(self._texts[index], self._texts)})"
            for index, (held, current) in enumerate(zip(self._held, now, strict=True))
            if current >= held
        ]


def golden_settings(data_dir: Path, **overrides: Any) -> Settings:
    """`make_settings` (row groups of the golden `ROW_GROUP_ROWS`) with a data
    key of the test's own under `data_dir`."""
    return make_settings(data_dir, hst_secret_key=generate_key(), **overrides)


def golden_run_id(fetch_ts_ms: int | None = None) -> str:
    """`new_run_id` with the golden nonce. Every parquet row carries its run
    id, so only a load under the golden run id writes the golden rows."""
    return f"{fetch_ts_ms}-{_NONCE}"


def assert_golden_artifacts(
    key: str, settings: Settings, manifest: RunManifest, written: list[Written]
) -> None:
    """Every artifact of one `execute` of the golden case `key`, run under the
    golden run id with `settings`, is the golden one.

    `written` is what `execute` reported through `on_write`, in order: the raw
    file, then one parquet file per table with rows. The golden table outcomes
    name their files under the golden run id, which is this load's own, so
    they compare as they stand. The raw file is the golden one once its
    commands are in the spelling of the base record (`base_spelling`).
    """
    golden = GOLDEN["cases"][key]
    assert manifest.run_id == RUN_ID
    for path, sha, size in written:
        data = path.read_bytes()
        assert (hashlib.sha256(data).hexdigest(), len(data)) == (sha, size), (
            f"{path} is not what was reported"
        )
    (raw_path, _sha, _size), *tables = written
    assert raw_path == rawstore.raw_path_of(settings.raw_dir, COLLECTOR_SOURCE, COLLECTOR_HOST, RUN_ID)
    sealed = json.loads(gzip.decompress(decrypt(dek(settings), raw_path.read_bytes())))
    assert raw_json_sha(base_spelling(split_case(key)[0], sealed)) == golden["raw_json_sha"]
    del sealed

    parquet = {path.relative_to(settings.sidestore_dir).parts[0]: path for path, _sha, _size in tables}
    assert sorted(parquet) == sorted(table for table, (rows, _digest) in golden["parquet"].items() if rows)
    for table, path in sorted(parquet.items()):
        assert list(sidestore_row_facts(path)) == golden["parquet"][table], table
        assert parquet_layout(path) == golden["parquet_layout"][table], table

    # no golden payload holds the command of an `ADDED_SINCE_BASE` section, so
    # the section reads `unknown`
    family = split_case(key)[0]
    base, added = without_added_sections(family, outcomes_json(manifest.sections))
    assert base == golden["sections"]
    assert added == {
        name: {"detail": "", "row_count": None, "status": "unknown"} for name in ADDED_SINCE_BASE[family]
    }
    assert outcomes_json(held_mac_statement(family, manifest.tables, written=True)) == golden["tables"]


def test_execute_writes_the_golden_artifacts_and_frees_the_payload(tmp_path, monkeypatch):
    golden = GOLDEN["cases"][CASE]
    settings = golden_settings(tmp_path)
    collector = make_collector("iosxe", settings)
    payload = WatchedPayload(case_payload(CASE))
    spelled = base_spelling("iosxe", payload)
    assert payload_sha(spelled) == golden["payload_sha"]
    watch = weakref.ref(payload)
    texts = WatchedTexts(payload)
    monkeypatch.setattr(collectors_base, "new_run_id", golden_run_id)
    written: list[Written] = []

    # the digests of the base record, taken with its declarations over the
    # payload in its spelling
    hash_as_base_record(monkeypatch, "iosxe")
    hashes = (raw_sha(collector, spelled), obs_sha(collector, spelled))
    del spelled
    manifest = coll.execute(
        collector,
        FakeSession(),
        raw=payload,
        collection_ts=SNAPSHOT_TS,
        source_name=COLLECTOR_SOURCE,
        fetch_window=FETCH_WINDOW,
        on_write=lambda path, sha, size: written.append((path, sha, size)),
    )
    del payload
    gc.collect()

    assert watch() is None, "the collector, or something the load left behind, still holds the payload"
    kept = "; ".join(texts.kept())
    assert not kept, f"the load still holds answers of the payload: {kept}"
    assert hashes == base_digests(CASE)
    assert_golden_artifacts(CASE, settings, manifest, written)


def test_devices_loaded_one_after_another_leave_nothing_behind(tmp_path):
    settings = golden_settings(tmp_path)
    # A first load pays for what lives as long as the process: imports,
    # compiled templates and template indexes. It is not a device's residue.
    coll.execute(
        make_collector("iosxe", settings),
        FakeSession(),
        raw=case_payload("iosxe/fixture/plain"),
        collection_ts=SNAPSHOT_TS,
        source_name=COLLECTOR_SOURCE,
    )
    collectors = []
    gc.collect()
    tracemalloc.start()
    try:
        start = tracemalloc.get_traced_memory()[0]
        for seed in range(3):
            collector = make_collector("iosxe", settings)
            collectors.append(collector)
            payload = iosxe_payload(**SCALES["small"], seed=seed)
            texts = WatchedTexts(payload)
            raw_sha(collector, payload)
            obs_sha(collector, payload)
            manifest = coll.execute(
                collector,
                FakeSession(),
                raw=payload,
                collection_ts=SNAPSHOT_TS,
                source_name=COLLECTOR_SOURCE,
            )
            assert manifest.tables["bgp_session_routes"].status == "complete"
            del payload, manifest
            gc.collect()
            kept = "; ".join(texts.kept())
            assert not kept, f"device {seed + 1}: the load still holds answers of the payload: {kept}"
            del texts
        gc.collect()
        current = tracemalloc.get_traced_memory()[0]
    finally:
        tracemalloc.stop()

    assert len(collectors) == 3
    assert current - start <= RESIDUE_BYTES, (
        f"{current - start:,} B still traced after three devices, {RESIDUE_BYTES:,} B allowed"
    )
