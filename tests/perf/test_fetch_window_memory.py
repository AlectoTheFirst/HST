"""The traced peak of a cycle's fetch window of large payloads, with spilling
on and off, and the peak of reading one spilled payload back.

Twenty-four async devices answer about 32 MiB each (R), with
COLLECT_MAX_CONCURRENCY=4 (C), COLLECT_THREAD_WORKERS=2 and
COLLECT_FETCH_BUFFER=64, so the whole fleet is one window. With spilling on
(COLLECT_SPILL_MB=16), each payload is sealed to a spill file once it is
hashed and the async lane admits C + 1 payloads at a time, so the window
peaks at C + 1 payloads plus the working memory of the hashes and seals, held
here to (C + 2) x 1.2 x R. With spilling off the window holds every payload, at least
20 x R. The load of a spilled payload reads it back from its file one device
at a time; for the IOS-XE tenth golden case that peak is held to 1.6 x R.

The payloads are synthetic text; nothing in them was captured from real
infrastructure. Buffers held natively (zlib, OpenSSL) are outside
tracemalloc. Opt-in, as the other perf tests are:
HST_PERF=1 pytest -m perf tests/perf/test_fetch_window_memory.py
"""

from __future__ import annotations

import functools
import gc
import os
import sys
import tracemalloc
from typing import Any

import pytest
from tests.app.test_fetch_spill import _settings, _spill_files, _unit
from tests.support.synthetic_payloads import COLLECTOR_SOURCE, case_payload, make_collector, make_settings

from hst import collectors as coll
from hst.app import runs_exec
from hst.app.crypto import dek, generate_key
from hst.core import Settings, rawstore

pytestmark = [
    pytest.mark.perf,
    pytest.mark.skipif(os.environ.get("HST_PERF") != "1", reason="HST_PERF not set"),
]

MIB = 1 << 20
DEVICES = 24
CONCURRENCY = 4
THREAD_WORKERS = 2
SPILL_MB = 16
WINDOW_FACTOR = 1.2
UNSPILLED_FLOOR = 20
READ_BACK_FACTOR = 1.6
TENTH = "iosxe/tenth/plain"

# 4096 routing-table lines, repeated into each answer of a payload.
_BLOCK = "".join(
    f"{i:>6} 10.{i % 251}.{i % 97}.0/24 via 192.0.2.{i % 13}, GigabitEthernet0/{i % 48}\n"
    for i in range(4096)
)


def _payload(host: str) -> dict[str, str]:
    """Eight answers of about 4 MiB each, the first line naming the host."""
    repeats = (4 * MIB) // len(_BLOCK)
    return {f"show command {n}": f"{host} {n}\n" + _BLOCK * repeats for n in range(8)}


def _size(value: Any) -> int:
    """Bytes a payload holds: its dict, keys and values."""
    if isinstance(value, dict):
        return sys.getsizeof(value) + sum(sys.getsizeof(k) + _size(v) for k, v in value.items())
    return sys.getsizeof(value)


@functools.cache
def _r() -> int:
    """R, the size of one device's payload."""
    return _size(_payload("r00"))


def _window_peak(tmp_path, spill_mb: int) -> tuple[int, int, dict[int, runs_exec._Fetched], Settings]:
    """(traced peak, traced memory held at the end, results, settings) of one
    window."""
    settings = _settings(
        tmp_path,
        collect_max_concurrency=CONCURRENCY,
        collect_thread_workers=THREAD_WORKERS,
        collect_fetch_buffer=64,
        collect_spill_mb=spill_mb,
    )
    units = [_unit(settings, f"r{i:02d}", _payload) for i in range(DEVICES)]
    gc.collect()
    tracemalloc.start()
    try:
        start = tracemalloc.get_traced_memory()[0]
        results = runs_exec._fetch_phase(settings, units, {}, False)
        current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return peak - start, current - start, results, settings


def test_spilling_holds_the_window_to_the_admitted_payloads(tmp_path):
    peak, held, results, _settings_used = _window_peak(tmp_path, SPILL_MB)
    r = _r()
    bound = (CONCURRENCY + 2) * WINDOW_FACTOR * r
    print(
        f"R={r:,} B  spilling on: peak {peak:,} B ({peak / r:.2f} R), held {held:,} B, bound {bound:,.0f} B"
    )

    assert all(f.spilled is not None and f.raw is None for f in results.values())
    assert peak <= bound
    for f in results.values():
        assert f.spilled is not None
        rawstore.drop_spill(f.spilled)


def test_without_spilling_the_window_holds_every_payload(tmp_path):
    peak, held, results, settings = _window_peak(tmp_path, 0)
    r = _r()
    print(f"R={r:,} B  spilling off: peak {peak:,} B ({peak / r:.2f} R), held {held:,} B")

    assert all(f.spilled is None and f.raw is not None for f in results.values())
    assert peak >= UNSPILLED_FLOOR * r
    assert not _spill_files(settings)


def test_a_spilled_tenth_case_reads_back_within_its_bound(tmp_path):
    settings = make_settings(tmp_path, hst_secret_key=generate_key())
    collector = make_collector(TENTH.split("/")[0], settings)
    payload = case_payload(TENTH)
    size = _size(payload)
    spilled = coll.spill(collector, payload, source_name=COLLECTOR_SOURCE, fetch_ts_ms=1_700_000_000_000)
    del payload
    key = dek(settings)
    gc.collect()

    tracemalloc.start()
    try:
        start = tracemalloc.get_traced_memory()[0]
        back = rawstore.read(spilled.path, key)
        peak = tracemalloc.get_traced_memory()[1] - start
    finally:
        tracemalloc.stop()
    print(f"{TENTH}: R={size:,} B  read-back peak {peak:,} B ({peak / size:.2f} R)")

    assert _size(back) > 0
    assert peak <= READ_BACK_FACTOR * size
