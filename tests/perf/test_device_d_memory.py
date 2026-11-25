"""Device D at a tenth of its size: the traced peak of every stage of one
device's collection against the peak model, its artifacts against the golden
values, and three devices in a row against each other.

Device D is the full-table IOS-XE edge router the collection memory model is
sized by. The tenth golden case (`iosxe/tenth/plain` in `tests/support/
synthetic_payloads.py`) has its shape at a tenth of its size: about 100k
routes, two peers whose received and accepted tables hold about 400k paths
between them, and a payload R of about 39 MB. It is synthetic; nothing in it
was captured from real infrastructure.

A device is hashed (`raw_sha` and `obs_sha`, which decide whether the fetch
is loaded) and then `execute`d: the raw store seals the payload
(`rawstore.write`) and `load_payload` normalizes it, loads the graph and
writes the side-store tables. Each stage is measured on its own, inside the
real `execute`, and held to the model:

- a hash: R + 16 MB;
- the seal, at gzip level 9: 1.7 x R;
- the load: R + 0.6 KB per RIB row (the `rib` list the parse keeps) + three
  row groups of 2.2 KB per side-store row (the rows read, their stamped
  copies and the Arrow batch) + 32 MB.

The payloads are built before tracing starts, so a traced figure is memory
above the payload, and each bound is checked against the payload's own size
plus that figure. Buffers held natively (zlib, OpenSSL, Arrow) are outside
tracemalloc, as they are outside the model.

Three devices are collected one after another, as a run loads its devices,
each through a collector of its own and every collector kept to the end.
Every device must write the golden artifacts and free its payload and every
answer in it, and the third must peak within 10% of the first.

Wall times are taken under tracemalloc.
`record_property` needs `-o junit_family=xunit1` beside `--junitxml`.
Run it with:
HST_PERF=1 pytest -m perf tests/perf/test_device_d_memory.py
"""

from __future__ import annotations

import contextlib
import functools
import gc
import os
import sys
import time
import tracemalloc
import weakref
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from tests.support.synthetic_payloads import (
    COLLECTOR_SOURCE,
    ROW_GROUP_ROWS,
    SNAPSHOT_TS,
    base_spelling,
    case_payload,
    load_golden,
    make_collector,
)
from tests.test_cisco_rib_volatility import base_digests, hash_as_base_record
from tests.test_collector_execute import FakeSession
from tests.test_device_d_small import (
    FETCH_WINDOW,
    WatchedPayload,
    WatchedTexts,
    Written,
    assert_golden_artifacts,
    golden_run_id,
    golden_settings,
)

from hst import collectors as coll
from hst.collectors import base as collectors_base
from hst.collectors.base import obs_sha, raw_sha
from hst.collectors.cli_collector import CiscoCliCollector
from hst.core import Settings, debug_capture, rawstore
from hst.core.model import RunManifest

pytestmark = [
    pytest.mark.perf,
    pytest.mark.skipif(os.environ.get("HST_PERF") != "1", reason="HST_PERF not set"),
]

KEY = "iosxe/tenth/plain"
GOLDEN = load_golden()["cases"][KEY]
DEVICES = 3
COMPRESS_LEVEL = 9

# The model's terms, in decimal units.
HASH_BYTES = 16_000_000
SEAL_FACTOR = 1.7
RIB_ROW_BYTES = 600
WRITER_ROW_BYTES = 2_200
LOAD_FIXED_BYTES = 32_000_000
RIB_ROWS = GOLDEN["parquet"]["rib"][0]

# Each measured stage's bound, as a function of the payload's size R.
BOUNDS: dict[str, Callable[[int], float]] = {
    "raw_sha": lambda r: r + HASH_BYTES,
    "obs_sha": lambda r: r + HASH_BYTES,
    "rawstore.write": lambda r: SEAL_FACTOR * r,
    "load_payload": lambda r: (
        r + RIB_ROW_BYTES * RIB_ROWS + 3 * WRITER_ROW_BYTES * ROW_GROUP_ROWS + LOAD_FIXED_BYTES
    ),
}

# The steps of `load_payload`, by their `debug_capture.step` names, measured
# as stages within it. They are recorded, not bounded.
LOAD_STEPS = ("normalize", "load", "write_side_tables")

# How much higher the last device may peak than the first.
PEAK_GROWTH = 0.10


@dataclass(frozen=True)
class _Stage:
    seconds: float
    peak: int  # the traced peak while the stage ran


@dataclass(frozen=True)
class _Device:
    payload_bytes: int
    settings: Settings
    hashes: tuple[str, str]
    manifest: RunManifest
    written: list[Written]
    stages: dict[str, _Stage]
    peak: int  # the traced peak of the whole device
    residue: int  # what stayed traced once the device was done
    freed: bool  # the payload was freed once `execute` returned and the caller dropped it
    kept: list[str]  # the payload's answers something still held once it was freed


class _Meter:
    """Wall time and traced peak of each stage of one device, and the traced
    peak of the device as a whole.

    tracemalloc keeps a single peak, which a stage resets when it starts. The
    peak reached until then is first carried into the device and into every
    stage still open, so stages nest: a step inside `load_payload` is
    measured on its own and still counts toward the load's peak.
    """

    def __init__(self) -> None:
        self.stages: dict[str, _Stage] = {}
        self.peak = 0
        self._open: dict[str, int] = {}
        tracemalloc.reset_peak()

    def _carry(self) -> None:
        peak = tracemalloc.get_traced_memory()[1]
        self.peak = max(self.peak, peak)
        for name, seen in self._open.items():
            self._open[name] = max(seen, peak)

    @contextlib.contextmanager
    def stage(self, name: str) -> Iterator[None]:
        self._carry()
        tracemalloc.reset_peak()
        self._open[name] = 0
        started = time.perf_counter()
        try:
            yield
        finally:
            seconds = time.perf_counter() - started
            self._carry()
            self.stages[name] = _Stage(seconds, self._open.pop(name))

    def run(self, name: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        with self.stage(name):
            return fn(*args, **kwargs)

    def close(self) -> int:
        self._carry()
        return self.peak


@contextlib.contextmanager
def _measured(meter: _Meter) -> Iterator[None]:
    """`execute` with its seal, its load and the load's own steps measured as
    stages, under the golden run id."""
    real_step = debug_capture.step

    @contextlib.contextmanager
    def step(name: str, **detail: Any) -> Iterator[dict[str, Any]]:
        with real_step(name, **detail) as out:
            if name not in LOAD_STEPS:
                yield out
                return
            with meter.stage(f"load_payload/{name}"):
                yield out

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(rawstore, "write", functools.partial(meter.run, "rawstore.write", rawstore.write))
        patch.setattr(
            collectors_base,
            "load_payload",
            functools.partial(meter.run, "load_payload", collectors_base.load_payload),
        )
        patch.setattr(debug_capture, "step", step)
        patch.setattr(collectors_base, "new_run_id", golden_run_id)
        yield


def _size(value: Any) -> int:
    """Bytes a payload holds: its dict, keys and values, into the nested
    outcomes mapping."""
    if isinstance(value, dict):
        return sys.getsizeof(value) + sum(sys.getsizeof(k) + _size(v) for k, v in value.items())
    return sys.getsizeof(value)


def _collect(
    collector: CiscoCliCollector, payload: WatchedPayload, meter: _Meter, written: list[Written]
) -> tuple[tuple[str, str], RunManifest]:
    """One device as a run collects it: both hashes, then `execute`."""
    with _measured(meter):
        hashes = (
            meter.run("raw_sha", raw_sha, collector, payload),
            meter.run("obs_sha", obs_sha, collector, payload),
        )
        manifest = coll.execute(
            collector,
            FakeSession(),
            raw=payload,
            collection_ts=SNAPSHOT_TS,
            source_name=COLLECTOR_SOURCE,
            fetch_window=FETCH_WINDOW,
            on_write=lambda path, sha, size: written.append((path, sha, size)),
        )
    return hashes, manifest


@pytest.fixture(scope="module")
def devices(tmp_path_factory: pytest.TempPathFactory) -> list[_Device]:
    work = tmp_path_factory.mktemp("device-d")
    # A warm-up collection loads what lives as long as the process: imports,
    # compiled templates and template indexes, the first Parquet writer.
    warm = make_collector("iosxe", golden_settings(work / "warm"))
    _collect(warm, WatchedPayload(case_payload("iosxe/small/plain")), _Meter(), [])
    del warm

    payloads = [WatchedPayload(case_payload(KEY)) for _ in range(DEVICES)]
    sizes = [_size(payload) for payload in payloads]
    watches = [WatchedTexts(payload) for payload in payloads]
    settings = [
        golden_settings(work / f"device-{number}", raw_compress_level=COMPRESS_LEVEL)
        for number in range(1, DEVICES + 1)
    ]
    collectors = [make_collector("iosxe", each) for each in settings]
    out: list[_Device] = []
    gc.collect()
    tracemalloc.start()
    try:
        for size, each, collector in zip(sizes, settings, collectors, strict=True):
            payload = payloads.pop(0)
            watch = weakref.ref(payload)
            texts = watches.pop(0)
            meter = _Meter()
            written: list[Written] = []
            hashes, manifest = _collect(collector, payload, meter, written)
            del payload
            gc.collect()
            out.append(
                _Device(
                    payload_bytes=size,
                    settings=each,
                    hashes=hashes,
                    manifest=manifest,
                    written=written,
                    stages=meter.stages,
                    peak=meter.close(),
                    residue=tracemalloc.get_traced_memory()[0],
                    freed=watch() is None,
                    kept=texts.kept(),
                )
            )
            del texts
    finally:
        tracemalloc.stop()
    return out


def _mb(value: float) -> str:
    return f"{value / 1e6:.1f} MB"


@pytest.mark.parametrize("stage", list(BOUNDS))
def test_every_stage_peaks_within_its_model(devices, stage, record_property, capsys):
    over = []
    lines = []
    for number, device in enumerate(devices, 1):
        size = device.payload_bytes
        measured = size + device.stages[stage].peak
        bound = BOUNDS[stage](size)
        record_property(f"device{number}.payload_bytes", size)
        record_property(f"device{number}.{stage}.peak_bytes", measured)
        record_property(f"device{number}.{stage}.bound_bytes", round(bound))
        record_property(f"device{number}.{stage}.seconds", round(device.stages[stage].seconds, 3))
        line = (
            f"{stage} device {number}: {_mb(measured)} ({measured / size:.2f} R, R {_mb(size)}), "
            f"bound {_mb(bound)}, {device.stages[stage].seconds:.2f} s traced"
        )
        if stage == "load_payload":
            for step in LOAD_STEPS:
                name = f"load_payload/{step}"
                sub = device.stages.get(name)
                if sub is None:  # the steps are recorded where the load takes them, not bounded
                    continue
                record_property(f"device{number}.{name}.peak_bytes", size + sub.peak)
                record_property(f"device{number}.{name}.seconds", round(sub.seconds, 3))
                line += f"; {step} {_mb(size + sub.peak)} in {sub.seconds:.2f} s"
        lines.append(line)
        if measured > bound:
            over.append(f"device {number}: {_mb(measured)} ({measured / size:.2f} R) over {_mb(bound)}")
    with capsys.disabled():
        print("\n" + "\n".join(lines))
    assert not over, f"{stage} peaks above its model: " + "; ".join(over)


def test_every_device_writes_the_golden_artifacts_and_frees_its_payload(devices, monkeypatch):
    # Each device hashed with the collector's declarations. The base record
    # holds the digests its declarations give the same payload in its
    # spelling (`hash_as_base_record`, `base_spelling`).
    collector = make_collector("iosxe", devices[0].settings)
    payload = case_payload(KEY)
    hashes = (raw_sha(collector, payload), obs_sha(collector, payload))
    hash_as_base_record(monkeypatch, "iosxe")
    spelled = base_spelling("iosxe", payload)
    golden = (raw_sha(collector, spelled), obs_sha(collector, spelled))
    del payload, spelled
    assert golden == base_digests(KEY)
    for number, device in enumerate(devices, 1):
        assert device.freed, f"device {number}: the payload is still held after execute returned"
        kept = "; ".join(device.kept)
        assert not kept, f"device {number}: the load still holds answers of the payload: {kept}"
        assert device.hashes == hashes, f"device {number}"
        assert_golden_artifacts(KEY, device.settings, device.manifest, device.written)


def test_the_third_device_peaks_within_ten_percent_of_the_first(devices, record_property, capsys):
    peaks = [device.payload_bytes + device.peak for device in devices]
    for number, (device, peak) in enumerate(zip(devices, peaks, strict=True), 1):
        record_property(f"device{number}.peak_bytes", peak)
        record_property(f"device{number}.residue_bytes", device.residue)
    with capsys.disabled():
        print(
            "\ndevice peaks: "
            + ", ".join(
                f"{_mb(peak)} (residue {device.residue / 1e3:.0f} kB)"
                for device, peak in zip(devices, peaks, strict=True)
            )
        )
    assert peaks[-1] <= (1 + PEAK_GROWTH) * peaks[0], (
        f"the third device peaks at {_mb(peaks[-1])}, the first at {_mb(peaks[0])}"
    )
