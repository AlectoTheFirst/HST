"""An observation-only publication is judged by the rule a full load is judged
by (app/runs_exec.py `_collect_sources` and `build_device_run`).

The path writes the payload's raw file and side tables and leaves the graph to
the carry. What it records about the device is what a full load of the same
payload records: the payload's sections, a degrading authoritative section
failing the device and a degrading optional one making it partial, and an
exception failing it. A device that fails on this path carries as a failed
unit does.

The cycle is exercised with the stubs of test_runs_exec_fleet.py, and the
device run with the real raw store, side store and manifests of
test_device_run.py.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from tests.app.test_device_run import _Cycle as _DeviceRunCycle
from tests.app.test_device_run import _DevCollector, _HostCfg
from tests.app.test_device_run import _Session as _DeviceRunSession
from tests.app.test_runs_exec_fleet import (
    NEW,
    NOW,
    PREV,
    _CollWithFetch,
    _Cycle,
    _fetch_fleet,
    _FetchingCollector,
    _recent,
    _Rt,
    _Rules,
    _Session,
    _settings,
    _status,
)

from hst import collectors as coll
from hst.app import runs_exec
from hst.app.crypto import generate_key
from hst.app.store import Device, Source
from hst.collectors import base as collectors_base
from hst.core import Settings, rawstore
from hst.core import manifest as manifestmod
from hst.core.model import SectionOutcome

MALFORMED = SectionOutcome(status="malformed", detail="the answer is not the table the command promises")


class _Authoritative(_FetchingCollector):
    """A device whose RIB section it cannot be read without."""

    AUTHORITATIVE_SECTIONS = ("rib",)


class _Judged(_CollWithFetch):
    """`coll` whose observation-only publication reports `sections` beside the
    tables it writes, or raises `raises`."""

    def __init__(self, sections: dict[str, SectionOutcome], raises: Exception | None = None) -> None:
        super().__init__(set())
        self.sections = sections
        self.raises = raises

    def execute_observations(
        self, collector, *, raw, collection_ts, source_name=None, on_write=None, fetch_window=None
    ):
        if self.raises is not None:
            raise self.raises
        manifest = super().execute_observations(
            collector,
            raw=raw,
            collection_ts=collection_ts,
            source_name=source_name,
            on_write=on_write,
            fetch_window=fetch_window,
        )
        manifest.sections = dict(self.sections)
        return manifest


@pytest.fixture
def cycle(monkeypatch):
    """One cycle over r1, whose configuration hash matches the run on record
    and whose observation hash does not, published through `judged`."""

    def run(judged: _Judged) -> tuple[_Cycle, str, list[Any], runs_exec.DeviceOutcome]:
        stub = _Cycle(PREV)
        monkeypatch.setattr(runs_exec, "cycle", stub)
        monkeypatch.setattr(runs_exec, "coll", judged)
        monkeypatch.setattr(runs_exec, "reasoner", _Rules())
        monkeypatch.setattr(runs_exec, "rt_reasoner", _Rt())
        monkeypatch.setattr(runs_exec.dbmod, "session", lambda settings: _Session())
        prior = {("edge", "r1"): _status("edge", "r1", "SHA", _recent(), obs="OLD-ARP")}
        fleet = _fetch_fleet("edge", _Authoritative("r1", "SHA", "NEW-ARP"))
        outs: list[runs_exec.DeviceOutcome] = []
        summary, ran, _, _ = runs_exec.execute_cycle(_settings(), [fleet], {"edge"}, None, prior, outs)
        (out,) = outs
        return stub, summary, ran, out

    return run


def test_a_failed_authoritative_section_fails_the_device(cycle):
    judged = _Judged({"rib": MALFORMED})

    stub, summary, ran, out = cycle(judged)

    assert judged.ran == [] and judged.observed == ["r1"]
    assert not out.ok and out.observations_only and not out.full
    assert out.error == "sections not collected: rib=malformed"
    assert out.sections == {"rib": MALFORMED} and out.authoritative == ("rib",)
    assert out.tables["arp"].row_count == 3
    assert runs_exec._device_outcome(out, "failed") == "failed"
    assert stub.scopes == {"vyos:r1": "failed"}
    assert stub.meta is not None and stub.meta["statuses"] == {"edge": "failed"}
    assert "edge/r1: configuration unchanged, observations written: arp=3 · failed: rib=malformed" in summary
    assert ran == []


def test_a_degraded_optional_section_makes_the_device_partial(cycle):
    stub, summary, ran, out = cycle(_Judged({"arp": MALFORMED}))

    assert out.ok and out.observations_only
    assert out.completeness == "partial"
    assert runs_exec._device_outcome(out, "partial") == "partial"
    assert stub.meta is not None and stub.meta["statuses"] == {"edge": "partial"}
    assert stub.meta["degraded"] is True
    assert stub.scopes == {"vyos:r1": "unchanged"}
    assert "edge/r1: configuration unchanged, observations written: arp=3 · partial: arp=malformed" in summary
    assert [d.host for _, d, _ in ran] == ["r1"]


def test_an_exception_fails_the_device(cycle):
    stub, summary, ran, out = cycle(_Judged({}, raises=KeyError("x")))

    assert not out.ok and out.error == "KeyError: 'x'"
    assert stub.scopes == {"vyos:r1": "failed"}
    assert stub.meta is not None and stub.meta["statuses"] == {"edge": "failed"}
    assert "edge/r1: configuration unchanged; observations not written: KeyError: 'x'" in summary
    assert ran == []


# --- the device run -------------------------------------------------------------------------

RUN_ID = "1700000000000-cccccccc"


class _Sectioned(_DevCollector):
    """`_DevCollector` whose payload states its own sections, read apart from
    normalizing as the Cisco families read theirs, and whose RIB section it
    cannot be read without."""

    AUTHORITATIVE_SECTIONS = ("rib",)

    def sections(self, raw: Any) -> dict[str, SectionOutcome]:
        return {name: SectionOutcome.model_validate(entry) for name, entry in raw["sections"].items()}

    def normalize(self, raw: Any) -> Any:
        batch = super().normalize(raw)
        batch.sections = self.sections(raw)
        return batch


def _payload(sections: dict[str, SectionOutcome]) -> dict[str, Any]:
    return {
        "host": "r1",
        "arp": [["10.0.0.9", "aa:bb:cc:dd:ee:ff"]],
        "sections": {name: outcome.model_dump() for name, outcome in sections.items()},
    }


def _device_run(
    monkeypatch: pytest.MonkeyPatch, data_dir: Path, payload: dict[str, Any], kind: str
) -> tuple[Settings, _DeviceRunCycle, manifestmod.DeviceEntry]:
    """Park `payload` for r1 as `kind` under a fixed run id, fold it into a
    device run, and return r1's manifest entry."""
    settings = Settings(_env_file=None, hst_data_dir=data_dir, hst_secret_key=generate_key())
    stub = _DeviceRunCycle(PREV)
    monkeypatch.setattr(runs_exec, "cycle", stub)
    monkeypatch.setattr(runs_exec, "reasoner", _Rules())
    monkeypatch.setattr(runs_exec, "rt_reasoner", _Rt())
    monkeypatch.setattr(runs_exec.dbmod, "session", lambda s: _DeviceRunSession())
    monkeypatch.setattr(collectors_base, "new_run_id", lambda fetch_ts_ms=None: RUN_ID)
    collector = _Sectioned(_HostCfg(host="r1", source_name="edge"), settings)
    unit = runs_exec.PreparedDevice(Device(1, "edge", "r1", None, True, "", NOW, NOW), collector, None)
    source = runs_exec.PreparedSource(Source(1, "edge", "vyos", {}, b"", True, NOW, NOW), [unit])
    coll.park(collector, payload, source_name="edge", kind=kind)

    _detail, _ran, key, _ = runs_exec.build_device_run(settings, [source])

    assert key == NEW
    (entry,) = [d for d in manifestmod.read(settings, NEW).devices if d.host == "r1"]
    return settings, stub, entry


def _judged(entry: manifestmod.DeviceEntry) -> dict[str, Any]:
    return entry.model_dump(mode="json", include={"outcome", "error", "sections", "tables"})


def test_a_device_run_judges_both_kinds_of_one_payload_alike(monkeypatch, tmp_path):
    payload = _payload({"rib": MALFORMED, "arp": SectionOutcome(status="ok", row_count=1)})

    full = _device_run(monkeypatch, tmp_path / "full", payload, rawstore.KIND_FULL)
    observed = _device_run(monkeypatch, tmp_path / "observed", payload, rawstore.KIND_OBSERVATION)

    assert _judged(observed[2]) == _judged(full[2])
    assert observed[2].outcome == "failed"
    assert observed[2].error == "sections not collected: rib=malformed"
    for settings, stub, _entry in (full, observed):
        assert rawstore.parked(settings.raw_dir) == []
        assert stub.scopes == {"vyos:r1": "failed"}


def test_a_device_run_records_the_sections_of_an_observation_payload(monkeypatch, tmp_path):
    sections = {
        "rib": SectionOutcome(status="ok", row_count=4),
        "arp": SectionOutcome(status="ok", row_count=1),
    }

    _, stub, entry = _device_run(monkeypatch, tmp_path, _payload(sections), rawstore.KIND_OBSERVATION)

    assert entry.outcome == "unchanged"
    assert entry.sections == sections
    assert stub.scopes == {"vyos:r1": "unchanged"}
