"""A fetch result the loader will skip does not carry its payload
(app/runs_exec.py `_fetch_phase_async`, its `decide`)."""

from __future__ import annotations

import gc
import weakref
from types import SimpleNamespace
from typing import Any

import pytest
from tests.app.test_runs_exec_fleet import (
    _CollWithFetch,
    _Cycle,
    _device,
    _recent,
    _Rt,
    _Rules,
    _Session,
    _settings,
    _source,
    _status,
)

from hst.app import runs_exec


class _Payload(dict):
    """A payload a weakref can watch."""


class _Threaded:
    """A device on the thread lane whose payload carries its own two hashes,
    as `_FetchingCollector` in test_runs_exec_fleet.py. `alive` maps each host
    to a weakref of the last payload it returned."""

    def __init__(self, host: str, sha: str, obs: str, alive: dict[str, weakref.ref]) -> None:
        self.host = host
        self.sha = sha
        self.obs = obs
        self.scope = f"vyos:{host}"
        self.SIDE_TABLES = ("arp",)
        self._alive = alive

    def fetch(self) -> _Payload:
        payload = _Payload(host=self.host, sha=self.sha, obs=self.obs, config="x" * 256)
        self._alive[self.host] = weakref.ref(payload)
        return payload


class _Async(_Threaded):
    """The same device on the async lane."""

    config = SimpleNamespace(transport="asyncssh")

    async def afetch(self) -> _Payload:
        return self.fetch()


class _Recording(_CollWithFetch):
    """`coll` that also records the payload each publication path was handed."""

    def __init__(self) -> None:
        super().__init__(set())
        self.handed: dict[str, Any] = {}

    def execute(
        self, collector, s, *, collection_ts, source_name, raw=None, on_write=None, fetch_window=None
    ):
        self.handed[collector.host] = raw
        return super().execute(
            collector,
            s,
            collection_ts=collection_ts,
            source_name=source_name,
            raw=raw,
            on_write=on_write,
            fetch_window=fetch_window,
        )

    def execute_observations(
        self, collector, *, raw, collection_ts, source_name=None, on_write=None, fetch_window=None
    ):
        self.handed[collector.host] = raw
        return super().execute_observations(
            collector,
            raw=raw,
            collection_ts=collection_ts,
            source_name=source_name,
            on_write=on_write,
            fetch_window=fetch_window,
        )


def _fleet(kind: type[_Threaded], alive: dict[str, weakref.ref]) -> runs_exec.PreparedSource:
    """Three devices, one per decision: `skip` matches both hashes on record,
    `obs` matches the configuration hash only, and `full` matches neither."""
    collectors = [
        kind("skip", "SHA", "OBS", alive),
        kind("obs", "SHA", "NEW-ARP", alive),
        kind("full", "OTHER", "OBS", alive),
    ]
    units = [runs_exec.PreparedDevice(_device("edge", c.host), c, None) for c in collectors]
    return runs_exec.PreparedSource(_source("edge"), units)


def _prior() -> dict[tuple[str, str], Any]:
    recent = _recent()
    return {
        ("edge", "skip"): _status("edge", "skip", "SHA", recent, obs="OBS"),
        ("edge", "obs"): _status("edge", "obs", "SHA", recent, obs="OLD-ARP"),
        ("edge", "full"): _status("edge", "full", "SHA", recent, obs="OBS"),
    }


@pytest.mark.parametrize("kind", [_Threaded, _Async], ids=["thread-lane", "async-lane"])
def test_a_skipped_result_carries_no_payload_and_the_others_carry_theirs(monkeypatch, kind):
    monkeypatch.setattr(runs_exec, "coll", _CollWithFetch(set()))
    alive: dict[str, weakref.ref] = {}
    fleet = _fleet(kind, alive)
    units = [("edge", unit) for unit in fleet.units]

    results = runs_exec._fetch_phase(_settings(), units, _prior(), True)
    by_host = {unit.device.host: results[id(unit)] for _, unit in units}

    skipped = by_host["skip"]
    assert skipped.skipped and not skipped.observations_only
    assert skipped.raw is None
    assert (skipped.sha, skipped.obs, skipped.fingerprint) == ("SHA", "OBS", "SHA")
    assert skipped.fetch_ms is not None
    assert skipped.fetch_started_ms is not None and skipped.fetch_finished_ms is not None

    observed = by_host["obs"]
    assert observed.observations_only and not observed.skipped
    assert observed.raw is not None and observed.raw["host"] == "obs"

    full = by_host["full"]
    assert not full.skipped and not full.observations_only
    assert full.raw is not None and full.raw["host"] == "full"

    # nothing else keeps the skipped payload alive either
    gc.collect()
    assert alive["skip"]() is None
    assert alive["obs"]() is not None and alive["full"]() is not None


@pytest.mark.parametrize("kind", [_Threaded, _Async], ids=["thread-lane", "async-lane"])
def test_without_the_skip_every_result_carries_its_payload(monkeypatch, kind):
    """A cold start never skips, so every result is loaded and carries its
    payload, the one whose hashes match included."""
    monkeypatch.setattr(runs_exec, "coll", _CollWithFetch(set()))
    alive: dict[str, weakref.ref] = {}
    units = [("edge", unit) for unit in _fleet(kind, alive).units]

    results = runs_exec._fetch_phase(_settings(), units, _prior(), False)

    for _, unit in units:
        fetched = results[id(unit)]
        assert not fetched.skipped and not fetched.observations_only
        assert fetched.raw is not None and fetched.raw["host"] == unit.device.host


@pytest.fixture
def cycle_rig(monkeypatch):
    cycle = _Cycle(1_000)
    coll = _Recording()
    monkeypatch.setattr(runs_exec, "cycle", cycle)
    monkeypatch.setattr(runs_exec, "coll", coll)
    monkeypatch.setattr(runs_exec, "reasoner", _Rules())
    monkeypatch.setattr(runs_exec, "rt_reasoner", _Rt())
    monkeypatch.setattr(runs_exec.dbmod, "session", lambda settings: _Session())
    return cycle, coll


@pytest.mark.parametrize("kind", [_Threaded, _Async], ids=["thread-lane", "async-lane"])
def test_the_cycle_records_a_skipped_unit_as_unchanged(monkeypatch, cycle_rig, kind):
    cycle, coll = cycle_rig
    alive: dict[str, weakref.ref] = {}
    fleet = _fleet(kind, alive)
    host_of = {id(unit): unit.device.host for unit in fleet.units}
    # which payloads the fetch window holds when the loader asks for each unit
    held_at_ask: list[tuple[str, bool, dict[str, bool]]] = []

    class _SpyBuffer(runs_exec._FetchBuffer):
        def __getitem__(self, key: int) -> runs_exec._Fetched:
            fetched = super().__getitem__(key)
            gc.collect()
            held_at_ask.append(
                (
                    host_of[key],
                    fetched.raw is None,
                    {h: ref() is not None for h, ref in sorted(alive.items())},
                )
            )
            return fetched

    monkeypatch.setattr(runs_exec, "_FetchBuffer", _SpyBuffer)
    outs: list[runs_exec.DeviceOutcome] = []

    summary, ran, _, _ = runs_exec.execute_cycle(_settings(), [fleet], {"edge"}, None, _prior(), outs)

    assert held_at_ask[0] == ("skip", True, {"full": True, "obs": True, "skip": False})
    assert [(host, no_raw) for host, no_raw, _ in held_at_ask] == [
        ("skip", True),
        ("obs", False),
        ("full", False),
    ]
    # the skip is recorded as unchanged
    assert "edge/skip: unchanged, carried" in summary
    assert cycle.scopes == {"vyos:skip": "unchanged", "vyos:obs": "unchanged"}
    assert cycle.collected == {"vyos:full"}
    assert [d.host for _, d, _ in ran] == ["skip", "obs", "full"]
    by_host = {o.host: o for o in outs}
    skipped = by_host["skip"]
    assert skipped.ok and skipped.skipped and not skipped.observations_only and not skipped.full
    assert (skipped.raw_sha, skipped.obs_sha, skipped.fingerprint) == ("SHA", "OBS", "SHA")
    assert skipped.fetch_ms is not None
    assert skipped.tables is not None and skipped.tables["arp"].status == "unchanged"
    assert cycle.meta is not None and cycle.meta["statuses"] == {"edge": "fresh"}
    # and the two other paths were handed their payloads
    assert coll.ran == ["full"] and coll.observed == ["obs"]
    assert sorted(coll.handed) == ["full", "obs"]
    assert coll.handed["obs"]["host"] == "obs" and coll.handed["full"]["host"] == "full"
