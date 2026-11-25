"""Device groups in the run model: partial fleets carry, a press builds its own
run, pins land per device."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import pytest
from tests.app.fakes import FakeStore

from hst.app import runs_exec
from hst.app.store import Device, DeviceSpec, Source
from hst.core import Settings
from hst.core.model import RunManifest, SectionOutcome, TableOutcome

PREV, NEW = 1_000, 2_000
NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)


def _source(name: str, type_: str = "vyos") -> Source:
    return Source(1, name, type_, {}, b"", True, NOW, NOW)


def _device(source: str, host: str) -> Device:
    return Device(1, source, host, None, True, "", NOW, NOW)


class _EmptyGraphTransaction:
    def run(self, query: str, **params: Any) -> list[dict[str, Any]]:
        return []


class _Session:
    def __enter__(self) -> _Session:
        return self

    def __exit__(self, *a: Any) -> bool:
        return False

    def execute_read(self, work):
        return work(_EmptyGraphTransaction())


class _Cycle:
    """Records what the run builders decide: the carry set and the meta node's
    statuses, kind and parent."""

    def __init__(self, pointer: int | None) -> None:
        self.pointer = pointer
        self.carried: tuple[str, ...] | None = None
        self.scopes: dict[str, str] = {}
        self.collected: set[str] = set()
        self.unasked: tuple[str, ...] = ()
        self.section_labels: dict[str, list[str]] = {}
        self.meta: dict[str, Any] | None = None
        self.steps: list[str] = []

    def current_ts(self, s: Any) -> int | None:
        return self.pointer

    def new_collection_ts(self) -> int:
        return NEW

    def carry_forward(
        self,
        s: Any,
        prev: int,
        cts: int,
        sources: list[str],
        *,
        scopes: dict[str, str] | None = None,
        collected: Any = (),
        unasked: Any = None,
        section_labels: Any = None,
    ) -> dict[str, int]:
        self.carried = tuple(sources)
        self.scopes = dict(scopes or {})
        self.collected = set(collected)
        self.unasked = tuple(sources if unasked is None else unasked)
        self.section_labels = {k: list(v) for k, v in (section_labels or {}).items()}
        return {"nodes": 1, "rels": 0}

    def cycle_counts(self, s: Any, cts: int) -> dict[str, int]:
        return {"nodes": 7, "rels": 9}

    def set_pointer(self, s: Any, cts: int) -> None:
        self.steps.append("set_pointer")
        self.pointer = cts

    def apply_site_assignments(self, s: Any, assigned: Any, cts: int | None = None) -> int:
        self.steps.append("apply_site_assignments")
        return 0

    def write_cycle_meta(self, s: Any, cts: int, **kw: Any) -> None:
        self.steps.append("write_cycle_meta")
        self.meta = kw


class _Coll:
    """`coll.execute` that fails for the hosts named in `bad`."""

    def __init__(self, bad: set[str]) -> None:
        self.bad = bad
        self.ran: list[str] = []

    def execute(
        self, collector: Any, s: Any, *, collection_ts: int, source_name: str, on_write: Any = None
    ) -> RunManifest:
        host = collector.host
        if host in self.bad:
            raise RuntimeError(f"{host} unreachable")
        self.ran.append(host)
        return RunManifest(run_id=f"{source_name}-{host}-{collection_ts}", source=source_name, scope=host)


class _FakeCollector:
    def __init__(self, host: str) -> None:
        self.host = host
        self.scope = f"vyos:{host}"


class _Rules:
    def run(self, s: Any, ts_ms: int | None = None, collection_ts: int | None = None) -> list[dict]:
        return []


class _Rt:
    def execute(self, session: Any, settings: Settings, collection_ts: int | None = None) -> RunManifest:
        return RunManifest(run_id="rt-i", source="reasoner", scope="rt-imports")

    def execute_rt_domains(
        self, session: Any, settings: Settings, collection_ts: int | None = None
    ) -> RunManifest:
        return RunManifest(run_id="rt-d", source="reasoner", scope="rt-domains")

    def execute_link_speed(
        self, session: Any, settings: Settings, collection_ts: int | None = None
    ) -> RunManifest:
        return RunManifest(run_id="ls", source="reasoner", scope="link-speed")


@pytest.fixture
def rig(monkeypatch):
    def build(*, pointer: int | None = PREV, bad: set[str] | None = None) -> tuple[_Cycle, _Coll]:
        cycle = _Cycle(pointer)
        coll = _Coll(bad or set())
        monkeypatch.setattr(runs_exec, "cycle", cycle)
        monkeypatch.setattr(runs_exec, "coll", coll)
        monkeypatch.setattr(runs_exec, "reasoner", _Rules())
        monkeypatch.setattr(runs_exec, "rt_reasoner", _Rt())
        monkeypatch.setattr(runs_exec.dbmod, "session", lambda settings: _Session())
        return cycle, coll

    return build


def _fleet(name: str, *hosts: str) -> runs_exec.PreparedSource:
    units = [runs_exec.PreparedDevice(_device(name, h), _FakeCollector(h), None) for h in hosts]
    return runs_exec.PreparedSource(_source(name), units)


def _settings() -> Settings:
    return Settings(_env_file=None, hst_secret_key="fleet-test-only-archive-key-32-bytes-minimum")


# --- section outcomes: a device that connected and loaded can be short --------------


class _SectionColl(_Coll):
    """`coll.execute` whose loads report per-section outcomes, keyed by host."""

    def __init__(self, sections: dict[str, dict[str, SectionOutcome]]) -> None:
        super().__init__(set())
        self.sections = sections

    def execute(self, collector, s, *, collection_ts, source_name, on_write=None):
        manifest = super().execute(
            collector, s, collection_ts=collection_ts, source_name=source_name, on_write=on_write
        )
        manifest.sections = self.sections.get(collector.host, {})
        return manifest


class _SectionCollector(_FakeCollector):
    AUTHORITATIVE_SECTIONS = ("rib",)
    SECTION_LABELS = {"nat": ("NatRule",), "arp": ()}


def _section_fleet(name: str, *hosts: str) -> runs_exec.PreparedSource:
    units = [runs_exec.PreparedDevice(_device(name, h), _SectionCollector(h), None) for h in hosts]
    return runs_exec.PreparedSource(_source(name), units)


def _run_with_sections(monkeypatch, sections):
    cycle = _Cycle(PREV)
    coll = _SectionColl(sections)
    monkeypatch.setattr(runs_exec, "cycle", cycle)
    monkeypatch.setattr(runs_exec, "coll", coll)
    monkeypatch.setattr(runs_exec, "reasoner", _Rules())
    monkeypatch.setattr(runs_exec, "rt_reasoner", _Rt())
    monkeypatch.setattr(runs_exec.dbmod, "session", lambda settings: _Session())
    outcomes: list[runs_exec.DeviceOutcome] = []
    runs_exec.execute_cycle(_settings(), [_section_fleet("edge", "r1")], {"edge"}, outcomes=outcomes)
    (outcome,) = outcomes
    return cycle, outcome


@pytest.mark.parametrize("status", ["failed", "unauthorized", "malformed"])
def test_any_degrading_authoritative_section_fails_the_device(monkeypatch, status):
    cycle, outcome = _run_with_sections(
        monkeypatch, {"r1": {"rib": SectionOutcome(status=status, detail="exited 1")}}
    )
    assert runs_exec._device_outcome(outcome, "failed") == "failed"
    assert outcome.ok is False and f"rib={status}" in outcome.error
    assert cycle.meta["statuses"] == {"edge": "failed"}


def test_a_failed_optional_section_reads_partial_and_degrades_the_run(monkeypatch):
    cycle, outcome = _run_with_sections(
        monkeypatch,
        {"r1": {"rib": SectionOutcome(status="ok"), "arp": SectionOutcome(status="failed")}},
    )
    assert runs_exec._device_outcome(outcome, "partial") == "partial"
    assert outcome.ok is True
    assert cycle.meta["statuses"] == {"edge": "partial"}
    assert cycle.meta["degraded"] is True


def test_an_unsupported_optional_section_reads_collected(monkeypatch):
    cycle, outcome = _run_with_sections(
        monkeypatch,
        {
            "r1": {
                "rib": SectionOutcome(status="ok"),
                "arp": SectionOutcome(status="unsupported"),
                "mac_table": SectionOutcome(status="empty", row_count=0),
            }
        },
    )
    assert runs_exec._device_outcome(outcome, "fresh") == "collected"
    assert cycle.meta["statuses"] == {"edge": "fresh"}
    assert cycle.meta["degraded"] is False


def test_a_payload_with_no_recorded_outcomes_is_not_a_degradation(monkeypatch):
    cycle, outcome = _run_with_sections(
        monkeypatch, {"r1": {"rib": SectionOutcome(), "arp": SectionOutcome()}}
    )
    assert runs_exec._device_outcome(outcome, "fresh") == "collected"
    assert cycle.meta["statuses"] == {"edge": "fresh"}


# --- table outcomes: the side store can lose a table a landed load wrote ------


class _TableColl(_Coll):
    """`coll.execute` whose loads report per-table side-store outcomes."""

    def __init__(self, tables: dict[str, dict[str, TableOutcome]]) -> None:
        super().__init__(set())
        self.tables = tables

    def execute(self, collector, s, *, collection_ts, source_name, on_write=None):
        manifest = super().execute(
            collector, s, collection_ts=collection_ts, source_name=source_name, on_write=on_write
        )
        manifest.tables = self.tables.get(collector.host, {})
        return manifest


def _run_with_tables(monkeypatch, tables):
    cycle = _Cycle(PREV)
    monkeypatch.setattr(runs_exec, "cycle", cycle)
    monkeypatch.setattr(runs_exec, "coll", _TableColl(tables))
    monkeypatch.setattr(runs_exec, "reasoner", _Rules())
    monkeypatch.setattr(runs_exec, "rt_reasoner", _Rt())
    monkeypatch.setattr(runs_exec.dbmod, "session", lambda settings: _Session())
    outcomes: list[runs_exec.DeviceOutcome] = []
    runs_exec.execute_cycle(_settings(), [_fleet("edge", "r1")], {"edge"}, outcomes=outcomes)
    (outcome,) = outcomes
    return cycle, outcome


def test_a_failed_side_store_write_degrades_the_run_and_partials_the_device(monkeypatch):
    cycle, outcome = _run_with_tables(
        monkeypatch,
        {
            "r1": {
                "rib": TableOutcome(status="failed", detail="PermissionError: read-only", row_count=4),
                "arp": TableOutcome(status="complete", row_count=2, path="sidestore/arp/edge/r1/x.parquet"),
            }
        },
    )
    assert runs_exec._device_outcome(outcome, "partial") == "partial"
    assert outcome.ok is True and outcome.error == ""
    assert cycle.meta["statuses"] == {"edge": "partial"}
    assert cycle.meta["degraded"] is True


def test_a_table_the_device_had_no_rows_in_is_not_a_degradation(monkeypatch):
    """A zero-row table writes no file and is an answer, not a gap: the device
    was read, the table was empty, and the run is whole."""
    cycle, outcome = _run_with_tables(
        monkeypatch,
        {
            "r1": {
                "rib": TableOutcome(status="complete", row_count=9, path="sidestore/rib/edge/r1/x.parquet"),
                "mac": TableOutcome(status="complete-empty", row_count=0),
            }
        },
    )
    assert runs_exec._device_outcome(outcome, "fresh") == "collected"
    assert cycle.meta["statuses"] == {"edge": "fresh"}
    assert cycle.meta["degraded"] is False


def test_a_partly_failed_group_reads_partial_and_joins_the_carry_set(rig):
    cycle, coll = rig(bad={"r2"})
    summary, ran, _, status = runs_exec.execute_cycle(
        _settings(), [_fleet("edge", "r1", "r2", "r3")], {"edge"}
    )
    assert status == "ok"
    assert coll.ran == ["r1", "r3"]
    assert cycle.carried == ("edge", "vyos")
    assert cycle.scopes == {"vyos:r2": "failed"}
    assert cycle.collected == {"vyos:r1", "vyos:r3"}
    assert cycle.meta["statuses"] == {"edge": "partial"}
    assert cycle.meta["degraded"] is True
    assert [(row.name, d.host) for row, d, _ in ran] == [("edge", "r1"), ("edge", "r3")]
    assert "r2 unreachable" in summary


def test_a_source_this_cycle_did_not_press_carries_every_device_as_not_run(rig):
    """A source outside the fresh set was never asked, so each of its devices is
    a scope this run holds no observation of and every one of them carries."""
    cycle, _ = rig()
    runs_exec.execute_cycle(_settings(), [_fleet("edge", "r1"), _fleet("core", "r9")], {"edge"})

    assert cycle.scopes == {"vyos:r9": "not-run"}
    assert cycle.collected == {"vyos:r1"}


def test_a_whole_group_failing_reads_failed_and_fails_the_run(rig):
    cycle, coll = rig(bad={"r1", "r2"})
    _, ran, key, status = runs_exec.execute_cycle(_settings(), [_fleet("edge", "r1", "r2")], {"edge"})
    assert coll.ran == []
    assert ran == []
    assert cycle.meta["statuses"] == {"edge": "failed"}
    assert cycle.carried == ("edge", "vyos")
    assert (key, status) == (NEW, "error")


def test_a_cycle_in_which_every_source_fails_fails_the_run(rig):
    cycle, _ = rig(bad={"r1", "r9"})
    unprepared = runs_exec.PreparedSource(_source("ctrl"), [], error="no credential")
    _, _, key, status = runs_exec.execute_cycle(
        _settings(),
        [_fleet("edge", "r1"), _fleet("core", "r9"), unprepared],
        {"edge", "core", "ctrl"},
    )
    assert cycle.meta["statuses"] == {"edge": "failed", "core": "failed", "ctrl": "failed"}
    assert (key, status) == (NEW, "error")


def test_a_cycle_with_one_collected_source_beside_failed_ones_is_ok(rig):
    cycle, _ = rig(bad={"r9"})
    _, _, _, status = runs_exec.execute_cycle(
        _settings(), [_fleet("edge", "r1"), _fleet("core", "r9")], {"edge", "core"}
    )
    assert cycle.meta["statuses"] == {"edge": "fresh", "core": "failed"}
    assert status == "ok"


def test_a_whole_fleet_collecting_reads_fresh_and_carries_nothing(rig):
    cycle, coll = rig()
    runs_exec.execute_cycle(_settings(), [_fleet("edge", "r1", "r2")], {"edge"})
    assert coll.ran == ["r1", "r2"]
    assert cycle.carried is None
    assert cycle.meta["statuses"] == {"edge": "fresh"}
    assert cycle.meta["degraded"] is False


class _CollidingColl(_Coll):
    """`coll.execute` whose second device collides with the first on a uid the
    run already holds under another anchor (core/loader.py
    `_check_cycle_anchors`)."""

    def execute(self, collector: Any, s: Any, **kw: Any) -> RunManifest:
        from hst.core.labels import CycleIdentityCollision

        if collector.host in self.bad:
            raise CycleIdentityCollision(
                "uid 'ip:vrf-dev-a-b-c:10.0.0.1' was written in this run with anchor='vrf:dev:a-b:c' "
                "and is declared again with anchor='vrf:dev:a:b-c': one uid cannot name two objects"
            )
        return super().execute(collector, s, **kw)


def test_a_uid_folding_two_devices_together_fails_the_run_not_the_device(rig, monkeypatch):
    from hst.core.labels import CycleIdentityCollision

    cycle, _ = rig()
    monkeypatch.setattr(runs_exec, "coll", _CollidingColl({"r2"}))
    with pytest.raises(CycleIdentityCollision, match=r"edge/r2: uid 'ip:vrf-dev-a-b-c:10\.0\.0\.1'"):
        runs_exec.execute_cycle(_settings(), [_fleet("edge", "r1", "r2", "r3")], {"edge"})
    assert cycle.carried is None and cycle.meta is None
    assert cycle.steps == [] and cycle.pointer == PREV


def test_a_device_that_cannot_even_build_fails_only_itself(rig):
    cycle, _ = rig()
    fleet = _fleet("edge", "r1")
    fleet.units.append(runs_exec.PreparedDevice(_device("edge", "r2"), None, "bad override"))
    _, ran, _, _ = runs_exec.execute_cycle(_settings(), [fleet], {"edge"})
    assert cycle.meta["statuses"] == {"edge": "partial"}
    assert [(d.host) for _, d, _ in ran] == ["r1"]


def test_a_whole_fleet_refresh_publishes_a_new_run(rig):
    cycle, coll = rig()
    summary, _, key, _ = runs_exec.execute_refresh(_settings(), [_fleet("edge", "r1", "r2")], "edge")
    assert coll.ran == ["r1", "r2"]
    assert key == NEW and cycle.pointer == NEW
    assert cycle.meta["kind"] == "refresh"
    assert cycle.meta["parent"] == PREV
    assert cycle.meta["statuses"] == {"edge": "fresh"}
    assert summary.startswith(f"refresh edge {NEW}:")


def test_a_partly_failed_refresh_reads_partial_and_carries_the_failed_device(rig):
    cycle, _ = rig(bad={"r2"})
    summary, ran, _, _ = runs_exec.execute_refresh(_settings(), [_fleet("edge", "r1", "r2")], "edge")
    assert cycle.meta["statuses"] == {"edge": "partial"}
    assert cycle.carried == ("edge", "vyos")
    assert "r2 unreachable" in summary
    assert [d.host for _, d, _ in ran] == ["r1"]


def test_a_refresh_where_every_device_fails_fails_the_run(rig):
    rig(bad={"r1", "r2"})
    with pytest.raises(RuntimeError, match="unreachable"):
        runs_exec.execute_refresh(_settings(), [_fleet("edge", "r1", "r2")], "edge")


async def test_pin_lands_on_the_device_row_and_the_bastion_pin_on_the_group():
    store = FakeStore()
    await store.create_source("edge", "vyos", {"jump_host": {"host": "b", "auth": {}}}, b"")
    await store.replace_devices("edge", [DeviceSpec("r1")])
    row = await store.get_source("edge")
    (device,) = await store.list_devices("edge")

    class _C:
        observed_host_key = "ssh-ed25519 DEV"
        observed_jump_key = "ssh-ed25519 JUMP"

    await runs_exec.pin_host_key(store, row, _C(), device)
    (pinned,) = await store.list_devices("edge")
    assert pinned.host_key == "ssh-ed25519 DEV"
    fresh = await store.get_source("edge")
    assert fresh.config["jump_host"]["host_key"] == "ssh-ed25519 JUMP"
    # the device key never lands on the group config
    assert "host_key" not in fresh.config or not fresh.config.get("host_key")


# --- the concurrent fetch path with change detection -------------------------------

from hst.app.store import DeviceStatus  # noqa: E402


class _FetchingCollector:
    """A collector whose fetch returns a payload carrying its own 'hash'."""

    def __init__(self, host: str, sha: str = "SHA", obs: str = "OBS") -> None:
        self.host = host
        self.sha = sha
        self.obs = obs
        self.scope = f"vyos:{host}"
        self.SIDE_TABLES = ("arp",)

    def fetch(self):
        return {"host": self.host, "sha": self.sha, "obs": self.obs}


class _CollWithFetch(_Coll):
    def __init__(self, bad: set[str]) -> None:
        super().__init__(bad)
        self.observed: list[str] = []
        self.accumulated: list[bool] = []

    def raw_sha(self, collector, raw):
        return raw["sha"]

    def obs_sha(self, collector, raw):
        return raw["obs"]

    def execute(
        self, collector, s, *, collection_ts, source_name, raw=None, on_write=None, fetch_window=None
    ):
        assert raw is not None, "the concurrent path must hand the pre-fetched payload in"
        return super().execute(collector, s, collection_ts=collection_ts, source_name=source_name)

    def execute_observations(
        self, collector, *, raw, collection_ts, source_name=None, on_write=None, fetch_window=None
    ):
        self.observed.append(collector.host)
        self.accumulated.append(on_write is not None)
        return RunManifest(
            run_id=f"{source_name}-{collector.host}-obs",
            source=str(source_name),
            scope=collector.scope,
            tables={"arp": TableOutcome(status="complete", row_count=3, path="arp.parquet")},
        )


@pytest.fixture
def rig2(monkeypatch):
    def build(*, pointer: int | None = PREV) -> tuple[_Cycle, _CollWithFetch]:
        cycle = _Cycle(pointer)
        coll = _CollWithFetch(set())
        monkeypatch.setattr(runs_exec, "cycle", cycle)
        monkeypatch.setattr(runs_exec, "coll", coll)
        monkeypatch.setattr(runs_exec, "reasoner", _Rules())
        monkeypatch.setattr(runs_exec, "rt_reasoner", _Rt())
        monkeypatch.setattr(runs_exec.dbmod, "session", lambda settings: _Session())
        return cycle, coll

    return build


def _fetch_fleet(name: str, *collectors: _FetchingCollector) -> runs_exec.PreparedSource:
    units = [runs_exec.PreparedDevice(_device(name, c.host), c, None) for c in collectors]
    return runs_exec.PreparedSource(_source(name), units)


def _status(source: str, host: str, sha: str, full_at: datetime | None, obs: str = "OBS") -> DeviceStatus:
    return DeviceStatus(
        id=1,
        source=source,
        host=host,
        last_obs_sha=obs,
        last_raw_sha=sha,
        last_attempt_at=full_at,
        last_success_at=full_at,
        last_full_at=full_at,
        consecutive_failures=0,
        last_error="",
        fetch_ms=None,
        normalize_ms=None,
        load_ms=None,
        updated_at=full_at or NOW,
    )


def _recent() -> datetime:
    return datetime.now(UTC)


def test_an_unchanged_device_skips_its_load_and_is_carried(rig2):
    cycle, coll = rig2()
    prior = {("edge", "r1"): _status("edge", "r1", "SHA", _recent())}
    outs: list[runs_exec.DeviceOutcome] = []
    fleet = _fetch_fleet("edge", _FetchingCollector("r1", "SHA"), _FetchingCollector("r2", "OTHER"))
    summary, ran, _, _ = runs_exec.execute_cycle(_settings(), [fleet], {"edge"}, None, prior, outs)

    assert coll.ran == ["r2"]  # r2 loaded; r1 never reached coll.execute
    assert "edge/r1: unchanged, carried" in summary
    assert cycle.meta["statuses"] == {"edge": "fresh"}
    assert cycle.meta["degraded"] is False
    assert cycle.carried == ("edge", "vyos")
    # both devices connected, so both pin
    assert [d.host for _, d, _ in ran] == ["r1", "r2"]
    by_host = {o.host: o for o in outs}
    assert by_host["r1"].ok and by_host["r1"].skipped and by_host["r1"].raw_sha == "SHA"
    assert by_host["r2"].ok and by_host["r2"].full and not by_host["r2"].skipped


def test_an_unchanged_device_carries_under_its_own_reason(rig2):
    cycle, _ = rig2()
    prior = {("edge", "r1"): _status("edge", "r1", "SHA", _recent())}
    fleet = _fetch_fleet("edge", _FetchingCollector("r1", "SHA"), _FetchingCollector("r2", "OTHER"))
    runs_exec.execute_cycle(_settings(), [fleet], {"edge"}, None, prior, [])

    assert cycle.scopes == {"vyos:r1": "unchanged"}
    assert cycle.collected == {"vyos:r2"}


def test_no_skip_on_a_cold_start(rig2):
    cycle, coll = rig2(pointer=None)
    prior = {("edge", "r1"): _status("edge", "r1", "SHA", _recent())}
    fleet = _fetch_fleet("edge", _FetchingCollector("r1", "SHA"))
    runs_exec.execute_cycle(_settings(), [fleet], {"edge"}, None, prior, [])
    assert coll.ran == ["r1"]
    assert cycle.carried is None


def test_a_stale_full_forces_the_load_despite_a_matching_hash(rig2):
    cycle, coll = rig2()
    old = datetime(2026, 8, 27, 0, 0, tzinfo=UTC)  # far beyond collect_full_interval_s
    prior = {("edge", "r1"): _status("edge", "r1", "SHA", old)}
    outs: list[runs_exec.DeviceOutcome] = []
    runs_exec.execute_cycle(
        _settings(), [_fetch_fleet("edge", _FetchingCollector("r1", "SHA"))], {"edge"}, None, prior, outs
    )
    assert coll.ran == ["r1"]
    assert outs[0].full and not outs[0].skipped
    assert cycle.carried is None


def test_only_arp_data_changing_publishes_side_tables_without_a_graph_rewrite(rig2):
    cycle, coll = rig2()
    prior = {("edge", "r1"): _status("edge", "r1", "SHA", _recent(), obs="OLD-ARP")}
    outs: list[runs_exec.DeviceOutcome] = []
    fleet = _fetch_fleet("edge", _FetchingCollector("r1", "SHA", "NEW-ARP"))
    summary, ran, _, _ = runs_exec.execute_cycle(_settings(), [fleet], {"edge"}, None, prior, outs)

    assert coll.ran == []
    assert coll.observed == ["r1"]
    # the file it writes is reported to the run's manifest accumulator
    assert coll.accumulated == [True]
    assert "observations written: arp=3" in summary
    assert cycle.scopes == {"vyos:r1": "unchanged"}
    assert cycle.carried == ("edge", "vyos")
    # a success, not a degradation
    assert cycle.meta["statuses"] == {"edge": "fresh"}
    assert cycle.meta["degraded"] is False
    assert [d.host for _, d, _ in ran] == ["r1"]
    (out,) = outs
    assert out.ok and out.observations_only and not out.skipped and not out.full
    assert out.obs_sha == "NEW-ARP" and out.raw_sha == "SHA"
    assert out.tables["arp"].row_count == 3


def test_matching_observations_skip_everything(rig2):
    cycle, coll = rig2()
    prior = {("edge", "r1"): _status("edge", "r1", "SHA", _recent(), obs="SAME-ARP")}
    outs: list[runs_exec.DeviceOutcome] = []
    fleet = _fetch_fleet("edge", _FetchingCollector("r1", "SHA", "SAME-ARP"))
    runs_exec.execute_cycle(_settings(), [fleet], {"edge"}, None, prior, outs)

    assert coll.ran == [] and coll.observed == []
    assert cycle.scopes == {"vyos:r1": "unchanged"}
    (out,) = outs
    assert out.skipped and not out.observations_only
    assert out.tables["arp"].status == "unchanged"


def test_a_row_with_no_recorded_observation_hash_skips(rig2):
    cycle, coll = rig2()
    prior = {("edge", "r1"): _status("edge", "r1", "SHA", _recent(), obs="")}
    outs: list[runs_exec.DeviceOutcome] = []
    fleet = _fetch_fleet("edge", _FetchingCollector("r1", "SHA", "NEW-ARP"))
    runs_exec.execute_cycle(_settings(), [fleet], {"edge"}, None, prior, outs)

    assert coll.ran == [] and coll.observed == []
    assert outs[0].skipped and not outs[0].observations_only
    # and the hash it will be compared against next time is recorded
    assert outs[0].obs_sha == "NEW-ARP"
    assert cycle.meta["degraded"] is False


def test_a_failed_optional_section_carries_that_sections_objects(monkeypatch):
    sections = {"r1": {"rib": SectionOutcome(status="ok"), "nat": SectionOutcome(status="failed")}}
    cycle, outcome = _run_with_sections(monkeypatch, sections)

    assert outcome.completeness == "partial"
    # the scope collected, so its other absences hold
    assert cycle.collected == {"vyos:r1"}
    assert cycle.scopes == {}
    assert cycle.section_labels == {"vyos:r1": ["NatRule"]}


def test_a_section_that_owns_no_label_carries_nothing(monkeypatch):
    sections = {"r1": {"rib": SectionOutcome(status="ok"), "arp": SectionOutcome(status="unauthorized")}}
    cycle, outcome = _run_with_sections(monkeypatch, sections)

    assert outcome.completeness == "partial"
    assert cycle.section_labels == {}


def test_a_fetch_failure_in_the_concurrent_path_reads_partial(rig2):
    class _Boom(_FetchingCollector):
        def fetch(self):
            raise RuntimeError(f"{self.host} unreachable")

    cycle, coll = rig2()
    outs: list[runs_exec.DeviceOutcome] = []
    fleet = _fetch_fleet("edge", _Boom("r1"), _FetchingCollector("r2"))
    summary, ran, _, _ = runs_exec.execute_cycle(_settings(), [fleet], {"edge"}, None, {}, outs)
    assert coll.ran == ["r2"]
    assert cycle.meta["statuses"] == {"edge": "partial"}
    assert "r1 unreachable" in summary
    assert [d.host for _, d, _ in ran] == ["r2"]
    by_host = {o.host: o for o in outs}
    assert not by_host["r1"].ok and "unreachable" in by_host["r1"].error
    assert by_host["r2"].ok


async def test_the_collect_cycle_body_reports_the_run_and_the_shed_case(monkeypatch):
    from hst.worker import collect
    from hst.worker.maintenance import Context

    ctx = Context(store=FakeStore(), settings=_settings())

    async def held(store, settings, source, triggered_by=None):
        return None

    monkeypatch.setattr(collect.runs_exec, "run_blocking", held)
    assert "skipped" in await collect.collect_cycle_body(ctx, None)

    async def done(store, settings, source, triggered_by=None):
        from hst.app.store import Run

        return Run(7, "cycle", "ok", NOW, NOW, "cycle 2000: 7 nodes, 9 rels · edge: …")

    monkeypatch.setattr(collect.runs_exec, "run_blocking", done)
    detail = await collect.collect_cycle_body(ctx, None)
    assert detail.startswith("run 7 ok")
    assert "cycle 2000" in detail


async def test_prepare_all_expands_fleets_and_reports_an_empty_group(tmp_path, monkeypatch):
    from hst.app.crypto import generate_key

    settings = Settings(_env_file=None, hst_secret_key=generate_key(), hst_data_dir=tmp_path)
    store = FakeStore()
    await store.create_source(
        "edge",
        "vyos",
        {"auth": {"method": "password", "username": "u"}},
        b"",
    )
    await store.replace_devices("edge", [DeviceSpec("r1"), DeviceSpec("r2", enabled=False), DeviceSpec("r3")])
    await store.create_source("lonely", "vyos", {}, b"")

    prepared, _ = await runs_exec._prepare_all(store, settings)
    by_name = {p.row.name: p for p in prepared}

    edge = by_name["edge"]
    assert edge.error is None
    assert [u.device.host for u in edge.units] == ["r1", "r3"]  # r2 disabled

    lonely = by_name["lonely"]
    assert lonely.error == "no enabled devices and no host"
    assert lonely.units == []


# --- ownership fencing: the fence and the drain ------------------------------------
#

import contextlib  # noqa: E402
import os  # noqa: E402
import threading  # noqa: E402

from hst.core import cycle as cyclemod  # noqa: E402
from hst.core import db as dbmod  # noqa: E402

NEO4J_URI = os.environ.get("NEO4J_TEST_URI")


@pytest.fixture
def pointer_graph():
    """A session against the scratch Neo4j, with the cycle pointer cleared."""
    from neo4j import GraphDatabase

    live = Settings(_env_file=None).neo4j_uri
    if dbmod.same_endpoint(NEO4J_URI or "", live):
        pytest.exit(
            f"NEO4J_TEST_URI ({NEO4J_URI}) is the live twin ({live}). This test deletes the "
            f"cycle pointer. Point it at a scratch database.",
            returncode=2,
        )
    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(os.environ.get("NEO4J_TEST_USER", "neo4j"), os.environ["NEO4J_TEST_PASSWORD"]),
    )
    drop = "MATCH (p:CyclePointer {uid: $uid}) DETACH DELETE p"
    with driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        s.run(drop, uid=cyclemod.POINTER_UID).consume()
        yield s
        s.run(drop, uid=cyclemod.POINTER_UID).consume()
    driver.close()


@pytest.mark.db
@pytest.mark.skipif(not NEO4J_URI, reason="NEO4J_TEST_URI not set")
def test_a_stale_fence_cannot_move_the_pointer(pointer_graph):
    s = pointer_graph
    cyclemod.set_pointer(s, 4_000, 7)
    assert cyclemod.current_ts(s) == 4_000

    with pytest.raises(cyclemod.StaleFence):
        cyclemod.set_pointer(s, 5_000, 6)
    assert cyclemod.current_ts(s) == 4_000  # the refused run left it where it was

    # the same acquisition may publish more than once: a cold-start refresh
    # falls through to a full cycle without releasing the lock
    cyclemod.set_pointer(s, 6_000, 7)
    assert cyclemod.current_ts(s) == 6_000

    cyclemod.set_pointer(s, 7_000, 8)
    assert cyclemod.current_ts(s) == 7_000


async def test_shutdown_during_a_paused_graph_write_holds_the_lock_until_the_thread_ends(monkeypatch):
    store = FakeStore()
    # a cycle with no enabled source publishes nothing and builds nothing
    await store.create_source("vyos", "vyos", {}, b"")
    entered, release = threading.Event(), threading.Event()

    def blocking(settings, prepared, fresh, assigned=None, prior=None, outcomes=None, **kw):
        entered.set()
        assert release.wait(30), "the builder thread was never released"
        return runs_exec.RunOutcome("paused", [], NEW)

    monkeypatch.setattr(runs_exec, "execute_cycle", blocking)

    before = set(runs_exec._TASKS)
    run = await runs_exec.launch(store, _settings(), "cycle")
    assert run is not None
    (task,) = set(runs_exec._TASKS) - before

    assert await asyncio.to_thread(entered.wait, 30), "the builder thread never started"
    task.cancel()
    await asyncio.sleep(0.05)
    assert store._cycle_lock.locked()

    release.set()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    assert not store._cycle_lock.locked()


# --- carry-forward by scope, against a real graph -----------------------------------
#

from hst.core.diff import diff_snapshots  # noqa: E402
from hst.core.loader import load  # noqa: E402
from hst.core.model import Batch, NodeRecord  # noqa: E402

CARRY_SCOPES = ["vyos:carry-a", "vyos:carry-b", "vyos:drop-keep", "vyos:drop-gone"]
KEPT, DROPPED = CARRY_SCOPES[2], CARRY_SCOPES[3]


@pytest.fixture
def carry_graph():
    """A session against the scratch Neo4j, holding only this test's two device
    scopes. Refuses the configured live twin the way the other db suites do."""
    from neo4j import GraphDatabase

    live = Settings(_env_file=None).neo4j_uri
    if dbmod.same_endpoint(NEO4J_URI or "", live):
        pytest.exit(
            f"NEO4J_TEST_URI ({NEO4J_URI}) is the live twin ({live}). This test deletes "
            f"objects. Point it at a scratch database.",
            returncode=2,
        )
    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(os.environ.get("NEO4J_TEST_USER", "neo4j"), os.environ["NEO4J_TEST_PASSWORD"]),
    )
    drop = "MATCH (n:Obj) WHERE n._scope IN $scopes DETACH DELETE n"
    scopes = [*CARRY_SCOPES, "meta:runs"]
    with driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        s.run(drop, scopes=scopes).consume()
        yield s
        s.run(drop, scopes=scopes).consume()
    driver.close()


def _rule(uid: str) -> NodeRecord:
    return NodeRecord(label="FwRule", uid=uid, props={"name": uid})


@pytest.mark.db
@pytest.mark.skipif(not NEO4J_URI, reason="NEO4J_TEST_URI not set")
def test_a_failed_sibling_keeps_its_last_known_objects_marked_stale_and_the_fresh_siblings_removals_hold(
    carry_graph, rig
):
    s = carry_graph
    both = [_rule("rule:a1"), _rule("rule:a2")]
    load(s, Batch(source="edge", scope=CARRY_SCOPES[0], nodes=both), collection_ts=PREV, ts_ms=900)
    load(
        s,
        Batch(source="edge", scope=CARRY_SCOPES[1], nodes=[_rule("rule:b1")]),
        collection_ts=PREV,
        ts_ms=900,
    )

    cycle, _ = rig(bad={"carry-b"})
    runs_exec.execute_cycle(_settings(), [_fleet("edge", "carry-a", "carry-b")], {"edge"})
    assert cycle.collected == {CARRY_SCOPES[0]}
    assert cycle.scopes == {CARRY_SCOPES[1]: "failed"}

    # what the run itself wrote: carry-a, without the rule it stopped reporting
    load(s, Batch(source="edge", scope=CARRY_SCOPES[0], nodes=both[:1]), collection_ts=NEW, ts_ms=2000)
    cyclemod.carry_forward(s, PREV, NEW, list(cycle.carried), scopes=cycle.scopes, collected=cycle.collected)

    rows = s.run(
        "MATCH (n:FwRule {collection_ts: $cts}) RETURN n.uid AS uid, n.carried AS carried, "
        "n.carried_reason AS reason, n.last_seen_ts AS last_seen ORDER BY n.uid",
        cts=NEW,
    ).data()
    assert [r["uid"] for r in rows] == ["rule:a1", "rule:b1"]  # rule:a2 is a removal
    assert (rows[0]["carried"], rows[0]["reason"]) == (False, None)
    assert (rows[1]["carried"], rows[1]["reason"], rows[1]["last_seen"]) == (True, "failed", 900)


def _inventory_graph(s) -> None:
    load(s, Batch(source="edge", scope=KEPT, nodes=[_rule("rule:keep")]), collection_ts=PREV, ts_ms=900)
    load(s, Batch(source="edge", scope=DROPPED, nodes=[_rule("rule:gone")]), collection_ts=PREV, ts_ms=900)


def _uids_at(s, cts: int) -> list[str]:
    rows = s.run("MATCH (n:FwRule {collection_ts: $cts}) RETURN n.uid AS uid ORDER BY n.uid", cts=cts).data()
    return [r["uid"] for r in rows]


@pytest.mark.db
@pytest.mark.skipif(not NEO4J_URI, reason="NEO4J_TEST_URI not set")
def test_a_device_dropped_from_a_running_source_is_removed_even_beside_an_unchanged_sibling(
    carry_graph, rig2
):
    s = carry_graph
    _inventory_graph(s)

    cycle, _ = rig2()
    prior = {("edge", "drop-keep"): _status("edge", "drop-keep", "SHA", _recent())}
    fleet = _fetch_fleet("edge", _FetchingCollector("drop-keep", "SHA"))
    runs_exec.execute_cycle(_settings(), [fleet], {"edge"}, None, prior, [])
    assert cycle.scopes == {KEPT: "unchanged"}
    assert cycle.unasked == ()  # the source ran, so it keeps no dropped device

    cyclemod.carry_forward(
        s,
        PREV,
        NEW,
        list(cycle.carried),
        scopes=cycle.scopes,
        collected=cycle.collected,
        unasked=cycle.unasked,
    )

    assert _uids_at(s, NEW) == ["rule:keep"]
    out = diff_snapshots(s, PREV, NEW)
    removed = {n["uid"] for n in out["nodes"]["removed"]}
    assert "rule:gone" in removed and "rule:keep" not in removed


@pytest.mark.db
@pytest.mark.skipif(not NEO4J_URI, reason="NEO4J_TEST_URI not set")
def test_a_device_dropped_from_a_source_this_cycle_never_asked_is_carried_not_run(carry_graph, rig):
    s = carry_graph
    _inventory_graph(s)

    cycle, _ = rig()
    runs_exec.execute_cycle(_settings(), [_fleet("edge", "drop-keep"), _fleet("core", "c1")], {"core"})
    assert cycle.scopes == {KEPT: "not-run"}
    assert set(cycle.unasked) == {"edge", "vyos"}

    cyclemod.carry_forward(
        s,
        PREV,
        NEW,
        list(cycle.carried),
        scopes=cycle.scopes,
        collected=cycle.collected,
        unasked=cycle.unasked,
    )

    rows = s.run(
        "MATCH (n:FwRule {collection_ts: $cts}) RETURN n.uid AS uid, n.carried AS carried, "
        "n.carried_reason AS reason, n.last_seen_ts AS last_seen ORDER BY n.uid",
        cts=NEW,
    ).data()
    assert [r["uid"] for r in rows] == ["rule:gone", "rule:keep"]
    assert all((r["carried"], r["reason"], r["last_seen"]) == (True, "not-run", 900) for r in rows)


def test_a_source_an_operator_stopped_carries_its_devices_and_the_cycle_publishes(rig):
    cycle, _ = rig()
    stop = runs_exec.RunStop()
    stop.for_source("edge")
    stop.for_source("core")
    stop.cancel_source("edge")

    _, ran, _, _ = runs_exec.execute_cycle(
        _settings(),
        [_fleet("edge", "r1", "r2"), _fleet("core", "r9")],
        {"edge", "core"},
        stop=stop,
    )

    assert cycle.meta["statuses"]["edge"] == "cancelled"
    assert cycle.scopes == {"vyos:r1": "cancelled", "vyos:r2": "cancelled"}
    assert cycle.collected == {"vyos:r9"}
    assert [(row.name, d.host) for row, d, _ in ran] == [("core", "r9")]
    assert cycle.meta["degraded"] is True


def test_stopping_the_whole_run_singles_out_no_source(rig):
    """`source_cancelled` is false once the run's own flag is up: the run's
    outcome is then the answer, and no source is picked out as the one stopped."""
    stop = runs_exec.RunStop()
    stop.for_source("edge")
    stop.set()
    assert not stop.source_cancelled("edge")


def test_a_cancelled_source_retires_nothing_it_did_not_collect(rig):
    cycle, _ = rig()
    stop = runs_exec.RunStop()
    stop.for_source("edge")
    stop.for_source("core")
    stop.cancel_source("edge")

    runs_exec.execute_cycle(
        _settings(),
        [_fleet("edge", "r1", "r2"), _fleet("core", "r9")],
        {"edge", "core"},
        stop=stop,
    )

    # 1. nothing of the stopped source answered for itself
    assert cycle.scopes == {"vyos:r1": "cancelled", "vyos:r2": "cancelled"}
    assert cycle.collected == {"vyos:r9"}
    assert "edge" in cycle.carried and "core" not in cycle.carried
    # 2. its dropped devices are kept, the source that ran keeps none
    assert "edge" in cycle.unasked
    assert "core" not in cycle.unasked


def test_a_source_stopped_after_its_load_began_degrades_to_the_failed_path(rig):
    cycle, _ = rig(bad={"r2"})
    runs_exec.execute_cycle(_settings(), [_fleet("edge", "r1", "r2")], {"edge"})

    assert cycle.meta["statuses"] == {"edge": "partial"}
    assert cycle.scopes == {"vyos:r2": "failed"}
    assert cycle.collected == {"vyos:r1"}
