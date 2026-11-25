"""Pausing collection retains graph ownership and evidence across snapshots."""

from types import SimpleNamespace

import pytest
from tests.app.fakes import FakeStore
from tests.app.test_inventory_collection import (
    VYOS_SECRETS,
    VYOS_SETTINGS,
    activate,
    built,  # noqa: F401 -- shared fixture
    make_store,
    seed_credential,
    seed_direct_connection,
    seed_profile,
    settings_for,
)
from tests.app.test_runs_exec_fleet import _device, _fleet, _source

from hst.app import runs_exec
from hst.app.store import DeviceSpec
from hst.core import cycle, manifest


def previous(monkeypatch, entries):
    monkeypatch.setattr(manifest, "read", lambda *_: SimpleNamespace(devices=entries))
    monkeypatch.setattr(manifest, "effective_runs", lambda *_: {})


def entry(host, *, source="edge", scope=None):
    return manifest.DeviceEntry(
        source=source,
        host=host,
        outcome="collected",
        scope=f"custom:{host}" if scope is None else scope,
        device_uids=[f"managed:{host}"],
        fetch_ts_ms=900,
        fetch_started_ms=890,
        fetch_finished_ms=900,
        raw_sha256="last-observation",
        effective_run="900-abcdef12",
    )


@pytest.mark.parametrize("v2", [False, True])
async def test_disabled_source_is_prepared_for_carry_without_building_collectors(tmp_path, monkeypatch, v2):
    store = await make_store() if v2 else FakeStore()
    if v2:
        await activate(store)
    await store.create_source("paused", "velocloud", {}, b"unreadable", enabled=False)

    def forbidden(*args, **kwargs):
        pytest.fail("disabled source attempted collector construction")

    monkeypatch.setattr(runs_exec.sources_glue, "build_collector", forbidden)
    prepared, secrets = await runs_exec._prepare_all(store, settings_for(tmp_path))
    assert [(p.row.name, p.units, p.error) for p in prepared] == [("paused", [], None)]
    assert secrets == {}
    statuses, _, ran, _, _ = runs_exec._collect_sources(
        None, prepared, {"paused"}, {}, 2000, forbidden, runs_exec.RunEvidence(settings_for(tmp_path))
    )
    assert statuses == {"paused": "carried"}
    assert ran == []


async def test_disabled_execution_record_keeps_its_host_outside_runnable_units(tmp_path):
    store = FakeStore()
    await store.create_source("edge", "vyos", {}, b"")
    await store.replace_devices("edge", [DeviceSpec("r1"), DeviceSpec("r2", enabled=False)])
    [prepared], _ = await runs_exec._prepare_all(store, settings_for(tmp_path))
    assert prepared.paused_hosts == {"r2"}
    assert [u.device.host for u in prepared.units] == ["r1"]
    assert ("edge", "r2") not in runs_exec._unit_index([prepared])


@pytest.mark.usefixtures("built")
async def test_disabled_inventory_target_is_preserved_but_archived_target_is_not(tmp_path):
    store = await make_store()
    settings = settings_for(tmp_path)
    await activate(store)
    cred = await seed_credential(store, settings, VYOS_SECRETS)
    profile = await seed_profile(store, "p", "vyos", VYOS_SETTINGS, cred)
    _, targets = await seed_direct_connection(store, settings, hosts=("r1", "r2", "r3"), profile=profile)
    async with store.inventory().transaction() as tx:
        paused, removed = targets["r2"], targets["r3"]
        await tx.update_target(
            paused.id, expected_revision=paused.revision, now=paused.updated_at, enabled=False
        )
        await tx.archive_target(removed.id, expected_revision=removed.revision, now=removed.updated_at)
    [prepared], _ = await runs_exec._prepare_all(store, settings)
    assert prepared.paused_hosts == {"r2"}
    assert [u.device.host for u in prepared.units] == ["r1"]


@pytest.mark.parametrize("failed", [False, True])
def test_partial_fleet_preserves_only_paused_or_unbuildable_partition_across_runs(
    tmp_path, monkeypatch, failed
):
    settings = settings_for(tmp_path)
    prepared = _fleet("edge", "active")
    if failed:
        prepared.units.append(runs_exec.PreparedDevice(_device("edge", "paused"), None, "bad profile"))
    else:
        prepared.paused_hosts = {"paused"}
    previous(monkeypatch, [entry("active"), entry("paused"), entry("removed")])
    calls = []

    def carry(*args, **kwargs):
        calls.append(kwargs)
        return {"nodes": 1, "rels": 1}

    monkeypatch.setattr(cycle, "carry_forward", carry)
    for prev in (1000, 2000):
        scopes = runs_exec.CarryScopes()
        scopes.ran(prepared.units[0])
        statuses = {"edge": "partial" if failed else "fresh"}
        carried = runs_exec._carry_phase(
            None, [prepared], statuses, set(), [], prev, prev + 1000, scopes, settings
        )
        assert carried == ["edge"]
        assert calls[-1]["scopes"] == {"custom:paused": "failed" if failed else "not-run"}
        assert calls[-1]["unasked"] == []
        entries = runs_exec._device_entries(
            settings, prev + 1000, prev, [prepared], statuses, runs_exec.RunEvidence(settings)
        )
        assert {d.host for d in entries} == {"active", "paused"}
        paused = next(d for d in entries if d.host == "paused")
        assert paused.scope == "custom:paused"
        assert paused.carried and paused.fetch_started_ms == 890
        previous(monkeypatch, entries)


def test_disabled_source_retains_controller_evidence_and_deleted_source_does_not(tmp_path, monkeypatch):
    settings = settings_for(tmp_path)
    source = _source("paused", "velocloud")
    source.enabled = False
    prepared = [runs_exec.PreparedSource(source, [])]
    previous(monkeypatch, [entry("vco.example", source="paused"), entry("other", source="deleted")])
    calls = []
    monkeypatch.setattr(cycle, "carry_forward", lambda *a, **kw: calls.append(kw) or {"nodes": 1, "rels": 0})
    for prev in (1000, 2000):
        statuses = {"paused": "carried"}
        runs_exec._carry_phase(
            None, prepared, statuses, set(), [], prev, prev + 1000, runs_exec.CarryScopes(), settings
        )
        assert "paused" in calls[-1]["unasked"]
        assert "deleted" not in calls[-1]["unasked"]
        entries = runs_exec._device_entries(
            settings, prev + 1000, prev, prepared, statuses, runs_exec.RunEvidence(settings)
        )
        assert [(d.source, d.host, d.outcome) for d in entries] == [("paused", "vco.example", "carried")]
        assert entries[0].raw_sha256 == "last-observation"
        assert entries[0].device_uids == ["managed:vco.example"]
        previous(monkeypatch, entries)


def test_old_manifest_recovers_scope_using_managed_uid_not_controller_address(tmp_path, monkeypatch):
    prepared = _fleet("edge", "active")
    prepared.paused_hosts = {"controller.example"}
    previous(monkeypatch, [entry("controller.example", scope="")])
    lookups = []
    monkeypatch.setattr(
        cycle, "_read", lambda *a, **kw: lookups.append(kw) or [{"scope": "appliance:managed"}]
    )
    monkeypatch.setattr(cycle, "carry_forward", lambda *a, **kw: {"nodes": 1, "rels": 0})
    scopes = runs_exec.CarryScopes()
    runs_exec._carry_phase(
        None, [prepared], {"edge": "fresh"}, set(), [], 1000, 2000, scopes, settings_for(tmp_path)
    )
    assert lookups == [{"prev": 1000, "uids": ["managed:controller.example"], "source": "edge"}]
    assert scopes.reasons == {"appliance:managed": "not-run"}
