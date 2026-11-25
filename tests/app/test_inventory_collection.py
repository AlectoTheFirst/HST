"""Effective collection resolution and the execution seams.

The rig at the top is shared with test_inventory_profiles.py,
test_inventory_scheduler.py and test_inventory_credentials.py: an
`InventoryFakeStore` whose legacy source writes are mirrored into the fake
repository's source rows, as one Postgres `sources` table would show them,
plus seeded users, a data key and an app factory that mounts the inventory
routers.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import httpx
import pytest
from cryptography.fernet import Fernet
from tests.app.conftest import PASSWORD, login
from tests.app.inventory_fakes import InventoryFakeStore

from hst.app import runs_exec
from hst.app import sources as glue
from hst.app.crypto import decrypt_secrets, dek, encrypt_secrets, generate_key
from hst.app.inventory import collection, credentials
from hst.app.inventory.connection_routes import register
from hst.app.inventory.contracts import Authority, EffectiveCollection, PlacementMode, TargetKind
from hst.app.main import create_app
from hst.app.security import hash_password
from hst.app.store import DeviceSpec
from hst.core import Settings
from hst.core.uid import slug

KEY = generate_key()
NOW = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)


def settings_for(tmp_path=None, **overrides) -> Settings:
    kw = {"_env_file": None, "hst_secret_key": KEY, **overrides}
    if tmp_path is not None:
        kw["hst_data_dir"] = tmp_path
    return Settings(**kw)


class RigStore(InventoryFakeStore):
    """InventoryFakeStore whose source writes are mirrored into the fake
    repository's `sources_rows`, the way one `sources` table serves both the
    legacy store and the inventory repository on Postgres."""

    async def create_source(self, name, type_, config, secrets, enabled=True):
        row = await super().create_source(name, type_, config, secrets, enabled)
        self._inventory.seed_source(row.id, name, type_, enabled=enabled)
        return row

    async def update_source(self, name, *, config=None, secrets=None, enabled=None):
        row = await super().update_source(name, config=config, secrets=secrets, enabled=enabled)
        if row is not None and enabled is not None:
            mirrored = self._inventory.tables.sources_rows.get(row.id)
            if mirrored is not None:
                mirrored.enabled = enabled
        return row

    async def delete_source(self, name):
        row = self.sources.get(name)
        gone = await super().delete_source(name)
        if row is not None:
            self._inventory.tables.sources_rows.pop(row.id, None)
        return gone


async def make_store() -> RigStore:
    store = RigStore()
    for name, role in (("vera", "viewer"), ("otto", "operator"), ("ada", "admin")):
        await store.create_user(name, hash_password(PASSWORD), role)
    return store


def make_client(store: RigStore, settings: Settings | None = None) -> httpx.AsyncClient:
    app = create_app(settings=settings or settings_for(), store=store, register_inventory=False)
    register(app)
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"})


async def activate(store: RigStore) -> None:
    async with store.inventory().transaction() as tx:
        await tx.activate(resolver_version=2, schema_version=1, backfill_version=1, now=NOW)


def data_key(settings: Settings) -> str:
    return dek(settings)


def other_data_key() -> str:
    """A data key this deployment does not hold."""
    return Fernet.generate_key().decode()


async def seed_credential(store: RigStore, settings: Settings, secrets: dict[str, str], name="lab-creds"):
    async with store.inventory().transaction() as tx:
        cred, _ = await tx.create_credential(
            display_name=name,
            sealed=credentials.seal(data_key(settings), secrets),
            secret_paths=sorted(secrets),
            actor_id=None,
            now=NOW,
        )
    return cred


async def seed_profile(store: RigStore, name, collector_type, settings_map, credential=None):
    async with store.inventory().transaction() as tx:
        profile, _ = await tx.create_profile(
            display_name=name,
            collector_type=collector_type,
            settings=settings_map,
            credential_id=credential.id if credential else None,
            credential_revision=credential.current_revision if credential else None,
            actor_id=None,
            now=NOW,
        )
    return profile


async def seed_direct_connection(
    store: RigStore, settings: Settings, *, name="lab", hosts=("r1",), profile=None
):
    """A vyos group with a fleet, its inventory targets, and the profile as
    the connection default when given."""
    row = await store.create_source(name, "vyos", {"interval_s": 60}, b"")
    devices = await store.replace_devices(name, [DeviceSpec(host=h) for h in hosts])
    targets = {}
    async with store.inventory().transaction() as tx:
        if profile is not None:
            inventory = await tx.get_source_inventory(row.id)
            await tx.update_source_inventory(
                row.id, expected_revision=inventory.inventory_revision, now=NOW, default_profile_id=profile.id
            )
        for device in devices:
            targets[device.host] = await tx.create_target(
                source_id=row.id,
                source_key=name,
                host=device.host,
                kind=TargetKind.DIRECT.value,
                now=NOW,
                legacy_device_id=device.id,
            )
    return row, targets


VYOS_SETTINGS = {"interval_s": 120, "auth": {"method": "password", "username": "vyos"}, "timeout": 30}
VYOS_SECRETS = {"auth.password": "s3cret-pw"}


class FakeCollector:
    """A collector stand-in: records the payload it was built from, answers a
    fetch and a probe, and reports one device uid per host."""

    VOLATILE_RAW_KEYS = ("uptime",)
    AUTHORITATIVE_SECTIONS = ()

    def __init__(self, payload: dict, *, sections=None):
        self.payload = payload
        self.config = SimpleNamespace(
            transport="asyncssh",
            host=payload.get("host", ""),
            site_code=payload.get("site_code"),
            effective_routing_scope=payload.get("routing_scope"),
            l2fabric=payload.get("l2fabric"),
            resolved_origins=payload.get("resolved_origins", {}),
        )
        self.observed_host_key = ""
        self.observed_jump_key = ""
        self.last_device_uids = [f"dev:x:{payload.get('host', 'ctrl')}"]
        self.last_device_locations = {}
        self.sections = sections or {}
        self.probed = 0

    async def afetch(self):
        return {"config": f"hostname {self.config.host}", "uptime": 1}

    def fetch(self):
        return {"config": f"hostname {self.config.host}", "uptime": 1}

    def probe(self):
        self.probed += 1
        return f"probe ok for {self.config.host}"


@pytest.fixture
def built(monkeypatch):
    """Patch the two builders so every execution path builds a FakeCollector
    from the resolved payload and records what it was handed."""
    made: list[tuple[str, dict | None, object]] = []

    def build_device(row, device, settings, **kw):
        eff = kw.get("effective")
        payload = eff.payload if eff is not None else glue.device_config(row, device)
        c = FakeCollector(payload)
        made.append((f"{row.name}/{device.host}", payload, eff))
        return c

    def build(row, settings, **kw):
        eff = kw.get("effective")
        payload = eff.payload if eff is not None else dict(row.config)
        c = FakeCollector(payload)
        made.append((row.name, payload, eff))
        return c

    monkeypatch.setattr(glue, "build_device_collector", build_device)
    monkeypatch.setattr(glue, "build_collector", build)
    return made


@pytest.fixture
def resolutions(monkeypatch):
    """Spy on the one resolver: every EffectiveCollection any path resolves."""
    seen: list[EffectiveCollection] = []
    original = collection.Resolver.resolve

    async def spy(self, row, **kw):
        resolved = await original(self, row, **kw)
        seen.append(resolved.effective)
        return resolved

    monkeypatch.setattr(collection.Resolver, "resolve", spy)
    return seen


# --- target key helper --------------------------------------------------------------


def test_target_key_is_one_pair_with_a_slugged_form():
    key = collection.target_key("Lab Site", "10.0.0.1")
    assert key == ("Lab Site", "10.0.0.1")
    assert key.slugged == (slug("Lab Site"), slug("10.0.0.1"))
    assert key.label == "Lab Site/10.0.0.1"
    assert collection.target_key("vco", "").label == "vco"


def test_unit_host_follows_the_status_host_rule():
    device = SimpleNamespace(host="r1")
    assert collection.unit_host(device, SimpleNamespace(host="other")) == "r1"
    assert collection.unit_host(None, SimpleNamespace(host="apic1")) == "apic1"
    assert collection.unit_host(None, SimpleNamespace()) == ""
    assert collection.unit_host(None, None) == ""


# --- v1: the legacy resolution ------------------------------------------------------------


async def test_v1_resolution_is_the_legacy_normalization_with_origins():
    store = await make_store()
    settings = settings_for()
    await store.create_site("fra", "Frankfurt", "", params={"routing_scope": "fra-scope"})
    row = await store.create_source("lab", "vyos", {"site_code": "fra", "interval_s": 60}, b"")
    devices = await store.replace_devices("lab", [DeviceSpec(host="r1", port=2222)])
    resolved = collection.resolve_v1(
        row, settings, device=devices[0], sites={s.code: s for s in await store.list_sites()}
    )
    legacy, origins = glue.resolve_normalization(
        row, settings, device=devices[0], sites={s.code: s for s in await store.list_sites()}
    )
    e = resolved.effective
    assert e.resolver_version == 1 and e.profile_id is None
    assert e.values["routing_scope"] == legacy["routing_scope"] == "fra-scope"
    assert e.origins["routing_scope"] == origins["routing_scope"] == "site"
    assert e.values["host"] == "r1" and e.values["port"] == 2222 and e.origins["host"] == "target"
    assert e.values["source_name"] == "lab" and e.origins["source_name"] == "internal"
    assert resolved.interval_s == 60


async def test_an_unactivated_store_resolves_under_v1_and_never_touches_profiles():
    store = await make_store()
    context = await collection.execution_context(store)
    assert context.resolver_version == 1 and not context.activated and not context.v2
    settings = settings_for()
    row = await store.create_source(
        "lab",
        "vyos",
        {"host": "gw", "auth": {"method": "password", "username": "u"}},
        encrypt_secrets(data_key(settings), {"auth.password": "pw"}),
    )
    async with store.inventory().transaction() as tx:
        resolver = collection.Resolver(tx, settings, context=context, key=data_key(settings))
        resolved = await resolver.resolve(row, with_secrets=True)
    assert resolved.effective.resolver_version == 1
    assert resolved.payload["auth"]["password"] == "pw"
    assert resolved.effective.values["auth.password"] == "***"


# --- v2: whole-profile assignment --------------------------------------------------------------


async def test_target_profile_wins_over_the_connection_profile_as_a_whole_revision():
    store = await make_store()
    settings = settings_for()
    await activate(store)
    cred = await seed_credential(store, settings, VYOS_SECRETS)
    conn_profile = await seed_profile(store, "conn-profile", "vyos", VYOS_SETTINGS, cred)
    target_profile = await seed_profile(
        store,
        "target-profile",
        "vyos",
        {"interval_s": 15, "auth": {"method": "password", "username": "ro"}},
        cred,
    )
    row, targets = await seed_direct_connection(store, settings, hosts=("r1", "r2"), profile=conn_profile)
    async with store.inventory().transaction() as tx:
        t = targets["r1"]
        await tx.update_target(t.id, expected_revision=t.revision, now=NOW, profile_id=target_profile.id)
    context = await collection.execution_context(store)
    assert context.v2 and context.activated
    devices = {d.host: d for d in await store.list_devices("lab")}
    async with store.inventory().transaction() as tx:
        resolver = collection.Resolver(tx, settings, context=context, key=data_key(settings))
        r1 = await resolver.resolve(row, device=devices["r1"], with_secrets=True)
        r2 = await resolver.resolve(row, device=devices["r2"], with_secrets=True)
    assert r1.effective.profile_id == target_profile.id and r1.profile_origin.value == "target"
    assert r2.effective.profile_id == conn_profile.id and r2.profile_origin.value == "connection"
    # whole revision: r1 does not inherit the connection profile's timeout,
    # and the row's own interval_s is not read under v2
    assert r1.effective.values["interval_s"] == 15 and "timeout" not in r1.effective.values
    assert r2.effective.values["interval_s"] == 120 and r2.effective.values["timeout"] == 30
    assert r1.effective.values["auth.username"] == "ro" and r1.effective.origins["auth.username"] == "profile"
    assert (
        r1.effective.values["auth.password"] == "***"
        and r1.effective.origins["auth.password"] == "credential"
    )
    assert r1.payload["auth"]["password"] == "s3cret-pw"
    assert r1.effective.credential_id == cred.id and r1.effective.credential_revision == 1
    assert r1.effective.target_id == targets["r1"].id
    assert r1.effective.configuration_digest != r2.effective.configuration_digest
    assert "s3cret-pw" not in r1.effective.model_dump_json()
    assert r1.interval_s == 15 and r2.interval_s == 120


async def test_v2_frozen_normalization_wins_and_geography_is_never_read():
    store = await make_store()
    settings = settings_for()
    await activate(store)
    await store.create_site("fra", "Frankfurt", "", params={"routing_scope": "fra-scope"})
    profile = await seed_profile(store, "p", "vyos", VYOS_SETTINGS)
    await seed_direct_connection(store, settings, profile=profile)
    await store.update_source("lab", config={"interval_s": 60, "site_code": "fra"})
    row = await store.get_source("lab")
    context = await collection.execution_context(store)
    device = (await store.list_devices("lab"))[0]
    async with store.inventory().transaction() as tx:
        resolver = collection.Resolver(tx, settings, context=context)
        unfrozen = await resolver.resolve(row, device=device, sites={"fra": (await store.list_sites())[0]})
        await tx.set_frozen_normalization(
            row.id,
            {
                "values": {"site_code": "fra", "routing_scope": "legacy-scope", "l2fabric": "fab1"},
                "origins": {"routing_scope": "site"},
            },
            NOW,
        )
    async with store.inventory().transaction() as tx:
        resolver = collection.Resolver(tx, settings, context=context)
        frozen = await resolver.resolve(row, device=device)
    # unfrozen: the fallback namespace, not the site's routing default
    assert unfrozen.effective.values["routing_scope"] == "inventory:lab"
    assert unfrozen.effective.origins["routing_scope"] == "fallback"
    assert frozen.effective.values["routing_scope"] == "legacy-scope"
    assert frozen.effective.origins["routing_scope"] == "site"
    assert frozen.effective.frozen_normalization == {
        "site_code": "fra",
        "routing_scope": "legacy-scope",
        "l2fabric": "fab1",
    }
    assert frozen.normalization_revision != unfrozen.normalization_revision


async def test_secrets_are_never_in_the_effective_collection_and_only_opened_on_request():
    store = await make_store()
    settings = settings_for()
    await activate(store)
    cred = await seed_credential(store, settings, VYOS_SECRETS)
    profile = await seed_profile(store, "p", "vyos", VYOS_SETTINGS, cred)
    row, _ = await seed_direct_connection(store, settings, profile=profile)
    context = await collection.execution_context(store)
    device = (await store.list_devices("lab"))[0]
    async with store.inventory().transaction() as tx:
        without = await collection.Resolver(tx, settings, context=context).resolve(row, device=device)
        with_ = await collection.Resolver(tx, settings, context=context, key=data_key(settings)).resolve(
            row, device=device, with_secrets=True
        )
    assert without.payload is None and without.secrets == {}
    assert with_.secrets == VYOS_SECRETS
    assert without.effective == with_.effective
    assert "s3cret-pw" not in with_.effective.model_dump_json()
    with pytest.raises(ValueError):
        glue.build_device_collector(row, device, settings, effective=without)


# --- repair required blocks collection ----------------------------------------------------


async def test_an_unreadable_credential_is_repair_required_and_blocks_collection(built):
    store = await make_store()
    settings = settings_for()
    await activate(store)
    other_key = other_data_key()
    async with store.inventory().transaction() as tx:
        cred, _ = await tx.create_credential(
            display_name="stale",
            sealed=encrypt_secrets(other_key, VYOS_SECRETS),
            secret_paths=sorted(VYOS_SECRETS),
            actor_id=None,
            now=NOW,
        )
    profile = await seed_profile(store, "p", "vyos", VYOS_SETTINGS, cred)
    row, _ = await seed_direct_connection(store, settings, profile=profile)
    context = await collection.execution_context(store)
    device = (await store.list_devices("lab"))[0]
    async with store.inventory().transaction() as tx:
        resolver = collection.Resolver(tx, settings, context=context, key=data_key(settings))
        with pytest.raises(collection.RepairRequired) as exc:
            await resolver.resolve(row, device=device, with_secrets=True)
    assert str(cred.id) in str(exc.value) and "s3cret" not in str(exc.value)
    # the cycle: the unit is an error naming the credential, no collector built
    prepared, merged = await runs_exec._prepare_all(store, settings)
    [unit] = prepared[0].units
    assert unit.collector is None and str(cred.id) in unit.error and "repair" in unit.error
    assert merged == {} and built == []
    # the per-target job: failed, recorded, never an empty success
    detail = await runs_exec.run_device_fetch(store, settings, "lab", "r1")
    assert detail.startswith("failed: lab/r1") and "repair" in detail
    [status] = await store.list_device_status("lab")
    assert status.consecutive_failures == 1 and "repair" in status.last_error


# --- one resolver, equal answers on every path ------------------------------------------------


async def test_cycle_job_probe_cli_scheduler_and_effective_api_resolve_identically(
    built, resolutions, monkeypatch, tmp_path
):
    from hst.worker.scheduler import Scheduler

    store = await make_store()
    settings = settings_for(tmp_path)
    await activate(store)
    cred = await seed_credential(store, settings, VYOS_SECRETS)
    profile = await seed_profile(store, "p", "vyos", VYOS_SETTINGS, cred)
    _, targets = await seed_direct_connection(store, settings, profile=profile)
    monkeypatch.setattr(
        runs_exec.coll, "park", lambda *a, **kw: tmp_path / "1780000000000-abcd1234.json.gz.enc"
    )

    # 1. the cycle's prepare step
    prepared, _ = await runs_exec._prepare_all(store, settings)
    [unit] = prepared[0].units
    assert unit.effective is not None and unit.collector is not None
    cycle_effective = unit.effective.effective
    # 2. the per-target job
    detail = await runs_exec.run_device_fetch(store, settings, "lab", "r1")
    assert "parked" in detail
    # 3. the scheduler's due check
    scheduler = Scheduler(store, settings, schedules=(), collect_fanout=True)
    scheduler.arm(NOW)
    due = await scheduler._due_targets(await store.list_sources(), {"lab": await store.list_devices("lab")})
    assert [(r.name, h, i) for r, h, i in due] == [("lab", "r1", 120)]
    # 4. the CLI adapter
    cli_effective = await collection.resolve_for_cli(store, settings, "lab", "r1")
    # 5. the effective-settings API and 6. the probe
    async with make_client(store, settings) as client:
        await login(client, "otto")
        r = await client.get(f"/api/inventory/targets/{targets['r1'].id}/effective")
        assert r.status_code == 200, r.text
        api_effective = EffectiveCollection.model_validate(r.json())
        r = await client.post(f"/api/inventory/targets/{targets['r1'].id}/probe", json={})
        assert r.status_code == 200, r.text
        probe = r.json()
        assert probe["ok"] and "probe ok" in probe["message"]
        probe_effective = EffectiveCollection.model_validate(probe["effective"])
    every = [cycle_effective, cli_effective, api_effective, probe_effective, *resolutions]
    assert len(resolutions) >= 6, (
        "cycle, job, scheduler, cli, api and probe each resolved through the resolver"
    )
    dumps = {e.model_dump_json() for e in every}
    assert len(dumps) == 1, "every path resolved the same effective collection"
    assert cycle_effective.configuration_digest == api_effective.configuration_digest
    assert all("s3cret" not in d for d in dumps)
    # the built collectors were handed the same secret-bearing payload each time
    payloads = {str(sorted(p.items())) for _, p, _ in built}
    assert len(payloads) == 1 and built[0][1]["auth"]["password"] == "s3cret-pw"


# --- the skip fingerprint --------------------------------------------------------


def test_fingerprint_is_the_raw_hash_under_v1_and_bound_under_v2():
    assert collection.fingerprint_for(None, "abc") == "abc"
    v1 = SimpleNamespace(
        effective=SimpleNamespace(resolver_version=1), normalization_revision="n", placement_generation=3
    )
    assert collection.fingerprint_for(v1, "abc") == "abc"
    v2 = SimpleNamespace(
        effective=SimpleNamespace(resolver_version=2), normalization_revision="n1", placement_generation=3
    )
    bound = collection.fingerprint_for(v2, "abc")
    assert bound != "abc" and bound == collection.skip_fingerprint("abc", "n1", 3)
    assert (
        collection.fingerprint_for(
            SimpleNamespace(
                effective=SimpleNamespace(resolver_version=2),
                normalization_revision="n1",
                placement_generation=4,
            ),
            "abc",
        )
        != bound
    )
    assert (
        collection.fingerprint_for(
            SimpleNamespace(
                effective=SimpleNamespace(resolver_version=2),
                normalization_revision="n2",
                placement_generation=3,
            ),
            "abc",
        )
        != bound
    )


async def test_a_placement_only_edit_rematerializes_a_device_whose_payload_did_not_change(
    built, monkeypatch, tmp_path
):
    store = await make_store()
    settings = settings_for(tmp_path)
    await activate(store)
    cred = await seed_credential(store, settings, VYOS_SECRETS)
    profile = await seed_profile(store, "p", "vyos", VYOS_SETTINGS, cred)
    await seed_direct_connection(store, settings, profile=profile)
    monkeypatch.setattr(
        runs_exec.coll, "park", lambda *a, **kw: tmp_path / "1780000000000-abcd1234.json.gz.enc"
    )
    fingerprints: list[str] = []
    real = collection.fingerprint_for

    def spy(resolved, sha):
        fingerprints.append(real(resolved, sha))
        return fingerprints[-1]

    monkeypatch.setattr(runs_exec.inventory_collection, "fingerprint_for", spy)
    first = await runs_exec.run_device_fetch(store, settings, "lab", "r1")
    assert "parked" in first
    # the park records the attempt alone; the device run that loads the
    # payload records its basis, bound as the fetch bound it
    [status] = await store.list_device_status("lab")
    assert status.last_raw_sha == ""
    fingerprint = fingerprints[-1]
    await store.record_device_basis("lab", "r1", now=datetime.now(UTC), raw_sha=fingerprint, full=True)
    second = await runs_exec.run_device_fetch(store, settings, "lab", "r1")
    assert second == "lab/r1: unchanged, not parked"
    async with store.inventory().transaction() as tx:
        await tx.bump_generation(NOW)  # a placement-only intent write
    third = await runs_exec.run_device_fetch(store, settings, "lab", "r1")
    assert third.startswith("lab/r1: parked ")
    assert fingerprints[-1] != fingerprint


async def test_v1_status_rows_keep_the_raw_hash(built, monkeypatch, tmp_path):
    store = await make_store()
    settings = settings_for(tmp_path)
    await store.create_source("lab", "vyos", {"interval_s": 60}, b"")
    await store.replace_devices("lab", [DeviceSpec(host="r1")])
    monkeypatch.setattr(
        runs_exec.coll, "park", lambda *a, **kw: tmp_path / "1780000000000-abcd1234.json.gz.enc"
    )
    collector = FakeCollector({"host": "r1"})
    raw = runs_exec.coll.raw_sha(collector, collector.fetch())
    # the basis a device run records for a v1 unit is the raw hash itself
    # (`fingerprint_for(None, ...)`), and the job compares the raw hash to it
    await store.upsert_device_status("lab", "r1", now=datetime.now(UTC), ok=True)
    await store.record_device_basis("lab", "r1", now=datetime.now(UTC), raw_sha=raw, full=True)
    detail = await runs_exec.run_device_fetch(store, settings, "lab", "r1")
    assert detail == "lab/r1: unchanged, not parked"
    [status] = await store.list_device_status("lab")
    assert status.last_raw_sha == raw


# --- the empty direct source --------------------------------------------------------------------


async def test_the_empty_direct_source_is_not_run_by_the_job_path(built):
    store = await make_store()
    settings = settings_for()
    await store.create_source("empty", "vyos", {"interval_s": 60}, b"")
    detail = await runs_exec.run_device_fetch(store, settings, "empty", "")
    assert detail == "skipped: empty has no enabled devices and no host"
    assert built == []


async def test_a_disabled_inventory_target_never_runs(built, monkeypatch, tmp_path):
    store = await make_store()
    settings = settings_for(tmp_path)
    await activate(store)
    cred = await seed_credential(store, settings, VYOS_SECRETS)
    profile = await seed_profile(store, "p", "vyos", VYOS_SETTINGS, cred)
    _, targets = await seed_direct_connection(store, settings, hosts=("r1", "r2"), profile=profile)
    async with store.inventory().transaction() as tx:
        t = targets["r2"]
        await tx.update_target(t.id, expected_revision=t.revision, now=NOW, enabled=False)
    prepared, _ = await runs_exec._prepare_all(store, settings)
    assert [u.device.host for u in prepared[0].units] == ["r1"]
    assert (
        await runs_exec.run_device_fetch(store, settings, "lab", "r2") == "skipped: lab/r2: target disabled"
    )
    async with store.inventory().transaction() as tx:
        t = targets["r1"]
        await tx.archive_target(t.id, expected_revision=t.revision, now=NOW)
    prepared, _ = await runs_exec._prepare_all(store, settings)
    assert prepared[0].units == []
    assert prepared[0].error == (
        "no eligible targets in inventory: 1 no active inventory target, 1 target disabled"
    )
    assert all(d.enabled for d in await store.list_devices("lab"))


# --- the publication seam -----------------------------------------------------------------------


class RecordingObservations:
    def __init__(self):
        self.staged: list[tuple] = []
        self.published: list[str] = []
        self.reconciled: list[str | None] = []

    async def stage_observations(
        self, txn, snapshot_key, target_key, observations, authority, *, succeeded=True, attempted_at=None
    ):
        self.staged.append(
            (snapshot_key, tuple(target_key), [o.graph_uid for o in observations], authority, succeeded)
        )

    async def publish(self, snapshot_key):
        self.published.append(snapshot_key)

    async def reconcile(self, latest_snapshot_key):
        self.reconciled.append(latest_snapshot_key)


def test_authority_verdict_is_partial_when_a_named_section_failed():
    from hst.core.model import SectionOutcome

    assert collection.authority_verdict({}) == Authority.COMPLETE
    ok = {"interfaces": SectionOutcome(status="ok")}
    assert collection.authority_verdict(ok, ("interfaces",)) == Authority.COMPLETE
    bad = {"interfaces": SectionOutcome(status="failed")}
    assert collection.authority_verdict(bad, ("interfaces",)) == Authority.PARTIAL


async def test_run_results_are_staged_and_published_through_the_seam(monkeypatch):
    store = await make_store()
    await activate(store)
    service = RecordingObservations()
    monkeypatch.setattr(collection, "_observation_service", service)
    row = await store.create_source("vco", "velocloud", {}, b"")
    collector = FakeCollector({"host": ""})
    collector.last_device_uids = ["velocloud:e1", "velocloud:e2"]
    collector.last_device_locations = {"velocloud:e1": ("ent/site-7", "Frankfurt")}
    ok_unit = runs_exec.PreparedDevice(None, collector, None)
    failed_row = await store.create_source("lab", "vyos", {}, b"")
    failed_unit = runs_exec.PreparedDevice(
        SimpleNamespace(host="r1", enabled=True), FakeCollector({"host": "r1"}), None
    )
    prepared = [runs_exec.PreparedSource(row, [ok_unit]), runs_exec.PreparedSource(failed_row, [failed_unit])]
    outcomes = [
        runs_exec.DeviceOutcome("vco", "", True, full=True),
        runs_exec.DeviceOutcome("lab", "r1", False, error="timeout"),
    ]
    capture = await runs_exec.capture_execution(store, prepared)
    assert capture.context.activated
    await runs_exec._stage_results(store, capture, 1234, prepared, outcomes)
    assert service.staged == [
        ("1234", ("vco", ""), ["velocloud:e1", "velocloud:e2"], Authority.COMPLETE, True),
        ("1234", ("lab", "r1"), [], Authority.PARTIAL, False),
    ]
    assert service.published == ["1234"]
    # an unpublished run stages nothing
    await runs_exec._stage_results(store, capture, None, prepared, outcomes)
    assert service.published == ["1234"]


async def test_the_seam_is_a_no_op_until_inventory_is_activated(monkeypatch):
    store = await make_store()
    service = RecordingObservations()
    monkeypatch.setattr(collection, "_observation_service", service)
    context = await collection.execution_context(store)
    assert collection.observation_service(context) is collection.NOOP_OBSERVATIONS
    await collection.reconcile_on_startup(store)
    assert service.reconciled == []
    await activate(store)
    async with store.inventory().transaction() as tx:
        await tx.stage_publication("900", parent_snapshot_key=None, now=NOW)
        await tx.mark_published("900", NOW)
    await collection.reconcile_on_startup(store)
    assert service.reconciled == ["900"]


def test_observed_devices_reads_uids_and_reported_locations():
    collector = FakeCollector({"host": ""})
    collector.last_device_uids = ["b", "a", "a"]
    collector.last_device_locations = {"a": ("loc-1", "Site One"), "b": "loc-2"}
    observed = collection.observed_devices(collector)
    assert [(o.graph_uid, o.reported_location_id, o.reported_location_name) for o in observed] == [
        ("a", "loc-1", "Site One"),
        ("b", "loc-2", ""),
    ]


# --- evidence in the manifest context --------------------------------------------------------------


async def test_the_normalization_context_carries_revisions_and_the_placement_generation(built):
    store = await make_store()
    settings = settings_for()
    await activate(store)
    cred = await seed_credential(store, settings, VYOS_SECRETS)
    profile = await seed_profile(store, "p", "vyos", VYOS_SETTINGS, cred)
    _, _ = await seed_direct_connection(store, settings, profile=profile)
    async with store.inventory().transaction() as tx:
        device, _ = await tx.register_device(
            "dev:x:r1", hostname="r1", platform="vyos", management_address="", snapshot_key=None, now=NOW
        )
        await tx.set_placement(
            device.id,
            mode=PlacementMode.AUTO,
            site_id=None,
            origin="manual",
            expected_revision=0,
            actor_id=None,
            now=NOW,
        )
    await store.record_target_devices("lab", "r1", ["dev:x:r1"], {})
    prepared, _ = await runs_exec._prepare_all(store, settings)
    # a placement write between preparation and capture is not in the
    # manifest: the revisions were read in the transaction that resolved the
    # units, beside the generation they carry
    async with store.inventory().transaction() as tx:
        await tx.set_placement(
            device.id,
            mode=PlacementMode.AUTO,
            site_id=None,
            origin="manual",
            expected_revision=1,
            actor_id=None,
            now=NOW,
        )
    capture = await runs_exec.capture_execution(store, prepared)
    state = await collection.execution_context(store)
    assert capture is prepared[0].capture
    assert capture.resolver_version == 2
    assert capture.placement_generation == prepared[0].units[0].effective.placement_generation
    assert capture.placement_revisions == {"dev:x:r1": 1}
    assert (await runs_exec.capture_execution(store)).placement_revisions == {"dev:x:r1": 2}
    assert state.placement_generation >= capture.placement_generation
    [unit] = prepared[0].units
    block = runs_exec._device_context(settings, prepared[0], unit)
    assert block["resolver_version"] == "2"
    assert block["profile_id"] == str(profile.id) and block["profile_revision"] == 1
    assert block["credential_id"] == str(cred.id) and block["credential_revision"] == 1
    assert block["configuration_digest"] == unit.effective.effective.configuration_digest
    assert block["normalization_revision"] == unit.effective.normalization_revision
    assert block["placement_generation"] == capture.placement_generation


# --- profile settings validation ------------------------------------------------------------------


def test_profile_settings_reject_every_non_profile_category():
    ok = collection.validate_profile_settings(
        "vyos", {"interval_s": 30, "auth": {"method": "password", "username": "u"}}
    )
    assert ok == {"interval_s": 30, "auth": {"method": "password", "username": "u"}}
    assert collection.validate_profile_settings("vyos", {"jump_host.host": "b"}) == {
        "jump_host": {"host": "b"}
    }
    for bad, category in (
        ({"host": "r1"}, "target"),
        ({"url": "https://x"}, "unknown"),
        ({"source_name": "x"}, "internal"),
        ({"routing_scope": "x"}, "legacy_normalization"),
        ({"auth": {"password": "pw"}}, "credential"),
        ({"made_up": 1}, "unknown"),
    ):
        with pytest.raises(collection.SettingsRejected) as exc:
            collection.validate_profile_settings("vyos", bad)
        assert category in str(exc.value)
    with pytest.raises(collection.SettingsRejected):
        collection.validate_profile_settings("velocloud", {"url": "https://vco"})
    with pytest.raises(collection.SettingsRejected):
        collection.validate_profile_settings("nope", {})


def test_connection_config_rejects_profile_and_secret_paths():
    assert collection.validate_connection_config(
        "velocloud", {"url": "https://vco", "enterprise_logical_ids": ["e1"]}
    )
    with pytest.raises(collection.SettingsRejected):
        collection.validate_connection_config("velocloud", {"auth": {"key": "k"}})
    with pytest.raises(collection.SettingsRejected):
        collection.validate_connection_config("vyos", {"interval_s": 5})


def test_nested_mapping_fields_take_their_field_category():
    assert collection.category_of("ndo", "site_fabrics.dc1") == "connection"
    assert collection.category_of("checkpoint_gateway", "vsid_gateway_object_uids.2") == "target"
    assert collection.category_of("checkpoint_gateway", "management_link.host") == "internal"
    assert collection.category_of("vyos", "nowhere.deep") is None
    assert collection.validate_connection_config("ndo", {"site_fabrics": {"dc1": "f1"}}) == {
        "site_fabrics": {"dc1": "f1"}
    }


async def test_unclassified_row_paths_never_become_effective_values(caplog):
    store = await make_store()
    settings = settings_for()
    await activate(store)
    cred = await seed_credential(store, settings, VYOS_SECRETS)
    profile = await seed_profile(store, "p", "vyos", VYOS_SETTINGS, cred)
    row, _ = await seed_direct_connection(store, settings, hosts=("r1",), profile=profile)
    stale = {**row.config, "collector_clock_quality": "ntp", "resolved_origins": {"host": "row"}}
    row = await store.update_source("lab", config=stale)
    context = await collection.execution_context(store)
    [device] = await store.list_devices("lab")
    async with store.inventory().transaction() as tx:
        resolver = collection.Resolver(tx, settings, context=context, key=data_key(settings))
        with caplog.at_level("WARNING", logger="hst.app.inventory.collection"):
            resolved = await resolver.resolve(row, device=device, with_secrets=True)
    assert resolved.unclassified == ("collector_clock_quality",)
    assert "collector_clock_quality" not in resolved.effective.values
    assert "collector_clock_quality" not in resolved.payload
    # an internal path off the row is classified, and not the row's to say:
    # the resolver writes its own origins, never the row's
    assert "resolved_origins.host" not in resolved.effective.values
    assert "host" not in resolved.payload["resolved_origins"]
    assert any("collector_clock_quality" in r.getMessage() for r in caplog.records)


def test_identity_paths_come_from_the_classification():
    assert "url" in collection.identity_paths("velocloud", "connection")
    assert "host" in collection.identity_paths("vyos", "target")
    assert "port" not in collection.identity_paths("vyos", "target")
    assert "orchestrator_release" not in collection.identity_paths("velocloud", "connection")


def test_flatten_and_unflatten_round_trip():
    nested = {"a": {"b": 1, "c": {"d": [1, 2]}}, "e": {}, "f": None}
    flat = collection.flatten(nested)
    assert flat == {"a.b": 1, "a.c.d": [1, 2], "e": {}, "f": None}
    assert collection.unflatten(flat) == nested


def test_credential_helpers_never_expose_plaintext():
    key = other_data_key()
    sealed = credentials.seal(key, {"auth.password": "pw"})
    assert json.loads(Fernet(key.encode()).decrypt(sealed)) == {"auth.password": "pw"}
    version = SimpleNamespace(credential_id=uuid.uuid4(), revision=1, sealed=sealed)
    assert credentials.is_readable(key, version)
    assert not credentials.is_readable(other_data_key(), version)
    assert decrypt_secrets(key, sealed) == {"auth.password": "pw"}
    assert credentials.redact_secret_names(["auth.password"]) == {"auth.password": "***"}


def test_zia_location_sites_is_not_an_identity_path():
    from hst.app.inventory import collection

    paths = collection.identity_paths("zia", "connection", "target")
    assert "tenant" in paths
    assert "location_sites" not in paths


def test_only_the_zscaler_tenant_keys_the_identity():
    """vanity_domain builds the token URL and customer_id the API paths: neither
    keys a uid or the scope, so an edit of either is a connection edit."""
    from hst.app.inventory import collection

    assert collection.identity_paths("zia", "connection", "target") == frozenset({"tenant"})
    assert collection.identity_paths("zpa", "connection", "target") == frozenset({"tenant"})


def test_the_zscaler_profiles_hide_capture_bgp_and_accept_a_stored_value():
    from hst.app.inventory import collection
    from hst.app.inventory import field_metadata as fm

    for ctype in ("zia", "zpa"):
        shown = [f.path for f in fm.COLLECTORS[ctype].fields if f.category == "profile"]
        assert "capture_bgp" not in shown, ctype
        assert collection.validate_profile_settings(ctype, {"capture_bgp": "all"}) == {"capture_bgp": "all"}
    assert "capture_bgp" in [f.path for f in fm.COLLECTORS["nxos"].fields if f.category == "profile"]
