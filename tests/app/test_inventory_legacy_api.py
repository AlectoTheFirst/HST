"""Activated compatibility endpoints route to revisioned inventory intent."""

import httpx
import pytest
from tests.app.conftest import PASSWORD, login
from tests.app.inventory_rig import device, fake_rig
from tests.app.test_inventory_collection import activate, settings_for

from hst.app.inventory.legacy import LegacyConnections, NormalizationMigrated
from hst.app.main import create_app
from hst.app.security import hash_password
from hst.app.store import DeviceSpec


async def activated(tmp_path):
    settings = settings_for(tmp_path)
    rig = fake_rig(settings=settings)
    await rig.seed_site("fra")
    original_create = rig.store.create_source

    async def create_source(name, type_, config, secrets, enabled=True):
        row = await original_create(name, type_, config, secrets, enabled=enabled)
        rig.fake.seed_source(row.id, name, type_, enabled=enabled)
        return row

    rig.store.create_source = create_source
    await activate(rig.store)
    service = LegacyConnections(rig.store, settings, context=rig.ctx)
    row = await service.create(
        "lab",
        "vyos",
        {
            "site_code": "fra",
            "interval_s": 60,
            "auth": {"method": "password", "username": "reader", "password": "test"},
        },
    )
    rig.source_ids["lab"] = row.id
    await service.replace_devices("lab", [DeviceSpec("router1")])
    await rig.run("100", {("lab", "router1"): ("complete", [device("dev:r1")])})
    return rig, settings


async def test_source_patch_creates_profile_revision_and_preserves_frozen_identity(tmp_path):
    rig, settings = await activated(tmp_path)
    await rig.store.create_user("ada", hash_password(PASSWORD), "admin")
    app = create_app(settings=settings, store=rig.store, register_inventory=False)
    app.state.inventory_context = rig.ctx
    from hst.app.inventory.connection_routes import install_error_handlers

    install_error_handlers(app)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t", headers={"X-HST-CSRF": "1"}
    ) as client:
        await login(client, "ada")
        response = await client.patch("/api/sources/lab", json={"config": {"interval_s": 120}})
        assert response.status_code == 200, response.text
        assert response.json()["config"]["interval_s"] == 120
        assert response.json()["config"]["routing_scope"] == "inventory:lab"
        response = await client.get("/api/sources")
        assert response.json()["sources"][0]["config"]["interval_s"] == 120
        refused = await client.patch("/api/sources/lab", json={"config": {"routing_scope": "different"}})
        assert refused.status_code == 409
        assert refused.json()["code"] == "normalization_migrated"
    assert "interval_s" not in (await rig.store.get_source("lab")).config
    async with rig.repo.transaction() as tx:
        inventory = await tx.get_source_inventory_by_key("lab")
        profile = await tx.get_profile(inventory.default_profile_id)
        assert profile.current_revision == 2


async def test_profile_shared_with_another_connection_is_cloned_before_legacy_edit(tmp_path):
    rig, settings = await activated(tmp_path)
    await rig.seed_source("other", "vyos")
    async with rig.repo.transaction() as tx:
        source = await tx.get_source_inventory_by_key("lab")
        other = await tx.get_source_inventory_by_key("other")
        original_profile = source.default_profile_id
        await tx.update_source_inventory(
            other.source_id,
            expected_revision=other.inventory_revision,
            default_profile_id=original_profile,
            now=rig.clock(),
        )
    service = LegacyConnections(rig.store, settings, context=rig.ctx)
    await service.patch("lab", {"interval_s": 300})
    async with rig.repo.transaction() as tx:
        assert (await tx.get_source_inventory_by_key("other")).default_profile_id == original_profile
        assert (await tx.get_source_inventory_by_key("lab")).default_profile_id != original_profile
        assert (await tx.get_profile(original_profile)).current_revision == 1


async def test_legacy_site_patch_is_bulk_placement_and_does_not_change_routing(tmp_path):
    rig, settings = await activated(tmp_path)
    await rig.seed_site("ams")
    service = LegacyConnections(rig.store, settings, context=rig.ctx)
    result = await service.patch("lab", {"site_code": "ams"})
    assert result.config["site_code"] == "ams"
    assert result.config["routing_scope"] == "inventory:lab"
    device = await rig.device_by_uid("dev:r1")
    async with rig.repo.transaction() as tx:
        assert (await tx.get_placement(device.id)).site_id == rig.site_ids["ams"]
        assert (await tx.get_active_target("lab", "router1")).onboarding_site_id == rig.site_ids["ams"]
    await service.patch("lab", {"site_code": ""})
    async with rig.repo.transaction() as tx:
        assert (await tx.get_placement(device.id)).mode == "unplaced"
    with pytest.raises(NormalizationMigrated):
        await service.patch("lab", {"l2fabric": "changed"})


async def test_target_replacement_preserves_kept_pin_and_archives_removed_observations(tmp_path):
    rig, settings = await activated(tmp_path)
    await rig.store.set_device_host_key("lab", "router1", "pinned-key")
    prior = (await rig.store.list_devices("lab"))[0]
    service = LegacyConnections(rig.store, settings, context=rig.ctx)
    await service.replace_devices("lab", [DeviceSpec("router1", port=2222), DeviceSpec("router2")])
    kept = next(d for d in await rig.store.list_devices("lab") if d.host == "router1")
    assert kept.id == prior.id and kept.host_key == "pinned-key" and kept.port == 2222
    await service.replace_devices("lab", [DeviceSpec("router2")])
    assert await rig.device_by_uid("dev:r1") is not None
    assert (await rig.observations("dev:r1"))[0].state != "current"


async def test_new_legacy_connection_uses_profile_and_probe_redacts_its_credentials(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from tests.app.test_inventory_collection import activate, make_store, settings_for

    from hst.app import sources as glue

    store = await make_store()
    settings = settings_for(tmp_path)
    await activate(store)
    service = LegacyConnections(store, settings)
    row = await service.create(
        "new-lab",
        "vyos",
        {
            "auth": {"method": "password", "username": "reader", "password": "password-value"},
            "interval_s": 90,
        },
    )
    assert row.config["routing_scope"] == "inventory:new-lab"
    await service.replace_devices("new-lab", [DeviceSpec("r1")])
    seen = []

    def collector(*args, **kwargs):
        seen.append(kwargs["effective"])
        return SimpleNamespace(probe=lambda: "login password-value succeeded")

    monkeypatch.setattr(glue, "build_device_collector", collector)
    result = await service.probe("new-lab")
    assert result == {"ok": True, "detail": "login *** succeeded"}
    assert seen[0].effective.profile_id is not None
    assert seen[0].effective.values["interval_s"] == 90


async def test_an_edit_of_a_stored_zia_connection_is_refused_only_for_the_tenant(tmp_path):
    rig, settings = await activated(tmp_path)
    service = LegacyConnections(rig.store, settings, context=rig.ctx)
    row = await service.create(
        "zia-acme",
        "zia",
        {
            "vanity_domain": "acme",
            "tenant": "acme",
            "auth": {"method": "oauth_client", "client_id": "cid", "client_secret": "not-a-real-secret"},
        },
    )
    rig.source_ids["zia-acme"] = row.id
    await rig.store.create_user("ada", hash_password(PASSWORD), "admin")
    app = create_app(settings=settings, store=rig.store, register_inventory=False)
    from hst.app.inventory.connection_routes import register

    register(app)
    app.state.inventory_context = rig.ctx
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t", headers={"X-HST-CSRF": "1"}
    ) as client:
        await login(client, "ada")
        response = await client.get("/api/inventory/connections")
        assert response.status_code == 200, response.text
        [conn] = [c for c in response.json() if c["name"] == "zia-acme"]
        url = f"/api/inventory/connections/{conn['id']}"
        edit = {"vanity_domain": "acme2", "tenant": "acme", "location_sites": ""}
        body = {"expected_revision": conn["revision"], "config": edit}
        refused = await client.patch(url, json=body)
        assert refused.status_code == 422, refused.text
        assert refused.json()["detail"] == {"credentials": ["auth.client_secret"]}
        body["secrets"] = {"auth.client_secret": "typed-again"}
        response = await client.patch(url, json=body)
        assert response.status_code == 200, response.text
        revision = response.json()["revision"]
        refused = await client.patch(url, json={"expected_revision": revision, "config": {"tenant": "other"}})
        assert refused.status_code == 422, refused.text
        assert "tenant" in refused.text


def test_a_zscaler_replacement_warns_of_the_new_uid_prefix_and_not_of_a_host_key():
    from types import SimpleNamespace

    from hst.app.inventory.connection_routes import _replacement_warnings

    zia = SimpleNamespace(type="zia", config={"tenant": "acme"})
    assert _replacement_warnings(zia, {"tenant": "Other Co"}) == [
        "the uid prefix of every node of this source changes from zia:acme to zia:other-co"
    ]
    assert _replacement_warnings(zia, {"tenant": "acme"}) == []
    ssh = SimpleNamespace(type="vyos", config={})
    assert any("host key" in w for w in _replacement_warnings(ssh, {"host": "10.0.0.9"}))


async def test_a_zia_location_sites_line_must_name_an_inventory_site(tmp_path):
    from hst.app.inventory.connection_routes import Validation, _check_location_sites

    rig, _settings = await activated(tmp_path)
    await _check_location_sites(rig.store, "zia", {"location_sites": "1001, fra"})
    with pytest.raises(Validation, match="no site has the code of the line '1002, nowhere'"):
        await _check_location_sites(rig.store, "zia", {"location_sites": "1001, fra\n1002, nowhere"})
    await _check_location_sites(rig.store, "zpa", {"location_sites": "x, nowhere"})


async def test_an_equinix_ibx_sites_line_may_not_spell_an_existing_site_another_way(tmp_path):
    """`FRA` for the site `fra` would be one Site node under a second code."""
    from hst.app.inventory.connection_routes import Validation, _check_location_sites

    rig, _settings = await activated(tmp_path)
    await _check_location_sites(rig.store, "equinix", {"ibx_sites": "FR2, fra\nFR9, fr9"})
    with pytest.raises(Validation, match=r"'FR5, FRA' \(the site 'fra'\)"):
        await _check_location_sites(rig.store, "equinix", {"ibx_sites": "FR2, fra\nFR5, FRA"})
