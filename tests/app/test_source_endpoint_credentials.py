"""A stored source credential follows no new endpoint and no weaker TLS check
unless the request supplies every stored secret again."""

from __future__ import annotations

import pytest
from tests.app.conftest import login
from tests.app.test_inventory_collection import (
    NOW,
    activate,
    data_key,
    make_client,
    make_store,
    seed_credential,
    seed_profile,
    settings_for,
)
from tests.app.test_sources_api import _dk, make_app_client

from hst.app import sources as glue
from hst.app.crypto import decrypt_secrets, encrypt_secrets
from hst.app.inventory import credentials
from hst.app.store import Source

ENDPOINT = "credentials required for an endpoint other than the stored one: "
WEAKER = "credentials required for a TLS check weaker than the stored one: "
API = "/api/inventory"

EQUINIX = {
    "name": "fabric",
    "type": "equinix",
    "config": {
        "api_url": "https://api.equinix.com",
        "auth": {"method": "oauth_client", "client_id": "cid", "client_secret": "not-a-real-secret"},
    },
}
APIC = {
    "name": "aci",
    "type": "apic",
    "config": {
        "url": "https://apic1.example",
        "fabric": "fab1",
        "auth": {"method": "user_password", "username": "ro", "password": "apic-pw"},
    },
}
VYOS = {
    "name": "edge",
    "type": "vyos",
    "config": {
        "host": "gw1",
        "host_key": "ssh-ed25519 AAAAPIN",
        "auth": {"method": "password", "username": "vyos", "password": "dev-pw"},
        "jump_host": {
            "host": "bastion1",
            "auth": {"method": "password", "username": "jump", "password": "jump-pw"},
        },
    },
}


@pytest.mark.parametrize(
    ("body", "overlay", "detail"),
    [
        (EQUINIX, {"api_url": "https://listener.example"}, ENDPOINT + "auth.client_secret"),
        (EQUINIX, {"tls": {"verify": False}}, WEAKER + "auth.client_secret"),
        (EQUINIX, {"tls": {"ca_bundle": "-----BEGIN CERTIFICATE-----"}}, WEAKER + "auth.client_secret"),
        (APIC, {"url": "https://listener.example"}, ENDPOINT + "auth.password"),
        (VYOS, {"host": "listener"}, ENDPOINT + "auth.password, jump_host.auth.password"),
        (VYOS, {"port": 2222}, ENDPOINT + "auth.password, jump_host.auth.password"),
        (VYOS, {"jump_host": {"host": "listener"}}, ENDPOINT + "auth.password, jump_host.auth.password"),
        (VYOS, {"host_key": ""}, WEAKER + "auth.password, jump_host.auth.password"),
    ],
)
async def test_a_source_patch_to_another_endpoint_keeps_no_stored_secret(seeded, body, overlay, detail):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        assert (await client.post("/api/sources", json=body)).status_code == 201
        before = await seeded.get_source(body["name"])
        refused = await client.patch(f"/api/sources/{body['name']}", json={"config": overlay})
        assert refused.status_code == 400, refused.text
        assert refused.json()["error"] == detail
        after = await seeded.get_source(body["name"])
        assert after.config == before.config
        assert decrypt_secrets(_dk(), after.secrets) == decrypt_secrets(_dk(), before.secrets)


async def test_a_source_patch_to_another_endpoint_with_every_secret_is_saved(seeded):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        assert (await client.post("/api/sources", json=VYOS)).status_code == 201
        partial = await client.patch(
            "/api/sources/edge",
            json={"config": {"host": "gw2", "auth": {"password": "new-dev-pw"}}},
        )
        assert partial.status_code == 400
        assert partial.json()["error"] == ENDPOINT + "jump_host.auth.password"
        saved = await client.patch(
            "/api/sources/edge",
            json={
                "config": {
                    "host": "gw2",
                    "auth": {"password": "new-dev-pw"},
                    "jump_host": {"auth": {"password": "new-jump-pw"}},
                }
            },
        )
        assert saved.status_code == 200, saved.text
        row = await seeded.get_source("edge")
        assert row.config["host"] == "gw2"
        assert decrypt_secrets(_dk(), row.secrets) == {
            "auth.password": "new-dev-pw",
            "jump_host.auth.password": "new-jump-pw",
        }


async def test_a_source_patch_that_keeps_the_endpoint_needs_no_secret(seeded):
    async with await make_app_client(seeded) as client:
        await login(client, "ada")
        assert (await client.post("/api/sources", json=EQUINIX)).status_code == 201
        same = {"api_url": "https://api.equinix.com", "interval_s": 300, "tls": {"verify": True}}
        r = await client.patch("/api/sources/fabric", json={"config": same})
        assert r.status_code == 200, r.text
        stricter = await client.patch(
            "/api/sources/fabric", json={"config": {"tls": {"verify": True, "ca_bundle": ""}}}
        )
        assert stricter.status_code == 200, stricter.text


def test_merge_config_refuses_a_new_endpoint_that_keeps_a_stored_secret():
    key = data_key(settings_for())
    config, secrets = glue.validate_source(APIC["type"], APIC["config"])
    row = Source(1, "aci", "apic", config, encrypt_secrets(key, secrets), True, NOW, NOW)
    with pytest.raises(glue.CredentialsRequired) as refused:
        glue.merge_config(row, {"url": "https://listener.example"}, key)
    assert str(refused.value) == ENDPOINT + "auth.password"
    assert refused.value.kept == ["auth.password"]
    merged, sealed = glue.merge_config(
        row, {"url": "https://apic2.example", "auth": {"password": "apic-pw"}}, key
    )
    assert merged["url"] == "https://apic2.example"
    assert decrypt_secrets(key, sealed) == {"auth.password": "apic-pw"}


# --- inventory ---------------------------------------------------------------------------


APIC_PROFILE = {"auth": {"method": "user_password", "username": "ro"}}
APIC_SECRETS = {"auth.password": "apic-pw"}


async def _apic_connection(tmp_path, profile_settings=None):
    store = await make_store()
    settings = settings_for(tmp_path)
    await activate(store)
    cred = await seed_credential(store, settings, APIC_SECRETS)
    profile = await seed_profile(store, "aci", "apic", profile_settings or APIC_PROFILE, cred)
    return store, settings, cred, profile


async def _bound_secrets(store, settings, source_key):
    """The secrets of the credential that the default profile of the connection binds."""
    async with store.inventory().transaction() as tx:
        inventory = await tx.get_source_inventory_by_key(source_key)
        profile = await tx.get_profile(inventory.default_profile_id)
        version = await tx.get_profile_version(profile.id, profile.current_revision)
        cred = await tx.get_credential_version(version.credential_id, version.credential_revision)
        return version.credential_id, credentials.open_sealed(data_key(settings), cred)


async def test_a_connection_patch_to_another_url_needs_the_stored_secrets(tmp_path):
    store, settings, cred, profile = await _apic_connection(tmp_path)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        r = await client.post(
            f"{API}/connections",
            json={
                "name": "aci",
                "collector_type": "apic",
                "config": {"url": "https://apic1.example", "fabric": "fab1"},
                "profile_id": str(profile.id),
            },
        )
        assert r.status_code == 201, r.text
        conn = r.json()
        refused = await client.patch(
            f"{API}/connections/{conn['id']}",
            json={"config": {"url": "https://listener.example"}, "expected_revision": conn["revision"]},
        )
        assert refused.status_code == 422, refused.text
        assert refused.json()["error"] == ENDPOINT + "auth.password"
        assert refused.json()["detail"] == {"credentials": ["auth.password"]}
        assert (await store.get_source("aci")).config["url"] == "https://apic1.example"
        saved = await client.patch(
            f"{API}/connections/{conn['id']}",
            json={
                "config": {"url": "https://apic2.example"},
                "secrets": {"auth.password": "new-apic-pw"},
                "expected_revision": conn["revision"],
            },
        )
        assert saved.status_code == 200, saved.text
        assert "new-apic-pw" not in saved.text
    assert (await store.get_source("aci")).config["url"] == "https://apic2.example"
    bound_id, secrets = await _bound_secrets(store, settings, "aci")
    assert bound_id != cred.id
    assert secrets == {"auth.password": "new-apic-pw"}


async def test_an_inventory_source_patch_to_another_url_needs_the_stored_secrets(tmp_path):
    from tests.app.test_inventory_legacy_api import activated

    rig, settings = await activated(tmp_path)
    from hst.app.inventory.legacy import LegacyConnections

    service = LegacyConnections(rig.store, settings, context=rig.ctx)
    await service.create("aci", "apic", APIC["config"])
    with pytest.raises(glue.CredentialsRequired) as refused:
        await service.patch("aci", {"url": "https://listener.example"})
    assert str(refused.value) == ENDPOINT + "auth.password"
    with pytest.raises(glue.CredentialsRequired):
        await service.patch("aci", {"tls": {"verify": False}})
    await service.patch("aci", {"url": "https://apic2.example", "auth": {"password": "new-apic-pw"}})
    assert (await rig.store.get_source("aci")).config["url"] == "https://apic2.example"


async def test_a_controller_replacement_needs_the_stored_secrets(tmp_path):
    store = await make_store()
    settings = settings_for(tmp_path)
    await activate(store)
    cred = await seed_credential(store, settings, {"auth.key": "vco-key"})
    profile = await seed_profile(store, "vco", "velocloud", {"auth": {"method": "api_key"}}, cred)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        r = await client.post(
            f"{API}/connections",
            json={
                "name": "vco",
                "collector_type": "velocloud",
                "config": {"url": "https://vco", "orchestrator_release": "6.4.0"},
                "profile_id": str(profile.id),
            },
        )
        assert r.status_code == 201, r.text
        [target] = (await client.get(f"{API}/targets", params={"connection_id": r.json()["id"]})).json()
        body = {
            "operation": "replace_target",
            "selection": {"ids": [target["id"]]},
            "change": {"endpoint_config": {"url": "https://listener.example"}},
        }
        refused = await client.post(f"{API}/operations/preview", json=body)
        assert refused.status_code == 422, refused.text
        assert refused.json()["error"] == ENDPOINT + "auth.key"
        assert refused.json()["detail"] == {"credentials": ["auth.key"]}
        body["change"]["secrets"] = {"auth.key": "new-vco-key"}
        preview = await client.post(f"{API}/operations/preview", json=body)
        assert preview.status_code == 200, preview.text
        assert "new-vco-key" not in preview.text
        applied = await client.post(
            f"{API}/operations/apply", json={"token": preview.json()["token"], "idempotency_key": "r1"}
        )
        assert applied.status_code == 200, applied.text
    assert (await store.get_source("vco")).config["url"] == "https://listener.example"
    bound_id, secrets = await _bound_secrets(store, settings, "vco")
    assert bound_id != cred.id
    assert secrets == {"auth.key": "new-vco-key"}


async def test_a_profile_edit_that_weakens_tls_or_moves_the_bastion_keeps_no_credential(tmp_path):
    store, settings, cred, profile = await _apic_connection(tmp_path)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        weaker = {"settings": {**APIC_PROFILE, "tls": {"verify": False}}, "expected_revision": 1}
        refused = await client.patch(f"{API}/profiles/{profile.id}", json=weaker)
        assert refused.status_code == 422, refused.text
        assert refused.json()["error"] == WEAKER + "auth.password"
        preview = await client.post(
            f"{API}/operations/preview",
            json={"operation": "edit_profile", "selection": {"ids": [str(profile.id)]}, "change": weaker},
        )
        assert preview.status_code == 422, preview.text
        assert preview.json()["error"] == WEAKER + "auth.password"
        same = {"settings": {**APIC_PROFILE, "interval_s": 600}, "expected_revision": 1}
        assert (await client.patch(f"{API}/profiles/{profile.id}", json=same)).status_code == 200
        other = await seed_credential(store, settings, {"auth.password": "typed-again"}, name="new")
        rebound = {**weaker, "credential_id": str(other.id), "expected_revision": 2}
        saved = await client.patch(f"{API}/profiles/{profile.id}", json=rebound)
        assert saved.status_code == 200, saved.text
        assert saved.json()["credential_id"] == str(other.id)

    store = await make_store()
    await activate(store)
    cred = await seed_credential(
        store, settings, {"auth.password": "dev-pw", "jump_host.auth.password": "jump-pw"}
    )
    vyos = {
        "auth": {"method": "password", "username": "vyos"},
        "jump_host": {"host": "bastion1", "auth": {"method": "password", "username": "jump"}},
    }
    profile = await seed_profile(store, "edge", "vyos", vyos, cred)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        moved = {**vyos, "jump_host": {**vyos["jump_host"], "host": "listener"}}
        refused = await client.patch(
            f"{API}/profiles/{profile.id}", json={"settings": moved, "expected_revision": 1}
        )
        assert refused.status_code == 422, refused.text
        assert refused.json()["error"] == ENDPOINT + "auth.password, jump_host.auth.password"


def test_the_refusal_lists_secret_paths_and_never_values():
    exc = glue.CredentialsRequired(ENDPOINT, ["b.key", "a.password"])
    assert str(exc) == ENDPOINT + "a.password, b.key"
