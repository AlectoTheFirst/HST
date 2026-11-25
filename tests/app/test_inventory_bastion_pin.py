"""A bastion's host key learned on first contact survives under resolver v2."""

from __future__ import annotations

from types import SimpleNamespace

from tests.app.conftest import login
from tests.app.test_inventory_collection import (
    VYOS_SECRETS,
    VYOS_SETTINGS,
    FakeCollector,
    activate,
    data_key,
    make_client,
    make_store,
    seed_credential,
    seed_direct_connection,
    seed_profile,
    settings_for,
)
from tests.app.test_inventory_collection import built as built
from tests.app.test_inventory_profiles import API, _connection, _target

from hst.app import runs_exec
from hst.app import sources as glue
from hst.app.inventory import collection

BASTION = {"host": "Bastion.Example", "port": 2222}
PIN = "ssh-ed25519 AAAABASTION"


def test_a_pin_is_kept_by_the_bastions_address() -> None:
    assert collection.jump_pin_key("Bastion.Example", 2222) == "bastion.example:2222"
    assert collection.jump_pin_key("b", None) == "b:22"
    config = {"jump_pins": {"b:22": PIN}}
    assert collection.jump_pin(config, "B", None) == PIN
    assert collection.jump_pin(config, "b", 2222) == ""
    assert collection.jump_pin({"jump_pins": "garbled"}, "b", None) == ""
    assert collection.jump_pin({}, "b", None) == ""


async def _resolved(settings_map, pins):
    store = await make_store()
    settings = settings_for()
    await activate(store)
    cred = await seed_credential(store, settings, VYOS_SECRETS)
    profile = await seed_profile(store, "p", "vyos", settings_map, cred)
    row, _ = await seed_direct_connection(store, settings, profile=profile)
    if pins is not None:
        await store.update_source("lab", config={**row.config, "jump_pins": pins})
        row = await store.get_source("lab")
    context = await collection.execution_context(store)
    (device,) = await store.list_devices("lab")
    async with store.inventory().transaction() as tx:
        resolver = collection.Resolver(tx, settings, context=context, key=data_key(settings))
        return await resolver.resolve(row, device=device, with_secrets=True)


async def test_the_learned_pin_is_laid_over_a_profile_that_states_none() -> None:
    resolved = await _resolved({**VYOS_SETTINGS, "jump_host": BASTION}, {"bastion.example:2222": PIN})
    assert resolved.effective.values["jump_host.host_key"] == PIN
    assert resolved.effective.origins["jump_host.host_key"] == "target"
    assert resolved.payload["jump_host"]["host_key"] == PIN


async def test_a_key_the_profile_states_wins_over_the_learned_one() -> None:
    settings_map = {**VYOS_SETTINGS, "jump_host": {**BASTION, "host_key": "ssh-ed25519 FROMPROFILE"}}
    resolved = await _resolved(settings_map, {"bastion.example:2222": PIN})
    assert resolved.payload["jump_host"]["host_key"] == "ssh-ed25519 FROMPROFILE"
    assert resolved.effective.origins["jump_host.host_key"] == "profile"


async def test_a_pin_of_another_address_is_not_applied() -> None:
    resolved = await _resolved({**VYOS_SETTINGS, "jump_host": BASTION}, {"bastion.example:22": PIN})
    assert not resolved.payload["jump_host"].get("host_key")


async def test_a_row_without_pins_resolves_with_no_bastion_key() -> None:
    resolved = await _resolved({**VYOS_SETTINGS, "jump_host": BASTION}, None)
    assert not resolved.payload["jump_host"].get("host_key")


class _Collector:
    def __init__(self, jump, observed_jump_key):
        self.observed_host_key = ""
        self.observed_jump_key = observed_jump_key
        self.config = SimpleNamespace(jump_host=jump)


async def test_first_contact_records_the_pin_by_address_and_never_rewrites_it() -> None:
    store = await make_store()
    row = await store.create_source("lab", "vyos", {"interval_s": 60}, b"")
    jump = SimpleNamespace(host="Bastion.Example", port=2222, host_key="")
    await runs_exec.pin_host_key(store, row, _Collector(jump, PIN))
    assert (await store.get_source("lab")).config["jump_pins"] == {"bastion.example:2222": PIN}
    await runs_exec.pin_host_key(store, row, _Collector(jump, "ssh-ed25519 OTHER"))
    assert (await store.get_source("lab")).config["jump_pins"] == {"bastion.example:2222": PIN}
    other = SimpleNamespace(host="b2", port=22, host_key="")
    await runs_exec.pin_host_key(store, row, _Collector(other, "ssh-ed25519 SECOND"))
    assert (await store.get_source("lab")).config["jump_pins"] == {
        "bastion.example:2222": PIN,
        "b2:22": "ssh-ed25519 SECOND",
    }


async def test_a_key_the_profile_states_is_not_recorded_on_the_row() -> None:
    store = await make_store()
    row = await store.create_source("lab", "vyos", {"interval_s": 60}, b"")
    jump = SimpleNamespace(host="b", port=22, host_key="ssh-ed25519 FROMPROFILE")
    await runs_exec.pin_host_key(store, row, _Collector(jump, "ssh-ed25519 FROMPROFILE"))
    assert "jump_pins" not in (await store.get_source("lab")).config


async def test_a_probe_pins_the_bastion_and_the_next_run_checks_it(tmp_path, built, monkeypatch) -> None:
    store = await make_store()
    settings = settings_for(tmp_path)
    await activate(store)
    cred = await seed_credential(store, settings, {**VYOS_SECRETS, "jump_host.auth.password": "jump-pw"})
    jump = {**BASTION, "auth": {"method": "password", "username": "jump"}}
    profile = await seed_profile(store, "bastion", "vyos", {**VYOS_SETTINGS, "jump_host": jump}, cred)
    payloads: list[dict] = []
    observed = [PIN]

    def build_device(row, device, settings_, **kw):
        payload = kw["effective"].payload
        payloads.append(payload)
        c = FakeCollector(payload)
        c.config.jump_host = SimpleNamespace(
            host=payload["jump_host"]["host"],
            port=payload["jump_host"]["port"],
            host_key=payload["jump_host"].get("host_key", ""),
        )
        c.observed_jump_key = observed[0]
        return c

    monkeypatch.setattr(glue, "build_device_collector", build_device)
    async with make_client(store, settings) as client:
        await login(client, "ada")
        conn = await _connection(client, profile_id=profile.id, enabled=False)
        target = await _target(client, conn["id"], "r1", enabled=False)
        await login(client, "otto")
        assert (await client.post(f"{API}/targets/{target['id']}/probe", json={})).status_code == 200
        assert not payloads[0]["jump_host"].get("host_key")
        assert (await store.get_source("lab")).config["jump_pins"] == {"bastion.example:2222": PIN}
        # the second contact checks the learned key, and a different one is never learned over it
        observed[0] = "ssh-ed25519 IMPOSTOR"
        assert (await client.post(f"{API}/targets/{target['id']}/probe", json={})).status_code == 200
        assert payloads[1]["jump_host"]["host_key"] == PIN
        assert (await store.get_source("lab")).config["jump_pins"] == {"bastion.example:2222": PIN}
        # the deliberate unpin, by an administrator
        await login(client, "ada")
        r = await client.patch(
            f"{API}/connections/{conn['id']}",
            json={"clear_jump_host_keys": True, "expected_revision": conn["revision"]},
        )
        assert r.status_code == 200, r.text
        assert "jump_pins" not in (await store.get_source("lab")).config
        await login(client, "otto")
        assert (await client.post(f"{API}/targets/{target['id']}/probe", json={})).status_code == 200
        assert not payloads[2]["jump_host"].get("host_key")
