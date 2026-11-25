"""The device identity registry as the collectors of a run see it:
app/sources.py `StoreResolver` and `registry_snapshot`, and app/runs_exec.py
`_arm_identity`."""

import asyncio
from types import SimpleNamespace

import pytest
from tests.app.fakes import FakeStore

from hst.app import runs_exec
from hst.app import sources as glue
from hst.core.identity import MemoryResolver


class _Counting(FakeStore):
    def __init__(self) -> None:
        super().__init__()
        self.calls: list[str] = []

    async def resolve_device(self, kind, value, hostname, run_id):
        self.calls.append("resolve")
        return await super().resolve_device(kind, value, hostname, run_id)

    async def bind_device(self, uid, kind, value, run_id):
        self.calls.append("bind")
        return await super().bind_device(uid, kind, value, run_id)


async def test_a_collector_thread_asks_the_store_once_per_identifier_and_run():
    store = _Counting()
    resolver = await glue.StoreResolver.open(store, run_id=7)

    first = await asyncio.to_thread(resolver.resolve_device, "serial", "FOC1234ABCD", "core1")
    again = await asyncio.to_thread(resolver.resolve_device, "serial", "foc1234abcd", "core9")
    await asyncio.to_thread(resolver.bind_device, first, "serial", "FOC5678EFGH")
    await asyncio.to_thread(resolver.bind_device, first, "serial", "FOC5678EFGH")

    assert first == again == "dev:core1"
    assert store.calls == ["resolve", "bind"]
    assert {(r.value, r.first_run_id) for r in await store.device_identities()} == {
        ("foc1234abcd", 7),
        ("foc5678efgh", 7),
    }


async def test_the_loop_thread_cannot_wait_on_itself():
    resolver = await glue.StoreResolver.open(FakeStore())

    with pytest.raises(RuntimeError, match="own event loop"):
        resolver.resolve_device("serial", "FOC1234ABCD", "core1")


async def test_the_generation_is_read_when_the_resolver_opens():
    store = FakeStore()
    await store.resolve_device("serial", "FOC1234ABCD", "core1", 1)
    await store.rekey_device("dev:core1", "dev:core2")

    resolver = await glue.StoreResolver.open(store)

    assert resolver.identity_generation() == 1


async def test_every_collector_of_the_run_gets_the_registry_bound_to_the_run():
    collector = SimpleNamespace(identity=MemoryResolver())
    stand_in = SimpleNamespace()
    units = [SimpleNamespace(collector=c) for c in (collector, stand_in, None)]

    await runs_exec._arm_identity(FakeStore(), [SimpleNamespace(units=units)], 42)

    assert isinstance(collector.identity, glue.StoreResolver)
    assert collector.identity.run_id == 42
    # a seam test's stand-in collector has no slot for it
    assert not hasattr(stand_in, "identity")


async def test_the_registry_snapshot_reads_the_store_and_never_writes_to_it():
    store = FakeStore()
    await store.resolve_device("serial", "FOC1234ABCD", "core1", 1)
    await store.rekey_device("dev:core1", "dev:renamed")

    snapshot = await glue.registry_snapshot(store)

    assert snapshot.resolve_device("serial", "FOC1234ABCD", "core1") == "dev:renamed"
    assert snapshot.resolve_device("serial", "FOC9999WXYZ", "core1") == "dev:core1"
    assert snapshot.identity_generation() == 1
    assert [r.uid for r in await store.device_identities()] == ["dev:renamed"]
