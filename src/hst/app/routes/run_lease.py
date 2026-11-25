"""The reader lease a route holds on the runs it reads."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Iterable, Iterator
from typing import Any

import anyio.from_thread
from fastapi import HTTPException, Request


def _lease(request: Request, keys: Iterable[int | None]) -> Any:
    wanted = sorted({int(k) for k in keys if k is not None})
    store = getattr(request.app.state, "store", None)
    lease = getattr(store, "lease_run", None)
    if lease is None or not wanted:
        return None
    return lease(wanted)


@contextlib.contextmanager
def leased(request: Request, keys: Iterable[int | None]) -> Iterator[None]:
    """Hold a lease on the runs a request reads, for the length of the block.

    The function is for a route that runs on a worker thread. The coroutines of
    the store run on the event loop through `anyio.from_thread`. No lease is held
    when the app state has no store or the store keeps no leases.
    """
    manager = _lease(request, keys)
    if manager is None:
        yield
        return
    anyio.from_thread.run(manager.__aenter__)
    try:
        yield
    finally:
        anyio.from_thread.run(manager.__aexit__, None, None, None)


@contextlib.asynccontextmanager
async def aleased(request: Request, keys: Iterable[int | None]) -> AsyncIterator[None]:
    """`leased` for a route that runs on the event loop."""
    manager = _lease(request, keys)
    if manager is None:
        yield
        return
    async with manager:
        yield


@contextlib.contextmanager
def reading(request: Request, s: Any, snap: Any) -> Iterator[None]:
    """Lease the run of `snap` for the block and fail with a 409 if it was pruned.

    A prune deletes a run's `:CycleRun` node before its objects. A run whose node
    existed before the lease and is gone inside it, before or after the read,
    was pruned by a turn that took its decision without the lease, and what was
    read from it is partial. A graph with no run node (a fixture load) is read
    as it is.
    """
    cts = getattr(snap, "cts", None)
    if cts is None:
        yield
        return
    # The import is deferred. The HST map routes import this module and load no graph client.
    from hst.core import cycle as cyclemod

    present = cyclemod.run_present(s, cts)

    def check() -> None:
        if present and not cyclemod.run_present(s, cts):
            raise HTTPException(409, detail=f"run {cts} was pruned while it was read")

    with leased(request, [cts]):
        check()
        yield
        check()
