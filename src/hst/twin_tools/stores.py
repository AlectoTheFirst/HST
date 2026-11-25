"""The app store as a catalogue tool body reads it.

`read_store` runs one coroutine against the app store. It uses the store on
the tool context, or a `PgStore` that it opens from the settings and disposes
of after the call. `store_error` maps a failed read to a `ToolError`. A store
that does not answer in time is `timeout`. A store that cannot be connected to
or read is `engine_unavailable`. Both errors are retryable.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from hst.app.ai.registry import ToolContext, ToolError


async def _with_store[T](ctx: ToolContext, work: Callable[[Any], Awaitable[T]]) -> T:
    store = ctx.store
    owned = store is None
    if store is None:
        from hst.app.store.pg import PgStore

        store = PgStore(ctx.settings.postgres_dsn, ctx.settings.postgres_ca_file)
    try:
        return await work(store)
    finally:
        if owned:
            await store.dispose()


def store_error(exc: BaseException) -> ToolError | None:
    """The `ToolError` of a store read that failed with `exc`, or None when
    `exc` is not a store failure.

    A store that does not answer in time is `timeout`. A store that cannot be
    connected to or read is `engine_unavailable`. Both errors are retryable.
    The message is redacted.
    """
    from hst.app.ai.redact import redact

    unavailable: tuple[type[BaseException], ...] = (OSError,)
    try:
        from sqlalchemy.exc import SQLAlchemyError
    except ImportError:
        pass
    else:
        unavailable = (OSError, SQLAlchemyError)
    if isinstance(exc, TimeoutError):
        return ToolError("timeout", "the app store did not answer in time", retryable=True)
    if isinstance(exc, unavailable):
        return ToolError(
            "engine_unavailable",
            redact(f"the app store could not be read: {type(exc).__name__}: {exc}"),
            retryable=True,
        )
    return None


def read_store[T](ctx: ToolContext, work: Callable[[Any], Awaitable[T]]) -> T:
    """The result of `work(store)`. A `ToolError` that `work` raises passes through."""
    try:
        return ctx.call_async(_with_store(ctx, work))
    except Exception as exc:
        error = store_error(exc)
        if error is None:
            raise
        raise error from None


def require(store: Any, method: str, what: str) -> None:
    """Raise `engine_unavailable` for a store that lacks `method`."""
    if not hasattr(store, method):
        raise ToolError("engine_unavailable", f"the app store keeps no {what}")
