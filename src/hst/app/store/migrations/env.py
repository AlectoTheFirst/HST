"""Alembic environment with an async engine.

`upgrade_to_head()` injects the URL and the script location.
"""

import asyncio

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

from hst.app.store.pg import metadata, pg_ssl_engine_kwargs


def _run(connection) -> None:
    context.configure(connection=connection, target_metadata=metadata)
    with context.begin_transaction():
        context.run_migrations()


# A 64-bit constant, the same in every process that migrates.
MIGRATION_LOCK = 8_071_552_014_921_337


async def _run_async() -> None:
    # config.attributes holds the CA file.
    url = context.config.get_main_option("sqlalchemy.url")
    ca_file = context.config.attributes.get("postgres_ca_file", "")
    engine = create_async_engine(url, **pg_ssl_engine_kwargs(ca_file))  # type: ignore[arg-type]
    # The lock uses its own connection.
    async with engine.connect() as lock_conn:
        await lock_conn.exec_driver_sql(f"SELECT pg_advisory_lock({MIGRATION_LOCK})")
        try:
            async with engine.connect() as conn:
                await conn.run_sync(_run)
        finally:
            # lock_conn returns to the pool.
            await lock_conn.exec_driver_sql(f"SELECT pg_advisory_unlock({MIGRATION_LOCK})")
    await engine.dispose()


if context.is_offline_mode():
    context.configure(
        url=context.config.get_main_option("sqlalchemy.url"), target_metadata=metadata, literal_binds=True
    )
    with context.begin_transaction():
        context.run_migrations()
else:
    asyncio.run(_run_async())
