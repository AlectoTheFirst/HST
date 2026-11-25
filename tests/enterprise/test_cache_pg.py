"""Transactional cache-index behavior against disposable Postgres only."""

import asyncio
import os
import time

import pytest

pytestmark = pytest.mark.pg
DSN = os.environ.get("HST_TEST_PG_DSN")
if not DSN:
    pytest.skip("HST_TEST_PG_DSN not set", allow_module_level=True)

from hst.analysis_model.cache import CacheError, CacheRecord, PgCacheIndex  # noqa: E402
from hst.app.store.pg import PgStore, analysis_cache_artifacts, upgrade_to_head  # noqa: E402


def test_publication_is_immutable_and_leases_fence_eviction():
    async def scenario():
        await asyncio.to_thread(upgrade_to_head, DSN)
        store = PgStore(DSN)
        try:
            async with store._engine.begin() as connection:
                await connection.execute(analysis_cache_artifacts.delete())
            index = PgCacheIndex(store._engine)
            now = time.time()
            record = CacheRecord("1" * 64, "2" * 64, "2.artifact", 100, now, now)
            await index.publish(record)
            held = await index.acquire(record.key)
            assert held and held.record.lease_count == 1
            assert await index.delete(record.key, record.artifact_sha256) is False
            await index.release(record.key, held.token)
            with pytest.raises(CacheError, match="not held"):
                await index.release(record.key, held.token)
            assert await index.delete(record.key, record.artifact_sha256) is True
            await index.publish(record)
            with pytest.raises(CacheError, match="cannot identify"):
                await index.publish(CacheRecord(record.key, "3" * 64, "3.artifact", 100, now, now))
        finally:
            await store.dispose()

    asyncio.run(scenario())
