"""Business Application revision contract against disposable Postgres."""

import asyncio
import os

import pytest

pytestmark = pytest.mark.pg
DSN = os.environ.get("HST_TEST_PG_DSN")
if not DSN:
    pytest.skip("HST_TEST_PG_DSN not set", allow_module_level=True)

from tests.app.test_business_application_store import (  # noqa: E402, F401
    test_application_analysis_sessions_are_found_by_application_id,
    test_application_revisions_are_immutable_noop_and_concurrency_fenced,
    test_revisions_record_their_origin_and_a_validation_for_another_definition_is_rejected,
    test_validation_records_are_keyed_by_the_digest_of_their_content,
)

from hst.app.store.pg import PgStore, assessment_records, upgrade_to_head  # noqa: E402


@pytest.fixture
async def store():
    await asyncio.to_thread(upgrade_to_head, DSN)
    instance = PgStore(DSN)
    async with instance._engine.begin() as connection:
        await connection.execute(assessment_records.delete())
    try:
        yield instance
    finally:
        await instance.dispose()
