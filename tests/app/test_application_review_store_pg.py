"""Review flags of Business Applications against disposable Postgres."""

import asyncio
import os
import uuid

import pytest

pytestmark = pytest.mark.pg
DSN = os.environ.get("HST_TEST_PG_DSN")
if not DSN:
    pytest.skip("HST_TEST_PG_DSN not set", allow_module_level=True)

from tests.app.test_application_review_store import (  # noqa: E402, F401
    test_a_flag_opens_once_and_closes_once,
    test_bound_sessions_hold_connection_and_simulation_sessions_of_the_application,
    test_bound_sessions_hold_the_newest_session_revision,
    test_concurrent_opens_leave_one_open_flag,
    test_the_history_lists_the_flags_of_an_application_newest_first,
)

from hst.app.store.pg import PgStore, application_reviews, assessment_records, upgrade_to_head  # noqa: E402


@pytest.fixture
async def store():
    await asyncio.to_thread(upgrade_to_head, DSN)
    instance = PgStore(DSN)
    async with instance._engine.begin() as connection:
        await connection.execute(application_reviews.delete())
        await connection.execute(assessment_records.delete())
    try:
        yield instance
    finally:
        await instance.dispose()


@pytest.fixture
async def users(store):
    """The ids of 2 users created for the test."""
    suffix = uuid.uuid4().hex[:8]
    ada = await store.create_user(f"ada-{suffix}", "h", "operator")
    bob = await store.create_user(f"bob-{suffix}", "h", "operator")
    return ada.id, bob.id
