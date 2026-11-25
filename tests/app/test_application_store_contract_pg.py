"""The Business Application and Analysis session store contract against a
disposable Postgres (the tests of `test_application_store_contract.py`)."""

import asyncio
import os

import pytest

pytestmark = pytest.mark.pg
DSN = os.environ.get("HST_TEST_PG_DSN")
if not DSN:
    pytest.skip("HST_TEST_PG_DSN not set", allow_module_level=True)

from tests.app.test_application_store_contract import (  # noqa: E402, F401
    test_a_failed_transaction_leaves_no_partial_write,
    test_a_stale_preview_conflicts_and_writes_nothing,
    test_an_explicit_removal_is_previewed_and_committed,
    test_an_old_revision_exports_exactly_after_a_newer_one,
    test_analysis_session_revisions_are_immutable_fenced_and_listed_newest,
    test_concurrent_commits_of_one_preview_write_one_revision,
    test_generations_are_stored_once,
    test_import_commits_once_and_an_unchanged_import_is_a_no_op,
    test_preview_writes_nothing,
    test_resolutions_are_keyed_by_digest_and_never_overwritten,
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
