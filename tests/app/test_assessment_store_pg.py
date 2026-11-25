"""HST_TEST_PG_DSN names a disposable database, never the live twin."""

import asyncio
import os

import pytest

pytestmark = pytest.mark.pg
DSN = os.environ.get("HST_TEST_PG_DSN")
if not DSN:
    pytest.skip("HST_TEST_PG_DSN not set", allow_module_level=True)

from tests.app.test_assessment_store import (  # noqa: E402, F401
    test_actor_admission_is_atomic_and_bounded,
    test_assessment_revisions_preserve_ordered_intents_and_old_run,
    test_cancel_queued_and_running_cannot_complete_search,
    test_dependency_invalidation_includes_absent_selectors_and_deduplicates,
    test_engine_and_freshness_expiry_are_separate_from_historical_result,
    test_exact_dedup_and_explicit_retry_keep_original_results,
    test_expired_workers_exhaust_three_attempts_and_cancelled_leases_are_reaped,
    test_first_inflight_run_and_later_historical_retry_remain_stale,
    test_invalid_inputs_roll_back_and_documents_are_bounded,
    test_late_completion_does_not_clear_publication_or_revision_invalidation,
    test_lease_recovery_fences_crashed_worker_and_preserves_checkpoint,
    test_revisions_are_immutable_and_concurrent_edits_are_fenced,
    test_unpinned_snapshots_and_oversize_results_are_rejected_atomically,
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
