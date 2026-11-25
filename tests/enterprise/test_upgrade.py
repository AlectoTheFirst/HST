import importlib

import pytest

from hst.analysis_model.upgrade import migration_dry_run
from hst.app.store.pg import metadata

RUNTIME = {
    "semantic_version": "2",
    "header_schema": "headers-v1",
    "ordering_version": "order-v1",
    "backend": "dd.cudd",
    "backend_version": "0.6.0",
    "build_identity": "wheel-sha256",
}


@pytest.mark.parametrize("revision", ["", "0022", "0026", "head", "23"])
def test_unqualified_schema_revision_cannot_produce_an_incomplete_upgrade_plan(revision):
    with pytest.raises(ValueError, match="requires schema revision"):
        migration_dry_run(current_revision=revision, runtime=RUNTIME)


def test_cache_migrations_are_chained_and_metadata_matches():
    revision_24 = importlib.import_module("hst.app.store.migrations.versions.0024_analysis_cache")
    revision_25 = importlib.import_module("hst.app.store.migrations.versions.0025_analysis_cache_leases")

    assert (revision_24.revision, revision_24.down_revision) == ("0024", "0023")
    assert (revision_25.revision, revision_25.down_revision) == ("0025", "0024")
    assert {
        "analysis_cache_artifacts",
        "analysis_cache_leases",
    } <= set(metadata.tables)


def test_additive_0024_0025_report_preserves_results_and_invalidates_old_cache():
    report = migration_dry_run(
        current_revision="0023",
        runtime=RUNTIME,
        cache_bindings=[{"key": "old", **RUNTIME, "backend_version": "0.5.7"}],
        saved_results=[
            {"identity": "v1", "engine": "legacy-v1", "engine_version": "1"},
            {"identity": "v2", "engine": "symbolic-v2", "engine_version": "2"},
        ],
        database_read_only=True,
        artifact_store_read_only=True,
        offline_runtime_ready=True,
    )

    assert report["schema"]["pending"] == ("0024", "0025")
    assert report["schema"]["actions"] == (
        "create analysis_cache_artifacts",
        "create analysis_cache_leases",
    )
    assert report["schema"]["can_apply"] is False
    assert report["cache"]["entries"][0] == {
        "key": "old",
        "action": "invalidate",
        "reasons": ("backend_version",),
    }
    assert report["cache"]["writable"] is False
    assert report["saved_results"]["mutated"] is False
    assert report["saved_results"]["entries"][0]["downgrade"] == "readable-by-v1"
    assert report["saved_results"]["entries"][1]["downgrade"] == "preserve-unreadable"
    assert report["runtime"]["offline_ready"] is True


def test_exact_runtime_binding_retains_cache_and_current_schema_serves_read_only():
    report = migration_dry_run(
        current_revision="0025",
        runtime=RUNTIME,
        cache_bindings=[{"key": "exact", **RUNTIME}],
        database_read_only=True,
        artifact_store_read_only=True,
    )

    assert report["schema"]["pending"] == ()
    assert report["schema"]["can_apply"] is False
    assert report["cache"]["entries"][0]["action"] == "retain"
    assert report["runtime"]["read_only_serving"] is True
