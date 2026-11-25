"""Manual target-estate acceptance against the shared scratch Neo4j."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from hst.bench import run_estate_acceptance
from hst.core.config import Settings

pytestmark = [
    pytest.mark.perf,
    pytest.mark.db,
    pytest.mark.skipif(
        os.environ.get("HST_ESTATE_ACCEPTANCE") != "1",
        reason="HST_ESTATE_ACCEPTANCE not set",
    ),
]


def test_target_estate_ingest_history_queries_retention_and_restore(tmp_path):
    devices = int(os.environ["HST_ESTATE_DEVICES"])
    runs = int(os.environ.get("HST_ESTATE_RUNS", "3"))
    rib_rows = int(os.environ.get("HST_ESTATE_RIB_ROWS", "1000"))
    peers = int(os.environ.get("HST_ESTATE_PEERS", "2"))
    paths = int(os.environ.get("HST_ESTATE_PATHS", "500"))
    output = Path(os.environ["HST_ESTATE_RESULT"])
    settings = Settings(
        _env_file=None,
        hst_data_dir=tmp_path,
        neo4j_uri=os.environ["NEO4J_TEST_URI"],
        neo4j_user=os.environ.get("NEO4J_TEST_USER", "neo4j"),
        neo4j_password=os.environ["NEO4J_TEST_PASSWORD"],
        neo4j_database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j"),
    )
    result = run_estate_acceptance(
        settings=settings,
        devices=devices,
        runs=runs,
        rib_rows=rib_rows,
        peers=peers,
        paths=paths,
        output=output,
    )

    tables_per_device = 3
    rows_per_device_run = rib_rows + peers * paths + peers
    assert result.estate.files == devices * runs * tables_per_device
    assert result.estate.rows == devices * runs * rows_per_device_run
    assert result.estate.lpm_matched == 1
    assert result.manifest_lpm_matched == 1
    assert result.graph_nodes_written == devices * runs * (1 + peers)
    assert result.graph_rels_written == devices * runs * peers
    assert len(result.retention_deleted) == 1
    assert result.restored_nodes == devices * (1 + peers)
    assert result.restored_rels == devices * peers
    assert result.sample_answers == {
        "devices": devices,
        "sessions": devices * peers,
        "links": devices * peers,
    }
    assert output.is_file()
