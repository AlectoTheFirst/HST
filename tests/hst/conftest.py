"""A scratch Neo4j for the HST database tests, and the fixtures loaded into it as runs."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from hst.core.fixtures import load_fixture
from hst.core.model import Batch

URI = os.environ.get("NEO4J_TEST_URI")
FIXTURES = sorted((Path(__file__).parents[2] / "fixtures").glob("*.yaml"))


@pytest.fixture(scope="module")
def neo4j_session() -> Iterator[Any]:
    from neo4j import GraphDatabase

    from hst.core import db as dbmod
    from hst.core.config import Settings

    if not URI:
        pytest.skip("NEO4J_TEST_URI not set")
    live = Settings(_env_file=None).neo4j_uri
    if dbmod.same_endpoint(URI, live):
        pytest.exit(
            f"NEO4J_TEST_URI ({URI}) is the live twin ({live}); use a scratch database.", returncode=2
        )
    driver = GraphDatabase.driver(
        URI,
        auth=(os.environ.get("NEO4J_TEST_USER", "neo4j"), os.environ["NEO4J_TEST_PASSWORD"]),
        notifications_min_severity="OFF",
    )
    with driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        dbmod.init_db(s)
        yield s
    driver.close()


def fixture_batches(edit: Callable[[Batch], None] | None = None) -> list[Batch]:
    batches = [load_fixture(path) for path in FIXTURES]
    if edit is not None:
        for batch in batches:
            edit(batch)
    return batches


def load_runs(session: Any, runs: Sequence[int], batches: Callable[[int], list[Batch]]) -> None:
    """Load the batches of each run under its key, after removing anything stamped with those keys."""
    from hst.core.loader import load

    drop_runs(session, runs)
    for index, cts in enumerate(runs):
        for i, batch in enumerate(batches(index)):
            load(session, batch, ts_ms=cts + i, run_id=f"hst-test-{cts}-{i}", collection_ts=cts)


def drop_runs(session: Any, runs: Sequence[int]) -> None:
    session.run("MATCH (n:Obj) WHERE n.collection_ts IN $runs DETACH DELETE n", runs=list(runs)).consume()
