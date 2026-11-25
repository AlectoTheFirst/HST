"""Crash injection: a crash during the pointer move
(core/cycle.py `set_pointer`), against a real Neo4j."""

from __future__ import annotations

import os

import pytest
from tests.crash.injectors import SimulatedCrash

from hst.core import cycle as cyclemod
from hst.core import db as dbmod
from hst.core.config import Settings

URI = os.environ.get("NEO4J_TEST_URI")

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set"),
]


def _refuse_if_live() -> None:
    live = Settings(_env_file=None).neo4j_uri
    if dbmod.same_endpoint(URI or "", live):
        pytest.exit(
            f"NEO4J_TEST_URI ({URI}) is the live twin ({live}). This suite deletes data. "
            f"Point it at a scratch database.",
            returncode=2,
        )


@pytest.fixture(scope="module")
def _driver():
    from neo4j import GraphDatabase

    _refuse_if_live()
    driver = GraphDatabase.driver(
        URI,
        auth=(os.environ.get("NEO4J_TEST_USER", "neo4j"), os.environ["NEO4J_TEST_PASSWORD"]),
    )
    with driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        dbmod.init_db(s)
    yield driver
    driver.close()


@pytest.fixture()
def session(_driver):
    with _driver.session(database=os.environ.get("NEO4J_TEST_DATABASE", "neo4j")) as s:
        _cleanup(s)
        yield s
        _cleanup(s)


def _cleanup(s) -> None:
    s.run("MATCH (p:CyclePointer {uid: $uid}) DETACH DELETE p", uid=cyclemod.POINTER_UID).consume()


def test_a_crash_after_the_pointer_write_commits_leaves_the_new_value_in_place(session, monkeypatch):
    cyclemod.set_pointer(session, 2_000)
    assert cyclemod.current_ts(session) == 2_000

    real_write = cyclemod._write

    def _write_then_crash(s, query, **params):
        real_write(s, query, **params)
        raise SimulatedCrash("crashed after the pointer write committed")

    monkeypatch.setattr(cyclemod, "_write", _write_then_crash)
    with pytest.raises(SimulatedCrash):
        cyclemod.set_pointer(session, 3_000)
    monkeypatch.undo()

    assert cyclemod.current_ts(session) == 3_000  # never absent, never torn


def test_a_crash_before_the_pointer_write_is_ever_sent_leaves_the_old_value_in_place(session, monkeypatch):
    cyclemod.set_pointer(session, 2_000)

    def _crash_before_write(s, query, **params):
        raise SimulatedCrash("crashed before the pointer write was ever sent")

    monkeypatch.setattr(cyclemod, "_write", _crash_before_write)
    with pytest.raises(SimulatedCrash):
        cyclemod.set_pointer(session, 3_000)
    monkeypatch.undo()

    assert cyclemod.current_ts(session) == 2_000  # never moved, never absent
