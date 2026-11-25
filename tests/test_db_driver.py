"""Driver lifetime."""

from __future__ import annotations

import pytest

from hst.core import db as dbmod
from hst.core.config import Settings


class FakeDriver:
    instances = 0

    def __init__(self, uri, **kw):
        FakeDriver.instances += 1
        self.uri = uri
        self.closed = False
        self.sessions = 0
        self.session_kwargs: list[dict] = []

    def session(self, **kw):
        self.sessions += 1
        self.session_kwargs.append(kw)
        return _Ctx()

    def close(self):
        self.closed = True


class _Ctx:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch):
    """The driver cache is process-global."""
    dbmod.close_drivers()
    FakeDriver.instances = 0
    monkeypatch.setattr(dbmod.GraphDatabase, "driver", lambda uri, **kw: FakeDriver(uri, **kw))
    yield
    dbmod.close_drivers()


def _settings(**kw):
    return Settings(_env_file=None, **kw)


def test_the_driver_is_built_once_and_reused():
    s = _settings()
    first = dbmod.get_driver(s)
    for _ in range(50):
        assert dbmod.get_driver(s) is first
    assert FakeDriver.instances == 1


def test_a_session_does_not_close_the_driver():
    s = _settings()
    with dbmod.session(s):
        pass
    with dbmod.session(s):
        pass
    driver = dbmod.get_driver(s)
    assert driver.closed is False
    assert driver.sessions == 2
    assert FakeDriver.instances == 1


def test_different_connection_parameters_get_different_drivers():
    a = dbmod.get_driver(_settings(neo4j_uri="bolt://one:7687"))
    b = dbmod.get_driver(_settings(neo4j_uri="bolt://two:7687"))
    assert a is not b
    assert FakeDriver.instances == 2

    c = dbmod.get_driver(_settings(neo4j_password="other"))
    assert c is not dbmod.get_driver(_settings())
    assert FakeDriver.instances == 4


def test_the_database_name_selects_a_session_not_a_driver():
    """Two databases on one server share a connection pool."""
    a = dbmod.get_driver(_settings(neo4j_database="neo4j"))
    b = dbmod.get_driver(_settings(neo4j_database="scratch"))
    assert a is b
    assert FakeDriver.instances == 1


def test_close_drivers_empties_the_cache():
    driver = dbmod.get_driver(_settings())
    dbmod.close_drivers()
    assert driver.closed is True
    assert dbmod.get_driver(_settings()) is not driver


def test_close_drivers_survives_a_driver_that_will_not_close():
    class Stubborn(FakeDriver):
        def close(self):
            raise RuntimeError("connection already gone")

    dbmod._DRIVERS[("x", "y", "z")] = Stubborn("bolt://x")
    dbmod.close_drivers()  # must not raise; a dead driver has nothing to salvage
    assert dbmod._DRIVERS == {}


def test_a_session_without_an_access_mode_leaves_the_driver_default():
    s = _settings(neo4j_database="scratch")
    with dbmod.session(s):
        pass
    assert dbmod.get_driver(s).session_kwargs == [{"database": "scratch"}]


def test_a_read_session_passes_its_access_mode_to_the_driver():
    s = _settings(neo4j_database="scratch")
    with dbmod.session(s, access_mode="READ"):
        pass
    assert dbmod.get_driver(s).session_kwargs == [{"database": "scratch", "default_access_mode": "READ"}]
