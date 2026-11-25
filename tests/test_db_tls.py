"""Neo4j TLS config: `neo4j_tls_ca_file`
producing `TrustCustomCAs` + `encrypted=True`, the `+s`/`+ssc` fail-fast, and the
plaintext-to-remote warning. No live database; `GraphDatabase.driver` is mocked.
"""

from __future__ import annotations

import logging
import re

import pytest
from neo4j import TrustCustomCAs

from hst.core import db as dbmod
from hst.core.config import Settings


class FakeDriver:
    def __init__(self, uri, **kw):
        self.uri = uri
        self.kw = kw

    def close(self):
        pass


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch):
    """The driver cache is process-global."""
    dbmod.close_drivers()
    calls: list[tuple[str, dict]] = []

    def fake_driver(uri, **kw):
        calls.append((uri, kw))
        return FakeDriver(uri, **kw)

    monkeypatch.setattr(dbmod.GraphDatabase, "driver", fake_driver)
    yield calls
    dbmod.close_drivers()


def _settings(**kw):
    return Settings(_env_file=None, **kw)


def test_ca_file_passes_trusted_certificates_and_encrypted(tmp_path, _isolated_cache):
    ca = tmp_path / "ca.pem"
    ca.write_text("not a real cert, only the path is used")

    dbmod.get_driver(_settings(neo4j_uri="bolt://db.internal:7687", neo4j_tls_ca_file=str(ca)))

    ((uri, kw),) = _isolated_cache
    assert uri == "bolt://db.internal:7687"
    assert kw["encrypted"] is True
    assert isinstance(kw["trusted_certificates"], TrustCustomCAs)


def test_ca_file_works_with_bare_neo4j_scheme_too(tmp_path, _isolated_cache):
    ca = tmp_path / "ca.pem"
    ca.write_text("placeholder")

    dbmod.get_driver(_settings(neo4j_uri="neo4j://db.internal:7687", neo4j_tls_ca_file=str(ca)))

    ((_, kw),) = _isolated_cache
    assert kw["encrypted"] is True


@pytest.mark.parametrize("scheme", ["bolt+s", "bolt+ssc", "neo4j+s", "neo4j+ssc"])
def test_ca_file_with_secure_scheme_fails_fast(tmp_path, scheme, _isolated_cache):
    ca = tmp_path / "ca.pem"
    ca.write_text("placeholder")

    pattern = re.escape(scheme)
    with pytest.raises(ValueError, match=rf"{pattern}.*neo4j_tls_ca_file|neo4j_tls_ca_file.*{pattern}"):
        dbmod.get_driver(_settings(neo4j_uri=f"{scheme}://db.internal:7687", neo4j_tls_ca_file=str(ca)))
    assert _isolated_cache == []  # failed before the driver was ever built


def test_plaintext_to_remote_host_warns(caplog, _isolated_cache):
    with caplog.at_level(logging.WARNING, logger="hst.core.db"):
        dbmod.get_driver(_settings(neo4j_uri="bolt://db.internal:7687"))

    assert any("db.internal" in r.message and "cleartext" in r.message for r in caplog.records)


def test_plaintext_to_loopback_stays_silent(caplog, _isolated_cache):
    with caplog.at_level(logging.WARNING, logger="hst.core.db"):
        dbmod.get_driver(_settings(neo4j_uri="bolt://localhost:7687"))
        dbmod.get_driver(_settings(neo4j_uri="bolt://127.0.0.1:7687"))
        dbmod.get_driver(_settings(neo4j_uri="bolt://[::1]:7687"))

    assert caplog.records == []


def test_ca_file_to_remote_host_does_not_also_warn(tmp_path, caplog, _isolated_cache):
    """Once a CA file is configured the connection is encrypted, so the
    plaintext-to-remote warning must not also fire."""
    ca = tmp_path / "ca.pem"
    ca.write_text("placeholder")

    with caplog.at_level(logging.WARNING, logger="hst.core.db"):
        dbmod.get_driver(_settings(neo4j_uri="bolt://db.internal:7687", neo4j_tls_ca_file=str(ca)))

    assert caplog.records == []


def test_secure_scheme_without_ca_file_stays_silent(caplog, _isolated_cache):
    """+s already carries TLS, so a remote host on that scheme is not the plaintext
    case the warning is guarding against."""
    with caplog.at_level(logging.WARNING, logger="hst.core.db"):
        dbmod.get_driver(_settings(neo4j_uri="bolt+s://db.internal:7687"))

    assert caplog.records == []


def test_an_unresolvable_host_warns(caplog, _isolated_cache):
    """A host that does not resolve logs a warning that names it."""
    with caplog.at_level(logging.WARNING, logger="hst.core.db"):
        dbmod.get_driver(_settings(neo4j_uri="bolt://this-host-does-not-resolve.invalid:7687"))

    assert any("this-host-does-not-resolve.invalid" in r.message for r in caplog.records)
