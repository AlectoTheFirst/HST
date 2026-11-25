"""Both destructive paths compare their target with the configured live URI by server (`same_endpoint`)."""

import pytest
from typer.testing import CliRunner

from hst.cli import app
from hst.core import db as dbmod
from hst.core.db import resolves, same_endpoint

runner = CliRunner()


@pytest.fixture
def resolver(monkeypatch):
    """Name resolution of `core/db.py` from a table."""
    table: dict[str, list[str]] = {"localhost": ["127.0.0.1", "::1"]}
    monkeypatch.setattr(dbmod, "_resolve", lambda host: table.get(host, []))
    return table


class TestSameEndpoint:
    def test_loopback_spellings_are_the_same_server(self):
        assert same_endpoint("bolt://localhost:7688", "bolt://127.0.0.1:7688")
        assert same_endpoint("bolt://[::1]:7688", "bolt://localhost:7688")

    def test_scheme_is_ignored(self):
        # bolt, neo4j and their +s variants all reach the same server
        assert same_endpoint("neo4j://twin.example:7687", "bolt://twin.example:7687")
        assert same_endpoint("neo4j+s://twin.example", "bolt://twin.example:7687")

    def test_the_default_port_is_implied(self):
        assert same_endpoint("bolt://host", "bolt://host:7687")

    def test_a_different_port_is_a_different_server(self):
        assert not same_endpoint("bolt://localhost:7688", "bolt://localhost:7687")

    def test_a_different_host_is_a_different_server(self):
        assert not same_endpoint("bolt://a.example", "bolt://b.example")

    def test_an_unparseable_uri_matches_nothing(self):
        assert not same_endpoint("", "bolt://x")
        assert not same_endpoint("://", "bolt://x")
        assert not same_endpoint("bolt://x:99999", "bolt://x:99999")

    def test_a_trailing_dot_is_the_same_host(self):
        assert same_endpoint("bolt://twin.example.:7687", "bolt://twin.example:7687")

    def test_two_names_with_a_common_address_are_the_same_server(self, resolver):
        resolver.update({"neo4j": ["172.18.0.3"], "hst-neo4j-1": ["172.18.0.3", "fd00::3"]})
        assert same_endpoint("bolt://hst-neo4j-1:7687", "bolt://neo4j:7687")

    def test_an_address_of_the_host_is_the_same_server(self, resolver):
        resolver.update({"neo4j": ["172.18.0.3"], "172.18.0.3": ["172.18.0.3"]})
        assert same_endpoint("bolt://172.18.0.3:7687", "bolt://neo4j:7687")

    def test_an_ipv4_mapped_address_is_its_ipv4_address(self, resolver):
        resolver.update({"neo4j": ["172.18.0.3"], "::ffff:172.18.0.3": ["::ffff:172.18.0.3"]})
        assert same_endpoint("bolt://[::ffff:172.18.0.3]:7687", "bolt://neo4j:7687")

    def test_two_names_with_no_common_address_are_different_servers(self, resolver):
        resolver.update({"neo4j": ["172.18.0.3"], "scratch": ["172.18.0.9"]})
        assert not same_endpoint("bolt://scratch:7687", "bolt://neo4j:7687")

    def test_a_name_that_does_not_resolve_matches_no_other_name(self, resolver):
        resolver.update({"neo4j": ["172.18.0.3"]})
        assert not same_endpoint("bolt://nowhere:7687", "bolt://neo4j:7687")
        assert not resolves("bolt://nowhere:7687")
        assert resolves("bolt://neo4j:7687")

    @pytest.mark.parametrize(
        "spelling",
        ["127.1", "0", "2130706433", "0x7f.0.0.1", "[::ffff:127.0.0.1]", "[::]", "localhost."],
    )
    def test_each_spelling_of_this_host_is_loopback(self, spelling):
        assert same_endpoint(f"bolt://{spelling}:7687", "bolt://localhost:7687")


def test_close_driver_closes_one_cached_driver_and_keeps_the_others(monkeypatch):
    from hst.core.config import Settings

    class Driver:
        closed = False

        def close(self):
            self.closed = True

    scratch, live = Driver(), Driver()
    target = Settings(_env_file=None, neo4j_uri="bolt://scratch:7999", neo4j_password="p")
    monkeypatch.setattr(
        dbmod,
        "_DRIVERS",
        {
            (target.neo4j_uri, target.neo4j_user, target.neo4j_password): scratch,
            ("bolt://live:7687", "neo4j", "p"): live,
        },
    )
    dbmod.close_driver(target)
    dbmod.close_driver(target)
    assert scratch.closed and not live.closed
    assert list(dbmod._DRIVERS) == [("bolt://live:7687", "neo4j", "p")]


class TestRebuildGuard:
    """These all exit before any database is touched."""

    def test_into_is_required_to_write(self):
        result = runner.invoke(app, ["rebuild", "--as-of", "2026-03-31"])
        assert result.exit_code == 2
        assert "--into is required" in result.stdout

    def test_an_unparseable_as_of_is_rejected(self):
        result = runner.invoke(app, ["rebuild", "--as-of", "not-a-date", "--into", "bolt://scratch:7687"])
        assert result.exit_code == 2
        assert "cannot parse --as-of" in result.stdout

    def test_the_live_twin_is_refused_in_every_spelling(self, monkeypatch):
        monkeypatch.setenv("NEO4J_URI", "bolt://localhost:7688")
        for spelling in (
            "bolt://localhost:7688",
            "bolt://127.0.0.1:7688",
            "neo4j://localhost:7688",
        ):
            result = runner.invoke(app, ["rebuild", "--as-of", "2026-03-31", "--into", spelling])
            assert result.exit_code == 2, f"{spelling} was not refused"
            assert "is the live twin" in result.stdout, spelling

    def test_a_scratch_target_gets_past_the_guard(self, monkeypatch, tmp_path):
        monkeypatch.setenv("NEO4J_URI", "bolt://localhost:7688")
        monkeypatch.setenv("HST_DATA_DIR", str(tmp_path))
        result = runner.invoke(app, ["rebuild", "--as-of", "2026-03-31", "--into", "bolt://scratch:7999"])
        assert result.exit_code == 1
        assert "no snapshots" in result.stdout
