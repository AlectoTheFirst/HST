"""`RibSource.search_routes`: one address or prefix looked up in the route
table of every device, each device from the run the snapshot selects."""

import pytest

pytest.importorskip("pyarrow")

from tests.test_ribsource import _row

from hst.core import sidestore
from hst.core.ribsource import RibSource


def _on(device: str, row: dict) -> dict:
    return {**row, "device_uid": device}


@pytest.fixture
def store(tmp_path):
    pytest.importorskip("duckdb")
    # r1, older run: a /16 that the newer run no longer holds
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "",
        "1700000000000-aaaaaaaa",
        [_row("10.24.0.0/16", "10.0.0.9", "eth9")],
        1000,
    )
    sidestore.write_table(
        tmp_path,
        "rib",
        "nxos",
        "",
        "1700000001000-bbbbbbbb",
        [
            _row("0.0.0.0/0", "10.0.0.1", "eth0"),
            _row("10.24.0.0/14", "10.0.0.2", "eth1", "bgp"),
            _row("10.24.0.0/24", "10.0.0.3", "eth2", "bgp"),
        ],
        2000,
    )
    sidestore.write_table(
        tmp_path,
        "rib",
        "iosxe",
        "",
        "1700000002000-cccccccc",
        [
            _on("dev:r2", _row("0.0.0.0/0", "10.1.0.1", "Gi1")),
            _on("dev:r2", _row("10.0.0.0/8", "10.1.0.2", "Gi2")),
        ],
        2000,
    )
    return tmp_path


def _found(page):
    return [(r["device_uid"], r["prefix"]) for r in page.rows]


def test_an_address_answers_each_table_s_match_and_the_routes_for_its_network(store):
    page = RibSource(store).search_routes("10.24.0.0")

    # r1 uses the /24, and also holds the /14 for the same network; r2 uses its /8.
    # Neither default route is listed: every table has one.
    assert _found(page) == [("dev:r1", "10.24.0.0/24"), ("dev:r1", "10.24.0.0/14"), ("dev:r2", "10.0.0.0/8")]
    assert page.total == 3


def test_an_address_inside_a_network_answers_the_longest_match_only(store):
    assert _found(RibSource(store).search_routes("10.24.3.7")) == [
        ("dev:r1", "10.24.0.0/14"),
        ("dev:r2", "10.0.0.0/8"),
    ]


def test_a_prefix_answers_the_routes_for_exactly_that_prefix(store):
    assert _found(RibSource(store).search_routes("10.24.0.0/14")) == [("dev:r1", "10.24.0.0/14")]


def test_each_device_answers_from_its_selected_run_only(store):
    assert ("dev:r1", "10.24.0.0/16") not in _found(RibSource(store).search_routes("10.24.0.0/16"))
    assert RibSource(store, as_of_ms=1000).search_routes("10.24.0.0/16").rows[0]["next_hop"] == "10.0.0.9"


def test_text_that_is_no_address_answers_nothing(store):
    assert RibSource(store).search_routes("fw-fra-01").rows == []


def test_the_limit_keeps_the_longest_prefixes(store):
    page = RibSource(store).search_routes("10.24.0.0", limit=1)
    assert _found(page) == [("dev:r1", "10.24.0.0/24")]
    assert page.total == 3
