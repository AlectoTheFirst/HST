"""`rib_mirrored` on a VyOS VrfInstance: the graph holds the whole RIB of that
table, so a forwarding static there without `rib_confirmed` is one the device
did not install. True only where every read that
feeds the table succeeded and the table is at or under the mirror limit."""

import json

from tests.test_vyos import CONFIG, LINKS, VERSION, _nh, _route

from hst.collectors.base import RAW_OUTCOMES_KEY
from hst.collectors.vyos import normalize_vyos

MAIN = "vrf:dev:gw:default"
T100 = "vrf:dev:gw:table100"
OK = {"status": "ok"}
READS = ("routes", "routes6", "routes_table_100", "routes6_table_100")


def _batch(
    routes=None, routes6=None, tables=None, tables6=None, outcomes=None, max_routes=1000, cfg_patch=None
):
    """CONFIG (a next-hop static 10.99.0.0/24 in main, wg0/wg1 defaults in
    policy table 100) with an FRR RIB and the outcomes a fetch records."""
    cfg = json.loads(json.dumps(CONFIG))
    if cfg_patch:
        cfg_patch(cfg)
    raw = {
        "config": cfg,
        "version_text": VERSION,
        "links": LINKS,
        "routes": {"default": routes or {}} if not isinstance(routes, str) else routes,
        "routes6": {"default": routes6 or {}},
        "routes_tables": tables if tables is not None else {"100": {}},
        "routes6_tables": tables6 if tables6 is not None else {"100": {}},
    }
    if outcomes is not False:
        raw[RAW_OUTCOMES_KEY] = outcomes if outcomes is not None else dict.fromkeys(READS, OK)
    return normalize_vyos(raw, l3dom="home", rib_graph_max_routes=max_routes)


def _mirrored(batch):
    return {n.uid: n.props.get("rib_mirrored") for n in batch.nodes if n.label == "VrfInstance"}


# the main table holds only the default by pppoe-like eth0
DEFAULT = _route("0.0.0.0/0", _nh(ip="203.0.113.1", dev="eth0"), protocol="kernel")
T100_ROWS = {"100": _route("0.0.0.0/0", _nh(dev="wg0"), _nh(dev="wg1"), table=100)}


def test_a_table_read_in_full_under_the_limit_is_mirrored():
    batch = _batch(routes=DEFAULT, tables=T100_ROWS)
    assert _mirrored(batch) == {MAIN: True, T100: True}
    # and the static the RIB does not hold carries no confirmation, which is
    # what the tracer reads as not installed in a mirrored table
    [static] = [r for r in batch.rels if r.rel_type == "STATIC_ROUTE" and r.end_uid.endswith(":10.99.0.0/24")]
    assert static.start_uid == MAIN and "rib_confirmed" not in static.props


def test_an_installed_static_is_confirmed_in_a_mirrored_table():
    """The normal case stays decided: the static FRR installed is folded and
    confirmed, so a mirrored table does not make it read as not installed."""
    routes = {**DEFAULT, **_route("10.99.0.0/24", _nh(ip="192.168.1.2", dev="eth1"))}
    batch = _batch(routes=routes, tables=T100_ROWS)
    assert _mirrored(batch)[MAIN] is True
    statics = [r for r in batch.rels if r.rel_type == "STATIC_ROUTE" and r.start_uid in (MAIN, T100)]
    assert statics and all(r.props.get("rib_confirmed") is True for r in statics)


def test_an_empty_answer_for_a_family_the_table_routes_statically_is_not_mirrored():
    """Table 100 read ok and empty while the configuration routes IPv4 into wg0
    and wg1 there: a tunnel that is down and an answer zebra gave empty read
    the same, so the empty table is no evidence that the statics are not
    installed."""
    batch = _batch(routes=DEFAULT)
    assert _mirrored(batch) == {MAIN: True, T100: False}


def test_an_empty_answer_of_a_family_with_no_static_in_the_table_is_a_full_read():
    batch = _batch(routes=DEFAULT, tables=T100_ROWS)
    assert _mirrored(batch) == {MAIN: True, T100: True}


def test_an_empty_family_answer_beside_a_static_of_that_family_is_not_mirrored():
    def patch(cfg):
        cfg["protocols"]["static"]["route6"] = {"2001:db8:99::/48": {"next-hop": {"2001:db8:1::2": {}}}}

    batch = _batch(routes=DEFAULT, tables=T100_ROWS, cfg_patch=patch)
    assert _mirrored(batch) == {MAIN: False, T100: True}
    # with an IPv6 row in main the read holds the family, and the static the
    # RIB does not hold may read not installed
    v6 = _route("::/0", _nh(ip="2001:db8:1::1", dev="eth0"), protocol="kernel")
    raw_batch = _batch(routes=DEFAULT, routes6=v6, tables=T100_ROWS, cfg_patch=patch)
    assert _mirrored(raw_batch) == {MAIN: True, T100: True}


def test_policy_table_rows_without_their_table_field_are_not_mirrored():
    """The table 100 answer's routes carry no `table`."""
    rows = _route("0.0.0.0/0", _nh(dev="wg0"), _nh(dev="wg1"), table=100)
    del rows["0.0.0.0/0"][0]["table"]
    batch = _batch(routes=DEFAULT, tables={"100": rows})
    assert _mirrored(batch) == {MAIN: False, T100: False}


def test_a_policy_table_answer_of_an_unknown_shape_is_not_mirrored():
    batch = _batch(routes=DEFAULT, tables={"100": {"100": T100_ROWS["100"]}})
    assert _mirrored(batch) == {MAIN: True, T100: False}
    text = json.dumps({"100": T100_ROWS["100"]})
    batch = _batch(routes=DEFAULT, tables={"100": text})
    assert _mirrored(batch) == {MAIN: True, T100: False}


def test_a_table_over_the_limit_is_not_mirrored():
    routes = {**DEFAULT, **_route("10.1.0.0/16", _nh(ip="203.0.113.1", dev="eth0"), protocol="bgp")}
    batch = _batch(routes=routes, tables=T100_ROWS, max_routes=1)
    assert _mirrored(batch) == {MAIN: False, T100: False}


def test_a_failed_read_of_one_family_leaves_the_table_not_mirrored():
    outcomes = {**dict.fromkeys(READS, OK), "routes6": {"status": "failed", "detail": "timeout"}}
    batch = _batch(routes=DEFAULT, tables=T100_ROWS, outcomes=outcomes)
    assert _mirrored(batch) == {MAIN: False, T100: True}
    outcomes = {**dict.fromkeys(READS, OK), "routes6_table_100": {"status": "failed", "detail": "timeout"}}
    batch = _batch(routes=DEFAULT, tables=T100_ROWS, outcomes=outcomes)
    assert _mirrored(batch) == {MAIN: True, T100: False}


def test_a_read_that_did_not_decode_leaves_the_table_not_mirrored():
    batch = _batch(routes='{"default": {"0.0.0.0/0": [', tables=T100_ROWS)
    assert _mirrored(batch) == {MAIN: False, T100: True}


def test_a_read_with_no_outcome_is_not_mirrored():
    assert _mirrored(_batch(routes=DEFAULT, tables=T100_ROWS, outcomes=False)) == {MAIN: False, T100: False}
    outcomes = {"routes": OK, "routes_table_100": OK, "routes6_table_100": OK}
    assert _mirrored(_batch(routes=DEFAULT, tables=T100_ROWS, outcomes=outcomes))[MAIN] is False


def test_a_static_row_the_fold_does_not_match_leaves_the_table_not_mirrored():
    routes = {
        **DEFAULT,
        **_route(
            "10.99.0.0/24",
            _nh(ip="192.168.1.2", fib=False, recursive=True),
            _nh(ip="203.0.113.1", dev="eth0", resolver=True),
        ),
    }
    batch = _batch(routes=routes, tables=T100_ROWS)
    assert _mirrored(batch) == {MAIN: False, T100: True}


def test_a_table_that_is_not_mirrored_is_written_false():
    """The load merges properties."""
    batch = _batch(routes=DEFAULT, tables=T100_ROWS, max_routes=0)
    assert set(_mirrored(batch).values()) == {False}
