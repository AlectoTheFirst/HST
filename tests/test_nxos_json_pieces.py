"""The NX-OS route table and BGP path tables, read in pieces.

`nxos._rib_rows` and the path readers (`_read_direction`, `_bgp_path_rows`)
walk the `TABLE_`/`ROW_` wrappers of an answer in place and decode one prefix
row at a time, so the decoded tree of a full-table answer never exists. The
tests hold what they return and raise to the base implementations, which
decode the whole answer, over every one-place change of small tables, over
every truncation and one-character edit of their text, and over the edge texts
and random answers of `tests/test_nxos_stream_parity.py`. The shapes the walk leaves to the
whole-tree reader (a repeated wrapper, a row that is not an object) are among
the changes, and the tests check that both readings are taken. The rest
measure what a read holds beside its result and how much of the answer one
decode reads, and, with the walk leaving every answer to the tree, that the
whole-tree reading frees the route tree before the BGP parse and holds one
path table at a time.
"""

from __future__ import annotations

import gc
import json
import tracemalloc
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from tests.support.synthetic_payloads import fixture_raw, nxos_payload
from tests.test_nxos_stream_parity import (
    EDGE_TEXTS,
    OK,
    OTHER_VALUES,
    _base_command_outcome,
    _base_json_payload,
    _base_parse_bgp_observations,
    _base_parse_bgp_paths,
    _decoded_bytes,
    _is_tree,
    _outcome,
    _path_text,
    _random_texts,
    _result,
    _route_text,
    _traced,
)

from hst.collectors import nxos
from hst.collectors.nxos import _rows

WHERE = {"vrf": "CUST-A", "peer_ip": "192.0.2.1", "direction": "accepted"}


def _base_rib_rows(text: Any) -> list[dict[str, Any]]:
    """The RIB records, read from the whole decoded answer."""
    rib = []
    for vrf_row in _rows(_base_json_payload(text, nxos.CMD_ROUTE), "vrf"):
        vrf_name = vrf_row.get("vrf-name-out", "")
        for addrf_row in _rows(vrf_row, "addrf"):
            for prefix_row in _rows(addrf_row, "prefix"):
                prefix = prefix_row.get("ipprefix")
                for path_row in _rows(prefix_row, "path"):
                    rib.append(
                        {
                            "vrf": vrf_name,
                            "prefix": prefix,
                            "next_hop": path_row.get("ipnexthop"),
                            "interface": path_row.get("ifname"),
                            "protocol": path_row.get("clientname"),
                            "metric": path_row.get("metric"),
                        }
                    )
    return rib


# --- small tables, with objects that can repeat a key --------------------------------------
#
# A tuple of (key, value) pairs is an object whose members keep their order and
# may repeat a key, which a dict cannot express; a list is an array.


def _dump(value: Any, item: str = ", ", key: str = ": ") -> str:
    """JSON text for `value`, with `item` between members and elements and
    `key` between a key and its value."""
    if isinstance(value, tuple):
        return "{" + item.join(json.dumps(k) + key + _dump(v, item, key) for k, v in value) + "}"
    if isinstance(value, list):
        return "[" + item.join(_dump(v, item, key) for v in value) + "]"
    return json.dumps(value)


def _table(name: str, rows: Any) -> tuple[str, Any]:
    return f"TABLE_{name}", ((f"ROW_{name}", rows),)


RIB_A = (("ipnexthop", "192.0.2.1"), ("ifname", "Ethernet1/1"), ("clientname", "bgp-65001"), ("metric", 0))
RIB_B = (("ipnexthop", "192.0.2.2"), ("clientname", "static"), ("metric", 1))


def _route_prefix(prefix: str, paths: Any) -> tuple[Any, ...]:
    return (("ipprefix", prefix), ("ucast-nhops", 1), _table("path", paths))


def _route_vrf(name: str, prefixes: Any) -> tuple[Any, ...]:
    return (("vrf-name-out", name), _table("addrf", (("addrf", "ipv4"), _table("prefix", prefixes))))


# Two VRFs: a row array and a lone row at every level, one prefix with two paths.
DEFAULT_ROW = _route_vrf(
    "default", [_route_prefix("10.0.0.0/24", [RIB_A, RIB_B]), _route_prefix("10.0.1.0/24", RIB_B)]
)
MGMT_ROW = _route_vrf("mgmt", _route_prefix("10.255.0.0/32", RIB_A))
ROUTE_DOC = (_table("vrf", [DEFAULT_ROW, MGMT_ROW]),)

BGP_A = (
    ("pathnr", 0),
    ("ipnexthop", "192.0.2.1"),
    ("aspath", "65010"),
    ("localpref", 100),
    ("metric", 0),
    ("origin", "i"),
    ("community", ["65010:1", "65010:2"]),
    ("best", "true"),
)
BGP_B = (("pathnr", 1), ("ipnexthop", "192.0.2.2"), ("bestpath", "false"))


def _path_prefix(prefix: str, paths: Any) -> tuple[Any, ...]:
    return (("ipprefix", prefix), _table("path", paths))


PREFIXES = [_path_prefix("10.1.0.0/24", [BGP_A, BGP_B]), _path_prefix("10.2.0.0/23", BGP_B)]
OWN_PREFIXES = _table("prefix", _path_prefix("10.9.0.0/16", BGP_A))
RD_ROWS = _table(
    "rd",
    [
        (("rd_val", "1:1"), _table("prefix", PREFIXES)),
        (_table("prefix", _path_prefix("10.3.0.0/16", BGP_A)),),
    ],
)


def _path_doc(*safi: tuple[str, Any]) -> tuple[Any, ...]:
    afi = (("afi", 1), _table("safi", (("safi", 1), *safi)))
    return (_table("vrf", (("vrf-name-out", "default"), _table("afi", afi))),)


PATH_DOCS = {
    "rd": _path_doc(RD_ROWS),
    "no-rd": _path_doc(_table("prefix", PREFIXES)),
    # a sub-family row with prefixes of its own beside route-distinguisher
    # rows, in both orders: the tree reads the route-distinguisher rows
    "rd-then-own": _path_doc(RD_ROWS, OWN_PREFIXES),
    "own-then-rd": _path_doc(OWN_PREFIXES, RD_ROWS),
}

# Values a change puts in place of a member or an element: every JSON type,
# the empty containers, and containers of what is not an object.
_REPLACEMENTS: tuple[Any, ...] = (None, True, 0, 7, "", "ab", [], [1], [None], [[]], (), (("x", 1),))


def _changes(node: Any) -> Iterator[Any]:
    """Every value that differs from `node` at one place: a member or element
    replaced, changed inside, removed or given again, or the members of an
    object reversed."""
    if isinstance(node, tuple):
        pairs = list(node)
        for i, (key, value) in enumerate(pairs):
            for other in (*_REPLACEMENTS, *_changes(value)):
                yield (*pairs[:i], (key, other), *pairs[i + 1 :])
            yield (*pairs[:i], *pairs[i + 1 :])
            yield (*pairs, (key, value))
            yield (*pairs, (key, None))
            yield ((key, 7), *pairs)
        yield tuple(reversed(pairs))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            for other in (*_REPLACEMENTS, *_changes(value)):
                yield [*node[:i], other, *node[i + 1 :]]
            yield [*node[:i], *node[i + 1 :]]
        yield [*node, 7]
        yield [*node, *node]


def _spellings(doc: Any) -> list[str]:
    """`doc` in three spacings, and with one key it follows spelled with an
    escape, which `json.loads` reads as the same key."""
    compact = _dump(doc, ",", ":")
    return [
        compact,
        _dump(doc),
        _dump(doc, ",\n  ", " :\t"),
        compact.replace('"TABLE_prefix"', '"TABLE\\u005fprefix"'),
    ]


def _texts(doc: Any) -> list[str]:
    """Every one-place change of `doc` in two spacings, each also cut short
    by its last character and followed by a second value: the change comes
    before a syntax error that makes the whole answer text that is not JSON."""
    texts: set[str] = set()
    for changed in [doc, *_changes(doc)]:
        for text in (_dump(changed, ",", ":"), _dump(changed)):
            texts.update((text, text[:-1], text + " 0"))
    return sorted(texts)


def _char_edits(text: str) -> Iterator[str]:
    """Every truncation of `text`, and `text` with one character removed or
    one inserted, at every position."""
    for i in range(len(text) + 1):
        yield text[:i]
        yield text[:i] + text[i + 1 :]
        for char in ',:{}[]" \n\\x\xa0':
            yield text[:i] + char + text[i:]


# --- what a reading has to match -----------------------------------------------------------


def _rib_differs(text: Any) -> bool:
    return _result(lambda: nxos._rib_rows(text)) != _result(lambda: _base_rib_rows(text))


def _path_differs(text: Any) -> bool:
    """Whether any reading of a path answer differs from the base parse: the
    records, the facts and count of the one read the parse makes, and the
    records read again the way that read found (the parse's `routes`)."""
    base = _result(lambda: _base_parse_bgp_paths(text, **WHERE))
    if _result(lambda: nxos.parse_bgp_paths(text, **WHERE)) != base:
        return True
    if _result(lambda: list(nxos._bgp_path_rows(text, **WHERE))) != base:
        return True
    read = _result(lambda: nxos._read_direction(text, **WHERE))
    if base[0] == "raised" or read[0] == "raised":
        return read != base
    rows = base[1]
    facts, count, whole = read[1]
    if count != len(rows) or facts != nxos._outcome_facts(text):
        return True
    if _outcome(nxos._command_outcome(text, OK, count, facts=facts)) != _outcome(
        _base_command_outcome(text, OK, len(rows))
    ):
        return True
    return bool(count) and list(nxos._bgp_path_rows(text, **WHERE, whole=whole)) != rows


@pytest.fixture
def whole_reads(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """How often the route and path readers fell back to the whole tree."""
    counts = {"rib": 0, "paths": 0}
    rib_records, iter_bgp_paths = nxos._rib_records, nxos._iter_bgp_paths

    def counting_rib(payload: dict[str, Any]) -> list[dict[str, Any]]:
        counts["rib"] += 1
        return rib_records(payload)

    def counting_paths(payload: dict[str, Any], **where: str) -> Iterator[dict[str, Any]]:
        counts["paths"] += 1
        return iter_bgp_paths(payload, **where)

    monkeypatch.setattr(nxos, "_rib_records", counting_rib)
    monkeypatch.setattr(nxos, "_iter_bgp_paths", counting_paths)
    return counts


# --- parity --------------------------------------------------------------------------------


def test_the_small_tables_are_read_in_pieces(whole_reads):
    for text in _spellings(ROUTE_DOC):
        assert nxos._rib_rows(text) == _base_rib_rows(text)
        assert len(nxos._rib_rows(text)) == 4
    for name, doc in PATH_DOCS.items():
        # The sub-family's own prefixes come before the route-distinguisher rows.
        whole = name == "own-then-rd"
        for text in _spellings(doc):
            rows = _base_parse_bgp_paths(text, **WHERE)
            assert nxos._read_direction(text, **WHERE) == (("object", ""), len(rows), whole), name
            assert rows
            assert list(nxos._bgp_path_rows(text, **WHERE, whole=whole)) == rows
    # the count and the rows of each spelling of that one table
    assert whole_reads == {"rib": 0, "paths": 2 * len(_spellings(PATH_DOCS["own-then-rd"]))}


def test_a_vrf_name_after_its_routes_is_read_in_pieces(whole_reads):
    """A renderer that orders keys otherwise prints `vrf-name-out` after
    `TABLE_addrf`. The records take the row's last name, as in the tree,
    without the tree."""
    name, routes = DEFAULT_ROW
    orders = [
        (routes, name),
        (routes, name, ("vrf-name-out", "other")),
        (("vrf-name-out", "first"), routes, name),
        (routes,),
    ]
    for order in orders:
        doc = (_table("vrf", [order, MGMT_ROW]),)
        for text in _spellings(doc):
            rib = nxos._rib_rows(text)
            assert rib == _base_rib_rows(text)
            assert [row["vrf"] for row in rib] == [dict(order).get("vrf-name-out", "")] * 3 + ["mgmt"]
    assert whole_reads["rib"] == 0


def test_every_one_place_change_of_a_route_table_reads_as_the_base_parse_did(whole_reads):
    texts = _texts(ROUTE_DOC)
    assert [text for text in texts if _rib_differs(text)] == []
    # both readings were taken
    assert 0 < whole_reads["rib"] < len(texts)


@pytest.mark.parametrize("name", sorted(PATH_DOCS))
def test_every_one_place_change_of_a_path_table_reads_as_the_base_parse_did(name, whole_reads):
    texts = _texts(PATH_DOCS[name])
    assert [text for text in texts if _path_differs(text)] == []
    # both readings were taken
    reads = [_result(lambda t=text: nxos._read_direction(t, **WHERE)) for text in texts]
    assert {read[1][2] for read in reads if read[0] == "value"} == {True, False}


def test_every_truncation_and_one_character_edit_reads_as_the_base_parse_did():
    route = _dump(ROUTE_DOC, ",", ":")
    assert [text for text in _char_edits(route) if _rib_differs(text)] == []
    path = _dump(PATH_DOCS["rd"], ",", ":")
    assert [text for text in _char_edits(path) if _path_differs(text)] == []


def test_the_edge_texts_and_random_answers_read_as_the_base_parse_did():
    routes = [
        lead + _route_text(3) + trail for lead in ("", " \n", "\xa0") for trail in ("", "\r\n", "\u2028")
    ]
    texts = [*routes, *EDGE_TEXTS, *OTHER_VALUES, *_random_texts(20_000, seed=4)]
    assert [text for text in texts if _rib_differs(text)] == []


def test_a_path_answer_the_walk_leaves_to_the_tree_is_read_whole_by_the_parse_and_its_rows(whole_reads):
    """A repeated `TABLE_vrf` keeps the last one in the tree. The walk has read
    the first by the time it meets the second, so the parse reads that answer
    whole, once to count its records and again on each read of its rows."""
    payload = nxos_payload(routes=20, peers=1, paths=12, denied_received=False)
    processes = nxos.parse_bgp_config(payload[nxos.CMD_BGP])
    command = next(c for c in payload if c.startswith("show bgp ipv4 ") and c.endswith(" routes | json"))
    last = _dump(tuple(json.loads(payload[command]).items()))
    first = _dump(PATH_DOCS["rd"])
    payload[command] = "{" + first[1:-1] + ", " + last[1:-1] + "}\n"

    base = _base_parse_bgp_observations(payload, processes)
    observed = nxos.parse_bgp_observations(payload, processes)
    assert whole_reads["paths"] == 1
    assert observed["directions"] == base["directions"]
    assert any(entry["command"] == command and entry["row_count"] for entry in base["directions"])
    assert list(observed["routes"]) == base["routes"]
    assert whole_reads["paths"] == 2


# --- what a read holds ---------------------------------------------------------------------


def test_a_route_answer_is_read_holding_one_prefix_row_at_a_time(whole_reads):
    text = f"\n{_route_text(20_000)}\n"
    rib, _before, returned, peak = _traced(lambda: nxos._rib_rows(text))
    assert len(rib) == 20_000
    assert rib == _base_rib_rows(text)
    assert whole_reads["rib"] == 0
    assert peak - returned < len(text) // 100, (peak - returned, len(text))


def _count(rows: Iterator[dict[str, Any]]) -> int:
    return sum(1 for _ in rows)


@pytest.mark.parametrize("reader", ["_read_direction", "_bgp_path_rows"])
def test_a_path_answer_is_read_holding_one_prefix_row_at_a_time(reader, whole_reads):
    prefixes = 40_000
    text = f"\n{_path_text(prefixes)}\n"
    where = {"vrf": "default", "peer_ip": "192.0.2.1", "direction": "received"}
    reads: dict[str, tuple[Callable[[], Any], Any]] = {
        "_read_direction": (lambda: nxos._read_direction(text, **where), (("object", ""), prefixes, False)),
        "_bgp_path_rows": (lambda: _count(nxos._bgp_path_rows(text, **where, whole=False)), prefixes),
    }
    read, expected = reads[reader]
    result, _before, _returned, peak = _traced(read)
    assert result == expected
    assert whole_reads["paths"] == 0
    assert peak < len(text) // 100, (peak, len(text))


def test_the_parse_holds_no_decoded_route_or_path_table(whole_reads):
    """A full-table route answer and a full-table peer, parsed and their paths
    read: beside what the parse returns, nothing near the size of an answer
    is held at any point."""
    payload = nxos_payload(routes=20_000, peers=1, paths=20_000, denied_received=False)
    largest = max(len(text) for text in payload.values() if isinstance(text, str))
    assert largest > 3_000_000

    inter, _before, returned, peak = _traced(lambda: nxos.parse(payload))
    assert len(inter["rib"]) > 20_000
    assert peak - returned < largest // 10, (peak - returned, largest)

    routes = inter["bgp_observed"]["routes"]
    count, _before, _returned, peak = _traced(lambda: _count(iter(routes)))
    assert count == len(routes) > 20_000
    assert peak < largest // 50, (peak, largest)
    assert whole_reads == {"rib": 0, "paths": 0}


def _leave_to_the_tree(*args: Any, **kwargs: Any) -> Any:
    """A walk that leaves every answer to the whole-tree reader."""
    raise nxos._Irregular


def test_the_whole_tree_reading_frees_the_route_tree_before_the_bgp_parse(monkeypatch, whole_reads):
    """Where the walk leaves the route answer to the tree, the tree is freed
    when `_rib_rows` returns: at the start of the BGP parse none of it is
    alive, and what the RIB records hold of it is about a fifth of it."""
    payload = dict(fixture_raw("nxos"))
    payload[nxos.CMD_ROUTE] = _route_text(20_000)
    keys = ("TABLE_addrf", "TABLE_path")

    gc.collect()
    tracemalloc.start()
    try:
        tree = nxos._json_payload(payload[nxos.CMD_ROUTE], nxos.CMD_ROUTE)
        tree_bytes = _decoded_bytes(tracemalloc.take_snapshot())
        del tree
    finally:
        tracemalloc.stop()

    # the fixture modules hold route tables of their own as dicts; held, so
    # that no id of theirs is reused
    before = [o for o in gc.get_objects() if _is_tree(o, keys)]
    known = {id(o) for o in before}
    seen: dict[str, Any] = {}
    rib_records, parse_bgp_observations = nxos._rib_records, nxos.parse_bgp_observations

    def at_records(tree: dict[str, Any]) -> list[dict[str, Any]]:
        gc.collect()
        seen["reading"] = sum(1 for o in gc.get_objects() if _is_tree(o, keys) and id(o) not in known)
        return rib_records(tree)

    def at_entry(raw: dict[str, str], processes: list[dict[str, Any]]) -> dict[str, Any]:
        gc.collect()
        seen["decoded"] = _decoded_bytes(tracemalloc.take_snapshot())
        seen["trees"] = [o for o in gc.get_objects() if _is_tree(o, keys) and id(o) not in known]
        return parse_bgp_observations(raw, processes)

    monkeypatch.setattr(nxos, "_rib_pieces", _leave_to_the_tree)
    monkeypatch.setattr(nxos, "_rib_records", at_records)
    monkeypatch.setattr(nxos, "parse_bgp_observations", at_entry)
    tracemalloc.start()
    try:
        inter = nxos.parse(payload)
    finally:
        tracemalloc.stop()
    assert whole_reads["rib"] == 1
    assert inter["rib"] == _base_rib_rows(payload[nxos.CMD_ROUTE])
    # the VRF row and every prefix row of the tree while it is read, and
    # none of them once the records are made
    assert seen["reading"] > 20_000
    assert seen["trees"] == []
    assert seen["decoded"] < 0.4 * tree_bytes, (seen["decoded"], tree_bytes)


def test_the_whole_tree_reading_holds_one_path_table_at_a_time(monkeypatch, whole_reads):
    """Where the walk leaves every path answer to the tree, the parse's count
    and each read of its rows decode one path table at a time, and each is
    freed before the next is decoded."""
    payload = nxos_payload(routes=200, peers=3, paths=300, denied_received=False)
    processes = nxos.parse_bgp_config(payload[nxos.CMD_BGP])
    base = _base_parse_bgp_observations(payload, processes)
    # held, so that no id of a table that was here before is reused
    before = [o for o in gc.get_objects() if _is_tree(o, ("TABLE_afi",))]
    known = {id(o) for o in before}
    alive: list[int] = []
    iter_bgp_paths = nxos._iter_bgp_paths

    def counting(tree: dict[str, Any], **where: str) -> Iterator[dict[str, Any]]:
        gc.collect()
        alive.append(sum(1 for o in gc.get_objects() if _is_tree(o, ("TABLE_afi",)) and id(o) not in known))
        return iter_bgp_paths(tree, **where)

    monkeypatch.setattr(nxos, "_path_pieces", _leave_to_the_tree)
    monkeypatch.setattr(nxos, "_iter_bgp_paths", counting)
    observed = nxos.parse_bgp_observations(payload, processes)
    tables = sum(1 for kind, _detail in observed["command_facts"].values() if kind == "object")
    with_rows = sum(1 for entry in observed["directions"] if entry["row_count"])
    assert tables >= with_rows > 1
    assert observed["directions"] == base["directions"]
    assert alive == [1] * tables
    alive.clear()
    assert list(observed["routes"]) == base["routes"]
    assert alive == [1] * with_rows
    assert whole_reads["paths"] == tables + with_rows


def _decoded_spans(read: Callable[[], Any], text: str) -> list[int]:
    """The length of the text each decode of `text` read while `read` ran."""
    raw_decode = json.JSONDecoder.raw_decode
    spans: list[int] = []

    def recording_raw_decode(self: json.JSONDecoder, s: str, idx: int = 0) -> tuple[Any, int]:
        value, end = raw_decode(self, s, idx)
        if s is text:
            spans.append(end - idx)
        return value, end

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(json.JSONDecoder, "raw_decode", recording_raw_decode)
        read()
    return spans


def test_no_decode_reads_more_than_one_prefix_row():
    """Every decode of a route or path answer reads one prefix row or a
    single value beside the rows; the longest is the longest prefix row."""
    prefixes = 2_000
    route = f"{_route_text(prefixes)}\n"
    path = f"{_path_text(prefixes)}\n"
    where = {"vrf": "default", "peer_ip": "192.0.2.1", "direction": "received"}
    route_tree = json.loads(route)["TABLE_vrf"]["ROW_vrf"]["TABLE_addrf"]["ROW_addrf"]
    path_tree = json.loads(path)["TABLE_vrf"]["ROW_vrf"]["TABLE_afi"]["ROW_afi"]["TABLE_safi"]["ROW_safi"]
    reads = {
        route: (lambda: nxos._rib_rows(route), route_tree["TABLE_prefix"]["ROW_prefix"]),
        path: (
            lambda: nxos._read_direction(path, **where),
            path_tree["TABLE_rd"]["ROW_rd"]["TABLE_prefix"]["ROW_prefix"],
        ),
    }
    for text, (read, rows) in reads.items():
        assert len(rows) == prefixes
        spans = _decoded_spans(read, text)
        assert len(spans) >= prefixes
        assert max(spans) == max(len(json.dumps(row)) for row in rows) < len(text) // 1000
