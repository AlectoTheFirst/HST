"""The NX-OS parse, side rows and outcomes against the golden values.

The golden values (`tests/support/stream_golden.json` and its overlays) pin
the parse, the section and table outcomes, the side rows and the parquet
files of every NX-OS case. The base implementations of `_json_payload`,
`_command_outcome`, `parse_bgp_paths` and `parse_bgp_observations` below
decode the whole answer. They pin the edges the synthetic payloads do not
reach: whitespace other than JSON's around an answer, `%` lines, JSON that is
not an object, and text that is not JSON.
"""

from __future__ import annotations

import gc
import json
import random
import sys
import tracemalloc
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from tests.support.synthetic_payloads import (
    ADDED_SINCE_BASE,
    CASES,
    COLLECTOR_HOST,
    COLLECTOR_SOURCE,
    ROW_GROUP_ROWS,
    RUN_ID,
    SNAPSHOT_TS,
    case_payload,
    fixture_raw,
    inter_digest,
    load_golden,
    make_collector,
    make_settings,
    nxos_payload,
    outcomes_json,
    parquet_layout,
    rows_digest,
    without_added_sections,
)

from hst.collectors import base as collectors_base
from hst.collectors import nxos, streams
from hst.collectors.nxos import (
    BGP_DIRECTION_KEYWORDS,
    CMD_BGP_SESSIONS,
    _bgp_best,
    _bgp_communities,
    _rows,
    bgp_capture_targets,
    bgp_route_command,
    parse_bgp_sessions,
)
from hst.collectors.util import as_int
from hst.core import manifest, sidestore, uid
from hst.core.l3domain import DEFAULT_VRF
from hst.core.model import SectionOutcome, TableOutcome

GOLDEN = load_golden()
NXOS_CASES = [key for key in CASES if key.startswith("nxos/")]
OK = SectionOutcome(status="ok")


# --- the base implementations ------------------------------------------------------------


def _base_json_payload(text: Any, command: str) -> dict[str, Any]:
    body = str(text or "").strip()
    if not body:
        return {}
    try:
        payload = json.loads(body)
    except ValueError as exc:
        head = body.splitlines()[0][:120]
        raise ValueError(f"{command!r} answered with text that is not JSON: {head!r}") from exc
    return payload if isinstance(payload, dict) else {}


def _base_command_outcome(text: Any, recorded: SectionOutcome | None, row_count: int | None) -> TableOutcome:
    if recorded is None:
        return TableOutcome(status="not-captured")
    if recorded.status == "unsupported":
        return TableOutcome(status="not-captured", detail=recorded.detail)
    if recorded.status != "ok":
        return TableOutcome(status="failed", detail=recorded.detail)
    body = str(text or "").strip()
    if not body:
        return TableOutcome(status="complete-empty", row_count=0)
    if body.startswith("%"):
        return TableOutcome(status="not-captured", detail=body.splitlines()[0].strip())
    try:
        payload = json.loads(body)
    except ValueError:
        return TableOutcome(status="failed", detail="the command answered with text that is not JSON")
    if not isinstance(payload, dict):
        return TableOutcome(status="failed", detail="the command answered with JSON that is not an object")
    count = row_count or 0
    if not count:
        return TableOutcome(status="complete-empty", row_count=0)
    return TableOutcome(status="complete", row_count=count)


def _base_parse_bgp_paths(text: str, *, vrf: str, peer_ip: str, direction: str) -> list[dict[str, Any]]:
    if not str(text or "").strip():
        return []
    try:
        payload = json.loads(text)
    except ValueError:
        return []
    if not isinstance(payload, dict):
        return []
    out: list[dict[str, Any]] = []
    for vrf_row in _rows(payload, "vrf"):
        for afi_row in _rows(vrf_row, "afi"):
            for safi_row in _rows(afi_row, "safi"):
                for holder in _rows(safi_row, "rd") or [safi_row]:
                    for prefix_row in _rows(holder, "prefix"):
                        prefix = prefix_row.get("ipprefix")
                        if not prefix:
                            continue
                        for path_row in _rows(prefix_row, "path"):
                            path_id = path_row.get("pathnr")
                            out.append(
                                {
                                    "vrf": vrf,
                                    "peer_ip": peer_ip,
                                    "direction": direction,
                                    "prefix": prefix,
                                    "path_id": None if path_id is None else str(path_id),
                                    "next_hop": path_row.get("ipnexthop"),
                                    "as_path": path_row.get("aspath") or None,
                                    "local_pref": as_int(path_row.get("localpref")),
                                    "med": as_int(path_row.get("metric")),
                                    "origin": path_row.get("origin"),
                                    "communities": _bgp_communities(path_row.get("community")),
                                    "best": _bgp_best(path_row, direction),
                                }
                            )
    return out


def _base_parse_bgp_observations(raw: dict[str, str], processes: list[dict[str, Any]]) -> dict[str, Any]:
    sessions = parse_bgp_sessions(raw.get(CMD_BGP_SESSIONS) or "")
    routes: list[dict[str, Any]] = []
    directions: list[dict[str, Any]] = []
    for vrf, peer_ip in bgp_capture_targets(processes, sessions):
        for direction in BGP_DIRECTION_KEYWORDS:
            command = bgp_route_command(vrf, peer_ip, direction)
            entry: dict[str, Any] = {
                "vrf": vrf,
                "peer_ip": peer_ip,
                "direction": direction,
                "command": command,
                "row_count": None,
            }
            if command in raw:
                rows = _base_parse_bgp_paths(raw[command], vrf=vrf, peer_ip=peer_ip, direction=direction)
                routes.extend(rows)
                entry["row_count"] = len(rows)
            directions.append(entry)
    return {"sessions": sessions, "routes": routes, "directions": directions}


# --- edge texts --------------------------------------------------------------------------


def _path_table(*, rd_level: bool) -> str:
    """A path table with two prefixes, the first with two paths, with or
    without the route-distinguisher level."""
    paths = [
        {
            "pathnr": 0,
            "ipnexthop": "192.0.2.1",
            "aspath": "65010",
            "localpref": 100,
            "metric": 0,
            "origin": "i",
            "community": ["65010:1", "65010:2"],
            "best": "true",
        },
        {"pathnr": 1, "ipnexthop": "192.0.2.2"},
    ]
    prefixes = [
        {"ipprefix": "10.1.0.0/24", "TABLE_path": {"ROW_path": paths}},
        {"ipprefix": "10.2.0.0/23", "TABLE_path": {"ROW_path": {"bestpath": "false"}}},
    ]
    holder: dict[str, Any] = {"TABLE_prefix": {"ROW_prefix": prefixes}}
    safi = {"safi": 1, **({"TABLE_rd": {"ROW_rd": holder}} if rd_level else holder)}
    afi = {"afi": 1, "TABLE_safi": {"ROW_safi": safi}}
    return json.dumps({"TABLE_vrf": {"ROW_vrf": {"vrf-name-out": "default", "TABLE_afi": {"ROW_afi": afi}}}})


_PATH_TABLE = _path_table(rd_level=True)
_PATH_TABLE_NO_RD = _path_table(rd_level=False)

# Whitespace around an answer's value mixes JSON's own and the other characters
# that `str.isspace` counts.
_EDGES = (
    "",
    " ",
    "\n",
    "\r\n",
    " \t\n\r ",
    "\x0b",
    "\x0c",
    "\x1c",
    "\x1f",
    "\x85",
    "\xa0",
    "\u2028",
    "\u2029",
    "\u3000",
    " \u2028\n",
    "\n\xa0 ",
)
_BODIES = (
    _PATH_TABLE,
    _PATH_TABLE_NO_RD,
    '{"TABLE_vrf": {"ROW_vrf": []}}',
    "{}",
    "[]",
    '"text"',
    "12",
    "null",
    "NaN",
    '{"a": "x\u2028y"}',
    '{"a":\n 1,\n "b": [1, 2]}',
    "% Inbound soft reconfiguration not enabled on this neighbor",
    "%",
    "% first line\r\nsecond line",
    "% first line\x1cstill the device's words",
    "% a\x1fb \x85c",
    "% words\xa0 \n",
    "{",
    '{"a": 1} {"b": 2}',
    '{"a": 1}x',
    "\ufeff{}",
    "not json\nsecond line",
    "x" * 300,
    "y" * 100 + "\u2029" + "z" * 100,
    '{"a":\n1,\n"b" 2}',
    "bad\x1fline",
    '{"a": 1}\x0c{"b": 2}',
    '{"a": 1}\xa0',
    _PATH_TABLE[:-1],
    _PATH_TABLE + "\xa0{}",
)
EDGE_TEXTS: list[Any] = [
    *(lead + body + trail for body in _BODIES for lead in _EDGES for trail in _EDGES),
    *(lead + trail for lead in _EDGES for trail in _EDGES),
]
# Values that are not str, which every reader turns into text with
# `str(text or "")`. The path parse hands the value itself to `json.loads`,
# which reads bytes and raises for a type it does not read (tested below).
NOT_TEXT: list[Any] = [None, 0, b"", _PATH_TABLE.encode(), b"not json", {}, []]
OTHER_VALUES: list[Any] = [*NOT_TEXT, 12, {"a": 1}]

_FRAGMENTS = (
    "{",
    "}",
    "[",
    "]",
    '"a"',
    ":",
    ",",
    "1",
    "-",
    ".5",
    "e3",
    "null",
    "true",
    "NaN",
    "%",
    "% Invalid",
    "\ufeff",
    "x",
    '"',
    " ",
    "\n",
    "\r\n",
    "\r",
    "\xa0",
    "\u2028",
    "\x0b",
    "\x1c",
    "\x85",
    '{"TABLE_vrf": {}}',
    _PATH_TABLE,
)
_EDGE_CHARS = " \t\n\r\x0b\x0c\x1c\x1d\x1e\x1f\x85\xa0\u1680\u2028\u2029\u3000"


def _random_texts(count: int, seed: int) -> Iterator[str]:
    """Answers made of JSON tokens, `%` lines and whitespace of every kind,
    with a run of edge whitespace on either side."""
    rng = random.Random(seed)
    for _ in range(count):
        lead = "".join(rng.choice(_EDGE_CHARS) for _ in range(rng.randrange(4)))
        body = "".join(rng.choice(_FRAGMENTS) for _ in range(rng.randrange(1, 6)))
        trail = "".join(rng.choice(_EDGE_CHARS) for _ in range(rng.randrange(4)))
        yield lead + body + trail


def _result(call: Callable[[], Any]) -> tuple[Any, ...]:
    """What a call returned, or the type and text of what it raised and of the
    exception that caused that."""
    try:
        return ("value", call())
    except Exception as exc:
        cause = exc.__cause__
        return ("raised", type(exc), str(exc), None if cause is None else type(cause))


def _outcome(outcome: TableOutcome) -> dict[str, Any]:
    return outcome.model_dump(mode="json")


# --- golden parity -----------------------------------------------------------------------


def _golden_inter_digest(inter: dict[str, Any]) -> str:
    """`inter_digest` of the parse in the shape the golden digest covers,
    without the `command_facts` of `bgp_observed`. The tests below check
    `command_facts` against the base outcome reading."""
    observed = {key: value for key, value in inter["bgp_observed"].items() if key != "command_facts"}
    return inter_digest({**inter, "bgp_observed": observed})


@pytest.mark.parametrize("key", NXOS_CASES)
def test_parse_outcomes_side_rows_and_parquet_match_the_golden_file(key, tmp_path):
    golden = GOLDEN["cases"][key]
    payload = case_payload(key)

    inter = nxos.parse(payload)
    assert isinstance(inter["bgp_observed"]["routes"], streams.ChainRows)
    assert _golden_inter_digest(inter) == golden["inter"]
    del inter

    collector = make_collector("nxos", make_settings(tmp_path / "data"))
    # no golden payload holds the command of an `ADDED_SINCE_BASE` section, so
    # the section reads `unknown`
    base, added = without_added_sections("nxos", outcomes_json(collector.sections(payload)))
    assert base == golden["sections"]
    assert added == {
        name: {"detail": "", "row_count": None, "status": "unknown"} for name in ADDED_SINCE_BASE["nxos"]
    }
    # the golden file holds no per-context OSPF outcome (`ospf_lsdb/<context uid>`)
    stated = {k: v for k, v in collector.table_outcomes(payload).items() if not k.startswith("ospf_lsdb/")}
    assert outcomes_json(stated) == golden["table_outcomes"]

    side = collector.side_tables(payload)
    assert isinstance(side["bgp_session_routes"], streams.MappedRows)
    assert {table: list(rows_digest(rows)) for table, rows in sorted(side.items())} == golden["side_tables"]

    parquet: dict[str, list[Any]] = {}
    layout: dict[str, dict[str, Any] | None] = {}
    for table, rows in sorted(side.items()):
        path = sidestore.write_table(
            tmp_path / "parquet",
            table,
            COLLECTOR_SOURCE,
            COLLECTOR_HOST,
            RUN_ID,
            rows,
            snapshot_ts=SNAPSHOT_TS,
            row_group_rows=ROW_GROUP_ROWS,
        )
        parquet[table] = [0, None] if path is None else list(manifest.sidestore_row_facts(path))
        layout[table] = parquet_layout(path)
    assert parquet == golden["parquet"]
    assert layout == golden["parquet_layout"]
    del side

    source, host = collectors_base._identity(collector, None)
    tables = collectors_base._write_side_tables(
        collector, payload, source, host, run_id=RUN_ID, collection_ts=SNAPSHOT_TS, on_write=None
    )
    assert (
        outcomes_json({k: v for k, v in tables.items() if not k.startswith("ospf_lsdb/")}) == golden["tables"]
    )


# --- edge parity against the base implementations ---------------------------------------


def test_the_in_place_reading_uses_the_whitespace_and_line_breaks_of_strip_splitlines_and_json():
    every = "".join(map(chr, range(sys.maxunicode + 1)))
    assert nxos._NON_SPACE.sub("", every) == "".join(c for c in every if c.isspace())
    breaks = "".join(c for c in every if len(f"a{c}b".splitlines()) == 2)
    assert "".join(nxos._LINE_BREAK.findall(every)) == breaks
    assert nxos._JSON_WHITESPACE.pattern == json.decoder.WHITESPACE.pattern


def test_json_payload_answers_and_raises_as_the_base_implementation_does():
    command = nxos.CMD_ROUTE
    texts = [*EDGE_TEXTS, *OTHER_VALUES, *_random_texts(20_000, seed=1)]
    mismatches = [
        text
        for text in texts
        if _result(lambda t=text: nxos._json_payload(t, command))
        != _result(lambda t=text: _base_json_payload(t, command))
    ]
    assert mismatches == []


def test_json_payload_quotes_the_first_line_of_text_that_is_not_json():
    text = "\n\xa0 not json\u2028second line\n"
    with pytest.raises(ValueError, match=r"answered with text that is not JSON: 'not json'$") as raised:
        nxos._json_payload(text, nxos.CMD_VLAN)
    assert isinstance(raised.value.__cause__, json.JSONDecodeError)
    long_line = " " + "q" * 500 + "\n"
    with pytest.raises(ValueError) as raised:
        nxos._json_payload(long_line, nxos.CMD_VLAN)
    assert str(raised.value).endswith(repr("q" * 120))


@pytest.mark.parametrize(
    "recorded",
    [
        None,
        OK,
        SectionOutcome(status="unsupported", detail="% Invalid command"),
        SectionOutcome(status="failed", detail="exited 1: Permission denied"),
    ],
)
def test_command_outcome_without_facts_reads_the_answer_as_the_base_implementation_does(recorded):
    texts = [*EDGE_TEXTS, *OTHER_VALUES, *_random_texts(5_000, seed=2)]
    mismatches = [
        (text, row_count)
        for text in texts
        for row_count in (None, 0, 3)
        if _outcome(nxos._command_outcome(text, recorded, row_count))
        != _outcome(_base_command_outcome(text, recorded, row_count))
    ]
    assert mismatches == []


def test_direction_facts_and_row_counts_match_the_base_outcome_and_path_parse():
    """One read of each answer states what `_command_outcome` read from the
    stripped answer and counts what `parse_bgp_paths` read from the answer as
    it is, and the lazy rows are the base parse's rows."""
    where = {"vrf": "CUST-A", "peer_ip": "192.0.2.1", "direction": "accepted"}
    texts = [*EDGE_TEXTS, *NOT_TEXT, *_random_texts(20_000, seed=3)]
    mismatches = []
    for text in texts:
        rows = _base_parse_bgp_paths(text, **where)
        facts, count = nxos._direction_facts(text, **where)
        same = (
            count == len(rows)
            and _outcome(nxos._command_outcome(text, OK, count, facts=facts))
            == _outcome(_base_command_outcome(text, OK, len(rows)))
            and facts == nxos._outcome_facts(text)
            and list(nxos._bgp_path_rows(text, **where)) == rows
            and nxos.parse_bgp_paths(text, **where) == rows
        )
        if not same:
            mismatches.append(text)
    assert mismatches == []
    # the edge texts reach every kind, and rows behind both kinds of edges
    kinds = {nxos._direction_facts(text, **where)[0][0] for text in EDGE_TEXTS}
    assert kinds == {"empty", "percent", "not-json", "not-object", "object"}
    assert nxos._direction_facts(f" \n{_PATH_TABLE}\r\n", **where)[1] == 3
    assert nxos._direction_facts(f"\xa0{_PATH_TABLE}", **where) == (("object", ""), 0)


def test_a_path_answer_of_a_type_json_loads_rejects_raises_as_the_base_parse_does():
    where = {"vrf": "default", "peer_ip": "192.0.2.1", "direction": "received"}
    for value in (12, {"a": 1}):
        base = _result(lambda v=value: _base_parse_bgp_paths(v, **where))
        assert base[0] == "raised"
        assert _result(lambda v=value: nxos.parse_bgp_paths(v, **where)) == base
        assert _result(lambda v=value: nxos._direction_facts(v, **where)) == base


def _edge_payload(seed: int) -> dict[str, Any]:
    """The small synthetic payload with every path command's answer replaced by
    an edge text, a different one per command and seed."""
    payload = case_payload("nxos/small/plain")
    rng = random.Random(seed)
    for command in [c for c in payload if isinstance(c, str) and c.startswith("show bgp ")]:
        if command != CMD_BGP_SESSIONS:
            payload[command] = rng.choice(EDGE_TEXTS)
    return payload


@pytest.mark.parametrize("seed", range(12))
def test_observations_and_their_outcomes_match_the_base_parse_over_edge_answers(seed, monkeypatch):
    payload = _edge_payload(seed)
    processes = nxos.parse_bgp_config(payload[nxos.CMD_BGP])
    device = "dev:edge"

    base = _base_parse_bgp_observations(payload, processes)
    observed = nxos.parse_bgp_observations(payload, processes)
    assert observed["sessions"] == base["sessions"]
    assert observed["directions"] == base["directions"]
    assert list(observed["routes"]) == base["routes"]
    assert len(observed["routes"]) == len(base["routes"])
    present = {entry["command"] for entry in base["directions"] if entry["command"] in payload}
    assert set(observed["command_facts"]) == present

    stated = nxos.bgp_table_outcomes(payload, {"bgp_observed": observed}, device, capture="all")
    monkeypatch.setattr(
        nxos,
        "_command_outcome",
        lambda text, recorded, row_count, *, facts=None: _base_command_outcome(text, recorded, row_count),
    )
    expected = nxos.bgp_table_outcomes(payload, {"bgp_observed": base}, device, capture="all")
    assert outcomes_json(stated) == outcomes_json(expected)


# --- the shape of the views --------------------------------------------------------------


def test_routes_are_a_chain_view_that_counts_every_direction_and_reads_fresh_rows():
    payload = case_payload("nxos/small/plain")
    observed = nxos.parse(payload)["bgp_observed"]
    routes = observed["routes"]
    assert isinstance(routes, streams.ChainRows)
    assert len(routes) == sum(entry["row_count"] or 0 for entry in observed["directions"])
    first, second = list(routes), list(routes)
    assert first == second
    assert first[0] is not second[0]
    assert routes[0] == first[0]
    assert routes[-1] == first[-1]


def test_bgp_session_routes_is_a_mapped_view_whose_rows_can_be_indexed():
    payload = case_payload("nxos/small/plain")
    routes = make_collector("nxos", None).side_tables(payload)["bgp_session_routes"]
    assert isinstance(routes, streams.MappedRows)
    rows = list(routes)
    assert len(routes) == len(rows)
    assert routes[0] == rows[0]
    assert routes[-1] == rows[-1]


def test_bgp_session_routes_carry_the_uids_of_their_own_vrf_and_peer():
    """One peer address in three VRFs is one session per VRF."""
    device = "dev:nxos-a"
    peer = "192.0.2.1"
    vrfs = ("CUST-A", "", "CUST-B", DEFAULT_VRF)
    tables = [
        nxos.parse_bgp_paths(_PATH_TABLE, vrf=vrf, peer_ip=peer, direction=direction)
        for vrf in vrfs
        for direction in BGP_DIRECTION_KEYWORDS
    ]
    # interleaved, so that each VRF's rows follow another VRF's
    routes = [row for rows in zip(*tables, strict=True) for row in rows]
    sessions = [{"vrf": vrf, "peer_ip": peer} for vrf in vrfs]
    side = nxos.bgp_side_rows({"bgp_observed": {"sessions": sessions, "routes": routes}}, device)

    stated = [(row["context_uid"], row["session_uid"]) for row in side["bgp_session_routes"]]
    expected = [
        (
            uid.vrf(device, r["vrf"] or DEFAULT_VRF),
            nxos._bgp_session_uid(device, r["vrf"] or DEFAULT_VRF, peer),
        )
        for r in routes
    ]
    assert stated == expected
    assert set(expected) == {(row["context_uid"], row["session_uid"]) for row in side["bgp_sessions"]}
    assert len(set(expected)) == 3


def test_path_and_route_answers_are_decoded_in_place_one_piece_at_a_time(monkeypatch):
    """Each path answer is read in pieces by the parse and again by each read
    of its rows, and the route answer by the parse: every piece is decoded
    once per pass and no answer is decoded whole. The outcomes decode nothing.
    Every decode reads the payload's own text, never a copy.

    The answers here end in a line break, as a device's do, and open with
    one: `str.strip` hands back the text itself when there is nothing to
    strip, so only an answer with whitespace at its edges tells a stripped
    copy from the answer."""
    payload = case_payload("nxos/small/plain")
    # Every empty str is one object.
    commands = [c for c, text in payload.items() if c.startswith("show bgp ipv4 ") and text.strip()]
    commands.append(nxos.CMD_ROUTE)
    for command in commands:
        payload[command] = f"\n{payload[command]}\r\n"
    own = {id(payload[command]): command for command in commands}
    bodies = {command: payload[command].strip() for command in commands}
    # where a decode of a whole answer starts
    starts = {command: len(payload[command]) - len(payload[command].lstrip()) for command in commands}
    raw_decode = json.JSONDecoder.raw_decode
    decoded: list[tuple[str, int]] = []
    copied: list[str] = []

    def recording_raw_decode(self: json.JSONDecoder, s: str, idx: int = 0) -> tuple[Any, int]:
        # every decode passes here: `json.loads`, `_decode_span` and any
        # other `JSONDecoder` alike
        command = own.get(id(s))
        if command is not None and s is payload[command]:
            decoded.append((command, idx))
        elif isinstance(s, str):
            copied.extend(command for command, body in bodies.items() if body in s)
        return raw_decode(self, s, idx)

    monkeypatch.setattr(json.JSONDecoder, "raw_decode", recording_raw_decode)
    collector = make_collector("nxos", None)

    observed = collector._inter(payload)["bgp_observed"]
    facts = observed["command_facts"]
    assert {kind for kind, _detail in facts.values()} == {"object", "percent", "empty"}
    tables = [command for command, (kind, _detail) in facts.items() if kind == "object"]
    assert tables
    # the answers are read in pieces: every piece once
    assert len(set(decoded)) == len(decoded)
    assert {command for command, _idx in decoded} == {*tables, nxos.CMD_ROUTE}
    assert [piece for piece in decoded if piece[1] == starts[piece[0]]] == []
    pieces = set(decoded)

    decoded.clear()
    collector.table_outcomes(payload)
    assert decoded == []

    rows = collector.side_tables(payload)["bgp_session_routes"]
    assert decoded == []
    assert sum(1 for _ in rows) == len(rows)
    with_rows = {entry["command"] for entry in observed["directions"] if entry["row_count"]}
    assert len(set(decoded)) == len(decoded)
    assert set(decoded) == {piece for piece in pieces if piece[0] in with_rows}
    assert [piece for piece in decoded if piece[1] == starts[piece[0]]] == []
    assert copied == []


# --- what stays alive --------------------------------------------------------------------


def _route_text(prefixes: int) -> str:
    """`show ip route vrf all | json` with one VRF holding every prefix, the
    shape of a full-table box whose last VRF is its biggest."""
    rows = [
        {
            "ipprefix": f"10.{i >> 8 & 255}.{i & 255}.0/24",
            "ucast-nhops": 1,
            "attached": False,
            "TABLE_path": {
                "ROW_path": {
                    "ipnexthop": f"192.0.2.{i % 250 + 1}",
                    "ifname": "Ethernet1/1",
                    "uptime": "P1D",
                    "pref": 20,
                    "metric": 0,
                    "clientname": "bgp-65001",
                    "type": "external",
                    "ubest": True,
                }
            },
        }
        for i in range(prefixes)
    ]
    table = {"addrf": "ipv4", "TABLE_prefix": {"ROW_prefix": rows}}
    vrf = {"vrf-name-out": "default", "TABLE_addrf": {"ROW_addrf": table}}
    return json.dumps({"TABLE_vrf": {"ROW_vrf": vrf}})


def _path_text(prefixes: int) -> str:
    """`show bgp ... neighbors <peer> received-routes | json` with one path per
    prefix, the shape of a full-table peer."""
    rows = [
        {
            "ipprefix": f"10.{i >> 8 & 255}.{i & 255}.0/24",
            "TABLE_path": {
                "ROW_path": {
                    "pathnr": 0,
                    "ipnexthop": f"192.0.2.{i % 250 + 1}",
                    "aspath": "65010 65020",
                    "localpref": 100,
                    "metric": 0,
                    "origin": "i",
                    "community": ["65010:1"],
                    "best": "true",
                }
            },
        }
        for i in range(prefixes)
    ]
    safi = {"safi": 1, "TABLE_rd": {"ROW_rd": {"TABLE_prefix": {"ROW_prefix": rows}}}}
    afi = {"afi": 1, "TABLE_safi": {"ROW_safi": safi}}
    return json.dumps({"TABLE_vrf": {"ROW_vrf": {"vrf-name-out": "default", "TABLE_afi": {"ROW_afi": afi}}}})


def _traced(read: Callable[[], Any]) -> tuple[Any, int | None, int, int]:
    """What `read` returned, and the memory traced while it ran: the most
    there was when its first decode began (None when it decoded nothing),
    what there was when it returned, and the most there was at all. Tracing
    starts after the answer is built, so the answer itself counts in none of
    them; a copy of it does."""
    raw_decode = json.JSONDecoder.raw_decode
    before: list[int] = []

    def tracing_raw_decode(self: json.JSONDecoder, s: str, idx: int = 0) -> tuple[Any, int]:
        if not before:
            before.append(tracemalloc.get_traced_memory()[1])
        return raw_decode(self, s, idx)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(json.JSONDecoder, "raw_decode", tracing_raw_decode)
        tracemalloc.start()
        try:
            result = read()
            returned, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
    return result, (before[0] if before else None), returned, peak


@pytest.mark.parametrize("reader", ["_json_payload", "_outcome_facts", "_direction_facts", "_bgp_path_rows"])
def test_an_answer_with_whitespace_at_its_edges_is_decoded_without_a_copy(reader):
    prefixes = 20_000
    text = f"\n{_path_text(prefixes)}\r\n"
    where = {"vrf": "default", "peer_ip": "192.0.2.1", "direction": "received"}
    reads: dict[str, tuple[Callable[[], Any], Callable[[Any], bool]]] = {
        "_json_payload": (lambda: nxos._json_payload(text, nxos.CMD_ROUTE), lambda tree: "TABLE_vrf" in tree),
        "_outcome_facts": (lambda: nxos._outcome_facts(text), lambda facts: facts == ("object", "")),
        "_direction_facts": (
            lambda: nxos._direction_facts(text, **where),
            lambda facts_and_count: facts_and_count == (("object", ""), prefixes),
        ),
        "_bgp_path_rows": (
            lambda: sum(1 for _ in nxos._bgp_path_rows(text, **where)),
            lambda count: count == prefixes,
        ),
    }
    read, expected = reads[reader]
    result, before_decode, _returned, _peak = _traced(read)
    assert expected(result)
    assert before_decode is not None
    assert before_decode < len(text) // 100, (before_decode, len(text))


def test_json_payload_holds_only_the_tree_and_quotes_bad_text_without_copying_it():
    """Beyond the tree it returns, reading a route answer holds nothing and at
    no point a copy of the answer; an answer that is not JSON is quoted from
    its first line, without splitting the rest."""
    text = f"\n{_route_text(20_000)}\n"
    tree, _before, returned, peak = _traced(lambda: nxos._json_payload(text, nxos.CMD_ROUTE))
    assert len(_rows(tree, "vrf")) == 1
    assert peak - returned < len(text) // 100, (peak - returned, len(text))
    del tree

    bad = f"\n not json {text}"
    raised, _before, _returned, peak = _traced(
        lambda: _result(lambda: nxos._json_payload(bad, nxos.CMD_ROUTE))
    )
    assert raised[:2] == ("raised", ValueError)
    assert str(raised[2]).endswith(repr("not json "))
    assert peak < len(bad) // 100, (peak, len(bad))


def _is_tree(value: Any, keys: tuple[str, ...]) -> bool:
    return isinstance(value, dict) and any(key in value for key in keys)


def _decoded_bytes(snapshot: tracemalloc.Snapshot) -> int:
    """The live blocks of a snapshot the JSON decoder allocated: the C scanner
    runs under `JSONDecoder.raw_decode`, the innermost Python frame of every
    object it builds."""
    decoder_file = json.decoder.__file__
    return sum(
        stat.size for stat in snapshot.statistics("filename") if stat.traceback[0].filename == decoder_file
    )


def test_the_route_tree_is_freed_before_the_bgp_parse(monkeypatch):
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
    parse_bgp_observations = nxos.parse_bgp_observations

    def at_entry(raw: dict[str, str], processes: list[dict[str, Any]]) -> dict[str, Any]:
        gc.collect()
        seen["decoded"] = _decoded_bytes(tracemalloc.take_snapshot())
        seen["trees"] = [o for o in gc.get_objects() if _is_tree(o, keys) and id(o) not in known]
        return parse_bgp_observations(raw, processes)

    monkeypatch.setattr(nxos, "parse_bgp_observations", at_entry)
    tracemalloc.start()
    try:
        inter = nxos.parse(payload)
    finally:
        tracemalloc.stop()
    assert len(inter["rib"]) == 20_000
    assert seen["trees"] == []
    assert seen["decoded"] < 0.4 * tree_bytes, (seen["decoded"], tree_bytes)


def test_the_parse_and_the_rows_decode_no_path_table_whole(monkeypatch):
    payload = nxos_payload(routes=200, peers=3, paths=300, denied_received=False)
    # held, so that no id of a table that was here before is reused
    before = [o for o in gc.get_objects() if _is_tree(o, ("TABLE_afi",))]
    known = {id(o) for o in before}
    alive: list[int] = []
    iter_bgp_paths = nxos._iter_bgp_paths

    def counting(tree: dict[str, Any], **where: Any) -> Iterator[dict[str, Any]]:
        gc.collect()
        alive.append(sum(1 for o in gc.get_objects() if _is_tree(o, ("TABLE_afi",)) and id(o) not in known))
        return iter_bgp_paths(tree, **where)

    monkeypatch.setattr(nxos, "_iter_bgp_paths", counting)
    observed = nxos.parse(payload)["bgp_observed"]
    tables = sum(1 for kind, _detail in observed["command_facts"].values() if kind == "object")
    # read in pieces: no path table is decoded whole
    assert tables
    assert alive == []
    alive.clear()
    assert len(list(observed["routes"])) == len(observed["routes"])
    assert alive == []
