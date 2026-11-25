"""Every IOS-XE and IOS-XR golden case must give its golden values
(`tests/support/stream_golden.json` and its overlays)."""

from __future__ import annotations

import importlib
import random
from pathlib import Path
from types import ModuleType
from typing import Any, NamedTuple

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
    expected_ios_paths,
    held_mac_statement,
    inter_digest,
    load_golden,
    make_collector,
    make_settings,
    outcomes_json,
    parquet_layout,
    rows_digest,
    split_case,
    without_added_sections,
)
from tests.test_cisco_common import assert_inter_shape
from tests.test_ios_bgp_table import random_table

from hst.collectors import base as collectors_base
from hst.collectors import cli_parse, iosxe, iosxr, streams
from hst.collectors.cisco_common import expand_protocol
from hst.collectors.cli_collector import CiscoCliCollector
from hst.collectors.util import canonical_mac
from hst.core import manifest, sidestore
from hst.core.model import SectionOutcome, TableOutcome

GOLDEN = load_golden()

_FAMILIES: dict[str, ModuleType] = {"iosxe": iosxe, "iosxr": iosxr}

# Every IOS-XE and IOS-XR case at the fixture, small and medium scales, in
# every variant.
TEXT_CASES = tuple(key for key in CASES if split_case(key)[0] in _FAMILIES and split_case(key)[1] != "tenth")
NXOS_CASES = tuple(key for key in CASES if split_case(key)[0] == "nxos" and split_case(key)[1] != "tenth")

# The per-template record keys each family's route and ARP rows read, and the
# key of its interface to VRF map, as the reference mappings below read them.
# The record keys of the next hop, the interface and the next hop's VRF.
_RIB_KEYS = {"iosxe": ("nexthop_ip", "nexthop_if", "nexthop_vrf"), "iosxr": ("next_hop", "interface", None)}
_VRF_KEY = {"iosxe": "name", "iosxr": "vrf"}

# The key order of every side row. The golden digests sort keys, so they
# cannot see an order change.
_SIDE_KEYS: dict[str, tuple[str, ...]] = {
    "rib": (
        "device_uid",
        "vrf",
        "context_uid",
        "prefix",
        "next_hop",
        "next_hop_context_uid",
        "interface",
        "protocol",
        "discard",
        "metric",
        "af",
        "prefixlen",
        "lo",
        "hi",
    ),
    "mac": ("device_uid", "vlan", "mac", "port_name", "bridge_domain_uid"),
    "arp": ("device_uid", "vrf", "context_uid", "ip", "mac", "interface_name", "af"),
    "bgp_session_routes": (
        "device_uid",
        "context_uid",
        "session_uid",
        "peer_ip",
        "safi",
        "direction",
        "rib_type",
        "policy_stage",
        "path_id",
        "prefix",
        "next_hop",
        "next_hop_context_uid",
        "as_path",
        "local_pref",
        "med",
        "origin",
        "communities",
        "best",
        "af",
        "prefixlen",
        "lo",
        "hi",
    ),
}


# --- the reference implementations -------------------------------------------------------


def _reference_rib_rows(
    route_rows: list[dict[str, Any]], *, next_hop_key: str, interface_key: str, next_hop_vrf_key: str | None
) -> list[dict]:
    """The reference mapping of the full record list. It reads a leaked
    route's next-hop VRF and the IOS-XR template's `connected` next hop and
    `vrf <name>` interface as `cisco_common.rib_row` reads them."""
    rows = []
    for r in route_rows:
        next_hop = r.get(next_hop_key) or None
        interface = r.get(interface_key) or None
        next_hop_vrf = (r.get(next_hop_vrf_key) or None) if next_hop_vrf_key else None
        if next_hop == "connected":
            next_hop = None
        if interface and interface.startswith("vrf "):
            next_hop_vrf, interface = interface[len("vrf ") :], None
        rows.append(
            {
                "vrf": r.get("vrf") or "default",
                "prefix": f"{r['network']}/{r['prefix_length']}",
                "next_hop": next_hop,
                "next_hop_vrf": next_hop_vrf,
                "interface": interface,
                "protocol": expand_protocol(r.get("protocol")),
                "metric": int(r["metric"]) if r.get("metric") else None,
            }
        )
    return rows


def _reference_if_vrf_map(vrf_rows: list[dict[str, Any]], *, vrf_key: str) -> dict[str, str]:
    # The map is keyed by the name `show vrf` prints. The golden payloads
    # spell every member in full.
    out: dict[str, str] = {}
    for row in vrf_rows:
        for ifname in row.get("interfaces") or []:
            out[ifname] = row[vrf_key]
    return out


def _reference_arp_rows(records: list[dict[str, Any]], vrf_by_if: dict[str, str]) -> list[dict]:
    return [
        {
            "vrf": vrf_by_if.get(r.get("interface") or "", "default"),
            "ip": r["ip_address"],
            "mac": canonical_mac(r.get("mac_address")),
            "interface_name": r.get("interface"),
        }
        for r in records
    ]


def _reference_command_outcome(
    text: Any, recorded: SectionOutcome | None, row_count: int | None
) -> TableOutcome:
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
    count = row_count or 0
    if not count:
        return TableOutcome(status="complete-empty", row_count=0)
    return TableOutcome(status="complete", row_count=count)


def _ordered(rows: Any) -> list[list[tuple[str, Any]]]:
    """Rows as their ordered items, so a comparison sees key order too."""
    return [list(row.items()) for row in rows]


# --- the golden cases --------------------------------------------------------------------


class _Case(NamedTuple):
    key: str
    family: str
    module: ModuleType
    payload: dict[str, Any]
    collector: CiscoCliCollector
    golden: dict[str, Any]


@pytest.fixture(scope="module", params=TEXT_CASES)
def case(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory) -> _Case:
    """One golden case: its payload, and a collector configured as the golden
    values were computed, over a data directory of its own. Module scope
    groups every test of a case, so each payload is built once."""
    key: str = request.param
    family, _scale, _variant = split_case(key)
    data_dir = tmp_path_factory.mktemp(key.replace("/", "-"))
    return _Case(
        key,
        family,
        _FAMILIES[family],
        case_payload(key),
        make_collector(family, make_settings(data_dir)),
        GOLDEN["cases"][key],
    )


@pytest.fixture(scope="module")
def inter(case: _Case) -> dict[str, Any]:
    """The family's `parse` of the case's payload, parsed once per case."""
    parsed: dict[str, Any] = case.module.parse(case.payload)
    return parsed


def test_parse_gives_the_golden_intermediate_shape(case: _Case, inter: dict[str, Any]) -> None:
    assert inter_digest(inter) == case.golden["inter"]
    # rib, arp and mac_table stay lists: the cross-family contract
    assert_inter_shape(inter)


def test_rib_and_arp_rows_equal_the_reference_mapping_of_the_records(
    case: _Case, inter: dict[str, Any]
) -> None:
    """Built at the parse site, the rows equal the reference mapping of the
    full record list, key order included."""
    module, os_name = case.module, case.family
    next_hop_key, interface_key, next_hop_vrf_key = _RIB_KEYS[os_name]
    records = cli_parse.parse(os_name, module.CMD_ROUTE, case.payload[module.CMD_ROUTE])
    expected_rib = _reference_rib_rows(
        records, next_hop_key=next_hop_key, interface_key=interface_key, next_hop_vrf_key=next_hop_vrf_key
    )
    vrf_rows = cli_parse.parse(os_name, module.CMD_VRF, case.payload[module.CMD_VRF])
    vrf_by_if = _reference_if_vrf_map(vrf_rows, vrf_key=_VRF_KEY[os_name])
    expected_arp = _reference_arp_rows(
        cli_parse.parse(os_name, module.CMD_ARP, case.payload[module.CMD_ARP]), vrf_by_if
    )

    assert type(inter["rib"]) is list and type(inter["arp"]) is list
    assert _ordered(inter["rib"]) == _ordered(expected_rib)
    assert _ordered(inter["arp"]) == _ordered(expected_arp)


def test_sections_and_table_outcomes_match_the_golden_file(case: _Case) -> None:
    # no golden payload holds the command of an `ADDED_SINCE_BASE` section, so
    # the section reads `unknown`
    base, added = without_added_sections(case.family, outcomes_json(case.collector.sections(case.payload)))
    assert base == case.golden["sections"]
    assert added == {
        name: {"detail": "", "row_count": None, "status": "unknown"} for name in ADDED_SINCE_BASE[case.family]
    }
    stated = held_mac_statement(case.family, case.collector.table_outcomes(case.payload), written=False)
    assert outcomes_json(stated) == case.golden["table_outcomes"]


@pytest.mark.parametrize("family", ["iosxe", "iosxr", "nxos"])
def test_the_added_sections_are_named_by_the_families_own_commands(family: str) -> None:
    """`ADDED_SINCE_BASE` names each section by the command the family declares for it."""
    module = importlib.import_module(f"hst.collectors.{family}")
    assert {name: module.SECTIONS[name].command for name in ADDED_SINCE_BASE[family]} == ADDED_SINCE_BASE[
        family
    ]


def test_side_tables_match_the_golden_file(case: _Case) -> None:
    side = case.collector.side_tables(case.payload)

    assert {table: list(rows_digest(rows)) for table, rows in side.items()} == case.golden["side_tables"]
    for table, keys in _SIDE_KEYS.items():
        if table in side:
            assert isinstance(side[table], streams.MappedRows), table
            assert all(tuple(row) == keys for row in side[table]), table
    for table in ("bgp_sessions", "ospf_lsdb"):
        if table in side:
            assert type(side[table]) is list, table


def test_a_side_row_can_be_read_by_index(case: _Case) -> None:
    """The shape `test_named_vrf_bgp` reads: one row by its index, without a
    pass over the rest."""
    side = case.collector.side_tables(case.payload)
    for table in ("rib", "bgp_session_routes"):
        rows = side.get(table) or []
        if not rows:
            continue
        first = next(iter(rows))
        assert rows[0] == first
        assert rows[-len(rows)] == first
        assert rows[len(rows) // 2] == list(rows)[len(rows) // 2]
        with pytest.raises(IndexError):
            rows[len(rows)]


def test_side_store_files_match_the_golden_file(case: _Case, tmp_path: Path) -> None:
    """Every table written from the views gives the golden rows, row groups,
    schema and row order."""
    side = case.collector.side_tables(case.payload)
    assert set(side) == set(case.golden["parquet"])
    for table, rows in sorted(side.items()):
        path = sidestore.write_table(
            tmp_path,
            table,
            COLLECTOR_SOURCE,
            COLLECTOR_HOST,
            RUN_ID,
            rows,
            snapshot_ts=SNAPSHOT_TS,
            row_group_rows=ROW_GROUP_ROWS,
        )
        facts = [0, None] if path is None else list(manifest.sidestore_row_facts(path))
        assert facts == case.golden["parquet"][table], table
        assert parquet_layout(path) == case.golden["parquet_layout"][table], table


def test_the_written_table_outcomes_match_the_golden_file(case: _Case) -> None:
    """`_write_side_tables` over the views: the same outcomes, row counts and
    file paths. The run id is the golden one, so the paths compare as they
    are."""
    source, host = collectors_base._identity(case.collector, None)
    outcomes = collectors_base._write_side_tables(
        case.collector, case.payload, source, host, run_id=RUN_ID, collection_ts=SNAPSHOT_TS, on_write=None
    )
    assert outcomes_json(held_mac_statement(case.family, outcomes, written=True)) == case.golden["tables"]


def test_observed_paths_are_a_view_over_the_payloads_own_answers(case: _Case, inter: dict[str, Any]) -> None:
    observed = inter["bgp_observed"]
    routes = observed["routes"]
    answered = [entry for entry in observed["directions"] if entry["row_count"] is not None]

    assert isinstance(routes, streams.ChainRows)
    assert len(routes) == sum(entry["row_count"] for entry in answered)
    parts = routes._parts
    assert len(parts) == len(answered)
    for (count, factory), entry in zip(parts, answered, strict=True):
        assert count == entry["row_count"]
        # the payload's own str, never a copy of it
        assert factory.args[0] is case.payload[entry["command"]]


def test_observed_paths_are_the_printed_paths_on_every_pass(case: _Case, inter: dict[str, Any]) -> None:
    """Each pass yields fresh dicts, the same on every pass; on a synthetic
    case they are the 13-key rows the generator printed
    (`expected_ios_paths`), in its order and key order. The family tests hold
    the fixture paths."""
    observed = inter["bgp_observed"]
    first = list(observed["routes"])
    second = list(observed["routes"])
    assert second == first
    assert all(a is not b for a, b in zip(first, second, strict=True))
    if split_case(case.key)[1] == "fixture":
        return
    printed = expected_ios_paths(case.key)
    expected: list[dict[str, Any]] = []
    for entry in observed["directions"]:
        paths = printed[entry["command"]]
        assert entry["row_count"] == len(paths)
        expected.extend(paths)
    assert _ordered(first) == _ordered(expected)


@pytest.mark.parametrize("key", NXOS_CASES)
def test_nxos_rib_mac_and_arp_side_rows_match_the_golden_file(key: str, tmp_path: Path) -> None:
    """`cisco_common.side_rows` builds these three tables for NX-OS too."""
    collector = make_collector("nxos", make_settings(tmp_path))
    side = collector.side_tables(case_payload(key))
    golden = GOLDEN["cases"][key]["side_tables"]
    for table in ("rib", "mac", "arp"):
        assert list(rows_digest(side[table])) == golden[table], table
        assert all(tuple(row) == _SIDE_KEYS[table] for row in side[table]), table


# --- the BGP path parser, line by line -----------------------------------------------------

_WINDOWS = (1, 7, 64, streams.WINDOW_CHARS)

# Fields of a path row, fields that are not, and every separator `str.split`
# or `str.splitlines` treats specially: the text is cut into lines by all of
# the second and into fields by all of both.
_FIELDS = (
    "*>",
    "*",
    "* i",
    "r>",
    "s>",
    "*>i",
    "10.0.0.0/24",
    "10.0.0.0",
    "2001:db8::/32",
    "192.0.2.1",
    "0",
    "100",
    "32768",
    "65001",
    "i",
    "e",
    "?",
    "x",
    "Network",
    "Total",
    "%",
)
_SPACES = (" ", " ", " ", "  ", "\t", "\xa0", "\u3000", "\x1f")
_BREAKS = ("\n", "\n", "\r\n", "\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029")


def _path_text(rng: random.Random) -> str:
    """A random path-table-like text: mostly lines of six to ten fields."""
    lines = []
    for _ in range(rng.randrange(0, 12)):
        fields = [rng.choice(_FIELDS) for _ in range(rng.randrange(0, 11))]
        line = ""
        for field in fields:
            line += field + rng.choice(_SPACES)
        lines.append(line.rstrip(" ") if rng.randrange(2) else line)
    text = ""
    for line in lines:
        text += line + rng.choice(_BREAKS)
    return text if rng.randrange(3) else text.rstrip("\n")


def _path_record(row: Any, *, peer_ip: str, direction: str) -> dict[str, Any]:
    """The `iter_bgp_paths` record of one printed path row."""
    status, prefix, next_hop, metric, local_pref, _weight, as_path, origin = row
    return {
        "peer_ip": peer_ip,
        "direction": direction,
        "prefix": prefix,
        "path_id": None,
        "next_hop": next_hop,
        "as_path": as_path,
        "local_pref": int(local_pref) if local_pref else None,
        "med": int(metric) if metric else None,
        "origin": origin,
        "communities": None,
        "best": None if direction == "received" else ">" in status,
    }


@pytest.mark.parametrize("family", sorted(_FAMILIES))
def test_the_path_parser_reads_random_tables_at_every_window_size(
    family: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Random tables give the records they were printed from at every window
    size. The random path-table-like text holds no complete header, so it
    yields no records; it checks that nothing raises."""
    module = _FAMILIES[family]
    rng = random.Random(f"bgp-path-lines:{family}")
    tables = [random_table(rng, rng.choice([0, 1, 2])) for _ in range(300)]
    texts = [_path_text(rng) for _ in range(1500)]
    read = {text: module.parse_bgp_paths(text, peer_ip="192.0.2.1", direction="accepted") for text in texts}
    assert not any(read.values())
    for window in _WINDOWS:
        monkeypatch.setattr(streams, "WINDOW_CHARS", window)
        for text, rows in tables:
            assert module._count_bgp_paths(text) == len(rows), (window, text)
            for direction in ("received", "accepted"):
                paths = [_path_record(row, peer_ip="192.0.2.1", direction=direction) for row in rows]
                built = module.parse_bgp_paths(text, peer_ip="192.0.2.1", direction=direction)
                assert _ordered(built) == _ordered(paths), (window, text)
                lazy = module.iter_bgp_paths(text, peer_ip="192.0.2.1", direction=direction)
                assert _ordered(lazy) == _ordered(paths), (window, text)
        for text in texts:
            paths = module.parse_bgp_paths(text, peer_ip="192.0.2.1", direction="accepted")
            assert _ordered(paths) == _ordered(read[text]), (window, text)
            assert module._count_bgp_paths(text) == len(paths), (window, text)


@pytest.mark.parametrize("key", [key for key in TEXT_CASES if split_case(key)[1] == "small"])
def test_the_path_parser_reads_every_golden_table_alike_at_every_window_size(
    key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    family, _scale, _variant = split_case(key)
    module = _FAMILIES[family]
    payload = case_payload(key)
    printed = expected_ios_paths(key)
    assert any(printed.values())
    for window in _WINDOWS:
        monkeypatch.setattr(streams, "WINDOW_CHARS", window)
        for command, paths in printed.items():
            text = payload[command]
            assert module._count_bgp_paths(text) == len(paths), window
            if not paths:
                continue
            read = module.iter_bgp_paths(text, peer_ip=paths[0]["peer_ip"], direction=paths[0]["direction"])
            unstamped = [{k: v for k, v in path.items() if k not in ("vrf", "af")} for path in paths]
            assert _ordered(read) == _ordered(unstamped), window


# --- the observation outcome ---------------------------------------------------------------

_OK = SectionOutcome(status="ok")
_RECORDED = (
    _OK,
    _OK,
    _OK,
    _OK,
    None,
    SectionOutcome(status="unsupported", detail="% Invalid input"),
    SectionOutcome(status="unauthorized", detail="denied"),
    SectionOutcome(status="failed"),
)

# Every whitespace and line-boundary class `strip` and `splitlines` know, a few
# that are neither (U+FEFF, U+200B), and the `%` a refusal starts with.
_PIECES = (
    "",
    " ",
    "\t",
    "\n",
    "\r",
    "\r\n",
    "\x0b",
    "\x0c",
    "\x1c",
    "\x1d",
    "\x1e",
    "\x1f",
    "\x85",
    "\xa0",
    "\u1680",
    "\u2000",
    "\u2028",
    "\u2029",
    "\u3000",
    "\ufeff",
    "\u200b",
    "%",
    "% ",
    "x",
    "BGP",
    "% BGP is not configured",
    "*> 10.0.0.0/24 192.0.2.1 0 100 0 65001 i",
)
_NOT_TEXT: tuple[Any, ...] = (None, 0, 5, [], {}, (), {"a": "% x"}, ["% y", "z"], False, True, 0.0)

# The named shapes, each followed by an explicit expectation below.
_NAMED = {
    "none": None,
    "empty": "",
    "whitespace only": " \t\r\n\x0b\x0c\x1c\x1f ",
    "next line U+0085": "\x85% refused\x85second",
    "line separator U+2028": "%\u2028refused",
    "no-break space": "\xa0% refused\xa0\n",
    "crlf": "% refused\r\nsecond\r\n",
    "% after leading whitespace": "  \n\t% soft reconfiguration not configured  \nmore",
    "% not at the start": "BGP table\n% trailing",
}


@pytest.mark.parametrize("family", sorted(_FAMILIES))
@pytest.mark.parametrize("name", sorted(_NAMED))
def test_the_outcome_of_a_named_answer_equals_the_base_outcome(family: str, name: str) -> None:
    text = _NAMED[name]
    for row_count in (None, 0, 3):
        assert _FAMILIES[family]._command_outcome(text, _OK, row_count) == _reference_command_outcome(
            text, _OK, row_count
        )


def test_the_named_answers_read_as_expected() -> None:
    """What the reference says about the named shapes, so the randomized
    comparison below cannot pass by two readings agreeing on a wrong one."""
    for module in _FAMILIES.values():
        outcome = module._command_outcome
        assert outcome(None, _OK, 3) == TableOutcome(status="complete-empty", row_count=0)
        assert outcome("", _OK, 3) == TableOutcome(status="complete-empty", row_count=0)
        assert outcome(_NAMED["whitespace only"], _OK, 3) == TableOutcome(
            status="complete-empty", row_count=0
        )
        assert outcome(_NAMED["next line U+0085"], _OK, 3).detail == "% refused"
        assert outcome(_NAMED["line separator U+2028"], _OK, 3).detail == "%"
        assert outcome(_NAMED["no-break space"], _OK, 3).detail == "% refused"
        assert outcome(_NAMED["crlf"], _OK, 3).detail == "% refused"
        assert outcome(_NAMED["% after leading whitespace"], _OK, 3) == TableOutcome(
            status="not-captured", detail="% soft reconfiguration not configured"
        )
        assert outcome(_NAMED["% not at the start"], _OK, 3) == TableOutcome(status="complete", row_count=3)


@pytest.mark.parametrize("family", sorted(_FAMILIES))
def test_the_outcome_equals_the_base_outcome_on_random_answers(family: str) -> None:
    """100,000 random answers per family, against the base implementation."""
    command_outcome = _FAMILIES[family]._command_outcome
    rng = random.Random(f"command-outcome:{family}")
    for index in range(100_000):
        if index % 50 == 0:
            text: Any = rng.choice(_NOT_TEXT)
        else:
            text = "".join(rng.choice(_PIECES) for _ in range(rng.randrange(0, 9)))
        recorded = rng.choice(_RECORDED)
        row_count = rng.choice((None, 0, 1, 7))
        assert command_outcome(text, recorded, row_count) == _reference_command_outcome(
            text, recorded, row_count
        ), (text, recorded, row_count)
