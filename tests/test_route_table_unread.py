"""A line of a Cisco route table the template cannot read costs that line alone."""

from __future__ import annotations

import io
import logging
from types import ModuleType
from typing import Any

import pytest
import tests.test_iosxe as iosxe_tests
import tests.test_iosxr as iosxr_tests
from ntc_templates.parse import _get_template_dir, parse_output
from tests.conftest import FakeSshSession
from tests.support.synthetic_payloads import SNAPSHOT_TS, case_payload, make_collector, make_settings
from textfsm import TextFSM, TextFSMError

from hst import collectors as coll
from hst.collectors import cli_parse, iosxe, iosxr, iosxr_bgp, streams
from hst.collectors.base import RAW_OUTCOMES_KEY
from hst.core.manifest import BGP_SESSIONS_TABLE, bgp_direction_key
from hst.core.model import SectionOutcome, TableOutcome, section_verdict

_MODULES: dict[str, ModuleType] = {"iosxe": iosxe, "iosxr": iosxr}
_FIXTURE = {"iosxe": iosxe_tests.ROUTE_TEXT, "iosxr": iosxr_tests.ROUTE_TEXT}
_UNKNOWN = "THIS IS NOT A ROUTE LINE"
_BANNER = "CCCC\n*** Authorised access only ***\n"


def _installed(family: str, text: str) -> list[dict[str, Any]]:
    """The records of the route template ntc-templates installs."""
    return parse_output(
        platform=cli_parse._PLATFORM[family],
        command=_MODULES[family].CMD_ROUTE,
        template_dir=_get_template_dir(),
        data=text,
    )


def _as_installed(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """`records` without the `backup` value the repository IOS-XR template
    adds, which the installed template does not have."""
    return [{k: v for k, v in r.items() if k != "backup"} for r in records]


def _read(family: str, text: str) -> tuple[list[dict[str, Any]], int]:
    return cli_parse.parse_with_unread(family, _MODULES[family].CMD_ROUTE, text)


def _insert(text: str, after: str, *lines: str) -> str:
    """`text` with `lines` after the first line that starts with `after`."""
    rows = text.split("\n")
    at = next(i for i, row in enumerate(rows) if row.startswith(after)) + 1
    return "\n".join([*rows[:at], *lines, *rows[at:]])


def _without_clitable(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(platform: str, command: str, data: str) -> list[dict[str, Any]]:
        raise AssertionError(f"{platform} {command!r} fell back to CliTable")

    monkeypatch.setattr(cli_parse, "_parse_via_clitable", refuse)


# --- the records every other line gives -------------------------------------------------------


_KNOWN_TABLES = [
    f"{family}/{case}"
    for family in ("iosxe", "iosxr")
    for case in ("fixture/plain", "small/plain", "small/unicode", "small/no_trailing_newline")
]


@pytest.mark.parametrize("key", _KNOWN_TABLES)
def test_a_table_whose_every_line_is_known_parses_as_the_installed_template_does(key: str) -> None:
    family = key.split("/")[0]
    text = case_payload(key)[_MODULES[family].CMD_ROUTE]
    records, unread = _read(family, text)
    assert unread == 0
    assert records and _as_installed(records) == _installed(family, text)


@pytest.mark.parametrize("family", ["iosxe", "iosxr"])
def test_a_banner_in_front_of_the_table_is_a_preamble_and_is_not_counted(family: str) -> None:
    assert _read(family, _BANNER + _FIXTURE[family]) == _read(family, _FIXTURE[family])
    assert _read(family, _FIXTURE[family])[1] == 0


# --- IOS-XR: a line upstream's template sends to Error --------------------------------------


def _xr_with_unknown_lines() -> tuple[str, str]:
    """A synthetic IOS-XR table, and the same table with three unknown lines:
    before its first route, where no value of a route is set yet, in the middle
    of the routes, and at its end."""
    text = case_payload("iosxr/small/plain")[iosxr.CMD_ROUTE]
    rows = text.split("\n")
    mid = len(rows) // 2
    mixed = "\n".join([*rows[:mid], f"{_UNKNOWN} 2", *rows[mid:]]) + f"{_UNKNOWN} 3\n"
    return text, _insert(mixed, "Gateway of last resort", f"{_UNKNOWN} 1")


@pytest.mark.parametrize("size", [1, 64, 1 << 20])
def test_an_iosxr_line_the_template_cannot_read_costs_that_line(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, size: int
) -> None:
    clean, mixed = _xr_with_unknown_lines()
    expected = _read("iosxr", clean)[0]
    _without_clitable(monkeypatch)
    monkeypatch.setattr(streams, "WINDOW_CHARS", size)
    with caplog.at_level(logging.WARNING, logger="hst.collectors.cli_parse"):
        assert _read("iosxr", mixed) == (expected, 3)
    assert [r.getMessage() for r in caplog.records] == [
        "iosxr: 'show route vrf all ipv4': 3 line(s) of the answer could not be read and were left out,"
        f" first '{_UNKNOWN} 1'"
    ]


def test_the_installed_iosxr_template_fails_on_the_same_text() -> None:
    """What the repository's template replaces."""
    with pytest.raises(TextFSMError, match=_UNKNOWN):
        _installed("iosxr", _xr_with_unknown_lines()[1])


def test_an_unknown_line_inside_a_route_entry_ends_the_entry() -> None:
    """`Routing entry for` opens the single-route detail state; a line it does
    not know is counted and the table is read on from the next line."""
    table = _FIXTURE["iosxr"]
    text = _insert(table, "VRF: mgmt", "Routing entry for 10.9.0.0/16", _UNKNOWN)
    records, unread = _read("iosxr", text)
    assert unread == 1
    assert [r["network"] for r in records] == [r["network"] for r in _read("iosxr", table)[0]]


# --- IOS-XE: a line upstream's template passes over without a word ---------------------------


# `+` marks a replicated route, a flag the IOS-XE template does not list.
_REPLICATED = "B  +     10.9.0.0/16 [20/0] via 203.0.113.1, 2w3d"


def test_an_iosxe_route_line_of_a_layout_the_template_lacks_is_counted() -> None:
    table = _FIXTURE["iosxe"]
    # The first lands before any route of the first VRF, the second right after
    # the next VRF's header has cleared every value.
    text = _insert(_insert(table, "Gateway of last resort", _REPLICATED), "Routing Table: mgmt", _REPLICATED)
    records, unread = _read("iosxe", text)
    assert unread == 2
    assert records == _read("iosxe", table)[0] == _installed("iosxe", text)


def test_an_iosxe_next_hop_line_with_no_network_is_dropped_as_required_drops_it() -> None:
    """The template marks NETWORK Required; `cli_parse` applies it for the
    repository's copy. A next-hop line before any network is not a route, and
    it is not an unread line either: a rule read it."""
    text = _insert(
        _FIXTURE["iosxe"], "Gateway of last resort", "                  [20/0] via 203.0.113.9, 2w3d"
    )
    records, unread = _read("iosxe", text)
    assert unread == 0
    assert records == _installed("iosxe", text) == _read("iosxe", _FIXTURE["iosxe"])[0]


def test_the_header_of_every_further_vrf_is_read() -> None:
    """The code legend, the gateway line and blank lines of each VRF after the
    first are named in the repository's template; the installed one passes
    over them."""
    text = case_payload("iosxe/small/plain")[iosxe.CMD_ROUTE]
    assert text.count("Routing Table:") > 1
    assert _read("iosxe", text)[1] == 0


# Route lines with more after the network than a rule reads: an IPv6 next hop,
# a column the template does not know, and an IPv6 next hop whose first groups
# are digits alone.
_XE_UNKNOWN_LAYOUTS = (
    "B        10.1.0.0/16 [20/0] via FE80::1, 00:00:05, GigabitEthernet2",
    "B        10.2.0.0/16 NEWCOL [20/0] via 10.0.0.9, 00:00:05",
    "B        10.3.0.0/16 [20/0] via 2001:1:2::1, 00:00:05, GigabitEthernet2",
)


@pytest.mark.parametrize("size", [1, 64, 1 << 20])
def test_an_iosxe_route_line_with_more_after_its_network_is_counted(
    monkeypatch: pytest.MonkeyPatch, size: int
) -> None:
    """Upstream's rules for a network whose route continues on the next line
    take any such line for one, and the route is left out without a word; the
    repository's copy ends them at the end of the line."""
    table = _FIXTURE["iosxe"]
    text = _insert(table, "Gateway of last resort", *_XE_UNKNOWN_LAYOUTS)
    _without_clitable(monkeypatch)
    monkeypatch.setattr(streams, "WINDOW_CHARS", size)
    assert _read("iosxe", text) == (_read("iosxe", table)[0], 3)


def test_the_installed_iosxe_template_reads_an_ipv6_next_hop_as_an_ipv4_one() -> None:
    """What the literal dots of the repository's copy prevent."""
    text = _insert(_FIXTURE["iosxe"], "Gateway of last resort", _XE_UNKNOWN_LAYOUTS[2])
    assert "2001:1:2" in [record["nexthop_ip"] for record in _installed("iosxe", text)]


def test_a_route_that_continues_on_the_next_line_is_read_as_upstream_reads_it() -> None:
    text = (
        "Routing Table: default\n"
        "Codes: L - local, C - connected, S - static, O - OSPF, B - BGP\n"
        "\n"
        "Gateway of last resort is not set\n"
        "\n"
        "O E2     10.1.1.0/24 \n"
        "           [110/20] via 10.0.0.1, 00:00:01, GigabitEthernet1\n"
        "      10.0.0.0/8 is variably subnetted, 2 subnets, 2 masks\n"
        "O        10.2.0.0\n"
        "           [110/20] via 10.0.0.2, 00:00:01, GigabitEthernet1\n"
    )
    records, unread = _read("iosxe", text)
    assert unread == 0
    assert [(r["network"], r["prefix_length"], r["nexthop_ip"]) for r in records] == [
        ("10.1.1.0", "24", "10.0.0.1"),
        ("10.2.0.0", "8", "10.0.0.2"),
    ]
    assert records == _installed("iosxe", text)


# --- the paths after an unread route line ------------------------------------------------------


_XR_MULTIPATH = (
    "VRF: default\n"
    "\n"
    "Gateway of last resort is not set\n"
    "\n"
    "S    10.0.0.0/24 [1/0] via 10.0.0.254, 00:10:00, GigabitEthernet0/0/0/0\n"
    "{unread}"
    "B    10.8.0.0/16 [200/0] via 10.2.2.1, 00:10:00, GigabitEthernet0/0/0/1\n"
    "               [200/0] via 10.2.2.2, 00:10:00, GigabitEthernet0/0/0/2\n"
)
_XR_UNREAD_ROUTE = "B    10.9.0.0/16 [200/0] via fe80::1, 00:10:00, GigabitEthernet0/0/0/1\n"
_XR_UNREAD_PATH = "               [200/0] via 10.1.1.{n}, 00:10:00, GigabitEthernet0/0/0/2\n"
_XE_MULTIPATH = (
    "Routing Table: default\n"
    "Codes: L - local, C - connected, S - static, B - BGP\n"
    "\n"
    "Gateway of last resort is not set\n"
    "\n"
    "S        10.0.0.0/24 [1/0] via 10.0.0.254, GigabitEthernet1\n"
    "{unread}"
    "B        10.8.0.0/16 [20/0] via 203.0.113.5, 2w3d\n"
    "                     [20/0] via 203.0.113.6, 2w3d\n"
)
_XE_UNREAD_ROUTE = _REPLICATED + "\n"
_XE_UNREAD_PATH = "                     [20/0] via 203.0.113.{n}, 2w3d\n"
_MULTIPATH = {
    "iosxr": (_XR_MULTIPATH, _XR_UNREAD_ROUTE, _XR_UNREAD_PATH),
    "iosxe": (_XE_MULTIPATH, _XE_UNREAD_ROUTE, _XE_UNREAD_PATH),
}


@pytest.mark.parametrize("size", [1, 64, 1 << 20])
@pytest.mark.parametrize("paths", [1, 2])
@pytest.mark.parametrize("family", ["iosxe", "iosxr"])
def test_the_further_paths_of_an_unread_route_are_unread(
    monkeypatch: pytest.MonkeyPatch, family: str, paths: int, size: int
) -> None:
    """Upstream's rule for a further path gives it to the route read last, which
    after an unread route line is the route before it."""
    table, route, path = _MULTIPATH[family]
    clean = table.format(unread="")
    text = table.format(unread=route + "".join(path.format(n=n) for n in range(paths)))
    _without_clitable(monkeypatch)
    monkeypatch.setattr(streams, "WINDOW_CHARS", size)
    records, unread = _read(family, text)
    assert unread == 1 + paths
    assert records == _read(family, clean)[0]
    assert _as_installed(records) == _installed(family, clean)
    assert len(records) == 3


@pytest.mark.parametrize("family", ["iosxe", "iosxr"])
def test_a_path_line_after_an_unknown_line_is_unread_too(family: str) -> None:
    table, _, path = _MULTIPATH[family]
    text = table.format(unread=f"{_UNKNOWN}\n" + path.format(n=7))
    assert _read(family, text) == (_read(family, table.format(unread=""))[0], 2)


@pytest.mark.parametrize(
    ("platform", "command", "table", "after", "continuation", "continuations"),
    [
        # a further path, and the rest of a connected route on the line below it
        ("cisco_ios", iosxe.CMD_ROUTE, "Routes", "AfterUnread", (r"^\s+\[", r"^\s+is\sdirectly"), 3),
        # a further path, with its next hop in this VRF or in another one
        ("cisco_xr", iosxr.CMD_ROUTE, "Start", "AFTER_UNREAD", (r"^\s+(?:\[",), 3),
    ],
)
def test_the_state_after_an_unread_line_reads_as_the_table_state_reads(
    platform: str, command: str, table: str, after: str, continuation: tuple[str, ...], continuations: int
) -> None:
    """The state holds a copy of the table state's rules, less the ones that
    read the line after a route line. The copies must not drift apart."""
    reading = cli_parse._unread_template(platform, command)
    assert reading is not None
    states = TextFSM(io.StringIO(reading.text)).states
    rules = [rule for rule in states[table] if not rule.match.startswith(continuation)]
    assert len(states[table]) - len(rules) == continuations
    copies = states[after]
    assert rules[-1].match == copies[-1].match == "^${UNREAD}"
    assert (rules[-1].record_op, rules[-1].new_state) == ("Record", after)
    assert (copies[-1].record_op, copies[-1].new_state) == ("Record", "")
    assert [rule.match for rule in copies[:-1]] == [rule.match for rule in rules[:-1]]
    for copy, rule in zip(copies[:-1], rules[:-1], strict=True):
        assert (copy.line_op, copy.record_op) == (rule.line_op, rule.record_op)
        assert copy.new_state == ("" if rule.line_op == "Continue" else rule.new_state or table)


# --- an answer with no line the template reads -------------------------------------------------


_NO_TABLE = [
    "% Permission denied for the role\n",
    "% Permission denied for the role",
    _BANNER,
    "NEW FORMAT LINE 1\n\n   \nNEW FORMAT LINE 2\n",
]


@pytest.mark.parametrize("size", [1, 1 << 20])
@pytest.mark.parametrize("answer", _NO_TABLE)
@pytest.mark.parametrize("family", ["iosxe", "iosxr"])
def test_an_answer_of_which_no_line_could_be_read_raises(
    monkeypatch: pytest.MonkeyPatch, family: str, answer: str, size: int
) -> None:
    """It is no route table with lines missing, and a `partial` rib section
    would load an empty RIB for the device."""
    monkeypatch.setattr(streams, "WINDOW_CHARS", size)
    with pytest.raises(TextFSMError, match="no line of the answer could be read") as caught:
        _read(family, answer)
    assert answer.splitlines()[0] in str(caught.value)


@pytest.mark.parametrize("family", ["iosxe", "iosxr"])
def test_the_clitable_reference_raises_on_the_same_answers(family: str) -> None:
    for answer in _NO_TABLE:
        with pytest.raises(TextFSMError, match="no line of the answer could be read"):
            cli_parse._parse_via_clitable(cli_parse._PLATFORM[family], _MODULES[family].CMD_ROUTE, answer)


@pytest.mark.parametrize("family", ["iosxe", "iosxr"])
def test_a_device_whose_route_answer_holds_no_readable_line_fails(family: str) -> None:
    payload = case_payload(f"{family}/small/plain")
    payload[_MODULES[family].CMD_ROUTE] = _NO_TABLE[0]
    with pytest.raises(TextFSMError, match="no line of the answer could be read"):
        make_collector(family, None).normalize(payload)


@pytest.mark.parametrize(
    ("family", "answer"),
    [
        ("iosxe", ""),
        ("iosxe", "\n \n"),
        ("iosxr", "% No matching routes found\n"),
        ("iosxr", "VRF: default\n\nGateway of last resort is not set\n\n"),
    ],
)
def test_an_answer_with_no_route_is_an_empty_table(family: str, answer: str) -> None:
    assert _read(family, answer) == ([], 0)


@pytest.mark.parametrize(
    "answer",
    [
        "VRF: default\n\nGateway of last resort is not set\n\n" + _UNKNOWN + "\n",
        # A line of whitespace inside a route entry is unread, and the entry
        # line was read.
        "Routing entry for 10.9.0.0/16\n   \n",
    ],
)
def test_a_table_with_no_route_and_an_unread_line_is_read_with_the_count(answer: str) -> None:
    assert _read("iosxr", answer) == ([], 1)


@pytest.mark.parametrize("family", ["iosxe", "iosxr"])
def test_a_blank_line_does_not_start_the_table(family: str) -> None:
    """A line of whitespace before the table is no sign that it has started:
    each leading line until the first one the template reads is a preamble."""
    head = ["CCCC", "", "*** Authorised access only ***", "   "]
    lines = [*head, *_FIXTURE[family].split("\n")]
    platform = cli_parse._PLATFORM[family]
    assert cli_parse._preamble(platform, _MODULES[family].CMD_ROUTE, lines) == len(head)
    assert _read(family, "\n".join(lines)) == _read(family, _FIXTURE[family])


# --- without the direct driver -----------------------------------------------------------------


def test_without_the_direct_driver_the_whole_text_is_read_in_one_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CliTable applies Required as the template declares it, which drops some
    unread lines' records before they are counted, so a template that declares
    UNREAD never falls back to it."""
    mixed = _xr_with_unknown_lines()[1]
    direct = _read("iosxr", mixed)
    xe_text = _insert(_FIXTURE["iosxe"], "Gateway of last resort", _REPLICATED)
    xe_direct = _read("iosxe", xe_text)
    multipath = {
        family: table.format(unread=route + path.format(n=1))
        for family, (table, route, path) in _MULTIPATH.items()
    }
    multipath_direct = {family: _read(family, text) for family, text in multipath.items()}
    monkeypatch.setattr(cli_parse, "_direct_supported", lambda: False)
    _without_clitable(monkeypatch)
    assert _read("iosxr", mixed) == direct
    assert _read("iosxe", xe_text) == xe_direct
    assert direct[1] == 3 and xe_direct[1] == 1
    for family, text in multipath.items():
        assert _read(family, text) == multipath_direct[family]
        assert multipath_direct[family][1] == 2
        with pytest.raises(TextFSMError, match="no line of the answer could be read"):
            _read(family, _NO_TABLE[0])


def test_the_clitable_reference_gives_the_records_without_the_unread_lines() -> None:
    clean, mixed = _xr_with_unknown_lines()
    reference = cli_parse._parse_via_clitable("cisco_xr", iosxr.CMD_ROUTE, mixed)
    assert reference == _read("iosxr", clean)[0]
    assert all("unread" not in record for record in reference)


# --- the templates and their index -------------------------------------------------------------


@pytest.mark.parametrize(
    ("platform", "command", "repository"),
    [
        ("cisco_ios", iosxe.CMD_ROUTE, True),
        ("cisco_ios", "sh ip ro vrf *", True),
        ("cisco_ios", "show ip route", False),
        ("cisco_ios", "show ip route summary", False),
        ("cisco_ios", "show ip rip database", False),
        ("cisco_xr", iosxr.CMD_ROUTE, True),
        ("cisco_xr", "show route", False),
        ("cisco_xr", "show route summary", False),
    ],
)
def test_the_repository_rows_take_the_collector_commands_alone(
    platform: str, command: str, repository: bool
) -> None:
    assert (cli_parse._template_dir(platform, command) == cli_parse._OVERRIDE_DIR) is repository


def test_only_the_repository_route_templates_declare_unread() -> None:
    assert cli_parse._unread_template("cisco_ios", iosxe.CMD_ROUTE) is not None
    assert cli_parse._unread_template("cisco_xr", iosxr.CMD_ROUTE) is not None
    assert cli_parse._unread_template("cisco_ios", "show ip access-lists") is None
    assert cli_parse._unread_template("cisco_ios", "show vrf") is None


def test_required_is_taken_off_the_value_lines_alone() -> None:
    text = (
        "Value Required,Filldown NETWORK (\\S+)\n"
        "Value Required NEXT_HOP (\\S+)\n"
        "Value Filldown,Required VRF (\\S+)\n"
        "Value UNREAD (.+)\n"
        "\n"
        "Start\n"
        "  ^Required -> Record\n"
    )
    assert cli_parse._without_required(text) == (
        "Value Filldown NETWORK (\\S+)\n"
        "Value NEXT_HOP (\\S+)\n"
        "Value Filldown VRF (\\S+)\n"
        "Value UNREAD (.+)\n"
        "\n"
        "Start\n"
        "  ^Required -> Record\n"
    )


# --- the rib section -----------------------------------------------------------------------------


def test_the_section_outcome_states_the_lines_left_out() -> None:
    ok = SectionOutcome(status="ok", row_count=7)
    assert cli_parse.unread_outcome(ok, 0) is ok
    assert cli_parse.unread_outcome(ok, 1) == SectionOutcome(
        status="partial", detail="1 line of the answer could not be read", row_count=7
    )
    assert cli_parse.unread_outcome(SectionOutcome(status="empty", row_count=0), 3) == SectionOutcome(
        status="partial", detail="3 lines of the answer could not be read", row_count=0
    )
    assert cli_parse.unread_outcome(SectionOutcome(status="unknown"), 2) == SectionOutcome(
        status="unknown", detail="2 lines of the answer could not be read"
    )
    failed = SectionOutcome(status="failed", detail="% Permission denied")
    assert cli_parse.unread_outcome(failed, 2) is failed


@pytest.mark.parametrize("family", ["iosxe", "iosxr"])
def test_the_rib_section_is_partial_and_nothing_else_changes(family: str) -> None:
    module = _MODULES[family]
    payload = case_payload(f"{family}/small/plain")
    clean = make_collector(family, None)
    expected_sections = clean.sections(payload)
    expected_rows = list(clean.side_tables(payload)["rib"])
    payload[module.CMD_ROUTE] = _insert(payload[module.CMD_ROUTE], "Gateway of last resort", _UNKNOWN)

    collector = make_collector(family, None)
    sections = collector.sections(payload)
    assert sections["rib"] == SectionOutcome(
        status="partial",
        detail="1 line of the answer could not be read",
        row_count=expected_sections["rib"].row_count,
    )
    assert {name: s for name, s in sections.items() if name != "rib"} == {
        name: s for name, s in expected_sections.items() if name != "rib"
    }
    assert section_verdict(sections, collector.AUTHORITATIVE_SECTIONS) == "ok"
    assert list(collector.side_tables(payload)["rib"]) == expected_rows
    assert collector.normalize(payload).sections == sections


def test_a_payload_that_predates_outcome_recording_keeps_unknown_and_gains_the_count() -> None:
    payload = case_payload("iosxr/fixture/plain")
    assert RAW_OUTCOMES_KEY not in payload
    payload[iosxr.CMD_ROUTE] = _insert(payload[iosxr.CMD_ROUTE], "VRF: mgmt", _UNKNOWN)
    assert make_collector("iosxr", None).sections(payload)["rib"] == SectionOutcome(
        status="unknown", detail="1 line of the answer could not be read"
    )


def test_the_intermediate_shape_holds_the_count_only_when_there_is_one() -> None:
    table = _FIXTURE["iosxr"]
    raw = dict(iosxr_tests.RAW)
    assert iosxr.RIB_UNREAD_KEY not in iosxr.parse(raw)
    raw[iosxr.CMD_ROUTE] = _insert(table, "VRF: mgmt", _UNKNOWN, _UNKNOWN)
    assert iosxr.parse(raw)[iosxr.RIB_UNREAD_KEY] == 2
    xe_raw = dict(iosxe_tests.RAW)
    assert iosxe.RIB_UNREAD_KEY not in iosxe.parse(xe_raw)
    xe_raw[iosxe.CMD_ROUTE] = _insert(_FIXTURE["iosxe"], "Gateway of last resort", _REPLICATED)
    assert iosxe.parse(xe_raw)[iosxe.RIB_UNREAD_KEY] == 1


def test_an_observation_load_writes_every_row_it_read(tmp_path: Any) -> None:
    """An IOS-XR table with a line the template cannot read loads every row
    it read, states the partial section, and does not fail the device."""
    pytest.importorskip("pyarrow")
    payload = case_payload("iosxr/small/plain")
    expected_rows = len(list(make_collector("iosxr", None).side_tables(payload)["rib"]))
    payload[iosxr.CMD_ROUTE] = _insert(payload[iosxr.CMD_ROUTE], "Gateway of last resort", _UNKNOWN)
    collector = make_collector("iosxr", make_settings(tmp_path))
    manifest = coll.load_observations(
        collector,
        payload,
        collection_ts=SNAPSHOT_TS,
        run_id="1700000000000-cccccccc",
        ts_ms=SNAPSHOT_TS,
        source_name="edge",
    )
    assert manifest.sections is not None
    assert manifest.sections["rib"].status == "partial"
    assert section_verdict(manifest.sections, collector.AUTHORITATIVE_SECTIONS) == "ok"
    assert manifest.tables["rib"].status == "complete"
    assert manifest.tables["rib"].row_count == expected_rows


# --- the BGP running-config, parsed once -----------------------------------------------------


def _counting(monkeypatch: pytest.MonkeyPatch, module: ModuleType, name: str) -> list[str]:
    """The texts `module.name` is called with from here on."""
    calls: list[str] = []
    original = getattr(module, name)

    def counted(text: str) -> Any:
        calls.append(text)
        return original(text)

    monkeypatch.setattr(module, name, counted)
    return calls


def _load_pass(collector: Any, payload: dict[str, Any]) -> None:
    """What a load asks of the collector for one payload."""
    collector.normalize(payload)
    list(collector.side_tables(payload)["rib"])
    collector.table_outcomes(payload)
    collector.sections(payload)


def test_the_iosxe_bgp_configuration_is_parsed_once_per_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _counting(monkeypatch, iosxe, "parse_bgp_config")
    payload = case_payload("iosxe/small/plain")
    _load_pass(make_collector("iosxe", None), payload)
    assert calls == [payload[iosxe.CMD_BGP]]


def test_the_iosxr_table_outcomes_read_the_parse_of_the_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _counting(monkeypatch, iosxr_bgp, "parse_bgp")
    payload = case_payload("iosxr/small/plain")
    collector = make_collector("iosxr", None)
    collector._inter(payload)
    assert calls == [payload[iosxr.CMD_BGP]]
    _load_pass(collector, payload)
    assert calls == [payload[iosxr.CMD_BGP]]


_VRF_CONFIG = {
    "iosxe": (
        "router bgp 65000\n"
        " bgp router-id 10.0.0.1\n"
        " address-family ipv4 vrf BLUE\n"
        "  neighbor 198.51.100.2 remote-as 65100\n"
        " exit-address-family\n"
    ),
    "iosxr": (
        "router bgp 65000\n"
        " bgp router-id 192.0.2.1\n"
        " vrf BLUE\n"
        "  neighbor 198.51.100.2\n"
        "   remote-as 65100\n"
        "   address-family ipv4 unicast\n"
        "!\n"
    ),
}


@pytest.mark.parametrize("family", ["iosxe", "iosxr"])
def test_a_failed_vrf_summary_is_stated_on_the_session_table(family: str) -> None:
    """The VRF scopes of the session table come from the payload's own parse."""
    outcomes = _vrf_summary_outcomes(
        family, {"status": "ok"}, {"status": "failed", "detail": "% BLUE denied"}
    )
    assert outcomes[BGP_SESSIONS_TABLE] == TableOutcome(status="failed", detail="% BLUE denied")


@pytest.mark.parametrize("family", ["iosxe", "iosxr"])
def test_of_two_failed_summaries_the_first_the_fetch_sends_is_stated(family: str) -> None:
    """The same statement on every run, whatever order a set would iterate in."""
    default = {"status": "failed", "detail": "% default denied"}
    outcomes = _vrf_summary_outcomes(family, default, {"status": "failed", "detail": "% BLUE denied"})
    assert outcomes[BGP_SESSIONS_TABLE] == TableOutcome(status="failed", detail="% default denied")


def _vrf_summary_outcomes(
    family: str, default: dict[str, str], blue: dict[str, str]
) -> dict[str, TableOutcome]:
    """The table outcomes of a payload configured with the VRF BLUE, whose
    default and BLUE session summaries were recorded as given."""
    module = _MODULES[family]
    summary = module.bgp_summary_command("BLUE")
    raw = dict(case_payload(f"{family}/fixture/plain"))
    raw[module.CMD_BGP] = _VRF_CONFIG[family]
    raw[module.CMD_BGP_SESSIONS] = ""
    raw[summary] = ""
    raw[RAW_OUTCOMES_KEY] = {module.CMD_BGP_SESSIONS: default, summary: blue}
    outcomes: dict[str, TableOutcome] = make_collector(family, None).table_outcomes(raw)
    return outcomes


# --- the address family of each neighbor ------------------------------------------------------

_V6_PEER = "2001:db8::2"
# IOS-XR exchanges IPv4 unicast with a neighbor only where `address-family ipv4
# unicast` is configured for it, on the neighbor or through the groups it uses.
_XR_V6_CONFIG = (
    "router bgp 65000\n"
    " af-group V4 address-family ipv4 unicast\n"
    " neighbor 198.51.100.2\n"
    "  remote-as 65100\n"
    "  address-family ipv4 unicast\n"
    f" neighbor {_V6_PEER}\n"
    "  remote-as 65100\n"
    "  address-family ipv6 unicast\n"
    " neighbor 2001:db8::3\n"
    "  remote-as 65100\n"
    "  address-family ipv4 unicast\n"
    " neighbor 2001:db8::4\n"
    "  remote-as 65100\n"
    "  use af-group V4\n"
    "!\n"
)
# `parse_bgp_config` reads the default VRF's `address-family ipv6` block into
# its IPv4 process; a VRF whose first block is `address-family ipv6 vrf` is an
# IPv6 process.
_XE_V6_CONFIG = (
    "router bgp 65000\n"
    f" neighbor {_V6_PEER} remote-as 65100\n"
    " neighbor 198.51.100.2 remote-as 65100\n"
    " address-family ipv4\n"
    "  neighbor 198.51.100.2 activate\n"
    " exit-address-family\n"
    " address-family ipv6\n"
    f"  neighbor {_V6_PEER} activate\n"
    " exit-address-family\n"
    " address-family ipv6 vrf BLUE\n"
    "  neighbor 2001:db8::5 remote-as 65200\n"
    "  neighbor 2001:db8::5 activate\n"
    " exit-address-family\n"
)
_V6_CONFIG = {"iosxe": _XE_V6_CONFIG, "iosxr": _XR_V6_CONFIG}
_V6_TARGETS = {
    "iosxe": [("default", 4, "198.51.100.2"), ("default", 4, _V6_PEER), ("BLUE", 6, "2001:db8::5")],
    "iosxr": [
        ("default", 4, "198.51.100.2"),
        ("default", 6, _V6_PEER),
        ("default", 4, "2001:db8::3"),
        ("default", 4, "2001:db8::4"),
    ],
}
_V6_DETAIL = {
    "iosxe": "IOS-XE BGP session observation captures IPv4 unicast only",
    "iosxr": "IOS-XR BGP session observation captures IPv4 unicast only",
}


def test_an_iosxr_ipv6_neighbor_carries_ipv4_unicast_where_it_is_configured() -> None:
    assert iosxr._bgp_scoped_targets(iosxr_bgp.parse_bgp(_XR_V6_CONFIG)) == _V6_TARGETS["iosxr"]


def test_every_neighbor_of_an_iosxe_ipv4_process_is_an_ipv4_target() -> None:
    """`parse_bgp_config` does not record which address-family block activates
    a neighbor, so an IPv6 neighbor of the default VRF is sent the IPv4 path
    commands, and the device's answer states whether it carries IPv4 unicast."""
    assert iosxe._bgp_scoped_targets(iosxe.parse_bgp_config(_XE_V6_CONFIG)) == _V6_TARGETS["iosxe"]


@pytest.mark.parametrize("family", ["iosxe", "iosxr"])
def test_a_fetch_reads_the_paths_of_the_ipv4_targets_alone(
    monkeypatch: pytest.MonkeyPatch, family: str
) -> None:
    module = _MODULES[family]
    raw = {**case_payload(f"{family}/fixture/plain"), module.CMD_BGP: _V6_CONFIG[family]}
    fake = FakeSshSession(lambda command: raw.get(command, "")).install(monkeypatch)
    fetched = make_collector(family, None).fetch()
    paths = [command for command in fake.commands[len(module.COMMANDS) :] if " neighbors " in command]
    assert paths == [
        module.bgp_route_command(peer, direction, vrf)
        for vrf, af, peer in _V6_TARGETS[family]
        if af == 4
        for direction in module.BGP_DIRECTION_KEYWORDS
    ]
    directions = make_collector(family, None)._inter(fetched)["bgp_observed"]["directions"]
    assert list(dict.fromkeys((e["vrf"], e["af"], e["peer_ip"]) for e in directions)) == _V6_TARGETS[family]


@pytest.mark.parametrize("family", ["iosxe", "iosxr"])
def test_a_session_of_another_address_family_is_stated(family: str) -> None:
    """On the session table, and on each direction of the session, which is
    sent no path command."""
    module = _MODULES[family]
    raw = dict(case_payload(f"{family}/fixture/plain"))
    raw[module.CMD_BGP] = _V6_CONFIG[family]
    raw[module.CMD_BGP_SESSIONS] = ""
    raw[RAW_OUTCOMES_KEY] = {module.CMD_BGP_SESSIONS: {"status": "ok"}}
    collector = make_collector(family, None)
    outcomes = collector.table_outcomes(raw)
    stated = TableOutcome(status="not-captured", detail=_V6_DETAIL[family])
    assert outcomes[BGP_SESSIONS_TABLE] == stated
    device_uid = collector._device_uid(collector._inter(raw))
    for vrf, af, peer in _V6_TARGETS[family]:
        session_uid = module._bgp_session_uid(device_uid, peer, vrf)
        for direction in module.BGP_DIRECTION_KEYWORDS:
            # The path command of an IPv4 target is absent from this payload.
            expected = stated if af == 6 else TableOutcome(status="not-captured")
            assert outcomes[bgp_direction_key(session_uid, direction)] == expected


@pytest.mark.parametrize("family", ["iosxe", "iosxr"])
def test_an_ipv4_only_configuration_states_nothing_on_the_session_table(family: str) -> None:
    module = _MODULES[family]
    raw = dict(case_payload(f"{family}/fixture/plain"))
    raw[module.CMD_BGP] = _VRF_CONFIG[family]
    raw[module.CMD_BGP_SESSIONS] = ""
    raw[module.bgp_summary_command("BLUE")] = ""
    raw[RAW_OUTCOMES_KEY] = {
        module.CMD_BGP_SESSIONS: {"status": "ok"},
        module.bgp_summary_command("BLUE"): {"status": "ok"},
    }
    assert BGP_SESSIONS_TABLE not in make_collector(family, None).table_outcomes(raw)
