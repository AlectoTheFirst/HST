"""cli_parse's direct TextFSM driver against the CliTable parse.

`cli_parse.parse` runs a single-template command through TextFSM itself, one
window of lines at a time. The
reference below is the CliTable parse: the preamble trim by
split and join, `parse_output` through `_parse_via_clitable`, and the same error
message. Every case gives equal records, or raises TextFSMError with an equal
message, at every window size.

The CLI texts are the hand-written fixtures of the IOS-XE, IOS-XR and cli_parse
tests, and synthetic route tables; nothing here was captured from real
infrastructure.
"""

from __future__ import annotations

import gc
import io
import os
import random
import time
import tracemalloc
from collections.abc import Callable
from typing import Any

import pytest
import tests.test_bgp_peer_router_id as bgp_router_id_tests
import tests.test_cli_parse as cli_parse_tests
import tests.test_iosxe as iosxe_tests
import tests.test_iosxr as iosxr_tests
from ntc_templates.parse import ParsingException
from textfsm import TextFSM, TextFSMError

from hst.collectors import cli_parse, iosxe, iosxr, streams

# The reference parse, kept before any test replaces the module attribute.
_CLITABLE = cli_parse._parse_via_clitable

_WINDOWS = (1, 7, 64, 1 << 20)

_ROUTE = {"iosxe": iosxe.CMD_ROUTE, "iosxr": iosxr.CMD_ROUTE}


def _reference(os_name: str, command: str, output: str) -> list[dict[str, Any]]:
    """The CliTable parse: split/join preamble trim, then `_parse_via_clitable`."""
    platform = cli_parse._PLATFORM[os_name]
    lines = output.split("\n")
    skipped = cli_parse._preamble(platform, command, lines)
    try:
        return _CLITABLE(platform, command, "\n".join(lines[skipped:]) if skipped else output)
    except TextFSMError as exc:
        head = " | ".join(line.strip() for line in lines[:3] if line.strip())
        raise TextFSMError(
            f"{os_name} ({platform}), command {command!r}: {exc}; "
            f"{skipped} preamble line(s) dropped, output starts {head[:160]!r}"
        ) from exc


def _outcome(fn: Callable[..., list[Any]], *args: Any, **kwargs: Any) -> tuple[str, Any]:
    try:
        return ("records", fn(*args, **kwargs))
    except TextFSMError as exc:
        return ("error", str(exc))


def _without_clitable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any fall back to CliTable fail the test, so parity cannot pass by
    comparing CliTable with itself."""

    def refuse(platform: str, command: str, data: str) -> list[dict[str, Any]]:
        raise AssertionError(f"{platform} {command!r} fell back to CliTable")

    monkeypatch.setattr(cli_parse, "_parse_via_clitable", refuse)


# Texts in the layout of templates the collector fixtures never fill: the
# generic OSPF database listing (Filldown, Clearall and a second state), the
# OSPF interface brief and the IOS-XR BGP table.
OSPF_DATABASE_TEXT = """\

            OSPF Router with ID (10.0.0.1) (Process ID 1)

\t\tRouter Link States (Area 0)

Link ID         ADV Router      Age         Seq#       Checksum Link count
10.0.0.1        10.0.0.1        120         0x80000002 0x00A1B2 2
10.0.0.2        10.0.0.2        130         0x80000003 0x00C3D4 3

\t\tNet Link States (Area 0)

Link ID         ADV Router      Age         Seq#       Checksum
10.0.12.2       10.0.0.2        140         0x80000001 0x00E5F6

\t\tType-5 AS External Link States

Link ID         ADV Router      Age         Seq#       Checksum Tag
192.0.2.0       10.0.0.1        150         0x80000001 0x001234 0
198.51.100.0    10.0.0.2        160         0x80000001 0x005678 100
"""

OSPF_INTERFACE_BRIEF_TEXT = """\
Interface    PID   Area            IP Address/Mask    Cost  State Nbrs F/C
Lo0          1     0               10.0.0.1/32        1     LOOP  0/0
Gi1          1     0               10.0.12.1/24       1     BDR   1/1
"""

IOSXR_BGP_TABLE_TEXT = """\
BGP router identifier 10.0.0.1, local AS number 65000
BGP generic scan interval 60 secs
Non-stop routing is enabled
BGP table state: Active
Table ID: 0xe0000000   RD version: 12
BGP main routing table version 12
BGP NSR Initial initsync version 4 (Reached)
BGP scan interval 60 secs

Status codes: s suppressed, d damped, h history, * valid, > best
              i - internal, r RIB-failure, S stale, N Nexthop-discard
Origin codes: i - IGP, e - EGP, ? - incomplete
   Network            Next Hop            Metric LocPrf Weight Path
*> 10.0.0.0/8         192.0.2.1                0    100      0 65001 i
* i                   192.0.2.2              900    100      0 65002 65003 i
*> 172.16.0.0/12      192.0.2.1                0    100      0 65001 ?

Processed 2 prefixes, 3 paths
"""


def _has_template(os_name: str, command: str) -> bool:
    platform = cli_parse._PLATFORM[os_name]
    index = cli_parse._index(cli_parse._template_dir(platform, command)).index
    return bool(index.GetRowMatch({"Command": command, "Platform": platform}))


def _templated_commands() -> list[tuple[str, str]]:
    """Every command the IOS-XE and IOS-XR collectors define that has a template."""
    commands = set()
    for os_name, collector in (("iosxe", iosxe), ("iosxr", iosxr)):
        for name, command in vars(collector).items():
            if name.startswith("CMD_") and isinstance(command, str) and _has_template(os_name, command):
                commands.add((os_name, command))
    return sorted(commands)


def _corpus() -> dict[tuple[str, str], list[str]]:
    """Every templated command, with each distinct text the collector tests'
    fixture dicts give it, plus the cli_parse tests' own commands and texts."""
    texts: dict[tuple[str, str], list[str]] = {key: [] for key in _templated_commands()}
    for os_name, fixtures in (("iosxe", iosxe_tests), ("iosxr", iosxr_tests)):
        for value in vars(fixtures).values():
            if not isinstance(value, dict):
                continue
            for command, text in value.items():
                key = (os_name, command)
                if key in texts and isinstance(text, str) and text and text not in texts[key]:
                    texts[key].append(text)
    show_vrf = cli_parse_tests.IOSXE_SHOW_VRF
    extra = [
        (("iosxe", "show ip interface brief"), cli_parse_tests.IOSXE_IP_INT_BRIEF),
        (("iosxe", "show ip interface brief"), cli_parse_tests.BANNER + cli_parse_tests.IOSXE_IP_INT_BRIEF),
        (("iosxr", "show ipv4 interface brief"), cli_parse_tests.IOSXR_IPV4_INT_BRIEF),
        (("iosxe", "show vrf"), show_vrf),
        (("iosxe", "show vrf"), cli_parse_tests.BANNER + show_vrf),
        (("iosxe", "show vrf"), cli_parse_tests.BANNER),
        (("iosxe", "show vrf"), "junk\n" * (cli_parse._PREAMBLE_LIMIT + 1) + show_vrf),
        (("iosxe", "show vrf"), "junk\n" * (cli_parse._PREAMBLE_LIMIT - 1) + show_vrf),
        (("iosxe", "show vrf"), "% Invalid input detected at '^' marker.\n"),
        (("iosxe", "show vrf"), "A device answer no detector knows\n"),
        (("iosxe", "show vrf"), "CCCC;\n"),
        (("iosxe", "show ip access-lists"), cli_parse_tests.IOSXE_ACL_ICMP),
        (("iosxe", "sh ip access-lists"), cli_parse_tests.IOSXE_ACL_ICMP),
        (("iosxe", iosxe.CMD_OSPF_IF), OSPF_INTERFACE_BRIEF_TEXT),
        # the per-VRF ARP command, read with the `show ip arp` template
        (("iosxe", iosxe.CMD_ARP_VRF), iosxe_tests.ARP_TEXT),
        (("iosxr", iosxr.CMD_BGP_SESSIONS), IOSXR_BGP_TABLE_TEXT),
        (("iosxr", iosxr.CMD_BGP_NEIGHBORS), bgp_router_id_tests.IOSXR_NEIGHBORS),
        # ntc-templates' index sends `show bgp vrf all neighbors` to the BGP table
        # template (`show bgp vrf (\S+) ...`); the collector reads it with
        # `cisco_bgp.parse_neighbor_router_ids`, not through a template.
        (("iosxr", iosxr.CMD_BGP_VRF_NEIGHBORS), bgp_router_id_tests.IOSXR_VRF_NEIGHBORS),
        (("iosxr", iosxr.CMD_BGP_VRF_NEIGHBORS), IOSXR_BGP_TABLE_TEXT),
    ]
    extra += [
        (("iosxe", command), OSPF_DATABASE_TEXT)
        for command in (
            iosxe.CMD_OSPF_DB_SUMMARY,
            iosxe.CMD_OSPF_DB_ASBR_SUMMARY,
            iosxe.CMD_OSPF_DB_EXTERNAL,
            iosxe.CMD_OSPF_DB_NSSA_EXTERNAL,
        )
    ]
    for key, text in extra:
        texts.setdefault(key, []).append(text)
    # One text written for another command of the same OS, so every template
    # also meets output it does not expect: most send it to Error.
    for (os_name, command), own in texts.items():
        foreign = [t for (o, c), ts in texts.items() if o == os_name and c != command for t in ts]
        own.append(max(foreign, key=len))
    return texts


_CORPUS = _corpus()

_BANNER = "CCCC\n*** Authorised access only ***\n"


def _with_nel(text: str) -> str:
    """`text` with U+0085 inside one line near its middle. `splitlines` breaks
    the line there and `split("\\n")` does not."""
    lines = text.split("\n")
    candidates = [i for i, line in enumerate(lines) if len(line) > 1]
    if not candidates:
        return text + "\x85"
    i = candidates[len(candidates) // 2]
    k = len(lines[i]) // 2
    lines[i] = lines[i][:k] + "\x85" + lines[i][k:]
    return "\n".join(lines)


def _variants(text: str) -> dict[str, str]:
    return {
        "as is": text,
        "no trailing newline": text.removesuffix("\n"),
        "banner": _BANNER + text,
        "crlf": text.replace("\n", "\r\n"),
        "nel": _with_nel(text),
    }


def _cases(texts: list[str]) -> list[tuple[str, str]]:
    cases = [("empty", "")]
    for number, text in enumerate(texts):
        cases += [(f"text {number}, {name}", variant) for name, variant in _variants(text).items()]
    return cases


def test_the_corpus_covers_every_templated_command_with_its_own_text():
    assert set(_templated_commands()) <= _CORPUS.keys()
    for (os_name, command), texts in _CORPUS.items():
        # At least one text of its own besides the foreign one.
        assert len(texts) >= 2, (os_name, command)
        assert cli_parse._single_template(cli_parse._PLATFORM[os_name], command) is not None, command


@pytest.mark.parametrize(("os_name", "command"), sorted(_CORPUS), ids=lambda v: v)
def test_the_direct_driver_matches_clitable(monkeypatch, os_name, command):
    cases = _cases(_CORPUS[(os_name, command)])
    expected = {name: _outcome(_reference, os_name, command, text) for name, text in cases}
    _without_clitable(monkeypatch)
    mismatches = []
    for size in _WINDOWS:
        monkeypatch.setattr(streams, "WINDOW_CHARS", size)
        for name, text in cases:
            got = _outcome(cli_parse.parse, os_name, command, text)
            if got != expected[name]:
                mismatches.append((size, name, expected[name], got))
    assert mismatches == []
    # The matrix reads records as well as errors.
    assert any(kind == "records" and records for kind, records in expected.values())


# --- synthetic route tables -----------------------------------------------------------


def _xe_routes(n: int) -> str:
    rnd = random.Random(5)
    out = [
        "Routing Table: default",
        "Codes: L - local, C - connected, S - static, B - BGP",
        "",
        "Gateway of last resort is not set",
        "",
    ]
    for i in range(n):
        if i and i % 10_000 == 0:
            out += ["", f"Routing Table: CUST{i // 10_000}", "Gateway of last resort is not set", ""]
        a, b, c = rnd.randrange(1, 223), rnd.randrange(256), rnd.randrange(256)
        if i % 100 == 0:
            out.append(f"S        {a}.{b}.{c}.0/24 [1/0] via 10.255.0.2, GigabitEthernet1/0/{i % 8}")
        else:
            out.append(f"B        {a}.{b}.{c}.0/24 [20/0] via 203.0.113.{i % 7 + 1}, 2w3d")
        if i % 10 == 0:
            out.append(f"                  [20/0] via 203.0.113.{i % 5 + 9}, 2w3d")
    return "\n".join(out) + "\n"


def _xr_routes(n: int) -> str:
    rnd = random.Random(7)
    out = ["Codes: C - connected, S - static, R - RIP, B - BGP, (>) - Diversion path", ""]
    for i in range(n):
        if i % 10_000 == 0:
            vrf = "default" if i == 0 else f"CUST{i // 10_000}"
            out += [f"VRF: {vrf}", "", "Gateway of last resort is not set", ""]
        a, b, c = rnd.randrange(1, 223), rnd.randrange(256), rnd.randrange(256)
        if i % 100 == 0:
            out.append(f"S    {a}.{b}.{c}.0/24 [1/0] via 10.255.0.2, 00:10:00, GigabitEthernet0/0/0/{i % 8}")
        else:
            out.append(f"B    {a}.{b}.{c}.0/24 [20/0] via 203.0.113.{i % 7 + 1}, 2w3d")
        if i % 10 == 0:
            out.append(f"                 [20/0] via 203.0.113.{i % 5 + 9}, 2w3d")
    return "\n".join(out) + "\n"


def _with_unknown_line(text: str) -> str:
    lines = text.split("\n")
    lines.insert(len(lines) // 2, "this line is not part of any route table")
    return "\n".join(lines)


_SYNTHETIC = {"iosxe": _xe_routes(30_000), "iosxr": _xr_routes(30_000)}


@pytest.fixture(scope="module")
def synthetic_reference() -> dict[str, tuple[str, Any]]:
    references = {
        os_name: _outcome(_reference, os_name, _ROUTE[os_name], text) for os_name, text in _SYNTHETIC.items()
    }
    references["iosxr unknown line"] = _outcome(
        _reference, "iosxr", iosxr.CMD_ROUTE, _with_unknown_line(_SYNTHETIC["iosxr"])
    )
    return references


@pytest.mark.parametrize("size", [1, 4096, 1 << 20])
@pytest.mark.parametrize("os_name", ["iosxe", "iosxr"])
def test_a_30k_route_table_matches_clitable(monkeypatch, synthetic_reference, os_name, size):
    expected = synthetic_reference[os_name]
    assert expected[0] == "records"
    assert len(expected[1]) == 33_000
    _without_clitable(monkeypatch)
    monkeypatch.setattr(streams, "WINDOW_CHARS", size)
    assert _outcome(cli_parse.parse, os_name, _ROUTE[os_name], _SYNTHETIC[os_name]) == expected


@pytest.mark.parametrize("size", [1, 4096, 1 << 20])
def test_an_unknown_line_mid_table_costs_that_line_alone(monkeypatch, synthetic_reference, size):
    expected = synthetic_reference["iosxr unknown line"]
    assert expected == synthetic_reference["iosxr"]
    _without_clitable(monkeypatch)
    monkeypatch.setattr(streams, "WINDOW_CHARS", size)
    text = _with_unknown_line(_SYNTHETIC["iosxr"])
    assert _outcome(cli_parse.parse, "iosxr", iosxr.CMD_ROUTE, text) == expected


# --- a state change to EOF ------------------------------------------------------------


def _lldp_neighbor(interface: str) -> str:
    return (
        "------------------------------------------------\n"
        f"Local Intf: {interface}\n"
        "Chassis id: aabb.ccdd.ef01\n"
        "Port id: Gi2/0/1\n"
        "Port Description: Gi2/0/1\n"
        "System Name: core1\n"
        "\n"
        "Time remaining: 100 seconds\n"
        "System Capabilities: B,R\n"
        "Enabled Capabilities: B,R\n"
        "Management Addresses:\n"
        "    IP: 10.0.0.254\n"
        "\n"
    )


# One neighbor, then a line the IOS-XE LLDP template sends to EOF, then two more
# neighbors TextFSM never reads.
LLDP_WITH_EOF = (
    _lldp_neighbor("Gi1/0/1")
    + "------------------------------------------------\n"
    + "% Invalid input detected at '^' marker.\n"
    + _lldp_neighbor("Gi1/0/2")
    + _lldp_neighbor("Gi1/0/3")
    + "------------------------------------------------\n"
    + "Total entries displayed: 3\n"
)


def _stopless_count(platform: str, command: str, text: str, size: int) -> int:
    """Records from a driver that keeps feeding windows after EOF: what the stop
    in `_parse_direct` prevents."""
    fsm = TextFSM(io.StringIO(cli_parse._single_template(platform, command)))
    count = 0
    for window in streams.line_windows(text, 0, size):
        result = fsm.ParseText(window, eof=False)
        count += len(result)
        del result[:]
    return count + len(fsm.ParseText("", eof=True))


@pytest.mark.parametrize("size", _WINDOWS)
def test_the_driver_stops_where_textfsm_stops(monkeypatch, size):
    expected = _reference("iosxe", iosxe.CMD_LLDP, LLDP_WITH_EOF)
    assert [r["local_interface"] for r in expected] == ["Gi1/0/1"]
    _without_clitable(monkeypatch)
    monkeypatch.setattr(streams, "WINDOW_CHARS", size)
    assert cli_parse.parse("iosxe", iosxe.CMD_LLDP, LLDP_WITH_EOF) == expected


def test_the_eof_case_catches_a_driver_that_does_not_stop():
    assert _stopless_count("cisco_ios", iosxe.CMD_LLDP, LLDP_WITH_EOF, 1) == 3


# --- the CliTable path ----------------------------------------------------------------

DIR_TEXT = """\
Directory of flash:/

    1  -rw-        2048  Jan 1 2024 00:00:00 +00:00  config.txt
    2  drwx        4096  Jan 1 2024 00:00:00 +00:00  logs

7340032 bytes total (3584000 bytes free)
"""


def test_a_command_with_no_index_row_raises_parsing_exception():
    assert cli_parse._single_template("cisco_ios", "show frobnicate widget") is None
    with pytest.raises(ParsingException, match="show frobnicate widget"):
        cli_parse.parse("iosxe", "show frobnicate widget", "any output at all")


def test_a_fillup_template_takes_the_clitable_path(monkeypatch):
    """Fillup writes into records already emitted, which a drained window does
    not hold, so the command takes the CliTable path."""
    assert cli_parse._single_template("cisco_ios", "dir") is None
    monkeypatch.setattr(streams, "WINDOW_CHARS", 1)
    records = cli_parse.parse("iosxe", "dir", DIR_TEXT)
    assert records == _CLITABLE("cisco_ios", "dir", DIR_TEXT)
    assert [(r["name"], r["total_size"]) for r in records] == [("config.txt", "7340032"), ("logs", "7340032")]


def test_a_multi_template_row_takes_the_clitable_path():
    assert cli_parse._single_template("cisco_ios", "show module") is None
    assert cli_parse.parse("iosxe", "show module", "") == _CLITABLE("cisco_ios", "show module", "")


def test_an_unknown_textfsm_turns_the_direct_driver_off(monkeypatch):
    assert cli_parse._direct_supported() is True
    monkeypatch.setattr(cli_parse, "_direct_supported", lambda: False)
    assert cli_parse._single_template.__wrapped__("cisco_ios", iosxe.CMD_ROUTE) is None


@pytest.mark.parametrize(
    ("os_name", "command", "text"),
    [
        ("iosxe", iosxe.CMD_ROUTE, iosxe_tests.ROUTE_TEXT),
        ("iosxe", "show vrf", cli_parse_tests.BANNER + cli_parse_tests.IOSXE_SHOW_VRF),
        ("iosxe", "show vrf", cli_parse_tests.BANNER),
        ("iosxr", iosxr.CMD_ROUTE, _BANNER + iosxr_tests.ROUTE_TEXT),
    ],
)
def test_the_clitable_path_trims_and_reports_as_the_direct_path(monkeypatch, os_name, command, text):
    direct = _outcome(cli_parse.parse, os_name, command, text)
    monkeypatch.setattr(cli_parse, "_single_template", lambda platform, command: None)
    assert _outcome(cli_parse.parse, os_name, command, text) == direct
    assert _outcome(_reference, os_name, command, text) == direct


# --- row= -----------------------------------------------------------------------------


def _rib_like(record: dict[str, Any]) -> dict[str, Any]:
    """The shape of a RIB side-table row, built from an IOS-XE route record."""
    return {
        "vrf": record.get("vrf") or "default",
        "prefix": f"{record['network']}/{record['prefix_length']}",
        "next_hop": record.get("nexthop_ip") or None,
        "interface": record.get("nexthop_if") or None,
        "protocol": record.get("protocol"),
        "metric": int(record["metric"]) if record.get("metric") else None,
    }


@pytest.mark.parametrize("size", [1, 1 << 20])
def test_row_maps_every_record_in_order(monkeypatch, size):
    monkeypatch.setattr(streams, "WINDOW_CHARS", size)
    text = _xe_routes(2_000)
    rows = cli_parse.parse("iosxe", iosxe.CMD_ROUTE, text, row=_rib_like)
    assert rows == [_rib_like(r) for r in cli_parse.parse("iosxe", iosxe.CMD_ROUTE, text)]
    assert len(rows) == 2_200

    def name(record: dict[str, Any]) -> tuple[str, str]:
        return (record["name"], record["total_size"])

    assert cli_parse.parse("iosxe", "dir", DIR_TEXT, row=name) == [
        name(r) for r in cli_parse.parse("iosxe", "dir", DIR_TEXT)
    ]


def test_a_row_error_propagates_unchanged():
    def bad(record: dict[str, Any]) -> Any:
        raise KeyError("prefix")

    with pytest.raises(KeyError):
        cli_parse.parse("iosxe", iosxe.CMD_ROUTE, iosxe_tests.ROUTE_TEXT, row=bad)


# --- tolerance ------------------------------------------------------------------------


def _bad_arp_table() -> str:
    """An IOS-XR ARP table of 500 entries, then a line its template sends to Error."""
    interface = "GigabitEthernet0/0/0/0"
    rows = [
        f"10.{i // 250}.{i % 250}.1        00:05:00   aabb.ccdd.{i:04x}  Dynamic    ARPA  {interface}"
        for i in range(500)
    ]
    header = "Address         Age        Hardware Addr   State      Type  Interface"
    return "\n".join([header, *rows, "this line is not part of any arp table"]) + "\n"


def _arp_like(record: dict[str, Any]) -> dict[str, Any]:
    """The shape of an ARP side-table row, built from an IOS-XR ARP record."""
    return {"ip": record["ip_address"], "mac": record["mac_address"], "interface_name": record["interface"]}


def test_within_tolerance_an_optional_command_error_discards_its_records(monkeypatch):
    _without_clitable(monkeypatch)
    monkeypatch.setattr(streams, "WINDOW_CHARS", 64)
    with cli_parse.tolerating({iosxr.CMD_VERSION}) as failures:
        assert cli_parse.parse("iosxr", iosxr.CMD_ARP, _bad_arp_table(), row=_arp_like) == []
        assert cli_parse.parse("iosxr", iosxr.CMD_ARP, _bad_arp_table()) == []
    assert list(failures) == [iosxr.CMD_ARP]
    assert "Input Line: this line is not part of any arp table" in failures[iosxr.CMD_ARP]
    assert f"iosxr (cisco_xr), command {iosxr.CMD_ARP!r}" in failures[iosxr.CMD_ARP]


def test_within_tolerance_a_required_command_error_raises(monkeypatch):
    _without_clitable(monkeypatch)
    with cli_parse.tolerating({iosxr.CMD_ARP}) as failures, pytest.raises(TextFSMError):
        cli_parse.parse("iosxr", iosxr.CMD_ARP, _bad_arp_table())
    assert failures == {}


# --- the direct path stays on ---------------------------------------------------------


@pytest.mark.parametrize("os_name", ["iosxe", "iosxr"])
def test_route_parses_take_the_direct_path(monkeypatch, os_name):
    """The route tables never fall back to CliTable."""
    _without_clitable(monkeypatch)
    fixture = {"iosxe": iosxe_tests.ROUTE_TEXT, "iosxr": iosxr_tests.ROUTE_TEXT}[os_name]
    assert len(cli_parse.parse(os_name, _ROUTE[os_name], fixture)) == 2
    assert len(cli_parse.parse(os_name, _ROUTE[os_name], _SYNTHETIC[os_name])) == 33_000


# --- the head of the output -----------------------------------------------------------


def test_the_head_is_the_start_of_split():
    rnd = random.Random(11)
    for _ in range(500):
        lines = ["x" * rnd.randrange(0, 5) for _ in range(rnd.randrange(0, 120))]
        text = "\n".join(lines) + rnd.choice(["", "\n", "\r\n", "\n\n"])
        assert cli_parse._head(text) == text.split("\n")[: cli_parse._PREAMBLE_LIMIT]


# --- memory and time ------------------------------------------------------------------


def test_a_mapped_route_parse_holds_little_more_than_its_rows():
    """At most 600 B per record above the text, the mapped rows included."""
    text = _xe_routes(100_000)
    cli_parse.parse("iosxe", iosxe.CMD_ROUTE, _xe_routes(10), row=_rib_like)
    gc.collect()
    was_tracing = tracemalloc.is_tracing()
    if not was_tracing:
        tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        before = tracemalloc.get_traced_memory()[0]
        rows = cli_parse.parse("iosxe", iosxe.CMD_ROUTE, text, row=_rib_like)
        peak = tracemalloc.get_traced_memory()[1] - before
    finally:
        if not was_tracing:
            tracemalloc.stop()
    assert len(rows) == 110_000
    assert peak / len(rows) <= 600


def _best_of(runs: int, fn: Callable[[], Any]) -> float:
    best = float("inf")
    for _ in range(runs):
        started = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - started)
    return best


@pytest.mark.perf
@pytest.mark.skipif(os.environ.get("HST_PERF") != "1", reason="HST_PERF not set")
def test_the_direct_route_parse_is_at_least_three_times_faster_than_clitable():
    text = _xe_routes(100_000)
    direct = _best_of(2, lambda: cli_parse.parse("iosxe", iosxe.CMD_ROUTE, text))
    clitable = _best_of(2, lambda: _CLITABLE("cisco_ios", iosxe.CMD_ROUTE, text))
    assert clitable / direct >= 3, f"direct {direct:.2f}s, CliTable {clitable:.2f}s"
