"""The IOS-XE and IOS-XR BGP path tables, read by column position
(`collectors/cisco_bgp_table.py`).

The tables here are laid out with IOS's own field widths, as Cisco documents
them and the ntc-templates of these commands read them; none was captured
from a real device. The synthetic cases (`tests/support/synthetic_payloads.py`)
are held to the values the generator printed (`expected_ios_paths`).
"""

from __future__ import annotations

import ipaddress
import json
import random
import re
from collections.abc import Iterator
from typing import Any

import pytest
from tests.support.gen_stream_golden import PARSER2_FIELDS
from tests.support.synthetic_payloads import (
    CASES,
    PARSER2_GOLDEN_PATH,
    SCALES,
    case_payload,
    expected_ios_paths,
    split_case,
)

from hst.collectors import cisco_bgp_table, iosxe, iosxr, iosxr_bgp, streams
from hst.collectors.base import RAW_OUTCOMES_KEY
from hst.collectors.cisco_bgp_table import Row, classful_prefix, holds_path_rows, path_rows
from hst.core.manifest import bgp_direction_key
from hst.core.model import TableOutcome

_MODULES = {"iosxe": iosxe, "iosxr": iosxr}
ZERO = "0.0.0.0"  # noqa: S104 - the default network and a local next hop, not a bind address
_WINDOWS = (1, 7, 64, streams.WINDOW_CHARS)

# --- table layouts -------------------------------------------------------------------------

XE_HEADER = "     Network          Next Hop            Metric LocPrf Weight Path"
CLASSIC_HEADER = "   Network          Next Hop            Metric LocPrf Weight Path"
XR_HEADER = "   Network            Next Hop            Metric LocPrf Weight Path"
FROM_HEADER = "Network            Next Hop        From            AS Path"


def _rest(next_hop: str, metric: str, local_pref: str, weight: str, path: str) -> str:
    """Next hop in 15 characters, then Metric in 10, LocPrf and Weight in 6,
    each after a space, then the AS path and origin after a space."""
    return f"{next_hop:<15} {metric:>10} {local_pref:>6} {weight:>6} {path}"


def xe(
    status: str,
    network: str,
    next_hop: str,
    metric: str = "",
    local_pref: str = "",
    weight: str = "0",
    path: str = "i",
) -> list[str]:
    """An IOS-XE 16 or later path: an RPKI code in column 0, the status in
    columns 1-3, the network at column 5 in 16 characters and a space. A
    wider network is printed alone, and the rest under the next hop column."""
    head = f"{status[0]}{status[1:]:<3} " if len(status) == 4 else f" {status:<3} "
    rest = _rest(next_hop, metric, local_pref, weight, path)
    if len(network) > 16:
        return [head + network, " " * 22 + rest]
    return [f"{head}{network:<16} {rest}"]


def classic(
    status: str,
    network: str,
    next_hop: str,
    metric: str = "",
    local_pref: str = "",
    weight: str = "0",
    path: str = "i",
) -> list[str]:
    """An IOS 12.x/15.x or IOS-XE 3.x path: the status in 3 characters, the
    network against it in 16 and a space."""
    rest = _rest(next_hop, metric, local_pref, weight, path)
    if len(network) > 16:
        return [f"{status:<3}{network}", " " * 20 + rest]
    return [f"{status:<3}{network:<16} {rest}"]


def xr(
    status: str,
    network: str,
    next_hop: str,
    metric: str = "",
    local_pref: str = "",
    weight: str = "0",
    path: str = "i",
) -> list[str]:
    """An IOS-XR path: the status in 3 characters, the network against it in
    18 and a space."""
    return [f"{status:<3}{network:<18} {_rest(next_hop, metric, local_pref, weight, path)}"]


def from_row(network: str, next_hop: str, source: str, path: str) -> list[str]:
    """A path of the IOS-XR advertised-routes table."""
    return [f"{network:<19}{next_hop:<16}{source:<16}{path}"]


_LAYOUTS = {"xe": (XE_HEADER, xe), "classic": (CLASSIC_HEADER, classic), "xr": (XR_HEADER, xr)}


def table(*parts: str | list[str]) -> str:
    return "\n".join(line for part in parts for line in ([part] if isinstance(part, str) else part)) + "\n"


XE_LEGEND = (
    "BGP table version is 58, local router ID is 10.255.255.1",
    "Status codes: s suppressed, d damped, h history, * valid, > best, i - internal,",
    "              r RIB-failure, S Stale, m multipath, b backup-path, f RT-Filter,",
    "              x best-external, a additional-path, c RIB-compressed,",
    "              t secondary path, L long-lived-stale,",
    "Origin codes: i - IGP, e - EGP, ? - incomplete",
    "RPKI validation codes: V valid, I invalid, N Not found",
    "",
)
XR_LEGEND = (
    "Thu Sep 24 10:00:00.000 UTC",
    "BGP router identifier 10.0.0.1, local AS number 65000",
    "BGP generic scan interval 60 secs",
    "Non-stop routing is enabled",
    "BGP table state: Active",
    "Table ID: 0xe0000000   RD version: 412345",
    "BGP main routing table version 412345",
    "BGP NSR Initial initsync version 4 (Reached)",
    "BGP NSR/ISSU Sync-Group versions 0/0",
    "BGP scan interval 60 secs",
    "",
    "Status codes: s suppressed, d damped, h history, * valid, > best",
    "              i - internal, r RIB-failure, S stale, N Nexthop-discard",
    "Origin codes: i - IGP, e - EGP, ? - incomplete",
)

# Example 1: blank Metric and LocPrf, classful networks, an AS set, origins e
# and ?, further paths of a prefix, a wrapped network with a further path, and
# an RPKI code with a LocPrf wider than its column.
IOSXE_ROUTES = table(
    *XE_LEGEND,
    XE_HEADER,
    xe("*>", ZERO, "192.0.2.1", path="64500 i"),
    xe("*>", "10.0.0.0", "192.0.2.1", metric="0", path="64500 ?"),
    xe("*>", "172.16.0.0", "192.0.2.1", local_pref="150", path="64500 64510 i"),
    xe("*>", "192.168.10.0", "192.0.2.1", metric="20", path="64500 {64520,64521} i"),
    xe("*>", "198.51.100.0/24", "192.0.2.1", path="64500 64496 64496 64496 e"),
    xe("*", "203.0.113.0/24", "192.0.2.9", path="64499 64496 i"),
    xe("*>", "", "192.0.2.1", metric="0", path="64500 64496 i"),
    xe("*>i", "10.1.1.0/24", "10.0.0.3", metric="0", local_pref="100", path="i"),
    xe("*mi", "", "10.0.0.4", metric="0", local_pref="100", path="i"),
    xe("*>", "100.100.100.128/25", "192.0.2.1", metric="0", path="64500 64511 i"),
    xe("*", "", "192.0.2.9", path="64499 64511 i"),
    xe("r>", "209.165.200.224/27", "192.0.2.1", path="64500 i"),
    xe("V*>", "209.165.201.0/24", "192.0.2.1", local_pref="1000000", path="64500 i"),
    "",
    "Total number of prefixes 11",
)
IOSXE_ROUTES_ROWS: list[Row] = [
    ("*>", "0.0.0.0/0", "192.0.2.1", "", "", "0", "64500", "i"),
    ("*>", "10.0.0.0/8", "192.0.2.1", "0", "", "0", "64500", "?"),
    ("*>", "172.16.0.0/16", "192.0.2.1", "", "150", "0", "64500 64510", "i"),
    ("*>", "192.168.10.0/24", "192.0.2.1", "20", "", "0", "64500 {64520,64521}", "i"),
    ("*>", "198.51.100.0/24", "192.0.2.1", "", "", "0", "64500 64496 64496 64496", "e"),
    ("*", "203.0.113.0/24", "192.0.2.9", "", "", "0", "64499 64496", "i"),
    ("*>", "203.0.113.0/24", "192.0.2.1", "0", "", "0", "64500 64496", "i"),
    ("*>i", "10.1.1.0/24", "10.0.0.3", "0", "100", "0", None, "i"),
    ("*mi", "10.1.1.0/24", "10.0.0.4", "0", "100", "0", None, "i"),
    ("*>", "100.100.100.128/25", "192.0.2.1", "0", "", "0", "64500 64511", "i"),
    ("*", "100.100.100.128/25", "192.0.2.9", "", "", "0", "64499 64511", "i"),
    ("r>", "209.165.200.224/27", "192.0.2.1", "", "", "0", "64500", "i"),
    ("V*>", "209.165.201.0/24", "192.0.2.1", "", "1000000", "0", "64500", "i"),
]

# Example 2: the classic layout, a classful network, weight 32768.
CLASSIC_ADVERTISED = table(
    "BGP table version is 27, local router ID is 172.16.232.181",
    "Status codes: s suppressed, d damped, h history, * valid, > best, i - internal,",
    "              r RIB-failure, S Stale",
    "Origin codes: i - IGP, e - EGP, ? - incomplete",
    "",
    CLASSIC_HEADER,
    classic("*>i", "10.0.0.0", "172.16.232.179", metric="0", local_pref="100", path="?"),
    classic("*>", "10.20.2.0/24", ZERO, metric="0", weight="32768"),
    classic("*>", "100.100.100.128/25", ZERO, metric="0", weight="32768"),
    "",
    "Total number of prefixes 3",
)
CLASSIC_ADVERTISED_ROWS: list[Row] = [
    ("*>i", "10.0.0.0/8", "172.16.232.179", "0", "100", "0", None, "?"),
    ("*>", "10.20.2.0/24", ZERO, "0", "", "32768", None, "i"),
    ("*>", "100.100.100.128/25", ZERO, "0", "", "32768", None, "i"),
]

# Example 3: a VRF table with its route distinguisher line.
IOSXE_VRF = table(
    *XE_LEGEND,
    XE_HEADER,
    "Route Distinguisher: 65000:1 (default for vrf BLUE)",
    xe("*>", "10.1.0.0/16", "198.51.100.2", metric="0", path="65100 i"),
    xe("*>", "10.2.0.0/16", "198.51.100.2", path="65100 65200 i"),
    "",
    "Total number of prefixes 2",
)
IOSXE_VRF_ROWS: list[Row] = [
    ("*>", "10.1.0.0/16", "198.51.100.2", "0", "", "0", "65100", "i"),
    ("*>", "10.2.0.0/16", "198.51.100.2", "", "", "0", "65100 65200", "i"),
]

# Example 4: IOS-XR, a `* i` status and a further path of a prefix.
IOSXR_ROUTES = table(
    *XR_LEGEND,
    XR_HEADER,
    xr("*>", "10.1.0.0/16", "192.0.2.1", metric="0", path="65100 i"),
    xr("*>", "10.2.0.0/16", "192.0.2.1", local_pref="150", path="65100 65200 i"),
    xr("*>i", "10.3.0.0/16", "10.0.0.3", metric="0", local_pref="100"),
    xr("* i", "", "10.0.0.4", metric="0", local_pref="100"),
    xr("*>", "100.100.100.128/25", "192.0.2.1", path="65100 i"),
    "",
    "Processed 4 prefixes, 5 paths",
)
IOSXR_ROUTES_ROWS: list[Row] = [
    ("*>", "10.1.0.0/16", "192.0.2.1", "0", "", "0", "65100", "i"),
    ("*>", "10.2.0.0/16", "192.0.2.1", "", "150", "0", "65100 65200", "i"),
    ("*>i", "10.3.0.0/16", "10.0.0.3", "0", "100", "0", None, "i"),
    ("* i", "10.3.0.0/16", "10.0.0.4", "0", "100", "0", None, "i"),
    ("*>", "100.100.100.128/25", "192.0.2.1", "", "", "0", "65100", "i"),
]

# Example 5: the IOS-XR advertised-routes layout, with an origin printed
# against the last AS.
IOSXR_ADVERTISED = table(
    "Thu Sep 24 10:00:00.000 UTC",
    FROM_HEADER,
    from_row("10.0.0.0/24", "10.0.0.1", "Local", "i"),
    from_row("10.1.0.0/16", "10.0.0.1", "192.0.2.3", "65300 i"),
    from_row("10.2.0.0/16", "10.0.0.1", "192.0.2.3", "65300 65310?"),
    "",
    "Processed 3 prefixes, 3 paths",
)
IOSXR_ADVERTISED_ROWS: list[Row] = [
    (None, "10.0.0.0/24", "10.0.0.1", "", "", "", None, "i"),
    (None, "10.1.0.0/16", "10.0.0.1", "", "", "", "65300", "i"),
    (None, "10.2.0.0/16", "10.0.0.1", "", "", "", "65300 65310", "?"),
]

# A VRF table whose route distinguisher line follows the header.
IOSXR_VRF = table(
    XR_HEADER,
    "Route Distinguisher: 65000:1 (default for vrf BLUE)",
    xr("*>", "10.1.0.0/16", "198.51.100.2", metric="0", path="65100 i"),
    "",
    "Processed 1 prefixes, 1 paths",
)
IOSXR_VRF_ROWS: list[Row] = [("*>", "10.1.0.0/16", "198.51.100.2", "0", "", "0", "65100", "i")]

EXAMPLES: dict[str, tuple[str, list[Row]]] = {
    "iosxe routes": (IOSXE_ROUTES, IOSXE_ROUTES_ROWS),
    "classic advertised": (CLASSIC_ADVERTISED, CLASSIC_ADVERTISED_ROWS),
    "iosxe vrf": (IOSXE_VRF, IOSXE_VRF_ROWS),
    "iosxr routes": (IOSXR_ROUTES, IOSXR_ROUTES_ROWS),
    "iosxr advertised": (IOSXR_ADVERTISED, IOSXR_ADVERTISED_ROWS),
    "iosxr vrf": (IOSXR_VRF, IOSXR_VRF_ROWS),
}


def shifted(text: str, columns: int) -> str:
    """`text` with every line after a standard header that starts with a
    status area moved `columns` right of the status area: the rows, and the
    lines that carry the rest of a wrapped network."""
    out: list[str] = []
    status_width: int | None = None
    for line in text.split("\n"):
        header = re.fullmatch(r"( *)Network +Next Hop +Metric +LocPrf +Weight +Path", line)
        if header:
            status_width = len(header.group(1))
        elif (
            status_width is not None
            and line.strip()
            and not line[:status_width].strip(" *>sdhirSmbfxacVINDtL-")
            and not line.startswith(("Route", "Total", "Processed"))
        ):
            line = line[:status_width] + " " * columns + line[status_width:]
        out.append(line)
    return "\n".join(out)


def _rows(text: str) -> list[Row]:
    return list(path_rows(text))


# --- the examples ------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(EXAMPLES))
def test_an_example_table_gives_its_rows(name: str) -> None:
    text, rows = EXAMPLES[name]
    assert _rows(text) == rows


def test_a_table_one_column_right_of_its_header_gives_the_same_rows() -> None:
    """The first row is read by its tokens, which teach the offset, and the
    rest by position at that offset."""
    text = shifted(IOSXE_ROUTES, 1)
    assert " *>   0.0.0.0" in text
    assert _rows(text) == IOSXE_ROUTES_ROWS


def test_an_origin_printed_against_the_last_as_is_read() -> None:
    text = table(XR_HEADER, "*> 10.1.0.0/16        192.0.2.1                0             0 65100 65200i")
    assert _rows(text) == [("*>", "10.1.0.0/16", "192.0.2.1", "0", "", "0", "65100 65200", "i")]
    text = table(FROM_HEADER, *from_row("10.9.0.0/16", "10.0.0.1", "192.0.2.3", "{65001,65002}e"))
    assert _rows(text) == [(None, "10.9.0.0/16", "10.0.0.1", "", "", "", "{65001,65002}", "e")]


@pytest.mark.parametrize(
    "network",
    ["abc", ".", "fe", "cafe", "1.2.3", "999.1.1.1", "10.0.0.0/99", "fe80::", ":/0", "\u0661.0.0.0/8"],
)
def test_a_malformed_network_is_no_row(network: str) -> None:
    text = table(XE_HEADER, xe("*>", network, "192.0.2.1", metric="0", path="65000 i"))
    assert _rows(text) == []


@pytest.mark.parametrize("next_hop", ["100", ":", ".:.", "a:b", "192.0.2", "192.0.2.256"])
def test_a_malformed_next_hop_is_no_row(next_hop: str) -> None:
    text = table(XE_HEADER, xe("*>", "10.0.0.0/8", next_hop, metric="0", path="65000 i"))
    assert _rows(text) == []


def test_ipv6_networks_and_next_hops_are_read() -> None:
    text = table(XE_HEADER, xe("*>", "2001:db8::/32", "2001:db8::1", metric="0", path="65000 i"))
    assert _rows(text) == [("*>", "2001:db8::/32", "2001:db8::1", "0", "", "0", "65000", "i")]


@pytest.mark.parametrize("family", sorted(_MODULES))
def test_the_family_records_carry_the_rows(family: str) -> None:
    module = _MODULES[family]
    accepted = module.parse_bgp_paths(IOSXE_ROUTES, peer_ip="192.0.2.1", direction="accepted")
    assert accepted[0] == {
        "peer_ip": "192.0.2.1",
        "direction": "accepted",
        "prefix": "0.0.0.0/0",
        "path_id": None,
        "next_hop": "192.0.2.1",
        "as_path": "64500",
        "local_pref": None,
        "med": None,
        "origin": "i",
        "communities": None,
        "best": True,
    }
    assert [(row["med"], row["local_pref"], row["best"]) for row in accepted[6:9]] == [
        (0, None, True),
        (0, 100, True),
        (0, 100, False),
    ]
    received = module.parse_bgp_paths(IOSXE_ROUTES, peer_ip="192.0.2.1", direction="received")
    assert [row["best"] for row in received] == [None] * len(IOSXE_ROUTES_ROWS)
    advertised = module.parse_bgp_paths(IOSXR_ADVERTISED, peer_ip="192.0.2.3", direction="advertised")
    assert [(row["best"], row["med"], row["local_pref"]) for row in advertised] == [(None, None, None)] * 3
    assert [row["as_path"] for row in advertised] == [None, "65300", "65300 65310"]


# --- variants ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("metric", "local_pref"), [("", ""), ("5", ""), ("", "200"), ("5", "200")], ids=["none", "m", "l", "ml"]
)
@pytest.mark.parametrize("layout", ["xe", "classic", "xr"])
def test_blank_and_printed_metric_and_local_preference(metric: str, local_pref: str, layout: str) -> None:
    header, render = _LAYOUTS[layout]
    text = table(header, render("*>", "10.0.0.0/24", "192.0.2.1", metric, local_pref, path="65001 65002 i"))
    assert _rows(text) == [("*>", "10.0.0.0/24", "192.0.2.1", metric, local_pref, "0", "65001 65002", "i")]


_STATUSES = (
    "*>", "*", "* i", "*>i", "r>i", "r>", "s>", "d", "h", "*m", "*mi", "*>x", "*a", "S>", "b", "f", "*c",
    "t", "*L", "", "V*>", "I*", "N*>i",
)  # fmt: skip


@pytest.mark.parametrize("status", _STATUSES)
def test_every_status_is_read(status: str) -> None:
    text = table(XE_HEADER, xe(status, "10.0.0.0/24", "192.0.2.1", metric="0"))
    [row] = _rows(text)
    assert row[0] == status
    assert (">" in row[0]) is (">" in status)
    if len(status) < 4:
        [row] = _rows(table(XR_HEADER, xr(status, "10.0.0.0/24", "192.0.2.1", metric="0")))
        assert row[0] == status


@pytest.mark.parametrize(
    ("network", "prefix"),
    [
        (ZERO, f"{ZERO}/0"),
        ("10.0.0.0", "10.0.0.0/8"),
        ("127.0.0.0", "127.0.0.0/8"),
        ("128.1.0.0", "128.1.0.0/16"),
        ("191.255.0.0", "191.255.0.0/16"),
        ("192.0.2.0", "192.0.2.0/24"),
        ("223.1.1.0", "223.1.1.0/24"),
        ("224.0.0.0", "224.0.0.0"),
        ("10.1.0.0/16", "10.1.0.0/16"),
        ("2001:db8::/32", "2001:db8::/32"),
    ],
)
def test_a_network_printed_without_a_length_gets_its_classful_length(network: str, prefix: str) -> None:
    assert classful_prefix(network) == prefix
    [row] = _rows(table(XE_HEADER, xe("*>", network, "192.0.2.1")))
    assert row[1] == prefix


def test_wrapped_networks_carry_their_status_and_their_further_paths() -> None:
    xe_text = table(
        XE_HEADER,
        xe("*>i", "100.100.100.128/25", "10.0.0.3", metric="0", local_pref="100"),
        xe("*", "", "10.0.0.4", metric="0", local_pref="100"),
        xe("*>", "10.0.0.0/8", "192.0.2.1"),
    )
    classic_text = table(
        CLASSIC_HEADER,
        classic("*>i", "100.100.100.128/25", "10.0.0.3", metric="0", local_pref="100"),
        classic("*", "", "10.0.0.4", metric="0", local_pref="100"),
        classic("*>", "10.0.0.0/8", "192.0.2.1"),
    )
    expected = [
        ("*>i", "100.100.100.128/25", "10.0.0.3", "0", "100", "0", None, "i"),
        ("*", "100.100.100.128/25", "10.0.0.4", "0", "100", "0", None, "i"),
        ("*>", "10.0.0.0/8", "192.0.2.1", "", "", "0", None, "i"),
    ]
    assert xe_text.splitlines()[2].startswith(" " * 22 + "10.0.0.3")
    assert classic_text.splitlines()[2].startswith(" " * 20 + "10.0.0.3")
    assert _rows(xe_text) == expected
    assert _rows(classic_text) == expected


@pytest.mark.parametrize(
    "before",
    [
        [],
        ["Route Distinguisher: 65000:1 (default for vrf BLUE)"],
        [""],
        ["*>   something the reader does not know"],
        xe("*>", "999.0.0.0/8", "192.0.2.1"),
    ],
    ids=["header", "rd line", "blank line", "unreadable line", "malformed row"],
)
def test_a_further_path_with_no_network_above_it_is_no_row(before: list[str]) -> None:
    text = table(XE_HEADER, *before, xe("*", "", "192.0.2.9"), xe("*>", "10.0.0.0/8", "192.0.2.1"))
    assert _rows(text) == [("*>", "10.0.0.0/8", "192.0.2.1", "", "", "0", None, "i")]


@pytest.mark.parametrize(
    "footer",
    [
        "Total number of prefixes 11",
        "Total number of prefixes 11 ",
        "Processed 4 prefixes, 5 paths",
        "Displayed 4 out of 4 total prefixes",
        "Originating default network 0.0.0.0",
    ],
)
def test_a_footer_is_no_row(footer: str) -> None:
    for header in (XE_HEADER, CLASSIC_HEADER, XR_HEADER, FROM_HEADER):
        assert _rows(table(header, "", footer)) == []


@pytest.mark.parametrize("local_pref", ["1000000", "4294967295"])
@pytest.mark.parametrize("metric", ["", "0"])
def test_a_local_preference_wider_than_its_column_pushes_the_rest_right(local_pref: str, metric: str) -> None:
    text = table(
        XE_HEADER,
        xe("*>i", "10.1.0.0/16", "10.0.0.3", metric=metric, local_pref=local_pref, path="65100 i"),
        xe("*>i", "10.2.0.0/16", "10.0.0.3", metric=metric, local_pref="100", path="65100 i"),
    )
    assert _rows(text) == [
        ("*>i", "10.1.0.0/16", "10.0.0.3", metric, local_pref, "0", "65100", "i"),
        ("*>i", "10.2.0.0/16", "10.0.0.3", metric, "100", "0", "65100", "i"),
    ]


def test_as_sets_confederations_and_origins() -> None:
    text = table(
        XE_HEADER,
        xe("*>", "10.1.0.0/16", "192.0.2.1", path="64500 {64520,64521} e"),
        xe("*>", "10.2.0.0/16", "192.0.2.1", path="(65010 65011) 64500 ?"),
        xe("*>", "10.3.0.0/16", "192.0.2.1", path="(65010) {64520} i"),
    )
    assert [(row[6], row[7]) for row in _rows(text)] == [
        ("64500 {64520,64521}", "e"),
        ("(65010 65011) 64500", "?"),
        ("(65010) {64520}", "i"),
    ]


def test_each_header_sets_the_columns_of_the_rows_below_it() -> None:
    text = IOSXE_VRF + CLASSIC_ADVERTISED + IOSXR_ADVERTISED + IOSXR_ROUTES
    assert _rows(text) == IOSXE_VRF_ROWS + CLASSIC_ADVERTISED_ROWS + IOSXR_ADVERTISED_ROWS + IOSXR_ROUTES_ROWS


def test_rows_without_a_header_are_no_rows() -> None:
    body = IOSXE_ROUTES.split(XE_HEADER)[1]
    assert _rows(body) == []
    assert _rows("*> 10.0.0.0/24 198.51.100.2 0 100 0 65100 i\n") == []


# --- offsets -----------------------------------------------------------------------------


@pytest.mark.parametrize("columns", [1, 2])
@pytest.mark.parametrize("name", sorted(EXAMPLES))
def test_a_table_up_to_two_columns_right_reads_by_position(
    name: str, columns: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    text, rows = EXAMPLES[name]
    assert _rows(shifted(text, columns)) == rows
    monkeypatch.setattr(cisco_bgp_table, "_BY_POSITION", False)
    assert _rows(shifted(text, columns)) == rows


@pytest.mark.parametrize("columns", [1, 2])
def test_a_shifted_table_costs_one_token_read_and_reads_the_rest_by_position(
    columns: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A token read on every row gives the same rows, so the test counts the reads."""
    real = cisco_bgp_table._fields_by_tokens
    calls: list[str] = []

    def counted(line: str, geometry: Any) -> Any:
        calls.append(line)
        return real(line, geometry)

    monkeypatch.setattr(cisco_bgp_table, "_fields_by_tokens", counted)
    assert _rows(IOSXE_ROUTES) == IOSXE_ROUTES_ROWS
    aligned = len(calls)
    calls.clear()
    assert _rows(shifted(IOSXE_ROUTES, columns)) == IOSXE_ROUTES_ROWS
    assert len(calls) == aligned + 1


def test_a_row_off_the_learned_offset_is_read_by_its_tokens() -> None:
    first_shifted = table(
        XE_HEADER,
        shifted(table(XE_HEADER, xe("*>", "10.1.0.0/16", "192.0.2.1", metric="0")), 2).splitlines()[1],
        xe("*>", "10.2.0.0/16", "192.0.2.1", metric="0"),
        xe("*>", "10.3.0.0/16", "192.0.2.1", metric="0"),
    )
    last_shifted = table(
        XE_HEADER,
        xe("*>", "10.1.0.0/16", "192.0.2.1", metric="0"),
        xe("*>", "10.2.0.0/16", "192.0.2.1", metric="0"),
        shifted(table(XE_HEADER, xe("*>", "10.3.0.0/16", "192.0.2.1", metric="0")), 1).splitlines()[1],
    )
    expected = [("*>", f"10.{index}.0.0/16", "192.0.2.1", "0", "", "0", None, "i") for index in (1, 2, 3)]
    assert _rows(first_shifted) == expected
    assert _rows(last_shifted) == expected


@pytest.mark.parametrize("columns", [3, 5])
def test_a_table_further_right_is_read_by_its_tokens(columns: int) -> None:
    """The position reading stops at 2 columns."""
    assert _rows(shifted(IOSXE_ROUTES, columns)) == IOSXE_ROUTES_ROWS


def test_numbers_left_of_their_columns_and_single_spaced_rows_are_no_rows() -> None:
    left = table(XE_HEADER, _LEFT_ROW)
    assert _rows(left) == []
    single = table(XE_HEADER, "*> 10.0.0.0/24 198.51.100.2 0 100 0 65100 i")
    assert _rows(single) == []


# --- windows -----------------------------------------------------------------------------


@pytest.mark.parametrize("family", sorted(_MODULES))
@pytest.mark.parametrize("window", _WINDOWS)
def test_every_example_reads_alike_at_every_window_size(
    family: str, window: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _MODULES[family]
    wrap = " *>  100.100.100.128/25\n"
    if window == 1:
        # the wrapped network and the rest of its path are windows of their own
        assert wrap in list(streams.line_windows(IOSXE_ROUTES, 0, window))
    monkeypatch.setattr(streams, "WINDOW_CHARS", window)
    for text, rows in EXAMPLES.values():
        assert _rows(text) == rows
        assert _rows(text.removesuffix("\n")) == rows
        records = module.parse_bgp_paths(text, peer_ip="192.0.2.1", direction="accepted")
        assert module._count_bgp_paths(text) == len(records) == len(rows)


# --- random tables -----------------------------------------------------------------------

_RANDOM_STATUSES = (
    "*>", "*", "* i", "*>i", "r>i", "r>", "s>", "d", "h", "*m", "*mi", "*>x", "S>", "", "b", "*a",
)  # fmt: skip


def _random_network(rng: random.Random) -> tuple[str, str]:
    """(printed network, stated prefix)."""
    kind = rng.randrange(6)
    if kind == 0:
        cls = rng.randrange(4)
        if cls == 0:
            return ZERO, f"{ZERO}/0"
        if cls == 1:
            first = rng.randrange(1, 127)
            return f"{first}.0.0.0", f"{first}.0.0.0/8"
        if cls == 2:
            network = f"{rng.randrange(128, 192)}.{rng.randrange(256)}.0.0"
            return network, f"{network}/16"
        network = f"{rng.randrange(192, 224)}.{rng.randrange(256)}.{rng.randrange(256)}.0"
        return network, f"{network}/24"
    octets = ".".join(str(rng.randrange(256)) for _ in range(4))
    prefix = f"{octets}/{rng.choice([8, 16, 20, 23, 24, 25, 27, 30, 32])}"
    return prefix, prefix


def random_table(rng: random.Random, shift: int = 0) -> tuple[str, list[Row]]:
    """A random path table in the IOS-XE, classic or IOS-XR layout, with
    every row moved `shift` columns right of its header, and the rows its
    values were printed from. Networks wider than the IOS-XE and classic
    network column wrap; the IOS-XR table holds none."""
    layout = rng.choice(sorted(_LAYOUTS))
    header, render = _LAYOUTS[layout]
    lines = [
        "BGP table version is 1, local router ID is 10.0.0.1",
        "Status codes: s suppressed, d damped, h history, * valid, > best, i - internal,",
        "Origin codes: i - IGP, e - EGP, ? - incomplete",
        "",
        header,
    ]
    rows: list[Row] = []
    last: str | None = None
    for _ in range(rng.randrange(0, 25)):
        if rng.random() < 0.05:
            lines.append(rng.choice(["Route Distinguisher: 65000:1 (default for vrf A)", ""]))
            last = None
            continue
        status = rng.choice(_RANDOM_STATUSES)
        if last is not None and rng.random() < 0.3:
            printed, prefix = "", last
        else:
            printed, prefix = _random_network(rng)
            if layout != "xr" and rng.random() < 0.15:
                octets = ".".join(str(rng.randrange(100, 256)) for _ in range(4))
                printed = prefix = f"{octets}/{rng.randrange(10, 33)}"
            if layout == "xr" and len(printed) > 18:
                continue
        next_hop = f"{rng.randrange(1, 224)}.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(256)}"
        metric = rng.choice(["", "0", str(rng.randrange(10 ** rng.randrange(1, 10)))])
        local_pref = rng.choice(["", "100", "150", str(rng.randrange(10 ** rng.randrange(1, 11)))])
        weight = rng.choice(["0", "32768", str(rng.randrange(65536))])
        tokens = [
            rng.choice([str(rng.randrange(1, 4294967295)), "{65001,65002}", "(65010 65011)"])
            for _ in range(rng.randrange(0, 5))
        ]
        as_path = " ".join(tokens)
        origin = rng.choice("ie?")
        lines += render(status, printed, next_hop, metric, local_pref, weight, f"{as_path} {origin}".lstrip())
        last = prefix
        rows.append((status, prefix, next_hop, metric, local_pref, weight, as_path or None, origin))
    lines += ["", "Total number of prefixes 0"]
    text = "\n".join(lines) + rng.choice(["\n", ""])
    return (shifted(text, shift) if shift else text), rows


def _random_tables(seed: str, count: int) -> Iterator[tuple[str, list[Row]]]:
    rng = random.Random(seed)
    for _ in range(count):
        yield random_table(rng, rng.choice([0, 0, 1, 2]))


def test_random_tables_give_the_rows_they_were_printed_from(monkeypatch: pytest.MonkeyPatch) -> None:
    """5,000 tables in the three layouts, moved 0, 1 or 2 columns right, each
    read at a window size of its own."""
    rng = random.Random("bgp-table-windows")
    for text, rows in _random_tables("bgp-tables", 5_000):
        monkeypatch.setattr(streams, "WINDOW_CHARS", rng.choice(_WINDOWS))
        assert _rows(text) == rows, text


_JUNK_HEADERS = (XE_HEADER, CLASSIC_HEADER, XR_HEADER, FROM_HEADER)
# Characters of a path row, whitespace `str.split` and `str.splitlines` treat
# specially, and digits beyond ASCII.
_JUNK = (
    *"0123456789abcdefABCDEF.:/ *>i?e{}(),",
    " ",
    " ",
    "  ",
    "\t",
    "\xa0",
    "\n",
    "\r",
    "\u00b2",
    "\u0661",
)


def _junk_text(rng: random.Random) -> str:
    """Headers, shifted random tables, and header-shaped lines with random
    characters replaced, in any order."""
    parts: list[str] = []
    for _ in range(rng.randrange(1, 8)):
        if rng.random() < 0.3:
            parts.append(rng.choice(_JUNK_HEADERS))
        elif rng.random() < 0.5:
            parts.append(random_table(rng, rng.choice([0, 1, 2, 3]))[0])
        else:
            header = rng.choice(_JUNK_HEADERS).replace("Network", "10.0.0.0").replace("Next Hop", "192.0.2.1")
            characters = list(header)
            for _ in range(rng.randrange(1, 12)):
                characters[rng.randrange(len(characters))] = rng.choice(_JUNK)
            parts.append("".join(characters))
    return "\n".join(parts)


def test_the_position_reading_gives_what_the_token_reading_gives(monkeypatch: pytest.MonkeyPatch) -> None:
    rng = random.Random("bgp-table-junk")
    texts = [text for text, _rows_ in _random_tables("bgp-tables", 5_000)]
    texts += [_junk_text(rng) for _ in range(5_000)]
    by_position = [_rows(text) for text in texts]
    monkeypatch.setattr(cisco_bgp_table, "_BY_POSITION", False)
    assert [_rows(text) for text in texts] == by_position
    monkeypatch.setattr(cisco_bgp_table, "_BY_POSITION", True)
    for index, text in enumerate(texts):
        monkeypatch.setattr(streams, "WINDOW_CHARS", _WINDOWS[index % 3])
        assert _rows(text) == by_position[index], text


# --- the synthetic cases -----------------------------------------------------------------

SYNTHETIC = tuple(key for key in CASES if split_case(key)[0] in _MODULES and split_case(key)[1] in SCALES)
_TOTAL = re.compile(r"^Total number of prefixes (\d+)$", re.MULTILINE)
_PROCESSED = re.compile(r"^Processed (\d+) prefixes, (\d+) paths$", re.MULTILINE)


@pytest.mark.parametrize("key", SYNTHETIC)
def test_a_synthetic_case_reads_the_printed_paths(key: str) -> None:
    family, _scale, variant = split_case(key)
    payload = case_payload(key)
    observed = _MODULES[family].parse(payload)["bgp_observed"]
    printed = expected_ios_paths(key)
    by_command: dict[str, list[dict[str, Any]]] = {}
    routes = iter(observed["routes"])
    for entry in observed["directions"]:
        by_command[entry["command"]] = [next(routes) for _ in range(entry["row_count"] or 0)]
    assert next(routes, None) is None
    assert by_command == printed
    assert any(printed.values())
    for command, paths in printed.items():
        for path in paths:
            ipaddress.ip_network(path["prefix"])
        if variant == "unicode" or not paths:
            continue
        # the footer counts what the device printed; the unicode variant
        # splits one line in two, so the reader loses paths there
        prefixes = len({path["prefix"] for path in paths})
        text = payload[command]
        processed = _PROCESSED.search(text)
        if family == "iosxr":
            assert processed is not None
            assert (int(processed.group(1)), int(processed.group(2))) == (prefixes, len(paths))
        else:
            total = _TOTAL.search(text)
            assert total is not None
            assert int(total.group(1)) == prefixes


def test_the_synthetic_tables_hold_every_shape() -> None:
    """Classful networks, wrapped networks, further paths, blank columns and
    both IOS-XR layouts, so the golden values cover them."""
    xe_text = "\n".join(
        text for command, text in case_payload("iosxe/small/plain").items() if "neighbors" in command
    )
    xr_text = "\n".join(
        text for command, text in case_payload("iosxr/small/plain").items() if "neighbors" in command
    )
    assert re.search(r"^ \*>  \d+\.\d+\.\d+\.0 ", xe_text, re.MULTILINE)
    assert re.search(r"^ \S*\s*\S* 1\d\d\.\d+\.\d+\.128/25$", xe_text, re.MULTILINE)
    assert re.search(r"^ \* {20}\S", xe_text, re.MULTILINE)
    assert re.search(r"^ \* i ", xe_text, re.MULTILINE)
    assert FROM_HEADER in xr_text and XR_HEADER in xr_text
    assert re.search(r"^\* i\d", xr_text, re.MULTILINE)


# --- parser version and golden overlay -----------------------------------------------------


def test_the_parser_version_is_2_and_the_overlay_records_it() -> None:
    overlay = json.loads(PARSER2_GOLDEN_PATH.read_text(encoding="utf-8"))
    assert iosxe.IosxeCollector.PARSER_VERSION == iosxr.IosxrCollector.PARSER_VERSION == "2"
    assert overlay["parser_versions"] == {"iosxe": "2", "iosxr": "2"}


def test_the_overlay_names_only_ios_cases_and_the_parser_fields() -> None:
    overlay = json.loads(PARSER2_GOLDEN_PATH.read_text(encoding="utf-8"))
    assert overlay["fields"] == list(PARSER2_FIELDS)
    assert sorted(overlay["cases"]) == sorted(key for key in CASES if split_case(key)[0] in _MODULES)
    for key, fields in overlay["cases"].items():
        assert fields, key
        assert set(fields) <= set(PARSER2_FIELDS), key
        # the parser version is part of raw_sha's normalization context
        assert "raw_sha" in fields, key


# --- an answer none of whose rows is read ----------------------------------------------------

_PEER = "198.51.100.2"
_CONFIG = {
    "iosxe": "router bgp 65000\n neighbor 198.51.100.2 remote-as 65100\n",
    "iosxr": "router bgp 65000\n neighbor 198.51.100.2\n  remote-as 65100\n  address-family ipv4 unicast\n",
}
# Every number 3 columns left of its column.
_LEFT_ROW = f" *>  {'10.0.0.0/24':<16} {_PEER:<15} {'0':>7} {'100':>6} {'0':>6} 65100 i"
_UNREAD = TableOutcome(status="failed", detail="the answer holds path rows, and none of them could be read")


def _accepted_outcome(family: str, answer: str) -> TableOutcome:
    """The outcome of the accepted direction of one configured peer that
    answered with `answer`."""
    module = _MODULES[family]
    command = module.bgp_route_command(_PEER, "accepted")
    raw: dict[str, Any] = {
        module.CMD_BGP: _CONFIG[family],
        command: answer,
        RAW_OUTCOMES_KEY: {command: {"status": "ok"}},
    }
    config = _CONFIG[family]
    bgp = iosxe.parse_bgp_config(config) if family == "iosxe" else iosxr_bgp.parse_bgp(config)
    observed = module.parse_bgp_observations(raw, bgp)
    outcomes = module.bgp_table_outcomes(raw, {"bgp_observed": observed}, "device:1", capture="all")
    return outcomes[bgp_direction_key(module._bgp_session_uid("device:1", _PEER), "accepted")]


@pytest.mark.parametrize("family", sorted(_MODULES))
def test_an_answer_whose_rows_are_all_unread_is_failed(family: str) -> None:
    headerless = "*> 10.0.0.0/24 198.51.100.2 0 100 0 65100 i\n"
    left = table(XE_HEADER, _LEFT_ROW)
    assert holds_path_rows(headerless) and holds_path_rows(left)
    assert _accepted_outcome(family, headerless) == _UNREAD
    assert _accepted_outcome(family, left) == _UNREAD


@pytest.mark.parametrize("family", sorted(_MODULES))
def test_an_answer_with_no_rows_or_one_read_row_is_what_it_holds(family: str) -> None:
    empty_xe = table(*XE_LEGEND, XE_HEADER, "", "Total number of prefixes 0")
    empty_xr = table(XR_HEADER, "", "Processed 0 prefixes, 0 paths")
    assert not holds_path_rows(empty_xe) and not holds_path_rows(empty_xr)
    for answer in (empty_xe, empty_xr, ""):
        assert _accepted_outcome(family, answer) == TableOutcome(status="complete-empty", row_count=0)
    one = table(XE_HEADER, xe("*>", "10.0.0.0/24", _PEER, metric="0", local_pref="100", path="65100 i"))
    assert _accepted_outcome(family, one) == TableOutcome(status="complete", row_count=1)
