"""The BGP path tables of IOS-XE and IOS-XR, read by column position.

The 3 per-neighbor path commands of both families (received routes, routes,
advertised routes) answer with one table layout. A header line holds the
column names, and each path has one line.

     Network          Next Hop            Metric LocPrf Weight Path
 *>  10.0.0.0         192.0.2.1                0             0 64500 ?
 *>i 10.1.1.0/24      10.0.0.3                 0    100      0 i
 *mi                  10.0.0.4                 0    100      0 i
 *>  100.100.100.128/25
                      192.0.2.1                0             0 64500 64511 i

Metric, LocPrf and Weight are right-aligned under the last letter of their
header word. A blank value is printed as spaces. A whitespace split does not
give the column of a number. The reader takes each column position from the
header line of the table. These rules apply to the rows.

- A row that sits at most 2 columns right of the header is read by position.
  The ntc-template of IOS `show ip bgp` accepts the same range for the same
  table. `_fields_by_tokens` reads a row at a larger offset by its tokens when
  the tokens fit the columns.
- A network longer than its column is printed alone on its line. The rest of
  the path is on the next line (the last row above).
- A further path of the same network has a blank network column. It takes the
  network of the row above it (the third row above).
- A classful network printed without a length gets its classful length
  (`classful_prefix`).
- The IOS-XR advertised-routes table has the layout
  "Network  Next Hop  From  AS Path". Its rows start at column 0 and have no
  status, metric, local preference or weight.

A line is a path row only when its network and next hop are well-formed
addresses and its numbers fit the columns. Any other line after a header is a
legend, a route distinguisher line, a footer or a line of a layout that the
reader does not know. Such a line ends the carry of a network into the rows
below it. The reader does not raise on any text.

The layouts come from the documentation of Cisco and the ntc-templates of
these commands. No live capture has confirmed them.
"""

from __future__ import annotations

import ipaddress
import itertools
import re
from collections.abc import Iterator

from . import streams

# A `Row` holds one path as (status, prefix, next_hop, metric, local_pref,
# weight, as_path, origin). `status` is the stripped status area, "" when the
# area is blank and None for a table without a status column. `prefix` has a
# length. A class D or E network printed without a length stays as printed.
# `metric`, `local_pref` and `weight` are ASCII digits as printed, or "".
# `as_path` holds the AS path tokens joined by single spaces, or None. `origin`
# is "i", "e" or "?".
Row = tuple[str | None, str, str, str, str, str, str | None, str]

# `_Fields` holds the fields that `_fields_by_tokens` reads from one line:
# network ("" when the column is blank), next hop ("" for a wrapped-network
# line), metric, local preference, weight, AS path and origin.
_Fields = tuple[str, str, str, str, str, str | None, str]

# `_Geometry` holds the columns of a standard header: the start of the network,
# the start of the next hop, the ends of Metric, LocPrf and Weight, and the
# start of the AS path. The status area ends where the network starts.
_Geometry = tuple[int, int, int, int, int, int]

_ORIGINS = frozenset("ie?")
# A status area holds only these characters. They are the status codes and the
# RPKI validation codes of the legends of both families, and the space.
_STATUS_CHARS = " *>sdhirSmbfxacVINDtL-"

_HEADER = re.compile(r"( *)Network +(Next[ -][Hh]op) +(Metric) +(LocPrf) +(Weight) +(Path) *").fullmatch
_FROM_HEADER = re.compile(r" *Network +Next[ -][Hh]op +From +AS[ -]Path *").fullmatch

_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
_IPV4 = rf"{_OCTET}(?:\.{_OCTET}){{3}}"
_IPV4_ADDRESS = re.compile(_IPV4).fullmatch
_IPV4_NETWORK = re.compile(rf"{_IPV4}(?:/(?:3[0-2]|[12]?[0-9]))?").fullmatch
# The pattern matches the characters of an IPv6 address and a required length.
# `_ipv6` checks the address.
_IPV6_NETWORK = re.compile(r"([0-9A-Fa-f.]*:[0-9A-Fa-f:.]*)/(?:12[0-8]|1[01][0-9]|[1-9]?[0-9])").fullmatch
_IPV6_CHARS = re.compile(r"[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*").fullmatch

# An origin printed against the last AS path token ("65200i", "{65001,65002}?").
_GLUED_ORIGIN = re.compile(r"([0-9{}(),.]+)([ie?])").fullmatch
_TOKEN = re.compile(r"\S+")
# A line that starts like a path row: a status area and an IPv4 address.
_ROW_LIKE = re.compile(r"^[ *>sdhirSmbfxacVINDtL-]{0,6}(?:[0-9]{1,3}\.){3}[0-9]{1,3}", re.MULTILINE).search

# The metric column is 10 characters wide and ends under "Metric".
_METRIC_WIDTH = 10
# `_MAX_SPREAD` is the largest difference between the first and the last
# distance of a line read by its tokens. `_MAX_OFFSET` is the largest offset
# from the header at which a row is read by position.
_MAX_SPREAD = 4
_MAX_OFFSET = 2
# Each layout lists the columns that the leading numbers of a line fill, with
# 0 for Metric, 1 for LocPrf and 2 for Weight. The layouts are tried in this
# order. Weight is never blank.
_NUMBER_LAYOUTS: tuple[tuple[int, ...], ...] = ((0, 1, 2), (0, 2), (1, 2), (2,))

# Rows that fit the columns are read by position. A test sets this to False to
# compare the position reading with the token reading.
_BY_POSITION = True


def classful_prefix(network: str) -> str:
    """Return `network` with its classful length when it is printed without a
    length. The length is /8, /16 or /24 by the first octet, and /0 for
    0.0.0.0. A network with a length, an IPv6 network, and a class D or E
    network stay as printed.

    `_network_ok` has accepted `network`."""
    if "/" in network or ":" in network:
        return network
    if network == "0.0.0.0":  # noqa: S104 - the default route
        return "0.0.0.0/0"
    first = int(network[: network.index(".")])
    if first < 128:
        return f"{network}/8"
    if first < 192:
        return f"{network}/16"
    if first < 224:
        return f"{network}/24"
    return network


def holds_path_rows(text: str) -> bool:
    """Return whether a line of `text` starts with a status area and an IPv4
    address. The reader could not read an answer that holds such a line and
    yields no row."""
    return _ROW_LIKE(text) is not None


def _ipv6(text: str) -> bool:
    if not _IPV6_CHARS(text):
        return False
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return False
    return True


def _network_ok(network: str) -> bool:
    """An IPv4 network with an optional length, or an IPv6 network with one."""
    if _IPV4_NETWORK(network):
        return True
    match = _IPV6_NETWORK(network)
    return match is not None and _ipv6(match.group(1))


def _next_hop_ok(next_hop: str) -> bool:
    return _IPV4_ADDRESS(next_hop) is not None or _ipv6(next_hop)


def _split_origin(tokens: list[str]) -> tuple[list[str], str] | None:
    """Return (the tokens before the origin, the origin). The origin is the
    last token or is printed against the last AS path token. Return None when
    the tokens do not end in an origin."""
    last = tokens[-1]
    if last in _ORIGINS:
        return tokens[:-1], last
    glued = _GLUED_ORIGIN(last)
    if glued is None:
        return None
    return [*tokens[:-1], glued.group(1)], glued.group(2)


def _fields_by_tokens(line: str, geometry: _Geometry) -> tuple[_Fields | None, int | None]:
    """One line of a table with the header `geometry`, read by its tokens.

    A first token that starts left of the next-hop column is the network. A
    network alone on its line is a wrapped network (next hop ""). The next
    token is the next hop. Of the rest, up to 3 leading numbers fill Metric,
    LocPrf and Weight in one of `_NUMBER_LAYOUTS`. Each number sits some
    distance right of the end of its column. The AS path (or the origin) sits
    some distance right of the Path column. A layout fits when no distance is
    negative or smaller than the distance before it, and the last distance
    exceeds the first by at most `_MAX_SPREAD`. Of the layouts that fit, the
    layout with the smallest excess wins, then the layout with the smallest
    first distance, then the earlier layout. `offset` is the distance when
    every distance of the winning layout is the same and is 0 to `_MAX_OFFSET`
    columns. The caller reads the following lines by position at `offset`."""
    n, h, metric_end, local_pref_end, weight_end, path = geometry
    tokens = [(m.start(), m.end() - 1, m.group()) for m in _TOKEN.finditer(line, n)]
    if not tokens:
        return None, None
    network = ""
    if tokens[0][0] < h:
        network = tokens[0][2]
        if len(tokens) == 1:
            return (network, "", "", "", "", None, ""), None
        tokens = tokens[1:]
    next_hop = tokens[0][2]
    rest = tokens[1:]
    if not rest:
        return None, None
    split = _split_origin([token for _start, _end, token in rest])
    if split is None:
        return None, None
    words, origin = split
    if not words:
        return None, None
    spans = [(start, end) for start, end, _token in rest[: len(words)]]
    if len(words) == len(rest):
        # The origin is printed against the last word. The word ends 1 column earlier.
        start, end = spans[-1]
        spans[-1] = (start, end - 1)
    numbers = 0
    for word in words[:3]:
        if not (word.isdigit() and word.isascii()):
            break
        numbers += 1
    ends = (metric_end, local_pref_end, weight_end)
    best: tuple[tuple[int, int], tuple[int, ...], list[int]] | None = None
    for layout in _NUMBER_LAYOUTS:
        count = len(layout)
        if count > numbers:
            continue
        shifts = [spans[index][1] - ends[column] for index, column in enumerate(layout)]
        shifts.append((spans[count][0] if count < len(spans) else rest[-1][0]) - path)
        if shifts[0] < 0 or any(later < earlier for earlier, later in itertools.pairwise(shifts)):
            continue
        spread = shifts[-1] - shifts[0]
        if spread > _MAX_SPREAD:
            continue
        score = (spread, shifts[0])
        if best is None or score < best[0]:
            best = (score, layout, shifts)
    if best is None:
        return None, None
    _score, layout, shifts = best
    values = ["", "", ""]
    for index, column in enumerate(layout):
        values[column] = words[index]
    offset = shifts[0] if shifts[-1] == shifts[0] and shifts[0] <= _MAX_OFFSET else None
    as_path = " ".join(words[len(layout) :]) or None
    return (network, next_hop, values[0], values[1], values[2], as_path, origin), offset


def _from_row(line: str) -> Row | None:
    """Read one line of the IOS-XR "Network  Next Hop  From  AS Path" table.
    A row starts at column 0. Return None when the line is not a row."""
    if line[:1] in ("", " "):
        return None
    tokens = line.split()
    if len(tokens) < 4:
        return None
    split = _split_origin(tokens[3:])
    if split is None:
        return None
    network, next_hop = tokens[0], tokens[1]
    if not _network_ok(network) or not _next_hop_ok(next_hop):
        return None
    words, origin = split
    return (None, classful_prefix(network), next_hop, "", "", "", " ".join(words) or None, origin)


def path_rows(text: str) -> Iterator[Row]:
    """Yield every path row of one path-table answer, in order (`Row`).

    No line before the first header line is a row. A standard header sets the
    column positions. A row is read by position when it fits the columns of
    the header, or the columns at the offset that a row read by its tokens
    set. `_fields_by_tokens` reads any other line by its tokens. The network
    and the next hop of a row are well-formed addresses.

    The text is read one line-aligned window at a time
    (`streams.line_windows`). The lines of the windows equal
    `text.splitlines()`. The rows do not depend on the window size."""
    by_position = _BY_POSITION
    status_chars, origins = _STATUS_CHARS, _ORIGINS
    network_ok, next_hop_ok = _network_ok, _next_hop_ok
    table = from_table = False
    geometry: _Geometry = (0, 0, 0, 0, 0, 0)
    n = 0
    # The columns of the header shifted by the offset: the start of the next hop,
    # the start of the metric, the ends of Metric, LocPrf and Weight, and the
    # start of the AS path.
    hop = metric = metric_end = local_pref_end = weight_end = path = 0
    carried: str | None = None
    pending: str | None = None
    good_hop: str | None = None
    for window in streams.line_windows(text, 0, streams.WINDOW_CHARS):
        for line in window.splitlines():
            if "Network" in line:
                header = _HEADER(line)
                if header is not None:
                    table, from_table = True, False
                    n = len(header.group(1))
                    geometry = (
                        n,
                        header.start(2),
                        header.end(3) - 1,
                        header.end(4) - 1,
                        header.end(5) - 1,
                        header.start(6),
                    )
                    _n, hop, metric_end, local_pref_end, weight_end, path = geometry
                    metric = metric_end - _METRIC_WIDTH + 1
                    carried = pending = None
                    continue
                if _FROM_HEADER(line) is not None:
                    table, from_table = False, True
                    carried = pending = None
                    continue
            if from_table:
                row = _from_row(line)
                if row is not None:
                    yield row
                continue
            if not table:
                continue
            status = line[:n]
            if status.strip(status_chars):
                carried = pending = None
                continue
            fields: _Fields | None = None
            if (
                by_position
                and len(line) > path
                and line[hop - 1] == " "
                and line[metric - 1] == " "
                and line[metric_end + 1] == " "
                and line[local_pref_end + 1] == " "
                and line[weight_end + 1] == " "
                and not line[path].isspace()
                and not line[weight_end + 2 : path].strip()
            ):
                tail = line[path:].rstrip()
                origin = tail[-1:]
                weight = line[local_pref_end + 2 : weight_end + 1].lstrip()
                metric_text = line[metric : metric_end + 1].lstrip()
                local_pref = line[metric_end + 2 : local_pref_end + 1].lstrip()
                network = line[n:hop].strip()
                next_hop = line[hop:metric].strip()
                if (
                    origin in origins
                    and (len(tail) == 1 or tail[-2] == " ")
                    and weight.isdigit()
                    and weight.isascii()
                    and (not metric_text or (metric_text.isdigit() and metric_text.isascii()))
                    and (not local_pref or (local_pref.isdigit() and local_pref.isascii()))
                    and (not network or network_ok(network))
                    and next_hop
                    and (next_hop == good_hop or next_hop_ok(next_hop))
                ):
                    as_path = tail[:-1].rstrip()
                    if "  " in as_path or not as_path.isprintable():
                        as_path = " ".join(as_path.split())
                    fields = (network, next_hop, metric_text, local_pref, weight, as_path or None, origin)
            if fields is None:
                fields, offset = _fields_by_tokens(line, geometry)
                if fields is None:
                    carried = pending = None
                    continue
                if offset is not None:
                    _n, hop, metric_end, local_pref_end, weight_end, path = (
                        value + offset for value in geometry
                    )
                    metric = metric_end - _METRIC_WIDTH + 1
                network, next_hop = fields[0], fields[1]
                if not next_hop:
                    # The next line holds the rest of the first path of a wrapped network.
                    if not network_ok(network):
                        carried = pending = None
                        continue
                    carried, pending = classful_prefix(network), status.strip()
                    continue
                if network and not network_ok(network):
                    carried = pending = None
                    continue
                if next_hop != good_hop and not next_hop_ok(next_hop):
                    carried = pending = None
                    continue
            else:
                network, next_hop = fields[0], fields[1]
            good_hop = next_hop
            status = status.strip()
            if network:
                carried = classful_prefix(network)
            elif carried is None:
                pending = None
                continue
            elif pending is not None and not status:
                status = pending
            pending = None
            yield (status, carried, next_hop, fields[2], fields[3], fields[4], fields[5], fields[6])
