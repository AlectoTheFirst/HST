"""Community-list and AS-path-list evaluation.

A `RoutePolicy` of kind `community-list` or `as-path-list` holds ordered
`MatchListEntry` children with `seq`, `action`, `match_type` and `value`. The
two kinds hold the IOS-XE and NX-OS `ip community-list` and
`ip as-path access-list`, the VyOS `policy community-list` and
`policy as-path-list`, and the IOS-XR `community-set` and `as-path-set`. The
collector stores the elements of an IOS-XR set as `permit` lines.

A list is walked in ascending `seq`. The action of the first matching line is
the result. A route that no line matches is denied. An IOS-XR set has only
permit elements. The IOS-XR tests `as-path in` and `community matches-any` are
true when one element of the set matches.

`match_type` sets the format of `value`.

  * `standard`: space-separated communities. The route must hold all of them.
    `internet` matches every route.
  * `expanded`: a Cisco regular expression matched against the route's
    communities as one space-separated string (or against the AS path, for an
    AS-path list).
  * `ios-regex`: an IOS-XR element regex. A community set matches it against
    each community on its own.
  * `wildcard`: one IOS-XR community pattern, `ASN:NN` where either half is a
    number, `*` or a `[lo..hi]` range.
  * `neighbor-is`, `originates-from`, `passes-through`: IOS-XR AS-path elements
    with a run of AS numbers at the start, at the end or anywhere in the path.
  * `length`: an IOS-XR AS-path length test, `eq|ge|le N`.

Any other `match_type` or a value that does not parse is unsupported.
`compile.py` reports the line. The line matches no route.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import Any


@dataclass(frozen=True)
class Line:
    """One `MatchListEntry` in a compiled policy.

    The class is frozen. A compiled policy must be hashable.
    """

    seq: int
    action: str
    match_type: str
    value: str

    @classmethod
    def of(cls, entry: Mapping[str, Any]) -> Line:
        return cls(
            seq=int(entry.get("seq") or 0),
            action=str(entry.get("action") or "").lower(),
            match_type=str(entry.get("match_type") or "").lower(),
            value=str(entry.get("value") or ""),
        )

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


type LineLike = Mapping[str, Any] | Line

# The RFC 1997 numbers of the well-known communities. `_canonical` maps a name
# to its number before a comparison.
_WELL_KNOWN = {
    "no-export": "65535:65281",
    "no-advertise": "65535:65282",
    "local-as": "65535:65283",
    "no-export-subconfed": "65535:65283",
}

# The Cisco `_` metacharacter matches the start, the end or a delimiter between AS numbers.
_CISCO_UNDERSCORE = r"(?:^|$|[ ,{}()])"

COMMUNITY_TYPES = frozenset({"standard", "expanded", "ios-regex", "wildcard"})
AS_PATH_TYPES = frozenset(
    {"expanded", "ios-regex", "neighbor-is", "originates-from", "passes-through", "length"}
)

_RANGE = re.compile(r"^\[(\d+)\.\.(\d+)\]$")
_LENGTH = re.compile(r"^(eq|ge|le|is)\s+(\d+)$")


def _canonical(community: str) -> str:
    text = str(community).strip().lower()
    return _WELL_KNOWN.get(text, text)


def _sort_key(community: str) -> tuple[int, int, str]:
    left, _, right = community.partition(":")
    if left.isdigit() and right.isdigit():
        return int(left), int(right), ""
    return 1 << 32, 0, community


@lru_cache(maxsize=1024)
def cisco_regex(pattern: str) -> re.Pattern[str] | None:
    """A Cisco regular expression as a Python one, or None when it does not
    compile. `_` is the only metacharacter Python lacks."""
    text = pattern.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        text = text[1:-1]
    try:
        return re.compile(text.replace("_", _CISCO_UNDERSCORE))
    except re.error:
        return None


def _half_matches(pattern: str, value: str) -> bool | None:
    if pattern == "*":
        return True
    if pattern.isdigit():
        return value == pattern
    if m := _RANGE.match(pattern):
        return value.isdigit() and int(m[1]) <= int(value) <= int(m[2])
    return None


def _wildcard_matches(pattern: str, community: str) -> bool | None:
    left, sep, right = pattern.partition(":")
    c_left, c_sep, c_right = community.partition(":")
    if not sep:
        return None
    if not c_sep:
        return False
    a = _half_matches(left, c_left)
    b = _half_matches(right, c_right)
    if a is None or b is None:
        return None
    return a and b


def _asns(value: str) -> tuple[int, ...] | None:
    tokens = value.strip().strip("'\"").split()
    if not tokens or not all(t.isdigit() for t in tokens):
        return None
    return tuple(int(t) for t in tokens)


def line_supported(entry: LineLike, kind: str) -> bool:
    """Whether the engine can evaluate this line of a `kind` list."""
    match_type = str(entry.get("match_type") or "").lower()
    value = str(entry.get("value") or "")
    if kind == "community-list":
        if match_type == "standard":
            return bool(value.split())
        if match_type in {"expanded", "ios-regex"}:
            return cisco_regex(value) is not None
        if match_type == "wildcard":
            return _wildcard_matches(value.strip(), "0:0") is not None
        return False
    if match_type in {"expanded", "ios-regex"}:
        return cisco_regex(value) is not None
    if match_type in {"neighbor-is", "originates-from", "passes-through"}:
        return _asns(value) is not None
    if match_type == "length":
        return _LENGTH.match(value.strip()) is not None
    return False


def community_line_matches(entry: LineLike, communities: Iterable[str]) -> bool:
    held = {_canonical(c) for c in communities}
    match_type = str(entry.get("match_type") or "").lower()
    value = str(entry.get("value") or "")
    if match_type == "standard":
        wanted = [_canonical(t) for t in value.split()]
        return bool(wanted) and all(w == "internet" or w in held for w in wanted)
    if match_type == "expanded":
        regex = cisco_regex(value)
        return regex is not None and regex.search(" ".join(sorted(held, key=_sort_key))) is not None
    if match_type == "ios-regex":
        regex = cisco_regex(value)
        return regex is not None and any(regex.search(c) for c in held)
    if match_type == "wildcard":
        return any(_wildcard_matches(value.strip(), c) for c in held)
    return False


def as_path_line_matches(entry: LineLike, as_path: tuple[int, ...]) -> bool:
    match_type = str(entry.get("match_type") or "").lower()
    value = str(entry.get("value") or "")
    if match_type in {"expanded", "ios-regex"}:
        regex = cisco_regex(value)
        return regex is not None and regex.search(" ".join(str(a) for a in as_path)) is not None
    if match_type in {"neighbor-is", "originates-from", "passes-through"}:
        run = _asns(value)
        if run is None or len(run) > len(as_path):
            return False
        if match_type == "neighbor-is":
            return as_path[: len(run)] == run
        if match_type == "originates-from":
            return as_path[-len(run) :] == run
        return any(as_path[i : i + len(run)] == run for i in range(len(as_path) - len(run) + 1))
    if match_type == "length":
        m = _LENGTH.match(value.strip())
        if m is None:
            return False
        op, n = m[1], int(m[2])
        length = len(as_path)
        return {"eq": length == n, "is": length == n, "ge": length >= n, "le": length <= n}[op]
    return False


def _ordered(entries: Iterable[LineLike]) -> list[LineLike]:
    return sorted(entries, key=lambda e: int(e.get("seq") or 0))


def community_list_permits(entries: Iterable[LineLike], communities: Iterable[str]) -> bool:
    """True when the first line matching the route's communities permits."""
    held = list(communities)
    for entry in _ordered(entries):
        if community_line_matches(entry, held):
            return str(entry.get("action") or "").lower() == "permit"
    return False


def community_set_matches_every(entries: Iterable[LineLike], communities: Iterable[str]) -> bool:
    """The IOS-XR test `community matches-every`.

    True when each element of the set matches one of the route's communities.
    """
    held = list(communities)
    lines = _ordered(entries)
    return bool(lines) and all(community_line_matches(entry, held) for entry in lines)


def as_path_list_permits(entries: Iterable[LineLike], as_path: tuple[int, ...]) -> bool:
    """True when the first line matching the route's AS path permits."""
    for entry in _ordered(entries):
        if as_path_line_matches(entry, as_path):
            return str(entry.get("action") or "").lower() == "permit"
    return False


def delete_matching(entries: Iterable[LineLike], communities: Iterable[str]) -> frozenset[str]:
    """The route's communities after `set comm-list <name> delete` or `delete community in <set>`.

    A community is removed when the first line that matches it is a permit line.
    Each community is tested on its own.
    """
    lines = _ordered(entries)
    kept = set()
    for community in communities:
        decided = False
        for entry in lines:
            if community_line_matches(entry, [community]):
                decided = str(entry.get("action") or "").lower() == "permit"
                break
        if not decided:
            kept.add(community)
    return frozenset(kept)
