"""Every parameter name of a compiled filter starts with `f_`."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from . import ipenc
from . import uid as uidmod

TextField = Literal["name", "hostname", "mac", "vendor", "port"]
RegexField = Literal["name", "hostname"]
TEXT_FIELDS: tuple[TextField, ...] = ("name", "hostname", "mac", "vendor", "port")
REGEX_FIELDS: tuple[RegexField, ...] = ("name", "hostname")
SCOPES = ("site", "vrf", "routing_domain", "segment", "device", "port")

TEXT_MAX_LEN = 128
SCOPE_MAX_ITEMS = 200
SCOPE_ITEM_MAX_LEN = 256
REGEX_MAX_LEN = 128
REGEX_MAX_REPEAT = 64
REGEX_MAX_UNBOUNDED = 3
REGEX_MAX_VALUE = 256
QUERY_TIMEOUT_S = 15.0

# The count a list returns is exact up to this many rows.
COUNT_CAP = 10_000


class FilterError(ValueError):
    """A filter, a regex or a cursor the caller sent that cannot be used."""


# --- the regex guard ------------------------------------------------------------------

_CLASS_ESCAPES = set("dDwWsS")


@dataclass
class _Group:
    quantifiers: int = 0
    alternation: bool = False


def _bad(reason: str) -> FilterError:
    return FilterError(f"regex refused: {reason}")


def _read_escape(pattern: str, i: int) -> int:
    """Return the index after the escape at `pattern[i]` (a backslash)."""
    if i + 1 >= len(pattern):
        raise _bad("trailing backslash")
    ch = pattern[i + 1]
    if ch in _CLASS_ESCAPES or not ch.isalnum():
        return i + 2
    raise _bad(f"escape \\{ch} is not supported")


def _read_class(pattern: str, i: int) -> int:
    """Return the index after the character class that opens at `pattern[i]`."""
    j = i + 1
    if j < len(pattern) and pattern[j] == "^":
        j += 1
    if j < len(pattern) and pattern[j] == "]":
        j += 1
    while j < len(pattern):
        ch = pattern[j]
        if ch == "\\":
            j = _read_escape(pattern, j)
            continue
        if ch == "[" or pattern.startswith("&&", j):
            raise _bad("nested character classes and class intersection are not supported")
        if ch == "]":
            return j + 1
        j += 1
    raise _bad("unterminated character class")


def _read_quantifier(pattern: str, i: int) -> tuple[int, bool] | None:
    """Return (index after, unbounded) of a quantifier at `pattern[i]`, or None."""
    ch = pattern[i]
    if ch in "*+":
        end, unbounded = i + 1, True
    elif ch == "?":
        end, unbounded = i + 1, False
    elif ch == "{":
        m = re.match(r"\{(\d{1,3})(,(\d{0,3}))?\}", pattern[i:])
        if m is None:
            raise _bad("malformed repetition")
        low = int(m.group(1))
        high = m.group(3)
        if m.group(2) and not high:
            unbounded = True
        else:
            unbounded = False
            if high and int(high) < low:
                raise _bad("repetition bounds out of order")
        if low > REGEX_MAX_REPEAT or (high and int(high) > REGEX_MAX_REPEAT):
            raise _bad(f"repetition bound above {REGEX_MAX_REPEAT}")
        end = i + m.end()
    else:
        return None
    if end < len(pattern) and pattern[end] == "+":
        raise _bad("possessive quantifiers are not supported")
    if end < len(pattern) and pattern[end] == "?":
        end += 1
    return end, unbounded


def check_regex(pattern: str) -> str:
    """Return `pattern` when it passes the guard, else raise a `FilterError`
    with the first rule that it breaks."""
    if not pattern:
        raise _bad("empty pattern")
    if len(pattern) > REGEX_MAX_LEN:
        raise _bad(f"longer than {REGEX_MAX_LEN} characters")
    stack: list[_Group] = [_Group()]
    unbounded = 0
    # `prev` is the kind of the previous token. A quantifier needs an atom or a
    # group. `closed` is the group that the previous token closed.
    prev: Literal["none", "atom", "group"] = "none"
    closed: _Group | None = None
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        quant = _read_quantifier(pattern, i)
        if quant is not None:
            if prev == "none":
                raise _bad("quantifier without a target")
            end, is_unbounded = quant
            if prev == "group" and closed is not None and (closed.quantifiers or closed.alternation):
                raise _bad("a quantified group may not hold a quantifier or an alternation")
            unbounded += is_unbounded
            if unbounded > REGEX_MAX_UNBOUNDED:
                raise _bad(f"more than {REGEX_MAX_UNBOUNDED} unbounded quantifiers")
            stack[-1].quantifiers += 1
            prev, closed, i = "none", None, end
            continue
        if ch == "\\":
            i, prev = _read_escape(pattern, i), "atom"
        elif ch == "[":
            i, prev = _read_class(pattern, i), "atom"
        elif ch == "(":
            if pattern.startswith("(?", i):
                if not pattern.startswith("(?:", i):
                    raise _bad("only plain and (?:) groups are supported")
                i += 3
            else:
                i += 1
            stack.append(_Group())
            if len(stack) > 8:
                raise _bad("groups nested deeper than 7")
            prev = "none"
        elif ch == ")":
            if len(stack) == 1:
                raise _bad("unbalanced parenthesis")
            closed = stack.pop()
            # The quantifiers and the alternation of a closed group count for its parent group.
            stack[-1].quantifiers += closed.quantifiers
            stack[-1].alternation = stack[-1].alternation or closed.alternation
            i, prev = i + 1, "group"
            continue
        elif ch == "|":
            stack[-1].alternation = True
            i, prev = i + 1, "none"
        elif ch in "^$":
            i, prev = i + 1, "none"
        elif ch in "]}":
            raise _bad(f"unescaped {ch}")
        else:
            i, prev = i + 1, "atom"
        closed = None
    if len(stack) != 1:
        raise _bad("unbalanced parenthesis")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise _bad(str(exc)) from exc
    return pattern


# --- the filter model -----------------------------------------------------------------


def _address(value: str, what: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError(f"{what} {value!r} is not an IP address") from exc


def _utc(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


class EntityFilter(BaseModel):
    """One list filter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ip: str | None = None
    subnet: str | None = None
    range_start: str | None = None
    range_end: str | None = None
    text: str | None = Field(default=None, min_length=1, max_length=TEXT_MAX_LEN)
    text_fields: tuple[TextField, ...] | None = None
    regex: str | None = None
    regex_fields: tuple[RegexField, ...] | None = None
    site: tuple[str, ...] | None = None
    vrf: tuple[str, ...] | None = None
    routing_domain: tuple[str, ...] | None = None
    segment: tuple[str, ...] | None = None
    device: tuple[str, ...] | None = None
    port: tuple[str, ...] | None = None
    last_seen_after: datetime | None = None
    last_seen_before: datetime | None = None

    @field_validator("ip")
    @classmethod
    def _ip(cls, v: str | None) -> str | None:
        return None if v is None else str(_address(v, "ip"))

    @field_validator("subnet")
    @classmethod
    def _subnet(cls, v: str | None) -> str | None:
        if v is None:
            return None
        try:
            return str(ipaddress.ip_network(v.strip(), strict=False))
        except ValueError as exc:
            raise ValueError(f"subnet {v!r} is not a prefix") from exc

    @field_validator("range_start", "range_end")
    @classmethod
    def _range_end(cls, v: str | None) -> str | None:
        return None if v is None else str(_address(v, "range bound"))

    @field_validator("regex")
    @classmethod
    def _regex(cls, v: str | None) -> str | None:
        if v is None:
            return None
        try:
            return check_regex(v)
        except FilterError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("text_fields", "regex_fields")
    @classmethod
    def _fields(cls, v: tuple[str, ...] | None) -> tuple[str, ...] | None:
        if v is not None and not v:
            raise ValueError("name at least one field, or none for all of them")
        return None if v is None else tuple(sorted(set(v)))

    @field_validator(*SCOPES)
    @classmethod
    def _scope(cls, v: tuple[str, ...] | None) -> tuple[str, ...] | None:
        if v is None:
            return None
        items = tuple(sorted({s.strip() for s in v if s.strip()}))
        if not items:
            raise ValueError("name at least one value")
        if len(items) > SCOPE_MAX_ITEMS:
            raise ValueError(f"at most {SCOPE_MAX_ITEMS} values")
        if any(len(s) > SCOPE_ITEM_MAX_LEN for s in items):
            raise ValueError(f"a value is longer than {SCOPE_ITEM_MAX_LEN} characters")
        return items

    @field_validator("last_seen_after", "last_seen_before")
    @classmethod
    def _time(cls, v: datetime | None) -> datetime | None:
        return _utc(v)

    @model_validator(mode="after")
    def _pairs(self) -> EntityFilter:
        if (self.range_start is None) != (self.range_end is None):
            raise ValueError("range_start and range_end go together")
        if self.range_start is not None and self.range_end is not None:
            lo, hi = ipaddress.ip_address(self.range_start), ipaddress.ip_address(self.range_end)
            if lo.version != hi.version:
                raise ValueError("range_start and range_end must be of one address family")
            if int(lo) > int(hi):
                raise ValueError("range_start is above range_end")
        if self.text_fields is not None and self.text is None:
            raise ValueError("text_fields needs text")
        if self.regex_fields is not None and self.regex is None:
            raise ValueError("regex_fields needs regex")
        after, before = self.last_seen_after, self.last_seen_before
        if after is not None and before is not None and after >= before:
            raise ValueError("last_seen_after is not before last_seen_before")
        return self

    def kinds(self) -> list[str]:
        """The filter kinds this filter sets, in a fixed order."""
        out = [k for k in ("ip", "subnet", "text", "regex", *SCOPES) if getattr(self, k) is not None]
        if self.range_start is not None:
            out.append("range")
        if self.last_seen_after is not None or self.last_seen_before is not None:
            out.append("last_seen")
        return out

    def fingerprint(self) -> str:
        """A short digest of the filter, to tie a cursor to the filter it paged."""
        canon = json.dumps(self.model_dump(mode="json", exclude_none=True), sort_keys=True)
        return hashlib.sha256(canon.encode()).hexdigest()[:16]


def parse_filter(values: dict[str, Any]) -> EntityFilter:
    """Return an `EntityFilter` from plain values. None and empty values are dropped.

    A `FilterError` with the first problem is raised when the values are not valid."""
    clean = {k: v for k, v in values.items() if v is not None and v != [] and v != ""}
    try:
        return EntityFilter.model_validate(clean)
    except ValidationError as exc:
        first = exc.errors()[0]
        loc = ".".join(str(p) for p in first.get("loc", ()))
        msg = str(first.get("msg", "invalid")).removeprefix("Value error, ")
        raise FilterError(f"{loc}: {msg}" if loc else msg) from exc


# --- per entity kind ------------------------------------------------------------------


def _attachment_scope(var: str) -> str:
    """Return the predicate of the site, device and port scopes of an attached object.

    One attachment must match every scope. `device` and `port` together match
    that port of that device."""
    return f"""EXISTS {{
  MATCH ({var})-[fa:ATTACHED]->(fat) WHERE fa._retired_at IS NULL AND NOT fat:Retired
  OPTIONAL MATCH (fat)-[fo:ON]->(fod:Device) WHERE fo._retired_at IS NULL
  WITH fat, coalesce(fod, CASE WHEN fat:Device THEN fat END) AS fdev
  WHERE fdev IS NOT NULL AND NOT fdev:Retired
    AND ($f_device IS NULL OR fdev.uid IN $f_device OR fdev.hostname IN $f_device)
    AND ($f_port IS NULL OR ((fat:Port OR fat:Interface) AND fat.name IN $f_port))
    AND ($f_site IS NULL OR EXISTS {{
      MATCH (fdev)-[fli:LOCATED_IN]->(fs:Site) WHERE fli._retired_at IS NULL AND fs.uid IN $f_site }})
}}"""


def _held_address(var: str, pred: Callable[[str, str], str]) -> str:
    """An address the object holds through HAS_IP, matching `pred`."""
    return f"""EXISTS {{
  MATCH ({var})-[fh:HAS_IP]->(fia:IpAddress) WHERE fh._retired_at IS NULL AND NOT fia:Retired
    AND {pred("fia.ip_key", "fia.ip")}
}}"""


def _prefix_context(var_ip: str, scope: Literal["vrf", "routing_domain"]) -> str:
    """Return the predicate on the VRF or the routing domain of the prefixes
    that the address `var_ip` is IN.

    The scope `vrf` matches the anchor of the prefix or the VrfInstance that
    ORIGINATES it. The scope `routing_domain` matches the anchor of the prefix
    or the RoutingDomain of that VrfInstance."""
    if scope == "vrf":
        context = """(fp.anchor IN $f_vrf OR EXISTS {
      MATCH (fp)<-[fog:ORIGINATES]-(fv:VrfInstance)
      WHERE fog._retired_at IS NULL AND (fv.uid IN $f_vrf OR fv.name IN $f_vrf) })"""
    else:
        context = """(fp.anchor IN $f_routing_domain OR EXISTS {
      MATCH (fp)<-[fog:ORIGINATES]-(:VrfInstance)-[fm:MEMBER_OF]->(frd:RoutingDomain)
      WHERE fog._retired_at IS NULL AND fm._retired_at IS NULL
        AND (frd.uid IN $f_routing_domain OR frd.name IN $f_routing_domain) })"""
    return f"""EXISTS {{
  MATCH ({var_ip})-[fn:IN]->(fp:Prefix) WHERE fn._retired_at IS NULL AND NOT fp:Retired
    AND {context}
}}"""


def _held_context(var: str, scope: Literal["vrf", "routing_domain"]) -> str:
    return f"""EXISTS {{
  MATCH ({var})-[fh:HAS_IP]->(fia:IpAddress) WHERE fh._retired_at IS NULL AND NOT fia:Retired
    AND {_prefix_context("fia", scope)}
}}"""


def _prefix_own_context(var: str, scope: Literal["vrf", "routing_domain"]) -> str:
    if scope == "vrf":
        return f"""({var}.anchor IN $f_vrf OR EXISTS {{
  MATCH ({var})<-[fog:ORIGINATES]-(fv:VrfInstance)
  WHERE fog._retired_at IS NULL AND (fv.uid IN $f_vrf OR fv.name IN $f_vrf) }})"""
    return f"""({var}.anchor IN $f_routing_domain OR EXISTS {{
  MATCH ({var})<-[fog:ORIGINATES]-(:VrfInstance)-[fm:MEMBER_OF]->(frd:RoutingDomain)
  WHERE fog._retired_at IS NULL AND fm._retired_at IS NULL
    AND (frd.uid IN $f_routing_domain OR frd.name IN $f_routing_domain) }})"""


def _contains(expr: str) -> str:
    return f"toLower(coalesce({expr}, '')) CONTAINS $f_text"


def _mac_contains(expr: str) -> str:
    """A MAC matches on its text and on its hex digits. `aabb`, `aa:bb` and
    `aa-bb` each find `aa:bb:cc:dd:ee:ff`."""
    return (
        f"({_contains(expr)} OR ($f_text_hex <> '' AND "
        f"replace(replace(replace(toLower(coalesce({expr}, '')), ':', ''), '-', ''), '.', '') "
        "CONTAINS $f_text_hex))"
    )


AddressPred = Callable[[str, str], str]


@dataclass(frozen=True)
class Target:
    """The filters that one entity kind supports, as Cypher over its match variable.

    `address(pred)` is the predicate that the object holds or is an address
    that matches `pred(key_expr, text_expr)`. `text` maps each field to a
    predicate on `$f_text`. `regex` maps each field to the Cypher of its
    value. `scopes` maps each scope to its predicate. `last_seen` is the Cypher
    of the last-seen time of the object in epoch milliseconds.
    """

    kind: str
    var: str
    address: Callable[[AddressPred], str] | None = None
    prefix_semantics: bool = False
    text: dict[str, str] = field(default_factory=dict)
    regex: dict[str, str] = field(default_factory=dict)
    scopes: dict[str, str] = field(default_factory=dict)
    attachment_scopes: frozenset[str] = frozenset()
    last_seen: str | None = None

    def supports(self) -> set[str]:
        out = set(self.scopes) | set(self.attachment_scopes)
        if self.address is not None:
            out |= {"ip", "subnet", "range"}
        if self.text:
            out.add("text")
        if self.regex:
            out.add("regex")
        if self.last_seen is not None:
            out.add("last_seen")
        return out


ENDPOINT = Target(
    kind="endpoint",
    var="e",
    address=lambda pred: f"({pred('e.ip_key', 'e.ip')} OR {_held_address('e', pred)})",
    text={
        "name": _contains("e.name"),
        "hostname": _contains("e.hostname"),
        "mac": _mac_contains("e.mac"),
        "vendor": _contains("e.oui"),
        "port": """EXISTS {
  MATCH (e)-[fa:ATTACHED]->(fat) WHERE fa._retired_at IS NULL AND NOT fat:Retired
    AND (fat:Port OR fat:Interface) AND toLower(coalesce(fat.name, '')) CONTAINS $f_text }""",
    },
    regex={"name": "e.name", "hostname": "e.hostname"},
    scopes={
        "segment": """EXISTS {
  MATCH (e)-[fib:IN]->(fbd) WHERE (fbd:BridgeDomain OR fbd:L2Segment)
    AND fib._retired_at IS NULL AND NOT fbd:Retired
    AND (fbd.uid IN $f_segment OR fbd.name IN $f_segment) }""",
        "vrf": _held_context("e", "vrf"),
        "routing_domain": _held_context("e", "routing_domain"),
    },
    attachment_scopes=frozenset({"site", "device", "port"}),
    last_seen="coalesce(e.last_seen, e.last_seen_ts)",
)

DEVICE = Target(
    kind="device",
    var="d",
    address=lambda pred: (
        f"({pred('null', 'd.mgmt_ip')} OR {_held_address('d', pred)} OR EXISTS {{\n"
        "  MATCH (d)<-[fo:ON]-(fi:Interface)-[fh:HAS_IP]->(fia:IpAddress)\n"
        "  WHERE fo._retired_at IS NULL AND fh._retired_at IS NULL AND NOT fi:Retired AND NOT fia:Retired\n"
        f"    AND {pred('fia.ip_key', 'fia.ip')} }})"
    ),
    text={
        "name": _contains("coalesce(d.hostname, d.uid)"),
        "hostname": _contains("d.hostname"),
        "mac": _mac_contains("d.mac"),
        "vendor": _contains("d.vendor"),
        "port": """EXISTS {
  MATCH (d)<-[fo:ON]-(fx) WHERE fo._retired_at IS NULL AND NOT fx:Retired
    AND (fx:Port OR fx:Interface) AND toLower(coalesce(fx.name, '')) CONTAINS $f_text }""",
    },
    regex={"name": "coalesce(d.hostname, d.uid)", "hostname": "d.hostname"},
    scopes={
        "site": """EXISTS {
  MATCH (d)-[fli:LOCATED_IN]->(fs:Site) WHERE fli._retired_at IS NULL AND fs.uid IN $f_site }""",
        "device": "(d.uid IN $f_device OR d.hostname IN $f_device)",
        "vrf": """EXISTS {
  MATCH (d)<-[fo:ON]-(:Interface)-[fiv:IN_VRF]->(fv:VrfInstance)
  WHERE fo._retired_at IS NULL AND fiv._retired_at IS NULL AND (fv.uid IN $f_vrf OR fv.name IN $f_vrf) }""",
    },
    last_seen="coalesce(d.last_seen_ts, d.collected_at)",
)

SITE = Target(
    kind="site",
    var="s",
    text={"name": _contains("s.code")},
    regex={"name": "s.code"},
    scopes={"site": "s.uid IN $f_site"},
)

SEGMENT = Target(
    kind="segment",
    var="b",
    text={"name": f"({_contains('b.name')} OR {_contains('b.uid')})"},
    regex={"name": "coalesce(b.name, b.uid)"},
    scopes={
        "segment": "(b.uid IN $f_segment OR b.name IN $f_segment)",
        "site": """EXISTS {
  MATCH (b)<-[frz:REALIZES]-(:VlanInstance)<-[fr:CARRIES|BOUND_TO]-(fx)-[fo:ON]->(fdev:Device)
        -[fli:LOCATED_IN]->(fs:Site)
  WHERE frz._retired_at IS NULL AND fr._retired_at IS NULL AND fo._retired_at IS NULL
    AND fli._retired_at IS NULL AND NOT fdev:Retired AND fs.uid IN $f_site }""",
        "device": """EXISTS {
  MATCH (b)<-[frz:REALIZES]-(:VlanInstance)<-[fr:CARRIES|BOUND_TO]-(fx)-[fo:ON]->(fdev:Device)
  WHERE frz._retired_at IS NULL AND fr._retired_at IS NULL AND fo._retired_at IS NULL
    AND NOT fdev:Retired AND (fdev.uid IN $f_device OR fdev.hostname IN $f_device) }""",
    },
)

PREFIX = Target(
    kind="prefix",
    var="p",
    # A prefix is a range of addresses. `ip` finds the prefixes that hold the
    # address. `subnet` and `range` find the prefixes that lie within them.
    address=lambda pred: pred("p", "p.cidr"),
    prefix_semantics=True,
    text={"name": _contains("p.cidr")},
    regex={"name": "p.cidr"},
    scopes={
        "vrf": _prefix_own_context("p", "vrf"),
        "routing_domain": _prefix_own_context("p", "routing_domain"),
    },
)

IP_ADDRESS = Target(
    kind="ip_address",
    var="a",
    address=lambda pred: pred("a.ip_key", "a.ip"),
    text={"name": _contains("a.ip")},
    regex={"name": "a.ip"},
    scopes={
        "vrf": _prefix_context("a", "vrf"),
        "routing_domain": _prefix_context("a", "routing_domain"),
        "segment": "a.anchor IN $f_segment",
    },
)

INTERFACE = Target(
    kind="interface",
    var="i",
    address=lambda pred: _held_address("i", pred),
    text={"name": _contains("i.name"), "mac": _mac_contains("i.mac")},
    regex={"name": "i.name"},
    scopes={
        "device": """EXISTS {
  MATCH (i)-[fo:ON]->(fd:Device) WHERE fo._retired_at IS NULL AND NOT fd:Retired
    AND (fd.uid IN $f_device OR fd.hostname IN $f_device) }""",
        "vrf": """EXISTS {
  MATCH (i)-[fiv:IN_VRF]->(fv:VrfInstance) WHERE fiv._retired_at IS NULL
    AND (fv.uid IN $f_vrf OR fv.name IN $f_vrf) }""",
    },
)

VRF = Target(
    kind="vrf",
    var="v",
    text={"name": _contains("v.name"), "hostname": _contains("v.hostname")},
    regex={"name": "v.name", "hostname": "v.hostname"},
    scopes={"vrf": "(v.uid IN $f_vrf OR v.name IN $f_vrf)"},
)

# The graph holds a business application as a BusinessService node.
APPLICATION = Target(
    kind="application",
    var="x",
    text={"name": _contains("x.name")},
    regex={"name": "x.name"},
)

TARGETS = {
    t.kind: t for t in (ENDPOINT, DEVICE, SITE, SEGMENT, PREFIX, IP_ADDRESS, INTERFACE, VRF, APPLICATION)
}


# --- compilation ----------------------------------------------------------------------


@dataclass(frozen=True)
class Compiled:
    """A compiled filter.

    `where` is a Cypher predicate, "true" when the filter sets nothing. `params`
    holds the parameters that `where` binds."""

    where: str
    params: dict[str, Any]

    @property
    def empty(self) -> bool:
        return not self.params


def _epoch_ms(value: datetime) -> int:
    return int(value.timestamp() * 1000)


def _address_preds(f: EntityFilter, prefix: bool) -> tuple[list[Callable[[str, str], str]], dict[str, Any]]:
    """The address predicates of `f` as functions of (key, text) expressions,
    and their parameters. For a prefix the key expression is the prefix
    variable. Its `lo_key` and `hi_key` are the bounds of the prefix."""
    preds: list[Callable[[str, str], str]] = []
    params: dict[str, Any] = {}
    if f.ip is not None:
        params["f_ip"] = f.ip
        params["f_ip_key"] = ipenc.graph_key(f.ip)
        if prefix:
            preds.append(lambda k, t: f"({k}.lo_key <= $f_ip_key AND {k}.hi_key >= $f_ip_key)")
        else:
            preds.append(lambda k, t: f"({k} = $f_ip_key OR {t} = $f_ip)")
    if f.subnet is not None:
        params["f_net_lo"], params["f_net_hi"] = ipenc.graph_prefix_keys(f.subnet) or ("", "")
        if prefix:
            preds.append(lambda k, t: f"({k}.lo_key >= $f_net_lo AND {k}.hi_key <= $f_net_hi)")
        else:
            preds.append(lambda k, t: f"({k} >= $f_net_lo AND {k} <= $f_net_hi)")
    if f.range_start is not None:
        params["f_range_lo"] = ipenc.graph_key(f.range_start)
        params["f_range_hi"] = ipenc.graph_key(f.range_end)
        if prefix:
            preds.append(lambda k, t: f"({k}.lo_key >= $f_range_lo AND {k}.hi_key <= $f_range_hi)")
        else:
            preds.append(lambda k, t: f"({k} >= $f_range_lo AND {k} <= $f_range_hi)")
    return preds, params


def compile_filter(f: EntityFilter, kind: str) -> Compiled:
    """`f` as a Cypher predicate over the match variable of entity `kind`."""
    target = TARGETS[kind]
    unsupported = [k for k in f.kinds() if k not in target.supports()]
    if unsupported:
        raise FilterError(f"{target.kind} lists do not support the filter(s): {', '.join(unsupported)}")
    clauses: list[str] = []
    params: dict[str, Any] = {}

    preds, address_params = _address_preds(f, target.prefix_semantics)
    if preds and target.address is not None:
        params |= address_params
        for pred in preds:
            clauses.append(target.address(pred))

    if f.text is not None:
        params["f_text"] = f.text.lower()
        params["f_text_hex"] = re.sub(r"[^0-9a-f]", "", f.text.lower())
        if params["f_text_hex"] != re.sub(r"[:.\-]", "", f.text.lower()):
            # The text is no MAC fragment. The MAC matches on its text only.
            params["f_text_hex"] = ""
        fields: tuple[str, ...] = f.text_fields or tuple(target.text)
        missing = [x for x in fields if x not in target.text]
        if missing:
            raise FilterError(f"{target.kind} lists do not support text over: {', '.join(missing)}")
        clauses.append("(" + " OR ".join(target.text[x] for x in fields) + ")")

    if f.regex is not None:
        params["f_regex"] = "(?i)" + f.regex
        params["f_regex_max"] = REGEX_MAX_VALUE
        fields = f.regex_fields or tuple(target.regex)
        missing = [x for x in fields if x not in target.regex]
        if missing:
            raise FilterError(f"{target.kind} lists do not support regex over: {', '.join(missing)}")
        alts = [
            f"({target.regex[x]} IS NOT NULL AND size({target.regex[x]}) <= $f_regex_max "
            f"AND {target.regex[x]} =~ $f_regex)"
            for x in fields
        ]
        clauses.append("(" + " OR ".join(alts) + ")")

    attachment = [s for s in SCOPES if s in target.attachment_scopes and getattr(f, s) is not None]
    for scope in SCOPES:
        value = getattr(f, scope)
        if value is None:
            continue
        params[f"f_{scope}"] = [uidmod.site(v) for v in value] if scope == "site" else list(value)
        if scope in target.scopes and scope not in attachment:
            clauses.append(target.scopes[scope])
    if attachment:
        for scope in ("site", "device", "port"):
            params.setdefault(f"f_{scope}", None)
        clauses.append(_attachment_scope(target.var))

    if f.last_seen_after is not None or f.last_seen_before is not None:
        if target.last_seen is None:  # supports() refused it above
            raise FilterError(f"{target.kind} lists do not support last_seen")
        if f.last_seen_after is not None:
            params["f_seen_after"] = _epoch_ms(f.last_seen_after)
            clauses.append(f"{target.last_seen} >= $f_seen_after")
        if f.last_seen_before is not None:
            params["f_seen_before"] = _epoch_ms(f.last_seen_before)
            clauses.append(f"{target.last_seen} < $f_seen_before")

    return Compiled(" AND ".join(f"({c})" for c in clauses) if clauses else "true", params)


# --- cursors --------------------------------------------------------------------------


@dataclass(frozen=True)
class Cursor:
    """The position after one row of one list.

    It holds the sort key and the uid of the row, the run, the entity kind and
    the filter fingerprint."""

    kind: str
    run: int | None
    key: str
    uid: str
    filter: str

    def encode(self) -> str:
        doc = {"v": 1, "t": self.kind, "r": self.run, "k": self.key, "u": self.uid, "f": self.filter}
        raw = json.dumps(doc, separators=(",", ":"), sort_keys=True).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")


CURSOR_MAX_LEN = 2048


def decode_cursor(text: str, *, kind: str, filter_print: str) -> Cursor:
    """The cursor `text` encodes, checked against the list it is used on."""
    if len(text) > CURSOR_MAX_LEN:
        raise FilterError("invalid cursor")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        doc = json.loads(raw)
    except (binascii.Error, ValueError) as exc:
        raise FilterError("invalid cursor") from exc
    if not isinstance(doc, dict) or doc.get("v") != 1:
        raise FilterError("invalid cursor")
    run, key, uid = doc.get("r"), doc.get("k"), doc.get("u")
    if not (
        (run is None or (isinstance(run, int) and not isinstance(run, bool)))
        and isinstance(key, str)
        and isinstance(uid, str)
    ):
        raise FilterError("invalid cursor")
    if doc.get("t") != kind:
        raise FilterError("the cursor belongs to another list")
    if doc.get("f") != filter_print:
        raise FilterError("the cursor belongs to another filter")
    return Cursor(kind=kind, run=run, key=key, uid=uid, filter=filter_print)


def seek_clause(var: str) -> str:
    """The predicate that keeps the rows after the cursor, in the order of
    `sort_key` then uid. It binds `$c_key` and `$c_uid`."""
    return f"(sort_key > $c_key OR (sort_key = $c_key AND {var}.uid > $c_uid))"


def after(rows: list[dict[str, Any]], cursor: Cursor | None, key: str = "name") -> list[dict[str, Any]]:
    """The rows past `cursor` in a list ordered by (`key`, uid)."""
    if cursor is None:
        return rows
    at = (cursor.key, cursor.uid)
    for i in range(len(rows) - 1, -1, -1):
        if (rows[i].get(key) or "", rows[i].get("uid") or "") == at:
            return rows[i + 1 :]
    return [r for r in rows if (r.get(key) or "", r.get("uid") or "") > at]
