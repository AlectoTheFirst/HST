"""The records of a stored step result that hold the terms of a claim.

The answer envelope (`envelope.py`) uses this module for 2 things. A claim
without a marker is `matched` to the steps of its turn that hold it. Every
claim with a cited or matched step stores the result records that hold it,
and the web client shows them.

A claim has 3 kinds of terms:

- identifiers: tokens with a digit and a letter (`core1`, `vlan20`), tokens
  with `-`, `_`, `:`, `.`, `/` or `@` inside (`LAN-WAN`, `192.168.2.45`,
  `vyos:core1:fw:LAN-WAN:10`), and upper-case words of 2 or more letters
  (`DMZ`). Protocol and field acronyms such as TCP, BGP or VRF are excluded.
- numbers, such as the 10 of "rule 10"
- value words: rule actions (drop, deny, permit, accept, allow, reject, block,
  in any inflection), `enabled`, `disabled`, `established` and the engine
  vocabularies

A record is one row of a Cypher table (`columns` and `data`), or one JSON
object of the result. The terms of an object are its own scalar values, the
values of its lists of scalars, the scalar values of the objects nested in it
outside lists, and the scalar values of the objects that enclose it. A string
value counts as a whole and as its parts split at whitespace, `:`, `/`, `,`,
`;`, `|`, `=`, `@` and brackets. `core1` is a term of `vyos:core1:fw:LAN-WAN`.
A host name also counts by its first label. Keys are not terms. After
compaction the `result_summary` of the step is one record.

A record supports a claim if 3 conditions hold. The claim has at least 1
identifier. Every identifier, number and value word of the claim is a term of
the record. The claim has a number, a value word, or 2 or more identifiers.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any

from hst.app.agent.tools import is_envelope
from hst.app.store import AiStep

# Records kept per step and claim, and the bounds of one walk.
RECORDS_PER_STEP = 5
_WALK_LIMIT = 20_000
_MAX_VALUE_CHARS = 512

_VALUE_FORMS: dict[str, tuple[str, ...]] = {
    "drop": ("drop", "drops", "dropped", "dropping"),
    "deny": ("deny", "denies", "denied", "denying"),
    "permit": ("permit", "permits", "permitted", "permitting"),
    "accept": ("accept", "accepts", "accepted", "accepting"),
    "allow": ("allow", "allows", "allowed", "allowing"),
    "reject": ("reject", "rejects", "rejected", "rejecting"),
    "block": ("block", "blocks", "blocked", "blocking"),
    "forward": ("forward", "forwards", "forwarded", "forwarding"),
    "pass": ("pass", "passes", "passed"),
    "fail": ("fail", "fails", "failed"),
    "decided": ("decided", "undecided"),
    "split": ("split",),
    "resolved": ("resolved",),
    "unresolved": ("unresolved",),
    "removed": ("removed",),
    "present": ("present",),
    "enabled": ("enabled",),
    "disabled": ("disabled",),
    "established": ("established",),
    "unknown": ("unknown",),
}
_STEM = {form: stem for stem, forms in _VALUE_FORMS.items() for form in forms}
_ACRONYMS = frozenset(
    {
        "tcp",
        "udp",
        "icmp",
        "ip",
        "ipv4",
        "ipv6",
        "bgp",
        "ospf",
        "isis",
        "vrf",
        "vlan",
        "nat",
        "acl",
        "dns",
        "http",
        "https",
        "ssh",
        "mtu",
        "rfc",
        "cidr",
        "id",
        "uid",
        "api",
        "snmp",
        "lldp",
        "cdp",
        "arp",
        "mac",
        "ok",
    }
)
_ABBREVIATIONS = frozenset({"e.g", "i.e", "vs", "cf", "etc"})
_TOKEN = re.compile(r"[0-9A-Za-z_](?:[0-9A-Za-z_.:/@-]*[0-9A-Za-z_])?")
_NUMBER = re.compile(r"[0-9]+(?:\.[0-9]+)?")
_IP = re.compile(r"[0-9.]+|[0-9a-f:]*:[0-9a-f:]*")
_INNER = frozenset("-_:./@")
_SEGMENT = re.compile(r"[\s:/,;|=@()\[\]{}<>\"']+")
# markdown emphasis and code marks around the words of a claim
_MARKUP = re.compile(r"[`*]")


@dataclass(frozen=True)
class ClaimTerms:
    identifiers: frozenset[str]
    numbers: frozenset[str]
    words: frozenset[str]


@dataclass(frozen=True)
class Record:
    """One record of a step result. `pointer` is the JSON pointer of the record
    in the stored result, or None for the summary of a compacted step. `terms`
    holds the terms of the record."""

    pointer: str | None
    terms: frozenset[str]

    @property
    def stems(self) -> frozenset[str]:
        return frozenset(_STEM[term] for term in self.terms if term in _STEM)


def claim_terms(text: str) -> ClaimTerms:
    """The identifiers, numbers and value words of one claim's text."""
    identifiers: set[str] = set()
    numbers: set[str] = set()
    words: set[str] = set()
    for token in _TOKEN.findall(_MARKUP.sub(" ", text)):
        low = token.lower()
        if low in _STEM:
            words.add(_STEM[low])
        elif _NUMBER.fullmatch(token):
            numbers.add(_number(token))
        elif low in _ABBREVIATIONS or low in _ACRONYMS or len(token) < 2:
            continue
        elif (
            (any(c.isdigit() for c in token) and any(c.isalpha() for c in token))
            or any(c in _INNER for c in token)
            or (token.isupper() and sum(c.isalpha() for c in token) >= 2)
        ):
            identifiers.add(low)
    return ClaimTerms(frozenset(identifiers), frozenset(numbers), frozenset(words))


def _number(text: str) -> str:
    value = float(text)
    return str(int(value)) if value.is_integer() else text


def _value_terms(value: Any) -> Iterator[str]:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        yield str(value)
    elif isinstance(value, float):
        yield str(int(value)) if value.is_integer() else repr(value)
    elif isinstance(value, str):
        yield from _text_terms(value)


def _text_terms(text: str) -> Iterator[str]:
    low = text.strip().lower()
    if not low or len(low) > _MAX_VALUE_CHARS:
        return
    yield low
    for part in _SEGMENT.split(low):
        part = part.strip(".")
        if not part:
            continue
        yield part
        if _NUMBER.fullmatch(part):
            yield _number(part)
        elif "." in part and not _IP.fullmatch(part):
            yield part.split(".", 1)[0]


def _escape(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, str | int | float | bool)


class _Walk:
    def __init__(self) -> None:
        self.records: list[Record] = []
        self.seen = 0

    def flat(self, value: Any) -> Iterator[str]:
        """The terms of every scalar under `value`."""
        stack = [value]
        while stack and self.seen < _WALK_LIMIT:
            node = stack.pop()
            self.seen += 1
            if isinstance(node, dict):
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
            else:
                yield from _value_terms(node)

    def own(self, node: dict[str, Any]) -> list[str]:
        """The terms of an object's scalars and lists of scalars, and of the
        objects nested in it outside lists."""
        terms: list[str] = []
        for value in node.values():
            if _is_scalar(value):
                terms.extend(_value_terms(value))
            elif isinstance(value, list) and all(_is_scalar(item) for item in value):
                for item in value:
                    terms.extend(_value_terms(item))
            elif isinstance(value, dict):
                terms.extend(self.own(value))
        return terms

    def table(self, node: dict[str, Any], pointer: str) -> bool:
        columns, data = node.get("columns"), node.get("data")
        if not isinstance(columns, list) or not isinstance(data, list):
            return False
        for i, item in enumerate(data):
            row = item.get("row") if isinstance(item, dict) else None
            if isinstance(row, list):
                self.records.append(Record(f"{pointer}/data/{i}", frozenset(self.flat(row))))
        return True

    def walk(self, node: Any, pointer: str, context: tuple[str, ...]) -> None:
        if self.seen >= _WALK_LIMIT:
            return
        self.seen += 1
        if isinstance(node, list):
            for i, item in enumerate(node):
                if isinstance(item, dict | list):
                    self.walk(item, f"{pointer}/{i}", context)
            return
        if not isinstance(node, dict) or self.table(node, pointer):
            return
        terms = self.own(node)
        if terms:
            self.records.append(Record(pointer, frozenset((*context, *terms))))
        own = [term for value in node.values() if _is_scalar(value) for term in _value_terms(value)]
        inner = (*context, *own)
        for key, value in node.items():
            if isinstance(value, dict | list):
                self.walk(value, f"{pointer}/{_escape(str(key))}", inner)


def records(step: AiStep) -> list[Record]:
    """The records of a step's stored result, or of its `result_summary`
    after compaction. A failed step and a result that is not JSON have none."""
    if step.is_error:
        return []
    if step.result is None:
        summary = step.result_summary or ""
        return [Record(None, frozenset(_text_terms(summary)))] if summary else []
    try:
        body = json.loads(step.result)
    except ValueError:
        return []
    walk = _Walk()
    if is_envelope(body):
        walk.walk(body["result"], "/result", ())
    else:
        walk.walk(body, "", ())
    return walk.records


def supports(claim: ClaimTerms, record: Record) -> bool:
    """Whether `record` supports `claim` by the rule of the module docstring."""
    if not claim.identifiers or not (claim.identifiers | claim.numbers) <= record.terms:
        return False
    if not claim.words <= record.stems:
        return False
    return bool(claim.numbers or claim.words) or len(claim.identifiers) >= 2


def supporting(claim: ClaimTerms, found: Sequence[Record]) -> list[Record]:
    """The records of one step that support `claim`, at most `RECORDS_PER_STEP`.
    Of nested records, only the innermost records are kept."""
    matched = [record for record in found if supports(claim, record)]
    inner = [
        record
        for record in matched
        if record.pointer is None
        or not any(
            other.pointer is not None and other.pointer.startswith(record.pointer + "/") for other in matched
        )
    ]
    return inner[:RECORDS_PER_STEP]
