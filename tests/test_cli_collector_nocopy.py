"""`exec_banner_of` and `_content_status` read an answer without copying it.

The banner search reads each answer's head line by line and stops at the
first line that differs, and the emptiness check tests a str in place. Each is
checked against the whole-answer split and the strip, embedded below.
"""

from __future__ import annotations

import json
import random
from typing import Any

import pytest

from hst.collectors import cli_collector
from hst.collectors.cli_collector import _content_status, _split_lines, _table_rows, exec_banner_of

CASES = 20_000


def _reference_exec_banner_of(outputs: Any) -> str:
    """The whole-answer split `exec_banner_of` is checked against."""
    texts = list(outputs)
    if len(texts) < 2:
        return ""
    first = texts[0].split("\n")
    shared = len(first)
    for text in texts[1:]:
        lines = text.split("\n")
        limit = min(shared, len(lines))
        i = 0
        while i < limit and lines[i] == first[i]:
            i += 1
        shared = i
        if shared == 0:
            return ""
    return "\n".join(first[:shared]) + "\n"


def _reference_content_status(text: Any, rows: int | None, table: str | None) -> tuple[str, int | None]:
    """The strip-based `_content_status` the in-place check is checked against."""
    if rows:
        return "ok", rows
    if table is not None:
        if not str(text or "").strip():
            return "empty", 0
        try:
            payload = json.loads(text) if isinstance(text, str) else text
        except ValueError:
            return "malformed", None
        if isinstance(payload, dict) and not payload:
            return "empty", 0
        if not isinstance(payload, dict) or f"TABLE_{table}" not in payload:
            return "malformed", None
        count = _table_rows(payload, table) if rows is None else rows
        return ("ok", count) if count else ("empty", 0)
    if rows is not None:
        return "empty", 0
    return ("ok", None) if str(text or "").strip() else ("empty", None)


# --- exec_banner_of ----------------------------------------------------------------

# Lines a device prints, chosen to collide: the same text with and without a
# carriage return, blank and whitespace-only lines, and lines that are
# prefixes of each other.
_LINES = [
    "",
    " ",
    "\r",
    "\t",
    "*** Authorized access only ***",
    "*** Authorized access only ***\r",
    "*** Authorized access only",
    "Banner",
    "Banner\r",
    "Router#",
    "Interface  IP-Address  OK? Method Status  Protocol",
    "Gi1/0/1  10.0.0.1  YES NVRAM up  up",
    "Gi1/0/1  10.0.0.1  YES NVRAM up  up\r",
    "B  10.0.0.0/8 [20/0] via 192.0.2.1",
    "x",
    "\xe9t\xe9",
    "\u2028",
]


def _lines(rnd: random.Random, most: int) -> list[str]:
    return [rnd.choice(_LINES) for _ in range(rnd.randint(0, most))]


def _text(lines: list[str], rnd: random.Random) -> str:
    """Lines joined as a device answer, with LF or CRLF endings and with or
    without a final line ending."""
    eol = rnd.choice(["\n", "\n", "\r\n"])
    text = eol.join(lines)
    if lines and rnd.random() < 0.6:
        text += eol
    return text


def _answers(rnd: random.Random) -> list[str]:
    """One fetch's answers: a shared banner in front of most of them, and the
    shapes that decide the result at its edges."""
    banner = _lines(rnd, 4)
    count = rnd.choice([0, 1, 2, 2, 3, 3, 4, 6])
    answers: list[str] = []
    for _ in range(count):
        shape = rnd.random()
        if shape < 0.08:
            answers.append("")  # an empty answer, or an optional command's stand-in
        elif shape < 0.16:
            answers.append(_text(banner, rnd))  # an answer that is nothing but the banner
        elif shape < 0.22:
            answers.append(rnd.choice(_LINES))  # one line with no newline at all
        elif shape < 0.3 and answers:
            answers.append(answers[-1])  # identical to the one before
        else:
            answers.append(_text(banner + _lines(rnd, 5), rnd))
    if count and rnd.random() < 0.1:
        answers = [answers[0]] * count  # every answer the same
    return answers


def test_split_lines_yields_exactly_what_split_returns():
    rnd = random.Random(7)
    samples = ["", "\n", "\n\n", "a", "a\n", "\na", "a\nb", "a\r\nb\r\n", "a\n\nb\n"]
    samples += [_text(_lines(rnd, 6), rnd) for _ in range(2_000)]
    for text in samples:
        assert list(_split_lines(text)) == text.split("\n"), repr(text)


def test_exec_banner_of_matches_the_whole_answer_split_on_random_fetches():
    rnd = random.Random(20260926)
    mismatches = []
    found = 0
    for _ in range(CASES):
        answers = _answers(rnd)
        expected = _reference_exec_banner_of(answers)
        got = exec_banner_of(iter(answers))
        if got != expected:
            mismatches.append((answers, expected, got))
        found += bool(expected)
    assert mismatches == []
    # the generator reaches both outcomes, not only the empty one
    assert CASES // 10 < found < CASES - CASES // 10


@pytest.mark.parametrize(
    "answers",
    [
        [],
        ["only one\n"],
        ["", ""],
        ["", "x"],
        ["x", ""],
        ["a", "a"],
        ["a\n", "a\n"],
        ["a\n", "a"],
        ["a", "a\n"],
        ["B\nB\n", "B\n"],
        ["B\n", "B\nB\n"],
        ["B\r\nx\r\n", "B\r\ny\r\n"],
        ["B\r\nx\r\n", "B\ny\n"],
        ["B\nx", "B\ny", "B\nz", ""],
        ["B\nC\nx", "B\nC\ny", "B\nz"],
        ["\n\nx", "\n\ny"],
    ],
)
def test_exec_banner_of_matches_the_whole_answer_split_at_the_edges(answers):
    assert exec_banner_of(answers) == _reference_exec_banner_of(answers)


def test_exec_banner_of_reads_no_further_than_the_first_differing_line(monkeypatch):
    produced: list[str] = []
    real = cli_collector._split_lines

    def counting(text: str):
        for line in real(text):
            produced.append(line)
            yield line

    monkeypatch.setattr(cli_collector, "_split_lines", counting)
    body = "\n".join(f"route {i}" for i in range(10_000))
    answers = [f"Banner\nfirst\n{body}", f"Banner\nsecond\n{body}", f"Banner\nthird\n{body}"]

    assert exec_banner_of(answers) == "Banner\n"
    assert len(produced) < 16


# --- _content_status -----------------------------------------------------------------

_TEXTS: list[Any] = [
    None,
    "",
    {},
    {"TABLE_mac": {"ROW_mac": [{"a": 1}, {"a": 2}]}},
    {"TABLE_mac": {"ROW_mac": {"a": 1}}},
    {"TABLE_mac": {}},
    {"other": 1},
    [],
    0,
    " ",
    "\t\n\r\x0b\x0c",
    "\x1c\x1d\x1e\x1f",
    "\x85",
    "\xa0",
    "\u2028",
    "\u2029",
    "\u3000",
    " \x85\xa0\u2028 ",
    "\u200b",  # a zero-width space is not whitespace to either check
    "text",
    " text ",
    "\x85text\xa0",
    "{}",
    " {} ",
    "\xa0{}",
    "[]",
    "not json",
    '{"TABLE_mac": {"ROW_mac": [{"a": 1}]}}',
    '{"TABLE_mac": {"ROW_mac": []}}',
    '{"TABLE_mac": {"ROW_mac": {"a": 1}}}',
    '{"TABLE_arp": {}}',
]


@pytest.mark.parametrize("table", [None, "mac"])
@pytest.mark.parametrize("rows", [None, 0, 3])
@pytest.mark.parametrize("text", _TEXTS, ids=repr)
def test_content_status_matches_the_strip_check(text, rows, table):
    assert _content_status(text, rows, table) == _reference_content_status(text, rows, table)


def test_isspace_and_strip_agree_on_every_code_point():
    """The in-place check rests on this: a str strips to nothing exactly when
    it is empty or every character in it is whitespace to `isspace`."""
    disagree = [cp for cp in range(0x110000) if (not chr(cp).strip()) != chr(cp).isspace()]
    assert disagree == []
