"""`ssh.StreamSanitizer`, `ssh._cli_rejection` and `ssh.shell_output_of`
against the whole-text code they must agree with."""

from __future__ import annotations

import json
import random
import re

import pytest

from hst.collectors import ssh
from hst.collectors.ssh import StreamSanitizer, sanitize_cli_text

# The alphabet of the design prototype's property check, and every shape the
# stages cut around: CRLF, colour codes behind a second ESC, OSC titles
# terminated by BEL or by `ESC \`, OSC introducers left open, bare and
# trailing ESCs, the pieces of an unfinished CSI, and characters that make a
# str UCS-2 or UCS-4.
ALPHABET = [
    "a",
    "b",
    " ",
    "  ",
    "\n",
    "\r\n",
    "\r",
    "\t",
    "\x1b[5C",
    "\x1b[2J",
    "\x1b]0;t\x07",
    "\x1b]x",
    "\x1b\\",
    "\x1bM",
    "\x07",
    "\x00",
    "\x7f",
    "% Invalid input",
    "x" * 50,
    "\u2500",
    "\x1b[",
    "\x1b",
    "\x1b]",
    "]",
    "[",
    "\\",
    "5",
    ";",
    "?",
    "C",
    "m",
    "/",
    "\x1b\x1b[31m",
    "\x1b[0m",
    "\x1b[1;32m",
    "\x1b[999999999C",
    "\x1b[?25l",
    "\x1b]0;r1: title\nspanning a line\x07",
    "\x1b]2;title\x1b\\",
    "\x85",
    "\u2028",
    "\xa0",
    "\u3000",
    "\x1c",
    "\x1f",
    "\x0b",
    "\x0c",
    "\U0001f600",
    "\ufffd",
    "r1#",
    '{"k": "v"}',
]


def stream(text: str, sizes: list[int]) -> str:
    """`text` fed in pieces of `sizes`, the remainder as one last piece."""
    sanitizer = StreamSanitizer()
    out, pos = [], 0
    for n in sizes:
        out.append(sanitizer.feed(text[pos : pos + n]))
        pos += n
    out.append(sanitizer.feed(text[pos:]))
    out.append(sanitizer.finish())
    return "".join(out)


def random_sizes(rng: random.Random, total: int, scales=(1, 3, 12, 64, 4096, 70_000)) -> list[int]:
    """Feed sizes from 1 to 70k covering `total`, at a scale drawn per case,
    so one case splits into single characters and another into large reads."""
    top = rng.choice(scales)
    sizes, covered = [], 0
    while covered < total:
        n = rng.randint(1, top)
        sizes.append(n)
        covered += n
    return sizes


def random_text(rng: random.Random, tokens: int) -> str:
    return "".join(rng.choice(ALPHABET) for _ in range(tokens))


def outcome(fn, *args):
    """What `fn` returns, or the class of the ValueError it raises.

    `_expand_csi` hands a cursor-forward CSI's digits to `int()`, which
    refuses more than 4300 of them, so `sanitize_cli_text` raises on such a
    sequence. The stream must raise as well, not return text.
    """
    try:
        return fn(*args)
    except ValueError as exc:
        return type(exc)


# --- the stream against the whole text --------------------------------------


@pytest.mark.parametrize("seed", range(4))
def test_any_split_of_a_short_answer_sanitizes_as_the_whole(seed):
    """50,000 cases per seed, 200,000 in all."""
    rng = random.Random(seed)
    mismatches = []
    for _ in range(50_000):
        text = random_text(rng, rng.randint(0, 60))
        sizes = random_sizes(rng, len(text))
        if stream(text, sizes) != sanitize_cli_text(text):
            mismatches.append((text, sizes))
    assert mismatches[:3] == []


def _long_block(rng: random.Random) -> str:
    """One run of a long answer, most of them longer than the line limit."""
    kind = rng.randrange(7)
    if kind == 0:
        # A whitespace-only run with no newline: nothing in it can be cut at.
        return rng.choice((" ", "\t", " \r", "\xa0", " \x1bA")) * rng.randint(36_000, 80_000)
    if kind == 1:
        return '{"prefix": "10.0.0.0/24", "nh": "192.0.2.1"}, ' * rng.randint(1_500, 3_000)
    if kind == 2:
        # A CSI that stays unfinished past the line limit.
        return "\x1b[" + rng.choice((";", "1", " ", "?")) * rng.randint(66_000, 80_000) + rng.choice("mCJ\n")
    if kind == 3:
        # An OSC whose body runs across 100 to 8,000 lines.
        return "\x1b]0;" + "title line\n" * rng.randint(100, 8_000) + rng.choice(("\x07", "\x1b\\", ""))
    if kind == 4:
        return "".join(f" 10.{i % 256}.0.0/16 via 192.0.2.1\r\n" for i in range(rng.randint(100, 3_000)))
    if kind == 5:
        return "\u2500" * rng.randint(70_000, 80_000)
    return random_text(rng, rng.randint(100, 3_000))


@pytest.mark.parametrize("seed", range(4))
def test_any_split_of_long_lines_sanitizes_as_the_whole(seed):
    """Answers past the line limit, where the last stage cuts inside a line
    or has to keep holding it, fed in pieces of 1 to 70k characters."""
    rng = random.Random(1000 + seed)
    mismatches = []
    for case in range(40):
        text = "".join(_long_block(rng) for _ in range(rng.randint(1, 4)))
        sizes = random_sizes(rng, len(text), scales=(64, 4096, 70_000))
        if outcome(stream, text, sizes) != outcome(sanitize_cli_text, text):
            mismatches.append(case)
    assert mismatches == []


def test_a_single_line_json_answer_streams_before_its_end():
    """NX-OS answers `| json` on one line. The last stage cuts it after its
    last character a right-strip cannot reach, so the text is handed on as it
    arrives and never held whole."""
    rows = [
        {"vrf-name-out": "default", "ipprefix": f"10.{i // 256 % 256}.{i % 256}.0/24"} for i in range(90_000)
    ]
    text = "\x1b[1m" + json.dumps({"TABLE_vrf": {"ROW_vrf": rows}}) + "\x1b[0m  \r\n"
    assert len(text) > 5_000_000
    rng = random.Random(5)
    sanitizer = StreamSanitizer()
    out: list[str] = []
    fed = emitted = 0
    for n in random_sizes(rng, len(text)):
        piece = text[fed : fed + n]
        fed += len(piece)
        out.append(sanitizer.feed(piece))
        emitted += len(out[-1])
        # Never more held back than the line limit and the piece just fed.
        assert fed - emitted <= (1 << 16) + len(piece) + 16
    out.append(sanitizer.finish())
    assert "".join(out) == sanitize_cli_text(text)


@pytest.mark.parametrize(
    "text",
    [
        "one\r\ntwo\r\nthree\r\n",
        "\x1b]0;a title\nthat spans\nlines\x07after\n",
        "\x1b\x1b[31mred\x1b[0m\n",
        "text then an OSC left open \x1b]0;never closed",
        "text then a trailing ESC\x1b",
        "a title \x1b]0;r1\x1b\\ ended by ESC backslash\n",
        "\x1b[5Ccolumns\x1b[12Cby cursor\x1b[3C\n",
        "prompt r1#\x1b[K",
        "\u2500\u2500 UCS-2 \x1b[1m\u2500\x1b[0m\r\n\U0001f600\n",
        "\x1b\x1b]t\x1b\x1b[1m\\A",
        "\x1b\x1b]t\x1b\x1b[1m\\x",
    ],
    ids=[
        "crlf",
        "osc-spanning-lines",
        "esc-esc-csi",
        "open-osc-at-end",
        "trailing-esc",
        "osc-ended-by-st",
        "cursor-forward",
        "erase-after-prompt",
        "ucs2-and-astral",
        "open-osc-esc-behind-a-csi-then-st",
        "open-osc-esc-behind-a-csi-then-st-then-text",
    ],
)
def test_every_split_point_of_each_shape_sanitizes_as_the_whole(text):
    expected = sanitize_cli_text(text)
    for cut in range(len(text) + 1):
        assert stream(text, [cut]) == expected, cut
    assert stream(text, [1] * len(text)) == expected


def _esc_after_open_osc_cases():
    """An open OSC, an ESC, a CSI sequence, then what follows the CSI.

    The CSI stage deletes the sequence, or holds it until it can tell, so the
    OSC stage can see the text end on that ESC. Whether the ESC ends the OSC
    depends on the character after the CSI: `ESC \\` closes the OSC and takes
    its body with it, and anything else leaves the ESC to the later steps.
    An ESC in front of the OSC can pair with the character that the closed
    OSC leaves behind, so the OSC stage has to hold the whole open OSC, not
    the trailing ESC alone.
    """
    leads = ("", "\x1b", "a\x1b", "\x1b\x1b")
    bodies = ("", "t", "0;r1: title", "a\nb")
    csis = ("\x1b[1m", "\x1b[m", "\x1b[5C", "\x1b[?25l", "\x1b[1;32m", "\x1b[1\x07")
    tails = ("\\A", "\\x", "\\\\", "\\_", "\\@", "\\Z", "\\[", "\\]x", "\\\x1b\\", "\\", "\x07A", "A")
    for lead in leads:
        for body in bodies:
            for csi in csis:
                for tail in tails:
                    yield lead + "\x1b]" + body + "\x1b" + csi + tail


def test_an_esc_behind_an_open_osc_waits_for_the_character_that_decides_it():
    rng = random.Random(7)
    mismatches = []
    for text in _esc_after_open_osc_cases():
        expected = sanitize_cli_text(text)
        splits = [[cut] for cut in range(len(text) + 1)]
        splits.append([1] * len(text))
        splits.extend(random_sizes(rng, len(text), scales=(1, 3, 12)) for _ in range(4))
        mismatches.extend((text, sizes) for sizes in splits if stream(text, sizes) != expected)
    assert mismatches[:3] == []


def test_a_whitespace_run_past_the_line_limit_fed_a_character_at_a_time():
    text = "head\n" + " \t" * 40_000 + "x  \n tail"
    assert stream(text, [1] * len(text)) == sanitize_cli_text(text)


def test_finish_starts_a_new_stream():
    sanitizer = StreamSanitizer()
    assert sanitizer.feed("a\x1b[3") + sanitizer.finish() == sanitize_cli_text("a\x1b[3")
    assert sanitizer.feed("b\r\n") + sanitizer.finish() == "b\n"


# --- _cli_rejection ---------------------------------------------------------


def reference_cli_rejection(stdout: str) -> str | None:
    """`_cli_rejection` as a walk over `splitlines`: the reference the single
    search has to match."""
    for line in stdout.splitlines():
        s = line.strip()
        if any(s.startswith(m) for m in ssh._CLI_ERROR_MARKERS):
            return s
    return None


_BREAKS = ["\n", "\n", "\n", "\r\n", "\r", "\x85", "\u2028", "\u2029", "\x0b", "\x0c", "\x1c", "\x1e"]
_LEADS = ["", "", " ", "  ", "\t", "\xa0", "\x1f", "\u3000", "\x85", "\u2028"]
_BODIES = [
    *ssh._CLI_ERROR_MARKERS,
    "% Invalid input detected at '^' marker.",
    "% Incomplete command.",
    'Line has invalid autocommand "show ip route"',
    "some output line",
    "10.0.0.0/24 via 192.0.2.1",
    "output then % Invalid input mid-line",
    "x% Invalid input",
    "%  Invalid input",
    "% invalid input",
    "",
    "JSONScripterror: size limit",
]


def _rejection_text(rng: random.Random) -> str:
    parts = []
    for _ in range(rng.randint(0, 8)):
        parts.append(rng.choice(_LEADS) + rng.choice(_BODIES) + rng.choice(_LEADS))
        parts.append(rng.choice(_BREAKS))
    if parts and rng.random() < 0.5:
        parts.pop()
    return "".join(parts)


def test_the_whitespace_class_is_str_isspace():
    """The single search stands on this: `\\s` in a str pattern matches what
    `str.strip` removes, over every code point."""
    space = re.compile(r"\s")
    assert [c for c in range(0x110000) if bool(space.match(chr(c))) != chr(c).isspace()] == []


@pytest.mark.parametrize("seed", range(2))
def test_cli_rejection_finds_what_the_line_walk_found(seed):
    rng = random.Random(2000 + seed)
    mismatches = []
    for _ in range(25_000):
        text = _rejection_text(rng)
        if ssh._cli_rejection(text) != reference_cli_rejection(text):
            mismatches.append(text)
    assert mismatches[:3] == []


def test_cli_rejection_takes_the_first_of_several_banners():
    text = "header\n  % Incomplete command.\n% Invalid input detected\n"
    assert ssh._cli_rejection(text) == "% Incomplete command."
    assert ssh._cli_rejection("% Ambiguous command: 'sh'\nmore") == "% Ambiguous command: 'sh'"


def test_cli_rejection_reads_lines_split_by_any_line_break():
    """`splitlines` splits on NEL and U+2028 too, so a banner after one is at
    the start of its line."""
    assert ssh._cli_rejection("out\x85% Invalid input here") == "% Invalid input here"
    assert ssh._cli_rejection("out\u2028\t% Bad IP address") == "% Bad IP address"
    assert ssh._cli_rejection("out % Invalid input here") is None


# --- shell_output_of ---------------------------------------------------------


def reference_shell_output_of(text: str, command: str, prompt: str) -> str:
    """`shell_output_of` on shortened copies of the text: the reference the
    offset version has to match."""
    wanted = command.strip()
    pos = 0
    for _ in range(ssh._ECHO_SEARCH_LINES):
        end = text.find("\n", pos)
        line = text[pos:] if end < 0 else text[pos:end]
        if line.strip() == wanted:
            text = "" if end < 0 else text[end + 1 :]
            break
        if end < 0:
            break
        pos = end + 1
    while True:
        text = text.rstrip()
        if not text:
            return ""
        start = text.rfind("\n") + 1
        if text[start:].strip() != prompt:
            return text + "\n"
        text = text[:start]


_COMMANDS = ["show ip route", " show ip route ", "", "show run | include hostname"]
_PROMPTS = ["r1#", "r1>", " r1#", "", "r1# "]
_SPACES = ["", "", " ", "\t", "\xa0", "\x85", "\u2028", "\x1c"]


def _shell_text(rng: random.Random, command: str, prompt: str) -> str:
    choices = [
        lambda: command,
        lambda: prompt,
        lambda: prompt.strip(),
        lambda: command.strip(),
        lambda: "",
        lambda: " 10.0.0.0/24 via 192.0.2.1",
        lambda: "hostname r1",
        lambda: "a banner line",
        lambda: "x" * rng.randint(1, 600),
        lambda: " " * rng.randint(1, 600),
    ]
    lines = [
        rng.choice(_SPACES) + rng.choice(choices)() + rng.choice(_SPACES) for _ in range(rng.randint(0, 30))
    ]
    text = "\n".join(lines)
    return text + rng.choice(("", "\n", "\n\n", "  \n ", "\t"))


@pytest.mark.parametrize("seed", range(2))
def test_shell_output_of_cuts_where_the_copying_version_cut(seed):
    rng = random.Random(3000 + seed)
    mismatches = []
    for _ in range(25_000):
        command, prompt = rng.choice(_COMMANDS), rng.choice(_PROMPTS)
        text = _shell_text(rng, command, prompt)
        if ssh.shell_output_of(text, command, prompt) != reference_shell_output_of(text, command, prompt):
            mismatches.append((text, command, prompt))
    assert mismatches[:3] == []


def test_shell_output_of_returns_one_slice_of_the_text():
    body = "".join(f" 10.{i % 256}.0.0/16 via 192.0.2.1\n" for i in range(50_000))
    text = f"show ip route\n{body}r1#"
    out = ssh.shell_output_of(text, "show ip route", "r1#")
    assert out == reference_shell_output_of(text, "show ip route", "r1#") == body
