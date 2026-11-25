"""The raw store reads a payload back without holding its token, its gzip
stream or its JSON text whole (core/rawstore.py `read`).

A read authenticates the token in full first (app/crypto.py `TokenReader`),
then decrypts, decompresses and decodes it a piece at a time (`_JsonReader`).
The payload it returns must be the one `json.loads` builds from the whole
content, for every file the store has written: the golden `payload_sha` of
every case pins it, and the reader is compared with `json.loads` on texts cut
at every boundary its pieces can fall on. Its errors are those of the whole
read, for content with more than one fault as well, and its memory beyond the
payload is a fixed buffer plus the largest string's decoded pieces while that
string is joined.
"""

from __future__ import annotations

import gc
import gzip
import io
import itertools
import json
import random
import tracemalloc
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet, InvalidToken
from tests.support.synthetic_payloads import (
    CASES,
    base_spelling,
    case_payload,
    iosxe_payload,
    load_golden,
    payload_sha,
    split_case,
)
from tests.test_rawstore_stream import _mixed_payload

from hst.app import crypto
from hst.app.crypto import SecretKeyError, decrypt, encrypt
from hst.core import rawstore

GOLDEN = load_golden()
KEY = Fernet.generate_key().decode()
RUN_ID = "1700000000000-aaaaaaaa"


def _whole_read(path: Path) -> Any:
    return json.loads(gzip.decompress(decrypt(KEY, path.read_bytes())))


def _sealed(tmp_path: Path, content: bytes, name: str = "edge1") -> Path:
    """A raw file holding `content` as its gzip content, sealed whole."""
    path = tmp_path / "edge" / name / f"{RUN_ID}{rawstore.SUFFIX}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encrypt(KEY, content))
    return path


# --- the payload ------------------------------------------------------------------------


@pytest.mark.parametrize("case", CASES)
def test_every_golden_case_reads_back_as_its_golden_payload(case, tmp_path):
    # the golden digest is of the payload in the spelling of the base record
    payload = base_spelling(split_case(case)[0], case_payload(case))
    path = rawstore.write(tmp_path, "edge", RUN_ID, payload, host="edge1", key=KEY)
    del payload

    assert payload_sha(rawstore.read(path, KEY)) == GOLDEN["cases"][case]["payload_sha"]


def test_a_payload_of_every_kind_reads_back_as_the_whole_read_returns_it(tmp_path):
    payload = _mixed_payload()
    path = rawstore.write(tmp_path, "vyos1", RUN_ID, payload, host="r1", key=KEY)

    assert rawstore.read(path, KEY) == _whole_read(path) == json.loads(json.dumps(payload, default=str))


@pytest.mark.parametrize(
    "payload",
    [["show version", {"b": "�"}, 3, None], "a string", 12.5, None, {}, []],
    ids=["list", "string", "number", "null", "empty-object", "empty-list"],
)
def test_a_payload_that_is_not_an_object_reads_back(payload, tmp_path):
    path = rawstore.write(tmp_path, "src", RUN_ID, payload, key=KEY)
    assert rawstore.read(path, KEY) == _whole_read(path) == payload


def test_a_token_over_gzip_compress_output_reads_back(tmp_path):
    """One Fernet token over the output of `gzip.compress`."""
    payload = _mixed_payload()
    path = _sealed(tmp_path, gzip.compress(json.dumps(payload, default=str).encode()))
    assert rawstore.read(path, KEY) == _whole_read(path) == json.loads(json.dumps(payload, default=str))


def test_gzip_content_of_several_members_reads_back_as_one_text(tmp_path):
    text = json.dumps({"show version": "x" * 50_000, "show clock": "12:00", "n": [1, 2, 3]}).encode()
    cuts = (0, 7, 25_003, 49_999, len(text))
    members = b"".join(gzip.compress(text[a:b]) for a, b in itertools.pairwise(cuts))
    path = _sealed(tmp_path, members)
    assert rawstore.read(path, KEY) == _whole_read(path) == json.loads(text)


def test_a_trace_reads_back_as_the_whole_read_returns_it(tmp_path):
    raw = rawstore.write(tmp_path, "edge", RUN_ID, {"x": 1}, host="edge1", key=KEY)
    lines = b"".join(json.dumps({"n": i, "body": "y" * i}).encode() + b"\n" for i in range(2_000))
    trace = rawstore.write_trace(raw, gzip.compress(lines), key=KEY)

    assert rawstore.read_trace(trace, KEY) == gzip.decompress(decrypt(KEY, trace.read_bytes())) == lines


# --- the JSON reader against json.loads -------------------------------------------------

# Texts whose every character a piece boundary is made to fall on below: every
# escape, surrogate pairs whole and split, lone surrogates, runs of backslashes
# and hex digits (which hold a cut back), numbers a cut can shorten, literals,
# whitespace everywhere and a repeated key.
TEXTS = {
    "escapes": json.dumps({"a": 'q"\\/\b\f\n\r\t\x01 \u00e9 \u2603 \U0001f600 \u2028 end'}),
    "pairs": '{"s": "\\ud83d\\ude00x\\ud83d\\ude00\\ud800\\u0041\\udc00\\ud800", "t": "\\ud83d\\ude00"}',
    "backslash-runs": json.dumps({"k": "\\" * 37 + '"' + "\\" * 12 + "u", "l": "\\\\u0041"}),
    "hex-runs": json.dumps({"hex": "0123456789abcdefABCDEF" * 40 + "u" * 30, "tail": "Fu\\"}),
    "numbers": '{"a": 1.5e3, "b": -0.25, "c": 12345678901234567890123, "d": 1E+10, "e": -2e-7, "f": 0}',
    "literals": '{"a": true, "b": false, "c": null, "d": NaN, "e": Infinity, "f": -Infinity}',
    "nested": json.dumps({"a": {"b": [1, {"c": "d" * 300}, [], {}], "e": "f"}, "g": [[[]]]}),
    "indented": json.dumps({"a": [1, 2, {"b": "c\nd"}], "e": {}}, indent=3),
    "repeated-key": '{"a": 1, "b": 2, "a": {"x": "y"}}',
    "raw-unicode": json.dumps({"z\u00fcrich": "\u2603 \U0001f600 \u00e9" * 50}, ensure_ascii=False),
    "list": json.dumps(["x" * 500, 1.25, None, {"a": "\\u"}, "\\"]),
    "string": json.dumps("\\" * 20 + "u0041" + "\U0001f600" * 20),
    "number": " 12345.5e-3 ",
    "empty-string-key": '{"": "", " ": " "}',
}
# (bytes read from the stream at a time, the window a member is retried with)
PIECES = [(1, 1), (2, 3), (3, 1), (5, 8), (7, 2), (64, 16)]


def _loaded(data: bytes, monkeypatch, read: int, window: int) -> Any:
    monkeypatch.setattr(rawstore, "_JSON_READ", read)
    monkeypatch.setattr(rawstore, "_JSON_WINDOW", window)
    return rawstore._JsonReader(io.BytesIO(data)).document()


def _same(a: Any, b: Any) -> bool:
    """Equal, NaN included, with the same key order and the same types."""
    if type(a) is not type(b):
        return False
    if isinstance(a, float):
        return a == b or (a != a and b != b)
    if isinstance(a, dict):
        return list(a) == list(b) and all(_same(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b, strict=True))
    return a == b


@pytest.mark.parametrize("name", list(TEXTS))
@pytest.mark.parametrize("read,window", PIECES, ids=[f"read{r}-window{w}" for r, w in PIECES])
def test_the_reader_decodes_what_json_loads_decodes(name, read, window, monkeypatch):
    data = TEXTS[name].encode("utf-8")
    assert _same(_loaded(data, monkeypatch, read, window), json.loads(data))


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "utf-16-be", "utf-32-le"])
def test_the_text_is_decoded_in_the_encoding_json_loads_detects(encoding, monkeypatch):
    for text in (TEXTS["raw-unicode"], TEXTS["escapes"], "[]", '"x"', "7"):
        data = text.encode(encoding)
        for read, window in PIECES:
            assert _same(_loaded(data, monkeypatch, read, window), json.loads(data)), (text, read)


def test_the_reader_decodes_what_json_loads_decodes_for_generated_texts(monkeypatch):
    """Strings drawn from the characters that decide a cut, nested values and
    numbers, under a fixed seed."""
    rng = random.Random(20260927)
    alphabet = ["a", " ", "\n", '"', "\\", "/", "\t", "\x01", "\u00e9", "\U0001f600", "\ud800", "u", "0", "F"]

    def text() -> str:
        return "".join(rng.choice(alphabet) for _ in range(rng.choice((0, 1, 3, 40, 400))))

    def value(depth: int = 0) -> Any:
        roll = rng.random()
        if depth > 3 or roll < 0.35:
            return text()
        if roll < 0.5:
            return rng.choice((0, -7, 2**70, 1.5, -2.5e-10, 1e300, True, False, None))
        if roll < 0.75:
            return {text(): value(depth + 1) for _ in range(rng.randint(0, 4))}
        return [value(depth + 1) for _ in range(rng.randint(0, 4))]

    for _ in range(150):
        document = {text(): value() for _ in range(rng.randint(0, 6))}
        for options in ({}, {"indent": 1}, {"ensure_ascii": False}, {"separators": (",", ":")}):
            data = json.dumps(document, **options).encode("utf-8", "surrogatepass")
            expected = json.loads(data)
            for read, window in PIECES:
                assert _same(_loaded(data, monkeypatch, read, window), expected)


MALFORMED = {
    "empty": "",
    "blank": "  ",
    "open-object": "{",
    "open-key": '{"a"',
    "open-value": '{"a":',
    "open-after-value": '{"a": 1',
    "trailing-comma": '{"a": 1,}',
    "array-trailing-comma": "[1,]",
    "missing-comma": "[1 2]",
    "missing-colon": '{"a" 1}',
    "number-key": "{1: 2}",
    "open-string": '"abc',
    "open-long-string": '{"a": "' + "x" * 5000,
    "bad-escape": '{"a": "\\x"}',
    "short-unicode-escape": '{"a": "\\u12"}',
    "control-character": '{"a": "\x01"}',
    "extra-data": '{"a": 1} x',
    "two-values": "1 2",
    "partial-literal": '{"a": tru}',
    "lone-minus": "[-]",
    "number-then-dot": "[1.]",
    "close-first": "]",
}


@pytest.mark.parametrize("name", list(MALFORMED))
def test_a_malformed_text_raises_the_error_json_loads_raises(name, monkeypatch):
    data = MALFORMED[name].encode()
    with pytest.raises(ValueError) as expected:
        json.loads(data)
    for read, window in [(1, 1), (3, 5), (1 << 20, 16 << 20)]:
        with pytest.raises(ValueError) as raised:
            _loaded(data, monkeypatch, read, window)
        assert type(raised.value) is type(expected.value)


def test_bytes_that_are_not_the_detected_encoding_raise_as_json_loads_raises(monkeypatch):
    data = b'{"a": "\xff\xfe\xfa"}'
    with pytest.raises(UnicodeDecodeError):
        json.loads(data)
    with pytest.raises(UnicodeDecodeError):
        _loaded(data, monkeypatch, 3, 5)


# --- errors -----------------------------------------------------------------------------


def test_a_file_under_another_key_is_refused(tmp_path):
    path = rawstore.write(tmp_path, "edge", RUN_ID, {"x": 1}, host="edge1", key=KEY)
    with pytest.raises(SecretKeyError) as raised:
        rawstore.read(path, Fernet.generate_key().decode())
    assert type(raised.value.__cause__) is InvalidToken


@pytest.mark.parametrize(
    "content",
    [b"not gzip at all", gzip.compress(b'{"a": 1}')[:-6], gzip.compress(b'{"a": 1}') + b"junk"],
    ids=["not-gzip", "truncated", "trailing-junk"],
)
def test_content_that_is_not_gzip_raises_as_gzip_decompress_raises(content, tmp_path):
    path = _sealed(tmp_path, content)
    with pytest.raises(Exception) as expected:
        gzip.decompress(content)
    with pytest.raises(Exception) as raised:
        rawstore.read(path, KEY)
    assert type(raised.value) is type(expected.value)


def test_content_that_is_not_json_raises_the_json_error(tmp_path):
    path = _sealed(tmp_path, gzip.compress(b'{"show version": "x", }'))
    with pytest.raises(json.JSONDecodeError):
        rawstore.read(path, KEY)


def _crc_flipped(content: bytes) -> bytes:
    """A gzip member whose CRC no longer matches its content."""
    return content[:-8] + bytes([content[-8] ^ 1]) + content[-7:]


# A JSON syntax error at the start of the text, and a long string after it,
# so the reader meets the syntax error in its first piece; each other fault
# sits after the string.
_EARLY = b'{"a": 1 "b": "' + b"x" * 3_000_000
MULTI_FAULT = {
    "json-then-utf8": gzip.compress(_EARLY + b'\xff"}'),
    "json-then-crc": _crc_flipped(gzip.compress(_EARLY + b'"}')),
    "json-then-utf8-then-crc": _crc_flipped(gzip.compress(_EARLY + b'\xff"}')),
    "utf8-then-crc": _crc_flipped(gzip.compress(b'{"a": "\xff' + b"x" * 3_000_000 + b'"}')),
    "json-then-truncated": gzip.compress(_EARLY + b'"}')[:-100],
    "json-then-trailing-junk": gzip.compress(_EARLY + b'"}') + b"junk",
    "json-then-odd-utf16": gzip.compress('{"a": 1 "b": "x"}'.encode("utf-16-le") + b"{"),
}


@pytest.mark.parametrize("read,window", [(64, 128), (1 << 20, 16 << 20)], ids=["small", "default"])
@pytest.mark.parametrize("name", list(MULTI_FAULT))
def test_content_with_more_than_one_fault_raises_what_the_whole_read_raises(
    name, read, window, tmp_path, monkeypatch
):
    """The whole read decompresses all of the content before it decodes any
    of it, and decodes all of the text before it parses any of it."""
    content = MULTI_FAULT[name]
    path = _sealed(tmp_path, content)
    with pytest.raises(Exception) as expected:
        _whole_read(path)
    monkeypatch.setattr(rawstore, "_JSON_READ", read)
    monkeypatch.setattr(rawstore, "_JSON_WINDOW", window)
    with pytest.raises(Exception) as raised:
        rawstore.read(path, KEY)
    assert type(raised.value) is type(expected.value)
    assert not isinstance(expected.value, json.JSONDecodeError)


def test_a_raw_file_copied_as_text_reads_back(tmp_path):
    """A token wrapped at 76 columns with CRLF line ends reads as `decrypt`
    reads it (app/crypto.py `TokenReader`)."""
    payload = _mixed_payload()
    path = rawstore.write(tmp_path, "edge", RUN_ID, payload, host="edge1", key=KEY)
    token = path.read_bytes()
    copied = tmp_path / "copied"
    copied.write_bytes(b"".join(token[i : i + 76] + b"\r\n" for i in range(0, len(token), 76)))

    assert rawstore.read(copied, KEY) == _whole_read(copied) == rawstore.read(path, KEY)


def test_a_file_rewritten_between_the_two_passes_returns_no_payload(tmp_path, monkeypatch):
    """The file is changed in place after the token authenticated and before
    it is decrypted: the read fails as a token under another key fails, and
    returns nothing of what it decrypted."""
    payload = {"show ip bgp": "10.0.0.0/8 via 192.0.2.1\n" * 200_000, "show clock": "12:00"}
    path = rawstore.write(tmp_path, "edge", RUN_ID, payload, host="edge1", key=KEY)
    token = path.read_bytes()
    at = len(token) // 2
    changed = token[:at] + (b"B" if token[at : at + 1] == b"A" else b"A") + token[at + 1 :]

    class Rewritten(crypto.TokenReader):
        def __init__(self, key: str, fh: Any) -> None:
            super().__init__(key, fh)
            with path.open("r+b") as out:
                out.write(changed)

    monkeypatch.setattr(rawstore, "TokenReader", Rewritten)
    with pytest.raises(SecretKeyError) as raised:
        rawstore.read(path, KEY)
    assert type(raised.value.__cause__) is InvalidToken


# --- memory -----------------------------------------------------------------------------


def _read_traced(path: Path) -> tuple[Any, int]:
    """The payload at `path`, and the peak the read allocated beyond the
    payload it returned."""
    gc.collect()
    was_tracing = tracemalloc.is_tracing()
    if not was_tracing:
        tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        payload = rawstore.read(path, KEY)
        kept, peak = tracemalloc.get_traced_memory()
    finally:
        if not was_tracing:
            tracemalloc.stop()
    return payload, peak - kept


def test_a_read_holds_the_payload_and_a_fixed_buffer(tmp_path):
    """Eight command answers of 6 MB: beyond the payload, the read holds its
    buffers and, while the answer being decoded is joined, that answer's
    decoded pieces, and nothing that grows with the whole payload."""
    answer = "10.0.0.0/24 via 192.0.2.1, 00:01:02, GigabitEthernet0/0\n" * 105_000
    payload = {f"show command {i}": answer.replace("10.0", f"10.{i}") for i in range(8)}
    path = rawstore.write(tmp_path, "edge", RUN_ID, payload, host="edge1", key=KEY)

    read, excess = _read_traced(path)

    assert read == payload
    assert excess <= len(answer) + (8 << 20), (
        f"{excess / 1e6:.1f} MB beyond a {len(json.dumps(payload)) / 1e6:.0f} MB payload"
    )


def test_a_full_table_payload_reads_back_holding_little_beyond_it(tmp_path):
    payload = iosxe_payload(routes=130_000, peers=2, paths=130_000, advertised=1_000, denied_received=False)
    largest = max(len(value) for value in payload.values() if isinstance(value, str))
    path = rawstore.write(tmp_path, "edge", RUN_ID, payload, host="edge1", key=KEY)

    read, excess = _read_traced(path)

    assert read == payload
    assert excess <= largest + (8 << 20), (
        f"{excess / 1e6:.1f} MB beyond the payload, largest {largest / 1e6:.1f} MB"
    )
