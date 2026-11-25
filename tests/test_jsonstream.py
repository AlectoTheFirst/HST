"""The streaming JSON encoder must reproduce `json.dumps` byte for byte (core/jsonstream.py)."""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import random
import time
import tracemalloc
from collections import Counter, OrderedDict, defaultdict
from typing import Any

import pytest

from hst.core.jsonstream import iter_json, iter_json_bytes, sha256_json

SORTS = (True, False)
SEPARATORS = ((",", ":"), (", ", ": "))
DEPTHS = (0, 1, 2, 5)
SLICES = (1, 3, 17, 1 << 20)
STRUCTURES = 2_000

# Every class of code point `encode_basestring_ascii` treats differently:
# plain ASCII, the two-character escapes, other control characters, DEL,
# Latin-1 and BMP characters, the JS line separators, the BOM, lone high
# and low surrogates, and astral characters that escape as a surrogate pair.
CHARS = (
    "a", "Z", "0", " ", "~", "/", '"', "\\",
    "\n", "\r", "\t", "\b", "\f", "\x00", "\x01", "\x1f", "\x7f",
    "\x80", "\xe9", "\xff", "\u2500", "\u2028", "\u2029", "\ufeff", "\ufffd",
    "\ud800", "\udbff", "\udc00", "\udfff", "\U0001f600", "\U0010ffff",
)  # fmt: skip
# Lengths on both sides of the 3- and 17-character slice boundaries, and
# longer than 3 slices.
LENGTHS = (0, 1, 2, 3, 4, 6, 16, 17, 18, 34, 35, 52)


class Shown:
    """A value `json.dumps` can encode only through `default=str`."""

    def __init__(self, text: str) -> None:
        self.text = text

    def __str__(self) -> str:
        return self.text


class Plain(dict):
    pass


class Reversed(dict):
    """A subclass whose `items()` the C encoder follows."""

    def items(self):
        return list(reversed(list(super().items())))


class Keyed(dict):
    """A subclass that hides its keys from iteration; the C encoder reads
    the storage through `items()` regardless."""

    def __iter__(self):
        return iter(())

    def keys(self):
        return []


def _text(rnd: random.Random) -> str:
    return "".join(rnd.choices(CHARS, k=rnd.choice(LENGTHS)))


def _scalar(rnd: random.Random) -> Any:
    pick = rnd.randrange(12)
    if pick < 5:
        return _text(rnd)
    if pick == 5:
        return rnd.choice((None, True, False))
    if pick == 6:
        return rnd.choice((0, -1, 7, 2**63, -(2**70), rnd.randrange(-(10**6), 10**6)))
    if pick == 7:
        return rnd.choice((0.0, -0.0, 0.1, 1 / 3, -2.5e-300, 1e300, rnd.uniform(-1e6, 1e6)))
    if pick == 8:
        return rnd.choice((float("nan"), float("inf"), float("-inf")))
    if pick == 9:
        return Shown(_text(rnd))
    if pick == 10:
        return rnd.choice(({}, [], (), Plain(), OrderedDict()))
    return rnd.choice(("", "k", "show ip route"))


def _key(rnd: random.Random, mixed: bool) -> Any:
    if mixed and rnd.random() < 0.4:
        return rnd.choice((0, 1, -3, 2**65, 1.5, float("nan"), True, False, None))
    if rnd.random() < 0.5:
        return rnd.choice(("a", "b", "payload", "normalization_context", "show version", "", "\u2028"))
    return _text(rnd)


def _mapping(rnd: random.Random, depth: int, budget: list[int]) -> dict[Any, Any]:
    kind = rnd.choice((dict, dict, dict, dict, Plain, OrderedDict, defaultdict, Counter, Reversed, Keyed))
    target: dict[Any, Any] = defaultdict(list) if kind is defaultdict else kind()
    # A dict with non-str keys is encoded whole at any depth, and with
    # sort_keys a mix of str and int keys raises.
    mixed = rnd.random() < 0.06
    for _ in range(rnd.randrange(6)):
        target[_key(rnd, mixed)] = _value(rnd, depth + 1, budget)
    if isinstance(target, OrderedDict) and len(target) > 1:
        # OrderedDict iterates in its own order, which after this is not
        # the storage order of the underlying dict.
        target.move_to_end(next(iter(target)))
    return target


def _value(rnd: random.Random, depth: int, budget: list[int]) -> Any:
    budget[0] -= 1
    if budget[0] > 0 and depth < 8:
        pick = rnd.random()
        if pick < 0.4:
            return _mapping(rnd, depth, budget)
        if pick < 0.55:
            items = [_value(rnd, depth + 1, budget) for _ in range(rnd.randrange(4))]
            return tuple(items) if rnd.random() < 0.3 else items
    return _scalar(rnd)


def _structure(rnd: random.Random) -> Any:
    budget = [rnd.randrange(4, 40)]
    if rnd.random() < 0.85:
        return _mapping(rnd, 0, budget)
    return _value(rnd, 0, budget)


def _dumps(obj: Any, sort_keys: bool, separators: tuple[str, str]) -> str | tuple[type, str]:
    try:
        return json.dumps(obj, sort_keys=sort_keys, default=str, separators=separators)
    except Exception as exc:
        return type(exc), str(exc)


def _streamed(obj: Any, sort_keys: bool, separators: tuple[str, str], **kw: int) -> str | tuple[type, str]:
    try:
        return "".join(iter_json(obj, sort_keys=sort_keys, separators=separators, **kw))
    except Exception as exc:
        return type(exc), str(exc)


@pytest.mark.parametrize(
    ("sort_keys", "separators", "max_depth", "slice_chars"),
    list(itertools.product(SORTS, SEPARATORS, DEPTHS, SLICES)),
)
def test_random_structures_encode_exactly_as_json_dumps(sort_keys, separators, max_depth, slice_chars):
    rnd = random.Random(f"{sort_keys}/{separators}/{max_depth}/{slice_chars}")
    mismatches = []
    encoded = 0
    for _ in range(STRUCTURES):
        obj = _structure(rnd)
        expected = _dumps(obj, sort_keys, separators)
        got = _streamed(obj, sort_keys, separators, max_depth=max_depth, slice_chars=slice_chars)
        if got != expected:
            mismatches.append((obj, expected, got))
            continue
        if isinstance(expected, str):
            encoded += 1
            chunk_bytes = rnd.choice((1, 5, 64, 1 << 16))
            chunks = list(
                iter_json_bytes(
                    obj,
                    sort_keys=sort_keys,
                    separators=separators,
                    max_depth=max_depth,
                    slice_chars=slice_chars,
                    chunk_bytes=chunk_bytes,
                )
            )
            if b"".join(chunks) != expected.encode() or any(len(c) < chunk_bytes for c in chunks[:-1]):
                mismatches.append((obj, expected, chunks))
    assert not mismatches, f"{len(mismatches)} mismatches, first: {mismatches[0]!r}"[:4000]
    # The error path must not crowd out the encoding path it is mixed into.
    assert encoded > STRUCTURES * 3 // 4


def test_strings_sliced_at_the_default_width_split_between_code_points():
    # The 1 MiB slice boundary at every position inside a run of an astral
    # character, a lone surrogate pair, a lone low surrogate and escaped
    # characters, including between the two halves of the pair.
    edge = "\U0001f600\ud800\udc00\udfff\x00\u2028\xe9"
    for shift in range(len(edge) + 1):
        value = "a" * ((1 << 20) - shift) + edge + '"\\' * 1000
        for obj in (value, {"payload": {"show ip route": value}}):
            for sort_keys, separators in itertools.product(SORTS, SEPARATORS):
                expected = json.dumps(obj, sort_keys=sort_keys, default=str, separators=separators)
                got = "".join(iter_json(obj, sort_keys=sort_keys, separators=separators, max_depth=2))
                assert got == expected, shift


def test_max_depth_decides_which_dicts_are_walked():
    obj = {"p": {"s": "abcdefghij"}}
    walked = list(iter_json(obj, sort_keys=True, separators=(",", ":"), max_depth=2, slice_chars=4))
    assert walked == ["{", '"p":', "{", '"s":"', "abcd", "efgh", "ij", '"', "}", "}"]
    # At max_depth 1 the inner dict is one json.dumps, its text sliced.
    whole = list(iter_json(obj, sort_keys=True, separators=(",", ":"), max_depth=1, slice_chars=4))
    assert whole == ["{", '"p":', '{"s"', ':"ab', "cdef", "ghij", '"}', "}"]
    assert "".join(walked) == "".join(whole) == json.dumps(obj, separators=(",", ":"))


def test_long_values_never_come_out_as_one_piece():
    # A value is escaped a slice at a time, and a value encoded whole is
    # handed on a slice at a time: no piece grows with the payload.
    slice_chars = 64
    obj = {
        "normalization_context": {"site_code": "s1", "parser_version": "1"},
        "payload": {
            "show ip route": "B 10.0.0.0/8 [20/0] via 1.2.3.4\n" * 5000,
            "show escaped": "\x00\U0001f600" * 5000,
            "_strata_dynamic_bgp": [{"peer": f"10.0.0.{i}", "vrf": "x" * 50} for i in range(500)],
            "nested": {"deeper": "y" * 100_000},
        },
    }
    pieces = list(iter_json(obj, sort_keys=True, separators=(",", ":"), max_depth=2, slice_chars=slice_chars))
    assert "".join(pieces) == json.dumps(obj, sort_keys=True, default=str, separators=(",", ":"))
    # 12 is the widest escape of one code point (an astral surrogate pair),
    # and a piece may also carry one short key.
    assert max(map(len, pieces)) <= 12 * slice_chars + 32


def test_mixed_str_and_int_keys_raise_the_dumps_type_error_when_sorted():
    for obj in ({"a": 1, 2: "b"}, {"x": {"a": 1, 2: "b"}}, {"x": {"y": {1: 0, "z": 0}}}):
        for max_depth in DEPTHS:
            with pytest.raises(TypeError) as expected:
                json.dumps(obj, sort_keys=True, default=str, separators=(",", ":"))
            with pytest.raises(TypeError) as got:
                "".join(iter_json(obj, sort_keys=True, separators=(",", ":"), max_depth=max_depth))
            assert str(got.value) == str(expected.value)
            # Unsorted, the same dict encodes, int key converted.
            assert "".join(
                iter_json(obj, sort_keys=False, separators=(",", ":"), max_depth=max_depth)
            ) == json.dumps(obj, default=str, separators=(",", ":"))


def test_unencodable_keys_raise_the_dumps_type_error():
    obj = {"x": {("a", 1): "tuple keys are rejected"}}
    with pytest.raises(TypeError) as expected:
        json.dumps(obj, default=str)
    for max_depth in DEPTHS:
        with pytest.raises(TypeError) as got:
            "".join(iter_json(obj, sort_keys=False, separators=(", ", ": "), max_depth=max_depth))
        assert str(got.value) == str(expected.value)


def test_int_float_bool_and_none_keys_match_dumps_at_walked_and_unwalked_depths():
    obj = {"top": {1: "one", 2.5: "x", False: "f", None: "n", "s": {7: {"k": "v"}}}, "s": {-4: []}}
    for sort_keys, separators, max_depth in itertools.product((False,), SEPARATORS, DEPTHS):
        expected = json.dumps(obj, sort_keys=sort_keys, default=str, separators=separators)
        assert (
            "".join(iter_json(obj, sort_keys=sort_keys, separators=separators, max_depth=max_depth))
            == expected
        )
    homogeneous = {"top": {3: "c", 1: "a", 2: {10: "x", 9: "y"}}}
    for separators, max_depth in itertools.product(SEPARATORS, DEPTHS):
        expected = json.dumps(homogeneous, sort_keys=True, default=str, separators=separators)
        assert (
            "".join(iter_json(homogeneous, sort_keys=True, separators=separators, max_depth=max_depth))
            == expected
        )


def test_dict_subclasses_encode_as_the_c_encoder_reads_them():
    ordered = OrderedDict([("b", 1), ("a", "x"), ("c", "y")])
    ordered.move_to_end("b")
    counts = Counter("hello")
    dd: defaultdict[str, list[int]] = defaultdict(list)
    dd["z"].append(1)
    dd["a"].append(2)
    shapes = (
        Plain(b="1", a={"n": Plain(y="2", x="3")}),
        {"o": ordered},
        {"c": counts},
        {"d": dd},
        Reversed(b="1", a="2", c={"k": "v"}),
        {"r": Reversed(b="1", a="2")},
        Keyed(b="1", a="2"),
        {"k": Keyed(b="1", a=Keyed(y="x"))},
        Reversed(),
    )
    for obj, sort_keys, separators, max_depth in itertools.product(shapes, SORTS, SEPARATORS, DEPTHS):
        expected = json.dumps(obj, sort_keys=sort_keys, default=str, separators=separators)
        got = "".join(
            iter_json(obj, sort_keys=sort_keys, separators=separators, max_depth=max_depth, slice_chars=1)
        )
        assert got == expected, (obj, sort_keys, separators, max_depth)


def test_default_str_objects_and_special_floats_match_dumps():
    obj = {
        "shown": Shown('caf\xe9 \U0001f600 \ud800 "q"'),
        "floats": [float("nan"), float("inf"), float("-inf"), -0.0, 1e-320],
        "top": Shown("x"),
        "set": {3, 1},
        "big": 2**100,
        "flags": (True, False, None),
    }
    for sort_keys, separators, max_depth in itertools.product(SORTS, SEPARATORS, DEPTHS):
        expected = json.dumps(obj, sort_keys=sort_keys, default=str, separators=separators)
        got = "".join(
            iter_json(obj, sort_keys=sort_keys, separators=separators, max_depth=max_depth, slice_chars=2)
        )
        assert got == expected
    assert (
        "".join(iter_json(Shown("\u2028"), sort_keys=True, separators=(",", ":"), max_depth=1)) == '"\\u2028"'
    )


def test_a_dict_that_contains_itself_raises_the_dumps_value_error():
    loop: dict[str, Any] = {"a": "x"}
    loop["self"] = loop
    via: dict[str, Any] = {"inner": {"back": None}}
    via["inner"]["back"] = via
    for obj in (loop, via, {"payload": loop}):
        with pytest.raises(ValueError, match="Circular reference detected"):
            json.dumps(obj, sort_keys=True, default=str)
        # A depth far past the Python recursion limit still ends in the same
        # ValueError, found where the dict recurs.
        for max_depth in (*DEPTHS, 100_000):
            with pytest.raises(ValueError, match="Circular reference detected"):
                "".join(iter_json(obj, sort_keys=True, separators=(",", ":"), max_depth=max_depth))


def test_a_value_shared_between_siblings_is_not_a_cycle():
    shared = {"k": "v"}
    obj = {"a": shared, "b": shared, "c": [shared, shared]}
    for max_depth in DEPTHS:
        got = "".join(iter_json(obj, sort_keys=True, separators=(",", ":"), max_depth=max_depth))
        assert got == json.dumps(obj, sort_keys=True, separators=(",", ":"))


def test_bytes_chunks_are_at_least_chunk_bytes_except_the_last():
    obj = {f"cmd {i}": "line\n" * i for i in range(200)}
    for chunk_bytes in (1, 100, 4096, 1 << 16, 1 << 30):
        chunks = list(
            iter_json_bytes(obj, sort_keys=True, separators=(",", ":"), max_depth=1, chunk_bytes=chunk_bytes)
        )
        assert b"".join(chunks) == json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
        assert all(len(c) >= chunk_bytes for c in chunks[:-1])
        assert all(isinstance(c, bytes) for c in chunks)


def test_sizes_below_one_are_refused():
    with pytest.raises(ValueError, match="slice_chars"):
        iter_json({}, sort_keys=True, separators=(",", ":"), max_depth=1, slice_chars=0)
    with pytest.raises(ValueError, match="chunk_bytes"):
        iter_json_bytes({}, sort_keys=True, separators=(",", ":"), max_depth=1, chunk_bytes=0)


def _raw_sha_shaped(payload: Any) -> dict[str, Any]:
    context = {
        "site_code": "s1",
        "routing_scope": "s1",
        "l2fabric": None,
        "resolver_version": "1",
        "normalization_versions": {"mtu": "2"},
        "normalization_outcomes": {"show ip route vrf *": {"status": "ok"}},
    }
    return {"payload": payload, "normalization_context": context}


def test_sha256_json_is_the_digest_of_the_dumps_bytes():
    rnd = random.Random("sha256_json")
    shapes: list[Any] = [
        _raw_sha_shaped(
            {"show version": "Cisco IOS XE", "show ip arp": "a\r\nb", "_dyn": [{"peer": "1.1.1.1"}]}
        ),
        {"show ip route": "\U0001f600" * 3000, "show run": "hostname r1\n"},
        "a bare string",
        [1, 2, {"a": "b"}],
        {},
    ]
    shapes += [_structure(rnd) for _ in range(300)]
    checked = 0
    for obj, sort_keys, separators, max_depth in itertools.product(shapes, SORTS, SEPARATORS, (1, 2)):
        expected = _dumps(obj, sort_keys, separators)
        if not isinstance(expected, str):
            continue
        digest = sha256_json(obj, sort_keys=sort_keys, separators=separators, max_depth=max_depth)
        assert digest == hashlib.sha256(expected.encode()).hexdigest()
        checked += 1
    assert checked > len(shapes) * 4


def _cli_text(size: int) -> str:
    # Route-table text with the characters JSON escapes (newline, quote,
    # backslash), repeated out to `size` characters.
    block = "".join(
        f'B        10.{i % 250}.{i % 199}.0/24 [20/0] via 203.0.113.{i % 7 + 1}, 2w3d "rt\\{i}"\n'
        for i in range(2000)
    )
    return (block * (size // len(block) + 1))[:size]


@pytest.mark.parametrize("wrapped", [False, True], ids=["bare", "raw_sha_shaped"])
def test_a_50_mb_string_is_hashed_in_bounded_memory(wrapped):
    big = _cli_text(50_000_000)
    obj: Any = _raw_sha_shaped({"show ip route": big, "show version": "IOS XE"}) if wrapped else big
    tracemalloc.start()
    try:
        digest = sha256_json(obj, sort_keys=True, separators=(",", ":"), max_depth=2)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 12_000_000, f"peak {peak / 1e6:.1f} MB above the input"
    expected = hashlib.sha256(json.dumps(obj, sort_keys=True, default=str, separators=(",", ":")).encode())
    assert digest == expected.hexdigest()


@pytest.mark.perf
@pytest.mark.skipif(os.environ.get("HST_PERF") != "1", reason="HST_PERF not set")
@pytest.mark.parametrize("values", [50, 5_000, 50_000])
def test_streaming_is_within_1_3x_of_dumps_and_encode(values):
    # A flat 50 MB payload of CLI answers, split into `values` commands.
    text = _cli_text(50_000_000)
    per = len(text) // values
    obj = {f"show command {i:06d}": text[i * per : (i + 1) * per] for i in range(values)}
    separators = (",", ":")

    def whole() -> None:
        json.dumps(obj, sort_keys=True, default=str, separators=separators).encode()

    def streamed() -> None:
        for _ in iter_json_bytes(obj, sort_keys=True, separators=separators, max_depth=2):
            pass

    def best(fn) -> float:
        times = []
        for _ in range(5):
            start = time.perf_counter()
            fn()
            times.append(time.perf_counter() - start)
        return min(times)

    reference, measured = best(whole), best(streamed)
    assert measured <= 1.3 * reference, f"{measured:.3f}s streamed vs {reference:.3f}s dumps+encode"
