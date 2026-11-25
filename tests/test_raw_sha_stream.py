"""`raw_sha` and `obs_sha` hash the JSON as it is encoded, and return the digests
of the whole-document `json.dumps` text (collectors/base.py, core/jsonstream.py)."""

from __future__ import annotations

import gc
import hashlib
import json
import random
import tracemalloc
from collections import OrderedDict
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest
from tests.support.synthetic_payloads import (
    CASES,
    base_spelling,
    case_payload,
    iosxe_payload,
    make_collector,
    make_settings,
    split_case,
)
from tests.test_cisco_rib_volatility import base_digests, hash_as_base_record

from hst.collectors import base
from hst.collectors.base import RAW_OUTCOMES_KEY, Collector, obs_sha, raw_sha


def _whole(obj: Any, *, sort_keys: bool, separators: tuple[str, str], max_depth: int) -> str:
    """The whole-document digest: SHA-256 of the whole `json.dumps` text.
    `max_depth` is the streamed call's own argument and changes nothing here."""
    dumped = json.dumps(obj, sort_keys=sort_keys, default=str, separators=separators)
    return hashlib.sha256(dumped.encode()).hexdigest()


def _reference(fn, collector: Any, raw: Any, monkeypatch: pytest.MonkeyPatch) -> str:
    """`fn(collector, raw)` with the hash computed from the whole text, over
    the same object `fn` builds."""
    with monkeypatch.context() as patched:
        patched.setattr(base.jsonstream, "sha256_json", _whole)
        return str(fn(collector, raw))


# --- the golden digests -----------------------------------------------------------------


@pytest.mark.parametrize("key", CASES)
def test_every_golden_case_hashes_to_its_golden_digests(key, tmp_path, monkeypatch):
    """The digests of the base record (`stream_golden.json`), under its
    declarations, the parser version included (`hash_as_base_record`), of the
    payload in its spelling (`base_spelling`).
    tests/test_cisco_rib_volatility.py pins the digests under the current ones."""
    family, _scale, _variant = split_case(key)
    collector = make_collector(family, make_settings(tmp_path))
    payload = base_spelling(family, case_payload(key))
    hash_as_base_record(monkeypatch, family)
    golden_raw, golden_obs = base_digests(key)

    assert raw_sha(collector, payload) == golden_raw
    assert obs_sha(collector, payload) == golden_obs


# --- parity with the whole-document hash ------------------------------------------------


class _Collector(Collector):
    name = "hashparity"
    VOLATILE_RAW_KEYS = ("show clock", "uptime")
    OBSERVATION_RAW_KEYS = ("show ip arp", "show ip route vrf *", "_dynamic")
    NORMALIZATION_OUTCOME_KEYS = ("show ip route vrf *",)

    def fetch(self):
        return {}

    def normalize(self, raw):
        raise NotImplementedError

    def probe(self):
        return ""


class _Shown:
    """A value `json.dumps` encodes only through `default=str`."""

    def __init__(self, text: str) -> None:
        self.text = text

    def __str__(self) -> str:
        return self.text


_CHARS = (
    "a", " ", "\n", "\r", "\t", '"', "\\", "/", "\x00", "\x7f", "\xe9", "\u2028", "\ufffd", "\U0001f600",
)  # fmt: skip


def _text(rnd: random.Random, longest: int) -> str:
    return "".join(rnd.choice(_CHARS) for _ in range(rnd.randrange(longest + 1)))


def _value(rnd: random.Random, depth: int) -> Any:
    roll = rnd.randrange(12 if depth < 3 else 7)
    if roll < 3:
        return _text(rnd, 40)
    if roll == 3:
        return rnd.choice([0, -7, 2**70, 1.5, float("inf"), True, None])
    if roll == 4:
        return rnd.choice([datetime(2026, 9, 1, tzinfo=UTC), Decimal("1.10"), _Shown("shown \u2603")])
    if roll == 5:
        return (1, "two")
    if roll == 6:
        # Keys `json.dumps` converts, sortable among themselves.
        return {2: "int key", 0.5: "float key", False: "bool key"}
    if roll < 9:
        return [_value(rnd, depth + 1) for _ in range(rnd.randrange(4))]
    items = [(_text(rnd, 6), _value(rnd, depth + 1)) for _ in range(rnd.randrange(5))]
    return OrderedDict(items) if roll == 9 else dict(items)


def _payload(rnd: random.Random) -> dict[str, Any]:
    raw: dict[str, Any] = {f"show cmd {_text(rnd, 3)}": _text(rnd, 400) for _ in range(rnd.randrange(6))}
    for key in ("show clock", "uptime", "show ip arp", "show ip route vrf *", "_dynamic", "show run"):
        if rnd.randrange(2):
            raw[key] = _value(rnd, 0)
    if rnd.randrange(2):
        raw[RAW_OUTCOMES_KEY] = {"show ip route vrf *": {"status": rnd.choice(["ok", "failed"])}}
    return raw


def test_the_streamed_hashes_equal_the_whole_document_hashes(monkeypatch):
    """Random payloads with every kind of value a fetch can hand over: escaped
    and astral characters, values only `default=str` can encode, non-str keys,
    nested and ordered dicts, and the volatile, observation and outcome keys
    that decide what each hash covers."""
    rnd = random.Random("raw_sha_stream")
    collector = _Collector(_Collector.ConfigModel(source_name="edge", site_code="hq"), None)
    compared = 0
    for _ in range(400):
        raw = _payload(rnd)
        assert raw_sha(collector, raw) == _reference(raw_sha, collector, raw, monkeypatch)
        assert obs_sha(collector, raw) == _reference(obs_sha, collector, raw, monkeypatch)
        compared += 1
    for raw in ([1, "two", {"three": 3}], "a bare string", None, {}):
        assert raw_sha(collector, raw) == _reference(raw_sha, collector, raw, monkeypatch)
        assert obs_sha(collector, raw) == _reference(obs_sha, collector, raw, monkeypatch)
    assert obs_sha(collector, "a bare string") == ""
    assert compared == 400


def test_a_payload_json_rejects_fails_the_hash_with_the_json_error(monkeypatch):
    """Keys `json.dumps` cannot sort raise its TypeError."""
    collector = _Collector(_Collector.ConfigModel(), None)
    raw = {"show ip arp": {1: "int key", None: "null key"}, "show run": "x"}

    with pytest.raises(TypeError) as streamed:
        raw_sha(collector, raw)
    with pytest.raises(TypeError) as whole:
        _reference(raw_sha, collector, raw, monkeypatch)
    assert str(streamed.value) == str(whole.value)
    with pytest.raises(TypeError):
        obs_sha(collector, raw)


def test_the_reference_reproduces_the_golden_digests(monkeypatch, tmp_path):
    """The patched reference reproduces a golden digest, so the parity sweep
    above compares against the whole-document formula and not against a
    second copy of the streamed hash."""
    key = "iosxe/fixture/unicode"
    collector = make_collector("iosxe", make_settings(tmp_path))
    payload = base_spelling("iosxe", case_payload(key))
    hash_as_base_record(monkeypatch, "iosxe")
    golden_raw, golden_obs = base_digests(key)

    assert _reference(raw_sha, collector, payload, monkeypatch) == golden_raw
    assert _reference(obs_sha, collector, payload, monkeypatch) == golden_obs


# --- memory -----------------------------------------------------------------------------


def _traced_peak(fn) -> tuple[Any, int]:
    """`fn()` and the tracemalloc peak of what it allocated beyond what was
    already live."""
    gc.collect()
    was_tracing = tracemalloc.is_tracing()
    if not was_tracing:
        tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        before = tracemalloc.get_traced_memory()[0]
        result = fn()
        peak = tracemalloc.get_traced_memory()[1] - before
    finally:
        if not was_tracing:
            tracemalloc.stop()
    return result, peak


def test_hashing_a_50_mb_payload_holds_a_few_megabytes(monkeypatch, tmp_path):
    """The whole-document hash holds the JSON text and its bytes, about twice
    the payload; the streamed one stays under 16 MB beyond the payload."""
    payload = iosxe_payload(routes=130_000, peers=2, paths=130_000, advertised=1_000, denied_received=False)
    size = len(json.dumps(payload))
    assert size > 50_000_000
    collector = make_collector("iosxe", make_settings(tmp_path))

    digest, peak = _traced_peak(lambda: raw_sha(collector, payload))
    assert peak <= 16_000_000, f"raw_sha peak {peak / 1e6:.1f} MB over a {size / 1e6:.0f} MB payload"
    observed, obs_peak = _traced_peak(lambda: obs_sha(collector, payload))
    assert obs_peak <= 16_000_000, f"obs_sha peak {obs_peak / 1e6:.1f} MB"

    assert digest == _reference(raw_sha, collector, payload, monkeypatch)
    assert observed == _reference(obs_sha, collector, payload, monkeypatch)
