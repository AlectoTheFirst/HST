"""Fetch-level change detection: the payload hash must see content, not noise."""

from __future__ import annotations

from datetime import UTC, datetime

from hst.collectors.base import Collector, raw_sha


class _C(Collector):
    name = "hashdummy"
    VOLATILE_RAW_KEYS = ("uptime",)

    def fetch(self):
        return {}

    def normalize(self, raw):
        raise NotImplementedError

    def probe(self):
        return ""


def _c() -> _C:
    return _C(_C.ConfigModel(), None)


def test_key_order_never_reads_as_change():
    c = _c()
    assert raw_sha(c, {"a": 1, "b": [1, 2]}) == raw_sha(c, {"b": [1, 2], "a": 1})


def test_volatile_keys_are_excluded_and_real_change_is_seen():
    c = _c()
    base = raw_sha(c, {"config": "x", "uptime": "1 day"})
    assert raw_sha(c, {"config": "x", "uptime": "2 days"}) == base
    assert raw_sha(c, {"config": "y", "uptime": "1 day"}) != base


def test_a_collector_declaring_nothing_hashes_everything():
    class _All(_C):
        VOLATILE_RAW_KEYS = ()

    c = _All(_All.ConfigModel(), None)
    assert raw_sha(c, {"uptime": "1 day"}) != raw_sha(c, {"uptime": "2 days"})


def test_non_json_values_and_non_dict_payloads_hash_rather_than_raise():
    c = _c()
    when = datetime(2026, 8, 27, tzinfo=UTC)
    assert raw_sha(c, {"seen": when}) == raw_sha(c, {"seen": when})
    assert raw_sha(c, ["a", "b"]) == raw_sha(c, ["a", "b"])
    assert raw_sha(c, ["a", "b"]) != raw_sha(c, ["a", "c"])
