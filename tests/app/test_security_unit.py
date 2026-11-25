"""Password hashing, tokens, and login throttling: pure unit tests."""

from collections.abc import Hashable
from concurrent.futures import ThreadPoolExecutor

from hst.app.security import (
    RateLimiter,
    hash_password,
    new_session_token,
    token_hash,
    verify_password,
)


def test_password_roundtrip_and_mismatch():
    h = hash_password("hunter22")
    assert h != "hunter22" and h.startswith("$argon2")
    assert verify_password(h, "hunter22")
    assert not verify_password(h, "hunter23")
    assert not verify_password("not-a-hash", "hunter22")


def test_session_tokens_are_unique_and_hash_deterministically():
    a, b = new_session_token(), new_session_token()
    assert a != b and len(a) >= 32
    assert token_hash(a) == token_hash(a) != token_hash(b)
    assert token_hash(a) != a  # never store the raw token


def _take(rl: RateLimiter, key: Hashable, now: float, limit: int | None = None) -> bool:
    """Reserve one unit of one key. True when the unit was taken."""
    return rl.reserve([(key, limit)], now=now).full is None


def test_tuple_keys_with_the_same_joined_text_are_separate_buckets():
    rl = RateLimiter(limit=1, window_s=60)
    per_user = ("user", "admin:203.0.113.7")
    per_user_and_address = ("user", "admin", "203.0.113.7")

    held = rl.reserve([(per_user, None)], now=100.0)

    assert rl.over_limit(per_user, now=100.0) and not rl.over_limit(per_user_and_address, now=100.0)
    assert _take(rl, per_user_and_address, now=100.0)
    assert rl.note_once(per_user, now=100.0) and rl.note_once(per_user_and_address, now=100.0)
    rl.release(held)
    assert set(rl._hits) == {per_user_and_address}


def test_rate_limiter_windows():
    rl = RateLimiter(limit=3, window_s=60)
    for _ in range(3):
        assert not rl.over_limit("k", now=100.0)
        assert _take(rl, "k", now=100.0)
    assert rl.over_limit("k", now=100.0)  # 4th in window blocked
    assert not _take(rl, "k", now=100.0)
    assert not rl.over_limit("other", now=100.0)  # keys are independent
    assert not rl.over_limit("k", now=161.0)  # window expired
    assert _take(rl, "k", now=161.0)


def test_over_limit_does_not_consume_budget():
    rl = RateLimiter(limit=3, window_s=60)
    for _ in range(10):
        assert not rl.over_limit("k", now=100.0)
    for _ in range(3):
        assert _take(rl, "k", now=100.0)
    assert rl.over_limit("k", now=100.0)
    assert not rl.over_limit("k", now=161.0)  # window expired


def test_rate_limiter_accepts_a_per_call_limit():
    """The looser per-username bucket shares one limiter with the strict buckets."""
    rl = RateLimiter(limit=2, window_s=60)
    for _ in range(3):
        assert _take(rl, "k", now=100.0, limit=20)
    assert rl.over_limit("k", now=100.0)
    assert not _take(rl, "k", now=100.0)
    assert not rl.over_limit("k", now=100.0, limit=20)


def test_reserve_takes_no_unit_when_one_bucket_is_full():
    rl = RateLimiter(limit=1, window_s=60)
    assert _take(rl, "b", now=100.0)

    refused = rl.reserve([("a", None), ("b", None), ("c", None)], now=100.0)

    assert refused.full == "b" and refused.held == ()
    assert set(rl._hits) == {"b"}


def test_reserve_reports_the_first_full_bucket():
    rl = RateLimiter(limit=1, window_s=60)
    assert rl.reserve([("a", None), ("b", None)], now=100.0).full is None
    assert rl.reserve([("a", None), ("b", None)], now=100.0).full == "a"
    assert rl.reserve([("b", None), ("a", None)], now=100.0).full == "b"


def test_release_gives_the_units_back():
    rl = RateLimiter(limit=2, window_s=60)
    first = rl.reserve([("a", None), ("b", None)], now=100.0)
    second = rl.reserve([("a", None), ("b", None)], now=100.0)
    assert rl.over_limit("a", now=100.0) and rl.over_limit("b", now=100.0)

    rl.release(first)
    assert rl._hits == {"a": (100.0, 1), "b": (100.0, 1)}
    rl.release(second)
    assert rl._hits == {}


def test_release_leaves_a_later_window_alone():
    rl = RateLimiter(limit=2, window_s=60)
    old = rl.reserve([("k", None)], now=100.0)
    assert _take(rl, "k", now=161.0)

    rl.release(old)

    assert rl._hits == {"k": (161.0, 1)}


def test_release_of_a_refused_reservation_changes_nothing():
    rl = RateLimiter(limit=1, window_s=60)
    assert _take(rl, "k", now=100.0)

    rl.release(rl.reserve([("k", None)], now=100.0))

    assert rl._hits == {"k": (100.0, 1)}


def test_reserve_from_parallel_threads_takes_at_most_the_limit():
    rl = RateLimiter(limit=5, window_s=60)
    with ThreadPoolExecutor(max_workers=16) as pool:
        taken = list(pool.map(lambda _: _take(rl, "k", now=100.0), range(400)))
    assert taken.count(True) == 5


def test_a_flood_of_fresh_keys_inside_one_window_takes_a_unit_for_each_key():
    rl = RateLimiter(limit=3, window_s=60)
    rl.MAX_KEYS = 8

    taken = [_take(rl, f"user-{i}", now=100.0 + i * 0.01) for i in range(50)]

    assert taken == [True] * 50
    assert set(rl._hits) == {f"user-{i}" for i in range(42, 50)}


def test_a_flood_of_fresh_keys_leaves_a_full_counter_inside_its_window():
    rl = RateLimiter(limit=3, window_s=60)
    rl.MAX_KEYS = 8
    for _ in range(3):
        assert _take(rl, "target", now=100.0)

    for i in range(50):
        _take(rl, f"flood-{i}", now=101.0 + i * 0.01)

    assert rl._hits["target"] == (100.0, 3)
    assert not _take(rl, "target", now=159.0)


def test_a_reservation_without_room_removes_the_counters_with_the_lowest_count():
    rl = RateLimiter(limit=3, window_s=60)
    rl.MAX_KEYS = 4
    assert _take(rl, "low-old", now=100.0)
    assert _take(rl, "low-new", now=101.0)
    assert _take(rl, "high", now=99.0) and _take(rl, "high", now=99.0)

    taken = rl.reserve([("a", None), ("b", None)], now=102.0)

    assert taken.full is None
    assert set(rl._hits) == {"low-new", "high", "a", "b"}


def test_a_reservation_keeps_the_counters_of_its_own_keys():
    rl = RateLimiter(limit=3, window_s=60)
    rl.MAX_KEYS = 2
    assert _take(rl, "a", now=100.0)
    assert _take(rl, "b", now=101.0) and _take(rl, "b", now=101.0)

    taken = rl.reserve([("a", None), ("c", None)], now=102.0)

    assert taken.full is None
    assert rl._hits == {"a": (100.0, 2), "c": (102.0, 1)}


def test_a_flood_of_fresh_keys_does_not_refuse_a_new_key():
    rl = RateLimiter(limit=3, window_s=60)
    for i in range(rl.MAX_KEYS * 2):
        assert _take(rl, ("ip", f"flood-{i}"), now=100.0 + i * 0.001)

    assert _take(rl, ("ip", "192.0.2.1"), now=110.0)
    assert len(rl._hits) <= rl.MAX_KEYS


def test_the_counter_of_a_removed_key_is_no_longer_noted():
    rl = RateLimiter(limit=1, window_s=60)
    rl.MAX_KEYS = 1
    assert _take(rl, "a", now=100.0)
    assert rl.note_once("a", now=100.0)

    assert _take(rl, "b", now=101.0)

    assert rl._noted == {}


def test_note_once_reports_a_key_once_per_window():
    rl = RateLimiter(limit=2, window_s=60)
    assert rl.note_once("k", now=100.0) is True
    for _ in range(20):
        assert rl.note_once("k", now=100.0) is False
    assert rl.note_once("other", now=100.0) is True  # keys are independent
    assert rl.note_once("k", now=161.0) is True  # a new window is a new report


def test_note_once_follows_the_window_the_counter_is_in():
    rl = RateLimiter(limit=2, window_s=60)
    _take(rl, "k", now=100.0)
    assert rl.note_once("k", now=110.0) is True
    assert rl.note_once("k", now=140.0) is False  # same window, already reported
    assert rl.note_once("k", now=200.0) is True  # counter expired, window is new


def test_note_once_does_not_consume_budget():
    rl = RateLimiter(limit=2, window_s=60)
    for _ in range(10):
        rl.note_once("k", now=100.0)
    assert not rl.over_limit("k", now=100.0)


def test_note_once_memory_is_bounded_by_the_counter_dict():
    rl = RateLimiter(limit=1, window_s=60)
    rl.MAX_KEYS = 8
    for i in range(50):
        _take(rl, f"user-{i}", now=100.0 + i * 0.01)
        rl.note_once(f"user-{i}", now=100.0 + i * 0.01)
    assert len(rl._noted) <= rl.MAX_KEYS + 1


def test_expired_counters_make_room_for_a_new_key():
    rl = RateLimiter(limit=3, window_s=60)
    rl.MAX_KEYS = 4
    for i in range(4):
        _take(rl, f"old-{i}", now=100.0)

    assert _take(rl, "fresh", now=200.0)
    assert set(rl._hits) == {"fresh"}
