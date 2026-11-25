"""Password hashing, session tokens, and login throttling."""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from collections.abc import Hashable, Iterable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_hasher = PasswordHasher()  # argon2id defaults

# The request models refuse a longer username or password before the store,
# the limiter and the hasher read it.
MAX_USERNAME_LENGTH = 64
MAX_PASSWORD_LENGTH = 1024


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def idle_after(settings: Any) -> timedelta:
    """The idle-expiry window of a session.

    The request path (app/auth.py) refuses a session past this window.
    """
    return timedelta(hours=settings.session_idle_timeout_hours)


def token_hash(token: str) -> str:
    """SHA-256 hex digest of a session token."""
    return hashlib.sha256(token.encode()).hexdigest()


def bearer_token(authorization: str | None) -> str | None:
    """The token of an `Authorization: Bearer <token>` header value.

    The scheme is matched without regard to case. The result is None when
    the header is absent, has another scheme, has no token or has a space in
    the token.
    """
    if not authorization:
        return None
    scheme, _, token = authorization.strip().partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token or " " in token:
        return None
    return token


@dataclass(frozen=True, slots=True)
class Reservation:
    """The result of `RateLimiter.reserve`."""

    # The key of the first full bucket. None when a unit was taken in each bucket.
    full: Hashable | None
    # The key and the window start of each unit taken.
    held: tuple[tuple[Hashable, float], ...] = ()


class RateLimiter:
    """Fixed-window counter per key that limits login attempts.

    A key is any hashable value. app/auth.py passes tuples.
    """

    MAX_KEYS = 4096

    def __init__(self, limit: int, window_s: int) -> None:
        self.limit, self.window_s = limit, window_s
        self._hits: dict[Hashable, tuple[float, int]] = {}
        # The window start for which `note_once` last returned True for each key.
        self._noted: dict[Hashable, float] = {}
        # The lock guards `_hits` and `_noted` against callers on uvicorn's threadpool.
        self._lock = threading.Lock()

    def _current(self, key: Hashable, now: float) -> tuple[float, int]:
        start, count = self._hits.get(key, (now, 0))
        return (now, 0) if now - start >= self.window_s else (start, count)

    def _make_room(self, keys: set[Hashable], now: float) -> None:
        """Remove counters until `_hits` has room for each of `keys`.

        The counters whose window ended go first. Then the counters with the
        lowest count go, the oldest window first. The counter of a key in `keys` stays.
        """

        def excess() -> int:
            return len(self._hits) + len(keys - self._hits.keys()) - self.MAX_KEYS

        if excess() <= 0:
            return
        self._hits = {k: v for k, v in self._hits.items() if now - v[0] < self.window_s}
        if excess() > 0:
            # One sort removes at least MAX_KEYS // 16 counters.
            spare = max(excess(), self.MAX_KEYS // 16)
            others = sorted(
                (k for k in self._hits if k not in keys),
                key=lambda k: (self._hits[k][1], self._hits[k][0]),
            )
            for key in others[:spare]:
                del self._hits[key]
        self._noted = {k: v for k, v in self._noted.items() if k in self._hits}

    def over_limit(self, key: Hashable, now: float | None = None, limit: int | None = None) -> bool:
        """True when the key has used its budget in the current window."""
        now = time.monotonic() if now is None else now
        with self._lock:
            _, count = self._current(key, now)
        return count >= (self.limit if limit is None else limit)

    def note_once(self, key: Hashable, now: float | None = None) -> bool:
        """True the first time a key is noted inside its current window."""
        now = time.monotonic() if now is None else now
        with self._lock:
            start, _ = self._current(key, now)
            if self._noted.get(key) == start:
                return False
            self._noted[key] = start
            if len(self._noted) > self.MAX_KEYS:
                # A noted key always has a live counter in `_hits`.
                self._noted = {k: v for k, v in self._noted.items() if k in self._hits}
            return True

    def reserve(
        self, buckets: Iterable[tuple[Hashable, int | None]], now: float | None = None
    ) -> Reservation:
        """Take one unit in each bucket, or no unit when a bucket is full.

        A bucket is a key and its limit. A limit of None is `self.limit`. The
        check and the take happen under one hold of the lock.
        """
        now = time.monotonic() if now is None else now
        buckets = tuple(buckets)
        with self._lock:
            for key, limit in buckets:
                if self._current(key, now)[1] >= (self.limit if limit is None else limit):
                    return Reservation(full=key)
            self._make_room({key for key, _ in buckets}, now)
            held = []
            for key, _ in buckets:
                start, count = self._current(key, now)
                self._hits[key] = (start, count + 1)
                held.append((key, start))
            return Reservation(full=None, held=tuple(held))

    def release(self, reservation: Reservation) -> None:
        """Give back each unit whose counter still has the window start of the reservation."""
        with self._lock:
            for key, start in reservation.held:
                entry = self._hits.get(key)
                if entry is None or entry[0] != start:
                    continue
                if entry[1] > 1:
                    self._hits[key] = (start, entry[1] - 1)
                else:
                    del self._hits[key]
                    self._noted.pop(key, None)
