"""The Zscaler OneAPI session holds a client-credentials OAuth2 token, the request
pacing and the Retry-After handling. The ZIA and ZPA collectors build one session for each
fetch and one for each probe. Each session has its own token, its own pace and
its own count of 429 answers. Two sources of one tenant share none of them.

First contact with a tenant:
    curl -s -X POST https://<vanity>.zslogin.net/oauth2/v1/token \\
        -d grant_type=client_credentials -d client_id=<id> -d client_secret=<secret>
    curl -s -H "Authorization: Bearer <token>" https://api.zsapi.net/zia/api/v1/status
    # save under data/raw/zscaler/first-contact/ and rerun the normalizers.

What a live tenant answers:
- The token URL is `https://<vanity>.zslogin.net/oauth2/v1/token` (`TOKEN_URL`).
  The vanity name is the name of the ZIdentity tenant. It can differ from the
  company name. The answer has `access_token`, `token_type` and `expires_in` in
  seconds. DEFAULT_TOKEN_LIFETIME_S replaces a missing or unparseable `expires_in`.
- Both products answer under `API_BASE`, ZPA at `/zpa/mgmtconfig/v1/...` and
  `/zpa/userconfig/v1/...`, ZIA at `/zia/api/v1/...`.
- ZPA collections have `totalPages`. ZIA collections are bare arrays without
  it. `get_paged` reads a bare array with `item_key=None`.
- ZPA reads the page size from `pagesize` (lower case). It ignores `pageSize` and
  sends 20 items. ZIA reads `pageSize`.
- The ZPA backend answers 429 before the OneAPI budget in `x-ratelimit-limit`
  (5000 per 60 s) is used up (DEFAULT_RATE).
- On a 429 the session reads Retry-After as a number of seconds, then
  x-ratelimit-reset, then waits RETRY_AFTER_FALLBACK, doubled on
  each later attempt (_rate_limit_wait).
"""

from __future__ import annotations

import logging
import math
import re
import time
from collections.abc import Callable
from typing import Any

import httpx

from . import http as http_client
from .auth import TlsConfig
from .util import renew_deadline

logger = logging.getLogger(__name__)

TOKEN_URL = "https://{vanity}.zslogin.net/oauth2/v1/token"  # noqa: S105 - the value is a URL
API_BASE = "https://api.zsapi.net"

MAX_RETRY_AFTER = 60.0

# The vanity domain is the first label of the token host. VANITY_LABEL matches
# one DNS label. A dot, `@`, `#`, `:` or `/` would move the token request, with
# the client secret, to another host.
VANITY_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def check_vanity(value: str) -> str:
    """Return `value` when it is one DNS label, else raise ValueError."""
    if VANITY_LABEL.fullmatch(value):
        return value
    raise ValueError(f"{value!r} is not one DNS label; the token host is https://<vanity_domain>.zslogin.net")


def check_tenant(value: str) -> str:
    """Return `value` when its slug is not empty, else raise ValueError."""
    from hst.core import uid

    if uid.slug(value):
        return value
    raise ValueError(f"{value!r} gives an empty tenant key")


# The first wait after a 429 that has no usable Retry-After or
# x-ratelimit-reset. The wait doubles on each later attempt of the same call.
RETRY_AFTER_FALLBACK = 5.0
# The wait before the one retry of a token request that answered 5xx or 429, or
# did not connect.
TOKEN_RETRY_WAIT_S = 5.0

# `get_paged` raises RuntimeError when a walk reaches this many pages.
MAX_PAGES = 10_000

# Calls per second.
DEFAULT_RATE = 2.0
MIN_RATE = 0.25
# How often one call waits and tries again after a 429 before the run fails.
MAX_RATE_LIMIT_RETRIES = 4
PACE_RECOVERY_CALLS = 60

# The token lifetime when the token response has no usable expires_in.
DEFAULT_TOKEN_LIFETIME_S = 3600
# The session renews the token after this fraction of its lifetime.
TOKEN_REFRESH_FRACTION = 0.66


class ZscalerTokenError(RuntimeError):
    """The token host refused the client, did not answer, or sent no token."""


class ZscalerSession:
    """One OneAPI bearer token, renewed before it lapses, and one token bucket,
    for every call of one fetch or one probe."""

    def __init__(
        self,
        vanity: str,
        client_id: str,
        client_secret: str,
        *,
        tls: TlsConfig | None = None,
        transport: httpx.BaseTransport | None = None,
        rate: float = DEFAULT_RATE,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        check: Callable[[], None] | None = None,
    ):
        self._vanity = check_vanity(vanity)
        self._client_id = client_id
        self._client_secret = client_secret
        self._rate = rate
        self._max_rate = rate
        self._clean_calls = 0
        self._sleep = sleep
        self._clock = clock
        self._check = check
        self._token: str | None = None
        self._token_expires = 0.0
        self._last_call: float | None = None
        self._client = http_client.client(API_BASE, tls or TlsConfig(), timeout=60, transport=transport)

    def _authenticate(self) -> None:
        # The token request skips _throttle() and the 429 retries.
        host = f"{self._vanity}.zslogin.net"
        resp = self._token_post()
        if resp is None or resp.status_code >= 500 or resp.status_code == 429:
            self._stop_check()
            self._sleep(TOKEN_RETRY_WAIT_S)
            resp = self._token_post(final=True)
        if resp is None or not resp.is_success:
            code = resp.status_code if resp is not None else "no answer"
            raise ZscalerTokenError(f"token request to {host} answered HTTP {code}")
        try:
            payload = resp.json()
        except ValueError as exc:
            raise ZscalerTokenError(f"token answer from {host} has no access_token") from exc
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise ZscalerTokenError(f"token answer from {host} has no access_token")
        self._token = token
        self._token_expires = renew_deadline(
            self._clock(),
            payload.get("expires_in"),
            default=DEFAULT_TOKEN_LIFETIME_S,
            fraction=TOKEN_REFRESH_FRACTION,
            floor=60,
        )

    def _token_post(self, *, final: bool = False) -> httpx.Response | None:
        """The token POST, or None after a transport error when `final` is False."""
        try:
            return self._client.post(
                TOKEN_URL.format(vanity=self._vanity),  # The absolute URL overrides base_url.
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
            )
        except httpx.TransportError as exc:
            if not final:
                return None
            raise ZscalerTokenError(
                f"token request to {self._vanity}.zslogin.net failed: {type(exc).__name__}"
            ) from exc

    def _stop_check(self) -> None:
        if self._check is not None:
            self._check()

    def _send(self, path: str, params: dict[str, Any] | None) -> httpx.Response:
        return self._client.get(path, params=params, headers={"Authorization": f"Bearer {self._token}"})

    def _ensure_token(self) -> None:
        if self._token is not None and self._clock() < self._token_expires:
            return
        self._authenticate()

    def _throttle(self) -> None:
        """Two calls are at least 1/rate seconds apart."""
        min_interval = 1.0 / self._rate
        now = self._clock()
        if self._last_call is not None and now - self._last_call < min_interval:
            self._sleep(min_interval - (now - self._last_call))
            now = self._last_call + min_interval
        self._last_call = now

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict | list:
        """Send one API GET and return its JSON.

        The `check` callable runs before each send. A cancel ends the fetch before
        the next request. The wait in progress (at most 60 s) and the request in
        flight (timeout 60 s) end first."""
        self._stop_check()
        self._ensure_token()
        self._throttle()
        resp = self._send(path, params)
        if resp.status_code == 401:
            self._authenticate()
            self._stop_check()
            self._last_call = self._clock()
            resp = self._send(path, params)
        attempts = 0
        waited = 0.0
        while resp.status_code == 429 and attempts < MAX_RATE_LIMIT_RETRIES:
            wait = self._rate_limit_wait(resp, attempts)
            self._sleep(wait)
            waited += wait
            self._rate = max(self._rate / 2, MIN_RATE)
            logger.warning(
                "zscaler: HTTP 429 for %s; pace lowered to %.2f calls per second", path, self._rate
            )
            attempts += 1
            self._stop_check()
            # The re-send follows the wait and skips _throttle(). It sets
            # _last_call, and the next get() is at least 1/rate seconds after it.
            self._last_call = self._clock()
            resp = self._send(path, params)
        if resp.status_code == 429:
            raise RuntimeError(
                f"Zscaler API rate-limited {path}: HTTP 429 on {attempts + 1} sends in a row; "
                f"waited {waited:.1f} s in total; pace now {self._rate:.2f} calls per second"
            )
        self._count_clean_call(drew_429=attempts > 0)
        resp.raise_for_status()
        return resp.json()

    def _count_clean_call(self, *, drew_429: bool) -> None:
        if drew_429:
            self._clean_calls = 0
            return
        self._clean_calls += 1
        if self._clean_calls >= PACE_RECOVERY_CALLS and self._rate < self._max_rate:
            self._rate = min(self._rate * 2, self._max_rate)
            logger.info(
                "zscaler: %d calls without HTTP 429; pace raised to %.2f calls per second",
                self._clean_calls,
                self._rate,
            )
            self._clean_calls = 0

    @staticmethod
    def _rate_limit_wait(resp: httpx.Response, attempt: int) -> float:
        """Return the seconds to wait after a 429.

        The value is a numeric Retry-After, else a numeric `x-ratelimit-reset`,
        else RETRY_AFTER_FALLBACK doubled for each earlier attempt. A header value
        that is not a finite number of 0 or more counts as missing. The result is
        at most MAX_RETRY_AFTER."""
        for header in ("Retry-After", "x-ratelimit-reset"):
            value = resp.headers.get(header)
            if value is None:
                continue
            try:
                seconds = float(value)
            except ValueError:
                continue  # an HTTP-date Retry-After
            if not math.isfinite(seconds) or seconds < 0:
                continue
            return min(seconds, MAX_RETRY_AFTER)
        return min(RETRY_AFTER_FALLBACK * 2**attempt, MAX_RETRY_AFTER)

    def get_paged(
        self,
        path: str,
        item_key: str | None,
        page_param: str = "page",
        size_param: str = "pageSize",
        size: int = 500,
        max_pages: int = MAX_PAGES,
        params: dict[str, Any] | None = None,
    ) -> list[dict]:
        """Return every item of a paged collection.

        `item_key` is the key of the list in a `{item_key: [...], "totalPages": n}`
        envelope. `None` reads a bare JSON array. The walk of a bare array ends on
        a short page or a repeated page.
        """
        items: list[dict] = []
        page = 1
        served = 0
        previous: list[dict] | None = None
        while True:
            data = self.get(path, params={**(params or {}), page_param: page, size_param: size})
            if item_key is None:
                batch = data if isinstance(data, list) else []
                if batch and batch == previous:
                    if len(batch) >= size:
                        raise RuntimeError(
                            f"Zscaler API {path}: page {page} answered the same {size} items "
                            f"as page {page - 1}"
                        )
                    return items  # the endpoint ignores `page` and answered page 1 again
            else:
                batch = data.get(item_key, []) if isinstance(data, dict) else []
            items.extend(batch)
            previous = batch
            try:
                total_pages = int(data["totalPages"]) if isinstance(data, dict) else None
            except (KeyError, TypeError, ValueError):
                total_pages = None
            if total_pages is not None:
                if page >= total_pages:
                    return items
            else:
                # A page is short when it holds fewer items than the largest page so far.
                served = max(served, len(batch))
                if len(batch) < served or not batch:
                    return items
            if page >= max_pages:
                raise RuntimeError(f"Zscaler API {path}: more than {max_pages} pages")
            page += 1

    def close(self) -> None:
        self._client.close()
