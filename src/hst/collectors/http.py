"""One httpx client factory for the HTTP collectors."""

from __future__ import annotations

import contextlib
import contextvars
import logging
import os
import ssl
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from hst.core import Settings

from . import http_trace
from .auth import SshJumpHost, TlsConfig
from .ssh import _AnswerBudget

logger = logging.getLogger(__name__)

DEFAULT_MAX_ANSWER_MB: int = Settings.model_fields["collect_max_answer_mb"].default


@dataclass
class _Fetch:
    source: str
    max_answer_mb: int
    warned: bool = False


_fetch: contextvars.ContextVar[_Fetch | None] = contextvars.ContextVar("hst_http_fetch", default=None)


@contextlib.contextmanager
def fetching(source: str, max_answer_mb: int | None) -> Iterator[None]:
    limit = DEFAULT_MAX_ANSWER_MB if max_answer_mb is None else max_answer_mb
    token = _fetch.set(_Fetch(source, limit))
    try:
        yield
    finally:
        _fetch.reset(token)


class _LimitedBody(httpx.SyncByteStream):
    """The answer limit counts the bytes before the content decoding."""

    def __init__(self, body: httpx.SyncByteStream, answer: _AnswerBudget) -> None:
        self._body = body
        self._answer = answer

    def __iter__(self) -> Iterator[bytes]:
        for piece in self._body:
            self._answer.take(len(piece))
            yield piece

    def close(self) -> None:
        self._body.close()


def _limit_answers(limit_mb: int) -> Callable[[httpx.Response], None]:
    def limit(response: httpx.Response) -> None:
        request = response.request
        answer = _AnswerBudget(
            f"the answer to {request.method} {request.url.host}{request.url.path}", limit_mb
        )
        if isinstance(response.stream, httpx.SyncByteStream):
            response.stream = _LimitedBody(response.stream, answer)

    return limit


def _ca_context(pem: str) -> ssl.SSLContext:
    # create_default_context(cadata=...) replaces the system store with the CA bundle.
    return ssl.create_default_context(cadata=pem)


def _unverified_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _load_client_cert(context: ssl.SSLContext, cert_pem: str, key_pem: str) -> None:
    """The temporary files have mode 0600. The key file is removed first, and a
    file that cannot be removed does not stop the removal of the other file."""
    cert_path: str | None = None
    key_path: str | None = None
    try:
        cert_fd, cert_path = tempfile.mkstemp(prefix="hst-tls-cert-", suffix=".pem")
        with os.fdopen(cert_fd, "w") as f:
            f.write(cert_pem)
        key_fd, key_path = tempfile.mkstemp(prefix="hst-tls-key-", suffix=".pem")
        with os.fdopen(key_fd, "w") as f:
            f.write(key_pem)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    finally:
        for path in (key_path, cert_path):
            if path is None:
                continue
            try:
                Path(path).unlink(missing_ok=True)
            except OSError:
                logger.exception("could not remove the temporary TLS file %s", path)


def client(
    base_url: str,
    tls: TlsConfig,
    *,
    timeout: int = 60,
    transport=None,
    jump_host: SshJumpHost | None = None,
    max_connections: int | None = None,
) -> httpx.Client:
    fetch = _fetch.get()
    if fetch is not None and not fetch.warned and httpx.URL(base_url).scheme == "http":
        fetch.warned = True
        logger.warning(
            "source %s: the credentials go to %s over HTTP without TLS",
            fetch.source,
            httpx.URL(base_url).host,
        )

    verify: bool | ssl.SSLContext = tls.verify
    if tls.verify and tls.ca_bundle:
        verify = _ca_context(tls.ca_bundle)

    if tls.client_cert is not None:
        # A client certificate needs an SSLContext for any value of `verify`.
        if not isinstance(verify, ssl.SSLContext):
            verify = ssl.create_default_context() if verify else _unverified_context()
        _load_client_cert(verify, tls.client_cert.cert, tls.client_cert.key.get_secret_value())

    # The limit hook runs before the trace hook.
    hooks: dict[str, list[Any]] = {}
    limit_mb = DEFAULT_MAX_ANSWER_MB if fetch is None else fetch.max_answer_mb
    if limit_mb:
        hooks["response"] = [_limit_answers(limit_mb)]
    trace = http_trace.current()
    if trace is not None:
        for event, traced in trace.hooks().items():
            hooks.setdefault(event, []).extend(traced)

    if jump_host is not None:
        from .http_jump import JumpTransport

        if transport is not None:
            raise ValueError("cannot combine an SSH jump host with another HTTP transport")
        context = httpx.create_ssl_context(verify=verify)
        transport = JumpTransport(base_url, jump_host, context, timeout, max_connections=max_connections or 1)
        try:
            return httpx.Client(
                base_url=base_url, timeout=timeout, transport=transport, trust_env=False, event_hooks=hooks
            )
        except BaseException:
            transport.close()
            raise
    return httpx.Client(
        base_url=base_url,
        verify=verify,
        timeout=timeout,
        transport=transport,
        limits=httpx.Limits(max_connections=max_connections, max_keepalive_connections=max_connections)
        if max_connections is not None
        else httpx.Limits(),
        event_hooks=hooks,
    )


def logged_in_client(
    base_url: str,
    tls: TlsConfig,
    login: Callable[[httpx.Client], None],
    *,
    timeout: int = 60,
    transport=None,
) -> httpx.Client:
    """Entering the returned client as a context manager raises."""
    c = client(base_url, tls, timeout=timeout, transport=transport)
    try:
        login(c)
    except BaseException:
        c.close()
        raise
    return c
