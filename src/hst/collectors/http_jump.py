"""HTTPS requests over an SSH direct-tcpip channel."""

from __future__ import annotations

import ssl
import time
from collections.abc import Callable, Iterator
from functools import partial
from typing import Any

import httpcore
import httpx
import paramiko

from . import ssh
from .auth import SshJumpHost


class _ChannelStream(httpcore.NetworkStream):
    def __init__(self, channel: paramiko.Channel):
        self.channel = channel
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls: ssl.SSLObject | None = None

    def _io(self, operation: Callable[[], Any], timeout: float | None) -> Any:
        deadline = None if timeout is None else time.monotonic() + timeout

        def budget() -> None:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise TimeoutError("HTTPS over SSH timed out")
            self.channel.settimeout(remaining)

        while True:
            budget()
            want_read = False
            try:
                result = operation()
                complete = True
            except ssl.SSLWantReadError:
                want_read, complete = True, False
            except ssl.SSLWantWriteError:
                complete = False
            pending = self.outgoing.read()
            if pending:
                budget()
                self.channel.sendall(pending)
            if complete:
                return result
            if want_read:
                budget()
                data = self.channel.recv(65536)
                if data:
                    self.incoming.write(data)
                else:
                    self.incoming.write_eof()

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        try:
            self.tls = ssl_context.wrap_bio(self.incoming, self.outgoing, server_hostname=server_hostname)
            self._io(self.tls.do_handshake, timeout)
            return self
        except TimeoutError as exc:
            self.close()
            raise httpcore.ConnectTimeout(str(exc)) from exc
        except (OSError, paramiko.SSHException) as exc:
            self.close()
            raise httpcore.ConnectError(str(exc)) from exc

    def read(self, max_bytes, timeout=None):
        try:
            if self.tls is not None:
                return self._io(lambda: self.tls.read(max_bytes), timeout)
            self.channel.settimeout(timeout)
            return self.channel.recv(max_bytes)
        except TimeoutError as exc:
            raise httpcore.ReadTimeout(str(exc)) from exc
        except (OSError, paramiko.SSHException) as exc:
            raise httpcore.ReadError(str(exc)) from exc

    def write(self, buffer, timeout=None):
        try:
            if self.tls is None:
                self.channel.settimeout(timeout)
                self.channel.sendall(buffer)
            else:
                while buffer:
                    sent = self._io(partial(self.tls.write, buffer), timeout)
                    buffer = buffer[sent:]
        except TimeoutError as exc:
            raise httpcore.WriteTimeout(str(exc)) from exc
        except (OSError, paramiko.SSHException) as exc:
            raise httpcore.WriteError(str(exc)) from exc

    def get_extra_info(self, info):
        if info == "ssl_object":
            return self.tls
        if info == "is_readable":
            return self.channel.closed or self.channel.eof_received or self.channel.recv_ready()
        return None

    def close(self):
        self.channel.close()


class _JumpBackend(httpcore.NetworkBackend):
    def __init__(self, transport: paramiko.Transport):
        self.transport = transport

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        try:
            channel = self.transport.open_channel(
                "direct-tcpip", (host, port), ("127.0.0.1", 0), timeout=timeout
            )
            return _ChannelStream(channel)
        except TimeoutError as exc:
            raise httpcore.ConnectTimeout(f"bastion could not reach {host}:{port}: {exc}") from exc
        except (OSError, paramiko.SSHException) as exc:
            raise httpcore.ConnectError(f"bastion could not reach {host}:{port}: {exc}") from exc


_POOL_ERRORS = (httpcore.NetworkError, httpcore.TimeoutException, httpcore.ProtocolError)


def _httpx_error(exc: Exception, request: httpx.Request) -> httpx.TransportError:
    error = getattr(httpx, type(exc).__name__, httpx.TransportError)
    return error(str(exc), request=request)


class _PoolBody(httpx.SyncByteStream):
    def __init__(self, body: Any, request: httpx.Request) -> None:
        self._body = body
        self._request = request

    def __iter__(self) -> Iterator[bytes]:
        try:
            yield from self._body
        except _POOL_ERRORS as exc:
            raise _httpx_error(exc, self._request) from exc

    def close(self) -> None:
        self._body.close()


class JumpTransport(httpx.BaseTransport):
    """One SSH session and one HTTP pool for a collector's complete fetch."""

    def __init__(
        self, url: str, jump: SshJumpHost, context: ssl.SSLContext, timeout: int, *, max_connections: int = 1
    ):
        self.origin = httpx.URL(url)
        if self.origin.scheme != "https":
            raise ValueError("VCO SSH jump host requires an HTTPS orchestrator URL")
        self.ssh, self.host_key = ssh._connect(
            jump.host, jump.port, jump.auth, jump.host_key, timeout, timeout, hop="bastion"
        )
        try:
            self.ssh.set_keepalive(ssh.KEEPALIVE_INTERVAL)
            self.pool = httpcore.ConnectionPool(
                ssl_context=context, network_backend=_JumpBackend(self.ssh), max_connections=max_connections
            )
        except BaseException:
            self.ssh.close()
            raise

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if (request.url.scheme, request.url.host, request.url.port) != (
            self.origin.scheme,
            self.origin.host,
            self.origin.port,
        ):
            raise httpx.ConnectError("SSH transport refuses a different VCO origin", request=request)
        try:
            response = self.pool.handle_request(
                httpcore.Request(
                    request.method,
                    str(request.url),
                    headers=request.headers.raw,
                    content=request.read(),
                    extensions=request.extensions,
                )
            )
        except _POOL_ERRORS as exc:
            raise _httpx_error(exc, request) from exc
        return httpx.Response(
            response.status,
            headers=response.headers,
            stream=_PoolBody(response.stream, request),
            extensions=response.extensions,
        )

    def close(self):
        try:
            self.pool.close()
        finally:
            self.ssh.close()
