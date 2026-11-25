"""Trust material for the app's own outbound HTTPS: AI providers, OIDC, SAML."""

from __future__ import annotations

import os
import ssl
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SKIP_VERIFY = "tls_skip_verify"
CA_BUNDLE = "tls_ca_bundle"


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Trust:
    verify: bool = True
    ca_pem: str = ""  # PEM text from a provider row. It takes precedence over ca_file.
    ca_file: str = ""  # path from the server settings

    @property
    def is_default(self) -> bool:
        """True when the SDK's own defaults apply and no client needs building."""
        return self.verify and not self.ca_pem and not self.ca_file

    def ssl_verify(self) -> bool | ssl.SSLContext:
        """The `verify` argument for an httpx or httpx2 client."""
        if not self.verify:
            return False
        if self.ca_pem:
            return ssl.create_default_context(cadata=self.ca_pem)
        if self.ca_file:
            return ssl.create_default_context(cafile=self.ca_file)
        return True

    @contextmanager
    def ca_file_path(self) -> Iterator[bool | str | None]:
        """The `verify` argument for a boto3 client: False, a CA file path, or
        None for the SDK default.
        """
        if not self.verify:
            yield False
            return
        if self.ca_pem:
            fd, path = tempfile.mkstemp(prefix="hst-tls-ca-", suffix=".pem")
            try:
                with os.fdopen(fd, "w") as f:
                    f.write(self.ca_pem)
                yield path
            finally:
                Path(path).unlink(missing_ok=True)
            return
        yield self.ca_file or None


def resolve(settings: Any, overrides: Mapping[str, Any] | None = None) -> Trust:
    """The trust of the server settings with the `tls_skip_verify` and the
    `tls_ca_bundle` of a provider row applied.

    The function reads only `tls_verify` and `tls_ca_bundle` of `settings`.
    """
    o = overrides or {}
    skip = _truthy(o.get(SKIP_VERIFY)) or not getattr(settings, "tls_verify", True)
    return Trust(
        verify=not skip,
        ca_pem=str(o.get(CA_BUNDLE) or "").strip(),
        ca_file=str(getattr(settings, "tls_ca_bundle", "") or ""),
    )


def weakens(stored: Mapping[str, Any], overrides: Mapping[str, Any]) -> bool:
    old, new = resolve(None, stored), resolve(None, overrides)
    return (old.verify and not new.verify) or (bool(new.ca_pem) and new.ca_pem != old.ca_pem)


def validate_ca_bundle(pem: str, *, what: str = CA_BUNDLE) -> None:
    """Raise ValueError unless `pem` loads as a certificate bundle."""
    try:
        ssl.create_default_context(cadata=pem)
    except (ssl.SSLError, ValueError) as exc:
        raise ValueError(f"{what} is not a PEM certificate bundle: {exc}") from exc
