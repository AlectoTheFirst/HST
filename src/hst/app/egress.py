"""Save-time scheme check for an admin-configured URL that receives a secret at use time."""

from __future__ import annotations

from urllib.parse import urlsplit


def check_https_url(url: str, *, what: str) -> None:
    """Raise ValueError unless `url` is an https:// URL with a host. `what`
    is the field name in the message (e.g. "base_url", "issuer", "token_endpoint").
    """
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError(f"{what} must be an https:// URL naming a host")
