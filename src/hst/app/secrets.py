"""Resolvers that return the secrets of a source row."""

from __future__ import annotations

from typing import Protocol

from hst.app.crypto import decrypt_secrets
from hst.app.store import Source


class SecretResolver(Protocol):
    def resolve(self, row: Source) -> dict[str, str]:
        """Secret values keyed by dotted config path (e.g. `auth.password`)."""
        ...


class FernetResolver:
    """Decrypts the secrets of a source row with one key.

    `resolve` raises SecretKeyError when the key does not decrypt them.
    """

    def __init__(self, key: str):
        self._key = key

    def resolve(self, row: Source) -> dict[str, str]:
        return decrypt_secrets(self._key, row.secrets)
