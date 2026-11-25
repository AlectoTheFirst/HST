"""The device uid and the rule that mints it.

The device uid is `dev:<name>`, the short hostname of the device when the
registry saw it for the first time. After that the uid does not change. A
device with a new serial, a new hostname or a new management address resolves
to the uid that the registry holds. Only the rename command
(`hst device rekey`) changes a uid.

The registry keys a device by the identifiers that its collectors see. The
kind `serial` is the chassis serial. The kind `ref` is `<source>:<ref>`, for a
device that reports no serial. One uid can hold many identifiers, for example
one row per member serial of a stack.

This module does no I/O. The registry is `PgStore.resolve_device`
(app/store/pg.py). `MemoryResolver` is the same rule in memory, for tests and
for a read of the registry that must not write to it.
"""

from __future__ import annotations

import hashlib
import ipaddress
import itertools
import logging
import threading
import weakref
from collections.abc import Container, Iterable, Iterator
from typing import Literal, Protocol

from . import uid

logger = logging.getLogger(__name__)

Kind = Literal["serial", "ref"]
KINDS: tuple[Kind, ...] = ("serial", "ref")

# The name of a device that reports no hostname.
UNNAMED = "unknown"

# A device with one of these short names gets a uid with a suffix.
DEFAULT_NAMES = frozenset(
    {
        "switch",
        "router",
        "localhost",
        UNNAMED,
        # the host name of a VyOS box whose configuration sets none (collectors/vyos.py)
        "vyos",
    }
)

SUFFIX_LEN = 4

# The values are compared after `_serial_text`.
PLACEHOLDER_SERIALS = frozenset(
    {
        "",
        "-",
        "none",
        "unknown",
        "n/a",
        "na",
        "not specified",
        "not applicable",
        "not available",
        "default string",
        "to be filled by o.e.m.",
        "o.e.m.",
        "oem",
        "system serial number",
        "chassis serial number",
        "base board serial number",
        "serial number",
        "serialnumber",
        "invalid",
        "empty",
        "undefined",
        "default",
        "0123456789",
        "123456789",
        "1234567890",
        "12345678",
    }
)


def _serial_text(value: str) -> str:
    """`value` stripped, in lowercase, with each run of whitespace as one space."""
    return " ".join(value.split()).lower()


def placeholder_serial(value: str | None) -> bool:
    text = _serial_text(value or "")
    return text in PLACEHOLDER_SERIALS or len(set(text.replace(" ", ""))) <= 1


def chassis_serial(value: object) -> str | None:
    """The reported chassis serial, stripped. None for an absent serial, an empty
    serial or a placeholder (`placeholder_serial`). A collector uses the result
    as the serial that it reports, as the registry key and as the `serial` of
    the Device."""
    text = str(value).strip() if value is not None else ""
    return None if placeholder_serial(text) else text


# resolver -> {serial identifier: (fallback identifier, short name)}. The value
# is of the first device that resolved by that serial through the resolver. One
# resolver serves one run (app/runs_exec.py `_arm_identity`).
_CLAIMS: weakref.WeakKeyDictionary[object, dict[str, tuple[tuple[str, str] | None, str]]] = (
    weakref.WeakKeyDictionary()
)
_CLAIMS_LOCK = threading.Lock()


def resolve_chassis(
    resolver: DeviceResolver, serial: object, fallback: tuple[Kind, str] | None, hostname: str | None
) -> str:
    """The Device uid of a device that reports `serial`.

    A device with no serial resolves by `fallback`. `fallback` is
    `("ref", "<source>:<ref>")`, or `("serial", <MAC>)` for a UniFi device. A
    device also resolves by `fallback` when a device with another fallback and
    another short name resolved by the same serial through `resolver`."""
    value = chassis_serial(serial)
    if value is None:
        if fallback is None:
            raise ValueError("a device with no serial needs a fallback identifier")
        return resolver.resolve_device(fallback[0], fallback[1], hostname)
    key = identifier("serial", value)
    mine = (fallback[0], identifier(fallback[0], fallback[1])) if fallback else None
    name = short_name(hostname)
    try:
        with _CLAIMS_LOCK:
            prior = _CLAIMS.setdefault(resolver, {}).setdefault(key, (mine, name))
    except TypeError:  # a resolver that cannot be weakly referenced keeps no record
        prior = (mine, name)
    if fallback is not None and prior[0] != mine and prior[1] != name:
        logger.warning(
            "serial %r is reported by %s and by %s in this run; %s resolves by %s %r instead",
            value,
            prior[1] or UNNAMED,
            name or UNNAMED,
            name or UNNAMED,
            fallback[0],
            fallback[1],
        )
        return resolver.resolve_device(fallback[0], fallback[1], hostname)
    return resolver.resolve_device("serial", value, hostname)


def short_name(hostname: str | None) -> str:
    text = (hostname or "").strip()
    try:
        ipaddress.ip_address(text)
    except ValueError:
        text = text.split(".", 1)[0]
    return uid.slug(text)


def identifier(kind: str, value: str) -> str:
    if kind == "serial":
        value = uid.slug(value)
    elif kind == "ref":
        value = ":".join(uid.slug(part) for part in value.split(":"))
    else:
        raise ValueError(f"unknown identifier kind {kind!r}; expected one of {', '.join(KINDS)}")
    if not value.strip(":"):
        raise ValueError(f"empty {kind} identifier")
    return value


def legacy_uid(kind: str, value: str) -> str:
    """The uid that the identifier gives without the registry. A serial gives
    `dev:<serial>`. A ref gives `dev:x:<source>:<ref>`. When the registry mints
    a uid, the references to this uid outside the graph move to the minted uid."""
    if kind == "serial":
        return f"dev:{uid.slug(value)}"
    source, _, ref = value.rpartition(":")
    return f"dev:x:{uid.slug(source)}:{uid.slug(ref)}"


def base_uid(hostname: str | None) -> str:
    """`dev:<short_name>`, the uid that every minted uid of this hostname starts
    with. A device without a hostname gets the name `unknown`."""
    return f"dev:{short_name(hostname) or UNNAMED}"


def plain_uid(hostname: str | None) -> str | None:
    """The `base_uid` of the hostname. A device gets this uid when no other
    device has it. None for a name in DEFAULT_NAMES."""
    base = base_uid(hostname)
    return None if base.removeprefix("dev:") in DEFAULT_NAMES else base


def valid_uid(value: str) -> bool:
    """Whether the rename command can set the uid `value`. The uid must be
    `dev:<name>`, with a name that `uid.slug` does not change."""
    name = value.removeprefix("dev:")
    return value.startswith("dev:") and bool(name) and uid.slug(name) == name


def mint(hostname: str | None, serial: str | None, ref: str | None, taken: Container[str]) -> str:
    """A new device uid. The uid is `plain_uid` when no device has that uid,
    else `dev:<short_name>-<suffix>`.

    The suffix is the last 4 characters of `slug(serial)`. A device without a
    serial gets the first 4 characters of the SHA-256 hash of `ref`
    (`<source>:<ref>`). If that uid is taken too, the suffix grows by one
    character until the uid is free.
    """
    plain = plain_uid(hostname)
    if plain is not None and plain not in taken:
        return plain
    base = base_uid(hostname)
    for suffix in _suffixes(serial, ref):
        candidate = f"{base}-{suffix}"
        if candidate not in taken:
            return candidate
    raise AssertionError("the suffixes do not end")  # pragma: no cover


def _suffixes(serial: str | None, ref: str | None) -> Iterator[str]:
    """The suffixes that `mint` tries, in order. A suffix is the end of the
    serial, or the start of the hash of the ref. Each suffix is one character
    longer than the suffix before it. When the serial or the hash has no more
    characters, the longest suffix follows with a counter that starts at 2."""
    text = uid.slug(serial or "")
    if text:
        candidates = [text[-n:] for n in range(min(SUFFIX_LEN, len(text)), len(text) + 1)]
    elif ref:
        digest = hashlib.sha256(ref.encode()).hexdigest()
        candidates = [digest[:n] for n in range(SUFFIX_LEN, len(digest) + 1)]
    else:
        raise ValueError("a device needs a serial or a ref to get a suffix")
    yield from candidates
    for n in itertools.count(2):
        yield f"{candidates[-1]}-{n}"


def mint_for(kind: str, value: str, hostname: str | None, taken: Container[str]) -> str:
    """`mint` for one identifier in its registry form (`identifier`)."""
    return mint(hostname, value if kind == "serial" else None, value if kind == "ref" else None, taken)


class DeviceResolver(Protocol):
    """The registry calls of a collector (`Collector.identity`)."""

    def resolve_device(self, kind: Kind, value: str, hostname: str | None) -> str:
        """The uid of the device that has this identifier. The registry mints
        it the first time that it sees the identifier."""
        ...

    def bind_device(self, uid: str, kind: Kind, value: str) -> None:
        """An identifier that the registry holds keeps its uid."""
        ...

    def identity_generation(self) -> int:
        """The registry generation. The rename command increments it."""
        ...


class MemoryResolver:
    """The registry in memory, with the same minting rule.

    A collector has a MemoryResolver by default (`Collector.identity`). A
    collector built in a test resolves without Postgres. A MemoryResolver built
    from the rows of the registry returns the uids of the registry and does not
    write to the registry. It mints the uid of a device that the registry does
    not know in memory only. A replay into a scratch graph gets the uids of the
    live registry from it.
    """

    def __init__(self, rows: Iterable[tuple[str, str, str]] = (), generation: int = 0) -> None:
        """`rows` are (uid, kind, value) triples, the value in its registry
        form."""
        self._uids: dict[tuple[str, str], str] = {}
        self._taken: set[str] = set()
        self._generation = generation
        for device_uid, kind, value in rows:
            self._uids[(kind, value)] = device_uid
            self._taken.add(device_uid)

    def resolve_device(self, kind: Kind, value: str, hostname: str | None) -> str:
        key = identifier(kind, value)
        found = self._uids.get((kind, key))
        if found is None:
            found = mint_for(kind, key, hostname, self._taken)
            self._uids[(kind, key)] = found
            self._taken.add(found)
        return found

    def bind_device(self, uid: str, kind: Kind, value: str) -> None:
        if uid not in self._taken:
            raise LookupError(f"no device has the uid {uid!r}")
        self._uids.setdefault((kind, identifier(kind, value)), uid)

    def identity_generation(self) -> int:
        return self._generation
