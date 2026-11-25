"""Question context. The server reads the records of the pinned run for the
addresses and the hostnames of a question."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from hst.app.agent.readers import ReaderPool

if TYPE_CHECKING:
    from hst.app.ai.registry import ToolContext, ToolRegistry

log = logging.getLogger("hst.ai")

MAX_ENTITIES = 4
MAX_ADDRESS_CANDIDATES = 6
MAX_DEVICE_CANDIDATES = 8
# A single entry larger than this is dropped from the job result.
MAX_ENTRY_CHARS = 64_000
# The catalogue tools the entries are read through.
ADDRESS_TOOL = "inventory_resolve"
DEVICE_TOOL = "impact_assess"

# The patterns match an address in the question text. They skip a candidate
# followed by "/", which is a prefix.
_V4_RE = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])(?!/)")
_V6_RE = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Fa-f:])(?!/)")

# A hostname candidate out of prose.
_HOSTNAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:[-_.][A-Za-z0-9]+)*")
_NOT_HOSTNAMES = frozenset({"ipv4", "ipv6", "l2", "l3", "as65000", "vrf", "bgp"})


def extract_entities(question: str) -> tuple[list[str], list[str]]:
    """The addresses and the hostname candidates of one question.

    Each list is in the order of appearance and has no duplicates.
    `MAX_ADDRESS_CANDIDATES` and `MAX_DEVICE_CANDIDATES` cap the lists.
    `ipaddress` validates each address. `impact_assess` resolves the hostname
    candidates.
    """
    addresses: list[str] = []
    for match in [*_V4_RE.finditer(question), *_V6_RE.finditer(question)]:
        try:
            addr = str(ipaddress.ip_address(match.group()))
        except ValueError:
            continue
        if addr not in addresses:
            addresses.append(addr)

    # The hostname scan runs on the question text without the addresses.
    remainder = _V6_RE.sub(" ", _V4_RE.sub(" ", question))
    names: list[str] = []
    for match in _HOSTNAME_RE.finditer(remainder):
        name = match.group()
        if len(name) < 3 or name.lower() in _NOT_HOSTNAMES:
            continue
        # A hostname candidate has a digit or a hyphen, as in "leaf101" and "dc1-spine2".
        if not any(c.isdigit() for c in name) and "-" not in name:
            continue
        if name.lower() not in [n.lower() for n in names]:
            names.append(name)

    return addresses[:MAX_ADDRESS_CANDIDATES], names[:MAX_DEVICE_CANDIDATES]


def _read(registry: ToolRegistry, ctx: ToolContext, tool: str, arguments: dict[str, Any]) -> Any:
    """The envelope of one catalogue read. None when the read failed, returned
    more than `MAX_ENTRY_CHARS` characters or returned text that is not JSON."""
    outcome = registry.invoke(replace(ctx, readers=ReaderPool()), tool, arguments)
    if outcome.is_error:
        # The read fails for an address that the graph does not hold, for an
        # ambiguous name and for a driver error.
        log.debug("context read %s(%s) failed: %s", tool, arguments, outcome.ui_text[:200])
        return None
    if len(outcome.ui_text) > MAX_ENTRY_CHARS:
        log.debug("context read %s(%s) dropped at %d characters", tool, arguments, len(outcome.ui_text))
        return None
    try:
        return json.loads(outcome.ui_text)
    except ValueError:
        return None


def build(ctx: ToolContext, question: str, registry: ToolRegistry | None = None) -> list[dict[str, Any]]:
    """The records of the run of the turn for the entities in `question`.

    The reads use the run of `ctx.snapshot`, or the pointer when the turn is
    not pinned. `ToolRegistry.invoke` checks the principal's permission on
    every read.

    Each entry is `{kind, subject, tool, result}`, where `result` is the
    tool's envelope. Addresses come first, then the devices a hostname
    resolved to uniquely. Returns an empty list on any error.
    """
    try:
        if registry is None:
            from hst.app.agent.tools import agent_registry

            registry = agent_registry()
        addresses, names = extract_entities(question)
        entries: list[dict[str, Any]] = []

        for address in addresses:
            if len(entries) >= MAX_ENTITIES:
                break
            envelope = _read(registry, ctx, ADDRESS_TOOL, {"kind": "address", "address": address})
            if envelope is not None:
                entries.append(
                    {"kind": "address", "subject": address, "tool": ADDRESS_TOOL, "result": envelope}
                )

        seen: set[str] = set()
        for name in names:
            if len(entries) >= MAX_ENTITIES:
                break
            # a name that matches no device or more than one is an error outcome
            envelope = _read(registry, ctx, DEVICE_TOOL, {"subject": "device", "device": name})
            result = envelope.get("result") if isinstance(envelope, dict) else None
            uid = str(result.get("device_uid") or "") if isinstance(result, dict) else ""
            if not uid or uid in seen:
                continue
            seen.add(uid)
            entries.append({"kind": "device", "subject": uid, "tool": DEVICE_TOOL, "result": envelope})

        return entries
    except Exception:
        log.warning("question context could not be built", exc_info=True)
        return []
