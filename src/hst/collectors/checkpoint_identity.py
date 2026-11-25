"""How a Gaia appliance finds its management identity in data the sources hold.

The management source (collectors/checkpoint.py) stores every gateway object
the server manages, with its uid, name, IPv4 address and type. The Gaia source
(collectors/checkpoint_gateway.py) knows the SSH host it read, the hostname the
appliance reports and the name of every virtual system in `vsx stat -v`. The
resolver joins the two in 3 steps.

1. The management scope is the scope string of the linked management source.
2. The appliance is the gateway object whose IPv4 address equals the SSH host,
   else the gateway object whose name equals the reported hostname.
3. Each VSID is the virtual system object whose name equals the VS name.

A typed override wins over each step. A step that finds nothing records a
warning with the appliance and the management source. The identity then uses
what the appliance reported. The appliance Device uses the host. A
FirewallInstance uses the VS name. These identities join no management object.
A trace finds no rulebase for them. The resolver reads neither the graph nor
the raw store. The caller passes the inventory.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

# FIRST CONTACT: the virtual system object types of show-gateways-and-servers are
# assumed, as GATEWAY_TYPES in collectors/checkpoint.py is. A VS name is matched against
# these types first and against every other gateway object after. VS 0 of a VSX member
# is the gateway or cluster object itself.
VS_TYPES = frozenset({"CpmiVsClusterNetobj", "CpmiVsNetobj"})

# FIRST CONTACT: the table under "Virtual Systems Status" of `vsx stat -v` is
# assumed to read
#
#     ID   | Type & Name        | Security Policy | Installed at | SIC Stat
#        1 | S vs-fr2-dmz       | vs-fr2-dmz_pol  | ...
#
# where the type letter is S (virtual system), B (bridge mode virtual system),
# R (virtual router) or W (virtual switch). The VSID is the first number on
# the line. The name is the first word after the type letter. On a line with
# no column separator ("7 VS7"), the name is the second word.
_VS_LINE = re.compile(r"^\s*(?P<vsid>\d+)\s*\|?\s*(?:(?P<kind>[A-Z])\s+)?(?P<name>[^|\s]+)")


@dataclass(frozen=True, slots=True)
class GatewayObject:
    """One gateway object of the management server. `domain_uid` is the uid of the
    domain of the object, or empty when the payload has no `domain` block."""

    uid: str
    name: str = ""
    ipv4: str = ""
    type: str = ""
    domain_uid: str = ""


def gateway_objects(raw: Mapping[str, Any]) -> tuple[GatewayObject, ...]:
    """The gateway objects of one management payload, from the `gateways` list that the
    management collector stores from show-gateways-and-servers.

    FIRST CONTACT: with details-level full every object is expected to have a `domain`
    block with `uid` and `name`. The package details have the same block, and
    collectors/checkpoint.py reads it there.
    """
    objects: list[GatewayObject] = []
    for gw in raw.get("gateways", []) or []:
        if not isinstance(gw, Mapping):
            continue
        object_uid = gw.get("uid")
        if not isinstance(object_uid, str) or not object_uid:
            continue
        domain = gw.get("domain")
        objects.append(
            GatewayObject(
                uid=object_uid,
                name=str(gw.get("name") or ""),
                ipv4=str(gw.get("ipv4-address") or ""),
                type=str(gw.get("type") or ""),
                domain_uid=str(domain.get("uid") or "") if isinstance(domain, Mapping) else "",
            )
        )
    return tuple(objects)


@dataclass(frozen=True, slots=True)
class ManagementInventory:
    """What the Gaia source knows of its management source at normalize time.

    `scope` is the scope string of the management source, or empty when the row could
    not be linked. `domain` is the domain name of that row, or empty on a single-domain
    server. `objects` is the last stored gateway list of the source, or empty. `problem`
    states why the scope or the objects are missing. It is empty when both are present.
    """

    source: str
    scope: str = ""
    domain: str = ""
    objects: tuple[GatewayObject, ...] = ()
    problem: str = ""


@dataclass(frozen=True, slots=True)
class GaiaObservation:
    """What the appliance reported about itself."""

    hostname: str = ""
    vs_names: Mapping[int, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class GatewayIdentity:
    """The resolved identity of one appliance and its virtual systems.

    `appliance_origin` is `override`, `address`, `name` or `host`. `host` is the
    fallback. `domain` is the management domain uid of the FirewallInstance identity.
    `domain_origin` is the source of `domain`. It is `override`, `object` (the domain
    block of the appliance object), `inventory` (the domain block of another object),
    `scope` (the domain name of the scope string) or `authority` (the scope string of a
    single-domain server). `vs_object_uids` holds one entry per VSID that has an
    identity. A VSID with no override, no matching object and no name has no entry, and
    the collector writes no context for it.
    """

    authority: str
    appliance_uid: str
    appliance_origin: str
    domain: str
    domain_origin: str
    vs_object_uids: Mapping[int, str]
    warnings: tuple[str, ...]
    appliance_type: str = ""


def parse_hostname(text: str) -> str:
    """Return the first non-empty line of the `clish -c 'show hostname'` output.

    FIRST CONTACT: Gaia clish is assumed to print the hostname alone on one
    line, with no label in front of it.
    """
    for line in str(text or "").splitlines():
        value = line.strip()
        if value:
            return value
    return ""


_RELEASE = re.compile(r"\bR\d+(?:\.\d+)*\b")


def parse_release(text: str) -> str:
    """Return the first `R<n>[.<n>]` token of the `show version` output as the Gaia
    release, else the first non-empty line.

    FIRST CONTACT: the output of `clish -c 'show version osedition'` is assumed to hold
    the release in the form `R81.20` on one of its lines.
    """
    match = _RELEASE.search(str(text or ""))
    if match is not None:
        return match.group(0)
    return parse_hostname(text)


def parse_vs_names(text: str) -> dict[int, str]:
    """VSID to VS name from `vsx stat -v` (the `_VS_LINE` shape above)."""
    names: dict[int, str] = {}
    for line in str(text or "").splitlines():
        match = _VS_LINE.match(line)
        if match is None:
            continue
        vsid = int(match.group("vsid"))
        names.setdefault(vsid, match.group("name"))
    return names


def _address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _by_address(objects: Iterable[GatewayObject], host: str) -> GatewayObject | None:
    wanted = _address(host)
    if wanted is None:
        return None
    for candidate in objects:
        if candidate.ipv4 and _address(candidate.ipv4) == wanted:
            return candidate
    return None


def _by_name(objects: Iterable[GatewayObject], name: str) -> GatewayObject | None:
    if not name:
        return None
    for candidate in objects:
        if candidate.name == name:
            return candidate
    return None


def _vs_by_name(objects: tuple[GatewayObject, ...], name: str) -> GatewayObject | None:
    if not name:
        return None
    return _by_name((o for o in objects if o.type in VS_TYPES), name) or _by_name(objects, name)


def _valid_uid(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and value.strip() == value


def resolve_identity(
    *,
    appliance: str,
    host: str,
    vsids: Iterable[int],
    observed: GaiaObservation,
    inventory: ManagementInventory | None,
    authority_override: str = "",
    authority_fallback: str = "",
    appliance_override: str = "",
    domain_override: str = "",
    vs_overrides: Mapping[int, str] | None = None,
) -> GatewayIdentity:
    """Resolve one appliance's identity in the order of the module docstring.

    `appliance` is the label the warnings use for this appliance. `host` is
    the SSH host the Gaia source read. `authority_fallback` is the scope the
    authority takes when neither an override nor the inventory provides one.

    The domain uid comes from `domain_override`, else from the appliance
    object's domain block, else from any object's domain block, else from the
    domain name of the scope, else from the scope string itself (a
    single-domain server has no domain part). `domain_origin` holds the
    source of the domain uid. The resolver writes no warning about it.
    """
    warnings: list[str] = []
    overrides = dict(vs_overrides or {})
    objects = inventory.objects if inventory is not None else ()
    source = inventory.source if inventory is not None else ""

    if authority_override:
        authority = authority_override
    elif inventory is not None and inventory.scope:
        authority = inventory.scope
    else:
        authority = authority_fallback

    matched: GatewayObject | None = None
    if appliance_override:
        appliance_uid, origin = appliance_override, "override"
        matched = next((o for o in objects if o.uid == appliance_override), None)
    else:
        matched = _by_address(objects, host)
        if matched is not None:
            appliance_uid, origin = matched.uid, "address"
        else:
            matched = _by_name(objects, observed.hostname)
            if matched is not None:
                appliance_uid, origin = matched.uid, "name"
            else:
                appliance_uid, origin = host, "host"

    if domain_override:
        domain, domain_origin = domain_override, "override"
    elif matched is not None and matched.domain_uid:
        domain, domain_origin = matched.domain_uid, "object"
    elif any(o.domain_uid for o in objects):
        domain, domain_origin = next(o.domain_uid for o in objects if o.domain_uid), "inventory"
    elif inventory is not None and inventory.domain:
        domain, domain_origin = inventory.domain, "scope"
    else:
        domain, domain_origin = authority, "authority"

    vs_object_uids: dict[int, str] = {}
    by_name: list[int] = []
    unnamed: list[int] = []
    for vsid in sorted(set(vsids)):
        override = overrides.get(vsid)
        if _valid_uid(override):
            vs_object_uids[vsid] = override
            continue
        name = observed.vs_names.get(vsid, "")
        found = _vs_by_name(objects, name)
        if found is not None:
            vs_object_uids[vsid] = found.uid
        elif name:
            vs_object_uids[vsid] = name
            by_name.append(vsid)
        else:
            unnamed.append(vsid)

    consequences: list[str] = []
    if not authority_override and authority != (inventory.scope if inventory is not None else ""):
        consequences.append(f"FirewallInstance.authority is {authority!r}")
    if origin == "host":
        consequences.append(f"the appliance Device is keyed by host {host!r}")
    if by_name:
        listed = ", ".join(str(v) for v in by_name)
        consequences.append(f"VS {listed} keep FirewallInstance nodes keyed by their VS names")

    if inventory is None:
        if not authority_override or origin == "host" or by_name:
            warnings.append(
                f"{appliance}: no management source is configured, so the identity comes from "
                f"the typed overrides alone; " + "; ".join(consequences)
            )
    elif inventory.problem:
        note = "; ".join(consequences)
        warnings.append(
            f"{appliance}: management source {source!r} gave no usable data ({inventory.problem})"
            + (f"; {note}" if note else "")
        )
    else:
        if origin == "host":
            seen = (
                f" or name {observed.hostname!r}"
                if observed.hostname
                else ", and the appliance reported no hostname"
            )
            warnings.append(
                f"{appliance}: no gateway object of management source {source!r} has address "
                f"{host!r}{seen}; the appliance Device is keyed by host {host!r}"
            )
        for vsid in by_name:
            warnings.append(
                f"{appliance}: VS {vsid} {observed.vs_names[vsid]!r} matches no virtual system "
                f"object of management source {source!r}; its FirewallInstance is keyed by the VS name"
            )
    for vsid in unnamed:
        warnings.append(
            f"{appliance}: VS {vsid} has no name in vsx stat -v and no configured object uid; "
            "its context is not written"
        )
    return GatewayIdentity(
        authority=authority,
        appliance_uid=appliance_uid,
        appliance_origin=origin,
        domain=domain,
        domain_origin=domain_origin,
        vs_object_uids=vs_object_uids,
        warnings=tuple(warnings),
        appliance_type=matched.type if matched else "",
    )
