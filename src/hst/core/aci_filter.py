"""The ACI filter-entry reading shared by the APIC collector and the three ACI gates.

The collector (collectors/apic.py) stores each vzEntry port with `aci_port`.
The trace gate (path/gates/aci.py), the strict symbolic gate
(path/gates/aci_symbolic.py) and the analysis-model gate
(analysis_model/gates.py) read the stored fields through `filter_entry`.
`vrf_enforcement` reads the pcEnfPref of the governing VRF for an EPG pair.
`filter_applies` reads the subject direction of a filter. `endpoint_identity`
chooses the EPG of an endpoint address.

`FilterEntry.unknown` holds each field whose stored value this module cannot
read.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# The l4:Port constants that APIC writes as names in vzEntry dFromPort/dToPort and sFromPort/sToPort.
ACI_PORT_NAMES: dict[str, int] = {
    "ftpdata": 20,
    "smtp": 25,
    "dns": 53,
    "http": 80,
    "pop3": 110,
    "https": 443,
    "rtsp": 554,
}

# The vzEntry prot vocabulary (the l3:Protocol constants).
ACI_PROTOCOLS: dict[str, int] = {
    "icmp": 1,
    "igmp": 2,
    "tcp": 6,
    "egp": 8,
    "igp": 9,
    "udp": 17,
    "icmpv6": 58,
    "eigrp": 88,
    "ospfigp": 89,
    "pim": 103,
    "l2tp": 115,
}

# vzEntry etherT values and the IP address families each one matches. A non-IP
# ether type matches no IP packet. "unspecified" matches every ether type.
_ETHER_FAMILIES: dict[str, frozenset[int]] = {
    "": frozenset({4, 6}),
    "unspecified": frozenset({4, 6}),
    "ip": frozenset({4, 6}),
    "ipv4": frozenset({4}),
    "ipv6": frozenset({6}),
    "arp": frozenset(),
    "fcoe": frozenset(),
    "mpls_ucast": frozenset(),
    "mac_security": frozenset(),
    "trill": frozenset(),
}

_WILDCARD = ("", "unspecified")

# The vzEntry applyToFrag values with which the entry matches every packet.
# With "yes" the entry matches only IP fragments.
_NOT_FRAGMENT_ONLY = ("no", "false")

# The USES_FILTER direction of a filter attached under a subject's vzInTerm
# (consumer to provider) or vzOutTerm (provider to consumer). A filter attached
# to the subject itself (vzRsSubjFiltAtt) has no direction and applies both ways.
DIRECTION_IN = "in"
DIRECTION_OUT = "out"


def aci_port(value: Any) -> str | None:
    """Return one vzEntry port attribute in the form that the collector stores.

    A named l4:Port constant becomes its number, for example "443" for "https".
    "unspecified" and any value outside `ACI_PORT_NAMES` are kept as sent. An
    attribute that APIC did not send becomes the vzEntry default "unspecified".
    The collector writes every port of every entry. A stored entry without a
    port value was not collected.
    """
    if value is None:
        return "unspecified"
    text = str(value).strip()
    number = ACI_PORT_NAMES.get(text.lower())
    return str(number) if number is not None else text


@dataclass(frozen=True, slots=True)
class FilterEntry:
    """The match conditions of one vzEntry.

    `families` holds the IP address families that the entry applies to. It is
    empty for a non-IP ether type. `protocol`, `source_ports` and
    `destination_ports` are None when the entry does not constrain that field.
    `unknown` holds each field ("af", "proto", "sport", "dport", "tcp_rules",
    "frag") whose constraint is not known. A field is unknown when its stored
    value cannot be read, when it was not collected, or when it is a TCP flag or
    a fragment condition. No engine evaluates TCP flag and fragment conditions.
    No engine may decide a match or a miss on an unknown field.
    """

    families: frozenset[int]
    protocol: int | None
    source_ports: tuple[int, int] | None
    destination_ports: tuple[int, int] | None
    unknown: frozenset[str]


def _port_range(low: Any, high: Any) -> tuple[tuple[int, int] | None, bool]:
    """Return the port range, or None for no constraint, and whether the range is unreadable."""
    if low is None:
        # The collector writes every port attribute that APIC sends. A missing
        # attribute was not collected, and its constraint is not known.
        return None, True
    text = str(low).strip().lower()
    if text in _WILDCARD:
        return None, False
    if high is None or str(high).strip().lower() in _WILDCARD:
        high = low
    bounds = []
    for value in (low, high):
        key = str(value).strip().lower()
        if key in ACI_PORT_NAMES:
            bounds.append(ACI_PORT_NAMES[key])
            continue
        try:
            bounds.append(int(key))
        except ValueError:
            return None, True
    if bounds[0] > bounds[1]:
        return None, True
    return (bounds[0], bounds[1]), False


def protocol_number(value: Any) -> int | None:
    """A protocol name or number as an IP protocol number, or None when unreadable."""
    key = str(value).strip().lower()
    if key in ACI_PROTOCOLS:
        return ACI_PROTOCOLS[key]
    try:
        number = int(key)
    except ValueError:
        return None
    return number if 0 <= number <= 255 else None


def filter_entry(
    *,
    ether_type: Any,
    proto: Any,
    s_from_port: Any,
    s_to_port: Any,
    d_from_port: Any,
    d_to_port: Any,
    tcp_rules: Any,
    apply_to_frag: Any,
) -> FilterEntry:
    """Read one stored vzEntry.

    A missing etherT is read as the vzEntry default "unspecified". The collector
    writes the etherT of every vzEntry that it stores. A missing prot or port
    was not collected and is unknown. A port range whose upper bound is missing
    or "unspecified" is the single lower port.

    tcpRules ("est", "syn", ...) narrows the entry to TCP segments with those
    flags. applyToFrag "yes" narrows it to IP fragments. No engine models these
    2 conditions. An entry that sets one is unknown on that field ("tcp_rules",
    "frag"). The collector writes both attributes on every entry. A missing
    attribute was not collected and is unknown.
    """
    unknown: set[str] = set()
    families = _ETHER_FAMILIES.get(str(ether_type if ether_type is not None else "").strip().lower())
    if families is None:
        unknown.add("af")
        families = frozenset({4, 6})
    protocol: int | None = None
    if proto is None:
        unknown.add("proto")
    elif str(proto).strip().lower() not in _WILDCARD:
        protocol = protocol_number(proto)
        if protocol is None:
            unknown.add("proto")
    ports: dict[str, tuple[int, int] | None] = {}
    for side, low, high in (("sport", s_from_port, s_to_port), ("dport", d_from_port, d_to_port)):
        ports[side], unreadable = _port_range(low, high)
        if unreadable:
            unknown.add(side)
    if tcp_rules is None or str(tcp_rules).strip().lower() not in _WILDCARD:
        unknown.add("tcp_rules")
    if apply_to_frag is None or str(apply_to_frag).strip().lower() not in _NOT_FRAGMENT_ONLY:
        unknown.add("frag")
    return FilterEntry(families, protocol, ports["sport"], ports["dport"], frozenset(unknown))


def stored_entry(props: Any) -> FilterEntry:
    proto = props.get("proto")
    ether_type = props.get("ether_type")
    return filter_entry(
        ether_type=ether_type if ether_type is not None else props.get("ether_t"),
        proto=proto if proto is not None else props.get("prot"),
        s_from_port=props.get("s_from_port"),
        s_to_port=props.get("s_to_port"),
        d_from_port=props.get("d_from_port"),
        d_to_port=props.get("d_to_port"),
        tcp_rules=props.get("tcp_rules"),
        apply_to_frag=props.get("apply_to_frag"),
    )


def filter_applies(direction: Any) -> bool:
    """Return whether a filter with this USES_FILTER direction applies to traffic
    from the consumer EPG to the provider EPG.

    A subject-level filter (no direction) and a vzInTerm filter ("in") apply. A
    vzOutTerm filter ("out") applies only to traffic from the provider to the
    consumer."""
    return str(direction or "").strip().lower() != DIRECTION_OUT


def entry_match(
    entry: FilterEntry,
    *,
    family: int | None,
    protocol: int | None,
    destination_port: int | None,
) -> str:
    """Return "match", "miss" or "unknown" for one entry and one flow.

    A flow field that is None is not known for the flow. An entry constraint on
    such a field is unknown. The flow has no source port, and a source-port
    range of the entry is unknown. A known mismatch on any field is a miss, also
    when another field is unknown. A TCP flag or fragment condition
    ("tcp_rules", "frag") stays unknown.
    """
    unknown = set(entry.unknown)
    if not entry.families:
        return "miss"
    if family is not None and "af" not in unknown and family not in entry.families:
        return "miss"
    if family is None and entry.families != frozenset({4, 6}):
        unknown.add("af")
    if entry.protocol is not None and protocol is not None and entry.protocol != protocol:
        return "miss"
    if entry.protocol is not None and protocol is None:
        unknown.add("proto")
    ports = entry.destination_ports
    if ports is not None and destination_port is not None:
        if not ports[0] <= destination_port <= ports[1]:
            return "miss"
    elif ports is not None:
        unknown.add("dport")
    if entry.source_ports is not None:
        unknown.add("sport")
    return "unknown" if unknown else "match"


def vrf_enforcement(src_vrf: Any, dst_vrf: Any, pc_enf_pref: Any) -> str:
    """Return the VRF enforcement mode of an EPG pair, "enforced", "unenforced" or "unknown".

    The mode is "unknown" when the VRF of one side is missing, when the 2 EPGs
    have different VRFs (a cross-VRF or shared-services contract), or when
    pcEnfPref has any other value.
    """
    if not src_vrf or not dst_vrf or src_vrf != dst_vrf:
        return "unknown"
    pref = str(pc_enf_pref or "").strip().lower()
    if pref in ("enforced", "unenforced"):
        return pref
    return "unknown"


# collectors/apic.py writes the VrfInstance.contract_bypass flags. A flag is set
# when the vzAny of the VRF provides or consumes a contract, when its preferred
# group is enabled, when an ESG is scoped to it, or when these classes were not
# collected.
BYPASS_NOT_COLLECTED = "not-collected"
_BYPASS_NAMES = {
    "vzany": "a vzAny contract",
    "preferred-group": "an enabled preferred group",
    "esg": "endpoint security groups",
}


def contract_bypass(value: Any) -> str | None:
    """Return the reason why an EPG pair without a permitting contract can be
    permitted in this VRF, or None when the VRF has no flag.

    `value` is the stored `contract_bypass` of the VRF, a comma-separated list
    of flags. vzAny contracts, the preferred group and ESGs can permit an EPG
    pair that no EPG-to-EPG contract permits. No gate evaluates them. A VRF with
    one of these flags cannot implicitly deny. A missing value and the flag
    "not-collected" also return a reason."""
    if value is None:
        return "the VRF's vzAny, preferred group and ESG use was not collected"
    flags = sorted({flag.strip().lower() for flag in str(value).split(",") if flag.strip()})
    if not flags:
        return None
    if BYPASS_NOT_COLLECTED in flags:
        return "the VRF's vzAny, preferred group and ESG use was not collected"
    named = [_BYPASS_NAMES.get(flag, f"{flag!r}") for flag in flags]
    return f"the VRF uses {', '.join(named)}, which no ACI gate evaluates"


def reverse_contract_gap(names: Any) -> str | None:
    """Return the reason why a pair cannot be implicitly denied when the
    destination EPG consumes a contract that the source EPG provides, or None
    without such a contract.

    A subject-level filter applies in both directions. Reverse filter ports are
    not collected. The provider-to-consumer direction of such a contract is not
    evaluated."""
    listed = sorted({str(name) for name in names or () if name})
    if not listed:
        return None
    return (
        f"the destination EPG consumes {', '.join(listed)}, which the source EPG provides; "
        "the provider-to-consumer direction of a contract is not evaluated"
    )


def endpoint_identity(rows: Any, contexts: Any = ()) -> tuple[dict[str, Any] | None, str | None]:
    """Return the EPG identity of an endpoint address, or the reason why it has none.

    `rows` are the (epg_uid, vrf_uid, pc_enf_pref) rows of the address, one for
    each EPG membership. ACI lets tenants and VRFs reuse an address. `contexts`
    holds the VRFs of the flow and scopes an address in 2 or more EPGs. When the
    VRF of exactly one identity is in `contexts`, that identity is the endpoint.
    Otherwise the identities stay ambiguous. The result is (None, None) for an
    address in no EPG.
    """
    rows = [row for row in rows if row.get("epg_uid")]
    identities = {(row["epg_uid"], row.get("vrf_uid")) for row in rows}
    scope = {context for context in contexts if context}
    if len(identities) > 1 and scope:
        matching = {identity for identity in identities if identity[1] in scope}
        if len(matching) == 1:
            identities = matching
            rows = [row for row in rows if (row["epg_uid"], row.get("vrf_uid")) in matching]
    if not rows:
        return None, None
    ip = rows[0].get("ip")
    if len(identities) > 1:
        return None, f"endpoint {ip} has multiple EPG identities"
    preferences = {str(row.get("pc_enf_pref") or "").strip().lower() for row in rows}
    if len(preferences) > 1:
        return None, f"endpoint {ip} has conflicting VRF enforcement values"
    return rows[0], None
