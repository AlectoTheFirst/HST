"""This module imports neither pyarrow nor duckdb."""

from __future__ import annotations

import ipaddress


def addr_bytes(addr: str) -> bytes:
    """The address as 16 bytes, an IPv4 address in its IPv4-mapped IPv6 form.

    The byte order of the results is the numeric order of the addresses."""
    ip = ipaddress.ip_address(addr)
    if ip.version == 4:
        ip = ipaddress.IPv6Address(f"::ffff:{ip}")
    return ip.packed


# The ::ffff:0:0/96 prefix that maps an IPv4 address into the IPv6 space, as
# the high bits of the 128-bit integer `addr_bytes` encodes.
_V4_MAPPED = 0xFFFF << 32


def prefix_bounds(prefix: str) -> tuple[bytes, bytes, int, int]:
    """(lo, hi, prefixlen, af) of a prefix in the `addr_bytes` encoding."""
    net = ipaddress.ip_network(prefix, strict=False)
    lo = int(net.network_address)
    hi = lo | ((1 << (net.max_prefixlen - net.prefixlen)) - 1)
    if net.version == 4:
        lo |= _V4_MAPPED
        hi |= _V4_MAPPED
    return lo.to_bytes(16, "big"), hi.to_bytes(16, "big"), net.prefixlen, net.version


# Within one family the string order of the keys is the numeric order of the addresses.


def _graph_key(version: int, value: int) -> str:
    return f"4:{value:08x}" if version == 4 else f"6:{value:032x}"


def graph_key(addr: object) -> str | None:
    """The graph key of one address, None for a value that is not an address.

    An IPv6 zone (`fe80::1%eth0`) is dropped. An address written with a prefix
    length (`10.0.0.5/24`) gets the key of its address.
    """
    if not isinstance(addr, str) or not addr.strip():
        return None
    text = addr.strip().split("%", 1)[0]
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        try:
            ip = ipaddress.ip_interface(text).ip
        except ValueError:
            return None
    return _graph_key(ip.version, int(ip))


def graph_prefix_keys(cidr: object) -> tuple[str, str] | None:
    """The graph keys (lo, hi) of the first and the last address of a prefix.
    None for a value that is not a prefix. Host bits are ignored, as in
    `prefix_bounds`."""
    if not isinstance(cidr, str) or not cidr.strip():
        return None
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return None
    lo = int(net.network_address)
    hi = lo | ((1 << (net.max_prefixlen - net.prefixlen)) - 1)
    return _graph_key(net.version, lo), _graph_key(net.version, hi)


def graph_address_props(labels: str | tuple[str, ...] | list[str], props: dict) -> dict[str, str]:
    names = {labels} if isinstance(labels, str) else set(labels)
    out: dict[str, str] = {}
    if names & {"IpAddress", "Endpoint"} and props.get("ip_key") is None:
        key = graph_key(props.get("ip"))
        if key is not None:
            out["ip_key"] = key
    if "Prefix" in names and props.get("lo_key") is None:
        keys = graph_prefix_keys(props.get("cidr"))
        if keys is not None:
            out["lo_key"], out["hi_key"] = keys
    return out
