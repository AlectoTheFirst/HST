"""The LPM reader compares `prefix_bounds` output byte-wise."""

from __future__ import annotations

import ipaddress
import random
from collections.abc import Iterator, Sequence
from typing import Any, overload

import pytest

from hst.core import debug_capture, ipenc


def _reference_addr_bytes(addr: str) -> bytes:
    """The reference of `ipenc.addr_bytes`, through `ipaddress`."""
    ip = ipaddress.ip_address(addr)
    if ip.version == 4:
        ip = ipaddress.IPv6Address(f"::ffff:{ip}")
    return ip.packed


def _reference_prefix_bounds(prefix: str) -> tuple[bytes, bytes, int, int]:
    """The reference of `ipenc.prefix_bounds`. It formats each bound as a
    string and parses it again through `_reference_addr_bytes`."""
    net = ipaddress.ip_network(prefix, strict=False)
    return (
        _reference_addr_bytes(str(net.network_address)),
        _reference_addr_bytes(str(net.broadcast_address)),
        net.prefixlen,
        net.version,
    )


EDGE_PREFIXES = [
    "0.0.0.0/0",
    "255.255.255.255/0",
    "255.255.255.255/32",
    "0.0.0.0/32",
    "10.1.2.3/32",
    "10.1.2.3/24",  # host bits set, accepted with strict=False
    "10.1.2.3/31",
    "192.168.1.1",  # no length: a host route
    "10.0.0.0/255.255.255.0",  # netmask form
    "10.0.0.0/0.0.0.255",  # hostmask form
    "::/0",
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0",
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
    "::/128",
    "::1/128",
    "2001:db8::1/128",
    "2001:db8::1/64",
    "2001:db8::",
    "::ffff:1.2.3.4/128",  # v4-mapped, stays af 6
    "::ffff:1.2.3.4/96",
    "::ffff:0.0.0.0/96",
    "::1.2.3.4/128",
    "fe80::%eth0/64",  # scope id: not part of the packed bytes
    "fe80::1%eth0/128",
]


def _random_prefixes(count: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    out: list[str] = []
    for i in range(count):
        kind = i % 3
        if kind == 0:
            addr = str(ipaddress.IPv4Address(rng.getrandbits(32)))
            out.append(f"{addr}/{rng.randint(0, 32)}")
        elif kind == 1:
            addr = str(ipaddress.IPv6Address(rng.getrandbits(128)))
            out.append(f"{addr}/{rng.randint(0, 128)}")
        else:
            v4 = ipaddress.IPv4Address(rng.getrandbits(32))
            out.append(f"::ffff:{v4}/{rng.randint(96, 128)}")
    return out


def test_prefix_bounds_matches_the_reference_on_edge_prefixes():
    for prefix in EDGE_PREFIXES:
        assert ipenc.prefix_bounds(prefix) == _reference_prefix_bounds(prefix), prefix


def test_prefix_bounds_matches_the_reference_on_random_prefixes():
    """100k random v4, v6 and v4-mapped prefixes, host bits set on almost all
    of them. The seed is fixed, so a failure names a reproducible prefix."""
    mismatches = [
        p
        for p in _random_prefixes(100_000, seed=20260926)
        if ipenc.prefix_bounds(p) != _reference_prefix_bounds(p)
    ]
    assert mismatches == []


def test_prefix_bounds_values_have_the_addr_bytes_shape():
    lo, hi, prefixlen, af = ipenc.prefix_bounds("10.1.2.3/24")
    assert (lo, hi) == (ipenc.addr_bytes("10.1.2.0"), ipenc.addr_bytes("10.1.2.255"))
    assert (prefixlen, af) == (24, 4)
    assert type(lo) is bytes and type(hi) is bytes and len(lo) == len(hi) == 16


INVALID_PREFIXES = [
    "",
    " ",
    "not-a-prefix",
    "10.0.0.256/24",
    "10.0.0.0/33",
    "10.0.0.0/-1",
    "10.0.0.0/24/1",
    "10.0.0/24",
    "10.0.0.0/255.0.255.0",
    " 10.0.0.0/24",
    "10.0.0.0/24 ",
    "::/129",
    "2001:db8::/64x",
    "2001:db8:::1/64",
    "gggg::/16",
    "10.0.0.0/",
    "/24",
]


@pytest.mark.parametrize("prefix", INVALID_PREFIXES)
def test_invalid_prefixes_raise_what_the_reference_raises(prefix):
    with pytest.raises(Exception) as expected:
        _reference_prefix_bounds(prefix)
    with pytest.raises(Exception) as actual:
        ipenc.prefix_bounds(prefix)
    assert type(actual.value) is type(expected.value)
    assert str(actual.value) == str(expected.value)


class _UniterableRows(Sequence[dict[str, Any]]):
    """A row view whose rows must never be built: iterating it or indexing it
    fails the test."""

    def __init__(self, n: int) -> None:
        self._n = n

    def __len__(self) -> int:
        return self._n

    @overload
    def __getitem__(self, index: int) -> dict[str, Any]: ...

    @overload
    def __getitem__(self, index: slice) -> Sequence[dict[str, Any]]: ...

    def __getitem__(self, index: int | slice) -> dict[str, Any] | Sequence[dict[str, Any]]:
        raise AssertionError("the view was indexed")

    def __iter__(self) -> Iterator[dict[str, Any]]:
        raise AssertionError("the view was iterated")


def test_debug_size_of_a_lazy_view_is_its_length_without_iterating_it():
    view = _UniterableRows(1_000_000)
    assert debug_capture._size(view) == {"items": 1_000_000}
    summary = debug_capture.payload_summary({"show ip route": view, "show arp": "a\nb"})
    assert summary["commands"]["show ip route"] == {"items": 1_000_000}
    assert summary["commands"]["show arp"] == {"chars": 3, "lines": 2}


def test_debug_size_keeps_its_answers_for_text_bytes_and_builtin_containers():
    assert debug_capture._size("") == {"chars": 0, "lines": 0}
    assert debug_capture._size("a\nb\n") == {"chars": 4, "lines": 3}
    assert debug_capture._size(["a", "b"]) == {"items": 2}
    assert debug_capture._size({"a": 1}) == {"items": 1}
    assert debug_capture._size(b"abc") is None
    assert debug_capture._size(bytearray(b"abc")) is None
    assert debug_capture._size(3) is None
    assert debug_capture.payload_summary({"blob": b"abc"})["commands"]["blob"] == {"type": "bytes"}
