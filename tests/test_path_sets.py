from hst.path import _intervals, _subtract, _to_cidrs


def _s(*specs):
    return _intervals(list(specs))


def test_parses_addresses_prefixes_and_ranges():
    assert _to_cidrs(_s("192.168.1.5")) == ["192.168.1.5/32"]
    assert _to_cidrs(_s("192.168.1.0/24")) == ["192.168.1.0/24"]
    assert _to_cidrs(_s("192.168.1.4-192.168.1.7")) == ["192.168.1.4/30"]


def test_overlapping_specs_merge():
    merged = _s("10.0.0.0/24", "10.0.0.128/25", "10.0.1.0/24")
    assert _to_cidrs(merged) == ["10.0.0.0/23"]


def test_subtract_splits_a_network():
    rest = _subtract(_s("192.168.10.0/24"), _s("192.168.10.43", "192.168.10.44"))
    cidrs = _to_cidrs(rest)
    assert "192.168.10.43/32" not in cidrs and "192.168.10.44/32" not in cidrs
    assert "192.168.10.0/27" in cidrs  # the untouched head of the range
    total = sum(int(c.split("/")[1]) and 2 ** (32 - int(c.split("/")[1])) for c in cidrs)
    assert total == 254  # 256 minus the two removed hosts


def test_subtract_everything_is_empty():
    assert _subtract(_s("10.1.2.0/24"), _s("10.0.0.0/8")) == []


def test_disjoint_subtract_is_a_noop():
    left = _s("192.168.1.0/24")
    assert _subtract(left, _s("10.0.0.0/8")) == left


def test_ipv6_and_ipv4_do_not_mix():
    mixed = _s("192.168.1.0/24", "fd00::/64")
    assert _to_cidrs(_subtract(mixed, _s("192.168.1.0/24"))) == ["fd00::/64"]
