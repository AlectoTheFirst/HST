from __future__ import annotations

from tests.enterprise.oracle import (
    apply,
    compose,
    enumerate_headers,
    freeze,
    intersect,
    project,
    rewrite,
    select,
    subtract,
    union,
)


def test_concrete_set_operations_have_literal_expected_members() -> None:
    universe = enumerate_headers({"protocol": [6, 17], "port": [53, 80]})
    tcp = select(universe, lambda packet: packet["protocol"] == 6)
    dns = select(universe, lambda packet: packet["port"] == 53)
    assert intersect(tcp, dns) == frozenset({freeze({"protocol": 6, "port": 53})})
    assert subtract(tcp, dns) == frozenset({freeze({"protocol": 6, "port": 80})})
    assert union(tcp, dns) == frozenset(
        {
            freeze({"protocol": 6, "port": 53}),
            freeze({"protocol": 6, "port": 80}),
            freeze({"protocol": 17, "port": 53}),
        }
    )


def test_projection_deduplicates_and_rewrite_composition_is_ordered() -> None:
    packets = enumerate_headers({"source": [1, 2], "port": [80, 443]})
    assert project(packets, ["port"]) == frozenset({freeze({"port": 80}), freeze({"port": 443})})
    assert rewrite(packets, {"source": 9}) == frozenset(
        {freeze({"source": 9, "port": 80}), freeze({"source": 9, "port": 443})}
    )

    def add_one(header):
        return {**header, "source": header["source"] + 1}

    def double(header):
        return {**header, "source": header["source"] * 2}

    one = frozenset({freeze({"source": 1, "port": 80})})
    assert apply(one, compose(add_one, double)) == frozenset({freeze({"source": 4, "port": 80})})
    assert apply(one, compose(double, add_one)) == frozenset({freeze({"source": 3, "port": 80})})
