"""The `equinix` group of the query catalog, which the Equinix page opens in
Explore with the metro it shows."""

from __future__ import annotations

import ast
import re

from hst import queries, reasoner

EQUINIX = [q for q in queries.QUERIES if q["group"] == "equinix"]


def test_the_group_has_its_queries_and_each_takes_the_optional_metro():
    assert {q["key"] for q in EQUINIX} == {
        "equinix-fabric-ports",
        "equinix-unbound-ports",
        "equinix-circuits",
        "equinix-circuit-cables",
        "equinix-ended-circuits",
        "equinix-network-edge",
        "equinix-device-links",
    }
    for q in EQUINIX:
        assert [p["name"] for p in q["params"]] == ["metro"], q["key"]
        assert q["params"][0]["optional"] is True
        assert "$metro = ''" in q["cypher"], q["key"]


def test_each_query_draws_its_subgraph_in_explore():
    for q in EQUINIX:
        assert re.search(r"AS _\w+", q["cypher"]), q["key"]


def test_the_ended_states_are_the_reasoners():
    assert ast.literal_eval(queries._ENDED_CIRCUIT_STATES) == reasoner.ENDED_CIRCUIT_STATES
    for key in ("equinix-unbound-ports", "equinix-circuits", "equinix-ended-circuits"):
        cypher = next(q["cypher"] for q in EQUINIX if q["key"] == key)
        assert queries._ENDED_CIRCUIT_STATES in cypher, key
