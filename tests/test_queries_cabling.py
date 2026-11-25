"""The Cabling query roots the Explore result tree at the device."""

from __future__ import annotations

from hst.queries import QUERIES


def test_the_cabling_query_returns_the_device_as_its_first_graph_column():
    cypher = next(q["cypher"] for q in QUERIES if q["key"] == "cabling")
    graph_columns = [
        part.split(" AS ")[1] for part in cypher.split("RETURN", 1)[1].split(",") if " AS _" in part
    ]
    assert graph_columns[0].strip() == "_da"
    assert graph_columns.index("_a") < graph_columns.index("_b")
