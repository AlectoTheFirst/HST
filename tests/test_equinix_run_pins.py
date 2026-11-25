"""The Equinix route and catalog read only the pinned run: every Network Edge
device lookup names the run, and the cabled flag reads the link of the pinned
run from the circuit's A end."""

from __future__ import annotations

from hst import queries
from hst.app.routes import equinix as route
from hst.core.db import CONSTRAINT_STATEMENTS


def _cypher(key: str) -> str:
    return next(q["cypher"] for q in queries.QUERIES if q["key"] == key)


def test_every_network_edge_device_lookup_names_the_run():
    texts = {
        "route._CIRCUITS": route._CIRCUITS,
        "_END_METRO": queries._END_METRO.format(e="a"),
        "_END_NAME": queries._END_NAME.format(e="a"),
        "equinix-device-links": _cypher("equinix-device-links"),
        "equinix-network-edge": _cypher("equinix-network-edge"),
    }
    unpinned = []
    for name, text in texts.items():
        pieces = text.split("MATCH")[1:]
        looked_up = [p for p in pieces if "edge_device_uid" in p]
        assert looked_up, name
        unpinned += [(name, p.strip()) for p in looked_up if "collection_ts" not in p]
    assert unpinned == []


def test_the_interface_edge_device_index_is_declared():
    assert (
        "CREATE INDEX interface_edge_device_uid IF NOT EXISTS FOR (n:Interface) ON (n.edge_device_uid)"
        in CONSTRAINT_STATEMENTS
    )


def test_the_cabled_flag_is_anchored_on_the_a_end_and_pinned():
    assert "(vc)-[:A_END]->" in queries.CIRCUIT_CABLED
    assert "c.collection_ts = $snap" in queries.CIRCUIT_CABLED
    for text in (route._CIRCUITS, _cypher("equinix-circuits"), _cypher("equinix-device-links")):
        assert queries.CIRCUIT_CABLED in text
        assert "MATCH (:Port)-[c:CONNECTED_TO" not in text
