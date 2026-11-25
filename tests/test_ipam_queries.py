"""The IPAdmin register queries read only the register properties the step writes."""

from __future__ import annotations

import re

from hst.core import ipam
from hst.queries import QUERIES


def test_the_register_queries_read_only_register_properties():
    by_key = {q["key"]: q for q in QUERIES}
    for key in ("ipam-register", "ipam-vlan-mismatch"):
        cypher = by_key[key]["cypher"]
        assert "$snap" in cypher, key
        names = set(re.findall(r"\b(ipam_\w+)\b", cypher))
        assert names and names <= set(ipam.PROPS), (key, names - set(ipam.PROPS))
    prefixes = by_key["prefixes"]["cypher"]
    assert "AS register," in prefixes and "AS register_vlan" in prefixes
