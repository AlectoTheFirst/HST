"""The vendor keys of the catalog: every vendor entry names a known product,
every presence label is registered, and an entry that reads a vendor label
carries a product unless it is listed as exempt."""

from __future__ import annotations

import re

from hst.core.labels import LABELS
from hst.demo import SCENARIOS
from hst.queries import PRODUCT_LABELS, PRODUCT_PLATFORMS, catalog, presence_cypher

VENDOR_LABEL = re.compile(r":(Zpa\w+|Zia\w+|Sdwan\w+|ZscalerDc|FabricPort|VirtualCircuit)\b")
# Reads the vendor labels in an OPTIONAL MATCH only, so it answers without them.
EXEMPT = {"scenario-dora-providers"}


def test_every_vendor_entry_names_a_known_product():
    for entry in catalog():
        prefix = entry["key"].split("-", 1)[0]
        if prefix in PRODUCT_LABELS:
            assert entry.get("requires") == prefix, entry["key"]
        if "requires" in entry:
            assert entry["requires"] in PRODUCT_LABELS, entry["key"]


def test_the_three_vendor_scenarios_carry_their_product():
    wanted = {"sdwan-steering": "sdwan", "zia-guest-egress": "zia", "equinix-fabric-circuit": "equinix"}
    found = {sc["key"]: sc.get("requires") for sc in SCENARIOS if sc["key"] in wanted}
    assert found == wanted


def test_every_presence_label_is_registered():
    for labels in PRODUCT_LABELS.values():
        for label in labels:
            assert label in LABELS, label
    assert set(PRODUCT_PLATFORMS) <= set(PRODUCT_LABELS)
    assert "WanLink" not in PRODUCT_LABELS["sdwan"]


def test_an_entry_that_reads_a_vendor_label_carries_a_product():
    loose = [
        entry["key"]
        for entry in catalog()
        if VENDOR_LABEL.search(entry["cypher"]) and "requires" not in entry and entry["key"] not in EXEMPT
    ]
    assert loose == []


def test_the_presence_statement_has_one_column_per_product():
    cypher = presence_cypher()
    assert cypher.startswith("RETURN ")
    for product in PRODUCT_LABELS:
        assert f" AS {product}" in cypher
    assert "$snap" in cypher and "WanLink" not in cypher
