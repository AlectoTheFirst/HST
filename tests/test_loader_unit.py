"""Loader unit tests against a fake session (no Neo4j needed)."""

from pathlib import Path

import pytest

from hst.core.fixtures import load_fixture
from hst.core.loader import load, node_upsert_query, rel_upsert_query

FIXTURE = Path(__file__).parents[1] / "fixtures" / "mini-dc.yaml"


class FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def data(self):
        return self._rows

    def consume(self):
        return None


class FakeSession:
    """Simulates first-contact loads: every node/rel is new, nothing is stale."""

    def __init__(self, owned=0, stale=0, owned_rels=0, stale_rels=0):
        self.queries = []
        self.owned = owned
        self.stale = stale
        self.owned_rels = owned_rels
        self.stale_rels = stale_rels

    def execute_write(self, work):
        # loader.load runs each statement in a managed transaction; the fake session
        # doubles as its own tx.
        return work(self)

    def run(self, q, **p):
        self.queries.append((q, p))
        ts = p.get("ts")
        if "UNWIND $rows" in q and "MERGE (n" in q:
            return FakeResult(
                [
                    {
                        "uid": r["uid"],
                        "before": {},
                        "after": {**r["props"], "_first_seen": ts, "_last_seen": ts},
                    }
                    for r in p["rows"]
                ]
            )
        if "MERGE (a)-" in q:
            return FakeResult(
                [
                    {
                        "start": r["start"],
                        "end": r["end"],
                        "before": {},
                        "after": {"_first_seen": ts, "_last_seen": ts},
                    }
                    for r in p["rows"]
                ]
            )
        if "n._last_seen < $ts" in q and "RETURN count(n) AS c" in q:
            return FakeResult([{"c": self.stale}])
        if "RETURN count(n) AS c" in q:
            return FakeResult([{"c": self.owned}])
        if "r._last_seen < $ts" in q and "RETURN count(r) AS c" in q:
            return FakeResult([{"c": self.stale_rels}])
        if "RETURN count(r) AS c" in q:
            return FakeResult([{"c": self.owned_rels}])
        return FakeResult([])


def test_full_fixture_first_load():
    batch = load_fixture(FIXTURE)
    s = FakeSession()
    manifest = load(s, batch, ts_ms=1_000)
    assert manifest.nodes_upserted == len(batch.nodes)
    assert manifest.nodes_created == len(batch.nodes)
    assert manifest.rels_created == len(batch.rels)
    assert manifest.rels_dropped_missing_endpoint == 0
    assert not manifest.retirement_skipped


def test_gate_labels_written():
    batch = load_fixture(FIXTURE)
    s = FakeSession()
    load(s, batch, ts_ms=1_000)
    node_queries = [q for q, _ in s.queries if "MERGE (n" in q]
    assert any(":Obj:Contract:Policy:Gate" in q for q in node_queries)
    assert any(":Obj:PbrPolicy:Policy:Gate" in q for q in node_queries)
    assert any(":Obj:Device:Phys" in q for q in node_queries)


def test_unknown_label_raises_before_touching_db():
    with pytest.raises(ValueError):
        node_upsert_query("Switcheroo")


def test_rel_key_in_merge_pattern():
    q = rel_upsert_query("SWITCHES", ("vid",))
    assert "MERGE (a)-[r:SWITCHES {vid: row.key.vid}]->(b)" in q
    q2 = rel_upsert_query("CONNECTED_TO", ())
    assert "MERGE (a)-[r:CONNECTED_TO]->(b)" in q2


def test_rel_key_names_that_are_not_identifiers_are_rejected():
    """rel_upsert_query cannot parameterize key names."""
    from hst.core.model import Batch

    batch = Batch.model_validate(
        {
            "source": "t",
            "scope": "t:1",
            "rels": [
                {
                    "type": "BOUND_TO",
                    "start": ["Interface", "if:x"],
                    "end": ["VlanInstance", "vlan:x"],
                    "key": {"vid: 1}]->(b) DELETE b //": 1},
                }
            ],
        }
    )
    with pytest.raises(ValueError, match="invalid rel key name"):
        batch.validate_registry()

    ok = Batch.model_validate(
        {
            "source": "t",
            "scope": "t:1",
            "rels": [
                {
                    "type": "BOUND_TO",
                    "start": ["Interface", "if:x"],
                    "end": ["VlanInstance", "vlan:x"],
                    "key": {"vid": 10},
                }
            ],
        }
    )
    ok.validate_registry()


class DroppingSession(FakeSession):
    """Returns one fewer row for rel merges, as if an endpoint was missing."""

    def execute_write(self, work):
        # loader.load runs each statement in a managed transaction; the fake session
        # doubles as its own tx.
        return work(self)

    def run(self, q, **p):
        if "MERGE (a)-" in q:
            self.queries.append((q, p))
            ts = p.get("ts")
            rows = p["rows"][1:]  # first row's endpoint "missing"
            return FakeResult(
                [
                    {"start": r["start"], "end": r["end"], "before": {}, "after": {"_first_seen": ts}}
                    for r in rows
                ]
            )
        return super().run(q, **p)


def test_missing_endpoints_are_surfaced_not_silent():
    batch = load_fixture(FIXTURE)
    s = DroppingSession()
    manifest = load(s, batch, ts_ms=1_000)
    assert manifest.rels_dropped_missing_endpoint > 0
    assert any("dropped" in e for e in manifest.errors)


# --- cycle model ------------------------------------------------------------------------
# A cycle re-creates its objects under (uid, collection_ts).


def test_merge_key_is_uid_plus_collection_ts():
    q = node_upsert_query("Device")
    assert "{uid: row.uid, collection_ts: $cts}" in q
    rq = rel_upsert_query("ON", ())
    assert "MATCH (a:Obj {uid: row.start, collection_ts: $cts})" in rq
    assert "(b:Obj {uid: row.end, collection_ts: $cts})" in rq


def test_fresh_writes_stamp_the_cycle_and_clear_carried():
    q = node_upsert_query("Device")
    assert "n.collected_at = $ts" in q and "n.carried = false" in q
    rq = rel_upsert_query("ON", ())
    assert "r.collection_ts = $cts" in rq and "r.carried = false" in rq


def test_fresh_writes_clear_the_carry_stamps():
    for q in (node_upsert_query("Device"), rel_upsert_query("ON", ())):
        prefix = q.split(".carried = false")[0].rsplit("SET", 1)[-1]
        assert ".carried_reason = null" in q and ".last_seen_ts = null" in q
        # stamps are cleared after `+= row.props`, so a source cannot re-set them either way
        assert q.index("+= ") < q.index(".carried_reason = null") or prefix


def test_load_passes_collection_ts_to_every_statement():
    batch = load_fixture(FIXTURE)
    s = FakeSession()
    load(s, batch, ts_ms=1_000, collection_ts=42)
    upserts = [p for q, p in s.queries if "UNWIND $rows" in q]
    assert upserts and all(p["cts"] == 42 for p in upserts)


def test_load_defaults_collection_ts_to_the_run_timestamp():
    batch = load_fixture(FIXTURE)
    s = FakeSession()
    load(s, batch, ts_ms=1_000)
    upserts = [p for q, p in s.queries if "UNWIND $rows" in q]
    assert upserts and all(p["cts"] == 1_000 for p in upserts)


def test_write_run_stamps_the_meta_node_with_snapshot_ts_not_collection_ts():
    """The :CollectionRun:Meta node records the run's collection_ts as `snapshot_ts`."""
    from hst.core.loader import WRITE_RUN

    assert "r.snapshot_ts = $cts" in WRITE_RUN
    assert "r.collection_ts" not in WRITE_RUN


def test_the_run_meta_write_carries_the_loads_own_collection_ts_as_snapshot_ts():
    batch = load_fixture(FIXTURE)
    s = FakeSession()
    load(s, batch, ts_ms=1_000, collection_ts=42)
    run_writes = [p for q, p in s.queries if "CollectionRun" in q]
    assert run_writes and all(p["cts"] == 42 for p in run_writes)


def test_the_run_meta_write_carries_the_batchs_section_outcomes():
    """The outcomes land as sorted `<section>=<status>` strings."""
    from hst.core.model import SectionOutcome

    batch = load_fixture(FIXTURE)
    batch.sections = {
        "rib": SectionOutcome(status="ok", row_count=3),
        "arp": SectionOutcome(status="failed", detail="'show ip arp' exited 1"),
    }
    s = FakeSession()
    manifest = load(s, batch, ts_ms=1_000, collection_ts=42)
    (run_props,) = [p["props"] for q, p in s.queries if "CollectionRun" in q]
    assert run_props["sections"] == ["arp=failed", "rib=ok"]
    assert manifest.sections["arp"].detail == "'show ip arp' exited 1"


def test_a_batch_with_no_section_outcomes_writes_an_empty_section_list():
    batch = load_fixture(FIXTURE)
    s = FakeSession()
    load(s, batch, ts_ms=1_000)
    (run_props,) = [p["props"] for q, p in s.queries if "CollectionRun" in q]
    assert run_props["sections"] == []


def test_no_retirement_statements_are_issued():
    batch = load_fixture(FIXTURE)
    s = FakeSession()
    load(s, batch, ts_ms=1_000)
    assert not [q for q, _ in s.queries if "_retired_at" in q or ":Retired" in q]


def test_payload_props_may_not_shadow_bookkeeping():
    import pytest as _pytest

    from hst.core.model import Batch

    with _pytest.raises(ValueError, match="reserved"):
        Batch.model_validate(
            {
                "source": "t",
                "scope": "t:1",
                "nodes": [{"label": "Site", "uid": "site:x", "props": {"_scope": "evil"}}],
            }
        )
    # vendor fields that resemble bookkeeping (ACI contract `scope`) are accepted
    Batch.model_validate(
        {
            "source": "t",
            "scope": "t:1",
            "nodes": [{"label": "Contract", "uid": "aci:f:c1", "props": {"scope": "context"}}],
        }
    )


# --- source assertions and materialization precedence ------------------------------------
# Two deployed collectors can write one uid in one cycle.


class MergingSession(FakeSession):
    """Keeps node state across loads."""

    def __init__(self):
        super().__init__()
        self.nodes: dict[tuple[str, int], dict] = {}

    def run(self, q, **p):
        self.queries.append((q, p))
        if "UNWIND $rows" in q and "MERGE (n" in q:
            rows = []
            for r in p["rows"]:
                node = self.nodes.setdefault(
                    (r["uid"], p["cts"]), {"uid": r["uid"], "collection_ts": p["cts"]}
                )
                before = dict(node)
                node.update(r["props"])
                node["collected_at"] = p["ts"]
                node["carried"] = False
                node["_run_id"] = p["run_id"]
                node.setdefault("_scope", p["scope"])
                sources = node.get("_sources") or []
                if p["source"] not in sources:
                    node["_sources"] = [*sources, p["source"]]
                rows.append({"uid": r["uid"], "before": before, "after": dict(node)})
            return FakeResult(rows)
        if "MATCH (n:Obj {uid: row.uid, collection_ts: $cts})" in q:
            for r in p["rows"]:
                self.nodes[(r["uid"], p["cts"])].update(r["props"])
            return FakeResult([])
        if "MERGE (a)-" in q:
            return FakeResult(
                [{"start": r["start"], "end": r["end"], "before": {}, "after": {}} for r in p["rows"]]
            )
        return FakeResult([])


# The two collectors' own words for one ACI leaf, trimmed to the overlapping
# fields plus one field each that only its own source knows.
APIC_LEAF = {
    "hostname": "leaf-101",
    "role": "leaf",
    "platform": "aci-leaf",
    "os_version": "n9000-15.2(7)",
    "serial": "FDO123",
    "dn": "topology/pod-1/node-101",
}
NXOS_LEAF = {
    "hostname": "leaf-101",
    "role": "router",
    "platform": "nxos",
    "os_version": "9.3(10)",
    "serial": "FDO123",
    "vendor": "cisco",
}


def _device_batch(collector: str, source: str, props: dict):
    """One device batch as a real run produces it: `source` is the inventory
    row's name, and the collector type appears only as the scope prefix."""
    from hst.core.model import Batch

    return Batch.model_validate(
        {
            "source": source,
            "scope": f"{collector}:leaf1",
            "nodes": [{"label": "Device", "uid": "dev:fdo123", "props": dict(props)}],
        }
    )


def _load_in_order(*loads: tuple[str, str, dict]) -> dict:
    s = MergingSession()
    for collector, source, props in loads:
        load(s, _device_batch(collector, source, props), ts_ms=1_000, collection_ts=42)
    return s.nodes[("dev:fdo123", 42)]


# (collector type, source row name) for the runs the tests load.
APIC = ("apic", "fab1")
NXOS = ("nxos", "dc1-leaves")
MANUAL = ("manual", "hand-entered")
# The reasoner does not go through the inventory, so its batch source stays
# "reasoner" while its scope is "derived:rt-domains" (core/reasoner.py).
REASONER = ("derived", "reasoner")


def _stored(node: dict) -> dict:
    """The node without the bookkeeping that records the load."""
    return {
        k: v
        for k, v in node.items()
        if k not in ("uid", "collection_ts", "collected_at", "carried", "_run_id", "_scope", "_sources")
    }


def test_two_sources_on_one_uid_converge_on_the_same_node_in_either_order():
    """The acceptance case: load the two batches both ways round. The effective
    values, and both sources' assertions, must come out identical."""
    forward = _load_in_order((*APIC, APIC_LEAF), (*NXOS, NXOS_LEAF))
    reverse = _load_in_order((*NXOS, NXOS_LEAF), (*APIC, APIC_LEAF))
    assert _stored(forward) == _stored(reverse)
    assert sorted(forward["_sources"]) == sorted(reverse["_sources"]) == ["dc1-leaves", "fab1"]


def test_the_observed_source_wins_the_fields_the_two_sources_disagree_on():
    for order in ((*APIC, APIC_LEAF), (*NXOS, NXOS_LEAF)), ((*NXOS, NXOS_LEAF), (*APIC, APIC_LEAF)):
        node = _load_in_order(*order)
        # the NX-OS collector is observed, the APIC one controller-configured
        assert node["role"] == "router"
        assert node["platform"] == "nxos"
        assert node["os_version"] == "9.3(10)"
        # agreed fields are untouched, and each source's own field survives
        assert node["hostname"] == "leaf-101"
        assert node["serial"] == "FDO123"
        assert node["dn"] == "topology/pod-1/node-101"
        assert node["vendor"] == "cisco"


def test_both_assertions_stay_recoverable_per_field():
    node = _load_in_order((*APIC, APIC_LEAF), (*NXOS, NXOS_LEAF))
    assert node["_assert.role"] == ['apic/fab1="leaf"', 'nxos/dc1-leaves="router"']
    assert node["_assert.platform"] == ['apic/fab1="aci-leaf"', 'nxos/dc1-leaves="nxos"']
    assert node["_assert.os_version"] == ['apic/fab1="n9000-15.2(7)"', 'nxos/dc1-leaves="9.3(10)"']
    assert node["_assert.hostname"] == ['apic/fab1="leaf-101"', 'nxos/dc1-leaves="leaf-101"']
    # and a field only one source knows records that one
    assert node["_assert.dn"] == ['apic/fab1="topology/pod-1/node-101"']
    assert node["_assert.vendor"] == ['nxos/dc1-leaves="cisco"']


def test_a_single_source_node_carries_no_assertion_properties():
    node = _load_in_order((*NXOS, NXOS_LEAF))
    assert not [k for k in node if k.startswith("_assert.")]
    # and re-loading the same source is not a conflict with itself
    again = _load_in_order((*NXOS, NXOS_LEAF), (*NXOS, NXOS_LEAF))
    assert not [k for k in again if k.startswith("_assert.")]


# --- the cycle-wide identity check ------------------------------------------------------
#
# `anchor_slug` folds `:` and `-` alike (core/uid.py), so `vrf:dev:a-b:c` and
# `vrf:dev:a:b-c` both key an address as `ip:vrf-dev-a-b-c:10.0.0.1`.


class AnchoredSession(MergingSession):
    """MergingSession plus the loader's pre-write anchor read: answers every
    uid the run already holds under a different anchor, as the graph would."""

    def run(self, q, **p):
        if "n.anchor <> row.anchor" in q:
            self.queries.append((q, p))
            hits = []
            for r in p["rows"]:
                node = self.nodes.get((r["uid"], p["cts"]))
                if node is None or node.get("carried") or node.get("anchor") is None:
                    continue
                if node["anchor"] != r["anchor"]:
                    hits.append({"uid": r["uid"], "prior": node["anchor"], "anchor": r["anchor"]})
            return FakeResult(hits)
        return super().run(q, **p)


def _ip_batch(device: str, anchor: str):
    from hst.core.model import Batch

    return Batch.model_validate(
        {
            "source": "dc1-leaves",
            "scope": f"nxos:{device}",
            "nodes": [
                {
                    "label": "IpAddress",
                    "uid": "ip:vrf-dev-a-b-c:10.0.0.1",
                    "props": {"ip": "10.0.0.1", "anchor": anchor},
                }
            ],
        }
    )


def test_two_batches_folding_two_anchors_onto_one_uid_are_rejected():
    """Device 1 writes the uid under one anchor; device 2's batch declares
    the same uid under the other. The second batch is rejected before any of
    its nodes is written, and the error names both anchors."""
    from hst.core.labels import CycleIdentityCollision

    s = AnchoredSession()
    load(s, _ip_batch("leaf1", "vrf:dev:a-b:c"), ts_ms=1_000, collection_ts=42)
    with pytest.raises(CycleIdentityCollision, match="one uid cannot name two objects") as excinfo:
        load(s, _ip_batch("leaf2", "vrf:dev:a:b-c"), ts_ms=1_001, collection_ts=42)

    assert "anchor='vrf:dev:a-b:c'" in str(excinfo.value)
    assert "anchor='vrf:dev:a:b-c'" in str(excinfo.value)
    # Nothing of the second batch landed.
    assert s.nodes[("ip:vrf-dev-a-b-c:10.0.0.1", 42)]["anchor"] == "vrf:dev:a-b:c"
    assert not any("MERGE (n" in q and p.get("scope") == "nxos:leaf2" for q, p in s.queries)


def test_the_same_anchor_from_two_batches_is_one_object():
    """The same address seen from two devices of one context (a shared VRF)
    is the same object: no collision, and both loads land."""
    s = AnchoredSession()
    load(s, _ip_batch("leaf1", "vrf:dev:a-b:c"), ts_ms=1_000, collection_ts=42)
    load(s, _ip_batch("leaf2", "vrf:dev:a-b:c"), ts_ms=1_001, collection_ts=42)
    assert s.nodes[("ip:vrf-dev-a-b-c:10.0.0.1", 42)]["anchor"] == "vrf:dev:a-b:c"


def test_the_anchor_check_runs_before_any_node_write_and_only_for_anchored_nodes():
    """The read precedes the first MERGE of the batch, and a batch with no
    anchored node issues no read at all."""
    s = AnchoredSession()
    load(s, _ip_batch("leaf1", "vrf:dev:a-b:c"), ts_ms=1_000, collection_ts=42)
    kinds = [
        "check" if "n.anchor <> row.anchor" in q else "merge" for q, _ in s.queries if "UNWIND $rows" in q
    ]
    assert kinds[:2] == ["check", "merge"]

    plain = AnchoredSession()
    load(plain, _device_batch("nxos", "dc1-leaves", NXOS_LEAF), ts_ms=1_000, collection_ts=42)
    assert not any("n.anchor <> row.anchor" in q for q, _ in plain.queries)


def test_a_carried_copy_under_another_anchor_does_not_collide():
    """A carried-forward node is the previous run's answer, and a fresh write
    is documented to win over it: the check skips it."""
    s = AnchoredSession()
    s.nodes[("ip:vrf-dev-a-b-c:10.0.0.1", 42)] = {
        "uid": "ip:vrf-dev-a-b-c:10.0.0.1",
        "collection_ts": 42,
        "anchor": "vrf:dev:a:b-c",
        "carried": True,
    }
    load(s, _ip_batch("leaf1", "vrf:dev:a-b:c"), ts_ms=1_000, collection_ts=42)
    assert s.nodes[("ip:vrf-dev-a-b-c:10.0.0.1", 42)]["anchor"] == "vrf:dev:a-b:c"


def test_a_derived_value_never_overwrites_a_collected_one():
    derived = (*REASONER, {**NXOS_LEAF, "role": "switch"})
    node = _load_in_order(derived, (*NXOS, NXOS_LEAF))
    assert node["role"] == "router"
    reverse = _load_in_order((*NXOS, NXOS_LEAF), derived)
    assert reverse["role"] == "router"
    assert reverse["_assert.role"] == ['derived/reasoner="switch"', 'nxos/dc1-leaves="router"']


def test_a_third_source_joins_the_assertions_it_did_not_write():
    node = _load_in_order(
        (*APIC, APIC_LEAF),
        (*NXOS, NXOS_LEAF),
        (*MANUAL, {"role": "leaf", "model": "N9K-C93180YC"}),
    )
    assert node["_assert.role"] == [
        'apic/fab1="leaf"',
        'manual/hand-entered="leaf"',
        'nxos/dc1-leaves="router"',
    ]
    assert node["_assert.dn"] == ['apic/fab1="topology/pod-1/node-101"']
    assert node["_assert.model"] == ['manual/hand-entered="N9K-C93180YC"']
    assert node["role"] == "router"


def test_classification_is_by_collector_type_and_not_by_the_source_row_name():
    """A source row is named by the deployment, for the fabric or fleet it
    stands for, and says nothing about authority. The collector type does, and
    it is the batch scope's prefix."""
    named_for_nothing = _load_in_order(("apic", "ord-fabric", APIC_LEAF), ("nxos", "ord-tor", NXOS_LEAF))
    assert named_for_nothing["role"] == "router"
    assert named_for_nothing["_assert.role"] == ['apic/ord-fabric="leaf"', 'nxos/ord-tor="router"']

    named_for_a_collector = _load_in_order(("apic", "nxos", APIC_LEAF), ("nxos", "vyos", NXOS_LEAF))
    assert named_for_a_collector["role"] == "router"
    assert named_for_a_collector["_assert.role"] == ['apic/nxos="leaf"', 'nxos/vyos="router"']


def test_the_collector_type_is_the_scope_prefix():
    from hst.core.loader import collector_type

    assert collector_type("nxos:leaf1") == "nxos"
    assert collector_type("iosxe:r1") == "iosxe"
    assert collector_type("apic:fab1") == "apic"
    assert collector_type("vyos:gw1") == "vyos"
    # a scope with more colons than one names its collector once
    assert collector_type("cp:fw.example.net:dom1") == "cp"
    assert collector_type("derived:rt-domains") == "derived"
    # a scope with no colon at all is its own collector type
    assert collector_type("reasoner") == "reasoner"


def test_the_assertion_pass_is_skipped_for_a_carried_forward_copy():
    """A carried copy is the previous cycle's answer, not an assertion made in
    this one, and core/cycle.py documents the fresh write as winning over it
    outright."""
    from hst.core.loader import assertion_props

    before = {"role": "leaf", "carried": True, "_sources": ["fab1"], "_scope": "apic:leaf1"}
    assert assertion_props("Device", "nxos", "dc1-leaves", before, {"role": "router"}) == {}


def test_precedence_is_by_collector_class_then_collector_type_then_row_name():
    from hst.core.loader import effective_value

    # observed over configured over derived, whatever order they are given in
    assert effective_value("Device", ['derived/reasoner="a"', 'apic/fab1="b"', 'nxos/tor="c"']) == "c"
    assert effective_value("Device", ['derived/reasoner="a"', 'apic/fab1="b"']) == "b"
    assert effective_value("Device", ['derived/reasoner="a"']) == "a"
    # a tie inside one class breaks on the collector type and then the row
    # name, so the answer never depends on the load order
    assert effective_value("Device", ['vyos/gw1="a"', 'nxos/tor="b"']) == "b"
    assert effective_value("Device", ['nxos/tor="b"', 'vyos/gw1="a"']) == "b"
    assert effective_value("Device", ['nxos/zz="a"', 'nxos/aa="b"']) == "b"
    # a row named after a collector is not ranked as that collector
    assert effective_value("Device", ['apic/nxos="b"', 'nxos/apic="c"']) == "c"
    # a collector type the table does not name counts as configured
    assert effective_value("Device", ['newthing/row1="a"', 'nxos/tor="c"']) == "c"
    assert effective_value("Device", ['newthing/row1="a"', 'derived/reasoner="z"']) == "a"
    # a label with no row in the table falls back to the default order
    assert effective_value("Lag", ['apic/fab1="b"', 'nxos/tor="c"']) == "c"


def test_assertion_values_round_trip_through_their_encoding():
    from hst.core.loader import decode_assertion, encode_assertion

    for value in ("9.3(10)", 1500, True, None, ["leaf-101", "leaf-101.example.net"]):
        assert decode_assertion(encode_assertion("nxos", "dc1-leaves", value)) == (
            "nxos",
            "dc1-leaves",
            value,
        )
    # a non-JSON value reads back as its own text and does not raise
    assert decode_assertion("nxos/dc1-leaves=leaf-101") == ("nxos", "dc1-leaves", "leaf-101")
    # and a head with no collector type reads as a row of unknown collector
    assert decode_assertion('dc1-leaves="leaf-101"') == ("", "dc1-leaves", "leaf-101")
