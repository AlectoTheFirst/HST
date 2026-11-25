"""The tier fold on the fixtures loaded as 3 runs, against a scratch Neo4j."""

import itertools
from typing import Any

import pytest
from tests.hst.conftest import drop_runs, fixture_batches, load_runs

from hst.core import manifest as manifestmod
from hst.core.model import Batch
from hst.map.tiers import bindings, bootstrap
from hst.map.tiers import delta as deltamod
from hst.map.tiers.fold import (
    CARRIED,
    NOT_OBSERVED,
    TIER_TABLES,
    Attribution,
    Folded,
    Parent,
    differences,
    fold,
)
from hst.map.tiers.schemas import DELTA_OF, key_of

RUNS = (4_300_000_000_000, 4_300_000_060_000, 4_300_000_120_000)
GONE = "dev:fra01-ips-01"
TOUCHED = "dev:fra01-core-02"
RULE = "fgt:FGT60F0000000001:root:policy:2"
CARRIED_DEVICE = "dev:leaf102"
POLICY = ("FwRulebase", "FwRule", "NatRule", "PbrPolicy")

pytestmark = pytest.mark.db


def _edit(batch: Batch) -> None:
    batch.nodes = [n for n in batch.nodes if n.uid not in (GONE, RULE)]
    batch.rels = [r for r in batch.rels if not {GONE, RULE} & {r.start_uid, r.end_uid}]
    for node in batch.nodes:
        if node.uid == TOUCHED:
            node.props = {**node.props, "serial": "FDO22229999"}


def _as_parent(key: int, folded: Folded) -> Parent:
    parent = Parent(key)
    parent.tables = {name: {key_of(name, r): dict(r) for r in folded.tables[name]} for name in TIER_TABLES}
    parent.bindings = folded.bindings
    return parent


@pytest.fixture(scope="module")
def runs(neo4j_session: Any) -> Any:
    session = neo4j_session
    load_runs(session, RUNS, lambda run: fixture_batches(_edit if run == 1 else None))
    session.run(
        "MATCH (d:Device {uid: $uid, collection_ts: $cts}) "
        "SET d.carried = true, d.carried_reason = 'not fetched'",
        uid=CARRIED_DEVICE,
        cts=RUNS[2],
    ).consume()
    first = fold(session, RUNS[0], Parent(None), None)
    folded, full, attributions = [first], [first], []
    for i, (parent_key, key) in enumerate(itertools.pairwise(RUNS)):
        parent = _as_parent(parent_key, folded[i])
        attribution = Attribution(parent.tables["render_t1"], parent.groups())
        manifestmod.graph_delta(session, parent_key, key, observer=attribution.observe)
        attribution.resolve(bootstrap.device_rows(session, key), parent.bindings)
        folded.append(fold(session, key, parent, attribution.affected))
        full.append(fold(session, key, parent, None))
        attributions.append(attribution)
    yield folded, full, attributions
    drop_runs(session, RUNS)


def test_the_fold_equals_the_bootstrap_on_every_run(runs: Any) -> None:
    folded, full, _ = runs
    for i in range(len(RUNS)):
        assert differences(folded[i], full[i]) == [], i
        for name in TIER_TABLES:
            assert folded[i].tables[name] == full[i].tables[name], (i, name)


def test_the_fold_reads_only_the_devices_the_delta_touched(runs: Any) -> None:
    folded, full, attributions = runs
    assert folded[1].read_devices < full[1].read_devices
    assert {GONE, TOUCHED, "dev:fra01-fgt-01"} <= attributions[0].affected
    assert CARRIED_DEVICE not in attributions[0].affected


def test_every_delta_is_invertible(runs: Any) -> None:
    folded, _, _ = runs
    for before, after in itertools.pairwise(folded):
        for name in TIER_TABLES:
            rows = [d for d in after.deltas[DELTA_OF[name]] if d["table"] == name]
            old = {key_of(name, r): dict(r) for r in before.tables[name]}
            new = {key_of(name, r): dict(r) for r in after.tables[name]}
            forward = {k: dict(v) for k, v in old.items()}
            deltamod.apply(forward, rows)
            assert _strip(forward) == _strip(new), name
            backward = {k: dict(v) for k, v in new.items()}
            deltamod.apply(backward, rows, inverse=True)
            assert _strip(backward) == _strip(old), name


def _strip(rows: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {k: {c: v for c, v in r.items() if c != "snapshot_ts"} for k, r in rows.items()}


def test_a_carried_device_is_not_observed(runs: Any) -> None:
    folded, _, _ = runs
    row = next(r for r in folded[2].tables["render_t1"] if r["uid"] == CARRIED_DEVICE)
    assert (row["status"], row["change"]) == (CARRIED, NOT_OBSERVED)
    t0 = {r["uid"]: r for r in folded[2].tables["render_t0"]}
    assert t0[row["block_uid"]]["carried_count"] == 1


def test_the_removed_device_and_rule_show_in_the_counts_and_markers(runs: Any) -> None:
    folded, _, _ = runs
    t1 = {r["uid"]: r for r in folded[1].tables["render_t1"]}
    assert GONE not in t1
    assert folded[1].counts["removed"] == 1
    assert t1[TOUCHED]["change"] == "none"
    fgt = {r["uid"]: r for r in folded[0].tables["render_t1"]}["dev:fra01-fgt-01"]
    assert t1["dev:fra01-fgt-01"]["n_rules"] == fgt["n_rules"] - 1
    assert t1["dev:fra01-fgt-01"]["change"] == "changed"
    back = {r["uid"]: r for r in folded[2].tables["render_t1"]}
    assert back[GONE]["change"] == "added"


def test_every_bound_policy_object_attributes_to_its_device(runs: Any) -> None:
    folded, _, _ = runs
    first = folded[0]
    policy = {b["object_uid"]: b["device_uid"] for b in first.bindings.to_pylist() if b["label"] in POLICY}
    nodes = {n.uid: n.label for batch in fixture_batches() for n in batch.nodes if n.label in POLICY}
    attribution = Attribution({r["uid"] for r in first.tables["render_t1"]}, {})
    for uid in nodes:
        attribution.pending.add(uid)
    resolved = attribution.resolve([], first.bindings)
    bound = {uid for uid in nodes if uid in policy}
    assert bound <= set(resolved)
    assert all(
        resolved[uid] in {b["device_uid"] for b in first.bindings.to_pylist() if b["object_uid"] == uid}
        for uid in bound
    )
    unbound = sorted((nodes[uid], uid) for uid in nodes if uid not in policy)
    assert [label for label, _uid in unbound] == [
        "FwRule",
        "FwRule",
        "FwRulebase",
        "FwRulebase",
        "PbrPolicy",
    ], unbound
    assert bindings.device_of("dev:leaf101/port/eth1-1", {"dev:leaf101"}) == "dev:leaf101"


def test_the_fold_writes_the_fabric_device_its_ports_the_cross_connect_and_the_circuit(runs: Any) -> None:
    first = runs[0][0]
    t1 = {r["uid"]: r for r in first.tables["render_t1"]}
    # A bound Fabric port sits in the site of its device, an unbound one in its LOCATED_IN site.
    assert t1["eqx:ibx:eqx-fr2:unknown"]["site_uid"] == "site:eqx-fr2"
    ports = {r["uid"]: r for r in first.tables["render_t2_ports"]}
    assert ports["eqx:port:fr2-00000000-0000-0001"]["device_uid"] == "eqx:ibx:eqx-fr2:unknown"
    assert ports["eqx:port:pa3-00000000-0000-0001"]["device_uid"] == "eqx:ibx:eqx-pa3:unknown"
    cross = {
        frozenset((c["a_port"], c["b_port"]))
        for c in first.tables["render_t2_cables"]
        if c["source"] == "equinix-cross-connect"
    }
    assert frozenset(("dev:fr2-ext-01/port/eth1-49", "eqx:port:fr2-00000000-0000-0001")) in cross
    circuit = {r["uid"]: r for r in first.tables["render_t1_circuits"]}["eqx:vc:fr2-pa3-00000000-0001"]
    assert (circuit["a_device"], circuit["a_port"], circuit["a_vlan"]) == (
        "eqx:ibx:eqx-fr2:unknown",
        "eqx:port:fr2-00000000-0000-0001",
        "100",
    )
    assert (circuit["z_device"], circuit["z_port"]) == (
        "eqx:ibx:eqx-pa3:unknown",
        "eqx:port:pa3-00000000-0000-0001",
    )
    fabric_ports = {r["uid"]: r for r in first.tables["render_t1_fabric_ports"]}
    bound = fabric_ports["eqx:port:fr2-00000000-0000-0001"]
    assert (bound["bound_by"], bound["port_uid"], bound["port_device"]) == (
        "operator",
        "dev:fr2-ext-01/port/eth1-49",
        "dev:fr2-ext-01",
    )
