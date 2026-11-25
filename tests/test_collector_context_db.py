"""Run the collector/evaluator context contract against the scratch Neo4j in CI."""

import pytest
from tests.test_integration_db import URI
from tests.test_integration_db import _driver as _driver
from tests.test_integration_db import session as session
from tests.test_vyos import _batch

from hst.app import simul_read
from hst.core.loader import load
from hst.path.gates.coverage import strict_gate_coverage
from hst.path.session import CycleSession
from hst.queries import RESOLVE_CONTEXT_QUERY

pytestmark = [pytest.mark.db, pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")]
CTS = 3_800_000_000_000
DEVICE = "dev:gw"
TABLE = f"vrf:{DEVICE}:table100"


def test_normalized_vyos_zone_policies_pass_coverage_preflight(session):
    load(session, _batch(), ts_ms=CTS, collection_ts=CTS, run_id="context-contract")
    pinned = CycleSession(session, CTS)
    result = strict_gate_coverage(
        pinned,
        DEVICE,
        stage="forward",
        in_interface_uid=f"{DEVICE}/if/eth1",
        out_interface_uid=None,
        evaluated_ids=(),
        composed_kinds={"FwRulebase", "PbrPolicy", "NatRule"},
        preflight=True,
    )
    assert not result.unknowns


def test_policy_table_reads_device_keyed_observations_without_interfaces(session):
    load(session, _batch(), ts_ms=CTS, collection_ts=CTS, run_id="context-contract")
    calls = []

    class Observations:
        def overlapping(self, device, context, *args, **kwargs):
            calls.append((device, context))
            return []

        def coverage(self, device):
            return "complete"

    result = simul_read.read_rib_input(
        CycleSession(session, CTS), devices=[DEVICE], rib_source=Observations()
    )
    table = next(c for c in result.input.contexts if c["uid"] == TABLE)
    assert table["device_uid"] == DEVICE
    assert table["platform"] == "vyos"
    assert (DEVICE, TABLE) in calls
    assert not any(e["kind"] == "context-has-no-device" for e in result.errors.as_dicts())
    resolved = session.run(RESOLVE_CONTEXT_QUERY, snap=CTS, name="table100", domain=None).data()
    assert resolved[0]["devices"] == [DEVICE]


def test_context_read_preserves_ambiguity_and_ignores_retired_or_other_snapshot_owners(session):
    load(session, _batch(), ts_ms=CTS, collection_ts=CTS, run_id="context-contract")
    # All synthetic records use a scope cleaned by the shared scratch fixture.
    session.run(
        """
      MATCH (v:VrfInstance {uid: $table, collection_ts: $snap})
      CREATE (other:Obj:Device {uid: 'context-other', platform: 'iosxe', collection_ts: $snap,
                           _scope: 'fixture:mini-dc'})
      CREATE (v)-[:OWNED_BY]->(other)
      CREATE (old:Obj:Device {uid: 'context-old', collection_ts: $old_snap, _scope: 'fixture:mini-dc'})
      CREATE (v)-[:OWNED_BY]->(old)
      CREATE (retired:Obj:Device {uid: 'context-retired', collection_ts: $snap, _scope: 'fixture:mini-dc'})
      CREATE (v)-[:OWNED_BY {_retired_at: $snap}]->(retired)
    """,
        table=TABLE,
        snap=CTS,
        old_snap=CTS - 1,
    ).consume()
    rows = session.run(simul_read._CONTEXTS, vrfs=[TABLE], snap=CTS).data()
    assert set(rows[0]["device_uids"]) == {DEVICE, "context-other"}
    result = simul_read.read_rib_input(CycleSession(session, CTS), contexts=[TABLE])
    table = next(c for c in result.input.contexts if c["uid"] == TABLE)
    assert table["device_uid"] is None
    assert any(e["kind"] == "context-observation-ambiguous" for e in result.errors.as_dicts())


def test_bgp_only_context_is_seeded_and_keeps_its_platform(session):
    load(session, _batch(), ts_ms=CTS, collection_ts=CTS, run_id="context-contract")
    session.run(
        """
      MATCH (v:VrfInstance {uid: $table, collection_ts: $snap})
      CREATE (rp:Obj:RoutingProcess {uid: 'context-bgp', proto: 'bgp', collection_ts: $snap,
                                _scope: 'fixture:mini-dc'})
      CREATE (rp)-[:IN_VRF]->(v)
    """,
        table=TABLE,
        snap=CTS,
    ).consume()
    seeds = session.run(simul_read._SEED_BY_DEVICE, dev=DEVICE, snap=CTS).data()
    assert {r["uid"] for r in seeds} >= {"context-bgp"}
    processes = session.run(simul_read._PROCESSES, procs=["context-bgp"], snap=CTS).data()
    assert processes[0]["platforms"] == ["vyos"]


@pytest.mark.parametrize("name,expected", [("default", [DEVICE]), ("table100", [])])
def test_missing_explicit_owner_retains_interface_evidence_or_reports_unknown(session, name, expected):
    load(session, _batch(), ts_ms=CTS, collection_ts=CTS, run_id="context-contract")
    context = f"vrf:{DEVICE}:{name}"
    session.run(
        "MATCH (v:VrfInstance {uid: $context, collection_ts: $snap})-[o:OWNED_BY]->() "
        "SET o._retired_at = $snap",
        context=context,
        snap=CTS,
    ).consume()
    rows = session.run(simul_read._CONTEXTS, vrfs=[context], snap=CTS).data()
    assert len(rows) == 1
    assert rows[0]["device_uids"] == expected
    resolved = session.run(RESOLVE_CONTEXT_QUERY, snap=CTS, name=name, domain=None).data()
    assert resolved[0]["devices"] == expected
