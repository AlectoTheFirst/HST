import pytest
from tests.test_integration_db import URI
from tests.test_integration_db import _driver as _driver
from tests.test_integration_db import session as session
from tests.test_vyos import _add_pppoe0, _rib_batch

from hst.app import simul_read
from hst.core.loader import load
from hst.path.session import CycleSession

pytestmark = [pytest.mark.db, pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")]
CTS = 3_800_000_000_000


def test_normalized_pppoe_default_producer_is_read_without_an_observed_address(session):
    batch = _rib_batch(cfg_patch=_add_pppoe0)
    load(session, batch, ts_ms=CTS, collection_ts=CTS, run_id="access-default-contract")
    result = simul_read.read_rib_input(CycleSession(session, CTS), devices=["dev:gw"])
    assert {
        "context_uid": "vrf:dev:gw:default",
        "device_uid": "dev:gw",
        "interface": "pppoe0",
        "origin": "pppoe",
    } in result.input.access_defaults

    session.run(
        "MATCH (i:Interface {uid: $uid, collection_ts: $snap}) SET i:Retired",
        uid="dev:gw/if/pppoe0",
        snap=CTS,
    ).consume()
    result = simul_read.read_rib_input(CycleSession(session, CTS), devices=["dev:gw"])
    assert not any(row["interface"] == "pppoe0" for row in result.input.access_defaults)
