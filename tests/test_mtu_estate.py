from types import SimpleNamespace

from tests.test_mtu_snapshot import row
from tests.test_mtu_vyos import DEV, observations, payload

import hst.path as path
from hst.core import uid
from hst.core.mtu import MtuRequest
from hst.path.gates import _Trail
from hst.path.mtu_topology import crossing, mtu_request, trace_scope


def test_recorded_vyos_mtu_reaches_path_budget_and_keeps_config_drift(monkeypatch):
    raw = payload()
    obs = observations(raw)

    def read(session, query, **params):
        if "HAS_MTU" in query:
            return [row(o) for o in obs if o.subject_uid in params["subject_uids"]]
        return []

    monkeypatch.setattr(path, "_read", read)

    @trace_scope()
    def walk(session):
        crossing(_Trail(), uid.interface(DEV, "eth0"), enforcement="l3")
        return {"hops": []}

    with mtu_request(MtuRequest(mode="unfragmented", ip_packet_bytes=1501), 4):
        first = walk(SimpleNamespace(cts=42))["mtu"]
    assert first["known_ceiling_bytes"] == 1500
    assert first["outcome"] == "fail"
    assert any(f["code"] == "MTU_POLICY_DRIFT" for f in first["findings"])
    assert first["observations"]
    raw["links"][0]["mtu"] = 1600
    obs = observations(raw)
    with mtu_request(MtuRequest(mode="unfragmented", ip_packet_bytes=1501), 4):
        second = walk(SimpleNamespace(cts=42))["mtu"]
    assert second["known_ceiling_bytes"] == 1600
    assert second["outcome"] == "unknown"  # physical/end-to-end coverage remains open
    assert first["fingerprint"] != second["fingerprint"]
    assert first["observations"][0]["uid"] in {o["uid"] for o in second["observations"]}
