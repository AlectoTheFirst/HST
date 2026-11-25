"""Fleet polling: the requests the enterprise-wide read set saves, per-edge cache
invalidation, and what a refused or failed read does to the graph.

The warm read set is four Portal operations per enterprise plus one BGP session
page, and `getAggregates` once per poll. Only a changed edge reads its `WAN` and
`controlPlane` modules again.
"""

import json
import threading
import time
from collections import Counter

import httpx
import pytest

from hst.collectors.base import raw_sha
from hst.collectors.velocloud import VeloCloudCollector, normalize_velocloud
from hst.core.config import Settings

from .test_velocloud import (
    PROFILE_ID,
    _config,
    _edge,
    _link,
    _overlay_raw,
    _profile,
    _wan_link,
    _wan_module,
)

CACHE_GLOB = "velocloud/poll-cache/*/current.json.gz.enc"
# every warm read of one enterprise, plus getAggregates once per poll
WARM = {
    "getAggregates": 1,
    "getEnterpriseEdges": 1,
    "getEnterpriseConfigurations": 1,
    "getEnterpriseRouteTable": 1,
    "bgpSessions": 1,
}
MODULES = "getEdgeConfigurationModules"


class Fleet:
    """One orchestrator that answers the captured shapes from `_overlay_raw`."""

    def __init__(self, monkeypatch):
        self.enterprises = _overlay_raw()["enterprises"]
        self.calls = Counter()
        self.fail: dict[str, int] = {}
        self.now = 1_790_000_000.0
        # `time` is one module object, so this patches the poll cache clock too
        monkeypatch.setattr("hst.collectors.velocloud.time.time", lambda: self.now)
        monkeypatch.setattr("hst.collectors.velocloud._transport", lambda _: httpx.MockTransport(self.reply))
        self.settings = Settings(_env_file=None, hst_secret_key="poll-cache-test-key-with-more-than-32-bytes")

    def poll(self, **changes):
        return VeloCloudCollector(_config(source_name="vco", **changes), self.settings).fetch()

    @property
    def cache_files(self):
        return sorted(self.settings.raw_dir.glob(CACHE_GLOB))

    def reply(self, request):
        operation = request.url.path.rsplit("/", 1)[-1]
        self.calls[operation] += 1
        if operation in self.fail:
            return httpx.Response(self.fail[operation], json={"error": {"message": operation}})
        if request.method == "POST":
            args = json.loads(request.content)
            if operation == "getAggregates":
                return httpx.Response(
                    200,
                    json={
                        "enterprises": [
                            {"logicalId": e["logicalId"], "id": n + 1} for n, e in enumerate(self.enterprises)
                        ]
                    },
                )
            ent = self.enterprises[args["enterpriseId"] - 1]
            if operation == "getEnterpriseEdges":
                return httpx.Response(200, json=ent["edges"])
            if operation == "getEnterpriseConfigurations":
                return httpx.Response(200, json=list(ent["profiles"].values()))
            if operation == "getEnterpriseRouteTable":
                return httpx.Response(200, json=ent["route_table"])
            eid = next(e["logicalId"] for e in ent["edges"] if e["id"] == args["edgeId"])
            return httpx.Response(200, json=ent["edge_details"][eid]["modules"])
        if operation == "enterprises":
            return httpx.Response(200, json=[{"logicalId": e["logicalId"]} for e in self.enterprises])
        ent = next(e for e in self.enterprises if e["logicalId"] == request.url.path.split("/")[5])
        if operation == "edges":
            return httpx.Response(200, json=ent["edges"])
        return httpx.Response(200, json=ent["bgp_sessions"])


def _minimal(fleet, *, enterprises: int, edges: int) -> None:
    """A fleet with no configuration body, for the request counts and the
    concurrency bound."""
    fleet.enterprises = []
    for index in range(enterprises):
        rows, details = [], {}
        for n in range(edges):
            eid = f"e-{index}-{n:04}"
            lid = f"l-{eid}"
            rows.append(_edge(eid, n + 1, eid, [_link(lid, "GE1", "172.16.0.2", "OurNet")]))
            details[eid] = {
                "modules": {
                    "WAN": _wan_module([_wan_link(lid, "GE1", mode="PRIVATE", isp="OurNet")]),
                    "controlPlane": {"version": "0", "type": "controlPlane", "data": {}},
                }
            }
        fleet.enterprises.append(
            {
                "logicalId": f"ent-{index}",
                "edges": rows,
                "profiles": {str(PROFILE_ID): _profile()},
                "edge_details": details,
                "route_table": {"profiles": [PROFILE_ID], "subnets": []},
                "bgp_sessions": [],
            }
        )


@pytest.fixture
def fleet(monkeypatch):
    return Fleet(monkeypatch)


def test_a_warm_poll_reads_five_operations_and_reuses_the_encrypted_cache(fleet):
    first = fleet.poll()
    assert fleet.calls[MODULES] == 2  # one per edge, cold
    fleet.calls.clear()
    fleet.now += 60
    second = fleet.poll()
    # the whole inventory, the profiles and the route table are reconciled live,
    # and no edge is read again
    assert fleet.calls == WARM
    assert second["poll_stats"]["cache_hits"] == 2
    collector = VeloCloudCollector(_config(source_name="vco"), fleet.settings)
    # a reused module keeps its observation time, so an unchanged poll is skipped
    assert raw_sha(collector, first) == raw_sha(collector, second)
    files = fleet.cache_files
    assert len(files) == 1
    assert b"OurNet" not in files[0].read_bytes()
    assert files[0].stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "change",
    [
        # the version stamp of one enterprise module
        lambda ent: ent["edges"][0]["configuration"]["enterprise"]["modules"][0].update(version="10"),
        # the edge's own override delta
        lambda ent: (
            ent["edges"][0]["configuration"]["enterprise"]["modules"][0]
            .setdefault("edgeSpecificData", {})
            .update(lan={"networks": []})
        ),
        # the profile the edge binds to
        lambda ent: ent["edges"][0]["configuration"]["enterprise"].update(id=99),
        # the address of a link the WAN module describes
        lambda ent: ent["edges"][0]["links"][0].update(ipAddress="172.16.1.3"),
        # the serial: a replaced edge keeps its logicalId
        lambda ent: ent["edges"][0].update(serialNumber="S-new"),
    ],
)
def test_a_changed_edge_is_refetched_alone(fleet, change):
    fleet.poll()
    fleet.calls.clear()
    fleet.now += 60
    change(fleet.enterprises[0])
    fleet.poll()
    assert fleet.calls[MODULES] == 1


def test_the_reuse_ceiling_refetches_every_edge_because_the_control_plane_has_no_stamp(fleet):
    fleet.poll()
    fleet.calls.clear()
    fleet.now += 1801
    fleet.poll()
    assert fleet.calls[MODULES] == 2
    # a zero ceiling reads every edge on every poll
    fleet.calls.clear()
    fleet.poll(configuration_refresh_s=0)
    assert fleet.calls[MODULES] == 2


def test_a_failed_module_refresh_keeps_the_last_known_body_and_marks_it_stale(fleet):
    first = fleet.poll()
    old = first["enterprises"][0]["edge_details"]["e-br"]["_freshness"]["modules"]
    fleet.now += 1801
    fleet.fail[MODULES] = 503
    raw = fleet.poll()
    assert raw["poll_stats"]["stale_reads"] == 2
    new = raw["enterprises"][0]["edge_details"]["e-br"]["_freshness"]["modules"]
    assert new["stale"] is True
    assert new["observed_at_ms"] == old["observed_at_ms"]
    batch = normalize_velocloud(raw)
    assert batch.sections["poll_refresh"].status == "failed"
    assert any("last-known data retained" in warning for warning in batch.warnings)
    links = [n for n in batch.nodes if n.label == "WanLink"]
    tunnels = [n for n in batch.nodes if n.label == "Tunnel"]
    assert len(links) == 4
    assert all(n.props["origin_config_recorded"] for n in links)
    assert all(n.props["configuration_stale"] for n in links)
    assert tunnels and all(n.props["configuration_stale"] for n in tunnels)
    assert any("module refresh failed" in str(n.props.get("gaps")) for n in batch.nodes)


def test_a_cold_module_failure_keeps_the_inventory_and_records_the_gap(fleet):
    fleet.fail[MODULES] = 503
    raw = fleet.poll()
    assert raw["poll_stats"]["stale_reads"] == 2
    batch = normalize_velocloud(raw, private_carriers={"ournet"})
    nodes = batch.nodes
    assert len([n for n in nodes if n.label == "Device"]) == 2
    # no controlPlane body, so no gateway and no tunnel at all
    assert not [n for n in nodes if n.label in ("Tunnel", "SdwanGateway")]
    assert any("Observation refresh failed" in str(n.props.get("gaps")) for n in nodes)
    assert any("no WAN module body" in str(n.props.get("gaps")) for n in nodes)
    # the link kind falls back to the carrier name, and it is not proven
    links = [n for n in nodes if n.label == "WanLink"]
    assert len(links) == 4
    assert not any(n.props["origin_config_recorded"] for n in links)


def test_an_unauthorized_module_read_is_not_hidden_as_a_gap(fleet):
    fleet.fail[MODULES] = 401
    with pytest.raises(httpx.HTTPStatusError):
        fleet.poll()


def test_a_refused_enterprise_read_is_a_recorded_gap_and_the_collection_stands(fleet):
    fleet.fail["getEnterpriseRouteTable"] = 403
    raw = fleet.poll()
    body = raw["enterprises"][0]
    assert body["route_table"] is None
    assert body["gaps"][0]["_capability"]["http_status"] == 403
    nodes = normalize_velocloud(raw).nodes
    assert len([n for n in nodes if n.label == "Device"]) == 2
    assert any("getEnterpriseRouteTable" in str(n.props.get("gaps")) for n in nodes)


def test_a_failed_inventory_read_stops_the_poll_and_keeps_the_cached_modules(fleet):
    fleet.poll()
    fleet.fail["getEnterpriseEdges"] = 503
    with pytest.raises(httpx.HTTPStatusError):
        fleet.poll()
    fleet.fail.clear()
    fleet.calls.clear()
    fleet.now += 60
    fleet.poll()
    assert fleet.calls[MODULES] == 0


def test_a_corrupt_cache_file_is_refetched(fleet):
    fleet.poll()
    for path in fleet.cache_files:
        path.write_bytes(b"broken cache")
    fleet.calls.clear()
    fleet.now += 60
    fleet.poll()
    assert fleet.calls[MODULES] == 2


@pytest.mark.parametrize(
    "changes",
    [
        {"auth": {"key": "different-token"}},
        {"url": "https://different-vco.example"},
        {"orchestrator_release": "6.5.0.0"},
        {"cache_enabled": False},
    ],
)
def test_changed_credentials_or_a_disabled_cache_force_live_reads(fleet, changes):
    fleet.poll()
    fleet.calls.clear()
    fleet.now += 60
    fleet.poll(**changes)
    assert fleet.calls[MODULES] == 2


def test_a_forced_refresh_does_not_roll_back_when_the_cache_is_enabled_again(fleet):
    fleet.poll()
    wan = fleet.enterprises[0]["edge_details"]["e-br"]["modules"]["WAN"]
    wan["data"]["links"][0]["upstreamMbps"] = 500
    fleet.now += 10
    fleet.poll(cache_enabled=False)
    fleet.calls.clear()
    fleet.now += 10
    raw = fleet.poll()
    modules = raw["enterprises"][0]["edge_details"]["e-br"]["modules"]
    assert modules["WAN"]["data"]["links"][0]["upstreamMbps"] == 500
    assert fleet.calls[MODULES] == 0


def test_a_removed_edge_is_evicted_and_not_resurrected_by_the_cache(fleet):
    fleet.poll()
    ent = fleet.enterprises[0]
    hub = ent["edges"].pop()
    fleet.now += 60
    raw = fleet.poll()
    assert list(raw["enterprises"][0]["edge_details"]) == ["e-br"]
    assert len([n for n in normalize_velocloud(raw).nodes if n.label == "Device"]) == 1
    # the evicted edge comes back as a cold read, never from the old entry
    ent["edges"].append(hub)
    fleet.calls.clear()
    fleet.now += 60
    fleet.poll()
    assert fleet.calls[MODULES] == 1


def test_request_concurrency_is_bounded(fleet, monkeypatch):
    _minimal(fleet, enterprises=1, edges=12)
    real = fleet.reply
    lock = threading.Lock()
    active = peak = 0

    def delayed(request):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.01)
            return real(request)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr("hst.collectors.velocloud._transport", lambda _: httpx.MockTransport(delayed))
    fleet.poll(enterprise_logical_ids="", poll_concurrency=2)
    assert peak == 2


def test_three_enterprises_and_1002_edges_have_a_linear_warm_request_count(fleet):
    _minimal(fleet, enterprises=3, edges=334)
    fleet.poll(enterprise_logical_ids="")
    # one discovery page, getAggregates once, four reads per enterprise, and one
    # module read per edge
    assert sum(fleet.calls.values()) == 1016
    assert fleet.calls[MODULES] == 1002
    assert fleet.calls["getAggregates"] == 1
    fleet.calls.clear()
    fleet.now += 60
    raw = fleet.poll(enterprise_logical_ids="")
    assert sum(fleet.calls.values()) == 14
    assert fleet.calls[MODULES] == 0
    assert [body["edges"][0]["logicalId"] for body in raw["enterprises"]] == [
        "e-0-0000",
        "e-1-0000",
        "e-2-0000",
    ]
