"""The read-only guard, run cancellation, the rate-limit retry and the numeric
ids every Portal operation addresses an enterprise and an edge by."""

import json
import threading

import httpx
import pytest

from hst.collectors.base import CollectionStopped
from hst.collectors.velocloud import (
    EDGE_MODULES,
    PORTAL_READ_PATHS,
    VeloCloudCollector,
    _numeric_id,
)
from hst.core.config import Settings

from .test_velocloud import ENT, _config


def test_portal_mutations_cannot_be_called_by_the_read_helper():
    """The helper resolves an operation key to one of the allowed read paths, so
    a mutation cannot be reached through it, by key or by path."""
    collector = VeloCloudCollector(_config(), Settings(_env_file=None))
    with httpx.Client(base_url="https://vco.example") as client:
        for operation in ("/portal/rest/edge/deleteEdge", "deleteEdge", "edge/deleteEdge"):
            with pytest.raises(ValueError, match="allowed read"):
                collector._portal_read(client, operation, {"id": 12})


def test_a_cancelled_run_stops_the_poll_at_its_next_request():
    calls = []

    def respond(request):
        calls.append(request.url.path)
        return httpx.Response(200, json={"data": [], "metaData": {}})

    collector = VeloCloudCollector(_config(), Settings(_env_file=None))
    collector.stop = threading.Event()
    with httpx.Client(base_url="https://vco.example", transport=httpx.MockTransport(respond)) as client:
        collector._get(client, "/enterprises")
        collector.stop.set()
        with pytest.raises(CollectionStopped):
            collector._get(client, "/enterprises")
    assert len(calls) == 1


def test_a_rate_limited_portal_read_is_retried_unchanged(monkeypatch):
    calls, sleeps = [], []

    def respond(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "2"})
        return httpx.Response(200, json={"enterprises": []})

    monkeypatch.setattr("hst.collectors.velocloud._sleep", sleeps.append)
    collector = VeloCloudCollector(_config(), Settings(_env_file=None))
    with httpx.Client(base_url="https://vco.example", transport=httpx.MockTransport(respond)) as client:
        assert collector._portal_read(client, "aggregates", {"enterpriseId": 1}) == {"enterprises": []}
    assert calls[0].content == calls[1].content
    assert calls[0].url.path == calls[1].url.path == PORTAL_READ_PATHS["aggregates"]
    assert sleeps == [2.0]


def test_the_pace_holds_even_when_every_worker_is_free_at_once(monkeypatch):
    clock_time = {"t": 0.0}
    sleeps = []

    def clock():
        return clock_time["t"]

    def sleep(seconds):
        sleeps.append(seconds)
        clock_time["t"] += seconds

    monkeypatch.setattr("hst.collectors.velocloud.time.monotonic", clock)
    monkeypatch.setattr("hst.collectors.velocloud._pace", sleep)
    collector = VeloCloudCollector(_config(), Settings(_env_file=None))
    for _ in range(5):
        collector._throttle()
        clock_time["t"] += 0.01  # each answer lands inside the 1/4s = 0.25s floor

    assert sleeps == [pytest.approx(0.24)] * 4


@pytest.mark.parametrize("value", [True, False, 0, -1, "12", 12.5, None, {}])
def test_a_value_that_is_not_a_positive_whole_number_is_not_a_numeric_id(value):
    assert _numeric_id(value) is None


@pytest.mark.parametrize("value", [1, 12, 12.0])
def test_a_positive_whole_number_is_a_numeric_id(value):
    assert _numeric_id(value) == int(value)


def test_a_whole_float_addresses_the_module_read_and_keys_the_profile(monkeypatch):
    bodies = {}

    def respond(request):
        path = request.url.path
        if request.method == "POST":
            bodies[path] = json.loads(request.content)
        if path == PORTAL_READ_PATHS["aggregates"]:
            return httpx.Response(200, json={"enterprises": [{"id": 34.0, "logicalId": ENT}]})
        if path == PORTAL_READ_PATHS["enterprise_edges"]:
            return httpx.Response(200, json=[{"id": 12.0, "logicalId": "e-br"}])
        if path == PORTAL_READ_PATHS["enterprise_configurations"]:
            return httpx.Response(200, json=[{"id": 77.0, "name": "profile-1"}])
        if path == PORTAL_READ_PATHS["route_table"]:
            return httpx.Response(200, json={"subnets": []})
        if path == PORTAL_READ_PATHS["configuration_modules"]:
            return httpx.Response(200, json={})
        return httpx.Response(200, json=[])

    monkeypatch.setattr("hst.collectors.velocloud._transport", lambda _: httpx.MockTransport(respond))
    raw = VeloCloudCollector(_config(), Settings(_env_file=None)).fetch()
    assert bodies[PORTAL_READ_PATHS["configuration_modules"]] == {
        "enterpriseId": 34,
        "edgeId": 12,
        "modules": list(EDGE_MODULES),
    }
    assert list(raw["enterprises"][0]["profiles"]) == ["77"]
