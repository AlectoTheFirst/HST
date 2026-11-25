"""Other source evidence stays scoped to its documented/declared semantics."""

import copy
from types import SimpleNamespace

import httpx
import pytest

from hst.collectors.base import RAW_OUTCOMES_KEY
from hst.collectors.checkpoint import normalize_checkpoint
from hst.collectors.nautobot import NautobotCollector, normalize_nautobot
from hst.collectors.netscaler import NetScalerCollector, NetScalerConfig, _netscaler_mtu
from hst.collectors.unifi import normalize_unifi
from hst.collectors.zia import normalize_zia
from hst.collectors.zpa import normalize_zpa
from hst.core.config import Settings
from hst.core.model import Batch
from hst.core.mtu import MtuContext, MtuObservation
from hst.core.mtu_read import resolve_constraints


def observations(batch):
    return [MtuObservation(uid=n.uid, **n.props) for n in batch.nodes if n.label == "MtuObservation"]


def test_unifi_jumbo_boolean_and_port_scalar_remain_unknown():
    raw = {
        "devices": [
            {
                "mac": "02:00:00:00:00:01",
                "serial": "synthetic",
                "type": "usw",
                "jumbo_enabled": True,
                "port_table": [{"port_idx": 1, "mtu": 9216}],
            }
        ]
    }
    batch = normalize_unifi(raw, site_code="synthetic", l3dom="synthetic", unifi_site="synthetic")
    rows = observations(batch)
    assert len(rows) == 2
    assert all(r.normalized_value is None and r.assertion_kind == "configured" for r in rows)
    assert {r.raw_value_json for r in rows} == {"true", "9216"}
    assert batch.sections["mtu"].status == "partial"


def nautobot_raw():
    return {
        "devices": [
            {
                "id": "synthetic",
                "name": "synthetic",
                "serial": "synthetic",
                "interfaces": [{"name": "Ethernet1/1", "type": "1000base-t", "mtu": 9000}],
            }
        ]
    }


def test_nautobot_mtu_needs_declared_basis_and_always_stays_intent():
    unknown = observations(normalize_nautobot(nautobot_raw(), host="synthetic"))
    assert len(unknown) == 1 and unknown[0].normalized_value is None
    typed = observations(normalize_nautobot(nautobot_raw(), host="synthetic", mtu_basis="ip_packet"))
    assert {o.metric for o in typed} == {"ipv4_mtu_bytes", "ipv6_mtu_bytes"}
    assert all(o.assertion_kind == "intent" and o.normalized_value == 9000 for o in typed)
    result = resolve_constraints(typed, MtuContext(af=4))
    assert not result.constraints and result.intent[0].value_bytes == 9000


def test_nautobot_mtu_observation_is_both_directions_and_rx_context_resolves_a_ceiling():
    typed = observations(normalize_nautobot(nautobot_raw(), host="synthetic", mtu_basis="ip_packet"))
    assert typed and all(o.direction == "both" for o in typed)
    rx = resolve_constraints(typed, MtuContext(af=4, direction="rx"))
    assert not rx.constraints
    assert rx.intent and rx.intent[0].bound_kind == "ceiling"
    assert rx.intent[0].value_bytes == 9000


def test_nautobot_failed_optional_source_cannot_use_old_mtu():
    raw = nautobot_raw()
    raw[RAW_OUTCOMES_KEY] = {"mtu:interfaces": {"status": "unauthorized"}}
    batch = normalize_nautobot(raw, host="synthetic", mtu_basis="ip_packet")
    assert not observations(batch)
    assert batch.sections["mtu"].status == "unauthorized"
    assert any(n.label == "Port" for n in batch.nodes)


def test_netscaler_scoped_untagged_configured_and_unknown_operational_frame():
    batch = Batch(source="netscaler", scope="synthetic")
    _netscaler_mtu(
        batch,
        {"Interface": [{"id": "1/1", "mtu": 1500, "actualmtu": 1518}]},
        device_uid="dev:synthetic",
        target="synthetic",
    )
    rows = observations(batch)
    configured = next(o for o in rows if o.assertion_kind == "configured")
    operational = next(o for o in rows if o.assertion_kind == "operational")
    assert configured.normalized_value == 1514
    assert configured.tag_depth == 0 and configured.direction == "both"
    assert operational.normalized_value is None
    assert not resolve_constraints([configured], MtuContext(af=4, tag_depth=1)).constraints
    assert batch.sections["mtu"].status == "partial"
    assert not any(n.label in {"Device", "Prefix", "IpAddress"} for n in batch.nodes)


def test_netscaler_no_guessed_appliance_owner_for_ha_group():
    batch = Batch(source="netscaler", scope="synthetic")
    _netscaler_mtu(batch, {"Interface": [{"id": "1/1", "mtu": 1500}]}, device_uid="", target="synthetic")
    assert not batch.nodes
    assert "Device UID is unresolved" in batch.sections["mtu"].detail


@pytest.mark.parametrize("status", ["unauthorized", "failed", "unsupported", "malformed"])
def test_netscaler_failed_fetch_does_not_use_stale_rows(status):
    batch = Batch(source="netscaler", scope="synthetic")
    raw = {"Interface": [{"id": "1/1", "mtu": 9000}], RAW_OUTCOMES_KEY: {"mtu:Interface": {"status": status}}}
    _netscaler_mtu(batch, raw, device_uid="dev:synthetic", target="synthetic")
    assert not batch.nodes
    assert batch.sections["mtu"].status == status


def test_netscaler_verified_read_resource_and_http_failure():
    coll = NetScalerCollector(
        NetScalerConfig(
            host="https://synthetic.invalid",
            scope_name="synthetic",
            on_uid="dev:synthetic",
            on_label="Device",
            auth={"username": "synthetic", "password": "synthetic"},
        ),
        Settings(_env_file=None),
    )
    paths = []

    def response(req):
        paths.append(req.url.path)
        return httpx.Response(200, json={"Interface": [{"id": "1/1", "mtu": 1500}]})

    raw = {}
    with httpx.Client(base_url=coll.config.host, transport=httpx.MockTransport(response)) as client:
        coll._fetch_mtu_interfaces(client, raw)
    assert paths == ["/nitro/v1/config/Interface"]
    assert raw[RAW_OUTCOMES_KEY]["mtu:Interface"]["status"] == "ok"
    with httpx.Client(
        base_url=coll.config.host, transport=httpx.MockTransport(lambda req: httpx.Response(403, json={}))
    ) as client:
        coll._fetch_mtu_interfaces(client, raw)
    assert raw[RAW_OUTCOMES_KEY]["mtu:Interface"]["status"] == "unauthorized"


def test_nautobot_optional_read_merges_by_device_and_interface_identity(monkeypatch):
    from hst.collectors import nautobot

    extra = nautobot_raw()["devices"]
    raw = copy.deepcopy(nautobot_raw())
    raw["devices"][0]["interfaces"][0].pop("mtu")
    queries = []

    def paged(client, query, field, **kwargs):
        queries.append(query)
        return extra

    monkeypatch.setattr(nautobot, "_paged", paged)
    coll = object.__new__(NautobotCollector)
    coll._fetch_mtu(SimpleNamespace(), raw)
    assert "description mtu" in queries[0]
    assert "mtu" not in raw["devices"][0]["interfaces"][0]
    assert raw["mtu_devices"][0]["interfaces"][0]["mtu"] == 9000
    batch = normalize_nautobot(raw, host="synthetic", mtu_basis="ip_packet")
    assert observations(batch)[0].normalized_value == 9000
    assert raw[RAW_OUTCOMES_KEY]["mtu:interfaces"]["status"] == "ok"


def test_sources_without_verified_dataplane_mtu_report_exact_capability_gap():
    for batch in (
        normalize_checkpoint({}, mgmt="synthetic", domain="synthetic"),
        normalize_zia({}, tenant="synthetic"),
        normalize_zpa({}, tenant="synthetic"),
    ):
        assert batch.sections["mtu"].status == "unsupported"
        assert not observations(batch)
        assert "MTU" in batch.sections["mtu"].detail


def test_declared_basis_and_netscaler_owner_invalidate_normalization_hash():
    from hst.collectors.base import raw_sha
    from hst.collectors.nautobot import NautobotConfig

    config = {"url": "https://synthetic.invalid", "auth": {"key": "synthetic"}}
    unknown = NautobotCollector(NautobotConfig(**config), Settings(_env_file=None))
    explicit = NautobotCollector(NautobotConfig(**config, mtu_basis="ip_packet"), Settings(_env_file=None))
    assert raw_sha(unknown, nautobot_raw()) != raw_sha(explicit, nautobot_raw())
    nsconfig = {
        "host": "https://synthetic.invalid",
        "scope_name": "synthetic",
        "on_uid": "rgrp:synthetic",
        "auth": {"username": "synthetic", "password": "synthetic"},
    }
    unresolved = NetScalerCollector(NetScalerConfig(**nsconfig), Settings(_env_file=None))
    resolved = NetScalerCollector(
        NetScalerConfig(**nsconfig, mtu_device_uid="dev:synthetic"), Settings(_env_file=None)
    )
    assert raw_sha(unresolved, {}) != raw_sha(resolved, {})
