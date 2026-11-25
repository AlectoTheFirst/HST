"""Manual inventory: a pasted list becomes Device stubs through the normal pipeline."""

import pytest

from hst.collectors.manual import ManualCollector, ManualConfig, parse_devices
from hst.core import Settings

LIST = """
# core boxes without an orchestrator
edge-r1, 10.0.0.1, nxos, router, FDO12345
edge-r2, 10.0.0.2, iosxe, router
lab-sw1,
"""


def _collector(devices=LIST):
    cfg = ManualConfig(devices=devices, site_code="dc1", l3dom="dc1", source_name="dc1-seed")
    return ManualCollector(cfg, Settings(_env_file=None))


def test_parse_devices():
    rows = parse_devices(LIST)
    assert rows[0] == {
        "hostname": "edge-r1",
        "mgmt_ip": "10.0.0.1",
        "platform": "nxos",
        "role": "router",
        "serial": "FDO12345",
    }
    assert rows[2] == {"hostname": "lab-sw1", "mgmt_ip": "", "platform": "", "role": "", "serial": ""}


def test_parse_rejects_bad_lines_with_line_numbers():
    with pytest.raises(ValueError, match="line 2"):
        parse_devices("ok-host, 10.0.0.1\n, 10.0.0.2")  # missing hostname
    with pytest.raises(ValueError, match="line 1"):
        parse_devices("r1, not-an-ip")


def test_batch_identity_serial_vs_by_ref():
    """Every uid is the row's hostname. The registry keys a row by its serial
    when it has one, else by its hostname under this source."""
    c = _collector()
    batch = c.normalize(c.fetch())
    assert batch.scope == "manual:dc1-seed"
    uids = {n.uid: n for n in batch.nodes}

    assert {n.uid for n in batch.nodes if n.label == "Device"} == {
        "dev:edge-r1",
        "dev:edge-r2",
        "dev:lab-sw1",
    }
    assert c.identity.resolve_device("serial", "FDO12345", None) == "dev:edge-r1"
    assert c.identity.resolve_device("ref", "manual:dc1-seed:edge-r2", None) == "dev:edge-r2"
    assert c.identity.resolve_device("ref", "manual:dc1-seed:lab-sw1", None) == "dev:lab-sw1"
    r1 = uids["dev:edge-r1"].props
    assert (r1["hostname"], r1["platform"], r1["role"]) == ("edge-r1", "nxos", "router")
    ip_edges = [(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "HAS_IP"]
    assert len(ip_edges) == 2  # lab-sw1 has no mgmt ip


def test_mgmt_ip_carries_the_anchor_prop_and_keeps_its_uid():
    from hst.core import uid as uidmod

    c = _collector()
    batch = c.normalize(c.fetch())
    ips = [n for n in batch.nodes if n.label == "IpAddress"]
    assert ips
    for n in ips:
        assert n.props["anchor"] == n.props["l3dom"]
        assert n.uid.split(":", 2)[1] == uidmod.slug(n.props["anchor"])


def test_v6_mgmt_ip_is_stamped_af_6():
    c = _collector("edge-r3, 2001:db8::1, iosxr, router\nedge-r1, 10.0.0.1")
    batch = c.normalize(c.fetch())
    ips = {n.props["ip"]: n.props for n in batch.nodes if n.label == "IpAddress"}
    assert ips["2001:db8::1"]["af"] == 6
    assert ips["10.0.0.1"]["af"] == 4


def test_probe_reports_count_and_fetch_is_raw_text():
    c = _collector()
    assert "3 device" in c.probe()
    assert c.fetch() == {"devices": LIST}  # raw snapshot = the pasted text


def test_a_hand_entered_row_places_no_device_itself():
    """A pasted list says nothing about where the kit is, so every row stays
    unplaced until an operator assigns it."""
    c = _collector()
    batch = c.normalize(c.fetch())
    assert {n.uid for n in batch.nodes if n.label == "Device"}
    assert not [n for n in batch.nodes if n.label == "Site"]
    assert not [r for r in batch.rels if r.rel_type == "LOCATED_IN"]


def test_devices_schema_carries_multiline_hint():
    schema = ManualConfig.model_json_schema()
    assert schema["properties"]["devices"]["format"] == "multiline"
