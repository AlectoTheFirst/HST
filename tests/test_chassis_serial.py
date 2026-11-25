"""A placeholder chassis serial names no chassis
in any collector (core/identity.py `chassis_serial`), and a serial that two
devices report in one run keys the later one by its own identifier
(`resolve_chassis`), with a warning."""

import logging

from tests.test_cisco_common import INTER, L3DOM, SCOPE, SOURCE

from hst.collectors import apic, nautobot, unifi
from hst.collectors.cisco_common import normalize_cisco
from hst.collectors.util import GraphBuilder
from hst.collectors.vyos import normalize_vyos
from hst.core.identity import MemoryResolver, chassis_serial, resolve_chassis


def _device(batch):
    return next(n for n in batch.nodes if n.label == "Device")


def test_chassis_serial_strips_a_serial_and_drops_a_placeholder():
    assert chassis_serial("  FDO1234ABCD ") == "FDO1234ABCD"
    for value in (None, "", "Not Specified", "0123456789", "000000", "To be filled by O.E.M."):
        assert chassis_serial(value) is None, value


def test_one_serial_reported_by_two_devices_in_a_run_keeps_them_two(caplog):
    registry = MemoryResolver()
    with caplog.at_level(logging.WARNING, logger="hst.core.identity"):
        one = resolve_chassis(registry, "ABC123", ("ref", "vyos-a:edge-a"), "edge-a")
        two = resolve_chassis(registry, "ABC123", ("ref", "vyos-b:edge-b"), "edge-b")
    assert one != two
    assert two == registry.resolve_device("ref", "vyos-b:edge-b", "edge-b")
    assert "serial 'ABC123' is reported by edge-a and by edge-b in this run" in caplog.text


def test_one_device_read_twice_or_by_two_sources_keeps_the_serial(caplog):
    registry = MemoryResolver()
    with caplog.at_level(logging.WARNING, logger="hst.core.identity"):
        first = resolve_chassis(registry, "FDO1", ("ref", "fab1:topology/pod-1/node-101"), "leaf101")
        again = resolve_chassis(registry, "FDO1", ("ref", "fab1:topology/pod-1/node-101"), "leaf101")
        nxos = resolve_chassis(registry, "FDO1", ("ref", "nxos:leaf101:leaf101"), "leaf101.corp.example")
    assert first == again == nxos == registry.resolve_device("serial", "FDO1", None)
    assert "reported by" not in caplog.text


def test_two_vyos_routers_reporting_one_unlisted_serial_stay_two_devices():
    registry = MemoryResolver()
    version = "Version:          VyOS 1.4.0\nHardware S/N:     SN-SHARED-1\n"
    batches = [
        normalize_vyos(
            {"config": {"system": {"host-name": host}}, "version_text": version, "links": []},
            l3dom="wan",
            source_name=f"row-{host}",
            resolver=registry,
        )
        for host in ("edge-a", "edge-b")
    ]
    assert _device(batches[0]).uid != _device(batches[1]).uid


def test_a_cisco_placeholder_serial_resolves_by_the_ref():
    registry = MemoryResolver()
    inter = {**INTER, "device": {**INTER["device"], "serial": "Not Specified"}}
    device = _device(normalize_cisco(inter, source=SOURCE, scope=SCOPE, l3dom=L3DOM, resolver=registry))
    assert device.props.get("serial") is None
    assert device.uid == registry.resolve_device("ref", f"{SCOPE}:sw1", None)


def test_an_apic_placeholder_serial_resolves_by_the_node_ref():
    registry = MemoryResolver()
    node = {"dn": "topology/pod-1/node-101", "name": "leaf101", "serial": "0000000", "role": "leaf"}
    b = GraphBuilder()
    apic._fabric_stage(b, {"fabricNode": [{"fabricNode": {"attributes": node}}]}, "fab1", registry)
    device = _device(b.batch("apic", "apic:fab1"))
    assert device.props.get("serial") is None
    assert device.uid == registry.resolve_device("ref", "fab1:topology/pod-1/node-101", None)


def test_a_nautobot_placeholder_serial_resolves_by_the_name():
    registry = MemoryResolver()
    duid = nautobot._device_uid({"name": "edge-a", "serial": "Default string"}, registry)
    assert duid == registry.resolve_device("ref", "nautobot:edge-a", None)


def test_a_unifi_placeholder_serial_resolves_by_the_mac():
    registry = MemoryResolver()
    b = GraphBuilder()
    raw = {"devices": [{"mac": "aa:bb:cc:00:00:01", "serial": "N/A", "name": "ap-1", "type": "uap"}]}
    unifi._device_stage(b, raw, "default", registry)
    device = _device(b.batch("unifi", "unifi:default"))
    assert device.props["serial"] == "aabbcc000001"
    assert device.uid == registry.resolve_device("serial", "aabbcc000001", None)


def test_a_manual_row_with_a_placeholder_serial_resolves_by_its_hostname():
    from hst.collectors.manual import ManualCollector, ManualConfig
    from hst.core import Settings

    cfg = ManualConfig(devices="edge-r1, 10.0.0.1, nxos, router, Not Specified\n", source_name="seed")
    c = ManualCollector(cfg, Settings(_env_file=None))
    device = _device(c.normalize(c.fetch()))
    assert device.props.get("serial") is None
    assert device.uid == c.identity.resolve_device("ref", "manual:seed:edge-r1", None)


def test_an_iosxe_stack_binds_no_placeholder_member():
    from tests.test_iosxe import RAW

    from hst.collectors import iosxe

    raw = dict(RAW)
    text = raw[iosxe.CMD_VERSION]
    serials = iosxe.stack_serials(raw)
    assert serials, "the fixture names a chassis serial"
    raw[iosxe.CMD_VERSION] = text.replace(serials[0], "0000000000")
    assert serials[0] not in iosxe.stack_serials(raw)
    assert iosxe.parse(raw)["device"]["serial"] != "0000000000"
