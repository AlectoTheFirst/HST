"""VyOS normalizer tests against a recorded-style `show configuration json` payload."""

import json
import os
from pathlib import Path

import pytest
from tests.conftest import FakeSshSession

from hst.collectors import vyos as vyos_mod
from hst.collectors.auth import SshPassword
from hst.collectors.vyos import VyosCollector, VyosConfig, normalize_vyos, section_outcomes
from hst.core import manifest, uid
from hst.core.identity import MemoryResolver
from hst.core.l3domain import DEFAULT_VRF
from hst.core.model import TableOutcome

HOST, USER = "gw1", "vyos"


def _collector():
    return VyosCollector(
        VyosConfig(host=HOST, auth=SshPassword(username=USER, password="pw"), site_code="dc1", l3dom="dc1"),
        None,
    )


# SSH transport plumbing (auth/pin forwarding, observed host keys) is shared by every CLI
# collector and is exercised once, parametrized over vendors, in
# test_ssh_transport_conformance.py. VyOS's own fetch()/probe() shape (below) is not shared.


def test_show_commands_are_wrapped_for_the_noninteractive_shell(monkeypatch):
    """`show ...` does not exist in the non-interactive vbash an exec lands in."""
    fake = FakeSshSession(lambda cmd: "OUT").install(monkeypatch)
    _collector()._ssh("show version")
    assert fake.commands[-1] == "/opt/vyatta/bin/vyatta-op-cmd-wrapper show version"
    _collector()._ssh("ip -j link show")
    assert fake.commands[-1] == "ip -j link show"  # only op-mode commands are wrapped


def _fetch_outputs(cmd: str) -> str:
    if "show configuration json" in cmd:
        return "{}"
    if "show version" in cmd:
        return VERSION
    if "vtysh" in cmd:
        return "{}"
    return "[]"


def test_fetch_runs_the_ip_commands_with_an_explicit_sbin_path(monkeypatch):
    """`ip` lives in a sbin directory that the non-interactive exec PATH does
    not include."""
    fake = FakeSshSession(_fetch_outputs).install(monkeypatch)
    raw = _collector().fetch()
    assert "PATH=/usr/sbin:/sbin:/usr/bin:/bin ip -j link show" in fake.commands
    assert "PATH=/usr/sbin:/sbin:/usr/bin:/bin ip -j addr show" in fake.commands
    assert 'PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ip route vrf all json"' in fake.commands
    assert 'PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ipv6 route vrf all json"' in fake.commands
    assert raw["links"] == [] and raw["addrs"] == []
    assert raw["routes"] == "{}" and raw["routes6"] == "{}"
    for key in ("links", "addrs", "routes", "routes6"):
        assert f"{key}_error" not in raw


def test_fetch_records_a_failed_ip_command(monkeypatch, caplog):
    from hst.collectors import ssh

    def outputs(cmd: str) -> str:
        if "addr show" in cmd:
            raise ssh.CommandFailed("exit 127: ip: command not found")
        return _fetch_outputs(cmd)

    FakeSshSession(outputs).install(monkeypatch)
    raw = _collector().fetch()
    assert raw["addrs"] == []
    assert raw["addrs_error"].startswith("CommandFailed")
    assert "links_error" not in raw
    assert "ip -j addr show" in caplog.text


# --- section outcomes: what each read produced -------------------------------


def test_a_failed_operational_read_reads_as_a_failed_section(monkeypatch):
    """VyOS has no ARP command in this collector."""
    from hst.collectors import ssh

    def outputs(cmd: str) -> str:
        if "addr show" in cmd:
            raise ssh.CommandFailed("exit 127: ip: command not found")
        return _fetch_outputs(cmd)

    FakeSshSession(outputs).install(monkeypatch)
    sections = section_outcomes(_collector().fetch())
    assert sections["addrs"].status == "failed"
    assert sections["version"].status == "ok"
    assert sections["config"].status == "empty"


def test_an_unauthorized_read_reads_as_unauthorized(monkeypatch):
    from hst.collectors import ssh

    def outputs(cmd: str) -> str:
        if "vtysh" in cmd and "show ip route" in cmd:
            raise ssh.CommandFailed("vtysh: Permission denied")
        return _fetch_outputs(cmd)

    FakeSshSession(outputs).install(monkeypatch)
    assert section_outcomes(_collector().fetch())["routes"].status == "unauthorized"


def test_a_read_that_came_back_with_nothing_reads_empty(monkeypatch):
    FakeSshSession(_fetch_outputs).install(monkeypatch)
    sections = section_outcomes(_collector().fetch())
    assert sections["addrs"].status == "empty" and sections["addrs"].row_count == 0
    assert sections["routes"].status == "empty"


def test_a_payload_with_no_recorded_outcomes_reads_unknown():
    raw = {"config": {}, "version_text": VERSION, "links": [], "addrs": []}
    assert {s.status for s in section_outcomes(raw).values()} == {"unknown"}


def test_fetch_reads_each_configured_policy_table(monkeypatch):
    """PBR tables are not VRFs, so `vrf all` never lists them; each table number
    the config declares gets its own v4 and v6 read."""
    cfg = {"protocols": {"static": {"table": {"100": {}, "200": {}}}}}

    def outputs(cmd: str) -> str:
        if "show configuration json" in cmd:
            return json.dumps(cfg)
        return _fetch_outputs(cmd)

    fake = FakeSshSession(outputs).install(monkeypatch)
    raw = _collector().fetch()
    for t in ("100", "200"):
        assert any(f'"show ip route table {t} json"' in c for c in fake.commands)
        assert any(f'"show ipv6 route table {t} json"' in c for c in fake.commands)
    assert set(raw["routes_tables"]) == {"100", "200"}
    assert set(raw["routes6_tables"]) == {"100", "200"}


def test_fetch_rejects_a_non_numeric_static_table_key(monkeypatch, caplog):
    """The table key lands inside a quoted vtysh argument on an SSH exec."""
    malicious = '1 json"; rm -rf /; echo "'
    cfg = {"protocols": {"static": {"table": {malicious: {}, "200": {}}}}}

    def outputs(cmd: str) -> str:
        if "show configuration json" in cmd:
            return json.dumps(cfg)
        return _fetch_outputs(cmd)

    fake = FakeSshSession(outputs).install(monkeypatch)
    raw = _collector().fetch()
    assert not any(malicious in c for c in fake.commands)
    assert not any("rm -rf" in c for c in fake.commands)
    assert malicious not in raw["routes_tables"]
    assert malicious not in raw["routes6_tables"]
    assert raw[f"routes_table_{malicious}_error"].startswith("ValueError")
    assert raw[f"routes6_table_{malicious}_error"].startswith("ValueError")
    assert malicious in caplog.text
    assert any('"show ip route table 200 json"' in c for c in fake.commands)
    assert any('"show ipv6 route table 200 json"' in c for c in fake.commands)
    assert raw["routes_tables"] == {"200": "{}"}
    assert raw["routes6_tables"] == {"200": "{}"}


def test_fetch_records_a_failed_route_read(monkeypatch, caplog):
    from hst.collectors import ssh

    def outputs(cmd: str) -> str:
        if "vtysh" in cmd:
            raise ssh.CommandFailed("exit 127: vtysh: command not found")
        return _fetch_outputs(cmd)

    FakeSshSession(outputs).install(monkeypatch)
    raw = _collector().fetch()
    assert raw["routes"] == [] and raw["routes6"] == []
    assert raw["routes_error"].startswith("CommandFailed")
    assert raw["routes6_error"].startswith("CommandFailed")
    assert "addrs_error" not in raw
    assert "show ip route vrf all json" in caplog.text


CONFIG = {
    "system": {"host-name": "gw"},
    "interfaces": {
        "ethernet": {
            "eth0": {"address": ["dhcp"], "description": "WAN"},
            "eth1": {
                "address": ["192.168.1.1/24"],
                "description": "LAN trunk",
                "vif": {
                    "30": {"address": ["192.168.30.1/24"], "description": "IoT"},
                    "40": {"address": ["192.168.40.1/24"], "description": "Guest"},
                },
            },
        },
        "wireguard": {
            "wg0": {
                "address": ["10.99.99.1/24"],
                "peer": {"phone": {"allowed-ips": ["10.99.99.2/32"]}},
            },
            "wg1": {
                "address": ["10.99.98.1/24"],
                "peer": {"backup": {"allowed-ips": ["10.99.98.2/32"]}},
            },
        },
    },
    "firewall": {
        "group": {
            "address-group": {"CAMERAS": {"address": ["192.168.30.50"]}},
            "network-group": {"RFC1918": {"network": ["192.168.0.0/16", "10.0.0.0/8"]}},
        },
        "zone": {
            "WAN": {
                "default-action": "drop",
                "member": {"interface": ["eth0"]},
                "from": {"LAN": {"firewall": {"name": "LAN-WAN"}}},
            },
            "LAN": {"default-action": "drop", "member": {"interface": ["eth1"]}},
            "IOT": {
                "default-action": "drop",
                "member": {"interface": ["eth1.30"]},
                "from": {"LAN": {"firewall": {"name": "LAN-IOT"}}},
            },
        },
        "ipv4": {
            "name": {
                "LAN-IOT": {
                    "default-action": "drop",
                    "rule": {"10": {"action": "accept", "protocol": "tcp", "destination": {"port": "443"}}},
                },
                "LAN-WAN": {
                    "default-action": "accept",
                    "rule": {
                        "10": {"action": "drop", "protocol": "tcp", "destination": {"port": "25"}},
                        "20": {
                            "action": "drop",
                            "outbound-interface": {"name": "eth0"},
                            "source": {"group": {"address-group": "CAMERAS"}},
                        },
                    },
                },
            },
            "forward": {
                "filter": {
                    "default-action": "drop",
                    "rule": {
                        "10": {
                            "action": "accept",
                            "protocol": "tcp",
                            "source": {"group": {"address-group": "CAMERAS"}},
                            "destination": {"address": "192.168.1.20", "port": "443"},
                        },
                        # The ECMP trace test sends CAMERAS to 8.8.8.8:443 over the wg
                        # tunnels, which no zone contains, so this chain is the gate.
                        "15": {
                            "action": "accept",
                            "protocol": "tcp",
                            "source": {"group": {"address-group": "CAMERAS"}},
                            "destination": {"port": "443"},
                        },
                        "20": {
                            "action": "drop",
                            "source": {"address": "192.168.40.0/24"},
                            "destination": {"group": {"network-group": "RFC1918"}},
                        },
                    },
                },
            },
        },
    },
    "nat": {
        "source": {
            "rule": {
                "100": {
                    "outbound-interface": {"name": "eth0"},
                    "source": {"address": "192.168.0.0/16"},
                    "translation": {"address": "masquerade"},
                }
            }
        },
        "destination": {
            "rule": {
                "10": {
                    "inbound-interface": {"name": "eth0"},
                    "protocol": "udp",
                    "destination": {"port": "51820"},
                    "translation": {"address": "192.168.1.10", "port": "51820"},
                }
            }
        },
    },
    "policy": {
        "route": {
            "VPN-PBR": {
                "interface": ["eth1.30"],
                "rule": {
                    "10": {
                        "description": "local stays local",
                        "destination": {"address": "192.168.0.0/16"},
                        "set": {"table": "main"},
                    },
                    "20": {"source": {"group": {"address-group": "CAMERAS"}}, "set": {"table": "100"}},
                    # port 8443, not 443: the database suite traces the whole IoT
                    # VLAN on tcp/443 and expects only CAMERAS steered into table 100
                    "30": {
                        "protocol": "tcp",
                        "destination": {"port": "8443"},
                        "set": {"table": "100"},
                    },
                },
            },
        },
    },
    "protocols": {
        "static": {
            "route": {"10.99.0.0/24": {"next-hop": {"192.168.1.2": {}}}},
            # two equal-cost defaults in the policy table: ECMP
            "table": {"100": {"route": {"0.0.0.0/0": {"interface": {"wg0": {}, "wg1": {}}}}}},
        }
    },
    "service": {
        "dhcp-server": {
            "shared-network-name": {
                "LAN": {"subnet": {"192.168.1.0/24": {}}},
            }
        }
    },
}

VERSION = "Version:          VyOS 1.5-rolling-202607150020\nHardware S/N:     QEMU1234\n"

LINKS = [
    {"ifname": "eth0", "address": "aa:bb:cc:99:99:98"},
    {"ifname": "eth1", "address": "aa:bb:cc:99:99:99"},
    {"ifname": "eth1.30", "address": "aa:bb:cc:99:99:99"},
]


def _batch(version_text=VERSION, source_name="", resolver=None):
    return normalize_vyos(
        {"config": CONFIG, "version_text": version_text, "links": LINKS},
        l3dom="home",
        source_name=source_name,
        resolver=resolver,
    )


def _device(batch):
    return next(n for n in batch.nodes if n.label == "Device")


def test_device_serial_and_fallback():
    """The registry keys the box by its serial when it reports one, else by
    `<source row>:<hostname>`. Either way the uid is the hostname."""
    registry = MemoryResolver()
    assert _device(_batch(resolver=registry)).uid == "dev:gw"
    assert registry.resolve_device("serial", "QEMU1234", None) == "dev:gw"
    # an unknown serial and the DMI placeholder of consumer boards are not serials
    for placeholder in ("Unknown", "Default string"):
        registry = MemoryResolver()
        device = _device(_batch(version_text=f"Hardware S/N:     {placeholder}\n", resolver=registry))
        assert device.uid == registry.resolve_device("ref", "vyos:gw", None) == "dev:gw"
        assert device.props.get("serial") is None

    # The source row name is part of the ref.
    registry = MemoryResolver()
    no_serial = "Hardware S/N:     Unknown\n"
    one = _batch(version_text=no_serial, source_name="vyos1", resolver=registry)
    two = _batch(version_text=no_serial, source_name="vyos2", resolver=registry)
    assert _device(one).uid == "dev:gw"
    assert _device(two).uid == "dev:gw-0376"


def test_side_rows_use_the_same_fallback_device_uid_as_normalize():
    """side_tables() and normalize() derive the serial-less Device uid from one
    helper, so rib side rows carry a `device_uid` that joins back to the Device
    node the same collector emitted, source row name included."""
    from hst.core import Settings

    raw = {
        "config": CONFIG,
        "version_text": "Hardware S/N:     Unknown\n",
        "links": LINKS,
        "routes": {"default": _route("10.99.9.0/24", _nh(ip="192.168.1.5", dev="eth1"), protocol="bgp")},
        "routes6": {"default": {}},
    }
    c = VyosCollector(
        VyosConfig(
            host=HOST,
            auth=SshPassword(username=USER, password="pw"),
            site_code="home",
            l3dom="home",
            source_name="vyos1",
        ),
        Settings(_env_file=None),
    )
    device_node = next(n.uid for n in c.normalize(raw).nodes if n.label == "Device")
    assert device_node == "dev:gw"
    rows = c.side_tables(raw)["rib"]
    assert rows and {r["device_uid"] for r in rows} == {device_node}


def test_subinterfaces_share_segments_with_unifi():
    batch = _batch()
    segs = {n.uid for n in batch.nodes if n.label == "BridgeDomain"}
    assert {"bd:vlan:fab0:30", "bd:vlan:fab0:40"} <= segs
    bound = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "BOUND_TO"}
    assert ("dev:gw/if/eth1.30", "vlan:dev:gw:30") in bound
    prefixes = {n.props["cidr"] for n in batch.nodes if n.label == "Prefix"}
    assert "192.168.30.0/24" in prefixes


def test_interface_macs_from_ip_link():
    batch = _batch()
    eth1 = next(n for n in batch.nodes if n.label == "Interface" and n.uid == "dev:gw/if/eth1")
    assert eth1.props["mac"] == "aabbcc999999"
    port = next(n for n in batch.nodes if n.label == "Port" and n.uid == "dev:gw/port/eth1")
    assert port.props["mac"] == "aabbcc999999"


def test_wan_link_for_dhcp_uplink():
    batch = _batch()
    assert any(n.label == "WanLink" and n.uid == "wan:gw:eth0" for n in batch.nodes)


def test_a_wan_link_is_on_the_interface_it_leaves_by():
    on = {
        (r.start_uid, r.end_uid) for r in _batch().rels if r.rel_type == "ON" and r.start_label == "WanLink"
    }
    assert on == {("wan:gw:eth0", "dev:gw/if/eth0")}
    on = {
        (r.start_uid, r.end_uid)
        for r in _op_batch().rels
        if r.rel_type == "ON" and r.start_label == "WanLink"
    }
    assert ("wan:gw:pppoe03", "dev:gw/if/pppoe03") in on


def test_firewall_chain_and_rules():
    batch = _batch()
    rulebases = {n.uid: n.props for n in batch.nodes if n.label == "FwRulebase"}
    fwd = rulebases["vyos:gw:fw:ipv4-forward"]
    assert fwd["default_action"] == "drop" and fwd["kind"] == "access"
    assert fwd["af"] == 4 and fwd["chain"] == "forward"
    assert rulebases["vyos:gw:fw:LAN-WAN"]["af"] == 4
    assert "chain" not in rulebases["vyos:gw:fw:LAN-WAN"]
    dev_enforces = {
        r.end_uid for r in batch.rels if r.rel_type == "ENFORCES" and r.start_uid.startswith("dev:")
    }
    assert "vyos:gw:fw:ipv4-forward" in dev_enforces
    assert "vyos:gw:fw:LAN-WAN" not in dev_enforces
    rules = {n.uid: n.props for n in batch.nodes if n.label == "FwRule"}
    assert rules["vyos:gw:fw:ipv4-forward:10"]["action"] == "accept"
    # The matcher reads an empty object list as "matches nothing".
    assert rules["vyos:gw:fw:ipv4-forward:15"]["dst_any"] is True
    assert rules["vyos:gw:fw:ipv4-forward:15"]["src_any"] is False
    assert rules["vyos:gw:fw:ipv4-forward:10"]["dst_any"] is False
    assert rules["vyos:gw:fw:LAN-WAN:10"]["src_any"] is True
    src = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "SRC"}
    assert ("vyos:gw:fw:ipv4-forward:10", "vyos:gw:grp:addr:CAMERAS") in src
    resolves = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "RESOLVES_TO"}
    assert ("vyos:gw:grp:addr:CAMERAS", "ip:home:192.168.30.50") in resolves


def test_nat_rules():
    batch = _batch()
    nats = {n.uid: n.props for n in batch.nodes if n.label == "NatRule"}
    snat = nats["vyos:gw:nat:source:100"]
    assert snat["kind"] == "snat" and snat["translation"] == "masquerade"
    dnat = nats["vyos:gw:nat:destination:10"]
    assert dnat["kind"] == "dnat"
    xlate = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "XLATE_DST"}
    assert ("vyos:gw:nat:destination:10", "ip:home:192.168.1.10") in xlate


def test_nat_rules_carry_the_whole_match_tuple():
    batch = _batch()
    nats = {n.uid: n.props for n in batch.nodes if n.label == "NatRule"}
    snat = nats["vyos:gw:nat:source:100"]
    assert snat["out_if"] == "eth0" and snat["orig_src"] == "192.168.0.0/16"
    assert snat["enabled"] is True and snat["exclude"] is False
    dnat = nats["vyos:gw:nat:destination:10"]
    assert dnat["in_if"] == "eth0" and dnat["protocol"] == "udp"
    assert dnat["orig_dst_port"] == "51820" and dnat["translation_port"] == "51820"


def test_nat_disable_exclude_ranges_and_static_tree():
    cfg = {
        "system": {"host-name": "gw"},
        "interfaces": {"ethernet": {"eth0": {"address": ["203.0.113.2/30"]}}},
        "nat": {
            "source": {
                "rule": {
                    "5": {
                        "exclude": {},
                        "source": {"address": "10.9.0.0/24"},
                        "outbound-interface": "eth0",
                    },
                    "6": {
                        "disable": {},
                        "source": {"address": "10.8.0.0-10.8.0.99"},
                        "translation": {"address": "203.0.113.2"},
                    },
                }
            },
            "static": {
                "rule": {
                    "1": {
                        "destination": {"address": "203.0.113.5"},
                        "translation": {"address": "10.0.0.99"},
                    }
                }
            },
        },
    }
    batch = normalize_vyos({"config": cfg, "version_text": VERSION, "links": LINKS}, l3dom="home")
    nats = {n.uid: n.props for n in batch.nodes if n.label == "NatRule"}
    excl = nats["vyos:gw:nat:source:5"]
    assert excl["exclude"] is True and excl["out_if"] == "eth0"  # 1.3 bare-string spelling
    disabled = nats["vyos:gw:nat:source:6"]
    assert disabled["enabled"] is False
    assert disabled["orig_src"] == "10.8.0.0-10.8.0.99"
    assert not any(n.label == "IpAddress" and "-" in n.props.get("ip", "") for n in batch.nodes)
    static = nats["vyos:gw:nat:static:1"]
    assert static["kind"] == "static" and static["translation"] == "10.0.0.99"


def test_static_route_and_wireguard_and_dhcp_flag():
    batch = _batch()
    statics = [r for r in batch.rels if r.rel_type == "STATIC_ROUTE"]
    assert statics and statics[0].props["next_hop"] == "192.168.1.2"
    tunnels = [n for n in batch.nodes if n.label == "Tunnel"]
    assert tunnels and tunnels[0].props["encap"] == "wireguard"
    lan = next(n for n in batch.nodes if n.label == "Prefix" and n.props["cidr"] == "192.168.1.0/24")
    assert lan.props.get("dhcp") is True


def test_pbr_policy_rules_and_table_redirect():
    batch = _batch()
    pbr = next(n for n in batch.nodes if n.label == "PbrPolicy")
    assert pbr.uid == "vyos:gw:pbr:VPN-PBR"
    # attached to the vif it steers
    enforces = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ENFORCES"}
    assert ("dev:gw/if/eth1.30", "vyos:gw:pbr:VPN-PBR") in enforces
    # ordered rules with match edges into the shared object model
    rules = {n.uid: n.props for n in batch.nodes if n.label == "FwRule" and n.uid.startswith("vyos:gw:pbr:")}
    assert rules["vyos:gw:pbr:VPN-PBR:10"]["position"] == 10
    src = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "SRC"}
    assert ("vyos:gw:pbr:VPN-PBR:20", "vyos:gw:grp:addr:CAMERAS") in src
    # rule 20 redirects into policy table 100, rule 10 into main
    redirects = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "REDIRECTS_VIA"}
    assert ("vyos:gw:pbr:VPN-PBR:20", "vrf:dev:gw:table100") in redirects
    assert ("vyos:gw:pbr:VPN-PBR:10", "vrf:dev:gw:default") in redirects
    # The SvcObject is namespaced under `pbr:`.
    svc = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "SVC"}
    svc_objs = {n.uid: n.props for n in batch.nodes if n.label == "SvcObject"}
    (rule30_svc,) = (end for start, end in svc if start == "vyos:gw:pbr:VPN-PBR:30")
    assert rule30_svc.startswith("vyos:gw:svc:pbr:")
    assert svc_objs[rule30_svc]["proto"] == "tcp"
    assert svc_objs[rule30_svc]["ports"] == ["8443"]


def test_policy_table_default_route_egresses_via_wireguard():
    batch = _batch()
    t100 = next(n for n in batch.nodes if n.label == "VrfInstance" and n.uid == "vrf:dev:gw:table100")
    assert t100.props["kind"] == "policy-table"
    statics = [r for r in batch.rels if r.rel_type == "STATIC_ROUTE" and r.start_uid == t100.uid]
    assert statics and statics[0].props["interface"] == "wg0"
    via = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "VIA"}
    assert ("pfx:vrf-dev-gw-table100:0.0.0.0/0", "dev:gw/if/wg0") in via


def test_zone_pairs_bind_rulesets_to_zone_direction():
    batch = _batch()
    zones = {n.uid: n.props for n in batch.nodes if n.label == "Zone"}
    assert zones["vyos:gw:zone:WAN"]["default_action"] == "drop"
    # `zone WAN from LAN firewall name LAN-WAN` is the LAN-to-WAN rulebase
    frm = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "FROM_ZONE"}
    to = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "TO_ZONE"}
    assert ("vyos:gw:fw:LAN-WAN", "vyos:gw:zone:LAN") in frm
    assert ("vyos:gw:fw:LAN-WAN", "vyos:gw:zone:WAN") in to


def test_firewall_rule_keeps_its_interface_condition():
    batch = _batch()
    rule = next(n for n in batch.nodes if n.uid == "vyos:gw:fw:LAN-WAN:20")
    assert rule.props["out_interface"] == "eth0"


def test_address_range_is_not_an_ip_address():
    """`address 10.0.0.5-10.0.0.9` is a range, not a host address."""
    cfg = json.loads(json.dumps(CONFIG))
    cfg["firewall"]["group"]["address-group"]["POOL"] = {"address": ["192.168.30.50-192.168.30.60"]}
    batch = normalize_vyos({"config": cfg, "version_text": VERSION, "links": LINKS}, l3dom="home")
    assert not [n for n in batch.nodes if n.label == "IpAddress" and "-" in n.props["ip"]]
    pool = next(n for n in batch.nodes if n.uid == "vyos:gw:grp:addr:POOL")
    assert pool.props["ranges"] == ["192.168.30.50-192.168.30.60"]


def test_equal_cost_routes_all_survive_collection():
    batch = _batch()
    via = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "VIA"}
    assert ("pfx:vrf-dev-gw-table100:0.0.0.0/0", "dev:gw/if/wg0") in via
    assert ("pfx:vrf-dev-gw-table100:0.0.0.0/0", "dev:gw/if/wg1") in via


def test_collector_uses_typed_config():
    from hst.core import Settings

    c = VyosCollector(
        VyosConfig(
            host="gw1", auth=SshPassword(username="vyos", password="pw"), site_code="dc1", l3dom="dc1"
        ),
        Settings(_env_file=None),
    )
    assert c.scope == "vyos:gw1"
    assert c.config.host_key == ""


# --- operational addresses (`ip -j addr show`) ---------------------------------
#
# The config JSON carries only configured addresses.

ADDRS = [
    {
        "ifname": "eth1",
        "addr_info": [
            {"family": "inet", "local": "192.168.1.1", "prefixlen": 24, "scope": "global"},
            # statically configured ULA, in CONFIG: added once
            {"family": "inet6", "local": "fd00:1234::1", "prefixlen": 64, "scope": "global"},
            # learned GUA: the delegated prefix from the provider
            {
                "family": "inet6",
                "local": "2001:db8:abcd::1",
                "prefixlen": 64,
                "scope": "global",
                "dynamic": True,
            },
            # privacy address: rotates, skipped
            {
                "family": "inet6",
                "local": "2001:db8:abcd::f00d",
                "prefixlen": 64,
                "scope": "global",
                "temporary": True,
            },
            # link-local: not a reachable prefix
            {"family": "inet6", "local": "fe80::1", "prefixlen": 64, "scope": "link"},
        ],
    },
    # PPPoE uplink: IPCP-assigned, point-to-point, host-length prefix
    {
        "ifname": "pppoe03",
        "addr_info": [
            {
                "family": "inet",
                "local": "203.0.113.45",
                "prefixlen": 32,
                "scope": "global",
                "address": "203.0.113.1",
            },
        ],
    },
    {
        "ifname": "eth99",
        "addr_info": [
            {"family": "inet", "local": "10.0.0.1", "prefixlen": 24, "scope": "global"},
        ],
    },
]


def _op_batch():
    cfg = json.loads(json.dumps(CONFIG))
    cfg["interfaces"]["ethernet"]["eth1"]["address"].append("fd00:1234::1/64")
    cfg["interfaces"]["pppoe"] = {"pppoe03": {"description": "WAN provider"}}
    return normalize_vyos(
        {"config": cfg, "version_text": VERSION, "links": LINKS, "addrs": ADDRS},
        l3dom="home",
    )


def _ips(batch):
    return {n.props["ip"]: n for n in batch.nodes if n.label == "IpAddress"}


def test_learned_ipv6_gua_is_collected_alongside_the_configured_ula():
    ips = _ips(_op_batch())
    assert "fd00:1234::1" in ips, "configured ULA lost"
    assert "2001:db8:abcd::1" in ips, "learned GUA missing"
    assert ips["fd00:1234::1"].props["origin"] == "configured"
    assert ips["2001:db8:abcd::1"].props["origin"] == "dynamic"


def test_pppoe_wan_address_is_collected():
    batch = _op_batch()
    ips = _ips(batch)
    assert "203.0.113.45" in ips, "PPPoE WAN address missing"
    assert ips["203.0.113.45"].props["origin"] == "dynamic"
    # attached to the interface it belongs to
    has_ip = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "HAS_IP"}
    assert ("dev:gw/if/pppoe03", "ip:vrf-dev-gw-default:203.0.113.45") in has_ip


def test_point_to_point_address_creates_no_host_length_prefix():
    """A /32 is a p2p link, not a one-address network."""
    prefixes = {n.props["cidr"] for n in _op_batch().nodes if n.label == "Prefix"}
    assert "203.0.113.45/32" not in prefixes


def test_link_local_and_privacy_addresses_are_skipped():
    ips = _ips(_op_batch())
    assert "fe80::1" not in ips, "link-local is not a reachable address"
    assert "2001:db8:abcd::f00d" not in ips, "RFC 4941 privacy address would churn the graph"


def test_an_interface_keeps_its_ipv6_link_local_addresses():
    """A route learned over the link names its next hop by the
    neighbour's link-local address, which the trace finds on the egress link
    by the interface property, not by an IpAddress node."""
    interfaces = {n.uid: n.props for n in _op_batch().nodes if n.label == "Interface"}
    assert interfaces["dev:gw/if/eth1"]["ipv6_link_local"] == ["fe80::1"]
    assert "ipv6_link_local" not in interfaces["dev:gw/if/pppoe03"]


def test_configured_address_is_not_duplicated_by_the_operational_merge():
    batch = _op_batch()
    eth1_v4 = [n for n in batch.nodes if n.label == "IpAddress" and n.props["ip"] == "192.168.1.1"]
    assert len(eth1_v4) == 1
    assert eth1_v4[0].props["origin"] == "configured"


def test_addresses_on_unconfigured_interfaces_are_ignored():
    """The configuration is the interface inventory; `ip addr` only enriches it."""
    assert "10.0.0.1" not in _ips(_op_batch())


def test_missing_addrs_key_is_tolerated():
    batch = normalize_vyos({"config": CONFIG, "version_text": VERSION, "links": LINKS}, l3dom="home")
    assert any(n.label == "IpAddress" for n in batch.nodes)


# --- link speed and duplex ---------------------------------------------------
#
# `link_speeds` holds one `<ifname> <speed> <duplex>` text line per interface under /sys/class/net.

LINK_SPEEDS_TEXT = "\n".join(
    [
        "eth0 1000 full",
        "",  # blank lines are tolerated
        "eth1 100 half",
        "eth2 -1 unknown",
        "pppoe03 unknown unknown",
    ]
)


def _speed_config():
    cfg = json.loads(json.dumps(CONFIG))
    cfg["interfaces"]["ethernet"]["eth2"] = {"description": "third port"}
    cfg["interfaces"]["pppoe"] = {"pppoe03": {"description": "WAN provider"}}
    return cfg


def test_operational_link_speed_and_duplex_land_on_ethernet_ports():
    batch = normalize_vyos(
        {
            "config": _speed_config(),
            "version_text": VERSION,
            "links": LINKS,
            "link_speeds": LINK_SPEEDS_TEXT,
        },
        l3dom="home",
    )
    ports = {n.props.get("name"): n.props for n in batch.nodes if n.label == "Port"}
    assert ports["eth0"]["speed_mbps"] == 1000
    assert ports["eth0"]["duplex"] == "full"
    assert ports["eth0"]["speed_source"] == "vyos:/sys/class/net/eth0/speed"
    assert ports["eth1"]["speed_mbps"] == 100
    assert ports["eth1"]["duplex"] == "half"
    assert ports["eth1"]["speed_source"] == "vyos:/sys/class/net/eth1/speed"
    assert "speed_mbps" not in ports["eth2"]
    assert "duplex" not in ports["eth2"]
    assert "speed_source" not in ports["eth2"]
    assert "pppoe03" not in ports


def test_configured_speed_and_duplex_are_recorded_only_when_fixed():
    """`auto`, the VyOS default for both settings, states no fixed value and
    stays null; a numeric speed and an explicit duplex are recorded."""
    cfg = json.loads(json.dumps(CONFIG))
    cfg["interfaces"]["ethernet"]["eth0"]["speed"] = "1000"
    cfg["interfaces"]["ethernet"]["eth0"]["duplex"] = "full"
    cfg["interfaces"]["ethernet"]["eth1"]["speed"] = "auto"
    cfg["interfaces"]["ethernet"]["eth1"]["duplex"] = "auto"
    batch = normalize_vyos({"config": cfg, "version_text": VERSION, "links": LINKS}, l3dom="home")
    ports = {n.props.get("name"): n.props for n in batch.nodes if n.label == "Port"}
    assert ports["eth0"]["speed_configured_mbps"] == 1000
    assert ports["eth0"]["duplex_configured"] == "full"
    assert "speed_configured_mbps" not in ports["eth1"]
    assert "duplex_configured" not in ports["eth1"]


def test_missing_link_speeds_key_gives_every_port_null_speed_and_an_unknown_section():
    raw = {"config": CONFIG, "version_text": VERSION, "links": LINKS}
    batch = normalize_vyos(raw, l3dom="home")
    ports = {n.props.get("name"): n.props for n in batch.nodes if n.label == "Port"}
    for name in ("eth0", "eth1"):
        assert "speed_mbps" not in ports[name]
        assert "duplex" not in ports[name]
        assert "speed_source" not in ports[name]
    assert section_outcomes(raw)["link_speeds"].status == "unknown"


# --- VRF-scoped addressing ----------------------------------------------------

VRF_CONFIG = {
    "system": {"host-name": "gw"},
    "vrf": {"name": {"RED": {"table": "100"}, "BLUE": {"table": "200"}}},
    "interfaces": {
        "ethernet": {
            "eth10": {"address": ["10.0.0.1/24"], "vrf": "RED"},
            "eth11": {"address": ["10.0.0.1/24"], "vrf": "BLUE"},
            "eth12": {"address": ["192.168.50.1/24"]},  # global table
        },
    },
}


def _vrf_batch():
    return normalize_vyos({"config": VRF_CONFIG, "version_text": VERSION, "links": []}, l3dom="home")


def test_same_subnet_in_two_vrfs_does_not_collapse_onto_one_prefix():
    prefixes = [n for n in _vrf_batch().nodes if n.label == "Prefix" and n.props["cidr"] == "10.0.0.0/24"]
    assert len(prefixes) == 2, "the two VRFs merged"
    assert len({n.uid for n in prefixes}) == 2


def test_same_address_in_two_vrfs_stays_two_nodes():
    ips = [n for n in _vrf_batch().nodes if n.label == "IpAddress" and n.props["ip"] == "10.0.0.1"]
    assert len(ips) == 2
    assert {n.props["l3dom"] for n in ips} == {"home:RED", "home:BLUE"}


def test_the_global_table_reads_as_the_bare_scope():
    ip = next(n for n in _vrf_batch().nodes if n.label == "IpAddress" and n.props["ip"] == "192.168.50.1")
    assert ip.props["l3dom"] == "home"


def test_each_vrf_becomes_its_own_instance_realizing_its_own_domain():
    batch = _vrf_batch()
    vrfs = {n.props["name"] for n in batch.nodes if n.label == "VrfInstance"}
    assert {"default", "RED", "BLUE"} <= vrfs
    domains = {n.uid for n in batch.nodes if n.label == "RoutingDomain"}
    assert len(domains) == 3, "each VRF needs its own domain or addresses merge"
    # PBR and route leaking reference the table number.
    red = next(n for n in batch.nodes if n.label == "VrfInstance" and n.props["name"] == "RED")
    assert red.props["table"] == "100"


def test_interfaces_are_bound_to_their_own_vrf():
    batch = _vrf_batch()
    in_vrf = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "IN_VRF"}
    red = next(n.uid for n in batch.nodes if n.label == "VrfInstance" and n.props["name"] == "RED")
    blue = next(n.uid for n in batch.nodes if n.label == "VrfInstance" and n.props["name"] == "BLUE")
    assert ("dev:gw/if/eth10", red) in in_vrf
    assert ("dev:gw/if/eth11", blue) in in_vrf


def test_an_interface_referencing_an_undeclared_vrf_is_still_modelled():
    cfg = json.loads(json.dumps(VRF_CONFIG))
    cfg["interfaces"]["ethernet"]["eth13"] = {"address": ["172.16.0.1/24"], "vrf": "GHOST"}
    batch = normalize_vyos({"config": cfg, "version_text": VERSION, "links": []}, l3dom="home")
    assert any(n.label == "VrfInstance" and n.props["name"] == "GHOST" for n in batch.nodes)


def test_default_vrf_instance_is_marked_is_global_with_default_table_id():
    batch = _batch()
    default = next(n for n in batch.nodes if n.label == "VrfInstance" and n.uid == "vrf:dev:gw:default")
    assert default.props["is_global"] is True
    assert default.props["table_id"] == "default"


def test_named_vrf_instance_carries_its_own_table_id_and_no_is_global():
    batch = _vrf_batch()
    red = next(n for n in batch.nodes if n.label == "VrfInstance" and n.props["name"] == "RED")
    assert red.props["table_id"] == "RED"
    assert "is_global" not in red.props


# --- forwarding-context identity ----------------------------------------------------
#
# Routed and connected addresses anchor on the owning VrfInstance uid.


def test_vrf_scoped_prefix_and_ip_uids_are_anchored_on_the_vrf_instance_uid():
    batch = _vrf_batch()
    red = next(n.uid for n in batch.nodes if n.label == "VrfInstance" and n.props["name"] == "RED")
    blue = next(n.uid for n in batch.nodes if n.label == "VrfInstance" and n.props["name"] == "BLUE")
    assert red != blue

    red_pfx = next(
        n
        for n in batch.nodes
        if n.label == "Prefix" and n.props["cidr"] == "10.0.0.0/24" and n.props["l3dom"] == "home:RED"
    )
    blue_pfx = next(
        n
        for n in batch.nodes
        if n.label == "Prefix" and n.props["cidr"] == "10.0.0.0/24" and n.props["l3dom"] == "home:BLUE"
    )
    assert red_pfx.uid == uid.prefix(red, "10.0.0.0/24")
    assert blue_pfx.uid == uid.prefix(blue, "10.0.0.0/24")
    assert red_pfx.props["anchor"] == red
    assert blue_pfx.props["anchor"] == blue

    red_ip = next(
        n
        for n in batch.nodes
        if n.label == "IpAddress" and n.props["ip"] == "10.0.0.1" and n.props["l3dom"] == "home:RED"
    )
    blue_ip = next(
        n
        for n in batch.nodes
        if n.label == "IpAddress" and n.props["ip"] == "10.0.0.1" and n.props["l3dom"] == "home:BLUE"
    )
    assert red_ip.uid == uid.ip(red, "10.0.0.1")
    assert blue_ip.uid == uid.ip(blue, "10.0.0.1")


def test_anchor_prop_present_on_every_emitted_prefix_and_ip():
    """The uid's identity segment is exactly `uid.slug(anchor)`."""
    batch = _vrf_batch()
    anchored = [n for n in batch.nodes if n.label in ("Prefix", "IpAddress")]
    assert anchored
    for n in anchored:
        assert "anchor" in n.props, n.uid
        assert n.uid.split(":", 2)[1] == uid.slug(n.props["anchor"]), n.uid


# --- IPv6 policy trees --------------------------------------------------------
#
# `firewall ipv6`, `protocols static route6` and `nat66` mirror their v4
# counterparts shape-for-shape.

V6_CONFIG = {
    "system": {"host-name": "gw"},
    "interfaces": {"ethernet": {"eth1": {"address": ["fd00:1234::1/64"]}}},
    "firewall": {
        "group": {
            "ipv6-address-group": {"SERVERS6": {"address": ["fd00:1234::10"]}},
            "ipv6-network-group": {"ULA": {"network": ["fd00::/8"]}},
        },
        "zone": {
            "WAN": {
                "member": {"interface": ["eth1"]},
                "from": {"LAN": {"firewall": {"ipv6-name": "LAN-WAN-6"}}},
            },
            "LAN": {"member": {"interface": ["eth1"]}},
        },
        "ipv6": {
            "name": {
                "LAN-WAN-6": {
                    "default-action": "drop",
                    "rule": {
                        "10": {
                            "action": "accept",
                            "source": {"group": {"address-group": "SERVERS6"}},
                            "destination": {"address": "2001:db8::20"},
                        },
                        # same references under the explicit ipv6-* spelling
                        "20": {
                            "action": "accept",
                            "source": {"group": {"ipv6-address-group": "SERVERS6"}},
                            "destination": {"group": {"ipv6-network-group": "ULA"}},
                        },
                    },
                },
            },
            "forward": {
                "filter": {
                    "default-action": "drop",
                    "rule": {
                        "10": {
                            "action": "drop",
                            "destination": {"group": {"network-group": "ULA"}},
                        },
                    },
                },
            },
        },
    },
    "nat66": {
        "source": {
            "rule": {
                "100": {
                    "source": {"address": "fd00:1234::/64"},
                    "translation": {"address": "masquerade"},
                }
            }
        },
        "destination": {
            "rule": {
                "10": {
                    "destination": {"address": "2001:db8::5"},
                    "translation": {"address": "fd00:1234::10"},
                }
            }
        },
    },
    "policy": {
        "route6": {
            "VPN-PBR-6": {
                "interface": ["eth1"],
                "rule": {
                    "10": {
                        "description": "local stays local",
                        "destination": {"group": {"network-group": "ULA"}},
                        "set": {"table": "main"},
                    },
                    "20": {
                        "source": {"group": {"ipv6-address-group": "SERVERS6"}},
                        "set": {"table": "100"},
                    },
                },
            },
        },
    },
    "protocols": {
        "static": {
            "route6": {"::/0": {"next-hop": {"fd00:1234::ff": {}}}},
            "table": {"100": {"route6": {"::/0": {"next-hop": {"fd00:1234::fe": {}}}}}},
        }
    },
}


def _v6_batch():
    return normalize_vyos({"config": V6_CONFIG, "version_text": VERSION, "links": []}, l3dom="home")


def test_ipv6_named_ruleset_and_chain_are_modelled():
    batch = _v6_batch()
    rulebases = {n.uid: n.props for n in batch.nodes if n.label == "FwRulebase"}
    assert rulebases["vyos:gw:fw:ipv6:LAN-WAN-6"]["default_action"] == "drop"
    assert rulebases["vyos:gw:fw:ipv6-forward"]["kind"] == "access"
    rules = {n.uid: n.props for n in batch.nodes if n.label == "FwRule"}
    assert rules["vyos:gw:fw:ipv6:LAN-WAN-6:10"]["action"] == "accept"
    assert rules["vyos:gw:fw:ipv6-forward:10"]["action"] == "drop"


def test_ipv6_groups_resolve_with_af_6():
    batch = _v6_batch()
    resolves = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "RESOLVES_TO"}
    assert ("vyos:gw:grp:addr6:SERVERS6", "ip:home:fd00:1234::10") in resolves
    assert ("vyos:gw:grp:net6:ULA", "pfx:home:fd00::/8") in resolves
    ip = next(n for n in batch.nodes if n.label == "IpAddress" and n.props["ip"] == "fd00:1234::10")
    assert ip.props["af"] == 6
    pfx = next(n for n in batch.nodes if n.label == "Prefix" and n.props["cidr"] == "fd00::/8")
    assert pfx.props["af"] == 6


def test_ipv6_rule_group_and_inline_address_edges():
    batch = _v6_batch()
    src = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "SRC"}
    # the v6 ruleset's group reference resolves against the ipv6 group namespace
    assert ("vyos:gw:fw:ipv6:LAN-WAN-6:10", "vyos:gw:grp:addr6:SERVERS6") in src
    dst = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "DST"}
    inline = next(u for _, u in dst if u.startswith("vyos:gw:obj:"))
    obj = next(n for n in batch.nodes if n.uid == inline)
    assert obj.props["name"] == "2001:db8::20"
    resolves = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "RESOLVES_TO"}
    assert (inline, "ip:home:2001:db8::20") in resolves


def test_ipv6_rule_group_references_resolve_from_both_spellings():
    """A v6 rule side names its groups as `address-group`/`network-group` or as
    `ipv6-address-group`/`ipv6-network-group` depending on VyOS version."""
    batch = _v6_batch()
    src = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "SRC"}
    dst = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "DST"}
    assert ("vyos:gw:fw:ipv6:LAN-WAN-6:10", "vyos:gw:grp:addr6:SERVERS6") in src
    assert ("vyos:gw:fw:ipv6:LAN-WAN-6:20", "vyos:gw:grp:addr6:SERVERS6") in src
    assert ("vyos:gw:fw:ipv6:LAN-WAN-6:20", "vyos:gw:grp:net6:ULA") in dst
    rules = {n.uid: n.props for n in batch.nodes if n.label == "FwRule"}
    assert rules["vyos:gw:fw:ipv6:LAN-WAN-6:20"]["src_any"] is False
    assert rules["vyos:gw:fw:ipv6:LAN-WAN-6:20"]["dst_any"] is False


def test_policy_route6_mirrors_the_v4_pbr_model():
    """`policy route6` steers into the same policy tables as `policy route`,
    with its own uid namespace (a v4 and a v6 policy may share a name) and its
    match sides in the v6 group namespace."""
    batch = _v6_batch()
    pbr = next(n for n in batch.nodes if n.label == "PbrPolicy")
    assert pbr.uid == "vyos:gw:pbr:ipv6:VPN-PBR-6"
    enforces = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ENFORCES"}
    assert ("dev:gw/if/eth1", "vyos:gw:pbr:ipv6:VPN-PBR-6") in enforces
    rules = {n.uid: n.props for n in batch.nodes if n.label == "FwRule" and n.uid.startswith("vyos:gw:pbr:")}
    assert rules["vyos:gw:pbr:ipv6:VPN-PBR-6:10"]["position"] == 10
    assert rules["vyos:gw:pbr:ipv6:VPN-PBR-6:10"]["action"] == "route"
    src = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "SRC"}
    dst = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "DST"}
    assert ("vyos:gw:pbr:ipv6:VPN-PBR-6:20", "vyos:gw:grp:addr6:SERVERS6") in src
    assert ("vyos:gw:pbr:ipv6:VPN-PBR-6:10", "vyos:gw:grp:net6:ULA") in dst
    # rule 20 redirects into policy table 100, rule 10 into main
    redirects = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "REDIRECTS_VIA"}
    assert ("vyos:gw:pbr:ipv6:VPN-PBR-6:20", "vrf:dev:gw:table100") in redirects
    assert ("vyos:gw:pbr:ipv6:VPN-PBR-6:10", "vrf:dev:gw:default") in redirects


def test_ipv6_zone_pair_binds_the_v6_ruleset():
    batch = _v6_batch()
    frm = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "FROM_ZONE"}
    to = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "TO_ZONE"}
    assert ("vyos:gw:fw:ipv6:LAN-WAN-6", "vyos:gw:zone:LAN") in frm
    assert ("vyos:gw:fw:ipv6:LAN-WAN-6", "vyos:gw:zone:WAN") in to


def test_route6_static_routes_resolve_with_af_6():
    batch = _v6_batch()
    statics = [r for r in batch.rels if r.rel_type == "STATIC_ROUTE"]
    assert any(
        r.end_uid == "pfx:vrf-dev-gw-default:::/0" and r.props["next_hop"] == "fd00:1234::ff" for r in statics
    )
    default6 = next(n for n in batch.nodes if n.label == "Prefix" and n.props["cidr"] == "::/0")
    assert default6.props["af"] == 6
    nh = next(n for n in batch.nodes if n.label == "IpAddress" and n.props["ip"] == "fd00:1234::ff")
    assert nh.props["af"] == 6


def test_nat66_rules_mirror_the_v4_model():
    batch = _v6_batch()
    nats = {n.uid: n.props for n in batch.nodes if n.label == "NatRule"}
    snat = nats["vyos:gw:nat66:source:100"]
    assert snat["kind"] == "snat" and snat["translation"] == "masquerade"
    dnat = nats["vyos:gw:nat66:destination:10"]
    assert dnat["kind"] == "dnat"
    xlate = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "XLATE_DST"}
    assert ("vyos:gw:nat66:destination:10", "ip:home:fd00:1234::10") in xlate
    xip = next(n for n in batch.nodes if n.label == "IpAddress" and n.props["ip"] == "fd00:1234::10")
    assert xip.props["af"] == 6


def test_config_without_v6_trees_produces_no_v6_policy_nodes():
    batch = _batch()  # base CONFIG carries no firewall ipv6 / route6 / nat66 / policy route6
    assert not [
        n for n in batch.nodes if n.uid.startswith(("vyos:gw:fw:ipv6", "vyos:gw:nat66:", "vyos:gw:pbr:ipv6"))
    ]
    assert not [n for n in batch.nodes if n.label == "Prefix" and n.props.get("af") == 6]


def test_learned_addresses_inherit_their_interfaces_vrf():
    addrs = [
        {
            "ifname": "eth10",
            "addr_info": [{"family": "inet6", "local": "2001:db8::1", "prefixlen": 64, "scope": "global"}],
        }
    ]
    batch = normalize_vyos(
        {"config": VRF_CONFIG, "version_text": VERSION, "links": [], "addrs": addrs},
        l3dom="home",
    )
    gua = next(n for n in batch.nodes if n.label == "IpAddress" and n.props["ip"] == "2001:db8::1")
    assert gua.props["l3dom"] == "home:RED"


# --- FRR RIB / learned routes (`vtysh -c "show ip route ... json"`) -------------


def _nh(ip=None, dev=None, fib=True, active=True, **extra):
    """One FRR nexthop object; `fib` marks membership in the installed set."""
    nh = {"fib": fib, "active": active, **extra}
    if ip:
        nh["ip"] = ip
    if dev:
        nh["interfaceName"] = dev
    return nh


def _route(prefix, *nexthops, protocol="static", table=254, metric=None, installed=True):
    """FRR omits `installed` on RIB-only routes."""
    r = {"prefix": prefix, "protocol": protocol, "table": table, "nexthops": list(nexthops)}
    if installed:
        r["installed"] = True
        r["selected"] = True
    if metric is not None:
        r["metric"] = metric
    return {prefix: [r]}


def _rib_batch(
    routes=None, routes6=None, tables=None, tables6=None, rib_graph_max_routes=1000, cfg_patch=None
):
    """CONFIG plus an FRR route payload: `routes`/`routes6` are the default
    vrf's by-prefix dicts, `tables`/`tables6` the per-policy-table ones."""
    cfg = json.loads(json.dumps(CONFIG))
    if cfg_patch:
        cfg_patch(cfg)
    raw = {
        "config": cfg,
        "version_text": VERSION,
        "links": LINKS,
        "routes": {"default": routes or {}},
        "routes6": {"default": routes6 or {}},
        "routes_tables": tables or {},
        "routes6_tables": tables6 or {},
    }
    return normalize_vyos(raw, l3dom="home", rib_graph_max_routes=rib_graph_max_routes)


def _add_pppoe0(cfg):
    cfg["interfaces"]["pppoe"] = {"pppoe0": {"description": "WAN"}}


def _learned(batch):
    return [r for r in batch.rels if r.rel_type == "LEARNED_ROUTE"]


def test_main_table_pppoe_default_becomes_a_learned_route():
    """CONFIG has no pppoe interface type."""
    entry = _route("0.0.0.0/0", _nh(ip="62.1.2.3", dev="pppoe0"), metric=1)
    batch = _rib_batch(routes=entry, cfg_patch=_add_pppoe0)
    learned = _learned(batch)
    assert any(
        r.start_uid == "vrf:dev:gw:default"
        and r.end_uid == "pfx:vrf-dev-gw-default:0.0.0.0/0"
        and r.props["next_hop"] == "62.1.2.3"
        for r in learned
    )
    via = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "VIA"}
    assert ("pfx:vrf-dev-gw-default:0.0.0.0/0", "dev:gw/if/pppoe0") in via


def test_a_v6_prefix_in_the_v4_listing_is_dropped():
    v4 = {**_route("0.0.0.0/0", _nh(dev="pppoe0"), metric=20), **_route("::/0", _nh(dev="pppoe0"))}
    batch = _rib_batch(routes=v4, cfg_patch=_add_pppoe0)
    assert len([r for r in _learned(batch) if r.end_uid == "pfx:vrf-dev-gw-default:0.0.0.0/0"]) == 1
    assert not any(r.end_uid == "pfx:vrf-dev-gw-default:::/0" for r in _learned(batch))


def test_a_rib_only_route_frr_did_not_install_is_not_mirrored():
    """FRR marks the routes that forward with `installed`."""
    routes = _route("10.7.0.0/16", _nh(ip="192.168.1.9", dev="eth1"), protocol="bgp")
    backup = _route(
        "10.7.0.0/16",
        _nh(ip="192.168.1.8", dev="eth1", fib=False, active=False),
        protocol="static",
        installed=False,
    )
    routes["10.7.0.0/16"].append(backup["10.7.0.0/16"][0])
    batch = _rib_batch(routes=routes)
    to_prefix = [r for r in _learned(batch) if r.end_uid == "pfx:vrf-dev-gw-default:10.7.0.0/16"]
    assert [r.props["next_hop"] for r in to_prefix] == ["192.168.1.9"]


def test_learned_route_identity_is_the_whole_nexthop_interface_pair():
    """MERGE property maps match by subset."""
    routes = _route("10.20.0.0/16", _nh(ip="10.0.0.1", dev="eth1"), protocol="bgp")
    routes["10.20.0.0/16"].append(_route("10.20.0.0/16", _nh(dev="eth1"))["10.20.0.0/16"][0])
    batch = _rib_batch(routes=routes)
    keys = [r.key for r in _learned(batch) if r.end_uid == "pfx:vrf-dev-gw-default:10.20.0.0/16"]
    assert keys == [{"via": "10.0.0.1|eth1"}, {"via": "|eth1"}]


def test_the_kernels_slaac_copy_of_a_connected_prefix_is_not_mirrored():
    """SLAAC installs its own copy of each connected v6 prefix (proto kernel,
    metric 256, installed but never `selected`)."""
    connected = _route("2001:db8:1::/64", _nh(dev="eth1"), protocol="connected")
    slaac = _route("2001:db8:1::/64", _nh(dev="eth1"), protocol="kernel", metric=256)
    slaac["2001:db8:1::/64"][0].pop("selected")
    connected["2001:db8:1::/64"].append(slaac["2001:db8:1::/64"][0])
    batch = _rib_batch(routes6=connected)
    assert not any(r.end_uid == "pfx:vrf-dev-gw-default:2001:db8:1::/64" for r in _learned(batch))


def test_a_recursive_nexthop_is_not_a_second_leg():
    """FRR lists the recursive nexthop beside what it resolved to."""
    routes = _route(
        "10.8.0.0/16",
        _nh(ip="10.255.0.1", fib=False, active=True, recursive=True),
        _nh(ip="192.168.1.7", dev="eth1", resolver=True),
        protocol="bgp",
    )
    batch = _rib_batch(routes=routes)
    to_prefix = [r for r in _learned(batch) if r.end_uid == "pfx:vrf-dev-gw-default:10.8.0.0/16"]
    assert [r.props["next_hop"] for r in to_prefix] == ["192.168.1.7"]


def test_table_static_dedup_skips_the_kernels_copy_of_a_config_route():
    batch = _rib_batch(tables={"100": _route("0.0.0.0/0", _nh(dev="wg0"), table=100)})
    t100 = next(n for n in batch.nodes if n.label == "VrfInstance" and n.uid == "vrf:dev:gw:table100")
    dup = [
        r
        for r in _learned(batch)
        if r.start_uid == t100.uid
        and r.end_uid == "pfx:vrf-dev-gw-table100:0.0.0.0/0"
        and r.props.get("interface") == "wg0"
    ]
    assert not dup
    statics = [
        r
        for r in batch.rels
        if r.rel_type == "STATIC_ROUTE" and r.start_uid == t100.uid and r.props.get("interface") == "wg0"
    ]
    assert len(statics) == 1


def _static_to(batch, start_uid, end_uid):
    return [
        r
        for r in batch.rels
        if r.rel_type == "STATIC_ROUTE" and r.start_uid == start_uid and r.end_uid == end_uid
    ]


def test_a_config_static_route_takes_the_egress_its_rib_row_resolved():
    batch = _rib_batch(routes=_route("10.99.0.0/24", _nh(ip="192.168.1.2", dev="eth1")))
    pfx = "pfx:vrf-dev-gw-default:10.99.0.0/24"
    assert not any(r.end_uid == pfx for r in _learned(batch))
    statics = _static_to(batch, "vrf:dev:gw:default", pfx)
    assert len(statics) == 1
    assert statics[0].key == {"next_hop": "192.168.1.2"}
    assert statics[0].props["rib_interface"] == "eth1"
    assert statics[0].props["rib_confirmed"] is True
    # `interface` stays unset: it is the relationship key of the
    # interface-declared route form, and writing it here as a plain property
    # would let that form's own upsert MERGE onto this edge by property subset
    assert "interface" not in statics[0].props
    via = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "VIA"}
    assert (pfx, "dev:gw/if/eth1") in via


def test_a_policy_table_static_route_takes_its_rib_rows_egress_too():
    """The same fold inside a `protocols static table N` stanza, which is the
    shape a PBR redirect steers into: the table's own route is what the
    redirected leg resolves its egress from."""

    def patch(cfg):
        cfg["protocols"]["static"]["table"]["300"] = {
            "route": {"10.0.30.0/24": {"next-hop": {"10.0.9.2": {}}}}
        }

    tables = {"300": _route("10.0.30.0/24", _nh(ip="10.0.9.2", dev="eth1"), table=300)}
    batch = _rib_batch(tables=tables, cfg_patch=patch)
    pfx = "pfx:vrf-dev-gw-table300:10.0.30.0/24"
    assert not any(r.end_uid == pfx for r in _learned(batch))
    statics = _static_to(batch, "vrf:dev:gw:table300", pfx)
    assert [r.props.get("rib_interface") for r in statics] == ["eth1"]
    assert statics[0].props["rib_confirmed"] is True
    via = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "VIA"}
    assert (pfx, "dev:gw/if/eth1") in via


def test_an_interface_declared_static_route_is_only_marked_rib_confirmed():
    batch = _rib_batch(tables={"100": _route("0.0.0.0/0", _nh(dev="wg0"), table=100)})
    pfx = "pfx:vrf-dev-gw-table100:0.0.0.0/0"
    statics = [r for r in _static_to(batch, "vrf:dev:gw:table100", pfx) if r.key == {"interface": "wg0"}]
    assert len(statics) == 1
    assert statics[0].props["rib_confirmed"] is True
    assert "rib_interface" not in statics[0].props


def test_a_blackhole_static_and_its_own_rib_row_stay_one_discard_route():
    """FRR reports an installed discard static as a row that names neither a
    next hop nor an interface."""

    def patch(cfg):
        cfg["protocols"]["static"]["route"]["10.0.0.0/8"] = {"blackhole": {}}

    batch = _rib_batch(routes=_route("10.0.0.0/8", _nh()), cfg_patch=patch)
    pfx = "pfx:vrf-dev-gw-default:10.0.0.0/8"
    statics = _static_to(batch, "vrf:dev:gw:default", pfx)
    assert len(statics) == 1
    assert statics[0].props.get("discard") == "blackhole"
    assert statics[0].props.get("rib_confirmed") is None
    assert statics[0].props.get("rib_interface") is None
    assert "next_hop" not in statics[0].key
    assert not [r for r in _learned(batch) if r.end_uid == pfx]


def test_a_reject_static_and_its_own_rib_row_stay_one_discard_route():
    """The reject discard kind takes the same drop as blackhole above."""

    def patch(cfg):
        cfg["protocols"]["static"]["route"]["10.0.0.0/8"] = {"reject": {}}

    batch = _rib_batch(routes=_route("10.0.0.0/8", _nh()), cfg_patch=patch)
    pfx = "pfx:vrf-dev-gw-default:10.0.0.0/8"
    statics = _static_to(batch, "vrf:dev:gw:default", pfx)
    assert len(statics) == 1
    assert statics[0].props.get("discard") == "reject"
    assert statics[0].props.get("rib_confirmed") is None


def test_ecmp_nexthops_become_two_learned_routes_to_one_prefix():
    entry = _route(
        "10.9.9.0/24", _nh(ip="10.9.9.1", dev="eth1"), _nh(ip="10.9.9.2", dev="eth1"), protocol="bgp"
    )
    batch = _rib_batch(routes=entry)
    to_prefix = [r for r in _learned(batch) if r.end_uid == "pfx:vrf-dev-gw-default:10.9.9.0/24"]
    assert {r.props["next_hop"] for r in to_prefix} == {"10.9.9.1", "10.9.9.2"}
    assert len(to_prefix) == 2


def test_connected_route_is_not_mirrored():
    entry = _route("192.168.1.0/24", _nh(dev="eth1"), protocol="connected")
    batch = _rib_batch(routes=entry)
    assert not [r for r in _learned(batch) if r.end_uid == "pfx:vrf-dev-gw-default:192.168.1.0/24"]


def test_v6_default_in_routes6_becomes_a_learned_route_with_af_6():
    entry = _route("::/0", _nh(ip="2001:db8::1", dev="eth1"), metric=1)
    batch = _rib_batch(routes6=entry)
    prefixes = {n.uid: n.props for n in batch.nodes if n.label == "Prefix"}
    assert prefixes["pfx:vrf-dev-gw-default:::/0"]["af"] == 6
    assert any(
        r.end_uid == "pfx:vrf-dev-gw-default:::/0" and r.props["next_hop"] == "2001:db8::1"
        for r in _learned(batch)
    )


def test_rib_graph_max_routes_thresholds_large_tables_but_not_small_ones():
    main_entry = _route("10.50.0.0/24", _nh(ip="192.168.1.99", dev="eth1"), protocol="bgp")
    big_table = {}
    for i in range(2):
        big_table.update(
            _route(f"10.60.{i}.0/24", _nh(ip="192.168.1.50", dev="eth1"), protocol="bgp", table=200)
        )
    batch = _rib_batch(routes=main_entry, tables={"200": big_table}, rib_graph_max_routes=1)
    assert any(r.end_uid == "pfx:vrf-dev-gw-default:10.50.0.0/24" for r in _learned(batch))
    assert not [r for r in _learned(batch) if r.end_uid.startswith("pfx:vrf-dev-gw-table200:10.60.")]


def test_side_tables_are_never_thresholded_even_when_the_graph_mirror_is():
    """side_tables() has no `max_routes`."""
    from hst.core import Settings
    from hst.core.ipenc import prefix_bounds

    hops = [_nh(ip=f"192.168.{50 + i // 250}.{(i % 250) + 1}", dev="eth1") for i in range(1001)]
    big_table = {"500": _route("10.0.0.0/24", *hops, protocol="bgp", table=500)}
    raw = {
        "config": CONFIG,
        "version_text": VERSION,
        "links": LINKS,
        "routes": {"default": {}},
        "routes6": {"default": {}},
        "routes_tables": big_table,
    }

    batch = normalize_vyos(raw, l3dom="home", rib_graph_max_routes=1000)
    assert not [
        r
        for r in batch.rels
        if r.rel_type == "LEARNED_ROUTE" and r.end_uid == "pfx:vrf-dev-gw-table500:10.0.0.0/24"
    ]

    c = VyosCollector(
        VyosConfig(
            host="gw1", auth=SshPassword(username="vyos", password="pw"), site_code="dc1", l3dom="dc1"
        ),
        Settings(_env_file=None),
    )
    tables = c.side_tables(raw)
    rows = tables["rib"]
    assert len(rows) == 1001, "side_tables must carry every row, unlike the graph mirror"
    table500 = [r for r in rows if r["vrf"] == "table500"]
    assert len(table500) == 1001
    row = table500[0]
    assert row["prefix"] == "10.0.0.0/24"
    assert row["interface"] == "eth1"
    lo, hi, plen, af = prefix_bounds("10.0.0.0/24")
    assert (row["lo"], row["hi"], row["prefixlen"], row["af"]) == (lo, hi, plen, af)

    raw_main = {
        "config": CONFIG,
        "version_text": VERSION,
        "links": LINKS,
        "routes": {"default": _route("10.99.9.0/24", _nh(ip="192.168.1.5", dev="eth1"), protocol="bgp")},
        "routes6": {"default": {}},
    }
    main_rows = c.side_tables(raw_main)["rib"]
    assert main_rows and main_rows[0]["vrf"] == "default"


def test_side_table_rows_carry_context_uid_for_their_forwarding_context():
    """context_uid is the uid of the VrfInstance node normalize_vyos emits for
    that table."""
    from hst.core import Settings

    raw = {
        "config": VRF_CONFIG,
        "version_text": VERSION,
        "links": [],
        "routes": {"default": _route("10.50.0.0/24", _nh(ip="192.168.1.99", dev="eth1"), protocol="bgp")},
        "routes6": {"default": {}},
        "routes_tables": {
            "100": _route("10.60.0.0/24", _nh(ip="10.0.0.9", dev="eth10"), protocol="bgp", table=100)
        },
    }
    c = VyosCollector(
        VyosConfig(
            host="gw1", auth=SshPassword(username="vyos", password="pw"), site_code="dc1", l3dom="dc1"
        ),
        Settings(_env_file=None),
    )
    rows = c.side_tables(raw)["rib"]
    vrf_nodes = {n.props["name"]: n.uid for n in c.normalize(raw).nodes if n.label == "VrfInstance"}

    main_row = next(r for r in rows if r["prefix"] == "10.50.0.0/24")
    assert main_row["vrf"] == "default"
    assert main_row["context_uid"] == vrf_nodes["default"]

    red_row = next(r for r in rows if r["prefix"] == "10.60.0.0/24")
    assert red_row["vrf"] == "RED"
    assert red_row["context_uid"] == vrf_nodes["RED"]


def test_a_leaked_rib_nexthop_carries_its_exporting_vrf_as_provenance():
    """FRR names the VRF a cross-VRF (leaked) nexthop resolves in."""
    raw = {
        "config": VRF_CONFIG,
        "version_text": VERSION,
        "links": [],
        "routes": {
            "default": _route("10.60.0.0/24", _nh(ip="10.0.0.9", dev="eth10", vrf="RED"), protocol="bgp")
        },
        "routes6": {"default": {}},
    }
    batch = normalize_vyos(raw, l3dom="dc1")
    vrf_uids = {n.props["name"]: n.uid for n in batch.nodes if n.label == "VrfInstance"}
    learned = [r for r in batch.rels if r.rel_type == "LEARNED_ROUTE"]
    assert learned and learned[0].props["next_hop_vrf"] == vrf_uids["RED"]


def test_a_same_vrf_rib_nexthop_carries_no_provenance():
    raw = {
        "config": VRF_CONFIG,
        "version_text": VERSION,
        "links": [],
        "routes": {"default": _route("10.61.0.0/24", _nh(ip="192.168.50.9", dev="eth12"), protocol="bgp")},
        "routes6": {"default": {}},
    }
    batch = normalize_vyos(raw, l3dom="dc1")
    learned = [r for r in batch.rels if r.rel_type == "LEARNED_ROUTE"]
    assert learned and learned[0].props.get("next_hop_vrf") is None


# --- WireGuard carrier-local address without `source-address` -----------------
#
# core1: neither wg0 nor wg44 states `source-address`.


def _wireguard_carrier_leg(tun_props: dict, inner):
    """A `_CANDIDATES` row shaped from one collected WireGuard Tunnel's own props."""
    from hst.path.gates.tunnel import build_carrier_legs

    row = {
        "tunnel_uid": "tun:core1:wg",
        "encap": "wireguard",
        "state": "up",
        "local_address": tun_props.get("local_address"),
        "remote_address": tun_props["endpoint"],
        "carrier_proto": tun_props["carrier_proto"],
        "carrier_port": tun_props["endpoint_port"],
        "local_port": None,
        "allowed_ips": tun_props["allowed_ips"],
        "binding_kind": "endpoint",
        "local_interface_uid": "if:core1:wg",
        "local_device_uid": "dev:core1",
        "local_context_uid": "vrf:core1:overlay",
        "local_underlay_interface_uid": "if:core1:pppoe0",
        "local_underlay_context_uid": "vrf:core1:wan",
        "remote_interface_uid": "if:peer:wg",
        "remote_device_uid": "dev:peer",
        "remote_context_uid": "vrf:peer:overlay",
        "remote_underlay_interface_uid": "if:peer:eth0",
        "remote_underlay_context_uid": "vrf:peer:wan",
        "peer_tunnel_uid": "tun:peer:wg",
    }
    (leg,) = build_carrier_legs([row], inner)
    return leg


def test_wireguard_local_address_is_derived_from_the_egress_interface_when_unconfigured():
    from hst.path.addrsets import _intervals, _ports, _protoset
    from hst.path.state import FlowRegion

    cfg = {
        "system": {"host-name": "core1"},
        "interfaces": {
            "pppoe": {"pppoe0": {"description": "WAN"}},
            "wireguard": {
                "wg0": {
                    "address": ["10.99.99.1/24"],
                    "peer": {
                        "branch": {"address": "203.0.113.35", "port": "1443", "allowed-ips": ["0.0.0.0/0"]}
                    },
                }
            },
        },
    }
    raw = {
        "config": cfg,
        "version_text": VERSION,
        "links": [],
        "addrs": [
            {
                "ifname": "pppoe0",
                "addr_info": [
                    {"family": "inet", "local": "203.0.113.45", "prefixlen": 32, "scope": "global"},
                ],
            }
        ],
        "routes": {"default": _route("0.0.0.0/0", _nh(dev="pppoe0"), protocol="static")},
        "routes6": {"default": {}},
    }
    batch = normalize_vyos(raw, l3dom="home")
    tun = next(n.props for n in batch.nodes if n.label == "Tunnel" and n.props.get("name") == "branch")
    assert tun["local_address"] == "203.0.113.45"
    assert tun["local_address_source"] == "derived:egress"

    inner = FlowRegion.from_query(
        _intervals(["192.168.10.44/32"]), _intervals(["8.8.8.8/32"]), _protoset(["tcp"]), _ports("443")
    )
    leg = _wireguard_carrier_leg(tun, inner)
    assert leg.status == "complete"
    assert not any("missing or invalid" in e for e in leg.evidence)
    assert leg.outer is not None
    assert leg.outer.rects[0].src == tuple(_intervals(["203.0.113.45"]))


def test_wireguard_local_address_stays_undetermined_without_a_matching_family_address():
    from hst.path.addrsets import _intervals, _ports, _protoset
    from hst.path.state import FlowRegion

    cfg = {
        "system": {"host-name": "core1"},
        "interfaces": {
            "pppoe": {"pppoe0": {"description": "WAN"}},
            "wireguard": {
                "wg44": {
                    "address": ["10.99.44.1/24"],
                    "peer": {
                        "branch6": {
                            "address": "2001:db8:abcd::35",
                            "port": "1443",
                            "allowed-ips": ["::/0"],
                        }
                    },
                }
            },
        },
    }
    raw = {
        "config": cfg,
        "version_text": VERSION,
        "links": [],
        "addrs": [
            {
                "ifname": "pppoe0",
                "addr_info": [
                    {"family": "inet", "local": "203.0.113.45", "prefixlen": 32, "scope": "global"},
                ],
            }
        ],
        "routes": {"default": {}},
        "routes6": {"default": _route("::/0", _nh(dev="pppoe0"), protocol="static")},
    }
    batch = normalize_vyos(raw, l3dom="home")
    tun = next(n.props for n in batch.nodes if n.label == "Tunnel" and n.props.get("name") == "branch6")
    assert "local_address" not in tun
    assert "local_address_source" not in tun

    inner = FlowRegion.from_query(
        _intervals(["2001:db8::10/128"]),
        _intervals(["2606:4700:4700::1111/128"]),
        _protoset(["tcp"]),
        _ports("443"),
    )
    leg = _wireguard_carrier_leg(tun, inner)
    assert leg.status == "indeterminate"
    assert leg.outer is None
    assert "missing or invalid" in leg.evidence[0]


def test_side_rows_keep_discard_leak_interface_only_and_ecmp_semantics():
    from hst.core import Settings
    from hst.path.gates.routing import _rib_route, _route_id

    cfg = {
        "system": {"host-name": "gw"},
        "vrf": {"name": {"RED": {"table": "100"}}},
        "interfaces": {
            "ethernet": {
                "eth1": {"address": ["192.168.1.1/24"]},
                "eth6": {"address": ["10.6.0.1/24"]},
                "eth10": {"address": ["10.0.0.1/24"], "vrf": "RED"},
            },
        },
        "protocols": {
            "static": {
                "route": {
                    "172.16.0.0/12": {"blackhole": {}},
                    "10.6.0.0/24": {"interface": {"eth6": {}}},
                }
            }
        },
    }
    raw = {
        "config": cfg,
        "version_text": VERSION,
        "links": [],
        "routes": {
            "default": {
                **_route("172.16.0.0/12", _nh(), protocol="static"),
                **_route("10.6.0.0/24", _nh(dev="eth6"), protocol="static"),
                **_route("10.70.0.0/24", _nh(ip="10.0.0.9", dev="eth10", vrf="RED"), protocol="bgp"),
                **_route(
                    "10.80.0.0/24",
                    _nh(ip="192.168.1.10", dev="eth1"),
                    _nh(ip="192.168.1.11", dev="eth1"),
                    protocol="bgp",
                ),
            }
        },
        "routes6": {"default": {}},
    }

    c = VyosCollector(
        VyosConfig(
            host="gw1", auth=SshPassword(username="vyos", password="pw"), site_code="dc1", l3dom="dc1"
        ),
        Settings(_env_file=None),
    )
    rows = c.side_tables(raw)["rib"]
    by_prefix = {r["prefix"]: r for r in rows if r["prefix"] != "10.80.0.0/24"}

    blackhole = by_prefix["172.16.0.0/12"]
    assert blackhole["discard"] == "blackhole"
    assert blackhole["next_hop"] is None and blackhole["interface"] is None
    assert blackhole["next_hop_context_uid"] is None

    iface_only = by_prefix["10.6.0.0/24"]
    assert iface_only["discard"] is None
    assert iface_only["next_hop"] is None and iface_only["interface"] == "eth6"

    batch = c.normalize(raw)
    vrf_uids = {n.props["name"]: n.uid for n in batch.nodes if n.label == "VrfInstance"}

    leaked = by_prefix["10.70.0.0/24"]
    assert leaked["discard"] is None
    assert leaked["next_hop_context_uid"] == vrf_uids["RED"]

    ecmp = [r for r in rows if r["prefix"] == "10.80.0.0/24"]
    assert {r["next_hop"] for r in ecmp} == {"192.168.1.10", "192.168.1.11"}
    assert all(r["discard"] is None and r["next_hop_context_uid"] is None for r in ecmp)

    cidrs = {r["prefix"] for r in rows}
    prefix_cidr = {n.uid: n.props["cidr"] for n in batch.nodes if n.label == "Prefix"}
    graph_identities = set()
    for rel in batch.rels:
        if rel.rel_type not in ("LEARNED_ROUTE", "STATIC_ROUTE"):
            continue
        cidr = prefix_cidr.get(rel.end_uid)
        if cidr not in cidrs:
            continue
        graph_row = {
            "cidr": cidr,
            "next_hop": rel.props.get("next_hop"),
            "egress_name": rel.props.get("interface") or rel.props.get("rib_interface"),
            "discard": rel.props.get("discard"),
        }
        graph_identities.add(_route_id(graph_row))

    store_identities = {_route_id(_rib_route(r)) for r in rows}
    assert graph_identities == store_identities


def test_a_static_next_hop_vrf_leak_is_recorded_on_the_route_edge():
    """`set protocols static route ... next-hop <ip> next-hop-vrf <name>` is a declared leak."""
    cfg = json.loads(json.dumps(VRF_CONFIG))
    cfg["protocols"] = {
        "static": {"route": {"10.70.0.0/24": {"next-hop": {"10.0.0.9": {"next-hop-vrf": "RED"}}}}}
    }
    raw = {"config": cfg, "version_text": VERSION, "links": []}
    batch = normalize_vyos(raw, l3dom="dc1")
    vrf_uids = {n.props["name"]: n.uid for n in batch.nodes if n.label == "VrfInstance"}
    statics = [
        r for r in batch.rels if r.rel_type == "STATIC_ROUTE" and r.props.get("next_hop") == "10.0.0.9"
    ]
    assert statics and statics[0].props["next_hop_vrf"] == vrf_uids["RED"]


def test_a_vyos_1_4_static_vrf_leak_is_recorded_on_the_route_edge():
    """VyOS 1.4 spells the leak `next-hop <ip> vrf <name>` and `interface
    <name> vrf <name>`."""
    cfg = json.loads(json.dumps(VRF_CONFIG))
    cfg["protocols"] = {
        "static": {
            "route": {
                "10.70.0.0/24": {"next-hop": {"10.0.0.9": {"vrf": "RED"}}},
                "10.71.0.0/24": {"interface": {"eth1": {"vrf": "RED"}}},
            }
        }
    }
    raw = {"config": cfg, "version_text": VERSION, "links": []}
    batch = normalize_vyos(raw, l3dom="dc1")
    vrf_uids = {n.props["name"]: n.uid for n in batch.nodes if n.label == "VrfInstance"}
    statics = {
        r.props.get("next_hop") or r.props.get("interface"): r.props
        for r in batch.rels
        if r.rel_type == "STATIC_ROUTE"
    }
    assert statics["10.0.0.9"]["next_hop_vrf"] == vrf_uids["RED"]
    assert statics["eth1"]["next_hop_vrf"] == vrf_uids["RED"]


def test_frrs_nexthop_vrf_is_folded_into_the_config_static_route():
    """A static route whose leak FRR reports in its own row (per-nexthop
    `vrf`) keeps that exporting context when the row is folded into the
    config route."""

    def patch(cfg):
        cfg["vrf"] = {"name": {"RED": {"table": "100"}}}
        cfg["protocols"] = {"static": {"route": {"10.70.0.0/24": {"next-hop": {"192.168.1.9": {}}}}}}

    batch = _rib_batch(
        routes=_route("10.70.0.0/24", _nh(ip="192.168.1.9", dev="eth1", vrf="RED")), cfg_patch=patch
    )
    vrf_uids = {n.props["name"]: n.uid for n in batch.nodes if n.label == "VrfInstance"}
    statics = [
        r for r in batch.rels if r.rel_type == "STATIC_ROUTE" and r.props.get("next_hop") == "192.168.1.9"
    ]

    assert len(statics) == 1
    assert statics[0].props["rib_confirmed"] is True
    assert statics[0].props["next_hop_vrf"] == vrf_uids["RED"]


def test_a_vif_records_vlan_carriage_on_its_physical_port():
    batch = normalize_vyos({"config": CONFIG, "version_text": VERSION, "links": []}, l3dom="home")
    ports = {n.props.get("name"): n.uid for n in batch.nodes if n.label == "Port"}
    vlans = {n.props.get("vid"): n.uid for n in batch.nodes if n.label == "VlanInstance"}
    carries = {(r.start_uid, r.end_uid): r.props for r in batch.rels if r.rel_type == "CARRIES"}
    assert (ports["eth1"], vlans[30]) in carries
    assert (ports["eth1"], vlans[40]) in carries
    assert carries[(ports["eth1"], vlans[30])]["native"] is False


# --- BGP / route-policy capture ------------------------------------------------
#
# Rule 20 of CUSTOMER-OUT references a prefix-list that is not defined.

BGP_CONFIG = {
    "system": {"host-name": "gw"},
    "interfaces": {"ethernet": {"eth0": {"address": ["203.0.113.1/30"]}}},
    "policy": {
        "prefix-list": {
            "CUSTOMER-IN": {
                "rule": {
                    "10": {"action": "permit", "prefix": "192.0.2.0/24", "le": "32"},
                    "20": {"action": "permit", "prefix": "198.51.0.0/16", "ge": "20", "le": "24"},
                },
            },
        },
        "route-map": {
            "COMMON-SET": {
                "rule": {"10": {"action": "permit", "set": {"local-preference": "150"}}},
            },
            "CUSTOMER-OUT": {
                "rule": {
                    "10": {
                        "action": "permit",
                        "match": {"ip": {"address": {"prefix-list": "CUSTOMER-IN"}}},
                        "set": {"local-preference": "200", "metric": "50"},
                        "call": "COMMON-SET",
                    },
                    "20": {
                        "action": "deny",
                        "match": {"ip": {"address": {"prefix-list": "GHOST-PL"}}},
                    },
                },
            },
        },
    },
    "protocols": {
        "bgp": {
            "system-as": "65000",
            "parameters": {"router-id": "203.0.113.1"},
            "neighbor": {
                "203.0.113.2": {
                    "remote-as": "65001",
                    "address-family": {
                        "ipv4-unicast": {
                            "prefix-list": {"import": "CUSTOMER-IN"},
                            "route-map": {"export": "CUSTOMER-OUT"},
                        },
                    },
                },
                "10.0.0.2": {
                    "remote-as": "65000",
                    "address-family": {"ipv4-unicast": {}},
                },
                "192.0.2.9": {"remote-as": "auto"},
            },
        },
    },
}


def _bgp_batch(caplog=None):
    return normalize_vyos({"config": BGP_CONFIG, "version_text": VERSION, "links": []}, l3dom="wan")


def test_bgp_process_is_captured_with_its_asn_and_router_id():
    batch = _bgp_batch()
    procs = {n.uid: n.props for n in batch.nodes if n.label == "RoutingProcess"}
    ru = "rproc:dev:gw:default:bgp"
    assert procs[ru]["proto"] == "bgp"
    assert procs[ru]["asn"] == 65000
    assert procs[ru]["router_id"] == "203.0.113.1"
    assert procs[ru]["ebgp_requires_policy"] is False
    in_vrf = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "IN_VRF" and r.start_uid == ru}
    assert ("rproc:dev:gw:default:bgp", "vrf:dev:gw:default") in in_vrf


def test_ebgp_and_ibgp_sessions_carry_local_and_peer_asn():
    batch = _bgp_batch()
    sessions = {n.props["peer_ip"]: n.props for n in batch.nodes if n.label == "BgpSession"}
    customer = sessions["203.0.113.2"]
    assert customer["local_asn"] == 65000 and customer["peer_asn"] == 65001  # eBGP: differ
    core = sessions["10.0.0.2"]
    assert core["local_asn"] == 65000 and core["peer_asn"] == 65000  # iBGP: equal
    has = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "HAS"}
    ru = "rproc:dev:gw:default:bgp"
    assert (ru, uid.bgp_session(ru, "203.0.113.2", "default")) in has
    assert (ru, uid.bgp_session(ru, "10.0.0.2", "default")) in has
    endpoints = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ENDPOINT"}
    # The address anchors on the session's own VRF.
    vrf_uid = "vrf:dev:gw:default"
    assert (uid.bgp_session(ru, "203.0.113.2", "default"), uid.ip(vrf_uid, "203.0.113.2")) in endpoints


def _session_props(neighbors, peer_groups=None):
    cfg = json.loads(json.dumps(BGP_CONFIG))
    cfg["protocols"]["bgp"]["neighbor"] = neighbors
    if peer_groups is not None:
        cfg["protocols"]["bgp"]["peer-group"] = peer_groups
    batch = normalize_vyos({"config": cfg, "version_text": VERSION, "links": []}, l3dom="wan")
    return batch, {n.props["peer_ip"]: n for n in batch.nodes if n.label == "BgpSession"}


def test_route_reflector_client_is_stated_on_every_session():
    """True from the neighbor or its peer-group, false when neither
    states it, absent when the peer-group is undefined and could have."""
    rr = {"ipv4-unicast": {"route-reflector-client": {}}}
    _batch, sessions = _session_props(
        {
            "10.0.0.2": {"remote-as": "65000", "address-family": rr},
            "10.0.0.3": {"remote-as": "65000", "peer-group": "CLIENTS"},
            "10.0.0.4": {"remote-as": "65000", "address-family": {"ipv4-unicast": {}}},
            "10.0.0.5": {"remote-as": "65000", "peer-group": "GHOST"},
        },
        {"CLIENTS": {"address-family": rr}},
    )
    assert sessions["10.0.0.2"].props["route_reflector_client"] is True
    assert sessions["10.0.0.3"].props["route_reflector_client"] is True
    assert sessions["10.0.0.4"].props["route_reflector_client"] is False
    assert "route_reflector_client" not in sessions["10.0.0.5"].props


def test_every_session_carries_the_cluster_id_and_the_process_its_unwritten_neighbors():
    """`parameters cluster-id`, in either form, is on every session.
    A neighbor with no resolvable remote-as writes no session, and its
    process names it so the simulation does not read it as absent."""
    cfg = json.loads(json.dumps(BGP_CONFIG))
    cfg["protocols"]["bgp"]["parameters"]["cluster-id"] = "167772161"
    batch = normalize_vyos({"config": cfg, "version_text": VERSION, "links": []}, l3dom="wan")
    sessions = {n.props["peer_ip"]: n.props for n in batch.nodes if n.label == "BgpSession"}
    assert {peer: props.get("cluster_id") for peer, props in sessions.items()} == {
        "203.0.113.2": "10.0.0.1",
        "10.0.0.2": "10.0.0.1",
    }
    process = next(n for n in batch.nodes if n.label == "RoutingProcess")
    assert process.props["session_gaps"] == ["neighbor 192.0.2.9 has no resolvable remote-as"]


def test_a_filter_list_and_a_prefix_list_beside_a_route_map_are_recorded():
    batch, sessions = _session_props(
        {
            "203.0.113.2": {
                "remote-as": "65001",
                "address-family": {
                    "ipv4-unicast": {
                        "filter-list": {"import": "AS-IN"},
                        "prefix-list": {"import": "CUSTOMER-IN"},
                        "route-map": {"import": "CUSTOMER-OUT"},
                    }
                },
            }
        }
    )
    session = sessions["203.0.113.2"]
    assert session.props["import_filter_list_name"] == "AS-IN"
    assert "export_filter_list_name" not in session.props
    assert (session.props["import_policy_name"], session.props["import_policy_kind"]) == (
        "CUSTOMER-OUT",
        "route-map",
    )
    assert session.props["import_prefix_list_name"] == "CUSTOMER-IN"
    filters = {
        (r.key.get("direction"), r.end_uid)
        for r in batch.rels
        if r.rel_type == "FILTERED_BY" and r.start_uid == session.uid
    }
    assert filters == {
        ("in", uid.route_policy("dev:gw", "route-map", "CUSTOMER-OUT")),
        ("in-prefix-list", uid.route_policy("dev:gw", "prefix-list", "CUSTOMER-IN")),
    }


def test_neighbor_with_unresolvable_remote_as_is_skipped(caplog):
    batch = _bgp_batch()
    sessions = {n.props["peer_ip"] for n in batch.nodes if n.label == "BgpSession"}
    assert "192.0.2.9" not in sessions
    assert "no resolvable remote-as" in caplog.text


def _summary_text(peers, vrf="default"):
    return json.dumps({vrf: {"ipv4Unicast": {"as": 65000, "peers": peers}}})


def test_remote_as_external_and_auto_take_the_asn_the_summary_reports():
    """`remote-as external` and `auto` name no ASN; FRR learns it from
    the peer's OPEN, and the summary reports it, so the session states it."""
    cfg = json.loads(json.dumps(BGP_CONFIG))
    cfg["protocols"]["bgp"]["neighbor"] = {
        "192.0.2.9": {"remote-as": "auto"},
        "192.0.2.10": {"peer-group": "UPLINKS"},
        "192.0.2.11": {"remote-as": "external"},
    }
    cfg["protocols"]["bgp"]["peer-group"] = {"UPLINKS": {"remote-as": "external"}}
    summary = _summary_text(
        {
            "192.0.2.9": {"state": "Established", "remoteAs": 65000},
            "192.0.2.10": {"state": "Established", "remoteAs": 65020},
            # an external peer FRR has not learned an ASN for reports 0
            "192.0.2.11": {"state": "Active", "remoteAs": 0},
        }
    )
    raw = {"config": cfg, "version_text": VERSION, "links": [], vyos_mod.BGP_SUMMARY_COMMAND: summary}
    batch = normalize_vyos(raw, l3dom="wan")
    sessions = {n.props["peer_ip"]: n.props for n in batch.nodes if n.label == "BgpSession"}
    assert sessions["192.0.2.9"]["peer_asn"] == 65000  # auto: iBGP here
    assert sessions["192.0.2.10"]["peer_asn"] == 65020  # external, from the peer-group
    assert "192.0.2.11" not in sessions
    observed = vyos_mod.summary_remote_as(summary)
    assert set(vyos_mod.bgp_capture_targets(cfg, observed)) == {
        (DEFAULT_VRF, "192.0.2.9"),
        (DEFAULT_VRF, "192.0.2.10"),
    }


def test_remote_as_external_refuses_the_process_asn():
    """`external` accepts only an ASN other than the process's own."""
    cfg = json.loads(json.dumps(BGP_CONFIG))
    cfg["protocols"]["bgp"]["neighbor"] = {"192.0.2.11": {"remote-as": "external"}}
    summary = _summary_text({"192.0.2.11": {"state": "Established", "remoteAs": 65000}})
    raw = {"config": cfg, "version_text": VERSION, "links": [], vyos_mod.BGP_SUMMARY_COMMAND: summary}
    batch = normalize_vyos(raw, l3dom="wan")
    assert not [n for n in batch.nodes if n.label == "BgpSession"]


def test_bgp_peer_address_matching_a_collected_interface_resolves_to_the_same_node():
    cfg = json.loads(json.dumps(BGP_CONFIG))
    cfg["interfaces"]["ethernet"]["eth1"] = {"address": ["10.0.0.2/32"]}
    batch = normalize_vyos({"config": cfg, "version_text": VERSION, "links": []}, l3dom="wan")

    ru = "rproc:dev:gw:default:bgp"
    su = uid.bgp_session(ru, "10.0.0.2", "default")
    endpoint_targets = {r.end_uid for r in batch.rels if r.rel_type == "ENDPOINT" and r.start_uid == su}
    assert len(endpoint_targets) == 1
    (peer_ip_uid,) = endpoint_targets

    has_ip = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "HAS_IP"}
    assert ("dev:gw/if/eth1", peer_ip_uid) in has_ip, (
        "the session's peer address and the interface's own address must be one node"
    )


def test_peer_address_uid_varies_with_vrf_and_address_only():
    wan_batch = normalize_vyos({"config": BGP_CONFIG, "version_text": VERSION, "links": []}, l3dom="wan")
    other_batch = normalize_vyos(
        {"config": BGP_CONFIG, "version_text": VERSION, "links": []},
        l3dom="some-other-domain",
    )

    def peer_uid(batch):
        ru = "rproc:dev:gw:default:bgp"
        su = uid.bgp_session(ru, "203.0.113.2", "default")
        return next(r.end_uid for r in batch.rels if r.rel_type == "ENDPOINT" and r.start_uid == su)

    assert peer_uid(wan_batch) == peer_uid(other_batch)


def test_prefix_list_entries_resolve_ge_and_le_to_a_length_range():
    batch = _bgp_batch()
    entries = {n.props["seq"]: n.props for n in batch.nodes if n.label == "PrefixListEntry"}
    le_only = entries[10]
    assert le_only["prefix"] == "192.0.2.0/24" and le_only["le"] == "32" and "ge" not in le_only
    assert (le_only["min_len"], le_only["max_len"]) == (24, 32)
    both = entries[20]
    assert (both["ge"], both["le"]) == ("20", "24")
    assert (both["min_len"], both["max_len"]) == (20, 24)
    pl_uid = "rtpol:dev:gw:prefix-list:CUSTOMER-IN"
    plist = next(n for n in batch.nodes if n.label == "RoutePolicy" and n.uid == pl_uid)
    assert plist.props["kind"] == "prefix-list"
    has_rule = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "HAS_RULE"}
    assert (pl_uid, uid.prefix_list_entry(pl_uid, 10)) in has_rule


def test_route_map_entry_carries_match_set_and_calls_another_policy():
    batch = _bgp_batch()
    rm_uid = "rtpol:dev:gw:route-map:CUSTOMER-OUT"
    rm = next(n for n in batch.nodes if n.label == "RoutePolicy" and n.uid == rm_uid)
    assert rm.props["kind"] == "route-map"
    entry_uid = uid.route_policy_entry(rm_uid, 10)
    entry = next(n for n in batch.nodes if n.uid == entry_uid)
    assert entry.props["kind"] == "clause" and entry.props["action"] == "permit"
    assert entry.props["match_prefix_lists"] == ["CUSTOMER-IN"]
    assert entry.props["set_local_pref"] == "200" and entry.props["set_metric"] == "50"
    assert entry.props["calls_policy"] == "COMMON-SET"
    refs = {(r.start_uid, r.end_uid, r.props.get("kind")) for r in batch.rels if r.rel_type == "REFERENCES"}
    pl_uid = "rtpol:dev:gw:prefix-list:CUSTOMER-IN"
    common_uid = "rtpol:dev:gw:route-map:COMMON-SET"
    assert (entry_uid, pl_uid, "prefix-list") in refs
    assert (entry_uid, common_uid, "call") in refs


def test_route_map_rule_keeps_the_match_keys_it_does_not_read():
    """A rule matching on an interface or an IPv6 prefix-list is not a rule with
    no match: the unread keys land in `match_unsupported`, the read ones do not."""
    config = json.loads(json.dumps(BGP_CONFIG))
    config["policy"]["route-map"]["CUSTOMER-OUT"]["rule"]["30"] = {
        "action": "deny",
        "match": {
            "interface": "eth1",
            "ipv6": {"address": {"prefix-list": "V6-BOGONS"}},
            "community": {"community-list": "CL1"},
        },
    }
    batch = normalize_vyos({"config": config, "version_text": VERSION, "links": []}, l3dom="wan")
    rm_uid = "rtpol:dev:gw:route-map:CUSTOMER-OUT"
    entry = next(n for n in batch.nodes if n.uid == uid.route_policy_entry(rm_uid, 30))
    assert entry.props["match_unsupported"] == [
        "match interface eth1",
        "match ipv6 address prefix-list V6-BOGONS",
    ]
    assert entry.props["match_community_lists"] == ["CL1"]
    read = next(n for n in batch.nodes if n.uid == uid.route_policy_entry(rm_uid, 10))
    assert "match_unsupported" not in read.props


def test_common_set_route_map_carries_its_own_local_pref():
    batch = _bgp_batch()
    common_uid = "rtpol:dev:gw:route-map:COMMON-SET"
    entry = next(n for n in batch.nodes if n.uid == uid.route_policy_entry(common_uid, 10))
    assert entry.props["set_local_pref"] == "150"


def test_a_dangling_prefix_list_reference_warns_and_keeps_the_raw_name_without_an_edge(caplog):
    batch = _bgp_batch()
    rm_uid = "rtpol:dev:gw:route-map:CUSTOMER-OUT"
    entry_uid = uid.route_policy_entry(rm_uid, 20)
    entry = next(n for n in batch.nodes if n.uid == entry_uid)
    assert entry.props["match_prefix_lists"] == ["GHOST-PL"]
    refs = {
        (r.start_uid, r.end_uid)
        for r in batch.rels
        if r.rel_type == "REFERENCES" and r.start_uid == entry_uid
    }
    assert refs == set()
    assert "undefined prefix-list 'GHOST-PL'" in caplog.text


def test_neighbor_prefix_list_import_resolves_when_no_route_map_is_attached():
    batch = _bgp_batch()
    sessions = {n.props["peer_ip"]: n.props for n in batch.nodes if n.label == "BgpSession"}
    customer = sessions["203.0.113.2"]
    assert customer["import_policy_name"] == "CUSTOMER-IN"
    assert customer["import_policy_kind"] == "prefix-list"
    assert customer["export_policy_name"] == "CUSTOMER-OUT"
    assert customer["export_policy_kind"] == "route-map"
    filtered = {
        (r.start_uid, r.end_uid, r.props.get("direction")) for r in batch.rels if r.rel_type == "FILTERED_BY"
    }
    ru = "rproc:dev:gw:default:bgp"
    su = uid.bgp_session(ru, "203.0.113.2", "default")
    assert (su, "rtpol:dev:gw:prefix-list:CUSTOMER-IN", "in") in filtered
    assert (su, "rtpol:dev:gw:route-map:CUSTOMER-OUT", "out") in filtered


# --- FILTERED_BY direction, port groups, discard routes and GRE/VTI tunnels ---


def test_a_neighbor_with_the_same_route_map_both_ways_yields_two_filtered_by_edges():
    """The FILTERED_BY edges carry a direction-scoped merge key."""
    cfg = json.loads(json.dumps(BGP_CONFIG))
    cfg["protocols"]["bgp"]["neighbor"]["203.0.113.2"]["address-family"]["ipv4-unicast"] = {
        "route-map": {"import": "CUSTOMER-OUT", "export": "CUSTOMER-OUT"},
    }
    batch = normalize_vyos({"config": cfg, "version_text": VERSION, "links": []}, l3dom="wan")
    ru = "rproc:dev:gw:default:bgp"
    su = uid.bgp_session(ru, "203.0.113.2", "default")
    rm_uid = "rtpol:dev:gw:route-map:CUSTOMER-OUT"
    filtered = [
        (r.start_uid, r.end_uid, r.props.get("direction"))
        for r in batch.rels
        if r.rel_type == "FILTERED_BY" and r.start_uid == su
    ]
    assert (su, rm_uid, "in") in filtered
    assert (su, rm_uid, "out") in filtered
    assert len(filtered) == 2


def test_a_tcp_rule_with_a_port_group_produces_a_scoped_svc_object():
    cfg = {
        "system": {"host-name": "gw"},
        "interfaces": {"ethernet": {"eth0": {"address": ["203.0.113.2/30"]}}},
        "firewall": {
            "group": {"port-group": {"WEB-PORTS": {"port": ["80", "443"]}}},
            "ipv4": {
                "forward": {
                    "filter": {
                        "rule": {
                            "10": {
                                "action": "accept",
                                "protocol": "tcp",
                                "destination": {"group": {"port-group": "WEB-PORTS"}},
                            }
                        }
                    }
                }
            },
        },
    }
    raw = {"config": cfg, "version_text": VERSION, "links": []}
    batch = normalize_vyos(raw, l3dom="dc1")
    svcs = {n.uid: n.props for n in batch.nodes if n.label == "SvcObject"}
    su = "vyos:gw:svc:tcp:grp:WEB-PORTS"
    assert su in svcs
    assert svcs[su]["proto"] == "tcp"
    assert svcs[su]["ports"] == ["80", "443"]
    svc = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "SVC"}
    assert ("vyos:gw:fw:ipv4-forward:10", su) in svc
    # the bare group object stays, for provenance
    assert "vyos:gw:svc:grp:WEB-PORTS" in svcs


def test_a_rule_with_a_port_group_and_no_protocol_gets_an_any_svc_object():
    """The scoped SvcObject uses the 'any' placeholder of the non-group branch."""
    cfg = {
        "system": {"host-name": "gw"},
        "interfaces": {"ethernet": {"eth0": {"address": ["203.0.113.2/30"]}}},
        "firewall": {
            "group": {"port-group": {"WEB-PORTS": {"port": ["80", "443"]}}},
            "ipv4": {
                "forward": {
                    "filter": {
                        "rule": {
                            "10": {
                                "action": "accept",
                                "destination": {"group": {"port-group": "WEB-PORTS"}},
                            }
                        }
                    }
                }
            },
        },
    }
    raw = {"config": cfg, "version_text": VERSION, "links": []}
    batch = normalize_vyos(raw, l3dom="dc1")
    svcs = {n.uid: n.props for n in batch.nodes if n.label == "SvcObject"}
    su = "vyos:gw:svc:any:grp:WEB-PORTS"
    assert su in svcs
    assert svcs[su].get("proto") is None
    assert svcs[su]["ports"] == ["80", "443"]
    assert svcs[su]["name"] == "any/WEB-PORTS"
    svc = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "SVC"}
    assert ("vyos:gw:fw:ipv4-forward:10", su) in svc


def test_a_blackhole_static_route_has_no_next_hop_and_no_via():
    cfg = {
        "system": {"host-name": "gw"},
        "interfaces": {"ethernet": {"eth0": {"address": ["203.0.113.2/30"]}}},
        "protocols": {"static": {"route": {"10.0.0.0/8": {"blackhole": {}}}}},
    }
    raw = {"config": cfg, "version_text": VERSION, "links": []}
    batch = normalize_vyos(raw, l3dom="dc1")
    statics = [r for r in batch.rels if r.rel_type == "STATIC_ROUTE"]
    assert len(statics) == 1
    edge = statics[0]
    assert edge.props.get("discard") == "blackhole"
    assert "next_hop" not in edge.props
    assert "interface" not in edge.props
    assert not [r for r in batch.rels if r.rel_type == "VIA"]


def test_a_reject_static_route_carries_discard_reject():
    cfg = {
        "system": {"host-name": "gw"},
        "interfaces": {"ethernet": {"eth0": {"address": ["203.0.113.2/30"]}}},
        "protocols": {"static": {"route": {"10.0.0.0/8": {"reject": {}}}}},
    }
    raw = {"config": cfg, "version_text": VERSION, "links": []}
    batch = normalize_vyos(raw, l3dom="dc1")
    statics = [r for r in batch.rels if r.rel_type == "STATIC_ROUTE"]
    assert len(statics) == 1
    assert statics[0].props.get("discard") == "reject"


def test_a_rib_nexthop_with_neither_ip_nor_interface_is_kept_as_a_blackhole_row():
    """FRR mirrors a kernel discard route as a nexthop carrying
    neither `ip` nor `interfaceName`."""
    batch = _rib_batch(routes=_route("172.16.0.0/12", _nh()))
    learned = [r for r in batch.rels if r.rel_type == "LEARNED_ROUTE"]
    assert learned and learned[0].props.get("next_hop") is None
    assert learned[0].props.get("interface") is None
    assert learned[0].props.get("discard") == "blackhole"


def test_a_gre_tunnel_interface_yields_a_tunnel_node_and_endpoint_edge():
    cfg = {
        "system": {"host-name": "gw"},
        "interfaces": {
            "ethernet": {"eth0": {"address": ["203.0.113.2/30"]}},
            "tunnel": {
                "tun0": {
                    "encapsulation": "gre",
                    "local-ip": "203.0.113.2",
                    "remote-ip": "198.51.100.9",
                }
            },
        },
    }
    raw = {"config": cfg, "version_text": VERSION, "links": []}
    batch = normalize_vyos(raw, l3dom="dc1")
    tun = next(n for n in batch.nodes if n.label == "Tunnel" and n.props.get("encap") == "gre")
    assert tun.props["endpoint"] == "198.51.100.9"
    assert tun.props["local_address"] == "203.0.113.2"
    assert tun.props["carrier_proto"] == "gre"
    endpoint = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ENDPOINT"}
    tun0_uid = uid.interface("dev:gw", "tun0")
    assert (tun.uid, tun0_uid) in endpoint


def test_a_vti_interface_yields_an_ipsec_tunnel_node():
    cfg = {
        "system": {"host-name": "gw"},
        "interfaces": {
            "ethernet": {"eth0": {"address": ["203.0.113.2/30"]}},
            "vti": {"vti0": {"address": ["10.255.0.1/30"]}},
        },
    }
    raw = {"config": cfg, "version_text": VERSION, "links": []}
    batch = normalize_vyos(raw, l3dom="dc1")
    tun = next(n for n in batch.nodes if n.label == "Tunnel" and n.props.get("encap") == "ipsec")
    assert tun.props["carrier_proto"] == "esp"


# --- carrier-frames: WireGuard interface MTU, GRE flags, VXLAN,
# and IPsec esp-group fields on the Tunnel node ------------------------------------


def _wireguard_cfg(wg_node: dict) -> dict:
    return {
        "system": {"host-name": "gw"},
        "interfaces": {
            "ethernet": {"eth0": {"address": ["203.0.113.2/30"]}},
            "wireguard": {"wg0": wg_node},
        },
    }


def _wg_peer(**overrides) -> dict:
    peer = {"address": "198.51.100.9", "port": "51820"}
    peer.update(overrides)
    return {"peer": {"peer1": peer}, "source-address": "203.0.113.2"}


def test_a_wireguard_tunnel_carries_the_interface_operational_mtu():
    """T-a/b (carrier-frames): the operational `ip -j link` MTU wins over the
    configured one when both are present."""
    cfg = _wireguard_cfg({**_wg_peer(), "mtu": "1420"})
    raw = {
        "config": cfg,
        "version_text": VERSION,
        "links": [{"ifname": "wg0", "mtu": 1370}],
    }
    batch = normalize_vyos(raw, l3dom="dc1")
    tun = next(n for n in batch.nodes if n.label == "Tunnel" and n.props.get("encap") == "wireguard")
    assert tun.props["tunnel_mtu"] == 1370


def test_a_wireguard_tunnel_falls_back_to_the_configured_mtu():
    cfg = _wireguard_cfg({**_wg_peer(), "mtu": "1420"})
    raw = {"config": cfg, "version_text": VERSION, "links": []}
    batch = normalize_vyos(raw, l3dom="dc1")
    tun = next(n for n in batch.nodes if n.label == "Tunnel" and n.props.get("encap") == "wireguard")
    assert tun.props["tunnel_mtu"] == 1420


def test_a_wireguard_tunnel_with_neither_reading_carries_no_mtu():
    cfg = _wireguard_cfg(_wg_peer())
    raw = {"config": cfg, "version_text": VERSION, "links": []}
    batch = normalize_vyos(raw, l3dom="dc1")
    tun = next(n for n in batch.nodes if n.label == "Tunnel" and n.props.get("encap") == "wireguard")
    assert tun.props.get("tunnel_mtu") is None


def _gre_cfg(tun0: dict) -> dict:
    return {
        "system": {"host-name": "gw"},
        "interfaces": {
            "ethernet": {"eth0": {"address": ["203.0.113.2/30"]}},
            "tunnel": {"tun0": tun0},
        },
    }


def test_a_gre_tunnel_with_a_key_records_the_key_flag_true():
    """T-c/f: `parameters ip key` present sets gre_key; checksum/sequence stay
    false because VyOS's tunnel interface has no such configuration keys at
    all (confirmed against vyos-1x's interfaces_tunnel.xml.in)."""
    cfg = _gre_cfg(
        {
            "encapsulation": "gre",
            "local-ip": "203.0.113.2",
            "remote-ip": "198.51.100.9",
            "parameters": {"ip": {"key": "5"}},
        }
    )
    raw = {"config": cfg, "version_text": VERSION, "links": []}
    batch = normalize_vyos(raw, l3dom="dc1")
    tun = next(n for n in batch.nodes if n.label == "Tunnel" and n.props.get("encap") == "gre")
    assert tun.props["gre_key"] is True
    assert tun.props["gre_checksum"] is False
    assert tun.props["gre_sequence"] is False


def test_a_gre_tunnel_without_a_key_records_every_flag_false():
    cfg = _gre_cfg({"encapsulation": "gre", "local-ip": "203.0.113.2", "remote-ip": "198.51.100.9"})
    raw = {"config": cfg, "version_text": VERSION, "links": []}
    batch = normalize_vyos(raw, l3dom="dc1")
    tun = next(n for n in batch.nodes if n.label == "Tunnel" and n.props.get("encap") == "gre")
    assert tun.props["gre_key"] is False
    assert tun.props["gre_checksum"] is False
    assert tun.props["gre_sequence"] is False


@pytest.mark.parametrize(
    ("encap", "local", "remote", "proto"),
    [
        ("ipip", "203.0.113.2", "198.51.100.9", 4),
        ("sit", "203.0.113.2", "198.51.100.9", 41),
        # DS-Lite B4: IPv4 inside an IPv6 carrier
        ("ipip6", "2001:db8:1::2", "2001:db8:2::2", 4),
        ("ip6ip6", "2001:db8:1::2", "2001:db8:2::2", 41),
        ("ip6gre", "2001:db8:1::2", "2001:db8:2::2", 47),
    ],
)
def test_an_ip_in_ip_tunnel_records_a_carrier_protocol_the_engine_reads(encap, local, remote, proto):
    from hst.path.gates.tunnel import _outer

    cfg = _gre_cfg({"encapsulation": encap, "source-address": local, "remote": remote})
    raw = {"config": cfg, "version_text": VERSION, "links": []}
    batch = normalize_vyos(raw, l3dom="dc1")
    tun = next(n for n in batch.nodes if n.label == "Tunnel" and n.props.get("encap") == encap)
    outer = _outer(
        {
            "local_address": tun.props["local_address"],
            "remote_address": tun.props["endpoint"],
            "carrier_proto": tun.props["carrier_proto"],
        }
    )
    assert outer is not None
    (rect,) = outer.rects
    assert rect.proto == frozenset({proto})
    assert rect.af == (6 if ":" in remote else 4)


def test_a_vxlan_interface_yields_a_tunnel_node_with_its_remote_and_source():
    cfg = {
        "system": {"host-name": "gw"},
        "interfaces": {
            "ethernet": {"eth0": {"address": ["203.0.113.2/30"]}},
            "vxlan": {"vxlan241": {"vni": "241", "remote": "198.51.100.9", "source-address": "203.0.113.2"}},
        },
    }
    raw = {"config": cfg, "version_text": VERSION, "links": []}
    batch = normalize_vyos(raw, l3dom="dc1")
    tun = next(n for n in batch.nodes if n.label == "Tunnel" and n.props.get("encap") == "vxlan")
    assert tun.props["endpoint"] == "198.51.100.9"
    assert tun.props["local_address"] == "203.0.113.2"
    assert tun.props["carrier_proto"] == "udp"
    endpoint = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ENDPOINT"}
    vxlan_uid = uid.interface("dev:gw", "vxlan241")
    assert (tun.uid, vxlan_uid) in endpoint


def _vti_cfg(*, encryption: str, hash_name: str | None, mode: str | None = None) -> dict:
    esp_group: dict = {"proposal": {"10": {"encryption": encryption}}}
    if hash_name:
        esp_group["proposal"]["10"]["hash"] = hash_name
    if mode:
        esp_group["mode"] = mode
    return {
        "system": {"host-name": "gw"},
        "interfaces": {
            "ethernet": {"eth0": {"address": ["203.0.113.2/30"]}},
            "vti": {"vti0": {"address": ["10.255.0.1/30"]}},
        },
        "vpn": {
            "ipsec": {
                "esp-group": {"ESP-HOME": esp_group},
                "site-to-site": {
                    "peer": {
                        "198.51.100.9": {
                            "local-address": "203.0.113.2",
                            "vti": {"bind": "vti0", "esp-group": "ESP-HOME"},
                        }
                    }
                },
            }
        },
    }


def test_a_vti_bound_to_a_site_to_site_peer_records_the_esp_group_fields():
    """T-e/f: `vpn ipsec esp-group ESP-HOME proposal 10 encryption/hash` and
    the site-to-site peer's `vti { bind, esp-group }` resolve onto the vti0
    Tunnel node, including the peer's own address for the outer family."""
    cfg = _vti_cfg(encryption="aes256", hash_name="sha256")
    raw = {"config": cfg, "version_text": VERSION, "links": []}
    batch = normalize_vyos(raw, l3dom="dc1")
    tun = next(n for n in batch.nodes if n.label == "Tunnel" and n.props.get("encap") == "ipsec")
    assert tun.props["esp_encryption"] == "aes256"
    assert tun.props["esp_hash"] == "sha256"
    assert tun.props["esp_mode"] == "tunnel"
    assert json.loads(tun.props["esp_proposals"]) == [{"encryption": "aes256", "hash": "sha256"}]
    assert tun.props["endpoint"] == "198.51.100.9"
    assert tun.props["local_address"] == "203.0.113.2"


def test_a_vti_esp_group_records_every_proposal_in_number_order():
    """A VyOS esp-group offers its proposals to the peer in ascending
    proposal-number order."""
    cfg = _vti_cfg(encryption="aes256gcm128", hash_name=None)
    cfg["vpn"]["ipsec"]["esp-group"]["ESP-HOME"]["proposal"]["20"] = {
        "encryption": "aes256",
        "hash": "sha256",
    }
    raw = {"config": cfg, "version_text": VERSION, "links": []}
    batch = normalize_vyos(raw, l3dom="dc1")
    tun = next(n for n in batch.nodes if n.label == "Tunnel" and n.props.get("encap") == "ipsec")
    assert tun.props["esp_encryption"] == "aes256gcm128"
    assert tun.props.get("esp_hash") is None
    assert json.loads(tun.props["esp_proposals"]) == [
        {"encryption": "aes256gcm128", "hash": None},
        {"encryption": "aes256", "hash": "sha256"},
    ]


def test_a_vti_esp_group_states_transport_mode_explicitly():
    cfg = _vti_cfg(encryption="aes256gcm128", hash_name=None, mode="transport")
    raw = {"config": cfg, "version_text": VERSION, "links": []}
    batch = normalize_vyos(raw, l3dom="dc1")
    tun = next(n for n in batch.nodes if n.label == "Tunnel" and n.props.get("encap") == "ipsec")
    assert tun.props["esp_encryption"] == "aes256gcm128"
    assert tun.props["esp_mode"] == "transport"


def test_a_vti_without_a_resolvable_esp_group_carries_no_esp_fields():
    cfg = {
        "system": {"host-name": "gw"},
        "interfaces": {
            "ethernet": {"eth0": {"address": ["203.0.113.2/30"]}},
            "vti": {"vti0": {"address": ["10.255.0.1/30"]}},
        },
    }
    raw = {"config": cfg, "version_text": VERSION, "links": []}
    batch = normalize_vyos(raw, l3dom="dc1")
    tun = next(n for n in batch.nodes if n.label == "Tunnel" and n.props.get("encap") == "ipsec")
    assert "esp_encryption" not in tun.props
    assert tun.props.get("endpoint") is None


# --- firewall rule semantics: connection state, interface scope, port specs ---------


def _fw_batch(firewall: dict, interfaces: dict | None = None):
    """One normalized batch for a standalone firewall section."""
    cfg = {
        "system": {"host-name": "gw"},
        "interfaces": interfaces or {"ethernet": {"eth0": {"address": ["203.0.113.2/30"]}}},
        "firewall": firewall,
    }
    raw = {"config": cfg, "version_text": VERSION, "links": []}
    return normalize_vyos(raw, l3dom="dc1")


def _by_uid(batch, label: str) -> dict:
    return {n.uid: n.props for n in batch.nodes if n.label == label}


def _one_rule(rule: dict, name: str = "WAN-LAN") -> dict:
    return {"ipv4": {"name": {name: {"default-action": "drop", "rule": {"10": rule}}}}}


def test_a_rule_state_clause_is_collected_in_the_1_3_leaf_shape():
    """VyOS 1.3 writes an explicit enable/disable value per state."""
    batch = _fw_batch(
        _one_rule(
            {
                "action": "accept",
                "state": {"established": "enable", "related": "enable", "new": "disable"},
            }
        )
    )
    rule = _by_uid(batch, "FwRule")["vyos:gw:fw:WAN-LAN:10"]
    assert rule["states"] == ["established", "related"]
    assert "states_opaque" not in rule


def test_a_rule_state_clause_is_collected_in_the_1_4_list_and_node_shapes():
    """1.4 and later write a valueless node per enabled state, or a list."""
    listed = _fw_batch(_one_rule({"action": "accept", "state": ["related", "established"]}))
    assert _by_uid(listed, "FwRule")["vyos:gw:fw:WAN-LAN:10"]["states"] == ["established", "related"]
    nodes = _fw_batch(_one_rule({"action": "accept", "state": {"new": {}, "established": {}}}))
    assert _by_uid(nodes, "FwRule")["vyos:gw:fw:WAN-LAN:10"]["states"] == ["established", "new"]


def test_a_rule_with_no_state_clause_carries_an_explicit_empty_states_list():
    """The loader's SET is additive."""
    rule = _by_uid(_fw_batch(_one_rule({"action": "accept"})), "FwRule")["vyos:gw:fw:WAN-LAN:10"]
    assert rule["states"] == [] and "states_opaque" not in rule


def test_a_rule_with_no_interface_group_scope_carries_explicit_empty_strings():
    rule = _by_uid(_fw_batch(_one_rule({"action": "accept"})), "FwRule")["vyos:gw:fw:WAN-LAN:10"]
    assert rule["in_interface_group"] == "" and rule["out_interface_group"] == ""


def test_a_state_clause_in_an_unreadable_shape_is_marked_opaque_with_a_reason():
    batch = _fw_batch(_one_rule({"action": "accept", "state": {"established": {"action": "accept"}}}))
    rule = _by_uid(batch, "FwRule")["vyos:gw:fw:WAN-LAN:10"]
    assert rule["states"] == []
    assert rule["states_opaque"] is True
    assert "established" in rule["states_opaque_reason"]


def test_a_state_naming_something_this_collector_does_not_model_is_opaque():
    batch = _fw_batch(_one_rule({"action": "accept", "state": ["established", "untracked"]}))
    rule = _by_uid(batch, "FwRule")["vyos:gw:fw:WAN-LAN:10"]
    assert rule["states_opaque"] is True and "untracked" in rule["states_opaque_reason"]


def test_the_global_state_policy_is_recorded_on_every_ruleset():
    """`firewall global-options state-policy` decides established, related and
    invalid traffic ahead of every ruleset."""
    batch = _fw_batch(
        {
            "global-options": {
                "state-policy": {
                    "established": {"action": "accept"},
                    "invalid": {"action": "drop"},
                    "related": {"action": "accept"},
                }
            },
            **_one_rule({"action": "accept"}),
        }
    )
    rb = _by_uid(batch, "FwRulebase")["vyos:gw:fw:WAN-LAN"]
    assert rb["global_state_policy"] == ["established=accept", "invalid=drop", "related=accept"]


def test_a_ruleset_without_a_state_policy_carries_no_global_state_policy():
    rb = _by_uid(_fw_batch(_one_rule({"action": "accept"})), "FwRulebase")["vyos:gw:fw:WAN-LAN"]
    assert "global_state_policy" not in rb


def test_an_interface_group_scope_is_collected():
    batch = _fw_batch(
        _one_rule(
            {
                "action": "drop",
                "outbound-interface": {"group": "WAN-GROUP"},
                "inbound-interface": {"group": "LAN-GROUP"},
            }
        )
    )
    rule = _by_uid(batch, "FwRule")["vyos:gw:fw:WAN-LAN:10"]
    assert rule["out_interface_group"] == "WAN-GROUP"
    assert rule["in_interface_group"] == "LAN-GROUP"
    assert "out_interface" not in rule and "in_interface" not in rule


def test_a_wildcard_and_a_negated_interface_name_are_kept_as_written():
    """The gate reads the '*' and the '!' as operators."""
    batch = _fw_batch(
        _one_rule(
            {
                "action": "drop",
                "outbound-interface": {"name": "eth2*"},
                "inbound-interface": {"name": "!eth0"},
            }
        )
    )
    rule = _by_uid(batch, "FwRule")["vyos:gw:fw:WAN-LAN:10"]
    assert rule["out_interface"] == "eth2*" and rule["in_interface"] == "!eth0"


def test_a_chain_without_a_default_action_is_marked_unknown():
    """An absent default-action is not a recorded drop: only the marker tells
    "the config did not set one" from "the vendor has no such concept"."""
    batch = _fw_batch({"ipv4": {"forward": {"filter": {"rule": {"10": {"action": "accept"}}}}}})
    rb = _by_uid(batch, "FwRulebase")["vyos:gw:fw:ipv4-forward"]
    assert rb.get("default_action") is None
    assert rb["default_action_unknown"] is True


def test_a_chain_with_a_default_action_is_not_marked_unknown():
    batch = _fw_batch(
        {"ipv4": {"forward": {"filter": {"default-action": "drop", "rule": {"10": {"action": "accept"}}}}}}
    )
    rb = _by_uid(batch, "FwRulebase")["vyos:gw:fw:ipv4-forward"]
    assert rb["default_action"] == "drop" and rb["default_action_unknown"] is False


def test_a_named_ruleset_without_a_default_action_is_marked_unknown():
    batch = _fw_batch({"ipv4": {"name": {"WAN-LAN": {"rule": {"10": {"action": "accept"}}}}}})
    rb = _by_uid(batch, "FwRulebase")["vyos:gw:fw:WAN-LAN"]
    assert rb["default_action_unknown"] is True


def test_a_zone_without_a_default_action_is_marked_unknown():
    batch = _fw_batch(
        {"zone": {"WAN": {"member": {"interface": ["eth0"]}}, "LAN": {"default-action": "drop"}}}
    )
    zones = {p["name"]: p for p in _by_uid(batch, "Zone").values()}
    assert zones["WAN"]["default_action_unknown"] is True
    assert zones["LAN"]["default_action_unknown"] is False


def test_a_zone_records_its_intra_zone_filtering_and_binds_its_ruleset_as_its_own_pair():
    """intra-zone-filtering decides traffic within a zone. Its action
    is on the Zone, its ruleset is bound as the pair (Z, Z), and a zone that
    states none says so."""
    batch = _fw_batch(
        {
            "ipv4": {"name": {"LAN-INTRA": {"default-action": "drop"}}},
            "zone": {
                "LAN": {"member": {"interface": ["eth0"]}, "intra-zone-filtering": {"action": "accept"}},
                "IOT": {"member": {"interface": ["eth1"]}},
                "DMZ": {"intra-zone-filtering": {"firewall": {"name": "LAN-INTRA"}}},
            },
        }
    )
    zones = {p["name"]: p for p in _by_uid(batch, "Zone").values()}
    assert (zones["LAN"]["intra_zone_filtering"], zones["LAN"]["intra_zone_action"]) == (True, "accept")
    assert zones["IOT"]["intra_zone_filtering"] is False
    assert zones["DMZ"]["intra_zone_filtering"] is True
    rb, dmz = "vyos:gw:fw:LAN-INTRA", "vyos:gw:zone:DMZ"
    pairs = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    assert {("FROM_ZONE", rb, dmz), ("TO_ZONE", rb, dmz)} <= pairs


def test_a_named_destination_port_resolves_through_the_well_known_table():
    """VyOS validates a service name against the target's own /etc/services."""
    batch = _fw_batch(_one_rule({"action": "accept", "protocol": "tcp", "destination": {"port": "ssh"}}))
    svc = _by_uid(batch, "SvcObject")["vyos:gw:svc:tcp-ssh"]
    assert svc["ports"] == ["22"]
    assert "opaque" not in svc


def test_an_unrecognised_service_name_marks_the_svcobject_opaque():
    batch = _fw_batch(
        _one_rule({"action": "accept", "protocol": "tcp", "destination": {"port": "my-custom-app"}})
    )
    svc = _by_uid(batch, "SvcObject")["vyos:gw:svc:tcp-my-custom-app"]
    assert svc["opaque"] is True
    assert "my-custom-app" in svc["opaque_reason"]
    # the raw spec stays for provenance alongside the marker
    assert svc["ports"] == ["my-custom-app"]


def test_a_comma_and_range_port_spec_becomes_a_list_of_ports_and_ranges():
    batch = _fw_batch(
        _one_rule(
            {"action": "accept", "protocol": "tcp_udp", "destination": {"port": "52217,53220,55265-55274"}}
        )
    )
    svc = _by_uid(batch, "SvcObject")["vyos:gw:svc:tcp_udp-52217,53220,55265-55274"]
    assert svc["ports"] == ["52217", "53220", "55265-55274"]
    assert "opaque" not in svc


def test_a_port_group_resolves_its_named_members_and_flags_the_rest():
    batch = _fw_batch(
        {
            "group": {"port-group": {"MIXED": {"port": ["ssh", "8080", "my-custom-app"]}}},
            **_one_rule(
                {
                    "action": "accept",
                    "protocol": "tcp",
                    "destination": {"group": {"port-group": "MIXED"}},
                }
            ),
        }
    )
    svcs = _by_uid(batch, "SvcObject")
    for su in ("vyos:gw:svc:grp:MIXED", "vyos:gw:svc:tcp:grp:MIXED"):
        assert svcs[su]["ports"] == ["22", "8080", "my-custom-app"]
        assert svcs[su]["opaque"] is True
        assert "my-custom-app" in svcs[su]["opaque_reason"]


def test_a_source_port_is_recorded_as_a_dimension_not_as_an_opaque_service():
    """A source port scopes the rule to a dimension the traced flow tuple does
    not carry."""
    batch = _fw_batch(
        _one_rule(
            {
                "action": "accept",
                "protocol": "udp",
                "destination": {"port": "546"},
                "source": {"port": "547"},
            }
        )
    )
    svc = _by_uid(batch, "SvcObject")["vyos:gw:svc:udp-546-src547"]
    assert svc["src_port"] == "547"
    assert "opaque" not in svc
    assert svc["ports"] == ["546"]
    # the display name carries the source port too, so the two services read
    # apart wherever the uid is not on show
    assert svc["name"] == "udp/546 src 547"


def test_a_source_port_does_not_collide_with_the_same_service_without_one():
    """The source port is part of the service identity: merging the two objects
    would spread one rule's source-port scope onto the other rule."""
    batch = _fw_batch(
        {
            "ipv4": {
                "name": {
                    "WAN-LAN": {
                        "default-action": "drop",
                        "rule": {
                            "10": {
                                "action": "accept",
                                "protocol": "udp",
                                "destination": {"port": "546"},
                                "source": {"port": "547"},
                            },
                            "20": {"action": "accept", "protocol": "udp", "destination": {"port": "546"}},
                        },
                    }
                }
            }
        }
    )
    svcs = _by_uid(batch, "SvcObject")
    assert svcs["vyos:gw:svc:udp-546-src547"]["src_port"] == "547"
    assert "src_port" not in svcs["vyos:gw:svc:udp-546"]


def test_a_negated_port_spec_is_reported_as_negated():
    """The matcher has no port negation."""
    batch = _fw_batch(_one_rule({"action": "accept", "protocol": "tcp", "destination": {"port": "!80"}}))
    svc = _by_uid(batch, "SvcObject")["vyos:gw:svc:tcp-!80"]
    assert svc["opaque"] is True
    assert svc["opaque_reason"] == "negated port spec is not modelled: '!80'"
    assert svc["ports"] == ["!80"]


def test_a_half_written_range_does_not_pass_as_a_range():
    batch = _fw_batch(_one_rule({"action": "accept", "protocol": "tcp", "destination": {"port": "80-"}}))
    svc = _by_uid(batch, "SvcObject")["vyos:gw:svc:tcp-80-"]
    assert svc["opaque"] is True and "80-" in svc["opaque_reason"]


def test_a_complete_range_reads_as_a_range():
    batch = _fw_batch(_one_rule({"action": "accept", "protocol": "tcp", "destination": {"port": "80-90"}}))
    svc = _by_uid(batch, "SvcObject")["vyos:gw:svc:tcp-80-90"]
    assert svc["ports"] == ["80-90"] and "opaque" not in svc


def test_a_negated_protocol_is_stored_as_written():
    """`protocol !tcp` is an operator the path matcher reads."""
    batch = _fw_batch(_one_rule({"action": "drop", "protocol": "!tcp"}))
    assert _by_uid(batch, "SvcObject")["vyos:gw:svc:!tcp-any"]["proto"] == "!tcp"


# A trimmed copy of a real `show configuration json` firewall section (core1,
# VyOS 2026.08.19 rolling): the shapes the collector has to read as written.
CORE1_FIREWALL = {
    "global-options": {
        "state-policy": {
            "established": {"action": "accept"},
            "invalid": {"action": "drop"},
            "related": {"action": "accept"},
        }
    },
    "group": {
        "address-group": {
            "us-streaming-clients": {
                "address": ["192.168.10.45", "192.168.210.50-192.168.210.100"],
            }
        }
    },
    "ipv4": {
        "name": {
            "IOT-LAN": {
                "default-action": "drop",
                "rule": {
                    "5": {
                        "action": "accept",
                        "description": "cam2ckey",
                        "destination": {"address": "192.168.2.8/32", "port": "7550"},
                        "protocol": "tcp_udp",
                    },
                    "20": {
                        "action": "accept",
                        "description": "ScanSnap all ports",
                        "destination": {"port": "52217,53220,55265-55274"},
                        "protocol": "tcp_udp",
                        "source": {"address": "192.168.105.16"},
                    },
                },
            },
            "LAN-WAN": {
                "default-action": "accept",
                "rule": {
                    "10": {
                        "action": "drop",
                        "outbound-interface": {"name": "eth2"},
                        "source": {"group": {"address-group": "us-streaming-clients"}},
                    }
                },
            },
        }
    },
    "ipv6": {
        "name": {
            "WAN6-LOCAL6": {
                "default-action": "drop",
                "default-log": {},
                "rule": {
                    "30": {
                        "action": "accept",
                        "destination": {"port": "546"},
                        "protocol": "udp",
                        "source": {"port": "547"},
                    }
                },
            }
        }
    },
    "zone": {
        "LAN": {
            "default-action": "drop",
            "from": {"IOT": {"firewall": {"ipv6-name": "IOT6-LAN6", "name": "IOT-LAN"}}},
            "member": {"interface": ["eth0"]},
        },
        "WAN": {"default-action": "drop", "member": {"interface": ["eth2"]}},
    },
}


def test_the_core1_firewall_section_normalizes_with_its_real_shapes():
    batch = _fw_batch(
        CORE1_FIREWALL,
        interfaces={
            "ethernet": {
                "eth0": {"address": ["192.168.2.1/24"]},
                "eth2": {"address": ["192.168.100.254/24"]},
            }
        },
    )
    rulebases = _by_uid(batch, "FwRulebase")
    # every ruleset in this configuration records its default-action
    for rb in rulebases.values():
        assert rb["default_action"] in ("drop", "accept")
        assert rb["default_action_unknown"] is False
        assert rb["global_state_policy"] == ["established=accept", "invalid=drop", "related=accept"]
    # no rule here carries a per-rule state clause: the state policy is global
    assert all(p["states"] == [] for p in _by_uid(batch, "FwRule").values())
    svcs = _by_uid(batch, "SvcObject")
    assert svcs["vyos:gw:svc:tcp_udp-52217,53220,55265-55274"]["ports"] == [
        "52217",
        "53220",
        "55265-55274",
    ]
    src_port_svc = svcs["vyos:gw:svc:udp-546-src547"]
    assert src_port_svc["src_port"] == "547" and "opaque" not in src_port_svc
    group = _by_uid(batch, "NetObject")["vyos:gw:grp:addr:us-streaming-clients"]
    assert group["ranges"] == ["192.168.210.50-192.168.210.100"]
    assert _by_uid(batch, "FwRule")["vyos:gw:fw:LAN-WAN:10"]["out_interface"] == "eth2"
    zones = {p["name"]: p for p in _by_uid(batch, "Zone").values()}
    assert zones["LAN"]["default_action_unknown"] is False


# The path-A test of tests/test_integration_db.py traces this device.
CONFIG_PATH_A = {
    "system": {"host-name": "patha-edge"},
    "interfaces": {
        "ethernet": {
            "eth0": {"address": ["dhcp"], "description": "WAN"},
            # tests/test_integration_db.py raises this `mtu` to 9000.
            "eth1": {"address": ["10.20.1.1/24"], "description": "LAN", "mtu": 1500},
            "eth2": {"address": ["10.0.9.1/24"], "description": "DC uplink"},
            "eth3": {"address": ["10.20.2.1/24"], "description": "LAN branch"},
        },
    },
    "firewall": {
        "zone": {
            "WAN": {
                "default-action": "drop",
                "member": {"interface": ["eth0", "eth2"]},
                "from": {"LAN": {"firewall": {"name": "LAN-WAN"}}},
            },
            "LAN": {"default-action": "drop", "member": {"interface": ["eth1", "eth3"]}},
        },
        "ipv4": {
            # A forwarded packet crosses the `forward filter` chain and the zone policy.
            "forward": {
                "filter": {
                    "default-action": "drop",
                    "rule": {
                        "10": {
                            "action": "accept",
                            "protocol": "tcp",
                            "destination": {"address": "10.0.30.0/24"},
                        }
                    },
                },
            },
            "name": {
                "LAN-WAN": {
                    "default-action": "drop",
                    "rule": {
                        "10": {
                            "action": "accept",
                            "protocol": "tcp",
                            "destination": {"address": "10.0.30.0/24"},
                        }
                    },
                },
            },
        },
    },
    "nat": {
        "source": {
            "rule": {
                # the ordinary edge masquerade: the whole client subnet, hidden
                # behind the DC uplink's own address
                "100": {
                    "outbound-interface": {"name": "eth2"},
                    "source": {"address": "10.20.1.0/24"},
                    "translation": {"address": "masquerade"},
                },
                # the branch segment leaves as a static address of its own,
                # which is the post-NAT source Check Point's deny rule is
                # written against
                "110": {
                    "outbound-interface": {"name": "eth2"},
                    "source": {"address": "10.20.2.0/24"},
                    "translation": {"address": "10.0.9.50"},
                },
            }
        },
    },
    "policy": {
        "route": {
            "DC-PBR": {
                "interface": ["eth1", "eth3"],
                "rule": {
                    "10": {
                        "description": "DC-bound to the second table",
                        "destination": {"address": "10.0.30.0/24"},
                        "set": {"table": "300"},
                    },
                },
            },
        },
    },
    # The second table's own route to the VIP network, declared the way a real
    # device declares it. The FRR RIB row for the same route is in
    # ROUTES_TABLES_PATH_A below: a capture of an installed static carries both
    # halves, and `_confirm_static_route` folds them into one route that keeps
    # this next hop and takes the egress interface FRR resolved it to.
    "protocols": {"static": {"table": {"300": {"route": {"10.0.30.0/24": {"next-hop": {"10.0.9.2": {}}}}}}}},
}

VERSION_PATH_A = "Version:          VyOS 1.5-rolling-202607150020\nHardware S/N:     PATHAEDGE1\n"

LINKS_PATH_A = [
    {"ifname": "eth0", "address": "aa:bb:cc:aa:aa:98"},
    {"ifname": "eth1", "address": "aa:bb:cc:aa:aa:99", "mtu": 1500},
    {"ifname": "eth2", "address": "aa:bb:cc:aa:aa:9a"},
    {"ifname": "eth3", "address": "aa:bb:cc:aa:aa:9b"},
]

# The FRR RIB half of table 300's route to the VIP network, as `show ip route table 300 json` reports it.
ROUTES_TABLES_PATH_A = {
    "300": {
        "10.0.30.0/24": [
            {
                "prefix": "10.0.30.0/24",
                "protocol": "static",
                "installed": True,
                "selected": True,
                "table": 300,
                "nexthops": [{"ip": "10.0.9.2", "interfaceName": "eth2", "fib": True, "active": True}],
            }
        ]
    }
}


def _path_a_batch():
    return normalize_vyos(
        {
            "config": CONFIG_PATH_A,
            "version_text": VERSION_PATH_A,
            "links": LINKS_PATH_A,
            "routes_tables": ROUTES_TABLES_PATH_A,
        },
        l3dom="patha",
    )


def test_path_a_table_300_route_carries_the_next_hop_and_the_resolved_egress():
    """The acceptance fixture's own second table, normalized with both halves
    of the capture present. They are one route, carrying the config's next hop
    and the RIB row's resolved egress, so the redirected leg has an egress for
    the zone pair to find a pair for and for the masquerade's
    outbound-interface to match."""
    batch = _path_a_batch()
    pfx = "pfx:vrf-dev-patha-edge-table300:10.0.30.0/24"
    statics = [r for r in batch.rels if r.rel_type == "STATIC_ROUTE" and r.end_uid == pfx]
    assert len(statics) == 1
    assert statics[0].props["next_hop"] == "10.0.9.2"
    assert statics[0].props["rib_interface"] == "eth2"
    assert statics[0].props["rib_confirmed"] is True
    assert not [r for r in batch.rels if r.rel_type == "LEARNED_ROUTE" and r.end_uid == pfx]
    via = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "VIA"}
    assert (pfx, "dev:patha-edge/if/eth2") in via


def test_path_a_carries_both_rulebase_models_and_two_source_nat_rules():
    """The shapes the acceptance test rests on: the device-wide forward chain
    beside the LAN-to-WAN zone policy, and one masquerade plus one static
    source translation, which is what makes the two clients arrive at Check
    Point as two different post-NAT sources."""
    batch = _path_a_batch()
    rulebases = _by_uid(batch, "FwRulebase")
    assert rulebases["vyos:patha-edge:fw:ipv4-forward"]["chain"] == "forward"
    assert "vyos:patha-edge:fw:LAN-WAN" in rulebases
    zone_bound = {r.start_uid for r in batch.rels if r.rel_type in ("FROM_ZONE", "TO_ZONE") and r.start_uid}
    assert zone_bound == {"vyos:patha-edge:fw:LAN-WAN"}
    nat = _by_uid(batch, "NatRule")
    assert nat["vyos:patha-edge:nat:source:100"]["translation"] == "masquerade"
    assert nat["vyos:patha-edge:nat:source:100"]["orig_src"] == "10.20.1.0/24"
    assert nat["vyos:patha-edge:nat:source:110"]["translation"] == "10.0.9.50"
    assert nat["vyos:patha-edge:nat:source:110"]["orig_src"] == "10.20.2.0/24"
    pbr_enforcers = {
        (r.start_label, r.start_uid)
        for r in batch.rels
        if r.rel_type == "ENFORCES" and r.end_uid == "vyos:patha-edge:pbr:DC-PBR"
    }
    # bound to its ingress interfaces, and enforced by the router like every policy it holds
    assert pbr_enforcers == {
        ("Interface", "dev:patha-edge/if/eth1"),
        ("Interface", "dev:patha-edge/if/eth3"),
        ("Device", "dev:patha-edge"),
    }


# --- OSPF: FRR via vtysh, per VRF -------------------------------------------------------
#
# The JSON field names below follow FRR's docs for `show ip ospf ... json`.

AREA_0 = "0.0.0.0"  # noqa: S104 - an OSPF area id
VERSION_OSPF = "Version:          VyOS 1.5-rolling-202607150020\nHardware S/N:     OSPFVYOS1\n"

OSPF_CFG = {
    "system": {"host-name": "gw-ospf"},
    "interfaces": {
        "ethernet": {
            "eth0": {"address": ["10.0.0.1/30"]},
            "eth1": {"address": ["10.0.1.1/30"]},
            "eth2": {"address": ["10.0.2.1/30"], "vrf": "RED"},
        }
    },
    "vrf": {"name": {"RED": {"table": "100", "protocols": {"ospf": {}}}}},
    "protocols": {"ospf": {"redistribute": {"connected": {}}}},
}

OSPF_DEFAULT_PROCESS = {
    "routerId": "10.255.0.1",
    "areas": {AREA_0: {}, "0.0.0.10": {"stub": True}},
}
OSPF_DEFAULT_INTERFACES = {
    "interfaces": {
        "eth0": {"area": AREA_0, "cost": 10, "networkType": "POINTOPOINT", "timerPassiveIface": False},
        "eth1": {"area": "0.0.0.10", "cost": 20, "networkType": "BROADCAST", "timerPassiveIface": True},
    }
}
OSPF_DEFAULT_NEIGHBORS = {
    "neighbors": {
        "10.255.0.2": [{"ifaceName": "eth0:10.0.0.1", "nbrState": "Full/DR", "address": "10.0.0.2"}]
    }
}
OSPF_DEFAULT_LSDB_ROUTER = {
    "routerLinkStates": {
        "areas": {
            AREA_0: [
                {
                    "lsId": "10.255.0.1",
                    "advertisedRouter": "10.255.0.1",
                    "lsaAge": 120,
                    "lsaSeqNumber": "0x80000005",
                    "routerLinks": [
                        {
                            "linkType": "point-to-point",
                            "linkId": "10.255.0.2",
                            "linkData": "10.0.0.1",
                            "metric": 10,
                        }
                    ],
                }
            ]
        }
    }
}
OSPF_DEFAULT_LSDB_NETWORK = {
    "networkLinkStates": {
        "areas": {
            AREA_0: [
                {
                    "lsId": "10.0.0.1",
                    "advertisedRouter": "10.255.0.1",
                    "lsaAge": 200,
                    "lsaSeqNumber": "0x80000002",
                    "networkMask": "255.255.255.252",
                    "attachedRouters": ["10.255.0.1", "10.255.0.2"],
                }
            ]
        }
    }
}
OSPF_DEFAULT_LSDB_SUMMARY = {
    "summaryLinkStates": {
        "areas": {
            "0.0.0.10": [
                {
                    "lsId": "10.10.10.0",
                    "advertisedRouter": "10.255.0.1",
                    "lsaAge": 60,
                    "lsaSeqNumber": "0x80000001",
                    "networkMask": "255.255.255.0",
                    "metric": 20,
                }
            ]
        }
    }
}
OSPF_DEFAULT_LSDB_ASBR_SUMMARY = {
    "asbrSummaryLinkStates": {
        "areas": {
            "0.0.0.10": [
                {
                    "lsId": "10.255.0.2",
                    "advertisedRouter": "10.255.0.1",
                    "lsaAge": 60,
                    "lsaSeqNumber": "0x80000001",
                    "metric": 10,
                }
            ]
        }
    }
}
OSPF_DEFAULT_LSDB_EXTERNAL = {
    "asExternalLinkStates": [
        {
            "lsId": "203.0.113.0",
            "advertisedRouter": "10.255.0.2",
            "lsaAge": 100,
            "lsaSeqNumber": "0x80000003",
            "networkMask": "255.255.255.0",
            "metricType": "E2",
            "metric": 100,
            "forwardAddress": "10.0.0.2",
        }
    ]
}
OSPF_DEFAULT_LSDB_NSSA_EXTERNAL = {
    "nssaExternalLinkStates": {
        "areas": {
            "0.0.0.10": [
                {
                    "lsId": "198.51.100.0",
                    "advertisedRouter": "10.255.0.3",
                    "lsaAge": 90,
                    "lsaSeqNumber": "0x80000002",
                    "networkMask": "255.255.255.0",
                    "metricType": "E1",
                    "metric": 50,
                    "forwardAddress": AREA_0,
                }
            ]
        }
    }
}

OSPF_RED_PROCESS = {"routerId": "10.255.1.1", "areas": {AREA_0: {}}}
OSPF_RED_INTERFACES = {
    "interfaces": {
        "eth2": {"area": AREA_0, "cost": 5, "networkType": "POINTOPOINT", "timerPassiveIface": False}
    }
}

OSPF_RAW = {
    "config": OSPF_CFG,
    "version_text": VERSION_OSPF,
    "links": [],
    "ospf_default_process": OSPF_DEFAULT_PROCESS,
    "ospf_default_interfaces": OSPF_DEFAULT_INTERFACES,
    "ospf_default_neighbors": OSPF_DEFAULT_NEIGHBORS,
    "ospf_default_lsdb_router": OSPF_DEFAULT_LSDB_ROUTER,
    "ospf_default_lsdb_network": OSPF_DEFAULT_LSDB_NETWORK,
    "ospf_default_lsdb_summary": OSPF_DEFAULT_LSDB_SUMMARY,
    "ospf_default_lsdb_asbr_summary": OSPF_DEFAULT_LSDB_ASBR_SUMMARY,
    "ospf_default_lsdb_external": OSPF_DEFAULT_LSDB_EXTERNAL,
    "ospf_default_lsdb_nssa_external": OSPF_DEFAULT_LSDB_NSSA_EXTERNAL,
    "ospf_RED_process": OSPF_RED_PROCESS,
    "ospf_RED_interfaces": OSPF_RED_INTERFACES,
    "ospf_RED_neighbors": {},
    "ospf_RED_lsdb_router": {},
    "ospf_RED_lsdb_network": {},
    "ospf_RED_lsdb_summary": {},
    "ospf_RED_lsdb_asbr_summary": {},
    "ospf_RED_lsdb_external": {},
    "ospf_RED_lsdb_nssa_external": {},
}


def _ospf_batch():
    return normalize_vyos(OSPF_RAW, l3dom="corp")


OSPF_DEV = "dev:gw-ospf"
OSPF_RPU_DEFAULT = "rproc:dev:gw-ospf:default:ospf"
OSPF_RPU_RED = "rproc:dev:gw-ospf:red:ospf"


def test_ospf_process_carries_router_id_and_is_in_its_own_vrf():
    batch = _ospf_batch()
    procs = {
        n.uid: n.props for n in batch.nodes if n.label == "RoutingProcess" and n.props.get("proto") == "ospf"
    }
    assert procs[OSPF_RPU_DEFAULT]["router_id"] == "10.255.0.1"
    assert procs[OSPF_RPU_RED]["router_id"] == "10.255.1.1"
    in_vrf = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "IN_VRF"}
    assert (OSPF_RPU_DEFAULT, "vrf:dev:gw-ospf:default") in in_vrf
    assert (OSPF_RPU_RED, "vrf:dev:gw-ospf:red") in in_vrf


def test_ospf_areas_carry_their_type_from_the_operational_read():
    batch = _ospf_batch()
    areas = {n.props["area_id"]: n.props["type"] for n in batch.nodes if n.label == "OspfArea"}
    assert areas[AREA_0] == "normal"
    assert areas["0.0.0.10"] == "stub"


def test_ospf_interfaces_carry_cost_network_type_and_passive_and_land_in_their_area():
    batch = _ospf_batch()
    in_area = {
        r.start_uid: r.props for r in batch.rels if r.rel_type == "IN_AREA" and r.start_label == "Interface"
    }
    eth0 = in_area[f"{OSPF_DEV}/if/eth0"]
    assert (eth0["cost"], eth0["network_type"], eth0["passive"]) == (10, "point-to-point", False)
    eth1 = in_area[f"{OSPF_DEV}/if/eth1"]
    assert (eth1["cost"], eth1["network_type"], eth1["passive"]) == (20, "broadcast", True)
    eth2 = in_area[f"{OSPF_DEV}/if/eth2"]
    assert eth2["cost"] == 5
    area_edges = {r.start_uid: r.end_uid for r in batch.rels if r.rel_type == "IN_AREA"}
    assert area_edges[f"{OSPF_DEV}/if/eth2"] != area_edges[f"{OSPF_DEV}/if/eth0"]


def test_ospf_adjacency_takes_its_state_from_the_slash_prefix_and_its_area_from_its_interface():
    batch = _ospf_batch()
    adjacencies = [n for n in batch.nodes if n.label == "OspfAdjacency"]
    assert len(adjacencies) == 1
    adj = adjacencies[0]
    assert adj.props["state"] == "FULL"  # "Full/DR" reads as the state word alone
    assert adj.props["area"] == AREA_0
    assert adj.props["neighbor_router_id"] == "10.255.0.2"
    assert adj.props["neighbor_ip"] == "10.0.0.2"
    assert adj.props["local_interface"] == "eth0"
    endpoints = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ENDPOINT"}
    assert (adj.uid, f"{OSPF_DEV}/if/eth0") in endpoints


def test_ospf_lsdb_covers_all_six_lsa_types_with_their_typed_bodies():
    tables = _collector().side_tables(OSPF_RAW)
    rows = {r["lsa_type"]: r for r in tables["ospf_lsdb"]}
    assert set(rows) == {"router", "network", "summary", "asbr-summary", "external", "nssa-external"}

    router = rows["router"]
    assert (router["lsid"], router["seq"], router["age"]) == ("10.255.0.1", 0x80000005, 120)
    assert router["links"] == [
        {"link_type": "point-to-point", "link_id": "10.255.0.2", "link_data": "10.0.0.1", "metric": 10}
    ]
    network = rows["network"]
    assert network["mask"] == "255.255.255.252"
    assert network["attached_routers"] == ["10.255.0.1", "10.255.0.2"]
    summary = rows["summary"]
    assert (summary["area"], summary["metric"]) == ("0.0.0.10", 20)
    asbr = rows["asbr-summary"]
    assert (asbr["lsid"], asbr["metric"]) == ("10.255.0.2", 10)
    external = rows["external"]
    assert external["area"] is None  # AS-external is flooded domain-wide
    assert (external["metric"], external["metric_type"], external["forwarding_address"]) == (
        100,
        2,
        "10.0.0.2",
    )
    nssa = rows["nssa-external"]
    assert (nssa["area"], nssa["metric_type"]) == ("0.0.0.10", 1)


def test_ospf_lsdb_rows_join_the_correct_vrf_for_a_named_vrf_with_mixed_case():
    raw = json.loads(json.dumps(OSPF_RAW))
    raw["ospf_RED_lsdb_router"] = {
        "routerLinkStates": {
            "areas": {AREA_0: [{"lsId": "10.255.1.1", "advertisedRouter": "10.255.1.1", "lsaAge": 10}]}
        }
    }
    tables = _collector().side_tables(raw)
    red_rows = [r for r in tables["ospf_lsdb"] if r["lsid"] == "10.255.1.1"]
    assert len(red_rows) == 1
    assert red_rows[0]["context_uid"] == "vrf:dev:gw-ospf:red"


def test_ospf_table_outcomes_reads_unsupported_when_no_vrf_configures_ospf():
    no_ospf_cfg = {"system": {"host-name": "gw-ospf"}}
    outcomes = _collector().table_outcomes({"config": no_ospf_cfg})
    assert outcomes["ospf_lsdb"].status == "unsupported"
    assert outcomes["ospf_lsdb"].detail


def test_ospf_table_outcomes_is_empty_when_a_vrf_configures_ospf():
    """`table_outcomes` states nothing about `ospf_lsdb`."""
    assert "ospf_lsdb" not in _collector().table_outcomes(OSPF_RAW)


def test_a_bare_empty_ospf_stanza_still_counts_as_configured():
    """`set protocols ospf` with no further config reads as `{}` in `show
    configuration json`."""
    cfg = {"system": {"host-name": "gw-ospf"}, "protocols": {"ospf": {}}}
    assert "ospf_lsdb" not in _collector().table_outcomes({"config": cfg})


def test_ospf_vtysh_commands_are_issued_per_vrf_where_ospf_is_configured(monkeypatch):
    cfg = {
        "system": {"host-name": "gw-ospf"},
        "vrf": {
            "name": {
                "RED": {"table": "100", "protocols": {"ospf": {}}},
                "BLUE": {"table": "200"},  # no ospf configured
            }
        },
        "protocols": {"ospf": {}},
    }

    def outputs(cmd: str) -> str:
        if "show configuration json" in cmd:
            return json.dumps(cfg)
        if "show version" in cmd:
            return VERSION_OSPF
        return "{}"

    fake = FakeSshSession(outputs).install(monkeypatch)
    raw = _collector().fetch()

    assert 'PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ip ospf json"' in fake.commands
    assert 'PATH=/usr/sbin:/sbin:/usr/bin:/bin vtysh -c "show ip ospf vrf RED json"' in fake.commands
    assert not any("vrf BLUE" in c for c in fake.commands)
    assert "ospf_default_process" in raw
    assert "ospf_RED_process" in raw
    assert "ospf_BLUE_process" not in raw


# --- BGP session and path observations ----------------------------------------------------
#
# The field names below are what FRR documents for these commands.

DEV = "dev:gw"
DEFAULT_VRF_UID = "vrf:dev:gw:default"
CUSTOMER, CORE, SYMBOLIC = "203.0.113.2", "10.0.0.2", "192.0.2.9"

BGP_SUMMARY_PAYLOAD = {
    "default": {
        "ipv4Unicast": {
            "routerId": "203.0.113.1",
            "as": 65000,
            "peers": {
                CUSTOMER: {"state": "Established", "pfxRcd": 1, "pfxSnt": 1},
                CORE: {"state": "Established", "pfxRcd": 1, "pfxSnt": 1},
                SYMBOLIC: {"state": "Idle", "pfxRcd": 0, "pfxSnt": 0},
            },
        }
    }
}

# The line FRR is assumed to answer with when soft reconfiguration inbound is
# not configured on the neighbor: a zero exit status and no rejection banner,
# so the fetch keeps it as output and the direction reads not-captured on the
# text alone (the same convention `nxos.py` documents for NX-OS).
BGP_NO_SOFT_RECONFIG = "% Inbound soft-reconfiguration is not configured for this neighbor\n"

# The inbound prefix-list admits one of the two prefixes CUSTOMER sent.
BGP_CUSTOMER_RECEIVED = {
    "receivedRoutes": {
        "10.20.0.0/24": [
            {
                "aspath": {"string": "65001"},
                "origin": "e",
                "metric": 0,
                "locPrf": 100,
                "bestpath": True,
                "communityList": [],
                "nexthops": [{"ip": CUSTOMER, "used": True}],
            }
        ],
        "10.99.0.0/24": [
            {"aspath": {"string": "65001"}, "origin": "e", "nexthops": [{"ip": CUSTOMER, "used": True}]}
        ],
    }
}
BGP_CUSTOMER_ACCEPTED = {
    "routes": {
        "10.20.0.0/24": [
            {
                "aspath": {"string": "65001"},
                "origin": "e",
                "metric": 0,
                "locPrf": 200,
                "communityList": ["65000:100"],
                "bestpath": True,
                "nexthops": [{"ip": CUSTOMER, "used": True}],
            }
        ]
    }
}
BGP_CUSTOMER_ADVERTISED = {
    "advertisedRoutes": {
        "10.30.0.0/24": [
            {
                "aspath": {"string": ""},
                "origin": "i",
                "metric": 0,
                "locPrf": 100,
                "bestpath": True,
                "nexthops": [{"ip": "203.0.113.1", "used": True}],
            }
        ]
    }
}
BGP_CORE_ACCEPTED = {
    "routes": {
        "10.20.0.0/24": [
            {
                "aspath": {"string": ""},
                "origin": "i",
                "metric": 0,
                "locPrf": 100,
                "bestpath": False,
                "nexthops": [{"ip": CORE, "used": True}],
            }
        ]
    }
}
BGP_CORE_ADVERTISED = {
    "advertisedRoutes": {
        "10.40.0.0/24": [
            {"aspath": {"string": ""}, "origin": "i", "nexthops": [{"ip": "10.0.0.1", "used": True}]}
        ]
    }
}


def _bgp_capture_raw():
    """The observation commands a `capture_bgp="all"` fetch issues over the
    `BGP_CONFIG` fixture, and what the box answers each with."""
    out = {vyos_mod.BGP_SUMMARY_COMMAND: json.dumps(BGP_SUMMARY_PAYLOAD)}
    answers = {
        (CUSTOMER, "received"): json.dumps(BGP_CUSTOMER_RECEIVED),
        (CUSTOMER, "accepted"): json.dumps(BGP_CUSTOMER_ACCEPTED),
        (CUSTOMER, "advertised"): json.dumps(BGP_CUSTOMER_ADVERTISED),
        (CORE, "received"): BGP_NO_SOFT_RECONFIG,
        (CORE, "accepted"): json.dumps(BGP_CORE_ACCEPTED),
        (CORE, "advertised"): json.dumps(BGP_CORE_ADVERTISED),
    }
    for (peer_ip, direction), text in answers.items():
        out[vyos_mod.bgp_route_command(DEFAULT_VRF, peer_ip, direction)] = text
    return out


def _bgp_obs_raw():
    """`{"config": BGP_CONFIG, ...}` plus the observation command outputs,
    with every command's outcome recorded `ok`."""
    capture = _bgp_capture_raw()
    return {
        "config": BGP_CONFIG,
        "version_text": VERSION,
        vyos_mod.RAW_OUTCOMES_KEY: {cmd: {"status": "ok"} for cmd in capture},
        **capture,
    }


def _bgp_fetch_outputs(cmd: str) -> str:
    if "show configuration json" in cmd:
        return json.dumps(BGP_CONFIG)
    if "show version" in cmd:
        return VERSION
    raw = _bgp_capture_raw()
    if cmd in raw:
        return raw[cmd]
    if "vtysh" in cmd:
        return "{}"
    return "[]"


def _bgp_collector(capture="all"):
    return VyosCollector(
        VyosConfig(
            host=HOST,
            auth=SshPassword(username=USER, password="pw"),
            site_code="wan",
            l3dom="wan",
            capture_bgp=capture,
        ),
        None,
    )


def _session_uid(peer_ip, vrf=DEFAULT_VRF):
    """The BgpSession uid an observed row of this peer joins the graph through."""
    return uid.bgp_session(uid.routing_process(DEV, vrf, "bgp"), peer_ip, vrf)


def test_bgp_capture_targets_skips_a_symbolic_remote_as():
    """192.0.2.9's remote-as ("auto") is symbolic."""
    assert set(vyos_mod.bgp_capture_targets(BGP_CONFIG)) == {(DEFAULT_VRF, CUSTOMER), (DEFAULT_VRF, CORE)}


def test_the_route_command_omits_the_vrf_clause_for_the_default_table():
    assert vyos_mod.bgp_route_command("", CUSTOMER, "received") == vyos_mod.bgp_route_command(
        DEFAULT_VRF, CUSTOMER, "received"
    )
    assert "vrf" not in vyos_mod.bgp_route_command(DEFAULT_VRF, CUSTOMER, "received")
    # the family is named, after the VRF clause: without it FRR reads IPv6 unicast
    assert "vrf RED ipv4 unicast neighbors" in vyos_mod.bgp_route_command("RED", CUSTOMER, "received")


def test_the_route_command_names_the_ipv4_unicast_family_for_every_direction():
    expected = {
        ("default", "received"): 'show bgp ipv4 unicast neighbors 203.0.113.2 received-routes json"',
        ("default", "accepted"): 'show bgp ipv4 unicast neighbors 203.0.113.2 routes json"',
        ("default", "advertised"): 'show bgp ipv4 unicast neighbors 203.0.113.2 advertised-routes json"',
        ("RED", "received"): 'show bgp vrf RED ipv4 unicast neighbors 203.0.113.2 received-routes json"',
        ("RED", "accepted"): 'show bgp vrf RED ipv4 unicast neighbors 203.0.113.2 routes json"',
        ("RED", "advertised"): 'show bgp vrf RED ipv4 unicast neighbors 203.0.113.2 advertised-routes json"',
    }
    for (vrf, direction), tail in expected.items():
        command = vyos_mod.bgp_route_command(vrf, CUSTOMER, direction)
        assert command == f'{vyos_mod._IP_PATH} vtysh -c "{tail}'
        # the spelling without the family clause, which only the read of a stored payload uses
        assert vyos_mod.legacy_bgp_route_command(vrf, CUSTOMER, direction) == command.replace(
            " ipv4 unicast neighbors ", " neighbors "
        )


def test_the_summary_command_stays_in_the_change_hash_because_it_feeds_a_side_table():
    assert vyos_mod.BGP_SUMMARY_COMMAND not in VyosCollector.VOLATILE_RAW_KEYS


def test_capture_all_reads_the_summary_and_three_directions_per_peer(monkeypatch):
    """The per-neighbor commands are derived from the configuration this same
    fetch read, so the command set is per fetch and not fixed."""
    fake = FakeSshSession(_bgp_fetch_outputs).install(monkeypatch)
    raw = _bgp_collector("all").fetch()
    assert vyos_mod.BGP_SUMMARY_COMMAND in fake.commands
    for peer_ip in (CUSTOMER, CORE):
        for direction in ("received", "accepted", "advertised"):
            assert vyos_mod.bgp_route_command(DEFAULT_VRF, peer_ip, direction) in fake.commands
    for direction in ("received", "accepted", "advertised"):
        assert vyos_mod.bgp_route_command(DEFAULT_VRF, SYMBOLIC, direction) not in fake.commands
    assert vyos_mod.BGP_SUMMARY_COMMAND in raw


def test_capture_all_reads_an_auto_peer_the_summary_reports_an_asn_for(monkeypatch):
    """The per-neighbor commands follow the summary, so a neighbor
    whose remote-as is `auto` is read once the summary reports its ASN."""
    payload = json.loads(json.dumps(BGP_SUMMARY_PAYLOAD))
    payload["default"]["ipv4Unicast"]["peers"][SYMBOLIC] = {"state": "Established", "remoteAs": 65009}

    def outputs(cmd):
        if cmd == vyos_mod.BGP_SUMMARY_COMMAND:
            return json.dumps(payload)
        return _bgp_fetch_outputs(cmd)

    fake = FakeSshSession(outputs).install(monkeypatch)
    raw = _bgp_collector("all").fetch()
    for direction in ("received", "accepted", "advertised"):
        assert vyos_mod.bgp_route_command(DEFAULT_VRF, SYMBOLIC, direction) in fake.commands
    batch = normalize_vyos(raw, l3dom="wan")
    sessions = {n.props["peer_ip"]: n.props for n in batch.nodes if n.label == "BgpSession"}
    assert sessions[SYMBOLIC]["peer_asn"] == 65009


def test_capture_none_asks_the_device_for_nothing_beyond_the_static_commands(monkeypatch):
    fake = FakeSshSession(_bgp_fetch_outputs).install(monkeypatch)
    collector = _bgp_collector("none")
    raw = collector.fetch()
    assert vyos_mod.BGP_SUMMARY_COMMAND not in fake.commands
    outcomes = collector.table_outcomes(raw)
    assert outcomes["bgp_sessions"].status == "not-captured"
    assert outcomes["bgp_session_routes"].status == "not-captured"
    assert "capture_bgp setting is none" in outcomes["bgp_session_routes"].detail
    directions = manifest.bgp_direction_outcomes(outcomes)
    assert len(directions) == 6
    assert {o.status for o in directions.values()} == {"not-captured"}


def test_capture_sessions_reads_summary_only_and_states_the_paths_not_captured(monkeypatch):
    fake = FakeSshSession(_bgp_fetch_outputs).install(monkeypatch)
    collector = _bgp_collector("sessions")
    raw = collector.fetch()
    assert vyos_mod.BGP_SUMMARY_COMMAND in fake.commands
    assert vyos_mod.bgp_route_command(DEFAULT_VRF, CUSTOMER, "accepted") not in fake.commands
    outcomes = collector.table_outcomes(raw)
    assert "bgp_sessions" not in outcomes
    assert outcomes["bgp_session_routes"].status == "not-captured"
    tables = collector.side_tables(raw)
    assert {r["peer_ip"] for r in tables["bgp_sessions"]} == {CUSTOMER, CORE, SYMBOLIC}
    assert tables["bgp_session_routes"] == []


def test_parse_bgp_summary_carries_state_and_prefix_counts():
    sessions = vyos_mod.parse_bgp_summary(json.dumps(BGP_SUMMARY_PAYLOAD))
    assert {(s["vrf"], s["peer_ip"], s["state"]) for s in sessions} == {
        ("default", CUSTOMER, "Established"),
        ("default", CORE, "Established"),
        ("default", SYMBOLIC, "Idle"),
    }
    # FRR's own uptime here is a duration.
    assert all(s["established_since_ms"] is None and s["capabilities"] is None for s in sessions)
    customer = next(s for s in sessions if s["peer_ip"] == CUSTOMER)
    assert (customer["prefixes_received"], customer["prefixes_advertised"]) == (1, 1)


def test_parse_bgp_paths_carries_attributes_and_the_best_marking():
    accepted = vyos_mod.parse_bgp_paths(
        json.dumps(BGP_CUSTOMER_ACCEPTED), vrf=DEFAULT_VRF, peer_ip=CUSTOMER, direction="accepted"
    )
    assert len(accepted) == 1
    row = accepted[0]
    assert row["prefix"] == "10.20.0.0/24"
    assert row["next_hop"] == CUSTOMER
    assert (row["local_pref"], row["med"], row["origin"]) == (200, 0, "e")
    assert row["communities"] == "65000:100"
    assert row["best"] is True
    assert row["path_id"] == "0"


def test_a_received_direction_is_pre_decision_and_carries_no_best_marking():
    received = vyos_mod.parse_bgp_paths(
        json.dumps(BGP_CUSTOMER_RECEIVED), vrf=DEFAULT_VRF, peer_ip=CUSTOMER, direction="received"
    )
    assert sorted(r["prefix"] for r in received) == ["10.20.0.0/24", "10.99.0.0/24"]
    assert all(r["best"] is None for r in received)


def test_two_peers_supplying_one_prefix_are_two_rows_and_best_marks_one():
    """The observation the `rib` table cannot make: which peer supplied which
    alternative, and which one the device chose."""
    customer = vyos_mod.parse_bgp_paths(
        json.dumps(BGP_CUSTOMER_ACCEPTED), vrf=DEFAULT_VRF, peer_ip=CUSTOMER, direction="accepted"
    )
    core = vyos_mod.parse_bgp_paths(
        json.dumps(BGP_CORE_ACCEPTED), vrf=DEFAULT_VRF, peer_ip=CORE, direction="accepted"
    )
    rows = [r for r in (*customer, *core) if r["prefix"] == "10.20.0.0/24"]
    assert sorted(r["peer_ip"] for r in rows) == sorted([CUSTOMER, CORE])
    assert [r["peer_ip"] for r in rows if r["best"]] == [CUSTOMER]


def test_side_tables_join_observations_to_the_session_node_and_its_context():
    raw = _bgp_obs_raw()
    tables = vyos_mod.bgp_side_rows(raw, DEV)
    batch = _bgp_batch()
    nodes = {n.uid for n in batch.nodes if n.label == "BgpSession"}
    for table in ("bgp_sessions", "bgp_session_routes"):
        assert tables[table]
        for row in tables[table]:
            assert row["device_uid"] == DEV
            assert row["context_uid"] == DEFAULT_VRF_UID
    # 192.0.2.9's symbolic remote-as mints no node.
    assert {r["session_uid"] for r in tables["bgp_sessions"]} - {_session_uid(SYMBOLIC)} <= nodes
    assert _session_uid(CUSTOMER) in nodes


def test_observed_path_rows_carry_the_interval_columns_and_the_stage():
    raw = _bgp_obs_raw()
    rows = vyos_mod.bgp_side_rows(raw, DEV)["bgp_session_routes"]
    row = next(r for r in rows if r["direction"] == "advertised" and r["peer_ip"] == CUSTOMER)
    assert (row["rib_type"], row["policy_stage"], row["safi"]) == ("adj-rib-out", "post-export", "unicast")
    assert (row["af"], row["prefixlen"]) == (4, 24)
    assert row["lo"] and row["hi"]
    assert row["next_hop_context_uid"] is None
    received = next(r for r in rows if r["direction"] == "received" and r["peer_ip"] == CUSTOMER)
    assert (received["rib_type"], received["policy_stage"]) == ("adj-rib-in", "pre-import")
    accepted = next(r for r in rows if r["direction"] == "accepted" and r["peer_ip"] == CUSTOMER)
    assert (accepted["rib_type"], accepted["policy_stage"]) == ("loc-rib", "post-import")


def test_a_received_direction_without_soft_reconfiguration_reports_not_captured():
    """FRR does not retain the pre-policy table and says so. The direction is
    `not-captured`."""
    raw = _bgp_obs_raw()
    directions = manifest.bgp_direction_outcomes(_bgp_collector("all").table_outcomes(raw))
    outcome = directions[(_session_uid(CORE), "received")]
    assert outcome.status == "not-captured"
    assert "soft-reconfiguration" in outcome.detail
    assert outcome.row_count is None
    assert directions[(_session_uid(CORE), "accepted")].status == "complete"
    assert directions[(_session_uid(CORE), "advertised")].status == "complete"


def test_a_direction_the_box_answered_with_an_empty_table_is_empty_not_uncaptured(monkeypatch):
    """The empty table in the form FRR prints it: the table key with no
    prefix and `totalPrefixCounter` 0. A bare `{}` is no such answer and
    reads `failed` (`test_an_answer_that_is_no_route_table_fails_with_a_reason`)."""
    command = vyos_mod.bgp_route_command(DEFAULT_VRF, CORE, "advertised")

    def outputs(cmd):
        if cmd == command:
            return '{"advertisedRoutes": {}, "totalPrefixCounter": 0, "filteredPrefixCounter": 0}'
        return _bgp_fetch_outputs(cmd)

    FakeSshSession(outputs).install(monkeypatch)
    collector = _bgp_collector("all")
    raw = collector.fetch()
    directions = manifest.bgp_direction_outcomes(collector.table_outcomes(raw))
    outcome = directions[(_session_uid(CORE), "advertised")]
    assert (outcome.status, outcome.row_count) == ("complete-empty", 0)


def test_a_box_without_bgpd_states_the_session_table_not_captured(monkeypatch):
    from hst.collectors import ssh

    command = vyos_mod.BGP_SUMMARY_COMMAND

    def outputs(cmd):
        if cmd == command:
            raise ssh.CommandFailed(f"{command!r} rejected by device: % Unknown command")
        return _bgp_fetch_outputs(cmd)

    FakeSshSession(outputs).install(monkeypatch)
    collector = _bgp_collector("all")
    raw = collector.fetch()
    outcomes = collector.table_outcomes(raw)
    assert outcomes["bgp_sessions"].status == "not-captured"
    assert "Unknown command" in outcomes["bgp_sessions"].detail
    assert collector.side_tables(raw)["bgp_sessions"] == []


def test_a_session_table_the_box_answered_leaves_the_write_outcome_alone():
    raw = _bgp_obs_raw()
    assert "bgp_sessions" not in _bgp_collector("all").table_outcomes(raw)


def test_a_direction_the_box_refuses_as_unsupported_reads_not_captured(monkeypatch):
    """`classify_command_failure` reads the device's own rejection banner: a
    box that lacks bgpd for the family is not a box someone has to fix."""
    from hst.collectors import ssh

    command = vyos_mod.bgp_route_command(DEFAULT_VRF, CUSTOMER, "accepted")

    def outputs(cmd):
        if cmd == command:
            raise ssh.CommandFailed(f"{command!r} rejected by device: % Unknown command")
        return _bgp_fetch_outputs(cmd)

    FakeSshSession(outputs).install(monkeypatch)
    collector = _bgp_collector("all")
    raw = collector.fetch()
    directions = manifest.bgp_direction_outcomes(collector.table_outcomes(raw))
    outcome = directions[(_session_uid(CUSTOMER), "accepted")]
    assert outcome.status == "not-captured"
    assert "Unknown command" in outcome.detail


def test_a_direction_refused_for_a_fixable_reason_reads_failed(monkeypatch):
    from hst.collectors import ssh

    command = vyos_mod.bgp_route_command(DEFAULT_VRF, CUSTOMER, "advertised")

    def outputs(cmd):
        if cmd == command:
            raise ssh.CommandFailed(f"{command!r} exited 1: Permission denied")
        return _bgp_fetch_outputs(cmd)

    FakeSshSession(outputs).install(monkeypatch)
    collector = _bgp_collector("all")
    raw = collector.fetch()
    directions = manifest.bgp_direction_outcomes(collector.table_outcomes(raw))
    outcome = directions[(_session_uid(CUSTOMER), "advertised")]
    assert outcome.status == "failed"


def test_every_session_direction_pair_is_captured_or_not_captured_with_a_reason():
    raw = _bgp_obs_raw()
    outcomes = _bgp_collector("all").table_outcomes(raw)
    directions = manifest.bgp_direction_outcomes(outcomes)
    assert len(directions) == len(vyos_mod.bgp_capture_targets(BGP_CONFIG)) * 3
    for outcome in directions.values():
        assert outcome.status in ("complete", "complete-empty", "not-captured")
        if outcome.status == "not-captured":
            assert outcome.detail
    assert directions[(_session_uid(CORE), "received")].status == "not-captured"
    # the summary command answered, so this run states nothing about the
    # table itself; only the one direction FRR cannot expose is stated
    assert "bgp_sessions" not in outcomes


def test_connected_rib_rows_reach_the_side_table_but_not_the_graph_mirror():
    from hst.core import Settings

    cfg = {
        "system": {"host-name": "gw"},
        "interfaces": {
            "ethernet": {
                "eth1": {"address": ["192.168.1.1/24"]},
                "eth6": {"address": ["10.6.0.1/24"]},
            },
        },
        "protocols": {"static": {"route": {"172.16.0.0/16": {"next-hop": {"192.168.1.254": {}}}}}},
    }
    raw = {
        "config": cfg,
        "version_text": VERSION,
        "links": [],
        "routes": {
            "default": {
                **_route("192.168.1.0/24", _nh(dev="eth1", directlyConnected=True), protocol="connected"),
                **_route("192.168.1.1/32", _nh(dev="eth1"), protocol="local"),
                **_route("172.16.0.0/16", _nh(ip="192.168.1.254", dev="eth1"), protocol="static"),
                **_route("10.80.0.0/24", _nh(ip="192.168.1.10", dev="eth1"), protocol="bgp"),
            }
        },
        "routes6": {"default": {}},
    }
    c = VyosCollector(
        VyosConfig(
            host="gw1", auth=SshPassword(username="vyos", password="pw"), site_code="dc1", l3dom="dc1"
        ),
        Settings(_env_file=None),
    )
    rows = {r["prefix"]: r for r in c.side_tables(raw)["rib"]}
    connected = rows["192.168.1.0/24"]
    assert connected["protocol"] == "connected"
    assert connected["next_hop"] is None and connected["interface"] == "eth1"
    assert connected["discard"] is None
    assert "192.168.1.1/32" not in rows, "a local host route is the device's own address, not a route"
    assert rows["10.80.0.0/24"]["protocol"] == "bgp"

    batch = normalize_vyos(raw, l3dom="dc1")
    learned = {r.end_uid for r in batch.rels if r.rel_type == "LEARNED_ROUTE"}
    assert not any(u.endswith(":192.168.1.0/24") for u in learned), "the prefix is ORIGINATES already"
    assert any(u.endswith(":10.80.0.0/24") for u in learned), "the BGP row still mirrors"
    originates = {r.end_uid for r in batch.rels if r.rel_type == "ORIGINATES"}
    assert any(u.endswith(":192.168.1.0/24") for u in originates)


# --- OverlayConnection (schema v0.30.0) ----------------------------------------


def _router(host: str, wan: str, interfaces: dict, vpn: dict | None = None):
    """One VyOS router with its WAN address on eth0. Its serial is its host
    name, so two routers are two devices in one run."""
    cfg = {
        "system": {"host-name": host},
        "interfaces": {"ethernet": {"eth0": {"address": [wan]}}, **interfaces},
    }
    if vpn:
        cfg["vpn"] = vpn
    version = VERSION.replace("QEMU1234", host.upper())
    return normalize_vyos({"config": cfg, "version_text": version, "links": []}, l3dom="wan")


def _gre(local: str, remote: str) -> dict:
    return {"encapsulation": "gre", "source-address": local, "remote-ip": remote}


def gre_router_pair():
    """Two VyOS routers at the two ends of one GRE tunnel."""
    a = _router(
        "vyos-a",
        "192.0.2.1/24",
        {"tunnel": {"tun10": _gre("192.0.2.1", "198.51.100.7")}},
    )
    b = _router(
        "vyos-b",
        "198.51.100.7/24",
        {"tunnel": {"tun20": _gre("198.51.100.7", "192.0.2.1")}},
    )
    return a, b


def _connections(batch) -> dict[str, dict]:
    return {n.uid: n.props for n in batch.nodes if n.label == "OverlayConnection"}


def _between(batch, conn: str) -> dict[str, tuple[str, str, dict]]:
    return {
        r.props["end"]: (r.end_label, r.end_uid, r.props)
        for r in batch.rels
        if r.rel_type == "BETWEEN" and r.start_uid == conn
    }


def _realized(batch, conn: str) -> set[str]:
    return {r.end_uid for r in batch.rels if r.rel_type == "REALIZED_BY" and r.start_uid == conn}


def test_two_vyos_routers_at_the_ends_of_one_gre_tunnel_write_one_connection():
    """Each router knows the far router only by its address. The key is the two
    tunnel addresses, which both routers compute the same way, so both batches
    write the same connection with the same end letters; the loader merges
    them and each batch states the end it reported."""
    a, b = gre_router_pair()
    conn = uid.overlay_connection("gre", "192.0.2.1", "198.51.100.7")
    assert conn == "oconn:gre:192.0.2.1~198.51.100.7"
    assert list(_connections(a)) == [conn] and list(_connections(b)) == [conn]
    props_a, props_b = _connections(a)[conn], _connections(b)[conn]
    assert props_a["kind"] == "tunnel" and props_a["technology"] == "gre"
    assert props_a["name"] == "vyos-a to 198.51.100.7"
    assert props_a["observed_from"] == ["a"] and props_b["observed_from"] == ["b"]
    dev_a, dev_b = _device(a).uid, _device(b).uid
    ends_a, ends_b = _between(a, conn), _between(b, conn)
    assert ends_a["a"][:2] == ("Device", dev_a) and ends_a["a"][2]["reported"] is True
    assert ends_a["a"][2]["role"] == "peer"
    # the far end is the remote address in the router's default table
    assert ends_a["b"][0] == "IpAddress" and ends_a["b"][2]["reported"] is False
    far = next(n for n in a.nodes if n.uid == ends_a["b"][1])
    assert far.props["ip"] == "198.51.100.7"
    assert ends_b["b"][:2] == ("Device", dev_b) and ends_b["b"][2]["reported"] is True
    # both batches realize the connection by the one tunnel both write
    tunnel = uid.tunnel("gre", "192.0.2.1", "198.51.100.7")
    assert _realized(a, conn) == _realized(b, conn) == {tunnel}


def test_a_gre_tunnel_without_a_source_address_is_told_apart_by_its_interface():
    """No far router can compute a key without the local address: the local
    tunnel interface is the discriminator, and the name carries it."""
    batch = _router(
        "vyos-a",
        "192.0.2.1/24",
        {
            "tunnel": {
                "tun10": {"encapsulation": "gre", "remote-ip": "198.51.100.7"},
                "tun11": {"encapsulation": "gre", "remote-ip": "198.51.100.8"},
            }
        },
    )
    conns = _connections(batch)
    by_name = {props["name"]: u for u, props in conns.items()}
    assert set(by_name) == {"vyos-a tun10 to 198.51.100.7", "vyos-a tun11 to 198.51.100.8"}
    if_uid = uid.interface(_device(batch).uid, "tun10")
    assert by_name["vyos-a tun10 to 198.51.100.7"] == uid.overlay_connection("gre", if_uid, "198.51.100.7")


def test_a_vti_tunnel_is_an_ipsec_connection_to_the_peer_address():
    vpn = {
        "ipsec": {
            "site-to-site": {
                "peer": {
                    "branch": {
                        "remote-address": "198.51.100.7",
                        "local-address": "192.0.2.1",
                        "vti": {"bind": "vti0"},
                    }
                }
            }
        }
    }
    batch = _router("vyos-a", "192.0.2.1/24", {"vti": {"vti0": {"address": ["10.255.0.1/30"]}}}, vpn)
    conn = uid.overlay_connection("ipsec", "192.0.2.1", "198.51.100.7")
    props = _connections(batch)[conn]
    assert props["technology"] == "ipsec" and props["name"] == "vyos-a to 198.51.100.7"
    assert _realized(batch, conn) == {uid.tunnel("ipsec", "192.0.2.1", "198.51.100.7")}


def test_a_wireguard_connection_keys_on_the_addresses_and_the_listen_ports():
    """Both routers know both listen ports, so the ports join the key and two
    WireGuard interfaces between the same two addresses stay two connections."""
    wg = {
        "wireguard": {
            "wg0": {
                "address": ["10.99.0.1/30"],
                "port": "51820",
                "source-address": "192.0.2.1",
                "peer": {
                    "site-b": {"address": "198.51.100.7", "port": "51821", "allowed-ips": ["10.99.0.2/32"]}
                },
            }
        }
    }
    batch = _router("vyos-a", "192.0.2.1/24", wg)
    conn = uid.overlay_connection("wireguard", "192.0.2.1:51820", "198.51.100.7:51821")
    props = _connections(batch)[conn]
    assert props["technology"] == "wireguard"
    assert props["name"] == "vyos-a to 198.51.100.7"
    tunnel = f"tun:wireguard:{_device(batch).uid}~wg0~site-b"
    assert _realized(batch, conn) == {tunnel}


def test_a_wireguard_peer_without_an_address_has_a_one_sided_connection():
    """A roaming peer names no address: the connection is keyed by the local
    interface and the peer name, and has the local end only."""
    batch = _batch()
    conns = {props["name"]: u for u, props in _connections(batch).items()}
    assert "gw wg0 to phone" in conns and "gw wg1 to backup" in conns
    conn = conns["gw wg0 to phone"]
    ends = _between(batch, conn)
    assert len(ends) == 1
    (letter,) = ends
    assert ends[letter][:2] == ("Device", _device(batch).uid)
    assert _connections(batch)[conn]["observed_from"] == [letter]


def test_a_vxlan_connection_ends_on_the_multicast_group():
    batch = _router(
        "vyos-a",
        "192.0.2.1/24",
        {"vxlan": {"vxlan10": {"vni": "10", "source-address": "192.0.2.1", "group": "239.1.1.1"}}},
    )
    conn = uid.overlay_connection("vxlan", "192.0.2.1", "239.1.1.1")
    props = _connections(batch)[conn]
    assert props["technology"] == "vxlan" and props["name"] == "vyos-a to 239.1.1.1"
    far = [e for e in _between(batch, conn).values() if e[0] == "IpAddress"]
    assert [next(n for n in batch.nodes if n.uid == e[1]).props["ip"] for e in far] == ["239.1.1.1"]


def test_the_overlay_connection_ends_rule_reads_the_reported_ends():
    """The reasoner rule that completes a connection two batches write: it
    reads only reported BETWEEN edges and changes only a connection with two
    reported ends."""
    from hst import reasoner

    rule = dict(reasoner.RULES)["overlay-connection-ends"]
    assert rule is not None
    assert "b.reported = true" in rule
    assert "WHERE size(ends) > 1" in rule
    assert "SET c.observed_from" in rule and "c.name" in rule


def test_route_map_rule_keeps_the_set_keys_it_does_not_read_and_reads_tag_and_metric():
    """A set key outside the mapped set lands in `set_unsupported`; a
    multi-AS prepend string is split; `match tag` and `match metric` are read."""
    config = json.loads(json.dumps(BGP_CONFIG))
    config["policy"]["route-map"]["CUSTOMER-OUT"]["rule"]["30"] = {
        "action": "permit",
        "match": {"tag": "7", "metric": "20"},
        "set": {
            "as-path": {"prepend": "65000 65000"},
            "ip-next-hop": "192.0.2.1",
            "metric": "+10",
            "community": {"delete": "CL-DEL"},
        },
    }
    batch = normalize_vyos({"config": config, "version_text": VERSION, "links": []}, l3dom="wan")
    rm_uid = "rtpol:dev:gw:route-map:CUSTOMER-OUT"
    entry = next(n for n in batch.nodes if n.uid == uid.route_policy_entry(rm_uid, 30))
    assert entry.props["set_unsupported"] == ["set ip-next-hop 192.0.2.1", "set metric +10"]
    assert entry.props["set_as_path_prepend"] == ["65000", "65000"]
    assert "set_metric" not in entry.props
    assert entry.props["set_comm_list_delete"] == "CL-DEL"
    assert entry.props["match_tags"] == [7]
    assert entry.props["match_metric"] == 20
    assert "match_unsupported" not in entry.props


def test_community_and_as_path_lists_are_collected_and_referenced():
    config = json.loads(json.dumps(BGP_CONFIG))
    config["policy"]["community-list"] = {
        "CL1": {"rule": {"10": {"action": "permit", "regex": "65000:1"}, "20": {"action": "deny"}}}
    }
    config["policy"]["as-path-list"] = {"AP1": {"rule": {"5": {"action": "permit", "regex": "_64512_"}}}}
    config["policy"]["route-map"]["CUSTOMER-OUT"]["rule"]["30"] = {
        "action": "deny",
        "match": {"community": {"community-list": "CL1"}, "as-path": "AP1"},
    }
    batch = normalize_vyos({"config": config, "version_text": VERSION, "links": []}, l3dom="wan")
    cl = "rtpol:dev:gw:community-list:CL1"
    ap = "rtpol:dev:gw:as-path-list:AP1"
    lines = {n.uid: n for n in batch.nodes if n.label == "MatchListEntry"}
    assert (
        lines[uid.match_list_entry(cl, 10)].props["match_type"],
        lines[uid.match_list_entry(cl, 10)].props["value"],
    ) == (
        "expanded",
        "65000:1",
    )
    assert lines[uid.match_list_entry(cl, 20)].props["match_type"] == "unsupported"
    assert lines[uid.match_list_entry(ap, 5)].props["value"] == "_64512_"
    entry_uid = uid.route_policy_entry("rtpol:dev:gw:route-map:CUSTOMER-OUT", 30)
    refs = {
        (r.end_uid, r.props.get("kind"))
        for r in batch.rels
        if r.rel_type == "REFERENCES" and r.start_uid == entry_uid
    }
    assert refs == {(cl, "community-list"), (ap, "as-path-list")}


# --- FRR's own shapes for the per-neighbor path commands (family clause) ------------------
#
# The three answers below copy the shape and the whitespace of a capture from a
# VyOS rolling 2026.10 router (the capture itself stays outside the
# repository): a newline before the first key, " } , " before
# the counters of `routes`, a path array per prefix for `routes`, one object
# per prefix for the adj forms, and the warning for a received table with no
# soft reconfiguration inbound. The addresses, the prefix and the hostname are
# documentation values, not the router's.

FRR_PEER = "192.0.2.36"
FRR_PREFIX = "198.51.100.1/32"
FRR_ROUTES_TEXT = (
    '{\n "vrfId": 0,\n "vrfName": "default",\n "tableVersion": 11,\n "routerId": "192.0.2.1",\n'
    ' "defaultLocPrf": 100,\n "localAS": 64512,\n "routes": { "198.51.100.1/32": [{"valid":true,'
    '"multipath":true,"pathFrom":"external","prefix":"198.51.100.1","prefixLen":32,'
    '"network":"198.51.100.1/32","version":11,"metric":0,"weight":0,"peerId":"192.0.2.36",'
    '"path":"64513","origin":"IGP","nexthops":[{"ip":"192.0.2.36","hostname":"node-a",'
    '"afi":"ipv4","used":true}]}]\n } , "totalRoutes": 1, "totalPaths": 2,"numRoutes":1\n }\n'
)
FRR_ADVERTISED_TEXT = (
    '{\n"bgpTableVersion":11,"bgpLocalRouterId":"192.0.2.1","defaultLocPrf":100,"localAS":64512,'
    '"advertisedRoutes": {"198.51.100.1/32":{"addrPrefix":"198.51.100.1","prefixLen":32,'
    '"network":"198.51.100.1/32","nextHop":"192.0.2.35","weight":0,"path":"64513","origin":"IGP",'
    '"valid":true,"best":true,"multipath":true}}\n,"totalPrefixCounter":1,"filteredPrefixCounter":0,'
    '"totalPathsCount":1}\n'
)
FRR_RECEIVED_TEXT = '{\n"warning": "Inbound soft reconfiguration not enabled"\n}\n'
FRR_CONFIG = {
    "system": {"host-name": "gw"},
    "protocols": {"bgp": {"system-as": "64512", "neighbor": {FRR_PEER: {"remote-as": "64513"}}}},
}


def _frr_raw(answers, *, config=None, command=vyos_mod.bgp_route_command):
    """A payload a `capture_bgp="all"` fetch seals: the summary, then
    `answers` ((vrf, peer, direction) -> text) under `command`'s spelling,
    every outcome `ok`."""
    cfg = config or FRR_CONFIG
    raw = {"config": cfg, "version_text": VERSION, vyos_mod.BGP_SUMMARY_COMMAND: "{}"}
    for (vrf, peer, direction), text in answers.items():
        raw[command(vrf, peer, direction)] = text
    raw[vyos_mod.RAW_OUTCOMES_KEY] = {k: {"status": "ok"} for k in raw if k not in ("config", "version_text")}
    return raw


def _frr_directions(raw, vrf=DEFAULT_VRF):
    outcomes = vyos_mod.bgp_table_outcomes(raw, DEV, capture="all")
    by_key = manifest.bgp_direction_outcomes(outcomes)
    return {
        (peer, d): by_key[(_session_uid(peer, vrf), d)]
        for peer in _frr_peers(raw)
        for d in ("received", "accepted", "advertised")
    }


def _frr_peers(raw):
    return [peer for _vrf, peer in vyos_mod.bgp_capture_targets(raw["config"])]


def test_frr_answers_in_the_captured_shapes_read_through_the_observation_path():
    raw = _frr_raw(
        {
            (DEFAULT_VRF, FRR_PEER, "received"): FRR_RECEIVED_TEXT,
            (DEFAULT_VRF, FRR_PEER, "accepted"): FRR_ROUTES_TEXT,
            (DEFAULT_VRF, FRR_PEER, "advertised"): FRR_ADVERTISED_TEXT,
        }
    )
    directions = _frr_directions(raw)
    assert directions[(FRR_PEER, "accepted")] == TableOutcome(status="complete", row_count=1)
    assert directions[(FRR_PEER, "advertised")] == TableOutcome(status="complete", row_count=1)
    received = directions[(FRR_PEER, "received")]
    assert (received.status, received.detail) == ("not-captured", "Inbound soft reconfiguration not enabled")

    rows = {r["direction"]: r for r in vyos_mod.bgp_side_rows(raw, DEV)["bgp_session_routes"]}
    assert set(rows) == {"accepted", "advertised"}
    accepted = rows["accepted"]
    assert accepted["session_uid"] == _session_uid(FRR_PEER)
    assert (accepted["prefix"], accepted["next_hop"], accepted["as_path"]) == (FRR_PREFIX, FRR_PEER, "64513")
    assert (accepted["origin"], accepted["med"], accepted["local_pref"]) == ("IGP", 0, None)
    # a multipath member with no `bestpath` key: not the best path
    assert accepted["best"] is False
    assert (accepted["rib_type"], accepted["path_id"], accepted["af"]) == ("loc-rib", "0", 4)
    advertised = rows["advertised"]
    assert (advertised["prefix"], advertised["next_hop"], advertised["as_path"]) == (
        FRR_PREFIX,
        "192.0.2.35",
        "64513",
    )
    assert (advertised["origin"], advertised["med"], advertised["local_pref"]) == ("IGP", None, None)
    assert advertised["best"] is True
    assert advertised["rib_type"] == "adj-rib-out"


def test_a_received_table_in_the_adj_shape_reads_one_row_per_prefix_and_no_best_marking():
    received = FRR_ADVERTISED_TEXT.replace("advertisedRoutes", "receivedRoutes").replace(
        "192.0.2.35", FRR_PEER
    )
    raw = _frr_raw({(DEFAULT_VRF, FRR_PEER, "received"): received})
    assert _frr_directions(raw)[(FRR_PEER, "received")] == TableOutcome(status="complete", row_count=1)
    (row,) = vyos_mod.bgp_side_rows(raw, DEV)["bgp_session_routes"]
    assert (row["next_hop"], row["as_path"], row["best"]) == (FRR_PEER, "64513", None)


def test_the_best_marking_of_an_accepted_path_reads_both_forms_of_bestpath():
    def best(path):
        text = json.dumps({"routes": {FRR_PREFIX: [path]}, "numRoutes": 1})
        (row,) = vyos_mod.parse_bgp_paths(text, vrf=DEFAULT_VRF, peer_ip=FRR_PEER, direction="accepted")
        return row["best"]

    assert best({"bestpath": True}) is True
    assert best({"bestpath": {"overall": True, "selectionReason": "First path received"}}) is True
    assert best({"bestpath": {"overall": False}}) is False
    assert best({"multipath": True}) is False
    # the adj forms carry `best`; an advertised path with neither key states nothing
    adj = json.dumps({"advertisedRoutes": {FRR_PREFIX: {"nextHop": "192.0.2.35"}}, "totalPrefixCounter": 1})
    (row,) = vyos_mod.parse_bgp_paths(adj, vrf=DEFAULT_VRF, peer_ip=FRR_PEER, direction="advertised")
    assert row["best"] is None


def test_the_as_path_and_next_hop_read_from_either_spelling():
    path = {"aspath": "64513 64600", "nextHop": "192.0.2.35"}
    text = json.dumps({"advertisedRoutes": {FRR_PREFIX: path}, "totalPrefixCounter": 1})
    (row,) = vyos_mod.parse_bgp_paths(text, vrf=DEFAULT_VRF, peer_ip=FRR_PEER, direction="advertised")
    assert (row["as_path"], row["next_hop"]) == ("64513 64600", "192.0.2.35")


@pytest.mark.parametrize(
    ("direction", "text", "words"),
    [
        ("accepted", "{}", "empty JSON object, with no routes table"),
        (
            "accepted",
            '{"vrfId": 0, "vrfName": "default"}',
            "no routes table; its top-level keys are vrfId, vrfName",
        ),
        ("accepted", "", "printed nothing"),
        ("accepted", '{"routes": []}', "routes table of the answer is not a JSON object"),
        ("accepted", '{"routes": {"198.51.100.1/32": ["not a path"]}}', "1 of the 1 prefixes"),
        ("accepted", '{"routes": {"198.51.100.1/32": []}}', "1 of the 1 prefixes"),
        ("accepted", '{"routes": {"not a prefix": [{}]}, "numRoutes": 1}', "1 of the 1 prefixes"),
        ("accepted", '{"routes": {"2001:db8::/32": [{}]}}', "1 of the 1 prefixes"),
        (
            "accepted",
            '{"routes": {"198.51.100.1/32": [{}], "198.51.100.2/32": "x"}, "numRoutes": 2}',
            "1 of the 2 prefixes",
        ),
        (
            "accepted",
            '{"routes": {"198.51.100.1/32": [{}]}, "numRoutes": 3}',
            "numRoutes 3 and its routes table has 1",
        ),
        (
            "advertised",
            '{"advertisedRoutes": {"198.51.100.1/32": "x"}, "totalPrefixCounter": 1}',
            "1 of the 1",
        ),
        (
            "advertised",
            '{"advertisedRoutes": {"198.51.100.1/32": {}}, "totalPrefixCounter": 2}',
            "totalPrefixCounter 2 and its advertisedRoutes table has 1",
        ),
        (
            "advertised",
            '{"advertisedRoutes": {}}',
            "advertisedRoutes table is empty and the answer states no",
        ),
        ("received", '{"totalPrefixCounter": 0, "filteredPrefixCounter": 0}', "no receivedRoutes table"),
    ],
)
def test_an_answer_that_is_no_route_table_fails_with_a_reason(direction, text, words):
    """Never `complete-empty` and never a short table: the direction is
    `failed`, its reason names what was found, and no row of it is kept."""
    raw = _frr_raw({(DEFAULT_VRF, FRR_PEER, direction): text})
    outcome = _frr_directions(raw)[(FRR_PEER, direction)]
    assert outcome.status == "failed", outcome
    assert words in outcome.detail
    assert len(vyos_mod.bgp_side_rows(raw, DEV)["bgp_session_routes"]) == 0
    assert not set(outcome.detail.split()) & {"proven", "possible", "holds", "reached", "mixed"}


def test_a_routes_table_is_judged_by_num_routes_and_not_total_paths():
    """`totalPaths` counts the paths of the printed prefixes across the whole
    table (2 in the capture, 1 printed for this neighbor)."""
    raw = _frr_raw({(DEFAULT_VRF, FRR_PEER, "accepted"): FRR_ROUTES_TEXT})
    assert _frr_directions(raw)[(FRR_PEER, "accepted")].status == "complete"


def test_an_empty_routes_table_is_complete_empty():
    text = '{\n "vrfId": 0,\n "routes": {  } , "totalRoutes": 0, "totalPaths": 0,"numRoutes":0\n }\n'
    raw = _frr_raw({(DEFAULT_VRF, FRR_PEER, "accepted"): text})
    assert _frr_directions(raw)[(FRR_PEER, "accepted")] == TableOutcome(status="complete-empty", row_count=0)


def test_a_warning_under_the_family_spelling_stays_not_captured_with_the_routers_words():
    raw = _frr_raw(
        {
            (DEFAULT_VRF, FRR_PEER, d): '{"warning": "No such neighbor or address family"}'
            for d in ("accepted",)
        }
    )
    outcome = _frr_directions(raw)[(FRR_PEER, "accepted")]
    assert (outcome.status, outcome.detail) == ("not-captured", "No such neighbor or address family")
    banner = _frr_raw({(DEFAULT_VRF, FRR_PEER, "received"): BGP_NO_SOFT_RECONFIG})
    outcome = _frr_directions(banner)[(FRR_PEER, "received")]
    assert (outcome.status, outcome.detail) == ("not-captured", BGP_NO_SOFT_RECONFIG.strip())


OLD_PEERS = ("192.0.2.30", "192.0.2.35", "192.0.2.36")


def test_a_payload_under_the_keys_without_the_family_clause_reads_not_captured():
    config = {
        "system": {"host-name": "gw"},
        "protocols": {
            "bgp": {"system-as": "64512", "neighbor": {peer: {"remote-as": "64513"} for peer in OLD_PEERS}}
        },
    }
    warning = '{"warning": "No such neighbor or address family"}'
    answers = {
        (DEFAULT_VRF, p, d): warning for p in OLD_PEERS for d in ("received", "accepted", "advertised")
    }
    raw = _frr_raw(answers, config=config, command=vyos_mod.legacy_bgp_route_command)
    directions = _frr_directions(raw)
    assert len(directions) == 9
    for outcome in directions.values():
        assert outcome == TableOutcome(status="not-captured", detail="No such neighbor or address family")
    observed = vyos_mod.bgp_observed(raw)
    assert {e["command"] for e in observed["directions"]} == {
        vyos_mod.legacy_bgp_route_command(*key) for key in answers
    }
    assert vyos_mod.bgp_side_rows(raw, DEV, observed=observed)["bgp_session_routes"] == []


def test_an_adj_answer_under_the_key_without_the_family_clause_reads_no_row():
    old = _frr_raw(
        {(DEFAULT_VRF, FRR_PEER, "advertised"): FRR_ADVERTISED_TEXT},
        command=vyos_mod.legacy_bgp_route_command,
    )
    assert _frr_directions(old)[(FRR_PEER, "advertised")] == TableOutcome(
        status="complete-empty", row_count=0
    )
    new = _frr_raw({(DEFAULT_VRF, FRR_PEER, "advertised"): FRR_ADVERTISED_TEXT})
    assert _frr_directions(new)[(FRR_PEER, "advertised")].row_count == 1


def test_a_neighbor_in_a_vrf_is_read_under_the_vrf_and_family_command():
    config = {
        "system": {"host-name": "gw"},
        "vrf": {
            "name": {
                "RED": {
                    "table": "300",
                    "protocols": {
                        "bgp": {"system-as": "64512", "neighbor": {FRR_PEER: {"remote-as": "64513"}}}
                    },
                }
            }
        },
    }
    raw = _frr_raw({("RED", FRR_PEER, "accepted"): FRR_ROUTES_TEXT}, config=config)
    command = f'{vyos_mod._IP_PATH} vtysh -c "show bgp vrf RED ipv4 unicast neighbors {FRR_PEER} routes json"'
    assert command in raw
    observed = vyos_mod.bgp_observed(raw)
    entry = next(e for e in observed["directions"] if e["direction"] == "accepted")
    assert (entry["command"], entry["row_count"]) == (command, 1)
    assert _frr_directions(raw, "RED")[(FRR_PEER, "accepted")].status == "complete"


# A real capture of the three answers of one neighbor, kept outside the
# repository (CONTRIBUTING.md); this test skips
# without one, in CI always. The directory holds `routes.json`,
# `advertised-routes.json` and `received-routes.json` as the router printed them.
FIRST_CONTACT = Path(
    os.environ.get("HST_VYOS_FIRST_CONTACT")
    or Path(__file__).resolve().parent.parent / "data/raw/vyos/first-contact"
)


@pytest.mark.skipif(
    not (FIRST_CONTACT / "routes.json").exists(), reason="no first-contact capture on this machine"
)
def test_first_contact_capture_reads_through_the_observation_path():
    texts = {
        d: (FIRST_CONTACT / f"{d}.json").read_text()
        for d in ("routes", "advertised-routes", "received-routes")
    }
    routes = json.loads(texts["routes"])
    peer = next(path["peerId"] for paths in routes["routes"].values() for path in paths)
    config = {
        "system": {"host-name": "gw"},
        "protocols": {
            "bgp": {"system-as": str(routes["localAS"]), "neighbor": {peer: {"remote-as": "65535"}}}
        },
    }
    raw = _frr_raw(
        {
            (DEFAULT_VRF, peer, "accepted"): texts["routes"],
            (DEFAULT_VRF, peer, "advertised"): texts["advertised-routes"],
            (DEFAULT_VRF, peer, "received"): texts["received-routes"],
        },
        config=config,
    )
    directions = _frr_directions(raw)
    for direction, name in (
        ("accepted", "routes"),
        ("advertised", "advertised-routes"),
        ("received", "received-routes"),
    ):
        payload = json.loads(texts[name])
        outcome = directions[(peer, direction)]
        if "warning" in payload:
            assert (outcome.status, outcome.detail) == ("not-captured", payload["warning"])
        else:
            assert outcome.status in ("complete", "complete-empty"), outcome
            rows = [
                r
                for r in vyos_mod.bgp_side_rows(raw, DEV)["bgp_session_routes"]
                if r["direction"] == direction
            ]
            assert len(rows) == (outcome.row_count or 0)
            assert all(r["prefix"] and r["next_hop"] and r["origin"] for r in rows)
