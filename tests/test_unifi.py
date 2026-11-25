"""UniFi normalizer tests against a recorded-style payload."""

import copy

import httpx
import pytest

from hst.collectors.unifi import normalize_unifi
from hst.core import reasoner, uid

RAW = {
    "devices": [
        {
            "type": "usw",
            "mac": "aa:bb:cc:00:00:01",
            "serial": "SW1234567",
            "name": "Rack-Switch",
            "model": "USW-24-POE",
            "version": "7.1.20",
            "ip": "192.168.1.5",
            "port_table": [
                {
                    "port_idx": 1,
                    "name": "Port 1",
                    "up": True,
                    "speed": 1000,
                    "full_duplex": True,
                    "lldp_table": [{"chassis_id": "aa:bb:cc:99:99:99", "port_id": "eth1"}],
                },
                {"port_idx": 2, "name": "Port 2", "up": True, "speed": 1000, "port_poe": True},
                {
                    "port_idx": 3,
                    "name": "Port 3",
                    "up": True,
                    "speed": 1000,
                    "last_connection": {"mac": "de:ad:be:ef:00:01", "connected": False},
                },
                # non-UniFi infrastructure without LLDP (a router WAN-side port) never
                # appears in the client table; the switch only remembers it here
                {
                    "port_idx": 4,
                    "name": "Port 4",
                    "up": True,
                    "speed": 1000,
                    "last_connection": {"mac": "aa:bb:cc:99:99:98", "connected": True, "ip": "192.168.1.254"},
                },
                # A down port records null speed, null duplex and no speed_source.
                {"port_idx": 5, "name": "Port 5", "up": False, "speed": 0, "full_duplex": False},
                # an up port at half duplex
                {"port_idx": 6, "name": "Port 6", "up": True, "speed": 100, "full_duplex": False},
            ],
        },
        {
            "type": "uap",
            "mac": "aa:bb:cc:00:00:02",
            "serial": "AP7654321",
            "name": "Living-Room-AP",
            "model": "U6-Lite",
            "version": "6.5.28",
            "ip": "192.168.1.6",
            "uplink": {"uplink_mac": "aa:bb:cc:00:00:01", "uplink_remote_port": 2, "port_idx": 0},
        },
    ],
    "networks": [
        {"_id": "n1", "name": "Default", "purpose": "corporate", "vlan": None, "ip_subnet": "192.168.1.1/24"},
        {"_id": "n30", "name": "IoT", "purpose": "corporate", "vlan": 30, "ip_subnet": "192.168.30.1/24"},
        {"_id": "n40", "name": "Guest", "purpose": "guest", "vlan": 40, "ip_subnet": "192.168.40.1/24"},
        {"_id": "nwan", "name": "WAN", "purpose": "wan"},
        # L2-only VLAN: the controller trunks it, the router (elsewhere) owns L3
        {"_id": "n50", "name": "VL_50_CAM", "purpose": "vlan-only", "vlan": 50},
    ],
    "wlans": [
        {"name": "HomeWiFi", "security": "wpapsk", "networkconf_id": "n1", "enabled": True},
        {"name": "IoT-WiFi", "security": "wpapsk", "networkconf_id": "n30", "enabled": True},
    ],
    "clients": [
        # the VyOS router seen as an ordinary wired client on port 1
        {
            "mac": "aa:bb:cc:99:99:99",
            "name": "gw",
            "is_wired": True,
            "ip": "192.168.1.1",
            "network_id": "n1",
            "sw_mac": "aa:bb:cc:00:00:01",
            "sw_port": 1,
        },
        {
            "mac": "11:22:33:44:55:66",
            "name": "nas",
            "is_wired": True,
            "ip": "192.168.1.20",
            "network_id": "n1",
            "sw_mac": "aa:bb:cc:00:00:01",
            "sw_port": 3,
        },
        {
            "mac": "77:88:99:aa:bb:cc",
            "hostname": "cam-door",
            "is_wired": False,
            "ip": "192.168.30.50",
            "network_id": "n30",
            "ap_mac": "aa:bb:cc:00:00:02",
            "essid": "IoT-WiFi",
        },
        # controllers report clients on vlan-only networks with network_id null
        # but the tag itself in `vlan`
        {
            "mac": "de:ad:be:ef:00:01",
            "hostname": "cam-garden",
            "is_wired": False,
            "ip": "192.168.50.9",
            "network_id": None,
            "vlan": 50,
            "ap_mac": "aa:bb:cc:00:00:02",
        },
        # a tag UniFi has no network for at all (router-only VLAN)
        {
            "mac": "de:ad:be:ef:00:02",
            "hostname": "mgmt-probe",
            "is_wired": False,
            "ip": "192.168.7.9",
            "network_id": None,
            "vlan": 7,
            "ap_mac": "aa:bb:cc:00:00:02",
        },
    ],
}


def _batch():
    return normalize_unifi(RAW, site_code="home", l3dom="home", unifi_site="default")


def test_devices_are_serial_keyed():
    batch = _batch()
    uids = {n.uid for n in batch.nodes if n.label == "Device"}
    assert uids == {"dev:rack-switch", "dev:living-room-ap"}


def test_uplink_becomes_one_connected_to_edge():
    batch = _batch()
    cables = [r for r in batch.rels if r.rel_type == "CONNECTED_TO"]
    assert len(cables) == 1
    ends = {cables[0].start_uid, cables[0].end_uid}
    assert ends == {"dev:living-room-ap/port/port0", "dev:rack-switch/port/port2"}


def test_port_carries_speed_mbps_duplex_and_speed_source_from_the_port_table():
    batch = _batch()
    ports = {n.props.get("name"): n.props for n in batch.nodes if n.label == "Port"}
    port1 = ports["Port 1"]
    assert port1["speed_mbps"] == 1000
    assert port1["duplex"] == "full"
    assert port1["speed_source"] == "unifi:port_table.speed"
    assert "speed" not in port1
    # no full_duplex in the raw record: duplex stays unset (null), never guessed
    assert "duplex" not in ports["Port 2"]
    assert ports["Port 2"]["speed_source"] == "unifi:port_table.speed"
    # up with a speed and full_duplex: false is a real half-duplex reading
    port6 = ports["Port 6"]
    assert port6["speed_mbps"] == 100
    assert port6["duplex"] == "half"
    assert port6["speed_source"] == "unifi:port_table.speed"


def test_a_down_port_reporting_speed_zero_carries_null_speed_and_oper_down():
    """A down UniFi port reports `speed: 0`."""
    batch = _batch()
    port5 = next(n.props for n in batch.nodes if n.label == "Port" and n.props.get("name") == "Port 5")
    assert "speed_mbps" not in port5
    assert "duplex" not in port5
    assert "speed_source" not in port5
    assert port5["oper"] == "down"


def _ap_uplink_batch(uplink_extra, *, switch_speed=2500):
    """A standalone switch and AP pair exercising the AP's synthetic uplink port."""
    raw = {
        "devices": [
            {
                "type": "usw",
                "mac": "aa:bb:cc:11:11:01",
                "serial": "SW-UPLINK-1",
                "name": "Uplink-Switch",
                "port_table": [
                    {"port_idx": 2, "name": "Port 2", "up": True, "speed": switch_speed, "full_duplex": True},
                ],
            },
            {
                "type": "uap",
                "mac": "aa:bb:cc:11:11:02",
                "serial": "AP-UPLINK-1",
                "name": "Uplink-AP",
                "adopted": True,
                "state": 1,
                "uplink": {
                    "uplink_mac": "aa:bb:cc:11:11:01",
                    "uplink_remote_port": 2,
                    "port_idx": 0,
                    **uplink_extra,
                },
            },
        ],
    }
    return normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default")


def test_ap_synthetic_port_carries_speed_duplex_and_source_from_uplink_object():
    """The controller's device record for an access point carries its negotiated
    uplink in `uplink`."""
    batch = _ap_uplink_batch({"speed": 2500, "full_duplex": True})
    ap_port = next(n.props for n in batch.nodes if n.label == "Port" and n.uid == "dev:uplink-ap/port/port0")
    assert ap_port["speed_mbps"] == 2500
    assert ap_port["duplex"] == "full"
    assert ap_port["speed_source"] == "unifi:uplink.speed"


def test_ap_synthetic_port_with_no_uplink_speed_carries_null_fields_and_no_source():
    batch = _ap_uplink_batch({})
    ap_port = next(n.props for n in batch.nodes if n.label == "Port" and n.uid == "dev:uplink-ap/port/port0")
    assert "speed_mbps" not in ap_port
    assert "duplex" not in ap_port
    assert "speed_source" not in ap_port


def test_ap_uplink_speed_agrees_with_the_switch_port_it_connects_to():
    batch = _ap_uplink_batch({"speed": 2500, "full_duplex": True}, switch_speed=2500)
    ports = {n.uid: n.props for n in batch.nodes if n.label == "Port"}
    switch_port = ports["dev:uplink-switch/port/port2"]
    ap_port = ports["dev:uplink-ap/port/port0"]
    assert reasoner.link_speed_agreement(switch_port["speed_mbps"], ap_port["speed_mbps"]) == (2500, "agree")


def test_networks_map_to_vlan_segment_prefix():
    batch = _batch()
    segs = {n.uid: n.props for n in batch.nodes if n.label == "BridgeDomain"}
    assert "bd:vlan:fab0:30" in segs
    assert segs["bd:vlan:fab0:40"]["security_class"] == "guest"
    prefixes = {n.props["cidr"] for n in batch.nodes if n.label == "Prefix"}
    assert "192.168.30.0/24" in prefixes
    # WAN-purpose network is skipped
    assert not any(n.props.get("name") == "WAN" for n in batch.nodes if n.label == "BridgeDomain")


def test_wlan_bridges_to_vlan():
    batch = _batch()
    bridged = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "BRIDGED_TO"}
    assert ("ssid:unifi:default:iot-wifi~47e0ddae", "vlan:unifi:default:30") in bridged


def test_clients_attach_and_get_addresses():
    batch = _batch()
    attached = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ATTACHED"}
    assert ("ep:unifi:default:112233445566", "dev:rack-switch/port/port3") in attached
    assert ("ep:unifi:default:778899aabbcc", "dev:living-room-ap") in attached
    in_prefix = {
        (r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "IN" and r.start_uid.startswith("ip:")
    }
    # endpoint addressing: anchored on the client's broadcast-domain uid, not the site l3dom
    assert ("ip:bd-vlan-fab0-30:192.168.30.50", "pfx:home:192.168.30.0/24") in in_prefix


def test_a_client_carries_the_vendor_of_its_mac_and_when_the_controller_last_saw_it():
    """stat/sta reports the OUI vendor name and `last_seen` in epoch seconds; the
    endpoint keeps the vendor as `oui` and the time in epoch milliseconds, the unit
    of every graph time. A row without them, or with a time that is no number,
    carries neither."""
    raw = {
        **RAW,
        "clients": [
            {**RAW["clients"][1], "oui": "Synology", "last_seen": 1_760_000_000},
            {**RAW["clients"][2], "oui": "", "last_seen": "yesterday"},
        ],
    }
    batch = normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default")
    eps = {n.uid: n.props for n in batch.nodes if n.label == "Endpoint"}
    assert eps["ep:unifi:default:112233445566"]["oui"] == "Synology"
    assert eps["ep:unifi:default:112233445566"]["last_seen"] == 1_760_000_000_000
    assert eps["ep:unifi:default:778899aabbcc"].get("oui") is None
    assert eps["ep:unifi:default:778899aabbcc"].get("last_seen") is None


def test_malformed_client_rows_are_skipped_not_fatal(caplog):
    raw = {
        **RAW,
        "clients": [
            *RAW["clients"],
            {
                "_id": "c-bad-ip",
                "mac": "0a:00:00:00:00:01",
                "is_wired": False,
                "ip": "not-an-ip",
                "network_id": "n1",
                "ap_mac": "aa:bb:cc:00:00:02",
            },
            {
                "_id": "c-bad-port",
                "mac": "0a:00:00:00:00:02",
                "is_wired": True,
                "ip": "192.168.1.30",
                "network_id": "n1",
                "sw_mac": "aa:bb:cc:00:00:01",
                "sw_port": "garbage",
            },
        ],
    }
    batch = normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default")
    eps = {n.uid for n in batch.nodes if n.label == "Endpoint"}
    assert {
        "ep:unifi:default:aabbcc999999",
        "ep:unifi:default:112233445566",
        "ep:unifi:default:778899aabbcc",
    } <= eps
    assert "ep:unifi:default:0a0000000001" not in eps and "ep:unifi:default:0a0000000002" not in eps
    assert "ip:home:192.168.1.30" not in {n.uid for n in batch.nodes if n.label == "IpAddress"}
    assert "c-bad-ip" in caplog.text and "'not-an-ip'" in caplog.text
    assert "c-bad-port" in caplog.text and "'garbage'" in caplog.text
    assert "skipped 2 of 7 client rows" in caplog.text


def test_clean_client_rows_report_no_skips(caplog):
    """The skip counter is silent when nothing was skipped."""
    _batch()
    assert "skipped" not in caplog.text


def test_lldp_hints_land_on_the_port():
    batch = _batch()
    port1 = next(n for n in batch.nodes if n.uid == "dev:rack-switch/port/port1")
    assert port1.props["lldp_neighbor_mac"] == "aabbcc999999"
    assert port1.props["lldp_neighbor_port"] == "eth1"


def test_every_device_carries_its_chassis_mac():
    """The chassis MAC is the identity a peer's LLDP table names a UniFi
    device by."""
    batch = _batch()
    switch = next(n for n in batch.nodes if n.uid == "dev:rack-switch")
    ap = next(n for n in batch.nodes if n.uid == "dev:living-room-ap")
    assert switch.props["mac"] == "aabbcc000001"
    assert ap.props["mac"] == "aabbcc000002"


def test_last_connection_mac_lands_on_the_port():
    batch = _batch()
    port4 = next(n for n in batch.nodes if n.uid == "dev:rack-switch/port/port4")
    assert port4.props["last_conn_mac"] == "aabbcc999998"
    port3 = next(n for n in batch.nodes if n.uid == "dev:rack-switch/port/port3")
    assert "last_conn_mac" not in port3.props


def test_uplink_record_lands_on_the_port_even_for_a_foreign_neighbor():
    """`port_by_mac_idx` holds only the ports of devices this collection saw."""
    raw = copy.deepcopy(RAW)
    switch = next(d for d in raw["devices"] if d["type"] == "usw")
    # port 6 carries no other uplink/LLDP/last_connection fact in RAW, so this
    # stays independent of the AP's own uplink onto port 2 (see
    # test_uplink_becomes_one_connected_to_edge)
    switch["uplink"] = {"uplink_mac": "AA:BB:CC:99:99:98", "uplink_remote_port": 0, "port_idx": 6}
    batch = normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default")
    port6 = next(n for n in batch.nodes if n.uid == "dev:rack-switch/port/port6")
    assert port6.props["uplink_mac"] == "aabbcc999998"
    assert port6.props["uplink_remote_port"] == 0
    cables = [r for r in batch.rels if r.rel_type == "CONNECTED_TO"]
    assert not any(c.start_uid == port6.uid or c.end_uid == port6.uid for c in cables)


def test_uplink_record_cables_a_unifi_peer():
    batch = _ap_uplink_batch({"speed": 2500, "full_duplex": True})
    ap_port = next(n for n in batch.nodes if n.uid == "dev:uplink-ap/port/port0")
    assert ap_port.props["uplink_mac"] == "aabbcc111101"
    assert ap_port.props["uplink_remote_port"] == 2
    cables = [r for r in batch.rels if r.rel_type == "CONNECTED_TO"]
    assert len(cables) == 1
    ends = {cables[0].start_uid, cables[0].end_uid}
    assert ends == {"dev:uplink-switch/port/port2", "dev:uplink-ap/port/port0"}


def _core_and_access(core_uplink, access_uplink=None):
    """A core switch with an access switch on port 20 and a non-UniFi gateway
    on port 25 (seen only by last_connection), each switch with its own
    `uplink` record."""
    core = {
        "type": "usw",
        "mac": "02:00:00:00:00:01",
        "name": "core-sw",
        "model": "USPM24P",
        "port_table": [
            {
                "port_idx": 20,
                "name": "Port 20",
                "up": True,
                "speed": 2500,
                "last_connection": {"mac": "02:00:00:00:00:02", "connected": True},
                "lldp_table": [{"chassis_id": "02:00:00:00:00:02", "port_id": "Port 5"}],
            },
            {
                "port_idx": 25,
                "name": "UPPER_LAN",
                "up": True,
                "speed": 10000,
                "last_connection": {"mac": "02:00:00:00:00:03", "connected": True},
            },
        ],
        "uplink": core_uplink,
    }
    access = {
        "type": "usw",
        "mac": "02:00:00:00:00:02",
        "name": "access-sw",
        "model": "USWED35",
        "port_table": [
            {
                "port_idx": 5,
                "name": "Port 5",
                "up": True,
                "speed": 2500,
                "last_connection": {"mac": "02:00:00:00:00:01", "connected": True},
                "lldp_table": [{"chassis_id": "02:00:00:00:00:01", "port_id": "Port 20"}],
            },
        ],
        "uplink": access_uplink or {"type": "wire"},
    }
    raw = {"devices": [core, access], "networks": [], "wlans": [], "clients": []}
    return normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default")


def test_an_uplink_record_the_port_facts_contradict_is_not_used_and_is_logged(caplog):
    """The controller named the core switch's gateway port (25) with the far
    end of the access link (access-sw port 5). Port 25 sees the gateway, and
    access-sw port 5 names port 20 over LLDP: the record writes no uplink
    facts and no cable, and the warning carries its event name."""
    batch = _core_and_access({"port_idx": 25, "uplink_mac": "02:00:00:00:00:02", "uplink_remote_port": 5})
    port25 = next(n for n in batch.nodes if n.uid == "dev:core-sw/port/port25")
    assert "uplink_mac" not in port25.props
    assert port25.props["last_conn_mac"] == "020000000003"
    cables = [r for r in batch.rels if r.rel_type == "CONNECTED_TO"]
    assert not any("dev:core-sw/port/port25" in (c.start_uid, c.end_uid) for c in cables)
    [record] = [r for r in caplog.records if getattr(r, "event", None) == "unifi.uplink_contradicted"]
    assert "core-sw" in record.getMessage() and "020000000003" in record.getMessage()


def test_the_far_ports_lldp_alone_contradicts_an_uplink_record(caplog):
    """A local port with no facts of its own: the far port's LLDP naming
    another port of this device is enough."""
    raw_uplink = {"port_idx": 25, "uplink_mac": "02:00:00:00:00:02", "uplink_remote_port": 5}
    core = {
        "type": "usw",
        "mac": "02:00:00:00:00:01",
        "name": "core-sw",
        "port_table": [{"port_idx": 25, "name": "UPPER_LAN", "up": True}],
        "uplink": raw_uplink,
    }
    access = {
        "type": "usw",
        "mac": "02:00:00:00:00:02",
        "name": "access-sw",
        "port_table": [
            {
                "port_idx": 5,
                "name": "Port 5",
                "up": True,
                "lldp_table": [{"chassis_id": "02:00:00:00:00:01", "port_id": "Port 20"}],
            }
        ],
    }
    batch = normalize_unifi(
        {"devices": [core, access], "networks": [], "wlans": [], "clients": []},
        site_code="home",
        l3dom="home",
        unifi_site="default",
    )
    assert not [r for r in batch.rels if r.rel_type == "CONNECTED_TO"]
    [record] = [r for r in caplog.records if getattr(r, "event", None) == "unifi.uplink_contradicted"]
    assert "Port 20" in record.getMessage()


def test_an_uplink_record_the_port_facts_confirm_cables(caplog):
    """The access switch's own record, port 5 to core-sw port 20, agrees with
    the LLDP and last_connection facts on both ends."""
    batch = _core_and_access(
        {"port_idx": 25, "type": "wire"},
        access_uplink={"port_idx": 5, "uplink_mac": "02:00:00:00:00:01", "uplink_remote_port": 20},
    )
    port5 = next(n for n in batch.nodes if n.uid == "dev:access-sw/port/port5")
    assert port5.props["uplink_mac"] == "020000000001"
    cables = [r for r in batch.rels if r.rel_type == "CONNECTED_TO"]
    assert [{c.start_uid, c.end_uid} for c in cables] == [
        {"dev:core-sw/port/port20", "dev:access-sw/port/port5"}
    ]
    assert not [r for r in caplog.records if getattr(r, "event", None) == "unifi.uplink_contradicted"]


def test_clients_can_be_excluded():
    batch = normalize_unifi(RAW, site_code="home", l3dom="home", unifi_site="default", include_clients=False)
    assert not any(n.label == "Endpoint" for n in batch.nodes)


def test_network_prefix_and_gateway_stamp_the_resolved_domain():
    """Routed addressing anchors on the gateway's VrfInstance uid when one is in scope."""
    batch = _batch()
    addressed = [n for n in batch.nodes if n.label in ("Prefix", "IpAddress")]
    assert addressed
    for n in addressed:
        assert n.props["l3dom"] == "home", n.uid
        assert "anchor" in n.props, n.uid
        assert n.uid.split(":", 2)[1] == uid.slug(n.props["anchor"]), n.uid


def test_vlan_only_network_becomes_named_segment():
    batch = _batch()
    segs = {n.uid: n.props for n in batch.nodes if n.label == "BridgeDomain"}
    assert segs["bd:vlan:fab0:50"]["name"] == "VL_50_CAM"


def test_client_vlan_tag_is_the_segment_fallback():
    batch = _batch()
    in_seg = {
        (r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "IN" and r.start_uid.startswith("ep:")
    }
    # network_id is null but the vlan tag names the shared segment
    assert ("ep:unifi:default:deadbeef0001", "bd:vlan:fab0:50") in in_seg
    # even a tag UniFi has no network object for gets the shared uid,
    # and the segment node rides along so the loader can anchor the edge
    assert ("ep:unifi:default:deadbeef0002", "bd:vlan:fab0:7") in in_seg
    assert any(n.uid == "bd:vlan:fab0:7" for n in batch.nodes if n.label == "BridgeDomain")


def test_client_address_family_follows_the_address():
    raw = {
        "devices": [
            {"type": "uap", "mac": "aa:bb:cc:00:00:02", "serial": "AP7654321", "name": "ap"},
        ],
        "networks": [],
        "wlans": [],
        "clients": [
            {
                "mac": "77:88:99:aa:bb:cc",
                "hostname": "cam-door",
                "is_wired": False,
                "ip": "fd00:30::50",
                "network_id": None,
                "ap_mac": "aa:bb:cc:00:00:02",
            },
            {
                "mac": "11:22:33:44:55:66",
                "hostname": "nas",
                "is_wired": False,
                "ip": "192.168.30.50",
                "network_id": None,
                "ap_mac": "aa:bb:cc:00:00:02",
            },
        ],
    }
    batch = normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default")
    ips = {n.props["ip"]: n for n in batch.nodes if n.label == "IpAddress"}
    assert ips["fd00:30::50"].props["af"] == 6
    assert ips["fd00:30::50"].uid == "ip:home:fd00:30::50"
    assert ips["192.168.30.50"].props["af"] == 4
    has_ip = {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "HAS_IP"}
    assert ("ep:unifi:default:778899aabbcc", "ip:home:fd00:30::50") in has_ip


# --- gateway visibility and firewall models ------------------------------------------
#
# The base RAW has no gateway-role device on purpose: it pins the no-gateway
# path (no Interface/VrfInstance emission). These fixtures add a UDM and the
# two firewall families a controller can carry.

UDM = {
    "type": "udm",
    "mac": "aa:bb:cc:00:00:03",
    "serial": "UDM0001",
    "name": "Gateway",
    "model": "UDM-SE",
    "version": "4.0.0",
    "ip": "192.168.1.1",
}

ZONES = [
    {"_id": "z1", "name": "Internal", "network_ids": ["n1", "n30"]},
    {"_id": "z2", "name": "Hotspot", "network_ids": ["n40"]},
]

POLICIES = [
    {
        "_id": "p1",
        "name": "guest-to-lan-block",
        "index": 10,
        "action": "BLOCK",
        "enabled": True,
        "protocol": "all",
        "source": {"zone_id": "z2", "matching_target": "ANY"},
        "destination": {"zone_id": "z1", "matching_target": "ANY"},
    },
    {
        "_id": "p2",
        "name": "lan-to-guest-web",
        "index": 11,
        "action": "ALLOW",
        "enabled": True,
        "protocol": "tcp",
        "source": {"zone_id": "z1", "matching_target": "ANY"},
        "destination": {"zone_id": "z2", "matching_target": "ANY", "port": 443},
    },
    # disabled: must not become a rule
    {
        "_id": "p3",
        "name": "off",
        "index": 12,
        "action": "ALLOW",
        "enabled": False,
        "source": {"zone_id": "z2"},
        "destination": {"zone_id": "z1"},
    },
    # NETWORK target, known network (n30 = 192.168.30.1/24): resolves to that
    # network's Prefix, dst_any stays False.
    {
        "_id": "p5",
        "name": "hotspot-to-iot",
        "index": 14,
        "action": "ALLOW",
        "enabled": True,
        "protocol": "all",
        "source": {"zone_id": "z2", "matching_target": "ANY"},
        "destination": {"zone_id": "z1", "matching_target": "NETWORK", "network_id": "n30"},
    },
    # NETWORK target, network id not among the collected networks: opaque,
    # never a confident drop.
    {
        "_id": "p6",
        "name": "hotspot-to-unknown-network",
        "index": 15,
        "action": "ALLOW",
        "enabled": True,
        "protocol": "all",
        "source": {"zone_id": "z2", "matching_target": "ANY"},
        "destination": {"zone_id": "z1", "matching_target": "NETWORK", "network_id": "n-unknown"},
    },
    # NETWORK target with neither network_id nor network_ids present: opaque.
    {
        "_id": "p7",
        "name": "hotspot-to-no-network-field",
        "index": 16,
        "action": "ALLOW",
        "enabled": True,
        "protocol": "all",
        "source": {"zone_id": "z2", "matching_target": "ANY"},
        "destination": {"zone_id": "z1", "matching_target": "NETWORK"},
    },
    # A target this normalizer cannot express as an address set at all: opaque.
    {
        "_id": "p8",
        "name": "hotspot-to-object",
        "index": 17,
        "action": "ALLOW",
        "enabled": True,
        "protocol": "all",
        "source": {"zone_id": "z2", "matching_target": "ANY"},
        "destination": {"zone_id": "z1", "matching_target": "OBJECT"},
    },
]

GROUPS = [
    {
        "_id": "g1",
        "name": "cameras",
        "group_type": "address-group",
        "group_members": ["192.168.30.50", "192.168.50.0/24"],
    },
    {"_id": "g2", "name": "web-ports", "group_type": "port-group", "group_members": [80, 443]},
]

CLASSIC_RULES = [
    {
        "_id": "fr2",
        "ruleset": "LAN_IN",
        "rule_index": 2001,
        "name": "allow-web",
        "action": "accept",
        "enabled": True,
        "protocol": "tcp",
        "src_firewallgroup_ids": [],
        "dst_firewallgroup_ids": ["g2"],
    },
    {
        "_id": "fr1",
        "ruleset": "LAN_IN",
        "rule_index": 2000,
        "name": "block-cameras-to-lan",
        "action": "drop",
        "enabled": True,
        "protocol": "all",
        "src_firewallgroup_ids": ["g1"],
        "dst_firewallgroup_ids": [],
        "dst_address": "192.168.1.0/24",
    },
    {
        "_id": "fr3",
        "ruleset": "LAN_IN",
        "rule_index": 2002,
        "name": "block-lan-to-iot",
        "action": "drop",
        "enabled": True,
        "protocol": "all",
        "src_firewallgroup_ids": [],
        "dst_firewallgroup_ids": [],
        "dst_networkconf_id": "n30",
        "dst_networkconf_type": "NETv4",
    },
    {
        "_id": "fr4",
        "ruleset": "LAN_IN",
        "rule_index": 2003,
        "name": "block-lan-to-decommissioned-network",
        "action": "drop",
        "enabled": True,
        "protocol": "all",
        "src_firewallgroup_ids": [],
        "dst_firewallgroup_ids": [],
        "dst_networkconf_id": "n-gone",
        "dst_networkconf_type": "NETv4",
    },
    {
        "_id": "fr5",
        "ruleset": "LAN_IN",
        "rule_index": 2004,
        "name": "block-lan-to-iot-and-extra-range",
        "action": "drop",
        "enabled": True,
        "protocol": "all",
        "src_firewallgroup_ids": [],
        "dst_firewallgroup_ids": [],
        # same network (n30) as fr3, but combined on this side with a literal
        # address scope: opaque for a reason specific to this rule's side,
        # not to n30 itself
        "dst_address": "10.0.0.0/8",
        "dst_networkconf_id": "n30",
        "dst_networkconf_type": "NETv4",
    },
    {
        "_id": "fr6",
        "ruleset": "LAN_IN",
        "rule_index": 2005,
        "name": "block-lan-to-unrouted-vlan",
        "action": "drop",
        "enabled": True,
        "protocol": "all",
        "src_firewallgroup_ids": [],
        "dst_firewallgroup_ids": [],
        # n50 is collected (vlan-only, trunked with no ip_subnet) but never
        # gets a Prefix: distinct from n-gone, which is not collected at all
        "dst_networkconf_id": "n50",
        "dst_networkconf_type": "NETv4",
    },
]


def _gw_batch(**extra):
    raw = {**RAW, "devices": RAW["devices"] + [UDM], **extra}
    return normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default")


def test_a_single_gateway_gets_engine_visible_interfaces():
    batch = _gw_batch()
    ifaces = {n.uid: n.props for n in batch.nodes if n.label == "Interface"}
    assert set(ifaces) == {
        "dev:gateway/if/br1",
        "dev:gateway/if/br30",
        "dev:gateway/if/br40",
    }
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    assert ("ON", "dev:gateway/if/br30", "dev:gateway") in rels
    assert ("IN_VRF", "dev:gateway/if/br30", "vrf:dev:gateway:default") in rels
    # routed addressing: anchored on the gateway's VrfInstance uid, not the site l3dom
    assert ("HAS_IP", "dev:gateway/if/br30", "ip:vrf-dev-gateway-default:192.168.30.1") in rels
    assert ("ORIGINATES", "vrf:dev:gateway:default", "pfx:vrf-dev-gateway-default:192.168.30.0/24") in rels
    # GATEWAY_FOR stays reasoner-owned
    assert not any(r.rel_type == "GATEWAY_FOR" for r in batch.rels)


def test_gateway_default_vrf_instance_is_marked_is_global():
    batch = _gw_batch()
    default = next(n for n in batch.nodes if n.label == "VrfInstance" and n.uid == "vrf:dev:gateway:default")
    assert default.props["is_global"] is True


def test_without_a_gateway_no_interfaces_are_invented():
    batch = _batch()
    assert not any(n.label in ("Interface", "VrfInstance") for n in batch.nodes)
    assert not any(r.rel_type in ("IN_VRF", "ORIGINATES") for r in batch.rels)


def test_two_gateways_emit_no_interfaces():
    second = {**UDM, "mac": "aa:bb:cc:00:00:04", "serial": "UDM0002", "name": "Gateway-2"}
    raw = {**RAW, "devices": RAW["devices"] + [UDM, second]}
    batch = normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default")
    assert not any(n.label == "Interface" for n in batch.nodes)


def test_zone_policies_land_in_the_vyos_shape():
    batch = _gw_batch(firewall_zones=ZONES, firewall_policies=POLICIES)
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}

    # zones contain the per-network gateway interfaces
    assert ("CONTAINS", "unifi:default:zone:z1", "dev:gateway/if/br1") in rels
    assert ("CONTAINS", "unifi:default:zone:z1", "dev:gateway/if/br30") in rels
    assert ("CONTAINS", "unifi:default:zone:z2", "dev:gateway/if/br40") in rels

    # one rulebase per (from, to) pair, joined the way _zone_pair_verdict matches
    assert ("FROM_ZONE", "unifi:default:fw:zone:z2:z1", "unifi:default:zone:z2") in rels
    assert ("TO_ZONE", "unifi:default:fw:zone:z2:z1", "unifi:default:zone:z1") in rels
    assert ("FROM_ZONE", "unifi:default:fw:zone:z1:z2", "unifi:default:zone:z1") in rels
    assert ("TO_ZONE", "unifi:default:fw:zone:z1:z2", "unifi:default:zone:z2") in rels

    rules = {n.props["rule_uid"]: n.props for n in batch.nodes if n.label == "FwRule"}
    assert rules["p1"]["action"] == "drop"
    assert rules["p1"]["src_any"] is True and rules["p1"]["dst_any"] is True
    assert rules["p1"]["svc_any"] is True
    assert rules["p2"]["action"] == "accept"
    assert rules["p2"]["svc_any"] is False  # tcp/443
    assert "p3" not in rules  # disabled

    svcs = {n.props.get("name") for n in batch.nodes if n.label == "SvcObject"}
    assert "tcp/443" in svcs


def _dst_objects(batch, rule_uid):
    """(uid, props) of every NetObject wired to `rule_uid` via a DST edge."""
    by_uid = {n.uid: n.props for n in batch.nodes if n.label == "NetObject"}
    dst_rels = (r for r in batch.rels if r.rel_type == "DST" and r.start_uid == rule_uid)
    return [(r.end_uid, by_uid[r.end_uid]) for r in dst_rels]


def test_a_network_target_resolves_to_its_networks_prefix():
    batch = _gw_batch(firewall_zones=ZONES, firewall_policies=POLICIES)
    rules = {n.props["rule_uid"]: n.props for n in batch.nodes if n.label == "FwRule"}
    assert rules["p5"]["dst_any"] is False

    objs = _dst_objects(batch, "unifi:default:fw:zone:z2:z1:p5")
    assert len(objs) == 1
    obj_uid, props = objs[0]
    assert not props.get("opaque")

    prefixes = {n.uid: n.props for n in batch.nodes if n.label == "Prefix"}
    resolves_to = (r for r in batch.rels if r.rel_type == "RESOLVES_TO" and r.start_uid == obj_uid)
    targets = [prefixes[r.end_uid] for r in resolves_to]
    assert any(p["cidr"] == "192.168.30.0/24" for p in targets)


def test_a_network_target_with_an_unknown_id_is_opaque_not_a_drop():
    batch = _gw_batch(firewall_zones=ZONES, firewall_policies=POLICIES)
    rules = {n.props["rule_uid"]: n.props for n in batch.nodes if n.label == "FwRule"}
    assert rules["p6"]["dst_any"] is False

    objs = _dst_objects(batch, "unifi:default:fw:zone:z2:z1:p6")
    assert len(objs) == 1
    assert objs[0][1]["opaque"] is True
    assert objs[0][1]["opaque_reason"]


def test_a_network_target_with_no_network_field_is_opaque():
    batch = _gw_batch(firewall_zones=ZONES, firewall_policies=POLICIES)
    rules = {n.props["rule_uid"]: n.props for n in batch.nodes if n.label == "FwRule"}
    assert rules["p7"]["dst_any"] is False

    objs = _dst_objects(batch, "unifi:default:fw:zone:z2:z1:p7")
    assert len(objs) == 1
    assert objs[0][1]["opaque"] is True
    assert objs[0][1]["opaque_reason"]


def test_an_unmodeled_matching_target_is_opaque_not_dropped_or_any():
    """OBJECT (and, by the same branch, CLIENT_MACS/REGION/APP/anything
    unrecognized) is not expressible as an address set."""
    batch = _gw_batch(firewall_zones=ZONES, firewall_policies=POLICIES)
    rules = {n.props["rule_uid"]: n.props for n in batch.nodes if n.label == "FwRule"}
    assert rules["p8"]["dst_any"] is False

    objs = _dst_objects(batch, "unifi:default:fw:zone:z2:z1:p8")
    assert len(objs) == 1
    assert objs[0][1]["opaque"] is True
    assert "OBJECT" in objs[0][1]["opaque_reason"]


def test_tcp_udp_policy_keeps_its_compound_proto():
    """The matcher splits compound specs on "_"."""
    policies = [
        {
            "_id": "p4",
            "name": "lan-to-guest-dns",
            "index": 13,
            "action": "ALLOW",
            "enabled": True,
            "protocol": "tcp_udp",
            "source": {"zone_id": "z1", "matching_target": "ANY"},
            "destination": {"zone_id": "z2", "matching_target": "ANY", "port": 53},
        },
    ]
    batch = _gw_batch(firewall_zones=ZONES, firewall_policies=policies)
    svcs = {n.props.get("name"): n.props for n in batch.nodes if n.label == "SvcObject"}
    assert svcs["tcp_udp/53"]["proto"] == "tcp_udp"


def test_classic_rulesets_land_in_the_checkpoint_shape():
    batch = _gw_batch(firewall_rules=CLASSIC_RULES, firewall_groups=GROUPS)
    rbs = {n.uid: n.props for n in batch.nodes if n.label == "FwRulebase"}
    assert rbs["unifi:default:fw:lan_in"]["kind"] == "access"

    enforces = [r for r in batch.rels if r.rel_type == "ENFORCES"]
    assert [(r.start_uid, r.end_uid) for r in enforces] == [("dev:gateway", "unifi:default:fw:lan_in")]
    # the controller programs the gateway: the binding is read, not inferred
    assert enforces[0].props["approximate"] is False

    rules = {n.props["rule_uid"]: n.props for n in batch.nodes if n.label == "FwRule"}
    assert rules["fr1"]["action"] == "drop" and rules["fr1"]["position"] == 2000
    assert rules["fr1"]["src_any"] is False and rules["fr1"]["dst_any"] is False
    assert rules["fr2"]["src_any"] is True and rules["fr2"]["svc_any"] is False
    # network-scoped side (dst_networkconf_id resolved through net_by_id): never any
    assert rules["fr3"]["src_any"] is True and rules["fr3"]["dst_any"] is False
    # network id absent from the collected networks: still not any, but opaque
    assert rules["fr4"]["src_any"] is True and rules["fr4"]["dst_any"] is False
    # combined scope (n30 plus a literal address on the same side): still not any
    assert rules["fr5"]["src_any"] is True and rules["fr5"]["dst_any"] is False

    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    assert ("RESOLVES_TO", "unifi:default:grp:g1", "ip:home:192.168.30.50") in rels
    assert ("RESOLVES_TO", "unifi:default:grp:g1", "pfx:home:192.168.50.0/24") in rels
    assert ("RESOLVES_TO", "unifi:default:addr:192.168.1.0-24", "pfx:home:192.168.1.0/24") in rels
    # The shared group object holds no protocol.
    assert ("SVC", "unifi:default:fw:lan_in:fr2", "unifi:default:svc:tcp-80,443") in rels
    assert ("SVC", "unifi:default:fw:lan_in:fr2", "unifi:default:svc:grp:g2") not in rels

    # network-scoped rule resolves to the network's own collected Prefix, the
    # same node _network_stage anchored on the gateway's VrfInstance
    assert (
        "RESOLVES_TO",
        "unifi:default:net:n30",
        "pfx:vrf-dev-gateway-default:192.168.30.0/24",
    ) in rels

    netobjs = {n.uid: n.props for n in batch.nodes if n.label == "NetObject"}
    assert netobjs["unifi:default:net:n-gone"]["opaque"] is True
    assert netobjs["unifi:default:net:n-gone"]["opaque_reason"]
    assert not any(
        r.start_uid == "unifi:default:net:n-gone" and r.rel_type == "RESOLVES_TO" for r in batch.rels
    )
    assert "opaque" not in netobjs["unifi:default:net:n30"]

    # fr5 combines n30 with a literal address on the same side: that rule's
    # side is opaque, but the opacity lands on a NetObject scoped to fr5's
    # dst side, not on the shared unifi:default:net:n30 object fr3 resolved
    assert "unifi:default:net:n30:rule:fr5:dst" in netobjs
    assert netobjs["unifi:default:net:n30:rule:fr5:dst"]["opaque"] is True
    assert netobjs["unifi:default:net:n30:rule:fr5:dst"]["opaque_reason"]

    # fr6's network (n50) is collected but has no prefix (vlan-only, no
    # ip_subnet): opaque for a different reason than the unresolvable n-gone,
    # and on the same shared per-network NetObject, not a per-rule one
    assert netobjs["unifi:default:net:n50"]["opaque"] is True
    assert "not among the collected networks" not in netobjs["unifi:default:net:n50"]["opaque_reason"]
    assert netobjs["unifi:default:net:n50"]["opaque_reason"]
    assert not any(r.start_uid == "unifi:default:net:n50" and r.rel_type == "RESOLVES_TO" for r in batch.rels)


def test_absent_firewall_keys_normalize_to_nothing():
    batch = _gw_batch()
    assert not any(n.label in ("Zone", "FwRulebase", "FwRule") for n in batch.nodes)


def test_collector_uses_typed_config():
    from hst.collectors.unifi import UnifiCollector, UnifiConfig
    from hst.core import Settings

    cfg = UnifiConfig(
        url="https://c",
        auth={"method": "user_password", "username": "ro", "password": "pw"},
        site="s1",
        site_code="dc1",
        l3dom="dc1",
    )
    c = UnifiCollector(cfg, Settings(_env_file=None))
    assert c.scope == "unifi:s1"
    assert c.config.auth.password.get_secret_value() == "pw"


def test_site_is_constrained_to_what_a_site_id_can_be():
    """`site` is interpolated into every request path."""
    from pydantic import ValidationError

    from hst.collectors.unifi import UnifiConfig

    auth = {"method": "user_password", "username": "ro", "password": "pw"}
    assert UnifiConfig(url="https://c", auth=auth).site == "default"
    assert UnifiConfig(url="https://c", auth=auth, site="a_b-1").site == "a_b-1"
    for bad in ("../../proxy", "s1/stat", "s 1", "", "x" * 33, "s1?fields=all", "s1#f"):
        with pytest.raises(ValidationError):
            UnifiConfig(url="https://c", auth=auth, site=bad)


def test_probe_closes_client_on_failed_login(monkeypatch):
    from hst.collectors.unifi import UnifiCollector, UnifiConfig
    from hst.core import Settings

    request = httpx.Request("POST", "https://c/api/auth/login")
    response = httpx.Response(401, request=request)

    def fake_post(self, *args, **kwargs):
        raise httpx.HTTPStatusError("unauthorized", request=request, response=response)

    close_calls = []
    original_close = httpx.Client.close

    def fake_close(self):
        close_calls.append(self)
        return original_close(self)

    monkeypatch.setattr(httpx.Client, "post", fake_post)
    monkeypatch.setattr(httpx.Client, "close", fake_close)

    cfg = UnifiConfig(
        url="https://c",
        auth={"method": "user_password", "username": "ro", "password": "pw"},
        site="s1",
        site_code="dc1",
        l3dom="dc1",
    )
    c = UnifiCollector(cfg, Settings(_env_file=None))

    with pytest.raises(httpx.HTTPStatusError):
        c.probe()

    assert len(close_calls) == 1


def test_probe_and_fetch_succeed_through_a_real_client(monkeypatch):
    from hst.collectors import unifi as unifi_mod

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, json={})
        # any /proxy/network/api/s/<site>/<path> GET
        return httpx.Response(200, json={"data": []})

    monkeypatch.setattr(unifi_mod, "_transport", lambda config: httpx.MockTransport(handler))
    from hst.collectors.unifi import UnifiCollector, UnifiConfig
    from hst.core import Settings

    c = UnifiCollector(
        UnifiConfig(url="https://c", auth={"method": "user_password", "username": "ro", "password": "pw"}),
        Settings(_env_file=None),
    )
    assert "login ok" in c.probe()
    raw = c.fetch()
    assert set(raw) == {
        "devices",
        "networks",
        "port_profiles",
        "wlans",
        "clients",
        "firewall_rules",
        "firewall_groups",
        "firewall_zones",
        "firewall_policies",
        "refused_reads",
    }


def test_fetch_tolerates_a_missing_firewall_family(monkeypatch):
    """A controller has classic firewallrule or the 9.x zone endpoints, never both."""
    from hst.collectors import unifi as unifi_mod

    seen_paths = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_paths.append(request.url.path)
        if request.url.path == "/api/auth/login":
            return httpx.Response(200, json={})
        if "/v2/api/site/" in request.url.path:
            return httpx.Response(404, json={"error": "no zone firewall here"})
        if request.url.path.endswith("rest/firewallrule"):
            return httpx.Response(200, json={"data": [{"_id": "r1", "ruleset": "LAN_IN"}]})
        return httpx.Response(200, json={"data": []})

    monkeypatch.setattr(unifi_mod, "_transport", lambda config: httpx.MockTransport(handler))
    from hst.collectors.unifi import UnifiCollector, UnifiConfig
    from hst.core import Settings

    c = UnifiCollector(
        UnifiConfig(url="https://c", auth={"method": "user_password", "username": "ro", "password": "pw"}),
        Settings(_env_file=None),
    )
    raw = c.fetch()
    assert raw["firewall_rules"] == [{"_id": "r1", "ruleset": "LAN_IN"}]
    assert raw["firewall_zones"] == [] and raw["firewall_policies"] == []
    assert "/proxy/network/v2/api/site/default/firewall/zones" in seen_paths
    assert "/proxy/network/v2/api/site/default/firewall-policies" in seen_paths


def test_port_carriage_comes_from_the_port_profile_or_the_ports_own_fields():
    """Wired-port VLAN carriage: per-port effective fields outrank the assigned
    profile, forward=all carries every known network, the native network is
    flagged, and a port without any carriage data emits nothing."""
    import json

    raw = json.loads(json.dumps(RAW))
    raw["port_profiles"] = [
        {
            "_id": "prof-trunk",
            "forward": "customize",
            "native_networkconf_id": "n1",
            "tagged_networkconf_ids": ["n30"],
        }
    ]
    raw["devices"][0]["port_table"][0]["portconf_id"] = "prof-trunk"
    raw["devices"][0]["port_table"][1]["forward"] = "all"
    raw["devices"][0]["port_table"][1]["native_networkconf_id"] = "n1"
    batch = normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default")
    ports = {n.props.get("name"): n.uid for n in batch.nodes if n.label == "Port"}
    vlans = {n.props.get("vid"): n.uid for n in batch.nodes if n.label == "VlanInstance"}
    carries = {(r.start_uid, r.end_uid): r.props for r in batch.rels if r.rel_type == "CARRIES"}
    # profile-resolved trunk: native vlan 1, tagged vlan 30, nothing else
    assert carries[(ports["Port 1"], vlans[1])]["native"] is True
    assert carries[(ports["Port 1"], vlans[30])]["native"] is False
    assert (ports["Port 1"], vlans[40]) not in carries
    # the port's own effective fields outrank any profile: all networks ride
    assert carries[(ports["Port 2"], vlans[1])]["native"] is True
    for vid in (30, 40, 50):
        assert carries[(ports["Port 2"], vlans[vid])]["native"] is False
    assert not [pair for pair in carries if pair[0] == ports["Port 3"]]


def _carriage(port_table_extra: dict[int, dict], overrides=None, profiles=None):
    """{(port name, vid): native} for the switch of RAW with the given port
    fields, port_overrides and port profiles."""
    raw = copy.deepcopy(RAW)
    for p in raw["devices"][0]["port_table"]:
        p.update(port_table_extra.get(p["port_idx"], {}))
    if overrides is not None:
        raw["devices"][0]["port_overrides"] = overrides
    raw["port_profiles"] = profiles or []
    batch = normalize_unifi(raw, site_code="home", l3dom="home", unifi_site="default")
    names = {n.uid: n.props.get("name") for n in batch.nodes if n.label == "Port"}
    vids = {n.uid: n.props.get("vid") for n in batch.nodes if n.label == "VlanInstance"}
    return {
        (names[r.start_uid], vids[r.end_uid]): r.props["native"]
        for r in batch.rels
        if r.rel_type == "CARRIES"
    }


def _on(carries, port):
    return {vid: native for (name, vid), native in carries.items() if name == port}


def test_a_block_all_port_carries_only_its_native_network():
    carries = _carriage(
        {1: {"forward": "customize", "tagged_vlan_mgmt": "block_all", "native_networkconf_id": "n30"}}
    )
    assert _on(carries, "Port 1") == {30: True}


def test_a_port_reporting_tagged_vlan_mgmt_auto_without_forward_carries_every_network():
    carries = _carriage({1: {"tagged_vlan_mgmt": "auto", "native_networkconf_id": "n1"}})
    assert _on(carries, "Port 1") == {1: True, 30: False, 40: False, 50: False}


def test_a_custom_tagged_vlan_mgmt_port_carries_all_but_the_excluded_networks():
    carries = _carriage(
        {
            1: {
                "tagged_vlan_mgmt": "custom",
                "native_networkconf_id": "n1",
                "excluded_networkconf_ids": ["n40"],
            }
        }
    )
    assert _on(carries, "Port 1") == {1: True, 30: False, 50: False}


def test_a_profile_an_override_assigns_outranks_the_port_table():
    """The dev trunk: port_overrides sets only portconf_id, and port_table
    reports forward all with no native network. The profile decides."""
    profiles = [
        {
            "_id": "isl",
            "forward": "customize",
            "native_networkconf_id": "n1",
            "excluded_networkconf_ids": ["n40", "n50"],
        }
    ]
    overrides = [{"port_idx": 1, "portconf_id": "isl"}]
    carries = _carriage({1: {"forward": "all"}}, overrides, profiles)
    assert _on(carries, "Port 1") == {1: True, 30: False}


def test_an_override_that_states_carriage_outranks_its_profile():
    profiles = [{"_id": "trunk", "forward": "all", "native_networkconf_id": "n1"}]
    overrides = [{"port_idx": 1, "portconf_id": "trunk", "forward": "native", "native_networkconf_id": "n30"}]
    carries = _carriage({1: {"forward": "all", "native_networkconf_id": "n1"}}, overrides, profiles)
    assert _on(carries, "Port 1") == {30: True}


def test_a_disabled_port_carries_no_network_not_even_its_native_one():
    carries = _carriage({1: {"forward": "disabled", "native_networkconf_id": "n1"}})
    assert _on(carries, "Port 1") == {}


def test_a_port_whose_assigned_profile_was_not_collected_carries_nothing():
    carries = _carriage({1: {"portconf_id": "gone", "forward": "all", "native_networkconf_id": "n1"}})
    assert _on(carries, "Port 1") == {}
