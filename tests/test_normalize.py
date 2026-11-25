import pytest

from hst.core.normalize import (
    IfNameResolver,
    canonical_ifname,
    iface_slug,
    normalize_hostname,
    short_ifname,
)


def test_canonical_expansion():
    assert canonical_ifname("Eth1/1") == "ethernet1/1"
    assert canonical_ifname("Ethernet1/1") == "ethernet1/1"
    assert canonical_ifname("Po10") == "port-channel10"
    assert canonical_ifname("Gi0/0/1") == "gigabitethernet0/0/1"
    assert canonical_ifname("Te1/1/1") == "tengigabitethernet1/1/1"
    assert canonical_ifname("Lo0") == "loopback0"
    assert canonical_ifname("Vlan100") == "vlan100"
    # NX-OS writes "mgmt0" and IOS-XR writes "Management0" for the same kind of port.
    assert canonical_ifname("mgmt0") == "management0"
    assert canonical_ifname("Management0") == "management0"


def test_short_names():
    assert short_ifname("ethernet1/1") == "eth1/1"
    assert short_ifname("Port-channel10") == "po10"
    assert short_ifname("TenGigabitEthernet1/1/1") == "te1/1/1"
    assert short_ifname("Vlan100") == "vlan100"
    # uids carry the short form "mgmt".
    assert short_ifname("Management0") == "mgmt0"


def test_unknown_types_pass_through():
    assert canonical_ifname("bond0") == "bond0"
    assert iface_slug("bond0") == "bond0"


# Each pair is one physical port spelled two ways: the full name as
# `show interfaces` prints it, and the abbreviation as `show cdp neighbors` prints it.
ABBREVIATION_PAIRS = [
    ("TwoGigabitEthernet1/0/1", "Tw1/0/1"),
    ("TwentyFiveGigE1/0/1", "Twe1/0/1"),
    ("GigabitEthernet1/0/1", "Gi1/0/1"),
    ("TenGigabitEthernet1/1/1", "Te1/1/1"),
    ("FortyGigabitEthernet1/1", "Fo1/1"),
    ("HundredGigabitEthernet1/1", "Hu1/1"),
    ("Ethernet1/1", "Eth1/1"),
    ("Port-channel10", "Po10"),
    ("Loopback0", "Lo0"),
    ("Management0", "mgmt0"),
    ("Serial0/0/0", "Se0/0/0"),
    ("Tunnel0", "Tu0"),
]


def test_abbreviated_and_full_spellings_share_one_uid():
    for full, abbrev in ABBREVIATION_PAIRS:
        assert iface_slug(full) == iface_slug(abbrev), f"{full} and {abbrev} split"


def test_two_gig_is_not_twentyfive_gig():
    assert canonical_ifname("Tw1/0/1") == "twogigabitethernet1/0/1"
    assert canonical_ifname("Twe1/0/1") == "twentyfivegige1/0/1"
    assert iface_slug("Tw1/0/1") != iface_slug("Twe1/0/1")


def test_type_resolution_is_case_insensitive():
    """netutils' string helpers are case-sensitive."""
    assert iface_slug("tunnel0") == iface_slug("Tunnel0") == "tu0"
    assert iface_slug("PORT-CHANNEL10") == iface_slug("Port-channel10") == "po10"


def test_po_is_port_channel_not_packet_over_sonet():
    """Lowercasing netutils' table collapses `Po` onto `PO`."""
    assert canonical_ifname("Po10") == "port-channel10"


def test_iface_slug_is_uid_safe():
    # '/' and ':' fold to '-'; the '.' of a subinterface stays
    assert iface_slug("Ethernet1/1.100") == "eth1-1.100"
    assert iface_slug("Ethernet1/1:100") == "eth1-1-100"


def test_iface_slug_keeps_a_subinterface_apart_from_a_slot():
    # one uid each: 'GigabitEthernet0/0.1' is a subinterface, '0/0/1' a port
    assert iface_slug("GigabitEthernet0/0.1") != iface_slug("GigabitEthernet0/0/1")
    assert iface_slug("Ethernet1/1.1") != iface_slug("Ethernet1/1/1")
    assert iface_slug("Gi0/0.1") == iface_slug("GigabitEthernet0/0.1")


@pytest.mark.parametrize(
    ("table", "printed", "expected"),
    [
        # the forms `iface_slug` alone does not match to the full name
        (["FiveGigabitEthernet1/0/1"], "Fi1/0/1", "FiveGigabitEthernet1/0/1"),
        (["MgmtEth0/RP0/CPU0/0"], "Mg0/RP0/CPU0/0", "MgmtEth0/RP0/CPU0/0"),
        (["Bundle-Ether10"], "BE10", "Bundle-Ether10"),
        (["Bundle-Ether10.100"], "BE10.100", "Bundle-Ether10.100"),
        (["TenGigE0/0/0/1"], "Te0/0/0/1", "TenGigE0/0/0/1"),
        (["TenGigE0/0/0/1"], "TE0/0/0/1", "TenGigE0/0/0/1"),
        (["HundredGigE0/0/1/0"], "Hu0/0/1/0", "HundredGigE0/0/1/0"),
        (["TwentyFiveGigE0/0/0/1"], "TF0/0/0/1", "TwentyFiveGigE0/0/0/1"),
        # the forms it does
        (["Vlan10"], "Vl10", "Vlan10"),
        (["Port-channel1"], "Po1", "Port-channel1"),
        (["Ethernet1/1"], "Eth1/1", "Ethernet1/1"),
        (["GigabitEthernet1/0/2"], "Gi1/0/2", "GigabitEthernet1/0/2"),
        (["GigabitEthernet0/0.1"], "Gi0/0.1", "GigabitEthernet0/0.1"),
        # an exact name is its own answer
        (["Ethernet1/1", "Ethernet1/1.1"], "Ethernet1/1.1", "Ethernet1/1.1"),
    ],
)
def test_if_name_resolver_gives_the_name_the_interface_table_spells(table, printed, expected):
    assert IfNameResolver(table)(printed) == expected


@pytest.mark.parametrize(
    ("table", "printed"),
    [
        # a subinterface is not a slot, and a slot is not a subinterface
        (["GigabitEthernet0/0/1"], "Gi0/0.1"),
        (["GigabitEthernet0/0.1"], "Gi0/0/1"),
        # another number, or no number
        (["GigabitEthernet1/0/2"], "Gi1/0/3"),
        (["Loopback0"], "Null0"),
        # two names the abbreviation fits
        (["FortyGigE0/0/0/1", "FiftyGigE0/0/0/1"], "F0/0/0/1"),
    ],
)
def test_if_name_resolver_leaves_a_name_it_cannot_place_as_printed(table, printed):
    assert IfNameResolver(table)(printed) == printed


def test_if_name_resolver_passes_an_empty_name_through_and_slugs_the_resolved_name():
    resolve = IfNameResolver(["FiveGigabitEthernet1/0/1", "Bundle-Ether10"])
    assert resolve(None) is None
    assert resolve("") == ""
    assert resolve.slug(None) == ""
    # the printed and the full spelling are one slug, which `iface_slug` alone gives two
    assert iface_slug("Fi1/0/1") != iface_slug("FiveGigabitEthernet1/0/1")
    assert (
        resolve.slug("Fi1/0/1")
        == resolve.slug("FiveGigabitEthernet1/0/1")
        == iface_slug("FiveGigabitEthernet1/0/1")
    )
    assert iface_slug("BE10") != iface_slug("Bundle-Ether10")
    assert resolve.slug("BE10") == iface_slug("Bundle-Ether10")


def test_hostname_normalization():
    h = normalize_hostname("Leaf101.DC1.Example.")
    assert h.short == "leaf101"
    assert h.fqdn == "leaf101.dc1.example"
    assert normalize_hostname("leaf101").fqdn is None
