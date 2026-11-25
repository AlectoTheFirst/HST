"""`show ip route vrf *`: a connected route whose network is too long for one
line continues with `is directly connected, <interface>` on the next line."""

from tests.test_iosxe import RAW

from hst.collectors import iosxe
from hst.collectors.iosxe import CMD_ROUTE, RIB_UNREAD_KEY

WRAPPED_ROUTE_TEXT = """\
Routing Table: SDWAN
Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP

Gateway of last resort is not set

      10.0.0.0/8 is variably subnetted, 3 subnets, 2 masks
C        10.254.103.0/30
                          is directly connected, Tunnel103
L        10.254.103.1/32
                          is directly connected, Tunnel103
S        10.20.0.0/16 [1/0] via 10.254.103.2
"""


def test_a_wrapped_connected_route_is_read_with_its_interface():
    inter = iosxe.parse({**RAW, CMD_ROUTE: WRAPPED_ROUTE_TEXT})

    assert inter.get(RIB_UNREAD_KEY, 0) == 0
    rows = {(r["prefix"], r["protocol"]): r for r in inter["rib"]}
    assert rows[("10.254.103.0/30", "connected")]["interface"] == "Tunnel103"
    assert rows[("10.254.103.0/30", "connected")]["next_hop"] is None
    assert rows[("10.20.0.0/16", "static")]["next_hop"] == "10.254.103.2"
    assert all(r["vrf"] == "SDWAN" for r in inter["rib"])


def test_a_wrapped_connected_route_after_an_unread_line_stays_unread():
    """The continuation belongs to the network on the line before it. After an
    unread line, that network is not known, so the continuation is unread too."""
    text = WRAPPED_ROUTE_TEXT.replace("C        10.254.103.0/30\n", "C        10.254.103.0/30 garbage\n")

    inter = iosxe.parse({**RAW, CMD_ROUTE: text})

    assert inter[RIB_UNREAD_KEY] == 2
    assert ("10.254.103.0/30", "connected") not in {(r["prefix"], r["protocol"]) for r in inter["rib"]}
