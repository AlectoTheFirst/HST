"""The symbolic model attaches a source on a subnet with a first-hop redundancy
group to the member that forwards (`_source_attachments`)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from tests.support.batch_inventory import inventory

from hst.analysis_model.network import _fhrp_standby_addresses, _source_attachments
from hst.collectors.util import GraphBuilder
from hst.impact.evaluate import Interface, Member, RequestSet, member

VIP = "ip:corp:10.11.10.1"
ONE, TWO = "dev:core-01/if/vlan10", "dev:core-02/if/vlan10"
USERS = (4, int.from_bytes(bytes([10, 11, 10, 0])), int.from_bytes(bytes([10, 11, 10, 255])))


def _graph(one="active", two="standby", kind="hsrp"):
    b = GraphBuilder()
    b.node("IpAddress", VIP, ip="10.11.10.1", af=4)
    for interface, state in ((ONE, one), (TWO, two)):
        b.node("Interface", interface, name="vlan10")
        b.rel("HAS_IP", "Interface", interface, "IpAddress", VIP, fhrp=kind, group=10, state=state)
    return inventory(b.batch("test", "fixture:estate"))


def _network():
    interfaces = tuple(
        Interface(device, uid, "vlan10", context, ("10.11.10.0/24",))
        for device, uid, context in (("dev:core-01", ONE, "vrf:one"), ("dev:core-02", TWO, "vrf:two"))
    )
    return SimpleNamespace(interfaces=interfaces)


REQUEST = RequestSet("users", (USERS,), "server", (Member("server", ((4, 1, 1),)),), member("server"))


@pytest.mark.parametrize(
    ("kind", "states"), [("hsrp", ("active", "standby")), ("vrrp", ("master", "backup"))]
)
def test_the_subnet_is_attached_to_the_forwarding_member_only(kind, states):
    graph = _graph(*states, kind=kind)
    assert _fhrp_standby_addresses(graph, ONE) == ()
    assert _fhrp_standby_addresses(graph, TWO) == ("10.11.10.1",)
    assert _source_attachments(_network(), REQUEST, 4, graph) == {"vrf:one": (USERS,)}


@pytest.mark.parametrize(
    "states",
    [("active", "active"), ("standby", "standby"), ("active", None), ("active", "unknown")],
    ids=["2-forwarders", "no-forwarder", "state-not-recorded", "state-unknown"],
)
def test_a_group_without_1_forwarder_and_a_state_of_each_member_keeps_each_attachment(states):
    graph = _graph(*states)
    assert _fhrp_standby_addresses(graph, TWO) == ()
    assert _source_attachments(_network(), REQUEST, 4, graph) == {"vrf:one": (USERS,), "vrf:two": (USERS,)}


def test_without_the_graph_each_interface_that_holds_the_subnet_is_an_attachment():
    assert _source_attachments(_network(), REQUEST, 4) == {"vrf:one": (USERS,), "vrf:two": (USERS,)}
