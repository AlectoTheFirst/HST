"""A statically addressed VyOS uplink gets a WanLink of kind `static`: the
interface a configured main-table default route leaves by, through a next hop
in that interface's connected prefix, or an interface-only default. The tracer
reads a WanLink ON the egress interface as the estate's exit."""

import copy
import json

from tests.test_vyos import CONFIG, LINKS, VERSION

from hst.collectors.vyos import normalize_vyos


def _wan(eth0=None, route=None, route6=None, table=None, extra=None):
    cfg = copy.deepcopy(CONFIG)
    cfg["interfaces"]["ethernet"]["eth0"] = eth0 or {
        "address": ["203.0.113.2/30", "2001:db8:ff::2/64"],
        "description": "WAN static",
    }
    static = cfg["protocols"]["static"]
    static["route"] = {**static.get("route", {}), **(route or {})}
    if route6:
        static["route6"] = route6
    if table:
        static["table"] = table
    if extra:
        extra(cfg)
    raw = {"config": json.loads(json.dumps(cfg)), "version_text": VERSION, "links": LINKS}
    return normalize_vyos(raw, l3dom="home")


def _links(batch):
    nodes = {n.uid: n.props for n in batch.nodes if n.label == "WanLink"}
    on = {r.start_uid: r.end_uid for r in batch.rels if r.rel_type == "ON" and r.start_label == "WanLink"}
    has = {r.end_uid for r in batch.rels if r.rel_type == "HAS_LINK"}
    assert set(nodes) == set(on) == has
    return {uid: (props["kind"], props["name"], on[uid]) for uid, props in nodes.items()}


V4_DEFAULT = {"0.0.0.0/0": {"next-hop": {"203.0.113.1": {}}}}


def test_a_default_route_through_a_gateway_on_a_static_interface_marks_it():
    assert _links(_wan(route=V4_DEFAULT)) == {"wan:gw:eth0": ("static", "WAN static", "dev:gw/if/eth0")}


def test_an_ipv6_default_and_an_interface_only_default_mark_it():
    v6 = {"::/0": {"next-hop": {"2001:db8:ff::1": {}}}}
    assert _links(_wan(route6=v6)) == {"wan:gw:eth0": ("static", "WAN static", "dev:gw/if/eth0")}
    # a link-local gateway names its interface
    v6ll = {"::/0": {"next-hop": {"fe80::1": {"interface": "eth0"}}}}
    assert _links(_wan(route6=v6ll)) == {"wan:gw:eth0": ("static", "WAN static", "dev:gw/if/eth0")}
    iface = {"0.0.0.0/0": {"interface": {"eth0": {}}}}
    assert _links(_wan(route=iface)) == {"wan:gw:eth0": ("static", "WAN static", "dev:gw/if/eth0")}


def test_both_families_by_one_interface_give_one_link():
    v6 = {"::/0": {"next-hop": {"2001:db8:ff::1": {}}}}
    assert list(_links(_wan(route=V4_DEFAULT, route6=v6))) == ["wan:gw:eth0"]


def test_a_dhcp_uplink_keeps_its_one_link_and_kind():
    """eth0 by DHCP already has its WanLink; a static default by it (the Oslo
    shape: dhcp with no-default-route plus a static default) adds none and
    does not rewrite its kind."""
    eth0 = {
        "address": ["dhcp", "203.0.113.2/30"],
        "description": "WAN",
        "dhcp-options": {"no-default-route": {}},
    }
    assert _links(_wan(eth0=eth0, route=V4_DEFAULT)) == {"wan:gw:eth0": ("dia", "WAN", "dev:gw/if/eth0")}


def test_a_pppoe_router_without_a_static_default_is_unchanged():
    def pppoe(cfg):
        cfg["interfaces"]["pppoe"] = {"pppoe0": {"description": "ISP", "source-interface": "eth0"}}

    eth0 = {"description": "to modem"}
    assert _links(_wan(eth0=eth0, extra=pppoe)) == {"wan:gw:pppoe0": ("dia", "ISP", "dev:gw/if/pppoe0")}


def test_backup_policy_table_blackhole_and_foreign_gateways_mark_nothing():
    # a floating backup: an explicit distance above the default
    backup = {"0.0.0.0/0": {"next-hop": {"203.0.113.1": {"distance": "10"}}}}
    assert _links(_wan(route=backup)) == {}
    # the default of a policy table (a WireGuard table) is not the estate's uplink
    table = {"100": {"route": {"0.0.0.0/0": {"next-hop": {"203.0.113.1": {}}}}}}
    assert _links(_wan(table=table)) == {}
    # a blackhole default leaves by no interface
    assert _links(_wan(route={"0.0.0.0/0": {"blackhole": {}}})) == {}
    # a gateway in no connected prefix (a recursive next hop) names no interface
    assert _links(_wan(route={"0.0.0.0/0": {"next-hop": {"198.51.100.1": {}}}})) == {}
    # a default into a tunnel interface is not a WAN link
    assert _links(_wan(route={"0.0.0.0/0": {"interface": {"wg0": {}}}})) == {}
    # a disabled form is not installed
    off = {"0.0.0.0/0": {"next-hop": {"203.0.113.1": {"disable": {}}}}}
    assert _links(_wan(route=off)) == {}


def test_a_default_to_an_internal_router_marks_nothing():
    core = {"address": ["10.0.0.2/24", "fd00:0:0:1::2/64"], "description": "to core"}
    assert _links(_wan(eth0=core, route={"0.0.0.0/0": {"next-hop": {"10.0.0.1": {}}}})) == {}
    assert _links(_wan(eth0=core, route6={"::/0": {"next-hop": {"fd00:0:0:1::1": {}}}})) == {}
    # an interface-only or a link-local default on an internal interface
    assert _links(_wan(eth0=core, route={"0.0.0.0/0": {"interface": {"eth0": {}}}})) == {}
    assert _links(_wan(eth0=core, route6={"::/0": {"next-hop": {"fe80::1": {"interface": "eth0"}}}})) == {}
    # a provider CPE on a CGNAT or private transfer network: the known limit
    cgnat = {"address": ["100.64.0.2/30"], "description": "to CPE"}
    assert _links(_wan(eth0=cgnat, route={"0.0.0.0/0": {"next-hop": {"100.64.0.1": {}}}})) == {}


def test_a_public_static_uplink_is_marked():
    """A gateway outside the private and special ranges (here public space
    beside the documentation ranges the other tests use)."""
    eth0 = {"address": ["1.1.1.2/30"], "description": "ISP"}
    route = {"0.0.0.0/0": {"next-hop": {"1.1.1.1": {}}}}
    assert _links(_wan(eth0=eth0, route=route)) == {"wan:gw:eth0": ("static", "ISP", "dev:gw/if/eth0")}
