"""NetScaler collector (fixture-first, no live capture): VirtualService,
Pool, PoolMember, Monitor, SNAT_FROM."""

from hst.collectors.netscaler import normalize_netscaler
from hst.core import uid as uidmod

LBVSERVER_WEB = {
    "name": "web-443",
    "ipv46": "10.0.30.10",
    "port": "443",
    "servicetype": "HTTP",
    "lbmethod": "LEASTCONNECTION",
}
LBVSERVER_DNS = {
    "name": "dns-53",
    "ipv46": "10.0.30.20",
    "port": "53",
    "servicetype": "UDP",
    "usip": "true",
}
LBVSERVER_APP = {
    "name": "app-9000",
    "ipv46": "10.0.30.30",
    "port": "9000",
    "servicetype": "TCP",
    "snat_ip": "10.0.30.99",
}

BINDINGS = [
    {"name": "web-443", "servicegroupname": "sg-web"},
    {"name": "dns-53", "servicegroupname": "sg-dns"},
    {"name": "app-9000", "servicegroupname": "sg-app"},
]

SERVICEGROUPS = [
    {"servicegroupname": "sg-web", "servicegrouptype": "HTTP"},
    {"servicegroupname": "sg-dns", "servicegrouptype": "UDP"},
    {"servicegroupname": "sg-app", "servicegrouptype": "TCP"},
]

MEMBERS = [
    {"servicegroupname": "sg-web", "ip": "10.0.10.5", "port": "8443", "weight": "1", "svrstate": "UP"},
    {
        "servicegroupname": "sg-web",
        "ip": "10.0.10.6",
        "port": "8443",
        "weight": "2",
        "svrstate": "OUT OF SERVICE",
    },
    {"servicegroupname": "sg-dns", "ip": "10.0.10.9", "port": "53", "weight": "1", "svrstate": "UP"},
    {"servicegroupname": "sg-app", "ip": "10.0.10.20", "port": "9000", "weight": "1", "svrstate": "UP"},
]

# sg-dns has no monitor binding (D-LB3).
MONITOR_BINDINGS = [{"servicegroupname": "sg-web", "monitor_name": "mon-http"}]
MONITORS = [{"monitorname": "mon-http", "type": "HTTP"}]

RAW = {
    "lbvserver": [LBVSERVER_WEB, LBVSERVER_DNS, LBVSERVER_APP],
    "lbvserver_servicegroup_binding": BINDINGS,
    "servicegroup": SERVICEGROUPS,
    "servicegroup_servicegroupmember_binding": MEMBERS,
    "servicegroup_lbmonitor_binding": MONITOR_BINDINGS,
    "lbmonitor": MONITORS,
}

SCOPE = "dc1-ns01"
ON_UID = "rgrp:ns-ha:dc1:ns01"


def _norm(**kw):
    kw.setdefault("on_uid", ON_UID)
    kw.setdefault("l3dom", "corp")
    return normalize_netscaler(RAW, scope_name=SCOPE, **kw)


def _index(batch):
    nodes = {n.uid: n for n in batch.nodes}
    rels = {(r.rel_type, r.start_uid, r.end_uid) for r in batch.rels}
    return nodes, rels


def test_virtualservice_node_props_and_default_snat_mode_is_automap():
    nodes, _ = _index(_norm())
    vs = nodes[uidmod.netscaler(SCOPE, "lbvs", "web-443")]
    assert vs.label == "VirtualService"
    assert vs.props["vip"] == "10.0.30.10"
    assert vs.props["port"] == 443
    assert vs.props["proto"] == "tcp"
    assert vs.props["kind"] == "lb"
    assert vs.props["snat_mode"] == "automap"


def test_usip_true_maps_to_snat_mode_none():
    nodes, _ = _index(_norm())
    vs = nodes[uidmod.netscaler(SCOPE, "lbvs", "dns-53")]
    assert vs.props["snat_mode"] == "none"
    assert vs.props["proto"] == "udp"


def test_explicit_snat_ip_maps_to_snat_from_and_emits_the_edge():
    batch = _norm()
    nodes, rels = _index(batch)
    vs = nodes[uidmod.netscaler(SCOPE, "lbvs", "app-9000")]
    assert vs.props["snat_mode"] == "snat_from"
    snip = uidmod.ip("corp", "10.0.30.99")
    assert nodes[snip].label == "IpAddress"
    assert ("SNAT_FROM", vs.uid, snip) in rels


def test_vip_edge_to_ipaddress():
    batch = _norm()
    nodes, rels = _index(batch)
    vs = uidmod.netscaler(SCOPE, "lbvs", "web-443")
    vip = uidmod.ip("corp", "10.0.30.10")
    assert nodes[vip].label == "IpAddress"
    assert ("VIP", vs, vip) in rels


def test_on_edge_to_the_configured_redundancy_group():
    batch = _norm()
    _, rels = _index(batch)
    vs = uidmod.netscaler(SCOPE, "lbvs", "web-443")
    assert ("ON", vs, ON_UID) in rels


def test_on_edge_targets_a_device_when_configured_that_way():
    batch = _norm(on_uid="dev:ns01a", on_label="Device")
    _, rels = _index(batch)
    vs = uidmod.netscaler(SCOPE, "lbvs", "web-443")
    assert ("ON", vs, "dev:ns01a") in rels


def test_pool_and_has_member_and_targets_edges():
    batch = _norm()
    nodes, rels = _index(batch)
    vs = uidmod.netscaler(SCOPE, "lbvs", "web-443")
    pool = uidmod.netscaler(SCOPE, "sg", "sg-web")
    assert nodes[pool].label == "Pool"
    assert ("USES", vs, pool) in rels
    member = f"{pool}/10.0.10.5:8443"
    assert nodes[member].label == "PoolMember"
    assert nodes[member].props["port"] == 8443
    assert nodes[member].props["weight"] == 1
    assert ("HAS_MEMBER", pool, member) in rels
    target = uidmod.ip("corp", "10.0.10.5")
    assert ("TARGETS", member, target) in rels


def test_a_vserver_bound_to_two_servicegroups_emits_a_pool_for_each():
    raw = dict(RAW)
    raw["lbvserver_servicegroup_binding"] = [
        *BINDINGS,
        {"name": "web-443", "servicegroupname": "sg-web-b"},
    ]
    raw["servicegroup"] = [*SERVICEGROUPS, {"servicegroupname": "sg-web-b", "servicegrouptype": "HTTP"}]
    raw["servicegroup_servicegroupmember_binding"] = [
        *MEMBERS,
        {
            "servicegroupname": "sg-web-b",
            "ip": "10.0.10.7",
            "port": "8443",
            "weight": "1",
            "svrstate": "UP",
        },
    ]

    nodes, rels = _index(normalize_netscaler(raw, scope_name=SCOPE, on_uid=ON_UID, l3dom="corp"))

    vs = uidmod.netscaler(SCOPE, "lbvs", "web-443")
    for sg in ("sg-web", "sg-web-b"):
        pool = uidmod.netscaler(SCOPE, "sg", sg)
        assert nodes[pool].label == "Pool"
        assert ("USES", vs, pool) in rels
    second = uidmod.netscaler(SCOPE, "sg", "sg-web-b")
    assert ("HAS_MEMBER", second, f"{second}/10.0.10.7:8443") in rels
    assert ("TARGETS", f"{second}/10.0.10.7:8443", uidmod.ip("corp", "10.0.10.7")) in rels


def test_member_with_no_bound_monitor_omits_state():
    batch = _norm()
    nodes, _ = _index(batch)
    pool = uidmod.netscaler(SCOPE, "sg", "sg-dns")
    member = f"{pool}/10.0.10.9:53"
    assert "state" not in nodes[member].props


def test_member_state_collapses_up_and_out_of_service_to_up_and_down():
    batch = _norm()
    nodes, _ = _index(batch)
    pool = uidmod.netscaler(SCOPE, "sg", "sg-web")
    assert nodes[f"{pool}/10.0.10.5:8443"].props["state"] == "up"
    assert nodes[f"{pool}/10.0.10.6:8443"].props["state"] == "down"


def test_pool_checked_by_monitor_when_bound():
    batch = _norm()
    nodes, rels = _index(batch)
    pool = uidmod.netscaler(SCOPE, "sg", "sg-web")
    mon = uidmod.netscaler(SCOPE, "mon", "mon-http")
    assert nodes[mon].label == "Monitor"
    assert nodes[mon].props["kind"] == "http"
    assert ("CHECKED_BY", pool, mon) in rels


def test_pool_without_a_bound_monitor_has_no_checked_by_edge():
    batch = _norm()
    _, rels = _index(batch)
    pool = uidmod.netscaler(SCOPE, "sg", "sg-dns")
    assert not [r for r in rels if r[0] == "CHECKED_BY" and r[1] == pool]


def test_pool_lb_method_is_lowercased_from_the_vservers_own_lbmethod():
    batch = _norm()
    nodes, _ = _index(batch)
    pool = nodes[uidmod.netscaler(SCOPE, "sg", "sg-web")]
    assert pool.props["lb_method"] == "leastconnection"


def test_batch_validates_against_the_schema_registry():
    # GraphBuilder.batch() runs Batch.validate_registry().
    batch = _norm()
    assert batch.source == "netscaler"
    assert batch.scope == f"netscaler:{SCOPE}"
