from hst.core import uid


def test_port_and_interface_use_short_canonical_names():
    dev = "dev:leaf101"
    assert uid.port(dev, "Ethernet1/1") == "dev:leaf101/port/eth1-1"
    assert uid.interface(dev, "Vlan100") == "dev:leaf101/if/vlan100"
    assert uid.interface(dev, "port-channel10") == "dev:leaf101/if/po10"


def test_scoped_addressing():
    assert uid.prefix("corp", "10.0.10.0/24") == "pfx:corp:10.0.10.0/24"
    assert uid.ip("corp", "10.0.10.5") == "ip:corp:10.0.10.5"
    assert uid.vlan("dev:dc1:sw1", 100) == "vlan:dev:dc1:sw1:100"


def test_vrf_instance_uid_anchor_slugs_deterministically():
    """Routed/connected addressing anchors on the owning VrfInstance uid."""
    vrf_uid = uid.vrf("dev:x", "corp")
    assert vrf_uid == "vrf:dev:x:corp"
    assert uid.prefix(vrf_uid, "10.0.0.0/8") == "pfx:vrf-dev-x-corp:10.0.0.0/8"
    assert uid.ip(vrf_uid, "10.0.0.5") == "ip:vrf-dev-x-corp:10.0.0.5"
    # mixed case / dotted table names embed the same way a plain scope string does
    mixed = uid.vrf("dev:leaf1", "Vrf CORP.1")
    assert uid.prefix(mixed, "10.1.0.0/24") == f"pfx:{uid.anchor_slug(mixed)}:10.1.0.0/24"
    assert uid.anchor_slug(mixed) == "vrf-dev-leaf1-~vrf-~c~o~r~p.1"


def test_case_distinct_vrf_anchors_produce_distinct_prefix_uids():
    """`uid.vrf` keeps the VRF name's case."""
    dev = "dev:leaf101"
    upper, lower = uid.vrf(dev, "Prod"), uid.vrf(dev, "prod")
    assert upper != lower
    assert uid.prefix(upper, "10.0.0.0/24") != uid.prefix(lower, "10.0.0.0/24")
    assert uid.ip(upper, "10.0.0.5") != uid.ip(lower, "10.0.0.5")
    # the all-lowercase VRF keeps the uid that `slug` gives it
    assert uid.prefix(lower, "10.0.0.0/24") == "pfx:vrf-dev-leaf101-prod:10.0.0.0/24"
    assert uid.ip(lower, "10.0.0.5") == "ip:vrf-dev-leaf101-prod:10.0.0.5"


def test_anchor_slug_is_identity_on_the_slug_alphabet():
    """Every character of `[a-z0-9._-]` passes through untouched."""
    for value in ("corp", "vrf-dev-x-corp", "bd-vlan-fab0-30", "a.b_c-d", "0123456789.-_x"):
        assert uid.anchor_slug(value) == value
    for value in ("vrf:dev:x:corp", "bd:vlan:fab0:30", "unifi:default:grp:cameras", "a  b", "x/y[z]"):
        assert uid.anchor_slug(value) == uid.slug(value)


def test_anchor_slug_is_injective_over_a_sample_set():
    """Characters outside the slug alphabet fold to '-' as in `slug`."""
    dev = "dev:leaf101"
    sample = [
        uid.vrf(dev, name)
        for name in ("prod", "Prod", "PROD", "pRod", "prod1", "prod.1", "Prod.1", "default", "Default")
    ] + ["corp", "CORP", "Corp", "corp2"]
    assert len(set(sample)) == len(sample)
    assert len({uid.anchor_slug(v) for v in sample}) == len(sample)
    assert len({uid.slug(v) for v in sample}) < len(sample)


def test_bridge_domain_uid_anchor_also_slugs_deterministically():
    """Endpoint addressing anchors on a bridge-domain uid the same way as on any
    other anchor: once that uid is used as an ip()/prefix() anchor it is
    slugged, deterministically."""
    seg = uid.bridge_domain("fab0", 30)
    assert seg == "bd:vlan:fab0:30"
    assert uid.ip(seg, "192.168.30.50") == "ip:bd-vlan-fab0-30:192.168.30.50"


def test_bridge_domain_is_the_pinned_cross_source_merge_key():
    # persisted merge key: VyOS, UniFi and the Cisco trio land on one shared node
    # only through exact equality, so this string must never change
    assert uid.bridge_domain("fab0", 30) == "bd:vlan:fab0:30"
    assert uid.bridge_domain("fab0", "30") == "bd:vlan:fab0:30"  # VyOS passes config-key strings
    assert uid.bridge_domain("Fab A", 30) == "bd:vlan:fab-a:30"  # declared name, slugged


def test_tunnel_is_direction_agnostic():
    a = uid.tunnel("gre", "ip:corp:1.1.1.1", "zs:fra4")
    b = uid.tunnel("gre", "zs:fra4", "ip:corp:1.1.1.1")
    assert a == b


def test_endpoint_mac_normalization():
    assert uid.endpoint("corp", "00:1C:7F:AA:BB:01") == "ep:corp:001c7faabb01"
    assert uid.endpoint("corp", "001c.7faa.bb01") == "ep:corp:001c7faabb01"


def test_routing_process_scopes_per_device_vrf_protocol():
    assert uid.routing_process("dev:leaf1", "default", "bgp") == "rproc:dev:leaf1:default:bgp"
    # vrf name slugs, device uid and protocol do not get re-cased
    assert uid.routing_process("dev:leaf1", "Vrf CORP.1", "BGP") == "rproc:dev:leaf1:vrf-corp.1:bgp"


def test_bgp_session_local_uid_is_the_routing_process_uid():
    proc = uid.routing_process("dev:leaf1", "default", "bgp")
    assert uid.bgp_session(proc, "192.0.2.1", "default") == f"bgp:{proc}~192.0.2.1:default"


def test_route_policy_keeps_name_case_and_disambiguates_by_kind():
    dev = "dev:leaf101"
    rm = uid.route_policy(dev, "route-map", "FROM-PEER")
    pl = uid.route_policy(dev, "prefix-list", "FROM-PEER")
    assert rm == f"rtpol:{dev}:route-map:FROM-PEER"
    assert pl == f"rtpol:{dev}:prefix-list:FROM-PEER"
    assert rm != pl


def test_route_policy_entry_and_prefix_list_entry_nest_under_their_policy():
    pol = uid.route_policy("dev:leaf101", "route-map", "FROM-PEER")
    assert uid.route_policy_entry(pol, 10) == f"{pol}/clause/10"
    assert uid.prefix_list_entry(pol, "20") == f"{pol}/line/20"  # str seq coerces like int() elsewhere


def test_fc_slugs_the_table_id_but_leaves_device_uid_verbatim():
    assert uid.fc("dev:leaf1", "default") == "fc:dev:leaf1:default"
    assert uid.fc("dev:leaf1", "Vrf CORP.1") == "fc:dev:leaf1:vrf-corp.1"  # mixed-case, dotted, spaced
    assert uid.fc("dev:MixedCase", "x") == "fc:dev:MixedCase:x"


def test_native_id_namespaces():
    assert uid.aci("fab1", "uni/tn-PROD/BD-web") == "aci:fab1:uni/tn-PROD/BD-web"  # DN case kept
    assert uid.azure("/Subscriptions/ABC/x").startswith("az:/subscriptions/abc/")
    assert uid.aws("arn:aws:ec2:eu-central-1:1:vpc/vpc-1") == "aws:arn:aws:ec2:eu-central-1:1:vpc/vpc-1"


def test_site_fold_names_the_code_that_is_the_same_site():
    """Codes are case-sensitive, and the graph has one Site per uid."""
    assert uid.site_fold("DC1", ["dc1", "hq"]) == "dc1"
    assert uid.site_fold("fra:1", ["fra-1"]) == "fra-1"
    assert uid.site_fold("dc1", ["dc1", "hq"]) is None
    assert uid.site_fold("dc2", ["dc1", "hq"]) is None


def test_exact_slug_keeps_a_slug_name_and_never_folds_two_names():
    assert uid.exact_slug("edge-in") == "edge-in"
    assert uid.exact_slug("101") == "101"
    upper, lower = uid.exact_slug("WEB-IN"), uid.exact_slug("web-in")
    assert lower == "web-in"
    assert upper.startswith("web-in~") and len(upper) == len("web-in~") + 8
    assert upper != lower
    assert uid.exact_slug("Web-In") not in (upper, lower)
    assert uid.exact_slug("WEB-IN") == upper
