"""L3 domain resolution."""

from hst.core.l3domain import DomainPolicy, Vrf, display_name, resolve


def test_two_vrfs_on_one_router_do_not_share_a_domain():
    policy = DomainPolicy(scope="home")
    red = resolve(Vrf(device="dev:gw", name="RED"), policy)
    blue = resolve(Vrf(device="dev:gw", name="BLUE"), policy)
    assert red != blue, "same-subnet VRFs would merge onto one Prefix node"


def test_a_device_without_vrfs_reads_as_the_bare_scope():
    assert resolve(Vrf(device="dev:gw"), DomainPolicy(scope="home")) == "home"


def test_same_named_vrfs_in_one_scope_join():
    policy = DomainPolicy(scope="campus")
    a = resolve(Vrf(device="dev:leaf1", name="CORP"), policy)
    b = resolve(Vrf(device="dev:leaf2", name="CORP"), policy)
    assert a == b == "campus:CORP"


def test_same_named_vrfs_in_different_scopes_stay_apart():
    a = resolve(Vrf(device="dev:leaf1", name="CORP"), DomainPolicy(scope="campus"))
    b = resolve(Vrf(device="dev:leaf9", name="CORP"), DomainPolicy(scope="dc"))
    assert a != b


def test_route_targets_join_vrfs_across_devices_whatever_they_are_called():
    """RTs outrank the naming convention."""
    policy = DomainPolicy(scope="fabric")
    a = resolve(Vrf(device="dev:leaf1", name="CORP", rts=("65000:100",)), policy)
    b = resolve(Vrf(device="dev:leaf2", name="CORPORATE", rts=("65000:100",)), policy)
    assert a == b


def test_route_target_order_does_not_change_identity():
    policy = DomainPolicy(scope="fabric")
    a = resolve(Vrf(device="d1", name="X", rts=("65000:2", "65000:1")), policy)
    b = resolve(Vrf(device="d2", name="Y", rts=("65000:1", "65000:2")), policy)
    assert a == b


def test_different_route_targets_stay_apart():
    policy = DomainPolicy(scope="fabric")
    a = resolve(Vrf(device="d1", name="X", rts=("65000:1",)), policy)
    b = resolve(Vrf(device="d2", name="X", rts=("65000:2",)), policy)
    assert a != b, "same name but different RTs are different domains"


def test_platforms_that_report_no_route_targets_still_resolve():
    policy = DomainPolicy(scope="site")
    assert resolve(Vrf(device="d1", name="RED"), policy) == "site:RED"


def test_an_override_beats_every_heuristic():
    policy = DomainPolicy(scope="fabric", overrides={"dev:leaf1:CORP": "legacy-core"})
    got = resolve(Vrf(device="dev:leaf1", name="CORP", rts=("65000:100",)), policy)
    assert got == "legacy-core"


def test_the_more_specific_override_wins():
    policy = DomainPolicy(
        scope="fabric", overrides={"fabric:CORP": "by-scope", "dev:leaf1:CORP": "by-device"}
    )
    assert resolve(Vrf(device="dev:leaf1", name="CORP"), policy) == "by-device"
    assert resolve(Vrf(device="dev:leaf2", name="CORP"), policy) == "by-scope"


def test_strict_never_merges_anything():
    policy = DomainPolicy(scope="fabric", strategy="strict")
    a = resolve(Vrf(device="dev:leaf1", name="CORP", rts=("65000:1",)), policy)
    b = resolve(Vrf(device="dev:leaf2", name="CORP", rts=("65000:1",)), policy)
    assert a != b


def test_strict_still_honours_an_override():
    policy = DomainPolicy(scope="f", strategy="strict", overrides={"dev:leaf1:CORP": "shared"})
    assert resolve(Vrf(device="dev:leaf1", name="CORP"), policy) == "shared"


def test_resolution_is_deterministic():
    policy = DomainPolicy(scope="home")
    vrf = Vrf(device="dev:gw", name="RED")
    assert resolve(vrf, policy) == resolve(vrf, policy)


def test_empty_vrf_name_is_the_global_table():
    assert resolve(Vrf(device="d", name=""), DomainPolicy(scope="home")) == "home"


def test_rt_domains_get_a_readable_label():
    assert display_name("rt:65000:100") == "route-target 65000:100"
    assert display_name("campus:CORP") == "campus:CORP"
