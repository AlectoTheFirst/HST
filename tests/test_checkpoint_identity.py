"""The Gaia identity resolver: management data decides, a typed override wins."""

from hst.collectors.checkpoint_identity import (
    GaiaObservation,
    GatewayObject,
    ManagementInventory,
    gateway_objects,
    parse_hostname,
    parse_release,
    parse_vs_names,
    resolve_identity,
)

MEMBER = GatewayObject(
    uid="member-uid", name="fw-a", ipv4="192.0.2.10", type="CpmiVsxClusterMember", domain_uid="domain-uid"
)
CLUSTER = GatewayObject(uid="cluster-uid", name="vsx-cluster", ipv4="192.0.2.1", type="CpmiVsxClusterNetobj")
VS1 = GatewayObject(uid="vs1-uid", name="vs-dmz", type="CpmiVsClusterNetobj")
VS2 = GatewayObject(uid="vs2-uid", name="vs-core", type="CpmiVsNetobj")
INVENTORY = ManagementInventory(
    source="cp-mgmt", scope="cp:mgmt.example", objects=(MEMBER, CLUSTER, VS1, VS2)
)
OBSERVED = GaiaObservation(hostname="fw-a", vs_names={0: "vsx-cluster", 1: "vs-dmz", 2: "vs-core"})


def _resolve(**overrides):
    arguments = {
        "appliance": "gaia-a/192.0.2.10",
        "host": "192.0.2.10",
        "vsids": (0, 1, 2),
        "observed": OBSERVED,
        "inventory": INVENTORY,
        "authority_fallback": "cp:typed.example",
    }
    arguments.update(overrides)
    return resolve_identity(**arguments)


def test_the_appliance_matches_by_address_and_the_scope_is_the_management_scope():
    identity = _resolve()

    assert identity.authority == "cp:mgmt.example"
    assert identity.appliance_uid == "member-uid"
    assert identity.appliance_origin == "address"
    assert identity.warnings == ()


def test_the_domain_uid_comes_from_the_appliance_object_then_any_object_then_the_scope():
    assert (_resolve().domain, _resolve().domain_origin) == ("domain-uid", "object")

    other = GatewayObject(uid="x", name="x", domain_uid="other-domain")
    bare = GatewayObject(uid="member-uid", name="fw-a", ipv4="192.0.2.10")
    inventory = ManagementInventory(source="cp-mgmt", scope="cp:mgmt.example", objects=(bare, other))
    identity = _resolve(inventory=inventory)
    assert (identity.domain, identity.domain_origin) == ("other-domain", "inventory")

    mds = ManagementInventory(source="cp-mgmt", scope="cp:mgmt.example:dom", domain="dom", objects=(bare,))
    identity = _resolve(inventory=mds)
    assert (identity.domain, identity.domain_origin) == ("dom", "scope")

    single = ManagementInventory(source="cp-mgmt", scope="cp:mgmt.example", objects=(bare,))
    identity = _resolve(inventory=single)
    assert (identity.domain, identity.domain_origin) == ("cp:mgmt.example", "authority")

    identity = _resolve(domain_override="typed")
    assert (identity.domain, identity.domain_origin) == ("typed", "override")


def test_an_overridden_appliance_reads_its_objects_domain():
    identity = _resolve(appliance_override="member-uid")

    assert (identity.domain, identity.domain_origin) == ("domain-uid", "object")


def test_the_release_is_the_first_r_token_else_the_first_line():
    assert parse_release("Product version Check Point Gaia R81.20\nOS build 634") == "R81.20"
    assert parse_release("R82") == "R82"
    assert parse_release("\nGaia 64-bit\n") == "Gaia 64-bit"
    assert parse_release("") == ""


def test_the_appliance_matches_by_reported_hostname_when_no_address_matches():
    identity = _resolve(host="gaia-a.example")

    assert identity.appliance_uid == "member-uid"
    assert identity.appliance_origin == "name"
    assert identity.warnings == ()


def test_each_vs_matches_the_object_with_its_name_and_vs_zero_finds_the_vsx_object():
    identity = _resolve()

    assert dict(identity.vs_object_uids) == {0: "cluster-uid", 1: "vs1-uid", 2: "vs2-uid"}


def test_a_virtual_system_object_is_preferred_over_another_object_with_the_same_name():
    twin = GatewayObject(uid="host-uid", name="vs-dmz", type="CpmiHostCkp")
    inventory = ManagementInventory(source="cp-mgmt", scope="cp:mgmt.example", objects=(twin, MEMBER, VS1))

    identity = _resolve(inventory=inventory, vsids=(1,))

    assert identity.vs_object_uids[1] == "vs1-uid"


def test_no_match_keeps_fallback_identities_and_warns_naming_appliance_and_source():
    identity = _resolve(
        appliance="gaia-b/198.51.100.9",
        host="198.51.100.9",
        vsids=(1,),
        observed=GaiaObservation(hostname="somewhere-else", vs_names={1: "vs-unknown"}),
    )

    assert identity.authority == "cp:mgmt.example"
    assert identity.appliance_uid == "198.51.100.9"
    assert identity.appliance_origin == "host"
    assert identity.vs_object_uids == {1: "vs-unknown"}
    assert len(identity.warnings) == 2
    for warning in identity.warnings:
        assert "gaia-b/198.51.100.9" in warning
        assert "'cp-mgmt'" in warning
    assert "'somewhere-else'" in identity.warnings[0]
    assert "keyed by host '198.51.100.9'" in identity.warnings[0]
    assert "VS 1 'vs-unknown'" in identity.warnings[1]
    assert "keyed by the VS name" in identity.warnings[1]


def test_a_vs_with_no_name_and_no_override_has_no_identity_and_is_reported():
    identity = _resolve(vsids=(1, 7), observed=GaiaObservation(hostname="fw-a", vs_names={1: "vs-dmz"}))

    assert dict(identity.vs_object_uids) == {1: "vs1-uid"}
    assert len(identity.warnings) == 1
    assert "VS 7 has no name in vsx stat -v" in identity.warnings[0]
    assert "its context is not written" in identity.warnings[0]


def test_typed_overrides_win_over_every_match():
    identity = _resolve(
        authority_override="cp:typed.example:dom",
        appliance_override="typed-member",
        vs_overrides={1: "typed-vs1"},
    )

    assert identity.authority == "cp:typed.example:dom"
    assert identity.appliance_uid == "typed-member"
    assert identity.appliance_origin == "override"
    assert dict(identity.vs_object_uids) == {0: "cluster-uid", 1: "typed-vs1", 2: "vs2-uid"}
    assert identity.warnings == ()


def test_a_blank_override_entry_falls_back_to_the_data():
    identity = _resolve(vs_overrides={1: " "})

    assert identity.vs_object_uids[1] == "vs1-uid"


def test_an_unreadable_management_source_is_one_warning_with_the_consequences():
    inventory = ManagementInventory(source="cp-mgmt", problem="no collected payload yet")

    identity = _resolve(inventory=inventory)

    assert identity.authority == "cp:typed.example"
    assert identity.appliance_uid == "192.0.2.10"
    assert dict(identity.vs_object_uids) == {0: "vsx-cluster", 1: "vs-dmz", 2: "vs-core"}
    assert len(identity.warnings) == 1
    warning = identity.warnings[0]
    assert "gaia-a/192.0.2.10" in warning
    assert "'cp-mgmt'" in warning
    assert "no collected payload yet" in warning
    assert "FirewallInstance.authority is 'cp:typed.example'" in warning
    assert "keyed by host '192.0.2.10'" in warning
    assert "VS 0, 1, 2 keep FirewallInstance nodes keyed by their VS names" in warning


def test_a_linked_scope_without_objects_keeps_the_scope():
    inventory = ManagementInventory(
        source="cp-mgmt", scope="cp:mgmt.example", problem="the last payload has no gateway objects"
    )

    identity = _resolve(inventory=inventory)

    assert identity.authority == "cp:mgmt.example"
    assert "FirewallInstance.authority" not in identity.warnings[0]


def test_no_management_source_with_full_overrides_is_silent():
    identity = _resolve(
        inventory=None,
        authority_override="cp:typed.example",
        appliance_override="typed-member",
        vs_overrides={0: "o0", 1: "o1", 2: "o2"},
    )

    assert identity.warnings == ()
    assert dict(identity.vs_object_uids) == {0: "o0", 1: "o1", 2: "o2"}


def test_no_management_source_and_a_missing_override_is_reported():
    identity = _resolve(inventory=None, authority_override="cp:typed.example", vsids=(1,))

    assert identity.appliance_uid == "192.0.2.10"
    assert identity.vs_object_uids == {1: "vs-dmz"}
    assert len(identity.warnings) == 1
    assert "no management source is configured" in identity.warnings[0]


def test_vsx_stat_names_parse_from_the_column_layout_and_from_the_bare_layout():
    table = "\n".join(
        [
            "VSX Gateway Status",
            "Name:   fw-a",
            "",
            "ID   | Type & Name          | Security Policy | Installed at    | SIC Stat",
            "-----+----------------------+-----------------+-----------------+---------",
            "   0 | S vsx-cluster        | vsx_pol         | 15Jul2026 10:11 | Trust",
            "   1 | S vs-dmz             | dmz_pol         | 15Jul2026 10:12 | Trust",
            "   2 | R vr-core            | <Not Applicable>|                 | Trust",
        ]
    )

    assert parse_vs_names(table) == {0: "vsx-cluster", 1: "vs-dmz", 2: "vr-core"}
    assert parse_vs_names("7 VS7\n8 VS8") == {7: "VS7", 8: "VS8"}
    assert parse_vs_names("") == {}


def test_hostname_is_the_first_non_empty_line():
    assert parse_hostname("\n  fw-a  \n") == "fw-a"
    assert parse_hostname("") == ""


def test_gateway_objects_keep_only_entries_with_a_uid():
    raw = {
        "gateways": [
            {
                "uid": "member-uid",
                "name": "fw-a",
                "type": "CpmiVsxClusterMember",
                "ipv4-address": "192.0.2.10",
                "domain": {"uid": "domain-uid", "name": "SMC User"},
            },
            {"name": "no-uid"},
            "not a mapping",
            {"uid": "vs1-uid", "name": "vs-dmz", "type": "CpmiVsClusterNetobj"},
        ]
    }

    assert gateway_objects(raw) == (MEMBER, VS1)
    assert gateway_objects({}) == ()
