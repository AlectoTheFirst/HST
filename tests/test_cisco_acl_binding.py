"""The binding of a Cisco interface ACL: `(Interface)-[:PROTECTED_BY {direction}]->(FwRulebase)`,
beside the device's ENFORCES."""

from tests.test_cisco_common import _PERMIT_ANY_ACE, DEV, SCOPE, _acl_batch

from hst.core import uid


def _bindings(batch) -> set[tuple[str, str, str]]:
    return {
        (r.start_uid, r.end_uid, r.props.get("direction")) for r in batch.rels if r.rel_type == "PROTECTED_BY"
    }


def test_each_binding_protects_its_interface_in_its_direction():
    acl = {
        "lists": {"SHARED": [_PERMIT_ANY_ACE]},
        "bindings": [
            {"interface": "Ethernet1/1", "direction": "in", "acl": "SHARED"},
            {"interface": "Vlan10", "direction": "out", "acl": "SHARED"},
        ],
    }

    batch = _acl_batch(acl)

    assert _bindings(batch) == {
        (uid.interface(DEV, "Ethernet1/1"), f"{SCOPE}:acl:shared~0e1d1edc", "in"),
        (uid.interface(DEV, "Vlan10"), f"{SCOPE}:acl:shared~0e1d1edc", "out"),
    }
    interfaces = {n.uid for n in batch.nodes if n.label == "Interface"}
    assert {start for start, _, _ in _bindings(batch)} <= interfaces


def test_a_binding_spelled_otherwise_binds_the_interface_node_of_that_name():
    acl = {
        "lists": {"X": [_PERMIT_ANY_ACE]},
        "bindings": [{"interface": "ethernet1/1", "direction": "in", "acl": "X"}],
    }

    assert {start for start, _, _ in _bindings(_acl_batch(acl))} == {uid.interface(DEV, "Ethernet1/1")}


def test_a_binding_to_an_interface_the_device_did_not_report_is_enforced_but_not_bound():
    acl = {
        "lists": {"X": []},
        "bindings": [{"interface": "GigabitEthernet9/9/9", "direction": "in", "acl": "X"}],
    }

    batch = _acl_batch(acl)

    assert _bindings(batch) == set()
    rb = next(n for n in batch.nodes if n.label == "FwRulebase")
    assert (DEV, rb.uid) in {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ENFORCES"}


def _rulebases(batch) -> dict[str, dict]:
    return {n.uid: n.props for n in batch.nodes if n.label == "FwRulebase"}


def test_one_list_bound_to_three_interfaces_is_one_rulebase_with_three_edges():
    acl = {
        "lists": {"WEB-IN": [_PERMIT_ANY_ACE, _PERMIT_ANY_ACE]},
        "bindings": [
            {"interface": "Ethernet1/1", "direction": "in", "acl": "WEB-IN"},
            {"interface": "port-channel1", "direction": "in", "acl": "WEB-IN"},
            {"interface": "Vlan10", "direction": "in", "acl": "WEB-IN"},
        ],
    }

    batch = _acl_batch(acl)

    rb_uid = f"{SCOPE}:acl:web-in~d601880c"
    rulebases = _rulebases(batch)
    # configured_revision is the digest of the reported entries the ENFORCES
    # edge records as installed
    props = dict(rulebases[rb_uid])
    revision = props.pop("configured_revision")
    (edge,) = [r for r in batch.rels if r.rel_type == "ENFORCES" and r.end_uid == rb_uid]
    assert edge.props["installed_revision"] == revision
    assert {**rulebases, rb_uid: props} == {
        rb_uid: {
            "name": "WEB-IN",
            "kind": "access",
            "vendor": "cisco",
            "match_context": "interface-acl",
            "default_action": "deny",
            "af": 4,
        }
    }
    assert _bindings(batch) == {
        (uid.interface(DEV, "Ethernet1/1"), rb_uid, "in"),
        (uid.interface(DEV, "port-channel1"), rb_uid, "in"),
        (uid.interface(DEV, "Vlan10"), rb_uid, "in"),
    }
    assert [
        (r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "ENFORCES" and r.end_uid == rb_uid
    ] == [(DEV, rb_uid)]
    # the rules once, in list order, with no interface of their own
    rules = sorted(
        (n for n in batch.nodes if n.label == "FwRule"),
        key=lambda n: n.props["position"],
    )
    assert [n.uid for n in rules] == [f"{rb_uid}:1", f"{rb_uid}:2"]
    assert all("in_interface" not in n.props and "out_interface" not in n.props for n in rules)
    assert {(r.start_uid, r.end_uid) for r in batch.rels if r.rel_type == "HAS_RULE"} == {
        (rb_uid, f"{rb_uid}:1"),
        (rb_uid, f"{rb_uid}:2"),
    }


def test_one_list_bound_in_and_out_on_one_interface_is_two_edges():
    acl = {
        "lists": {"EDGE": [_PERMIT_ANY_ACE]},
        "bindings": [
            {"interface": "Ethernet1/1", "direction": "in", "acl": "EDGE"},
            {"interface": "Ethernet1/1", "direction": "out", "acl": "EDGE"},
        ],
    }

    batch = _acl_batch(acl)

    assert set(_rulebases(batch)) == {f"{SCOPE}:acl:edge~b5833faa"}
    assert _bindings(batch) == {
        (uid.interface(DEV, "Ethernet1/1"), f"{SCOPE}:acl:edge~b5833faa", "in"),
        (uid.interface(DEV, "Ethernet1/1"), f"{SCOPE}:acl:edge~b5833faa", "out"),
    }


def test_two_lists_are_two_rulebases_each_bound_to_its_own_interfaces():
    acl = {
        "lists": {"A": [_PERMIT_ANY_ACE], "B": [_PERMIT_ANY_ACE]},
        "bindings": [
            {"interface": "Ethernet1/1", "direction": "in", "acl": "A"},
            {"interface": "port-channel1", "direction": "in", "acl": "B"},
            {"interface": "Vlan10", "direction": "out", "acl": "A"},
        ],
    }

    batch = _acl_batch(acl)

    assert {uid: props["name"] for uid, props in _rulebases(batch).items()} == {
        f"{SCOPE}:acl:a~559aead0": "A",
        f"{SCOPE}:acl:b~df7e70e5": "B",
    }
    assert _bindings(batch) == {
        (uid.interface(DEV, "Ethernet1/1"), f"{SCOPE}:acl:a~559aead0", "in"),
        (uid.interface(DEV, "Vlan10"), f"{SCOPE}:acl:a~559aead0", "out"),
        (uid.interface(DEV, "port-channel1"), f"{SCOPE}:acl:b~df7e70e5", "in"),
    }


def test_a_repeated_binding_is_one_edge():
    acl = {
        "lists": {"X": [_PERMIT_ANY_ACE]},
        "bindings": [
            {"interface": "Ethernet1/1", "direction": "in", "acl": "X"},
            {"interface": "ethernet1/1", "direction": "in", "acl": "X"},
        ],
    }

    rels = [r for r in _acl_batch(acl).rels if r.rel_type == "PROTECTED_BY"]

    assert len(rels) == 1


def test_a_list_bound_nowhere_the_device_reported_is_one_placeholder_rulebase():
    """An uncollected list bound to two unreported interfaces: one rulebase, one
    placeholder rule, no binding edge."""
    acl = {
        "lists": {},
        "bindings": [
            {"interface": "GigabitEthernet9/9/8", "direction": "in", "acl": "GHOST"},
            {"interface": "GigabitEthernet9/9/9", "direction": "out", "acl": "GHOST"},
        ],
    }

    batch = _acl_batch(acl)

    assert set(_rulebases(batch)) == {f"{SCOPE}:acl:ghost~23d24152"}
    assert [n.uid for n in batch.nodes if n.label == "FwRule"] == [f"{SCOPE}:acl:ghost~23d24152:1"]
    assert _bindings(batch) == set()


def test_two_lists_differing_only_by_case_are_two_rulebases():
    """Cisco ACL names are case sensitive: WEB-IN and web-in are two lists."""
    upper = [{**_PERMIT_ANY_ACE, "action": "deny"}]
    acl = {
        "lists": {"WEB-IN": upper, "web-in": [_PERMIT_ANY_ACE]},
        "bindings": [
            {"interface": "Ethernet1/1", "direction": "in", "acl": "WEB-IN"},
            {"interface": "Vlan10", "direction": "in", "acl": "web-in"},
        ],
    }

    batch = _acl_batch(acl)

    rulebases = _rulebases(batch)
    assert {props["name"] for props in rulebases.values()} == {"WEB-IN", "web-in"}
    by_name = {props["name"]: rb_uid for rb_uid, props in rulebases.items()}
    assert by_name["web-in"] == f"{SCOPE}:acl:web-in"
    assert by_name["WEB-IN"] == f"{SCOPE}:acl:{uid.exact_slug('WEB-IN')}"
    actions = {
        r.start_uid: n.props["action"]
        for r in batch.rels
        if r.rel_type == "HAS_RULE"
        for n in batch.nodes
        if n.uid == r.end_uid
    }
    assert actions == {by_name["WEB-IN"]: "deny", by_name["web-in"]: "permit"}
    assert _bindings(batch) == {
        (uid.interface(DEV, "Ethernet1/1"), by_name["WEB-IN"], "in"),
        (uid.interface(DEV, "Vlan10"), by_name["web-in"], "in"),
    }


def test_a_binding_to_an_unreported_interface_stays_on_the_rulebase():
    """The device did not report GigabitEthernet9/9/9, so there is no node to bind
    from; the binding is kept as `<interface> <direction>` on the rulebase, beside
    the edge of the binding that does have a node."""
    acl = {
        "lists": {"X": [_PERMIT_ANY_ACE]},
        "bindings": [
            {"interface": "Ethernet1/1", "direction": "in", "acl": "X"},
            {"interface": "GigabitEthernet9/9/9", "direction": "in", "acl": "X"},
            {"interface": "GigabitEthernet9/9/9", "direction": "out", "acl": "X"},
        ],
    }

    batch = _acl_batch(acl)

    rb_uid = f"{SCOPE}:acl:{uid.exact_slug('X')}"
    assert _rulebases(batch)[rb_uid]["unreported_bindings"] == [
        "GigabitEthernet9/9/9 in",
        "GigabitEthernet9/9/9 out",
    ]
    assert _bindings(batch) == {(uid.interface(DEV, "Ethernet1/1"), rb_uid, "in")}


def test_a_list_bound_only_to_reported_interfaces_carries_no_unreported_bindings():
    acl = {
        "lists": {"X": [_PERMIT_ANY_ACE]},
        "bindings": [{"interface": "Vlan10", "direction": "out", "acl": "X"}],
    }

    assert "unreported_bindings" not in next(iter(_rulebases(_acl_batch(acl)).values()))
