"""Strict local-zone policy uses explicit identities and complete tuples."""

from hst.collectors.vyos import normalize_vyos
from hst.path.addrsets import _intervals, _ports
from hst.path.gates import local_zone
from hst.path.gates.local_zone import LocalZoneTransition
from hst.path.state import FlowRegion

TCP = frozenset({6})


def _region(*, sport="1000-1001"):
    return FlowRegion.from_query(
        _intervals(["10.0.0.5"]),
        _intervals(["10.0.0.1"]),
        TCP,
        _ports("443"),
        _ports(sport),
    )


def _rb(uid="rb:lan-local", *, af=4, local=True):
    return {
        "rb_uid": uid,
        "rb_name": uid,
        "af": af,
        "default_action": "drop",
        "default_action_unknown": False,
        "global_state_policy": None,
        "src_uid": "zone:lan",
        "src_name": "LAN",
        "src_local": False,
        "dst_uid": "zone:local",
        "dst_name": "LOCAL",
        "dst_local": local,
    }


def _rule():
    return {
        "uid": "rule:ssh-reply",
        "pos": 1,
        "action": "accept",
        "name": "source-port",
        "out_if": None,
        "in_if": None,
        "out_if_group": None,
        "in_if_group": None,
        "states": [],
        "states_opaque": False,
        "src_any": True,
        "dst_any": True,
        "svc_any": False,
        "src_negate": False,
        "dst_negate": False,
        "svc_negate": False,
        "src_cidrs": [],
        "src_ips": [],
        "dst_cidrs": [],
        "dst_ips": [],
        "src_ranges": [],
        "dst_ranges": [],
        "protos": ["tcp"],
        "ports": ["443"],
        "src_ports": ["1000"],
        "svc_src_port": True,
        "src_obj_count": 0,
        "dst_obj_count": 0,
        "svc_obj_count": 1,
        "src_opaque": False,
        "dst_opaque": False,
        "svc_opaque": False,
    }


def _transition(monkeypatch, zones, rulebases, rules=(), owned_zones=None):
    if owned_zones is None:
        owned_zones = [
            {
                "zone_uid": "zone:lan",
                "zone_name": "LAN",
                "local_zone": False,
                "default_action": "drop",
                "default_action_unknown": False,
            },
            {
                "zone_uid": "zone:local",
                "zone_name": "LOCAL",
                "local_zone": True,
                "default_action": "drop",
                "default_action_unknown": False,
            },
        ]

    def read(_session, query, **_params):
        if query == local_zone._LOCAL_ZONE_CONTEXT_QUERY:
            return list(zones)
        if query == local_zone._OWNED_ZONES_QUERY:
            return list(owned_zones)
        if query == local_zone._LOCAL_ZONE_RULEBASES_QUERY:
            return list(rulebases)
        if query == local_zone._LOCAL_RULES_QUERY:
            return list(rules)
        raise AssertionError("unexpected query")

    monkeypatch.setattr(local_zone._path, "_read", read)
    return LocalZoneTransition(None, "dev:r1", "if:lan", None, "input", "new")


def test_device_without_zone_policy_explicitly_passes(monkeypatch):
    gate = _transition(monkeypatch, [], [], owned_zones=[])
    assert gate.apply(_region())[0][1].kind == "pass"


def test_fully_collected_nonlocal_zones_pass_local_hop(monkeypatch):
    ordinary = [{"zone_uid": "zone:lan", "local_zone": False}]
    gate = _transition(monkeypatch, [], [], owned_zones=ordinary)
    assert gate.apply(_region())[0][1].kind == "pass"


def test_unmarked_local_zone_is_unknown_without_structural_guess(monkeypatch):
    gate = _transition(
        monkeypatch,
        [
            {
                "if_uid": "if:lan",
                "if_name": "eth1",
                "zone_uid": "zone:lan",
                "zone_name": "LAN",
            }
        ],
        [_rb(local=None)],
        owned_zones=[{"zone_uid": "zone:local", "local_zone": None}],
    )
    out = gate.apply(_region())
    assert out[0][1].kind == "indeterminate"
    assert "lack a collected local-zone marker" in out[0][1].reason


def test_explicit_local_zone_partitions_source_port_first_match(monkeypatch):
    gate = _transition(
        monkeypatch,
        [
            {
                "if_uid": "if:lan",
                "if_name": "eth1",
                "zone_uid": "zone:lan",
                "zone_name": "LAN",
            }
        ],
        [_rb()],
        [_rule()],
    )
    out = gate.apply(_region())
    by_sport = {region.rects[0].sport: effect for region, effect in out}

    assert by_sport[tuple(_ports("1000"))].kind == "permit"
    assert by_sport[tuple(_ports("1001"))].kind == "deny"
    assert by_sport[tuple(_ports("1001"))].terminal
    assert gate.considered_ids == ["rb:lan-local"]
    assert all(effect.data["rb_uid"] == "rb:lan-local" for effect in by_sport.values())


def test_other_pair_and_address_family_are_exact_exclusions(monkeypatch):
    other_pair = {**_rb("rb:guest-local"), "src_uid": "zone:guest", "src_name": "GUEST"}
    gate = _transition(
        monkeypatch,
        [
            {
                "if_uid": "if:lan",
                "if_name": "eth1",
                "zone_uid": "zone:lan",
                "zone_name": "LAN",
            }
        ],
        [_rb(), _rb("rb:lan-local-v6", af=6), other_pair],
        [_rule()],
    )
    effects = [effect for _region_, effect in gate.apply(_region())]
    assert gate.excluded_ids == ["rb:guest-local", "rb:lan-local-v6"]
    assert effects[0].data["excluded_ids"] == ["rb:guest-local", "rb:lan-local-v6"]


def test_multiple_interface_zone_identities_are_unknown(monkeypatch):
    zones = [
        {"if_uid": "if:lan", "if_name": "eth1", "zone_uid": "zone:lan", "zone_name": "LAN"},
        {
            "if_uid": "if:lan",
            "if_name": "eth1",
            "zone_uid": "zone:guest",
            "zone_name": "GUEST",
        },
    ]
    out = _transition(monkeypatch, zones, [_rb()]).apply(_region())
    assert out[0][1].kind == "indeterminate"
    assert "multiple zone identities" in out[0][1].reason


def test_unbound_input_pair_uses_explicit_local_zone_default(monkeypatch):
    gate = _transition(
        monkeypatch,
        [{"if_uid": "if:lan", "if_name": "eth1", "zone_uid": "zone:lan"}],
        [],
    )
    effect = gate.apply(_region())[0][1]
    assert effect.kind == "deny"
    assert effect.terminal
    assert effect.data["by"] == "zone-default"
    assert effect.data["zone_uid"] == "zone:local"


def test_vyos_normalizer_records_local_zone_presence_and_device_ownership():
    batch = normalize_vyos(
        {
            "config": {
                "system": {"host-name": "edge"},
                "firewall": {
                    "zone": {
                        "LOCAL": {"local-zone": "", "default-action": "drop"},
                        "LAN": {},
                    }
                },
            },
            "version_text": "Hardware S/N:     ZONE123\n",
        },
        l3dom="dc1",
    )
    zones = {node.props["name"]: node for node in batch.nodes if node.label == "Zone"}
    assert zones["LOCAL"].props["local_zone"] is True
    assert zones["LAN"].props["local_zone"] is False
    owned = [rel for rel in batch.rels if rel.rel_type == "OWNED_BY" and rel.start_label == "Zone"]
    assert {rel.start_uid for rel in owned} == {zones["LOCAL"].uid, zones["LAN"].uid}


def _source_rule(uid, pos, action, src_cidrs):
    return {
        **_rule(),
        "uid": uid,
        "pos": pos,
        "action": action,
        "src_any": not src_cidrs,
        "src_cidrs": list(src_cidrs),
        "src_obj_count": 1 if src_cidrs else 0,
        "svc_any": True,
        "protos": [],
        "ports": [],
        "src_ports": [],
        "svc_src_port": False,
        "svc_obj_count": 0,
    }


def _prefix_region():
    return FlowRegion.from_query(
        _intervals(["10.0.1.0/24"]), _intervals(["10.0.0.1"]), TCP, _ports("22"), None
    )


def _half_rules():
    return [
        _source_rule("rule:half", 10, "accept", ["10.0.1.0/25"]),
        _source_rule("rule:rest", 20, "drop", []),
    ]


def _lan_zone():
    return [{"if_uid": "if:lan", "if_name": "eth1", "zone_uid": "zone:lan", "zone_name": "LAN"}]


def test_a_rule_that_hits_part_of_the_source_leaves_the_whole_rectangle_undecided(monkeypatch):
    gate = _transition(monkeypatch, _lan_zone(), [_rb()], _half_rules())
    region = _prefix_region()
    out = gate.apply(region)

    # nothing of the rectangle is dropped: the part rule 10 does not cover is answered too
    assert [part.rects[0].src for part, _effect in out] == [region.rects[0].src]
    (effect,) = [effect for _part, effect in out]
    assert effect.kind == "indeterminate" and effect.data["partial"]
    assert effect.data["rb_uid"] == "rb:lan-local"


def test_the_address_filter_refines_a_partial_local_zone_hit(monkeypatch):
    from hst.impact.evaluate import _AddressFilter
    from hst.path.gates.firewall import _RULEBASE_RULES

    rules = _half_rules()
    _transition(monkeypatch, _lan_zone(), [_rb()], rules)
    inner = local_zone._path._read

    def read(session, query, **params):
        if query == _RULEBASE_RULES:
            return list(rules)
        return inner(session, query, **params)

    monkeypatch.setattr(local_zone._path, "_read", read)
    gate = LocalZoneTransition(None, "dev:r1", "if:lan", None, "input", "new")
    out = _AddressFilter(None, gate).apply(_prefix_region())

    by_src = {part.rects[0].src: effect.kind for part, effect in out}
    assert by_src == {
        tuple(_intervals(["10.0.1.0/25"])): "permit",
        tuple(_intervals(["10.0.1.128/25"])): "deny",
    }


def test_output_fall_through_is_decided_only_where_both_zone_defaults_agree(monkeypatch):
    zones = [{"if_uid": "if:wan", "if_name": "eth0", "zone_uid": "zone:wan", "zone_name": "WAN"}]

    def owned(wan_default):
        return [
            {"zone_uid": "zone:wan", "zone_name": "WAN", "local_zone": False,
             "default_action": wan_default, "default_action_unknown": False},
            {"zone_uid": "zone:local", "zone_name": "LOCAL", "local_zone": True,
             "default_action": "drop", "default_action_unknown": False},
        ]  # fmt: skip

    region = FlowRegion.from_query(_intervals(["10.0.0.1"]), _intervals(["192.0.2.1"]), TCP, _ports("443"))
    for wan_default, kind in (("drop", "deny"), ("accept", "indeterminate")):
        _transition(monkeypatch, zones, [], owned_zones=owned(wan_default))
        gate = LocalZoneTransition(None, "dev:r1", None, "if:wan", "output", "new")
        (effect,) = [effect for _part, effect in gate.apply(region)]
        assert effect.kind == kind, wan_default


def _scoped_rules(scope):
    return [
        {**_source_rule("rule:scoped", 10, "drop", []), "in_if": scope},
        _source_rule("rule:rest", 20, "accept", []),
    ]


def _one_host_region():
    return FlowRegion.from_query(_intervals(["10.0.1.5"]), _intervals(["10.0.0.1"]), TCP, _ports("22"), None)


def _zone_named(name):
    return [{"if_uid": "if:lan", "if_name": name, "zone_uid": "zone:lan", "zone_name": "LAN"}]


def test_an_inbound_scoped_rule_on_an_ingress_with_no_name_is_undecided(monkeypatch):
    gate = _transition(monkeypatch, _zone_named(None), [_rb()], _scoped_rules("eth1"))
    (effect,) = [effect for _part, effect in gate.apply(_one_host_region())]
    assert effect.kind == "indeterminate"
    assert effect.data["rule_pos"] == 10
    assert "ingress interface name did not resolve" in effect.reason


def test_an_inbound_scoped_rule_with_a_resolved_name_is_decided(monkeypatch):
    hit = _transition(monkeypatch, _zone_named("eth1"), [_rb()], _scoped_rules("eth1"))
    assert [(e.kind, e.data["rule_pos"]) for _p, e in hit.apply(_one_host_region())] == [("deny", 10)]
    miss = _transition(monkeypatch, _zone_named("eth1"), [_rb()], _scoped_rules("eth2"))
    assert [(e.kind, e.data["rule_pos"]) for _p, e in miss.apply(_one_host_region())] == [("permit", 20)]


def test_an_unscoped_rule_set_decides_whatever_the_interface_name(monkeypatch):
    gate = _transition(monkeypatch, _zone_named(None), [_rb()], [_source_rule("rule:any", 10, "accept", [])])
    assert [(e.kind, e.data["rule_pos"]) for _p, e in gate.apply(_one_host_region())] == [("permit", 10)]
