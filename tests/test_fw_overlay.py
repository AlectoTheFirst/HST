"""The tests cover the policy change overlay (`hst.simul.fw_overlay`) without a database."""

from typing import Any

import pytest
from tests.support.query_text import unpinned

from hst.path import INDETERMINATE, classify_action
from hst.path.gates.firewall import (
    _RULEBASE_RULES,
    _device_rulebase_verdict,
    _first_match,
    _zone_pair_verdict,
)
from hst.simul.fw_overlay import (
    Catalog,
    ChangeSet,
    ProposalError,
    compare_paths,
    parse_intents,
    path_rows,
)

# --- fakes ----------------------------------------------------------------


class _Result:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def data(self) -> list[dict[str, Any]]:
        return self._rows


class _Tx:
    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers

    def run(self, query: str, **params: Any) -> _Result:
        query = unpinned(query)
        for fragment, rows in self.answers.items():
            if fragment in query:
                return _Result(rows(params) if callable(rows) else list(rows))
        return _Result([])


class _Session:
    """A session the real `_read` can drive: `execute_read` runs the unit of
    work against a fake transaction."""

    def __init__(self, answers: dict[str, Any], cts: int | None = None) -> None:
        self.answers = answers
        if cts is not None:
            self.cts = cts

    def execute_read(self, work: Any, /) -> Any:
        return work(_Tx(self.answers))


class _Overlaid(_Session):
    def __init__(self, answers: dict[str, Any], changes: ChangeSet) -> None:
        super().__init__(answers)
        self._changes = changes

    def overlay(self, query: str, params: dict[str, Any], rows: Any) -> Any:
        return self._changes.rewrite(query, params, rows)


def rule(uid: str, pos: int, action: str, **over: Any) -> dict[str, Any]:
    row = {
        "uid": uid,
        "pos": pos,
        "action": action,
        "name": None,
        "out_if": None,
        "in_if": None,
        "src_any": True,
        "dst_any": True,
        "svc_any": True,
        "src_cidrs": [],
        "src_ips": [],
        "dst_cidrs": [],
        "dst_ips": [],
        "protos": [],
        "ports": [],
        "src_ranges": [],
        "dst_ranges": [],
    }
    row.update(over)
    return row


def changeset(intents: list[dict[str, Any]], catalog: Catalog | None = None, **kw: Any) -> ChangeSet:
    cat = catalog or Catalog()
    return ChangeSet(intents=parse_intents(intents, cat), catalog=cat, **kw)


DENY_TWO_HOSTS = {
    "kind": "fw_rule.add",
    "params": {
        "rulebase": "fw:LAN",
        "position": 10,
        "action": "drop",
        "source": "any",
        "destination": ["192.168.2.35", "192.168.2.36"],
        "name": "block the two hosts",
    },
}


# --- rewriting ------------------------------------------------------------


def test_a_proposed_rule_is_placed_ahead_of_the_first_rule_at_its_position():
    rows = [rule("r:20", 20, "accept"), rule("r:30", 30, "accept")]
    out = changeset([{**DENY_TWO_HOSTS, "params": {**DENY_TWO_HOSTS["params"], "position": 25}}]).rewrite(
        _RULEBASE_RULES, {"rb": "fw:LAN"}, rows
    )
    assert [r["uid"] for r in out] == ["r:20", "fw:rule:proposed:0", "r:30"]
    # the collected rules keep the positions a verdict would cite
    assert [r["pos"] for r in out] == [20, 25, 30]


def test_a_rule_proposed_past_every_position_goes_last():
    rows = [rule("r:20", 20, "accept")]
    out = changeset([{**DENY_TWO_HOSTS, "params": {**DENY_TWO_HOSTS["params"], "position": 900}}]).rewrite(
        _RULEBASE_RULES, {"rb": "fw:LAN"}, rows
    )
    assert [r["uid"] for r in out] == ["r:20", "fw:rule:proposed:0"]


def test_a_change_set_for_another_rulebase_leaves_this_one_alone():
    rows = [rule("r:20", 20, "accept")]
    out = changeset([DENY_TWO_HOSTS]).rewrite(_RULEBASE_RULES, {"rb": "fw:OTHER"}, rows)
    assert [r["uid"] for r in out] == ["r:20"]


def test_a_query_the_overlay_does_not_name_is_returned_untouched():
    rows = [{"anything": 1}]
    assert changeset([DENY_TWO_HOSTS]).rewrite("MATCH (d:Device) RETURN d", {}, rows) is rows


def test_more_than_one_rule_and_more_than_one_rulebase_in_one_set():
    changes = changeset(
        [
            DENY_TWO_HOSTS,
            {
                "kind": "fw_rule.add",
                "params": {
                    "rulebase": "fw:WAN",
                    "position": 5,
                    "action": "accept",
                    "source": "10.0.0.0/8",
                    "destination": "any",
                },
            },
        ]
    )
    lan = changes.rewrite(_RULEBASE_RULES, {"rb": "fw:LAN"}, [rule("r:20", 20, "accept")])
    wan = changes.rewrite(_RULEBASE_RULES, {"rb": "fw:WAN"}, [rule("w:20", 20, "drop")])
    assert [r["uid"] for r in lan] == ["fw:rule:proposed:0", "r:20"]
    assert [r["uid"] for r in wan] == ["fw:rule:proposed:1", "w:20"]


def test_a_rule_can_be_removed_and_another_modified_in_the_same_set():
    rows = [rule("r:10", 10, "accept"), rule("r:20", 20, "accept")]
    changes = changeset(
        [
            {"kind": "fw_rule.remove", "params": {"rulebase": "fw:LAN", "rule": "r:10"}},
            {"kind": "fw_rule.modify", "params": {"rulebase": "fw:LAN", "rule": "r:20", "action": "drop"}},
        ]
    )
    out = changes.rewrite(_RULEBASE_RULES, {"rb": "fw:LAN"}, rows)
    assert [(r["uid"], r["action"]) for r in out] == [("r:20", "drop")]


def test_disabling_a_rule_takes_it_out_of_the_list():
    rows = [rule("r:10", 10, "accept")]
    changes = changeset(
        [{"kind": "fw_rule.modify", "params": {"rulebase": "fw:LAN", "rule": "r:10", "enabled": False}}]
    )
    assert changes.rewrite(_RULEBASE_RULES, {"rb": "fw:LAN"}, rows) == []


def test_a_rule_named_for_change_that_the_rulebase_does_not_hold_is_refused():
    changes = changeset([{"kind": "fw_rule.remove", "params": {"rulebase": "fw:LAN", "rule": "r:99"}}])
    with pytest.raises(ProposalError, match="holds no enabled FwRule"):
        changes.rewrite(_RULEBASE_RULES, {"rb": "fw:LAN"}, [rule("r:10", 10, "accept")])


# --- match values ---------------------------------------------------------


CATALOG = Catalog(
    net_objects={
        "no:inner": {"uid": "no:inner", "name": "INNER", "addrs": ["10.1.0.0/24"], "members": []},
        "no:outer": {
            "uid": "no:outer",
            "name": "SERVERS",
            "addrs": ["10.2.0.5"],
            "members": ["no:inner"],
        },
        "no:cycle_a": {"uid": "no:cycle_a", "name": "A", "addrs": ["10.9.0.1"], "members": ["no:cycle_b"]},
        "no:cycle_b": {"uid": "no:cycle_b", "name": "B", "addrs": ["10.9.0.2"], "members": ["no:cycle_a"]},
        "no:empty": {"uid": "no:empty", "name": "FQDN-ONLY", "addrs": [], "members": []},
    },
    svc_objects={"so:web": {"uid": "so:web", "name": "WEB", "protos": ["tcp"], "ports": ["80,443"]}},
    zones={
        "zone:lan": {"uid": "zone:lan", "name": "LAN", "interfaces": ["eth0", "eth1"]},
        "zone:empty": {"uid": "zone:empty", "name": "DMZ", "interfaces": []},
    },
)


def _one_added_row(params: dict[str, Any], catalog: Catalog = CATALOG) -> list[dict[str, Any]]:
    changes = changeset([{"kind": "fw_rule.add", "params": params}], catalog)
    return changes.rewrite(_RULEBASE_RULES, {"rb": "fw:LAN"}, [])


def test_a_netobject_group_resolves_through_its_nested_members():
    rows = _one_added_row(
        {"rulebase": "fw:LAN", "position": 10, "action": "drop", "source": "any", "destination": "SERVERS"}
    )
    assert sorted(rows[0]["dst_cidrs"]) == ["10.1.0.0/24", "10.2.0.5"]


def test_a_membership_cycle_is_cut_rather_than_followed():
    rows = _one_added_row(
        {"rulebase": "fw:LAN", "position": 10, "action": "drop", "source": "any", "destination": "no:cycle_a"}
    )
    assert sorted(rows[0]["dst_cidrs"]) == ["10.9.0.1", "10.9.0.2"]


def test_a_group_that_resolves_to_no_address_is_refused_rather_than_matched_as_empty():
    with pytest.raises(ProposalError, match="resolves to no address"):
        _one_added_row(
            {
                "rulebase": "fw:LAN",
                "position": 10,
                "action": "drop",
                "source": "any",
                "destination": "FQDN-ONLY",
            }
        )


def test_an_unknown_match_value_is_refused_rather_than_evaluated_as_indeterminate():
    with pytest.raises(ProposalError, match="neither an address"):
        _one_added_row(
            {"rulebase": "fw:LAN", "position": 10, "action": "drop", "source": "any", "destination": "nope"}
        )


def test_a_svcobject_supplies_the_rules_protocols_and_ports():
    rows = _one_added_row(
        {
            "rulebase": "fw:LAN",
            "position": 10,
            "action": "drop",
            "source": "any",
            "destination": "any",
            "services": "WEB",
        }
    )
    assert rows[0]["protos"] == ["tcp"] and rows[0]["ports"] == ["80,443"]
    assert rows[0]["svc_any"] is False


def test_a_zone_scoped_proposal_becomes_one_row_per_interface_at_the_same_position():
    rows = _one_added_row(
        {
            "rulebase": "fw:LAN",
            "position": 10,
            "action": "drop",
            "source": "any",
            "destination": "any",
            "from_zone": "LAN",
        }
    )
    assert [r["in_if"] for r in rows] == ["eth0", "eth1"]
    assert {r["pos"] for r in rows} == {10}


def test_a_zone_with_no_interface_is_refused():
    with pytest.raises(ProposalError, match="contains no Interface"):
        _one_added_row(
            {
                "rulebase": "fw:LAN",
                "position": 10,
                "action": "drop",
                "source": "any",
                "destination": "any",
                "from_zone": "DMZ",
            }
        )


def test_an_action_the_tracer_would_not_classify_is_refused():
    with pytest.raises(ProposalError, match="not a proposable firewall action"):
        _one_added_row({"rulebase": "fw:LAN", "position": 10, "action": "redirect-layer"})


def test_an_intent_kind_outside_the_catalog_is_refused_by_name():
    with pytest.raises(ProposalError, match="policy overlay does not express"):
        parse_intents([{"kind": "route_policy.attach", "params": {}}], Catalog())


# --- NAT ------------------------------------------------------------------


def _nat_row(uid: str, pos: int, **over: Any) -> dict[str, Any]:
    row = {"uid": uid, "pos": pos, "rb_uid": "fw:nat", "rb_name": "NAT", "kind": "snat", "enabled": True}
    row.update(over)
    return row


NAT_QUERY = "MATCH (rb)-[hr:HAS_RULE]->(n:NatRule)"


def test_a_proposed_nat_rule_joins_the_devices_rulebase_in_position_order():
    changes = changeset(
        [
            {
                "kind": "nat_rule.add",
                "params": {
                    "device": "dev:fw1",
                    "position": 5,
                    "kind": "snat",
                    "orig_src": "10.0.0.0/24",
                    "translation": "masquerade",
                },
            }
        ]
    )
    out = changes.rewrite(NAT_QUERY, {"dev": "dev:fw1"}, [_nat_row("nat:10", 10)])
    assert [r["uid"] for r in out] == ["nat:rule:proposed:0", "nat:10"]
    added = out[0]
    assert added["rb_uid"] == "fw:nat" and added["orig_src_addrs"] == ["10.0.0.0/24"]
    # `_nat_match_set` prefers the raw config column over the resolved addresses
    assert added["orig_src_raw"] is None
    assert added["translation"] == "masquerade"


def test_a_nat_rule_can_be_removed_and_a_nat_rule_on_another_device_is_untouched():
    changes = changeset([{"kind": "nat_rule.remove", "params": {"device": "dev:fw1", "rule": "nat:10"}}])
    assert changes.rewrite(NAT_QUERY, {"dev": "dev:fw1"}, [_nat_row("nat:10", 10)]) == []
    kept = changes.rewrite(NAT_QUERY, {"dev": "dev:fw2"}, [_nat_row("nat:10", 10)])
    assert [r["uid"] for r in kept] == ["nat:10"]


def test_restating_a_nat_match_column_clears_the_raw_string_it_would_lose_to():
    changes = changeset(
        [
            {
                "kind": "nat_rule.modify",
                "params": {"device": "dev:fw1", "rule": "nat:10", "orig_src": "10.5.0.0/24"},
            }
        ]
    )
    out = changes.rewrite(NAT_QUERY, {"dev": "dev:fw1"}, [_nat_row("nat:10", 10, orig_src_raw="10.0.0.0/24")])
    assert out[0]["orig_src_addrs"] == ["10.5.0.0/24"] and out[0]["orig_src_raw"] is None


def _modify(rows: list[dict[str, Any]], **params: Any) -> dict[str, Any]:
    intent = {"kind": "nat_rule.modify", "params": {"device": "dev:fw1", "rule": "nat:10", **params}}
    (out,) = changeset([intent]).rewrite(NAT_QUERY, {"dev": "dev:fw1"}, rows)
    return out


def test_restating_the_translated_side_a_vyos_rule_reads_from_translation_takes_effect():
    """Restating the translated side clears `translation`."""
    from hst.path.addrsets import _intervals
    from hst.path.gates.nat import _nat_row_sets

    snat = _nat_row("nat:10", 10, translation="203.0.113.5", xlate_src_addrs=["203.0.113.5"])
    out = _modify([snat], xlate_src="203.0.113.9")
    assert out["translation"] is None and out["xlate_src_addrs"] == ["203.0.113.9"]
    assert _nat_row_sets(out, "snat")[2] == _intervals(["203.0.113.9"])
    # the side the kind does not read from `translation` leaves it alone: a
    # dnat rule's translation is its destination
    dnat = _nat_row("nat:10", 10, kind="dnat", translation="10.0.0.5", xlate_dst_addrs=["10.0.0.5"])
    out = _modify([dnat], xlate_src="203.0.113.9")
    assert out["translation"] == "10.0.0.5"
    assert _nat_row_sets(out, "dnat")[3] == _intervals(["10.0.0.5"])


def test_restating_an_original_side_as_any_leaves_the_rule_decidable():
    from hst.path.gates.nat import _nat_base_rule

    row = _nat_row(
        "nat:10",
        10,
        orig_src_present=True,
        orig_src_raw="10.0.0.0/24",
        translation="masquerade",
        exclude=False,
        protocol=None,
    )
    out = _modify([row], orig_src="any")
    assert out["orig_src_present"] is False and out["orig_src_raw"] is None
    assert _nat_base_rule(out, "snat", False, [], [])["opaque"] is False


def test_a_nat_modify_applies_kind_and_exclude():
    out = _modify([_nat_row("nat:10", 10)], kind="static", exclude=True)
    assert (out["kind"], out["static_flag"], out["exclude"]) == ("static", True, True)
    with pytest.raises(ProposalError, match="not proposable"):
        _modify([_nat_row("nat:10", 10)], kind="twice-nat")
    # a kind that moves the raw translation to the other side must restate it
    with pytest.raises(ProposalError, match="restate xlate_dst"):
        _modify([_nat_row("nat:10", 10, translation="203.0.113.5")], kind="dnat")
    out = _modify([_nat_row("nat:10", 10, translation="203.0.113.5")], kind="dnat", xlate_dst="10.0.0.7")
    assert out["translation"] is None and out["xlate_dst_addrs"] == ["10.0.0.7"]


def test_a_nat_modify_refuses_a_position_and_an_empty_change():
    for params in ({"position": 5}, {}):
        with pytest.raises(ProposalError):
            changeset(
                [{"kind": "nat_rule.modify", "params": {"device": "dev:fw1", "rule": "nat:10", **params}}]
            )


def test_a_nat_kind_the_tracer_cannot_direction_resolve_is_refused():
    with pytest.raises(ProposalError, match="not proposable"):
        changeset(
            [{"kind": "nat_rule.add", "params": {"device": "dev:fw1", "position": 5, "kind": "twice-nat"}}]
        )


# --- zones ----------------------------------------------------------------

ZONE_PAIR_QUERY = "MATCH (rb:FwRulebase)-[fz:FROM_ZONE]->(src), (rb)-[tz:TO_ZONE]->(dst)"
INGRESS_ZONE_QUERY = "RETURN z.name AS name"


def test_moving_an_interface_into_a_zone_re_reads_the_pair_it_forms():
    asked: list[tuple[str, str]] = []

    def pair_rows(src: str, dst: str) -> list[dict[str, Any]]:
        asked.append((src, dst))
        return [{"rb_uid": "fw:DMZ-to-WAN", "rb_name": "DMZ→WAN"}]

    changes = changeset(
        [{"kind": "zone.add_interface", "params": {"zone": "zone:empty", "interface": "if:eth9"}}],
        CATALOG,
        zone_of=lambda iface: {"if:eth8": "zone:lan"}.get(iface),
        pair_rows=pair_rows,
    )
    out = changes.rewrite(
        ZONE_PAIR_QUERY, {"in_if": "if:eth9", "out_if": "if:eth8"}, [{"rb_uid": "fw:collected"}]
    )
    assert asked == [("zone:empty", "zone:lan")]
    assert [r["rb_uid"] for r in out] == ["fw:DMZ-to-WAN"]


def test_a_flow_through_no_interface_the_change_moved_reads_the_collected_pair():
    changes = changeset(
        [{"kind": "zone.add_interface", "params": {"zone": "zone:lan", "interface": "if:eth9"}}],
        CATALOG,
        zone_of=lambda iface: None,
        pair_rows=lambda src, dst: [],
    )
    rows = [{"rb_uid": "fw:collected"}]
    assert changes.rewrite(ZONE_PAIR_QUERY, {"in_if": "if:a", "out_if": "if:b"}, rows) == rows


def test_taking_an_interface_out_of_its_only_zone_leaves_the_flow_with_no_zone_pair():
    changes = changeset(
        [{"kind": "zone.remove_interface", "params": {"zone": "zone:lan", "interface": "if:eth0"}}],
        CATALOG,
        zone_of=lambda iface: "zone:lan",
        pair_rows=lambda src, dst: [{"rb_uid": "fw:pair"}],
    )
    out = changes.rewrite(
        ZONE_PAIR_QUERY, {"in_if": "if:eth0", "out_if": "if:eth1"}, [{"rb_uid": "fw:collected"}]
    )
    assert out == []


def test_the_ingress_zone_note_follows_the_move():
    changes = changeset(
        [{"kind": "zone.add_interface", "params": {"zone": "zone:lan", "interface": "if:eth9"}}],
        CATALOG,
    )
    out = changes.rewrite(INGRESS_ZONE_QUERY, {"in_if": "if:eth9"}, [{"name": "OLD"}])
    assert out == [{"name": "LAN"}]


def test_moving_into_a_zone_with_no_recorded_default_is_indeterminate_at_fall_through():
    """The moved-in zone row holds the zone's default-action columns (`_rewrite_ingress_zone`)."""
    catalog = Catalog(
        zones={
            "zone:lan": {
                "uid": "zone:lan",
                "name": "LAN",
                "default_action": "drop",
                "default_action_unknown": False,
                "interfaces": ["eth0"],
            },
            "zone:new": {
                "uid": "zone:new",
                "name": "NEW",
                "default_action": None,
                "default_action_unknown": True,
                "interfaces": [],
            },
        }
    )
    changes = changeset(
        [{"kind": "zone.add_interface", "params": {"zone": "zone:new", "interface": "if:eth9"}}],
        catalog,
        zone_of=lambda iface: {"if:eth0": "zone:lan"}.get(iface),
        pair_rows=lambda src, dst: [],
    )

    def ingress_zone_row(params: dict[str, Any]) -> list[dict[str, Any]]:
        if params["in_if"] == "if:eth0":
            return [{"name": "LAN", "default_action": "drop", "default_action_unknown": False}]
        return [{"name": "OLD", "default_action": None, "default_action_unknown": False}]

    answers = {ZONE_PAIR_QUERY: [], INGRESS_ZONE_QUERY: ingress_zone_row}
    v = _zone_pair_verdict(_Overlaid(answers, changes), "if:eth0", "if:eth9", _SRC, _DST, 443, "tcp", 4)
    assert v is not None
    assert classify_action(v["action"]) == INDETERMINATE


def _unreported_state_rules_catalog(marked: bool) -> Catalog:
    """LAN, and a NEW zone with a recorded drop default whose
    connection-state rules the collection did not report when `marked` (the
    UniFi zone marker, `established_default_unknown`)."""
    return Catalog(
        zones={
            "zone:lan": {
                "uid": "zone:lan",
                "name": "LAN",
                "default_action": "drop",
                "default_action_unknown": False,
                "established_default_unknown": False,
                "interfaces": ["eth0"],
            },
            "zone:new": {
                "uid": "zone:new",
                "name": "NEW",
                "default_action": "drop",
                "default_action_unknown": False,
                "established_default_unknown": marked,
                "interfaces": [],
            },
        }
    )


def _moved_reply_verdict(catalog: Catalog, conn_state: str) -> Any:
    changes = changeset(
        [{"kind": "zone.add_interface", "params": {"zone": "zone:new", "interface": "if:eth9"}}],
        catalog,
        zone_of=lambda iface: {"if:eth0": "zone:lan"}.get(iface),
        pair_rows=lambda src, dst: [],
    )

    def zone_row(params: dict[str, Any]) -> list[dict[str, Any]]:
        if params["in_if"] == "if:eth0":
            return [{"name": "LAN", "default_action": "drop", "default_action_unknown": False}]
        return [{"name": "OLD", "default_action": "drop", "default_action_unknown": False}]

    answers = {ZONE_PAIR_QUERY: [], INGRESS_ZONE_QUERY: zone_row}
    return _zone_pair_verdict(
        _Overlaid(answers, changes), "if:eth0", "if:eth9", _SRC, _DST, 443, "tcp", 4, conn_state=conn_state
    )


def test_the_moved_in_zone_row_carries_the_unreported_state_rules_marker():
    changes = changeset(
        [{"kind": "zone.add_interface", "params": {"zone": "zone:new", "interface": "if:eth9"}}],
        _unreported_state_rules_catalog(marked=True),
    )
    out = changes.rewrite(INGRESS_ZONE_QUERY, {"in_if": "if:eth9"}, [{"name": "OLD"}])
    assert out == [
        {
            "name": "NEW",
            "default_action": "drop",
            "default_action_unknown": False,
            "established_default_unknown": True,
        }
    ]


def test_a_reply_into_a_moved_in_zone_with_unreported_state_rules_is_undecided_as_the_tracer_reads_it():
    """A new flow takes the recorded drop."""
    marked = _unreported_state_rules_catalog(marked=True)
    reply = _moved_reply_verdict(marked, "established")
    assert reply is not None
    assert classify_action(reply["action"]) == INDETERMINATE

    collected = {
        ZONE_PAIR_QUERY: [],
        INGRESS_ZONE_QUERY: lambda params: [
            {
                "name": "LAN" if params["in_if"] == "if:eth0" else "NEW",
                "default_action": "drop",
                "default_action_unknown": False,
                "established_default_unknown": params["in_if"] != "if:eth0",
            }
        ],
    }
    traced = _zone_pair_verdict(
        _Session(collected), "if:eth0", "if:eth9", _SRC, _DST, 443, "tcp", 4, conn_state="established"
    )
    assert traced is not None
    assert (reply["action"], reply["indeterminate_reason"]) == (
        traced["action"],
        traced["indeterminate_reason"],
    )

    fresh = _moved_reply_verdict(marked, "new")
    assert fresh is not None and fresh["action"] == "drop"
    unmarked = _moved_reply_verdict(_unreported_state_rules_catalog(marked=False), "established")
    assert unmarked is not None and unmarked["action"] == "drop"


def test_a_zone_move_without_a_lookup_says_so():
    changes = changeset(
        [{"kind": "zone.add_interface", "params": {"zone": "zone:lan", "interface": "if:eth9"}}],
        CATALOG,
    )
    rows = [{"rb_uid": "fw:collected"}]
    assert changes.rewrite(ZONE_PAIR_QUERY, {"in_if": "if:eth9", "out_if": "if:eth8"}, rows) == rows
    assert [e["kind"] for e in changes.errors.as_dicts()] == ["zone-move-not-resolvable"]


# --- the tracer's own gate, over the overlaid rows -------------------------

_ANSWERS: dict[str, Any] = {
    "MATCH (dev:Device {uid: $dev})-[e:ENFORCES]->(rb:FwRulebase)": [
        {
            "rb_uid": "fw:LAN",
            "rb_name": "LAN policy",
            "vendor": "vyos",
            "af": None,
            "default_action": "drop",
            "approximate": False,
        }
    ],
    "MATCH (i:Interface) WHERE i.uid IN [$a, $b]": [],
    "(rb:FwRulebase {uid: $rb})-[hr:HAS_RULE]->(r:FwRule)": [rule("r:100", 100, "accept")],
}

_SRC = [(4, 0x0A000005, 0x0A000005)]  # 10.0.0.5
_DST = [(4, 0xC0A80223, 0xC0A80223)]  # 192.168.2.35


def _verdict(session: Any) -> dict[str, Any]:
    return _device_rulebase_verdict(session, "dev:fw1", "if:in", "if:out", _SRC, _DST, 443, "tcp", 4)


def test_the_tracers_own_gate_reads_the_collected_rules_without_an_overlay():
    got = _verdict(_Session(_ANSWERS))
    assert (got["action"], got["pos"], got["rule_uid"]) == ("accept", 100, "r:100")


def test_the_tracers_own_gate_decides_by_the_proposed_rule_once_it_is_overlaid():
    """`_device_rulebase_verdict` is unaware of the overlay."""
    changes = changeset([DENY_TWO_HOSTS])
    got = _verdict(_Overlaid(_ANSWERS, changes))
    assert got["action"] == "drop"
    assert got["pos"] == 10
    assert got["rule_uid"] == "fw:rule:proposed:0"


def test_a_flow_the_proposed_rule_does_not_cover_keeps_its_collected_verdict():
    changes = changeset([DENY_TWO_HOSTS])
    other = [(4, 0xC0A80230, 0xC0A80230)]  # 192.168.2.48
    got = _device_rulebase_verdict(
        _Overlaid(_ANSWERS, changes), "dev:fw1", "if:in", "if:out", _SRC, other, 443, "tcp", 4
    )
    assert (got["action"], got["rule_uid"]) == ("accept", "r:100")


def test_a_session_without_an_overlay_reads_the_collected_rules():
    """The hook is per session object."""
    plain, overlaid = _Session(_ANSWERS), _Overlaid(_ANSWERS, changeset([DENY_TWO_HOSTS]))
    assert _verdict(overlaid)["action"] == "drop"
    assert _verdict(plain)["action"] == "accept"


def test_a_restated_side_drops_the_collected_rows_opacity_and_negation():
    """A modify states a side in full."""
    collected = rule(
        "r:100",
        100,
        "accept",
        src_any=False,
        src_cidrs=[],
        src_obj_count=1,
        src_opaque=True,
        src_negate=True,
        src_opaque_reasons=["an access-role identifies users, not addresses"],
    )
    answers = {**_ANSWERS, "(rb:FwRulebase {uid: $rb})-[hr:HAS_RULE]->(r:FwRule)": [collected]}
    changes = changeset(
        [
            {
                "kind": "fw_rule.modify",
                "params": {"rulebase": "fw:LAN", "rule": "r:100", "source": "10.0.0.0/24"},
            }
        ]
    )
    got = _verdict(_Overlaid(answers, changes))
    assert (got["action"], got["rule_uid"], got["by"]) == ("accept", "r:100", "rule")


def test_a_restated_destination_drops_the_collected_rows_opacity_and_negation():
    collected = rule(
        "r:100",
        100,
        "accept",
        dst_any=False,
        dst_cidrs=[],
        dst_obj_count=1,
        dst_opaque=True,
        dst_negate=True,
        dst_opaque_reasons=["an access-role identifies users, not addresses"],
    )
    changes = changeset(
        [
            {
                "kind": "fw_rule.modify",
                "params": {"rulebase": "fw:LAN", "rule": "r:100", "destination": "10.0.0.0/24"},
            }
        ]
    )
    row = changes.rewrite(_RULEBASE_RULES, {"rb": "fw:LAN"}, [collected])[0]
    assert row["dst_opaque"] is False
    assert row["dst_negate"] is False
    assert row["dst_opaque_reasons"] == []


def test_a_restated_service_drops_the_collected_rows_opacity_and_negation():
    collected = rule(
        "r:100",
        100,
        "accept",
        svc_any=False,
        protos=[],
        ports=[],
        svc_obj_count=1,
        svc_opaque=True,
        svc_negate=True,
        svc_opaque_reasons=["unsupported checkpoint service kind: service-other"],
    )
    changes = changeset(
        [
            {
                "kind": "fw_rule.modify",
                "params": {"rulebase": "fw:LAN", "rule": "r:100", "protocols": ["tcp"], "ports": ["443"]},
            }
        ]
    )
    row = changes.rewrite(_RULEBASE_RULES, {"rb": "fw:LAN"}, [collected])[0]
    assert row["svc_opaque"] is False
    assert row["svc_negate"] is False
    assert row["svc_opaque_reasons"] == []


def test_a_proposed_rule_carries_the_gates_opacity_columns():
    """A proposal is stated in full."""
    row = _one_added_row(
        {"rulebase": "fw:LAN", "position": 10, "action": "drop", "source": "any", "destination": "SERVERS"}
    )[0]
    assert row["src_obj_count"] == row["dst_obj_count"] == row["svc_obj_count"] == 0
    assert not row["src_opaque"] and not row["dst_opaque"] and not row["svc_opaque"]
    assert not row["src_negate"] and not row["dst_negate"] and not row["svc_negate"]


# --- the routing follow-on's input ----------------------------------------


def test_only_a_deny_contributes_to_the_address_set_the_change_denies():
    changes = changeset(
        [
            DENY_TWO_HOSTS,
            {
                "kind": "fw_rule.add",
                "params": {
                    "rulebase": "fw:LAN",
                    "position": 11,
                    "action": "accept",
                    "source": "any",
                    "destination": "10.0.0.0/8",
                },
            },
        ]
    )
    assert changes.denied_sets() == [(4, 0xC0A80223, 0xC0A80224)]


def test_a_deny_to_any_destination_names_no_address_set():
    changes = changeset(
        [
            {
                "kind": "fw_rule.add",
                "params": {
                    "rulebase": "fw:LAN",
                    "position": 10,
                    "action": "drop",
                    "source": "10.0.0.1",
                    "destination": "any",
                },
            }
        ]
    )
    assert changes.denied_sets() == []


def test_the_two_sides_of_a_deny_are_kept_apart_by_direction():
    """A next hop is not affected the same way by a deny that stops traffic to it
    and one that stops traffic from it, so the two sides do not merge."""
    denied = changeset(
        [
            DENY_TWO_HOSTS,
            {
                "kind": "fw_rule.add",
                "params": {
                    "rulebase": "fw:LAN",
                    "position": 11,
                    "action": "drop",
                    "source": "10.9.9.9",
                    "destination": "any",
                },
            },
        ]
    ).denied_directions()
    assert denied.to_specs == ["192.168.2.35", "192.168.2.36"]
    assert denied.from_specs == ["10.9.9.9"]
    assert denied.any_denied() is True


def test_a_side_stated_as_any_contributes_no_address_in_either_direction():
    denied = changeset(
        [
            {
                "kind": "fw_rule.add",
                "params": {
                    "rulebase": "fw:LAN",
                    "position": 10,
                    "action": "drop",
                    "source": "any",
                    "destination": "any",
                },
            }
        ]
    ).denied_directions()
    assert denied.to_specs == []
    assert denied.from_specs == []
    assert denied.any_denied() is False


def test_unevaluated_for_routing_names_a_remove_and_a_nat_modify_not_an_add_permit():
    """`denied_directions()` reads only `fw_rule.add` deny intents."""
    changes = changeset(
        [
            {
                "kind": "fw_rule.add",
                "params": {
                    "rulebase": "fw:LAN",
                    "position": 10,
                    "action": "permit",
                    "source": "any",
                    "destination": "any",
                },
            },
            {"kind": "fw_rule.remove", "params": {"rulebase": "fw:LAN", "rule": "fw:rule:1"}},
            {
                "kind": "nat_rule.modify",
                "params": {"device": "dev:edge1", "rule": "nat:rule:1", "enabled": False},
            },
        ]
    )
    unevaluated = changes.unevaluated_for_routing()
    assert {intent.kind for intent in unevaluated} == {"fw_rule.remove", "nat_rule.modify"}
    assert not any(intent.kind == "fw_rule.add" for intent in unevaluated)


def test_unevaluated_for_routing_is_empty_for_an_add_permit_alone():
    changes = changeset(
        [
            {
                "kind": "fw_rule.add",
                "params": {
                    "rulebase": "fw:LAN",
                    "position": 10,
                    "action": "permit",
                    "source": "any",
                    "destination": "any",
                },
            }
        ]
    )
    assert changes.unevaluated_for_routing() == []


# --- path rows -------------------------------------------------------------


def _leg(**over: Any) -> dict[str, Any]:
    leg = {
        "cidr": "10.10.10.0/24",
        "egress": "eth0",
        "next_hop": "10.0.0.1",
        "table": "main",
        "blocked": False,
        "indeterminate": False,
        "verdict": "egress via eth0",
    }
    leg.update(over)
    return leg


def test_two_equal_cost_paths_differ_by_next_hop_and_are_not_merged_away():
    rows = path_rows([_leg(next_hop="10.0.0.1"), _leg(next_hop="10.0.0.2")])
    assert [r["next_hop"] for r in rows] == ["10.0.0.1", "10.0.0.2"]

    compared = compare_paths(rows, rows)
    assert compared["path_count_after"] == 2
    group = compared["groups"][0]
    assert group["path_count"] == 2
    assert group["next_hops"] == ["10.0.0.1", "10.0.0.2"]
    assert group["next_hop_count"] == 2


def test_a_blocked_path_names_the_rule_that_decided_it():
    after = path_rows(
        [_leg(blocked=True, firewall="LAN policy (LAN>WAN) drop by rule 10", fw_uid="fw:LAN")],
        {"fw:LAN"},
    )
    assert after[0]["blocked"] is True
    assert after[0]["decided_by"] == "LAN policy (LAN>WAN) drop by rule 10"
    assert after[0]["rulebase"] == "fw:LAN"
    assert after[0]["changed_rulebase_applies"] is True
    # a path the change decides needs no explanation of why it survived
    assert "note" not in after[0]


def test_a_path_no_changed_rulebase_governs_says_so_on_the_row():
    other = path_rows([_leg(firewall="INTRA (LAN>LAN) accept by rule 3", fw_uid="fw:INTRA")], {"fw:LAN"})
    assert other[0]["changed_rulebase_applies"] is False
    assert other[0]["note"] == "decided by fw:INTRA, which this change does not alter"

    none = path_rows([_leg()], {"fw:LAN"})
    assert none[0]["rulebase"] is None
    assert none[0]["note"] == (
        "no rulebase decided this path in the snapshot, so no rulebase this change alters governs it"
    )


def test_the_counts_say_how_many_paths_are_blocked_without_reading_prose():
    before = path_rows([_leg(cidr=f"10.{i}.0.0/16", next_hop=f"10.0.0.{i}") for i in range(13)], {"fw:LAN"})
    after = path_rows(
        [
            _leg(
                cidr=f"10.{i}.0.0/16",
                next_hop=f"10.0.0.{i}",
                blocked=i < 7,
                firewall="LAN policy (LAN>WAN) drop by rule 10" if i < 7 else None,
                fw_uid="fw:LAN" if i < 7 else None,
            )
            for i in range(13)
        ],
        {"fw:LAN"},
    )
    compared = compare_paths(before, after)
    assert compared["path_count_before"] == 13
    assert compared["path_count_after"] == 13
    assert compared["blocked_before"] == 0
    assert compared["blocked_after"] == 7
    assert compared["changed"] == 7


def test_paths_that_share_an_outcome_are_one_row_carrying_how_many_it_stands_for():
    before = path_rows([_leg(cidr=f"10.{i}.0.0/16", next_hop=f"10.0.0.{i}") for i in range(13)], {"fw:LAN"})
    after = path_rows(
        [
            _leg(
                cidr=f"10.{i}.0.0/16",
                next_hop=f"10.0.0.{i}",
                blocked=i < 7,
                firewall="LAN policy (LAN>WAN) drop by rule 10" if i < 7 else None,
                fw_uid="fw:LAN" if i < 7 else None,
            )
            for i in range(13)
        ],
        {"fw:LAN"},
    )
    compared = compare_paths(before, after)
    assert compared["group_count"] == 2
    blocked, survived = compared["groups"]
    assert blocked["path_count"] == 7
    assert blocked["after"]["blocked"] is True
    assert blocked["changed"] is True
    # the sample is capped, the count beside it is not
    assert len(blocked["destinations"]) == 4
    assert blocked["destination_count"] == 7
    assert blocked["sample_truncated"] is True
    assert survived["path_count"] == 6
    assert survived["changed"] is False
    assert survived["note"].startswith("no rulebase decided this path")


def test_a_path_only_one_side_records_is_a_row_with_that_side_absent():
    before = path_rows([_leg(next_hop="10.0.0.1"), _leg(next_hop="10.0.0.2")])
    after = path_rows([_leg(next_hop="10.0.0.1")])
    compared = compare_paths(before, after)
    assert compared["changed"] == 1
    gone = [g for g in compared["groups"] if g["after"] is None]
    assert len(gone) == 1
    assert gone[0]["next_hops"] == ["10.0.0.2"]


def test_the_group_list_is_capped_and_says_that_it_is():
    rows = path_rows(
        [_leg(cidr=f"10.{i}.0.0/16", egress=f"eth{i}", next_hop=f"10.0.0.{i}") for i in range(20)]
    )
    compared = compare_paths(rows, rows)
    assert compared["group_count"] == 20
    assert len(compared["groups"]) == 8
    assert compared["truncated"] is True
    assert compared["path_count_after"] == 20


def test_only_a_firewall_intent_names_a_rulebase_the_change_rewrites():
    changes = changeset(
        [
            {
                "kind": "fw_rule.add",
                "params": {
                    "rulebase": "fw:LAN",
                    "position": 10,
                    "action": "drop",
                    "source": "any",
                    "destination": "192.168.2.35",
                },
            },
            {"kind": "zone.add_interface", "params": {"zone": "zone:lan", "interface": "if:eth0"}},
        ],
        Catalog(zones={"zone:lan": {"name": "LAN", "interfaces": ["eth0"]}}),
    )
    assert changes.changed_rulebases() == {"fw:LAN"}


# --- the proposed rule's services reach the gate index-paired --------------


def _proposed_matches(params: dict[str, Any], port: int | None, proto: str | None) -> bool:
    """The tracer's first-match walk decides whether the proposal covers this flow."""
    rows = _one_added_row(params)
    return _first_match(rows, None, None, _SRC, _DST, port, proto) is not None


def test_a_proposed_rule_crosses_its_protocols_with_its_ports():
    """A rule stating tcp and udp on port 443 means that port on both protocols."""
    params = {
        "rulebase": "fw:LAN",
        "position": 10,
        "action": "drop",
        "source": "any",
        "destination": "any",
        "protocols": ["tcp", "udp"],
        "ports": ["443"],
    }
    assert _proposed_matches(params, 443, "tcp")
    assert _proposed_matches(params, 443, "udp")
    assert not _proposed_matches(params, 8080, "udp")


def test_every_stated_port_pairs_with_every_stated_protocol():
    params = {
        "rulebase": "fw:LAN",
        "position": 10,
        "action": "drop",
        "source": "any",
        "destination": "any",
        "protocols": ["tcp", "udp"],
        "ports": ["80", "443"],
    }
    assert _proposed_matches(params, 443, "tcp")
    assert _proposed_matches(params, 80, "udp")
    assert not _proposed_matches(params, 8080, "tcp")


def test_a_stated_protocol_with_no_port_pairs_with_an_unconstrained_port():
    """None on one side of a pair means that dimension is unconstrained for it,
    which is what the gate reads a null column entry as for a collected rule."""
    params = {
        "rulebase": "fw:LAN",
        "position": 10,
        "action": "drop",
        "source": "any",
        "destination": "any",
        "protocols": ["tcp"],
    }
    rows = _one_added_row(params)
    assert (rows[0]["protos"], rows[0]["ports"]) == (["tcp"], [None])
    assert _proposed_matches(params, 9999, "tcp")
    assert not _proposed_matches(params, 9999, "udp")


def test_a_stated_port_with_no_protocol_pairs_with_an_unconstrained_protocol():
    params = {
        "rulebase": "fw:LAN",
        "position": 10,
        "action": "drop",
        "source": "any",
        "destination": "any",
        "ports": ["443"],
    }
    rows = _one_added_row(params)
    assert (rows[0]["protos"], rows[0]["ports"]) == ([None], ["443"])
    assert _proposed_matches(params, 443, "udp")
    assert not _proposed_matches(params, 80, "udp")


# --- the local-zone gate's reads -------------------------------------------


def _gate_constants(module: Any) -> dict[str, str]:
    return {name: value for name, value in vars(module).items() if isinstance(value, str)}


def test_every_gate_read_of_a_rulebases_rules_is_rewritten():
    from hst.path.gates import firewall, local_zone

    rule_reads = {
        f"{module.__name__}.{name}": value
        for module in (firewall, local_zone)
        for name, value in _gate_constants(module).items()
        if "(rb:FwRulebase {uid: $rb})-[hr:HAS_RULE]->(r:FwRule)" in value
    }
    assert "hst.path.gates.local_zone._LOCAL_RULES_QUERY" in rule_reads
    changes = changeset(
        [{"kind": "fw_rule.add", "params": {**DENY_TWO_HOSTS["params"], "rulebase": "fw:LAN"}}]
    )
    for name, query in rule_reads.items():
        assert [r["name"] for r in changes.rewrite(query, {"rb": "fw:LAN"}, [])] == ["block the two hosts"], (
            name
        )


def test_a_read_that_only_resembles_the_rule_read_is_left_alone():
    from hst.app import fw_overlay_read

    changes = changeset([DENY_TWO_HOSTS])
    rows = [{"uid": "fw:other"}]
    assert changes.rewrite(fw_overlay_read._RULEBASE_DEVICES, {"rb": "fw:LAN"}, rows) is rows


def _zone_context_rows() -> list[dict[str, Any]]:
    return [
        {"if_uid": "if:eth0", "if_name": "eth0", "zone_uid": "zone:lan", "zone_name": "LAN"},
        {"if_uid": "if:eth1", "if_name": "eth1", "zone_uid": "zone:wan", "zone_name": "WAN"},
    ]


def test_a_zone_move_is_applied_to_the_local_zone_context_read():
    from hst.path.gates.local_zone import _LOCAL_ZONE_CONTEXT_QUERY

    catalog = Catalog(
        zones={
            "zone:lan": {"uid": "zone:lan", "name": "LAN"},
            "zone:dmz": {"uid": "zone:dmz", "name": "DMZ"},
        }
    )
    params = {"dev": "dev:r1", "in_if": "if:eth0", "out_if": "if:eth1"}
    moved = changeset(
        [{"kind": "zone.add_interface", "params": {"zone": "DMZ", "interface": "if:eth0"}}], catalog
    )
    assert moved.rewrite(_LOCAL_ZONE_CONTEXT_QUERY, params, _zone_context_rows()) == [
        {"if_uid": "if:eth0", "if_name": "eth0", "zone_uid": "zone:dmz", "zone_name": "DMZ"},
        {"if_uid": "if:eth1", "if_name": "eth1", "zone_uid": "zone:wan", "zone_name": "WAN"},
    ]
    left = changeset(
        [{"kind": "zone.remove_interface", "params": {"zone": "zone:lan", "interface": "if:eth0"}}], catalog
    )
    assert left.rewrite(_LOCAL_ZONE_CONTEXT_QUERY, params, _zone_context_rows()) == [
        {"if_uid": "if:eth1", "if_name": "eth1", "zone_uid": "zone:wan", "zone_name": "WAN"}
    ]
    untouched = _zone_context_rows()
    other = {**params, "in_if": "if:eth1", "out_if": ""}
    assert moved.rewrite(_LOCAL_ZONE_CONTEXT_QUERY, other, untouched) == untouched


def test_a_zone_join_of_an_interface_with_no_collected_name_leaves_it_unbound():
    from hst.path.gates.local_zone import _LOCAL_ZONE_CONTEXT_QUERY

    catalog = Catalog(zones={"zone:dmz": {"uid": "zone:dmz", "name": "DMZ"}})
    changes = changeset(
        [{"kind": "zone.add_interface", "params": {"zone": "zone:dmz", "interface": "if:eth9"}}], catalog
    )
    params = {"dev": "dev:r1", "in_if": "if:eth9", "out_if": ""}
    assert changes.rewrite(_LOCAL_ZONE_CONTEXT_QUERY, params, []) == []
    assert [e["kind"] for e in changes.errors.as_dicts()] == ["zone-move-not-resolvable"]


def _local_zone_session(changes: ChangeSet | None) -> _Session:
    answers = {
        "AS if_uid, i.name AS if_name": _zone_context_rows()[:1],
        "zone.local_zone AS local_zone": [
            {"zone_uid": "zone:lan", "zone_name": "LAN", "local_zone": False, "default_action": "drop"},
            {"zone_uid": "zone:local", "zone_name": "LOCAL", "local_zone": True, "default_action": "drop"},
        ],
        "RETURN DISTINCT rb.uid AS rb_uid": [
            {
                "rb_uid": "fw:lan-local",
                "rb_name": "LAN-LOCAL",
                "af": None,
                "default_action": "drop",
                "default_action_unknown": False,
                "global_state_policy": None,
                "src_uid": "zone:lan",
                "src_name": "LAN",
                "src_local": False,
                "dst_uid": "zone:local",
                "dst_name": "LOCAL",
                "dst_local": True,
            }
        ],
    }
    return _Overlaid(answers, changes) if changes else _Session(answers)


def test_a_proposed_local_zone_rule_changes_the_local_zone_gate_decision():
    from hst.path.addrsets import _intervals, _ports
    from hst.path.gates.local_zone import LocalZoneTransition
    from hst.path.state import FlowRegion

    region = FlowRegion.from_query(
        _intervals(["10.0.0.5"]), _intervals(["10.0.0.1"]), frozenset({6}), _ports("22"), None
    )

    def decide(session: Any) -> list[str]:
        gate = LocalZoneTransition(session, "dev:r1", "if:eth0", None, "input", "new")
        return [effect.kind for _region, effect in gate.apply(region)]

    assert decide(_local_zone_session(None)) == ["deny"]
    permit = {
        "rulebase": "fw:lan-local",
        "position": 10,
        "action": "accept",
        "source": "any",
        "destination": "any",
        "name": "allow ssh",
    }
    changes = changeset([{"kind": "fw_rule.add", "params": permit}])
    assert decide(_local_zone_session(changes)) == ["permit"]


# --- the address family of a proposed NAT rule ------------------------------------------


def _vyos_nat_row(uid: str, pos: int, **over: Any) -> dict[str, Any]:
    from tests.test_path_nat import _nat_row as full_row

    return full_row(uid=uid, pos=pos, rb_uid="vyos:r1:nat:source", rb_name="nat-source", **over)


def _proposed_masquerade(sibling_af: Any) -> list[dict[str, Any]]:
    changes = changeset(
        [
            {
                "kind": "nat_rule.add",
                "params": {
                    "device": "dev:fw1",
                    "position": 100,
                    "kind": "snat",
                    "rulebase": "vyos:r1:nat:source",
                    "rulebase_name": "nat-source",
                    "out_interface": "pppoe0",
                    "translation": "masquerade",
                },
            }
        ]
    )
    sibling = _vyos_nat_row("nat:10", 10, af=sibling_af, out_if="pppoe0", translation="203.0.113.7")
    return changes.rewrite(NAT_QUERY, {"dev": "dev:fw1"}, [sibling])


def test_a_proposed_nat_rule_takes_the_family_its_rulebase_states():
    from hst.path.addrsets import _intervals
    from hst.path.gates.nat import _nat_partition, _nat_stage_rules

    out = _proposed_masquerade(4)
    [new] = [r for r in out if r["uid"] == "nat:rule:proposed:0"]
    assert new["af"] == 4
    rules = [r for r in _nat_stage_rules(out, "snat", "pppoe0") if r["uid"] == new["uid"]]
    v6 = _nat_partition(rules, _intervals(["2001:db8:1::10"]), _intervals(["2606:4700::1"]), 443, "tcp")
    assert [p["rule"] for p in v6] == [None]
    # a rulebase whose rows state no family leaves the proposal without one
    [old] = [r for r in _proposed_masquerade(None) if r["uid"] == "nat:rule:proposed:0"]
    assert old.get("af") is None


def test_a_deployed_proposed_masquerade_reads_as_realized():
    """The device holds the proposed VyOS masquerade, collected with af=4."""
    from hst.assessment.service import _nat_semantics

    collected = [
        _vyos_nat_row("nat:10", 10, af=4, out_if="pppoe0", translation="203.0.113.7"),
        _vyos_nat_row("nat:100", 100, af=4, out_if="pppoe0", translation="masquerade"),
    ]
    assert _nat_semantics(_proposed_masquerade(4)) == _nat_semantics(collected)
    # a before snapshot with no `af`
    assert _nat_semantics(_proposed_masquerade(None)) == _nat_semantics(collected)
    nat66 = [dict(r, af=6) if r["uid"] == "nat:100" else r for r in collected]
    assert _nat_semantics(_proposed_masquerade(4)) != _nat_semantics(nat66)
