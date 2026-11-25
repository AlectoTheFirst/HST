"""Cisco ACL normalization checked through a finite, independent oracle."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from hst.policy.acl import compile_cisco_interface_acl
from hst.policy.compile import PolicyCompiler
from hst.policy.ir import AllOf, AnyOf, Atom, Constant, Not, Unknown
from hst.symbolic import BackendUnavailableError, HeaderSchema, SymbolicManager, header

FIXTURE = Path(__file__).parents[2] / "fixtures/enterprise/acl/cisco-interface-acl.json"


@pytest.fixture
def manager():
    try:
        native = SymbolicManager(HeaderSchema.ipv4())
    except BackendUnavailableError:
        if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
            pytest.fail("required native backend missing")
        pytest.skip("optional native backend missing")
    with native:
        yield native
    assert len(native._bdd) == 0


def _record() -> dict[str, object]:
    return json.loads(FIXTURE.read_text())


def _query(manager: SymbolicManager, **values: int):
    fields = {
        "source_address": int.from_bytes(bytes((10, 0, 2, 9)), "big"),
        "destination_address": int.from_bytes(bytes((198, 51, 100, 9)), "big"),
        "protocol": 6,
        "source_port": 12345,
        "destination_port": 443,
        "tcp_flags": 0x10,
        "fragment_offset": 0,
        "dscp": 0,
    }
    fields.update(values)
    return header(manager, fields, explicitly_all=manager.schema.field_names)


def test_compiles_all_bindings_as_ordered_conjunctive_layers(manager):
    model = compile_cisco_interface_acl(_record())
    assert [(b.interface, b.direction, b.pipeline) for b in model.bindings] == [
        ("Gi0/0", "in", "forward-ingress"),
        ("Gi0/1", "out", "forward-egress"),
    ]
    selected = model.policy_for_binding("Gi0/0", "in", "forward-ingress")
    assert selected.ordered_layers == ("edge-in",)
    query = _query(manager)
    decision = PolicyCompiler(manager, selected.context, query.known_fields).compile(selected).evaluate(query)
    assert decision.bounds.lower.equivalent(query)
    assert decision.bounds.upper.equivalent(query)


def test_noncontiguous_wildcard_and_established_are_exact(manager):
    model = compile_cisco_interface_acl(_record())
    selected = model.policy_for_binding("Gi0/0", "in", "forward-ingress")
    compiler = PolicyCompiler(manager, selected.context, frozenset(manager.schema.field_names))
    for packet, expected in [
        (_query(manager), True),
        (_query(manager, tcp_flags=0x04), True),
        (_query(manager, tcp_flags=0x02), False),
        (_query(manager, source_address=int.from_bytes(bytes((10, 0, 3, 9)), "big")), False),
    ]:
        outcome = compiler.compile(selected).evaluate(packet).bounds
        assert (outcome.lower.equivalent(packet) and outcome.upper.equivalent(packet)) is expected


def test_independent_finite_oracle_matches_compiled_first_match(manager):
    model = compile_cisco_interface_acl(_record())
    selected = model.policy_for_binding("Gi0/0", "in", "forward-ingress")
    compiler = PolicyCompiler(manager, selected.context, frozenset(manager.schema.field_names))
    for source in (int.from_bytes(bytes((10, 0, 2, 1)), "big"), int.from_bytes(bytes((10, 0, 3, 1)), "big")):
        for flags in (0x02, 0x04, 0x10):
            packet = _query(manager, source_address=source, tcp_flags=flags)
            result = compiler.compile(selected).evaluate(packet).bounds
            concrete = source & 0x00000100 == 0 and flags & 0x14 != 0
            assert (result.lower.equivalent(packet) and result.upper.equivalent(packet)) is concrete


def test_ipv6_prefix_and_unmodeled_rule_field_are_conservative():
    record = _record()
    record["context"] = {**record["context"], "address_family": 6}  # type: ignore[index]
    base = record["rulebases"][0]  # type: ignore[index]
    base["af"] = 6
    base["rules"][0].pop("src_wildcard")
    base["rules"][0].update({"src": "2001:db8:1::/64", "dst_any": True, "proto": "icmpv6", "mystery": "x"})
    model = compile_cisco_interface_acl(record)
    rule = model.policy_for_binding("Gi0/0", "in", "forward-ingress").layers[0].rules[0]
    assert any(
        isinstance(term, Unknown) and term.code == "UNMODELED_ACL_FIELD" for term in _walk(rule.predicate)
    )
    assert any(
        isinstance(term, Atom) and term.field == "source_address" and term.other is not None
        for term in _walk(rule.predicate)
    )


def test_missing_binding_family_enabled_and_installation_are_unknown():
    record = _record()
    del record["installed"]
    base = record["rulebases"][0]  # type: ignore[index]
    for key in ("interface", "pipeline", "af", "installed"):
        base.pop(key)
    base["rules"][0].pop("enabled")
    model = compile_cisco_interface_acl(record)
    assert isinstance(model.bindings[0].applicability, Unknown)
    selected = model.policy_for_binding("Gi0/0", "in", "forward-ingress")
    leaves = _walk(selected.installation) + _walk(selected.layers[0].rules[0].predicate)
    assert {term.code for term in leaves if isinstance(term, Unknown)} >= {
        "INSTALLATION_UNKNOWN",
        "ACL_BINDING_UNKNOWN",
        "ADDRESS_FAMILY_UNKNOWN",
        "RULE_ENABLED_UNKNOWN",
    }


def test_existing_rule_scope_properties_are_preserved_as_binding_evidence():
    record = _record()
    base = record["rulebases"][0]  # type: ignore[index]
    interface = base.pop("interface")
    direction = base.pop("direction")
    base["rules"][0][f"{direction}_interface"] = interface
    base.pop("pipeline")
    model = compile_cisco_interface_acl(record)
    assert (model.bindings[0].interface, model.bindings[0].direction) == ("Gi0/0", "in")
    assert isinstance(model.bindings[0].applicability, Unknown)


def test_collected_dscp_icmp_fragment_and_explicit_flag_fields_are_lowered():
    record = _record()
    rule = record["rulebases"][0]["rules"][0]  # type: ignore[index]
    rule.update(
        {
            "states": [],
            "ports": None,
            "dscp": 46,
            "icmp_type": 8,
            "icmp_code": 0,
            "fragments": True,
            "tcp_flags": 0x02,
            "tcp_flags_mask": 0x02,
        }
    )
    selected = compile_cisco_interface_acl(record).policy_for_binding("Gi0/0", "in", "forward-ingress")
    terms = _walk(selected.layers[0].rules[0].predicate)
    assert {(term.field, term.value, term.other) for term in terms if isinstance(term, Atom)} >= {
        ("dscp", 46, None),
        ("icmp_type", 8, None),
        ("icmp_code", 0, None),
        ("tcp_flags", 2, 2),
    }
    assert _contains_fragment_not(selected.layers[0].rules[0].predicate)


def _walk(predicate):
    if isinstance(predicate, (Constant, Atom, Unknown)):
        return [predicate]
    if isinstance(predicate, Not):
        return _walk(predicate.term)
    if isinstance(predicate, (AllOf, AnyOf)):
        return [item for term in predicate.terms for item in _walk(term)]
    raise AssertionError(predicate)


def _contains_fragment_not(predicate) -> bool:
    if isinstance(predicate, Not):
        return isinstance(predicate.term, Atom) and predicate.term.field == "fragment_offset"
    if isinstance(predicate, (AllOf, AnyOf)):
        return any(_contains_fragment_not(term) for term in predicate.terms)
    return False
