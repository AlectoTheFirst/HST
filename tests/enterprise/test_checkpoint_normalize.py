"""Synthetic Check Point source payloads through the native policy compiler."""

from __future__ import annotations

import copy
import os
from dataclasses import replace
from ipaddress import ip_address

import pytest

from hst.collectors.checkpoint_policy import collect_checkpoint_policy
from hst.policy.checkpoint import normalize_checkpoint_capture, normalize_checkpoint_policy
from hst.policy.compile import PolicyCompiler
from hst.policy.ir import Constant, ExecutionContext, Unknown
from hst.policy.profiles import CheckpointProfile
from hst.symbolic import BackendUnavailableError, HeaderSchema, SymbolicManager, header

CTX = ExecutionContext("estate", "manager", "domain", "vs-uid", "vrf", 4)
PROFILE = CheckpointProfile("R81.20", "R81.20", "1.9")
MANIFEST = "a" * 64


def obj(uid, kind, **fields):
    return {"uid": uid, "type": kind, "domain": {"uid": "domain"}, **fields}


def rule(uid="allow", action="accept", **fields):
    return (
        obj(
            uid,
            "access-rule",
            source=["group"],
            destination=["any"],
            service=["https"],
            **{
                "source-negate": False,
                "destination-negate": False,
                "service-negate": False,
                "time": ["any"],
                "vpn": ["any"],
                "content": ["any"],
                "enabled": True,
                "install-on": ["target"],
                "action": action,
            },
        )
        | fields
    )


def inputs():
    return {
        "profile": PROFILE,
        "context": CTX,
        "manifest_digest": MANIFEST,
        "package": obj("package", "package", **{"access-layers": ["root"]}),
        "layers": {"root": obj("root", "access-layer", **{"implicit-cleanup-action": "drop"})},
        "rulebases": {"root": [rule()]},
        "objects": [
            obj("any", "CpmiAnyObject"),
            obj("accept", "RulebaseAction", name="Accept"),
            obj("drop", "RulebaseAction", name="Drop"),
            obj("call", "RulebaseAction", name="Apply Layer"),
            obj("host", "host", **{"ipv4-address": "192.0.2.1"}),
            obj("group", "group", members=["host"]),
            obj(
                "https",
                "service-tcp",
                port="443",
                **{"source-port": "", "protocol": "None", "match-by-protocol-signature": False},
            ),
        ],
        "installation": Constant(True),
        "target_bindings": {"target": (CTX.firewall_instance,)},
        "capture_complete": True,
        "implied_complete": True,
    }


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


def query(manager, source="192.0.2.1", port=443):
    return header(
        manager,
        {
            "source_address": int(ip_address(source)),
            "protocol": 6,
            "fragment_offset": 0,
            "destination_port": port,
        },
        explicitly_all=manager.schema.field_names,
    )


def decision(manager, raw, *, source="192.0.2.1", port=443, compiler=None):
    request = query(manager, source, port)
    compiled = (compiler or PolicyCompiler(manager, CTX, request.known_fields)).compile(
        normalize_checkpoint_policy(**raw).policy
    )
    result = compiled.evaluate(request)
    return (not result.bounds.lower.is_empty(), not result.bounds.upper.is_empty()), result


def test_source_objects_first_match_sections_and_source_only_edit(manager):
    raw = inputs()
    request = query(manager)
    compiler = PolicyCompiler(manager, CTX, request.known_fields)
    raw["rulebases"]["root"] = [
        obj("section", "access-section", rulebase=[rule()]),
        rule("deny", "drop", source=["any"], service=["any"]),
    ]
    assert decision(manager, raw, compiler=compiler)[0] == (True, True)
    assert decision(manager, raw, source="192.0.2.2", compiler=compiler)[0] == (False, False)
    old_digest = normalize_checkpoint_policy(**raw).source_digest
    raw["objects"][4]["ipv4-address"] = "192.0.2.2"
    assert old_digest != normalize_checkpoint_policy(**raw).source_digest
    for address, expected in (("192.0.2.1", (False, False)), ("192.0.2.2", (True, True))):
        incremental = decision(manager, raw, source=address, compiler=compiler)[0]
        assert incremental == decision(manager, raw, source=address)[0] == expected


def test_inline_cleanup_terminates_parent_and_ordered_accept_continues(manager):
    raw = inputs()
    raw["layers"]["child"] = obj("child", "access-layer", **{"implicit-cleanup-action": "drop"})
    raw["rulebases"]["root"] = [
        rule("parent", "call", **{"inline-layer": "child"}),
        rule("fallback", source=["any"], service=["any"]),
    ]
    raw["rulebases"]["child"] = []
    assert decision(manager, raw)[0] == (False, False)
    raw["layers"]["child"]["implicit-cleanup-action"] = "accept"
    assert decision(manager, raw)[0] == (True, True)
    raw["package"]["access-layers"].append("last")
    raw["layers"]["last"] = obj("last", "access-layer", **{"implicit-cleanup-action": "drop"})
    raw["rulebases"]["last"] = []
    assert decision(manager, raw)[0] == (False, False)


@pytest.mark.parametrize(
    "field,value",
    [
        ("capture_complete", False),
        ("implied_complete", False),
        ("installation", Unknown("INSTALLATION_NOT_OBSERVED", "package")),
    ],
)
def test_evidence_missing_prevents_definite_answers(manager, field, value):
    raw = inputs()
    raw[field] = value
    assert decision(manager, raw)[0] == (False, True)
    assert decision(manager, raw, port=80)[0] == (False, True)


def test_known_context_unknown_is_scoped_but_unclassified_rule_is_not(manager):
    raw = inputs()
    raw["rulebases"]["root"][0]["time"] = ["schedule-not-captured"]
    assert decision(manager, raw)[0] == (False, True)
    assert decision(manager, raw, source="192.0.2.2")[0] == (False, False)
    audit = normalize_checkpoint_policy(**raw).audit
    assert any(item.field == "time" and item.classification == "unsupported" for item in audit)
    raw["rulebases"]["root"][0]["future-negation"] = True
    assert decision(manager, raw, source="192.0.2.2")[0] == (False, True)


def test_service_protocol_handler_is_not_equated_with_port(manager):
    raw = inputs()
    raw["objects"][-1]["protocol"] = "HTTPS"
    assert decision(manager, raw)[0] == (False, True)
    assert decision(manager, raw, port=80)[0] == (False, False)
    raw["objects"][-1]["protocol"] = {"uid": "handler"}
    assert decision(manager, raw)[0] == (False, True)


def test_missing_group_cycle_exclusion_and_namespace_collisions(manager):
    raw = inputs()
    raw["objects"][5]["members"].append("missing")
    assert decision(manager, raw)[0] == (True, True)
    assert decision(manager, raw, source="192.0.2.2")[0] == (False, True)
    raw["objects"][5]["members"][-1] = "group"
    assert decision(manager, raw, source="192.0.2.2")[0] == (False, True)
    raw["objects"][5] = obj("group", "group-with-exclusion", include="any", **{"except": "host"})
    assert decision(manager, raw)[0] == (False, False)
    assert decision(manager, raw, source="192.0.2.2")[0] == (True, True)
    raw["objects"].append(obj("host", "host", **{"domain": {"uid": "other"}, "ipv4-address": "192.0.2.2"}))
    assert decision(manager, raw)[0] == (False, True)
    raw["objects"][5]["except"] = {"uid": "host", "domain": {"uid": "domain"}}
    assert decision(manager, raw)[0] == (False, False)


def test_explicit_disabled_target_and_missing_cleanup(manager):
    raw = inputs()
    raw["rulebases"]["root"][0]["enabled"] = False
    assert decision(manager, raw)[0] == (False, False)
    raw["rulebases"]["root"][0]["enabled"] = "false"
    assert decision(manager, raw)[0] == (False, True)
    raw["target_bindings"]["target"] = ("another-vs",)
    assert decision(manager, raw)[0] == (False, False)
    del raw["layers"]["root"]["implicit-cleanup-action"]
    assert decision(manager, raw)[0] == (False, True)


def test_profile_and_explicit_evidence_validation():
    with pytest.raises(ValueError, match="unqualified"):
        CheckpointProfile("R80.40", "R81.20", "1.9")
    raw = inputs()
    raw["capture_complete"] = "true"
    with pytest.raises(TypeError, match="booleans"):
        normalize_checkpoint_policy(**raw)
    raw = inputs()
    raw["target_bindings"] = {"target": "vs-uid"}
    with pytest.raises(ValueError, match="tuples"):
        normalize_checkpoint_policy(**raw)
    raw = inputs()
    raw["rulebases"]["root"] = [obj("section", "access-section", new_field=True)]
    assert len(normalize_checkpoint_policy(**raw).policy.layers[0].rules) == 1


def test_capture_bridge_preserves_revision_and_implied_gaps(manager):
    raw = inputs()
    dictionary = [*raw["objects"], obj("target", "simple-gateway")]

    def api(command, payload):
        if command == "show-package":
            return copy.deepcopy(raw["package"])
        if command == "show-access-layer":
            return copy.deepcopy(raw["layers"][payload["uid"]])
        if command == "show-access-rulebase":
            return {
                "from": 1,
                "to": 1,
                "total": 1,
                "rulebase": copy.deepcopy(raw["rulebases"]["root"]),
                "objects-dictionary": dictionary,
            }
        raise AssertionError(command)

    capture = collect_checkpoint_policy(
        api,
        authority_uid=CTX.authority,
        domain_uid=CTX.domain,
        package_uid="package",
        manifest_digest=MANIFEST,
        snapshot_revision="revision-1",
        revision_probe=lambda: "revision-1",
        chunk_sink=lambda data: "sealed-receipt",
        implied_rules_complete=True,
    )
    assert capture.complete
    normalized = normalize_checkpoint_capture(
        capture,
        profile=PROFILE,
        context=CTX,
        installation=Constant(True),
        target_bindings=raw["target_bindings"],
        implied_complete=True,
    )
    request = query(manager)
    compiler = PolicyCompiler(manager, CTX, request.known_fields)
    result = compiler.compile(normalized.policy).evaluate(request)
    assert result.bounds.lower.equivalent(result.bounds.upper)
    assert not result.bounds.lower.is_empty()
    unknown = normalize_checkpoint_capture(
        capture,
        profile=PROFILE,
        context=CTX,
        installation=Constant(True),
        target_bindings=raw["target_bindings"],
    )
    assert compiler.compile(unknown.policy).evaluate(request).bounds.lower.is_empty()
    with pytest.raises(ValueError, match="authority/domain"):
        normalize_checkpoint_capture(
            capture,
            profile=PROFILE,
            context=replace(CTX, domain="wrong"),
            installation=Constant(True),
            target_bindings=raw["target_bindings"],
        )


@pytest.mark.parametrize(
    "host",
    [
        obj("host", "host", **{"ipv4-address": 3221225985}),
        obj("host", "host", **{"ipv6-address": "malformed"}),
        obj(
            "host",
            "network",
            **{"subnet4": "192.0.2.0", "mask-length4": 24, "subnet-mask": "255.255.255.255"},
        ),
    ],
)
def test_malformed_address_and_conflicting_masks_are_unknown(manager, host):
    raw = inputs()
    raw["objects"][4] = host
    assert decision(manager, raw)[0] == (False, True)


def test_shared_layer_without_domain_qualification_is_unknown(manager):
    raw = inputs()
    raw["layers"]["root"]["domain"] = {"uid": "another-domain"}
    assert decision(manager, raw)[0] == (False, True)
