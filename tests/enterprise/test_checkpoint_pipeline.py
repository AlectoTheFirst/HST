"""Installed Check Point policy inputs reach the immutable network traversal."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address

import pytest
from tests.enterprise.test_checkpoint_normalize import CTX, MANIFEST, inputs, obj

from hst.analysis_model.compile import compile_model
from hst.analysis_model.evidence import (
    CaptureOutcome,
    ClockQuality,
    EvidencePolicy,
    EvidenceWindow,
    RevisionEvidence,
)
from hst.analysis_model.model import ChoiceAssignment, EntrySpec, ModelInput, NodeSpec, StateKey
from hst.core.firewall_read import InstallationExpectation, InstallationObservation, installation_predicate
from hst.impact.symbolic_walk import walk
from hst.policy.checkpoint import normalize_checkpoint_policy
from hst.policy.compile import PolicyCompiler
from hst.policy.ir import ExecutionContext
from hst.symbolic import BackendUnavailableError, HeaderSchema, SymbolicManager, header


@pytest.fixture(params=(4, 6))
def manager(request):
    try:
        native = SymbolicManager(HeaderSchema.ipv4() if request.param == 4 else HeaderSchema.ipv6())
    except BackendUnavailableError:
        if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
            pytest.fail("required native backend missing")
        pytest.skip("optional native backend missing")
    with native:
        yield native
    assert len(native._bdd) == 0


def test_authoritative_installation_controls_network_proof(manager):
    family = manager.schema.address_family
    context = ExecutionContext(CTX.estate, CTX.authority, CTX.domain, CTX.firewall_instance, CTX.vrf, family)
    address = "192.0.2.1" if family == 4 else "2001:db8::1"
    now = datetime(2026, 9, 12, 12, tzinfo=UTC)
    expected = InstallationExpectation(
        CTX.firewall_instance, "package", "revision", MANIFEST, "manager/domain/vs-uid/vrf", "context"
    )
    observation = InstallationObservation(
        CTX.firewall_instance,
        "package",
        "context",
        MANIFEST,
        EvidenceWindow(
            "package",
            "gateway",
            "installation",
            now - timedelta(seconds=1),
            now,
            observation_time=now,
            outcome=CaptureOutcome.COMPLETE,
            clock_quality=ClockQuality.TRUSTED,
            revision=RevisionEvidence("revision", "revision", ("capture",)),
            revision_required=True,
            revision_scope=expected.revision_scope,
        ),
    )
    key = StateKey("firewall-filter", context)
    request = header(
        manager,
        {
            "source_address": int(ip_address(address)),
            "protocol": 6,
            "destination_port": 443,
            "fragment_offset": 0,
        },
        explicitly_all=manager.schema.field_names,
    )
    for observations, definite in (((observation,), True), ((), False)):
        raw = inputs()
        raw["context"] = context
        raw["objects"][4] = obj("host", "host", **{f"ipv{family}-address": address})
        raw["installation"] = installation_predicate(
            expected, observations, analysis_time=now, evidence_policy=EvidencePolicy()
        )
        policy = normalize_checkpoint_policy(**raw).policy
        model = compile_model(
            ModelInput(
                MANIFEST,
                (NodeSpec(key, terminal="permit", policy=policy),),
                (EntrySpec(key),),
                (ChoiceAssignment("only"),),
                True,
            ),
            manager,
            request.known_fields,
        )
        result = walk(model, request, request_id="installed-checkpoint")
        assert result.database_reads == 0
        assert result.bounds.lower.is_empty() != definite
        assert not result.bounds.upper.is_empty()
        if not definite:
            assert "INSTALLATION_NOT_OBSERVED" in result.gap_refs


def test_family_network_range_and_port_boundaries(manager):
    family = manager.schema.address_family
    context = ExecutionContext(CTX.estate, CTX.authority, CTX.domain, CTX.firewall_instance, CTX.vrf, family)
    raw = inputs()
    raw["context"] = context
    first, inside, outside, length = (
        ("192.0.2.0", "192.0.2.1", "192.0.3.1", 24)
        if family == 4
        else ("2001:db8::", "2001:db8::1", "2001:db8:1::1", 64)
    )
    raw["objects"][4] = obj("host", "network", **{f"subnet{family}": first, f"mask-length{family}": length})
    raw["objects"][-1]["port"] = "440-445,>=65000"
    for address, port, expected in (
        (inside, 440, True),
        (inside, 445, True),
        (inside, 446, False),
        (inside, 65535, True),
        (outside, 443, False),
    ):
        request = header(
            manager,
            {
                "source_address": int(ip_address(address)),
                "protocol": 6,
                "destination_port": port,
                "fragment_offset": 0,
            },
            explicitly_all=manager.schema.field_names,
        )
        result = (
            PolicyCompiler(manager, context, request.known_fields)
            .compile(normalize_checkpoint_policy(**raw).policy)
            .evaluate(request)
        )
        assert result.bounds.lower.equivalent(result.bounds.upper)
        assert result.bounds.lower.is_empty() != expected
    raw["objects"][4] = obj(
        "host", "address-range", **{f"ipv{family}-address-first": first, f"ipv{family}-address-last": inside}
    )
    request = header(
        manager,
        {
            "source_address": int(ip_address(inside)),
            "protocol": 6,
            "destination_port": 443,
            "fragment_offset": 0,
        },
        explicitly_all=manager.schema.field_names,
    )
    result = (
        PolicyCompiler(manager, context, request.known_fields)
        .compile(normalize_checkpoint_policy(**raw).policy)
        .evaluate(request)
    )
    assert not result.bounds.lower.is_empty()
