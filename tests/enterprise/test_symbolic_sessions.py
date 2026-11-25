from __future__ import annotations

import importlib
import os

import pytest

from hst.policy.ir import ExecutionContext
from hst.symbolic import HeaderSchema, PacketRelation, SymbolicManager, header, initial_relation
from hst.symbolic.session import (
    BindingOwner,
    FlowTuple,
    NatBinding,
    SynchronizationEvidence,
    reverse_nat_relation,
)

if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
    importlib.import_module("dd.cudd")
else:
    pytest.importorskip("dd.cudd", reason="native symbolic wheel required for session tests")


def _context(instance: str) -> ExecutionContext:
    return ExecutionContext("estate", "manager", "domain", instance, "vrf", 4)


def _owner(client: str, instance: str = "vs-a") -> BindingOwner:
    return BindingOwner(_context(instance), client, ("pool-a", client))


@pytest.mark.parametrize("protocol", [6, 17])
def test_reverse_binding_restores_tcp_and_udp_tuple(protocol: int) -> None:
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        owner = _owner("request-1")
        binding = NatBinding(
            "binding-1",
            owner,
            FlowTuple(protocol, 0x0A000001, 0xCB007109, 12345, 443),
            FlowTuple(protocol, 0xC000020A, 0xCB007109, 50001, 443),
        )
        result = reverse_nat_relation(manager, binding, reply_owner=owner)
        assert result.status == "exact" and result.relation is not None
        reply = header(
            manager,
            {
                "protocol": protocol,
                "source_address": 0xCB007109,
                "destination_address": 0xC000020A,
                "source_port": 443,
                "destination_port": 50001,
            },
        )
        restored = result.relation.image(reply).render(
            ["source_address", "destination_address", "source_port", "destination_port"], limit=2
        )
        assert dict(restored.rows[0]) == {
            "source_address": 0xCB007109,
            "destination_address": 0x0A000001,
            "source_port": 443,
            "destination_port": 12345,
        }


def test_clients_sharing_public_address_cannot_borrow_binding() -> None:
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        first = _owner("request-1")
        second = _owner("request-2")
        binding = NatBinding(
            "binding-1",
            first,
            FlowTuple(6, 0x0A000001, 0xCB007109, 12001, 443),
            FlowTuple(6, 0xC000020A, 0xCB007109, 50000, 443),
        )
        rejected = reverse_nat_relation(manager, binding, reply_owner=second)
        assert rejected.status == "rejected"
        assert rejected.gap_code == "NAT_BINDING_SCOPE_MISMATCH"


def test_asymmetric_context_needs_exact_validated_sync_evidence() -> None:
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        owner = _owner("request-1")
        reply_owner = _owner("request-1", "vs-b")
        binding = NatBinding(
            "binding-1",
            owner,
            FlowTuple(17, 0x0A000001, 0xCB007109, 12001, 53),
            FlowTuple(17, 0xC000020A, 0xCB007109, 50000, 53),
        )
        rejected = reverse_nat_relation(manager, binding, reply_owner=reply_owner)
        assert rejected.status == "rejected"
        evidence = SynchronizationEvidence(
            "binding-1", owner.execution_context, reply_owner.execution_context, True, "obs-1"
        )
        accepted = reverse_nat_relation(manager, binding, reply_owner=reply_owner, synchronization=evidence)
        assert accepted.status == "exact"


def test_missing_binding_is_unknown() -> None:
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        result = reverse_nat_relation(manager, None, reply_owner=_owner("request-1"))
        assert result.status == "unknown"
        assert result.gap_code == "NAT_BINDING_NOT_OBSERVED"


def test_reverse_binding_keeps_original_client_correlation_for_identical_current_tuple() -> None:
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        first_owner = _owner("request-1")
        first = NatBinding(
            "binding-1",
            first_owner,
            FlowTuple(6, 0x0A000001, 0xCB007109, 12001, 443),
            FlowTuple(6, 0xC000020A, 0xCB007109, 50000, 443),
        )
        second = NatBinding(
            "binding-2",
            _owner("request-2"),
            FlowTuple(6, 0x0A000002, 0xCB007109, 12002, 443),
            FlowTuple(6, 0xC000020A, 0xCB007109, 50000, 443),
        )
        requests = initial_relation(
            header(
                manager,
                {
                    "protocol": 6,
                    "source_address": [0x0A000001, 0x0A000002],
                    "destination_address": 0xCB007109,
                    "source_port": [12001, 12002],
                    "destination_port": 443,
                    "fragment_offset": 0,
                },
            )
        )
        shared_forward = PacketRelation.rewrite(manager, first.translated_forward.fields()).image(requests)
        reverse_packets = PacketRelation.rewrite(manager, first.translated_forward.reversed_fields()).image(
            shared_forward
        )
        reverse = reverse_nat_relation(manager, first, reply_owner=first_owner)
        assert reverse.relation is not None
        restored = reverse.relation.image(reverse_packets)
        assert {
            row["source_address"]
            for row in restored.render(["source_address"], bank="original", limit=4).rows
        } == {first.original_forward.source_address}
        assert second.original_forward.source_address not in {
            row["source_address"]
            for row in restored.render(["source_address"], bank="original", limit=4).rows
        }


def test_reverse_binding_rejects_fragment_padding_and_preserves_request_knowledge() -> None:
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        owner = _owner("request-1")
        binding = NatBinding(
            "binding-1",
            owner,
            FlowTuple(17, 0x0A000001, 0xCB007109, 0, 0),
            FlowTuple(17, 0xC000020A, 0xCB007109, 0, 0),
        )
        reverse = reverse_nat_relation(manager, binding, reply_owner=owner)
        assert reverse.relation is not None
        noninitial = header(
            manager,
            {
                "protocol": 17,
                "source_address": 0xCB007109,
                "destination_address": 0xC000020A,
                "source_port": 0,
                "destination_port": 0,
                "fragment_offset": 1,
            },
        )
        assert reverse.relation.image(noninitial).is_empty()

        correlated = initial_relation(
            header(manager, binding.original_forward.fields(), explicitly_all=("dscp",))
        )
        reply = PacketRelation.rewrite(
            manager, {**binding.translated_forward.reversed_fields(), "fragment_offset": 0}
        ).image(correlated)
        restored = reverse.relation.image(reply)
        assert restored.known_fields == correlated.known_fields


def test_protocol_and_reply_owner_family_are_strict() -> None:
    with pytest.raises(ValueError, match="TCP and UDP"):
        FlowTuple(6.0, 1, 2, 3, 4)  # type: ignore[arg-type]
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        owner = _owner("request-1")
        binding = NatBinding(
            "binding-1",
            owner,
            FlowTuple(6, 1, 2, 3, 4),
            FlowTuple(6, 5, 2, 6, 4),
        )
        wrong_family = BindingOwner(
            ExecutionContext("estate", "manager", "domain", "vs-b", "vrf", 6),
            owner.request_id,
            owner.choice_scope,
        )
        evidence = SynchronizationEvidence(
            "binding-1",
            wrong_family.execution_context,
            wrong_family.execution_context,
            True,
            "obs",
        )
        with pytest.raises(ValueError, match="reply owner family"):
            reverse_nat_relation(manager, binding, reply_owner=wrong_family, synchronization=evidence)


def test_synchronization_validation_flag_rejects_a_non_boolean() -> None:
    with pytest.raises(TypeError, match="explicit boolean"):
        SynchronizationEvidence(
            "binding-1",
            _context("vs-a"),
            _context("vs-b"),
            "false",  # type: ignore[arg-type]
            "obs",
        )
