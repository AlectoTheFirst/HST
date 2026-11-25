import importlib
import os

import pytest

from hst.analysis_model.sessions import SessionCatalog
from hst.policy.ir import ExecutionContext
from hst.symbolic import HeaderSchema, SymbolicManager, header
from hst.symbolic.relations import PacketRelation
from hst.symbolic.session import BindingOwner, FlowTuple, NatBinding, SynchronizationEvidence

if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
    importlib.import_module("dd.cudd")
else:
    pytest.importorskip("dd.cudd", reason="native symbolic wheel required for these tests")


def ctx(owner):
    return ExecutionContext("e", "a", "d", owner, "v", 4)


def test_reply_state_is_owner_request_and_choice_scoped():
    owner = BindingOwner(ctx("fw-a"), "request", ("member:a",))
    binding = NatBinding("binding", owner, FlowTuple(6, 1, 2, 1000, 443), FlowTuple(6, 3, 2, 4000, 443))
    catalog = SessionCatalog((binding,))
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        assert (
            catalog.reverse(
                manager,
                "binding",
                reply_context=ctx("fw-a"),
                request_id="request",
                choice_scope=("member:a",),
            ).status
            == "exact"
        )
        assert (
            catalog.reverse(
                manager, "binding", reply_context=ctx("fw-a"), request_id="other", choice_scope=("member:a",)
            ).status
            == "rejected"
        )
        assert (
            catalog.reverse(
                manager,
                "binding",
                reply_context=ctx("fw-b"),
                request_id="request",
                choice_scope=("member:a",),
            ).status
            == "rejected"
        )


def test_validated_binding_specific_synchronization_allows_asymmetric_reply():
    owner = BindingOwner(ctx("fw-a"), "request", ())
    binding = NatBinding("binding", owner, FlowTuple(17, 1, 2, 1000, 53), FlowTuple(17, 3, 2, 4000, 53))
    sync = SynchronizationEvidence("binding", ctx("fw-a"), ctx("fw-b"), True, "evidence")
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        assert (
            SessionCatalog((binding,), (sync,))
            .reverse(manager, "binding", reply_context=ctx("fw-b"), request_id="request", choice_scope=())
            .status
            == "exact"
        )


def test_reverse_flow_restores_chained_deterministic_translation():
    with SymbolicManager(HeaderSchema.ipv4()) as manager:
        first = PacketRelation.rewrite(
            manager,
            {"source_address": 3},
            guard=header(manager, {"source_address": 1, "destination_address": 2}),
        )
        second = PacketRelation.rewrite(
            manager,
            {"destination_address": 4},
            guard=header(manager, {"source_address": 3, "destination_address": 2}),
        )
        translated_reply = header(manager, {"source_address": 4, "destination_address": 3})
        restored = first.compose(second).reverse_flow().image(translated_reply)
        expected = header(manager, {"source_address": 2, "destination_address": 1})
        assert restored.equivalent(expected)
