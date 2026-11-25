import os
from datetime import UTC, datetime

import pytest

from hst.analysis_model.evidence import CollectionRecipe, EvidenceGap, GapCode, ScopeKind, project_gaps
from hst.symbolic import BackendUnavailableError, HeaderSchema, SymbolicManager, header


@pytest.fixture
def manager():
    try:
        native = SymbolicManager(HeaderSchema.ipv4())
    except BackendUnavailableError:
        if os.environ.get("HST_SYMBOLIC_REQUIRE") == "1":
            raise
        pytest.skip("native symbolic wheel required for PacketSet gap projection")
    try:
        yield native
    finally:
        native.close()


def gap():
    return EvidenceGap(
        GapCode.PARTIAL_EVIDENCE,
        "vsx-a",
        "checkpoint-a",
        "access",
        observed_interval=(datetime(2026, 9, 12, tzinfo=UTC), datetime(2026, 9, 12, 0, 1, tzinfo=UTC)),
    )


def recipe():
    return CollectionRecipe(
        "checkpoint.access",
        "checkpoint-a",
        "vsx-a",
        "access",
        ("POST /show-access",),
        "collect.read",
    )


def test_projection_retains_exact_packet_scope_and_only_authorized_actual_recipe(manager):
    universe = header(manager, {"protocol": 6, "destination_port": [80, 443]})
    http = universe.intersect(header(manager, {"destination_port": 80}))
    known_recipe = recipe()
    projected = project_gaps(
        (gap(),),
        universe,
        exact_scopes={gap(): http},
        recipes=(known_recipe,),
        permissions=frozenset({"collect.read"}),
    )
    assert projected[0].scope_kind == ScopeKind.EXACT
    assert projected[0].packets.equivalent(http)
    assert projected[0].recipe == known_recipe


def test_projection_is_conservative_without_known_scope_or_permission(manager):
    universe = header(manager, {"protocol": 6, "destination_port": [80, 443]})
    projected = project_gaps((gap(),), universe, recipes=(recipe(),))
    assert projected[0].scope_kind == ScopeKind.CONSERVATIVE
    assert projected[0].packets.equivalent(universe)
    assert projected[0].recipe is None


def test_projection_rejects_scope_outside_request_universe(manager):
    universe = header(manager, {"protocol": 6, "destination_port": 80})
    outside = header(manager, {"protocol": 6, "destination_port": 443})
    with pytest.raises(ValueError, match="within request_universe"):
        project_gaps((gap(),), universe, exact_scopes={gap(): outside})
