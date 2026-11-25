"""Placement resolution and the collection-state rule, as pure functions."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from hst.app.inventory import placement as p
from hst.app.inventory.contracts import (
    Authority,
    CollectionState,
    ObservationState,
    PlacementBasis,
    PlacementMode,
    PlacementOrigin,
    PlacementState,
)
from hst.app.inventory.observations import (
    TargetEvidence,
    collection_state,
    stale_threshold,
)

NOW = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
FRA, AMS = 10, 11


def claim(
    site: int | None,
    *,
    state: ObservationState = ObservationState.CURRENT,
    bound_location: bool = True,
    connection: str = "1",
) -> p.Claim:
    return p.Claim(
        target_id=uuid.uuid4(),
        connection_id=connection,
        state=state,
        authority=Authority.COMPLETE,
        location_handle=uuid.uuid4() if bound_location else None,
        location_name="loc",
        site_id=site,
    )


# --- explicit modes --------------------------------------------------------------------


def test_assigned_returns_its_site_whatever_the_observations_say():
    intent = p.Intent(PlacementMode.ASSIGNED, FRA, revision=2, applied_revision=2, published_site_id=FRA)
    r = p.resolve(intent, [claim(AMS), claim(AMS, connection="2")])
    assert r.state == PlacementState.ASSIGNED
    assert r.desired_site_id == FRA and r.publish_site_id == FRA
    assert r.basis == PlacementBasis.ASSIGNED
    assert not r.conflict and not r.stale and not r.pending
    assert [c.site_id for c in r.contributing] == [AMS, AMS]


def test_assigned_with_origin_onboarding_reports_that_basis():
    intent = p.Intent(PlacementMode.ASSIGNED, FRA, origin=PlacementOrigin.ONBOARDING, revision=1)
    r = p.resolve(intent, [])
    assert r.basis == PlacementBasis.ONBOARDING
    assert r.desired_site_id == FRA


def test_explicit_unplaced_blocks_automatic_placement():
    intent = p.Intent(PlacementMode.UNPLACED, None, revision=3, applied_revision=3, published_site_id=None)
    r = p.resolve(intent, [claim(FRA)])
    assert r.state == PlacementState.UNPLACED
    assert r.desired_site_id is None and r.publish_site_id is None
    assert r.basis == PlacementBasis.NONE
    assert not r.pending


# --- auto ----------------------------------------------------------------------------------


def test_no_placement_row_is_auto_at_revision_zero():
    r = p.resolve(None, [])
    assert r.mode == PlacementMode.AUTO
    assert r.desired_revision == 0 and r.applied_revision == 0
    assert r.state == PlacementState.UNPLACED
    assert not r.pending


def test_auto_with_one_bound_site_from_several_targets_places_there():
    r = p.resolve(None, [claim(FRA), claim(FRA, connection="2")])
    assert r.state == PlacementState.AUTO
    assert r.desired_site_id == FRA
    assert r.basis == PlacementBasis.BOUND_LOCATIONS
    assert not r.conflict


def test_auto_with_two_bound_sites_is_a_conflict_with_no_site_chosen():
    r = p.resolve(None, [claim(FRA), claim(AMS, connection="2")])
    assert r.state == PlacementState.CONFLICT
    assert r.conflict and r.desired_site_id is None and r.publish_site_id is None
    # both claims are there for the operator to see
    assert sorted(c.site_id for c in r.contributing if c.site_id) == [FRA, AMS]


def test_conflict_is_deterministic_whatever_the_order_of_claims():
    a, b = claim(FRA), claim(AMS, connection="2")
    assert p.resolve(None, [a, b]).contributing == p.resolve(None, [b, a]).contributing


def test_unbound_location_does_not_veto_a_bound_one_but_is_shown_as_evidence():
    r = p.resolve(None, [claim(FRA), claim(None, connection="2")])
    assert r.desired_site_id == FRA and not r.conflict
    unbound = [c for c in r.contributing if c.site_id is None]
    assert len(unbound) == 1 and unbound[0].location_handle is not None


def test_only_unbound_locations_is_unplaced():
    r = p.resolve(None, [claim(None), claim(None, connection="2")])
    assert r.state == PlacementState.UNPLACED and r.desired_site_id is None


def test_observation_without_a_location_makes_no_claim():
    r = p.resolve(None, [claim(None, bound_location=False)])
    assert r.contributing == ()
    assert r.state == PlacementState.UNPLACED


def test_stale_only_evidence_is_stale_and_carries_the_prior_published_site():
    intent = p.Intent(PlacementMode.AUTO, None, revision=0, applied_revision=0, published_site_id=FRA)
    r = p.resolve(intent, [claim(FRA, state=ObservationState.STALE)])
    assert r.state == PlacementState.STALE and r.stale
    assert r.desired_site_id is None, "stale evidence is never a fresh assertion"
    assert r.publish_site_id == FRA, "the edge is carried, not removed"
    assert r.published_site_id == FRA
    assert not r.pending


def test_a_current_claim_outranks_stale_evidence_of_another_site():
    r = p.resolve(None, [claim(FRA, state=ObservationState.STALE), claim(AMS, connection="2")])
    assert r.state == PlacementState.AUTO and r.desired_site_id == AMS
    assert not r.stale and not r.conflict


def test_absent_observations_contribute_nothing():
    r = p.resolve(None, [claim(FRA, state=ObservationState.ABSENT)])
    assert r.contributing == ()
    assert r.state == PlacementState.UNPLACED


# --- pending -----------------------------------------------------------------------------


def test_pending_when_the_intent_revision_is_not_covered_even_if_the_site_is_the_same():
    intent = p.Intent(PlacementMode.ASSIGNED, FRA, revision=3, applied_revision=2, published_site_id=FRA)
    r = p.resolve(intent, [])
    assert r.pending and r.summary_state == PlacementState.PENDING


def test_pending_when_a_binding_change_moves_an_auto_device_at_the_same_revision():
    intent = p.Intent(PlacementMode.AUTO, None, revision=1, applied_revision=1, published_site_id=FRA)
    r = p.resolve(intent, [claim(AMS)])
    assert r.desired_site_id == AMS and r.published_site_id == FRA
    assert r.pending


def test_not_pending_once_the_publication_covers_revision_and_site():
    intent = p.Intent(PlacementMode.AUTO, None, revision=1, applied_revision=1, published_site_id=AMS)
    r = p.resolve(intent, [claim(AMS)])
    assert not r.pending and r.summary_state == PlacementState.AUTO


def test_conflict_after_a_published_site_is_pending_until_the_edge_is_withdrawn():
    intent = p.Intent(PlacementMode.AUTO, None, revision=1, applied_revision=1, published_site_id=FRA)
    r = p.resolve(intent, [claim(FRA), claim(AMS, connection="2")])
    assert r.conflict and r.pending
    after = p.Intent(PlacementMode.AUTO, None, revision=1, applied_revision=1, published_site_id=None)
    assert not p.resolve(after, [claim(FRA), claim(AMS, connection="2")]).pending


# --- onboarding default ------------------------------------------------------------------


def test_onboarding_default_agrees_when_every_target_with_a_default_names_one_site():
    d = p.onboarding_default([FRA, None, FRA])
    assert d.site_id == FRA and not d.conflict


def test_onboarding_default_conflict_when_defaults_disagree_regardless_of_order():
    assert p.onboarding_default([FRA, AMS]).conflict
    assert p.onboarding_default([AMS, FRA]).site_id is None
    assert p.onboarding_default([AMS, FRA]).candidates == (FRA, AMS)


def test_onboarding_default_absent_when_no_target_has_one():
    d = p.onboarding_default([None, None])
    assert d.site_id is None and not d.conflict and d.candidates == ()


# --- collection state --------------------------------------------------------------


def ev(*, attempted=True, ok=True, age_s: float = 10, deadline: float | None = 900) -> TargetEvidence:
    return TargetEvidence(attempted, ok, NOW - timedelta(seconds=age_s) if attempted else None, deadline)


def test_stale_threshold_is_three_intervals_with_a_five_minute_floor():
    assert stale_threshold(60, 0) == 300
    assert stale_threshold(600, 0) == 1800
    assert stale_threshold(0, 900) == 2700
    assert stale_threshold(0, 30) == 300
    assert stale_threshold(0, 0) is None


def test_collection_state_vocabulary():
    assert collection_state([], NOW) == CollectionState.NEVER
    assert collection_state([ev(attempted=False)], NOW) == CollectionState.NEVER
    assert collection_state([ev(ok=False), ev(ok=False)], NOW) == CollectionState.FAILED
    assert collection_state([ev(ok=False), ev()], NOW) == CollectionState.PARTIAL
    assert collection_state([ev(), ev(age_s=5000)], NOW) == CollectionState.STALE
    assert collection_state([ev(), ev()], NOW) == CollectionState.CURRENT


def test_manual_collection_has_no_invented_stale_deadline():
    old = ev(age_s=10_000_000, deadline=None)
    assert collection_state([old], NOW) == CollectionState.MANUAL
    # a periodic target beside it gives the device a deadline again
    assert collection_state([old, ev()], NOW) == CollectionState.CURRENT
    assert collection_state([old, ev(age_s=5000)], NOW) == CollectionState.STALE


def test_a_failed_target_that_once_succeeded_reads_failed():
    assert collection_state([ev(ok=False, age_s=5)], NOW) == CollectionState.FAILED
