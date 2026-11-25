"""Placement resolution."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from hst.app.inventory.contracts import (
    Authority,
    ObservationState,
    PlacementBasis,
    PlacementMode,
    PlacementOrigin,
    PlacementState,
)


@dataclass(frozen=True)
class Intent:
    """The placement row of a device, or the implicit `auto` row of a device
    that has none (revision 0, nothing applied)."""

    mode: PlacementMode = PlacementMode.AUTO
    site_id: int | None = None
    origin: PlacementOrigin = PlacementOrigin.MANUAL
    revision: int = 0
    applied_revision: int = 0
    published_site_id: int | None = None
    published_snapshot_key: str | None = None
    actor_id: int | None = None
    updated_at: datetime | None = None


@dataclass(frozen=True)
class Claim:
    """The location evidence of one observation.

    `site_id` is the binding of the reported location. It is None when the location is unbound
    or when the observation reports no location. `location_handle` is None when the
    observation reports no location."""

    target_id: UUID
    connection_id: str
    state: ObservationState
    authority: Authority
    location_handle: UUID | None = None
    location_name: str = ""
    site_id: int | None = None


@dataclass(frozen=True)
class Resolved:
    mode: PlacementMode
    state: PlacementState
    basis: PlacementBasis
    desired_site_id: int | None
    publish_site_id: int | None
    conflict: bool
    stale: bool
    pending: bool
    desired_revision: int
    applied_revision: int
    published_site_id: int | None
    published_snapshot_key: str | None
    origin: PlacementOrigin
    actor_id: int | None
    updated_at: datetime | None
    contributing: tuple[Claim, ...] = field(default_factory=tuple)

    @property
    def summary_state(self) -> PlacementState:
        """Return the value of the indexed column `placement_state`.

        The value is `pending` when the last publication has not covered the intent. Otherwise
        it is the resolved state."""
        return PlacementState.PENDING if self.pending else self.state


def _location_claims(claims: list[Claim]) -> list[Claim]:
    return [c for c in claims if c.state != ObservationState.ABSENT and c.location_handle is not None]


def resolve(intent: Intent | None, claims: list[Claim]) -> Resolved:
    """Resolve the placement of one device.

    An `intent` of None stands for a device without a placement row, in mode auto at revision 0.
    `claims` are the observations of the device with their location binding. The result does
    not depend on the order of `claims`."""
    it = intent or Intent()
    contributing = _location_claims(claims)
    if it.mode == PlacementMode.ASSIGNED:
        desired = it.site_id
        state, basis, conflict, stale = PlacementState.ASSIGNED, PlacementBasis.ASSIGNED, False, False
        publish = desired
    elif it.mode == PlacementMode.UNPLACED:
        desired = None
        state, basis, conflict, stale = PlacementState.UNPLACED, PlacementBasis.NONE, False, False
        publish = None
    else:
        current = sorted(
            {c.site_id for c in contributing if c.state == ObservationState.CURRENT and c.site_id is not None}
        )
        stale_sites = {c.site_id for c in contributing if c.state == ObservationState.STALE and c.site_id}
        if len(current) == 1:
            desired = current[0]
            state, basis, conflict, stale = PlacementState.AUTO, PlacementBasis.BOUND_LOCATIONS, False, False
            publish = desired
        elif len(current) > 1:
            desired = None
            state, basis, conflict, stale = (
                PlacementState.CONFLICT,
                PlacementBasis.BOUND_LOCATIONS,
                True,
                False,
            )
            publish = None
        elif stale_sites:
            desired = None
            state, basis, conflict, stale = PlacementState.STALE, PlacementBasis.BOUND_LOCATIONS, False, True
            publish = it.published_site_id
        else:
            desired = None
            state, basis, conflict, stale = PlacementState.UNPLACED, PlacementBasis.NONE, False, False
            publish = None
    if it.mode == PlacementMode.ASSIGNED and it.origin == PlacementOrigin.ONBOARDING:
        basis = PlacementBasis.ONBOARDING
    pending = it.revision > it.applied_revision or publish != it.published_site_id
    return Resolved(
        mode=it.mode,
        state=state,
        basis=basis,
        desired_site_id=desired,
        publish_site_id=publish,
        conflict=conflict,
        stale=stale,
        pending=pending,
        desired_revision=it.revision,
        applied_revision=it.applied_revision,
        published_site_id=it.published_site_id,
        published_snapshot_key=it.published_snapshot_key,
        origin=it.origin,
        actor_id=it.actor_id,
        updated_at=it.updated_at,
        contributing=tuple(sorted(contributing, key=lambda c: (c.connection_id, str(c.target_id)))),
    )


@dataclass(frozen=True)
class OnboardingDefault:
    """The result of the one-time onboarding rule for a newly registered device.

    `site_id` is the agreed site, or None. `candidates` are the distinct default sites of the
    targets."""

    site_id: int | None
    candidates: tuple[int, ...]

    @property
    def conflict(self) -> bool:
        return len(self.candidates) > 1


def onboarding_default(target_site_ids: list[int | None]) -> OnboardingDefault:
    """Apply the onboarding defaults of the targets to a device seen for the first time.

    A target without a default has no vote. One distinct site is the agreed site. With 2 or
    more distinct sites the result has no site, the device stays in auto mode and the caller
    records the conflict."""
    candidates = tuple(sorted({s for s in target_site_ids if s is not None}))
    return OnboardingDefault(candidates[0] if len(candidates) == 1 else None, candidates)
