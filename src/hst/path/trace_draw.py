from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .gates import Stage

if TYPE_CHECKING:
    from .gates import _Trail


def _zpa_early_result(
    trail: _Trail, *, verdict: str, indeterminate: bool, blocking_uid: str | None = None
) -> dict[str, Any]:
    leg: dict[str, Any] = {"indeterminate": indeterminate}
    if blocking_uid:
        leg["blocked"] = True
        leg["blocking_uid"] = blocking_uid
    trail.rank_hops()
    return {
        "hops": trail.hops,
        "legs": [leg],
        "verdict": verdict,
        "notes": trail.notes,
        "warnings": trail.warnings,
        "indeterminate": indeterminate,
        "boundary": False,
    }


def _zpa_stop(trail: _Trail, reason: str, *, blocking_uid: str | None = None) -> dict[str, Any]:
    """The result of a brokered trace that stops with `reason`. `reason` is a
    warning and the verdict. The object `blocking_uid` blocked the flow if it is
    set. The stop is indeterminate if it is not set."""
    trail.warn(reason)
    return _zpa_early_result(
        trail, verdict=reason, indeterminate=blocking_uid is None, blocking_uid=blocking_uid
    )


def _dev_label(dev: dict[str, Any]) -> Any:
    """A device row's name, or its uid when it has none."""
    return dev["dev_name"] or dev["dev_uid"]


def _draw_arrival(
    trail: _Trail,
    at: dict[str, Any],
    *,
    if_note: str | None = None,
    dev_fallback: str = "",
    dev_note: str = "",
) -> None:
    """Draws the ingress interface and the device that the flow arrives on.
    `if_note` defaults to "on <device name>". A device with no name has the
    label `dev_fallback`."""
    trail.hop(
        at["if_uid"],
        "Interface",
        at["if_name"],
        f"on {at['dev_name']}" if if_note is None else if_note,
        stage=Stage.INGRESS_IF,
    )
    trail.hop(at["dev_uid"], "Device", at["dev_name"] or dev_fallback, dev_note, stage=Stage.DEVICE)


# The keys are the reasons of core/cycle.py `CARRY_REASONS` except `unchanged`.
_CARRIED_WHY = {
    "not-run": "its source did not run this cycle",
    "failed": "its collection failed this cycle",
    "cancelled": "its collection was stopped this cycle",
    "section-failed": "a section of it was not collected this cycle",
}


def _warn_carried(trail: _Trail, dev: dict[str, Any]) -> None:
    reason = dev.get("dev_carried_reason") or dev.get("carried_reason")
    if reason == "unchanged":
        return
    why = _CARRIED_WHY.get(str(reason), _CARRIED_WHY["not-run"])
    trail.warn(f"{_dev_label(dev)}: state carried forward from an earlier run ({why})")


def _indeterminate_stop(
    trail: _Trail, leg: dict[str, Any], lane: int, reason: str, **fields: Any
) -> tuple[list[dict[str, Any]], int]:
    leg["indeterminate"] = True
    leg.update(fields)
    leg.setdefault("indeterminate_reason", reason)
    trail.warn(reason)
    return [leg], lane + 1


def _reply_not_derived(
    verdict: str, destinations: list[str], notes: list[str] | None = None
) -> dict[str, Any]:
    """The reply result for a forward leg the reply cannot be walked from."""
    return {
        "hops": [],
        "legs": [],
        "notes": list(notes or []),
        "warnings": [],
        "verdict": verdict,
        "indeterminate": True,
        "boundary": False,
        "asymmetric": False,
        "comparison_notes": [],
        "destinations": destinations,
    }
