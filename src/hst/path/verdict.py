"""Firewall rule action vocabulary and classification.

Every gate answers with PERMIT, DENY, or INDETERMINATE. `classify_action`
maps an action the engine does not recognise to INDETERMINATE.
"""

from __future__ import annotations

PERMIT_ACTIONS = frozenset({"accept", "permit", "allow", "pass"})
DENY_ACTIONS = frozenset({"drop", "reject", "deny", "blocked", "block"})

PERMIT, DENY, INDETERMINATE = "permit", "deny", "indeterminate"


def classify_action(action: str | None) -> str:
    a = (action or "").strip().lower()
    if a in PERMIT_ACTIONS:
        return PERMIT
    if a in DENY_ACTIONS:
        return DENY
    return INDETERMINATE
