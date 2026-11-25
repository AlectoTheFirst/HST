"""The uid lookups outside the path package name the run index."""

from __future__ import annotations

import pytest
from tests.test_time_travel import anchor_problems

from hst.app.ai import context_resolver
from hst.app.routes import explore
from hst.twin_tools import inventory

HINT = "USING INDEX n:Obj(uid, collection_ts)"


@pytest.mark.parametrize(
    "query",
    [
        inventory._CARRIED_QUERY,
        context_resolver._VERIFY_UIDS,
        explore._by_uid("q"),
    ],
)
def test_a_uid_lookup_hints_the_composite_index_and_pins_the_run(query: str) -> None:
    assert HINT in query
    assert "coalesce(n.collection_ts" not in query
    assert anchor_problems(query + " RETURN n") == []
