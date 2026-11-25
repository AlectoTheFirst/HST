"""The uid lookups outside the path package (AI tools, page context, the explorer) seek obj_uid_cts."""

from typing import Any

import pytest

from hst.app.ai import context_resolver
from hst.app.routes import explore
from hst.twin_tools import inventory

RUN = 4_500_000_000_000

pytestmark = pytest.mark.db


def _operators(plan: Any) -> list[tuple[str, str]]:
    out = [(plan["operatorType"], str(plan.get("args", {}).get("Details", "")))]
    for child in plan.get("children") or []:
        out += _operators(child)
    return out


@pytest.mark.parametrize(
    ("query", "params"),
    [
        (inventory._CARRIED_QUERY, {"uids": ["dev:x"], "snap": RUN}),
        (context_resolver._VERIFY_UIDS, {"uids": ["dev:x"], "snap": RUN}),
        (explore._by_uid("q") + "RETURN n", {"q": "dev:x", "snap": RUN}),
    ],
)
def test_a_uid_lookup_seeks_the_run_index_and_scans_no_label(
    neo4j_session: Any, query: str, params: Any
) -> None:
    plan = neo4j_session.run("EXPLAIN " + query, **params).consume().plan
    operators = _operators(plan)
    seeks = [op for op, details in operators if "IndexSeek" in op and "collection_ts" in details]
    assert seeks, (operators, query)
    assert not [op for op, _ in operators if op.startswith(("NodeByLabelScan", "AllNodesScan"))], (
        operators,
        query,
    )
