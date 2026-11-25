"""What the loader's upsert statements return (core/loader.py)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hst.core.fixtures import load_fixture
from hst.core.loader import load, node_upsert_query, rel_upsert_query

FIXTURE = Path(__file__).parents[1] / "fixtures" / "mini-dc.yaml"


def _return_clause(query: str) -> str:
    return query.strip().splitlines()[-1]


def test_a_node_upsert_returns_the_uid_and_the_map_before_the_write():
    query = node_upsert_query("Device")
    assert _return_clause(query) == "RETURN row.uid AS uid, before"
    assert "WITH n, row, properties(n) AS before" in query


def test_a_relationship_upsert_returns_its_collected_at_before_the_write():
    query = rel_upsert_query("CONNECTED_TO", ("port",))
    assert _return_clause(query) == "RETURN row.start AS start, row.end AS end, before"
    assert "WITH r, row, r {.collected_at} AS before" in query
    assert "properties(r)" not in query


class _Session:
    """Every node is new. Each relationship MERGE row is answered with the next
    `before` of a repeating list, and the answers are kept."""

    def __init__(self, rel_befores: list[Any]) -> None:
        self.rel_befores = rel_befores
        self.answered: list[Any] = []

    def execute_write(self, work: Any) -> Any:
        return work(self)

    def run(self, query: str, **params: Any) -> Any:
        rows: list[dict[str, Any]] = []
        if "MERGE (n" in query:
            rows = [{"uid": r["uid"], "before": {"uid": r["uid"]}} for r in params["rows"]]
        elif "MERGE (a)-" in query:
            for r in params["rows"]:
                before = self.rel_befores[len(self.answered) % len(self.rel_befores)]
                self.answered.append(before)
                rows.append({"start": r["start"], "end": r["end"], "before": before})

        class _Result:
            def data(self) -> list[dict[str, Any]]:
                return rows

        return _Result()


def test_a_relationship_counts_as_created_when_it_had_no_collected_at():
    batch = load_fixture(FIXTURE)
    session = _Session(
        [
            {"collected_at": None},  # what the projection returns for a new relationship
            {"collected_at": 1_000},  # an existing one
            {},
            None,
            {"collected_at": 0},
        ]
    )

    manifest = load(session, batch, ts_ms=2_000)

    assert len(session.answered) == manifest.rels_upserted == len(batch.rels)
    created = sum(1 for before in session.answered if not before or before.get("collected_at") is None)
    assert 0 < created < len(batch.rels)
    assert manifest.rels_created == created
    assert manifest.nodes_created == len(batch.nodes)
