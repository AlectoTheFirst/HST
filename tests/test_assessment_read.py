"""Saved model-tool results preserve historical identity and hide worker capabilities."""

from types import SimpleNamespace

import pytest

from hst.assessment import read
from hst.assessment.store import MemoryAssessmentStore


@pytest.fixture
def store(monkeypatch):
    class Store(MemoryAssessmentStore):
        closed = False

        async def dispose(self):
            self.closed = True

    instance = Store()
    monkeypatch.setattr(read, "PgStore", lambda *args: instance)
    return instance


async def test_exact_run_never_resolves_latest_and_omits_worker_secrets(store):
    settings = SimpleNamespace(postgres_dsn="unused", postgres_ca_file="")
    assessment = await store.create_assessment(
        title="Checkout", purpose="evaluation", definition={}, created_by=1
    )
    queued = await store.enqueue_analysis(
        assessment_id=assessment.id,
        assessment_revision=1,
        kind="evaluate",
        inputs={"request": "recorded"},
        snapshot_refs=[{"snapshot": "100"}],
        engine_version="build-original",
        created_by=1,
    )
    claimed = await store.claim_analysis("worker-private")
    result = await read.read_saved(settings, queued.id)
    assert claimed.lease_token
    assert result["run"]["inputs"] == {"request": "recorded"}
    assert result["run"]["engine_version"] == "build-original"
    assert not {"lease_token", "checkpoint", "claimed_by"} & result["run"].keys()
    assert store.closed
    listed = await read.read_saved(settings)
    assert listed["assessments"][0]["runs"][0]["id"] == queued.id


async def test_tool_result_limit_and_input_bounds(store, monkeypatch):
    settings = SimpleNamespace(postgres_dsn="unused", postgres_ca_file="")
    assessment = await store.create_assessment(
        title="Checkout", purpose="evaluation", definition={}, created_by=1
    )
    run = await store.enqueue_analysis(
        assessment_id=assessment.id,
        assessment_revision=1,
        kind="evaluate",
        inputs={},
        snapshot_refs=[{"snapshot": "100"}],
        engine_version="build",
        created_by=1,
    )
    monkeypatch.setattr(read, "MAX_RESULT_BYTES", 10)
    result = await read.read_saved(settings, run.id)
    assert "export" in result["error"]
    with pytest.raises(ValueError, match="limit"):
        await read.read_saved(settings, limit=1000)


async def _one_assessment(store) -> None:
    await store.create_assessment(title="Checkout", purpose="evaluation", definition={}, created_by=1)


def _no_pg_store(*args):
    raise AssertionError("a PgStore was opened although an app store was given")


async def test_read_saved_uses_the_given_store_and_leaves_it_open(monkeypatch):
    app_store = MemoryAssessmentStore()
    await _one_assessment(app_store)
    monkeypatch.setattr(read, "PgStore", _no_pg_store)
    disposed: list[bool] = []

    async def dispose():
        disposed.append(True)

    monkeypatch.setattr(app_store, "dispose", dispose, raising=False)

    listed = await read.read_saved(SimpleNamespace(), store=app_store)

    assert [a["title"] for a in listed["assessments"]] == ["Checkout"]
    assert disposed == []


async def test_listed_runs_carry_their_snapshot_references_only_on_request():
    app_store = MemoryAssessmentStore()
    assessment = await app_store.create_assessment(
        title="Checkout", purpose="evaluation", definition={}, created_by=1
    )
    await app_store.enqueue_analysis(
        assessment_id=assessment.id,
        assessment_revision=1,
        kind="evaluate",
        inputs={},
        snapshot_refs=[{"snapshot": "100", "manifest_sha256": "a" * 64, "estate": "e"}],
        engine_version="build",
        created_by=1,
    )

    plain = await read.read_saved(SimpleNamespace(), store=app_store)
    with_refs = await read.read_saved(SimpleNamespace(), store=app_store, snapshot_refs=True)

    assert "snapshot_refs" not in plain["assessments"][0]["runs"][0]
    assert with_refs["assessments"][0]["runs"][0]["snapshot_refs"] == [
        {"snapshot": "100", "manifest_sha256": "a" * 64, "estate": "e"}
    ]
