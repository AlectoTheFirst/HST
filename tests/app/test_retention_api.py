"""Retention settings: the API, the bounds, and the environment fallback."""

from __future__ import annotations

import pytest
from tests.app.conftest import login

from hst.app import retention
from hst.app.main import create_app
from hst.core import Settings


@pytest.fixture
def app(seeded):
    return create_app(
        settings=Settings(
            _env_file=None,
            cycle_keep_runs=30,
            login_event_retention_days=90,
            cypher_event_retention_days=180,
            job_history_retention_days=30,
        ),
        store=seeded,
    )


async def test_settings_are_admin_only(client):
    await login(client, "otto")
    assert (await client.get("/api/settings/retention")).status_code == 403
    assert (await client.patch("/api/settings/retention", json={"cycle_keep_runs": 5})).status_code == 403


async def test_environment_values_answer_before_anything_is_stored(client):
    await login(client, "ada")
    body = (await client.get("/api/settings/retention")).json()
    assert body == {
        "cycle_keep_runs": 30,
        "cycle_keep_device_runs": 48,
        "login_event_retention_days": 90,
        "cypher_event_retention_days": 180,
        "job_history_retention_days": 30,
        "ai_conversation_retention_days": 90,
        "ai_step_result_days": 14,
        "ai_event_retention_days": 180,
        "updated_at": None,
    }


async def test_a_stored_value_overrides_the_environment(client, store):
    await login(client, "ada")
    r = await client.patch("/api/settings/retention", json={"cycle_keep_runs": 7})
    assert r.status_code == 200, r.text
    assert r.json()["cycle_keep_runs"] == 7
    assert r.json()["updated_at"] is not None
    body = (await client.get("/api/settings/retention")).json()
    assert body["cycle_keep_runs"] == 7
    assert body["login_event_retention_days"] == 90
    # only what was sent is on the document, so the rest stays environment-driven
    assert store.settings_rows[retention.SETTINGS_KEY].value == {"cycle_keep_runs": 7}


async def test_patch_leaves_the_fields_it_omits_alone(client):
    await login(client, "ada")
    await client.patch("/api/settings/retention", json={"cycle_keep_runs": 7})
    await client.patch("/api/settings/retention", json={"login_event_retention_days": 14})
    body = (await client.get("/api/settings/retention")).json()
    assert body["cycle_keep_runs"] == 7
    assert body["login_event_retention_days"] == 14


async def test_zero_days_is_keep_everything_and_is_accepted(client):
    await login(client, "ada")
    r = await client.patch(
        "/api/settings/retention",
        json={"login_event_retention_days": 0, "cypher_event_retention_days": 0},
    )
    assert r.status_code == 200
    assert r.json()["login_event_retention_days"] == 0
    assert r.json()["cypher_event_retention_days"] == 0


@pytest.mark.parametrize(
    "body",
    [
        {"cycle_keep_runs": 0},  # the current cycle is the twin; 0 has no meaning
        {"cycle_keep_runs": -1},
        {"cycle_keep_device_runs": -1},
        {"cycle_keep_device_runs": retention.MAX_KEEP_RUNS + 1},
        {"login_event_retention_days": -1},
        {"cypher_event_retention_days": -1},
        {"job_history_retention_days": -1},
        {"cycle_keep_runs": retention.MAX_KEEP_RUNS + 1},
        {"login_event_retention_days": retention.MAX_RETENTION_DAYS + 1},
    ],
)
async def test_out_of_range_values_are_refused(client, body):
    await login(client, "ada")
    assert (await client.patch("/api/settings/retention", json=body)).status_code == 422


def test_merged_ignores_a_document_field_of_the_wrong_type():
    settings = Settings(_env_file=None, cycle_keep_runs=30, login_event_retention_days=90)
    limits = retention.merged({"cycle_keep_runs": "lots", "login_event_retention_days": True}, settings)
    assert limits.cycle_keep_runs == 30
    assert limits.login_event_retention_days == 90


async def test_resolve_reads_the_stored_document(store):
    settings = Settings(_env_file=None, cycle_keep_runs=30)
    await store.put_setting(retention.SETTINGS_KEY, {"cycle_keep_runs": 3}, b"")
    assert (await retention.resolve(store, settings)).cycle_keep_runs == 3


async def test_the_job_history_limit_is_stored_and_read_like_the_others(client, store):
    await login(client, "ada")
    r = await client.patch("/api/settings/retention", json={"job_history_retention_days": 7})
    assert r.status_code == 200
    assert r.json()["job_history_retention_days"] == 7
    assert store.settings_rows[retention.SETTINGS_KEY].value == {"job_history_retention_days": 7}
    assert r.json()["cycle_keep_runs"] == 30


def test_a_document_without_the_job_history_limit_takes_its_default():
    settings = Settings(_env_file=None, job_history_retention_days=30)
    limits = retention.merged({"cycle_keep_runs": 5}, settings)
    assert limits.cycle_keep_runs == 5
    assert limits.job_history_retention_days == 30


async def test_the_ai_limits_are_stored_and_read_like_the_others(client, store):
    await login(client, "ada")
    r = await client.patch(
        "/api/settings/retention",
        json={"ai_conversation_retention_days": 30, "ai_step_result_days": 0, "ai_event_retention_days": 365},
    )
    assert r.status_code == 200, r.text
    body = (await client.get("/api/settings/retention")).json()
    assert (
        body["ai_conversation_retention_days"],
        body["ai_step_result_days"],
        body["ai_event_retention_days"],
    ) == (
        30,
        0,
        365,
    )
    assert store.settings_rows[retention.SETTINGS_KEY].value == {
        "ai_conversation_retention_days": 30,
        "ai_step_result_days": 0,
        "ai_event_retention_days": 365,
    }


@pytest.mark.parametrize(
    "body",
    [
        {"ai_conversation_retention_days": -1},
        {"ai_step_result_days": -1},
        {"ai_event_retention_days": retention.MAX_RETENTION_DAYS + 1},
    ],
)
async def test_out_of_range_ai_limits_are_refused(client, body):
    await login(client, "ada")
    assert (await client.patch("/api/settings/retention", json=body)).status_code == 422


def test_the_ai_limits_default_from_the_environment_and_merge_per_field():
    settings = Settings(_env_file=None, ai_step_result_days=7)
    limits = retention.merged({"ai_event_retention_days": 30, "ai_conversation_retention_days": -5}, settings)
    assert (
        limits.ai_conversation_retention_days,
        limits.ai_step_result_days,
        limits.ai_event_retention_days,
    ) == (
        0,
        7,
        30,
    )
    env = retention.defaults(Settings(_env_file=None))
    assert (env.ai_conversation_retention_days, env.ai_step_result_days, env.ai_event_retention_days) == (
        90,
        14,
        180,
    )


async def test_the_device_run_count_is_stored_and_read_like_the_others(client, store):
    """Device and refresh runs are kept by their own count beside the cycles."""
    await login(client, "ada")
    r = await client.patch("/api/settings/retention", json={"cycle_keep_device_runs": 12})
    assert r.status_code == 200, r.text
    assert r.json()["cycle_keep_device_runs"] == 12
    assert (await client.get("/api/settings/retention")).json()["cycle_keep_device_runs"] == 12
    assert store.settings_rows[retention.SETTINGS_KEY].value == {"cycle_keep_device_runs": 12}
    assert (await retention.resolve(store, Settings(_env_file=None))).cycle_keep_device_runs == 12


async def test_zero_device_runs_is_accepted(client):
    await login(client, "ada")
    r = await client.patch("/api/settings/retention", json={"cycle_keep_device_runs": 0})
    assert r.status_code == 200
    assert r.json()["cycle_keep_device_runs"] == 0
