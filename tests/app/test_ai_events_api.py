"""GET /api/settings/ai/events: the admin read of the AI audit trail."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from tests.app.conftest import login

from hst.app.store import AiEvent


@pytest.mark.parametrize("username", ["vera", "otto"])
async def test_viewers_and_operators_are_denied(client, username):
    await login(client, username)
    assert (await client.get("/api/settings/ai/events")).status_code == 403


async def test_events_come_newest_first_with_a_daily_token_sum_per_user(client, seeded):
    ada = await seeded.get_user_by_username("ada")
    today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    latest = today + timedelta(hours=23)
    for at, user_id, tokens in (
        (today, None, (3, 1)),
        (today + timedelta(seconds=1), ada.id, (100, 20)),
        (today + timedelta(seconds=2), ada.id, (50, 5)),
        (today - timedelta(days=1), ada.id, (7, 7)),
        (today - timedelta(days=40), ada.id, (9, 9)),
    ):
        await seeded.record_ai_event(
            AiEvent(
                at=at,
                origin="web",
                event="provider.round",
                outcome="ok",
                user_id=user_id,
                tokens_in=tokens[0],
                tokens_out=tokens[1],
            )
        )
    await seeded.record_ai_event(
        AiEvent(
            at=latest,
            origin="mcp",
            event="tool.call",
            outcome="error",
            tool="trace_path",
            error_class="ValueError",
        )
    )

    await login(client, "ada")
    r = await client.get("/api/settings/ai/events", params={"limit": 2})
    assert r.status_code == 200, r.text
    body = r.json()

    assert [(e["event"], e["tool"], e["username"]) for e in body["events"]] == [
        ("tool.call", "trace_path", None),
        ("provider.round", None, "ada"),
    ]
    assert body["events"][0]["at"] == latest.isoformat()
    assert body["daily_tokens"] == [
        {
            "day": today.date().isoformat(),
            "user_id": ada.id,
            "username": "ada",
            "tokens_in": 150,
            "tokens_out": 25,
        },
        {"day": today.date().isoformat(), "user_id": None, "username": None, "tokens_in": 3, "tokens_out": 1},
        {
            "day": (today - timedelta(days=1)).date().isoformat(),
            "user_id": ada.id,
            "username": "ada",
            "tokens_in": 7,
            "tokens_out": 7,
        },
    ]

    one_day = (await client.get("/api/settings/ai/events", params={"days": 1})).json()
    assert [row["tokens_in"] for row in one_day["daily_tokens"]] == [150, 3]
