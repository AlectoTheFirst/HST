"""Alembic: the migrations run forwards, run backwards, and match the models."""

import asyncio
import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.pg
DSN = os.environ.get("HST_TEST_PG_DSN")
if not DSN:
    pytest.skip("HST_TEST_PG_DSN not set", allow_module_level=True)

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from alembic.util.exc import CommandError  # noqa: E402
from sqlalchemy import create_engine, inspect  # noqa: E402

from hst.app.store import pg as pgmod  # noqa: E402
from hst.app.store.pg import metadata, upgrade_to_head  # noqa: E402

# The inspector is synchronous and uses +psycopg.
SYNC_DSN = DSN.replace("+asyncpg", "+psycopg")


def _cfg() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(pgmod.__file__).parent / "migrations"))
    cfg.set_main_option("sqlalchemy.url", DSN.replace("%", "%%"))
    return cfg


@pytest.fixture
def at_head():
    """Leaves the database at head whatever the test did to it."""
    upgrade_to_head(DSN)
    yield
    upgrade_to_head(DSN)


def test_every_model_table_exists_at_head(at_head):
    engine = create_engine(SYNC_DSN)
    try:
        present = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()
    missing = {t.name for t in metadata.sorted_tables} - present
    assert not missing, f"tables in metadata but not in the migrated schema: {sorted(missing)}"
    assert "alembic_version" in present


def test_the_migrations_describe_the_models(at_head):
    try:
        command.check(_cfg())
    except CommandError as exc:
        pytest.fail(f"the models and the migrations disagree: {exc}")


def test_downgrade_to_base_and_back_up_again(at_head):
    cfg = _cfg()
    command.downgrade(cfg, "base")

    engine = create_engine(SYNC_DSN)
    try:
        after_down = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()
    left = {t.name for t in metadata.sorted_tables} & after_down
    assert not left, f"downgrade left tables behind: {sorted(left)}"

    command.upgrade(cfg, "head")
    engine = create_engine(SYNC_DSN)
    try:
        after_up = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()
    assert {t.name for t in metadata.sorted_tables} <= after_up


def test_upgrade_to_head_is_idempotent(at_head):
    asyncio.run(asyncio.to_thread(upgrade_to_head, DSN))
    upgrade_to_head(DSN)


def test_sso_schema_matches_the_design(at_head):
    engine = create_engine(SYNC_DSN)
    try:
        insp = inspect(engine)
        users_cols = {c["name"]: c for c in insp.get_columns("users")}
        identities_cols = {c["name"] for c in insp.get_columns("identities")}
        auth_state_cols = {c["name"] for c in insp.get_columns("auth_state")}
        identities_unique = insp.get_unique_constraints("identities")
        group_mappings_unique = insp.get_unique_constraints("group_mappings")
    finally:
        engine.dispose()

    assert users_cols["password_hash"]["nullable"] is True
    assert users_cols["role_source"]["nullable"] is False

    assert {"user_id", "provider_id", "subject", "email", "last_login_at"} <= identities_cols
    assert {"id", "provider_id", "kind", "payload", "expires_at"} <= auth_state_cols

    assert {"provider_id", "subject"} in (set(u["column_names"]) for u in identities_unique)
    assert {"provider_id", "group_name"} in (set(u["column_names"]) for u in group_mappings_unique)


def test_changes_schema_matches_the_design(at_head):
    """The change entity: a nullable snapshot pin, a status check constraint, and
    cascading intents."""
    engine = create_engine(SYNC_DSN)
    try:
        insp = inspect(engine)
        changes_cols = {c["name"]: c for c in insp.get_columns("changes")}
        intents_cols = {c["name"]: c for c in insp.get_columns("change_intents")}
        changes_checks = insp.get_check_constraints("changes")
        intents_unique = insp.get_unique_constraints("change_intents")
        intents_fks = insp.get_foreign_keys("change_intents")
    finally:
        engine.dispose()

    assert changes_cols["snapshot_cts"]["nullable"] is True
    assert changes_cols["created_by"]["nullable"] is True
    assert changes_cols["status"]["nullable"] is False
    assert any(c["name"] == "ck_changes_status" for c in changes_checks)

    assert {"change_id", "position", "kind", "params"} <= set(intents_cols)
    assert {"change_id", "position"} in (set(u["column_names"]) for u in intents_unique)
    (fk,) = [f for f in intents_fks if f["referred_table"] == "changes"]
    assert fk["options"].get("ondelete", "").upper() == "CASCADE"


def _ai_schema() -> tuple[set[str], set[str]]:
    """The AI audit tables present, and the columns of `cypher_events`."""
    engine = create_engine(SYNC_DSN)
    try:
        insp = inspect(engine)
        tables = set(insp.get_table_names()) & {"ai_events", "ai_prompt_versions"}
        cypher_cols = {c["name"] for c in insp.get_columns("cypher_events")}
    finally:
        engine.dispose()
    return tables, cypher_cols


def test_ai_events_schema_matches_the_design(at_head):
    """The table holds metadata only, user_id ON DELETE SET NULL, no foreign key on
    the conversation ids, and the two indexes the retention sweep and the
    per-user read use."""
    engine = create_engine(SYNC_DSN)
    try:
        insp = inspect(engine)
        cols = {c["name"]: c for c in insp.get_columns("ai_events")}
        fks = insp.get_foreign_keys("ai_events")
        indexes = {i["name"]: i["column_names"] for i in insp.get_indexes("ai_events")}
        prompt_cols = {c["name"]: c for c in insp.get_columns("ai_prompt_versions")}
        prompt_pk = insp.get_pk_constraint("ai_prompt_versions")
        cypher_cols = {c["name"]: c for c in insp.get_columns("cypher_events")}
    finally:
        engine.dispose()

    assert {name for name, col in cols.items() if not col["nullable"]} == {
        "id",
        "at",
        "origin",
        "event",
        "outcome",
    }
    (fk,) = fks
    assert (fk["referred_table"], fk["constrained_columns"]) == ("users", ["user_id"])
    assert fk["options"].get("ondelete", "").upper() == "SET NULL"
    assert indexes == {"ix_ai_events_at": ["at"], "ix_ai_events_user_at": ["user_id", "at"]}
    assert prompt_pk["constrained_columns"] == ["hash"]
    assert prompt_cols["content"]["nullable"] is False
    assert cypher_cols["origin"]["nullable"] is True
    assert cypher_cols["ai_step_id"]["nullable"] is True


def test_0032_downgrades_and_upgrades_again(at_head):
    cfg = _cfg()
    command.downgrade(cfg, "0031")
    tables, cypher_cols = _ai_schema()
    assert tables == set()
    assert not {"origin", "ai_step_id"} & cypher_cols

    command.upgrade(cfg, "head")
    tables, cypher_cols = _ai_schema()
    assert tables == {"ai_events", "ai_prompt_versions"}
    assert {"origin", "ai_step_id"} <= cypher_cols


_CONVERSATION_TABLES = {"ai_conversations", "ai_messages", "ai_steps", "ai_links"}


def _conversation_tables() -> set[str]:
    engine = create_engine(SYNC_DSN)
    try:
        return set(inspect(engine).get_table_names()) & _CONVERSATION_TABLES
    finally:
        engine.dispose()


def test_ai_conversation_schema_matches_the_design(at_head):
    """A conversation is deleted with its user, and messages,
    steps and links with their conversation. Labels and message seqs are
    unique per conversation."""
    engine = create_engine(SYNC_DSN)
    try:
        insp = inspect(engine)
        fks = {
            (table, fk["constrained_columns"][0]): (fk["referred_table"], fk["options"].get("ondelete"))
            for table in _CONVERSATION_TABLES
            for fk in insp.get_foreign_keys(table)
        }
        uniques = {
            table: {tuple(u["column_names"]) for u in insp.get_unique_constraints(table)}
            for table in ("ai_messages", "ai_steps")
        }
        # the indexes behind the unique constraints are checked above
        indexes = {
            i["name"]: i["column_names"]
            for table in _CONVERSATION_TABLES
            for i in insp.get_indexes(table)
            if "duplicates_constraint" not in i
        }
        step_cols = {c["name"]: c for c in insp.get_columns("ai_steps")}
    finally:
        engine.dispose()

    assert fks == {
        ("ai_conversations", "user_id"): ("users", "CASCADE"),
        ("ai_messages", "conversation_id"): ("ai_conversations", "CASCADE"),
        ("ai_messages", "prompt_hash"): ("ai_prompt_versions", None),
        ("ai_steps", "conversation_id"): ("ai_conversations", "CASCADE"),
        ("ai_steps", "message_id"): ("ai_messages", "CASCADE"),
        ("ai_links", "conversation_id"): ("ai_conversations", "CASCADE"),
        ("ai_links", "message_id"): ("ai_messages", "CASCADE"),
        ("ai_links", "step_id"): ("ai_steps", "CASCADE"),
    }
    assert uniques == {
        "ai_messages": {("conversation_id", "seq")},
        "ai_steps": {("conversation_id", "label")},
    }
    assert indexes == {
        "ix_ai_conversations_user_last": ["user_id", "last_message_at"],
        "ix_ai_conversations_last": ["last_message_at"],
        "ix_ai_messages_active": ["status"],
        "ix_ai_steps_message": ["message_id"],
        "ix_ai_links_ref": ["kind", "ref_id"],
    }
    assert step_cols["result"]["nullable"] is True
    assert step_cols["result_sha256"]["nullable"] is False


def test_0033_downgrades_and_upgrades_again(at_head):
    cfg = _cfg()
    command.downgrade(cfg, "0032")
    assert _conversation_tables() == set()

    command.upgrade(cfg, "head")
    assert _conversation_tables() == _CONVERSATION_TABLES


def _token_table_present() -> bool:
    engine = create_engine(SYNC_DSN)
    try:
        return "personal_access_tokens" in inspect(engine).get_table_names()
    finally:
        engine.dispose()


def test_personal_access_token_schema_matches_the_design(at_head):
    """A token is stored as its hash, one row per token, deleted with
    its user. The scope is read or read-write, and only last_used_at may be null."""
    engine = create_engine(SYNC_DSN)
    try:
        insp = inspect(engine)
        cols = {c["name"]: c for c in insp.get_columns("personal_access_tokens")}
        fks = insp.get_foreign_keys("personal_access_tokens")
        uniques = {tuple(u["column_names"]) for u in insp.get_unique_constraints("personal_access_tokens")}
        checks = {c["name"] for c in insp.get_check_constraints("personal_access_tokens")}
        indexes = {
            i["name"]: i["column_names"]
            for i in insp.get_indexes("personal_access_tokens")
            if "duplicates_constraint" not in i
        }
    finally:
        engine.dispose()

    assert set(cols) == {
        "id",
        "token_hash",
        "user_id",
        "name",
        "scope",
        "created_at",
        "expires_at",
        "last_used_at",
    }
    assert {name for name, col in cols.items() if col["nullable"]} == {"last_used_at"}
    (fk,) = fks
    assert (fk["referred_table"], fk["constrained_columns"]) == ("users", ["user_id"])
    assert fk["options"].get("ondelete", "").upper() == "CASCADE"
    assert uniques == {("token_hash",)}
    assert "ck_personal_access_tokens_scope" in checks
    assert indexes == {"ix_personal_access_tokens_user": ["user_id"]}


def test_0034_downgrades_and_upgrades_again(at_head):
    cfg = _cfg()
    command.downgrade(cfg, "0033")
    assert not _token_table_present()

    command.upgrade(cfg, "head")
    assert _token_table_present()


def _evidence_table_present() -> bool:
    engine = create_engine(SYNC_DSN)
    try:
        return "evidence_exports" in inspect(engine).get_table_names()
    finally:
        engine.dispose()


def test_evidence_exports_schema_matches_the_design(at_head):
    """One row per download of decrypted evidence. The row outlives its account."""
    engine = create_engine(SYNC_DSN)
    try:
        insp = inspect(engine)
        cols = {c["name"]: c for c in insp.get_columns("evidence_exports")}
        fks = insp.get_foreign_keys("evidence_exports")
        indexes = {i["name"]: i["column_names"] for i in insp.get_indexes("evidence_exports")}
    finally:
        engine.dispose()

    assert set(cols) == {
        "id",
        "at",
        "user_id",
        "username",
        "kind",
        "raw_mode",
        "source",
        "host",
        "run_id",
        "payloads",
    }
    assert {name for name, col in cols.items() if col["nullable"]} == {"user_id", "raw_mode"}
    (fk,) = fks
    assert (fk["referred_table"], fk["constrained_columns"]) == ("users", ["user_id"])
    assert fk["options"].get("ondelete", "").upper() == "SET NULL"
    assert indexes == {"ix_evidence_exports_at": ["at"]}


def test_0036_downgrades_and_upgrades_again(at_head):
    cfg = _cfg()
    command.downgrade(cfg, "0035")
    assert not _evidence_table_present()

    command.upgrade(cfg, "head")
    assert _evidence_table_present()


def _network_map_tables_present() -> bool:
    engine = create_engine(SYNC_DSN)
    try:
        return {"network_map_layouts", "network_map_views"} <= set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def test_0037_downgrades_and_upgrades_again(at_head):
    cfg = _cfg()
    command.downgrade(cfg, "0036")
    assert not _network_map_tables_present()

    command.upgrade(cfg, "head")
    assert _network_map_tables_present()
