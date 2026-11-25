"""Admin user management, with the self-lockout guards."""

from tests.app.conftest import PASSWORD, login


async def test_admin_only(client):
    await login(client, "otto")
    assert (await client.get("/api/users")).status_code == 403


async def test_create_list_patch(client):
    await login(client, "ada")
    nils = {"username": "nils", "password": "long-enough-pw", "role": "viewer"}
    r = await client.post("/api/users", json=nils)
    assert r.status_code == 201
    body = r.json()
    assert body["username"] == "nils" and "password_hash" not in body
    assert body["has_password"] is True and body["role_source"] == "local" and body["identities"] == []
    r = await client.post("/api/users", json=nils)
    assert r.status_code == 409
    users = (await client.get("/api/users")).json()["users"]
    assert [u["username"] for u in users] == ["ada", "nils", "otto", "vera"]
    nils = next(u for u in users if u["username"] == "nils")
    r = await client.patch(f"/api/users/{nils['id']}", json={"role": "operator", "disabled": True})
    assert r.status_code == 200 and r.json()["role"] == "operator"


async def test_a_disabled_account_has_no_session_after_it_is_enabled_again(client, app, seeded):
    import httpx

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://t", headers={"X-HST-CSRF": "1"}
    ) as vera:
        await login(vera, "vera")
        assert (await vera.get("/api/me")).status_code == 200
        await login(client, "ada")
        vera_id = (await seeded.get_user_by_username("vera")).id
        assert (await client.patch(f"/api/users/{vera_id}", json={"disabled": True})).status_code == 200
        assert (await client.patch(f"/api/users/{vera_id}", json={"disabled": False})).status_code == 200
        assert (await vera.get("/api/me")).status_code == 401


async def test_identities_and_role_source_columns(client, store):
    await login(client, "ada")
    okta = await store.create_auth_provider("okta", "oidc", {}, None, enabled=True)
    sso_user = await store.create_user("sso-nils", None, "viewer")
    await store.update_user(sso_user.id, role_source="mapped")
    await store.create_identity(sso_user.id, okta.id, "sub-1")

    users = (await client.get("/api/users")).json()["users"]
    row = next(u for u in users if u["username"] == "sso-nils")
    assert row["has_password"] is False
    assert row["role_source"] == "mapped"
    assert row["identities"] == ["okta"]

    local_row = next(u for u in users if u["username"] == "ada")
    assert local_row["has_password"] is True and local_row["identities"] == []


async def test_patch_role_forces_local_role_source(client, store):
    await login(client, "ada")
    okta = await store.create_auth_provider("okta", "oidc", {}, None, enabled=True)
    sso_user = await store.create_user("sso-otto", None, "viewer")
    await store.update_user(sso_user.id, role_source="mapped")
    await store.create_identity(sso_user.id, okta.id, "sub-2")

    r = await client.patch(f"/api/users/{sso_user.id}", json={"role": "operator"})
    assert r.status_code == 200
    assert r.json()["role"] == "operator" and r.json()["role_source"] == "local"

    # sending role_source alone (no role) clears the override back to 'mapped'
    r = await client.patch(f"/api/users/{sso_user.id}", json={"role_source": "mapped"})
    assert r.status_code == 200
    assert r.json()["role_source"] == "mapped" and r.json()["role"] == "operator"  # role untouched here


async def test_validation(client):
    await login(client, "ada")
    bad = [
        {"username": "X!", "password": "long-enough-pw", "role": "viewer"},
        {"username": "ok", "password": "short", "role": "viewer"},
        # eleven characters: one under the floor setup and the CLI share
        {"username": "ok", "password": "elevenchars", "role": "viewer"},
        {"username": "ok", "password": "long-enough-pw", "role": "root"},
    ]
    for body in bad:
        assert (await client.post("/api/users", json=body)).status_code == 422
    # the reset path enforces the same floor as creation
    assert (await client.patch("/api/users/1", json={"password": "elevenchars"})).status_code == 422


async def test_admin_cannot_lock_themself_out(client, seeded):
    await login(client, "ada")
    ada = await seeded.get_user_by_username("ada")
    for body in ({"disabled": True}, {"role": "viewer"}):
        r = await client.patch(f"/api/users/{ada.id}", json=body)
        assert r.status_code == 400 and "yourself" in r.json()["error"]
    assert (await client.patch("/api/users/999", json={"role": "viewer"})).status_code == 404


async def test_password_reset_changes_login(client, seeded):
    await login(client, "ada")
    vera = await seeded.get_user_by_username("vera")
    r = await client.patch(f"/api/users/{vera.id}", json={"password": "new-password-1"})
    assert r.status_code == 200
    r = await client.post("/api/login", json={"username": "vera", "password": "new-password-1"})
    assert r.status_code == 200


async def test_password_reset_revokes_that_users_existing_sessions(app, seeded):
    import httpx

    def browser():
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t", headers={"X-HST-CSRF": "1"}
        )

    async with browser() as attacker, browser() as admin:
        await login(attacker, "vera")
        assert (await attacker.get("/api/me")).status_code == 200

        await login(admin, "ada")
        vera = await seeded.get_user_by_username("vera")
        r = await admin.patch(f"/api/users/{vera.id}", json={"password": "new-password-1"})
        assert r.status_code == 200

        assert (await attacker.get("/api/me")).status_code == 401
        # and the admin's own session is untouched
        assert (await admin.get("/api/users")).status_code == 200


async def test_admin_can_revoke_an_accounts_sessions_without_touching_its_password(app, seeded):
    import httpx

    def browser():
        return httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://t", headers={"X-HST-CSRF": "1"}
        )

    async with browser() as lost_laptop, browser() as admin:
        await login(lost_laptop, "vera")
        assert (await lost_laptop.get("/api/me")).status_code == 200

        await login(admin, "ada")
        vera = await seeded.get_user_by_username("vera")
        before = vera.password_hash
        r = await admin.delete(f"/api/users/{vera.id}/sessions")
        assert r.status_code == 200 and r.json() == {"revoked": 1, "revoked_tokens": 0}

        assert (await lost_laptop.get("/api/me")).status_code == 401
        assert (await admin.get("/api/users")).status_code == 200  # the admin is untouched
        assert (await seeded.get_user_by_username("vera")).password_hash == before
        assert (
            await lost_laptop.post("/api/login", json={"username": "vera", "password": PASSWORD})
        ).status_code == 200


async def test_revoking_sessions_is_admin_only_and_404s_on_an_unknown_account(client, seeded):
    await login(client, "otto")
    vera = await seeded.get_user_by_username("vera")
    assert (await client.delete(f"/api/users/{vera.id}/sessions")).status_code == 403

    await login(client, "ada")
    assert (await client.delete("/api/users/999999/sessions")).status_code == 404
    # an account with nothing to revoke is not an error; it is already signed out
    assert (await client.delete(f"/api/users/{vera.id}/sessions")).json() == {
        "revoked": 0,
        "revoked_tokens": 0,
    }


async def _token(store, user, name="laptop"):
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    return await store.create_access_token(
        f"hash-{name}", user.id, name, "read", now + timedelta(days=30), now
    )


async def test_a_password_reset_and_a_sign_out_revoke_the_accounts_tokens(client, seeded):
    """A token is a credential as a session is."""
    vera = await seeded.get_user_by_username("vera")
    otto = await seeded.get_user_by_username("otto")
    await _token(seeded, vera)
    await _token(seeded, otto, "otto")
    await login(client, "ada")

    r = await client.patch(f"/api/users/{vera.id}", json={"password": "new-password-1"})
    assert r.status_code == 200
    assert await seeded.list_access_tokens(vera.id) == []

    await _token(seeded, vera, "again")
    r = await client.delete(f"/api/users/{vera.id}/sessions")
    assert r.json() == {"revoked": 0, "revoked_tokens": 1}
    assert await seeded.list_access_tokens(vera.id) == []
    assert len(await seeded.list_access_tokens(otto.id)) == 1


async def test_an_admin_lists_and_revokes_another_accounts_tokens(client, seeded):
    vera = await seeded.get_user_by_username("vera")
    token = await _token(seeded, vera)

    await login(client, "otto")
    assert (await client.get(f"/api/users/{vera.id}/access-tokens")).status_code == 403
    assert (await client.delete(f"/api/users/{vera.id}/access-tokens/{token.id}")).status_code == 403

    await login(client, "ada")
    listed = (await client.get(f"/api/users/{vera.id}/access-tokens")).json()["tokens"]
    assert [(t["id"], t["name"]) for t in listed] == [(token.id, "laptop")]
    assert "token" not in listed[0]
    assert (await client.get("/api/users/999999/access-tokens")).status_code == 404

    assert (await client.delete(f"/api/users/{vera.id}/access-tokens/{token.id}")).status_code == 204
    assert (await client.delete(f"/api/users/{vera.id}/access-tokens/{token.id}")).status_code == 404
    assert await seeded.list_access_tokens(vera.id) == []


async def test_a_token_lives_at_most_90_days(client, seeded):
    await login(client, "otto")
    r = await client.post("/api/access-tokens", json={"name": "ci", "expires_in_days": 91})
    assert r.status_code == 422
    assert (
        await client.post("/api/access-tokens", json={"name": "ci", "expires_in_days": 90})
    ).status_code == 201
