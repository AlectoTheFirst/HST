"""GET /api/hst/device-text: a device's version, routing, ACL and NAT configuration at a run."""

from pathlib import Path
from typing import Any

import pytest
from tests.app.conftest import login
from tests.hst.test_routes import client, data_dir  # noqa: F401

from hst.core import Settings
from hst.map import markers

TEXT = {"fetched_ts": 200, "sections": [{"key": "routing", "title": "Routing", "parts": []}]}


@pytest.fixture
def device_text(monkeypatch: Any) -> list[tuple[str, int]]:
    from hst.map import tier3

    calls: list[tuple[str, int]] = []

    def fake(settings: Any, key: str, device: str, run: int) -> dict[str, Any] | None:
        calls.append((device, run))
        return TEXT if device == "dev:a" else None

    monkeypatch.setattr(tier3, "device_text", fake)
    return calls


async def test_the_device_configuration_needs_interfaces_read(
    client: Any,  # noqa: F811
    device_text: list[tuple[str, int]],
) -> None:
    await login(client, "vera")
    assert (
        await client.get("/api/hst/device-text", params={"uid": "dev:a", "snapshot": "200"})
    ).status_code == 403

    await login(client, "otto")
    r = await client.get("/api/hst/device-text", params={"uid": "dev:a", "snapshot": "200"})

    assert r.status_code == 200
    assert r.json() == {"uid": "dev:a", "snapshot": 200, **TEXT}
    assert device_text == [("dev:a", 200)]


async def test_a_device_with_no_fetch_is_404_and_a_cold_run_409(
    client: Any,  # noqa: F811
    device_text: list[tuple[str, int]],
    data_dir: Path,  # noqa: F811
) -> None:
    await login(client, "otto")
    assert (
        await client.get("/api/hst/device-text", params={"uid": "dev:z", "snapshot": "200"})
    ).status_code == 404

    markers_dir = Settings(_env_file=None, hst_data_dir=data_dir).manifests_dir  # type: ignore[call-arg]
    markers.write(markers_dir, {**markers.read(markers_dir, 100), "state": "cold"})
    r = await client.get("/api/hst/device-text", params={"uid": "dev:a", "snapshot": "100"})

    assert r.status_code == 409 and "cold" in r.json()["error"]


async def test_the_text_loses_the_values_the_sources_are_configured_with(
    client: Any,  # noqa: F811
    monkeypatch: Any,
) -> None:
    """A credential in a place no key or keyword names: only the configured
    values find it."""
    from hst.app import runs_exec
    from hst.map import tier3

    secret = "opaque-community-5531"
    sections = [{"key": "routing", "title": "Routing", "parts": [{"text": f"snmp {secret} ro"}]}]
    monkeypatch.setattr(tier3, "device_text", lambda *args: {"fetched_ts": 1, "sections": sections})
    monkeypatch.setattr(
        tier3,
        "interface_text",
        lambda *args: {"command": "c", "fetched_ts": 1, "text": f"description {secret}"},
    )
    monkeypatch.setattr(
        tier3,
        "interface_facts",
        lambda *args: {"uid": "dev:a/port/e0", "device_uid": "dev:a", "name": "e0"},
    )

    async def configured(store: Any, settings: Any) -> list[str]:
        return [secret]

    monkeypatch.setattr(runs_exec, "configured_secrets", configured)
    await login(client, "otto")

    device = await client.get("/api/hst/device-text", params={"uid": "dev:a", "snapshot": "200"})
    interface = await client.get(
        "/api/hst/interface-text", params={"uid": "dev:a/port/e0", "snapshot": "200"}
    )

    assert device.status_code == 200 and secret not in device.text
    assert device.json()["sections"][0]["parts"][0]["text"] == "snmp *** ro"
    assert interface.status_code == 200 and interface.json()["text"] == "description ***"


async def test_the_text_is_not_returned_when_the_sources_credentials_cannot_be_read(
    client: Any,  # noqa: F811
    device_text: list[tuple[str, int]],
    monkeypatch: Any,
) -> None:
    from hst.app import runs_exec

    async def broken(store: Any, settings: Any) -> list[str]:
        raise RuntimeError("the credential store is down")

    monkeypatch.setattr(runs_exec, "configured_secrets", broken)
    await login(client, "otto")

    r = await client.get("/api/hst/device-text", params={"uid": "dev:a", "snapshot": "200"})

    assert r.status_code == 503
    assert "was not redacted" in r.json()["error"]
