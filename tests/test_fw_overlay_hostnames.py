from typing import Any

from tests.test_fw_overlay_read import DENY, NO_BGP_ROWS, _install

from hst import path as pathmod
from hst.app import fw_overlay_read


def _trace(
    session: Any,
    src: str,
    dst: str,
    port: Any = None,
    proto: str = "tcp",
    rib: Any = None,
    gateways: Any = None,
) -> dict:
    return {
        "verdict": "permitted",
        "indeterminate": False,
        "warnings": [],
        "legs": [],
        "hops": [{"uid": "dev:access1", "kind": "Device", "label": "access1"}],
    }


def _simulate(monkeypatch, hostnames: list[dict[str, Any]]) -> dict[str, Any]:
    _install(
        monkeypatch,
        {
            **NO_BGP_ROWS,
            "MATCH (d:Device)-[e:ENFORCES]->(rb:FwRulebase:Obj {uid: $rb, collection_ts: $snap})": [
                {"uid": "dev:fdo2335xyz"},
                {"uid": "dev:fdo2335abc"},
            ],
            "RETURN d.uid AS uid, d.hostname AS hostname": hostnames,
        },
    )
    monkeypatch.setattr(pathmod, "trace", _trace)
    return fw_overlay_read.simulate_change(
        object(), intents=[DENY], flows=[{"src": "192.168.2.10", "dst": "192.168.2.35"}]
    )


def test_the_changed_devices_carry_their_hostnames_and_the_error_names_them(monkeypatch):
    body = _simulate(
        monkeypatch,
        [
            {"uid": "dev:fdo2335xyz", "hostname": "fw-fra-01"},
            {"uid": "dev:fdo2335abc", "hostname": "fw-fra-02"},
        ],
    )

    assert body["changed_devices"] == ["dev:fdo2335abc", "dev:fdo2335xyz"]
    assert body["changed_device_hostnames"] == {"dev:fdo2335abc": "fw-fra-02", "dev:fdo2335xyz": "fw-fra-01"}
    detail = body["flows"][0]["model_error"]["detail"]
    assert "alters (fw-fra-01, fw-fra-02)" in detail
    assert "dev:" not in detail


def test_a_device_with_no_hostname_is_named_by_its_uid(monkeypatch):
    body = _simulate(monkeypatch, [{"uid": "dev:fdo2335xyz", "hostname": "fw-fra-01"}])

    assert body["changed_device_hostnames"] == {"dev:fdo2335xyz": "fw-fra-01"}
    assert "alters (dev:fdo2335abc, fw-fra-01)" in body["flows"][0]["model_error"]["detail"]
