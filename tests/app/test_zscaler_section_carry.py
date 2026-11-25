"""A refused optional ZIA or ZPA read records the labels the run carries forward."""

from __future__ import annotations

import functools

import httpx
import pytest
from tests import test_zia, test_zpa

from hst.app import runs_exec
from hst.collectors import zia, zpa, zscaler_auth
from hst.core import Settings

ZPA_BASE = "/zpa/mgmtconfig/v1/admin/customers/cust-1"


@pytest.fixture(autouse=True)
def _no_pacing(monkeypatch):
    session = functools.partial(zscaler_auth.ZscalerSession, sleep=lambda s: None)
    monkeypatch.setattr(zia, "ZscalerSession", session)
    monkeypatch.setattr(zpa, "ZscalerSession", session)


def _refusing(transport: httpx.MockTransport, path: str, code: int) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == path:
            return httpx.Response(code, json={"id": "refused"})
        return transport.handle_request(request)

    return httpx.MockTransport(handler)


def _zia_carry(monkeypatch, path: str, code: int):
    transport, _calls = test_zia.make_mock()
    monkeypatch.setattr(zia, "_transport", lambda config: _refusing(transport, path, code))
    collector = zia.ZiaCollector(test_zia._cfg(), Settings(_env_file=None))
    batch = collector.normalize(collector.fetch())
    scopes = runs_exec.CarryScopes()
    scopes.ran(runs_exec.PreparedDevice(None, collector, None), batch.sections)
    return batch, scopes


def _zpa_carry(monkeypatch, path: str, code: int):
    transport, _calls = test_zpa.make_mock()
    monkeypatch.setattr(zpa, "_transport", lambda config: _refusing(transport, path, code))
    collector = zpa.ZpaCollector(test_zpa._cfg(), Settings(_env_file=None))
    batch = collector.normalize(collector.fetch())
    scopes = runs_exec.CarryScopes()
    scopes.ran(runs_exec.PreparedDevice(None, collector, None), batch.sections)
    return batch, scopes


def test_a_failed_zia_forwarding_rules_read_carries_the_rules(monkeypatch):
    batch, scopes = _zia_carry(monkeypatch, "/zia/api/v1/forwardingRules", 503)
    assert batch.sections["forwarding_rules"].status == "failed"
    assert scopes.collected == {"zia:acme"}
    assert scopes.sections == {"zia:acme": ["ZiaForwardingRule"]}


def test_a_refused_zia_location_groups_read_carries_the_groups(monkeypatch):
    batch, scopes = _zia_carry(monkeypatch, "/zia/api/v1/locations/groups", 403)
    assert batch.sections["location_groups"].status == "unauthorized"
    assert scopes.sections == {"zia:acme": ["ZiaLocationGroup"]}


def test_a_refused_zpa_client_forwarding_read_carries_the_rules(monkeypatch):
    path = f"{ZPA_BASE}/policySet/rules/policyType/CLIENT_FORWARDING_POLICY"
    batch, scopes = _zpa_carry(monkeypatch, path, 403)
    assert batch.sections["client_forwarding_rules"].status == "unauthorized"
    assert scopes.collected == {"zpa:acme"}
    assert scopes.sections == {"zpa:acme": ["ZpaClientForwardingRule"]}


def test_a_refused_scim_read_carries_nothing(monkeypatch):
    path = "/zpa/userconfig/v1/customers/cust-1/scimgroup/idpId/idp-1"
    batch, scopes = _zpa_carry(monkeypatch, path, 403)
    assert batch.sections["scim_groups"].status == "unauthorized"
    assert scopes.collected == {"zpa:acme"}
    assert scopes.sections == {}


def test_an_unsupported_section_carries_nothing(monkeypatch):
    batch, scopes = _zia_carry(monkeypatch, "/zia/api/v1/forwardingRules", 404)
    assert batch.sections["forwarding_rules"].status == "unsupported"
    assert scopes.collected == {"zia:acme"}
    assert scopes.sections == {}
