"""Management policy targets alone must not prove live VSX enforcement."""

import pytest
from tests.test_integration_db import URI, _driver, _load_vsx, session  # noqa: F401

from hst import path as pathmod

pytestmark = [pytest.mark.db, pytest.mark.skipif(not URI, reason="NEO4J_TEST_URI not set")]


def test_management_only_vsx_binding_remains_indeterminate(session):  # noqa: F811
    pinned = _load_vsx(session)
    session.run(
        "MATCH (fi:FirewallInstance)-[e:ENFORCES]->(:FwRulebase) WHERE fi._scope = 'test:vsx-gaia' DELETE e"
    ).consume()
    result = pathmod.trace(pinned, "10.1.0.0/24", "8.8.8.8", port=443, proto="tcp")
    legs = [leg for leg in result["legs"] if not leg.get("blocked")]
    assert legs
    assert any(leg.get("indeterminate") for leg in legs)
    assert not any(leg.get("snat") for leg in legs)
