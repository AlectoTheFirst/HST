"""The SPA's schema fixtures are generated from the real config models."""

import json
from pathlib import Path

from hst.collectors.apic import ApicConfig
from hst.collectors.checkpoint import CpConfig
from hst.collectors.nxos import NxosConfig


def test_spa_schema_fixtures_match_the_models():
    fixtures = json.loads(Path("web/src/settings/schema.fixtures.json").read_text())
    assert fixtures == {
        "apic": ApicConfig.model_json_schema(),
        "nxos": NxosConfig.model_json_schema(),
        "checkpoint": CpConfig.model_json_schema(),
    }
