"""The secret resolver seam of collector construction."""

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from hst.app import sources as glue
from hst.app.crypto import SecretKeyError, encrypt_secrets
from hst.app.secrets import FernetResolver
from hst.app.store import Source
from hst.collectors.base import REGISTRY, Collector, SourceConfig


class DummyConfig(SourceConfig):
    host: str
    password: SecretStr
    port: int = 22


class DummyCollector(Collector):
    name = "dummy"
    KIND = "orchestrator"
    ConfigModel = DummyConfig

    def __init__(self, config, settings):
        super().__init__(config, settings)
        self.scope = f"dummy:{config.host}"

    def fetch(self):
        return {}

    def normalize(self, raw):
        raise NotImplementedError

    def probe(self):
        return f"would connect to {self.config.host}:{self.config.port}"


@pytest.fixture(autouse=True)
def register_dummy():
    REGISTRY["dummy"] = DummyCollector
    yield
    del REGISTRY["dummy"]


def _row(secrets: bytes, config: dict) -> Source:
    # Source is a dataclass with no defaults; every field must be supplied
    return Source(1, "r1", "dummy", config, secrets, True, None, None)


def test_fernet_resolver_returns_the_stored_map():
    key = Fernet.generate_key().decode()
    row = _row(encrypt_secrets(key, {"auth.password": "pw"}), {})
    assert FernetResolver(key).resolve(row) == {"auth.password": "pw"}


def test_fernet_resolver_raises_on_a_wrong_key():
    row = _row(encrypt_secrets(Fernet.generate_key().decode(), {"auth.password": "pw"}), {})
    with pytest.raises(SecretKeyError):
        FernetResolver(Fernet.generate_key().decode()).resolve(row)


def test_build_collector_accepts_an_injected_resolver():
    class StaticResolver:
        def resolve(self, row):
            return {"password": "from-elsewhere"}

    row = _row(b"", {"host": "r1"})
    settings = type(
        "S",
        (),
        {"hst_secret_key": "ignored", "l2fabric_of": lambda self, _name: "default"},
    )()
    collector = glue.build_collector(row, settings, resolver=StaticResolver())
    assert collector.config.password.get_secret_value() == "from-elsewhere"
