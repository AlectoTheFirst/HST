"""The platform glue: secret split, schema export, collector construction."""

import pytest
from pydantic import SecretStr, ValidationError

import hst.app.sources as glue
from hst.app.crypto import dek, encrypt_secrets, generate_key
from hst.app.store import Source
from hst.collectors.auth import SshAuth, SshJumpHost, TlsConfig
from hst.collectors.base import REGISTRY, Collector, SourceConfig
from hst.core import Settings


class DummyConfig(SourceConfig):
    host: str
    password: SecretStr
    port: int = 22


class DummyCollector(Collector):
    name = "dummy"
    ConfigModel = DummyConfig
    KIND = "orchestrator"

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


def test_secret_fields_found_by_annotation():
    assert glue.secret_fields(DummyConfig) == {"password"}
    assert glue.secret_fields(SourceConfig) == set()


def test_validate_splits_config_and_secrets():
    config, secrets = glue.validate_source("dummy", {"host": "r1", "password": "pw"})
    assert config == {
        "host": "r1",
        "port": 22,
        "site_code": "home",
        "routing_scope": None,
        "interval_s": 0,
        "source_name": "",
        "capture_bgp": "all",
        "l2fabric": None,
        "resolved_origins": {},
    }
    assert secrets == {"password": "pw"}
    with pytest.raises(ValidationError):
        glue.validate_source("dummy", {"password": "pw"})  # host missing
    with pytest.raises(KeyError):
        glue.validate_source("nope", {})


def test_routing_scope_alias_and_fallback():
    assert SourceConfig(l3dom="corp").routing_scope == "corp"
    assert SourceConfig(routing_scope="corp").effective_routing_scope == "corp"
    assert SourceConfig(site_code="dc1").effective_routing_scope == "dc1"


def test_source_types_exports_schemas():
    types = {t["type"]: t["schema"] for t in glue.source_types()}
    assert "dummy" in types
    assert types["dummy"]["properties"]["password"]["writeOnly"] is True


def test_build_collector_decrypts_and_names():
    settings = Settings(_env_file=None, hst_secret_key=generate_key())
    key = dek(settings)
    row = Source(
        1,
        "edge-r1",
        "dummy",
        {"host": "r1", "site_code": "dc1", "l3dom": "dc1", "port": 22, "source_name": ""},
        encrypt_secrets(key, {"password": "pw"}),
        True,
        None,
        None,
    )
    c = glue.build_collector(row, settings)
    assert isinstance(c, DummyCollector)
    assert c.config.password.get_secret_value() == "pw"
    assert c.config.source_name == "edge-r1"
    assert c.probe() == "would connect to r1:22"


class NestedConfig(SourceConfig):
    host: str
    auth: SshAuth
    tls: TlsConfig = TlsConfig()
    jump_host: SshJumpHost | None = None


def test_secret_paths_walks_nested_models_and_unions():
    paths = glue.secret_paths(NestedConfig)
    assert paths == {
        "auth.password",
        "auth.private_key",
        "auth.passphrase",
        "jump_host.auth.password",
        "jump_host.auth.private_key",
        "jump_host.auth.passphrase",
        "tls.client_cert.key",
    }


def test_secret_paths_finds_flat_secrets():
    assert glue.secret_paths(DummyConfig) == {"password"}


def test_split_secrets_emits_only_the_variant_present_on_the_instance():
    model = NestedConfig(host="r1", auth={"method": "password", "username": "u", "password": "pw"})
    config, secrets = glue.split_secrets(model)
    assert secrets == {"auth.password": "pw"}
    assert config["auth"] == {"method": "password", "username": "u"}
    assert config["tls"] == {"verify": True, "ca_bundle": "", "client_cert": None}
    assert "password" not in config["auth"]


def test_inject_secrets_restores_nested_paths():
    config = {"host": "r1", "auth": {"method": "password", "username": "u"}}
    merged = glue.inject_secrets(config, {"auth.password": "pw"})
    assert merged["auth"] == {"method": "password", "username": "u", "password": "pw"}
    assert config["auth"] == {"method": "password", "username": "u"}  # input untouched


def test_split_then_inject_round_trips_the_model():
    original = NestedConfig(
        host="r1",
        auth={"method": "private_key", "username": "u", "private_key": "pem", "passphrase": "pp"},
        tls={"verify": False},
    )
    config, secrets = glue.split_secrets(original)
    assert NestedConfig(**glue.inject_secrets(config, secrets)) == original


def test_round_trip_survives_an_empty_optional_secret():
    original = NestedConfig(host="r1", auth={"method": "private_key", "username": "u", "private_key": "pem"})
    config, secrets = glue.split_secrets(original)
    assert secrets["auth.passphrase"] == ""
    assert NestedConfig(**glue.inject_secrets(config, secrets)) == original


def test_inject_secrets_rejects_a_shape_mismatch():
    with pytest.raises(ValueError, match="disagree"):
        glue.inject_secrets({"auth": "oops"}, {"auth.password": "pw"})


def test_secret_paths_for_payload_follows_the_chosen_method():
    wanted = glue.secret_paths_for_payload(
        NestedConfig, {"host": "r1", "auth": {"method": "password", "username": "u"}}
    )
    assert wanted == {"auth.password"}
    wanted = glue.secret_paths_for_payload(
        NestedConfig, {"host": "r1", "auth": {"method": "private_key", "username": "u"}}
    )
    assert wanted == {"auth.private_key", "auth.passphrase"}


def test_secret_paths_for_payload_defaults_to_the_first_variant():
    wanted = glue.secret_paths_for_payload(NestedConfig, {"host": "r1"})
    assert wanted == {"auth.password"}


def test_secret_paths_for_payload_skips_an_absent_optional_block():
    assert "jump_host.auth.password" not in glue.secret_paths_for_payload(
        NestedConfig, {"host": "r1", "auth": {"method": "password"}}
    )
    wanted = glue.secret_paths_for_payload(
        NestedConfig,
        {
            "host": "r1",
            "auth": {"method": "agent", "username": "u"},
            "jump_host": {"host": "b", "auth": {"method": "private_key", "username": "h"}},
        },
    )
    assert wanted == {"jump_host.auth.private_key", "jump_host.auth.passphrase"}


def test_overlay_replaces_a_branch_whose_method_changes():
    base = {"auth": {"method": "user_password", "username": "u", "password": "x"}}
    assert glue._overlay(base, {"auth": {"method": "api_key", "key": "k"}})["auth"] == {
        "method": "api_key",
        "key": "k",
    }
    assert glue._overlay(base, {"auth": {"password": "y"}})["auth"] == {
        "method": "user_password",
        "username": "u",
        "password": "y",
    }


# --- device fleets ----------------------------------------------------------------


class GroupConfig(SourceConfig):
    """The SSH shape: host optional (a fleet source has none), a pin field."""

    host: str = ""
    password: SecretStr
    port: int = 22
    host_key: str = ""


class GroupCollector(DummyCollector):
    name = "groupdummy"
    ConfigModel = GroupConfig
    KIND = "group"

    def __init__(self, config, settings):
        super().__init__(config, settings)
        self.scope = f"groupdummy:{config.host}"


@pytest.fixture(autouse=True)
def register_groupdummy():
    REGISTRY["groupdummy"] = GroupCollector
    yield
    del REGISTRY["groupdummy"]


def _device(host: str, port: int | None = None, host_key: str = ""):
    from hst.app.store import Device

    return Device(1, "edge-r1", host, port, True, host_key, None, None)


def _group_row(key: str) -> Source:
    return Source(
        1,
        "edge-r1",
        "groupdummy",
        {"host": "", "site_code": "dc1", "l3dom": "dc1", "port": 22},
        encrypt_secrets(key, {"password": "pw"}),
        True,
        None,
        None,
    )


def test_kind_is_declared_by_the_collector_not_inferred_from_its_schema():
    assert glue.kind_of("groupdummy") == "group"
    assert glue.is_group("groupdummy") is True
    assert glue.kind_of("dummy") == "orchestrator"
    assert glue.is_group("dummy") is False
    assert glue.is_group("unifi") is False
    assert glue.is_group("checkpoint") is False
    assert glue.is_group("netscaler") is True


def test_every_registered_collector_declares_a_usable_kind():
    from hst.collectors.base import REGISTRY as LIVE

    for name, cls in LIVE.items():
        assert cls.KIND in ("group", "orchestrator"), name


def test_register_refuses_a_collector_that_declares_no_kind():
    from hst.collectors.base import register

    undeclared = type("UndeclaredCollector", (Collector,), {"name": "undeclared"})
    with pytest.raises(TypeError, match="must set KIND"):
        register(undeclared)
    assert "undeclared" not in REGISTRY


def test_build_device_collector_overlays_host_port_and_pin():
    settings = Settings(_env_file=None, hst_secret_key=generate_key())
    key = dek(settings)
    row = _group_row(key)
    device = _device("r7", port=2222, host_key="ssh-ed25519 PIN")
    c = glue.build_device_collector(row, device, settings)
    assert isinstance(c, GroupCollector)
    assert c.config.host == "r7"
    assert c.config.port == 2222
    assert c.config.host_key == "ssh-ed25519 PIN"
    # the group's, and the device row has no say in either
    assert c.config.site_code == "dc1"
    assert c.config.routing_scope == "dc1"
    assert c.config.password.get_secret_value() == "pw"  # the group's secret
    assert c.config.source_name == "edge-r1"
    assert c.scope == "groupdummy:r7"  # retirement partition follows the device


def test_device_without_port_follows_the_group():
    settings = Settings(_env_file=None, hst_secret_key=generate_key())
    row = _group_row(dek(settings))
    c = glue.build_device_collector(row, _device("r8"), settings)
    assert c.config.port == 22
