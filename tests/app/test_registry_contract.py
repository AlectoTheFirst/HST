"""Registry invariant: every collector's secret fields are SecretStr, stay out of
the non-secret config dict, and are marked write-only in the exported JSON schema."""

from pydantic import SecretStr

import hst.app.sources as glue
from hst import collectors as coll

MINIMAL_PAYLOADS = {
    "unifi": {"url": "https://x", "auth": {"method": "user_password", "username": "u", "password": "p"}},
    "vyos": {"host": "h", "auth": {"method": "password", "username": "vyos", "password": "pw"}},
    "manual": {"devices": ""},
    "apic": {
        "url": "https://apic.example",
        "fabric": "fab1",
        "auth": {"method": "user_password", "username": "ro", "password": "pw"},
    },
    "ndo": {
        "url": "https://ndo.example",
        "auth": {"method": "user_password", "username": "ro", "password": "pw"},
    },
    "checkpoint": {"host": "cp-mgmt.example", "auth": {"method": "api_key", "key": "key1"}},
    "checkpoint_gateway": {
        "host": "cp-gw.example",
        "auth": {"method": "password", "username": "admin", "password": "pw"},
        "estate": "estate-1",
        "management_source": "cp-mgmt",
        "expert_shell_account": "admin",
    },
    "equinix": {
        "auth": {"method": "oauth_client", "client_id": "cid", "client_secret": "cs"},
        "ibx_sites": "FR2, fr2",
        "port_bindings": "11111111-aaaa, dev:abc/port/eth1-1",
    },
    "velocloud": {
        "url": "https://vco.example",
        "enterprise_logical_ids": "ent-1",
        "orchestrator_release": "6.4.0.0",
        "auth": {"method": "api_key", "key": "key1"},
    },
    "nautobot": {"url": "https://nautobot.example", "auth": {"method": "api_key", "key": "tok"}},
    "nxos": {"host": "n9k1", "auth": {"method": "password", "username": "ro", "password": "pw"}},
    "iosxe": {"host": "sw1x", "auth": {"method": "password", "username": "ro", "password": "pw"}},
    "iosxr": {"host": "xr1", "auth": {"method": "password", "username": "ro", "password": "pw"}},
    "zia": {
        "vanity_domain": "acme",
        "tenant": "acme",
        "auth": {"method": "oauth_client", "client_id": "cid", "client_secret": "cs"},
    },
    "zpa": {
        "vanity_domain": "acme",
        "tenant": "acme",
        "customer_id": "cust-1",
        "auth": {"method": "oauth_client", "client_id": "cid", "client_secret": "cs"},
    },
    "netscaler": {
        "host": "https://ns01.example",
        "auth": {"method": "user_password", "username": "nsroot", "password": "pw"},
        "scope_name": "dc1-ns01",
        "on_uid": "rgrp:ns-ha:dc1:ns01",
    },
}


def _leaf_owner(model_cls, path):
    """(owner model, field name) for a dotted secret path, searching every
    union variant for the one that carries the leaf."""
    head, _, tail = path.partition(".")
    if not tail:
        if head not in model_cls.model_fields:
            raise KeyError(path)
        return model_cls, head
    for variant in glue._model_variants(model_cls.model_fields[head].annotation):
        try:
            return _leaf_owner(variant, tail)
        except KeyError:
            continue
    raise KeyError(path)


def _assert_no_secret_values(name, obj, at=""):
    if isinstance(obj, dict):
        for key, value in obj.items():
            _assert_no_secret_values(name, value, f"{at}{key}.")
    else:
        assert not isinstance(obj, SecretStr), (
            f"{name}.{at[:-1]} is SecretStr-typed but leaked into the non-secret config dict"
        )


def test_registry_contract():
    for name, cls in coll.REGISTRY.items():
        assert name in MINIMAL_PAYLOADS, f"collector {name!r} has no minimal payload in MINIMAL_PAYLOADS"
        model_cls = cls.ConfigModel

        for path in glue.secret_paths(model_cls):
            owner, leaf = _leaf_owner(model_cls, path)
            assert owner.model_fields[leaf].annotation is SecretStr, (
                f"{name}.{path} is in secret_paths() but not annotated SecretStr"
            )
            schema = owner.model_json_schema()
            assert schema["properties"][leaf].get("writeOnly") is True, (
                f"{name}.{path} is a secret field but its JSON schema entry is not writeOnly"
            )

        config, _ = glue.validate_source(name, MINIMAL_PAYLOADS[name])
        _assert_no_secret_values(name, config)
