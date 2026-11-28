"""Every collector config field that selects the network destination or the TLS
check of a source carries an endpoint mark in the field metadata."""

from __future__ import annotations

import types
import typing
from collections.abc import Iterator

import pytest
from pydantic import BaseModel

from hst import collectors as coll
from hst.app.inventory import field_metadata as fm
from hst.collectors.auth import SshJumpHost, TlsConfig

DESTINATION_NAMES = frozenset({"host", "port", "url", "api_url", "base_url", "vanity_domain"})
DESTINATION_SUFFIXES = ("_url", "_host", "_port", "_domain", "proxy")
PIN_PARTS = ("host_key", "fingerprint")

# Connection and target fields of type str or int that select no network destination.
# A new field of either category fails the test until it is marked or listed here.
NOT_AN_ENDPOINT = frozenset(
    {
        ("apic", "fabric"),
        ("checkpoint", "domain"),
        ("checkpoint_gateway", "estate"),
        ("checkpoint_gateway", "management_source"),
        ("checkpoint_gateway", "management_authority_uid"),
        ("checkpoint_gateway", "management_domain_uid"),
        ("checkpoint_gateway", "appliance_uid"),
        ("checkpoint_gateway", "observation_uid"),
        ("checkpoint_gateway", "management_host"),
        ("checkpoint_gateway", "management_domain"),
        ("checkpoint_gateway", "gateway_release"),
        ("checkpoint_gateway", "gateway_contexts"),
        ("checkpoint_gateway", "cluster_mode"),
        ("checkpoint_gateway", "vsid_gateway_object_uids"),
        ("checkpoint_gateway", "evidence_file"),
        ("equinix", "ibx_sites"),
        ("equinix", "port_bindings"),
        ("equinix", "edge_device_bindings"),
        ("manual", "devices"),
        ("manual", "mtu_evidence"),
        ("nautobot", "mtu_basis"),
        ("ndo", "site_fabrics"),
        ("netscaler", "scope_name"),
        ("netscaler", "on_uid"),
        ("netscaler", "on_label"),
        ("netscaler", "mtu_device_uid"),
        ("unifi", "site"),
        ("velocloud", "enterprise_logical_ids"),
        ("velocloud", "orchestrator_release"),
        ("velocloud", "api_base_path"),
        ("velocloud", "poll_concurrency"),
        ("velocloud", "configuration_refresh_s"),
        ("zia", "tenant"),
        ("zia", "location_sites"),
        ("zpa", "tenant"),
        ("zpa", "customer_id"),
    }
)


def _models(annotation) -> list[type[BaseModel]]:
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return [annotation]
    if typing.get_origin(annotation) is typing.Annotated:
        return _models(typing.get_args(annotation)[0])
    if typing.get_origin(annotation) in (typing.Union, types.UnionType):
        return [m for arg in typing.get_args(annotation) for m in _models(arg)]
    return []


def _scalar(annotation) -> type | None:
    if typing.get_origin(annotation) is typing.Annotated:
        return _scalar(typing.get_args(annotation)[0])
    if typing.get_origin(annotation) in (typing.Union, types.UnionType):
        found = {_scalar(a) for a in typing.get_args(annotation)} - {None, type(None)}
        return found.pop() if len(found) == 1 else None
    if typing.get_origin(annotation) is typing.Literal:
        return str
    return annotation if annotation in (str, int, bool) else None


def leaves(model: type[BaseModel], prefix: str = "") -> Iterator[tuple[str, type[BaseModel], type | None]]:
    """(dotted path, owning model, scalar type) of every field of `model`, nested models included."""
    for name, field in model.model_fields.items():
        path = f"{prefix}{name}"
        nested = _models(field.annotation)
        if nested:
            for sub in nested:
                yield from leaves(sub, f"{path}.")
        else:
            yield path, model, _scalar(field.annotation)


def structural_role(path: str, owner: type[BaseModel]) -> str | None:
    """The endpoint role of a field of a TLS block or an SSH jump host."""
    name = path.rsplit(".", 1)[-1]
    if issubclass(owner, TlsConfig):
        return {"verify": fm.VERIFY, "ca_bundle": fm.TRUST}.get(name)
    if issubclass(owner, SshJumpHost):
        return {"host": fm.DESTINATION, "port": fm.DESTINATION, "host_key": fm.PIN}.get(name)
    return None


def named_role(path: str) -> str | None:
    """The endpoint role that the name of a field suggests."""
    name = path.rsplit(".", 1)[-1]
    if any(part in name for part in PIN_PARTS):
        return fm.PIN
    if name in DESTINATION_NAMES or name.endswith(DESTINATION_SUFFIXES):
        return fm.DESTINATION
    return None


def unmarked(
    collector_type: str, model: type[BaseModel], classification: fm.CollectorClassification
) -> list[str]:
    """The problems of one collector: a field without the endpoint role it needs, and a
    connection or target field that is neither marked nor reviewed."""
    roles: dict[str, set[str]] = {}
    categories: dict[str, set[str]] = {}
    for f in classification.fields:
        roles.setdefault(f.path, set()).add(f.endpoint)
        categories.setdefault(f.path, set()).add(f.category)
    problems = []
    for path, owner, scalar in leaves(model):
        found = roles.get(path, set())
        reviewed = (collector_type, path) in NOT_AN_ENDPOINT
        need = structural_role(path, owner)
        if need is not None and reviewed:
            problems.append(f"{collector_type}.{path}: listed as no endpoint")
        if need is None and not reviewed:
            need = named_role(path)
        if need is not None and found != {need}:
            problems.append(f"{collector_type}.{path}: needs {need}, has {sorted(found)}")
        open_category = categories.get(path, set()) & {"connection", "target"}
        if need is None and open_category and scalar in (str, int) and found == {""} and not reviewed:
            problems.append(f"{collector_type}.{path}: {sorted(open_category)} field is not reviewed")
    return problems


@pytest.mark.parametrize("collector_type", sorted(coll.REGISTRY))
def test_every_endpoint_field_of_the_registry_is_marked(collector_type):
    classification = fm.COLLECTORS.get(collector_type)
    if classification is None:
        pytest.fail(f"{collector_type} has no field classification")
    model = coll.REGISTRY[collector_type].ConfigModel
    assert unmarked(collector_type, model, classification) == []


def test_every_reviewed_field_exists():
    known = {(t, f.path) for t, c in fm.COLLECTORS.items() for f in c.fields}
    assert NOT_AN_ENDPOINT - known == set()


def test_an_endpoint_mark_holds_a_known_role():
    for c in fm.COLLECTORS.values():
        for f in c.fields:
            assert f.endpoint in fm.ENDPOINT_ROLES, (c.collector_type, f.path)
            if f.endpoint:
                assert not f.secret, (c.collector_type, f.path)


class _NewConfig(BaseModel):
    url: str
    tls: TlsConfig = TlsConfig()
    jump_host: SshJumpHost | None = None
    proxy: str = ""
    label: str = ""


def _row(path: str, category: str, endpoint: str = "") -> fm.FieldClassification:
    return fm.FieldClassification(
        path=path,
        variant=None,
        category=category,
        secret=False,
        identity_sensitivity="none",
        profile_applicability="n/a",
        label=path,
        endpoint=endpoint,
    )


def test_a_new_collector_without_marks_fails():
    paths = [path for path, _owner, _scalar in leaves(_NewConfig)]
    bare = fm.CollectorClassification(
        "new",
        "orchestrator",
        "tests._NewConfig",
        tuple(_row(p, "profile" if "." in p else "connection") for p in paths),
    )
    problems = unmarked("new", _NewConfig, bare)
    for path in ("url", "proxy", "tls.verify", "tls.ca_bundle", "jump_host.host", "jump_host.port"):
        assert any(p.startswith(f"new.{path}:") for p in problems), path
    assert any(p.startswith("new.label:") and "not reviewed" in p for p in problems)
    assert not any(p.startswith("new.tls.client_cert") for p in problems)


def test_a_new_collector_with_marks_passes():
    role = {
        "url": fm.DESTINATION,
        "proxy": fm.DESTINATION,
        "tls.verify": fm.VERIFY,
        "tls.ca_bundle": fm.TRUST,
        "jump_host.host": fm.DESTINATION,
        "jump_host.port": fm.DESTINATION,
        "jump_host.host_key": fm.PIN,
    }
    paths = [path for path, _owner, _scalar in leaves(_NewConfig) if path != "label"]
    marked = fm.CollectorClassification(
        "new",
        "orchestrator",
        "tests._NewConfig",
        (*(_row(p, "profile", role.get(p, "")) for p in paths), _row("label", "profile")),
    )
    assert unmarked("new", _NewConfig, marked) == []
