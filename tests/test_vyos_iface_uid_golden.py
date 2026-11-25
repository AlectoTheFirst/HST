"""The golden overlay of the interface uid change."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from tests.support.synthetic_payloads import make_settings
from tests.support.synthetic_vyos import (
    CASES,
    IFACE_UID_GOLDEN_PATH,
    answers,
    base_shape,
    batch_digest,
    defaults_free,
    iface_uid_version_1,
    installation_free,
    link_local_free,
    load_golden,
    make_collector,
    new_raw,
    session_settings_free,
)

from hst.core import uid


def _overlay() -> dict[str, Any]:
    document: dict[str, Any] = json.loads(IFACE_UID_GOLDEN_PATH.read_text(encoding="utf-8"))
    return document


def _overlay_cases() -> dict[str, Any]:
    cases: dict[str, Any] = _overlay()["cases"]
    return cases


def test_version_one_folds_the_dot_and_the_block_puts_the_current_slug_back() -> None:
    assert uid.interface("dev:gw", "eth1.30") == "dev:gw/if/eth1.30"
    with iface_uid_version_1():
        assert uid.interface("dev:gw", "eth1.30") == "dev:gw/if/eth1-30"
        assert uid.port("dev:gw", "eth1.30") == "dev:gw/port/eth1-30"
        # the collision under version 1
        assert uid.interface("dev:gw", "GigabitEthernet0/0.1") == uid.interface(
            "dev:gw", "GigabitEthernet0/0/1"
        )
    assert uid.interface("dev:gw", "eth1.30") == "dev:gw/if/eth1.30"
    assert uid.interface("dev:gw", "GigabitEthernet0/0.1") != uid.interface("dev:gw", "GigabitEthernet0/0/1")


def test_the_overlay_records_the_normalize_field() -> None:
    overlay = _overlay()
    assert overlay["fields"] == ["normalize"]
    assert _overlay_cases()
    assert set(_overlay_cases()) <= set(CASES)
    assert all(set(fields) == {"normalize"} for fields in _overlay_cases().values())


def test_the_golden_is_the_namespace_golden_with_the_overlay_laid_over_it() -> None:
    namespace = load_golden(iface_uid=False)
    laid = load_golden()
    for key in CASES:
        assert laid["cases"][key] == {**namespace["cases"][key], **_overlay_cases().get(key, {})}, key
    with pytest.raises(ValueError):
        load_golden(namespace=False)


@pytest.mark.parametrize("key", CASES)
def test_an_overlay_digest_is_the_one_without_it_under_version_one_uids(key: str, tmp_path: Path) -> None:
    """Every case under version 1 uids gives the digest without the overlay. A
    case is in the overlay exactly when the uids move, and then the overlay
    digest is that of the load as it is."""
    collector = make_collector(make_settings(tmp_path))
    # without the installation evidence of the rulesets, the
    # default-valued properties (`DEFAULT_PROPS`) and the BgpSession settings,
    # and the IPv6 link-local addresses of an interface
    batch = link_local_free(
        session_settings_free(defaults_free(installation_free(collector.normalize(new_raw(answers(key))))))
    )
    with iface_uid_version_1():
        earlier = link_local_free(
            session_settings_free(
                defaults_free(installation_free(collector.normalize(new_raw(answers(key)))))
            )
        )
    before = load_golden(namespace=True, iface_uid=False)["cases"][key]["normalize"]
    assert batch_digest(base_shape(earlier)) == before
    assert (batch_digest(base_shape(batch)) != before) == (key in _overlay_cases())
    if key not in _overlay_cases():
        return
    assert batch_digest(base_shape(batch)) == _overlay_cases()[key]["normalize"]
    assert any("." in n.uid.rsplit("/", 1)[-1] for n in batch.nodes if n.label in {"Interface", "Port"})
    # the uids move without two of them joining
    assert len({n.uid for n in earlier.nodes}) == len({n.uid for n in batch.nodes})
