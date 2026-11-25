"""The tests check the device role from the hostname and the run step that writes it."""

from __future__ import annotations

from typing import Any

import pytest

from hst import reasoner
from hst.core import finalize
from hst.core.config import Settings
from hst.core.device_roles import DEFAULT_TIER_TOKENS, TIER_ROLES, classify, tier_from_hostname
from hst.core.labels import DEVICE_ROLES


@pytest.mark.parametrize(
    ("hostname", "tier"),
    [
        ("ber1-fw-01", "firewall"),
        ("ber1fw01", "firewall"),
        ("ber1-vs3-ext", "firewall"),
        ("BER1-FW-VS2", "firewall"),
        ("ham-swc-02", "core"),
        ("ham-swc02", "core"),
        ("ham2swd14", "distribution"),
        ("mue1-swa-112.corp.example", "access"),
        ("ber1-ap-112", "access-point"),
        ("fra1-wlc01", "wireless"),
        ("fra1-rti-01", "internet-edge"),
        ("off7-rtw01", "wan-edge"),
        ("dc1-rth-02", "sdwan-hub"),
        ("off7_rts_01", "sdwan-edge"),
        # no token: a code inside a longer word is not one
        ("map01", None),
        ("fraswc01", None),
        # two tiers name no tier
        ("ber-swc-fw01", None),
        ("", None),
        (None, None),
    ],
)
def test_the_role_code_is_a_whole_letter_token(hostname: str | None, tier: str | None) -> None:
    assert tier_from_hostname(hostname, DEFAULT_TIER_TOKENS) == tier


def test_every_tier_maps_to_a_registered_role() -> None:
    assert set(TIER_ROLES.values()) <= DEVICE_ROLES
    assert set(DEFAULT_TIER_TOKENS.values()) <= set(TIER_ROLES)


@pytest.mark.parametrize(
    ("hostname", "reported", "has_fhrp", "expected"),
    [
        # a blanket collector role gives way to the hostname
        ("ber1-swa-01", "router", False, ("switch", "hostname", "access")),
        ("ber1-swc-01", "router", False, ("router", "hostname", "core")),
        ("ber1-swd-01", "router", False, ("router", "hostname", "distribution")),
        ("ber1-ap-01", "unknown", False, ("ap", "hostname", "access-point")),
        ("ber1-fw-01", "router", False, ("firewall", "hostname", "firewall")),
        # routed access: an access switch in an FHRP group is a gateway
        ("ber1-swa-01", "router", True, ("router", "evidence", "access")),
        # FHRP changes nothing for a tier that is already a router
        ("ber1-swd-01", "router", True, ("router", "hostname", "distribution")),
        # no token keeps the blanket role
        ("edge-17", "router", False, ("router", "default", None)),
        (None, None, False, ("unknown", "default", None)),
        # a collector fact wins over the name, for the role and for the tier
        ("off7-rts-01", "sdwan-hub", False, ("sdwan-hub", "collector", "sdwan-hub")),
        ("dc1-rth-01", "sdwan-edge", False, ("sdwan-edge", "collector", "sdwan-edge")),
        ("fr2-vs-inside", "firewall", False, ("firewall", "collector", "firewall")),
        ("ber1-swc-01", "switch", False, ("switch", "collector", "core")),
    ],
)
def test_precedence_is_collector_evidence_hostname_default(
    hostname: str | None, reported: str | None, has_fhrp: bool, expected: tuple[str, str, str | None]
) -> None:
    c = classify(hostname, reported, has_fhrp, DEFAULT_TIER_TOKENS)
    assert (c.role, c.basis, c.tier) == expected


def test_routing_adjacency_makes_an_access_switch_a_gateway_and_a_static_route_does_not() -> None:
    routed = classify("ber1-swa-07", "router", False, DEFAULT_TIER_TOKENS, True)
    assert (routed.role, routed.basis, routed.tier) == ("router", "evidence", "access")
    plain = classify("ber1-swa-07", "router", False, DEFAULT_TIER_TOKENS, False)
    assert (plain.role, plain.basis, plain.tier) == ("switch", "hostname", "access")
    # routing evidence changes nothing for a collector fact or for a device with no token
    assert classify("ber1-swc-01", "switch", False, DEFAULT_TIER_TOKENS, True).basis == "collector"
    assert classify("edge-17", "router", False, DEFAULT_TIER_TOKENS, True).basis == "default"


def test_the_fetch_reads_routing_adjacency_pinned_to_the_run() -> None:
    q = reasoner.FETCH_DEVICE_ROLES
    assert "AS has_routing" in q and "OspfAdjacency:Obj" in q and "BgpSession:Obj" in q
    assert "a.collection_ts = $cts" in q and "s.collection_ts = $cts" in q


def test_the_step_takes_a_routing_adjacency_as_evidence() -> None:
    tx = _Tx(
        [
            {
                "uid": "dev:ber1-swa-07",
                "hostname": "ber1-swa-07",
                "reported": "router",
                "has_fhrp": False,
                "has_routing": True,
            },
            {
                "uid": "dev:ber1-swa-08",
                "hostname": "ber1-swa-08",
                "reported": "router",
                "has_fhrp": False,
                "has_routing": False,
            },
        ]
    )
    reasoner.apply_device_roles(_Session(tx), collection_ts=7, tokens=DEFAULT_TIER_TOKENS)
    [write] = tx.writes
    assert [(r["uid"], r["role"], r["basis"]) for r in write["rows"]] == [
        ("dev:ber1-swa-07", "router", "evidence"),
        ("dev:ber1-swa-08", "switch", "hostname"),
    ]


def test_the_setting_refuses_a_token_for_an_unknown_tier() -> None:
    with pytest.raises(ValueError, match="unknown tiers"):
        Settings(_env_file=None, hostname_tier_tokens={"cr": "kernel"})
    assert Settings(_env_file=None, hostname_tier_tokens={"cr": "core"}).hostname_tier_tokens == {
        "cr": "core"
    }


class _Result:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def data(self) -> list[dict[str, Any]]:
        return self._rows

    def consume(self) -> None:
        return None


class _Tx:
    def __init__(self, devices: list[dict[str, Any]]) -> None:
        self.devices = devices
        self.writes: list[dict[str, Any]] = []

    def run(self, query: str, **params: Any) -> _Result:
        if query is reasoner.FETCH_DEVICE_ROLES:
            return _Result(self.devices)
        assert query is reasoner.SET_DEVICE_ROLES
        self.writes.append(params)
        return _Result([])


class _Session:
    def __init__(self, tx: _Tx) -> None:
        self.tx = tx
        self.transactions: list[str] = []

    def execute_write(self, work: Any) -> Any:
        self.transactions.append("write")
        return work(self.tx)

    def execute_read(self, work: Any) -> Any:
        self.transactions.append("read")
        return work(self.tx)


def test_the_step_writes_every_device_and_keeps_the_reported_role() -> None:
    """A carried device arrives with the role an earlier run set and the
    collector's value in `role_reported`; the fetch hands back the latter, and
    the write keeps it, so the step classifies the same way every run."""
    tx = _Tx(
        [
            {"uid": "dev:ber1-swa-01", "hostname": "ber1-swa-01", "reported": "router", "has_fhrp": False},
            {"uid": "dev:ber1-swa-02", "hostname": "ber1-swa-02", "reported": "router", "has_fhrp": True},
            {
                "uid": "dev:off7-rts-01",
                "hostname": "off7-rts-01",
                "reported": "sdwan-edge",
                "has_fhrp": False,
            },
            {"uid": "dev:edge-17", "hostname": "edge-17", "reported": None, "has_fhrp": False},
        ]
    )
    report = reasoner.apply_device_roles(_Session(tx), collection_ts=7, tokens=DEFAULT_TIER_TOKENS)

    assert report == {
        "devices": 4,
        "changed": 1,
        "basis": {"collector": 1, "default": 1, "evidence": 1, "hostname": 1},
    }
    [write] = tx.writes
    assert write["cts"] == 7
    assert write["rows"] == [
        {
            "uid": "dev:ber1-swa-01",
            "role": "switch",
            "reported": "router",
            "basis": "hostname",
            "tier": "access",
        },
        {
            "uid": "dev:ber1-swa-02",
            "role": "router",
            "reported": "router",
            "basis": "evidence",
            "tier": "access",
        },
        {
            "uid": "dev:off7-rts-01",
            "role": "sdwan-edge",
            "reported": "sdwan-edge",
            "basis": "collector",
            "tier": "sdwan-edge",
        },
        {"uid": "dev:edge-17", "role": "unknown", "reported": "unknown", "basis": "default", "tier": None},
    ]


def test_a_run_with_no_device_writes_nothing() -> None:
    tx = _Tx([])
    report = reasoner.apply_device_roles(_Session(tx), collection_ts=7, tokens=DEFAULT_TIER_TOKENS)
    assert report == {"devices": 0, "changed": 0, "basis": {}}
    assert tx.writes == []


def test_the_roles_are_written_chunk_devices_per_transaction() -> None:
    """The devices are read in a read transaction."""
    from hst.core.loader import CHUNK

    devices = [
        {"uid": f"dev:r{i}", "hostname": f"r{i}", "reported": "router", "has_fhrp": False}
        for i in range(CHUNK + 1)
    ]
    tx = _Tx(devices)
    session = _Session(tx)
    report = reasoner.apply_device_roles(session, collection_ts=7, tokens=DEFAULT_TIER_TOKENS)

    assert report["devices"] == CHUNK + 1
    assert [len(w["rows"]) for w in tx.writes] == [CHUNK, 1]
    assert session.transactions == ["read", "write", "write"]
    assert [r["uid"] for w in tx.writes for r in w["rows"]] == [d["uid"] for d in devices]


def test_finalize_sets_the_roles_before_the_rules_read_them() -> None:
    order: list[str] = []
    settings = Settings(
        _env_file=None,
        hst_secret_key="finalize-device-roles-wiring-test-key-32-bytes",
        hostname_tier_tokens={"swa": "access"},
    )

    class _Rules:
        def apply_device_roles(self, session: Any, collection_ts: int, tokens: dict[str, str]) -> dict:
            order.append(f"roles {collection_ts} {sorted(tokens)}")
            return {"devices": 3, "changed": 1, "basis": {"default": 1, "hostname": 2}}

        def run(self, session: Any, collection_ts: int | None = None) -> list[dict]:
            order.append(f"rules {collection_ts}")
            return []

    class _Manifests:
        def _manifest(self, *a: Any, **k: Any) -> Any:
            from hst.core.model import RunManifest

            return RunManifest(run_id="x", source="reasoner", scope="x")

        execute_rt_domains = execute_link_speed = _manifest

    class _Cycle:
        def apply_site_assignments(self, session: Any, assigned: Any, cts: int | None = None) -> int:
            return 0

    details = finalize.finalize_derivations(
        object(), settings, 4242, {}, rules=_Rules(), route_targets=_Manifests(), cycle=_Cycle()
    )

    assert order == ["roles 4242 ['swa']", "rules 4242"]
    # the step's line goes last, after the lines whose order is a contract
    assert [line.split(":")[0] for line in details] == [
        "reasoner",
        "rt-domains",
        "link-speed",
        "device-roles",
    ]
    assert details[-1] == "device-roles: 3 device(s), 1 role(s) changed (default 1, hostname 2)"
