"""Synthetic network-QoS fields exercise buffer sizing versus forwarding limits.

Invented policy/classes and values, based on the public N9K 10.5(x) QoS
guide. No production capture is included.
"""

import asyncio
import copy
import json
from types import SimpleNamespace

import pytest

import test_nxos as nx
from hst.collectors import nxos
from hst.collectors.base import RAW_OUTCOMES_KEY, raw_sha
from hst.collectors.cisco_common import MTU_COMMANDS

QOS_COMMAND = MTU_COMMANDS["nxos"]["qos"]
QOS_TEXT = """  Type network-qos policy-maps
  ============================
  policy-map type network-qos synthetic-buffer-policy
    class type network-qos synthetic-small
      match qos-group 0
      mtu 1500
    class type network-qos synthetic-large
      match qos-group 1
      mtu 9000
      pause pfc-cos 1
"""


def capture(model="Nexus9000 C93360YC-FX2 chassis", release="10.5(4)", version_key="nxos_ver_str"):
    raw = copy.deepcopy(nx.RAW)
    version = dict(nx.VERSION_PAYLOAD)
    version.pop("sys_ver_str")
    version.update(chassis_id=model, **{version_key: release})
    raw[nxos.CMD_VERSION] = json.dumps(version)
    raw[QOS_COMMAND] = QOS_TEXT
    raw[MTU_COMMANDS["nxos"]["system"]] = "system jumbomtu 9216\n"
    raw[MTU_COMMANDS["nxos"]["media"]] = "Ethernet1/1 is up\n  MTU 1500 bytes\n"
    raw[MTU_COMMANDS["nxos"]["ipv4"]] = "Ethernet1/1 is up\n  IP MTU: 1500 bytes\n"
    raw[RAW_OUTCOMES_KEY] = {command: {"status": "ok"} for command in raw}
    return raw


def qos_observations(batch):
    return [
        n for n in batch.nodes if n.label == "MtuObservation" and n.props["raw_evidence_ref"] == QOS_COMMAND
    ]


@pytest.mark.parametrize(
    "model",
    ["C93360YC-FX2", "N9K-C93360YC-FX2", "Nexus9000 C93360YC-FX2 chassis", "Nexus 9000 C93360YC-FX2"],
)
@pytest.mark.parametrize(
    ("release", "version_key"), [("10.5(4)", "nxos_ver_str"), ("10.5(1)F", "sys_ver_str")]
)
def test_buffer_sizing_is_not_a_forwarding_limit(model, release, version_key):
    raw = capture(model, release, version_key)
    before = copy.deepcopy(raw)
    batch = nx._collector().normalize(raw)

    assert not batch.validate_registry()
    assert not qos_observations(batch)
    assert batch.sections["mtu_qos"].status == "ok"
    assert batch.sections["mtu_qos"].row_count == 2
    assert "not a forwarding MTU limit" in batch.sections["mtu_qos"].detail
    assert raw == before

    # The system jumbo preset is not an independent forwarding limit;
    # the interface's own reported MTU supplies the payload ceiling.
    obs = [n.props for n in batch.nodes if n.label == "MtuObservation"]
    system = [o for o in obs if o["raw_evidence_ref"] == MTU_COMMANDS["nxos"]["system"]]
    media = [o for o in obs if o["raw_evidence_ref"] == MTU_COMMANDS["nxos"]["media"]]
    assert not system
    assert batch.sections["mtu_system"].status == "ok"
    assert "selectable preset" in batch.sections["mtu_system"].detail
    assert media and media[0]["metric"] == "l2_payload_mtu_bytes"
    assert media[0]["normalized_value"] == 1500
    assert media[0]["gaps"] == []
    assert any(o["metric"] == "ipv4_mtu_bytes" and o["normalized_value"] == 1500 for o in obs)


@pytest.mark.parametrize(
    ("model", "release"),
    [
        ("Nexus9000 C93180YC-EX chassis", "10.5(4)"),
        ("Nexus5000 C5548UP chassis", "10.5(4)"),
        ("C93360YC-FX2", "9.3(5)"),
        ("C93360YC-FX2", "11.1(1)"),
        ("C93360YC-FX2", None),
        (None, "10.5(4)"),
        ("C93360YC-FX2-other", "10.5(4)"),
    ],
)
def test_unverified_profiles_keep_unresolved_policy_evidence(model, release):
    batch = nx._collector().normalize(capture(model, release))
    obs = qos_observations(batch)
    assert len(obs) == 2
    assert all(o.props["gaps"] == ["MTU_POLICY_UNRESOLVED", "MTU_SEMANTICS_UNKNOWN"] for o in obs)
    assert batch.sections["mtu_qos"].detail == ""


@pytest.mark.parametrize("status", ["unauthorized", "unsupported", "failed", "malformed"])
def test_buffer_profile_does_not_hide_failed_capture(status):
    raw = capture()
    raw[RAW_OUTCOMES_KEY][QOS_COMMAND] = {"status": status}
    batch = nx._collector().normalize(raw)
    assert batch.sections["mtu_qos"].status == status
    assert not qos_observations(batch)


@pytest.mark.parametrize(
    ("body", "status"),
    [(QOS_TEXT.replace("1500", "broken"), "malformed"), ("unrecognized", "partial"), ("", "empty")],
)
def test_buffer_profile_validates_capture_shape(body, status):
    raw = capture()
    raw[QOS_COMMAND] = body
    batch = nx._collector().normalize(raw)
    assert batch.sections["mtu_qos"].status == status
    assert batch.sections["mtu_qos"].detail == ""


@pytest.mark.parametrize("json_native", [False, True])
def test_fetch_keeps_qos_text_in_both_json_modes(json_native):
    collector = nx._collector()
    collector.config.json_native = json_native
    collector.config.capture_mtu = True
    collector.config.capture_bgp = "none"
    source = capture()
    sent = []

    class Session:
        async def run(self, command):
            sent.append(command)
            plain = command.removesuffix(" native") if command.endswith(" | json native") else command
            return source.get(plain, "")

    raw = asyncio.run(collector._afetch_over(Session()))
    assert QOS_COMMAND in sent
    assert not any(command.startswith(QOS_COMMAND + " |") for command in sent)
    assert (nxos.CMD_VERSION + (" native" if json_native else "")) in sent
    assert raw[QOS_COMMAND] == QOS_TEXT
    assert not qos_observations(collector.normalize(raw))


def test_parser_upgrade_reprocesses_unchanged_captures():
    collector = nx._collector()
    previous = SimpleNamespace(
        config=collector.config,
        PARSER_VERSION="1",
        VOLATILE_RAW_KEYS=collector.VOLATILE_RAW_KEYS,
        NORMALIZATION_VERSIONS=collector.NORMALIZATION_VERSIONS,
        NORMALIZATION_OUTCOME_KEYS=collector.NORMALIZATION_OUTCOME_KEYS,
    )
    raw = capture()
    assert raw_sha(collector, raw) != raw_sha(previous, raw)
