"""An SSH collector reads its run's stop flag before each command."""

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any

import pytest
from tests.support import synthetic_payloads as sp
from tests.support import synthetic_vyos as sv

from hst.collectors import iosxe
from hst.collectors.base import CollectionStopped
from hst.collectors.checkpoint_gateway import CpGatewayCollector, CpGatewayConfig
from hst.collectors.cisco_common import MTU_COMMANDS
from hst.collectors.cli_collector import SshCliCollector


class _Session:
    """Records every command and answers from `answers`; raises the stop
    flag once the `stop_after`-th command has been answered."""

    def __init__(self, answers: dict[str, Any], stop: threading.Event | None = None, stop_after: int = 0):
        self.answers = answers
        self.sent: list[str] = []
        self._stop = stop
        self._stop_after = stop_after

    async def run(self, command: str) -> str:
        self.sent.append(command)
        if self._stop is not None and len(self.sent) == self._stop_after:
            self._stop.set()
        answer = self.answers.get(command, "")
        return answer if isinstance(answer, str) else json.dumps(answer)


class _Probe(SshCliCollector):
    name = "probe"
    COMMANDS = ("show a", "show b", "show c")
    OPTIONAL_COMMANDS = {"show b": ""}

    def __init__(self) -> None:  # the loop needs no config
        self.stop = None

    def normalize(self, raw):  # pragma: no cover - not reached
        raise NotImplementedError

    def probe(self) -> str:  # pragma: no cover - not reached
        raise NotImplementedError


def test_the_command_loop_sends_nothing_after_the_stop():
    collector = _Probe()
    collector.stop = threading.Event()
    session = _Session({}, collector.stop, stop_after=1)

    with pytest.raises(CollectionStopped):
        asyncio.run(collector._afetch_over(session))

    assert session.sent == ["show a"]


def test_a_flag_that_stays_down_changes_nothing():
    stopped, plain = _Probe(), _Probe()
    stopped.stop = threading.Event()
    answers = {"show a": "a\n", "show b": "b\n", "show c": "c\n"}

    assert asyncio.run(stopped._afetch_over(_Session(answers))) == asyncio.run(
        plain._afetch_over(_Session(answers))
    )


@pytest.mark.parametrize("family", sp.FAMILIES)
def test_a_cisco_fetch_sends_no_bgp_command_after_the_stop(family):
    collector = sp.make_collector(family, None)
    collector.stop = threading.Event()
    session = _Session(dict(sp.fixture_raw(family)), collector.stop, stop_after=len(collector.COMMANDS))

    with pytest.raises(CollectionStopped):
        asyncio.run(collector._afetch_over(session))

    assert session.sent == list(collector.COMMANDS)


@pytest.mark.parametrize("family", sp.FAMILIES)
def test_the_mtu_capture_sends_no_command_after_the_stop(family):
    collector = sp.make_collector(family, None, capture_bgp="none")
    collector.config.capture_mtu = True
    collector.stop = threading.Event()
    first_mtu = next(iter(MTU_COMMANDS[family].values()))
    raw = dict(sp.fixture_raw(family))
    # IOS-XE reads the ARP table of each VRF before the MTU capture
    arp_vrfs = iosxe.arp_vrf_commands(raw[iosxe.CMD_VRF]) if family == "iosxe" else []
    sent = len(collector.COMMANDS) + len(arp_vrfs) + 1
    session = _Session(raw, collector.stop, stop_after=sent)

    with pytest.raises(CollectionStopped):
        asyncio.run(collector._afetch_over(session))

    assert session.sent[-1] == first_mtu
    assert len(session.sent) == sent


def test_a_vyos_optional_read_is_not_a_failed_section_when_the_run_stops():
    collector = sv.make_collector(None)
    collector.stop = threading.Event()

    class _Vyos(_Session):
        async def run(self, command: str) -> str:
            await super().run(command)
            if command.endswith("show configuration json"):
                return "{}"
            if command.endswith("show version"):
                return "Version: VyOS 1.4"
            return "[]"

    session = _Vyos({}, collector.stop, stop_after=3)

    with pytest.raises(CollectionStopped):
        asyncio.run(collector._afetch_over(session))

    assert len(session.sent) == 3
    assert session.sent[-1].endswith("ip -j link show")


def test_the_vyos_bgp_loop_sends_nothing_once_the_run_is_stopped():
    collector = sv.make_collector(None)
    collector.stop = threading.Event()
    collector.stop.set()
    session = _Session({})

    with pytest.raises(CollectionStopped):
        asyncio.run(collector._afetch_bgp_observations(session, {"config": {}}, {}))

    assert session.sent == []


def test_a_check_point_gateway_fetch_sends_no_vs_command_after_the_stop():
    """Each VS command's refusal is a failed section, and the handling catches
    `RuntimeError`: the stop is read before it."""
    collector = CpGatewayCollector(
        CpGatewayConfig(
            host="gaia-a",
            auth={"method": "password", "username": "reader", "password": "secret"},
            estate="estate",
            management_authority_uid="manager",
            appliance_uid="member-a",
            observation_uid="snapshot-a",
            vsid_gateway_object_uids={7: "vs-object-7"},
            expert_shell_account="reader",
            gateway_contexts=(7,),
        ),
        None,
    )
    collector.stop = threading.Event()
    sent: list[str] = []

    class _Gaia:
        async def run(self, command: str) -> str:
            sent.append(command)
            if command.startswith("vsenv "):
                collector.stop.set()
                return "[]"
            return ""

    with pytest.raises(CollectionStopped):
        asyncio.run(collector._afetch_over(_Gaia()))

    assert len([command for command in sent if command.startswith("vsenv ")]) == 1
