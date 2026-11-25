"""Where the model's reply handling is the device's (`network_session.reply_order_gap`).

The model undoes a translation of the reply first, then reads the routing state's inbound
filter and the state admission. A restored reply is decided only where the device does the
same: the order of the inbound filter and the reverse translation, and the state admission
as the collected configuration states it (the tracer, path/gates/firewall.py
`_FILTER_VIEW_BY_VENDOR` and `_INTERFACE_ACL_VIEW`). The Oslo router of the demo estate is
dressed as each platform; nothing here needs the native backend.
"""

from __future__ import annotations

import copy

import pytest
from tests.test_demo_enterprise_vyos import DEV, MAIN, _estate
from tests.test_symbolic_vyos_service_ports import _inventory

from hst.analysis_model.network_session import reply_order_gap
from hst.core.model import RelRecord
from hst.policy.ir import ExecutionContext

CTX = ExecutionContext("estate", "graph", "graph", DEV, MAIN, 4)
ETH0 = f"{DEV}/if/eth0"


def platform_variant(platform=None, acl=None, state_policy=True):
    """The estate with the Oslo router's platform set to `platform`, an
    interface ACL bound to its uplink eth0 in direction `acl`, and its global
    state policy kept or taken away."""
    batch = copy.deepcopy(_estate(1))
    for node in batch.nodes:
        if node.uid == DEV and platform:
            node.props = {**node.props, "platform": platform}
        if not state_policy and "global_state_policy" in node.props:
            node.props = {k: v for k, v in node.props.items() if k != "global_state_policy"}
    if acl:
        base = copy.deepcopy(next(n for n in batch.nodes if n.uid == "vyos:osl01-vyos-01:fw:LAN-LOCAL"))
        base.uid = "acl:outside"
        base.props = {**base.props, "uid": "acl:outside", "match_context": "interface-acl", "vendor": "cisco"}
        batch.nodes.append(base)
        batch.rels.append(
            RelRecord(
                type="PROTECTED_BY",
                start_label="Interface",
                start_uid=ETH0,
                end_label="FwRulebase",
                end_uid="acl:outside",
                key={"direction": acl},
                props={"direction": acl},
            )
        )
    return batch


@pytest.mark.parametrize(
    ("variant", "expected"),
    [
        ({}, None),
        ({"platform": "iosxe"}, None),
        ({"platform": "nxos"}, None),
        ({"platform": "iosxe", "acl": "in"}, "SESSION_REPLY_ACL_BEFORE_RESTORE"),
        ({"platform": "iosxe", "acl": "out"}, None),
        ({"acl": "in"}, "SESSION_REPLY_ACL_BEFORE_RESTORE"),
        ({"platform": "checkpoint"}, None),
        ({"platform": "checkpoint", "state_policy": False}, "SESSION_STATE_POLICY_NOT_COLLECTED"),
        ({"platform": "fortigate"}, "SESSION_STATE_POLICY_NOT_COLLECTED"),
        ({"platform": "paloalto"}, "SESSION_REPLY_ORDER_NOT_ESTABLISHED"),
    ],
)
def test_the_reply_is_decided_only_where_the_model_orders_it_as_the_device_does(variant, expected):
    assert reply_order_gap(_inventory(platform_variant(**variant)), CTX, ETH0, 4) == expected


def test_a_context_with_no_device_is_not_established():
    other = ExecutionContext("estate", "graph", "graph", "dev:nowhere", MAIN, 4)
    assert reply_order_gap(_inventory(_estate(1)), other, ETH0, 4) == "SESSION_REPLY_ORDER_NOT_ESTABLISHED"
