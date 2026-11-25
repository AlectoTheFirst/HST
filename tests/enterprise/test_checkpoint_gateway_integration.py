"""Gaia/VSX observations keep local VS identities qualified."""

import asyncio

from hst.collectors.checkpoint_gateway import (
    CpGatewayCollector,
    CpGatewayConfig,
    normalize_checkpoint_gateway,
)


def _config():
    return CpGatewayConfig(
        host="gaia-a",
        auth={"method": "password", "username": "reader", "password": "secret"},
        estate="estate",
        management_authority_uid="manager",
        appliance_uid="member-a",
        observation_uid="snapshot-a",
        vsid_gateway_object_uids={7: "vs-object-7", 8: "vs-object-8"},
        expert_shell_account="reader",
    )


def test_gateway_contexts_use_logical_identity_and_only_observed_installations_bind():
    batch = normalize_checkpoint_gateway(
        {
            "contexts": {
                "7": {
                    "vsid": 7,
                    "interfaces": [
                        {"ifname": "eth1", "addr_info": [{"local": "192.0.2.1", "prefixlen": 24}]}
                    ],
                    "routes": [{"dst": "198.51.100.0/24"}],
                    "installations": [
                        {
                            "rulebase_uid": "cp:manager:domain:layer",
                            "installed_revision": "r1",
                            "complete": True,
                        }
                    ],
                }
            }
        },
        _config(),
    )

    assert any(node.label == "VrfInstance" and node.props["name"] == "vs:7" for node in batch.nodes)
    binding = next(rel for rel in batch.rels if rel.rel_type == "ENFORCES")
    assert binding.props["installed"] is True
    assert binding.props["installed_revision"] == "r1"


def test_management_configuration_is_not_an_installation_observation():
    batch = normalize_checkpoint_gateway({"contexts": {"7": {"vsid": 7}}}, _config())

    assert not [rel for rel in batch.rels if rel.rel_type == "ENFORCES"]
    assert batch.sections["installation"].status == "unknown"


def test_two_vs_with_the_same_interface_name_are_logically_qualified_and_emit_rib_rows():
    config = _config()
    raw = {
        "contexts": {
            "7": {
                "vsid": 7,
                "interfaces": [{"ifname": "eth1", "addr_info": [{"local": "192.0.2.1", "prefixlen": 24}]}],
                "routes4": [{"dst": "198.51.100.0/24", "gateway": "192.0.2.2", "dev": "eth1"}],
                "installation": "Policy foo installed successfully",
            },
            "8": {
                "vsid": 8,
                "interfaces": [{"ifname": "eth1", "addr_info": [{"local": "192.0.2.1", "prefixlen": 24}]}],
                "routes4": [{"dst": "203.0.113.0/24", "gateway": "192.0.2.2", "dev": "eth1"}],
                "installation": "Policy foo installed successfully",
            },
        }
    }
    batch = normalize_checkpoint_gateway(raw, config)

    interfaces = [node for node in batch.nodes if node.label == "Interface" and node.props["name"] == "eth1"]
    assert len({node.uid for node in interfaces}) == 2
    assert len([node for node in batch.nodes if node.label == "FirewallInstance"]) == 2
    assert len([rel for rel in batch.rels if rel.rel_type == "LEARNED_ROUTE"]) == 2
    assert not [rel for rel in batch.rels if rel.rel_type == "ENFORCES"]


def test_fetch_uses_expert_account_per_vs_commands_and_normalizes_observed_routes():
    class Session:
        def __init__(self):
            self.commands = []

        async def run(self, command):
            self.commands.append(command)
            if command == "clish -c 'show version osedition'":
                return "Gaia R81.20"
            if command == "clish -c 'show hostname'":
                return "gaia-a"
            if command == "vsx stat -v":
                return "7 VS7\n8 VS8"
            if "ip -j address show" in command:
                return '[{"ifname":"eth1","addr_info":[{"local":"192.0.2.1","prefixlen":24}]}]'
            if "ip -6 -j route" in command:
                return "[]"
            if "ip -j route" in command:
                return '[{"dst":"198.51.100.0/24","gateway":"192.0.2.2","dev":"eth1"}]'
            if "fw stat -s" in command:
                return "Policy installed"
            if "ip -d -j link" in command or "neigh show" in command:
                return "[]"
            if "fw ctl arp -n" in command or "fw getifs" in command or "brctl show" in command:
                return ""
            if "cphaprob state" in command or "clish -c 'set virtual-system " in command:
                return ""
            raise AssertionError(command)

    collector = CpGatewayCollector(_config(), None)
    session = Session()
    raw = asyncio.run(collector._afetch_over(session))
    batch = collector.normalize(raw)

    scoped = [command for command in session.commands if command.startswith("vsenv ")]
    assert len(scoped) == 32
    assert all("vsenv 7 >/dev/null &&" in command or "vsenv 8 >/dev/null &&" in command for command in scoped)
    assert len(collector.side_tables(raw)["rib"]) == 2
    assert len([rel for rel in batch.rels if rel.rel_type == "LEARNED_ROUTE"]) == 2


def test_non_main_or_incomplete_multipath_rib_stays_partial_not_a_main_fib_proof():
    raw = {
        "contexts": {
            "7": {
                "vsid": 7,
                "routes4": [
                    {"dst": "10.0.0.0/8", "table": 100, "dev": "eth1"},
                    {"dst": "203.0.113.0/24", "nexthops": [{"gateway": "192.0.2.2"}, {}]},
                ],
            }
        }
    }
    collector = CpGatewayCollector(_config(), None)
    batch = collector.normalize(raw)

    assert batch.sections["routes"].status == "partial"
    assert collector.side_tables(raw)["rib"] == []
    assert collector.table_outcomes(raw)["rib"].status == "partial"


def test_unmapped_vs_overrides_successful_capture_outcomes_without_erasing_mapped_rows():
    config = _config().model_copy(update={"vsid_gateway_object_uids": {7: "vs-object-7"}})
    raw = {
        "_outcomes": {
            "vs:7:interfaces": {"status": "ok"},
            "vs:7:routes4": {"status": "ok"},
            "vs:8:interfaces": {"status": "ok"},
            "vs:8:routes4": {"status": "ok"},
        },
        "contexts": {
            "7": {
                "vsid": 7,
                "routes4": [{"dst": "198.51.100.0/24", "dev": "eth1"}],
                "installations": [{"rulebase_uid": "rb", "installed_revision": "r1", "complete": True}],
            },
            "8": {"vsid": 8, "routes4": [{"dst": "203.0.113.0/24", "dev": "eth1"}]},
        },
    }
    collector = CpGatewayCollector(config, None)
    batch = collector.normalize(raw)

    assert batch.sections["interfaces"].status == "failed"
    assert batch.sections["routes"].status == "failed"
    assert batch.sections["installation"].status == "partial"
    assert collector.table_outcomes(raw)["rib"].status == "partial"
    assert [row["prefix"] for row in collector.side_tables(raw)["rib"]] == ["198.51.100.0/24"]
