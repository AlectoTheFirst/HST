"""Controller collectors publish typed completeness for flow-gate inputs."""

from types import SimpleNamespace

from hst.collectors.apic import ApicCollector
from hst.collectors.checkpoint import CpCollector
from hst.collectors.unifi import UnifiCollector
from hst.core.identity import MemoryResolver
from hst.core.model import Batch


def test_apic_atomic_policy_classes_publish_complete_empty(monkeypatch):
    collector = object.__new__(ApicCollector)
    collector.config = SimpleNamespace(fabric="fab", site_code="site", effective_routing_scope="site")
    collector.identity = MemoryResolver()
    monkeypatch.setattr(
        "hst.collectors.apic.normalize_apic",
        lambda *_args, **_kwargs: Batch(source="apic", scope="apic:fab"),
    )

    batch = collector.normalize({})

    assert batch.sections["policy"].status == "empty"


def test_unifi_optional_policy_families_publish_observed_rows(monkeypatch):
    collector = object.__new__(UnifiCollector)
    collector.config = SimpleNamespace(
        site_code="site",
        effective_routing_scope="site",
        site="default",
        include_clients=False,
        source_name="campus",
        l2fabric=None,
    )
    collector.settings = SimpleNamespace(l2fabric_of=lambda *_args: "default")
    collector.identity = MemoryResolver()
    monkeypatch.setattr(
        "hst.collectors.unifi.normalize_unifi",
        lambda *_args, **_kwargs: Batch(source="unifi", scope="unifi:default"),
    )

    # One gateway enforces the rules: with none they are bound to nothing and
    # the section reads partial.
    gateway = {"mac": "aa:bb:cc:00:00:01", "type": "udm"}
    batch = collector.normalize({"devices": [gateway], "firewall_rules": [{"_id": "one"}]})

    assert (batch.sections["policy"].status, batch.sections["policy"].row_count) == ("ok", 1)


def test_checkpoint_partial_nat_fetch_is_failed_evidence(monkeypatch):
    collector = object.__new__(CpCollector)
    collector.config = SimpleNamespace(host="manager", domain="", site_code="site")
    collector.identity = MemoryResolver()
    monkeypatch.setattr(
        "hst.collectors.checkpoint.normalize_checkpoint",
        lambda *_args, **_kwargs: Batch(source="checkpoint", scope="cp:manager"),
    )

    batch = collector.normalize(
        {
            "rulebases": {"layer": [[{"rulebase": []}]]},
            "nat": {"Standard": []},
            "policy_section_errors": ["show-nat-rulebase Standard: HTTP 500"],
        }
    )

    assert batch.sections["access"].status == "ok"
    assert batch.sections["nat"].status == "failed"
    assert "HTTP 500" in batch.sections["nat"].detail
