"""Management package capture is joined to graph policy scope conservatively."""

from hst.collectors.checkpoint import normalize_checkpoint
from hst.core import uid


def _raw(targets):
    return {
        "gateways": [{"uid": "gateway-a", "name": "fw-a", "type": "simple-gateway"}],
        "layers": [{"uid": "layer-a", "name": "Access"}],
        "packages": [{"uid": "package-a", "name": "Package A"}],
        "package_details": {
            "package-a": {
                "uid": "package-a",
                "access-layers": [{"uid": "layer-a"}],
                "installation-targets": targets,
            }
        },
        "rulebases": {
            "layer-a": [
                {
                    "rulebase": [
                        {
                            "uid": "rule-a",
                            "type": "access-rule",
                            "rule-number": 1,
                            "action": "accept",
                            "source": [],
                            "destination": [],
                            "service": [],
                        }
                    ],
                    "objects-dictionary": [],
                }
            ]
        },
        "nat": {},
    }


def test_configured_package_target_scopes_graph_binding_without_claiming_installation():
    batch = normalize_checkpoint(_raw([{"uid": "gateway-a"}]), mgmt="manager", domain="domain")
    device = "dev:fw-a"  # minted from the gateway name
    rulebase = uid.checkpoint("manager", "domain", "layer-a")
    enforces = [rel for rel in batch.rels if rel.rel_type == "ENFORCES"]

    assert [(rel.start_uid, rel.end_uid, rel.props) for rel in enforces] == [
        (device, rulebase, {"configured": True})
    ]


def test_missing_package_target_does_not_bind_every_gateway():
    batch = normalize_checkpoint(_raw([]), mgmt="manager", domain="domain")

    assert not [rel for rel in batch.rels if rel.rel_type == "ENFORCES"]
