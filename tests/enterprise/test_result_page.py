"""Retained DAG pages render exact buckets without replaying the network."""

from types import SimpleNamespace

from hst.app import crypto
from hst.assessment.result_artifacts import ResultArtifactStore
from hst.assessment.result_page import execute_page
from hst.symbolic import header
from hst.symbolic.artifacts import encode_packet_sets

from .test_assessment_symbolic_bridge import native as native


def test_saved_exact_bucket_pages_remain_complete(native, tmp_path):
    settings = SimpleNamespace(
        hst_data_dir=tmp_path,
        hst_secret_key="synthetic-test-key-" * 3,
        hst_secret_key_file=None,
    )
    population = header(native, {"source_address": [1, 3, 5]}).rename(from_bank="current", to_bank="original")
    empty = native.empty()
    artifact = encode_packet_sets(
        {
            "population": population,
            "before/lower": population,
            "before/upper": population,
            "after/lower": empty,
            "after/upper": empty,
        }
    )
    store = ResultArtifactStore(tmp_path, crypto.dek(settings))
    ref = store.publish(artifact, estate="synthetic", manifest_sha256="a" * 64, request_id="b" * 64)
    inputs = {
        "artifact_ref": ref,
        "snapshot_refs": [{"estate": "synthetic", "manifest_sha256": "a" * 64}],
        "bucket": "decided_change.loss",
        "offset": 1,
        "limit": 1,
    }
    page = execute_page(settings, inputs)
    assert page["items"] == ["0.0.0.3/32"]
    assert page["count_decimal"] == page["address_count_decimal"] == "3"
    assert page["next_offset_decimal"] == "2"
    assert execute_page(settings, {**inputs, "offset": 2})["items"] == ["0.0.0.5/32"]


def test_the_condition_fails_bucket_is_the_population_outside_the_upper_bound(native, tmp_path):
    """`condition_fails` pages the clients the evidence settles the other way:
    the population minus the side's upper bound. After the change every
    client fails; before it none does."""
    settings = SimpleNamespace(
        hst_data_dir=tmp_path,
        hst_secret_key="synthetic-test-key-" * 3,
        hst_secret_key_file=None,
    )
    population = header(native, {"source_address": [1, 3, 5]}).rename(from_bank="current", to_bank="original")
    empty = native.empty()
    artifact = encode_packet_sets(
        {
            "population": population,
            "before/lower": population,
            "before/upper": population,
            "after/lower": empty,
            "after/upper": empty,
        }
    )
    store = ResultArtifactStore(tmp_path, crypto.dek(settings))
    ref = store.publish(artifact, estate="synthetic", manifest_sha256="a" * 64, request_id="b" * 64)
    inputs = {
        "artifact_ref": ref,
        "snapshot_refs": [{"estate": "synthetic", "manifest_sha256": "a" * 64}],
        "bucket": "fails.after",
        "offset": 0,
        "limit": 10,
    }
    assert execute_page(settings, inputs)["items"] == ["0.0.0.1/32", "0.0.0.3/32", "0.0.0.5/32"]
    assert execute_page(settings, {**inputs, "bucket": "fails.before"})["items"] == []
