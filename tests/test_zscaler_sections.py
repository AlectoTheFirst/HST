"""Optional-section reads shared by the ZIA and ZPA collectors."""

from __future__ import annotations

import httpx
import pytest

from hst.collectors.zscaler_sections import SectionReads, section_outcomes


def _refuse(code: int, path: str) -> list[dict]:
    request = httpx.Request("GET", f"https://api.zsapi.net{path}")
    raise httpx.HTTPStatusError("refused", request=request, response=httpx.Response(code, request=request))


@pytest.mark.parametrize(
    ("first", "second", "worst"),
    [((404, "/a"), (403, "/b"), 403), ((404, "/a"), (503, "/b"), 503), ((403, "/a"), (503, "/b"), 503)],
)
def test_the_worst_refusal_sets_the_status(first, second, worst):
    reads = SectionReads()
    reads.read("keys", _refuse, *first)
    reads.read("keys", _refuse, *second)
    error = reads.errors()["keys"]
    assert error["status"] == worst
    assert error["detail"] == f"HTTP {first[0]} for {first[1]}; HTTP {second[0]} for {second[1]}"


def test_the_first_refusal_wins_a_tie():
    reads = SectionReads()
    reads.read("keys", _refuse, 401, "/a")
    reads.read("keys", _refuse, 403, "/b")
    assert reads.errors()["keys"]["status"] == 401


def test_every_read_refused_reads_like_a_single_read():
    reads = SectionReads()
    reads.read("keys", _refuse, 404, "/a")
    errors = reads.errors()
    assert "answered" not in errors["keys"]
    outcome = section_outcomes({"keys": [], "section_errors": errors}, ["keys"])["keys"]
    assert outcome.status == "unsupported"
    assert outcome.row_count is None


def test_a_section_with_answered_reads_counts_the_rows_it_kept():
    reads = SectionReads()
    rows = reads.read("keys", lambda: [{"id": 1}])
    rows += reads.read("keys", _refuse, 404, "/b")
    errors = reads.errors()
    assert errors["keys"]["answered"] == 1
    outcome = section_outcomes({"keys": rows, "section_errors": errors}, ["keys"])["keys"]
    assert outcome.status == "partial"
    assert outcome.row_count == 1
    assert outcome.detail == "HTTP 404 for /b"


def test_a_section_error_without_a_row_count_keeps_its_outcome():
    raw = {
        "provisioning_keys": [],
        "section_errors": {"provisioning_keys": {"status": 403, "detail": "HTTP 403 for /x"}},
    }
    outcome = section_outcomes(raw, ["provisioning_keys"])["provisioning_keys"]
    assert outcome.status == "unauthorized"
    assert outcome.detail == "HTTP 403 for /x"
    assert outcome.row_count is None


def test_a_section_the_payload_does_not_hold_is_left_out():
    assert section_outcomes({}, ["keys"]) == {}


def test_a_transport_error_reads_failed():
    import httpx

    from hst.collectors.zscaler_sections import SectionReads, section_outcomes

    request = httpx.Request("GET", "https://api.zsapi.net/zia/api/v1/forwardingRules")

    def timed_out():
        raise httpx.ReadTimeout("timed out", request=request)

    reads = SectionReads()
    assert reads.read("forwarding_rules", timed_out) == []
    errors = reads.errors()
    assert errors["forwarding_rules"]["status"] == 0
    assert errors["forwarding_rules"]["detail"] == "ReadTimeout for /zia/api/v1/forwardingRules"
    outcome = section_outcomes({"forwarding_rules": [], "section_errors": errors}, ("forwarding_rules",))
    assert outcome["forwarding_rules"].status == "failed"
