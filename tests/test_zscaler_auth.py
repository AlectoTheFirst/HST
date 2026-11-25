"""ZscalerSession: OneAPI client-credentials token, pacing and Retry-After."""

import ssl
import urllib.parse

import httpx
import pytest

from hst.collectors import http as http_client
from hst.collectors.auth import TlsConfig
from hst.collectors.zscaler_auth import RETRY_AFTER_FALLBACK, ZscalerSession


def _token_ok(body_asserts=None):
    def respond(request: httpx.Request) -> httpx.Response:
        if body_asserts is not None:
            body = dict(urllib.parse.parse_qsl(request.content.decode()))
            body_asserts(body)
        return httpx.Response(200, json={"access_token": "tok-1"})

    return respond


def test_token_fetched_once_and_bearer_sent_on_every_call():
    calls = {"token": 0, "auth_headers": []}

    def body_asserts(body):
        calls["token"] += 1
        assert body == {"grant_type": "client_credentials", "client_id": "cid", "client_secret": "sec"}

    token_handler = _token_ok(body_asserts)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            return token_handler(request)
        calls["auth_headers"].append(request.headers.get("Authorization"))
        return httpx.Response(200, json={"items": []})

    session = ZscalerSession(
        "acme", "cid", "sec", transport=httpx.MockTransport(handler), sleep=lambda s: None, clock=lambda: 0.0
    )
    session.get("/zia/api/v1/status")
    session.get("/zia/api/v1/status")
    session.close()

    assert calls["token"] == 1
    assert calls["auth_headers"] == ["Bearer tok-1", "Bearer tok-1"]


def test_429_then_200_retries_with_exact_retry_after_sleep():
    sleeps = []
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            return _token_ok()(request)
        state["n"] += 1
        if state["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "7"})
        return httpx.Response(200, json={"items": [{"id": 1}]})

    session = ZscalerSession(
        "acme", "cid", "sec", transport=httpx.MockTransport(handler), sleep=sleeps.append, clock=lambda: 0.0
    )
    out = session.get("/zia/api/v1/status")

    assert out == {"items": [{"id": 1}]}
    assert sleeps == [7.0]


def test_429_twice_raises_runtime_error_with_guidance():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            return _token_ok()(request)
        return httpx.Response(429, headers={"Retry-After": "2"})

    session = ZscalerSession(
        "acme", "cid", "sec", transport=httpx.MockTransport(handler), sleep=lambda s: None, clock=lambda: 0.0
    )
    with pytest.raises(RuntimeError, match="rate-limited"):
        session.get("/zia/api/v1/status")


def test_retry_after_capped_at_60_seconds():
    sleeps = []
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            return _token_ok()(request)
        state["n"] += 1
        if state["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "300"})
        return httpx.Response(200, json={"items": []})

    session = ZscalerSession(
        "acme", "cid", "sec", transport=httpx.MockTransport(handler), sleep=sleeps.append, clock=lambda: 0.0
    )
    session.get("/zia/api/v1/status")

    assert sleeps == [60.0]


def test_http_date_retry_after_falls_back_to_a_fixed_delay():
    sleeps = []
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            return _token_ok()(request)
        state["n"] += 1
        if state["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"})
        return httpx.Response(200, json={"items": []})

    session = ZscalerSession(
        "acme", "cid", "sec", transport=httpx.MockTransport(handler), sleep=sleeps.append, clock=lambda: 0.0
    )
    out = session.get("/zia/api/v1/status")

    assert out == {"items": []}
    assert sleeps == [RETRY_AFTER_FALLBACK]


def test_three_429s_are_waited_out_and_the_pace_halves_each_time():
    sleeps = []
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            return _token_ok()(request)
        state["n"] += 1
        if state["n"] <= 3:
            return httpx.Response(429, headers={"Retry-After": "2"})
        return httpx.Response(200, json={"items": []})

    session = ZscalerSession(
        "acme",
        "cid",
        "sec",
        rate=2.0,
        transport=httpx.MockTransport(handler),
        sleep=sleeps.append,
        clock=lambda: 0.0,
    )
    assert session.get("/zpa/x") == {"items": []}
    assert sleeps == [2.0, 2.0, 2.0]
    assert session._rate == 0.25  # 2.0 halved 3 times, and never below MIN_RATE


def test_429_without_retry_after_waits_for_the_rate_limit_reset():
    sleeps = []
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            return _token_ok()(request)
        state["n"] += 1
        if state["n"] == 1:
            return httpx.Response(429, headers={"x-ratelimit-reset": "9"})
        return httpx.Response(200, json={"items": []})

    session = ZscalerSession(
        "acme", "cid", "sec", transport=httpx.MockTransport(handler), sleep=sleeps.append, clock=lambda: 0.0
    )
    session.get("/zpa/x")
    assert sleeps == [9.0]


def test_429_without_any_hint_backs_off_doubling():
    sleeps = []
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            return _token_ok()(request)
        state["n"] += 1
        if state["n"] <= 2:
            return httpx.Response(429)
        return httpx.Response(200, json={"items": []})

    session = ZscalerSession(
        "acme", "cid", "sec", transport=httpx.MockTransport(handler), sleep=sleeps.append, clock=lambda: 0.0
    )
    session.get("/zpa/x")
    assert sleeps == [RETRY_AFTER_FALLBACK, RETRY_AFTER_FALLBACK * 2]


def test_the_default_pace_is_two_calls_per_second():
    clock_time = {"t": 0.0}
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        clock_time["t"] += seconds

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            return _token_ok()(request)
        return httpx.Response(200, json={"items": []})

    session = ZscalerSession(
        "acme",
        "cid",
        "sec",
        transport=httpx.MockTransport(handler),
        sleep=sleep,
        clock=lambda: clock_time["t"],
    )
    session.get("/zpa/x")
    session.get("/zpa/x")
    assert sleeps == [pytest.approx(0.5)]


def test_get_paged_flattens_until_a_short_page():
    pages_requested = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            return _token_ok()(request)
        page = int(request.url.params["page"])
        size = int(request.url.params["pageSize"])
        assert size == 2
        pages_requested.append(page)
        if page == 1:
            return httpx.Response(200, json={"items": [{"id": 1}, {"id": 2}]})
        return httpx.Response(200, json={"items": [{"id": 3}]})

    session = ZscalerSession(
        "acme", "cid", "sec", transport=httpx.MockTransport(handler), sleep=lambda s: None, clock=lambda: 0.0
    )
    out = session.get_paged("/zia/api/v1/locations", "items", size=2)

    assert out == [{"id": 1}, {"id": 2}, {"id": 3}]
    assert pages_requested == [1, 2]


def test_get_paged_survives_a_server_that_clamps_page_size():
    pages_requested = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            return _token_ok()(request)
        page = int(request.url.params["page"])
        assert int(request.url.params["pageSize"]) == 500
        pages_requested.append(page)
        chunk = [{"id": i} for i in range(5)][(page - 1) * 2 : page * 2]
        return httpx.Response(200, json={"items": chunk})

    session = ZscalerSession(
        "acme", "cid", "sec", transport=httpx.MockTransport(handler), sleep=lambda s: None, clock=lambda: 0.0
    )
    out = session.get_paged("/zia/api/v1/locations", "items")

    assert out == [{"id": i} for i in range(5)]
    assert pages_requested == [1, 2, 3]


def test_get_paged_honors_total_pages_over_the_short_page_rule():
    """With totalPages in the envelope the last full-length page is final: no
    trailing empty-page probe."""
    pages_requested = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            return _token_ok()(request)
        page = int(request.url.params["page"])
        pages_requested.append(page)
        items = [{"id": 2 * page - 1}, {"id": 2 * page}]
        return httpx.Response(200, json={"items": items, "totalPages": 2})

    session = ZscalerSession(
        "acme", "cid", "sec", transport=httpx.MockTransport(handler), sleep=lambda s: None, clock=lambda: 0.0
    )
    out = session.get_paged("/zia/api/v1/locations", "items", size=2)

    assert out == [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}]
    assert pages_requested == [1, 2]


def test_token_refreshes_before_expiry_mid_pagination():
    clock_time = {"t": 0.0}
    tokens = iter(["tok-1", "tok-2"])
    calls = {"token": 0, "auth": []}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            calls["token"] += 1
            return httpx.Response(200, json={"access_token": next(tokens), "expires_in": 100})
        calls["auth"].append(request.headers.get("Authorization"))
        # a slow page: by the next page's token check the 66s refresh point is past
        clock_time["t"] += 80.0
        if int(request.url.params["page"]) == 1:
            return httpx.Response(200, json={"items": [{"id": 1}, {"id": 2}]})
        return httpx.Response(200, json={"items": []})

    session = ZscalerSession(
        "acme",
        "cid",
        "sec",
        transport=httpx.MockTransport(handler),
        sleep=lambda s: None,
        clock=lambda: clock_time["t"],
    )
    out = session.get_paged("/zia/api/v1/locations", "items", size=2)

    assert out == [{"id": 1}, {"id": 2}]
    assert calls["token"] == 2
    assert calls["auth"] == ["Bearer tok-1", "Bearer tok-2"]


def test_401_reauthenticates_once_and_retries():
    tokens = iter(["tok-1", "tok-2"])
    calls = {"token": 0, "n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            calls["token"] += 1
            return httpx.Response(200, json={"access_token": next(tokens)})
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(401)
        assert request.headers["Authorization"] == "Bearer tok-2"
        return httpx.Response(200, json={"ok": True})

    session = ZscalerSession(
        "acme", "cid", "sec", transport=httpx.MockTransport(handler), sleep=lambda s: None, clock=lambda: 0.0
    )
    out = session.get("/zia/api/v1/status")

    assert out == {"ok": True}
    assert calls["token"] == 2


def test_second_401_is_a_real_authorization_problem():
    calls = {"token": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            calls["token"] += 1
            return httpx.Response(200, json={"access_token": f"tok-{calls['token']}"})
        return httpx.Response(401)

    session = ZscalerSession(
        "acme", "cid", "sec", transport=httpx.MockTransport(handler), sleep=lambda s: None, clock=lambda: 0.0
    )
    with pytest.raises(httpx.HTTPStatusError):
        session.get("/zia/api/v1/status")
    assert calls["token"] == 2  # exactly one re-authentication


def test_token_bucket_sleeps_when_calls_land_inside_1_over_rate():
    clock_time = {"t": 0.0}
    sleeps = []

    def clock():
        return clock_time["t"]

    def sleep(seconds):
        sleeps.append(seconds)
        clock_time["t"] += seconds

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            return _token_ok()(request)
        return httpx.Response(200, json={"items": []})

    session = ZscalerSession(
        "acme", "cid", "sec", rate=5.0, transport=httpx.MockTransport(handler), sleep=sleep, clock=clock
    )
    session.get("/zia/api/v1/status")
    clock_time["t"] += 0.05  # well inside the 1/5s = 0.2s minimum spacing
    session.get("/zia/api/v1/status")

    assert sleeps == [pytest.approx(0.15)]


def _test_ca_pem() -> str:
    """A self-signed CA certificate, PEM."""
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.x509.oid import NameOID

    key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "hst-test-ca")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2020, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2020, 1, 1, tzinfo=UTC) + timedelta(days=365 * 30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, None)
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture
def captured(monkeypatch):
    """httpx.Client construction kwargs, without constructing a client."""
    seen = {}

    class FakeClient:
        def __init__(self, **kwargs):
            seen.update(kwargs)

        def close(self):
            pass

    monkeypatch.setattr(http_client.httpx, "Client", FakeClient)
    return seen


def test_zscaler_session_verifies_by_default(captured):
    ZscalerSession("acme", "cid", "sec").close()
    assert captured["verify"] is True


def test_zscaler_session_verify_false_is_honoured_the_same_way_as_the_generic_path(captured):
    ZscalerSession("acme", "cid", "sec", tls=TlsConfig(verify=False)).close()
    assert captured["verify"] is False


def test_zscaler_session_ca_bundle_becomes_a_context_the_same_way_as_the_generic_path(captured):
    ZscalerSession("acme", "cid", "sec", tls=TlsConfig(ca_bundle=_test_ca_pem())).close()
    context = captured["verify"]
    assert isinstance(context, ssl.SSLContext)
    assert context.cert_store_stats()["x509_ca"] == 1


# --- stop, token errors, retry spacing and the 429 limit ----------------------------------------


class _Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def _api(handler):
    def route(request: httpx.Request) -> httpx.Response:
        if request.url.host == "acme.zslogin.net":
            return _token_ok()(request)
        return handler(request)

    return route


def test_the_check_runs_before_each_request_and_ends_a_paged_walk():
    import threading

    from hst.collectors.base import CollectionStopped

    stop = threading.Event()
    api_calls = []

    def check():
        if stop.is_set():
            raise CollectionStopped("collection cancelled")

    def handler(request):
        api_calls.append(request.url.path)
        stop.set()
        return httpx.Response(200, json={"list": [{"id": 1}], "totalPages": 3})

    session = ZscalerSession(
        "acme", "cid", "sec", transport=httpx.MockTransport(_api(handler)), sleep=lambda s: None, check=check
    )
    with pytest.raises(CollectionStopped):
        session.get_paged("/zpa/x", "list")
    assert len(api_calls) == 1


def test_the_check_runs_after_a_429_wait_before_the_retry():
    import threading

    from hst.collectors.base import CollectionStopped

    stop = threading.Event()
    sleeps, api_calls = [], []

    def check():
        if stop.is_set():
            raise CollectionStopped("collection cancelled")

    def sleep(seconds):
        sleeps.append(seconds)
        stop.set()

    def handler(request):
        api_calls.append(request.url.path)
        return httpx.Response(429, headers={"Retry-After": "3"})

    session = ZscalerSession(
        "acme", "cid", "sec", transport=httpx.MockTransport(_api(handler)), sleep=sleep, check=check
    )
    with pytest.raises(CollectionStopped):
        session.get("/zia/api/v1/status")
    assert sleeps == [3.0] and len(api_calls) == 1


def _token_session(token_answers, sleeps=None, clock=None):
    from hst.collectors.zscaler_auth import ZscalerTokenError  # noqa: F401

    calls = {"token": 0}
    answers = iter(token_answers)

    def handler(request):
        if request.url.host == "acme.zslogin.net":
            calls["token"] += 1
            answer = next(answers)
            if isinstance(answer, Exception):
                raise answer
            return answer
        return httpx.Response(200, json={"ok": True})

    session = ZscalerSession(
        "acme",
        "cid",
        "sec",
        transport=httpx.MockTransport(handler),
        sleep=(sleeps.append if sleeps is not None else lambda s: None),
        clock=clock or (lambda: 0.0),
    )
    return session, calls


def test_a_token_refusal_raises_a_token_error():
    from hst.collectors.zscaler_auth import ZscalerTokenError

    sleeps = []
    session, calls = _token_session([httpx.Response(401)], sleeps)
    with pytest.raises(ZscalerTokenError) as caught:
        session.get("/zia/api/v1/status")
    assert not isinstance(caught.value, httpx.HTTPStatusError)
    assert calls["token"] == 1 and sleeps == []


def test_a_token_host_5xx_is_retried_once():
    sleeps = []
    session, calls = _token_session(
        [httpx.Response(503), httpx.Response(200, json={"access_token": "t"})], sleeps
    )
    assert session.get("/zia/api/v1/status") == {"ok": True}
    assert sleeps == [5.0] and calls["token"] == 2


def test_a_second_token_failure_raises_a_token_error():
    from hst.collectors.zscaler_auth import ZscalerTokenError

    session, calls = _token_session([httpx.Response(503), httpx.Response(503)])
    with pytest.raises(ZscalerTokenError, match="answered HTTP 503"):
        session.get("/zia/api/v1/status")
    assert calls["token"] == 2


def test_a_token_transport_error_raises_a_token_error():
    from hst.collectors.zscaler_auth import ZscalerTokenError

    session, _calls = _token_session([httpx.ConnectError("no route"), httpx.ConnectError("no route")])
    with pytest.raises(ZscalerTokenError, match="failed: ConnectError"):
        session.get("/zia/api/v1/status")


def test_a_token_answer_without_an_access_token_raises_a_token_error():
    from hst.collectors.zscaler_auth import ZscalerTokenError

    session, _calls = _token_session([httpx.Response(200, json={})])
    with pytest.raises(ZscalerTokenError):
        session.get("/zia/api/v1/status")


def test_the_token_request_carries_no_bearer_header():
    clock = _Clock()
    tokens = iter(["tok-1", "tok-2"])
    token_headers, api_headers = [], []

    def handler(request):
        if request.url.host == "acme.zslogin.net":
            token_headers.append(request.headers.get("authorization"))
            return httpx.Response(200, json={"access_token": next(tokens), "expires_in": 100})
        api_headers.append(request.headers.get("authorization"))
        clock.now += 80
        return httpx.Response(200, json={})

    session = ZscalerSession(
        "acme", "cid", "sec", transport=httpx.MockTransport(handler), sleep=clock.sleep, clock=clock
    )
    session.get("/a")
    session.get("/b")
    assert token_headers == [None, None]
    assert api_headers == ["Bearer tok-1", "Bearer tok-2"]


def test_the_call_after_a_429_retry_is_spaced_from_the_retry():
    clock = _Clock()
    sends = []

    def handler(request):
        sends.append(clock.now)
        if len(sends) == 1:
            return httpx.Response(429, headers={"Retry-After": "1"})
        return httpx.Response(200, json={})

    session = ZscalerSession(
        "acme", "cid", "sec", transport=httpx.MockTransport(_api(handler)), sleep=clock.sleep, clock=clock
    )
    for _ in range(3):
        session.get("/zia/api/v1/status")
    assert sends == [0.0, 1.0, 2.0, 3.0]
    assert session._rate == 1.0


def test_the_call_after_a_401_retry_is_spaced_from_the_retry():
    clock = _Clock()
    sends = []

    def handler(request):
        if request.url.host == "acme.zslogin.net":
            clock.now += 0.2
            return httpx.Response(200, json={"access_token": "t"})
        sends.append(round(clock.now, 6))
        return httpx.Response(401 if len(sends) == 1 else 200, json={})

    session = ZscalerSession(
        "acme", "cid", "sec", transport=httpx.MockTransport(handler), sleep=clock.sleep, clock=clock
    )
    session.get("/a")
    session.get("/b")
    assert sends == [0.2, 0.4, 0.9]


def test_one_call_waits_out_at_most_four_429s():
    sleeps, sends = [], []

    def handler(request):
        sends.append(1)
        return httpx.Response(429, headers={"Retry-After": "2"})

    session = ZscalerSession(
        "acme",
        "cid",
        "sec",
        transport=httpx.MockTransport(_api(handler)),
        sleep=sleeps.append,
        clock=lambda: 0.0,
    )
    with pytest.raises(RuntimeError) as caught:
        session.get("/zia/api/v1/status")
    assert str(caught.value) == (
        "Zscaler API rate-limited /zia/api/v1/status: HTTP 429 on 5 sends in a row; "
        "waited 8.0 s in total; pace now 0.25 calls per second"
    )
    assert len(sends) == 5 and sleeps == [2.0, 2.0, 2.0, 2.0]


@pytest.mark.parametrize("value", ["-1", "nan", "inf"])
def test_a_negative_or_non_finite_retry_after_counts_as_missing(value):
    response = httpx.Response(429, headers={"Retry-After": value})
    assert ZscalerSession._rate_limit_wait(response, 0) == RETRY_AFTER_FALLBACK


def test_a_non_numeric_retry_after_falls_through_to_the_rate_limit_reset():
    response = httpx.Response(
        429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT", "x-ratelimit-reset": "9"}
    )
    assert ZscalerSession._rate_limit_wait(response, 0) == 9.0


def test_the_pace_doubles_after_a_stretch_without_a_429():
    from hst.collectors.zscaler_auth import PACE_RECOVERY_CALLS

    state = {"n": 0}

    def handler(request):
        state["n"] += 1
        return httpx.Response(429 if state["n"] <= 3 else 200, headers={"Retry-After": "0"}, json={})

    session = ZscalerSession(
        "acme",
        "cid",
        "sec",
        transport=httpx.MockTransport(_api(handler)),
        sleep=lambda s: None,
        clock=lambda: 0.0,
    )
    session.get("/a")
    paces = [session._rate]
    for _ in range(4):
        for _ in range(PACE_RECOVERY_CALLS):
            session.get("/a")
        paces.append(session._rate)
    assert paces == [0.25, 0.5, 1.0, 2.0, 2.0]


def test_a_429_restarts_the_recovery_count():
    from hst.collectors.zscaler_auth import PACE_RECOVERY_CALLS

    script = iter(
        [429, 200] + [200] * (PACE_RECOVERY_CALLS - 1) + [429, 200] + [200] * (PACE_RECOVERY_CALLS - 1)
    )

    def handler(request):
        return httpx.Response(next(script), headers={"Retry-After": "0"}, json={})

    session = ZscalerSession(
        "acme",
        "cid",
        "sec",
        transport=httpx.MockTransport(_api(handler)),
        sleep=lambda s: None,
        clock=lambda: 0.0,
    )
    session.get("/a")  # 429 then 200: pace 1.0
    for _ in range(PACE_RECOVERY_CALLS - 1):
        session.get("/a")
    assert session._rate == 1.0
    session.get("/a")  # 429 then 200: pace 0.5, count restarts
    for _ in range(PACE_RECOVERY_CALLS - 1):
        session.get("/a")
    assert session._rate == 0.5


def test_each_pace_change_is_logged(caplog):
    import logging

    from hst.collectors.zscaler_auth import PACE_RECOVERY_CALLS

    state = {"n": 0}

    def handler(request):
        state["n"] += 1
        return httpx.Response(429 if state["n"] <= 3 else 200, headers={"Retry-After": "0"}, json={})

    session = ZscalerSession(
        "acme",
        "cid",
        "sec",
        transport=httpx.MockTransport(_api(handler)),
        sleep=lambda s: None,
        clock=lambda: 0.0,
    )
    with caplog.at_level(logging.INFO, logger="hst.collectors.zscaler_auth"):
        session.get("/zia/api/v1/status")
        for _ in range(PACE_RECOVERY_CALLS):
            session.get("/zia/api/v1/status")
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    infos = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
    assert any("/zia/api/v1/status" in m and "0.25" in m for m in warnings)
    assert any("0.50" in m for m in infos)


def _paged_session(handler):
    return ZscalerSession(
        "acme",
        "cid",
        "sec",
        transport=httpx.MockTransport(_api(handler)),
        sleep=lambda s: None,
        clock=lambda: 0.0,
    )


def test_get_paged_raises_when_a_full_page_repeats():
    sends = []

    def handler(request):
        sends.append(dict(request.url.params))
        return httpx.Response(200, json=[{"id": 1}, {"id": 2}])

    with pytest.raises(RuntimeError) as caught:
        _paged_session(handler).get_paged("/zia/api/v1/x", None, size=2)
    assert str(caught.value) == "Zscaler API /zia/api/v1/x: page 2 answered the same 2 items as page 1"
    assert len(sends) == 2


def test_get_paged_ends_when_a_short_bare_array_page_repeats():
    sends = []

    def handler(request):
        sends.append(1)
        return httpx.Response(200, json=[{"id": 1}, {"id": 2}])

    assert len(_paged_session(handler).get_paged("/zia/api/v1/x", None)) == 2
    assert len(sends) == 2


def test_get_paged_raises_past_max_pages():
    sends = []

    def handler(request):
        page = int(request.url.params["page"])
        sends.append(page)
        return httpx.Response(200, json=[{"id": page * 10}, {"id": page * 10 + 1}])

    with pytest.raises(RuntimeError, match="more than 3 pages"):
        _paged_session(handler).get_paged("/zia/api/v1/x", None, size=2, max_pages=3)
    assert len(sends) == 3


def test_get_paged_walks_two_zpa_pages_with_lower_case_pagesize_and_a_string_total():
    sends = []

    def handler(request):
        sends.append(dict(request.url.params))
        page = int(request.url.params["page"])
        return httpx.Response(200, json={"list": [{"id": page}, {"id": page + 10}], "totalPages": "2"})

    items = _paged_session(handler).get_paged("/zpa/x", "list", size_param="pagesize")
    assert len(items) == 4
    assert len(sends) == 2
    assert all(p.get("pagesize") == "500" and "pageSize" not in p for p in sends)
