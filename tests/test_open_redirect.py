import pytest

from yawast.reporting.injection import InjectionPoint
from yawast.reporting.result import Result
from yawast.scanner.modules.http import open_redirect


class DummyResponse:
    def __init__(self, text="", headers=None, status_code=302):
        self.text = text
        self.headers = headers or {}
        self.status_code = status_code
        self.request = type(
            "Request", (), {"url": "http://test.local/page?redir=foo", "method": "GET"}
        )()
        self.content = text.encode("utf-8")


@pytest.fixture(autouse=True)
def patch_check_response(monkeypatch):
    monkeypatch.setattr(
        open_redirect.response_scanner, "check_response", lambda *a, **kw: []
    )
    # Clear tested combinations before each test
    if hasattr(open_redirect.check_injection, "_tested_combinations"):
        open_redirect.check_injection._tested_combinations.clear()


@pytest.mark.parametrize(
    "payload,location",
    [
        ("//evil.com", "//evil.com"),
        ("http://evil.com", "http://evil.com"),
        ("https://evil.com", "https://evil.com"),
        ("/\\evil.com", "/\\evil.com"),
        ("//attacker.com/path", "//attacker.com/path"),
    ],
)
def test_open_redirect_detected(monkeypatch, payload, location):
    def fake_http_get(url, **kwargs):
        return DummyResponse("", headers={"Location": location}, status_code=302)

    monkeypatch.setattr(open_redirect.network, "http_get", fake_http_get)
    ip = InjectionPoint("http://test.local/page?redir=foo", "redir", "GET", "foo")
    results = open_redirect.check_injection(ip.url, DummyResponse(), ip, None)
    assert any(
        r.vulnerability == open_redirect.Vulnerabilities.OPEN_REDIRECT_CONFIRMED
        for r in results
    )
    assert any(
        payload in (r.evidence.custom or {}).get("location", "") for r in results
    )


def test_open_redirect_not_detected(monkeypatch):
    def fake_http_get(url, **kwargs):
        return DummyResponse(
            "", headers={"Location": "http://test.local/page"}, status_code=302
        )

    monkeypatch.setattr(open_redirect.network, "http_get", fake_http_get)
    ip = InjectionPoint("http://test.local/page?redir=foo", "redir", "GET", "foo")
    results = open_redirect.check_injection(ip.url, DummyResponse(), ip, None)
    assert not results


def test_open_redirect_no_location_header(monkeypatch):
    def fake_http_get(url, **kwargs):
        return DummyResponse("", headers={}, status_code=302)

    monkeypatch.setattr(open_redirect.network, "http_get", fake_http_get)
    ip = InjectionPoint("http://test.local/page?redir=foo", "redir", "GET", "foo")
    results = open_redirect.check_injection(ip.url, DummyResponse(), ip, None)
    assert not results


def test_open_redirect_post_method(monkeypatch):
    ip = InjectionPoint("http://test.local/page?redir=foo", "redir", "POST", "foo")
    results = open_redirect.check_injection(ip.url, DummyResponse(), ip, None)
    assert not results


def test_open_redirect_duplicate_detection(monkeypatch):
    # Ensure duplicate (page, field, method) combos are not tested twice
    def fake_http_get(url, **kwargs):
        return DummyResponse("", headers={"Location": "//evil.com"}, status_code=302)

    monkeypatch.setattr(open_redirect.network, "http_get", fake_http_get)
    ip = InjectionPoint("http://test.local/page?redir=foo", "redir", "GET", "foo")
    # Clear tested combinations
    if hasattr(open_redirect.check_injection, "_tested_combinations"):
        open_redirect.check_injection._tested_combinations.clear()
    results1 = open_redirect.check_injection(ip.url, DummyResponse(), ip, None)
    results2 = open_redirect.check_injection(ip.url, DummyResponse(), ip, None)
    assert results1
    assert not results2


def test_open_redirect_unsafe_link(monkeypatch):
    def fake_http_get(url, **kwargs):
        return DummyResponse("", headers={"Location": "//evil.com"}, status_code=302)

    monkeypatch.setattr(open_redirect.network, "http_get", fake_http_get)
    monkeypatch.setattr(open_redirect, "is_unsafe_link", lambda url, _: True)
    ip = InjectionPoint("http://test.local/page?redir=foo", "redir", "GET", "foo")
    results = open_redirect.check_injection(ip.url, DummyResponse(), ip, None)
    assert not results


def test_open_redirect_unsafe_form(monkeypatch):
    ip = InjectionPoint("http://test.local/page?redir=foo", "redir", "GET", "foo")
    monkeypatch.setattr(open_redirect, "is_unsafe_form", lambda soup, field: True)
    results = open_redirect.check_injection(ip.url, DummyResponse(), ip, None)
    assert not results


def test_open_redirect_handles_exception(monkeypatch):
    def fake_http_get(url, **kwargs):
        raise Exception("network error")

    monkeypatch.setattr(open_redirect.network, "http_get", fake_http_get)
    ip = InjectionPoint("http://test.local/page?redir=foo", "redir", "GET", "foo")
    results = open_redirect.check_injection(ip.url, DummyResponse(), ip, None)
    assert not results
