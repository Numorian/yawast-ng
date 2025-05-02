import sys
from unittest.mock import Mock, patch
from urllib.parse import urlparse

import pytest
from bs4 import BeautifulSoup
from requests.models import Request, Response

from yawast.reporting.enums import Vulnerabilities
from yawast.reporting.injection import InjectionPoint
from yawast.scanner.modules.http import response_scanner


def make_response(url, method="GET"):
    req = Request()
    req.url = url
    req.method = method
    res = Response()
    res.request = req
    return res


class TestFindInjectionPoints:
    def test_injection_points_url_params_only(self):
        url = "http://example.com/page"
        res = make_response("http://example.com/page?foo=bar&baz=qux", "POST")
        points = response_scanner._find_injection_points(url, res, soup=None)
        expected = [
            InjectionPoint(url, "foo", "POST", "bar"),
            InjectionPoint(url, "baz", "POST", "qux"),
        ]
        assert points == expected

    def test_injection_points_form_fields_only(self):
        url = "http://example.com/page"
        res = make_response(url, "GET")
        html = """
        <form method="post" action="/submit">
            <input type="text" name="username" value="alice">
            <input type="password" name="password" value="secret">
        </form>
        """
        soup = BeautifulSoup(html, "html.parser")
        points = response_scanner._find_injection_points(url, res, soup)
        expected = [
            InjectionPoint("http://example.com/submit", "username", "POST", "alice"),
            InjectionPoint("http://example.com/submit", "password", "POST", "secret"),
        ]
        assert points == expected

    def test_injection_points_url_and_form_fields(self):
        url = "http://example.com/page?foo=bar"
        res = make_response("http://example.com/page?foo=bar", "GET")
        html = """
        <form>
            <input type="text" name="q" value="search">
        </form>
        """
        soup = BeautifulSoup(html, "html.parser")
        points = response_scanner._find_injection_points(url, res, soup)
        expected = [
            InjectionPoint(url, "foo", "GET", "bar"),
            InjectionPoint(url, "q", "GET", "search"),
        ]
        assert points == expected

    def test_injection_points_form_action_missing(self):
        url = "http://example.com/page"
        res = make_response(url, "POST")
        html = """
        <form>
            <input type="text" name="x" value="1">
        </form>
        """
        soup = BeautifulSoup(html, "html.parser")
        points = response_scanner._find_injection_points(url, res, soup)
        expected = [
            InjectionPoint(url, "x", "GET", "1"),
        ]
        assert points == expected

    def test_injection_points_no_params_no_forms(self):
        url = "http://example.com/page"
        res = make_response(url, "GET")
        soup = BeautifulSoup("<html></html>", "html.parser")
        points = response_scanner._find_injection_points(url, res, soup)
        assert points == []

    def test_injection_points_form_input_missing_name_value(self):
        url = "http://example.com/page"
        res = make_response(url, "GET")
        html = """
        <form action="/a" method="post">
            <input type="text">
        </form>
        """
        soup = BeautifulSoup(html, "html.parser")
        points = response_scanner._find_injection_points(url, res, soup)
        expected = [
            InjectionPoint("http://example.com/a", "", "POST", ""),
        ]
        assert points == expected

    def test_injection_points_form_action_hash(self):
        url = "http://example.com/page"
        html = """
        <form action="#" method="GET">
            <p>
                User ID:
                <input type="text" size="15" name="id">
                <input type="submit" name="Submit" value="Submit">
            </p>
        </form>
        """

        class DummyReq:
            url = "http://example.com/page"
            method = "GET"

        class DummyRes:
            request = DummyReq()

        soup = BeautifulSoup(html, "html.parser")
        points = response_scanner._find_injection_points(url, DummyRes(), soup)
        assert any(p.field == "id" and p.url == url for p in points)


class DummyRaw:
    version = 11
    status = 200
    reason = "OK"
    _original_response = None


class DummyRes:
    def __init__(self, text="", status_code=200, url="http://foo", method="GET"):
        self.text = text
        self.status_code = status_code
        self.content = text.encode()
        self.headers = {
            "Content-Type": "text/html"
        }  # Ensure response_body_is_text returns True
        self.request = Mock(url=url, method=method)
        self.raw = DummyRaw()


def test_check_response_injection_enabled(monkeypatch):
    # Simulate --injection present
    monkeypatch.setattr(sys, "argv", ["prog", "scan", "--injection"])
    # Patch get_options to return --injection
    monkeypatch.setattr(response_scanner.utils, "get_options", lambda: ["--injection"])
    # Patch _find_injection_points to return a dummy point
    monkeypatch.setattr(
        response_scanner,
        "_find_injection_points",
        lambda url, res, soup: [InjectionPoint(url, "q", "GET", "test")],
    )

    # Patch sql_injection.check_injection to return a dummy result
    class DummyResult:
        vulnerability = Vulnerabilities.SQLI_CONFIRMED
        message = "Dummy SQLi result"
        evidence = {"db": "mysql"}

    # Patch at the correct import location for check_injection
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.sql_injection.check_injection",
        lambda url, res, point, soup: [DummyResult()],
    )
    # Patch unrelated result-producing functions to return nothing
    monkeypatch.setattr(response_scanner.retirejs, "get_results", lambda *a, **k: [])
    monkeypatch.setattr(
        response_scanner.apache_tomcat, "get_version", lambda *a, **k: []
    )
    monkeypatch.setattr(
        response_scanner.error_checker, "check_response", lambda *a, **k: []
    )
    monkeypatch.setattr(
        response_scanner.iis, "check_telerik_rau_enabled", lambda *a, **k: []
    )
    monkeypatch.setattr(response_scanner, "_check_cache_headers", lambda *a, **k: [])
    monkeypatch.setattr(
        response_scanner.http_basic, "get_header_issues", lambda *a, **k: []
    )
    monkeypatch.setattr(
        response_scanner.http_basic, "get_cookie_issues", lambda *a, **k: []
    )
    monkeypatch.setattr(
        response_scanner.rails, "check_cve_2019_5418", lambda *a, **k: []
    )
    monkeypatch.setattr(response_scanner, "_check_charset", lambda *a, **k: [])
    # Patch network.response_body_is_text to always return True
    monkeypatch.setattr("yawast.shared.network.response_body_is_text", lambda res: True)
    res = DummyRes()
    results = response_scanner.check_response("http://foo", res, soup=None)
    print("[TEST DEBUG] results:", results)
    for r in results:
        print(
            "[TEST DEBUG] result type:",
            type(r),
            "vuln:",
            getattr(r, "vulnerability", None),
        )
    assert any(
        getattr(r, "vulnerability", None) == Vulnerabilities.SQLI_CONFIRMED
        for r in results
    )


def test_check_response_injection_disabled(monkeypatch):
    # Simulate no --injection present
    monkeypatch.setattr(sys, "argv", ["prog", "scan"])
    monkeypatch.setattr(response_scanner.utils, "get_options", lambda: [])
    # Patch _find_injection_points to return a dummy point
    monkeypatch.setattr(
        response_scanner,
        "_find_injection_points",
        lambda url, res, soup: [InjectionPoint(url, "q", "GET", "test")],
    )
    # Patch sql_injection.check_injection to fail if called
    monkeypatch.setattr(
        response_scanner.sql_injection,
        "check_injection",
        lambda url, res, point: (_ for _ in ()).throw(
            Exception("Should not be called")
        ),
    )
    res = DummyRes()
    results = response_scanner.check_response("http://foo", res, soup=None)
    print("[TEST DEBUG] results:", results)
    for r in results:
        print(
            "[TEST DEBUG] result type:",
            type(r),
            "vuln:",
            getattr(r, "vulnerability", None),
        )
    # Should not include SQLI_POTENTIAL
    assert not any(
        getattr(r, "vulnerability", None) == Vulnerabilities.SQLI_POTENTIAL
        for r in results
    )
