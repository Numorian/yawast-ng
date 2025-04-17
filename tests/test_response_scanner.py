import unittest
from unittest import mock
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from requests.models import Request, Response

from yawast.reporting.injection import InjectionPoint
from yawast.scanner.modules.http import response_scanner


def make_response(url, method="GET"):
    req = Request()
    req.url = url
    req.method = method
    res = Response()
    res.request = req
    return res


class TestFindInjectionPoints(unittest.TestCase):
    def test_injection_points_url_params_only(self):
        url = "http://example.com/page"
        res = make_response("http://example.com/page?foo=bar&baz=qux", "POST")
        points = response_scanner._find_injection_points(url, res, soup=None)
        expected = [
            InjectionPoint(url, "foo", "POST", "bar"),
            InjectionPoint(url, "baz", "POST", "qux"),
        ]
        self.assertEqual(points, expected)

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
        self.assertEqual(points, expected)

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
        self.assertEqual(points, expected)

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
        self.assertEqual(points, expected)

    def test_injection_points_no_params_no_forms(self):
        url = "http://example.com/page"
        res = make_response(url, "GET")
        soup = BeautifulSoup("<html></html>", "html.parser")
        points = response_scanner._find_injection_points(url, res, soup)
        self.assertEqual(points, [])

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
        self.assertEqual(points, expected)
