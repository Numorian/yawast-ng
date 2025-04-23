import sys
import types
from unittest import mock

import pytest

from yawast.shared import utils
from yawast.shared.utils import fix_relative_link


class TestUtils:
    @pytest.fixture
    def base_url(self):
        return "http://example.com/path/page.html"

    @pytest.fixture
    def base_url_https(self):
        return "https://example.com:8080/path/page.html"

    def test_absolute_url(self, base_url):
        href = "http://other.com/test"
        assert fix_relative_link(href, base_url) == href

    def test_protocol_relative_url(self, base_url, base_url_https):
        href = "//cdn.example.com/lib.js"
        expected = "http://cdn.example.com/lib.js"
        assert fix_relative_link(href, base_url) == expected

        href = "//cdn.example.com/lib.js"
        expected = "https://cdn.example.com/lib.js"
        assert fix_relative_link(href, base_url_https) == expected

    def test_leading_slash(self, base_url):
        href = "/images/logo.png"
        expected = "http://example.com/images/logo.png"
        assert fix_relative_link(href, base_url) == expected

    def test_dot_slash(self, base_url):
        href = "./about.html"
        expected = "http://example.com/path/about.html"
        assert fix_relative_link(href, base_url) == expected

    def test_double_dot_slash(self, base_url):
        href = "../contact.html"
        expected = "http://example.com/contact.html"
        assert fix_relative_link(href, base_url) == expected

    def test_relative_filename(self, base_url):
        href = "file.txt"
        expected = "http://example.com/path/file.txt"
        assert fix_relative_link(href, base_url) == expected

    def test_already_full_url(self, base_url):
        href = "https://another.com/test"
        assert fix_relative_link(href, base_url) == href

    def test_edge_case_empty_href(self, base_url):
        href = ""
        expected = base_url
        assert fix_relative_link(href, base_url) == expected


def test_is_url(monkeypatch):
    monkeypatch.setattr(utils, "extract_url", lambda x: "http://foo.com/")
    monkeypatch.setattr(utils.checkers, "is_url", lambda url, allow_special_ips: True)
    assert utils.is_url("foo.com")
    monkeypatch.setattr(utils.checkers, "is_url", lambda url, allow_special_ips: False)
    assert not utils.is_url("foo.com")
    monkeypatch.setattr(utils, "extract_url", lambda x: 1 / 0)
    assert not utils.is_url("foo.com")


def test_is_ip(monkeypatch):
    monkeypatch.setattr(utils.checkers, "is_ip_address", lambda x: x == "1.2.3.4")
    assert utils.is_ip("1.2.3.4")
    assert not utils.is_ip("notanip")


def test_is_private_ip():
    assert utils.is_private_ip("10.0.0.1")
    assert not utils.is_private_ip("8.8.8.8")


def test_get_domain():
    assert utils.get_domain("http://user:pass@foo.com:8080/path") == "foo.com"
    assert utils.get_domain("http://foo.com:8080/path") == "foo.com"
    assert utils.get_domain("http://foo.com/path") == "foo.com"


def test_is_printable_str(monkeypatch):
    monkeypatch.setattr(utils, "output", mock.Mock(debug=lambda x: None))
    b = b"abc"
    assert utils.is_printable_str(b)
    b2 = b"\xff\xfe"
    assert not utils.is_printable_str(b2)


def test_strip_ansi_str():
    s = "\x1b[31mRed\x1b[0m"
    assert utils.strip_ansi_str(s) == "Red"


def test_get_port():
    assert utils.get_port("http://foo.com:8080/") == 8080
    assert utils.get_port("https://foo.com/") == 443
    assert utils.get_port("http://foo.com/") == 80
    assert utils.get_port("http://user:pass@foo.com:8080/") == 8080


def test_extract_url():
    assert (
        utils.extract_url("http://foo.com:8080/path?query#frag")
        == "http://foo.com:8080/"
    )
    assert utils.extract_url("foo.com") == "http://foo.com/"
    assert utils.extract_url("http//foo.com") == "http://foo.com/"
    assert utils.extract_url("http:/foo.com") == "http://foo.com/"


def test_fix_relative_link():
    base = "http://foo.com/bar/"
    assert utils.fix_relative_link("/baz", base) == "http://foo.com/baz"
    assert utils.fix_relative_link("baz", base) == "http://foo.com/bar/baz"
    assert utils.fix_relative_link(".baz", base) == "http://foo.com/bar/.baz"
    assert utils.fix_relative_link("http://other.com/", base) == "http://other.com/"
    assert utils.fix_relative_link("//other.com/", base).startswith("http://")


def test_exit_message(monkeypatch):
    monkeypatch.setattr(
        sys, "exit", lambda code: (_ for _ in ()).throw(SystemExit(code))
    )
    with pytest.raises(SystemExit):
        utils.exit_message("bye")


def test_prompt(monkeypatch):
    monkeypatch.setattr(utils.config, "allow_interactive", False)
    assert utils.prompt("msg") == ""
    monkeypatch.setattr(utils.config, "allow_interactive", True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdin, "flush", lambda: None)
    monkeypatch.setattr("builtins.input", lambda msg: "answer")
    assert utils.prompt("msg") == "answer"
