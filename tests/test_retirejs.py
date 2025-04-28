from unittest import mock

import pytest
from bs4 import BeautifulSoup

from yawast.scanner.modules.http import retirejs


class DummyRequest:
    def __init__(self, url):
        self.url = url


class DummyRes:
    status_code = 200
    headers = {}

    def __init__(self, text="", content=b"{}", url="http://foo"):
        self.text = text
        self.content = content
        self.request = DummyRequest(url)


# --- get_results exception branch ---
def test_get_results_exception(monkeypatch):
    soup = BeautifulSoup("<html></html>", "html.parser")
    res = DummyRes()
    # Patch _get_retirejs_results to raise
    monkeypatch.setattr(
        retirejs,
        "_get_retirejs_results",
        lambda *a, **k: (_ for _ in ()).throw(Exception("fail")),
    )
    dbg = mock.Mock()
    monkeypatch.setattr(retirejs, "output", mock.Mock(debug_exception=dbg))
    out = retirejs.get_results(soup, "http://foo", res)
    assert out == []
    assert dbg.called


# --- _get_retirejs_results: scan_endpoint exception, SRI, external/internal JS, dynamic vuln ---
def test_get_retirejs_results_scan_endpoint_exception(monkeypatch):
    retirejs._data = {"dummy": 1}
    retirejs._checked = []
    # Use a domain that is in the file to simulate internal JS (should not expect external JS result)
    soup = BeautifulSoup('<script src="/foo.js"></script>', "html.parser")
    res = DummyRes(url="http://otherdomain.com")
    # scan_endpoint raises
    monkeypatch.setattr(
        retirejs.retirejs,
        "scan_endpoint",
        lambda *a, **k: (_ for _ in ()).throw(Exception("fail")),
    )
    dbg = mock.Mock()
    monkeypatch.setattr(
        retirejs, "output", mock.Mock(debug=mock.Mock(), debug_exception=dbg)
    )
    out_issues, out_results = retirejs._get_retirejs_results(
        soup, "https://otherdomain.com/page", "otherdomain.com", res
    )
    # For internal JS, no external JS result is expected
    assert out_issues == []
    assert out_results == []
    assert dbg.called


def test_get_retirejs_results_with_sri(monkeypatch):
    retirejs._data = {"dummy": 1}
    retirejs._checked = []
    soup = BeautifulSoup(
        '<script src="/foo.js" integrity="sha256-abc"></script>', "html.parser"
    )
    res = DummyRes()
    monkeypatch.setattr(retirejs.retirejs, "scan_endpoint", lambda *a, **k: [])
    out_issues, out_results = retirejs._get_retirejs_results(
        soup, "https://foo.com/page", "foo.com", res
    )
    # Should not report JS_EXTERNAL_NO_SRI
    assert all("No SRI" not in r.description for r in out_results)


# --- _get_data: network/http error and JSON decode error ---
def test_get_data_network_error(monkeypatch):
    retirejs._data = None
    # Simulate network.http_get raises
    monkeypatch.setattr(
        retirejs.network,
        "http_get",
        lambda url: (_ for _ in ()).throw(Exception("fail")),
    )
    dbg = mock.Mock()
    monkeypatch.setattr(
        retirejs, "output", mock.Mock(debug=mock.Mock(), debug_exception=dbg)
    )
    retirejs._get_data()
    assert retirejs._data is None
    assert dbg.called


def test_get_data_json_error(monkeypatch):
    retirejs._data = None

    # Simulate network.http_get returns bad JSON
    class Dummy:
        content = b"not json"

    monkeypatch.setattr(retirejs.network, "http_get", lambda url: Dummy())
    dbg = mock.Mock()
    monkeypatch.setattr(
        retirejs, "output", mock.Mock(debug=mock.Mock(), debug_exception=dbg)
    )
    retirejs._get_data()
    assert retirejs._data is None
    assert dbg.called


# --- reset ---
def test_reset():
    retirejs._checked = ["foo"]
    retirejs._reports = ["bar"]
    retirejs.reset()
    assert retirejs._checked == []
    assert retirejs._reports == []
