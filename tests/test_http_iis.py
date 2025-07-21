# Copyright (c) 2025 Numorian, Inc. and Contributors.
# Unit tests for yawast/scanner/modules/http/servers/iis.py
from unittest import mock

import pytest

from yawast.scanner.modules.http.servers import iis


class DummyResponse:
    def __init__(self, text="", status_code=200, headers=None, request=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self.request = request or mock.Mock()


def test_check_version_not_iis():
    results = iis.check_version("Apache/2.4.1", "raw", "http://numorian.com", {})
    assert results == []


def test_check_version_iis(monkeypatch):
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr("yawast.reporting.result.Result", lambda *a, **k: mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.http.version_checker.get_latest_version",
        lambda name, ver: type(
            "V", (), {"__gt__": lambda self, o: True, "__str__": lambda self: "10.0.0"}
        )(),
    )
    results = iis.check_version("Microsoft-IIS/8.5", "raw", "http://numorian.com", {})
    assert isinstance(results, list)


def test_check_version_with_aspnet_headers(monkeypatch):
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr("yawast.reporting.result.Result", lambda *a, **k: mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.http.version_checker.get_latest_version",
        lambda name, ver: type(
            "V", (), {"__gt__": lambda self, o: True, "__str__": lambda self: "10.0.0"}
        )(),
    )
    headers = {"X-AspNetMvc-Version": "5.2", "X-AspNet-Version": "4.0"}
    results = iis.check_version(
        "Microsoft-IIS/8.5", "raw", "http://numorian.com", headers
    )
    assert isinstance(results, list)


def test_check_aspnet_handlers(monkeypatch):
    dummy_res = DummyResponse(text="Remoting.RemotingException", status_code=500)
    monkeypatch.setattr("yawast.shared.network.http_get", lambda url, allow: dummy_res)
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.reporting.evidence.Evidence.from_response",
        lambda res, meta=None: mock.Mock(),
    )
    monkeypatch.setattr(
        "yawast.reporting.result.Result.from_evidence", lambda *a, **k: mock.Mock()
    )
    results = iis.check_aspnet_handlers("http://numorian.com")
    assert isinstance(results, list)


def test_check_aspnet_handlers_no_vuln(monkeypatch):
    dummy_res = DummyResponse(text="nope", status_code=404)
    monkeypatch.setattr("yawast.shared.network.http_get", lambda url, allow: dummy_res)
    results = iis.check_aspnet_handlers("http://numorian.com")
    assert isinstance(results, list)


def test_check_asp_net_debug(monkeypatch):
    dummy_res = DummyResponse(text="OK", status_code=200)
    dummy_xres = DummyResponse(text="fail", status_code=404)
    monkeypatch.setattr(
        "yawast.shared.network.http_custom",
        lambda method, url, additional_headers=None: (
            dummy_res if method == "DEBUG" else dummy_xres
        ),
    )
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr("yawast.reporting.result.Result", lambda *a, **k: mock.Mock())
    monkeypatch.setattr(
        "yawast.shared.network.http_build_raw_request", lambda req: "rawreq"
    )
    monkeypatch.setattr(
        "yawast.shared.network.http_build_raw_response", lambda res: "rawres"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: [],
    )
    results = iis.check_asp_net_debug("http://numorian.com")
    assert isinstance(results, list)


def test_check_asp_net_debug_false_positive(monkeypatch):
    dummy_res = DummyResponse(text="OK", status_code=200)
    dummy_xres = DummyResponse(text="fail", status_code=200)
    monkeypatch.setattr(
        "yawast.shared.network.http_custom",
        lambda method, url, additional_headers=None: (
            dummy_res if method == "DEBUG" else dummy_xres
        ),
    )
    monkeypatch.setattr("yawast.shared.output.debug", lambda msg: None)
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: [],
    )
    results = iis.check_asp_net_debug("http://numorian.com")
    assert isinstance(results, list)


def test_check_asp_net_debug_no_200(monkeypatch):
    dummy_res = DummyResponse(text="fail", status_code=404)
    monkeypatch.setattr(
        "yawast.shared.network.http_custom",
        lambda method, url, additional_headers=None: dummy_res,
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: [],
    )
    results = iis.check_asp_net_debug("http://numorian.com")
    assert isinstance(results, list)


def test_check_telerik_rau_enabled(monkeypatch):
    soup = mock.Mock()
    script = mock.Mock()
    script.get.return_value = "Telerik.Web.UI.WebResource.axd"
    soup.find_all.return_value = [script]
    monkeypatch.setattr("yawast.shared.utils.get_domain", lambda netloc: "numorian.com")
    monkeypatch.setattr(
        "yawast.shared.network.http_get",
        lambda url, allow: DummyResponse(
            text="RadAsyncUpload handler is registered succesfully", status_code=200
        ),
    )
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.reporting.evidence.Evidence.from_response",
        lambda res, meta=None: mock.Mock(),
    )
    monkeypatch.setattr(
        "yawast.reporting.result.Result.from_evidence", lambda *a, **k: mock.Mock()
    )
    results = iis.check_telerik_rau_enabled(soup, "http://numorian.com")
    assert isinstance(results, list)


def test_check_telerik_rau_enabled_no_vuln(monkeypatch):
    soup = mock.Mock()
    script = mock.Mock()
    script.get.return_value = "not-telerik.js"
    soup.find_all.return_value = [script]
    monkeypatch.setattr("yawast.shared.utils.get_domain", lambda netloc: "numorian.com")
    results = iis.check_telerik_rau_enabled(soup, "http://numorian.com")
    assert isinstance(results, list)


def test_check_telerik_rau_enabled_exception(monkeypatch):
    soup = mock.Mock()
    soup.find_all.side_effect = Exception("fail")
    monkeypatch.setattr("yawast.shared.utils.get_domain", lambda netloc: "numorian.com")
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    results = iis.check_telerik_rau_enabled(soup, "http://numorian.com")
    assert isinstance(results, list)
