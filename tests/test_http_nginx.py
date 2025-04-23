from unittest import mock

import pytest

from yawast.scanner.modules.http.servers import nginx


def test_check_banner_with_version(monkeypatch):
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr("yawast.reporting.result.Result", lambda *a, **k: mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.http.version_checker.get_latest_version",
        lambda name, ver: type(
            "V", (), {"__gt__": lambda self, o: True, "__str__": lambda self: "1.25.0"}
        )(),
    )
    banner = "nginx/1.24.0"
    results = nginx.check_banner(banner, "raw", "http://example.com")
    assert isinstance(results, list)


def test_check_banner_no_version(monkeypatch):
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr("yawast.reporting.result.Result", lambda *a, **k: mock.Mock())
    banner = "nginx"
    results = nginx.check_banner(banner, "raw", "http://example.com")
    assert isinstance(results, list)


def test_check_banner_not_nginx():
    banner = "Apache/2.4.58"
    results = nginx.check_banner(banner, "raw", "http://example.com")
    assert results == []


def test_check_all(monkeypatch):
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.nginx.check_status", lambda url: ["status"]
    )
    results = nginx.check_all("http://example.com")
    assert "status" in results


def test_check_status_found(monkeypatch):
    dummy_res = mock.Mock(
        text="Active connections:", status_code=200, request=mock.Mock()
    )
    monkeypatch.setattr("yawast.shared.network.http_get", lambda url, allow: dummy_res)
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
    results = nginx.check_status("http://example.com")
    assert isinstance(results, list)


def test_check_status_not_found(monkeypatch):
    dummy_res = mock.Mock(text="Not found", status_code=404, request=mock.Mock())
    monkeypatch.setattr("yawast.shared.network.http_get", lambda url, allow: dummy_res)
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: ["scan"],
    )
    results = nginx.check_status("http://example.com")
    assert "scan" in results
