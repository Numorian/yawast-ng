#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
#  See the LICENSE file for full license details.

from unittest import mock

import pytest

from yawast.scanner.modules.http.servers import apache_httpd


class TestHttpApacheHttpd:
    def test_check_banner(self):
        res = apache_httpd.check_banner(
            "Apache", "<raw-request-data>", "http://adamcaudill.com"
        )

        assert len(res) == 1
        assert res[0].message == "Generic Apache Server Banner Found"

    def test_check_banner_future(self):
        res = apache_httpd.check_banner(
            "Apache/99.9.9", "<raw-request-data>", "http://adamcaudill.com"
        )

        assert len(res) == 1
        assert res[0].message == "Apache Server Version Exposed: Apache/99.9.9"

    def test_check_banner_old_24(self):
        res = apache_httpd.check_banner(
            "Apache/2.4.7", "<raw-request-data>", "http://adamcaudill.com"
        )

        assert len(res) == 2
        assert res[0].message == "Apache Server Version Exposed: Apache/2.4.7"
        assert "Apache Server Outdated:" in res[1].message

    def test_check_banner_old_php(self):
        res = apache_httpd.check_banner(
            "Apache/2.4.6 (FreeBSD) PHP/5.4.23",
            "<raw-request-data>",
            "http://adamcaudill.com",
        )

        assert len(res) == 4
        assert res[0].message == "Apache Server Version Exposed: Apache/2.4.6"
        assert "Apache Server Outdated:" in res[1].message
        assert res[2].message == "PHP Version Exposed: PHP/5.4.23"
        assert "PHP Outdated:" in res[3].message

    def test_check_banner_old_php_ossl(self):
        res = apache_httpd.check_banner(
            "Apache/2.4.6 (FreeBSD) PHP/5.4.23 OpenSSL/0.9.8n",
            "<raw-request-data>",
            "http://adamcaudill.com",
        )

        assert len(res) == 5
        assert res[0].message == "Apache Server Version Exposed: Apache/2.4.6"
        assert "Apache Server Outdated:" in res[1].message
        assert res[2].message == "PHP Version Exposed: PHP/5.4.23"
        assert "PHP Outdated:" in res[3].message
        assert res[4].message == "OpenSSL Version Exposed: OpenSSL/0.9.8n"

    def test_check_banner_old_22(self):
        res = apache_httpd.check_banner(
            "Apache/2.2.7", "<raw-request-data>", "http://adamcaudill.com"
        )

        assert len(res) == 2
        assert res[0].message == "Apache Server Version Exposed: Apache/2.2.7"
        assert "Apache Server Outdated:" in res[1].message

    def test_check_banner_old_invalid(self):
        res = apache_httpd.check_banner(
            "Apache/1.1.7", "<raw-request-data>", "http://adamcaudill.com"
        )

        assert len(res) == 2
        assert res[0].message == "Apache Server Version Exposed: Apache/1.1.7"
        assert "Apache Server Outdated:" in res[1].message


def test_check_banner_with_version(monkeypatch):
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr("yawast.reporting.result.Result", lambda *a, **k: mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.http.version_checker.get_latest_version",
        lambda name, ver: type(
            "V", (), {"__gt__": lambda self, o: True, "__str__": lambda self: "2.4.60"}
        )(),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.php.check_version",
        lambda module, raw, url: ["php"],
    )
    banner = "Apache/2.4.58 PHP/8.1.0 OpenSSL/1.1.1"
    results = apache_httpd.check_banner(banner, "raw", "http://numorian.com")
    assert isinstance(results, list)


def test_check_banner_no_version(monkeypatch):
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr("yawast.reporting.result.Result", lambda *a, **k: mock.Mock())
    banner = "Apache"
    results = apache_httpd.check_banner(banner, "raw", "http://numorian.com")
    assert isinstance(results, list)


def test_check_banner_not_apache():
    banner = "nginx/1.18.0"
    results = apache_httpd.check_banner(banner, "raw", "http://numorian.com")
    assert results == []


def test_check_banner_distro_string(monkeypatch):
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr("yawast.reporting.result.Result", lambda *a, **k: mock.Mock())
    banner = "Apache/2.4.58 (Debian) PHP/8.1.0"
    monkeypatch.setattr(
        "yawast.scanner.modules.http.version_checker.get_latest_version",
        lambda name, ver: None,
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.php.check_version",
        lambda module, raw, url: [],
    )
    results = apache_httpd.check_banner(banner, "raw", "http://numorian.com")
    assert isinstance(results, list)


def test_check_all(monkeypatch):
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_httpd.check_server_status",
        lambda url: ["status"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_httpd.check_server_info",
        lambda url: ["info"],
    )
    results = apache_httpd.check_all("http://numorian.com")
    assert "status" in results and "info" in results


def test_check_server_status_found(monkeypatch):
    dummy_res = mock.Mock(text="Apache Server Status", status_code=200)
    monkeypatch.setattr("yawast.shared.network.http_get", lambda url, allow: dummy_res)
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr("yawast.reporting.result.Result", lambda *a, **k: mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: [],
    )
    results = apache_httpd.check_server_status("http://numorian.com")
    assert isinstance(results, list)


def test_check_server_status_not_found(monkeypatch):
    dummy_res = mock.Mock(text="Not found", status_code=404)
    monkeypatch.setattr("yawast.shared.network.http_get", lambda url, allow: dummy_res)
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: ["scan"],
    )
    results = apache_httpd.check_server_status("http://numorian.com")
    assert "scan" in results


def test_check_server_info_found(monkeypatch):
    dummy_res = mock.Mock(text="Apache Server Information", status_code=200)
    monkeypatch.setattr("yawast.shared.network.http_get", lambda url, allow: dummy_res)
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr("yawast.reporting.result.Result", lambda *a, **k: mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: [],
    )
    results = apache_httpd.check_server_info("http://numorian.com")
    assert isinstance(results, list)


def test_check_server_info_not_found(monkeypatch):
    dummy_res = mock.Mock(text="Not found", status_code=404)
    monkeypatch.setattr("yawast.shared.network.http_get", lambda url, allow: dummy_res)
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: ["scan"],
    )
    results = apache_httpd.check_server_info("http://numorian.com")
    assert "scan" in results
