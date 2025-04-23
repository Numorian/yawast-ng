# Copyright (c) 2025 Adam Caudill and Contributors.
# Unit tests for yawast/scanner/modules/http/servers/apache_tomcat.py
from unittest import mock

import pytest

from yawast.scanner.modules.http.servers import apache_tomcat


class DummyResponse:
    def __init__(
        self, text="", status_code=200, url="http://example.com", request=None
    ):
        self.text = text
        self.status_code = status_code
        self.url = url
        self.request = request or mock.Mock()


def test_get_version_found(monkeypatch):
    res = DummyResponse(text="Apache Tomcat/9.0.1", status_code=404)
    monkeypatch.setattr(
        "yawast.shared.network.http_build_raw_request", lambda req: "rawreq"
    )
    monkeypatch.setattr(
        "yawast.shared.network.http_build_raw_response", lambda res: "rawres"
    )
    monkeypatch.setattr("yawast.reporting.result.Result", lambda *a, **k: mock.Mock())
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_tomcat._check_version_outdated",
        lambda v, u, b: [],
    )
    results = apache_tomcat.get_version("http://example.com", res)
    assert isinstance(results, list)


def test_get_version_not_found(monkeypatch):
    res = DummyResponse(text="No Tomcat here", status_code=404)
    results = apache_tomcat.get_version("http://example.com", res)
    assert results == []


def test_get_version_exception(monkeypatch):
    res = DummyResponse(text=None, status_code=404)
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    results = apache_tomcat.get_version("http://example.com", res)
    assert results == []


def test_check_version(monkeypatch):
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_tomcat._check_version_404",
        lambda url: ["a"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_tomcat._check_version_verb",
        lambda url: ["b"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_tomcat._check_version_post",
        lambda url: ["c"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_tomcat._check_version_406",
        lambda url: ["d"],
    )
    results = apache_tomcat.check_version("http://example.com")
    assert results == ["a", "b", "c", "d"]


def test_check_manager(monkeypatch):
    # Simulate manager page found
    dummy_res = DummyResponse(text="<tt>conf/tomcat-users.xml</tt>", status_code=200)
    monkeypatch.setattr(
        "yawast.shared.network.http_get", lambda url, *a, **k: dummy_res
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
        "yawast.scanner.modules.http.servers.apache_tomcat.check_manager_password",
        lambda url: ["pw"],
    )
    results = apache_tomcat.check_manager("http://example.com")
    assert "pw" in results


def test_check_manager_no_manager(monkeypatch):
    # Simulate no manager page
    dummy_res = DummyResponse(text="nope", status_code=200)
    monkeypatch.setattr(
        "yawast.shared.network.http_get", lambda url, *a, **k: dummy_res
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: ["scan"],
    )
    results = apache_tomcat.check_manager("http://example.com")
    assert "scan" in results


def test_check_manager_exception(monkeypatch):
    monkeypatch.setattr(
        "yawast.shared.network.http_get",
        lambda url, *a, **k: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    results = apache_tomcat.check_manager("http://example.com")
    assert results == []


def test_check_manager_password(monkeypatch):
    dummy_res = DummyResponse(
        text='<font size="+2">Tomcat Web Application Manager</font>', status_code=200
    )
    monkeypatch.setattr(
        "yawast.shared.network.http_get", lambda url, *a, **k: dummy_res
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
    results = apache_tomcat.check_manager_password("http://example.com")
    assert isinstance(results, list)


def test_check_manager_password_no_hit(monkeypatch):
    dummy_res = DummyResponse(text="nope", status_code=200)
    monkeypatch.setattr(
        "yawast.shared.network.http_get", lambda url, *a, **k: dummy_res
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: ["scan"],
    )
    results = apache_tomcat.check_manager_password("http://example.com")
    assert "scan" in results


def test_check_manager_password_exception(monkeypatch):
    monkeypatch.setattr(
        "yawast.shared.network.http_get",
        lambda url, *a, **k: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    results = apache_tomcat.check_manager_password("http://example.com")
    assert results == []


def test_check_cve_2017_12615_rce(monkeypatch):
    dummy_put = DummyResponse(status_code=201)
    dummy_get = DummyResponse(text="abc123", status_code=200)
    monkeypatch.setattr(
        "yawast.shared.network.http_put", lambda url, body, allow: dummy_put
    )
    monkeypatch.setattr("yawast.shared.network.http_get", lambda url, allow: dummy_get)
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
    results = apache_tomcat.check_cve_2017_12615("http://example.com")
    assert isinstance(results, list)


def test_check_cve_2017_12615_no_rce(monkeypatch):
    dummy_put = DummyResponse(status_code=201)
    dummy_get = DummyResponse(text="nope", status_code=200)
    monkeypatch.setattr(
        "yawast.shared.network.http_put", lambda url, body, allow: dummy_put
    )
    monkeypatch.setattr("yawast.shared.network.http_get", lambda url, allow: dummy_get)
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: ["scan"],
    )
    results = apache_tomcat.check_cve_2017_12615("http://example.com")
    assert "scan" in results


def test_check_cve_2017_12615_status_not_2xx(monkeypatch):
    dummy_put = DummyResponse(status_code=404)
    monkeypatch.setattr(
        "yawast.shared.network.http_put", lambda url, body, allow: dummy_put
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: ["scan"],
    )
    results = apache_tomcat.check_cve_2017_12615("http://example.com")
    assert "scan" in results


def test_check_cve_2017_12615_exception(monkeypatch):
    monkeypatch.setattr(
        "yawast.shared.network.http_put",
        lambda *a, **k: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    results = apache_tomcat.check_cve_2017_12615("http://example.com")
    assert results == []


def test_check_cve_2019_0232_found(monkeypatch):
    dummy_res = DummyResponse(text="<DIR>", status_code=200)
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
        lambda url, res: ["scan"],
    )
    links = ["cgi-bin/test"]
    results = apache_tomcat.check_cve_2019_0232(links)
    assert "scan" in results


def test_check_cve_2019_0232_no_dir(monkeypatch):
    dummy_res = DummyResponse(text="nope", status_code=200)
    monkeypatch.setattr("yawast.shared.network.http_get", lambda url, allow: dummy_res)
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: ["scan"],
    )
    links = ["cgi-bin/test"]
    results = apache_tomcat.check_cve_2019_0232(links)
    assert "scan" in results


def test_check_cve_2019_0232_no_cgi(monkeypatch):
    links = ["not-cgi"]
    results = apache_tomcat.check_cve_2019_0232(links)
    assert isinstance(results, list)


def test_check_cve_2019_0232_exception(monkeypatch):
    monkeypatch.setattr(
        "yawast.shared.network.http_get",
        lambda *a, **k: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    links = ["cgi-bin/test"]
    results = apache_tomcat.check_cve_2019_0232(links)
    assert results == []


def test_check_struts_sample_404(monkeypatch):
    monkeypatch.setattr(
        "yawast.shared.network.check_404_response",
        lambda url: (False, None, None, None),
    )
    results = apache_tomcat.check_struts_sample("http://example.com")
    assert results == []


def test_check_struts_sample_found(monkeypatch):
    monkeypatch.setattr(
        "yawast.shared.network.check_404_response", lambda url: (True, None, None, None)
    )
    dummy_res = DummyResponse(status_code=200)
    monkeypatch.setattr("yawast.shared.network.http_get", lambda url, allow: dummy_res)
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: ["scan"],
    )
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr("yawast.reporting.result.Result", lambda *a, **k: mock.Mock())
    monkeypatch.setattr(
        "yawast.shared.network.http_build_raw_request", lambda req: "rawreq"
    )
    monkeypatch.setattr(
        "yawast.shared.network.http_build_raw_response", lambda res: "rawres"
    )
    results = apache_tomcat.check_struts_sample("http://example.com")
    assert "scan" in results


def test_check_struts_sample_status_200(monkeypatch):
    monkeypatch.setattr(
        "yawast.shared.network.check_404_response", lambda url: (True, None, None, None)
    )
    dummy_res = DummyResponse(status_code=200)
    monkeypatch.setattr("yawast.shared.network.http_get", lambda url, allow: dummy_res)
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: [],
    )
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr("yawast.reporting.result.Result", lambda *a, **k: mock.Mock())
    monkeypatch.setattr(
        "yawast.shared.network.http_build_raw_request", lambda req: "rawreq"
    )
    monkeypatch.setattr(
        "yawast.shared.network.http_build_raw_response", lambda res: "rawres"
    )
    results = apache_tomcat.check_struts_sample("http://example.com")
    assert isinstance(results, list)


def test_check_struts_sample_exception(monkeypatch):
    monkeypatch.setattr(
        "yawast.shared.network.check_404_response",
        lambda url: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    results = apache_tomcat.check_struts_sample("http://example.com")
    assert results == []


def test_check_version_404(monkeypatch):
    dummy_res = DummyResponse(status_code=404)
    monkeypatch.setattr("yawast.shared.network.http_get", lambda url, allow: dummy_res)
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_tomcat.get_version",
        lambda url, res, method: ["ver"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: ["scan"],
    )
    results = apache_tomcat._check_version_404("http://example.com")
    assert "ver" in results and "scan" in results


def test_check_version_404_exception(monkeypatch):
    monkeypatch.setattr(
        "yawast.shared.network.http_get",
        lambda *a, **k: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    results = apache_tomcat._check_version_404("http://example.com")
    assert results == []


def test_check_version_verb(monkeypatch):
    dummy_res = DummyResponse(status_code=404)
    monkeypatch.setattr(
        "yawast.shared.network.http_custom", lambda method, url: dummy_res
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_tomcat.get_version",
        lambda url, res, method: ["ver"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: ["scan"],
    )
    results = apache_tomcat._check_version_verb("http://example.com")
    assert "ver" in results and "scan" in results


def test_check_version_verb_exception(monkeypatch):
    monkeypatch.setattr(
        "yawast.shared.network.http_custom",
        lambda *a, **k: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    results = apache_tomcat._check_version_verb("http://example.com")
    assert results == []


def test_check_version_post(monkeypatch):
    dummy_res = DummyResponse(status_code=404)
    monkeypatch.setattr(
        "yawast.shared.network.http_custom", lambda method, url: dummy_res
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_tomcat.get_version",
        lambda url, res, method: ["ver"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: ["scan"],
    )
    results = apache_tomcat._check_version_post("http://example.com")
    assert "ver" in results and "scan" in results


def test_check_version_post_exception(monkeypatch):
    monkeypatch.setattr(
        "yawast.shared.network.http_custom",
        lambda *a, **k: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    results = apache_tomcat._check_version_post("http://example.com")
    assert results == []


def test_check_version_406(monkeypatch):
    dummy_res = DummyResponse(status_code=404)
    monkeypatch.setattr(
        "yawast.shared.network.http_get", lambda url, allow, headers=None: dummy_res
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_tomcat.get_version",
        lambda url, res, method: ["ver"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: ["scan"],
    )
    results = apache_tomcat._check_version_406("http://example.com")
    assert "ver" in results and "scan" in results


def test_check_version_406_exception(monkeypatch):
    monkeypatch.setattr(
        "yawast.shared.network.http_get",
        lambda *a, **k: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    results = apache_tomcat._check_version_406("http://example.com")
    assert results == []


def test_get_version_from_body():
    body = "Error: Apache Tomcat/8.5.12 is running."
    ver = apache_tomcat._get_version_from_body(body, 404)
    assert ver == "8.5.12"
    ver_none = apache_tomcat._get_version_from_body("No Tomcat", 404)
    assert ver_none is None


def test_check_version_outdated(monkeypatch):
    monkeypatch.setattr(
        "yawast.scanner.modules.http.version_checker.get_latest_version",
        lambda name, ver: type(
            "V", (), {"__gt__": lambda self, o: True, "__str__": lambda self: "10.0.0"}
        )(),
    )
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr("yawast.reporting.result.Result", lambda *a, **k: mock.Mock())
    results = apache_tomcat._check_version_outdated(
        "8.5.12", "http://example.com", "body"
    )
    assert isinstance(results, list)
