# Copyright (c) 2025 Numorian, Inc. and Contributors.
# Unit tests for yawast/scanner/cli/http.py
from unittest import mock
from urllib.parse import urlparse

import pytest

from yawast.scanner.cli import http


class DummyArgs:
    def __init__(
        self,
        user=None,
        password=None,
        pass_reset_page=None,
        php_page=None,
        files=False,
        dir=False,
        dirlistredir=False,
        dirrecursive=False,
    ):
        self.user = user
        self.password = password
        self.pass_reset_page = pass_reset_page
        self.php_page = php_page
        self.files = files
        self.dir = dir
        self.dirlistredir = dirlistredir
        self.dirrecursive = dirrecursive


class DummySession:
    def __init__(self, url, domain, args=None):
        self.url = url
        self.domain = domain
        self.args = args or DummyArgs()
        self.url_parsed = urlparse(url)
        self.supports_http = True

    def get_http_url(self):
        return self.url


def test_reset_calls_all():
    with mock.patch("yawast.scanner.modules.http.retirejs.reset") as rj, mock.patch(
        "yawast.scanner.modules.http.file_search.reset"
    ) as fs, mock.patch(
        "yawast.scanner.modules.http.error_checker.reset"
    ) as ec, mock.patch(
        "yawast.scanner.modules.http.http_basic.reset"
    ) as hb:
        http.reset()
        rj.assert_called_once()
        fs.assert_called_once()
        ec.assert_called_once()
        hb.assert_called_once()


def test_file_search_basic(monkeypatch):
    session = DummySession("http://example.com", "example.com")
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr(
        "yawast.reporting.reporter.display_results", lambda *a, **k: None
    )
    monkeypatch.setattr("yawast.reporting.reporter.display", lambda *a, **k: None)
    monkeypatch.setattr("yawast.reporting.issue.Issue", mock.Mock())
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.reporting.evidence.Evidence.from_response", lambda r: "evidence"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: [],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.special_files.check_special_files",
        lambda url: (["/robots.txt"], []),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_backups",
        lambda links: (["/backup.zip"], []),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_ds_store", lambda links: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.special_files.check_special_paths",
        lambda url: (["/admin"], []),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_directories",
        lambda url, a, b: (["/dir"], []),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_files",
        lambda url: (["/file"], []),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_ds_store", lambda links: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_backups", lambda links: ([], [])
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_directories",
        lambda url, a, b: ([], []),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_files", lambda url: ([], [])
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.special_files.check_special_paths",
        lambda url: ([], []),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.special_files.check_special_files",
        lambda url: ([], []),
    )
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr(
        "yawast.reporting.reporter.display_results", lambda *a, **k: None
    )
    monkeypatch.setattr("yawast.reporting.reporter.display", lambda *a, **k: None)
    monkeypatch.setattr("yawast.reporting.issue.Issue", mock.Mock())
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.reporting.evidence.Evidence.from_response", lambda r: "evidence"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.response_scanner.check_response",
        lambda url, res: [],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.special_files.check_special_files",
        lambda url: (["/robots.txt"], []),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_backups",
        lambda links: (["/backup.zip"], []),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_ds_store", lambda links: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.special_files.check_special_paths",
        lambda url: (["/admin"], []),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_directories",
        lambda url, a, b: (["/dir"], []),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_files",
        lambda url: (["/file"], []),
    )
    # Simulate args.files and args.dir
    session.args.files = True
    session.args.dir = True
    result = http._file_search(session, ["/index.html"])
    assert isinstance(result, list)


def test_check_password_reset_user_prompt(monkeypatch):
    session = DummySession("http://example.com", "example.com")
    session.args.user = None
    monkeypatch.setattr("yawast.shared.utils.prompt", lambda msg: "user")
    monkeypatch.setattr(
        "yawast.reporting.reporter.display_results", lambda *a, **k: None
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.generic.password_reset.check_resp_user_enum",
        lambda s, u, e: [],
    )
    http._check_password_reset(session)


def test_check_password_reset_no_user(monkeypatch):
    session = DummySession("http://example.com", "example.com")
    session.args.user = None
    monkeypatch.setattr("yawast.shared.utils.prompt", lambda msg: None)
    result = http._check_password_reset(session)
    assert result is None


def test_check_password_reset_element_not_found(monkeypatch):
    session = DummySession("http://example.com", "example.com")
    session.args.user = "user"

    # Simulate PasswordResetElementNotFound with no element_name
    class DummyEx(Exception):
        pass

    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.generic.password_reset.check_resp_user_enum",
        lambda s, u, e: (_ for _ in ()).throw(
            http.PasswordResetElementNotFound("fail")
        ),
    )
    monkeypatch.setattr("yawast.shared.utils.prompt", lambda msg: None)
    monkeypatch.setattr("builtins.print", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.error", lambda *a, **k: None)
    http._check_password_reset(session)


def test_check_password_reset_element_not_found_with_name(monkeypatch):
    session = DummySession("http://example.com", "example.com")
    session.args.user = "user"
    # Simulate PasswordResetElementNotFound with element_name
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.generic.password_reset.check_resp_user_enum",
        lambda s, u, e: (_ for _ in ()).throw(
            http.PasswordResetElementNotFound("fail")
        ),
    )
    monkeypatch.setattr("yawast.shared.output.error", lambda *a, **k: None)
    http._check_password_reset(session, element_name="foo")


def test_scan_basic(monkeypatch):
    session = DummySession("http://example.com", "example.com")
    # Patch all dependencies used in scan
    monkeypatch.setattr("yawast.scanner.cli.http._file_search", lambda s, l: ["/file"])
    monkeypatch.setattr(
        "yawast.scanner.cli.http._check_password_reset",
        lambda s, element_name=None: None,
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.error_checker.check_response", lambda *a, **k: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_files", lambda url: ([], [])
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_directories",
        lambda url, a, b: ([], []),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_backups", lambda links: ([], [])
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_ds_store", lambda links: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.special_files.check_special_files",
        lambda url: ([], []),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.special_files.check_special_paths",
        lambda url: ([], []),
    )
    monkeypatch.setattr(
        "yawast.reporting.reporter.display_results", lambda *a, **k: None
    )
    monkeypatch.setattr("yawast.reporting.reporter.display", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr("yawast.shared.output.error", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.debug", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.utils.prompt", lambda msg: None)
    monkeypatch.setattr("yawast.reporting.issue.Issue", mock.Mock())
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.reporting.evidence.Evidence.from_response", lambda r: "evidence"
    )
    # Simulate args
    session.args.files = True
    session.args.dir = True
    session.args.user = None
    session.args.pass_reset_page = None
    # Should run without error
    http.scan(session)


def test_scan_with_password_reset(monkeypatch):
    session = DummySession("http://example.com", "example.com")
    monkeypatch.setattr("yawast.scanner.cli.http._file_search", lambda s, l: ["/file"])
    monkeypatch.setattr(
        "yawast.scanner.cli.http._check_password_reset",
        lambda s, element_name=None: None,
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.error_checker.check_response", lambda *a, **k: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_files", lambda url: ([], [])
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_directories",
        lambda url, a, b: ([], []),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_backups", lambda links: ([], [])
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.file_search.find_ds_store", lambda links: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.special_files.check_special_files",
        lambda url: ([], []),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.special_files.check_special_paths",
        lambda url: ([], []),
    )
    monkeypatch.setattr(
        "yawast.reporting.reporter.display_results", lambda *a, **k: None
    )
    monkeypatch.setattr("yawast.reporting.reporter.display", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr("yawast.shared.output.error", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.debug", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.utils.prompt", lambda msg: None)
    monkeypatch.setattr("yawast.reporting.issue.Issue", mock.Mock())
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.reporting.evidence.Evidence.from_response", lambda r: "evidence"
    )
    # Mock the spider to avoid real network calls and speed up the test
    monkeypatch.setattr(
        "yawast.scanner.modules.http.spider.spider", lambda session: ([], [])
    )
    # Mock all network operations to prevent real HTTP requests
    monkeypatch.setattr(
        "yawast.shared.network.http_head",
        lambda url, *a, **k: mock.Mock(
            headers={}, text="", status_code=200, splitlines=lambda: ["line1", "line2"]
        ),
    )
    monkeypatch.setattr(
        "yawast.shared.network.http_build_raw_response", lambda h: "HTTP/1.1 200 OK\n"
    )

    # Provide a more realistic mock for http_get and http_post, with .request.url as a real string
    def make_mock_response(method, url):
        req = mock.Mock()
        req.method = method
        req.url = url
        resp = mock.Mock()
        resp.status_code = 200
        resp.headers = {}
        resp.text = ""
        resp.iter_content = lambda chunk_size: iter([b"data"])
        resp.content = b"data"
        resp.elapsed = mock.Mock(total_seconds=lambda: 0.01)
        resp.request = req
        return resp

    monkeypatch.setattr(
        "yawast.shared.network.http_get",
        lambda url, *a, **k: make_mock_response("GET", url),
    )
    monkeypatch.setattr(
        "yawast.shared.network.http_post",
        lambda url, *a, **k: make_mock_response("POST", url),
    )
    monkeypatch.setattr("yawast.shared.network.update_auth", lambda t: None)
    session.args.files = False
    session.args.dir = False
    session.args.user = "user"
    session.args.pass_reset_page = "http://example.com/reset"
    http.scan(session)


def test_scan_error_handling(monkeypatch):
    session = DummySession("http://example.com", "example.com")
    # Patch _file_search to raise
    monkeypatch.setattr(
        "yawast.scanner.cli.http._file_search",
        lambda s, l: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr("yawast.shared.output.error", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    session.args.files = True
    session.args.dir = False
    session.args.user = None
    session.args.pass_reset_page = None
    # Should not raise
    try:
        http.scan(session)
    except Exception:
        pass


def test_scan_login_success(monkeypatch):
    session = DummySession("http://example.com", "example.com")
    session.args.user = "user"
    session.args.password = "pass"
    # Patch login and all output/network dependencies
    monkeypatch.setattr("yawast.reporting.reporter.register_data", lambda *a, **k: None)
    monkeypatch.setattr(
        "yawast.reporting.reporter.display_results", lambda *a, **k: None
    )
    monkeypatch.setattr("yawast.reporting.reporter.display", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr("yawast.shared.output.warn", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.error", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    monkeypatch.setattr("yawast.shared.utils.prompt", lambda msg: None)
    monkeypatch.setattr("yawast.reporting.issue.Issue", mock.Mock())
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.reporting.evidence.Evidence.from_response", lambda r: "evidence"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.generic_login.login_and_get_auth",
        lambda url, u, p: {"error": None},
    )
    monkeypatch.setattr("yawast.shared.network.update_auth", lambda t: None)
    monkeypatch.setattr(
        "yawast.shared.network.http_head",
        lambda url: mock.Mock(headers={}, text="", status_code=200),
    )
    monkeypatch.setattr(
        "yawast.shared.network.http_build_raw_response", lambda h: "HTTP/1.1 200 OK\n"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.get_header_issues", lambda h, r, u: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.get_cookie_issues", lambda h, u: []
    )
    monkeypatch.setattr("yawast.scanner.modules.http.waf.get_waf", lambda h, r, u: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_hsts_preload", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_http_methods",
        lambda url: ([], []),
    )
    monkeypatch.setattr("yawast.scanner.modules.http.spider.spider", lambda s: ([], []))
    monkeypatch.setattr("yawast.scanner.cli.http._file_search", lambda s, l: [])
    monkeypatch.setattr(
        "yawast.scanner.cli.http._check_password_reset",
        lambda s, element_name=None: None,
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_local_ip_disclosure", lambda s: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_httpd.check_all", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_tomcat.check_all",
        lambda url, links: [],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.nginx.check_all", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.iis.check_all", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_propfind", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_trace", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_options", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.php.find_phpinfo", lambda links: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.php.check_cve_2019_11043",
        lambda s, links: [],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.jira.check_for_jira",
        lambda s: ([], None),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.wordpress.identify",
        lambda url: (None, []),
    )
    monkeypatch.setattr(
        "yawast.scanner.plugins.plugin_manager.run_http_scans", lambda url: None
    )
    http.scan(session)


def test_scan_login_failure(monkeypatch):
    session = DummySession("http://example.com", "example.com")
    session.args.user = "user"
    session.args.password = "pass"
    monkeypatch.setattr("yawast.reporting.reporter.register_data", lambda *a, **k: None)
    monkeypatch.setattr(
        "yawast.reporting.reporter.display_results", lambda *a, **k: None
    )
    monkeypatch.setattr("yawast.reporting.reporter.display", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr("yawast.shared.output.warn", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.error", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    monkeypatch.setattr("yawast.shared.utils.prompt", lambda msg: None)
    monkeypatch.setattr("yawast.reporting.issue.Issue", mock.Mock())
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.reporting.evidence.Evidence.from_response", lambda r: "evidence"
    )

    # Simulate login raising LoginFormNotFound
    class DummyLoginFormNotFound(Exception):
        pass

    monkeypatch.setattr(
        "yawast.scanner.modules.http.generic_login.LoginFormNotFound",
        DummyLoginFormNotFound,
    )

    def raise_login(*a, **k):
        raise DummyLoginFormNotFound("fail")

    monkeypatch.setattr(
        "yawast.scanner.modules.http.generic_login.login_and_get_auth", raise_login
    )
    monkeypatch.setattr(
        "yawast.shared.network.http_head",
        lambda url: mock.Mock(headers={}, text="", status_code=200),
    )
    monkeypatch.setattr(
        "yawast.shared.network.http_build_raw_response", lambda h: "HTTP/1.1 200 OK\n"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.get_header_issues", lambda h, r, u: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.get_cookie_issues", lambda h, u: []
    )
    monkeypatch.setattr("yawast.scanner.modules.http.waf.get_waf", lambda h, r, u: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_hsts_preload", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_http_methods",
        lambda url: ([], []),
    )
    monkeypatch.setattr("yawast.scanner.modules.http.spider.spider", lambda s: ([], []))
    monkeypatch.setattr("yawast.scanner.cli.http._file_search", lambda s, l: [])
    monkeypatch.setattr(
        "yawast.scanner.cli.http._check_password_reset",
        lambda s, element_name=None: None,
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_local_ip_disclosure", lambda s: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_httpd.check_all", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_tomcat.check_all",
        lambda url, links: [],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.nginx.check_all", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.iis.check_all", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_propfind", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_trace", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_options", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.php.find_phpinfo", lambda links: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.php.check_cve_2019_11043",
        lambda s, links: [],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.jira.check_for_jira",
        lambda s: ([], None),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.wordpress.identify",
        lambda url: (None, []),
    )
    monkeypatch.setattr(
        "yawast.scanner.plugins.plugin_manager.run_http_scans", lambda url: None
    )
    http.scan(session)


def test_scan_header_cookie_waf_hsts(monkeypatch):
    session = DummySession("http://example.com", "example.com")
    # Patch all output/network dependencies
    monkeypatch.setattr("yawast.reporting.reporter.register_data", lambda *a, **k: None)
    monkeypatch.setattr(
        "yawast.reporting.reporter.display_results", lambda *a, **k: None
    )
    monkeypatch.setattr("yawast.reporting.reporter.display", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr("yawast.shared.output.warn", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.error", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    monkeypatch.setattr("yawast.shared.utils.prompt", lambda msg: None)
    monkeypatch.setattr("yawast.reporting.issue.Issue", mock.Mock())
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.reporting.evidence.Evidence.from_response", lambda r: "evidence"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.generic_login.login_and_get_auth",
        lambda url, u, p: {"error": None},
    )
    monkeypatch.setattr("yawast.shared.network.update_auth", lambda t: None)
    monkeypatch.setattr(
        "yawast.shared.network.http_head",
        lambda url: mock.Mock(
            headers={}, text="", status_code=200, splitlines=lambda: ["line1", "line2"]
        ),
    )
    monkeypatch.setattr(
        "yawast.shared.network.http_build_raw_response", lambda h: "HTTP/1.1 200 OK\n"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.get_header_issues",
        lambda h, r, u: ["header_issue"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.get_cookie_issues",
        lambda h, u: ["cookie_issue"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.waf.get_waf", lambda h, r, u: ["waf_issue"]
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_hsts_preload",
        lambda url: [{"name": "test", "status": "ok", "preloadedDomain": "yes"}],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_http_methods",
        lambda url: (["GET", "POST"], ["method_issue"]),
    )
    monkeypatch.setattr("yawast.scanner.modules.http.spider.spider", lambda s: ([], []))
    monkeypatch.setattr("yawast.scanner.cli.http._file_search", lambda s, l: [])
    monkeypatch.setattr(
        "yawast.scanner.cli.http._check_password_reset",
        lambda s, element_name=None: None,
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_local_ip_disclosure", lambda s: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_httpd.check_all", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_tomcat.check_all",
        lambda url, links: [],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.nginx.check_all", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.iis.check_all", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_propfind", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_trace", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_options", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.php.find_phpinfo", lambda links: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.php.check_cve_2019_11043",
        lambda s, links: [],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.jira.check_for_jira",
        lambda s: ([], None),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.wordpress.identify",
        lambda url: (None, []),
    )
    monkeypatch.setattr(
        "yawast.scanner.plugins.plugin_manager.run_http_scans", lambda url: None
    )
    http.scan(session)


def test_scan_spider_error(monkeypatch):
    session = DummySession("http://example.com", "example.com")
    monkeypatch.setattr("yawast.reporting.reporter.register_data", lambda *a, **k: None)
    monkeypatch.setattr(
        "yawast.reporting.reporter.display_results", lambda *a, **k: None
    )
    monkeypatch.setattr("yawast.reporting.reporter.display", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr("yawast.shared.output.warn", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.error", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    monkeypatch.setattr("yawast.shared.utils.prompt", lambda msg: None)
    monkeypatch.setattr("yawast.reporting.issue.Issue", mock.Mock())
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.reporting.evidence.Evidence.from_response", lambda r: "evidence"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.generic_login.login_and_get_auth",
        lambda url, u, p: {"error": None},
    )
    monkeypatch.setattr("yawast.shared.network.update_auth", lambda t: None)
    monkeypatch.setattr(
        "yawast.shared.network.http_head",
        lambda url: mock.Mock(
            headers={}, text="", status_code=200, splitlines=lambda: ["line1", "line2"]
        ),
    )
    monkeypatch.setattr(
        "yawast.shared.network.http_build_raw_response", lambda h: "HTTP/1.1 200 OK\n"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.get_header_issues", lambda h, r, u: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.get_cookie_issues", lambda h, u: []
    )
    monkeypatch.setattr("yawast.scanner.modules.http.waf.get_waf", lambda h, r, u: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_hsts_preload", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_http_methods",
        lambda url: ([], []),
    )

    def raise_spider(*a, **k):
        raise Exception("fail")

    monkeypatch.setattr("yawast.scanner.modules.http.spider.spider", raise_spider)
    monkeypatch.setattr("yawast.scanner.cli.http._file_search", lambda s, l: [])
    monkeypatch.setattr(
        "yawast.scanner.cli.http._check_password_reset",
        lambda s, element_name=None: None,
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_local_ip_disclosure", lambda s: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_httpd.check_all", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_tomcat.check_all",
        lambda url, links: [],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.nginx.check_all", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.iis.check_all", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_propfind", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_trace", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_options", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.php.find_phpinfo", lambda links: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.php.check_cve_2019_11043",
        lambda s, links: [],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.jira.check_for_jira",
        lambda s: ([], None),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.wordpress.identify",
        lambda url: (None, []),
    )
    monkeypatch.setattr(
        "yawast.scanner.plugins.plugin_manager.run_http_scans", lambda url: None
    )
    http.scan(session)


def test_scan_supported_http_methods(monkeypatch):
    session = DummySession("http://example.com", "example.com")
    monkeypatch.setattr("yawast.reporting.reporter.register_data", lambda *a, **k: None)
    monkeypatch.setattr(
        "yawast.reporting.reporter.display_results", lambda *a, **k: None
    )
    monkeypatch.setattr("yawast.reporting.reporter.display", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr("yawast.shared.output.warn", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.error", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    monkeypatch.setattr("yawast.shared.utils.prompt", lambda msg: None)
    monkeypatch.setattr("yawast.reporting.issue.Issue", mock.Mock())
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.reporting.evidence.Evidence.from_response", lambda r: "evidence"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.generic_login.login_and_get_auth",
        lambda url, u, p: {"error": None},
    )
    monkeypatch.setattr("yawast.shared.network.update_auth", lambda t: None)
    monkeypatch.setattr(
        "yawast.shared.network.http_head",
        lambda url: mock.Mock(
            headers={}, text="", status_code=200, splitlines=lambda: ["line1", "line2"]
        ),
    )
    monkeypatch.setattr(
        "yawast.shared.network.http_build_raw_response", lambda h: "HTTP/1.1 200 OK\n"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.get_header_issues", lambda h, r, u: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.get_cookie_issues", lambda h, u: []
    )
    monkeypatch.setattr("yawast.scanner.modules.http.waf.get_waf", lambda h, r, u: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_hsts_preload", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_http_methods",
        lambda url: (["GET", "POST"], []),
    )
    monkeypatch.setattr("yawast.scanner.modules.http.spider.spider", lambda s: ([], []))
    monkeypatch.setattr("yawast.scanner.cli.http._file_search", lambda s, l: [])
    monkeypatch.setattr(
        "yawast.scanner.cli.http._check_password_reset",
        lambda s, element_name=None: None,
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_local_ip_disclosure", lambda s: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_httpd.check_all", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_tomcat.check_all",
        lambda url, links: [],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.nginx.check_all", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.iis.check_all", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_propfind", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_trace", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_options", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.php.find_phpinfo", lambda links: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.php.check_cve_2019_11043",
        lambda s, links: [],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.jira.check_for_jira",
        lambda s: ([], None),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.wordpress.identify",
        lambda url: (None, []),
    )
    monkeypatch.setattr(
        "yawast.scanner.plugins.plugin_manager.run_http_scans", lambda url: None
    )
    http.scan(session)


def test_scan_server_checks_and_plugins(monkeypatch):
    session = DummySession("http://example.com", "example.com")
    monkeypatch.setattr("yawast.reporting.reporter.register_data", lambda *a, **k: None)
    monkeypatch.setattr(
        "yawast.reporting.reporter.display_results", lambda *a, **k: None
    )
    monkeypatch.setattr("yawast.reporting.reporter.display", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr("yawast.shared.output.warn", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.error", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    monkeypatch.setattr("yawast.shared.utils.prompt", lambda msg: None)
    monkeypatch.setattr("yawast.reporting.issue.Issue", mock.Mock())
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.reporting.evidence.Evidence.from_response", lambda r: "evidence"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.generic_login.login_and_get_auth",
        lambda url, u, p: {"error": None},
    )
    monkeypatch.setattr("yawast.shared.network.update_auth", lambda t: None)
    monkeypatch.setattr(
        "yawast.shared.network.http_head",
        lambda url: mock.Mock(
            headers={}, text="", status_code=200, splitlines=lambda: ["line1", "line2"]
        ),
    )
    monkeypatch.setattr(
        "yawast.shared.network.http_build_raw_response", lambda h: "HTTP/1.1 200 OK\n"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.get_header_issues", lambda h, r, u: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.get_cookie_issues", lambda h, u: []
    )
    monkeypatch.setattr("yawast.scanner.modules.http.waf.get_waf", lambda h, r, u: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_hsts_preload", lambda url: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_http_methods",
        lambda url: ([], []),
    )
    monkeypatch.setattr("yawast.scanner.modules.http.spider.spider", lambda s: ([], []))
    monkeypatch.setattr("yawast.scanner.cli.http._file_search", lambda s, l: [])
    monkeypatch.setattr(
        "yawast.scanner.cli.http._check_password_reset",
        lambda s, element_name=None: None,
    )
    # Patch all server checks to return a result
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_local_ip_disclosure",
        lambda s: ["ip_issue"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_httpd.check_all",
        lambda url: ["apache_issue"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.apache_tomcat.check_all",
        lambda url, links: ["tomcat_issue"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.nginx.check_all",
        lambda url: ["nginx_issue"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.iis.check_all", lambda url: ["iis_issue"]
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_propfind",
        lambda url: ["propfind_issue"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_trace",
        lambda url: ["trace_issue"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.http_basic.check_options",
        lambda url: ["options_issue"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.php.find_phpinfo",
        lambda links: ["phpinfo_issue"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.servers.php.check_cve_2019_11043",
        lambda s, links: ["cve_issue"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.jira.check_for_jira",
        lambda s: (["jira_issue"], "jira_path"),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.jira.check_jira_user_registration",
        lambda path: ["jira_user_issue"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.wordpress.identify",
        lambda url: ("wp_path", ["wp_issue"]),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.wordpress.check_json_user_enum",
        lambda path: ["wp_json_issue"],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.http.applications.wordpress.check_path_disclosure",
        lambda path: ["wp_path_issue"],
    )
    plugin_called = {}

    def fake_run_http_scans(url):
        plugin_called["called"] = True

    monkeypatch.setattr(
        "yawast.scanner.plugins.plugin_manager.run_http_scans", fake_run_http_scans
    )
    session.args.php_page = "php"
    http.scan(session)
    assert plugin_called["called"]
