# Copyright (c) 2025 Adam Caudill and Contributors.
# Unit tests for yawast/scanner/cli/http.py
from unittest import mock

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
