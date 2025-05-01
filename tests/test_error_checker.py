#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
#  See the LICENSE file for full license details.

from unittest import mock

import pytest
import requests
import requests_mock

from yawast.scanner.modules.http import error_checker


class DummyResponse:
    def __init__(self, text="", status_code=200, request=None):
        self.text = text
        self.status_code = status_code
        self.request = request or mock.Mock(method="GET")


class TestErrorChecker:
    def test_check_response_none(self):
        with requests_mock.Mocker() as m:
            url = "http://example.com"
            m.get(url, text="body")

            resp = requests.get(url)

        res = error_checker.check_response(url, resp)

        assert len(res) == 0

    def test_check_response_php(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="Fatal error: Call to a member function getId() on a non-object "
                "in /var/www/docroot/application/modules/controllers/"
                "ModalController.php on line 609",
            )

            resp = requests.get(url)

        res = error_checker.check_response(url, resp)

        assert len(res) == 1

    def test_check_response_java(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="Failed to convert property value of type [java.lang.String] to"
                " required type [boolean] for property order; nested exception is"
                " java.lang.IllegalArgumentException",
            )

            resp = requests.get(url)

        res = error_checker.check_response(url, resp)

        assert len(res) == 1

    def test_check_response_fp(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(url, text="at (202)")

            resp = requests.get(url)

        res = error_checker.check_response(url, resp)

        assert len(res) == 0


def test_check_response_detects_error(monkeypatch):
    # Setup a rule that matches 'error123' in the body
    rule = error_checker._MatchRule("error123\t0\tError\t0\tHigh")
    error_checker._data = [rule]
    error_checker._reports = []
    res = DummyResponse(text="something error123 something")
    monkeypatch.setattr(
        "yawast.reporting.result.Result.from_evidence", lambda *a, **k: mock.Mock()
    )
    monkeypatch.setattr(
        "yawast.reporting.evidence.Evidence.from_response", lambda res: mock.Mock()
    )
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    results = error_checker.check_response("http://example.com", res)
    assert isinstance(results, list)
    assert len(results) == 1


def test_check_response_duplicate(monkeypatch):
    rule = error_checker._MatchRule("error123\t0\tError\t0\tHigh")
    error_checker._data = [rule]
    error_checker._reports = []
    res = DummyResponse(text="something error123 something")
    monkeypatch.setattr(
        "yawast.reporting.result.Result.from_evidence", lambda *a, **k: mock.Mock()
    )
    monkeypatch.setattr(
        "yawast.reporting.evidence.Evidence.from_response", lambda res: mock.Mock()
    )
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    # First call adds the report
    error_checker.check_response("http://example.com", res)
    # Second call should be deduped
    results = error_checker.check_response("http://example.com", res)
    assert results == []


def test_check_response_none(monkeypatch):
    results = error_checker.check_response("http://example.com", None)
    assert results == []


def test_check_response_exception(monkeypatch):
    # Simulate a rule that will raise in regex
    class BadRule:
        pattern = 123  # not a regex
        match_group = "0"
        confidence = "High"

    error_checker._data = [BadRule()]
    error_checker._reports = []
    res = DummyResponse(text="foo")
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    results = error_checker.check_response("http://example.com", res)
    assert results == []


def test_reset():
    error_checker._reports = ["foo"]
    error_checker.reset()
    assert error_checker._reports == []


def test_get_data_success(monkeypatch):
    # Simulate network.http_get returning a response with two lines
    class DummyNetResp:
        text = "error123\t0\tError\t0\tHigh\nerror456\t0\tError\t0\tLow"

    monkeypatch.setattr("yawast.shared.network.http_get", lambda url: DummyNetResp())
    error_checker._data = []
    error_checker._get_data()
    assert len(error_checker._data) >= 2


def test_get_data_exception(monkeypatch):
    monkeypatch.setattr(
        "yawast.shared.network.http_get",
        lambda url: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr("yawast.shared.output.debug", lambda msg: None)
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    error_checker._data = []
    error_checker._get_data()
    assert isinstance(error_checker._data, list)
