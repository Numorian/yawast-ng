import pytest
from h11 import Response

from yawast.reporting.injection import InjectionPoint
from yawast.scanner.modules.http import sql_injection


class DummyResponse:
    def __init__(self, text):
        self.text = text
        self.request = None


def test_injection_point_eq():
    a = InjectionPoint("url1", "field1", "GET", "val1")
    b = InjectionPoint("url1", "field1", "GET", "val1")
    c = InjectionPoint("url2", "field1", "GET", "val1")
    assert a == b
    assert not (a == c)


def test_injection_point_to_dict():
    a = InjectionPoint("url1", "field1", "POST", "val2")
    d = a.to_dict()
    assert d == {"url": "url1", "field": "field1", "method": "POST", "value": "val2"}


def test_sql_injection_skips_on_error_signature(monkeypatch):
    # Simulate a response with a SQL error signature in the base response
    error_text = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    res = DummyResponse(error_text)
    inj_point = InjectionPoint("http://test/?id=1", "id", "GET", "1")
    # Should skip scanning and return no results
    results = sql_injection.check_injection("http://test/?id=1", res, inj_point, None)
    assert results == []


def test_sql_injection_scans_when_no_error_signature(monkeypatch):
    # Simulate a response with no SQL error signature
    res = DummyResponse("Normal page")
    inj_point = InjectionPoint("http://test/?id=1", "id", "GET", "1")

    # Patch network.http_get to simulate a SQLi error on payload
    def fake_get(url):
        class R:
            text = "SQL syntax error MySQL"
            request = None

        return R()

    monkeypatch.setattr("yawast.shared.network.http_get", fake_get)
    # Clear deduplication cache before each test
    if hasattr(sql_injection.check_injection, "_tested_combinations"):
        sql_injection.check_injection._tested_combinations.clear()
    results = sql_injection.check_injection("http://test/?id=1", res, inj_point, None)
    assert any(r.vulnerability for r in results)
