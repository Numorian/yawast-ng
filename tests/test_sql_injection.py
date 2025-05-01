from unittest.mock import Mock

import pytest

from yawast.reporting.enums import Vulnerabilities
from yawast.reporting.injection import InjectionPoint
from yawast.scanner.modules.http import sql_injection


class DummyResponse:
    def __init__(self, text, status_code=200, request=None):
        self.text = text
        self.status_code = status_code
        self.request = request or Mock()


@pytest.mark.parametrize(
    "db,error,expected_vuln",
    [
        (
            "mysql",
            "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1",
            Vulnerabilities.SQLI_MYSQL_CONFIRMED,
        ),
        (
            "mssql",
            "Unclosed quotation mark after the character string",
            Vulnerabilities.SQLI_MSSQL_CONFIRMED,
        ),
        (
            "oracle",
            "ORA-00933: SQL command not properly ended",
            Vulnerabilities.SQLI_ORACLE_CONFIRMED,
        ),
        (
            "postgres",
            'PostgreSQL ERROR: syntax error at or near "\'"',
            Vulnerabilities.SQLI_POSTGRES_CONFIRMED,
        ),
        ("generic", "syntax error", Vulnerabilities.SQLI_CONFIRMED),
    ],
)
def test_check_injection_confirmed(db, error, expected_vuln, monkeypatch):
    url = "http://test/"
    inj_point = InjectionPoint(url, "q", "GET", "test")
    base_res = DummyResponse("normal page", 200)
    # Patch network.http_get to return a response with the error
    monkeypatch.setattr(
        sql_injection.network,
        "http_get",
        lambda u: DummyResponse(error, 200, request=Mock()),
    )
    results = sql_injection.check_injection(url, base_res, inj_point)
    assert any(r.vulnerability == expected_vuln for r in results)
    assert any(db in r.evidence["db"] for r in results if "db" in r.evidence)
    assert any("Confirmed SQL Injection" in r.message for r in results)


@pytest.mark.parametrize(
    "db,error,expected_vuln",
    [
        ("mysql", "", Vulnerabilities.SQLI_POTENTIAL),
        ("mssql", "", Vulnerabilities.SQLI_POTENTIAL),
        ("oracle", "", Vulnerabilities.SQLI_POTENTIAL),
        ("postgres", "", Vulnerabilities.SQLI_POTENTIAL),
        ("generic", "", Vulnerabilities.SQLI_POTENTIAL),
    ],
)
def test_check_injection_potential(db, error, expected_vuln, monkeypatch):
    url = "http://test/"
    inj_point = InjectionPoint(url, "q", "GET", "test")
    base_res = DummyResponse("normal page", 200)

    # Patch network.http_get to return a response with a different length
    def fake_get(u):
        # Simulate a response with a different length (potential SQLi)
        return DummyResponse("x" * (len(base_res.text) + 200), 200, request=Mock())

    monkeypatch.setattr(sql_injection.network, "http_get", fake_get)
    results = sql_injection.check_injection(url, base_res, inj_point)
    assert any(r.vulnerability == expected_vuln for r in results)
    assert any("Potential SQL Injection" in r.message for r in results)


def test_check_injection_no_issue(monkeypatch):
    url = "http://test/"
    inj_point = InjectionPoint(url, "q", "GET", "test")
    base_res = DummyResponse("normal page", 200)
    # Patch network.http_get to return a normal response
    monkeypatch.setattr(
        sql_injection.network,
        "http_get",
        lambda u: DummyResponse("normal page", 200, request=Mock()),
    )
    results = sql_injection.check_injection(url, base_res, inj_point)
    assert results == []


def test_check_injection_handles_exceptions(monkeypatch):
    url = "http://test/"
    inj_point = InjectionPoint(url, "q", "GET", "test")
    base_res = DummyResponse("normal page", 200)
    # Patch network.http_get to raise an exception
    monkeypatch.setattr(
        sql_injection.network,
        "http_get",
        lambda u: (_ for _ in ()).throw(Exception("fail")),
    )
    results = sql_injection.check_injection(url, base_res, inj_point)
    assert results == []
