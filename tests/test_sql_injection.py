import time
from unittest.mock import Mock

import pytest

from yawast.reporting.enums import Vulnerabilities
from yawast.reporting.injection import InjectionPoint
from yawast.scanner.modules.http import sql_injection


# Patch response_scanner.check_response to a no-op for all tests that call check_injection
@pytest.fixture(autouse=True)
def patch_check_response(monkeypatch):
    monkeypatch.setattr(
        sql_injection.response_scanner, "check_response", lambda *a, **kw: None
    )


class DummyResponse:
    def __init__(self, text, status_code=200, request=None, delay=0):
        self.text = text
        self.status_code = status_code
        self.request = request or Mock()
        self._delay = delay

    def __getattribute__(self, name):
        if name == "text":
            delay = object.__getattribute__(self, "_delay")
            if delay:
                time.sleep(delay)
        return object.__getattribute__(self, name)


@pytest.fixture(autouse=True)
def clear_check_injection_cache():
    # Clear the static set before each test for isolation
    if hasattr(sql_injection.check_injection, "_tested_combinations"):
        sql_injection.check_injection._tested_combinations.clear()


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
    soup = None
    results = sql_injection.check_injection(url, base_res, inj_point, soup)
    assert any(r.vulnerability == expected_vuln for r in results)
    assert any(db in r.evidence["db"] for r in results if "db" in r.evidence)
    assert any("Confirmed SQL Injection" in r.message for r in results)


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
    soup = None
    results = sql_injection.check_injection(url, base_res, inj_point, soup)
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
    soup = None
    results = sql_injection.check_injection(url, base_res, inj_point, soup)
    assert results == []


@pytest.mark.parametrize(
    "db,payload,expected_vuln,delay",
    [
        ("mysql", "' OR SLEEP(3)-- ", Vulnerabilities.SQLI_MYSQL_BLIND_CONFIRMED, 3),
        (
            "mssql",
            "' WAITFOR DELAY '0:0:3'-- ",
            Vulnerabilities.SQLI_MSSQL_BLIND_CONFIRMED,
            3,
        ),
        (
            "oracle",
            "' OR 1=1 WAIT 3-- ",
            Vulnerabilities.SQLI_ORACLE_BLIND_CONFIRMED,
            3,
        ),
        (
            "postgres",
            "' OR pg_sleep(3)-- ",
            Vulnerabilities.SQLI_POSTGRES_BLIND_CONFIRMED,
            3,
        ),
        ("generic", "' OR 1=1-- ", Vulnerabilities.SQLI_BLIND_CONFIRMED, 3),
    ],
)
def test_blind_sqli_confirmed(monkeypatch, db, payload, expected_vuln, delay):
    url = "http://test/?q=1"  # Use a numeric value to match real-world/DVWA
    inj_point = InjectionPoint(url, "q", "GET", "1")
    base_res = DummyResponse("normal page", 200)

    # Track if this is the baseline or payload request
    call_count = {"count": 0}

    def fake_get(u):
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(u)
        qs = parse_qs(parsed.query)
        call_count["count"] += 1
        if call_count["count"] == 1:
            # Baseline request: no delay
            return DummyResponse("normal page", 200, request=Mock(), delay=0)
        if qs.get("q", [None])[0] == payload:
            return DummyResponse("delayed", 200, request=Mock(), delay=delay)
        return DummyResponse("normal page", 200, request=Mock())

    monkeypatch.setattr(sql_injection.network, "http_get", fake_get)

    def fake_sleep(x):
        t[0] += x

    monkeypatch.setattr(time, "sleep", fake_sleep)
    t = [1000.0]

    def fake_time():
        # Only advance time for the payload request (second call)
        if call_count["count"] == 1:
            return t[0]
        t[0] += delay
        return t[0]

    monkeypatch.setattr(time, "time", fake_time)
    soup = None
    results = sql_injection.check_injection(url, base_res, inj_point, soup)
    assert any(r.vulnerability == expected_vuln for r in results)
    assert any("Blind SQL Injection" in r.message for r in results)


def test_blind_sqli_confirmed_with_extra_param(monkeypatch):
    """
    Test Blind SQLi detection when extra parameters (like Submit=Submit) are present in the URL.
    """
    url = "http://test/?id=1&Submit=Submit"
    inj_point = InjectionPoint(url, "id", "GET", "1")
    base_res = DummyResponse("normal page", 200)
    call_count = {"count": 0}
    payload = "' OR SLEEP(3)-- "
    delay = 3
    expected_vuln = Vulnerabilities.SQLI_MYSQL_BLIND_CONFIRMED

    def fake_get(u):
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(u)
        qs = parse_qs(parsed.query)
        call_count["count"] += 1
        if call_count["count"] == 1:
            # Baseline request: no delay
            return DummyResponse("normal page", 200, request=Mock(), delay=0)
        if (
            qs.get("id", [None])[0] == payload
            and qs.get("Submit", [None])[0] == "Submit"
        ):
            return DummyResponse("delayed", 200, request=Mock(), delay=delay)
        return DummyResponse("normal page", 200, request=Mock())

    monkeypatch.setattr(sql_injection.network, "http_get", fake_get)
    t = [1000.0]

    def fake_sleep(x):
        t[0] += x

    monkeypatch.setattr(time, "sleep", fake_sleep)

    def fake_time():
        if call_count["count"] == 1:
            return t[0]
        t[0] += delay
        return t[0]

    monkeypatch.setattr(time, "time", fake_time)
    soup = None
    results = sql_injection.check_injection(url, base_res, inj_point, soup)
    assert any(r.vulnerability == expected_vuln for r in results)
    assert any("Blind SQL Injection" in r.message for r in results)


def test_nonblind_sqli_confirmed_with_extra_param(monkeypatch):
    """
    Test non-blind SQLi detection when extra parameters (like Submit=Submit) are present in the URL.
    """
    url = "http://test/?id=1&Submit=Submit"
    inj_point = InjectionPoint(url, "id", "GET", "1")
    base_res = DummyResponse("normal page", 200)
    payload = "'"
    expected_vuln = Vulnerabilities.SQLI_MYSQL_CONFIRMED

    def fake_get(u):
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(u)
        qs = parse_qs(parsed.query)
        # Simulate SQL error only if both id and Submit are present
        if (
            qs.get("id", [None])[0] == payload
            and qs.get("Submit", [None])[0] == "Submit"
        ):
            return DummyResponse(
                "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1",
                200,
                request=Mock(),
            )
        return DummyResponse("normal page", 200, request=Mock())

    monkeypatch.setattr(sql_injection.network, "http_get", fake_get)
    soup = None
    results = sql_injection.check_injection(url, base_res, inj_point, soup)
    assert any(r.vulnerability == expected_vuln for r in results)
    assert any("Confirmed SQL Injection" in r.message for r in results)


def test_no_duplicate_checks_for_same_page_param(monkeypatch):
    """
    Ensure that check_injection does not test the same page/param/method more than once.
    """
    # Reset the static set for isolation
    if hasattr(sql_injection.check_injection, "_tested_combinations"):
        sql_injection.check_injection._tested_combinations.clear()
    url1 = "http://test/page.php?doc=readme"
    url2 = "http://test/page.php?doc=copying"
    first_payload = sql_injection.SQLI_PAYLOADS[0]
    inj_point1 = InjectionPoint(url1, "doc", "GET", first_payload)
    inj_point2 = InjectionPoint(url2, "doc", "GET", first_payload)
    base_res = DummyResponse("normal page", 200)
    # Only the first matching payload should trigger a match and break the loop
    called = {"count": 0}

    def fake_get(u):
        from urllib.parse import parse_qs, urlparse

        called["count"] += 1
        parsed = urlparse(u)
        qs = parse_qs(parsed.query)
        val = qs.get("doc", [None])[0]
        # Only match if the payload matches the first payload
        if val == first_payload:
            from yawast.scanner.modules.http.sql_injection import detect_sqli_error

            db, sig = detect_sqli_error(
                "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1"
            )
            return DummyResponse(
                "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1",
                200,
                request=Mock(),
            )
        return DummyResponse("normal page", 200, request=Mock())

    monkeypatch.setattr(sql_injection.network, "http_get", fake_get)
    # First call: should perform the check (first payload triggers match)
    soup = None
    results1 = sql_injection.check_injection(url1, base_res, inj_point1, soup)
    calls_after_first = called["count"]
    # Second call: should be skipped (same page/param/method)
    results2 = sql_injection.check_injection(url2, base_res, inj_point2, soup)
    assert called["count"] == calls_after_first  # No new calls should be made
    assert results1
    assert results2 == []


def test_check_injection_dvwa_mariadb_error(monkeypatch):
    url = "http://localhost:4280/vulnerabilities/sqli/?id=1&Submit=Submit"
    inj_point = InjectionPoint(url, "id", "GET", "1")
    base_res = DummyResponse("normal page", 200)
    dvwa_error = (
        "Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; "
        "check the manual that corresponds to your MariaDB server version for the right syntax to use near ''''' at line 1 "
        "in /var/www/html/vulnerabilities/sqli/source/low.php:11 Stack trace: #0 /var/www/html/vulnerabilities/sqli/source/low.php(11): "
        "mysqli_query(Object(mysqli), 'SELECT first_na...') #1 /var/www/html/vulnerabilities/sqli/index.php(34): require_once('/var/www/html/v...') #2 {main} thrown in /var/www/html/vulnerabilities/sqli/source/low.php on line 11"
    )
    # Patch network.http_get to return a response with the DVWA MariaDB error
    monkeypatch.setattr(
        sql_injection.network,
        "http_get",
        lambda u: DummyResponse(dvwa_error, 200, request=Mock()),
    )
    soup = None
    results = sql_injection.check_injection(url, base_res, inj_point, soup)
    assert any(r.vulnerability == Vulnerabilities.SQLI_MYSQL_CONFIRMED for r in results)
    assert any("Confirmed SQL Injection" in r.message for r in results)


def test_check_injection_preserves_extra_params(monkeypatch):
    url = "http://test/?id=1&Submit=Submit"
    inj_point = InjectionPoint(url, "id", "GET", "1")
    base_res = DummyResponse("normal page", 200)
    called = {"url": None}
    payload = "'"
    expected_url = "http://test/?id=%27&Submit=Submit"

    def fake_get(u):
        called["url"] = u
        # Simulate SQL error for the payload
        if "id=%27" in u and "Submit=Submit" in u:
            return DummyResponse(
                "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1",
                200,
                request=Mock(),
            )
        return DummyResponse("normal page", 200, request=Mock())

    monkeypatch.setattr(sql_injection.network, "http_get", fake_get)
    soup = None
    results = sql_injection.check_injection(url, base_res, inj_point, soup)
    assert any(r.vulnerability == Vulnerabilities.SQLI_MYSQL_CONFIRMED for r in results)
    assert any("Confirmed SQL Injection" in r.message for r in results)
    assert "id=" in called["url"]
    assert "Submit=Submit" in called["url"]


def test_check_injection_preserves_all_params_and_replaces_target(monkeypatch):
    url = "http://test/?id=1&Submit=Submit&foo=bar"
    inj_point = InjectionPoint(url, "id", "GET", "1")
    base_res = DummyResponse("normal page", 200)
    called_urls = []
    payload = "'"

    def fake_get(u):
        called_urls.append(u)
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(u)
        qs = parse_qs(parsed.query)
        # Simulate SQL error only if all params are present and id is replaced
        if (
            qs.get("id", [None])[0] == payload
            and qs.get("Submit", [None])[0] == "Submit"
            and qs.get("foo", [None])[0] == "bar"
        ):
            return DummyResponse(
                "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1",
                200,
                request=Mock(),
            )
        return DummyResponse("normal page", 200, request=Mock())

    monkeypatch.setattr(sql_injection.network, "http_get", fake_get)
    soup = None
    results = sql_injection.check_injection(url, base_res, inj_point, soup)
    assert any(r.vulnerability == Vulnerabilities.SQLI_MYSQL_CONFIRMED for r in results)
    assert any("Confirmed SQL Injection" in r.message for r in results)
    # Confirm all params are present in the called URL
    assert any(
        "id=%27" in u and "Submit=Submit" in u and "foo=bar" in u for u in called_urls
    )


def test_check_injection_uses_form_fields(monkeypatch):
    from bs4 import BeautifulSoup

    url = "http://test/?id=1"
    inj_point = InjectionPoint(url, "id", "GET", "1")
    # Simulate a form with id and Submit fields
    html = """
    <form action="#" method="GET">
        <p>
            User ID:
            <input type="text" size="15" name="id">
            <input type="submit" name="Submit" value="Submit">
        </p>
    </form>
    """
    soup = BeautifulSoup(html, "html.parser")

    class DummyRes:
        def __init__(self):
            self.text = html

    base_res = DummyRes()
    called_urls = []
    payload = "'"

    def fake_get(u):
        called_urls.append(u)
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(u)
        qs = parse_qs(parsed.query)
        # Simulate SQL error only if both id and Submit are present
        if (
            qs.get("id", [None])[0] == payload
            and qs.get("Submit", [None])[0] == "Submit"
        ):
            return DummyResponse(
                "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1",
                200,
                request=Mock(),
            )
        return DummyResponse("normal page", 200, request=Mock())

    monkeypatch.setattr(sql_injection.network, "http_get", fake_get)
    results = sql_injection.check_injection(url, base_res, inj_point, soup)
    assert any(r.vulnerability == Vulnerabilities.SQLI_MYSQL_CONFIRMED for r in results)
    assert any("Confirmed SQL Injection" in r.message for r in results)
    # Confirm all form fields are present in the called URL
    assert any("id=%27" in u and "Submit=Submit" in u for u in called_urls)


def test__extract_form_params_basic():
    from bs4 import BeautifulSoup

    html = """<form action="#" method="GET">
        <input type="text" name="id" value="1">
        <input type="submit" name="Submit" value="Submit">
    </form>"""
    soup = BeautifulSoup(html, "html.parser")

    params = sql_injection._extract_form_params(soup, "id", "testval")
    assert params["id"] == "testval"
    assert params["Submit"] == "Submit"


def test__extract_form_params_includes_all_fields():
    from bs4 import BeautifulSoup

    html = """<form action="#" method="GET">
        <input type="text" name="id">
        <input type="submit" name="Submit" value="Submit">
        <input type="hidden" name="hidden_field">
    </form>"""
    soup = BeautifulSoup(html, "html.parser")
    params = sql_injection._extract_form_params(soup, "id", "testval")
    # All fields should be present, even if value is missing
    assert params["id"] == "testval"
    assert params["Submit"] == "Submit"
    assert params["hidden_field"] == ""


def test__build_params_for_request_get():
    url = "http://test/?id=1&Submit=Submit"
    method = "GET"
    field = "id"
    value = "'"
    form_params = {"id": "'", "Submit": "Submit"}
    test_url, params = sql_injection._build_params_for_request(
        method, url, field, value, form_params
    )
    assert "id=%27" in test_url
    assert "Submit=Submit" in test_url
    assert params is None


def test__build_params_for_request_post():
    url = "http://test/"
    method = "POST"
    field = "id"
    value = "'"
    form_params = {"id": "'", "Submit": "Submit"}
    test_url, params = sql_injection._build_params_for_request(
        method, url, field, value, form_params
    )
    assert test_url == url
    assert params["id"] == "'"
    assert params["Submit"] == "Submit"


def test__get_vuln_map():
    m = sql_injection._get_vuln_map()
    assert m["mysql"] == sql_injection.Vulnerabilities.SQLI_MYSQL_CONFIRMED
    m2 = sql_injection._get_vuln_map(blind=True)
    assert m2["mysql"] == sql_injection.Vulnerabilities.SQLI_MYSQL_BLIND_CONFIRMED


def test_sql_injection_skips_on_error_signature(monkeypatch):
    # Simulate a response with a SQL error signature in the base response
    error_text = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    res = DummyResponse(error_text)
    inj_point = InjectionPoint("http://test/?id=1", "id", "GET", "1")
    # Should skip scanning and return no results
    results = sql_injection.check_injection("http://test/?id=1", res, inj_point, None)
    assert results == []


def test_sql_injection_scans_when_no_error_signature(monkeypatch):
    # Simulate a response with no SQL error signature in the base response
    res = DummyResponse("Normal page")
    inj_point = InjectionPoint("http://test/?id=1", "id", "GET", "1")

    # Patch network.http_get to simulate a SQLi error on payloads
    def fake_get(url):
        # Return a SQL error only if the payload is present in the URL
        if url != "http://test/?id=1":

            class R:
                text = "SQL syntax error MySQL"
                request = None

            return R()
        else:

            class R:
                text = "Normal page"
                request = None

            return R()

    monkeypatch.setattr("yawast.shared.network.http_get", fake_get)
    # Clear deduplication cache before each test
    if hasattr(sql_injection.check_injection, "_tested_combinations"):
        sql_injection.check_injection._tested_combinations.clear()
    results = sql_injection.check_injection("http://test/?id=1", res, inj_point, None)
    assert any(r.vulnerability for r in results)
