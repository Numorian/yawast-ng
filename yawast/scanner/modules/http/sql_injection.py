#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
#  See the LICENSE file for full license details.

import copy
import re
import time
from typing import List

from bs4 import BeautifulSoup
from h11 import Response

from yawast.reporting.enums import Vulnerabilities
from yawast.reporting.evidence import Evidence
from yawast.reporting.injection import InjectionPoint
from yawast.reporting.result import Result
from yawast.scanner.modules.http.helpers import is_unsafe_form, is_unsafe_link
from yawast.shared import network

# Common SQLi payloads and error signatures for different DBs
SQLI_PAYLOADS = [
    "'",
    '"',
    "'--",
    '"--',
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 1=1--",
    '" OR 1=1--',
    "') OR ('1'='1",
    '") OR ("1"="1',
    "' OR 'a'='a",
    '" OR "a"="a',
    "' OR 1=1#",
    '" OR 1=1#',
    "' OR 1=1/*",
    '" OR 1=1/*',
]

ERROR_SIGNATURES = {
    "mysql": [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"mysqli_sql_exception",
        r"You have an error in your SQL syntax",
        r"MariaDB server version",
    ],
    "mssql": [
        r"Unclosed quotation mark after the character string",
        r"Microsoft OLE DB Provider for SQL Server",
        r"Microsoft SQL Native Client",
        r"\[SQL Server\]",
    ],
    "oracle": [
        r"ORA-\d+:",
        r"Oracle error",
        r"quoted string not properly terminated",
    ],
    "postgres": [
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
    ],
    "generic": [
        r"you have an error in your sql syntax;",
        r"syntax error",
        r"sql error",
        r"database error",
        r"unknown column",
        r"ODBC SQL Server Driver",
        r"JDBC Exception",
    ],
}

# Blind SQLi time-based payloads for different DBs
BLIND_SQLI_PAYLOADS = {
    "mysql": ["' OR SLEEP(3)-- ", '" OR SLEEP(3)-- '],
    "mssql": ["' WAITFOR DELAY '0:0:3'-- ", '" WAITFOR DELAY "0:0:3"-- '],
    "oracle": ["' OR 1=1 WAIT 3-- ", '" OR 1=1 WAIT 3-- '],
    "postgres": ["' OR pg_sleep(3)-- ", '" OR pg_sleep(3)-- '],
    "generic": ["' OR 1=1-- ", '" OR 1=1-- '],
}
BLIND_SQLI_DELAY = 2.5  # seconds


def strip_html_tags(text):
    import re

    return re.sub(r"<[^>]+>", "", text)


# Helper to check for error signatures
def detect_sqli_error(text):
    text = strip_html_tags(text)
    for db, sigs in ERROR_SIGNATURES.items():
        for sig in sigs:
            if re.search(sig, text, re.IGNORECASE):
                return db, sig
    return None, None


def _extract_form_params(soup, field, orig_value):
    """Extract all form fields for the relevant form containing the injection field."""
    if soup is not None:
        forms = soup.find_all("form")
        for form in forms:
            inputs = form.find_all("input")
            input_names = [i.get("name") for i in inputs if i.get("name")]
            if field in input_names:
                form_params = {}
                for inp in inputs:
                    name = inp.get("name")
                    if not name:
                        continue
                    # Always include the field, even if value is missing
                    if name == field:
                        form_params[name] = orig_value
                    else:
                        form_params[name] = inp.get("value", "")
                return form_params
    return None


def _build_params_for_request(method, url, field, value, form_params=None):
    """Build the params/query dict for a request, using form_params if available."""
    from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

    parsed = urlparse(url)
    if method == "GET":
        qs = parse_qs(parsed.query)
        if form_params:
            qs = {k: [v] for k, v in form_params.items()}
        qs[field] = [value]
        new_query = urlencode(qs, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        return test_url, None
    elif method == "POST":
        params = form_params.copy() if form_params else {}
        params[field] = value
        return url, params
    return url, None


def _get_vuln_map(blind=False):
    if not blind:
        return {
            "mysql": Vulnerabilities.SQLI_MYSQL_CONFIRMED,
            "mssql": Vulnerabilities.SQLI_MSSQL_CONFIRMED,
            "oracle": Vulnerabilities.SQLI_ORACLE_CONFIRMED,
            "postgres": Vulnerabilities.SQLI_POSTGRES_CONFIRMED,
            "generic": Vulnerabilities.SQLI_CONFIRMED,
        }
    else:
        return {
            "mysql": Vulnerabilities.SQLI_MYSQL_BLIND_CONFIRMED,
            "mssql": Vulnerabilities.SQLI_MSSQL_BLIND_CONFIRMED,
            "oracle": Vulnerabilities.SQLI_ORACLE_BLIND_CONFIRMED,
            "postgres": Vulnerabilities.SQLI_POSTGRES_BLIND_CONFIRMED,
            "generic": Vulnerabilities.SQLI_BLIND_CONFIRMED,
        }


def check_injection(
    url: str, res: Response, injection_point: InjectionPoint, soup: BeautifulSoup
) -> List[Result]:
    """Check for SQL injection vulnerabilities in injection points."""
    # Track tested (page, parameter, method) combinations
    if not hasattr(check_injection, "_tested_combinations"):
        check_injection._tested_combinations = set()
    tested = check_injection._tested_combinations

    # Use the path (not full query) for page uniqueness
    from urllib.parse import urlparse

    parsed = urlparse(url)
    page = parsed.path
    field = injection_point.field
    method = injection_point.method.upper()
    combo = (page, field, method)
    if combo in tested:
        return []
    tested.add(combo)

    results: List[Result] = []

    if res is None:
        return results

    # Check for unrelated SQL error signatures in the base response
    db, sig = detect_sqli_error(res.text)
    if db:
        # Unrelated SQL error found, skip scanning to avoid false positive
        return []

    # Determine method and base params
    method = injection_point.method.upper()
    field = injection_point.field
    orig_value = injection_point.value

    # Skip unsafe forms
    if is_unsafe_form(soup, field):
        return []

    form_params = _extract_form_params(soup, field, orig_value)

    # Try each payload (error-based SQLi)
    found = False
    for payload in SQLI_PAYLOADS:
        if found:
            break
        test_url, params = _build_params_for_request(
            method, url, field, payload, form_params
        )

        if is_unsafe_link(test_url, ""):
            return []

        response = None
        try:
            if method == "GET":
                response = network.http_get(test_url)
            elif method == "POST":
                response = network._requester.post(test_url, data=params)
            else:
                continue
        except Exception:
            continue
        if not response:
            continue
        db, sig = detect_sqli_error(response.text)

        if db:
            vuln_map = _get_vuln_map()
            vuln = vuln_map.get(db, Vulnerabilities.SQLI_CONFIRMED)
            evidence = Evidence(
                test_url,
                str(response.request),
                response.text,
                {"payload": payload, "signature": sig, "db": db},
            )
            results.append(
                Result(
                    f"Confirmed SQL Injection ({db}) at {field} using payload: {payload} on page: {url}",
                    vuln,
                    test_url,
                    evidence,
                )
            )
            found = True
            break
    # Blind SQLi: time-based
    for db, payloads in BLIND_SQLI_PAYLOADS.items():
        for payload in payloads:
            # Baseline
            baseline_url, baseline_params = _build_params_for_request(
                method, url, field, orig_value, form_params
            )
            baseline_response = None
            baseline_time = None
            try:
                start_base = time.time()
                if method == "GET":
                    baseline_response = network.http_get(baseline_url)
                    _ = baseline_response.text
                elif method == "POST":
                    baseline_response = network.http_post(
                        baseline_url, data=baseline_params
                    )
                    _ = baseline_response.text
                else:
                    continue
                baseline_time = time.time() - start_base
            except Exception:
                continue
            # Payload
            test_url, params = _build_params_for_request(
                method, url, field, payload, form_params
            )
            response = None
            start = time.time()
            try:
                if method == "GET":
                    response = network.http_get(test_url)
                    _ = response.text
                elif method == "POST":
                    response = network._requester.post(test_url, data=params)
                    _ = response.text
                else:
                    continue
            except Exception:
                continue
            elapsed = time.time() - start
            if response is None or baseline_time is None:
                continue
            delay_diff = elapsed - baseline_time
            if delay_diff > BLIND_SQLI_DELAY:
                vuln_map = _get_vuln_map(blind=True)
                vuln = vuln_map.get(db, Vulnerabilities.SQLI_BLIND_CONFIRMED)
                evidence = Evidence(
                    test_url,
                    str(response.request),
                    response.text,
                    {
                        "payload": payload,
                        "db": db,
                        "elapsed": elapsed,
                        "baseline": baseline_time,
                        "delay_diff": delay_diff,
                    },
                )
                results.append(
                    Result(
                        f"Confirmed Blind SQL Injection ({db}) at {field} using payload: {payload} on page: {url} (detected by delay)",
                        vuln,
                        test_url,
                        evidence,
                    )
                )
                break
    return results
