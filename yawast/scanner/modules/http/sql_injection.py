#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
#  See the LICENSE file for full license details.

import copy
import re
from typing import List

from h11 import Response

from yawast.reporting.enums import Vulnerabilities
from yawast.reporting.evidence import Evidence
from yawast.reporting.injection import InjectionPoint
from yawast.reporting.result import Result
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

# Helper to check for error signatures


def detect_sqli_error(text):
    for db, sigs in ERROR_SIGNATURES.items():
        for sig in sigs:
            if re.search(sig, text, re.IGNORECASE):
                return db, sig
    return None, None


def check_injection(
    url: str, res: Response, injection_point: InjectionPoint
) -> List[Result]:
    """Check for SQL injection vulnerabilities in injection points."""
    results: List[Result] = []

    if res is None:
        return results

    # Determine method and base params
    method = injection_point.method.upper()
    field = injection_point.field
    orig_value = injection_point.value

    # Try each payload
    for payload in SQLI_PAYLOADS:
        test_value = orig_value + payload
        params = {field: test_value}
        test_url = url
        response = None
        try:
            if method == "GET":
                # Replace param in query string
                from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                qs[field] = [test_value]
                new_query = urlencode(qs, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                response = network.http_get(test_url)
            elif method == "POST":
                response = network._requester.post(url, data=params)
            else:
                continue
        except Exception as ex:
            continue
        if not response:
            continue
        # Check for SQL error signatures
        db, sig = detect_sqli_error(response.text)
        if db:
            # Confirmed SQLi for this DB
            vuln_map = {
                "mysql": Vulnerabilities.SQLI_MYSQL_CONFIRMED,
                "mssql": Vulnerabilities.SQLI_MSSQL_CONFIRMED,
                "oracle": Vulnerabilities.SQLI_ORACLE_CONFIRMED,
                "postgres": Vulnerabilities.SQLI_POSTGRES_CONFIRMED,
                "generic": Vulnerabilities.SQLI_CONFIRMED,
            }
            vuln = vuln_map.get(db, Vulnerabilities.SQLI_CONFIRMED)
            evidence = Evidence(
                test_url,
                str(response.request),
                response.text,
                {"payload": payload, "signature": sig, "db": db},
            )
            results.append(
                Result(
                    f"Confirmed SQL Injection ({db}) at {field} using payload: {payload}",
                    vuln,
                    test_url,
                    evidence,
                )
            )
        else:
            # Heuristic: if response length or status code changes significantly, flag as potential
            if (
                abs(len(response.text) - len(res.text)) > 100
                or response.status_code != res.status_code
            ):
                # Try to guess DB for potential
                vuln_map = {
                    "mysql": Vulnerabilities.SQLI_MYSQL_POTENTIAL,
                    "mssql": Vulnerabilities.SQLI_MSSQL_POTENTIAL,
                    "oracle": Vulnerabilities.SQLI_ORACLE_POTENTIAL,
                    "postgres": Vulnerabilities.SQLI_POSTGRES_POTENTIAL,
                    "generic": Vulnerabilities.SQLI_POTENTIAL,
                }
                # Try to guess DB by error message in original response
                db, _ = detect_sqli_error(res.text)
                vuln = vuln_map.get(db, Vulnerabilities.SQLI_POTENTIAL)
                evidence = Evidence(
                    test_url,
                    str(response.request),
                    response.text,
                    {"payload": payload, "note": "Response changed significantly"},
                )
                results.append(
                    Result(
                        f"Potential SQL Injection at {field} using payload: {payload}",
                        vuln,
                        test_url,
                        evidence,
                    )
                )
    return results
