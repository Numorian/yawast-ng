from typing import List, Dict
from requests.models import Response
from urllib.parse import urlparse

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.evidence import Evidence
from yawast.scanner.plugins.http import response_scanner
from yawast.scanner.plugins.result import Result
from yawast.scanner.plugins.http.servers import apache_httpd, php, iis, nginx, python
from yawast.shared import network


def get_header_issues(res: Response, raw: str, url: str) -> List[Result]:
    results: List[Result] = []
    headers = res.headers

    if "X-Powered-By" in headers:
        results.append(
            Result.from_evidence(
                Evidence.from_response(res),
                f'X-Powered-By Header Present: {headers["X-Powered-By"]} ({url})',
                Vulnerabilities.HTTP_HEADER_X_POWERED_BY,
            )
        )

        # check to see if this is a php version
        results += php.check_version(headers["X-Powered-By"], raw, url)

    if "X-XSS-Protection" in headers:
        # header is present, check the value
        if headers["X-XSS-Protection"] == 0:
            results.append(
                Result.from_evidence(
                    Evidence.from_response(res),
                    f"X-XSS-Protection Disabled Header Present ({url})",
                    Vulnerabilities.HTTP_HEADER_X_XSS_PROTECTION_DISABLED,
                )
            )
    else:
        results.append(
            Result.from_evidence(
                Evidence.from_response(res),
                f"X-XSS-Protection Header Not Present ({url})",
                Vulnerabilities.HTTP_HEADER_X_XSS_PROTECTION_MISSING,
            )
        )

    if "X-Runtime" in headers:
        results.append(
            Result.from_evidence(
                Evidence.from_response(res),
                f"X-Runtime Header Present; likely indicates a RoR application ({url})",
                Vulnerabilities.HTTP_HEADER_X_RUNTIME,
            )
        )

    if "X-Backend-Server" in headers:
        results.append(
            Result.from_evidence(
                Evidence.from_response(res),
                f'X-Backend-Server Header Present: {headers["X-Backend-Server"]} ({url})',
                Vulnerabilities.HTTP_HEADER_X_BACKEND_SERVER,
            )
        )

    if "Via" in headers:
        results.append(
            Result.from_evidence(
                Evidence.from_response(res),
                f'Via Header Present: #{headers["Via"]} ({url})',
                Vulnerabilities.HTTP_HEADER_VIA,
            )
        )

    if "X-Frame-Options" in headers:
        if "allow" in str(headers["X-Frame-Options"]).lower():
            results.append(
                Result.from_evidence(
                    Evidence.from_response(res),
                    f'X-Frame-Options Header: {headers["X-Frame-Options"]} ({url})',
                    Vulnerabilities.HTTP_HEADER_X_FRAME_OPTIONS_ALLOW,
                )
            )
    else:
        results.append(
            Result.from_evidence(
                Evidence.from_response(res),
                f"X-Frame-Options Header Not Present ({url})",
                Vulnerabilities.HTTP_HEADER_X_FRAME_OPTIONS_MISSING,
            )
        )

    if "X-Content-Type-Options" not in headers:
        results.append(
            Result.from_evidence(
                Evidence.from_response(res),
                f"X-Content-Type-Options Header Not Present ({url})",
                Vulnerabilities.HTTP_HEADER_X_CONTENT_TYPE_OPTIONS_MISSING,
            )
        )

    if "Content-Security-Policy" not in headers:
        results.append(
            Result.from_evidence(
                Evidence.from_response(res),
                f"Content-Security-Policy Header Not Present ({url})",
                Vulnerabilities.HTTP_HEADER_CONTENT_SECURITY_POLICY_MISSING,
            )
        )

    if "Referrer-Policy" not in headers:
        results.append(
            Result.from_evidence(
                Evidence.from_response(res),
                f"Referrer-Policy Header Not Present ({url})",
                Vulnerabilities.HTTP_HEADER_REFERRER_POLICY_MISSING,
            )
        )

    if "Feature-Policy" not in headers:
        results.append(
            Result.from_evidence(
                Evidence.from_response(res),
                f"Feature-Policy Header Not Present ({url})",
                Vulnerabilities.HTTP_HEADER_FEATURE_POLICY_MISSING,
            )
        )

    if "Access-Control-Allow-Origin" in headers:
        if headers["Access-Control-Allow-Origin"] == "*":
            results.append(
                Result.from_evidence(
                    Evidence.from_response(res),
                    f"Access-Control-Allow-Origin: Unrestricted ({url})",
                    Vulnerabilities.HTTP_HEADER_CORS_ACAO_UNRESTRICTED,
                )
            )

    if "Strict-Transport-Security" not in headers:
        results.append(
            Result.from_evidence(
                Evidence.from_response(res),
                f"Strict-Transport-Security Header Not Present ({url})",
                Vulnerabilities.HTTP_HEADER_HSTS_MISSING,
            )
        )

    if "Server" in headers:
        results += get_server_banner_issues(headers["Server"], raw, url, headers)

    return results


def get_server_banner_issues(
    server: str, raw: str, url: str, headers: Dict
) -> List[Result]:
    results: List[Result] = []

    results += apache_httpd.check_banner(server, raw, url)
    results += nginx.check_banner(server, raw, url)
    results += iis.check_version(server, raw, url, headers)
    results += python.check_banner(server, raw, url)

    return results


def check_propfind(url: str) -> List[Result]:
    results: List[Result] = []

    res = network.http_custom("PROPFIND", url)
    body = res.text

    if res.status_code <= 400 and len(body) > 0:
        if "Content-Type" in res.headers and "text/xml" in res.headers["Content-Type"]:
            results.append(
                Result(
                    "Possible Info Disclosure: PROPFIND Enabled",
                    Vulnerabilities.HTTP_PROPFIND_ENABLED,
                    url,
                    [
                        network.http_build_raw_request(res.request),
                        network.http_build_raw_response(res),
                    ],
                )
            )

    results += response_scanner.check_response(url, res)

    return results


def check_trace(url: str) -> List[Result]:
    results: List[Result] = []

    res = network.http_custom("TRACE", url)
    body = res.text

    if res.status_code == 200 and "TRACE / HTTP/1.1" in body:
        results.append(
            Result(
                "HTTP TRACE Enabled",
                Vulnerabilities.HTTP_TRACE_ENABLED,
                url,
                [
                    network.http_build_raw_request(res.request),
                    network.http_build_raw_response(res),
                ],
            )
        )

    results += response_scanner.check_response(url, res)

    return results


def check_options(url: str) -> List[Result]:
    results: List[Result] = []

    res = network.http_options(url)

    if "Allow" in res.headers:
        results.append(
            Result(
                f"Allow HTTP Verbs (OPTIONS): {res.headers['Allow']}",
                Vulnerabilities.HTTP_OPTIONS_ALLOW,
                url,
                [
                    network.http_build_raw_request(res.request),
                    network.http_build_raw_response(res),
                ],
            )
        )

    if "Public" in res.headers:
        results.append(
            Result(
                f"Public HTTP Verbs (OPTIONS): {res.headers['Public']}",
                Vulnerabilities.HTTP_OPTIONS_PUBLIC,
                url,
                [
                    network.http_build_raw_request(res.request),
                    network.http_build_raw_response(res),
                ],
            )
        )

    results += response_scanner.check_response(url, res)

    return results


def get_cookie_issues(res: Response, raw: str, url: str) -> List[Result]:
    if "Set-Cookie" in res.headers:
        cookies = res.raw.headers.getlist("Set-Cookie")

        return _get_cookie_issues(cookies, raw, url)
    else:
        return []


def _get_cookie_issues(cookies: List[str], raw: str, url: str) -> List[Result]:
    results: List[Result] = []
    parsed = urlparse(url)

    for cookie in cookies:
        comp = cookie.split(";")

        # get the name
        name = comp[0].split("=")[0]

        # normalize the components
        comp = list(map(str.strip, comp))
        comp = list(map(str.lower, comp))

        # check Secure flag
        if "secure" not in comp:
            if parsed.scheme == "https":
                results.append(
                    Result(
                        f"Cookie Missing Secure Flag: {cookie}",
                        Vulnerabilities.COOKIE_MISSING_SECURE_FLAG,
                        url,
                        [name, raw],
                    )
                )
            else:
                # secure flag over HTTP is invalid
                if "secure" in comp:
                    results.append(
                        Result(
                            f"Cookie Secure Flag Invalid (over HTTP): {cookie}",
                            Vulnerabilities.COOKIE_INVALID_SECURE_FLAG,
                            url,
                            [name, raw],
                        )
                    )

        # check HttpOnly flag
        if "httponly" not in comp:
            results.append(
                Result(
                    f"Cookie Missing HttpOnly Flag: {cookie}",
                    Vulnerabilities.COOKIE_MISSING_HTTPONLY_FLAG,
                    url,
                    [name, raw],
                )
            )

        # check SameSite flag
        if (
            "samesite=lax" not in comp
            and "samesite=strict" not in comp
            and "samesite=none" not in comp
        ):
            results.append(
                Result(
                    f"Cookie Missing SameSite Flag: {cookie}",
                    Vulnerabilities.COOKIE_MISSING_SAMESITE_FLAG,
                    url,
                    [name, raw],
                )
            )

        # check SameSite=None flag
        if "samesite=none" in comp:
            if "secure" in comp:
                results.append(
                    Result(
                        f"Cookie With SameSite=None Flag: {cookie}",
                        Vulnerabilities.COOKIE_WITH_SAMESITE_NONE_FLAG,
                        url,
                        [name, raw],
                    )
                )
            else:
                results.append(
                    Result(
                        f"Cookie SameSite=None Flag Invalid (without Secure flag): {cookie}",
                        Vulnerabilities.COOKIE_INVALID_SAMESITE_NONE_FLAG,
                        url,
                        [name, raw],
                    )
                )

    return results
