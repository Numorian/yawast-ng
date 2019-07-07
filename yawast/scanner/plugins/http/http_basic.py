import socket
from http.client import HTTPResponse
from typing import List, Dict, Union, Tuple, Any
from urllib.parse import urlparse

from nassl.ssl_client import OpenSslVersionEnum
from requests.models import Response
from sslyze import server_connectivity_tester
from sslyze.utils import ssl_connection_configurator, http_response_parser
from sslyze.utils.ssl_connection import SslConnection

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.evidence import Evidence
from yawast.scanner.plugins.http import response_scanner
from yawast.scanner.plugins.http.servers import apache_httpd, php, iis, nginx, python
from yawast.scanner.plugins.result import Result
from yawast.scanner.session import Session
from yawast.shared import network, utils, output

_checked_cookies: Dict[Vulnerabilities, List[str]] = {}


def reset():
    global _checked_cookies

    _checked_cookies = {}


def get_header_issues(res: Response, raw: str, url: str) -> List[Result]:
    results: List[Result] = []

    try:
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
            if "0" in headers["X-XSS-Protection"]:
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
    except Exception:
        output.debug_exception()

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
                Result.from_evidence(
                    Evidence.from_response(res),
                    "Possible Info Disclosure: PROPFIND Enabled",
                    Vulnerabilities.HTTP_PROPFIND_ENABLED,
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
            Result.from_evidence(
                Evidence.from_response(res),
                "HTTP TRACE Enabled",
                Vulnerabilities.HTTP_TRACE_ENABLED,
            )
        )

    results += response_scanner.check_response(url, res)

    return results


def check_options(url: str) -> List[Result]:
    results: List[Result] = []

    res = network.http_options(url)

    if "Allow" in res.headers:
        results.append(
            Result.from_evidence(
                Evidence.from_response(res),
                f"Allow HTTP Verbs (OPTIONS): {res.headers['Allow']}",
                Vulnerabilities.HTTP_OPTIONS_ALLOW,
            )
        )

    if "Public" in res.headers:
        results.append(
            Result.from_evidence(
                Evidence.from_response(res),
                f"Public HTTP Verbs (OPTIONS): {res.headers['Public']}",
                Vulnerabilities.HTTP_OPTIONS_PUBLIC,
            )
        )

    results += response_scanner.check_response(url, res)

    return results


def check_local_ip_disclosure(session: Session) -> List[Result]:
    def _send_http_10_get(
        con: Union[SslConnection, socket.socket]
    ) -> Tuple[str, HTTPResponse]:
        req = (
            "HEAD / HTTP/1.0\r\n"
            "User-Agent: {user_agent}\r\n"
            "Accept: */*\r\n\r\n".format(user_agent=network.YAWAST_UA)
        )

        if type(con) is SslConnection:
            con.ssl_client.write(req.encode("utf_8"))

            res = http_response_parser.HttpResponseParser.parse_from_ssl_connection(
                con.ssl_client
            )
        else:
            con.sendall(req.encode("utf_8"))

            res = http_response_parser.HttpResponseParser.parse_from_socket(con)

        return req, res

    def _resp_to_str(res: HTTPResponse) -> str:
        ver = "1.1" if res.version == 11 else "1.0"
        body = f"HTTP/{ver} {res.code} {res.reason}\r\n"
        for k, v in res.headers.items():
            body += f"{k}: {v}\r\n"

        return body

    def _get_ip(res: HTTPResponse) -> Union[str, None]:
        loc = res.getheader("Location")
        if loc is not None:
            # it's a redirect, check to see if there's an IP in it
            parsed = urlparse(loc)
            domain = utils.get_domain(parsed.netloc)

            if utils.is_ip(domain):
                # it's an IP, now, is it private?
                if utils.is_private_ip(domain):
                    return domain
                else:
                    return None

        return None

    def _get_result(client, prt):
        req, resp = _send_http_10_get(client)
        ip = _get_ip(resp)

        if ip is not None:
            results.append(
                Result(
                    f"Private IP Found: {ip} via HTTP 1.0 Redirect",
                    Vulnerabilities.SERVER_INT_IP_EXP_HTTP10,
                    session.url,
                    {
                        "request": req,
                        "response": _resp_to_str(resp),
                        "ip": {ip},
                        "port": prt,
                    },
                )
            )

    results: List[Result] = []

    if session.url_parsed.scheme == "https":
        conn_tester = server_connectivity_tester.ServerConnectivityTester(
            hostname=session.domain, port=utils.get_port(session.url)
        )

        server_info = conn_tester.perform()

        conn = ssl_connection_configurator.SslConnectionConfigurator.get_connection(
            ssl_version=OpenSslVersionEnum.SSLV23,
            server_info=server_info,
            should_ignore_client_auth=True,
            ssl_verify_locations=None,
            should_use_legacy_openssl=False,
        )

        conn.connect()

        try:
            _get_result(conn, utils.get_port(session.url))
        except Exception:
            output.debug_exception()

    if session.supports_http:
        url = session.get_http_url()
        port = utils.get_port(url)
        conn = socket.socket()
        conn.connect((utils.get_domain(url), port))

        try:
            _get_result(conn, port)
        except Exception:
            output.debug_exception()

    return results


def get_cookie_issues(res: Response, url: str) -> List[Result]:
    if "Set-Cookie" in res.headers:
        cookies = res.raw.headers.getlist("Set-Cookie")

        return _get_cookie_issues(cookies, url, res)
    else:
        return []


def _get_cookie_issues(cookies: List[str], url: str, res: Response) -> List[Result]:
    global _checked_cookies

    # setup the checked list
    if Vulnerabilities.COOKIE_MISSING_SECURE_FLAG not in _checked_cookies:
        _checked_cookies[Vulnerabilities.COOKIE_MISSING_SECURE_FLAG] = []
    if Vulnerabilities.COOKIE_INVALID_SECURE_FLAG not in _checked_cookies:
        _checked_cookies[Vulnerabilities.COOKIE_INVALID_SECURE_FLAG] = []
    if Vulnerabilities.COOKIE_MISSING_HTTPONLY_FLAG not in _checked_cookies:
        _checked_cookies[Vulnerabilities.COOKIE_MISSING_HTTPONLY_FLAG] = []
    if Vulnerabilities.COOKIE_MISSING_SAMESITE_FLAG not in _checked_cookies:
        _checked_cookies[Vulnerabilities.COOKIE_MISSING_SAMESITE_FLAG] = []
    if Vulnerabilities.COOKIE_WITH_SAMESITE_NONE_FLAG not in _checked_cookies:
        _checked_cookies[Vulnerabilities.COOKIE_WITH_SAMESITE_NONE_FLAG] = []
    if Vulnerabilities.COOKIE_INVALID_SAMESITE_NONE_FLAG not in _checked_cookies:
        _checked_cookies[Vulnerabilities.COOKIE_INVALID_SAMESITE_NONE_FLAG] = []

    results: List[Result] = []

    try:
        parsed = urlparse(url)

        for cookie in cookies:
            comp = cookie.split(";")

            # get the name
            name = comp[0].split("=")[0]

            # normalize the components
            comp = list(map(str.strip, comp))
            comp = list(map(str.lower, comp))

            # check Secure flag
            if "secure" not in comp and parsed.scheme == "https":
                if (
                    name
                    not in _checked_cookies[Vulnerabilities.COOKIE_MISSING_SECURE_FLAG]
                ):
                    results.append(
                        Result.from_evidence(
                            Evidence.from_response(res, {"cookie": name}),
                            f"Cookie Missing Secure Flag: {cookie}",
                            Vulnerabilities.COOKIE_MISSING_SECURE_FLAG,
                        )
                    )

                    _checked_cookies[Vulnerabilities.COOKIE_MISSING_SECURE_FLAG].append(
                        name
                    )
            elif "secure" in comp and parsed.scheme == "http":
                # secure flag over HTTP is invalid
                if (
                    name
                    not in _checked_cookies[Vulnerabilities.COOKIE_INVALID_SECURE_FLAG]
                ):
                    results.append(
                        Result.from_evidence(
                            Evidence.from_response(res, {"cookie": name}),
                            f"Cookie Secure Flag Invalid (over HTTP): {cookie}",
                            Vulnerabilities.COOKIE_INVALID_SECURE_FLAG,
                        )
                    )

                    _checked_cookies[Vulnerabilities.COOKIE_INVALID_SECURE_FLAG].append(
                        name
                    )

            # check HttpOnly flag
            if "httponly" not in comp:
                if (
                    name
                    not in _checked_cookies[
                        Vulnerabilities.COOKIE_MISSING_HTTPONLY_FLAG
                    ]
                ):
                    results.append(
                        Result.from_evidence(
                            Evidence.from_response(res, {"cookie": name}),
                            f"Cookie Missing HttpOnly Flag: {cookie}",
                            Vulnerabilities.COOKIE_MISSING_HTTPONLY_FLAG,
                        )
                    )

                    _checked_cookies[
                        Vulnerabilities.COOKIE_MISSING_HTTPONLY_FLAG
                    ].append(name)

            # check SameSite flag
            if (
                "samesite=lax" not in comp
                and "samesite=strict" not in comp
                and "samesite=none" not in comp
            ):
                if (
                    name
                    not in _checked_cookies[
                        Vulnerabilities.COOKIE_MISSING_SAMESITE_FLAG
                    ]
                ):
                    results.append(
                        Result.from_evidence(
                            Evidence.from_response(res, {"cookie": name}),
                            f"Cookie Missing SameSite Flag: {cookie}",
                            Vulnerabilities.COOKIE_MISSING_SAMESITE_FLAG,
                        )
                    )

                    _checked_cookies[
                        Vulnerabilities.COOKIE_MISSING_SAMESITE_FLAG
                    ].append(name)

            # check SameSite=None flag
            if "samesite=none" in comp:
                if "secure" in comp:
                    if (
                        name
                        not in _checked_cookies[
                            Vulnerabilities.COOKIE_WITH_SAMESITE_NONE_FLAG
                        ]
                    ):
                        results.append(
                            Result.from_evidence(
                                Evidence.from_response(res, {"cookie": name}),
                                f"Cookie With SameSite=None Flag: {cookie}",
                                Vulnerabilities.COOKIE_WITH_SAMESITE_NONE_FLAG,
                            )
                        )

                        _checked_cookies[
                            Vulnerabilities.COOKIE_WITH_SAMESITE_NONE_FLAG
                        ].append(name)
                else:
                    if (
                        name
                        not in _checked_cookies[
                            Vulnerabilities.COOKIE_INVALID_SAMESITE_NONE_FLAG
                        ]
                    ):
                        results.append(
                            Result.from_evidence(
                                Evidence.from_response(res, {"cookie": name}),
                                f"Cookie SameSite=None Flag Invalid (without Secure flag): {cookie}",
                                Vulnerabilities.COOKIE_INVALID_SAMESITE_NONE_FLAG,
                            )
                        )

                        _checked_cookies[
                            Vulnerabilities.COOKIE_INVALID_SAMESITE_NONE_FLAG
                        ].append(name)
    except Exception:
        output.debug_exception()

    return results
