#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
#  See the LICENSE file for full license details.

from typing import List

from bs4 import BeautifulSoup
from h11 import Response

from yawast.reporting.enums import Vulnerabilities
from yawast.reporting.injection import InjectionPoint
from yawast.reporting.result import Result
from yawast.scanner.modules.http import response_scanner
from yawast.scanner.modules.http.helpers import is_unsafe_form, is_unsafe_link
from yawast.shared import network

COMMAND_PAYLOADS = [
    ";id",  # Unix
    "|id",
    "&id",
    "||id",
    "|whoami",
    "&whoami",
    "|cat /etc/passwd",
    "&cat /etc/passwd",
    "|type C:\\Windows\\win.ini",  # Windows
    "&type C:\\Windows\\win.ini",
    "|ping -c 1 127.0.0.1",
    "&ping -c 1 127.0.0.1",
]


def _extract_form_params(soup, field, orig_value):
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
                    if name == field:
                        form_params[name] = orig_value
                    else:
                        form_params[name] = inp.get("value", "")
                return form_params
    return None


def _build_params_for_request(method, url, field, value, form_params=None):
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


def check_injection(
    url: str, res: Response, injection_point: InjectionPoint, soup: BeautifulSoup
) -> List[Result]:
    """
    Checks for command injection by injecting payloads and looking for OS command output in the response.
    """
    if not hasattr(check_injection, "_tested_combinations"):
        check_injection._tested_combinations = set()
    tested = check_injection._tested_combinations

    from urllib.parse import urlparse

    results = []
    orig_value = injection_point.value
    method = injection_point.method.upper()
    field = injection_point.field

    parsed = urlparse(url)
    page = parsed.path
    combo = (page, field, method)
    if combo in tested:
        return []
    tested.add(combo)

    if is_unsafe_form(soup, field):
        return []
    form_params = _extract_form_params(soup, field, orig_value)

    for payload in COMMAND_PAYLOADS:
        test_url, params = _build_params_for_request(
            method, url, field, payload, form_params
        )
        if is_unsafe_link(test_url, ""):
            return []
        try:
            if method == "GET":
                resp = network.http_get(test_url)
                response_scanner.check_response(test_url, resp, soup, False)
            elif method == "POST":
                resp = network.http_post(test_url, data=params)
                response_scanner.check_response(test_url, resp, soup, False)
            else:
                continue
        except Exception:
            continue

        # High-confidence command execution markers
        found = False
        marker = None
        # Check for both 'uid=' and 'gid=' on the same line (id output)
        for line in resp.text.splitlines():
            if "uid=" in line and "gid=" in line:
                marker = line.strip()
                found = True
                break
        # Check for /etc/passwd root entry
        if not found and "root:x:0:0:" in resp.text:
            marker = "root:x:0:0:"
            found = True
        # Check for Windows win.ini markers
        if not found and (
            "[extensions]" in resp.text or "for 16-bit app support" in resp.text
        ):
            marker = (
                "[extensions]"
                if "[extensions]" in resp.text
                else "for 16-bit app support"
            )
            found = True
        # Check for Microsoft Windows (only if not present in normal responses, but here we assume it's rare)
        if not found and "Microsoft Windows" in resp.text:
            marker = "Microsoft Windows"
            found = True
        # Check for Linux or Darwin kernel version (very rare in normal output)
        if not found and (
            "Linux version" in resp.text or "Darwin Kernel Version" in resp.text
        ):
            marker = (
                "Linux version"
                if "Linux version" in resp.text
                else "Darwin Kernel Version"
            )
            found = True

        # Check that the marker was not present in the original response (res)
        if (
            found
            and marker is not None
            and res is not None
            and marker in getattr(res, "text", "")
        ):
            found = False  # Marker was already present before injection, so skip

        if found:
            results.append(
                Result(
                    f"Command Injection confirmed with payload: {payload} on page: {url}",
                    Vulnerabilities.COMMAND_EXECUTION_CONFIRMED,
                    test_url,
                    {"payload": payload, "url": test_url, "reflected": True},
                )
            )
            break
    return results
