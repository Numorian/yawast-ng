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

XSS_PAYLOADS = [
    "<script>alert(1337)</script>",
    '"onmouseover=alert(1) x="',
    "'><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]


# Helper: Extract all form fields for the relevant form containing the injection field
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


# Helper: Build the params/query dict for a request, using form_params if available
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


def _detect_dom_xss(html: str) -> bool:
    """
    Detects possible DOM-based XSS by searching for dangerous JavaScript patterns
    where user-controllable sources are assigned to dangerous sinks.
    """
    import re

    # Common sources and sinks for DOM XSS
    sources = [
        r"location(?:\.hash|\.search|\.pathname|\.href)?",
        r"document\.URL",
        r"document\.documentURI",
        r"document\.referrer",
        r"window\.name",
        r"localStorage",
        r"sessionStorage",
        r"cookie",
    ]
    sinks = [
        r"innerHTML",
        r"outerHTML",
        r"document\.write",
        r"document\.writeln",
        r"eval",
        r"setTimeout",
        r"setInterval",
        r"Function",
    ]
    # Regex to find script blocks
    script_blocks = re.findall(
        r"<script.*?>(.*?)</script>", html, re.DOTALL | re.IGNORECASE
    )
    for script in script_blocks:
        # Track variable assignments from sources
        var_sources = {}
        lines = script.split("\n")
        for line in lines:
            # var foo = location.hash; or foo = location.hash;
            for source in sources:
                m = re.search(rf"(?:var|let|const)?\s*(\w+)\s*=\s*{source}", line)
                if m:
                    var_sources[m.group(1)] = source
        for line in lines:
            for sink in sinks:
                # direct assignment: sink = source
                for source in sources:
                    if re.search(rf"{sink}\s*=\s*.*{source}", line):
                        return True
                # variable propagation: sink = var (where var was set from a source)
                m = re.search(rf"{sink}\s*=\s*(\w+)", line)
                if m and m.group(1) in var_sources:
                    return True
                # function call: sink(var) or sink(source)
                if re.search(rf"{sink}\s*\((.*?)\)", line):
                    args = re.findall(rf"{sink}\s*\((.*?)\)", line)
                    for arg in args:
                        # arg is a comma-separated list
                        for a in arg.split(","):
                            a = a.strip()
                            if a in var_sources or any(
                                re.search(source, a) for source in sources
                            ):
                                return True
    return False


def check_injection(
    url: str, res: Response, injection_point: InjectionPoint, soup: BeautifulSoup
) -> List[Result]:
    """
    Checks for reflected XSS by injecting payloads and looking for them in the response.
    """
    # Track tested (page, parameter, method) combinations
    if not hasattr(check_injection, "_tested_combinations"):
        check_injection._tested_combinations = set()
    tested = check_injection._tested_combinations

    from urllib.parse import urlparse

    results = []
    orig_value = injection_point.value
    method = injection_point.method.upper()
    field = injection_point.field

    # Use the path (not full query) for page uniqueness
    parsed = urlparse(url)
    page = parsed.path
    combo = (page, field, method)
    if combo in tested:
        return []
    tested.add(combo)

    # Skip unsafe forms
    if is_unsafe_form(soup, field):
        return []
    form_params = _extract_form_params(soup, field, orig_value)

    for payload in XSS_PAYLOADS:
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

        if payload in resp.text:
            results.append(
                Result(
                    f"Reflected XSS confirmed with payload: {payload} on page: {url}",
                    Vulnerabilities.XSS_REFLECTED,
                    test_url,
                    {"payload": payload, "url": test_url, "reflected": True},
                )
            )
            break  # Stop scanning after the first positive result
        # DOM-based XSS detection
        if _detect_dom_xss(resp.text):
            results.append(
                Result(
                    f"DOM-based XSS pattern detected in JavaScript on page: {url}",
                    Vulnerabilities.XSS_DOM,
                    test_url,
                    {"payload": payload, "url": test_url, "dom_xss": True},
                )
            )
            break
    return results
