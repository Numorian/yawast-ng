from typing import List

from bs4 import BeautifulSoup
from h11 import Response

from yawast.reporting.enums import Vulnerabilities
from yawast.reporting.evidence import Evidence
from yawast.reporting.injection import InjectionPoint
from yawast.reporting.result import Result
from yawast.scanner.modules.http import response_scanner
from yawast.scanner.modules.http.helpers import is_unsafe_form, is_unsafe_link
from yawast.shared import network

OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "http://evil.com",
    "https://evil.com",
    "/\\evil.com",
    "//attacker.com/path",
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


def check_injection(
    url: str, res: Response, injection_point: InjectionPoint, soup: BeautifulSoup
) -> List[Result]:
    """
    Checks for Open Redirect by injecting payloads and looking for Location header changes in the response.
    Only GET parameters are processed.
    """
    if not hasattr(check_injection, "_tested_combinations"):
        check_injection._tested_combinations = set()
    tested = check_injection._tested_combinations

    from urllib.parse import urlparse

    results = []
    orig_value = injection_point.value
    method = injection_point.method.upper()
    field = injection_point.field

    # Only test GET parameters
    if method != "GET":
        return []

    parsed = urlparse(url)
    page = parsed.path
    combo = (page, field, method)
    if combo in tested:
        return []

    # Skip unsafe forms
    if is_unsafe_form(soup, field):
        return []
    form_params = _extract_form_params(soup, field, orig_value)

    found = False
    for payload in OPEN_REDIRECT_PAYLOADS:
        test_url, params = _build_params_for_request(
            method, url, field, payload, form_params
        )
        if is_unsafe_link(test_url, ""):
            return []
        try:
            resp = network.http_get(test_url, allow_redirects=False)
            response_scanner.check_response(test_url, resp, soup, False)
        except Exception:
            continue

        # Check for Location header with our payload
        location = resp.headers.get("Location", "")
        if location and (payload in location or location.startswith(payload)):
            evidence = Evidence(
                test_url,
                None,
                None,
                {"payload": payload, "url": test_url, "location": location},
            )
            results.append(
                Result(
                    f"Open Redirect confirmed with payload: {payload} on page: {url}",
                    Vulnerabilities.OPEN_REDIRECT_CONFIRMED,
                    test_url,
                    evidence,
                )
            )
            found = True
            break  # Stop after first positive result
    tested.add(combo)
    return results
