#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

import warnings
from datetime import datetime
from typing import List, Union
from urllib.parse import urlparse

from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
from dateutil import tz
from dateutil.parser import parse
from requests.models import Response

from yawast.reporting import reporter
from yawast.reporting.enums import Vulnerabilities
from yawast.reporting.evidence import Evidence
from yawast.reporting.injection import InjectionPoint
from yawast.reporting.result import Result
from yawast.scanner.modules.http import error_checker, http_basic, retirejs
from yawast.scanner.modules.http.servers import apache_tomcat, iis, rails
from yawast.shared import network, output, utils


def check_response(
    url: str, res: Response, soup: Union[BeautifulSoup, None] = None
) -> List[Result]:
    # make sure we actually have something
    if res is None:
        return []

    results: List[Result] = []

    raw_full = network.http_build_raw_response(res)

    if soup or network.response_body_is_text(res):
        body = res.text

        if soup is None:
            warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
            soup = BeautifulSoup(body, features="html.parser")

        # check for things thar require parsed HTML
        results += retirejs.get_results(soup, url, res)
        results += apache_tomcat.get_version(url, res)
        results += error_checker.check_response(url, res, body)
        results += iis.check_telerik_rau_enabled(soup, url)

        results += _check_cache_headers(url, res)

        points = _find_injection_points(url, res, soup)
        reporter.register_injection_points(points)

    results += http_basic.get_header_issues(res, raw_full, url)
    results += http_basic.get_cookie_issues(res, url)

    # only check for this if we have a good response - no point in doing this for errors
    if res.status_code < 400:
        results += rails.check_cve_2019_5418(url)

    # we perform this check even if the response isn't text as this also covers missing content-type
    results += _check_charset(url, res)

    return results


def _find_injection_points(
    url: str, res: Response, soup: Union[BeautifulSoup, None] = None
):
    """
    This function checks for potential injection points in the response.
    It will check for the following:
    - URL parameters
    - Form fields
    """
    injection_points: List[InjectionPoint] = []

    # check the URL for parameters
    if res.request.url:
        # check for URL parameters
        parsed_url = urlparse(res.request.url)
        if parsed_url.query:
            # look for any parameters in the query string
            for param in parsed_url.query.split("&"):
                if "=" in param:
                    name, value = param.split("=", 1)

                    ip = InjectionPoint(url, name, res.request.method, value)
                    injection_points.append(ip)

    # check the response for form fields
    if soup:
        # check for form fields
        forms = soup.find_all("form")
        for form in forms:
            # get the method and action
            method = form.get("method", "GET").upper()
            action = form.get("action", "")
            if not action:
                action = res.request.url

            # make action absolute
            action = utils.fix_relative_link(action, url)

            # get the input fields
            inputs = form.find_all("input")
            for input_field in inputs:
                name = input_field.get("name", "")
                value = input_field.get("value", "")

                ip = InjectionPoint(action, name, method, value)
                injection_points.append(ip)

    return injection_points


def _check_charset(url: str, res: Response) -> List[Result]:
    results: List[Result] = []

    # if the body is empty, we really don't care about this
    if len(res.content) == 0:
        return results

    try:
        if "Content-Type" in res.headers:
            content_type = str(res.headers["Content-Type"]).lower()

            if "charset" not in content_type and "text/html" in content_type:
                # not charset specified
                results.append(
                    Result.from_evidence(
                        Evidence.from_response(res, {"content-type": content_type}),
                        f"Charset Not Defined in '{res.headers['Content-Type']}' at {url}",
                        Vulnerabilities.HTTP_HEADER_CONTENT_TYPE_NO_CHARSET,
                    )
                )
        else:
            # content-type missing
            results.append(
                Result.from_evidence(
                    Evidence.from_response(res),
                    f"Content-Type Missing: {url} ({res.request.method} - {res.status_code})",
                    Vulnerabilities.HTTP_HEADER_CONTENT_TYPE_MISSING,
                )
            )
    except Exception:
        output.debug_exception()

    return results


def _check_cache_headers(url: str, res: Response) -> List[Result]:
    results = []

    try:
        ev = Evidence.from_response(res)

        if "Cache-Control" in res.headers:
            # we have the header, check the content
            if "public" in str(res.headers["Cache-Control"]).lower():
                results.append(
                    Result.from_evidence(
                        ev,
                        f"Cache-Control: Public: {url}",
                        Vulnerabilities.HTTP_HEADER_CACHE_CONTROL_PUBLIC,
                    )
                )

            if "no-cache" not in str(res.headers["Cache-Control"]).lower():
                results.append(
                    Result.from_evidence(
                        ev,
                        f"Cache-Control: no-cache Not Found: {url}",
                        Vulnerabilities.HTTP_HEADER_CACHE_CONTROL_NO_CACHE_MISSING,
                    )
                )

            if "no-store" not in str(res.headers["Cache-Control"]).lower():
                results.append(
                    Result.from_evidence(
                        ev,
                        f"Cache-Control: no-store Not Found: {url}",
                        Vulnerabilities.HTTP_HEADER_CACHE_CONTROL_NO_STORE_MISSING,
                    )
                )

            if "private" not in str(res.headers["Cache-Control"]).lower():
                results.append(
                    Result.from_evidence(
                        ev,
                        f"Cache-Control: private Not Found: {url}",
                        Vulnerabilities.HTTP_HEADER_CACHE_CONTROL_PRIVATE_MISSING,
                    )
                )
        else:
            # header missing
            results.append(
                Result.from_evidence(
                    ev,
                    f"Cache-Control Header Not Found: {url}",
                    Vulnerabilities.HTTP_HEADER_CACHE_CONTROL_MISSING,
                )
            )

        if "Expires" not in res.headers:
            results.append(
                Result.from_evidence(
                    ev,
                    f"Expires Header Not Found: {url}",
                    Vulnerabilities.HTTP_HEADER_EXPIRES_MISSING,
                )
            )
        else:
            # parse the date, and check to see if it's in the past
            try:
                # using fuzzy=true here could lead to some false positives due to it doing whatever it can to produce
                # a valid date - but it is the most forgiving option we have to ensure odd servers don't cause issues
                dt = parse(res.headers["Expires"], fuzzy=True)
                if dt > datetime.now(tz.UTC):
                    # Expires is in the future - it's an issue
                    results.append(
                        Result.from_evidence(
                            ev,
                            f"Expires Header - Future Dated ({res.headers['Expires']}): {url}",
                            Vulnerabilities.HTTP_HEADER_EXPIRES_FUTURE,
                        )
                    )
            except Exception:
                output.debug_exception()

        if "Pragma" not in res.headers or "no-cache" not in str(res.headers["Pragma"]):
            results.append(
                Result.from_evidence(
                    ev,
                    f"Pragma: no-cache Not Found: {url}",
                    Vulnerabilities.HTTP_HEADER_PRAGMA_NO_CACHE_MISSING,
                )
            )
    except Exception:
        output.debug_exception()

    return results
