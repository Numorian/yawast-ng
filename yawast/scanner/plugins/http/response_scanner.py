import inspect
from typing import List, Union

from bs4 import BeautifulSoup
from requests.models import Response

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.http import http_basic, retirejs, error_checker
from yawast.scanner.plugins.http.servers import rails, apache_tomcat
from yawast.scanner.plugins.result import Result
from yawast.shared import network


def check_response(
    url: str, res: Response, soup: Union[BeautifulSoup, None] = None
) -> List[Result]:
    # make sure we actually have something
    if res is None:
        return []

    results = []

    raw_full = "\n".join(network.http_build_raw_response(res))

    if "Content-Type" in res.headers and "text/html" in res.headers["Content-Type"]:
        body = res.text

        # don't bother with these, if the body is empty
        if len(body) > 0:
            if soup is None:
                soup = BeautifulSoup(body, "html.parser")

            # check for things thar require parsed HTML
            results += retirejs.get_results(soup, url, raw_full)
            results += apache_tomcat.get_version(url, res)
            results += error_checker.check_response(url, res, body)

    results += http_basic.get_header_issues(res.headers, raw_full, url)
    results += http_basic.get_cookie_issues(res, raw_full, url)

    # this function will trigger a recursive call, as it calls this to check the response.
    # to deal with this, we'll check the caller, to make sure it's not what we're about to call.
    if "check_cve_2019_5418" not in inspect.stack()[1].function:
        results += rails.check_cve_2019_5418(url)

    results += _check_charset(url, res, raw_full)

    return results


def _check_charset(url: str, res: Response, raw: str) -> List[Result]:
    results = []

    if "Content-Type" in res.headers:
        content_type = str(res.headers["Content-Type"]).lower()

        if "charset" not in content_type and "text/html" in content_type:
            # not charset specified
            results.append(
                Result(
                    f"Charset Not Defined in '{res.headers['Content-Type']}' at {url}",
                    Vulnerabilities.HTTP_HEADER_CONTENT_TYPE_NO_CHARSET,
                    url,
                    [res.headers["Content-Type"], raw],
                )
            )
    else:
        # content-type missing
        results.append(
            Result(
                f"Content-Type Missing: {url}",
                Vulnerabilities.HTTP_HEADER_CONTENT_TYPE_MISSING,
                url,
                raw,
            )
        )

    return results
