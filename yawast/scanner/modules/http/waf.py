#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

from typing import Dict, List

from yawast.reporting.enums import Vulnerabilities
from yawast.reporting.result import Result


def get_waf(headers: Dict, raw: str, url: str) -> List[Result]:
    results = []

    if "Server" in headers:
        if headers["Server"] == "cloudflare":
            results.append(
                Result(
                    "WAF Detected: Cloudflare", Vulnerabilities.WAF_CLOUDFLARE, url, raw
                )
            )

    if "X-CDN" in headers or "X-Iinfo" in headers:
        results.append(
            Result("WAF Detected: Incapsula", Vulnerabilities.WAF_INCAPSULA, url, raw)
        )

    return results
