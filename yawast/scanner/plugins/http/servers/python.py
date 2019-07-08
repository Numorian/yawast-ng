from typing import List

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.result import Result


def check_banner(banner: str, raw: str, url: str) -> List[Result]:
    if not banner.startswith("Python/"):
        return []

    results = [
        Result(
            f"Python Version Exposed: {banner}",
            Vulnerabilities.HTTP_BANNER_PYTHON_VERSION,
            url,
            {"response": raw, "banner": banner},
        )
    ]

    return results
