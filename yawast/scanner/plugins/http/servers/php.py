from typing import List, cast
from packaging import version

from yawast.scanner.plugins.http import version_checker
from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.result import Result


def check_version(banner: str, raw: str, url: str) -> List[Result]:
    if not banner.startswith("PHP/"):
        return []

    results = []

    # we've got a PHP version
    results.append(
        Result(
            f"PHP Version Exposed: {banner}",
            Vulnerabilities.HTTP_PHP_VERSION_EXPOSED,
            url,
            raw,
        )
    )

    # parse the version, and get the latest version - see if the server is up to date
    ver = cast(version.Version, version.parse(banner.split("/")[1]))
    curr_version = version_checker.get_latest_version("php", ver)

    if curr_version is not None and curr_version > ver:
        results.append(
            Result(
                f"PHP Outdated: {ver} - Current: {curr_version}",
                Vulnerabilities.SERVER_PHP_OUTDATED,
                url,
                raw,
            )
        )

    return results
