import re
from typing import Tuple, Union, List, cast
from urllib.parse import urljoin

from packaging import version
from requests import Response

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.evidence import Evidence
from yawast.scanner.plugins.http import version_checker
from yawast.scanner.plugins.result import Result
from yawast.shared import network


def identify(url: str) -> Tuple[Union[str, None], List[Result]]:
    results = []

    # find WordPress
    res, path = _identify_by_path(url, "")

    if path is None:
        res, path = _identify_by_path(url, "blog/")

    # check to see if we have a valid hit
    if path is not None:
        # we have a WordPress install, let's see if we can get a version
        body = res.text

        ver = "Unknown"
        # this works for modern versions
        m = re.search(r"login.min.css\?ver=\d+\.\d+\.?\d*", body)
        if m:
            ver = m.group(0).split("=")[1]
        else:
            # the current method doesn't work, fall back to an older method
            m = re.search(r"load-styles.php\?[\w,;=&%]+;ver=\d+\.\d+\.?\d*", body)
            if m:
                ver = m.group(0).split("=")[-1]

        # report that we found WordPress
        results.append(
            Result.from_evidence(
                Evidence.from_response(res, {"version": ver}),
                f"Found WordPress v{ver} at {path}",
                Vulnerabilities.APP_WORDPRESS_VERSION,
            )
        )

        # is this a current version?
        ver = cast(version.Version, version.parse(ver))
        curr_version = version_checker.get_latest_version("wordpress", ver)

        if curr_version is not None and curr_version > ver:
            results.append(
                Result.from_evidence(
                    Evidence.from_response(
                        res,
                        {
                            "installed_version": str(ver),
                            "current_verison": str(curr_version),
                        },
                    ),
                    f"WordPress Outdated: {ver} - Current: {curr_version}",
                    Vulnerabilities.APP_WORDPRESS_OUTDATED,
                )
            )

        return path, results
    else:
        return None, []


def check_json_user_enum(url: str) -> List[Result]:
    results = []
    target = urljoin(url, "wp-json/wp/v2/users")

    res = network.http_get(target, False)
    body = res.text

    if res.status_code < 300 and "slug" in body:
        data = res.json()

        # log the enum finding
        results.append(
            Result.from_evidence(
                Evidence.from_response(res),
                f"WordPress WP-JSON User Enumeration at {target}",
                Vulnerabilities.APP_WORDPRESS_USER_ENUM_API,
            )
        )

        # log the individual users
        for user in data:
            results.append(
                Result.from_evidence(
                    Evidence.from_response(
                        res,
                        {
                            "user_id": user["id"],
                            "user_slug": user["slug"],
                            "user_name": user["name"],
                        },
                    ),
                    f"ID: {user['id']}\tUser Slug: '{user['slug']}'\t\tUser Name: '{user['name']}'",
                    Vulnerabilities.APP_WORDPRESS_USER_FOUND,
                )
            )

    return results


def _identify_by_path(url: str, path: str) -> Tuple[Response, Union[str, None]]:
    target = urljoin(url, f"{path}wp-login.php")

    res = network.http_get(target, False)
    body = res.text

    if res.status_code == 200 and "Powered by WordPress" in body:
        return res, urljoin(url, path)
    else:
        return res, None
