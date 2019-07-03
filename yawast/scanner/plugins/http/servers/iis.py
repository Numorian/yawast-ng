import secrets
from typing import List, cast, Dict
from urllib.parse import urljoin

from packaging import version

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.evidence import Evidence
from yawast.scanner.plugins.http import version_checker, response_scanner
from yawast.scanner.plugins.result import Result
from yawast.shared import network, output


def check_all(url: str) -> List[Result]:
    results: List[Result] = []

    results += check_asp_net_debug(url)
    results += check_aspnet_handlers(url)

    return results


def check_version(banner: str, raw: str, url: str, headers: Dict) -> List[Result]:
    results: List[Result] = []

    if not banner.startswith("Microsoft-IIS/"):
        return results

    # we've got an IIS version
    results.append(
        Result(
            f"IIS Version Exposed: {banner}",
            Vulnerabilities.HTTP_BANNER_IIS_VERSION,
            url,
            raw,
        )
    )

    # parse the version, and get the latest version - see if the server is up to date
    ver = cast(version.Version, version.parse(banner.split("/")[1]))
    curr_version = version_checker.get_latest_version("iis", ver)

    if curr_version is not None and curr_version > ver:
        results.append(
            Result(
                f"IIS Outdated: {ver} - Current: {curr_version}",
                Vulnerabilities.SERVER_IIS_OUTDATED,
                url,
                raw,
            )
        )

    # IIS servers may expose a couple other versions, related to ASP.NET, check for those
    if "X-AspNetMvc-Version" in headers:
        results.append(
            Result(
                f'ASP.NET MVC Version Exposed: {headers["X-AspNetMvc-Version"]}',
                Vulnerabilities.HTTP_HEADER_X_ASPNETMVC_VERSION,
                url,
                raw,
            )
        )

        ver = cast(version.Version, version.parse(headers["X-AspNetMvc-Version"]))
        curr_version = version_checker.get_latest_version("aspnet_mvc", ver)

        if curr_version is not None and curr_version > ver:
            results.append(
                Result(
                    f"ASP.NET MVC Outdated: {ver} - Current: {curr_version}",
                    Vulnerabilities.SERVER_ASPNETMVC_OUTDATED,
                    url,
                    raw,
                )
            )

    if "X-AspNet-Version" in headers:
        results.append(
            Result(
                f'ASP.NET CLR Version Exposed: {headers["X-AspNet-Version"]}',
                Vulnerabilities.HTTP_HEADER_X_ASPNET_VERSION,
                url,
                raw,
            )
        )

        ver = cast(version.Version, version.parse(headers["X-AspNet-Version"]))
        curr_version = version_checker.get_latest_version("aspnet", ver)

        if curr_version is not None and curr_version > ver:
            results.append(
                Result(
                    f"ASP.NET Outdated: {ver} - Current: {curr_version}",
                    Vulnerabilities.SERVER_ASPNET_OUTDATED,
                    url,
                    raw,
                )
            )

    return results


def check_aspnet_handlers(url: str) -> List[Result]:
    results = []

    file_name = secrets.token_hex(12)

    exts = ["ashx", "aspx", "asmx", "soap", "rem"]

    for ext in exts:
        target = urljoin(url, f"{file_name}.{ext}")
        vuln = False

        res = network.http_get(target, False)
        body = res.text

        if "Location" in res.headers and "aspxerrorpath" in res.headers["Location"]:
            vuln = True
        elif (
            res.status_code >= 400
            and "Remoting.RemotingException" in body
            or "HttpException" in body
            or "FileNotFoundException" in body
        ):
            vuln = True

        if vuln:
            results.append(
                Result.from_evidence(
                    Evidence.from_response(res, {"handler": ext}),
                    f"ASP.NET Handler Enumeration: {ext}",
                    Vulnerabilities.SERVER_ASPNET_HANDLER_ENUM,
                )
            )

    return results


def check_asp_net_debug(url: str) -> List[Result]:
    results: List[Result] = []

    res = network.http_custom(
        "DEBUG", url, additional_headers={"Command": "stop-debug", "Accept": "*/*"}
    )

    if res.status_code == 200 and "OK" in res.text:
        # we've got a hit, but could be a false positive
        # try this again, with a different verb
        xres = network.http_custom(
            "XDEBUG", url, additional_headers={"Command": "stop-debug", "Accept": "*/*"}
        )

        # if we get a 200 when using an invalid verb, it's a false positive
        # if we get something else, then the DEBUG actually did something
        if xres.status_code != 200:
            results.append(
                Result(
                    "ASP.NET Debugging Enabled",
                    Vulnerabilities.SERVER_ASPNET_DEBUG_ENABLED,
                    url,
                    [
                        network.http_build_raw_request(res.request),
                        network.http_build_raw_response(res),
                    ],
                )
            )
        else:
            output.debug("Server responds to invalid HTTP verbs with status 200")

    results += response_scanner.check_response(url, res)

    return results
