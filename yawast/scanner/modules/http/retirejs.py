#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

import json
from typing import Any, Dict, List, Tuple, Union
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from requests import Response

from yawast.external import retirejs
from yawast.reporting.enums import Severity, Vulnerabilities, VulnerabilityReference
from yawast.reporting.evidence import Evidence
from yawast.reporting.result import Result
from yawast.shared import network, output, utils

_data: Union[Dict[Any, Any], None] = {}
_checked: List[str] = []
_reports: List[str] = []


def get_results(soup: BeautifulSoup, url: str, res: Response) -> List[Result]:
    global _reports

    results: List[Result] = []

    try:
        parsed = urlparse(url)
        domain = utils.get_domain(parsed.netloc)

        issues, r = _get_retirejs_results(soup, url, domain, res)
        results += r
        for js_url, issue in issues:
            comp = issue["component"]
            ver = issue["version"]

            if "vulnerabilities" in issue:
                for vuln in issue["vulnerabilities"]:
                    info = f'Vulnerable JavaScript: {comp}-{ver} ({js_url}): Severity: {vuln["severity"]}'

                    # make sure we haven't reported this issue before
                    if info not in _reports:
                        _reports.append(info)

                        # produce the name for the vulnerability
                        # first, we'll check vuln["identifiers"] to see if we have a CVE,
                        # if not, we'll check for githubID, and this issue. we should
                        # always have one of these, but if we don't, we'll just use the
                        # component name
                        name = None
                        if "CVE" in vuln["identifiers"]:
                            # CVE is an array, so we'll just use the first one
                            cve = vuln["identifiers"]["CVE"][0]
                            name = f"Js_Vulnerable_Version_{comp}_{cve}"
                        elif "githubID" in vuln["identifiers"]:
                            name = f"Js_Vulnerable_Version_{comp}_{vuln["identifiers"]["githubID"]}"
                        elif "issue" in vuln["identifiers"]:
                            name = f"Js_Vulnerable_Version_{comp}_{vuln["identifiers"]["issue"]}"
                        else:
                            name = f"Js_Vulnerable_Version_{comp}_{ver}_OTHER"

                        # check the Vulnerabilities enum to see if we have this one already
                        vulnerability: Vulnerabilities
                        if not hasattr(Vulnerabilities, name.upper()):
                            # map vuln["severity"] to our Severity enum
                            if vuln["severity"] == "high":
                                severity = Severity.HIGH
                            elif vuln["severity"] == "medium":
                                severity = Severity.MEDIUM
                            else:
                                severity = Severity.LOW

                            # build the description. it should be in vuln["identifiers"]["summary"]
                            # but if that's not there, we'll just constructe a string
                            if "summary" in vuln["identifiers"]:
                                description = vuln["identifiers"]["summary"]
                            else:
                                description = (
                                    f"Vulnerable JavaScript: {comp}-{ver} ({js_url})"
                                )

                            Vulnerabilities.add(name, severity, description)
                            vulnerability = Vulnerabilities.get(name)

                            # vuln["info"] should be a list of links, we can add those as references
                            for link in vuln["info"]:
                                link_name = link.split("/")[-1]
                                vulnerability.references.append(
                                    VulnerabilityReference(link_name, link)
                                )
                        else:
                            # we already have this one, so just use it
                            vulnerability = Vulnerabilities.get(name)

                        results.append(
                            Result.from_evidence(
                                Evidence.from_response(
                                    res,
                                    {
                                        "js_file": js_url,
                                        "js_lib": comp,
                                        "js_lib_ver": ver,
                                        "vuln_info": list(vuln["info"]),
                                        "vuln_sev": vuln["severity"],
                                    },
                                ),
                                info,
                                vulnerability,
                            )
                        )
                        output.debug(
                            f"Found JS vulnerability: {comp}-{ver} ({js_url}): Severity: {vuln['severity']}"
                        )
    except Exception:
        output.debug_exception()

    return results


def reset():
    global _checked, _reports

    _checked = []
    _reports = []


def _get_retirejs_results(
    soup: BeautifulSoup, url: str, domain: str, res: Response
) -> Tuple[List[Tuple[str, Dict]], List[Result]]:
    global _data, _checked
    issues = []
    results: List[Result] = []

    if _data is None or len(_data) == 0:
        _get_data()

    if _data is not None:
        # get all the JS files
        elements = [i for i in soup.find_all("script") if i.get("src")]

        for element in elements:
            file = element.get("src")
            # fix relative URLs
            if str(file).startswith("//"):
                file = f"https:{file}"
            if str(file).startswith("/") or (not str(file).startswith("http")):
                if urlparse(url).scheme == "https":
                    file = urljoin(f"https://{domain}", file)
                else:
                    file = urljoin(f"http://{domain}", file)

            if file not in _checked:
                findings = retirejs.scan_endpoint(file, _data)

                _checked.append(file)

                if domain not in file:
                    # external JS file
                    results.append(
                        Result.from_evidence(
                            Evidence.from_response(
                                res, {"js_file": file, "element": str(element)}
                            ),
                            f"External JavaScript File: {file}",
                            Vulnerabilities.JS_EXTERNAL_FILE,
                        )
                    )

                    # we have an external script; check for SRI
                    if not element.get("integrity"):
                        results.append(
                            Result.from_evidence(
                                Evidence.from_response(
                                    res, {"js_file": file, "element": str(element)}
                                ),
                                f"External JavaScript Without SRI: {file}",
                                Vulnerabilities.JS_EXTERNAL_NO_SRI,
                            )
                        )

                for find in findings:
                    issues.append((file, find))

        return issues, results
    else:
        # this means we couldn't get the data, so bail
        return [], []


def _get_data() -> None:
    global _data

    data: Union[Dict[Any, Any], None] = None
    data_url = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"

    try:
        raw = network.http_get(data_url).content
        raw_js = raw.decode("utf-8").replace("§§version§§", "[0-9][0-9.a-z_\\\\-]+")

        data = json.loads(raw_js)

    except Exception as error:
        output.debug(f"Failed to get version data: {error}")
        output.debug_exception()

    _data = data
