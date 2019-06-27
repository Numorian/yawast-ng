from typing import List, Tuple, Any
from urllib.parse import urljoin

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.evidence import Evidence
from yawast.scanner.plugins.http import response_scanner
from yawast.scanner.plugins.result import Result
from yawast.shared import network


def check_special_files(url: str) -> Tuple[List[str], List[Result]]:
    targets = [
        "crossdomain.xml",
        "clientaccesspolicy.xml",
        "sitemap.xml",
        "WS_FTP.LOG",
        "ws_ftp.log",
        "Trace.axd",
        "elmah.axd",
        "readme.html",
        "RELEASE-NOTES.txt",
        "docs/RELEASE-NOTES.txt",
        "CHANGELOG.txt",
        "core/CHANGELOG.txt",
        "license.txt",
    ]

    return _check_url(url, targets)


def check_special_paths(url: str) -> Tuple[List[str], List[Result]]:
    targets = [
        ".git/",
        ".git/index",
        ".svn/entries",
        ".svn/wc.db",
        ".hg/",
        ".svn/",
        ".bzr/",
        ".cvs/",
    ]

    return _check_url(url, targets)


def _check_url(url: str, targets: List[str]) -> Tuple[List[str], List[Result]]:
    files: List[str] = []
    results: List[Result] = []

    for target in targets:
        target_url = urljoin(url, target)

        res = network.http_get(target_url, False)

        results += response_scanner.check_response(target_url, res)

        if res.status_code < 300:
            files.append(target_url)
            results.append(
                Result.from_evidence(
                    Evidence.from_response(res),
                    f"File found: {target_url}",
                    Vulnerabilities.SERVER_SPECIAL_FILE_EXPOSED,
                )
            )

    return files, results
