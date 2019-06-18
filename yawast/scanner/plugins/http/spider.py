from yawast.reporting.enums import Vulnerabilities
from yawast.shared import network, output
from yawast.scanner.plugins.result import Result
from yawast.scanner.plugins.http import response_scanner
from typing import List, Dict, Tuple
from requests.models import Response
from bs4 import BeautifulSoup

_links = []
_results = []
_insecure = []


def spider(url) -> Tuple[List[str], List[Result]]:
    global _links, _results, _insecure
    _get_links(url, url)

    # copy data and reset
    links = _links[:]
    _links = []
    results = _results
    _results = []
    _insecure = []

    return links, results


def _get_links(base_url: str, url: str):
    global _links, _results, _insecure

    res = network.http_get(url, False)

    soup = BeautifulSoup(res.text, "html.parser")

    # check the response for issues
    _results += response_scanner.check_response(url, res, soup)

    for link in soup.find_all("a"):
        href = link.get("href")

        if href is not None:
            # check to see if this link is in scope
            if base_url in href and href not in _links:
                if "." in href.split("/")[-1]:
                    file_ext = href.split("/")[-1].split(".")[-1]
                else:
                    file_ext = None

                _links.append(href)

                # filter out some of the obvious binary files
                if file_ext is None or file_ext not in [
                    "gzip",
                    "jpg",
                    "jpeg",
                    "gif",
                    "woff",
                    "zip",
                    "exe",
                    "gz",
                    "pdf",
                ]:
                    _get_links(base_url, href)
                else:
                    output.debug(
                        f'Skipping URL "{href}" due to file extension "{file_ext}"'
                    )
            else:
                # TODO: Check PSL, if outside of scope, it's an issue

                if (
                    "https://" in base_url
                    and "http://" in href
                    and href not in _insecure
                ):
                    # link from secure to insecure
                    _insecure.append(href)

                    _results.append(
                        Result(
                            f"Insecure Link: {url} links to {href}",
                            Vulnerabilities.HTTP_INSECURE_LINK,
                            url,
                            [href, res.text],
                        )
                    )
                pass

    # handle redirects
    if "Location" in res.headers:
        # TODO: Handle relative URLs
        redirect = res.headers["Location"]

        # make sure that we aren't redirected out of scope
        if base_url in redirect:
            _get_links(base_url, redirect)
