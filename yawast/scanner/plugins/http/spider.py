from yawast.shared import network, output
from yawast.scanner.plugins.result import Result
from yawast.scanner.plugins.http import response_scanner
from typing import List, Dict, Tuple
from requests.models import Response
from bs4 import BeautifulSoup

_links = []
_results = []


def spider(url) -> Tuple[List[str], List[Result]]:
    global _links, _results
    _get_links(url, url)

    # copy data and reset
    links = _links[:]
    _links = []
    results = _results
    _results = []

    return links, results


def _get_links(base_url: str, url: str):
    global _links, _results

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
                ]:
                    _links.append(href)
                    _get_links(base_url, href)
                else:
                    output.debug(
                        f'Skipping URL "{href}" due to file extension "{file_ext}"'
                    )
            else:
                # TODO: Check PSL, if outside of scope, it's an issue
                # TODO: Check for HTTP links from HTTPS source
                pass

    # handle redirects
    if "Location" in res.headers:
        # TODO: Handle relative URLs
        redirect = res.headers["Location"]

        # make sure that we aren't redirected out of scope
        if base_url in redirect:
            _get_links(base_url, redirect)
