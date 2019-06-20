from typing import List, Tuple
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.http import response_scanner
from yawast.scanner.plugins.result import Result
from yawast.shared import network, output

_links = []
_results = []
_insecure = []


def spider(url) -> Tuple[List[str], List[Result]]:
    global _links, _results, _insecure
    _get_links(url, [url])

    # copy data and reset
    links = _links[:]
    _links = []
    results = _results
    _results = []
    _insecure = []

    return links, results


def _get_links(base_url: str, urls: List[str]):
    global _links, _results, _insecure

    for url in urls:
        queue = []

        res = network.http_get(url, False)

        if "Content-Type" in res.headers and "text/html" in res.headers["Content-Type"]:
            soup = BeautifulSoup(res.text, "html.parser")
        else:
            _results += response_scanner.check_response(url, res)

            return

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
                        queue.append(href)
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
            redirect = res.headers["Location"]

            # check for relative link
            if str(redirect).startswith("/"):
                redirect = urljoin(base_url, redirect)

            # make sure that we aren't redirected out of scope
            if base_url in redirect:
                queue.append(redirect)

        _get_links(base_url, queue)
