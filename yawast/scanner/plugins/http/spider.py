import time
from multiprocessing import Manager, Lock
from multiprocessing.dummy import Pool
from typing import List, Tuple
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.plugins.http import response_scanner, http_utils
from yawast.scanner.plugins.result import Result
from yawast.shared import network, output

_links = []
_insecure = []
_lock = Lock()
_tasks = []


def spider(url) -> Tuple[List[str], List[Result]]:
    global _links, _insecure, _tasks, _lock

    results = []

    # create processing pool
    pool = Pool()
    mgr = Manager()
    queue = mgr.Queue()

    asy = pool.apply_async(_get_links, (url, [url], queue, pool))

    # work around a Python bug - this sets a long timeout
    # this  triggers signals to be properly processed
    # see https://stackoverflow.com/a/1408476
    # asy.get(timeout=999999)
    with _lock:
        _tasks.append(asy)

    while True:
        if all(t is None or t.ready() for t in _tasks):
            break
        else:
            count_none = 0
            count_ready = 0
            count_not_ready = 0

            for t in _tasks:
                if t is None:
                    count_none += 1
                elif t.ready():
                    count_ready += 1
                else:
                    count_not_ready += 1

            output.debug(
                f"Spider Task Status: None: {count_none}, Ready: {count_ready}, Not Ready: {count_not_ready}"
            )

        time.sleep(3)

    pool.close()

    while not queue.empty():
        res = queue.get()

        if len(res) > 0:
            for re in res:
                if re not in results:
                    results.append(re)

    # copy data and reset
    links = _links[:]
    _links = []
    _insecure = []

    return links, results


def _get_links(base_url: str, urls: List[str], queue, pool):
    global _links, _insecure, _tasks, _lock

    results = []

    for url in urls:
        try:
            to_process = []

            res = network.http_get(url, False)

            if http_utils.is_text(res):
                soup = BeautifulSoup(res.text, "html.parser")
            else:
                # no clue what this is
                results += response_scanner.check_response(url, res)

                return

            # check the response for issues
            results += response_scanner.check_response(url, res, soup)

            for link in soup.find_all("a"):
                href = link.get("href")

                if href is not None:
                    # check to see if this link is in scope
                    if base_url in href and href not in _links:
                        if "." in href.split("/")[-1]:
                            file_ext = href.split("/")[-1].split(".")[-1]
                        else:
                            file_ext = None

                        with _lock:
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
                            to_process.append(href)
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
                            with _lock:
                                _insecure.append(href)

                            results.append(
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
                    to_process.append(redirect)

            asy = pool.apply_async(_get_links, (base_url, to_process, queue, pool))

            with _lock:
                _tasks.append(asy)
        except Exception:
            output.debug_exception()

    queue.put(results)
