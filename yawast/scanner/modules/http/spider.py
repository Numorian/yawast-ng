#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

import re
import time
import xml.etree.ElementTree as ET
from multiprocessing import Lock, Manager
from multiprocessing.dummy import Pool
from typing import List, Tuple
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from yawast import config
from yawast.reporting.enums import Vulnerabilities
from yawast.reporting.evidence import Evidence
from yawast.reporting.result import Result
from yawast.scanner.modules.http import response_scanner
from yawast.scanner.session import Session
from yawast.shared import network, output, utils

_links: List[str] = []
_insecure: List[str] = []
_lock = Lock()
_tasks = []


def spider(session: Session) -> Tuple[List[str], List[Result]]:
    global _links, _insecure, _tasks, _lock

    results: List[Result] = []
    url = session.url

    # create processing pool
    pool = Pool()
    mgr = Manager()
    queue = mgr.Queue()

    asy = pool.apply_async(_start_scan, (session, url, [url], queue, pool))

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

    for t in _tasks:
        try:
            t.get()
        except Exception:
            output.debug_exception()

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
    _tasks = []

    return links, results


def _start_scan(session: Session, base_url: str, urls: List[str], queue, pool):
    global _links, _insecure, _tasks, _lock

    # check to see if there's a sitemap.xml file - if there is, we'll
    # use that to get the list of URLs to scan - otherwise, we'll
    # just start with the base URL
    sitemap_url = urljoin(base_url, "sitemap.xml")
    res = network.http_get(sitemap_url, False)
    if res.status_code == 200:
        # parse the sitemap.xml file and get the list of URLs
        try:
            tree = ET.ElementTree(ET.fromstring(res.text))
            root = tree.getroot()
            urls = []
            for child in root:
                for url in child:
                    if url.tag.endswith("loc"):
                        urls.append(url.text)

            output.debug(f"Spider: Found {len(urls)} URLs in sitemap.xml.")

            if len(urls) > 0:
                # start the spider with the URLs from the sitemap
                with _lock:
                    # loop through the URLs and queue them for processing
                    for url in urls:
                        if url not in _links:
                            asy = pool.apply_async(
                                _get_links, (session, url, [url], queue, pool)
                            )
                            _tasks.append(asy)
            else:
                output.debug(f"Spider: No URLs found in sitemap.xml.")
                asy = pool.apply_async(
                    _get_links, (session, base_url, [base_url], queue, pool)
                )

                with _lock:
                    _tasks.append(asy)
        except Exception:
            output.debug_exception()
            urls = [base_url]
    else:
        urls = [base_url]
        output.debug(
            f"Spider: No sitemap found at {sitemap_url}. Starting with base URL."
        )

        asy = pool.apply_async(_get_links, (session, base_url, [base_url], queue, pool))

        with _lock:
            _tasks.append(asy)


def _get_links(session: Session, base_url: str, urls: List[str], queue, pool):
    global _links, _insecure, _tasks, _lock

    results: List[Result] = []

    # fail-safe to make sure we don't go too crazy
    if len(_links) > config.max_spider_pages:
        # if we have more than 10,000 URLs in our list, just stop
        output.debug(
            "Spider: Link list contains > 10,000 items. Stopped gathering more links."
        )

        return

    for url in urls:
        try:
            # list of pages found that will need to be processed
            to_process: List[str] = []

            res = network.http_get(url, False)

            if network.response_body_is_text(res):
                soup = BeautifulSoup(res.text, "html.parser")
            else:
                # no clue what this is
                soup = None

            results += response_scanner.check_response(url, res, soup)

            if soup is not None:
                for link in soup.find_all("a"):
                    href = link.get("href")

                    if href is not None:
                        # fix // links
                        href = str(href).strip()

                        href = utils.fix_relative_link(href, url)

                        # check to see if this link is in scope
                        if href.startswith(base_url) and href not in _links:
                            if "." in href.split("/")[-1]:
                                file_ext = href.split("/")[-1].split(".")[-1]
                            else:
                                file_ext = None

                            with _lock:
                                _links.append(href)

                            # check to see if this is a PHP file
                            if file_ext is not None and str(file_ext).lower() == "php":
                                # check to see if we have a php_page set
                                if session.args.php_page is None:
                                    session.args.php_page = href
                                    output.debug(
                                        f"Spider: Found PHP page: {href} - setting as php_page"
                                    )

                            # filter out some of the obvious binary files
                            if file_ext is None or str(file_ext).lower() not in [
                                "gzip",
                                "jpg",
                                "jpeg",
                                "gif",
                                "woff",
                                "zip",
                                "exe",
                                "gz",
                                "pdf",
                                "iso",
                                "pkg",
                                "dmg",
                            ]:
                                if not _is_unsafe_link(href, link.string):
                                    to_process.append(href)
                                else:
                                    output.debug(
                                        f"Skipping unsafe URL: {link.string} - {href}"
                                    )
                            else:
                                output.debug(
                                    f'Skipping URL "{href}" due to file extension "{file_ext}"'
                                )
                        else:
                            if (
                                base_url.startswith("https://")
                                and str(href).startswith("http://")
                                and str(href) not in _insecure
                            ):
                                # link from secure to insecure
                                with _lock:
                                    _insecure.append(str(href))

                                results.append(
                                    Result.from_evidence(
                                        Evidence.from_response(res, {"link": href}),
                                        f"Insecure Link: {url} links to {href}",
                                        Vulnerabilities.HTTP_INSECURE_LINK,
                                    )
                                )

            # handle redirects
            if "Location" in res.headers:
                redirect = res.headers["Location"]

                # check for relative link
                if str(redirect).startswith("/"):
                    redirect = urljoin(base_url, redirect)

                # make sure that we aren't redirected out of scope
                if str(redirect).startswith(base_url):
                    to_process.append(redirect)

            if len(to_process) > 0:
                asy = pool.apply_async(_get_links, (base_url, to_process, queue, pool))

                with _lock:
                    _tasks.append(asy)
        except Exception:
            output.debug_exception()

    output.debug(f"GetLinks Task Completed - {len(results)} issues found.")
    queue.put(results)


def _is_unsafe_link(href: str, description: str) -> bool:
    """
    Check for strings that indicate an unsafe link
    :param href:
    :param description:
    :return:
    """
    unsafe_fragments = [
        "logoff",
        "log off",
        "log_off",
        "logout",
        "log out",
        "log_out",
        "delete",
        "destroy",
    ]

    ret = False

    try:
        description = str(description).lower() if description is not None else ""
        href = str(href).lower()

        for frag in unsafe_fragments:
            if frag in href or frag in description:
                return True
    except Exception:
        output.debug_exception()

    return ret
