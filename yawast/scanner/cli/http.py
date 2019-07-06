from typing import List, Union

from yawast.external.spinner import Spinner
from yawast.reporting import reporter
from yawast.reporting.enums import Vulnerabilities
from yawast.reporting.issue import Issue
from yawast.scanner.plugins.evidence import Evidence
from yawast.scanner.plugins.http import (
    http_basic,
    waf,
    spider,
    retirejs,
    special_files,
    file_search,
    error_checker,
)
from yawast.scanner.plugins.http.applications import wordpress
from yawast.scanner.plugins.http.servers import apache_httpd, apache_tomcat, nginx, iis
from yawast.scanner.plugins.result import Result
from yawast.scanner.session import Session
from yawast.shared import network, output


def scan(session: Session):
    reporter.register_data("url", session.url)
    reporter.register_data("domain", session.domain)

    output.empty()
    output.norm("HEAD:")
    head = network.http_head(session.url)

    raw = network.http_build_raw_response(head)
    for line in raw.splitlines():
        output.norm(f"\t{line}")

    output.empty()

    res = http_basic.get_header_issues(head, raw, session.url)
    if len(res) > 0:
        output.norm("Header Issues:")

        reporter.display_results(res, "\t")
        output.empty()

    res = http_basic.get_cookie_issues(head, session.url)
    if len(res) > 0:
        output.norm("Cookie Issues:")

        reporter.display_results(res, "\t")
        output.empty()

    # check for WAF signatures
    res = waf.get_waf(head.headers, raw, session.url)
    if len(res) > 0:
        output.norm("WAF Detection:")

        reporter.display_results(res, "\t")
        output.empty()

    output.norm("Performing vulnerability scan (this will take a while)...")

    links: List[str] = []
    with Spinner():
        try:
            links, res = spider.spider(session.url)
        except Exception as error:
            output.debug_exception()
            output.error(f"Error running scan: {str(error)}")

    output.norm(f"Identified {len(links) + 1} pages.")
    output.empty()

    if len(res) > 0:
        output.norm("Issues Detected:")

        reporter.display_results(res, "\t")
        output.empty()

    # get files, and add those to the link list
    links += _file_search(session, links)

    with Spinner():
        res = http_basic.check_local_ip_disclosure(session)
    if len(res) > 0:
        reporter.display_results(res, "\t")

    with Spinner():
        res = apache_httpd.check_all(session.url)
    if len(res) > 0:
        reporter.display_results(res, "\t")

    with Spinner():
        res = apache_tomcat.check_all(session.url, links)
    if len(res) > 0:
        reporter.display_results(res, "\t")

    with Spinner():
        res = nginx.check_all(session.url)
    if len(res) > 0:
        reporter.display_results(res, "\t")

    with Spinner():
        res = iis.check_all(session.url)
    if len(res) > 0:
        reporter.display_results(res, "\t")

    with Spinner():
        res = http_basic.check_propfind(session.url)
    if len(res) > 0:
        reporter.display_results(res, "\t")

    with Spinner():
        res = http_basic.check_trace(session.url)
    if len(res) > 0:
        reporter.display_results(res, "\t")

    with Spinner():
        res = http_basic.check_options(session.url)
    if len(res) > 0:
        reporter.display_results(res, "\t")

    with Spinner():
        wp_path, res = wordpress.identify(session.url)
    if len(res) > 0:
        reporter.display_results(res, "\t")

    if wp_path is not None:
        with Spinner():
            res = wordpress.check_json_user_enum(wp_path)
        if len(res) > 0:
            reporter.display_results(res, "\t")


def reset():
    retirejs.reset()
    file_search.reset()
    error_checker.reset()
    http_basic.reset()


def _file_search(session: Session, orig_links: List[str]) -> List[str]:
    new_files: List[str] = []
    file_good, file_res, path_good, path_res = network.check_404_response(session.url)

    # these are here for data typing
    results: Union[List[Result], None]
    links: Union[List[str], None]

    if not file_good:
        reporter.display(
            "Web server does not respond properly to file 404 errors.",
            Issue(
                Vulnerabilities.SERVER_INVALID_404_FILE,
                session.url,
                Evidence.from_response(file_res),
            ),
        )
    if not path_good:
        reporter.display(
            "Web server does not respond properly to path 404 errors.",
            Issue(
                Vulnerabilities.SERVER_INVALID_404_PATH,
                session.url,
                Evidence.from_response(path_res),
            ),
        )

    if not (file_good or path_good):
        output.norm(
            "Site does not respond properly to non-existent file/path requests; skipping some checks."
        )

    if file_good:
        links, results = special_files.check_special_files(session.url)
        if len(results) > 0:
            reporter.display_results(results, "\t")

            new_files += links

        if session.args.files:
            output.empty()
            output.norm("Searching for common files (this will take a few minutes)...")

            with Spinner():
                try:
                    links, results = file_search.find_files(session.url)
                except Exception as error:
                    output.debug_exception()
                    output.error(f"Error running scan: {str(error)}")
                    results = None
                    links = None

            if results is not None and len(results) > 0:
                reporter.display_results(results, "\t")

            if links is not None and len(links) > 0:
                new_files += links

                for l in links:
                    if l not in orig_links:
                        output.norm(f"\tNew file found: {l}")

                output.empty()

    if path_good:
        links, results = special_files.check_special_paths(session.url)

        if len(results) > 0:
            reporter.display_results(results, "\t")

            new_files += links

        if session.args.dir:
            output.empty()
            output.norm(
                "Searching for common directories (this will take a few minutes)..."
            )

            with Spinner():
                try:
                    links, results = file_search.find_directories(
                        session.url,
                        session.args.dirlistredir,
                        session.args.dirrecursive,
                    )
                except Exception as error:
                    output.debug_exception()
                    output.error(f"Error running scan: {str(error)}")
                    results = None
                    links = None

            if results is not None and len(results) > 0:
                reporter.display_results(results, "\t")

            if links is not None and len(links) > 0:
                new_files += links

                for l in links:
                    if l not in orig_links:
                        output.norm(f"\tNew directory found: {l}")

                output.empty()

    return new_files
