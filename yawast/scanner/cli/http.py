#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

from typing import List, Optional, Union

from selenium.common.exceptions import WebDriverException

from yawast.external.spinner import Spinner
from yawast.reporting import reporter
from yawast.reporting.enums import Vulnerabilities
from yawast.reporting.evidence import Evidence
from yawast.reporting.issue import Issue
from yawast.reporting.result import Result
from yawast.scanner.modules.http import (
    error_checker,
    file_search,
    generic_login,
    http_basic,
    response_scanner,
    retirejs,
    special_files,
    spider,
    waf,
)
from yawast.scanner.modules.http.applications import jira, wordpress
from yawast.scanner.modules.http.applications.generic import password_reset
from yawast.scanner.modules.http.applications.generic.password_reset import (
    PasswordResetElementNotFound,
)
from yawast.scanner.modules.http.servers import (
    apache_httpd,
    apache_tomcat,
    iis,
    nginx,
    php,
)
from yawast.scanner.plugins import plugin_manager
from yawast.scanner.session import Session
from yawast.shared import network, output, utils


def scan(session: Session):
    reporter.register_data("url", session.url)
    reporter.register_data("domain", session.domain)

    # start by attempting to login, if we have credentials
    if session.args.user is not None and session.args.password is not None:
        try:
            output.norm("\tAttempting to login...")
            tokens = generic_login.login_and_get_auth(
                session.url, session.args.user, session.args.password
            )

            if tokens["error"] is not None and len(tokens["error"]) > 0:
                output.warn(f"Potential login failure: {tokens['error']}")

            network.update_auth(tokens)
            output.norm(f"\tLogin completed.")
            output.empty()
        except generic_login.LoginFormNotFound as error:
            output.warn(
                "Unable to find a known login form. Please report this issue: "
                "https://github.com/Numorian/yawast-ng/issues"
            )
        except Exception as error:
            output.debug_exception()
            output.error(f"Error performing login: {str(error)}")

    output.empty()
    output.norm("HEAD:")
    head = network.http_head(session.url)

    raw = network.http_build_raw_response(head)
    for line in raw.splitlines():
        output.norm(f"\t{line}")

    output.empty()

    res = http_basic.get_header_issues(head, raw, session.url)
    if res:
        output.norm("Header Issues:")

        reporter.display_results(res, "\t")
        output.empty()

    res = http_basic.get_cookie_issues(head, session.url)
    if res:
        output.norm("Cookie Issues:")

        reporter.display_results(res, "\t")
        output.empty()

    # check for WAF signatures
    res = waf.get_waf(head.headers, raw, session.url)
    if res:
        output.norm("WAF Detection:")

        reporter.display_results(res, "\t")
        output.empty()

    # check the HSTS preload status
    results = http_basic.check_hsts_preload(session.url)
    if len(results) > 0:
        reporter.register_data("hsts_preload_status", results)

        output.norm("HSTS Preload Status (Chromium):")
        for result in results:
            output.norm(
                f"\t({result['name']}) Status: {result['status']}; Preloaded Domain: {result['preloadedDomain']}"
            )
        output.empty()

    methods, res = http_basic.check_http_methods(session.url)
    if len(methods) == 0:
        output.norm("Server responds to invalid HTTP methods - check skipped.")
    else:
        reporter.register_data("http_methods_supported", methods)

        output.norm("Supported HTTP methods:")

        for method in methods:
            output.norm(f"\t{method}")

    output.empty()

    if res:
        reporter.display_results(res, "\t")
        output.empty()

    output.norm("Performing vulnerability scan (this will take a while)...")

    links: List[str] = []
    with Spinner():
        try:
            links, res = spider.spider(session)
        except Exception as error:
            output.debug_exception()
            output.error(f"Error running scan: {str(error)}")

    output.norm(f"Identified {len(links) + 1} pages.")
    output.empty()

    if res:
        output.norm("Issues Detected:")

        reporter.display_results(res, "\t")
        output.empty()

    # get files, and add those to the link list
    links += _file_search(session, links)

    # this doens't have the spinner, and is handled differently
    # because it's one of the rare places that we can be interactive
    if (
        session.args.pass_reset_page is not None
        and len(session.args.pass_reset_page) > 0
    ):
        _check_password_reset(session)

    with Spinner():
        res = http_basic.check_local_ip_disclosure(session)
    if res:
        reporter.display_results(res, "\t")

    with Spinner():
        res = apache_httpd.check_all(session.url)
    if res:
        reporter.display_results(res, "\t")

    with Spinner():
        res = apache_tomcat.check_all(session.url, links)
    if res:
        reporter.display_results(res, "\t")

    with Spinner():
        res = nginx.check_all(session.url)
    if res:
        reporter.display_results(res, "\t")

    with Spinner():
        res = iis.check_all(session.url)
    if res:
        reporter.display_results(res, "\t")

    with Spinner():
        res = http_basic.check_propfind(session.url)
    if res:
        reporter.display_results(res, "\t")

    with Spinner():
        res = http_basic.check_trace(session.url)
    if res:
        reporter.display_results(res, "\t")

    with Spinner():
        res = http_basic.check_options(session.url)
    if res:
        reporter.display_results(res, "\t")

    with Spinner():
        res = php.find_phpinfo(links)
    if res:
        reporter.display_results(res, "\t")

    if session.args.php_page is not None and len(session.args.php_page) > 0:
        with Spinner():
            res = php.check_cve_2019_11043(session, links)
        if res:
            reporter.display_results(res, "\t")

    with Spinner():
        res, jira_path = jira.check_for_jira(session)
    if res:
        reporter.display_results(res, "\t")

    if jira_path is not None:
        with Spinner():
            res = jira.check_jira_user_registration(jira_path)
        if res:
            reporter.display_results(res, "\t")

    with Spinner():
        wp_path, res = wordpress.identify(session.url)
    if res:
        reporter.display_results(res, "\t")

    if wp_path is not None:
        with Spinner():
            res = wordpress.check_json_user_enum(wp_path)
            res += wordpress.check_path_disclosure(wp_path)
        if res:
            reporter.display_results(res, "\t")

    # run the scanning plugins
    plugin_manager.run_http_scans(session.url)


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

    # check the 404 responses for any issues
    results = response_scanner.check_response(file_res.url, file_res)
    results += response_scanner.check_response(path_res.url, path_res)
    if results:
        reporter.display_results(results, "\t")

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
            "Site does not respond properly to non-existent file/path requests; search may take longer."
        )

    links, results = special_files.check_special_files(session.url)
    if results:
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

        if results is not None and results:
            reporter.display_results(results, "\t")

        if links is not None and links:
            new_files += links

            for l in links:
                if l not in orig_links:
                    output.norm(f"\tNew file found: {l}")

            output.empty()

    # check for common backup files
    all_links = orig_links + new_files
    with Spinner():
        backups, res = file_search.find_backups(all_links)
    if res:
        reporter.display_results(res, "\t")
    if backups:
        new_files += backups

    if path_good:
        links, results = special_files.check_special_paths(session.url)

        if results:
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

            if results is not None and results:
                reporter.display_results(results, "\t")

            if links is not None and links:
                new_files += links

                for l in links:
                    if l not in orig_links:
                        output.norm(f"\tNew directory found: {l}")

                output.empty()

    # check for .DS_Store files
    res = file_search.find_ds_store(new_files)

    if res:
        reporter.display_results(res, "\t")

    return new_files


def _check_password_reset(session: Session, element_name: Optional[str] = None):
    user = session.args.user
    if user is None:
        user = utils.prompt("What is a valid user? ")

    if user is None or len(user) == 0:
        # we don't have a valid user, so we can't do anything
        # as there's no path forward, we'll just return
        return

    try:
        with Spinner():
            res = password_reset.check_resp_user_enum(session, user, element_name)

        if res:
            reporter.display_results(res, "\t")
    except WebDriverException as e:
        output.error("Selenium error encountered: " + e.msg)
    except PasswordResetElementNotFound as e:
        if element_name is not None:
            # we failed to find the element, and we had one specified - this isn't going to work
            output.error(
                "Unable to find a matching element to perform the User Enumeration via Password Reset: "
                + str(e)
            )
        else:
            # we failed, because we don't have the element - so we prompt for it.
            print(
                "Unable to find a known element to enter the user name. Please identify the proper element."
            )
            print(
                "If this element seems to be common, please request that it be "
                "added: https://github.com/Numorian/yawast-ng/issues"
            )
            name = utils.prompt("What is the user/email entry element name? ")

            if name is None or len(name) == 0:
                # we don't have a valid element name, so we can't do anything
                # as there's no path forward, we'll just return
                return

            _check_password_reset(session, name)
    except Exception as e:
        output.error(
            "Failed to execute Password Reset Page User Enumeration: " + str(e)
        )
