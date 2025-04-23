#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.
import os
from pathlib import Path

import pytest
import requests
import requests_mock
from bs4 import BeautifulSoup

from tests import utils
from yawast import command_line
from yawast.scanner.cli import http
from yawast.scanner.modules.http import file_search, http_basic, response_scanner
from yawast.scanner.modules.http.applications import jira, wordpress
from yawast.scanner.modules.http.response_scanner import _check_cache_headers
from yawast.scanner.modules.http.servers import (
    apache_tomcat,
    iis,
    nginx,
    php,
    python,
    rails,
)
from yawast.scanner.modules.http.special_files import (
    check_special_files,
    check_special_paths,
)
from yawast.scanner.modules.http.spider import spider
from yawast.scanner.modules.http.waf import get_waf
from yawast.scanner.session import Session
from yawast.shared import network, output


class TestHttpBasic:
    def test_get_header_issues_no_sec_headers(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(url, text="body")

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        assert len(res) == 7

    def test_get_header_issues_none(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="body",
                headers={
                    "X-XSS-Protection": "1",
                    "X-Frame-Options": "blah",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "blah",
                    "Referrer-Policy": "blah",
                    "Feature-Policy": "blah",
                    "Strict-Transport-Security": "blah",
                    "Server": "blah",
                    "X-Olaf": "⛄",
                },
            )

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        assert len(res) == 0

    def test_get_header_issues_dup_header(self):
        network.init("", "", "")
        output.setup(False, False, False)

        # we are using www.tumblr.com as they return multiple vary header
        url = "https://www.tumblr.com"

        output.setup(False, True, True)
        with utils.capture_sys_output() as (stdout, stderr):
            resp = requests.get(url)
            results = http_basic.get_header_issues(
                resp, network.http_build_raw_response(resp), url
            )

        assert results is not None
        assert len(results) > 0
        assert "Exception" not in stderr.getvalue()
        assert "Error" not in stdout.getvalue()
        assert any(
            "set multiple times with different values" in r.message for r in results
        )

    def test_get_header_issues_powered_by(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="body",
                headers={
                    "X-XSS-Protection": "1",
                    "X-Frame-Options": "blah",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "blah",
                    "Referrer-Policy": "blah",
                    "Feature-Policy": "blah",
                    "Strict-Transport-Security": "blah",
                    "X-Powered-By": "blah",
                },
            )

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        assert len(res) == 1
        assert "X-Powered-By Header Present" in res[0].message

    def test_get_header_issues_xss(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="body",
                headers={
                    "X-XSS-Protection": "0",
                    "X-Frame-Options": "blah",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "blah",
                    "Referrer-Policy": "blah",
                    "Feature-Policy": "blah",
                    "Strict-Transport-Security": "blah",
                },
            )

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        assert len(res) == 1
        assert "X-XSS-Protection Disabled Header Present" in res[0].message

    def test_get_header_issues_runtime(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="body",
                headers={
                    "X-XSS-Protection": "1",
                    "X-Frame-Options": "blah",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "blah",
                    "Referrer-Policy": "blah",
                    "Feature-Policy": "blah",
                    "Strict-Transport-Security": "blah",
                    "X-Runtime": "1",
                },
            )

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        assert len(res) == 1
        assert "X-Runtime Header Present" in res[0].message

    def test_get_header_issues_backend(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="body",
                headers={
                    "X-XSS-Protection": "1",
                    "X-Frame-Options": "blah",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "blah",
                    "Referrer-Policy": "blah",
                    "Feature-Policy": "blah",
                    "Strict-Transport-Security": "blah",
                    "X-Backend-Server": "1",
                },
            )

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        assert len(res) == 1
        assert "X-Backend-Server Header Present" in res[0].message

    def test_get_header_issues_via(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="body",
                headers={
                    "X-XSS-Protection": "1",
                    "X-Frame-Options": "blah",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "blah",
                    "Referrer-Policy": "blah",
                    "Feature-Policy": "blah",
                    "Strict-Transport-Security": "blah",
                    "Via": "1",
                },
            )

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        assert len(res) == 1
        assert "Via Header Present" in res[0].message

    def test_get_header_issues_xfa(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="body",
                headers={
                    "X-XSS-Protection": "1",
                    "X-Frame-Options": "allow",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "blah",
                    "Referrer-Policy": "blah",
                    "Feature-Policy": "blah",
                    "Strict-Transport-Security": "blah",
                },
            )

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        assert len(res) == 1
        assert "X-Frame-Options Header" in res[0].message

    def test_get_header_issues_acao(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(
                url,
                text="body",
                headers={
                    "X-XSS-Protection": "1",
                    "X-Frame-Options": "blah",
                    "X-Content-Type-Options": "nosniff",
                    "Content-Security-Policy": "blah",
                    "Referrer-Policy": "blah",
                    "Feature-Policy": "blah",
                    "Strict-Transport-Security": "blah",
                    "Access-Control-Allow-Origin": "*",
                },
            )

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        assert len(res) == 1
        assert "Access-Control-Allow-Origin: Unrestricted" in res[0].message

    def test_check_propfind_none_err(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("PROPFIND", url, text="body", status_code=500)

            res = http_basic.check_propfind(url)

        for r in res:
            assert "PROPFIND Enabled" not in r.message

    def test_check_propfind_none_ok(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("PROPFIND", url, text="body", status_code=200)

            res = http_basic.check_propfind(url)

        for r in res:
            assert "PROPFIND Enabled" not in r.message

    def test_check_propfind(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri(
                "PROPFIND",
                url,
                text="body",
                status_code=200,
                headers={"Content-Type": "text/xml"},
            )

            res = http_basic.check_propfind(url)

        assert any("PROPFIND Enabled" in r.message for r in res)

    def test_check_trace_none_err(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("TRACE", url, text="body", status_code=500)

            res = http_basic.check_trace(url)

        for r in res:
            assert "HTTP TRACE Enabled" not in r.message

    def test_check_trace_none_ok(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("TRACE", url, text="body", status_code=200)

            res = http_basic.check_trace(url)

        for r in res:
            assert "HTTP TRACE Enabled" not in r.message

    def test_check_trace(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("TRACE", url, text="TRACE / HTTP/1.1", status_code=200)

            res = http_basic.check_trace(url)

        assert any("HTTP TRACE Enabled" in r.message for r in res)

    def test_check_opts_none_err(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("OPTIONS", url, status_code=500)

            res = http_basic.check_options(url)

        for r in res:
            assert "HTTP Verbs (OPTIONS)" not in r.message

    def test_check_opts_none_ok(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("OPTIONS", url, status_code=200)

            res = http_basic.check_options(url)

        for r in res:
            assert "HTTP Verbs (OPTIONS)" not in r.message

    def test_check_opts_allow(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("OPTIONS", url, status_code=200, headers={"Allow": "GET"})

            res = http_basic.check_options(url)

        assert any("Allow HTTP Verbs (OPTIONS)" in r.message for r in res)

    def test_check_opts_public(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("OPTIONS", url, status_code=200, headers={"Public": "GET"})

            res = http_basic.check_options(url)

        assert any("Public HTTP Verbs (OPTIONS)" in r.message for r in res)

    def test_cache_headers_none(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.get(url, text="body", headers={})

            resp = requests.get(url)

        res = _check_cache_headers(url, resp)

        assert any("Cache-Control Header Not Found" in r.message for r in res)
        assert any("Expires Header Not Found" in r.message for r in res)
        assert any("Pragma: no-cache Not Found" in r.message for r in res)

    def test_cache_headers_expires_invalid(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.get(url, text="body", headers={"Expires": "1"})

            resp = requests.get(url)

        res = _check_cache_headers(url, resp)

        assert not any("Expires Header Not Found" in r.message for r in res)

    def test_cache_headers_expires_future(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.get(
                url,
                text="body",
                headers={"Expires": "Expires: Wed, 21 Oct 2099 07:28:00 GMT"},
            )

            resp = requests.get(url)

        res = _check_cache_headers(url, resp)

        assert not any("Expires Header Not Found" in r.message for r in res)
        assert any("Expires Header - Future Dated" in r.message for r in res)

    def test_cache_headers_expires_past(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.get(
                url,
                text="body",
                headers={"Expires": "Expires: Wed, 21 Oct 2015 07:28:00 GMT"},
            )

            resp = requests.get(url)

        res = _check_cache_headers(url, resp)

        assert not any("Expires Header Not Found" in r.message for r in res)
        assert not any("Expires Header - Future Dated" in r.message for r in res)

    def test_cache_headers_pragma(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.get(url, text="body", headers={"Pragma": "no-cache"})

            resp = requests.get(url)

        res = _check_cache_headers(url, resp)

        assert not any("Pragma: no-cache Not Found" in r.message for r in res)

    def test_cache_headers_cc_public(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.get(url, text="body", headers={"Cache-Control": "Public"})

            resp = requests.get(url)

        res = _check_cache_headers(url, resp)

        assert any("Cache-Control: Public" in r.message for r in res)
        assert any("Cache-Control: no-cache Not Found" in r.message for r in res)
        assert any("Cache-Control: no-store Not Found" in r.message for r in res)
        assert any("Cache-Control: private Not Found" in r.message for r in res)

    def test_cache_headers_cc_private(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.get(url, text="body", headers={"Cache-Control": "Private"})

            resp = requests.get(url)

        res = _check_cache_headers(url, resp)

        assert any("Cache-Control: no-cache Not Found" in r.message for r in res)
        assert any("Cache-Control: no-store Not Found" in r.message for r in res)

    def test_response_scanner_vuln(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/files/EchoLoginForm"
        resp = network.http_get(url)

        http.reset()
        res = response_scanner.check_response(url, resp)

        assert any("Vulnerable JavaScript" in r.message for r in res)

    def test_response_scanner_ext(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"
        resp = network.http_get(url)

        http.reset()
        res = response_scanner.check_response(url, resp)

        assert any("External JavaScript File" in r.message for r in res)

    def test_rails_cve_2019_5418_none(self):
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(url, text="body")

            rails.reset()
            res = rails.check_cve_2019_5418(url)

        assert not any("Rails CVE-2019-5418" in r.message for r in res)

    def test_rails_cve_2019_5418(self):
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(url, text="root:x:0:0:root:/root:/bin/bash")

            rails.reset()
            res = rails.check_cve_2019_5418(url)

        assert any("Rails CVE-2019-5418" in r.message for r in res)

    def test_rails_cve_2019_5418_fp(self):
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(url, text="root: File")

            rails.reset()
            res = rails.check_cve_2019_5418(url)

        assert not any("Rails CVE-2019-5418" in r.message for r in res)

    def test_python_check_banner(self):
        res = python.check_banner("Python/3.0.3", "head_data", "http://example.com")

        assert any("Python Version Exposed" in r.message for r in res)

    def test_nginx_check_banner_gen(self):
        res = nginx.check_banner("nginx", "head_data", "http://example.com")

        assert any("Generic Nginx Server Banner Found" in r.message for r in res)

    def test_nginx_check_banner(self):
        res = nginx.check_banner("nginx/1.0.0", "head_data", "http://example.com")

        assert any("Nginx Version Exposed" in r.message for r in res)

    def test_nginx_check_banner_outdated(self):
        res = nginx.check_banner("nginx/1.0.0", "head_data", "http://example.com")

        assert any("Nginx Outdated" in r.message for r in res)

    def test_wp_path_disc_nix(self):
        network.init("", "", "")
        output.setup(False, False, False)
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(requests_mock.ANY, status_code=404)
            m.head(requests_mock.ANY, status_code=404)
            m.get(
                f"{url}wp-content/plugins/akismet/akismet.php",
                text="<b>Fatal error</b>:  x y() in <b>/home/akismet.php</b> on line <b>32</b><br />",
                status_code=500,
            )
            m.head(f"{url}wp-content/plugins/akismet/akismet.php", status_code=500)

            res = wordpress.check_path_disclosure(url)

        assert any("WordPress File Path Disclosure" in r.message for r in res)
        assert any("/home/akismet.php" in r.message for r in res)

    def test_wp_path_disc_win(self):
        network.init("", "", "")
        output.setup(False, False, False)
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(requests_mock.ANY, status_code=404)
            m.head(requests_mock.ANY, status_code=404)
            m.get(
                f"{url}wp-content/plugins/akismet/akismet.php",
                text="<b>Fatal error</b>:  x y() in <b>C:\\home\\akismet.php</b> on line <b>32</b><br />",
                status_code=500,
            )
            m.head(f"{url}wp-content/plugins/akismet/akismet.php", status_code=500)

            res = wordpress.check_path_disclosure(url)

        assert any("WordPress File Path Disclosure" in r.message for r in res)
        assert any("C:\\home\\akismet.php" in r.message for r in res)

    def test_wp_path_disc_none_err(self):
        network.init("", "", "")
        output.setup(False, False, False)
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(
                requests_mock.ANY,
                text="<b>Fatal error</b>:  x y() in /home/akismet.php on line 32",
            )
            m.head(requests_mock.ANY)

            res = wordpress.check_path_disclosure(url)

        assert not any("WordPress File Path Disclosure" in r.message for r in res)

    def test_wp_path_disc_none(self):
        network.init("", "", "")
        output.setup(False, False, False)
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(requests_mock.ANY, text="hello world")
            m.head(requests_mock.ANY)

            res = wordpress.check_path_disclosure(url)

        assert not any("WordPress File Path Disclosure" in r.message for r in res)

    def test_php_find_info(self):
        network.init("", "", "")
        output.setup(False, False, False)
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(requests_mock.ANY, status_code=404)
            m.head(requests_mock.ANY, status_code=404)
            m.get(f"{url}phpinfo.php", text='</a><h1 class="p">PHP Version 4.4.1</h1>')
            m.head(f"{url}phpinfo.php", status_code=200)

            res = php.find_phpinfo([url])

        assert any("PHP Info Found" in r.message for r in res)

    def test_php_find_info_none(self):
        network.init("", "", "")
        output.setup(False, False, False)
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(requests_mock.ANY, status_code=404)
            m.head(requests_mock.ANY, status_code=404)
            m.get(
                f"{url}phpinfo.php",
                text="</a><h1>PHP Version 4.4.1</h1>",
                status_code=500,
            )
            m.head(f"{url}phpinfo.php", status_code=200)

            res = php.find_phpinfo([url])

        assert not any("PHP Info Found" in r.message for r in res)

    def test_check_404(self):
        network.init("", "", "X-Test=123")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(requests_mock.ANY, text="body", status_code=200)
                m.head(requests_mock.ANY, status_code=200)

                try:
                    file, _, _, _ = network.check_404_response(url)
                except Exception as error:
                    assert error is None

            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_check_put(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.put(requests_mock.ANY, text="body", status_code=200)

                try:
                    res = network.http_put(url, "data")
                except Exception as error:
                    assert error is None

            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()
            assert res is not None

    def test_wp_ident(self):
        network.init("", "", "")
        url = "https://underscores.me/wp/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            try:
                _, res = wordpress.identify(url)
            except Exception as error:
                assert error is None

            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()
            assert any("Found WordPress" in r.message for r in res)

    def test_wp_json_user_enum(self):
        network.init("", "", "")
        url = "https://underscores.me/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            try:
                res = wordpress.check_json_user_enum(url)
            except Exception as error:
                assert error is None

            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()
            assert any("WordPress WP-JSON User Enumeration" in r.message for r in res)

    def test_find_backup_ext(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            try:
                http.reset()
                _, _ = file_search.find_backups(
                    [url, f"{url}readme.html", f"{url}#test"]
                )
            except Exception as error:
                assert error is None

            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_find_backup_ext_all(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(requests_mock.ANY, text="not found", status_code=404)
                m.get(f"{url}test/readme.html", text="body", status_code=200)
                m.get(f"{url}test/readme.html~", text="body", status_code=200)
                m.head(requests_mock.ANY, status_code=404)
                m.head(f"{url}test/readme.html", status_code=200)
                m.head(f"{url}test/readme.html~", status_code=200)

                try:
                    http.reset()
                    _, res = file_search.find_backups([url, f"{url}test/readme.html"])
                except Exception as error:
                    assert error is None

            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()
            assert any("Found backup file" in r.message for r in res)

    def test_net_init_empty(self):
        try:
            network.init("", "", "")
        except Exception as error:
            assert error is None

        assert network._requester is not None

        network.reset()

    def test_net_init_none(self):
        try:
            network.init(None, None, None)
        except Exception as error:
            assert error is None

        assert network._requester is not None

        network.reset()

    def test_net_init_valid_proxy(self):
        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                network.init("http://127.0.0.1:1234", "", "")
        except Exception as error:
            assert error is None

        assert network._requester is not None
        assert "Exception" not in stderr.getvalue()
        assert "Error" not in stdout.getvalue()
        assert "Invalid proxy server specified" not in stdout.getvalue()

        network.reset()

    def test_net_init_valid_proxy_alt(self):
        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                network.init("127.0.0.1:1234", "", "")
        except Exception as error:
            assert error is None

        assert network._requester is not None
        assert "Exception" not in stderr.getvalue()
        assert "Error" not in stdout.getvalue()
        assert "Invalid proxy server specified" not in stdout.getvalue()

        network.reset()

    def test_net_init_invalid_proxy_ftp(self):
        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                network.init("ftp://127.0.0.1:1234", "", "")

                _ = network.http_get("http://example.com")
        except Exception as error:
            assert error is None

        assert network._requester is not None
        assert "Exception" not in stderr.getvalue()
        assert "Error" in stdout.getvalue()
        assert "Invalid proxy server specified" in stdout.getvalue()

        network.reset()

    def test_net_init_valid_cookie(self):
        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                network.init("", "SESSION=123", "")

                _ = network.http_get("http://example.com")
        except Exception as error:
            assert error is None

        assert network._requester is not None
        assert "Exception" not in stderr.getvalue()
        assert "Error" not in stdout.getvalue()
        assert "cookie must be in NAME=VALUE format" not in stdout.getvalue()

        network.reset()

    def test_net_init_two_valid_cookie(self):
        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                network.init("", "SESSION=123;C=456", "")

                _ = network.http_get("http://example.com")
        except Exception as error:
            assert error is None

        assert network._requester is not None
        assert "Exception" not in stderr.getvalue()
        assert "Error" not in stdout.getvalue()
        assert "cookie must be in NAME=VALUE format" not in stdout.getvalue()

        network.reset()

    def test_net_init_invalid_cookie(self):
        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                network.init("", "SESSION123", "")

                _ = network.http_get("http://example.com")
        except Exception as error:
            assert error is None

        assert network._requester is not None
        assert "Exception" not in stderr.getvalue()
        assert "Error" in stdout.getvalue()
        assert "cookie must be in NAME=VALUE format" in stdout.getvalue()

        network.reset()

    def test_net_init_valid_header(self):
        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                network.init("", "", "AUTH=123")

                _ = network.http_get("http://example.com")
        except Exception as error:
            assert error is None

        assert network._requester is not None
        assert "Exception" not in stderr.getvalue()
        assert "Error" not in stdout.getvalue()
        assert "header must be in NAME=VALUE format" not in stdout.getvalue()

        network.reset()

    def test_net_init_valid_header_alt(self):
        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                network.init("", "", "AUTH: 123")

                _ = network.http_get("http://example.com")
        except Exception as error:
            assert error is None

        assert network._requester is not None
        assert "Exception" not in stderr.getvalue()
        assert "Error" not in stdout.getvalue()
        assert "header must be in NAME=VALUE format" not in stdout.getvalue()

        network.reset()

    def test_net_init_invalid_header(self):
        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                network.init("", "", "AUTH123")

                _ = network.http_get("http://example.com")
        except Exception as error:
            assert error is None

        assert network._requester is not None
        assert "Exception" not in stderr.getvalue()
        assert "Error" in stdout.getvalue()
        assert "header must be in NAME=VALUE format" in stdout.getvalue()

        network.reset()

    def test_jira_found(self):
        url = "https://www.example.org/"

        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/jira_dashboard.txt")
        contents = Path(path).read_text()

        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                with requests_mock.Mocker() as m:
                    m.get(url, text="body", status_code=200)
                    m.get(f"{url}secure/Dashboard.jspa", text=contents, status_code=200)
                    m.get(
                        f"{url}jira/secure/Dashboard.jspa", text="body", status_code=404
                    )

                    session = Session(None, url)

                    results, jira_url = jira.check_for_jira(session)
        except Exception as error:
            assert error is None

        assert jira_url is not None
        assert results is not None
        assert len(results) > 0
        assert "Exception" not in stderr.getvalue()
        assert "Error" not in stdout.getvalue()
        assert any("Jira Installation Found" in r.message for r in results)
        assert any("v8.1.0-801000" in r.message for r in results)

        network.reset()

    def test_jira_user_reg(self):
        url = "https://www.example.org/secure/Dashboard.jspa"

        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/jira_registration.txt")
        contents = Path(path).read_text()

        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                with requests_mock.Mocker() as m:
                    m.get(
                        "https://www.example.org/secure/Signup!default.jspa",
                        text=contents,
                        status_code=200,
                    )

                    results = jira.check_jira_user_registration(url)
        except Exception as error:
            assert error is None

        assert results is not None
        assert len(results) > 0
        assert "Exception" not in stderr.getvalue()
        assert "Error" not in stdout.getvalue()
        assert any("Jira User Registration Enabled" in r.message for r in results)

        network.reset()

    def test_ds_store(self):
        url = "https://www.example.org/"

        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                with requests_mock.Mocker() as m:
                    m.get(requests_mock.ANY, status_code=404)
                    m.head(requests_mock.ANY, status_code=404)
                    m.get(f"{url}.DS_Store", content=b"\0\0\0\1Bud1\0", status_code=200)
                    m.head(f"{url}.DS_Store", status_code=200)

                    results = file_search.find_ds_store([url])
        except Exception as error:
            assert error is None

        assert results is not None
        assert len(results) > 0
        assert "Exception" not in stderr.getvalue()
        assert "Error" not in stdout.getvalue()
        assert any(".DS_Store File Found" in r.message for r in results)

        network.reset()

    def test_cve_2019_11043_false(self):
        network.init("", "", "")
        output.setup(False, False, False)
        url = "https://www.example.org/"

        p = command_line.build_parser()
        ns = p.parse_args(args=["scan"])
        s = Session(ns, url)

        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                with requests_mock.Mocker() as m:
                    m.get(requests_mock.ANY, status_code=200)
                    m.head(requests_mock.ANY, status_code=200)

                    results = php.check_cve_2019_11043(
                        s, ["https://www.example.org/test/"]
                    )
        except Exception as error:
            assert error is None

        assert results is not None
        assert len(results) == 0
        assert "Exception" not in stderr.getvalue()
        assert "Error" not in stdout.getvalue()

        network.reset()

    def test_telerik_rau_enabled(self):
        network.init("", "", "")
        output.setup(False, False, False)
        url = "https://www.example.org/"

        try:
            output.setup(False, True, True)
            with utils.capture_sys_output() as (stdout, stderr):
                with requests_mock.Mocker() as m:
                    m.get(
                        url=url,
                        text='<html><body><script src="/Telerik.Web.UI.WebResource.axd'
                        '?_ABC=1" type="text/javascript"></script></body></html>',
                    )
                    m.get(
                        url=f"{url}Telerik.Web.UI.WebResource.axd?type=rau",
                        text='{ "message" : "RadAsyncUpload handler is registered succesfully, '
                        'however, it may not be accessed directly." }',
                    )

                    res = network.http_get(url)
                    body = res.text
                    soup = BeautifulSoup(body, "html.parser")

                    results = iis.check_telerik_rau_enabled(soup, url)
        except Exception as error:
            assert error is None

        assert results is not None
        assert "Exception" not in stderr.getvalue()
        assert "Error" not in stdout.getvalue()
        assert any(
            "Telerik UI for ASP.NET AJAX RadAsyncUpload Enabled" in r.message
            for r in results
        )

        network.reset()

    def test_spider_single(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"
        session = Session(None, url)

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(
                    requests_mock.ANY,
                    text="<html><body><p>body</p></body></html>",
                    status_code=200,
                )
                m.head(requests_mock.ANY, status_code=200)

                try:
                    links, res = spider(session)
                except Exception as error:
                    assert error is None

            assert res is not None
            assert links is not None
            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_spider_link(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"
        session = Session(None, url)

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(
                    requests_mock.ANY,
                    text="<html><body><p><a href='/'>link</a></p></body></html>",
                    status_code=200,
                )
                m.head(requests_mock.ANY, status_code=200)

                try:
                    links, res = spider(session)
                except Exception as error:
                    assert error is None

            assert res is not None
            assert links is not None
            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_spider_logout(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"
        session = Session(None, url)

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(
                    requests_mock.ANY,
                    text="<html><body><p><a href='/'>logout</a></p></body></html>",
                    status_code=200,
                )
                m.head(requests_mock.ANY, status_code=200)

                try:
                    links, res = spider(session)
                except Exception as error:
                    assert error is None

            assert res is not None
            assert links is not None
            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_spider_jpg(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"
        session = Session(None, url)

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(
                    requests_mock.ANY,
                    text="<html><body><p><a href='/file.jpg'>jpg</a></p></body></html>",
                    status_code=200,
                )
                m.get(f"{url}file.jpg", content=b"\0\0\0", status_code=200)
                m.head(requests_mock.ANY, status_code=200)

                try:
                    links, res = spider(session)
                except Exception as error:
                    assert error is None

            assert res is not None
            assert links is not None
            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_spider_insecure(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"
        session = Session(None, url)

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(
                    requests_mock.ANY,
                    text="<html><body><p><a href='http://example.com/'>insecure</a></p></body></html>",
                    status_code=200,
                )
                m.head(requests_mock.ANY, status_code=200)

                try:
                    links, res = spider(session)
                except Exception as error:
                    assert error is None

            assert res is not None
            assert links is not None
            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_spider_redirect(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"
        session = Session(None, url)

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(
                    requests_mock.ANY,
                    text="<html><body><p><a href='/redirect/'>redirect</a></p></body></html>",
                    status_code=200,
                )
                m.get(f"{url}redirect/", status_code=301, headers={"Location": "/"})
                m.head(requests_mock.ANY, status_code=200)
                m.head(f"{url}redirect/", status_code=301, headers={"Location": "/"})

                try:
                    links, res = spider(session)
                except Exception as error:
                    assert error is None

            assert res is not None
            assert links is not None
            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_special_files(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(requests_mock.ANY, text="not found", status_code=404)
                m.get(f"{url}license.txt", status_code=200, text="license")
                m.head(requests_mock.ANY, status_code=404)
                m.head(f"{url}license.txt", status_code=200)

                try:
                    links, res = check_special_files(url)
                except Exception as error:
                    assert error is None

            assert res is not None
            assert links is not None
            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_special_paths(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(requests_mock.ANY, text="not found", status_code=404)
                m.get(f"{url}.git/index", status_code=200, text="git")
                m.head(requests_mock.ANY, status_code=404)
                m.head(f"{url}.git/index", status_code=200)

                try:
                    links, res = check_special_paths(url)
                except Exception as error:
                    assert error is None

            assert res is not None
            assert links is not None
            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_waf_cloudflare(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(
                    requests_mock.ANY,
                    text="not found",
                    status_code=404,
                    headers={"Server": "cloudflare"},
                )
                m.head(
                    requests_mock.ANY, status_code=404, headers={"Server": "cloudflare"}
                )

                try:
                    head = network.http_head(url)
                    raw = network.http_build_raw_response(head)
                    res = get_waf(head.headers, raw, url)
                except Exception as error:
                    assert error is None

            assert res is not None
            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_waf_incapsula(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(
                    requests_mock.ANY,
                    text="not found",
                    status_code=404,
                    headers={"X-CDN": "123"},
                )
                m.head(requests_mock.ANY, status_code=404, headers={"X-CDN": "123"})

                try:
                    head = network.http_head(url)
                    raw = network.http_build_raw_response(head)
                    res = get_waf(head.headers, raw, url)
                except Exception as error:
                    assert error is None

            assert res is not None
            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_404_all_200(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(requests_mock.ANY, text="body", status_code=200)
                m.head(requests_mock.ANY, status_code=200)

                try:
                    _, _ = network.http_file_exists(url)
                except Exception as error:
                    assert error is None

            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_404_redirect(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(requests_mock.ANY, status_code=301, headers={"Location": "/"})
                m.head(requests_mock.ANY, status_code=301, headers={"Location": "/"})

                try:
                    _, _ = network.http_file_exists(url)
                except Exception as error:
                    assert error is None

            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_404_bad_head(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(requests_mock.ANY, text="body", status_code=404)
                m.head(requests_mock.ANY, status_code=500)

                try:
                    _, _ = network.http_file_exists(url)
                except Exception as error:
                    assert error is None

            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_404_all_401(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(requests_mock.ANY, text="body", status_code=401)
                m.head(requests_mock.ANY, status_code=401)

                try:
                    _, _ = network.http_file_exists(url)
                except Exception as error:
                    assert error is None

            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_404_all_500(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(requests_mock.ANY, text="body", status_code=500)
                m.head(requests_mock.ANY, status_code=500)

                try:
                    _, _ = network.http_file_exists(url)
                except Exception as error:
                    assert error is None

            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_404_all_200_bin(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(requests_mock.ANY, text="body", status_code=200)
                m.head(requests_mock.ANY, status_code=200)
                m.get(url, content=b"\0\0\0\1\2\3\4", status_code=200)

                try:
                    _, _ = network.http_file_exists(url)
                except Exception as error:
                    assert error is None

            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_404_all_200_bin_all(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(requests_mock.ANY, content=b"\0\0\0\1\2\3\4", status_code=200)
                m.head(requests_mock.ANY, status_code=200)
                m.get(url, content=b"\0\0\0\1\2\3\5", status_code=200)

                try:
                    _, _ = network.http_file_exists(url)
                except Exception as error:
                    assert error is None

            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_404_all_200_diff(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(requests_mock.ANY, text="body", status_code=200)
                m.head(requests_mock.ANY, status_code=200)
                m.get(url, text="this is different", status_code=200)

                try:
                    _, _ = network.http_file_exists(url)
                except Exception as error:
                    assert error is None

            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_404_similar(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(requests_mock.ANY, text="Error", status_code=200)
                m.head(requests_mock.ANY, status_code=200)
                m.get(url, text="Error1", status_code=200)

                try:
                    _, _ = network.http_file_exists(url)
                except Exception as error:
                    assert error is None

            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_tomcat_version(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(requests_mock.ANY, text="body", status_code=500)
                m.post(requests_mock.ANY, text="body", status_code=500)
                m.head(requests_mock.ANY, status_code=500)

                try:
                    res = apache_tomcat.check_version(url)
                except Exception as error:
                    assert error is None

            assert res is not None
            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_http_methods_good(self):
        network.init("", "", "")
        url = "https://adamcaudill.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.register_uri(requests_mock.ANY, requests_mock.ANY, status_code=405)
                m.get(requests_mock.ANY, text="body", status_code=200)
                m.post(requests_mock.ANY, text="body", status_code=200)
                m.head(requests_mock.ANY, status_code=200)

                try:
                    methods, res = http_basic.check_http_methods(url)
                except Exception as error:
                    assert error is None

            assert res is not None
            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()

    def test_hsts_preload_status_false(self):
        network.init("", "", "")
        url = "https://www.google.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            try:
                res = http_basic.check_hsts_preload(url)
            except Exception as error:
                assert error is None

        assert len(res) == 1
        assert "Exception" not in stderr.getvalue()
        assert "Error" not in stderr.getvalue()

    def test_hsts_preload_status_true(self):
        network.init("", "", "")
        url = "https://garron.net/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            try:
                res = http_basic.check_hsts_preload(url)
            except Exception as error:
                assert error is None

        assert len(res) == 1
        assert "Exception" not in stderr.getvalue()
        assert "Error" not in stderr.getvalue()
