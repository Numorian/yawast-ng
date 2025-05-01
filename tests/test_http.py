#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
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

        with requests_mock.Mocker() as m:
            m.get(url, text="body")

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        assert len(res) == 7

    def test_get_header_issues_none(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
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

    def test_find_duplicate_headers(self):
        from yawast.scanner.modules.http.http_basic import find_duplicate_headers

        # Simulate raw HTTP headers with duplicates
        raw = (
            "X-Test: foo\n"
            "Vary: Accept-Encoding\n"
            "Vary: Cookie\n"
            "X-Test: foo\n"  # same value, not a duplicate
            "X-Test: bar\n"  # different value, should be flagged
            "Set-Cookie: a=1\n"
            "Set-Cookie: b=2\n"  # allowed duplicate
            "Link: <a>\n"
            "Link: <b>\n"  # allowed duplicate
        )
        dups = find_duplicate_headers(raw)
        assert "vary" in dups
        assert "x-test" in dups
        assert "set-cookie" not in dups
        assert "link" not in dups

    def test_get_header_issues_powered_by(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
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

        with requests_mock.Mocker() as m:
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

        with requests_mock.Mocker() as m:
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

        with requests_mock.Mocker() as m:
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

        with requests_mock.Mocker() as m:
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

        with requests_mock.Mocker() as m:
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

        with requests_mock.Mocker() as m:
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
        url = "https://example.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                m.get(
                    url,
                    text="<html></html>",
                    status_code=200,
                )
                # Simulate wp-login.php in both root and blog/ subdir
                for path in ["", "blog/"]:
                    m.get(
                        f"{url}{path}wp-login.php",
                        text="<html><head><link rel='stylesheet' href='wp-admin/css/login.min.css?ver=6.0'></head><body>Powered by WordPress</body></html>",
                        status_code=200,
                    )
                try:
                    _, res = wordpress.identify(url)
                except Exception as error:
                    assert error is None

            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()
            messages = [r.message for r in res]
            if not any("Found WordPress" in msg for msg in messages):
                raise AssertionError(f"Result messages: {messages}")
            assert any("Found WordPress" in msg for msg in messages)

    def test_wp_json_user_enum(self):
        network.init("", "", "")
        url = "https://example.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            with requests_mock.Mocker() as m:
                # Simulate a WordPress REST API user enumeration response
                api_url = f"{url}wp-json/wp/v2/users"
                m.get(
                    api_url,
                    json=[{"id": 1, "name": "admin", "slug": "admin"}],
                    status_code=200,
                )
                m.head(api_url, status_code=200)
                # Simulate the main site root (may be checked for JSON API presence)
                m.get(url, text="", status_code=200)
                m.head(url, status_code=200)
                try:
                    res = wordpress.check_json_user_enum(url)
                except Exception as error:
                    assert error is None

            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()
            messages = [r.message for r in res]
            if not any("WP-JSON User Enumeration" in msg for msg in messages):
                raise AssertionError(f"Result messages: {messages}")
            assert any("WP-JSON User Enumeration" in msg for msg in messages)

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

    def test_get_cookie_issues_flags(self):
        # Covers missing/invalid flags and SameSite logic
        from yawast.scanner.modules.http.http_basic import (
            _get_cookie_issues,
            get_cookie_issues,
            reset,
        )

        class DummyRes:
            headers = {"Set-Cookie": "a=1; Secure; HttpOnly; SameSite=None"}
            raw = type(
                "raw",
                (),
                {
                    "headers": type(
                        "headers",
                        (),
                        {
                            "getlist": lambda self, k: [
                                "a=1; Secure; HttpOnly; SameSite=None",
                                "b=2",
                            ]
                        },
                    )()
                },
            )()

        reset()
        # HTTPS, all flags present
        res = DummyRes()
        out = get_cookie_issues(res, "https://example.com")
        assert isinstance(out, list)
        # HTTP, missing Secure, SameSite, HttpOnly
        cookies = ["b=2"]
        out2 = _get_cookie_issues(cookies, "http://example.com", res)
        assert isinstance(out2, list)

    def test_decode_big_ip_cookie(self, monkeypatch):
        from yawast.scanner.modules.http import http_basic

        # Patch utils.is_private_ip to always return True
        monkeypatch.setattr("yawast.shared.utils.is_private_ip", lambda ip: True)
        # IPv4 pattern
        val = "2263487148.3013.0000"
        assert http_basic._decode_big_ip_cookie(val) is not None
        # IPv4 rd pattern
        val2 = "rd5o00000000000000000000ffffc0000201o80"
        assert http_basic._decode_big_ip_cookie(val2) is not None
        # IPv6 vi pattern
        val3 = "vi20010112000000000000000000000030.20480"
        assert http_basic._decode_big_ip_cookie(val3) is not None
        # IPv6 rd pattern
        val4 = "rd3o20010112000000000000000000000030o80"
        assert http_basic._decode_big_ip_cookie(val4) is not None
        # Non-matching
        assert http_basic._decode_big_ip_cookie("notamatch") is None

    def test_check_local_ip_disclosure(self, monkeypatch):
        from types import SimpleNamespace

        from yawast.scanner.modules.http import http_basic

        # Mock session
        session = SimpleNamespace()
        session.url = "https://example.com"
        session.url_parsed = SimpleNamespace(scheme="https")
        session.supports_http = False
        # Patch utils.get_port, get_domain
        monkeypatch.setattr("yawast.shared.utils.get_port", lambda url: 443)
        monkeypatch.setattr("yawast.shared.utils.get_domain", lambda url: "example.com")

        # Patch socket and ssl
        class DummyConn:
            def sendall(self, data):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                pass

        class DummyResp:
            version = 11
            code = 302
            reason = "Found"
            headers = {"Location": "http://10.0.0.1/"}

            def getheader(self, k):
                return self.headers.get(k)

        class DummyParser:
            @staticmethod
            def parse_from_socket(con):
                return DummyResp()

        monkeypatch.setattr(
            "yawast.external.http_response_from_socket.HttpResponseParser", DummyParser
        )

        # Patch ssl.create_default_context
        class DummySSLContext:
            check_hostname = False
            verify_mode = None

            def wrap_socket(self, sock, server_hostname=None):
                return DummyConn()

        monkeypatch.setattr("ssl.create_default_context", lambda: DummySSLContext())
        # Patch socket.create_connection
        monkeypatch.setattr("socket.create_connection", lambda addr: DummyConn())
        # Patch output.debug_exception
        monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
        # Patch Result
        monkeypatch.setattr(
            "yawast.reporting.result.Result",
            lambda *a, **k: SimpleNamespace(message=a[0]),
        )
        # Patch Vln
        monkeypatch.setattr(
            "yawast.reporting.enums.Vulnerabilities",
            SimpleNamespace(SERVER_INT_IP_EXP_HTTP10="vuln"),
        )
        results = http_basic.check_local_ip_disclosure(session)
        assert isinstance(results, list)

    def test_get_header_issues_exception(self, monkeypatch):
        from yawast.scanner.modules.http import http_basic

        class DummyRes:
            headers = {}
            raw = type("raw", (), {"_original_response": None})()

        # Patch Evidence.from_response to raise
        monkeypatch.setattr(
            "yawast.reporting.evidence.Evidence.from_response",
            lambda *a, **k: (_ for _ in ()).throw(Exception("fail")),
        )
        monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
        out = http_basic.get_header_issues(DummyRes(), "", "http://example.com")
        assert out == []

    def test_check_http_methods_early_return(self, monkeypatch):
        from yawast.scanner.modules.http import http_basic

        # Patch network.http_custom to return a response with status_code < 405
        class DummyRes:
            status_code = 200

        monkeypatch.setattr(
            "yawast.shared.network.http_custom", lambda *a, **k: DummyRes()
        )
        monkeypatch.setattr(
            "yawast.scanner.modules.http.response_scanner.check_response",
            lambda url, res: ["checked"],
        )
        methods, results = http_basic.check_http_methods("http://example.com")
        assert methods == []
        assert results == ["checked"]

    def test_check_http_methods_file_path(self, monkeypatch, tmp_path):
        from yawast.scanner.modules.http import http_basic

        # Create a temp file with HTTP methods
        file_path = tmp_path / "methods.txt"
        file_path.write_text("GET\nPOST\n")

        # Patch network.http_custom to return status_code < 405 for GET, >= 405 for POST
        class DummyRes:
            def __init__(self, code):
                self.status_code = code

        def http_custom(method, url):
            return DummyRes(200 if method == "GET" else 405)

        monkeypatch.setattr("yawast.shared.network.http_custom", http_custom)
        monkeypatch.setattr(
            "yawast.scanner.modules.http.response_scanner.check_response",
            lambda url, res: [],
        )
        methods, _ = http_basic.check_http_methods("http://example.com", str(file_path))
        assert "GET" in methods and "POST" not in methods

    def test_check_hsts_preload_exception(self, monkeypatch):
        from yawast.scanner.modules.http import http_basic

        monkeypatch.setattr(
            "yawast.shared.utils.get_domain",
            lambda url: (_ for _ in ()).throw(Exception("fail")),
        )
        monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
        out = http_basic.check_hsts_preload("http://example.com")
        assert out == []

    def test_check_local_ip_disclosure_http_branch(self, monkeypatch):
        from types import SimpleNamespace

        from yawast.scanner.modules.http import http_basic

        session = SimpleNamespace()
        session.url = "http://example.com"
        session.url_parsed = SimpleNamespace(scheme="http")
        session.supports_http = True
        session.get_http_url = lambda: "http://example.com"
        monkeypatch.setattr("yawast.shared.utils.get_port", lambda url: 80)
        monkeypatch.setattr("yawast.shared.utils.get_domain", lambda url: "example.com")

        class DummyConn:
            def connect(self, addr):
                pass

            def sendall(self, data):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                pass

        class DummyResp:
            version = 11
            code = 302
            reason = "Found"
            headers = {"Location": "http://10.0.0.1/"}

            def getheader(self, k):
                return self.headers.get(k)

        class DummyParser:
            @staticmethod
            def parse_from_socket(con):
                return DummyResp()

        monkeypatch.setattr(
            "yawast.external.http_response_from_socket.HttpResponseParser", DummyParser
        )
        monkeypatch.setattr("socket.socket", lambda *a, **k: DummyConn())
        monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
        monkeypatch.setattr(
            "yawast.reporting.result.Result",
            lambda *a, **k: SimpleNamespace(message=a[0]),
        )
        monkeypatch.setattr(
            "yawast.reporting.enums.Vulnerabilities",
            SimpleNamespace(SERVER_INT_IP_EXP_HTTP10="vuln"),
        )
        results = http_basic.check_local_ip_disclosure(session)
        assert isinstance(results, list)

    def test_check_local_ip_disclosure_exception(self, monkeypatch):
        from types import SimpleNamespace

        from yawast.scanner.modules.http import http_basic

        session = SimpleNamespace()
        session.url = "https://example.com"
        session.url_parsed = SimpleNamespace(scheme="https")
        session.supports_http = False
        monkeypatch.setattr("yawast.shared.utils.get_port", lambda url: 443)
        monkeypatch.setattr("yawast.shared.utils.get_domain", lambda url: "example.com")

        class DummyConn:
            def sendall(self, data):
                raise Exception("fail")

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                pass

        class DummyParser:
            @staticmethod
            def parse_from_socket(con):
                return None

        monkeypatch.setattr(
            "yawast.external.http_response_from_socket.HttpResponseParser", DummyParser
        )

        class DummySSLContext:
            check_hostname = False
            verify_mode = None

            def wrap_socket(self, sock, server_hostname=None):
                return DummyConn()

        monkeypatch.setattr("ssl.create_default_context", lambda: DummySSLContext())
        monkeypatch.setattr("socket.create_connection", lambda addr: DummyConn())
        monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
        monkeypatch.setattr(
            "yawast.reporting.result.Result",
            lambda *a, **k: SimpleNamespace(message=a[0]),
        )
        monkeypatch.setattr(
            "yawast.reporting.enums.Vulnerabilities",
            SimpleNamespace(SERVER_INT_IP_EXP_HTTP10="vuln"),
        )
        results = http_basic.check_local_ip_disclosure(session)
        assert isinstance(results, list)

    def test__get_cookie_issues_exception(self, monkeypatch):
        from yawast.scanner.modules.http import http_basic

        monkeypatch.setattr(
            "yawast.reporting.enums.Vulnerabilities",
            type(
                "V",
                (),
                {
                    "COOKIE_MISSING_SECURE_FLAG": "a",
                    "COOKIE_INVALID_SECURE_FLAG": "b",
                    "COOKIE_MISSING_HTTPONLY_FLAG": "c",
                    "COOKIE_MISSING_SAMESITE_FLAG": "d",
                    "COOKIE_WITH_SAMESITE_NONE_FLAG": "e",
                    "COOKIE_INVALID_SAMESITE_NONE_FLAG": "f",
                    "COOKIE_BIGIP_IP_DISCLOSURE": "g",
                },
            )(),
        )
        monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
        # Simulate urlparse raising
        import builtins

        orig_urlparse = __import__("urllib.parse").parse.urlparse
        monkeypatch.setattr(
            "urllib.parse.urlparse",
            lambda url: (_ for _ in ()).throw(Exception("fail")),
        )
        out = http_basic._get_cookie_issues(["a=1"], "http://example.com", None)
        assert out == []
        monkeypatch.setattr("urllib.parse.urlparse", orig_urlparse)

    def test_get_header_issues_duplicate_headers(self, monkeypatch):
        from yawast.scanner.modules.http import http_basic

        class DummyOriginalResponse:
            headers = "X-Test: foo\nX-Test: bar\n"

        class DummyRaw:
            _original_response = DummyOriginalResponse()

        class DummyRes:
            headers = {
                "X-XSS-Protection": "1",
                "X-Frame-Options": "blah",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "blah",
                "Referrer-Policy": "blah",
                "Feature-Policy": "blah",
                "Strict-Transport-Security": "blah",
                "Server": "blah",
            }
            raw = DummyRaw()

        monkeypatch.setattr(
            "yawast.scanner.modules.http.http_basic.find_duplicate_headers",
            lambda raw: ["x-test"],
        )
        monkeypatch.setattr(
            "yawast.reporting.evidence.Evidence.from_response",
            lambda *a, **k: type("Ev", (), {})(),
        )
        monkeypatch.setattr(
            "yawast.reporting.result.Result.from_evidence",
            lambda *a, **k: type("R", (), {"message": "dup"})(),
        )
        monkeypatch.setattr(
            "yawast.scanner.modules.http.servers.apache_httpd.check_banner",
            lambda *a, **k: [],
        )
        monkeypatch.setattr(
            "yawast.scanner.modules.http.servers.nginx.check_banner", lambda *a, **k: []
        )
        monkeypatch.setattr(
            "yawast.scanner.modules.http.servers.iis.check_version", lambda *a, **k: []
        )
        monkeypatch.setattr(
            "yawast.scanner.modules.http.servers.python.check_banner",
            lambda *a, **k: [],
        )
        out = http_basic.get_header_issues(DummyRes(), "", "http://example.com")
        assert any("dup" in r.message for r in out)

    def test_decode_big_ip_cookie_not_private(self, monkeypatch):
        from yawast.scanner.modules.http import http_basic

        monkeypatch.setattr("yawast.shared.utils.is_private_ip", lambda ip: False)
        # Should return None for all patterns
        assert http_basic._decode_big_ip_cookie("2263487148.3013.0000") is None
        assert (
            http_basic._decode_big_ip_cookie("rd5o00000000000000000000ffffc0000201o80")
            is None
        )
        assert (
            http_basic._decode_big_ip_cookie("vi20010112000000000000000000000030.20480")
            is None
        )
        assert (
            http_basic._decode_big_ip_cookie("rd3o20010112000000000000000000000030o80")
            is None
        )

    def test_check_local_ip_disclosure_no_private_found(self, monkeypatch):
        from types import SimpleNamespace

        from yawast.scanner.modules.http import http_basic

        session = SimpleNamespace()
        session.url = "https://example.com"
        session.url_parsed = SimpleNamespace(scheme="https")
        session.supports_http = True
        session.get_http_url = lambda: "http://example.com"
        monkeypatch.setattr(
            "yawast.shared.utils.get_port",
            lambda url: 443 if url.startswith("https") else 80,
        )
        monkeypatch.setattr("yawast.shared.utils.get_domain", lambda url: "example.com")

        class DummyConn:
            def sendall(self, data):
                pass

            def connect(self, addr):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                pass

        class DummyResp:
            version = 11
            code = 302
            reason = "Found"
            headers = {"Location": "http://8.8.8.8/"}  # Not private

            def getheader(self, k):
                return self.headers.get(k)

        class DummyParser:
            @staticmethod
            def parse_from_socket(con):
                return DummyResp()

        monkeypatch.setattr(
            "yawast.external.http_response_from_socket.HttpResponseParser", DummyParser
        )
        monkeypatch.setattr(
            "ssl.create_default_context",
            lambda: type(
                "C",
                (),
                {
                    "check_hostname": False,
                    "verify_mode": None,
                    "wrap_socket": lambda self, sock, server_hostname=None: DummyConn(),
                },
            )(),
        )
        monkeypatch.setattr("socket.create_connection", lambda addr: DummyConn())
        monkeypatch.setattr("socket.socket", lambda *a, **k: DummyConn())
        monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
        monkeypatch.setattr(
            "yawast.reporting.result.Result",
            lambda *a, **k: SimpleNamespace(message=a[0]),
        )
        monkeypatch.setattr(
            "yawast.reporting.enums.Vulnerabilities",
            SimpleNamespace(SERVER_INT_IP_EXP_HTTP10="vuln"),
        )
        monkeypatch.setattr("yawast.shared.utils.is_ip", lambda ip: True)
        monkeypatch.setattr("yawast.shared.utils.is_private_ip", lambda ip: False)
        results = http_basic.check_local_ip_disclosure(session)
        assert results == []

    def test__get_cookie_issues_bigip_not_match(self, monkeypatch):
        from yawast.scanner.modules.http import http_basic

        monkeypatch.setattr(
            "yawast.reporting.enums.Vulnerabilities",
            type(
                "V",
                (),
                {
                    "COOKIE_MISSING_SECURE_FLAG": "a",
                    "COOKIE_INVALID_SECURE_FLAG": "b",
                    "COOKIE_MISSING_HTTPONLY_FLAG": "c",
                    "COOKIE_MISSING_SAMESITE_FLAG": "d",
                    "COOKIE_WITH_SAMESITE_NONE_FLAG": "e",
                    "COOKIE_INVALID_SAMESITE_NONE_FLAG": "f",
                    "COOKIE_BIGIP_IP_DISCLOSURE": "g",
                },
            )(),
        )
        monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
        monkeypatch.setattr("yawast.shared.utils.is_private_ip", lambda ip: True)
        # Should not add a result if pattern doesn't match
        out = http_basic._get_cookie_issues(
            ["BIGipServerWEB=notamatch"], "https://example.com", type("R", (), {})()
        )
        assert out is not None

    def test_get_server_banner_issues_all(self, monkeypatch):
        from yawast.scanner.modules.http import http_basic

        # Patch all check_banner/check_version to return unique results
        monkeypatch.setattr(
            "yawast.scanner.modules.http.servers.apache_httpd.check_banner",
            lambda *a, **k: ["apache"],
        )
        monkeypatch.setattr(
            "yawast.scanner.modules.http.servers.nginx.check_banner",
            lambda *a, **k: ["nginx"],
        )
        monkeypatch.setattr(
            "yawast.scanner.modules.http.servers.iis.check_version",
            lambda *a, **k: ["iis"],
        )
        monkeypatch.setattr(
            "yawast.scanner.modules.http.servers.python.check_banner",
            lambda *a, **k: ["python"],
        )
        out = http_basic.get_server_banner_issues("server", "raw", "url", {})
        assert set(out) == {"apache", "nginx", "iis", "python"}

    def test_check_propfind_exception(self, monkeypatch):
        import pytest

        from yawast.scanner.modules.http import http_basic

        monkeypatch.setattr(
            "yawast.shared.network.http_custom",
            lambda *a, **k: (_ for _ in ()).throw(Exception("fail")),
        )
        monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
        with pytest.raises(Exception):
            http_basic.check_propfind("http://example.com")

    def test_check_trace_exception(self, monkeypatch):
        import pytest

        from yawast.scanner.modules.http import http_basic

        monkeypatch.setattr(
            "yawast.shared.network.http_custom",
            lambda *a, **k: (_ for _ in ()).throw(Exception("fail")),
        )
        monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
        with pytest.raises(Exception):
            http_basic.check_trace("http://example.com")

    def test_check_options_exception(self, monkeypatch):
        import pytest

        from yawast.scanner.modules.http import http_basic

        monkeypatch.setattr(
            "yawast.shared.network.http_options",
            lambda *a, **k: (_ for _ in ()).throw(Exception("fail")),
        )
        monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
        with pytest.raises(Exception):
            http_basic.check_options("http://example.com")

    def test_check_http_methods_file_exception(self, monkeypatch):
        import pytest

        from yawast.scanner.modules.http import http_basic

        class DummyRes:
            status_code = 405

        monkeypatch.setattr(
            "yawast.shared.network.http_custom", lambda *a, **k: DummyRes()
        )
        monkeypatch.setattr(
            "yawast.scanner.modules.http.response_scanner.check_response",
            lambda url, res: [],
        )
        # Patch open to raise
        import builtins

        orig_open = builtins.open
        monkeypatch.setattr(
            "builtins.open", lambda *a, **k: (_ for _ in ()).throw(Exception("fail"))
        )
        with pytest.raises(Exception):
            http_basic.check_http_methods(
                "http://example.com", path="/tmp/doesnotexist.txt"
            )
        monkeypatch.setattr("builtins.open", orig_open)
