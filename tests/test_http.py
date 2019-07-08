from unittest import TestCase

import requests
import requests_mock

from yawast.scanner.plugins.http import http_basic, response_scanner
from yawast.scanner.plugins.http.response_scanner import _check_cache_headers
from yawast.scanner.plugins.http.servers import rails
from yawast.shared import network


class TestHttpBasic(TestCase):
    def test_get_header_issues_no_sec_headers(self):
        url = "http://example.com"

        with requests_mock.Mocker(real_http=True) as m:
            m.get(url, text="body")

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        self.assertEqual(7, len(res))

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
                },
            )

            resp = requests.get(url)

        res = http_basic.get_header_issues(
            resp, network.http_build_raw_response(resp), url
        )

        self.assertEqual(0, len(res))

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

        self.assertEqual(1, len(res))
        self.assertIn("X-Powered-By Header Present", res[0].message)

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

        self.assertEqual(1, len(res))
        self.assertIn("X-XSS-Protection Disabled Header Present", res[0].message)

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

        self.assertEqual(1, len(res))
        self.assertIn("X-Runtime Header Present", res[0].message)

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

        self.assertEqual(1, len(res))
        self.assertIn("X-Backend-Server Header Present", res[0].message)

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

        self.assertEqual(1, len(res))
        self.assertIn("Via Header Present", res[0].message)

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

        self.assertEqual(1, len(res))
        self.assertIn("X-Frame-Options Header", res[0].message)

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

        self.assertEqual(1, len(res))
        self.assertIn("Access-Control-Allow-Origin: Unrestricted", res[0].message)

    def test_check_propfind_none_err(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("PROPFIND", url, text="body", status_code=500)

            res = http_basic.check_propfind(url)

        for r in res:
            self.assertNotIn("PROPFIND Enabled", r.message)

    def test_check_propfind_none_ok(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("PROPFIND", url, text="body", status_code=200)

            res = http_basic.check_propfind(url)

        for r in res:
            self.assertNotIn("PROPFIND Enabled", r.message)

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

        self.assertTrue(any("PROPFIND Enabled" in r.message for r in res))

    def test_check_trace_none_err(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("TRACE", url, text="body", status_code=500)

            res = http_basic.check_trace(url)

        for r in res:
            self.assertNotIn("HTTP TRACE Enabled", r.message)

    def test_check_trace_none_ok(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("TRACE", url, text="body", status_code=200)

            res = http_basic.check_trace(url)

        for r in res:
            self.assertNotIn("HTTP TRACE Enabled", r.message)

    def test_check_trace(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("TRACE", url, text="TRACE / HTTP/1.1", status_code=200)

            res = http_basic.check_trace(url)

        self.assertTrue(any("HTTP TRACE Enabled" in r.message for r in res))

    def test_check_opts_none_err(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("OPTIONS", url, status_code=500)

            res = http_basic.check_options(url)

        for r in res:
            self.assertNotIn("HTTP Verbs (OPTIONS)", r.message)

    def test_check_opts_none_ok(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("OPTIONS", url, status_code=200)

            res = http_basic.check_options(url)

        for r in res:
            self.assertNotIn("HTTP Verbs (OPTIONS)", r.message)

    def test_check_opts_allow(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("OPTIONS", url, status_code=200, headers={"Allow": "GET"})

            res = http_basic.check_options(url)

        self.assertTrue(any("Allow HTTP Verbs (OPTIONS)" in r.message for r in res))

    def test_check_opts_public(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.register_uri("OPTIONS", url, status_code=200, headers={"Public": "GET"})

            res = http_basic.check_options(url)

        self.assertTrue(any("Public HTTP Verbs (OPTIONS)" in r.message for r in res))

    def test_cache_headers_none(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.get(url, text="body", headers={})

            resp = requests.get(url)

        res = _check_cache_headers(url, resp)

        self.assertTrue(any("Cache-Control Header Not Found" in r.message for r in res))
        self.assertTrue(any("Expires Header Not Found" in r.message for r in res))
        self.assertTrue(any("Pragma: no-cache Not Found" in r.message for r in res))

    def test_cache_headers_expires(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.get(url, text="body", headers={"Expires": "1"})

            resp = requests.get(url)

        res = _check_cache_headers(url, resp)

        self.assertFalse(any("Expires Header Not Found" in r.message for r in res))

    def test_cache_headers_pragma(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.get(url, text="body", headers={"Pragma": "no-cache"})

            resp = requests.get(url)

        res = _check_cache_headers(url, resp)

        self.assertFalse(any("Pragma: no-cache Not Found" in r.message for r in res))

    def test_cache_headers_cc_public(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.get(url, text="body", headers={"Cache-Control": "Public"})

            resp = requests.get(url)

        res = _check_cache_headers(url, resp)

        self.assertTrue(any("Cache-Control: Public" in r.message for r in res))
        self.assertTrue(
            any("Cache-Control: no-cache Not Found" in r.message for r in res)
        )
        self.assertTrue(
            any("Cache-Control: no-store Not Found" in r.message for r in res)
        )
        self.assertTrue(
            any("Cache-Control: private Not Found" in r.message for r in res)
        )

    def test_cache_headers_cc_private(self):
        url = "http://example.com"

        with requests_mock.Mocker() as m:
            m.get(url, text="body", headers={"Cache-Control": "Private"})

            resp = requests.get(url)

        res = _check_cache_headers(url, resp)

        self.assertTrue(
            any("Cache-Control: no-cache Not Found" in r.message for r in res)
        )
        self.assertTrue(
            any("Cache-Control: no-store Not Found" in r.message for r in res)
        )

    def test_response_scanner(self):
        network.init("", "")
        url = "https://adamcaudill.com/"
        resp = network.http_get(url)

        res = response_scanner.check_response(url, resp)

        self.assertTrue(any("External JavaScript File" in r.message for r in res))
        self.assertTrue(any("Vulnerable JavaScript" in r.message for r in res))

    def test_rails_cve_2019_5418_none(self):
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(url, text="body")

            rails.reset()
            res = rails.check_cve_2019_5418(url)

        self.assertFalse(any("Rails CVE-2019-5418" in r.message for r in res))

    def test_rails_cve_2019_5418(self):
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(url, text="root:x:0:0:root:/root:/bin/bash")

            rails.reset()
            res = rails.check_cve_2019_5418(url)

        self.assertTrue(any("Rails CVE-2019-5418" in r.message for r in res))

    def test_rails_cve_2019_5418_fp(self):
        url = "http://example.com/"

        with requests_mock.Mocker() as m:
            m.get(url, text="root: File")

            rails.reset()
            res = rails.check_cve_2019_5418(url)

        self.assertFalse(any("Rails CVE-2019-5418" in r.message for r in res))
