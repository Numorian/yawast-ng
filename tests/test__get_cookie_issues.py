from unittest import TestCase

import requests
import requests_mock

from yawast.scanner.plugins.http import http_basic
from yawast.scanner.plugins.http.http_basic import get_cookie_issues


class TestGetCookieIssues(TestCase):
    def test__get_cookie_issues_no_sec_no_tls(self):
        http_basic.reset()

        with requests_mock.Mocker() as m:
            url = "http://example.com"
            m.get(
                url,
                text="body",
                headers={
                    "Set-Cookie": "sessionid=38afes7a8; HttpOnly; SameSite=Lax; Path=/"
                },
            )

            resp = requests.get(url)

            res = get_cookie_issues(resp, url)

            self.assertEqual(0, len(res))

    def test__get_cookie_issues_sec_no_tls(self):
        http_basic.reset()

        with requests_mock.Mocker() as m:
            url = "http://example.com"
            m.get(
                url,
                text="body",
                headers={
                    "Set-Cookie": "sessionid=38afes7a8; HttpOnly; Secure; SameSite=Lax; Path=/"
                },
            )

            resp = requests.get(url)

            res = get_cookie_issues(resp, url)

            self.assertEqual(1, len(res))
            self.assertIn("Cookie Secure Flag Invalid (over HTTP)", res[0].message)

    def test__get_cookie_issues_no_sec_no_tls_ssn(self):
        http_basic.reset()

        with requests_mock.Mocker() as m:
            url = "https://example.com"
            m.get(
                url,
                text="body",
                headers={
                    "Set-Cookie": "sessionid=38afes7a8; HttpOnly; SameSite=None; Path=/"
                },
            )

            resp = requests.get(url)

            res = get_cookie_issues(resp, url)

            self.assertEqual(2, len(res))
            self.assertIn("Cookie Missing Secure Flag", res[0].message)
            self.assertIn(
                "Cookie SameSite=None Flag Invalid (without Secure flag)",
                res[1].message,
            )

    def test__get_cookie_issues_no_sec(self):
        http_basic.reset()

        with requests_mock.Mocker() as m:
            url = "https://example.com"
            m.get(
                url,
                text="body",
                headers={
                    "Set-Cookie": "sessionid=38afes7a8; HttpOnly; SameSite=Lax; Path=/"
                },
            )

            resp = requests.get(url)

            res = get_cookie_issues(resp, url)

            self.assertEqual(1, len(res))
            self.assertIn("Cookie Missing Secure Flag", res[0].message)

    def test__get_cookie_issues_no_ho(self):
        http_basic.reset()

        with requests_mock.Mocker() as m:
            url = "http://example.com"
            m.get(
                url,
                text="body",
                headers={"Set-Cookie": "sessionid=38afes7a8; SameSite=Lax; Path=/"},
            )

            resp = requests.get(url)

            res = get_cookie_issues(resp, url)

            self.assertEqual(1, len(res))
            self.assertIn("Cookie Missing HttpOnly Flag", res[0].message)

    def test__get_cookie_issues_no_ss(self):
        http_basic.reset()

        with requests_mock.Mocker() as m:
            url = "https://example.com"
            m.get(
                url,
                text="body",
                headers={"Set-Cookie": "sessionid=38afes7a8; Secure; HttpOnly; Path=/"},
            )

            resp = requests.get(url)

            res = get_cookie_issues(resp, url)

            self.assertEqual(1, len(res))
            self.assertIn("Cookie Missing SameSite Flag", res[0].message)
