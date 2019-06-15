from unittest import TestCase
from yawast.scanner.plugins.http.http_basic import _get_cookie_issues


class TestGetCookieIssues(TestCase):
    def test__get_cookie_issues_no_sec_no_tls(self):
        res = _get_cookie_issues(
            ["sessionid=38afes7a8; HttpOnly; SameSite=Lax; Path=/"],
            "<raw-data>",
            "http://adamcaudill.com",
        )

        self.assertEqual(0, len(res))

    def test__get_cookie_issues_no_sec_no_tls_ssn(self):
        res = _get_cookie_issues(
            ["sessionid=38afes7a8; HttpOnly; SameSite=None; Path=/"],
            "<raw-data>",
            "https://adamcaudill.com",
        )

        self.assertEqual(2, len(res))
        self.assertIn("Cookie Missing Secure Flag", res[0].message)
        self.assertIn(
            "Cookie SameSite=None Flag Invalid (without Secure flag)", res[1].message
        )

    def test__get_cookie_issues_no_sec(self):
        res = _get_cookie_issues(
            ["sessionid=38afes7a8; HttpOnly; SameSite=Lax; Path=/"],
            "<raw-data>",
            "https://adamcaudill.com",
        )

        self.assertEqual(1, len(res))
        self.assertIn("Cookie Missing Secure Flag", res[0].message)

    def test__get_cookie_issues_no_ho(self):
        res = _get_cookie_issues(
            ["sessionid=38afes7a8; Secure; SameSite=Lax; Path=/"],
            "<raw-data>",
            "http://adamcaudill.com",
        )

        self.assertEqual(1, len(res))
        self.assertIn("Cookie Missing HttpOnly Flag", res[0].message)

    def test__get_cookie_issues_no_ss(self):
        res = _get_cookie_issues(
            ["sessionid=38afes7a8; Secure; HttpOnly; Path=/"],
            "<raw-data>",
            "http://adamcaudill.com",
        )

        self.assertEqual(1, len(res))
        self.assertIn("Cookie Missing SameSite Flag", res[0].message)
