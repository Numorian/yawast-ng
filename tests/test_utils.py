import unittest

from yawast.shared.utils import fix_relative_link


class TestFixRelativeLink(unittest.TestCase):
    def setUp(self):
        self.base_url = "http://example.com/path/page.html"
        self.base_url_https = "https://example.com:8080/path/page.html"

    def test_absolute_url(self):
        href = "http://other.com/test"
        self.assertEqual(fix_relative_link(href, self.base_url), href)

    def test_protocol_relative_url(self):
        href = "//cdn.example.com/lib.js"
        expected = "http://cdn.example.com/lib.js"
        self.assertEqual(fix_relative_link(href, self.base_url), expected)

        href = "//cdn.example.com/lib.js"
        expected = "https://cdn.example.com/lib.js"
        self.assertEqual(fix_relative_link(href, self.base_url_https), expected)

    def test_leading_slash(self):
        href = "/images/logo.png"
        expected = "http://example.com/images/logo.png"
        self.assertEqual(fix_relative_link(href, self.base_url), expected)

    def test_dot_slash(self):
        href = "./about.html"
        expected = "http://example.com/path/about.html"
        self.assertEqual(fix_relative_link(href, self.base_url), expected)

    def test_double_dot_slash(self):
        href = "../contact.html"
        expected = "http://example.com/contact.html"
        self.assertEqual(fix_relative_link(href, self.base_url), expected)

    def test_relative_filename(self):
        href = "file.txt"
        expected = "http://example.com/path/file.txt"
        self.assertEqual(fix_relative_link(href, self.base_url), expected)

    def test_already_full_url(self):
        href = "https://another.com/test"
        self.assertEqual(fix_relative_link(href, self.base_url), href)

    def test_edge_case_empty_href(self):
        href = ""
        expected = self.base_url
        self.assertEqual(fix_relative_link(href, self.base_url), expected)
