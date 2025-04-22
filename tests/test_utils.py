import pytest

from yawast.shared.utils import fix_relative_link


class TestUtils:
    @pytest.fixture
    def base_url(self):
        return "http://example.com/path/page.html"

    @pytest.fixture
    def base_url_https(self):
        return "https://example.com:8080/path/page.html"

    def test_absolute_url(self, base_url):
        href = "http://other.com/test"
        assert fix_relative_link(href, base_url) == href

    def test_protocol_relative_url(self, base_url, base_url_https):
        href = "//cdn.example.com/lib.js"
        expected = "http://cdn.example.com/lib.js"
        assert fix_relative_link(href, base_url) == expected

        href = "//cdn.example.com/lib.js"
        expected = "https://cdn.example.com/lib.js"
        assert fix_relative_link(href, base_url_https) == expected

    def test_leading_slash(self, base_url):
        href = "/images/logo.png"
        expected = "http://example.com/images/logo.png"
        assert fix_relative_link(href, base_url) == expected

    def test_dot_slash(self, base_url):
        href = "./about.html"
        expected = "http://example.com/path/about.html"
        assert fix_relative_link(href, base_url) == expected

    def test_double_dot_slash(self, base_url):
        href = "../contact.html"
        expected = "http://example.com/contact.html"
        assert fix_relative_link(href, base_url) == expected

    def test_relative_filename(self, base_url):
        href = "file.txt"
        expected = "http://example.com/path/file.txt"
        assert fix_relative_link(href, base_url) == expected

    def test_already_full_url(self, base_url):
        href = "https://another.com/test"
        assert fix_relative_link(href, base_url) == href

    def test_edge_case_empty_href(self, base_url):
        href = ""
        expected = base_url
        assert fix_relative_link(href, base_url) == expected
