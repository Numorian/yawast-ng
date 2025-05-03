import pytest
from bs4 import BeautifulSoup

from yawast.scanner.modules.http.helpers import is_unsafe_form, is_unsafe_link


def make_form(html):
    return BeautifulSoup(html, "html.parser")


def test_is_unsafe_form_detects_reset_button():
    html = (
        """<form><input type="text" name="foo"><button>Reset Password</button></form>"""
    )
    soup = make_form(html)
    assert is_unsafe_form(soup, "foo")


def test_is_unsafe_form_detects_delete_submit():
    html = """<form><input type="text" name="bar"><input type="submit" value="Delete"></form>"""
    soup = make_form(html)
    assert is_unsafe_form(soup, "bar")


def test_is_unsafe_form_detects_change_password():
    html = """<form><input type="text" name="baz"><button>Change Password</button></form>"""
    soup = make_form(html)
    assert is_unsafe_form(soup, "baz")


def test_is_unsafe_form_detects_reset_type():
    html = (
        """<form><input type="text" name="qux"><input type="reset" value="Go"></form>"""
    )
    soup = make_form(html)
    assert is_unsafe_form(soup, "qux")


def test_is_unsafe_form_safe_form():
    html = """<form><input type="text" name="safe"><input type="submit" value="Submit"></form>"""
    soup = make_form(html)
    assert not is_unsafe_form(soup, "safe")


def test_is_unsafe_form_detects_password_field():
    html = """<form><input type="text" name="user"><input type="password" name="pass"></form>"""
    soup = make_form(html)
    assert is_unsafe_form(soup, "user")
    assert is_unsafe_form(soup, "pass")


def test_is_unsafe_link_detects():
    assert is_unsafe_link("/logout", "logout") is True
    assert is_unsafe_link("/foo", "delete") is True
    assert is_unsafe_link("/foo", "destroy") is True
    assert is_unsafe_link("/logoff", "") is True
    assert is_unsafe_link("/foo", "log out") is True
    assert is_unsafe_link("/foo", "log_off") is True
    assert is_unsafe_link("/foo", "log out") is True
    assert is_unsafe_link("/foo", "log_out") is True


def test_is_unsafe_link_exception():
    class Bad:
        def __str__(self):
            raise Exception("fail")

    # Should not raise, should return False
    assert is_unsafe_link("/foo", Bad()) is False
