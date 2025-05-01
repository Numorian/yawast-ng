import sys
from unittest import mock

import pytest

from yawast.commands import utils as cutils
from yawast.shared import utils


def make_session(scheme="http", url="http://example.com"):
    session = mock.Mock()
    session.url = url
    session.url_parsed.scheme = scheme
    session.supports_http = False
    session.supports_https = False
    session.redirects_https = False
    session.get_http_url.return_value = "http://example.com"
    return session


def test_check_redirect_http_tls_redirect():
    session = make_session("http", "http://example.com")
    with mock.patch(
        "yawast.shared.network.check_ssl_redirect", return_value="https://example.com"
    ) as check_ssl_redirect, mock.patch(
        "yawast.shared.network.check_www_redirect", return_value=None
    ), mock.patch.object(
        session, "update_url"
    ) as update_url, mock.patch(
        "builtins.print"
    ) as mprint:
        cutils.check_redirect(session)
        check_ssl_redirect.assert_called_once_with("http://example.com")
        update_url.assert_called_once_with("https://example.com")
        mprint.assert_any_call("Server redirects to TLS: Scanning: https://example.com")
        assert session.redirects_https is True


def test_check_redirect_http_no_redirect():
    session = make_session("http", "http://example.com")
    with mock.patch(
        "yawast.shared.network.check_ssl_redirect", return_value=None
    ), mock.patch(
        "yawast.shared.network.check_www_redirect", return_value=None
    ), mock.patch(
        "builtins.print"
    ) as mprint:
        cutils.check_redirect(session)
        mprint.assert_not_called()  # No print if no redirect


def test_check_redirect_http_ssl_redirect_exception_then_https_head_success():
    session = make_session("http", "http://example.com")
    with mock.patch(
        "yawast.shared.network.check_ssl_redirect", side_effect=Exception("fail")
    ), mock.patch(
        "yawast.shared.output.debug_exception"
    ) as debug_exc, mock.patch.object(
        session, "update_scheme"
    ) as update_scheme, mock.patch(
        "yawast.shared.network.http_head", return_value=True
    ), mock.patch(
        "yawast.shared.network.check_www_redirect", return_value=None
    ), mock.patch(
        "builtins.print"
    ) as mprint:
        cutils.check_redirect(session)
        debug_exc.assert_called()
        update_scheme.assert_called_once_with("https")
        assert session.supports_https is True
        assert session.supports_http is False
        mprint.assert_any_call("Server does not respond to HTTP, switching to HTTPS")
        mprint.assert_any_call(f"Scanning: {session.url}")


def test_check_redirect_http_ssl_redirect_exception_then_https_head_fails():
    session = make_session("http", "http://example.com")
    with mock.patch(
        "yawast.shared.network.check_ssl_redirect", side_effect=Exception("fail")
    ), mock.patch(
        "yawast.shared.output.debug_exception"
    ) as debug_exc, mock.patch.object(
        session, "update_scheme"
    ) as update_scheme, mock.patch(
        "yawast.shared.network.http_head", side_effect=Exception("fail2")
    ), mock.patch(
        "yawast.shared.network.check_www_redirect", return_value=None
    ), mock.patch(
        "builtins.print"
    ):
        with pytest.raises(ValueError) as exc:
            cutils.check_redirect(session)
        debug_exc.assert_called()
        update_scheme.assert_called_once_with("https")
        assert "Fatal Error: Can not connect to" in str(exc.value)


def test_check_redirect_https_head_success():
    session = make_session("https", "https://example.com")
    with mock.patch("yawast.shared.network.http_head", return_value=True), mock.patch(
        "yawast.shared.network.check_www_redirect", return_value=None
    ), mock.patch("builtins.print") as mprint:
        cutils.check_redirect(session)
        assert session.supports_https is True
        assert session.supports_http is True
        mprint.assert_any_call("Server responds to HTTP requests")


def test_check_redirect_https_head_fails():
    session = make_session("https", "https://example.com")
    with mock.patch(
        "yawast.shared.network.http_head", side_effect=Exception("fail")
    ), mock.patch("yawast.shared.output.debug_exception") as debug_exc, mock.patch(
        "yawast.shared.network.check_www_redirect", return_value=None
    ), mock.patch(
        "builtins.print"
    ) as mprint:
        cutils.check_redirect(session)
        debug_exc.assert_called()
        mprint.assert_any_call("Server does not respond to HTTP requests")


def test_check_redirect_www_redirect():
    session = make_session("http", "http://example.com")
    with mock.patch(
        "yawast.shared.network.check_ssl_redirect", return_value=None
    ), mock.patch(
        "yawast.shared.network.check_www_redirect",
        return_value="http://www.example.com",
    ) as check_www_redirect, mock.patch.object(
        session, "update_url"
    ) as update_url, mock.patch(
        "builtins.print"
    ) as mprint:
        cutils.check_redirect(session)
        check_www_redirect.assert_called_once_with("http://example.com")
        update_url.assert_called_once_with("http://www.example.com")
        mprint.assert_any_call(
            "Server performs WWW redirect: Scanning: http://www.example.com"
        )


def test_get_options_basic(monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["prog", "scan", "--injection", "--foo", "bar", "-x"]
    )
    opts = utils.get_options()
    assert "--injection" in opts
    assert "--foo" in opts
    assert "-x" in opts
    assert "bar" not in opts
    assert "scan" not in opts


def test_get_options_no_options(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["prog", "scan", "url"])
    opts = utils.get_options()
    assert opts == []


def test_get_options_only_options(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["prog", "--a", "--b", "--c"])
    opts = utils.get_options()
    assert set(opts) == {"--a", "--b", "--c"}
