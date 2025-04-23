from unittest import mock

import pytest

from yawast.commands import ssl as ssl_cmd


def make_session(**kwargs):
    session = mock.Mock()
    session.url = kwargs.get("url", "https://example.com")
    session.domain = kwargs.get("domain", "example.com")
    session.url_parsed.scheme = kwargs.get("scheme", "https")
    session.url_parsed.port = kwargs.get("port", 443)
    session.args.internalssl = kwargs.get("internalssl", False)
    session.args.tdessessioncount = kwargs.get("tdessessioncount", False)
    return session


def test_ssl_success_internal(monkeypatch):
    session = make_session(internalssl=True)
    with mock.patch("socket.gethostbyname", return_value="1.2.3.4"), mock.patch(
        "yawast.commands.utils.check_redirect"
    ), mock.patch(
        "yawast.scanner.cli.ssl_internal.scan"
    ) as ssl_internal_scan, mock.patch(
        "builtins.print"
    ), mock.patch(
        "yawast.shared.utils.is_ip", return_value=True
    ), mock.patch(
        "yawast.shared.utils.get_port", return_value=443
    ):
        ssl_cmd.start(session)
        ssl_internal_scan.assert_called_once()


def test_ssl_success_labs(monkeypatch):
    session = make_session()
    with mock.patch("socket.gethostbyname", return_value="1.2.3.4"), mock.patch(
        "yawast.commands.utils.check_redirect"
    ), mock.patch("yawast.scanner.cli.ssl_labs.scan") as ssl_labs_scan, mock.patch(
        "builtins.print"
    ), mock.patch(
        "yawast.shared.utils.is_ip", return_value=False
    ), mock.patch(
        "yawast.shared.utils.get_port", return_value=443
    ):
        ssl_cmd.start(session)
        ssl_labs_scan.assert_called_once()


def test_ssl_dns_error(monkeypatch):
    session = make_session()
    with mock.patch("socket.gethostbyname", side_effect=OSError("fail")), mock.patch(
        "yawast.shared.output.debug_exception"
    ) as debug_exc, mock.patch("yawast.shared.output.error") as error, mock.patch(
        "builtins.print"
    ):
        ssl_cmd.start(session)
        debug_exc.assert_called()
        error.assert_called()


def test_ssl_redirect_error(monkeypatch):
    session = make_session()
    with mock.patch("socket.gethostbyname", return_value="1.2.3.4"), mock.patch(
        "yawast.commands.utils.check_redirect", side_effect=Exception("fail")
    ), mock.patch("yawast.shared.output.debug_exception") as debug_exc, mock.patch(
        "yawast.shared.output.error"
    ) as error, mock.patch(
        "builtins.print"
    ):
        ssl_cmd.start(session)
        debug_exc.assert_called()
        error.assert_called()


def test_ssl_internal_error(monkeypatch):
    session = make_session(internalssl=True)
    with mock.patch("socket.gethostbyname", return_value="1.2.3.4"), mock.patch(
        "yawast.commands.utils.check_redirect"
    ), mock.patch(
        "yawast.scanner.cli.ssl_internal.scan", side_effect=Exception("fail")
    ), mock.patch(
        "yawast.shared.output.error"
    ) as error, mock.patch(
        "builtins.print"
    ), mock.patch(
        "yawast.shared.utils.is_ip", return_value=True
    ), mock.patch(
        "yawast.shared.utils.get_port", return_value=443
    ):
        ssl_cmd.start(session)
        error.assert_called_with("Error running scan with SSLyze: fail")


def test_ssl_labs_error(monkeypatch):
    session = make_session()
    with mock.patch("socket.gethostbyname", return_value="1.2.3.4"), mock.patch(
        "yawast.commands.utils.check_redirect"
    ), mock.patch(
        "yawast.scanner.cli.ssl_labs.scan", side_effect=Exception("fail")
    ), mock.patch(
        "yawast.shared.output.debug_exception"
    ) as debug_exc, mock.patch(
        "yawast.shared.output.error"
    ) as error, mock.patch(
        "yawast.shared.output.norm"
    ) as norm, mock.patch(
        "builtins.print"
    ), mock.patch(
        "yawast.shared.utils.is_ip", return_value=False
    ), mock.patch(
        "yawast.shared.utils.get_port", return_value=443
    ), mock.patch(
        "yawast.scanner.cli.ssl_internal.scan"
    ):
        ssl_cmd.start(session)
        debug_exc.assert_called()
        error.assert_any_call("Error running scan with SSL Labs: fail")
        norm.assert_called()


def test_ssl_labs_internal_error(monkeypatch):
    session = make_session()
    with mock.patch("socket.gethostbyname", return_value="1.2.3.4"), mock.patch(
        "yawast.commands.utils.check_redirect"
    ), mock.patch(
        "yawast.scanner.cli.ssl_labs.scan", side_effect=Exception("fail")
    ), mock.patch(
        "yawast.shared.output.debug_exception"
    ), mock.patch(
        "yawast.shared.output.error"
    ) as error, mock.patch(
        "yawast.shared.output.norm"
    ), mock.patch(
        "yawast.scanner.cli.ssl_internal.scan", side_effect=Exception("fail2")
    ), mock.patch(
        "builtins.print"
    ), mock.patch(
        "yawast.shared.utils.is_ip", return_value=False
    ), mock.patch(
        "yawast.shared.utils.get_port", return_value=443
    ):
        ssl_cmd.start(session)
        error.assert_any_call("Error running scan with SSLyze: fail2")


def test_ssl_tdessessioncount(monkeypatch):
    session = make_session(tdessessioncount=True)
    with mock.patch("socket.gethostbyname", return_value="1.2.3.4"), mock.patch(
        "yawast.commands.utils.check_redirect"
    ), mock.patch("yawast.scanner.cli.ssl_internal.scan"), mock.patch(
        "yawast.scanner.cli.ssl_labs.scan"
    ), mock.patch(
        "yawast.scanner.cli.ssl_sweet32.scan"
    ) as sweet32_scan, mock.patch(
        "yawast.shared.utils.is_ip", return_value=True
    ), mock.patch(
        "yawast.shared.utils.get_port", return_value=443
    ), mock.patch(
        "yawast.shared.output.error"
    ) as error, mock.patch(
        "builtins.print"
    ):
        ssl_cmd.start(session)
        error.assert_any_call(
            "The --tdessessioncount option is currently disabled. See https://github.com/Numorian/yawast-ng/issues/11"
        )
        sweet32_scan.assert_called_once()
