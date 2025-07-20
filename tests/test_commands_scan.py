from unittest import mock

import pytest

from yawast.commands import scan as scan_cmd


def make_session(**kwargs):
    session = mock.Mock()
    session.url = kwargs.get("url", "https://numorian.com")
    session.domain = kwargs.get("domain", "numorian.com")
    session.url_parsed.scheme = kwargs.get("scheme", "https")
    session.url_parsed.port = kwargs.get("port", 443)
    session.args.nodns = kwargs.get("nodns", False)
    session.args.ports = kwargs.get("ports", False)
    session.args.nossl = kwargs.get("nossl", False)
    session.args.internalssl = kwargs.get("internalssl", False)
    session.args.tdessessioncount = kwargs.get("tdessessioncount", False)
    return session


def test_scan_success_all(monkeypatch):
    session = make_session()
    with mock.patch("socket.gethostbyname", return_value="1.2.3.4"), mock.patch(
        "yawast.commands.utils.check_redirect"
    ), mock.patch("yawast.scanner.cli.dns.scan") as dns_scan, mock.patch(
        "yawast.scanner.cli.network.scan"
    ) as net_scan, mock.patch(
        "yawast.scanner.cli.ssl_internal.scan"
    ) as ssl_internal_scan, mock.patch(
        "yawast.scanner.cli.http.scan"
    ) as http_scan, mock.patch(
        "yawast.scanner.plugins.plugin_manager.run_other_scans"
    ) as run_plugins, mock.patch(
        "yawast.scanner.cli.http.reset"
    ) as http_reset, mock.patch(
        "builtins.print"
    ):
        scan_cmd.start(session)
        dns_scan.assert_called_once()
        net_scan.assert_not_called()  # ports is False
        ssl_internal_scan.assert_called_once()
        http_scan.assert_called_once()
        run_plugins.assert_called_once()
        http_reset.assert_called_once()


def test_scan_dns_ports(monkeypatch):
    session = make_session(ports=True)
    with mock.patch("socket.gethostbyname", return_value="1.2.3.4"), mock.patch(
        "yawast.commands.utils.check_redirect"
    ), mock.patch("yawast.scanner.cli.dns.scan") as dns_scan, mock.patch(
        "yawast.scanner.cli.network.scan"
    ) as net_scan, mock.patch(
        "yawast.scanner.cli.ssl_internal.scan"
    ) as ssl_internal_scan, mock.patch(
        "yawast.scanner.cli.http.scan"
    ) as http_scan, mock.patch(
        "yawast.scanner.plugins.plugin_manager.run_other_scans"
    ), mock.patch(
        "yawast.scanner.cli.http.reset"
    ), mock.patch(
        "builtins.print"
    ):
        scan_cmd.start(session)
        dns_scan.assert_called_once()
        net_scan.assert_called_once()
        ssl_internal_scan.assert_called_once()
        http_scan.assert_called_once()


def test_scan_nodns(monkeypatch):
    session = make_session(nodns=True)
    with mock.patch("socket.gethostbyname", return_value="1.2.3.4"), mock.patch(
        "yawast.commands.utils.check_redirect"
    ), mock.patch("yawast.scanner.cli.dns.scan") as dns_scan, mock.patch(
        "yawast.scanner.cli.network.scan"
    ), mock.patch(
        "yawast.scanner.cli.ssl_internal.scan"
    ) as ssl_internal_scan, mock.patch(
        "yawast.scanner.cli.http.scan"
    ) as http_scan, mock.patch(
        "yawast.scanner.plugins.plugin_manager.run_other_scans"
    ), mock.patch(
        "yawast.scanner.cli.http.reset"
    ), mock.patch(
        "builtins.print"
    ):
        scan_cmd.start(session)
        dns_scan.assert_not_called()
        ssl_internal_scan.assert_called_once()
        http_scan.assert_called_once()


def test_scan_dns_error(monkeypatch):
    session = make_session()
    with mock.patch("socket.gethostbyname", side_effect=OSError("fail")), mock.patch(
        "yawast.shared.output.debug_exception"
    ) as debug_exc, mock.patch("yawast.shared.output.error") as error, mock.patch(
        "builtins.print"
    ):
        scan_cmd.start(session)
        debug_exc.assert_called()
        error.assert_called()


def test_scan_redirect_error(monkeypatch):
    session = make_session()
    with mock.patch("socket.gethostbyname", return_value="1.2.3.4"), mock.patch(
        "yawast.commands.utils.check_redirect", side_effect=Exception("fail")
    ), mock.patch("yawast.shared.output.debug_exception") as debug_exc, mock.patch(
        "yawast.shared.output.error"
    ) as error, mock.patch(
        "builtins.print"
    ):
        scan_cmd.start(session)
        debug_exc.assert_called()
        error.assert_called()


def test_scan_ssl_labs(monkeypatch):
    session = make_session()
    session.args.internalssl = False
    session.args.nossl = False
    with mock.patch("socket.gethostbyname", return_value="1.2.3.4"), mock.patch(
        "yawast.commands.utils.check_redirect"
    ), mock.patch("yawast.scanner.cli.dns.scan"), mock.patch(
        "yawast.scanner.cli.network.scan"
    ), mock.patch(
        "yawast.scanner.cli.ssl_internal.scan"
    ), mock.patch(
        "yawast.scanner.cli.ssl_labs.scan"
    ) as ssl_labs_scan, mock.patch(
        "yawast.scanner.cli.http.scan"
    ), mock.patch(
        "yawast.scanner.plugins.plugin_manager.run_other_scans"
    ), mock.patch(
        "yawast.scanner.cli.http.reset"
    ), mock.patch(
        "yawast.shared.utils.is_ip", return_value=False
    ), mock.patch(
        "yawast.shared.utils.get_port", return_value=443
    ), mock.patch(
        "builtins.print"
    ):
        scan_cmd.start(session)
        ssl_labs_scan.assert_called_once()


def test_scan_ssl_labs_error(monkeypatch):
    session = make_session()
    session.args.internalssl = False
    session.args.nossl = False
    with mock.patch("socket.gethostbyname", return_value="1.2.3.4"), mock.patch(
        "yawast.commands.utils.check_redirect"
    ), mock.patch("yawast.scanner.cli.dns.scan"), mock.patch(
        "yawast.scanner.cli.network.scan"
    ), mock.patch(
        "yawast.scanner.cli.ssl_internal.scan"
    ) as ssl_internal_scan, mock.patch(
        "yawast.scanner.cli.ssl_labs.scan", side_effect=Exception("fail")
    ), mock.patch(
        "yawast.scanner.cli.http.scan"
    ), mock.patch(
        "yawast.scanner.plugins.plugin_manager.run_other_scans"
    ), mock.patch(
        "yawast.scanner.cli.http.reset"
    ), mock.patch(
        "yawast.shared.utils.is_ip", return_value=False
    ), mock.patch(
        "yawast.shared.utils.get_port", return_value=443
    ), mock.patch(
        "yawast.shared.output.debug_exception"
    ) as debug_exc, mock.patch(
        "yawast.shared.output.error"
    ) as error, mock.patch(
        "yawast.shared.output.norm"
    ) as norm, mock.patch(
        "builtins.print"
    ):
        scan_cmd.start(session)
        debug_exc.assert_called()
        error.assert_called()
        norm.assert_called()


def test_scan_tdessessioncount(monkeypatch):
    session = make_session(tdessessioncount=True)
    with mock.patch("socket.gethostbyname", return_value="1.2.3.4"), mock.patch(
        "yawast.commands.utils.check_redirect"
    ), mock.patch("yawast.scanner.cli.dns.scan"), mock.patch(
        "yawast.scanner.cli.network.scan"
    ), mock.patch(
        "yawast.scanner.cli.ssl_internal.scan"
    ) as ssl_internal_scan, mock.patch(
        "yawast.scanner.cli.ssl_labs.scan"
    ), mock.patch(
        "yawast.scanner.cli.ssl_sweet32.scan"
    ) as sweet32_scan, mock.patch(
        "yawast.scanner.cli.http.scan"
    ), mock.patch(
        "yawast.scanner.plugins.plugin_manager.run_other_scans"
    ), mock.patch(
        "yawast.scanner.cli.http.reset"
    ), mock.patch(
        "yawast.shared.utils.is_ip", return_value=False
    ), mock.patch(
        "yawast.shared.utils.get_port", return_value=443
    ), mock.patch(
        "yawast.shared.output.error"
    ) as error, mock.patch(
        "builtins.print"
    ):
        scan_cmd.start(session)
        error.assert_any_call(
            "The --tdessessioncount option is currently disabled. See https://github.com/Numorian/yawast-ng/issues/11"
        )
        sweet32_scan.assert_called_once()
