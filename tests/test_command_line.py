from unittest import mock

import pytest

from yawast import command_line


def test_process_urls_empty(monkeypatch):
    with mock.patch("yawast.shared.utils.exit_message") as exit_message:
        command_line.process_urls([])
        exit_message.assert_called_once_with(
            "YAWAST Error: You must specify at least one URL."
        )


def test_process_urls_invalid_url(monkeypatch):
    with mock.patch("yawast.shared.utils.is_url", return_value=False), mock.patch(
        "yawast.shared.utils.exit_message"
    ) as exit_message:
        command_line.process_urls(["not_a_url"])
        exit_message.assert_called_once()


def test_process_urls_valid_url(monkeypatch):
    with mock.patch("yawast.shared.utils.is_url", return_value=True):
        urls = command_line.process_urls(["http://example.com"])
        assert urls == ["http://example.com"]


def test_process_urls_param(monkeypatch, capsys):
    with mock.patch("yawast.shared.utils.is_url", return_value=True):
        urls = command_line.process_urls(["-bad", "http://good.com"])
        assert urls == ["http://good.com"]
        captured = capsys.readouterr()
        assert (
            "Invalid parameter" in captured.err or "Invalid parameter" in captured.out
        )


def test_command_scan_calls(monkeypatch):
    args = mock.Mock()
    urls = ["http://example.com"]
    with mock.patch(
        "yawast.shared.utils.extract_url", return_value="http://example.com"
    ), mock.patch(
        "yawast.shared.utils.get_domain", return_value="example.com"
    ), mock.patch(
        "yawast.reporting.reporter.setup"
    ) as setup, mock.patch(
        "yawast.scanner.session.Session"
    ) as Session, mock.patch(
        "yawast.commands.scan.start"
    ) as scan_start:
        command_line.command_scan(args, urls)
        setup.assert_called_once_with("example.com")
        scan_start.assert_called()


def test_command_dns_calls(monkeypatch):
    args = mock.Mock()
    urls = ["http://example.com"]
    with mock.patch(
        "yawast.shared.utils.extract_url", return_value="http://example.com"
    ), mock.patch(
        "yawast.shared.utils.get_domain", return_value="example.com"
    ), mock.patch(
        "yawast.reporting.reporter.setup"
    ) as setup, mock.patch(
        "yawast.scanner.session.Session"
    ) as Session, mock.patch(
        "yawast.commands.dns.start"
    ) as dns_start:
        command_line.command_dns(args, urls)
        setup.assert_called_once_with("example.com")
        dns_start.assert_called()


def test_command_ssl_calls(monkeypatch):
    args = mock.Mock()
    urls = ["http://example.com"]
    with mock.patch(
        "yawast.shared.utils.extract_url", return_value="http://example.com"
    ), mock.patch(
        "yawast.shared.utils.get_domain", return_value="example.com"
    ), mock.patch(
        "yawast.reporting.reporter.setup"
    ) as setup, mock.patch(
        "yawast.scanner.session.Session"
    ) as Session, mock.patch(
        "yawast.commands.ssl.start"
    ) as ssl_start:
        command_line.command_ssl(args, urls)
        setup.assert_called_once_with("example.com")
        ssl_start.assert_called()


def test_command_version():
    # This is a no-op, but should be covered
    command_line.command_version(None, None)
