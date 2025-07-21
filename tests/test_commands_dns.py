import socket
from unittest import mock

import pytest

from yawast.commands import dns as dns_cmd


def test_start_success():
    session = mock.Mock()
    session.url = "http://numorian.com"
    session.domain = "numorian.com"
    with mock.patch(
        "socket.gethostbyname", return_value="1.2.3.4"
    ) as gethost, mock.patch("yawast.scanner.cli.dns.scan") as scan, mock.patch(
        "builtins.print"
    ) as mprint:
        dns_cmd.start(session)
        gethost.assert_called_once_with("numorian.com")
        scan.assert_called_once_with(session)
        mprint.assert_any_call("Scanning: http://numorian.com")


def test_start_gaierror():
    session = mock.Mock()
    session.url = "http://badhost"
    session.domain = "badhost"
    with mock.patch(
        "socket.gethostbyname", side_effect=socket.gaierror("fail")
    ), mock.patch("yawast.scanner.cli.dns.scan") as scan, mock.patch(
        "builtins.print"
    ) as mprint:
        dns_cmd.start(session)
        scan.assert_not_called()
        mprint.assert_any_call("Fatal Error: Unable to resolve badhost (fail)")
