# Copyright (c) 2025 Adam Caudill and Contributors.
# Unit tests for yawast/scanner/cli/dns.py
from unittest import mock

import pytest

from yawast.scanner.cli import dns


class DummyArgs:
    def __init__(self, srv=False, subdomains=False):
        self.srv = srv
        self.subdomains = subdomains


class DummySession:
    def __init__(self, domain, url, srv=False, subdomains=False):
        self.domain = domain
        self.url = url
        self.args = DummyArgs(srv=srv, subdomains=subdomains)


def test_get_ip_info_success():
    with mock.patch("socket.gethostbyname", return_value="1.2.3.4"), mock.patch(
        "yawast.scanner.modules.dns.network_info.network_info", return_value="info"
    ):
        ip, ni = dns._get_ip_info("example.com")
        assert ip == "1.2.3.4"
        assert ni == "info"


def test_get_ip_info_failure():
    with mock.patch("socket.gethostbyname", side_effect=Exception()), mock.patch(
        "yawast.scanner.modules.dns.network_info.network_info", return_value="info"
    ), mock.patch("yawast.shared.output.debug_exception") as dbg:
        ip, ni = dns._get_ip_info("badhost")
        assert ip == "(Unavailable)"
        assert ni == "(Unavailable)"
        dbg.assert_called()


def test_scan_ip_domain(monkeypatch):
    # If the domain is an IP, scan should return early
    session = DummySession(domain="8.8.8.8", url="http://8.8.8.8")
    called = {}
    monkeypatch.setattr(
        "yawast.reporting.reporter.register_data",
        lambda *a, **k: called.setdefault("register_data", True),
    )
    monkeypatch.setattr("yawast.shared.utils.is_ip", lambda d: True)
    dns.scan(session)
    assert called["register_data"]


def test_scan_normal_domain(monkeypatch):
    # Test main scan flow with a normal domain, mocking all dependencies
    session = DummySession(domain="example.com", url="http://example.com")
    monkeypatch.setattr("yawast.reporting.reporter.register_data", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.utils.is_ip", lambda d: False)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.basic.get_ips", lambda d: ["1.2.3.4"]
    )
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_host", lambda ip: "host")
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.network_info.network_info", lambda ip: "info"
    )
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_text", lambda d: ["txt"])
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.basic.get_mx", lambda d: [("mx.example.com", 10)]
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.basic.get_ns", lambda d: ["ns.example.com"]
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.srv.find_srv_records",
        lambda d: [("srv", "srv.example.com", 123)],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.subdomains.find_subdomains",
        lambda d: [("A", "sub.example.com", "2.2.2.2")],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.caa.get_caa",
        lambda d: [("example.com", "CAA", ['issue "letsencrypt.org"'])],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.dnssec.get_dnskey",
        lambda d: [(257, 3, "alg", b"key")],
    )
    monkeypatch.setattr("yawast.reporting.reporter.display", lambda *a, **k: None)
    monkeypatch.setattr(
        "yawast.reporting.issue.Issue.from_result", lambda *a, **k: None
    )
    monkeypatch.setattr("yawast.reporting.result.Result", lambda *a, **k: None)
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.network_info.purge_data", lambda: None
    )
    # Test with no SRV or subdomains
    dns.scan(session)
    # Test with SRV
    session.args.srv = True
    dns.scan(session)
    # Test with subdomains
    session.args.srv = False
    session.args.subdomains = True
    dns.scan(session)
