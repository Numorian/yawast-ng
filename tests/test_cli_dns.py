# Copyright (c) 2025 Numorian, Inc. and Contributors.
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
        ip, ni = dns._get_ip_info("numorian.com")
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
    session = DummySession(domain="numorian.com", url="http://numorian.com")
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
        "yawast.scanner.modules.dns.basic.get_mx", lambda d: [("mx.numorian.com", 10)]
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.basic.get_ns", lambda d: ["ns.numorian.com"]
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.srv.find_srv_records",
        lambda d: [("srv", "srv.numorian.com", 123)],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.subdomains.find_subdomains",
        lambda d: [("A", "sub.numorian.com", "2.2.2.2")],
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.caa.get_caa",
        lambda d: [("numorian.com", "CAA", ['issue "letsencrypt.org"'])],
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


def test_scan_txt_exception(monkeypatch):
    session = DummySession(domain="numorian.com", url="http://numorian.com")
    monkeypatch.setattr("yawast.reporting.reporter.register_data", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.utils.is_ip", lambda d: False)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_ips", lambda d: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.basic.get_text",
        lambda d: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr(
        "yawast.shared.output.error", lambda msg: setattr(session, "txt_error", msg)
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.network_info.purge_data", lambda: None
    )
    dns.scan(session)
    assert hasattr(session, "txt_error")


def test_scan_mx_exception(monkeypatch):
    session = DummySession(domain="numorian.com", url="http://numorian.com")
    monkeypatch.setattr("yawast.reporting.reporter.register_data", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.utils.is_ip", lambda d: False)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_ips", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_text", lambda d: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.basic.get_mx",
        lambda d: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr(
        "yawast.shared.output.error", lambda msg: setattr(session, "mx_error", msg)
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.network_info.purge_data", lambda: None
    )
    dns.scan(session)
    assert hasattr(session, "mx_error")


def test_scan_ns_exception(monkeypatch):
    session = DummySession(domain="numorian.com", url="http://numorian.com")
    monkeypatch.setattr("yawast.reporting.reporter.register_data", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.utils.is_ip", lambda d: False)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_ips", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_text", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_mx", lambda d: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.basic.get_ns",
        lambda d: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr(
        "yawast.shared.output.error", lambda msg: setattr(session, "ns_error", msg)
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.network_info.purge_data", lambda: None
    )
    dns.scan(session)
    assert hasattr(session, "ns_error")


def test_scan_srv_exception(monkeypatch):
    session = DummySession(domain="numorian.com", url="http://numorian.com", srv=True)
    monkeypatch.setattr("yawast.reporting.reporter.register_data", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.utils.is_ip", lambda d: False)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_ips", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_text", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_mx", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_ns", lambda d: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.srv.find_srv_records",
        lambda d: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr(
        "yawast.shared.output.error", lambda msg: setattr(session, "srv_error", msg)
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.network_info.purge_data", lambda: None
    )
    dns.scan(session)
    assert hasattr(session, "srv_error")


def test_scan_subdomains_exception(monkeypatch):
    session = DummySession(
        domain="numorian.com", url="http://numorian.com", subdomains=True
    )
    monkeypatch.setattr("yawast.reporting.reporter.register_data", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.utils.is_ip", lambda d: False)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_ips", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_text", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_mx", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_ns", lambda d: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.subdomains.find_subdomains",
        lambda d: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr(
        "yawast.shared.output.error",
        lambda msg: setattr(session, "subdomains_error", msg),
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.network_info.purge_data", lambda: None
    )
    dns.scan(session)
    assert hasattr(session, "subdomains_error")


def test_scan_caa_exception(monkeypatch):
    session = DummySession(domain="numorian.com", url="http://numorian.com")
    monkeypatch.setattr("yawast.reporting.reporter.register_data", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.utils.is_ip", lambda d: False)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_ips", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_text", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_mx", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_ns", lambda d: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.caa.get_caa",
        lambda d: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr(
        "yawast.shared.output.error", lambda msg: setattr(session, "caa_error", msg)
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.network_info.purge_data", lambda: None
    )
    dns.scan(session)
    assert hasattr(session, "caa_error")


def test_scan_caa_missing(monkeypatch):
    session = DummySession(domain="numorian.com", url="http://numorian.com")
    monkeypatch.setattr("yawast.reporting.reporter.register_data", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.utils.is_ip", lambda d: False)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_ips", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_text", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_mx", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_ns", lambda d: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.caa.get_caa",
        lambda d: [("numorian.com", "CAA", [])],
    )
    monkeypatch.setattr(
        "yawast.reporting.reporter.display",
        lambda *a, **k: setattr(session, "caa_display", True),
    )
    monkeypatch.setattr(
        "yawast.reporting.issue.Issue.from_result", lambda *a, **k: None
    )
    monkeypatch.setattr("yawast.reporting.result.Result", lambda *a, **k: None)
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.network_info.purge_data", lambda: None
    )
    dns.scan(session)
    assert hasattr(session, "caa_display")


def test_scan_dnssec_missing(monkeypatch):
    session = DummySession(domain="numorian.com", url="http://numorian.com")
    monkeypatch.setattr("yawast.reporting.reporter.register_data", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.utils.is_ip", lambda d: False)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_ips", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_text", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_mx", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_ns", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.caa.get_caa", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.dnssec.get_dnskey", lambda d: [])
    monkeypatch.setattr(
        "yawast.reporting.reporter.display",
        lambda *a, **k: setattr(session, "dnssec_display", True),
    )
    monkeypatch.setattr(
        "yawast.reporting.issue.Issue.from_result", lambda *a, **k: None
    )
    monkeypatch.setattr("yawast.reporting.result.Result", lambda *a, **k: None)
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.network_info.purge_data", lambda: None
    )
    dns.scan(session)
    assert hasattr(session, "dnssec_display")


def test_scan_dnssec_exception(monkeypatch):
    session = DummySession(domain="numorian.com", url="http://numorian.com")
    monkeypatch.setattr("yawast.reporting.reporter.register_data", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.utils.is_ip", lambda d: False)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_ips", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_text", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_mx", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.basic.get_ns", lambda d: [])
    monkeypatch.setattr("yawast.scanner.modules.dns.caa.get_caa", lambda d: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.dnssec.get_dnskey",
        lambda d: (_ for _ in ()).throw(Exception("fail")),
    )
    monkeypatch.setattr(
        "yawast.shared.output.error", lambda msg: setattr(session, "dnssec_error", msg)
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.network_info.purge_data", lambda: None
    )
    dns.scan(session)
    assert hasattr(session, "dnssec_error")
