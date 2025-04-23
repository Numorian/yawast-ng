#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

from unittest import mock

import pytest

from tests import utils
from yawast import command_line
from yawast.scanner.cli import ssl_internal
from yawast.scanner.session import Session
from yawast.shared import output


def test_ssl_internal():
    url = "https://github.com/"

    output.setup(False, False, False)
    with utils.capture_sys_output() as (stdout, stderr):
        p = command_line.build_parser()
        ns = p.parse_args(args=["scan"])
        s = Session(ns, url)

        try:
            ssl_internal.scan(s)
        except Exception as error:
            assert error is None

        assert "Exception" not in stderr.getvalue()
        assert "Error" not in stderr.getvalue()
        assert "Error" not in stdout.getvalue()


class DummySession:
    def __init__(self, domain="example.com", url="https://example.com"):
        self.domain = domain
        self.url = url
        self.args = mock.Mock()


def make_scan_result(status_map):
    # Helper to create a fake scan result with given status for each scan type
    class DummyAttempt:
        def __init__(self, status, error_reason=None, result=None):
            self.status = status
            self.error_reason = error_reason
            self.result = result

    class DummyResult:
        pass

    dr = DummyResult()
    for k, v in status_map.items():
        setattr(dr, k, DummyAttempt(**v))
    # Add certificate_info with a completed status and a fake deployment
    dr.certificate_info = DummyAttempt(
        status=status_map.get("certificate_info", {"status": "COMPLETED"})["status"],
        error_reason=None,
        result=mock.Mock(
            certificate_deployments=[
                mock.Mock(
                    received_certificate_chain=[mock.Mock(), mock.Mock()],
                    ocsp_response=None,
                    path_validation_results=[
                        mock.Mock(
                            was_validation_successful=True,
                            trust_store=mock.Mock(name="RootStore"),
                        )
                    ],
                )
            ]
        ),
    )
    return dr


def test_scan_all_error_branches(monkeypatch):
    session = DummySession()
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.basic.get_ips", lambda d: ["1.2.3.4"]
    )
    monkeypatch.setattr("yawast.shared.utils.get_port", lambda url: 443)

    # Patch Scanner to yield a result with all scan types in ERROR status
    class DummyScanner:
        def queue_scans(self, reqs):
            pass

        def get_results(self):
            DummyEnum = mock.Mock()
            DummyEnum.ERROR = "ERROR"
            DummyEnum.COMPLETED = "COMPLETED"
            DummyEnum.VULNERABLE_WEAK_ORACLE = "VULN_WEAK"
            DummyEnum.VULNERABLE_STRONG_ORACLE = "VULN_STRONG"
            DummyEnum.FULLY_SUPPORTED = "FULLY"
            DummyEnum.PARTIALLY_SUPPORTED = "PARTIAL"
            status_map = {
                "ssl_2_0_cipher_suites": {"status": "ERROR", "error_reason": "fail"},
                "ssl_3_0_cipher_suites": {"status": "ERROR", "error_reason": "fail"},
                "tls_1_0_cipher_suites": {"status": "ERROR", "error_reason": "fail"},
                "tls_1_1_cipher_suites": {"status": "ERROR", "error_reason": "fail"},
                "tls_1_2_cipher_suites": {"status": "ERROR", "error_reason": "fail"},
                "tls_1_3_cipher_suites": {"status": "ERROR", "error_reason": "fail"},
                "tls_compression": {"status": "ERROR", "error_reason": "fail"},
                "tls_fallback_scsv": {"status": "ERROR", "error_reason": "fail"},
                "heartbleed": {"status": "ERROR", "error_reason": "fail"},
                "openssl_ccs_injection": {"status": "ERROR", "error_reason": "fail"},
                "session_renegotiation": {"status": "ERROR", "error_reason": "fail"},
                "session_resumption": {"status": "ERROR", "error_reason": "fail"},
                "robot": {"status": "ERROR", "error_reason": "fail"},
                "tls_1_3_early_data": {"status": "ERROR", "error_reason": "fail"},
            }
            dummy_result = mock.Mock(
                scan_status="OK",
                scan_result=make_scan_result(status_map),
            )
            return [dummy_result]

    monkeypatch.setattr("yawast.scanner.cli.ssl_internal.Scanner", DummyScanner)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.error", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr("yawast.shared.output.info", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.vuln", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.debug_exception", lambda: None)
    monkeypatch.setattr("yawast.reporting.reporter.display", lambda *a, **k: None)
    monkeypatch.setattr("yawast.reporting.reporter.register_data", lambda *a, **k: None)
    monkeypatch.setattr("yawast.reporting.issue.Issue", mock.Mock())
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.get_common_names", lambda c: ["CN"]
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.get_alt_names", lambda c: ["alt"]
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.get_must_staple", lambda c: False
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.format_extensions", lambda c: ["ext"]
    )
    monkeypatch.setattr("yawast.scanner.modules.ssl.cert_info.get_scts", lambda c: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.get_ct_log_name", lambda s: "ctlog"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.check_symantec_root", lambda fp: False
    )
    monkeypatch.setattr(
        "yawast.scanner.cli.ssl_internal.SslyzeOutputAsJson",
        mock.Mock(return_value=mock.Mock(model_dump_json=lambda: "{}")),
    )
    monkeypatch.setattr(
        "yawast.scanner.cli.ssl_internal.ServerScanResultAsJson",
        mock.Mock(model_validate=lambda r: {}),
    )
    ssl_internal.scan(session)


def test_scan_exception(monkeypatch):
    session = DummySession()
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.basic.get_ips", lambda d: ["1.2.3.4"]
    )
    monkeypatch.setattr("yawast.shared.utils.get_port", lambda url: 443)

    class DummyScanner:
        def queue_scans(self, reqs):
            pass

        def get_results(self):
            raise Exception("fail")

    monkeypatch.setattr("yawast.scanner.cli.ssl_internal.Scanner", DummyScanner)
    monkeypatch.setattr("yawast.shared.output.norm", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.error", lambda *a, **k: None)
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    monkeypatch.setattr(
        "yawast.shared.output.debug_exception",
        lambda: setattr(session, "debugged", True),
    )
    ssl_internal.scan(session)
    assert hasattr(session, "debugged")


def test_get_trusted_root_stores():
    dummy_trust = mock.Mock()
    dummy_trust.was_validation_successful = True
    dummy_trust.trust_store.name = "RootStore"
    dummy_result = mock.Mock(path_validation_results=[dummy_trust])
    out = ssl_internal._get_trusted_root_stores(dummy_result)
    assert out == ["RootStore"]


def test_is_cipher_suite_secure():
    dummy_suite = mock.Mock(is_anonymous=False, key_size=256)
    assert ssl_internal._is_cipher_suite_secure(
        dummy_suite, "TLS_RSA_WITH_AES_256_CBC_SHA"
    )
    dummy_suite.is_anonymous = True
    assert not ssl_internal._is_cipher_suite_secure(
        dummy_suite, "TLS_RSA_WITH_AES_256_CBC_SHA"
    )
    dummy_suite.is_anonymous = False
    dummy_suite.key_size = 64
    assert not ssl_internal._is_cipher_suite_secure(
        dummy_suite, "TLS_RSA_WITH_AES_256_CBC_SHA"
    )
    dummy_suite.key_size = 256
    assert not ssl_internal._is_cipher_suite_secure(dummy_suite, "RC4-SHA")
    assert not ssl_internal._is_cipher_suite_secure(dummy_suite, "DES-CBC3-SHA")


def test_get_leaf_cert_info(monkeypatch):
    # Create a mock certificate with all required attributes and methods
    cert = mock.Mock()
    cert.subject.rfc4514_string.return_value = "CN=example.com"
    cert.issuer.rfc4514_string.return_value = "CN=issuer.com"
    cert_info_mock = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_internal.cert_info", cert_info_mock)
    cert_info_mock.get_common_names.return_value = ["example.com"]
    cert_info_mock.get_alt_names.return_value = ["alt.example.com"]
    cert_info_mock.get_must_staple.return_value = True
    cert_info_mock.format_extensions.return_value = ["ext1", "ext2"]
    cert_info_mock.get_scts.return_value = [
        (0, "logid", mock.Mock(isoformat=lambda s: "2025-04-23 00:00:00"))
    ]
    cert_info_mock.get_ct_log_name.return_value = "ctlog"
    cert.signature_algorithm_oid._name = "sha256WithRSAEncryption"
    cert.not_valid_before_utc.isoformat.return_value = "2025-01-01 00:00:00"
    cert.not_valid_after_utc.isoformat.return_value = "2026-01-01 00:00:00"
    cert.serial_number = 123456
    cert.fingerprint.side_effect = lambda algo: b"\x01\x02\x03"
    output_lines = []
    monkeypatch.setattr("yawast.shared.output.norm", lambda s: output_lines.append(s))
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    ssl_internal._get_leaf_cert_info(cert)
    assert any("Certificate Information:" in l for l in output_lines)
    assert any("Subject: CN=example.com" in l for l in output_lines)
    assert any("Common Names: example.com" in l for l in output_lines)
    assert any("Alternative names:" in l for l in output_lines)
    assert any("Not Before: 2025-01-01 00:00:00" in l for l in output_lines)
    assert any("Not After: 2026-01-01 00:00:00" in l for l in output_lines)
    assert any("Key: sha256WithRSAEncryption" in l for l in output_lines)
    assert any("Serial: 1e240" in l for l in output_lines)  # 123456 in hex
    assert any("Issuer: CN=issuer.com" in l for l in output_lines)
    assert any("OCSP Must Staple: True" in l for l in output_lines)
    assert any("Extensions: ext1" in l for l in output_lines)
    assert any("Extensions: ext2" in l for l in output_lines)
    assert any("SCT: ctlog - 2025-04-23 00:00:00" in l for l in output_lines)
    assert any("Fingerprint: 010203" in l for l in output_lines)
    assert any("https://censys.io/certificates?q=010203" in l for l in output_lines)
    assert any("https://crt.sh/?q=010203" in l for l in output_lines)


def test_get_cert_chain(monkeypatch):
    cert = mock.Mock()
    cert.subject.rfc4514_string.return_value = "CN=chain.example.com"
    cert.signature_algorithm_oid._name = "sha256WithRSAEncryption"
    cert.fingerprint.side_effect = [b"\x01\x02\x03", b"\x04\x05\x06"]
    monkeypatch.setattr(
        "yawast.scanner.cli.ssl_internal.cert_info.check_symantec_root",
        lambda fp: fp == "010203",
    )
    monkeypatch.setattr("yawast.reporting.reporter.display", lambda *a, **k: None)
    monkeypatch.setattr("yawast.reporting.issue.Issue", mock.Mock())
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    output_lines = []
    monkeypatch.setattr("yawast.shared.output.norm", lambda s: output_lines.append(s))
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    ssl_internal._get_cert_chain([cert], "https://example.com")
    assert any("Certificate Chain:" in l for l in output_lines)
    assert any("Subject: CN=chain.example.com" in l for l in output_lines)
    assert any("Signature: sha256WithRSAEncryption" in l for l in output_lines)
    assert any("https://crt.sh/?q=040506" in l for l in output_lines)


def test_get_suite_info(monkeypatch):
    # Prepare mocks for output and reporter
    output_lines = []
    info_lines = []
    vuln_lines = []
    monkeypatch.setattr("yawast.shared.output.norm", lambda s: output_lines.append(s))
    monkeypatch.setattr("yawast.shared.output.info", lambda s: info_lines.append(s))
    monkeypatch.setattr("yawast.shared.output.vuln", lambda s: vuln_lines.append(s))
    monkeypatch.setattr("yawast.reporting.reporter.register", lambda *a, **k: None)
    monkeypatch.setattr("yawast.reporting.issue.Issue", mock.Mock())
    monkeypatch.setattr("yawast.reporting.enums.Vulnerabilities", mock.Mock())
    # Secure CBC suite
    secure_cbc_suite = mock.Mock()
    secure_cbc_suite.cipher_suite.name = "TLS_RSA_WITH_AES_256_CBC_SHA"
    secure_cbc_suite.cipher_suite.key_size = 256
    # Secure non-CBC suite
    secure_suite = mock.Mock()
    secure_suite.cipher_suite.name = "TLS_RSA_WITH_AES_256_GCM_SHA384"
    secure_suite.cipher_suite.key_size = 256
    # Insecure suite
    insecure_suite = mock.Mock()
    insecure_suite.cipher_suite.name = "RC4-SHA"
    insecure_suite.cipher_suite.key_size = 128
    # Patch _is_cipher_suite_secure to control logic
    monkeypatch.setattr(
        ssl_internal, "_is_cipher_suite_secure", lambda s, n: "CBC" in n or "GCM" in n
    )
    # Compose result
    result = mock.Mock()
    result.accepted_cipher_suites = [secure_cbc_suite, secure_suite, insecure_suite]
    result.rejected_cipher_suites = [mock.Mock(), mock.Mock()]
    ssl_internal._get_suite_info("TLS 1.2", result, "https://example.com")
    # Check output for all branches
    assert any("TLS 1.2:" in l for l in output_lines)
    assert any("CBC_SHA" in l for l in info_lines)
    assert any("GCM_SHA384" in l for l in output_lines)
    assert any("RC4-SHA" in l for l in vuln_lines)
    assert any("2 suites rejected" in l for l in output_lines)
    # Test rejected only branch
    result.accepted_cipher_suites = []
    result.rejected_cipher_suites = [mock.Mock(), mock.Mock(), mock.Mock()]
    output_lines.clear()
    ssl_internal._get_suite_info("TLS 1.1", result, "https://example.com")
    assert any("all suites (3) rejected" in l for l in output_lines)
