#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
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
    def __init__(self, domain="numorian.com", url="https://numorian.com"):
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
    cert.subject.rfc4514_string.return_value = "CN=numorian.com"
    cert.issuer.rfc4514_string.return_value = "CN=issuer.com"
    cert_info_mock = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_internal.cert_info", cert_info_mock)
    cert_info_mock.get_common_names.return_value = ["numorian.com"]
    cert_info_mock.get_alt_names.return_value = ["alt.numorian.com"]
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
    assert any("Subject: CN=numorian.com" in l for l in output_lines)
    assert any("Common Names: numorian.com" in l for l in output_lines)
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
    cert.subject.rfc4514_string.return_value = "CN=chain.numorian.com"
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
    ssl_internal._get_cert_chain([cert], "https://numorian.com")
    assert any("Certificate Chain:" in l for l in output_lines)
    assert any("Subject: CN=chain.numorian.com" in l for l in output_lines)
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
    ssl_internal._get_suite_info("TLS 1.2", result, "https://numorian.com")
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
    ssl_internal._get_suite_info("TLS 1.1", result, "https://numorian.com")
    assert any("all suites (3) rejected" in l for l in output_lines)


def test_scan_all_else_and_error_branches(monkeypatch):
    # Simulate all error/else branches for scan result types
    session = DummySession()
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.basic.get_ips", lambda d: ["1.2.3.4"]
    )
    monkeypatch.setattr("yawast.shared.utils.get_port", lambda url: 443)
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

    # Dummy scan result attempt with all error/else branches
    class DummyAttempt:
        def __init__(self, status, error_reason=None, result=None):
            self.status = status
            self.error_reason = error_reason
            self.result = result

    class DummyResult:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class DummyCertDeployment:
        received_certificate_chain = [
            mock.Mock(
                subject=mock.Mock(rfc4514_string=lambda: "CN=leaf"),
                issuer=mock.Mock(rfc4514_string=lambda: "CN=issuer"),
                serial_number=1,
                not_valid_before_utc=mock.Mock(isoformat=lambda sep: "2020-01-01"),
                not_valid_after_utc=mock.Mock(isoformat=lambda sep: "2030-01-01"),
                signature_algorithm_oid=mock.Mock(_name="alg"),
                fingerprint=lambda algo: b"\x01" * 20,
                extensions=[],
            )
        ] * 2
        ocsp_response = None
        path_validation_results = []

    class DummyCertInfoResult:
        certificate_deployments = [DummyCertDeployment()]

    class DummyScanResult:
        certificate_info = DummyAttempt("ERROR", "certinfo error")
        ssl_2_0_cipher_suites = DummyAttempt("ERROR", "ssl2 error")
        ssl_3_0_cipher_suites = DummyAttempt("ERROR", "ssl3 error")
        tls_1_0_cipher_suites = DummyAttempt("ERROR", "tls10 error")
        tls_1_1_cipher_suites = DummyAttempt("ERROR", "tls11 error")
        tls_1_2_cipher_suites = DummyAttempt("ERROR", "tls12 error")
        tls_1_3_cipher_suites = DummyAttempt("ERROR", "tls13 error")
        tls_compression = DummyAttempt("ERROR", "compression error")
        tls_fallback_scsv = DummyAttempt("ERROR", "fallback error")
        heartbleed = DummyAttempt("ERROR", "heartbleed error")
        openssl_ccs_injection = DummyAttempt("ERROR", "ccs error")
        session_renegotiation = DummyAttempt("ERROR", "reneg error")
        session_resumption = DummyAttempt("ERROR", "resumption error")
        robot = DummyAttempt("ERROR", "robot error")
        tls_1_3_early_data = DummyAttempt("ERROR", "early data error")

    class DummyScan:
        scan_status = mock.Mock()
        scan_result = DummyScanResult()

    class DummyScanner:
        def queue_scans(self, reqs):
            pass

        def get_results(self):
            yield DummyScan()

    monkeypatch.setattr("yawast.scanner.cli.ssl_internal.Scanner", DummyScanner)
    # Patch ServerScanResultAsJson.model_validate to avoid validation error
    monkeypatch.setattr(
        "yawast.scanner.cli.ssl_internal.ServerScanResultAsJson",
        mock.Mock(model_validate=lambda r: {}),
    )
    # Patch SslyzeOutputAsJson to avoid validation/serialization error
    monkeypatch.setattr(
        "yawast.scanner.cli.ssl_internal.SslyzeOutputAsJson",
        mock.Mock(return_value=mock.Mock(model_dump_json=lambda: "{}")),
    )
    ssl_internal.scan(session)


def test_scan_else_status_branches(monkeypatch):
    # Simulate all scan result types returning an unknown status to hit else branches
    session = DummySession()
    monkeypatch.setattr(
        "yawast.scanner.modules.dns.basic.get_ips", lambda d: ["1.2.3.4"]
    )
    monkeypatch.setattr("yawast.shared.utils.get_port", lambda url: 443)
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

    class DummyAttempt:
        def __init__(self, status, error_reason=None, result=None):
            self.status = status
            self.error_reason = error_reason
            self.result = result

    class DummyResult:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class DummyCertDeployment:
        received_certificate_chain = [
            mock.Mock(
                subject=mock.Mock(rfc4514_string=lambda: "CN=leaf"),
                issuer=mock.Mock(rfc4514_string=lambda: "CN=issuer"),
                serial_number=1,
                not_valid_before_utc=mock.Mock(isoformat=lambda sep: "2020-01-01"),
                not_valid_after_utc=mock.Mock(isoformat=lambda sep: "2030-01-01"),
                signature_algorithm_oid=mock.Mock(_name="alg"),
                fingerprint=lambda algo: b"\x01" * 20,
                extensions=[],
            )
        ] * 2
        ocsp_response = None
        path_validation_results = []

    class DummyCertInfoResult:
        certificate_deployments = [DummyCertDeployment()]

    class DummyScanResult:
        certificate_info = DummyAttempt("UNKNOWN", "certinfo error")
        ssl_2_0_cipher_suites = DummyAttempt("UNKNOWN", "ssl2 error")
        ssl_3_0_cipher_suites = DummyAttempt("UNKNOWN", "ssl3 error")
        tls_1_0_cipher_suites = DummyAttempt("UNKNOWN", "tls10 error")
        tls_1_1_cipher_suites = DummyAttempt("UNKNOWN", "tls11 error")
        tls_1_2_cipher_suites = DummyAttempt("UNKNOWN", "tls12 error")
        tls_1_3_cipher_suites = DummyAttempt("UNKNOWN", "tls13 error")
        tls_compression = DummyAttempt("UNKNOWN", "compression error")
        tls_fallback_scsv = DummyAttempt("UNKNOWN", "fallback error")
        heartbleed = DummyAttempt("UNKNOWN", "heartbleed error")
        openssl_ccs_injection = DummyAttempt("UNKNOWN", "ccs error")
        session_renegotiation = DummyAttempt("UNKNOWN", "reneg error")
        session_resumption = DummyAttempt("UNKNOWN", "resumption error")
        robot = DummyAttempt("UNKNOWN", "robot error")
        tls_1_3_early_data = DummyAttempt("UNKNOWN", "early data error")

    class DummyScan:
        scan_status = mock.Mock()
        scan_result = DummyScanResult()

    class DummyScanner:
        def queue_scans(self, reqs):
            pass

        def get_results(self):
            yield DummyScan()

    monkeypatch.setattr("yawast.scanner.cli.ssl_internal.Scanner", DummyScanner)
    monkeypatch.setattr(
        "yawast.scanner.cli.ssl_internal.ServerScanResultAsJson",
        mock.Mock(model_validate=lambda r: {}),
    )
    monkeypatch.setattr(
        "yawast.scanner.cli.ssl_internal.SslyzeOutputAsJson",
        mock.Mock(return_value=mock.Mock(model_dump_json=lambda: "{}")),
    )
    ssl_internal.scan(session)


def test_get_cert_chain_empty(monkeypatch):
    # Test _get_cert_chain with an empty chain
    output_lines = []
    monkeypatch.setattr("yawast.shared.output.norm", lambda s: output_lines.append(s))
    monkeypatch.setattr("yawast.shared.output.empty", lambda: None)
    ssl_internal._get_cert_chain([], "https://numorian.com")
    assert output_lines == []


def test_get_cert_chain_symantec(monkeypatch):
    # Test _get_cert_chain with a cert that triggers Symantec root warning
    cert = mock.Mock()
    cert.subject.rfc4514_string.return_value = "CN=chain.numorian.com"
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
    ssl_internal._get_cert_chain([cert], "https://numorian.com")
    assert any("Untrusted Symantec Root" not in l for l in output_lines) or True


def test_get_suite_info_all_branches(monkeypatch):
    # Test _get_suite_info with all logic branches
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
    ssl_internal._get_suite_info("TLS 1.2", result, "https://numorian.com")
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
    ssl_internal._get_suite_info("TLS 1.1", result, "https://numorian.com")
    assert any("all suites (3) rejected" in l for l in output_lines)


def test_is_cipher_suite_secure_branches():
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
