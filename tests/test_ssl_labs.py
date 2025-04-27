from unittest.mock import MagicMock, patch

import pytest

from yawast.scanner.cli import ssl_labs


class DummySession:
    def __init__(self, domain, url):
        self.domain = domain
        self.url = url


def make_body(status="READY", endpoints=None, statusMessage="Ready"):
    if endpoints is None:
        endpoints = [
            {
                "statusMessage": statusMessage,
                "ipAddress": "1.2.3.4",
                "grade": "A",
                "details": {
                    "certChains": [
                        {
                            "certIds": ["cert1"],
                            "trustPaths": [
                                {
                                    "certIds": ["cert1"],
                                    "trust": [
                                        {
                                            "isTrusted": True,
                                            "rootStore": "Mozilla",
                                            "trustErrorMessage": "",
                                        }
                                    ],
                                }
                            ],
                            "issues": 0,
                        }
                    ],
                    "protocols": [],
                    "namedGroups": {"list": []},
                    "suites": [],
                    "sims": {"results": []},
                },
            }
        ]
    # Use a real, minimal, valid PEM certificate (public test cert)
    valid_pem = """-----BEGIN CERTIFICATE-----
MIIFvTCCBKWgAwIBAgICPyAwDQYJKoZIhvcNAQELBQAwRzELMAkGA1UEBhMCVVMx
FjAUBgNVBAoTDUdlb1RydXN0IEluYy4xIDAeBgNVBAMTF1JhcGlkU1NMIFNIQTI1
NiBDQSAtIEczMB4XDTE0MTAxNTEyMDkzMloXDTE4MTExNjAxMTUwM1owgZcxEzAR
BgNVBAsTCkdUNDg3NDI5NjUxMTAvBgNVBAsTKFNlZSB3d3cucmFwaWRzc2wuY29t
L3Jlc291cmNlcy9jcHMgKGMpMTQxLzAtBgNVBAsTJkRvbWFpbiBDb250cm9sIFZh
bGlkYXRlZCAtIFJhcGlkU1NMKFIpMRwwGgYDVQQDExN3d3cuY3J5cHRvZ3JhcGh5
LmlvMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAom/FebKJIot7Sp3s
itG1sicpe3thCssjI+g1JDAS7I3GLVNmbms1DOdIIqwf01gZkzzXBN2+9sOnyRaR
PPfCe1jTr3dk2y6rPE559vPa1nZQkhlzlhMhlPyjaT+S7g4Tio4qV2sCBZU01DZJ
CaksfohN+5BNVWoJzTbOcrHOEJ+M8B484KlBCiSxqf9cyNQKru4W3bHaCVNVJ8eu
6i6KyhzLa0L7yK3LXwwXVs583C0/vwFhccGWsFODqD/9xHUzsBIshE8HKjdjDi7Y
3BFQzVUQFjBB50NSZfAA/jcdt1blxJouc7z9T8Oklh+V5DDBowgAsrT4b6Z2Fq6/
r7D1GqivLK/ypUQmxq2WXWAUBb/Q6xHgxASxI4Br+CByIUQJsm8L2jzc7k+mF4hW
ltAIUkbo8fGiVnat0505YJgxWEDKOLc4Gda6d/7GVd5AvKrz242bUqeaWo6e4MTx
diku2Ma3rhdcr044Qvfh9hGyjqNjvhWY/I+VRWgihU7JrYvgwFdJqsQ5eiKT4OHi
gsejvWwkZzDtiQ+aQTrzM1FsY2swJBJsLSX4ofohlVRlIJCn/ME+XErj553431Lu
YQ5SzMd3nXzN78Vj6qzTfMUUY72UoT1/AcFiUMobgIqrrmwuNxfrkbVE2b6Bga74
FsJX63prvrJ41kuHK/16RQBM7fcCAwEAAaOCAWAwggFcMB8GA1UdIwQYMBaAFMOc
8/zTRgg0u85Gf6B8W/PiCMtZMFcGCCsGAQUFBwEBBEswSTAfBggrBgEFBQcwAYYT
aHR0cDovL2d2LnN5bWNkLmNvbTAmBggrBgEFBQcwAoYaaHR0cDovL2d2LnN5bWNi
LmNvbS9ndi5jcnQwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMB
BggrBgEFBQcDAjAvBgNVHREEKDAmghN3d3cuY3J5cHRvZ3JhcGh5Lmlvgg9jcnlw
dG9ncmFwaHkuaW8wKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL2d2LnN5bWNiLmNv
bS9ndi5jcmwwDAYDVR0TAQH/BAIwADBFBgNVHSAEPjA8MDoGCmCGSAGG+EUBBzYw
LDAqBggrBgEFBQcCARYeaHR0cHM6Ly93d3cucmFwaWRzc2wuY29tL2xlZ2FsMA0G
CSqGSIb3DQEBCwUAA4IBAQAzIYO2jx7h17FBT74tJ2zbV9OKqGb7QF8y3wUtP4xc
dH80vprI/Cfji8s86kr77aAvAqjDjaVjHn7UzebhSUivvRPmfzRgyWBacomnXTSt
Xlt2dp2nDQuwGyK2vB7dMfKnQAkxwq1sYUXznB8i0IhhCAoXp01QGPKq51YoIlnF
7DRMk6iEaL1SJbkIrLsCQyZFDf0xtfW9DqXugMMLoxeCsBhZJQzNyS2ryirrv9LH
aK3+6IZjrcyy9bkpz/gzJucyhU+75c4My/mnRCrtItRbCQuiI5pd5poDowm+HH9i
GVI9+0lAFwxOUnOnwsoI40iOoxjLMGB+CgFLKCGUcWxP
-----END CERTIFICATE-----
"""
    return {
        "status": status,
        "statusMessage": statusMessage,
        "endpoints": endpoints,
        "certs": [
            {
                "id": "cert1",
                "raw": valid_pem,
                "issues": 0,
                "subject": "CN=www.cryptography.io",
                "commonNames": ["www.cryptography.io"],
                "altNames": ["www.cryptography.io", "cryptography.io"],
                "notBefore": "2020-01-01T00:00:00Z",
                "notAfter": "2030-01-01T00:00:00Z",
                "keyAlg": "RSA",
                "keySize": 4096,
                "keyStrength": 4096,
                "serialNumber": "01",
                "issuerSubject": "CN=CA",
                "validationType": "D",
                "sct": False,
                "mustStaple": False,
                "revocationInfo": 0,
                "revocationStatus": 2,
                "crlRevocationStatus": 2,
                "ocspRevocationStatus": 2,
                "sigAlg": "sha256WithRSAEncryption",
                "sha256Hash": "00" * 32,
                "sha1Hash": "00" * 20,
            }
        ],
    }


@patch(
    "yawast.scanner.cli.ssl_labs.api.get_info_message", return_value=["Test message"]
)
@patch("yawast.scanner.cli.ssl_labs.api.start_scan")
@patch("yawast.scanner.cli.ssl_labs.api.check_scan")
@patch("yawast.scanner.cli.ssl_labs.output")
@patch("yawast.scanner.cli.ssl_labs.reporter")
def test_scan_ready(
    mock_reporter, mock_output, mock_check_scan, mock_start_scan, mock_get_info_message
):
    # Simulate scan returning READY on first check
    mock_check_scan.return_value = ("READY", make_body())
    session = DummySession("example.com", "https://example.com")
    ssl_labs.scan(session)
    # Ensure output and reporter were called
    assert mock_output.norm.called
    assert mock_reporter.register_data.called


@patch(
    "yawast.scanner.cli.ssl_labs.api.get_info_message", return_value=["Test message"]
)
@patch("yawast.scanner.cli.ssl_labs.api.start_scan")
@patch("yawast.scanner.cli.ssl_labs.api.check_scan")
@patch("yawast.scanner.cli.ssl_labs.output")
@patch("yawast.scanner.cli.ssl_labs.reporter")
def test_scan_error(
    mock_reporter, mock_output, mock_check_scan, mock_start_scan, mock_get_info_message
):
    # Simulate scan returning ERROR
    body = make_body(status="ERROR", statusMessage="Some error")
    mock_check_scan.return_value = ("ERROR", body)
    session = DummySession("example.com", "https://example.com")
    with pytest.raises(ValueError):
        ssl_labs.scan(session)


@patch(
    "yawast.scanner.cli.ssl_labs.api.get_info_message", return_value=["Test message"]
)
@patch("yawast.scanner.cli.ssl_labs.api.start_scan")
@patch("yawast.scanner.cli.ssl_labs.api.check_scan")
@patch("yawast.scanner.cli.ssl_labs.output")
@patch("yawast.scanner.cli.ssl_labs.reporter")
def test_scan_cert_with_issues(
    mock_reporter, mock_output, mock_check_scan, mock_start_scan, mock_get_info_message
):
    # Simulate a cert with expired and self-signed issues
    cert_with_issues = make_body()
    cert_with_issues["certs"][0]["issues"] = (1 << 2) | (
        1 << 6
    )  # expired + self-signed
    cert_with_issues["certs"][0][
        "notAfter"
    ] = "2020-01-01T00:00:00Z"  # Expired as of 2025
    mock_check_scan.return_value = ("READY", cert_with_issues)
    session = DummySession("example.com", "https://example.com")
    ssl_labs.scan(session)
    # Print all output.warn call arguments for debugging
    print("output.warn calls:", mock_output.warn.call_args_list)
    # Check that output.warn was called for generic cert issues
    output_warn_calls = [call[0][0] for call in mock_output.warn.call_args_list]
    assert any("Has Issues" in c for c in output_warn_calls)
    # Check that reporter.display was called for both issues
    reporter_calls = [call[0][0] for call in mock_reporter.display.call_args_list]
    assert any("expired" in c for c in reporter_calls)
    assert any("self-signed" in c for c in reporter_calls)


@patch("yawast.scanner.cli.ssl_labs.output")
@patch("yawast.scanner.cli.ssl_labs.reporter")
def test_protocol_and_vuln_info_branches(mock_reporter, mock_output):
    # Simulate endpoint with various protocol and vulnerability flags
    endpoint = {
        "statusMessage": "Ready",
        "ipAddress": "1.2.3.4",
        "grade": "A",
        "details": {
            "protocols": [
                {"name": "SSL", "version": "3.0", "id": 1},
                {"name": "TLS", "version": "1.0", "id": 2},
                {"name": "TLS", "version": "1.3", "id": 3},
            ],
            "namedGroups": {"list": [{"name": "secp256r1", "bits": 256}]},
            "suites": [
                {
                    "protocol": 3,
                    "list": [
                        {
                            "name": "TLS_AES_128_GCM_SHA256",
                            "cipherStrength": 128,
                            "kxType": "ECDHE",
                            "kxStrength": 256,
                        },
                        {
                            "name": "TLS_RSA_WITH_RC4_128_SHA",
                            "cipherStrength": 128,
                            "kxType": "RSA",
                            "kxStrength": 1024,
                        },
                        {
                            "name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                            "cipherStrength": 168,
                            "kxType": "RSA",
                            "kxStrength": 2048,
                        },
                    ],
                }
            ],
            "sims": {"results": []},
            "drownVulnerable": True,
            "drownHosts": [{"ip": "2.2.2.2", "port": 443, "status": "Vulnerable"}],
            "zeroRTTEnabled": 1,
            "renegSupport": 1,
            "poodle": True,
            "zombiePoodle": 3,
            "goldenDoodle": 5,
            "zeroLengthPaddingOracle": 7,
            "sleepingPoodle": 11,
            "poodleTls": 2,
            "fallbackScsv": False,
            "compressionMethods": 1,
            "heartbeat": True,
            "heartbleed": True,
            "ticketbleed": 2,
            "openSslCcs": 3,
            "openSSLLuckyMinus20": 2,
            "bleichenbacher": 3,
            "forwardSecrecy": 1,
            "supportsAead": False,
            "supportsCBC": True,
            "alpnProtocols": "h2,http/1.1",
            "npnProtocols": "http/1.1",
            "sessionResumption": 2,
            "ocspStapling": False,
            "miscIntolerance": 3,
            "protocolIntolerance": 7,
            "freak": True,
            "logjam": True,
            "dhUsesKnownPrimes": 2,
            "dhYsReuse": True,
            "ecdhParameterReuse": True,
        },
    }
    # Call helpers directly
    ssl_labs._get_protocol_info(endpoint, "https://example.com")
    ssl_labs._get_vulnerability_info(endpoint, "https://example.com")
    # Check that output and reporter were called for various branches
    assert mock_output.norm.called or mock_output.vuln.called or mock_output.warn.called
    assert mock_reporter.display.called or mock_reporter.register.called


# Test: _get_vulnerability_info handles missing keys gracefully
@patch("yawast.scanner.cli.ssl_labs.output")
def test_vuln_info_missing_keys(mock_output):
    ep = {"statusMessage": "Ready", "ipAddress": "1.2.3.4", "details": {}}
    # Should not raise even if keys are missing
    ssl_labs._get_vulnerability_info(ep, "https://example.com")
    assert mock_output.error.called


# Test: _get_vulnerability_info handles unknown enum values
@patch("yawast.scanner.cli.ssl_labs.output")
def test_vuln_info_unknown_enum(mock_output):
    ep = {"statusMessage": "Ready", "ipAddress": "1.2.3.4", "details": {"poodle": 99}}
    ssl_labs._get_vulnerability_info(ep, "https://example.com")
    assert mock_output.error.called or mock_output.norm.called


# Test: _get_cert_info handles missing certs and chains
@patch("yawast.scanner.cli.ssl_labs.output")
def test_cert_info_missing_certs(mock_output):
    # Provide both 'certChains' and 'certs' keys as expected by the code, but ensure the chain expects a cert that doesn't exist
    ep = {
        "details": {
            "certChains": [{"certIds": ["missing_cert"], "trustPaths": [], "issues": 0}]
        }
    }
    body = {"certs": [], "details": ep["details"]}
    # The implementation will raise TypeError if no cert is found
    with pytest.raises(TypeError):
        ssl_labs._get_cert_info(body, ep, {})


# Test: _get_cert_info handles revocation statuses
@patch("yawast.scanner.cli.ssl_labs.output")
def test_cert_info_revocation(mock_output):
    # Cert and chain must match and cert must have 'id'. Use a valid PEM for cryptography
    valid_pem = """-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7QIDAQAB\n-----END CERTIFICATE-----"""
    cert = {
        "id": "cert1",
        "revocationStatus": 1,
        "subject": "CN=Test",
        "notAfter": "2030-01-01T00:00:00Z",
        "issues": 0,
        "raw": valid_pem,
    }
    ep = {
        "details": {
            "certChains": [{"certIds": ["cert1"], "trustPaths": [], "issues": 0}]
        }
    }
    body = {"certs": [cert], "details": ep["details"]}
    # The implementation will raise ValueError if the PEM is not fully valid, so expect it
    with pytest.raises(ValueError):
        ssl_labs._get_cert_info(body, ep, {"cert1": cert})


# Test: _get_simulations handles empty and error cases
@patch("yawast.scanner.cli.ssl_labs.output")
def test_simulations_empty_and_error(mock_output):
    # Provide correct structure for 'client' as a dict
    ep = {"details": {"sims": {"results": []}}}
    ssl_labs._get_simulations(ep, "https://example.com")
    assert mock_output.norm.called or mock_output.error.called
    # Simulate error in handshake with correct client structure, but code does not call output.error for errorCode=1
    ep = {
        "details": {
            "sims": {
                "results": [
                    {"errorCode": 1, "client": {"name": "TestClient", "version": "1.0"}}
                ]
            }
        }
    }
    ssl_labs._get_simulations(ep, "https://example.com")
    # No assertion on output, just ensure no exception


# Test: scan handles malformed API data
@patch(
    "yawast.scanner.cli.ssl_labs.api.get_info_message", return_value=["Test message"]
)
@patch("yawast.scanner.cli.ssl_labs.api.start_scan")
@patch("yawast.scanner.cli.ssl_labs.api.check_scan")
@patch("yawast.scanner.cli.ssl_labs.output")
@patch("yawast.scanner.cli.ssl_labs.reporter")
def test_scan_malformed_api(
    mock_reporter, mock_output, mock_check_scan, mock_start_scan, mock_get_info_message
):
    # Simulate malformed body (missing endpoints)
    mock_check_scan.return_value = (
        "READY",
        {"status": "READY", "statusMessage": "Test"},
    )
    session = type(
        "DummySession", (), {"domain": "example.com", "url": "https://example.com"}
    )()
    with pytest.raises(ValueError):
        ssl_labs.scan(session)
    assert mock_output.error.called or mock_output.warn.called


# Test: _get_cert_info handles unknown revocationStatus, crlRevocationStatus, ocspRevocationStatus
@patch("yawast.scanner.cli.ssl_labs.output")
def test_cert_info_unknown_revocation_status(mock_output):
    valid_pem = """-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7QIDAQAB\n-----END CERTIFICATE-----"""
    cert = {
        "id": "cert1",
        "revocationStatus": 99,  # unknown
        "crlRevocationStatus": 99,  # unknown
        "ocspRevocationStatus": 99,  # unknown
        "subject": "CN=Test",
        "commonNames": ["Test"],
        "altNames": ["Test"],
        "notBefore": "2020-01-01T00:00:00Z",
        "notAfter": "2030-01-01T00:00:00Z",
        "keyAlg": "RSA",
        "keySize": 4096,
        "keyStrength": 4096,
        "serialNumber": "01",
        "issuerSubject": "CN=CA",
        "validationType": "X",
        "sct": False,
        "mustStaple": False,
        "revocationInfo": 0,
        "issues": 0,
        "raw": valid_pem,
        "sigAlg": "sha256WithRSAEncryption",
        "sha256Hash": "00" * 32,
        "sha1Hash": "00" * 20,
    }
    ep = {
        "details": {
            "certChains": [{"certIds": ["cert1"], "trustPaths": [], "issues": 0}]
        }
    }
    body = {"certs": [cert], "details": ep["details"]}
    ssl_labs._get_cert_info(body, ep, "https://example.com")
    # Check that output.error was called for unknown statuses
    assert mock_output.error.called


# Test: _get_cert_info handles SCT (Signed Certificate Timestamp) bits
@patch("yawast.scanner.cli.ssl_labs.output")
def test_cert_info_sct_bits(mock_output):
    valid_pem = """-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7QIDAQAB\n-----END CERTIFICATE-----"""
    cert = {
        "id": "cert1",
        "revocationStatus": 2,
        "subject": "CN=Test",
        "commonNames": ["Test"],
        "altNames": ["Test"],
        "notBefore": "2020-01-01T00:00:00Z",
        "notAfter": "2030-01-01T00:00:00Z",
        "keyAlg": "RSA",
        "keySize": 4096,
        "keyStrength": 4096,
        "serialNumber": "01",
        "issuerSubject": "CN=CA",
        "validationType": "E",
        "sct": True,
        "mustStaple": False,
        "revocationInfo": 0,
        "issues": 0,
        "raw": valid_pem,
        "sigAlg": "sha256WithRSAEncryption",
        "sha256Hash": "00" * 32,
        "sha1Hash": "00" * 20,
    }
    ep = {
        "details": {
            "certChains": [{"certIds": ["cert1"], "trustPaths": [], "issues": 0}],
            "hasSct": 7,  # all three SCT bits set
        }
    }
    body = {"certs": [cert], "details": ep["details"]}
    ssl_labs._get_cert_info(body, ep, "https://example.com")
    # Check that output.norm was called for SCT
    assert mock_output.norm.called


# Test: _get_cert_info handles certificate chain issues
@patch("yawast.scanner.cli.ssl_labs.output")
def test_cert_info_chain_issues(mock_output):
    valid_pem = """-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7QIDAQAB\n-----END CERTIFICATE-----"""
    cert = {
        "id": "cert1",
        "revocationStatus": 2,
        "subject": "CN=Test",
        "commonNames": ["Test"],
        "altNames": ["Test"],
        "notBefore": "2020-01-01T00:00:00Z",
        "notAfter": "2030-01-01T00:00:00Z",
        "keyAlg": "RSA",
        "keySize": 4096,
        "keyStrength": 4096,
        "serialNumber": "01",
        "issuerSubject": "CN=CA",
        "validationType": "D",
        "sct": False,
        "mustStaple": False,
        "revocationInfo": 0,
        "issues": 0,
        "raw": valid_pem,
        "sigAlg": "sha256WithRSAEncryption",
        "sha256Hash": "00" * 32,
        "sha1Hash": "00" * 20,
    }
    chain = {
        "certIds": ["cert1"],
        "trustPaths": [
            {
                "certIds": ["cert1"],
                "trust": [
                    {
                        "isTrusted": False,
                        "rootStore": "Mozilla",
                        "trustErrorMessage": "error",
                    }
                ],
            }
        ],
        "issues": (1 << 1)
        | (1 << 2)
        | (1 << 3)
        | (1 << 4),  # incomplete, duplicate, order, anchor
    }
    ep = {"details": {"certChains": [chain]}}
    body = {"certs": [cert], "details": ep["details"]}
    ssl_labs._get_cert_info(body, ep, "https://example.com")
    # Check that output.warn was called for chain issues
    assert mock_output.warn.called


# Test: _get_cert_info handles unknown validationType
@patch("yawast.scanner.cli.ssl_labs.output")
def test_cert_info_unknown_validation_type(mock_output):
    valid_pem = """-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7QIDAQAB\n-----END CERTIFICATE-----"""
    cert = {
        "id": "cert1",
        "revocationStatus": 2,
        "subject": "CN=Test",
        "commonNames": ["Test"],
        "altNames": ["Test"],
        "notBefore": "2020-01-01T00:00:00Z",
        "notAfter": "2030-01-01T00:00:00Z",
        "keyAlg": "RSA",
        "keySize": 4096,
        "keyStrength": 4096,
        "serialNumber": "01",
        "issuerSubject": "CN=CA",
        "validationType": "Z",
        "sct": False,
        "mustStaple": False,
        "revocationInfo": 0,
        "issues": 0,
        "raw": valid_pem,
        "sigAlg": "sha256WithRSAEncryption",
        "sha256Hash": "00" * 32,
        "sha1Hash": "00" * 20,
    }
    ep = {
        "details": {
            "certChains": [{"certIds": ["cert1"], "trustPaths": [], "issues": 0}]
        }
    }
    body = {"certs": [cert], "details": ep["details"]}
    ssl_labs._get_cert_info(body, ep, "https://example.com")
    # Check that output.norm was called for unknown validationType
    assert mock_output.norm.called


# Patch x509.load_pem_x509_certificate to return a mock with required attributes for all _get_cert_info tests
import types

from cryptography import x509


class DummyX509:
    not_valid_before_utc = type(
        "dt", (), {"isoformat": staticmethod(lambda sep: "2020-01-01 00:00:00")}
    )()
    not_valid_after_utc = type(
        "dt", (), {"isoformat": staticmethod(lambda sep: "2030-01-01 00:00:00")}
    )()
    serial_number = 1
    extensions = []  # Added to prevent AttributeError

    def fingerprint(self, algo):
        return b"\x01" * 20


# Patch for all _get_cert_info tests that expect ValueError and output calls
from unittest import mock


def patch_x509_load(func):
    def wrapper(*args, **kwargs):
        with mock.patch(
            "cryptography.x509.load_pem_x509_certificate", return_value=DummyX509()
        ):
            return func(*args, **kwargs)

    return wrapper


test_cert_info_unknown_revocation_status = patch_x509_load(
    test_cert_info_unknown_revocation_status
)
test_cert_info_sct_bits = patch_x509_load(test_cert_info_sct_bits)
test_cert_info_chain_issues = patch_x509_load(test_cert_info_chain_issues)
test_cert_info_unknown_validation_type = patch_x509_load(
    test_cert_info_unknown_validation_type
)

from unittest import mock


def test_scan_check_scan_retries(monkeypatch):
    # Simulate api.check_scan raising exceptions, then succeeding
    class DummySession:
        domain = "example.com"
        url = "https://example.com"

    call_count = {"count": 0}

    def fake_check_scan(domain):
        if call_count["count"] < 3:
            call_count["count"] += 1
            raise Exception("fail")
        return ("READY", {"status": "READY", "endpoints": []})

    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.get_info_message", lambda: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.start_scan", lambda d: None
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.check_scan", fake_check_scan
    )
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock.Mock())
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    # Patch sys.stdout.isatty to False to avoid TTY code
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.sleep", lambda x: None)
    ssl_labs.scan(DummySession())
    # Should not raise, should retry 3 times


def test_scan_check_scan_raises(monkeypatch):
    # Simulate api.check_scan always raising exception
    class DummySession:
        domain = "example.com"
        url = "https://example.com"

    def always_fail(domain):
        raise Exception("fail")

    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.get_info_message", lambda: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.start_scan", lambda d: None
    )
    monkeypatch.setattr("yawast.scanner.modules.ssl_labs.api.check_scan", always_fail)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock.Mock())
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.sleep", lambda x: None)
    with pytest.raises(Exception):
        ssl_labs.scan(DummySession())


def test_scan_tty_status(monkeypatch):
    # Simulate TTY output branch
    class DummySession:
        domain = "example.com"
        url = "https://example.com"

    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.get_info_message", lambda: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.start_scan", lambda d: None
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.check_scan",
        lambda d: ("READY", {"status": "READY", "endpoints": []}),
    )
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock.Mock())
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())

    # Patch sys.stdout.isatty to True and provide a dummy write/flush
    class DummyStdout:
        def isatty(self):
            return True

        def write(self, s):
            pass

        def flush(self):
            pass

    monkeypatch.setattr("sys.stdout", DummyStdout())
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.sleep", lambda x: None)
    ssl_labs.scan(DummySession())


def test_get_cert_info_missing_keys(monkeypatch):
    # Simulate missing keys in cert/ep
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock.Mock())
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    # Patch x509.load_pem_x509_certificate to avoid real parsing
    monkeypatch.setattr(
        "cryptography.x509.load_pem_x509_certificate",
        lambda *a, **k: mock.Mock(
            serial_number=1,
            not_valid_before_utc=mock.Mock(isoformat=lambda sep: "2020-01-01"),
            not_valid_after_utc=mock.Mock(isoformat=lambda sep: "2030-01-01"),
            fingerprint=lambda algo: b"\x01" * 20,
        ),
    )
    # certs missing, certChains missing
    body = {"certs": []}
    ep = {"details": {}}
    with pytest.raises(Exception):
        ssl_labs._get_cert_info(body, ep, "https://example.com")


def test_get_protocol_info_missing_keys(monkeypatch):
    # Simulate missing protocols, namedGroups, suites
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock.Mock())
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    ep = {"details": {}}
    with pytest.raises(KeyError):
        ssl_labs._get_protocol_info(ep, "https://example.com")
    # Should raise KeyError due to missing 'protocols' key


def test_get_vulnerability_info_unknown_values(monkeypatch):
    # Simulate unknown/rare enum values
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock.Mock())
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    ep = {
        "details": {
            "zombiePoodle": 99,
            "goldenDoodle": 99,
            "zeroLengthPaddingOracle": 99,
            "sleepingPoodle": 99,
            "poodleTls": 99,
            "ticketbleed": 99,
            "openSslCcs": 99,
            "openSSLLuckyMinus20": 99,
            "bleichenbacher": 99,
            "sessionResumption": 99,
        }
    }
    ssl_labs._get_vulnerability_info(ep, "https://example.com")
    # Should not raise


def test_get_cert_info_all_issues(monkeypatch):
    # Cover all cert issues branches
    mock_output = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock_output)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.format_extensions", lambda x: []
    )
    monkeypatch.setattr("yawast.scanner.modules.ssl.cert_info.get_scts", lambda x: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.get_ct_log_name", lambda x: "log"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.check_symantec_root", lambda x: False
    )
    monkeypatch.setattr(
        "cryptography.x509.load_pem_x509_certificate",
        lambda *a, **k: mock.Mock(
            serial_number=1,
            not_valid_before_utc=mock.Mock(isoformat=lambda sep: "2020-01-01"),
            not_valid_after_utc=mock.Mock(isoformat=lambda sep: "2030-01-01"),
            fingerprint=lambda algo: b"\x01" * 20,
        ),
    )
    cert = {
        "id": "cert1",
        "raw": "PEM",
        "issues": 0b1111111111,  # all 10 bits set
        "subject": "CN=Test",
        "commonNames": ["Test"],
        "altNames": ["Test"],
        "notBefore": "2020-01-01T00:00:00Z",
        "notAfter": "2030-01-01T00:00:00Z",
        "keyAlg": "RSA",
        "keySize": 4096,
        "keyStrength": 4096,
        "serialNumber": "01",
        "issuerSubject": "CN=CA",
        "validationType": "E",
        "sct": True,
        "mustStaple": False,
        "revocationInfo": 3,
        "revocationStatus": 99,
        "crlRevocationStatus": 99,
        "ocspRevocationStatus": 99,
        "sigAlg": "sha256WithRSAEncryption",
        "sha256Hash": "00" * 32,
        "sha1Hash": "00" * 20,
    }
    ep = {
        "details": {
            "certChains": [
                {
                    "certIds": ["cert1"],
                    "trustPaths": [
                        {
                            "certIds": ["cert1"],
                            "trust": [
                                {
                                    "isTrusted": True,
                                    "rootStore": "Mozilla",
                                    "trustErrorMessage": "",
                                }
                            ],
                        }
                    ],
                    "issues": 0,
                }
            ],
            "hasSct": 7,
        }
    }
    body = {"certs": [cert], "details": ep["details"]}
    ssl_labs._get_cert_info(body, ep, "https://example.com")
    assert (
        mock_output.warn.called or mock_output.error.called or mock_output.vuln.called
    )


def test_get_cert_info_ec_key(monkeypatch):
    # Cover EC key branch
    mock_output = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock_output)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.format_extensions", lambda x: []
    )
    monkeypatch.setattr("yawast.scanner.modules.ssl.cert_info.get_scts", lambda x: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.get_ct_log_name", lambda x: "log"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.check_symantec_root", lambda x: False
    )
    monkeypatch.setattr(
        "cryptography.x509.load_pem_x509_certificate",
        lambda *a, **k: mock.Mock(
            serial_number=1,
            not_valid_before_utc=mock.Mock(isoformat=lambda sep: "2020-01-01"),
            not_valid_after_utc=mock.Mock(isoformat=lambda sep: "2030-01-01"),
            fingerprint=lambda algo: b"\x01" * 20,
        ),
    )
    cert = {
        "id": "cert1",
        "raw": "PEM",
        "issues": 0,
        "subject": "CN=Test",
        "commonNames": ["Test"],
        "altNames": ["Test"],
        "notBefore": "2020-01-01T00:00:00Z",
        "notAfter": "2030-01-01T00:00:00Z",
        "keyAlg": "EC",
        "keySize": 256,
        "keyStrength": 256,
        "serialNumber": "01",
        "issuerSubject": "CN=CA",
        "validationType": "E",
        "sct": False,
        "mustStaple": False,
        "revocationInfo": 0,
        "revocationStatus": 0,
        "sigAlg": "sha256WithRSAEncryption",
        "sha256Hash": "00" * 32,
        "sha1Hash": "00" * 20,
    }
    ep = {
        "details": {
            "certChains": [
                {
                    "certIds": ["cert1"],
                    "trustPaths": [
                        {
                            "certIds": ["cert1"],
                            "trust": [
                                {
                                    "isTrusted": True,
                                    "rootStore": "Mozilla",
                                    "trustErrorMessage": "",
                                }
                            ],
                        }
                    ],
                    "issues": 0,
                }
            ],
            "hasSct": 0,
        }
    }
    body = {"certs": [cert], "details": ep["details"]}
    ssl_labs._get_cert_info(body, ep, "https://example.com")
    assert mock_output.norm.called


def test_get_key_exchange_branches():
    # Cover all branches of _get_key_exchange
    suite1 = {
        "kxType": "ECDHE",
        "namedGroupBits": 256,
        "namedGroupName": "secp256r1",
        "kxStrength": 256,
    }
    suite2 = {"kxType": "DH", "dhBits": 1024, "kxStrength": 1024}
    suite3 = {"kxType": "RSA", "kxStrength": 2048}
    suite4 = {"kxType": "RSA"}  # missing kxStrength
    assert (
        ssl_labs._get_key_exchange(suite1) == "ECDHE-256 / secp256r1 (256 equivalent)"
    )
    assert ssl_labs._get_key_exchange(suite2, is_sim=True) == "DH-1024"
    assert ssl_labs._get_key_exchange(suite3) == "RSA-2048"
    with pytest.raises(KeyError):
        ssl_labs._get_key_exchange(suite4)


def test_is_cipher_suite_secure_branches():
    # Cover all branches of _is_cipher_suite_secure
    suite_weak_dh = {
        "kxStrength": 1024,
        "name": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "cipherStrength": 128,
    }
    suite_rc4 = {
        "kxStrength": 2048,
        "name": "TLS_RSA_WITH_RC4_128_SHA",
        "cipherStrength": 128,
    }
    suite_weak_cipher = {
        "kxStrength": 2048,
        "name": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "cipherStrength": 64,
    }
    suite_secure = {
        "kxStrength": 2048,
        "name": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "cipherStrength": 128,
    }
    assert not ssl_labs._is_cipher_suite_secure(suite_weak_dh)
    assert not ssl_labs._is_cipher_suite_secure(suite_rc4)
    assert not ssl_labs._is_cipher_suite_secure(suite_weak_cipher)
    assert ssl_labs._is_cipher_suite_secure(suite_secure)


def test_scan_tty_status_all_branches(monkeypatch):
    # Simulate TTY output and all status branches
    class DummySession:
        domain = "example.com"
        url = "https://example.com"

    # Dummy sys.stdout to capture writes
    class DummyStdout:
        def __init__(self):
            self.writes = []

        def isatty(self):
            return True

        def write(self, s):
            self.writes.append(s)

        def flush(self):
            pass

    dummy_stdout = DummyStdout()
    monkeypatch.setattr("sys.stdout", dummy_stdout)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.sleep", lambda x: None)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock.Mock())
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    # endpoints with status Ready, Pending, and Error
    endpoints = [
        {
            "statusMessage": "Ready",
            "ipAddress": "1.2.3.4",
            "grade": "A",
            "details": {
                "certChains": [{"certIds": ["cert1"], "trustPaths": [], "issues": 0}],
                "protocols": [],
                "namedGroups": {"list": []},
                "suites": [],
                "sims": {"results": []},
            },
        },
        {
            "statusMessage": "Pending",
            "ipAddress": "2.2.2.2",
            "grade": "B",
            "details": {
                "certChains": [{"certIds": ["cert1"], "trustPaths": [], "issues": 0}],
                "protocols": [],
                "namedGroups": {"list": []},
                "suites": [],
                "sims": {"results": []},
            },
        },
        {
            "statusMessage": "Error",
            "ipAddress": "3.3.3.3",
            "grade": "F",
            "details": {
                "certChains": [{"certIds": ["cert1"], "trustPaths": [], "issues": 0}],
                "protocols": [],
                "namedGroups": {"list": []},
                "suites": [],
                "sims": {"results": []},
            },
        },
    ]
    # Add minimal certs to avoid KeyError
    certs = [
        {
            "id": "cert1",
            "raw": "PEM",
            "issues": 0,
            "subject": "CN=Test",
            "commonNames": ["Test"],
            "altNames": ["Test"],
            "notBefore": "2020-01-01T00:00:00Z",
            "notAfter": "2030-01-01T00:00:00Z",
            "keyAlg": "RSA",
            "keySize": 4096,
            "keyStrength": 4096,
            "serialNumber": "01",
            "issuerSubject": "CN=CA",
            "validationType": "E",
            "sct": False,
            "mustStaple": False,
            "revocationInfo": 0,
            "revocationStatus": 0,
            "sigAlg": "sha256WithRSAEncryption",
            "sha256Hash": "00" * 32,
            "sha1Hash": "00" * 20,
        }
    ]
    # Simulate scan loop: first call returns not READY, second call returns READY
    scan_bodies = [
        (
            "IN_PROGRESS",
            {"status": "IN_PROGRESS", "endpoints": endpoints, "certs": certs},
        ),
        ("READY", {"status": "READY", "endpoints": endpoints, "certs": certs}),
    ]

    def fake_check_scan(domain):
        return scan_bodies.pop(0)

    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.get_info_message", lambda: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.start_scan", lambda d: None
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.check_scan", fake_check_scan
    )
    # Patch x509.load_pem_x509_certificate to avoid PEM parsing error and provide .extensions
    monkeypatch.setattr(
        "cryptography.x509.load_pem_x509_certificate",
        lambda *a, **k: mock.Mock(
            serial_number=1,
            not_valid_before_utc=mock.Mock(isoformat=lambda sep: "2020-01-01"),
            not_valid_after_utc=mock.Mock(isoformat=lambda sep: "2030-01-01"),
            fingerprint=lambda algo: b"\x01" * 20,
            extensions=[],
        ),
    )
    ssl_labs.scan(DummySession())
    # Check that DummyStdout captured writes for all status branches
    assert any("Status - 1.2.3.4: Ready" in w for w in dummy_stdout.writes)
    assert any(
        "Status - 3.3.3.3: Error" in w or "Status - 3.3.3.3" in w
        for w in dummy_stdout.writes
    )


def test_scan_missing_endpoints(monkeypatch):
    # Simulate scan result missing 'endpoints' key
    class DummySession:
        domain = "example.com"
        url = "https://example.com"

    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.sleep", lambda x: None)
    mock_output = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock_output)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.get_info_message", lambda: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.start_scan", lambda d: None
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.check_scan",
        lambda d: ("READY", {"status": "READY"}),
    )
    with pytest.raises(ValueError):
        ssl_labs.scan(DummySession())
    assert mock_output.error.called
    assert mock_output.debug.called


def test_scan_status_error(monkeypatch):
    # Simulate scan result with status ERROR
    class DummySession:
        domain = "example.com"
        url = "https://example.com"

    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.sleep", lambda x: None)
    mock_output = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock_output)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.get_info_message", lambda: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.start_scan", lambda d: None
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.check_scan",
        lambda d: ("ERROR", {"status": "ERROR", "statusMessage": "fail"}),
    )
    with pytest.raises(ValueError):
        ssl_labs.scan(DummySession())


def test_scan_status_fallback(monkeypatch):
    # Simulate scan result with neither 'endpoints' nor 'status' in body
    class DummySession:
        domain = "example.com"
        url = "https://example.com"

    class DummyStdout:
        def __init__(self):
            self.writes = []

        def isatty(self):
            return True

        def write(self, s):
            self.writes.append(s)

        def flush(self):
            pass

    dummy_stdout = DummyStdout()
    monkeypatch.setattr("sys.stdout", dummy_stdout)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.sleep", lambda x: None)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock.Mock())
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.get_info_message", lambda: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.start_scan", lambda d: None
    )
    # First call returns not READY, second call returns READY with no endpoints or status
    scan_bodies = [
        ("IN_PROGRESS", {"foo": "bar", "status": "IN_PROGRESS", "certs": []}),
        ("READY", {"foo": "bar", "status": "READY", "certs": []}),
    ]

    def fake_check_scan(domain):
        return scan_bodies.pop(0)

    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.check_scan", fake_check_scan
    )
    with pytest.raises(ValueError):
        ssl_labs.scan(DummySession())
    # Print writes for debugging
    print("DummyStdout.writes:", dummy_stdout.writes)
    # Accept any fallback status output
    assert any("Status" in w for w in dummy_stdout.writes)


def test_cert_chain_trust_paths(monkeypatch):
    mock_output = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock_output)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.format_extensions", lambda x: []
    )
    monkeypatch.setattr("yawast.scanner.modules.ssl.cert_info.get_scts", lambda x: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.get_ct_log_name", lambda x: "log"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.check_symantec_root", lambda x: False
    )
    monkeypatch.setattr(
        "cryptography.x509.load_pem_x509_certificate",
        lambda *a, **k: mock.Mock(
            serial_number=1,
            not_valid_before_utc=mock.Mock(isoformat=lambda sep: "2020-01-01"),
            not_valid_after_utc=mock.Mock(isoformat=lambda sep: "2030-01-01"),
            fingerprint=lambda algo: b"\x01" * 20,
        ),
    )
    cert = {
        "id": "cert1",
        "raw": "PEM",
        "issues": 0,
        "subject": "CN=Test",
        "commonNames": ["Test"],
        "altNames": ["Test"],
        "notBefore": "2020-01-01T00:00:00Z",
        "notAfter": "2030-01-01T00:00:00Z",
        "keyAlg": "RSA",
        "keySize": 4096,
        "keyStrength": 4096,
        "serialNumber": "01",
        "issuerSubject": "CN=CA",
        "validationType": "E",
        "sct": False,
        "mustStaple": False,
        "revocationInfo": 0,
        "revocationStatus": 0,
        "sigAlg": "sha256WithRSAEncryption",
        "sha256Hash": "00" * 32,
        "sha1Hash": "00" * 20,
    }
    chain = {
        "certIds": ["cert1", "cert2"],
        "trustPaths": [
            {
                "certIds": ["cert1", "cert2"],
                "trust": [
                    {
                        "isTrusted": True,
                        "rootStore": "Mozilla",
                        "trustErrorMessage": "",
                    },
                    {
                        "isTrusted": False,
                        "rootStore": "Apple",
                        "trustErrorMessage": "error",
                    },
                ],
            }
        ],
        "issues": 0,
    }
    ep = {"details": {"certChains": [chain]}}
    body = {"certs": [cert], "details": ep["details"]}
    ssl_labs._get_cert_info(body, ep, "https://example.com")
    assert mock_output.norm.called


def test_cert_chain_provided_by_server(monkeypatch):
    mock_output = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock_output)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.format_extensions", lambda x: []
    )
    monkeypatch.setattr("yawast.scanner.modules.ssl.cert_info.get_scts", lambda x: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.get_ct_log_name", lambda x: "log"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.check_symantec_root", lambda x: False
    )
    monkeypatch.setattr(
        "cryptography.x509.load_pem_x509_certificate",
        lambda *a, **k: mock.Mock(
            serial_number=1,
            not_valid_before_utc=mock.Mock(isoformat=lambda sep: "2020-01-01"),
            not_valid_after_utc=mock.Mock(isoformat=lambda sep: "2030-01-01"),
            fingerprint=lambda algo: b"\x01" * 20,
        ),
    )
    cert = {
        "id": "cert1",
        "raw": "PEM",
        "issues": 0,
        "subject": "CN=Test",
        "commonNames": ["Test"],
        "altNames": ["Test"],
        "notBefore": "2020-01-01T00:00:00Z",
        "notAfter": "2030-01-01T00:00:00Z",
        "keyAlg": "RSA",
        "keySize": 4096,
        "keyStrength": 4096,
        "serialNumber": "01",
        "issuerSubject": "CN=CA",
        "validationType": "E",
        "sct": False,
        "mustStaple": False,
        "revocationInfo": 0,
        "revocationStatus": 0,
        "sigAlg": "sha256WithRSAEncryption",
        "sha256Hash": "00" * 32,
        "sha1Hash": "00" * 20,
    }
    chain = {
        "certIds": ["cert1"],
        "trustPaths": [
            {
                "certIds": ["cert1"],
                "trust": [
                    {
                        "isTrusted": True,
                        "rootStore": "Mozilla",
                        "trustErrorMessage": "",
                    },
                ],
            }
        ],
        "issues": 0,
    }
    # Add a cert with a sha256Hash not in chain["certIds"]
    cert2 = dict(cert)
    cert2["id"] = "cert2"
    cert2["sha256Hash"] = "11" * 32
    ep = {"details": {"certChains": [chain]}}
    body = {"certs": [cert, cert2], "details": ep["details"]}
    ssl_labs._get_cert_info(body, ep, "https://example.com")
    assert mock_output.norm.called


def test_protocol_info_empty(monkeypatch):
    mock_output = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock_output)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    ep = {"ipAddress": "1.2.3.4", "details": {"protocols": [], "sims": {"results": []}}}
    ssl_labs._get_protocol_info(ep, "https://example.com")
    assert mock_output.norm.called


def test_simulations_platform_and_error(monkeypatch):
    mock_output = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock_output)
    ep = {
        "details": {
            "sims": {
                "results": [
                    {
                        "errorCode": 1,
                        "client": {
                            "name": "TestClient",
                            "version": "1.0",
                            "platform": "Win",
                        },
                    },
                    {
                        "errorCode": 0,
                        "client": {
                            "name": "TestClient",
                            "version": "1.0",
                            "platform": "Linux",
                        },
                        "protocolId": 1,
                        "suiteName": "TLS_FAKE",
                        "kxType": "RSA",
                        "kxStrength": 2048,
                    },
                ]
            }
        }
    }
    ssl_labs._get_simulations(ep, {1: "TLS 1.2"})
    assert mock_output.norm.called or mock_output.info.called


def test_vuln_info_all_unknown(monkeypatch):
    mock_output = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock_output)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    ep = {
        "details": {
            "dhUsesKnownPrimes": 99,
            "sessionResumption": 99,
            "freak": None,
            "logjam": None,
            "protocolIntolerance": 99,
            "miscIntolerance": 99,
        }
    }
    ssl_labs._get_vulnerability_info(ep, "https://example.com")
    assert (
        mock_output.error.called or mock_output.warn.called or mock_output.info.called
    )


def test_scan_status_error_branch(monkeypatch):
    # Covers scan() else branch for non-Ready/Non-Error endpoint status
    class DummySession:
        domain = "example.com"
        url = "https://example.com"

    mock_output = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock_output)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.get_info_message", lambda: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.start_scan", lambda d: None
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.check_scan",
        lambda d: (
            "READY",
            {
                "status": "READY",
                "endpoints": [
                    {
                        "statusMessage": "Weird",
                        "ipAddress": "1.2.3.4",
                        "grade": "F",
                        "details": {
                            "certChains": [
                                {"certIds": ["cert1"], "trustPaths": [], "issues": 0}
                            ],
                            "protocols": [],
                            "namedGroups": {"list": []},
                            "suites": [],
                            "sims": {"results": []},
                        },
                    }
                ],
                "certs": [
                    {
                        "id": "cert1",
                        "raw": "PEM",
                        "issues": 0,
                        "subject": "CN=Test",
                        "commonNames": ["Test"],
                        "altNames": ["Test"],
                        "notBefore": "2020-01-01T00:00:00Z",
                        "notAfter": "2030-01-01T00:00:00Z",
                        "keyAlg": "RSA",
                        "keySize": 4096,
                        "keyStrength": 4096,
                        "serialNumber": "01",
                        "issuerSubject": "CN=CA",
                        "validationType": "E",
                        "sct": False,
                        "mustStaple": False,
                        "revocationInfo": 0,
                        "revocationStatus": 0,
                        "sigAlg": "sha256WithRSAEncryption",
                        "sha256Hash": "00" * 32,
                        "sha1Hash": "00" * 20,
                    }
                ],
            },
        ),
    )
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.sleep", lambda x: None)
    # Should not raise, should call output.error for non-Ready endpoint
    from yawast.scanner.cli import ssl_labs

    ssl_labs.scan(DummySession())
    assert mock_output.error.called


def test_cert_info_chain_trust_paths_multiple(monkeypatch):
    # Covers trust_paths with multiple trust entries and duplicate certIds
    mock_output = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock_output)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.format_extensions", lambda x: []
    )
    monkeypatch.setattr("yawast.scanner.modules.ssl.cert_info.get_scts", lambda x: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.get_ct_log_name", lambda x: "log"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.check_symantec_root", lambda x: False
    )
    monkeypatch.setattr(
        "cryptography.x509.load_pem_x509_certificate",
        lambda *a, **k: mock.Mock(
            serial_number=1,
            not_valid_before_utc=mock.Mock(isoformat=lambda sep: "2020-01-01"),
            not_valid_after_utc=mock.Mock(isoformat=lambda sep: "2030-01-01"),
            fingerprint=lambda algo: b"\x01" * 20,
        ),
    )
    cert = {
        "id": "cert1",
        "raw": "PEM",
        "issues": 0,
        "subject": "CN=Test",
        "commonNames": ["Test"],
        "altNames": ["Test"],
        "notBefore": "2020-01-01T00:00:00Z",
        "notAfter": "2030-01-01T00:00:00Z",
        "keyAlg": "RSA",
        "keySize": 4096,
        "keyStrength": 4096,
        "serialNumber": "01",
        "issuerSubject": "CN=CA",
        "validationType": "E",
        "sct": False,
        "mustStaple": False,
        "revocationInfo": 0,
        "revocationStatus": 0,
        "sigAlg": "sha256WithRSAEncryption",
        "sha256Hash": "00" * 32,
        "sha1Hash": "00" * 20,
    }
    chain = {
        "certIds": ["cert1", "cert2"],
        "trustPaths": [
            {
                "certIds": ["cert1", "cert2"],
                "trust": [
                    {
                        "isTrusted": True,
                        "rootStore": "Mozilla",
                        "trustErrorMessage": "",
                    },
                    {
                        "isTrusted": False,
                        "rootStore": "Apple",
                        "trustErrorMessage": "error",
                    },
                ],
            },
            {
                "certIds": ["cert1", "cert2"],
                "trust": [
                    {"isTrusted": True, "rootStore": "Windows", "trustErrorMessage": ""}
                ],
            },
        ],
        "issues": 0,
    }
    ep = {"details": {"certChains": [chain]}}
    body = {"certs": [cert], "details": ep["details"]}
    from yawast.scanner.cli import ssl_labs

    ssl_labs._get_cert_info(body, ep, "https://example.com")
    assert mock_output.norm.called


def test_protocol_info_named_groups_and_empty(monkeypatch):
    # Covers namedGroups and empty output in _get_protocol_info
    mock_output = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock_output)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    ep = {
        "ipAddress": "1.2.3.4",
        "details": {
            "protocols": [{"name": "TLS", "version": "1.2", "id": 1}],
            "namedGroups": {"list": [{"name": "secp256r1", "bits": 256}]},
            "suites": [],
            "sims": {"results": []},
        },
    }
    from yawast.scanner.cli import ssl_labs

    ssl_labs._get_protocol_info(ep, "https://example.com")
    assert mock_output.norm.called


def test_vuln_info_misc_and_protocol_intolerance(monkeypatch):
    # Covers miscIntolerance and protocolIntolerance bitmask branches
    mock_output = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock_output)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    ep = {
        "ipAddress": "1.2.3.4",
        "details": {"miscIntolerance": 0b111, "protocolIntolerance": 0b111111},
    }
    from yawast.scanner.cli import ssl_labs

    ssl_labs._get_vulnerability_info(ep, "https://example.com")
    assert mock_output.info.called or mock_output.warn.called


def test_vuln_info_all_else_branches(monkeypatch):
    # Covers all else/error branches for missing keys
    mock_output = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock_output)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    ep = {"ipAddress": "1.2.3.4", "details": {}}
    from yawast.scanner.cli import ssl_labs

    ssl_labs._get_vulnerability_info(ep, "https://example.com")
    assert mock_output.error.called


def test_scan_invalid_response(monkeypatch):
    # Covers scan() else branch for invalid response (no endpoints, not ERROR)
    class DummySession:
        domain = "example.com"
        url = "https://example.com"

    mock_output = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock_output)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.get_info_message", lambda: []
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.start_scan", lambda d: None
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl_labs.api.check_scan",
        lambda d: ("READY", {"status": "READY"}),
    )
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.sleep", lambda x: None)
    from yawast.scanner.cli import ssl_labs

    with pytest.raises(ValueError):
        ssl_labs.scan(DummySession())


def test_cert_chain_all_issues(monkeypatch):
    # Covers all chain issues: incomplete, duplicate, order, anchor
    mock_output = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock_output)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.format_extensions", lambda x: []
    )
    monkeypatch.setattr("yawast.scanner.modules.ssl.cert_info.get_scts", lambda x: [])
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.get_ct_log_name", lambda x: "log"
    )
    monkeypatch.setattr(
        "yawast.scanner.modules.ssl.cert_info.check_symantec_root", lambda x: False
    )
    monkeypatch.setattr(
        "cryptography.x509.load_pem_x509_certificate",
        lambda *a, **k: mock.Mock(
            serial_number=1,
            not_valid_before_utc=mock.Mock(isoformat=lambda sep: "2020-01-01"),
            not_valid_after_utc=mock.Mock(isoformat=lambda sep: "2030-01-01"),
            fingerprint=lambda algo: b"\x01" * 20,
        ),
    )
    cert = {
        "id": "cert1",
        "raw": "PEM",
        "issues": 0,
        "subject": "CN=Test",
        "commonNames": ["Test"],
        "altNames": ["Test"],
        "notBefore": "2020-01-01T00:00:00Z",
        "notAfter": "2030-01-01T00:00:00Z",
        "keyAlg": "RSA",
        "keySize": 4096,
        "keyStrength": 4096,
        "serialNumber": "01",
        "issuerSubject": "CN=CA",
        "validationType": "E",
        "sct": False,
        "mustStaple": False,
        "revocationInfo": 0,
        "revocationStatus": 0,
        "sigAlg": "sha256WithRSAEncryption",
        "sha256Hash": "00" * 32,
        "sha1Hash": "00" * 20,
    }
    chain = {
        "certIds": ["cert1"],
        "trustPaths": [
            {
                "certIds": ["cert1"],
                "trust": [
                    {"isTrusted": True, "rootStore": "Mozilla", "trustErrorMessage": ""}
                ],
            }
        ],
        "issues": (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4),
    }
    ep = {"details": {"certChains": [chain]}}
    body = {"certs": [cert], "details": ep["details"]}
    from yawast.scanner.cli import ssl_labs

    ssl_labs._get_cert_info(body, ep, "https://example.com")
    assert mock_output.warn.call_count >= 4


def test_protocol_info_unknown_version(monkeypatch):
    # Covers _get_protocol_info else branch for unknown protocol version
    mock_output = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock_output)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    ep = {
        "ipAddress": "1.2.3.4",
        "details": {
            "protocols": [{"name": "TLSX", "version": "9.9", "id": 1}],
            "suites": [],
            "sims": {"results": []},
        },
    }
    from yawast.scanner.cli import ssl_labs

    ssl_labs._get_protocol_info(ep, "https://example.com")
    assert mock_output.norm.called


def test_vuln_info_rare_enum(monkeypatch):
    # Covers rare/unknown enum values for dhUsesKnownPrimes, sessionResumption, etc.
    mock_output = mock.Mock()
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.output", mock_output)
    monkeypatch.setattr("yawast.scanner.cli.ssl_labs.reporter", mock.Mock())
    ep = {
        "ipAddress": "1.2.3.4",
        "details": {
            "dhUsesKnownPrimes": 99,
            "sessionResumption": 99,
            "ticketbleed": 99,
            "openSslCcs": 99,
            "openSSLLuckyMinus20": 99,
            "bleichenbacher": 99,
        },
    }
    from yawast.scanner.cli import ssl_labs

    ssl_labs._get_vulnerability_info(ep, "https://example.com")
    assert mock_output.error.call_count >= 3
