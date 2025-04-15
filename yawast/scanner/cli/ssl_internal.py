#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

import json
from datetime import datetime, timezone
from typing import List

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from sslyze import (
    CertificateDeploymentAnalysisResult,
    CipherSuite,
    CipherSuitesScanResult,
    RobotScanResultEnum,
    ScanCommandAttemptStatusEnum,
    Scanner,
    ServerNetworkLocation,
    ServerScanRequest,
    ServerScanResultAsJson,
    ServerScanStatusEnum,
    SslyzeOutputAsJson,
    TlsResumptionSupportEnum,
    __version__,
)
from validator_collection import checkers

from yawast.reporting import issue, reporter
from yawast.reporting.enums import Vulnerabilities
from yawast.scanner.modules.dns import basic
from yawast.scanner.modules.ssl import cert_info
from yawast.scanner.session import Session
from yawast.shared import output, utils


def scan(session: Session):
    output.norm(
        f"Beginning SSL scan using sslyze {__version__.__version__} (this could take a minute or two)"
    )
    output.empty()

    ips = basic.get_ips(session.domain)
    port = utils.get_port(session.url)
    all_results = []

    for ip in ips:
        try:
            scanner = Scanner()
            scanner.queue_scans(
                [
                    ServerScanRequest(
                        server_location=ServerNetworkLocation(
                            hostname=session.domain,
                            port=port,
                            ip_address=ip,
                        )
                    )
                ]
            )

            output.norm(f"IP: {ip}:{port}")

            for result in scanner.get_results():
                all_results.append(result)

                if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
                    if checkers.is_ipv6(ip):
                        output.error(
                            "\tError connecting to IPv6 IP. Please ensure that your system is configured properly."
                        )

                    output.error(f"\tConnection failed ({str(error)})")
                    output.empty()

                    continue

                # if we're here, we have a result
                certinfo_attempt = result.scan_result.certificate_info
                if certinfo_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                    output.error(
                        f"\tError performing certificate scan: {certinfo_attempt.error_reason}"
                    )
                    output.empty()
                elif certinfo_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    # we have certificate info
                    certinfo_result = certinfo_attempt.result

                    for cert_deployment in certinfo_result.certificate_deployments:
                        leaf_cert = cert_deployment.received_certificate_chain[0]
                        cert_chain = cert_deployment.received_certificate_chain[1:]

                        # print info on the server cert
                        _get_leaf_cert_info(leaf_cert)

                        # get all but the first element
                        _get_cert_chain(cert_chain, session.url)

                        # list the root stores this is trusted by
                        trust = ""
                        for t in _get_trusted_root_stores(cert_deployment):
                            trust += f"{t} (trusted) "

                        output.norm(f"\tRoot Stores: {trust}")

                        output.empty()

                        if cert_deployment.ocsp_response is not None:
                            output.norm("\tOCSP Stapling: Yes")
                        else:
                            reporter.display(
                                "\tOCSP Stapling: No",
                                issue.Issue(
                                    Vulnerabilities.TLS_OCSP_STAPLE_MISSING,
                                    session.url,
                                    {},
                                ),
                            )

                # get info for the various versions of SSL/TLS
                output.norm("\tCipher Suite Support:")

                # get info for sslv2
                ssl2_attempt = result.scan_result.ssl_2_0_cipher_suites
                if ssl2_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                    output.error(
                        f"\tError performing SSLv2 scan: {ssl2_attempt.error_reason}"
                    )
                    output.empty()
                elif ssl2_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    ssl2_result = ssl2_attempt.result

                    _get_suite_info("SSLv2", ssl2_result, session.url)

                # get info for sslv3
                ssl3_attempt = result.scan_result.ssl_3_0_cipher_suites
                if ssl3_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                    output.error(
                        f"\tError performing SSLv3 scan: {ssl3_attempt.error_reason}"
                    )
                    output.empty()
                elif ssl3_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    ssl3_result = ssl3_attempt.result
                    _get_suite_info("SSLv3", ssl3_result, session.url)

                # get info for tlsv1.0
                tls10_attempt = result.scan_result.tls_1_0_cipher_suites
                if tls10_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                    output.error(
                        f"\tError performing TLSv1.0 scan: {tls10_attempt.error_reason}"
                    )
                    output.empty()
                elif tls10_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    tls10_result = tls10_attempt.result
                    _get_suite_info("TLSv1.0", tls10_result, session.url)

                # get info for tlsv1.1
                tls11_attempt = result.scan_result.tls_1_1_cipher_suites
                if tls11_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                    output.error(
                        f"\tError performing TLSv1.1 scan: {tls11_attempt.error_reason}"
                    )
                    output.empty()
                elif tls11_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    tls11_result = tls11_attempt.result
                    _get_suite_info("TLSv1.1", tls11_result, session.url)

                # get info for tlsv1.2
                tls12_attempt = result.scan_result.tls_1_2_cipher_suites
                if tls12_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                    output.error(
                        f"\tError performing TLSv1.2 scan: {tls12_attempt.error_reason}"
                    )
                    output.empty()
                elif tls12_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    tls12_result = tls12_attempt.result
                    _get_suite_info("TLSv1.2", tls12_result, session.url)

                # get info for tlsv1.3
                tls13_attempt = result.scan_result.tls_1_3_cipher_suites
                if tls13_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                    output.error(
                        f"\tError performing TLSv1.3 scan: {tls13_attempt.error_reason}"
                    )
                    output.empty()
                elif tls13_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    tls13_result = tls13_attempt.result
                    _get_suite_info("TLSv1.3", tls13_result, session.url)

                output.empty()

                # check compression
                compression_attempt = result.scan_result.tls_compression
                if compression_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                    output.error(
                        f"\tError performing compression scan: {compression_attempt.error_reason}"
                    )
                    output.empty()
                elif (
                    compression_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED
                ):
                    compression_result = compression_attempt.result
                    if compression_result.supports_compression:
                        reporter.display(
                            f"\tCompression: Enabled",
                            issue.Issue(
                                Vulnerabilities.TLS_COMPRESSION_ENABLED, session.url, {}
                            ),
                        )
                    else:
                        output.norm("\tCompression: None")
                else:
                    output.error(
                        f"\tError performing compression scan: {compression_attempt.error_reason}"
                    )
                    output.empty()

                # check TLS_FALLBACK_SCSV
                fallback_attempt = result.scan_result.tls_fallback_scsv
                if fallback_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                    output.error(
                        f"\tError performing fallback scan: {fallback_attempt.error_reason}"
                    )
                    output.empty()
                elif fallback_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    fallback_result = fallback_attempt.result
                    if fallback_result.supports_fallback_scsv:
                        output.norm("\tDowngrade Prevention: Yes")
                    else:
                        reporter.display(
                            "\tDowngrade Prevention: No",
                            issue.Issue(
                                Vulnerabilities.TLS_FALLBACK_SCSV_MISSING,
                                session.url,
                                {},
                            ),
                        )
                else:
                    output.error(
                        f"\tError performing fallback scan: {fallback_attempt.error_reason}"
                    )
                    output.empty()

                # check Heartbleed
                heartbleed_attempt = result.scan_result.heartbleed
                if heartbleed_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                    output.error(
                        f"\tError performing Heartbleed scan: {heartbleed_attempt.error_reason}"
                    )
                    output.empty()
                elif (
                    heartbleed_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED
                ):
                    heartbleed_result = heartbleed_attempt.result
                    if heartbleed_result.is_vulnerable_to_heartbleed:
                        reporter.display(
                            "\tHeartbleed: Vulnerable",
                            issue.Issue(
                                Vulnerabilities.TLS_HEARTBLEED, session.url, {}
                            ),
                        )
                    else:
                        output.norm("\tHeartbleed: No")
                else:
                    output.error(
                        f"\tError performing Heartbleed scan: {heartbleed_attempt.error_reason}"
                    )
                    output.empty()

                # check OpenSSL CCS injection vulnerability (CVE-2014-0224)
                ccs_attempt = result.scan_result.openssl_ccs_injection
                if ccs_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                    output.error(
                        f"\tError performing OpenSSL CCS injection scan: {ccs_attempt.error_reason}"
                    )
                    output.empty()
                elif ccs_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    ccs_result = ccs_attempt.result
                    if ccs_result.is_vulnerable_to_ccs_injection:
                        reporter.display(
                            "\tOpenSSL CCS (CVE-2014-0224): Vulnerable",
                            issue.Issue(
                                Vulnerabilities.TLS_OPENSSL_CVE_2014_0224,
                                session.url,
                                {},
                            ),
                        )
                    else:
                        output.norm("\tOpenSSL CCS (CVE-2014-0224): No")
                else:
                    output.error(
                        f"\tError performing OpenSSL CCS injection scan: {ccs_attempt.error_reason}"
                    )
                    output.empty()

                # check SessionRenegotiation
                session_renegotiation_attempt = result.scan_result.session_renegotiation
                if (
                    session_renegotiation_attempt.status
                    == ScanCommandAttemptStatusEnum.ERROR
                ):
                    output.error(
                        f"\tError performing session renegotiation scan: {session_renegotiation_attempt.error_reason}"
                    )
                    output.empty()
                elif (
                    session_renegotiation_attempt.status
                    == ScanCommandAttemptStatusEnum.COMPLETED
                ):
                    session_renegotiation_result = session_renegotiation_attempt.result
                    if (
                        session_renegotiation_result.is_vulnerable_to_client_renegotiation_dos
                    ):
                        reporter.display(
                            "\tSession Renegotiation: Vulnerable",
                            issue.Issue(
                                Vulnerabilities.TLS_SESSION_RENEGOTIATION,
                                session.url,
                                {},
                            ),
                        )
                    else:
                        output.norm("\tSession Renegotiation: No")
                else:
                    output.error(
                        f"\tError performing session renegotiation scan: {session_renegotiation_attempt.error_reason}"
                    )
                    output.empty()

                # check SessionResumption
                session_resumption_attempt = result.scan_result.session_resumption
                if (
                    session_resumption_attempt.status
                    == ScanCommandAttemptStatusEnum.ERROR
                ):
                    output.error(
                        f"\tError performing session resumption scan: {session_resumption_attempt.error_reason}"
                    )
                    output.empty()
                elif (
                    session_resumption_attempt.status
                    == ScanCommandAttemptStatusEnum.COMPLETED
                ):
                    session_resumption_result = session_resumption_attempt.result
                    if (
                        session_resumption_result.session_id_resumption_result
                        == TlsResumptionSupportEnum.FULLY_SUPPORTED
                    ):
                        reporter.display(
                            "\tSession Resumption (Session ID): Enabled",
                            issue.Issue(
                                Vulnerabilities.TLS_SESSION_RESP_ENABLED,
                                session.url,
                                {},
                            ),
                        )
                    elif (
                        session_resumption_result.session_id_resumption_result
                        == TlsResumptionSupportEnum.PARTIALLY_SUPPORTED
                    ):
                        reporter.display(
                            "\tSession Resumption (Session ID): Partially Supported",
                            issue.Issue(
                                Vulnerabilities.TLS_SESSION_RESP_ENABLED,
                                session.url,
                                {},
                            ),
                        )
                    else:
                        output.norm("\tSession Resumption (Session ID): No")

                    if (
                        session_resumption_result.tls_ticket_resumption_result
                        == TlsResumptionSupportEnum.FULLY_SUPPORTED
                    ):
                        reporter.display(
                            "\tSession Resumption (TLS Ticket): Enabled",
                            issue.Issue(
                                Vulnerabilities.TLS_SESSION_RESP_ENABLED,
                                session.url,
                                {},
                            ),
                        )
                    elif (
                        session_resumption_result.tls_ticket_resumption_result
                        == TlsResumptionSupportEnum.PARTIALLY_SUPPORTED
                    ):
                        reporter.display(
                            "\tSession Resumption (TLS Ticket): Partially Supported",
                            issue.Issue(
                                Vulnerabilities.TLS_SESSION_RESP_ENABLED,
                                session.url,
                                {},
                            ),
                        )
                    else:
                        output.norm("\tSession Resumption (TLS Ticket)): No")
                else:
                    output.error(
                        f"\tError performing session resumption scan: {session_resumption_attempt.error_reason}"
                    )
                    output.empty()

                # check ROBOT
                robot_attempt = result.scan_result.robot
                if robot_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                    output.error(
                        f"\tError performing ROBOT scan: {robot_attempt.error_reason}"
                    )
                    output.empty()
                elif robot_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                    robot_result = robot_attempt.result
                    if (
                        robot_result.robot_result
                        == RobotScanResultEnum.VULNERABLE_WEAK_ORACLE
                    ):
                        reporter.display(
                            "\tROBOT: Vulnerable - Not Exploitable",
                            issue.Issue(
                                Vulnerabilities.TLS_ROBOT_ORACLE_WEAK, session.url, {}
                            ),
                        )
                    elif (
                        robot_result.robot_result
                        == RobotScanResultEnum.VULNERABLE_STRONG_ORACLE
                    ):
                        reporter.display(
                            "\tROBOT: Vulnerable - Exploitable",
                            issue.Issue(
                                Vulnerabilities.TLS_ROBOT_ORACLE_STRONG, session.url, {}
                            ),
                        )
                    else:
                        output.norm("\tROBOT: No")
                else:
                    output.error(
                        f"\tError performing ROBOT scan: {robot_attempt.error_reason}"
                    )
                    output.empty()

                # check TLS 1.3 Early Data
                early_data_attempt = result.scan_result.tls_1_3_early_data
                if early_data_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                    output.error(
                        f"\tError performing TLS 1.3 early data scan: {early_data_attempt.error_reason}"
                    )
                    output.empty()
                elif (
                    early_data_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED
                ):
                    early_data_result = early_data_attempt.result
                    if early_data_result.supports_early_data:
                        output.info("\tTLS 1.3 0-RTT Support: Yes")
                    else:
                        output.norm("\tTLS 1.3 0-RTT Support: No")
                else:
                    output.error(
                        f"\tError performing TLS 1.3 early data scan: {early_data_attempt.error_reason}"
                    )
                    output.empty()

            output.empty()
        except Exception as error:
            output.debug_exception()

            output.error(f"Error performing TLS scan: #{str(error)}")

    if len(all_results) > 0:
        # get the json data, and add it to the reporter
        json_output = SslyzeOutputAsJson(
            server_scan_results=[
                ServerScanResultAsJson.model_validate(res) for res in all_results
            ],
            invalid_server_strings=[],
            date_scans_started=datetime.now(timezone.utc),
            date_scans_completed=datetime.now(timezone.utc),
        )
        clean_json = json.loads(json_output.model_dump_json())
        reporter.register_data("sslyze_results", clean_json)


def _get_leaf_cert_info(cert: x509.Certificate):
    output.norm("Certificate Information:")

    output.norm(f"\tSubject: {cert.subject.rfc4514_string()}")
    output.norm(f'\tCommon Names: {" ".join(cert_info.get_common_names(cert))}')

    output.norm("\tAlternative names:")
    alt_names = cert_info.get_alt_names(cert)
    for name in alt_names:
        output.norm(f"\t\t{name}")

    output.norm(f'\tNot Before: {cert.not_valid_before.isoformat(" ")}')
    output.norm(f'\tNot After: {cert.not_valid_after.isoformat(" ")}')

    output.norm(f"\tKey: {cert.signature_algorithm_oid._name}")

    # TODO: Public Key Hash

    serial = format(cert.serial_number, "02x")
    output.norm(f"\tSerial: {serial}")

    output.norm(f"\tIssuer: {cert.issuer.rfc4514_string()}")

    output.norm(f"\tOCSP Must Staple: {cert_info.get_must_staple(cert)}")

    output.empty()

    exts = cert_info.format_extensions(cert)
    for ext in exts:
        output.norm(f"\tExtensions: {ext}")

    output.empty()

    scts = cert_info.get_scts(cert)
    for sct in scts:
        output.norm(
            f'\tSCT: {cert_info.get_ct_log_name(sct[1])} - {sct[2].isoformat(" ")}'
        )

    output.empty()

    cert_hash = bytes.hex(cert.fingerprint(hashes.SHA1()))
    output.norm(f"\tFingerprint: {cert_hash}")
    output.norm(f"\t\thttps://censys.io/certificates?q={cert_hash}")
    output.norm(f"\t\thttps://crt.sh/?q={cert_hash}")

    output.empty()


def _get_cert_chain(chain: List[x509.Certificate], url: str):
    if len(chain) > 0:
        output.norm("\tCertificate Chain:")

        for cert in chain:
            output.norm(f"\t\tSubject: {cert.subject.rfc4514_string()}")
            output.norm(f"\t\t Signature: {cert.signature_algorithm_oid._name}")

            fp = bytes.hex(cert.fingerprint(hashes.SHA256()))
            if cert_info.check_symantec_root(fp):
                reporter.display(
                    "\t\t Untrusted Symantec Root",
                    issue.Issue(
                        Vulnerabilities.TLS_SYMANTEC_ROOT, url, {"fingerprint": fp}
                    ),
                )

            output.norm(
                f"\t\t https://crt.sh/?q={bytes.hex(cert.fingerprint(hashes.SHA1()))}"
            )

        output.empty()


def _get_trusted_root_stores(
    result: CertificateDeploymentAnalysisResult,
) -> List[str]:
    trusted = []

    for res in result.path_validation_results:
        if res.was_validation_successful:
            trusted.append(res.trust_store.name)

    return trusted


def _get_suite_info(proto: str, result: CipherSuitesScanResult, url: str):
    output.norm(f"\t\t{proto}:")

    if len(result.accepted_cipher_suites) > 0:
        for accounted_suite in result.accepted_cipher_suites:
            suite = accounted_suite.cipher_suite
            name = suite.name

            if _is_cipher_suite_secure(suite, name):
                if "CBC" in name:
                    output.info(f"\t\t  {name.ljust(50)} - {suite.key_size}-bits")

                    reporter.register(
                        issue.Issue(
                            Vulnerabilities.TLS_CBC_CIPHER_SUITE, url, {"cipher": name}
                        )
                    )
                else:
                    output.norm(f"\t\t  {name.ljust(50)} - {suite.key_size}-bits")
            else:
                output.vuln(f"\t\t  {name.ljust(50)} - {suite.key_size}-bits")

                reporter.register(
                    issue.Issue(
                        Vulnerabilities.TLS_INSECURE_CIPHER_SUITE, url, {"cipher": name}
                    )
                )

        output.norm(f"\t\t  ({len(result.rejected_cipher_suites)} suites rejected)")
    else:
        output.norm(
            f"\t\t  (all suites ({len(result.rejected_cipher_suites)}) rejected)"
        )


def _is_cipher_suite_secure(suite: CipherSuite, name: str) -> bool:
    ret = True

    if suite.is_anonymous:
        ret = False

    if "RC4" in name:
        ret = False

    if "DES" in name:
        ret = False

    if suite.key_size is not None:
        if suite.key_size < 128:
            ret = False

    return ret
