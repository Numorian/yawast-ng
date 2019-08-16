---
layout: default
title: Scanning TLS
permalink: /tls/
---

## Overview of TLS Scanning

YAWAST includes two modes for performing checks against TLS configurations; one uses [SSL Labs](https://www.ssllabs.com/) (default), which includes a very detailed analysis of the system. For cases where SSL Labs can't be used, YAWAST will use a bundled copy of [sslyze](https://github.com/nabla-c0d3/sslyze) (`--internalssl`). 

By default, YAWAST will use SSL Labs; if that fails or if it can't be used (scanning an IP address, or a port other than 443), YAWAST will automatically switch to using sslyze instead.

### SWEET32 Testing

The [SWEET32](https://adamcaudill.com/2016/09/15/testing-sweet32-yawast/) test works with both modes, and doesn't rely on external components. Details on how this test works and its limitations are explained at the above link.

### Tests Performed

Via either SSL Labs or sslyze, YAWAST performs a large number of checks, including some custom things that neither of these scanners currently offer. For the most up-to-date list of what they check for, please see the [Checks Performed](/checks/) page.

## SSL Labs Mode

The default mode is to use the SSL Labs API, which makes all users bound by their [terms and conditions](https://www.ssllabs.com/downloads/Qualys_SSL_Labs_Terms_of_Use.pdf), and obviously results in the domain you are scanning being sent to them.

This mode is the most comprehensive, and contains more data than the Internal (sslyze) Mode. Unless there is a good reason to use the Internal Mode, this is what you should use.

```
       Beginning SSL Labs scan (this could take a minute or two)

       [SSL Labs] This assessment service is provided free of charge by Qualys SSL Labs, subject to our terms and conditions:
			↳ https://www.ssllabs.com/about/terms.html
       Status - 2606:4700:30:0:0:0:6818:65b6: Ready
       Status - 2606:4700:30:0:0:0:6818:64b6: Ready
       Status - 104.24.100.182: Ready
       Status - 104.24.101.182: Ready
       Status: Working...

       IP: 104.24.101.182 - Grade: A
       Certificate Information:
          Subject: CN=sni67677.cloudflaressl.com, OU=PositiveSSL Multi-Domain, OU=Domain Control Validated
          Common Names: sni67677.cloudflaressl.com
          Alternative names:
             sni67677.cloudflaressl.com
             *.adamcaudill.com
             adamcaudill.com
          Not Before: 2019-07-21 00:00:00
          Not After: 2020-01-27 23:59:59
          Key: EC 256 (RSA equivalent: 3072)
          Serial: 8dcb43e86505327f64952bd9a060ccfa
          Issuer: CN=COMODO ECC Domain Validation Secure Server CA 2, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
          Extended Validation: No (Domain Control)
          Certificate Transparency: SCT in certificate
          OCSP Must Staple: False
          Revocation information: CRL information available
          Revocation information: OCSP information available
          Revocation Status: certificate not revoked
          CRL Revocation Status: certificate not revoked
          OCSP Revocation Status: certificate not revoked

          Extensions: authorityKeyIdentifier, critical=False, key_identifier=40096167f0bc83714fde12082c6fd4d42b763d96, authority_cert_issuer=None,
			↳ authority_cert_serial_number=None
          Extensions: subjectKeyIdentifier, critical=False, digest=d0f8d68236b55cac2d9a8e7bd9d5e69938b68cfe
          Extensions: keyUsage, critical=True, digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
			↳ key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False
          Extensions: basicConstraints, critical=True, ca=False, path_length=None
          Extensions: extendedKeyUsage, critical=False, usages=(serverAuth, clientAuth)
          Extensions: certificatePolicies, critical=False, policies=(policy_identifier=1.3.6.1.4.1.6449.1.2.2.7,
			↳ policy_qualifiers=['https://secure.comodo.com/CPS'], policy_identifier=2.23.140.1.2.1, policy_qualifiers=None)
          Extensions: cRLDistributionPoints, critical=False, distribution_points=(http://crl.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crl)
          Extensions: OCSP, critical=False, descriptions=(caIssuers=http://crt.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crt,
			↳ OCSP=http://ocsp.comodoca4.com)

          SCT: Google 'Argon2020' log - 2019-07-21 10:28:58.437000
          SCT: Cloudflare 'Nimbus2020' Log - 2019-07-21 10:28:58.482000

          Fingerprint: 08352a2f7dbe6c1c4b12905ef2b40e2067a1d8bc
             https://censys.io/certificates?q=08352a2f7dbe6c1c4b12905ef2b40e2067a1d8bc
             https://crt.sh/?q=08352a2f7dbe6c1c4b12905ef2b40e2067a1d8bc

          Certificate Chains:
            Path 1:
             Root Stores: Mozilla (trusted) Apple (trusted) Android (trusted) Java (trusted) Windows (trusted)
             CN=sni67677.cloudflaressl.com, OU=PositiveSSL Multi-Domain, OU=Domain Control Validated
              Signature: SHA256withECDSA  Key: EC-256
               https://crt.sh/?q=08352a2f7dbe6c1c4b12905ef2b40e2067a1d8bc
             CN=COMODO ECC Domain Validation Secure Server CA 2, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
              Signature: SHA384withECDSA  Key: EC-256
               https://crt.sh/?q=75cfd9bc5cefa104ecc1082d77e63392ccba5291
             CN=COMODO ECC Certification Authority, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
              Signature: SHA384withECDSA  Key: EC-384
               https://crt.sh/?q=9f744e9f2b4dbaec0f312c50b6563b8e2d93c311
               (provided by server)
            Path 2:
             Root Stores: Mozilla (trusted) Apple (trusted) Android (trusted) Java (trusted) Windows (trusted)
             CN=sni67677.cloudflaressl.com, OU=PositiveSSL Multi-Domain, OU=Domain Control Validated
              Signature: SHA256withECDSA  Key: EC-256
               https://crt.sh/?q=08352a2f7dbe6c1c4b12905ef2b40e2067a1d8bc
             CN=COMODO ECC Domain Validation Secure Server CA 2, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
              Signature: SHA384withECDSA  Key: EC-256
               https://crt.sh/?q=75cfd9bc5cefa104ecc1082d77e63392ccba5291
             CN=COMODO ECC Certification Authority, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
              Signature: SHA384withRSA  Key: EC-384
               https://crt.sh/?q=ae223cbf20191b40d7ffb4ea5701b65fdc68a1ca
             CN=AddTrust External CA Root, OU=AddTrust External TTP Network, O=AddTrust AB, C=SE
              Signature: SHA1withRSA  Key: RSA-2048
               https://crt.sh/?q=02faf3e291435468607857694df5e45b68851868
               (provided by server)

       Configuration Information:
          Protocol Support:
[Info]       TLS 1.0
             TLS 1.1
             TLS 1.2
             TLS 1.3

          Named Group Support:
             x25519 256
             secp256r1 256
             secp384r1 384
             secp224r1 224
             secp521r1 521

          Cipher Suite Support:
             TLS 1.0
[Info]         TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[Info]         TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               - 256-bits - ECDH-256 / x25519 (3072 equivalent)
             TLS 1.1
[Info]         TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[Info]         TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               - 256-bits - ECDH-256 / x25519 (3072 equivalent)
             TLS 1.2
               TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256            - 128-bits - ECDH-256 / x25519 (3072 equivalent)
               OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256  - 256-bits - ECDH-256 / x25519 (3072 equivalent)
               TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256      - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[Info]         TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[Info]         TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256            - 128-bits - ECDH-256 / x25519 (3072 equivalent)
               TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384            - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[Info]         TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[Info]         TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384            - 256-bits - ECDH-256 / x25519 (3072 equivalent)
             TLS 1.3
               TLS_AES_128_GCM_SHA256                             - 128-bits - ECDH-256 / x25519 (3072 equivalent)
               TLS_AES_256_GCM_SHA384                             - 256-bits - ECDH-256 / x25519 (3072 equivalent)
               TLS_CHACHA20_POLY1305_SHA256                       - 256-bits - ECDH-256 / x25519 (3072 equivalent)

          Handshake Simulation:
[Info]       Android 2.3.7                - Simulation Failed
             Android 4.0.4                - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
             Android 4.1.1                - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
             Android 4.2.2                - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
             Android 4.3                  - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
             Android 4.4.2                - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
             Android 5.0.0                - TLS 1.2 - OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
             Android 6.0                  - TLS 1.2 - OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
             Android 7.0                  - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 - ECDH-256 / x25519 (3072 equivalent)
             Baidu Jan 2015               - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
             BingPreview Jan 2015         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[Info]       Chrome 49 / XP SP3           - Simulation Failed
             Chrome 69 / Win 7            - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / x25519 (3072 equivalent)
             Chrome 70 / Win 10           - TLS 1.3 - TLS_AES_128_GCM_SHA256 - ECDH-256 / x25519 (3072 equivalent)
             Firefox 31.3.0 ESR / Win 7   - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
             Firefox 47 / Win 7           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
             Firefox 49 / XP SP3          - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
             Firefox 62 / Win 7           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / x25519 (3072 equivalent)
             Googlebot Feb 2018           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / x25519 (3072 equivalent)
[Info]       IE 6 / XP                    - Simulation Failed
             IE 7 / Vista                 - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[Info]       IE 8 / XP                    - Simulation Failed
             IE 8-10 / Win 7              - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
             IE 11 / Win 7                - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
             IE 11 / Win 8.1              - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
             IE 10 / Win Phone 8.0        - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
             IE 11 / Win Phone 8.1        - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
             IE 11 / Win Phone 8.1 Update - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
             IE 11 / Win 10               - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
             Edge 15 / Win 10             - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / x25519 (3072 equivalent)
             Edge 13 / Win Phone 10       - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[Info]       Java 6u45                    - Simulation Failed
             Java 7u25                    - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
             Java 8u161                   - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[Info]       OpenSSL 0.9.8y               - Simulation Failed
             OpenSSL 1.0.1l               - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
             OpenSSL 1.0.2e               - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
             Safari 5.1.9 / OS X 10.6.8   - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
             Safari 6 / iOS 6.0.1         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
             Safari 6.0.4 / OS X 10.8.4   - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
             Safari 7 / iOS 7.1           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
             Safari 7 / OS X 10.9         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
             Safari 8 / iOS 8.4           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
             Safari 8 / OS X 10.10        - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
             Safari 9 / iOS 9             - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
             Safari 9 / OS X 10.11        - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
             Safari 10 / iOS 10           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
             Safari 10 / OS X 10.12       - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
             Apple ATS 9 / iOS 9          - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
             Yahoo Slurp Jan 2015         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
             YandexBot Jan 2015           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)

          Protocol & Vulnerability Information:
[Info]       SNI Required: Yes
             DROWN: No
             TLS 1.3 0-RTT Support: No
             Secure Renegotiation: secure renegotiation supported
             POODLE (SSL): No
             Zombie POODLE: No
             GOLDENDOODLE: No
             OpenSSL 0-Length Padding Oracle (CVE-2019-1559): No
             Sleeping POODLE: No
             POODLE (TLS): No
             Downgrade Prevention: Yes
             Compression: No
             Heartbeat: Disabled
             Heartbleed: No
             Ticketbleed (CVE-2016-9244): No
             OpenSSL CCS (CVE-2014-0224): No
             OpenSSL Padding Oracle (CVE-2016-2107): No
             ROBOT: No
             Forward Secrecy: Yes (all simulated clients)
             AEAD Cipher Suites Supported: Yes
[Info]       CBC Cipher Suites Supported: Yes
             ALPN: h2 http/1.1
             NPN: h2 http/1.1
[Info]       Session Resumption: Enabled
[Info]       OCSP Stapling: No
             FREAK: No
             Logjam: No
             ECDH Public Server Param Reuse: No
```

## Internal (sslyze) Mode

To use the embedded sslyze TLS / SSL scanner, simply pass `--internalssl` on the command line. Here is a sample of the output generated by this component:

```
       Beginning SSL scan using sslyze 2.1.3 (this could take a minute or two)

       IP: 104.24.100.182:443
       Certificate Information:
          Subject: OU=Domain Control Validated,OU=PositiveSSL Multi-Domain,CN=sni67677.cloudflaressl.com
          Common Names: sni67677.cloudflaressl.com
          Alternative names:
             sni67677.cloudflaressl.com
             *.adamcaudill.com
             adamcaudill.com
          Not Before: 2019-07-21 00:00:00
          Not After: 2020-01-27 23:59:59
          Key: ecdsa-with-SHA256
          Serial: 8dcb43e86505327f64952bd9a060ccfa
          Issuer: C=GB,ST=Greater Manchester,L=Salford,O=COMODO CA Limited,CN=COMODO ECC Domain Validation Secure Server CA 2
          OCSP Must Staple: False

          Extensions: authorityKeyIdentifier, critical=False, key_identifier=40096167f0bc83714fde12082c6fd4d42b763d96, authority_cert_issuer=None,
			↳ authority_cert_serial_number=None
          Extensions: subjectKeyIdentifier, critical=False, digest=d0f8d68236b55cac2d9a8e7bd9d5e69938b68cfe
          Extensions: keyUsage, critical=True, digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
			↳ key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False
          Extensions: basicConstraints, critical=True, ca=False, path_length=None
          Extensions: extendedKeyUsage, critical=False, usages=(serverAuth, clientAuth)
          Extensions: certificatePolicies, critical=False, policies=(policy_identifier=1.3.6.1.4.1.6449.1.2.2.7,
			↳ policy_qualifiers=['https://secure.comodo.com/CPS'], policy_identifier=2.23.140.1.2.1, policy_qualifiers=None)
          Extensions: cRLDistributionPoints, critical=False, distribution_points=(http://crl.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crl)
          Extensions: OCSP, critical=False, descriptions=(caIssuers=http://crt.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crt,
			↳ OCSP=http://ocsp.comodoca4.com)

          SCT: Google 'Argon2020' log - 2019-07-21 10:28:58.437000
          SCT: Cloudflare 'Nimbus2020' Log - 2019-07-21 10:28:58.482000

          Fingerprint: 08352a2f7dbe6c1c4b12905ef2b40e2067a1d8bc
             https://censys.io/certificates?q=08352a2f7dbe6c1c4b12905ef2b40e2067a1d8bc
             https://crt.sh/?q=08352a2f7dbe6c1c4b12905ef2b40e2067a1d8bc

          Certificate Chain:
             Subject: C=GB,ST=Greater Manchester,L=Salford,O=COMODO CA Limited,CN=COMODO ECC Domain Validation Secure Server CA 2
              Signature: ecdsa-with-SHA384
              https://crt.sh/?q=75cfd9bc5cefa104ecc1082d77e63392ccba5291
             Subject: C=GB,ST=Greater Manchester,L=Salford,O=COMODO CA Limited,CN=COMODO ECC Certification Authority
              Signature: ecdsa-with-SHA384
              https://crt.sh/?q=9f744e9f2b4dbaec0f312c50b6563b8e2d93c311

          Root Stores: Android (trusted) Apple (trusted) Java (trusted) Mozilla (trusted) Windows (trusted)

          Cipher Suite Support:
             SSLv2:
               (all suites (7) rejected)
             SSLv3:
               (all suites (121) rejected)
             TLSv1.0:
[Info]         TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               - 256-bits
[Info]         TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               - 128-bits
               (119 suites rejected)
             TLSv1.1:
[Info]         TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               - 256-bits
[Info]         TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               - 128-bits
               (119 suites rejected)
             TLSv1.2:
               TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256      - 256-bits
               TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384            - 256-bits
[Info]         TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384            - 256-bits
[Info]         TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               - 256-bits
               TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256            - 128-bits
[Info]         TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256            - 128-bits
[Info]         TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               - 128-bits
               (153 suites rejected)
             TLSv1.3:
               TLS_CHACHA20_POLY1305_SHA256                       - 256-bits
               TLS_AES_256_GCM_SHA384                             - 256-bits
               TLS_AES_128_GCM_SHA256                             - 128-bits
               (2 suites rejected)

          Compression: None
          Downgrade Prevention: Yes
          Heartbleed: No
          OpenSSL CCS (CVE-2014-0224): No
          Secure Renegotiation: secure renegotiation supported
          Session Resumption Tickets Supported: True
          Session Resumption: 5 of 5 successful
          ROBOT: No
          TLS 1.3 0-RTT Support: No
[Info]    OCSP Stapling: No
```

