---
layout: default
title: Scanning TLS
permalink: /tls/
---

## Overview of TLS Scanning

YAWAST includes two modes for performing checks against TLS configurations, one uses [SSL Labs](https://www.ssllabs.com/) (default), which includes a very detailed analysis of the system. For cases where SSL Labs can't be used, YAWAST will use a bundled copy of [sslyze](https://github.com/nabla-c0d3/sslyze) (`--internalssl`). 

By default, YAWAST will use SSL Labs, if that fails or if it can't be used (scanning an IP address, or a port other than 443), YAWAST will automatically switch to using sslyze instead.

### SWEET32 Testing

The [SWEET32](https://adamcaudill.com/2016/09/15/testing-sweet32-yawast/) test works with both modes, and doesn't rely on external components. Details on how this test works, and its limitations are explained at the above link.

### Tests Performed

Via either SSL Labs or sslyze, YAWAST performs a large number of checks, including some custom things that neither of these scanners currently offer. For the most up to date list of what they check for, please see the [Checks Performed](/checks/) page.

## SSL Labs Mode

The default mode is to use the SSL Labs API, which makes all users bound by their [terms and conditions](https://www.ssllabs.com/downloads/Qualys_SSL_Labs_Terms_of_Use.pdf), and obviously results in the domain you are scanning being sent to them.

This mode is the most comprehensive, and contains more data than the Internal (sslyze) Mode. Unless there is a good reason to use the Internal Mode, this is what you should use.

```
Beginning SSL Labs scan (this could take a minute or two)
[SSL Labs] This assessment service is provided free of charge by Qualys SSL Labs, subject to our terms and conditions: https://www.ssllabs.com/about/terms.html
.............................

	SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d=adamcaudill.com&hideResults=on

[I] IP: 104.28.27.55 - Grade: A+

	Certificate Information:
[I] 		Subject: CN=sni67677.cloudflaressl.com, OU=PositiveSSL Multi-Domain, OU=Domain Control Validated
[I] 		Common Names: sni67677.cloudflaressl.com
[I] 		Alternative names:
[I] 			sni67677.cloudflaressl.com
[I] 			*.adamcaudill.com
[I] 			adamcaudill.com
[I] 		Not Before: 2017-07-26T00:00:00+00:00
[I] 		Not After: 2018-02-01T23:59:59+00:00
[I] 		Key: EC 256 (RSA equivalent: 3072)
[I] 		Public Key Hash: 045a733405a4046b5bcc8abbd1e1cbd1d1d3b55c
[I] 		Version: 2
[I] 		Serial: 77574794376740264441751965250081500687
[I] 		Issuer: CN=COMODO ECC Domain Validation Secure Server CA 2, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
[I] 		Signature algorithm: SHA256withECDSA
[I] 		Extended Validation: No (Domain Control)
[I] 		Certificate Transparency: No
[I] 		OCSP Must Staple: false
[I] 		Revocation information: CRL information available
[I] 		Revocation information: OCSP information available
[I] 		Revocation status: certificate not revoked
[I] 		Extensions:
[I] 			authorityKeyIdentifier = keyid:40:09:61:67:F0:BC:83:71:4F:DE:12:08:2C:6F:D4:D4:2B:76:3D:96, 
[I] 			subjectKeyIdentifier = D0:F8:D6:82:36:B5:5C:AC:2D:9A:8E:7B:D9:D5:E6:99:38:B6:8C:FE
[I] 			keyUsage = critical, Digital Signature
[I] 			basicConstraints = critical, CA:FALSE
[I] 			extendedKeyUsage = TLS Web Server Authentication, TLS Web Client Authentication
[I] 			certificatePolicies = Policy: 1.3.6.1.4.1.6449.1.2.2.7,   CPS: https://secure.comodo.com/CPS, Policy: 2.23.140.1.2.1, 
[I] 			crlDistributionPoints = , Full Name:,   URI:http://crl.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crl, 
[I] 			authorityInfoAccess = CA Issuers - URI:http://crt.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crt, OCSP - URI:http://ocsp.comodoca4.com, 
[I] 		Hash: 2cf22bbb21e5a3eaa042feadc8fbc86ff0d3b1e1
			https://censys.io/certificates?q=2cf22bbb21e5a3eaa042feadc8fbc86ff0d3b1e1
			https://crt.sh/?q=2cf22bbb21e5a3eaa042feadc8fbc86ff0d3b1e1

[I] 		Certificate Chains:
		  Path 1:
[I] 			CN=sni67677.cloudflaressl.com, OU=PositiveSSL Multi-Domain, OU=Domain Control Validated
[I] 			  Signature: SHA256withECDSA  Key: EC-256
[I] 			  https://crt.sh/?q=2cf22bbb21e5a3eaa042feadc8fbc86ff0d3b1e1
[I] 			CN=COMODO ECC Domain Validation Secure Server CA 2, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
[I] 			  Signature: SHA384withECDSA  Key: EC-256
[I] 			  https://crt.sh/?q=75cfd9bc5cefa104ecc1082d77e63392ccba5291
[I] 			CN=COMODO ECC Certification Authority, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
[I] 			  Signature: SHA384withECDSA  Key: EC-384
[I] 			  https://crt.sh/?q=9f744e9f2b4dbaec0f312c50b6563b8e2d93c311
		  Path 2:
[I] 			CN=sni67677.cloudflaressl.com, OU=PositiveSSL Multi-Domain, OU=Domain Control Validated
[I] 			  Signature: SHA256withECDSA  Key: EC-256
[I] 			  https://crt.sh/?q=2cf22bbb21e5a3eaa042feadc8fbc86ff0d3b1e1
[I] 			CN=COMODO ECC Domain Validation Secure Server CA 2, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
[I] 			  Signature: SHA384withECDSA  Key: EC-256
[I] 			  https://crt.sh/?q=75cfd9bc5cefa104ecc1082d77e63392ccba5291
[I] 			CN=COMODO ECC Certification Authority, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
[I] 			  Signature: SHA384withRSA  Key: EC-384
[I] 			  https://crt.sh/?q=ae223cbf20191b40d7ffb4ea5701b65fdc68a1ca
[I] 			CN=AddTrust External CA Root, OU=AddTrust External TTP Network, O=AddTrust AB, C=SE
[I] 			  Signature: SHA1withRSA  Key: RSA-2048
[I] 			  https://crt.sh/?q=02faf3e291435468607857694df5e45b68851868

	Configuration Information:
		Protocol Support:
[I] 			TLS 1.0
[I] 			TLS 1.1
[I] 			TLS 1.2
[I] 			TLS 1.3

		Named Group Support:
[I] 			x25519 256
[I] 			secp256r1 256
[I] 			secp384r1 384
[I] 			secp224r1 224
[I] 			secp521r1 521

		Cipher Suite Support:
[I] 			TLS 1.0
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			TLS 1.1
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			TLS 1.2
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256            - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256  - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256      - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256            - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384            - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384            - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			TLS 1.3
[I] 			  TLS_AES_128_GCM_SHA256                             - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_AES_256_GCM_SHA384                             - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_CHACHA20_POLY1305_SHA256                       - 256-bits - ECDH-256 / x25519 (3072 equivalent)

		Handshake Simulation:
[W] 			Android 2.3.7                - Simulation Failed
[I] 			Android 4.0.4                - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 4.1.1                - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 4.2.2                - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 4.3                  - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 4.4.2                - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 5.0.0                - TLS 1.2 - OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 6.0                  - TLS 1.2 - OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 7.0                  - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 - ECDH-256 / x25519 (3072 equivalent)
[I] 			Baidu Jan 2015               - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			BingPreview Jan 2015         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[W] 			Chrome 49 / XP SP3           - Simulation Failed
[I] 			Chrome 57 / Win 7            - TLS 1.3 - TLS_AES_128_GCM_SHA256 - ECDH-256 / x25519 (3072 equivalent)
[I] 			Firefox 31.3.0 ESR / Win 7   - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Firefox 47 / Win 7           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Firefox 49 / XP SP3          - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Firefox 53 / Win 7           - TLS 1.3 - TLS_AES_128_GCM_SHA256 - ECDH-256 / x25519 (3072 equivalent)
[I] 			Googlebot Feb 2015           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[W] 			IE 6 / XP                    - Simulation Failed
[I] 			IE 7 / Vista                 - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[W] 			IE 8 / XP                    - Simulation Failed
[I] 			IE 8-10 / Win 7              - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			IE 11 / Win 7                - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			IE 11 / Win 8.1              - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			IE 10 / Win Phone 8.0        - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			IE 11 / Win Phone 8.1        - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			IE 11 / Win Phone 8.1 Update - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			IE 11 / Win 10               - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Edge 13 / Win 10             - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Edge 13 / Win Phone 10       - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[W] 			Java 6u45                    - Simulation Failed
[I] 			Java 7u25                    - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Java 8u31                    - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[W] 			OpenSSL 0.9.8y               - Simulation Failed
[I] 			OpenSSL 1.0.1l               - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			OpenSSL 1.0.2e               - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 5.1.9 / OS X 10.6.8   - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 6 / iOS 6.0.1         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 6.0.4 / OS X 10.8.4   - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 7 / iOS 7.1           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 7 / OS X 10.9         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 8 / iOS 8.4           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 8 / OS X 10.10        - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 9 / iOS 9             - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 9 / OS X 10.11        - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 10 / iOS 10           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 10 / OS X 10.12       - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Apple ATS 9 / iOS 9          - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Yahoo Slurp Jan 2015         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			YandexBot Jan 2015           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)

		Protocol & Vulnerability Information:
[I] 			DROWN: No
[I] 			Secure Renegotiation: secure renegotiation supported
[I] 			POODLE (SSL): No
[I] 			POODLE (TLS): No
[I] 			Downgrade Prevention: Yes
[I] 			Compression: No
[I] 			Heartbleed: No
[I] 			OpenSSL CCS (CVE-2014-0224): No
[I] 			OpenSSL Padding Oracle (CVE-2016-2107): No
[I] 			Forward Secrecy: Yes (all simulated clients)
[I] 			OCSP Stapling: Yes
[I] 			FREAK: No
[I] 			Logjam: No
[I] 			DH public server param (Ys) reuse: No
[I] 			Protocol Intolerance: No

Confirming your OpenSSL supports 3DES cipher suites...
TLS Session Request Limit: Checking number of requests accepted using 3DES suites...

[I] TLS Session Request Limit: Server does not support 3DES cipher suites
```

## Internal (sslyze) Mode

To use the embedded sslyze TLS / SSL scanner, simply pass `--internalssl` on the command line. Here is a sample of the output generated by this component:

```
[I] Found X509 Certificate:
[I] 		Issued To: sni67677.cloudflaressl.com / 
[I] 		Issuer: COMODO ECC Domain Validation Secure Server CA 2 / COMODO CA Limited
[I] 		Version: 2
[I] 		Serial: 167670175484361448885961646389808341945
[I] 		Subject: /OU=Domain Control Validated/OU=PositiveSSL Multi-Domain/CN=sni67677.cloudflaressl.com
[I] 		Expires: 2017-07-02 23:59:59 UTC
[I] 		Signature Algorithm: ecdsa-with-SHA256
[I] 		Key: EC-prime256v1
[I] 			Key Hash: 26c91946d32c2e664dd4c131ffd2b11bd6270331
[I] 		Extensions:
[I] 			authorityKeyIdentifier = keyid:40:09:61:67:F0:BC:83:71:4F:DE:12:08:2C:6F:D4:D4:2B:76:3D:96, 
[I] 			subjectKeyIdentifier = D0:F8:D6:82:36:B5:5C:AC:2D:9A:8E:7B:D9:D5:E6:99:38:B6:8C:FE
[I] 			keyUsage = critical, Digital Signature
[I] 			basicConstraints = critical, CA:FALSE
[I] 			extendedKeyUsage = TLS Web Server Authentication, TLS Web Client Authentication
[I] 			certificatePolicies = Policy: 1.3.6.1.4.1.6449.1.2.2.7,   CPS: https://secure.comodo.com/CPS, Policy: 2.23.140.1.2.1, 
[I] 			crlDistributionPoints = , Full Name:,   URI:http://crl.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crl, 
[I] 			authorityInfoAccess = CA Issuers - URI:http://crt.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crt, OCSP - URI:http://ocsp.comodoca4.com, 
[I] 		Alternate Names:
[I] 			sni67677.cloudflaressl.com
[I] 			*.adamcaudill.com
[I] 			adamcaudill.com
[I] 		Hash: 06746b606927dab24f9b339329639151112c9363
			https://censys.io/certificates?q=06746b606927dab24f9b339329639151112c9363
			https://crt.sh/?q=06746b606927dab24f9b339329639151112c9363

[I] Certificate: Chain
[I] 		Issued To: sni67677.cloudflaressl.com / 
[I] 			Issuer: COMODO ECC Domain Validation Secure Server CA 2 / COMODO CA Limited
[I] 			Expires: 2017-07-02 23:59:59 UTC
[I] 			Key: EC-prime256v1
[I] 			Signature Algorithm: ecdsa-with-SHA256
[I] 			Hash: 06746b606927dab24f9b339329639151112c9363

[I] 		Issued To: COMODO ECC Domain Validation Secure Server CA 2 / COMODO CA Limited
[I] 			Issuer: COMODO ECC Certification Authority / COMODO CA Limited
[I] 			Expires: 2029-09-24 23:59:59 UTC
[I] 			Key: EC-prime256v1
[I] 			Signature Algorithm: ecdsa-with-SHA384
[I] 			Hash: 75cfd9bc5cefa104ecc1082d77e63392ccba5291

[I] 		Issued To: COMODO ECC Certification Authority / COMODO CA Limited
[I] 			Issuer: AddTrust External CA Root / AddTrust AB
[I] 			Expires: 2020-05-30 10:48:38 UTC
[I] 			Key: EC-secp384r1
[I] 			Signature Algorithm: sha384WithRSAEncryption
[I] 			Hash: ae223cbf20191b40d7ffb4ea5701b65fdc68a1ca


		Qualys SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d=adamcaudill.com&hideResults=on

Supported Ciphers (based on your OpenSSL version):
	Checking for TLSv1 suites (98 possible suites)
[I] 		Version: TLSv1  	Bits: 256	Cipher: ECDHE-ECDSA-AES256-SHA
[I] 		Version: TLSv1  	Bits: 128	Cipher: ECDHE-ECDSA-AES128-SHA
[W] 		Version: TLSv1  	Bits: 112	Cipher: ECDHE-ECDSA-DES-CBC3-SHA
	Checking for TLSv1_2 suites (98 possible suites)
[I] 		Version: TLSv1.2	Bits: 256	Cipher: ECDHE-ECDSA-AES256-GCM-SHA384
[I] 		Version: TLSv1.2	Bits: 256	Cipher: ECDHE-ECDSA-AES256-SHA384
[I] 		Version: TLSv1.2	Bits: 256	Cipher: ECDHE-ECDSA-AES256-SHA
[I] 		Version: TLSv1.2	Bits: 128	Cipher: ECDHE-ECDSA-AES128-GCM-SHA256
[I] 		Version: TLSv1.2	Bits: 128	Cipher: ECDHE-ECDSA-AES128-SHA256
[I] 		Version: TLSv1.2	Bits: 128	Cipher: ECDHE-ECDSA-AES128-SHA
	Checking for TLSv1_1 suites (98 possible suites)
[I] 		Version: TLSv1.1	Bits: 256	Cipher: ECDHE-ECDSA-AES256-SHA
[I] 		Version: TLSv1.1	Bits: 128	Cipher: ECDHE-ECDSA-AES128-SHA
	Checking for SSLv3 suites (98 possible suites)

[I] HSTS: Enabled (strict-transport-security: max-age=15552000; preload)
```

