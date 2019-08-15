---
layout: default
title: Sample Output
permalink: /sample/
---

Below is an example of the output from a typical `scan` with YAWAST - using `scan` - the normal go-to option. Here's what you get when scanning my website:

```
$ yawast scan https://adamcaudill.com --tdessessioncount --dir --files --srv --subdomains
__   _____  _    _  ___   _____ _____ 
\ \ / / _ \| |  | |/ _ \ /  ___|_   _|
 \ V / /_\ \ |  | / /_\ \\ `--.  | |  
  \ /|  _  | |/\| |  _  | `--. \ | |  
  | || | | \  /\  / | | |/\__/ / | |  
  \_/\_| |_/\/  \/\_| |_/\____/  \_/  

YAWAST v0.6.0.beta5 - The YAWAST Antecedent Web Application Security Toolkit
 Copyright (c) 2013-2017 Adam Caudill <adam@adamcaudill.com>
 Support & Documentation: https://github.com/adamcaudill/yawast
 Ruby 2.2.4-p230; OpenSSL 1.0.2j  26 Sep 2016 (x86_64-darwin16)
 Latest Version: YAWAST v0.5.2 is the officially supported version, please update.

Scanning: https://adamcaudill.com/

DNS Information:
[I] 		104.28.27.55 (N/A)
[I] 			US - CLOUDFLARENET - CloudFlare, Inc.
			https://www.shodan.io/host/104.28.27.55
			https://censys.io/ipv4/104.28.27.55
[I] 		104.28.26.55 (N/A)
[I] 			US - CLOUDFLARENET - CloudFlare, Inc.
			https://www.shodan.io/host/104.28.26.55
			https://censys.io/ipv4/104.28.26.55
[I] 		2400:CB00:2048:1::681C:1A37 (N/A)
[I] 			US - CLOUDFLARENET - CloudFlare, Inc.
			https://www.shodan.io/host/2400:cb00:2048:1::681c:1a37
[I] 		2400:CB00:2048:1::681C:1B37 (N/A)
[I] 			US - CLOUDFLARENET - CloudFlare, Inc.
			https://www.shodan.io/host/2400:cb00:2048:1::681c:1b37
[I] 		TXT: v=spf1 mx a ptr include:_spf.google.com ~all
[I] 		TXT: brave-ledger-verification=0262b8f382f60074e0131f65243fa7caba48b15eb664ec8d0d3e0b3a26a45b47
[I] 		TXT: google-site-verification=QTO_7Q7UXmrUIwieJliLTXV3XuQdqNvTPVcug_TwH0w
[I] 		MX: aspmx5.googlemail.com (30) - 74.125.131.26 (US - GOOGLE - Google Inc.)
[I] 		MX: aspmx4.googlemail.com (30) - 108.177.96.26 (US - GOOGLE - Google Inc.)
[I] 		MX: aspmx3.googlemail.com (30) - 108.177.15.27 (US - GOOGLE - Google Inc.)
[I] 		MX: alt2.aspmx.l.google.com (20) - 108.177.15.27 (US - GOOGLE - Google Inc.)
[I] 		MX: aspmx2.googlemail.com (30) - 209.85.203.26 (US - GOOGLE - Google Inc.)
[I] 		MX: alt1.aspmx.l.google.com (20) - 209.85.203.27 (US - GOOGLE - Google Inc.)
[I] 		MX: aspmx.l.google.com (10) - 74.125.141.27 (US - GOOGLE - Google Inc.)
[I] 		NS: hal.ns.cloudflare.com - 173.245.59.174 (US - CLOUDFLARENET - CloudFlare, Inc.)
[I] 		NS: vera.ns.cloudflare.com - 173.245.58.147 (US - CLOUDFLARENET - CloudFlare, Inc.)
[I] 		SRV: _bittorrent._tcp.adamcaudill.com: example.com:1 - 93.184.216.34 (US - EDGECAST - MCI Communications Services, Inc. d/b/a Verizon Business)
[I] 		A: www.adamcaudill.com: 104.28.27.55 (US - CLOUDFLARENET - CloudFlare, Inc.)
[I] 		A: www.adamcaudill.com: 104.28.26.55 (US - CLOUDFLARENET - CloudFlare, Inc.)
[I] 		CAA (adamcaudill.com): 0 iodef "mailto:adam@adamcaudill.com"
[I] 		CAA (adamcaudill.com): 0 issue "letsencrypt.org"
[I] 		CAA (adamcaudill.com): 0 issue "globalsign.com"
[I] 		CAA (adamcaudill.com): 0 issue "comodoca.com"
[I] 		CAA (adamcaudill.com): 0 issue "digicert.com"
[I] 		CAA (com): No Records Found

[I] HEAD:
[I] 		date: Sun, 22 Oct 2017 14:56:30 GMT
[I] 		content-type: text/html; charset=UTF-8
[I] 		connection: close
[I] 		set-cookie: __cfduid=0123456789abcdef; expires=Mon, 22-Oct-18 14:56:29 GMT; path=/; domain=.adamcaudill.com; HttpOnly; Secure
[I] 		vary: Accept-Encoding,Cookie
[I] 		last-modified: Fri, 13 Oct 2017 19:39:19 GMT
[I] 		x-content-type-options: nosniff
[I] 		x-frame-options: sameorigin
[I] 		pragma: public
[I] 		cache-control: public, max-age=86400
[I] 		cf-cache-status: REVALIDATED
[I] 		expires: Mon, 23 Oct 2017 14:56:30 GMT
[I] 		strict-transport-security: max-age=15552000; preload
[I] 		server: cloudflare-nginx
[I] 		cf-ray: 0123456789abcdef-MIA

[I] NOTE: Server appears to be Cloudflare; WAF may be in place.

[I] X-Frame-Options Header: sameorigin
[I] X-Content-Type-Options Header: nosniff
[W] Content-Security-Policy Header Not Present
[W] Public-Key-Pins Header Not Present

[I] Cookies:
[I] 		__cfduid=0123456789abcdef; expires=Mon, 22-Oct-18 14:56:29 GMT; path=/; domain=.adamcaudill.com; HttpOnly; Secure
[W] 			Cookie missing SameSite flag


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

[I] HSTS: Enabled (strict-transport-security: max-age=15552000; preload)
[I] HSTS Preload: Chrome - false; Firefox - false; Tor - false
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-ECDSA-AES128-GCM-SHA256
    Session-ID: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    Session-ID-ctx: 
    Master-Key: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    Key-Arg   : None
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 64800 (seconds)
    TLS session ticket:
    0000 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    0010 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    0020 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    0030 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    0040 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    0050 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    0060 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    0070 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    0080 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    0090 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    00a0 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    00b0 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    00c0 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................

    Start Time: 1508684351
    Timeout   : 300 (sec)
    Verify return code: 20 (unable to get local issuer certificate)

[W] '/readme.html' found: https://adamcaudill.com/readme.html


Checking for common files (this will take a few minutes)...
[I] '/favicon.ico' found: https://adamcaudill.com/favicon.ico
[I] '/keybase.txt' found: https://adamcaudill.com/keybase.txt
[I] '/license.txt' found: https://adamcaudill.com/license.txt
[I] '/robots.txt' found: https://adamcaudill.com/robots.txt
[I] '/sitemap_index.xml' found: https://adamcaudill.com/sitemap_index.xml
[I] '/tools' found: https://adamcaudill.com/tools
[I] '/wp-config.php' found: https://adamcaudill.com/wp-config.php
[I] '/wp-cron.php' found: https://adamcaudill.com/wp-cron.php
[I] '/wp-links-opml.php' found: https://adamcaudill.com/wp-links-opml.php
[I] '/wp-json' found: https://adamcaudill.com/wp-json
[I] '/wp-load.php' found: https://adamcaudill.com/wp-load.php
[I] '/wp-login.php' found: https://adamcaudill.com/wp-login.php
[I] '/wp-json/wp/v2/users' found: https://adamcaudill.com/wp-json/wp/v2/users
[I] '/wp-json/wp/v2/posts' found: https://adamcaudill.com/wp-json/wp/v2/posts

[I] Allow HTTP Verbs (OPTIONS): GET,HEAD,POST,OPTIONS

Searching for common directories...
[I] 	Found: 'https://adamcaudill.com//'
[I] 	Found: 'https://adamcaudill.com/0000/'
[I] 	Found: 'https://adamcaudill.com/2006/'
[I] 	Found: 'https://adamcaudill.com/2003/'
[I] 	Found: 'https://adamcaudill.com/2005/'
[I] 	Found: 'https://adamcaudill.com/2007/'
[I] 	Found: 'https://adamcaudill.com/2004/'
[I] 	Found: 'https://adamcaudill.com/2008/'
[I] 	Found: 'https://adamcaudill.com/2009/'
[I] 	Found: 'https://adamcaudill.com/2011/'
[I] 	Found: 'https://adamcaudill.com/2012/'
[I] 	Found: 'https://adamcaudill.com/2016/'
[I] 	Found: 'https://adamcaudill.com/2014/'
[I] 	Found: 'https://adamcaudill.com/2010/'
[I] 	Found: 'https://adamcaudill.com/2013/'
[I] 	Found: 'https://adamcaudill.com/2015/'
[I] 	Found: 'https://adamcaudill.com/2017/'
[I] 	Found: 'https://adamcaudill.com/ABOUT/'
[I] 	Found: 'https://adamcaudill.com/ARCHIVES/'
[I] 	Found: 'https://adamcaudill.com/About/'
[I] 	Found: 'https://adamcaudill.com/Archives/'
[I] 	Found: 'https://adamcaudill.com/BLOG/'
[I] 	Found: 'https://adamcaudill.com/Blog/'
[I] 	Found: 'https://adamcaudill.com/Photo/'
[I] 	Found: 'https://adamcaudill.com/Resume/'
[I] 	Found: 'https://adamcaudill.com/TOOLS/'
[I] 	Found: 'https://adamcaudill.com/Tools/'
[I] 	Found: 'https://adamcaudill.com/about/'
[I] 	Found: 'https://adamcaudill.com/archives/'
[I] 	Found: 'https://adamcaudill.com/blog/'
[I] 	Found: 'https://adamcaudill.com/feed/'
[I] 	Found: 'https://adamcaudill.com/pgp/'
[I] 	Found: 'https://adamcaudill.com/photo/'
[I] 	Found: 'https://adamcaudill.com/reading/'
[I] 	Found: 'https://adamcaudill.com/resume/'
[I] 	Found: 'https://adamcaudill.com/speaking/'
[I] 	Found: 'https://adamcaudill.com/tools/'
[I] 	Found: 'https://adamcaudill.com/wp-content/'

[I] Meta Generator: WordPress 4.8.2
Scan complete (00:51:05 seconds).
```

