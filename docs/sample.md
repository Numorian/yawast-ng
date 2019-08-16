---
layout: default
title: Sample Output
permalink: /sample/
---

Below is an example of the output from a typical `scan` with YAWAST - using `scan` - the normal go-to option. Here's what you get when scanning my website:

```
$ yawast scan https://adamcaudill.com 
  --tdessessioncount 
  --dir 
  --files 
  --srv 
  --subdomains 
  --ports 
  --user='adam' 
  --pass_reset_page='https://adamcaudill.com/wp-login.php\?action\=lostpassword'

 .-.          .-
  \ \        / /                       _
   \ \      / /                       | |
    \ \    / /  __ ___      ____ _ ___| |_
     \ \  / /  / _` \ \ /\ / / _` / __| __|
      \ `  /  | (_| |\ V  V / (_| \__ \ |_
       \  /    \__,_| \_/\_/ \__,_|___/\__|
       / /
   |`-' /     ...where a pentest starts
    '..'

The YAWAST Antecedent Web Application Security Toolkit (v0.8.2)
 Copyright (c) 2013-2019 Adam Caudill <adam@adamcaudill.com> and Contributors
 Support & Documentation: https://yawast.org
 Python 3.7.3 (default, May 18 2019, 17:17:19) [Clang 10.0.1 (clang-1001.0.46.4)] (CPython)
 OpenSSL 1.0.2r  26 Feb 2019
 Platform: Darwin-18.6.0-x86_64-i386-64bit (en_US.UTF-8 / UTF-8)
 CPU(s): 8@2900MHz - RAM: 16.00GB (5.99GB Available)
 Supported Version: 0.8.2 - You are on a pre-release version. Take care.

 Started at 2019-08-15 17:33:40 EDT (-0400)

Connection Status:
 IPv4 -> Internet: 206.189.196.12
 IPv6 -> Internet: Connection Failed

Scanning: https://adamcaudill.com/
Server responds to HTTP requests


       DNS Information:
          104.28.27.55 (N/A)
             US - CLOUDFLARENET - Cloudflare, Inc.
             https://www.shodan.io/host/104.28.27.55
             https://censys.io/ipv4/104.28.27.55

          104.28.26.55 (N/A)
             US - CLOUDFLARENET - Cloudflare, Inc.
             https://www.shodan.io/host/104.28.26.55
             https://censys.io/ipv4/104.28.26.55

          2606:4700:30::681c:1b37 (N/A)
             US - CLOUDFLARENET - Cloudflare, Inc.
             https://www.shodan.io/host/2606:4700:30::681c:1b37

          2606:4700:30::681c:1a37 (N/A)
             US - CLOUDFLARENET - Cloudflare, Inc.
             https://www.shodan.io/host/2606:4700:30::681c:1a37

          TXT: "v=spf1 mx a ptr include:_spf.google.com ~all"
          TXT: "google-site-verification=QTO_7Q7UXmrUIwieJliLTXV3XuQdqNvTPVcug_TwH0w"
          TXT: "brave-ledger-verification=0262b8f382f60074e0131f65243fa7caba48b15eb664ec8d0d3e0b3a26a45b47"

          MX: alt1.aspmx.l.google.com. (20) - 209.85.203.26 (US - GOOGLE - Google LLC)
          MX: alt2.aspmx.l.google.com. (20) - 173.194.76.26 (US - GOOGLE - Google LLC)
          MX: aspmx2.googlemail.com. (30) - 209.85.203.26 (US - GOOGLE - Google LLC)
          MX: aspmx3.googlemail.com. (30) - 173.194.76.26 (US - GOOGLE - Google LLC)
          MX: aspmx4.googlemail.com. (30) - 74.125.128.26 (US - GOOGLE - Google LLC)
          MX: aspmx5.googlemail.com. (30) - 108.177.14.27 (US - GOOGLE - Google LLC)
          MX: aspmx.l.google.com. (10) - 74.125.141.26 (US - GOOGLE - Google LLC)

          NS: hal.ns.cloudflare.com. - 173.245.59.174 (US - CLOUDFLARENET - Cloudflare, Inc.)
          NS: vera.ns.cloudflare.com. - 173.245.58.147 (US - CLOUDFLARENET - Cloudflare, Inc.)

       Searching for SRV records, this will take a minute...

          SRV: _bittorrent._tcp.adamcaudill.com.: example.com.:1 - 93.184.216.34 (US - EDGECAST - MCI Communications Services, Inc. d/b/a Verizon Business)

       Searching for sub-domains, this will take a few minutes...

          Subdomain: (A) www.adamcaudill.com.: 104.28.27.55 (US - CLOUDFLARENET - Cloudflare, Inc.)
          Subdomain: (A) www.adamcaudill.com.: 104.28.26.55 (US - CLOUDFLARENET - Cloudflare, Inc.)
          Subdomain: (AAAA) www.adamcaudill.com.: 2606:4700:30::681c:1a37 (US - CLOUDFLARENET - Cloudflare, Inc.)
          Subdomain: (AAAA) www.adamcaudill.com.: 2606:4700:30::681c:1b37 (US - CLOUDFLARENET - Cloudflare, Inc.)

          CAA (adamcaudill.com): "0 issue "letsencrypt.org""
          CAA (adamcaudill.com): "0 issuewild "comodoca.com""
          CAA (adamcaudill.com): "0 issuewild "digicert.com""
          CAA (adamcaudill.com): "0 issuewild "letsencrypt.org""
          CAA (adamcaudill.com): "0 iodef "mailto:adam@adamcaudill.com""
          CAA (adamcaudill.com): "0 issue "comodoca.com""
          CAA (adamcaudill.com): "0 issue "digicert.com""
          CAA (adamcaudill.com): "0 issue "globalsign.com""
          CAA (com): No Records Found

[Info]    DNSKEY: Domain does not use DNSSEC


       Open Ports:
[Info]    Open Port: IP: 104.28.26.55 - Port: 80 (Assigned Service: http - World Wide Web HTTP)
[Info]    Open Port: IP: 104.28.26.55 - Port: 443 (Assigned Service: https - http protocol over TLS/SSL)
[Info]    Open Port: IP: 104.28.26.55 - Port: 8080 (Assigned Service: http-alt - HTTP Alternate (see port 80))
[Info]    Open Port: IP: 104.28.26.55 - Port: 8443 (Assigned Service: pcsync-https - PCsync HTTPS)
[Info]    Open Port: IP: 104.28.27.55 - Port: 443 (Assigned Service: https - http protocol over TLS/SSL)
[Info]    Open Port: IP: 104.28.27.55 - Port: 8080 (Assigned Service: http-alt - HTTP Alternate (see port 80))
[Info]    Open Port: IP: 104.28.27.55 - Port: 80 (Assigned Service: http - World Wide Web HTTP)
[Info]    Open Port: IP: 104.28.27.55 - Port: 8443 (Assigned Service: pcsync-https - PCsync HTTPS)

       Beginning SSL Labs scan (this could take a minute or two)

       [SSL Labs] This assessment service is provided free of charge by Qualys SSL Labs, subject to our terms and conditions:
			↳ https://www.ssllabs.com/about/terms.html
       Status - 2606:4700:30:0:0:0:681c:1b37: Ready
       Status - 2606:4700:30:0:0:0:681c:1a37: Ready
       Status - 104.28.27.55: Ready
       Status - 104.28.26.55: Ready
       Status: Working...

       IP: 2606:4700:30:0:0:0:681c:1b37 - Grade: A+
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

       IP: 2606:4700:30:0:0:0:681c:1a37 - Grade: A+
          [...snip...]

       IP: 104.28.27.55 - Grade: A+
          [...snip...]

       IP: 104.28.26.55 - Grade: A+
          [...snip...]

       TLS Session Request Limit: Checking number of requests accepted using 3DES suites (IP: 104.28.26.55:443)

          Server rejected our connection (TLS / Alert: handshake failure)


       TLS Session Request Limit: Checking number of requests accepted using 3DES suites (IP: 104.28.27.55:443)

          Server rejected our connection (TLS / Alert: handshake failure)


       TLS Session Request Limit: Checking number of requests accepted using 3DES suites (IP: 2606:4700:30::681c:1a37:443)

          Server rejected our connection (TLS / Alert: handshake failure)


       TLS Session Request Limit: Checking number of requests accepted using 3DES suites (IP: 2606:4700:30::681c:1b37:443)

          Server rejected our connection (TLS / Alert: handshake failure)


       HEAD:
          HTTP/1.1 200 OK
          Date: Thu, 15 Aug 2019 21:39:36 GMT
          Content-Type: text/html; charset=UTF-8
          Connection: keep-alive
          Set-Cookie: __cfduid=d70da009903a15a498cd1f45e6af3eb251565905176; expires=Fri, 14-Aug-20 21:39:36 GMT; path=/; domain=.adamcaudill.com; HttpOnly;
			↳ Secure
          Vary: Accept-Encoding,Cookie
          Last-Modified: Wed, 05 Jun 2019 20:08:58 GMT
          X-Content-Type-Options: nosniff
          Referrer-Policy:
          Pragma: public
          Cache-Control: public, max-age=86400
          CF-Cache-Status: HIT
          Age: 3847
          Expires: Fri, 16 Aug 2019 21:39:36 GMT
          Strict-Transport-Security: max-age=15552000; preload
          Expect-CT: max-age=604800, report-uri="https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct"
          Server: cloudflare
          CF-RAY: 506e52760df5b72d-JAX
          Content-Encoding: gzip

       Header Issues:
[Info]    X-XSS-Protection Header Not Present (https://adamcaudill.com/)
[Info]    X-Frame-Options Header Not Present (https://adamcaudill.com/)
[Info]    Content-Security-Policy Header Not Present (https://adamcaudill.com/)
[Info]    Feature-Policy Header Not Present (https://adamcaudill.com/)

       Cookie Issues:
[Info]    Cookie Missing SameSite Flag: __cfduid=d70da009903a15a498cd1f45e6af3eb251565905176; expires=Fri, 14-Aug-20 21:39:36 GMT; path=/;
			↳ domain=.adamcaudill.com; HttpOnly; Secure

       WAF Detection:
[Info]    WAF Detected: Cloudflare

       Performing vulnerability scan (this will take a while)...
       Identified 1722 pages.

       Issues Detected:
[Info]    External JavaScript File: https://s0.wp.com/wp-content/js/devicepx-jetpack.js?ver=201923
[Info]    External JavaScript File: https://stats.wp.com/e-201923.js
[Info]    External JavaScript File: https://ajax.cloudflare.com/cdn-cgi/scripts/95c75768/cloudflare-static/rocket-loader.min.js
[Warn]    Vulnerable JavaScript: jquery-1.12.4 (https://adamcaudill.com/wp-includes/js/jquery/jquery.js?ver=1.12.4-wp): Severity: medium - Info:
			↳  https://github.com/jquery/jquery/issues/2432 http://blog.jquery.com/2016/01/08/jquery-2-2-and-1-12-released/
			↳ https://nvd.nist.gov/vuln/detail/CVE-2015-9251 http://research.insecurelabs.org/jquery/test/
[Warn]    Vulnerable JavaScript: jquery-1.12.4 (https://adamcaudill.com/wp-includes/js/jquery/jquery.js?ver=1.12.4-wp): Severity: medium - Info:
			↳  https://bugs.jquery.com/ticket/11974 https://nvd.nist.gov/vuln/detail/CVE-2015-9251 http://research.insecurelabs.org/jquery/test/
[Warn]    Vulnerable JavaScript: jquery-1.12.4 (https://adamcaudill.com/wp-includes/js/jquery/jquery.js?ver=1.12.4-wp): Severity: low - Info:
			↳ https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/ https://nvd.nist.gov/vuln/detail/CVE-2019-11358
			↳ https://github.com/jquery/jquery/commit/753d591aea698e57d6db58c9f722cd0808619b1b
[Info]    Cache-Control: Public: https://adamcaudill.com/
[Info]    Cache-Control: no-cache Not Found: https://adamcaudill.com/
[Info]    Cache-Control: no-store Not Found: https://adamcaudill.com/
[Info]    Cache-Control: private Not Found: https://adamcaudill.com/
[Info]    Pragma: no-cache Not Found: https://adamcaudill.com/
[Info]    Insecure Link: https://adamcaudill.com/2012/10/07/upek-windows-password-decryption/ links to
			↳ http://blog.crackpassword.com/2012/08/upek-fingerprint-readers-a-huge-security-hole/
[Info]    Insecure Link: https://adamcaudill.com/2012/10/07/upek-windows-password-decryption/ links to
			↳ http://support.authentec.com/Downloads/Windows/ProtectorSuite.aspx
[Info]    Insecure Link: https://adamcaudill.com/category/security_research/page/2/ links to http://www.dovestones.com/active-directory-
			↳ password-reset/
[Info]    Insecure Link: https://adamcaudill.com/category/security_research/page/2/ links to http://www.brandonw.net/
[Info]    Insecure Link: https://adamcaudill.com/category/security_research/page/2/ links to http://siege.org/phpmyid
[Info]    Insecure Link: https://adamcaudill.com/category/security_research/page/2/ links to http://www.vicidial.org/vicidial.php
[Info]    Insecure Link: https://adamcaudill.com/category/security_research/page/2/ links to http://www.vicidial.com/
[Info]    External JavaScript File: https://platform.twitter.com/widgets.js
[Info]    Insecure Link: https://adamcaudill.com/category/essays/ links to http://www.adambarth.com/papers/2008/jackson-barth-b.pdf
[Info]    Insecure Link: https://adamcaudill.com/category/essays/ links to http://www.phrack.org/
[Info]    Insecure Link: https://adamcaudill.com/category/essays/ links to http://www.darkreading.com/attacks-and-breaches/target-ignored-data-
			↳ breach-alarms/d/d-id/1127712
[Info]    Insecure Link: https://adamcaudill.com/category/security_research/ links to http://www.telerik.com/fiddler
[Info]    Insecure Link: https://adamcaudill.com/category/security_research/ links to http://www.allroundautomations.com/plsqldev.html
[Info]    Insecure Link: https://adamcaudill.com/category/security_research/ links to http://brandonw.net/
[Info]    Insecure Link: https://adamcaudill.com/speaking/ links to http://www.codemash.org/
[Info]    Insecure Link: https://adamcaudill.com/speaking/ links to http://www.codestock.org/
[Info]    Insecure Link: https://adamcaudill.com/speaking/ links to http://stirtrek.com/
[Info]    Insecure Link: https://adamcaudill.com/speaking/ links to http://www.tricitiesug.net/
[Info]    Insecure Link: https://adamcaudill.com/speaking/ links to http://wncdotnet.com/
[Info]    External JavaScript File: https://s0.wp.com/wp-content/js/devicepx-jetpack.js?ver=201933
[Info]    External JavaScript File: https://stats.wp.com/e-201933.js
[Info]    File found: https://adamcaudill.com/readme.html
[Info]    File found: https://adamcaudill.com/license.txt

       Searching for common files (this will take a few minutes)...
[Info]    Cookie Missing HttpOnly Flag: wordpress_test_cookie=WP+Cookie+check; path=/; secure
[Info]    Cookie Missing SameSite Flag: wordpress_test_cookie=WP+Cookie+check; path=/; secure
          New file found: https://adamcaudill.com/#wp-config.php#
          New file found: https://adamcaudill.com/favicon.ico
          New file found: https://adamcaudill.com/keybase.txt
          New file found: https://adamcaudill.com/license.txt
          New file found: https://adamcaudill.com/robots.txt
          New file found: https://adamcaudill.com/sitemap_index.xml
          New file found: https://adamcaudill.com/tools
          New file found: https://adamcaudill.com/wp-config.php
          New file found: https://adamcaudill.com/wp-cron.php
          New file found: https://adamcaudill.com/wp-json
          New file found: https://adamcaudill.com/wp-json/wp/v2/posts
          New file found: https://adamcaudill.com/wp-json/wp/v2/users
          New file found: https://adamcaudill.com/wp-links-opml.php
          New file found: https://adamcaudill.com/wp-load.php
          New file found: https://adamcaudill.com/wp-login.php


       Searching for common directories (this will take a few minutes)...
[Info]    External JavaScript File: https://s0.wp.com/wp-content/js/devicepx-jetpack.js?ver=201927
[Info]    External JavaScript File: https://stats.wp.com/e-201927.js
[Info]    External JavaScript File: https://s0.wp.com/wp-content/js/devicepx-jetpack.js?ver=201926
[Info]    External JavaScript File: https://stats.wp.com/e-201926.js
[Info]    External JavaScript File: https://s0.wp.com/wp-content/js/devicepx-jetpack.js?ver=201925
[Info]    External JavaScript File: https://stats.wp.com/e-201925.js
[Info]    External JavaScript File: https://s0.wp.com/wp-content/js/devicepx-jetpack.js?ver=201932
[Info]    External JavaScript File: https://stats.wp.com/e-201932.js
[Info]    External JavaScript File: https://s0.wp.com/wp-content/js/devicepx-jetpack.js?ver=201928
[Info]    External JavaScript File: https://stats.wp.com/e-201928.js
[Info]    External JavaScript File: https://s0.wp.com/wp-content/js/devicepx-jetpack.js?ver=201930
[Info]    External JavaScript File: https://stats.wp.com/e-201930.js
          New directory found: https://adamcaudill.com/0000/
          New directory found: https://adamcaudill.com/2003/
          New directory found: https://adamcaudill.com/2004/
          New directory found: https://adamcaudill.com/2005/
          New directory found: https://adamcaudill.com/2006/
          New directory found: https://adamcaudill.com/2007/
          New directory found: https://adamcaudill.com/2008/
          New directory found: https://adamcaudill.com/2009/
          New directory found: https://adamcaudill.com/2010/
          New directory found: https://adamcaudill.com/2011/
          New directory found: https://adamcaudill.com/2012/
          New directory found: https://adamcaudill.com/2013/
          New directory found: https://adamcaudill.com/2014/
          New directory found: https://adamcaudill.com/2015/
          New directory found: https://adamcaudill.com/2016/
          New directory found: https://adamcaudill.com/2017/
          New directory found: https://adamcaudill.com/2018/
          New directory found: https://adamcaudill.com/2019/
          New directory found: https://adamcaudill.com/ABOUT/
          New directory found: https://adamcaudill.com/ARCHIVES/
          New directory found: https://adamcaudill.com/About/
          New directory found: https://adamcaudill.com/Archives/
          New directory found: https://adamcaudill.com/BLOG/
          New directory found: https://adamcaudill.com/Blog/
          New directory found: https://adamcaudill.com/Feed/
          New directory found: https://adamcaudill.com/Photo/
          New directory found: https://adamcaudill.com/Resume/
          New directory found: https://adamcaudill.com/TOOLS/
          New directory found: https://adamcaudill.com/Tools/
          New directory found: https://adamcaudill.com/archives/
          New directory found: https://adamcaudill.com/feed/
          New directory found: https://adamcaudill.com/reading/
          New directory found: https://adamcaudill.com/tools/
          New directory found: https://adamcaudill.com/wp-content/

[Warn]    Password Reset: Possible User Enumeration - Difference in Response
[Info]    Cache-Control Header Not Found: https://adamcaudill.com/
[Info]    Expires Header Not Found: https://adamcaudill.com/
[Info]    X-Content-Type-Options Header Not Present (https://adamcaudill.com/)
[Warn]    Strict-Transport-Security Header Not Present (https://adamcaudill.com/)
[Info]    Allow HTTP Verbs (OPTIONS): POST,OPTIONS,GET,HEAD
[Info]    Found WordPress v5.2.1 at https://adamcaudill.com/
[Warn]    WordPress Outdated: 5.2.1 - Current: 5.2.2
[Warn]    WordPress WP-JSON User Enumeration at https://adamcaudill.com/wp-json/wp/v2/users
[Info]    ID: 1 User Slug: 'adam'    User Name: 'Adam Caudill'

       Completed (Elapsed: 3:26:28.570819 - Peak Memory: 0.61GB)
```

