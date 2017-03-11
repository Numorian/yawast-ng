## YAWAST [![Build Status](https://travis-ci.org/adamcaudill/yawast.svg?branch=master)](https://travis-ci.org/adamcaudill/yawast) [![Code Climate](https://codeclimate.com/github/adamcaudill/yawast/badges/gpa.svg)](https://codeclimate.com/github/adamcaudill/yawast) [![Test Coverage](https://codeclimate.com/github/adamcaudill/yawast/badges/coverage.svg)](https://codeclimate.com/github/adamcaudill/yawast/coverage) [![Gem Version](https://badge.fury.io/rb/yawast.svg)](https://badge.fury.io/rb/yawast)

**The YAWAST Antecedent Web Application Security Toolkit**

YAWAST is an application meant to simplify initial analysis and information gathering for penetration testers and security auditors. It performs basic checks in these categories:

* TLS/SSL - Versions and cipher suites supported; common issues.
* Information Disclosure - Checks for common information leaks.
* Presence of Files or Directories - Checks for files or directories that could indicate a security issue.
* Common Vulnerabilities
* Missing Security Headers

This is meant to provide a easy way to perform initial analysis and information discovery. It's not a full testing suite, and it certainly isn't Metasploit. The idea is to provide a quick way to perform initial data collection, which can then be used to better target further tests. It is especially useful when used in conjunction with Burp Suite (via the `--proxy` parameter).

### Installing

The simplest method to install is to use the RubyGem installer:

`gem install yawast`

This allows for simple updates (`gem update yawast`) and makes it easy to ensure that you are always using the latest version.

YAWAST requires Ruby 2.2+, and is tested on Mac OSX, Linux, and Windows.

**Kali Rolling**

To install on Kali, just run `gem install yawast` - all of the dependentcies are already installed.

**Ubuntu 16.04**

To install YAWAST, you first need to install a couple packages via `apt-get`:

```
sudo apt-get install ruby ruby-dev
sudo gem install yawast
```

**Mac OSX**

The version of Ruby shipped with Mac OSX 10.11 is too old, so the recommended solution is to use RVM:

```
gpg --keyserver hkp://keys.gnupg.net --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3
\curl -sSL https://get.rvm.io | bash -s stable
source ~/.rvm/scripts/rvm
rvm install 2.2
rvm use 2.2 --default
gem install yawast
```

**Windows**

To install on Windows, you need to first install Ruby; this can be done easily with the latest version of [RubyInstaller](https://rubyinstaller.org/downloads/). Once Ruby is installed, YAWAST can be installed via `gem install yawast` as normal.

### Tests

The following tests are performed:

* *(Generic)* Info Disclosure: X-Powered-By header present
* *(Generic)* Info Disclosure: X-Pingback header present
* *(Generic)* Info Disclosure: X-Backend-Server header present
* *(Generic)* Info Disclosure: X-Runtime header present
* *(Generic)* Info Disclosure: Via header present
* *(Generic)* Info Disclosure: PROPFIND Enabled
* *(Generic)* TRACE Enabled
* *(Generic)* X-Frame-Options header not present
* *(Generic)* X-Content-Type-Options header not present
* *(Generic)* Content-Security-Policy header not present
* *(Generic)* Public-Key-Pins header not present
* *(Generic)* X-XSS-Protection disabled header present
* *(Generic)* SSL: HSTS not enabled
* *(Generic)* Source Control: Common source control directories present
* *(Generic)* Presence of crossdomain.xml or clientaccesspolicy.xml
* *(Generic)* Presence of sitemap.xml
* *(Generic)* Presence of WS_FTP.LOG
* *(Generic)* Presence of RELEASE-NOTES.txt
* *(Generic)* Presence of readme.html
* *(Generic)* Missing cookie flags (Secure & HttpOnly)
* *(Generic)* Search for files & common directories
* *(Apache)* Info Disclosure: Module listing enabled
* *(Apache)* Info Disclosure: Server version
* *(Apache)* Info Disclosure: OpenSSL module version
* *(Apache)* Presence of /server-status
* *(Apache)* Presence of /server-info
* *(Apache Tomcat)* Presence of Tomcat Manager
* *(Apache Tomcat)* Presence of Tomcat Host Manager
* *(Apache Tomcat)* Tomcat Manager Weak Password
* *(Apache Tomcat)* Tomcat Host Manager Weak Password
* *(Apache Tomcat)* Tomcat version detection via invalid HTTP verb
* *(IIS)* Info Disclosure: Server version
* *(ASP.NET)* Info Disclosure: ASP.NET version
* *(ASP.NET)* Info Disclosure: ASP.NET MVC version
* *(ASP.NET)* Presence of Trace.axd
* *(ASP.NET)* Presence of Elmah.axd
* *(ASP.NET)* Debugging Enabled
* *(nginx)* Info Disclosure: Server version
* *(PHP)* Info Disclosure: PHP version

CMS Detection:

* Generic (Generator meta tag) *[Real detection coming as soon as I get around to it...]*

SSL Information:

* Certificate details
* Certificate chain
* Supported ciphers
* Maximum requests in a single connection

Checks for the following SSL issues are performed:

* Expired Certificate
* Self-Signed Certificate
* MD5 Signature
* SHA1 Signature
* RC4 Cipher Suites
* Weak (< 128 bit) Cipher Suites
* SWEET32

In addition to these tests, certain basic information is also displayed, such as IPs (and the PTR record for each IP), HTTP HEAD request, and others.

### Usage

* Standard scan: `./yawast scan <url> [--internalssl] [--tdessessioncount] [--nossl] [--nociphers] [--dir] [--dirrecursive] [--dirlistredir] [--files] [--srv [--subdomains] [--proxy localhost:8080] [--cookie SESSIONID=12345]`
* HEAD-only scan: `./yawast head <url> [--internalssl] [--tdessessioncount] [--nossl] [--nociphers] [--proxy localhost:8080] [--cookie SESSIONID=12345]`
* SSL information: `./yawast ssl <url> [--internalssl] [--tdessessioncount] [--nociphers]`
* CMS detection: `./yawast cms <url> [--proxy localhost:8080] [--cookie SESSIONID=12345]`

For detailed information, just call `./yawast -h` to see the help page. To see information for a specific command, call `./yawast -h <command>` for full details. Here is an example, the details for the options to the `scan` command:

```
  OPTIONS:
        
    --nossl 
        Disables SSL checks
        
    --nociphers 
        Disables check for supported ciphers (only with --internalssl)
        
    --internalssl 
        Disable SSL Labs integration
        
    --tdessessioncount 
        Counts the number of messages that can be sent in a single session
        
    --dir 
        Enables directory search
        
    --dirrecursive 
        Recursive directory search (only with --dir)
        
    --dirlistredir 
        Show 301 redirects (only with --dir)
        
    --files 
        Performs a search for a large list of common files
        
    --srv 
        Scan for known SRV DNS Records
        
    --subdomains 
        Search for Common Subdomains
        
    --proxy STRING 
        HTTP Proxy Server (such as Burp Suite)
        
    --cookie STRING 
        Session cookie
```

### Using with Burp Suite

By default, Burp Suite's proxy listens on localhost at port 8080, to use YAWAST with Burp Suite (or any proxy for that matter), just add this to the command line:

`--proxy localhost:8080`

### Authenticated Testing

For authenticated testing, YAWAST allows you to specify a cookie to be passed via the `--cookie` parameter.

`--cookie SESSIONID=1234567890`

### Sample

Using `scan` - the normal go-to option, here's what you get when scanning my website:

```
$ yawast scan https://adamcaudill.com --dir --tdessessioncount
 __   _____  _    _  ___   _____ _____ 
 \ \ / / _ \| |  | |/ _ \ /  ___|_   _|
  \ V / /_\ \ |  | / /_\ \\ `--.  | |  
   \ /|  _  | |/\| |  _  | `--. \ | |  
   | || | | \  /\  / | | |/\__/ / | |  
   \_/\_| |_/\/  \/\_| |_/\____/  \_/  
 
 YAWAST v0.5.0.beta2 - The YAWAST Antecedent Web Application Security Toolkit
  Copyright (c) 2013-2017 Adam Caudill <adam@adamcaudill.com>
  Support & Documentation: https://github.com/adamcaudill/yawast
  Ruby 2.2.4-p230; OpenSSL 1.0.2f  28 Jan 2016 (x86_64-darwin15)
 
 Scanning: https://adamcaudill.com/
 
 DNS Information:
 [I] 		104.28.26.55 (N/A)
 [I] 			US - CLOUDFLARENET - CloudFlare, Inc.
 [I] 			San Francisco, California, US
 			https://www.shodan.io/host/104.28.26.55
 			https://censys.io/ipv4/104.28.26.55
 [I] 		104.28.27.55 (N/A)
 [I] 			US - CLOUDFLARENET - CloudFlare, Inc.
 [I] 			San Francisco, California, US
 			https://www.shodan.io/host/104.28.27.55
 			https://censys.io/ipv4/104.28.27.55
 [I] 		2400:CB00:2048:1::681C:1A37 (N/A)
 [I] 			US - CLOUDFLARENET - CloudFlare, Inc.
 [I] 			US
 			https://www.shodan.io/host/2400:cb00:2048:1::681c:1a37
 [I] 		2400:CB00:2048:1::681C:1B37 (N/A)
 [I] 			US - CLOUDFLARENET - CloudFlare, Inc.
 [I] 			US
 			https://www.shodan.io/host/2400:cb00:2048:1::681c:1b37
 [I] 		TXT: v=spf1 mx a ptr include:_spf.google.com ~all
 [I] 		TXT: google-site-verification=QTO_7Q7UXmrUIwieJliLTXV3XuQdqNvTPVcug_TwH0w
 [I] 		MX: aspmx4.googlemail.com (30)
 [I] 		MX: aspmx.l.google.com (10)
 [I] 		MX: alt1.aspmx.l.google.com (20)
 [I] 		MX: aspmx2.googlemail.com (30)
 [I] 		MX: alt2.aspmx.l.google.com (20)
 [I] 		MX: aspmx3.googlemail.com (30)
 [I] 		MX: aspmx5.googlemail.com (30)
 [I] 		NS: vera.ns.cloudflare.com
 [I] 		NS: hal.ns.cloudflare.com
 
 [I] HEAD:
 [I] 		date: Tue, 03 Jan 2017 03:05:26 GMT
 [I] 		content-type: text/html; charset=UTF-8
 [I] 		connection: close
 [I] 		set-cookie: __cfduid=a; expires=Wed, 03-Jan-18 03:05:26 GMT; path=/; domain=.adamcaudill.com; HttpOnly
 [I] 		x-xss-protection: 1; mode=block
 [I] 		content-security-policy-report-only: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' *.wp.com ajax.cloudflare.com platform.twitter.com s0.wp.com ssl.google-analytics.com cdn.syndication.twimg.com; style-src 'self' 'unsafe-inline' fonts.googleapis.com *.twimg.com platform.twitter.com s0.wp.com; img-src 'self' data: *.wp.com static.flickr.com *.ted.com *.w.org *.gravatar.com *.twimg.com ssl.google-analytics.com *.twitter.com *.staticflickr.com; font-src 'self' data: fonts.googleapis.com fonts.gstatic.com public.slidesharecdn.com; media-src 'self' *.ted.com; child-src 'self' www.slideshare.net www.youtube.com *.twitter.com; frame-ancestors 'self'; reflected-xss block; referrer no-referrer-when-downgrade; report-uri https://adamcaudill.report-uri.io/r/default/csp/reportOnly;
 [I] 		vary: Accept-Encoding,Cookie
 [I] 		last-modified: Tue, 03 Jan 2017 01:49:31 GMT
 [I] 		cache-control: public, max-age=86400
 [I] 		expires: Wed, 04 Jan 2017 03:05:26 GMT
 [I] 		x-frame-options: sameorigin
 [I] 		pragma: public
 [I] 		cf-cache-status: REVALIDATED
 [I] 		strict-transport-security: max-age=15552000; preload
 [I] 		x-content-type-options: nosniff
 [I] 		server: cloudflare-nginx
 [I] 		cf-ray: a-MIA
 
 [I] NOTE: Server appears to be Cloudflare; WAF may be in place.
 
 [I] X-Frame-Options Header: sameorigin
 [I] X-Content-Type-Options Header: nosniff
 [W] Content-Security-Policy Header Not Present
 [W] Public-Key-Pins Header Not Present
 
 [I] Cookies:
 [I] 		__cfduid=a; expires=Wed, 03-Jan-18 03:05:26 GMT; path=/; domain=.adamcaudill.com; HttpOnly
 [W] 			Cookie missing Secure flag
 
 
 Beginning SSL Labs scan (this could take a minute or two)
 [SSL Labs] This assessment service is provided free of charge by Qualys SSL Labs, subject to our terms and conditions: https://www.ssllabs.com/about/terms.html
 .............................................
 
 	SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d=adamcaudill.com&hideResults=on
 
 [I] IP: 104.28.27.55 - Grade: A+
 
 	Certificate Information:
 [I] 		Subject: CN=sni67677.cloudflaressl.com,OU=PositiveSSL Multi-Domain,OU=Domain Control Validated
 [I] 		Common Names: ["sni67677.cloudflaressl.com"]
 [I] 		Alternative names:
 [I] 			sni67677.cloudflaressl.com
 [I] 			*.adamcaudill.com
 [I] 			adamcaudill.com
 [I] 		Not Before: 2016-12-29T00:00:00+00:00
 [I] 		Not After: 2017-07-02T23:59:59+00:00
 [I] 		Key: EC 256 (RSA equivalent: 3072)
 [I] 		Public Key Hash: a2e0276e6a44138fea0f4afc01a4e6a3e165d15e
 [I] 		Version: 2
 [I] 		Serial: 167670175484361448885961646389808341945
 [I] 		Issuer: COMODO ECC Domain Validation Secure Server CA 2
 [I] 		Signature algorithm: SHA256withECDSA
 [I] 		Extended Validation: No (Domain Control)
 [I] 		Certificate Transparency: No
 [I] 		OCSP Must Staple: No
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
 [I] 		Hash: 06746b606927dab24f9b339329639151112c9363
 			https://censys.io/certificates?q=06746b606927dab24f9b339329639151112c9363
 			https://crt.sh/?q=06746b606927dab24f9b339329639151112c9363
 
 	Configuration Information:
 		Protocol Support:
 [I] 			TLS 1.0
 [I] 			TLS 1.1
 [I] 			TLS 1.2
 
 		Cipher Suite Support:
 [I] 			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256            - 128-bits - ECDHE-256-bits
 [I] 			TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256            - 128-bits - ECDHE-256-bits
 [I] 			TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               - 128-bits - ECDHE-256-bits
 [I] 			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384            - 256-bits - ECDHE-256-bits
 [I] 			TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384            - 256-bits - ECDHE-256-bits
 [I] 			TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               - 256-bits - ECDHE-256-bits
 [I] 			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256      - 256-bits - ECDHE-256-bits
 [I] 			OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256  - 256-bits - ECDHE-256-bits
 
 		Handshake Simulation:
 [E] 			Android 2.3.7                - Simulation Failed
 [I] 			Android 4.0.4                - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
 [I] 			Android 4.1.1                - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
 [I] 			Android 4.2.2                - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
 [I] 			Android 4.3                  - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
 [I] 			Android 4.4.2                - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			Android 5.0.0                - TLS 1.2 - OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
 [I] 			Android 6.0                  - TLS 1.2 - OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
 [I] 			Android 7.0                  - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
 [I] 			Baidu Jan 2015               - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
 [I] 			BingPreview Jan 2015         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [E] 			Chrome 49 / XP SP3           - Simulation Failed
 [I] 			Chrome 51 / Win 7            - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			Firefox 31.3.0 ESR / Win 7   - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			Firefox 47 / Win 7           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			Firefox 49 / XP SP3          - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			Firefox 49 / Win 7           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			Googlebot Feb 2015           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [E] 			IE 6 / XP                    - Simulation Failed
 [I] 			IE 7 / Vista                 - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
 [E] 			IE 8 / XP                    - Simulation Failed
 [I] 			IE 8-10 / Win 7              - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
 [I] 			IE 11 / Win 7                - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			IE 11 / Win 8.1              - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			IE 10 / Win Phone 8.0        - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
 [I] 			IE 11 / Win Phone 8.1        - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			IE 11 / Win Phone 8.1 Update - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			IE 11 / Win 10               - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			Edge 13 / Win 10             - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			Edge 13 / Win Phone 10       - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [E] 			Java 6u45                    - Simulation Failed
 [I] 			Java 7u25                    - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
 [I] 			Java 8u31                    - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [E] 			OpenSSL 0.9.8y               - Simulation Failed
 [I] 			OpenSSL 1.0.1l               - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			OpenSSL 1.0.2e               - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			Safari 5.1.9 / OS X 10.6.8   - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
 [I] 			Safari 6 / iOS 6.0.1         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
 [I] 			Safari 6.0.4 / OS X 10.8.4   - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
 [I] 			Safari 7 / iOS 7.1           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
 [I] 			Safari 7 / OS X 10.9         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
 [I] 			Safari 8 / iOS 8.4           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
 [I] 			Safari 8 / OS X 10.10        - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
 [I] 			Safari 9 / iOS 9             - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			Safari 9 / OS X 10.11        - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			Safari 10 / iOS 10           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			Safari 10 / OS X 10.12       - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			Apple ATS 9 / iOS 9          - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			Yahoo Slurp Jan 2015         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 [I] 			YandexBot Jan 2015           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 
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
 [W] 			OCSP Stapling: No
 [I] 			FREAK: No
 [I] 			Logjam: No
 [I] 			DH public server param (Ys) reuse: No
 [I] 			Protocol Intolerance: No
 
 TLS Session Request Limit: Checking number of requests accepted using 3DES suites...
 
 [I] TLS Session Request Limit: Server does not support 3DES cipher suites
 
 [I] HSTS: Enabled (strict-transport-security: max-age=15552000; preload)
 
 [W] '/readme.html' found: https://adamcaudill.com/readme.html
 
 Searching for common directories...
 [I] 	Found: 'https://adamcaudill.com/2005/'
 [I] 	Found: 'https://adamcaudill.com/2006/'
 [I] 	Found: 'https://adamcaudill.com/2004/'
 [I] 	Found: 'https://adamcaudill.com/2003/'
 [I] 	Found: 'https://adamcaudill.com/2008/'
 [I] 	Found: 'https://adamcaudill.com/2007/'
 [I] 	Found: 'https://adamcaudill.com/2010/'
 [I] 	Found: 'https://adamcaudill.com/2011/'
 [I] 	Found: 'https://adamcaudill.com/2013/'
 [I] 	Found: 'https://adamcaudill.com/2014/'
 [I] 	Found: 'https://adamcaudill.com/2009/'
 [I] 	Found: 'https://adamcaudill.com/2016/'
 [I] 	Found: 'https://adamcaudill.com/2015/'
 [I] 	Found: 'https://adamcaudill.com/About/'
 [I] 	Found: 'https://adamcaudill.com/Blog/'
 [I] 	Found: 'https://adamcaudill.com/about/'
 [I] 	Found: 'https://adamcaudill.com/archives/'
 [I] 	Found: 'https://adamcaudill.com/blog/'
 [I] 	Found: 'https://adamcaudill.com/feed/'
 [I] 	Found: 'https://adamcaudill.com/files/'
 [I] 	Found: 'https://adamcaudill.com/pgp/'
 [I] 	Found: 'https://adamcaudill.com/photo/'
 [I] 	Found: 'https://adamcaudill.com/resume/'
 [I] 	Found: 'https://adamcaudill.com/tools/'
 [I] 	Found: 'https://adamcaudill.com/wp-content/'
 [I] 	Found: 'https://adamcaudill.com/wp-includes/'
 
 [I] Meta Generator: WordPress 4.7
 Scan complete.
```

### About The Output

You'll notice that most lines begin with a letter in a bracket, this is to tell you how to interpret the result at a glance. There are four possible values:

* [I] - This indicates that the line is informational, and doesn't necessarily indicate a security issue.
* [W] - This is a Warning, which means that it could be an issue, or could expose useful information. These need to be evaluated on a case-by-case basis to determine the impact.
* [V] - This is a Vulnerability, it indicates an issue that is known to be an issue, and needs to be addressed.
* [E] - This indicates that an error occurred, sometimes these are serious and indicate an issue with your environment, the target server, or the application. In other cases, they may just be informational to let you know that something didn't go as planned.

The indicator used may change over time based on new research or better detection techniques. In all cases, results should be carefully evaluated within the context of the application, how it's used, and what threats apply. The indicator is guidance, a hint if you will, it's up to you to determine the real impact.

### TLS / SSL Testing

YAWAST offers two modes for testing TLS / SSL - one is custom, and most useful for internal systems, and the other uses the [SSL Labs](https://www.ssllabs.com/) API.

#### Internal Mode

To use the custom internal TLS / SSL scanner (which uses your copy of OpenSSL), simply pass `--internalssl` on the command line. Here is a sample of the output generated by this tester.

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

This version is more limited than the SSL Labs option, though will work in cases where SSL Labs is unable to connect to the target server.

#### SSL Labs Mode

The default mode is to use the SSL Labs API, which makes all users bound by their [terms and conditions](https://www.ssllabs.com/downloads/Qualys_SSL_Labs_Terms_of_Use.pdf), and obviously results in the domain you are scanning being sent to them.

This mode is the most comprehensive, and contains far more data than the Internal Mode. Unless there is a good reason to use the Internal Mode, this is what you should use.

### About The Name

When this project was started, the original name was "Yet Another Web Application Security Tool" - as the project became more serious, the name was changed. The current name better reflects the role of the tool, and its place in the penetration tester's workflow. It's meant to be a first step, to come before the serious manual work, and provide information to allow a tester to be up and running quicker. The tests that are performed are based on that goal, as well as the availability and complexity of tests in other tools. If another common tool can do a given task better, it won't be done here.

### Special Thanks

* [SecLists](https://github.com/danielmiessler/SecLists) - Various lists are based on the resources collected by this project.
* [Shopify](https://www.shopify.com/) for [ssllabs.rb](https://github.com/Shopify/ssllabs.rb), which provides the Qualsys SSL Labs integration.
