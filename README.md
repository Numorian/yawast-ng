## YAWAST [![Build Status](https://travis-ci.org/adamcaudill/yawast.svg?branch=master)](https://travis-ci.org/adamcaudill/yawast) [![Code Climate](https://codeclimate.com/github/adamcaudill/yawast/badges/gpa.svg)](https://codeclimate.com/github/adamcaudill/yawast) [![PyPI version](https://badge.fury.io/py/yawast.svg)](https://badge.fury.io/py/yawast) [![Docker Pulls](https://img.shields.io/docker/pulls/adamcaudill/yawast.svg)](https://hub.docker.com/r/adamcaudill/yawast/) [![Twitter Follow](https://img.shields.io/twitter/follow/adamcaudill.svg?style=social)](https://twitter.com/intent/user?screen_name=adamcaudill)

![YAWAST](yawast_logo_v1.svg)

**The YAWAST Antecedent Web Application Security Toolkit**

YAWAST is an application meant to simplify initial analysis and information gathering for penetration testers and security auditors. It performs basic checks in these categories:

* TLS/SSL - Versions and cipher suites supported; common issues.
* Information Disclosure - Checks for common information leaks.
* Presence of Files or Directories - Checks for files or directories that could indicate a security issue.
* Common Vulnerabilities
* Missing Security Headers

This is meant to provide a easy way to perform initial analysis and information discovery. It's not a full testing suite, and it certainly isn't Metasploit. The idea is to provide a quick way to perform initial data collection, which can then be used to better target further tests. It is especially useful when used in conjunction with Burp Suite (via the `--proxy` parameter).

Please see [the wiki](https://github.com/adamcaudill/yawast/wiki) for full documentation.

### Installing

YAWAST is packaged as a Python [package](https://pypi.org/project/yawast/) & Docker container to make installing it as easy as possible. Details are available [on the wiki](https://github.com/adamcaudill/yawast/wiki/Installation).

The simplest options to install are:

As a Python package: `pip3 install yawast` (YAWAST requires Python 3.7)

Via Docker: `docker pull adamcaudill/yawast`

It's strongly recommended that you review the [installation](https://github.com/adamcaudill/yawast/wiki/Installation) documentation, to make sure you have the proper dependencies.

### Tests

The following tests are performed:

* *(Generic)* User Enumeration via Password Reset Form Response Differences
* *(Generic)* User Enumeration via Password Reset Form Timing Differences
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
* *(Generic)* Referrer-Policy header not present
* *(Generic)* Feature-Policy header not present
* *(Generic)* X-XSS-Protection disabled header present
* *(Generic)* SSL: HSTS not enabled
* *(Generic)* Source Control: Common source control directories present
* *(Generic)* Presence of crossdomain.xml or clientaccesspolicy.xml
* *(Generic)* Presence of sitemap.xml
* *(Generic)* Presence of WS_FTP.LOG
* *(Generic)* Presence of RELEASE-NOTES.txt
* *(Generic)* Presence of readme.html
* *(Generic)* Presence of CHANGELOG.txt
* *(Generic)* Presence of license.txt
* *(Generic)* Missing cookie flags (Secure, HttpOnly, and SameSite)
* *(Generic)* Cookies with SameSite=None flag
* *(Generic)* Search for 14,405 common files (via `--files`) & 21,332 common directories (via `--dir`)
* *(Generic)* CAA DNS records missing
* *(Generic)* DNSSEC not enabled
* *(Generic)* Detailed error messages
* *(Generic)* Charset not defined
* *(Generic)* Content-Type header missing
* *(Generic)* Insecure links
* *(Generic)* Internal IP address exposed
* *(JavaScript)* Vulnerable libraries used (via RetireJS)
* *(JavaScript)* Third-party scripts used
* *(Apache)* Info Disclosure: Module listing enabled
* *(Apache)* Info Disclosure: Server version
* *(Apache)* Info Disclosure: OpenSSL module version
* *(Apache)* Presence of /server-status
* *(Apache)* Presence of /server-info
* *(Apache)* Outdated version
* *(Apache Tomcat)* Presence of Tomcat Manager
* *(Apache Tomcat)* Presence of Tomcat Host Manager
* *(Apache Tomcat)* Tomcat Manager Weak Password
* *(Apache Tomcat)* Tomcat Host Manager Weak Password
* *(Apache Tomcat)* Tomcat version detection via invalid HTTP verb
* *(Apache Tomcat)* Tomcat version detection via File Not Found
* *(Apache Tomcat)* Tomcat PUT RCE (CVE-2017-12617)
* *(Apache Tomcat)* Tomcat Windows RCE (CVE-2019-0232)
* *(Apache Tomcat)* Outdated version
* *(Apache Struts)* Sample files which may be vulnerable
* *(Nginx)* Info Disclosure: Server version
* *(Nginx)* Info Disclosure: Server status
* *(Nginx)* Outdated version
* *(IIS)* Info Disclosure: Server version
* *(ASP.NET)* Info Disclosure: ASP.NET version
* *(ASP.NET)* Info Disclosure: ASP.NET MVC version
* *(ASP.NET)* Info Disclosure: Registered handlers
* *(ASP.NET)* Presence of Trace.axd
* *(ASP.NET)* Presence of Elmah.axd
* *(ASP.NET)* Debugging Enabled
* *(ASP.NET)* Outdated version
* *(PHP)* Info Disclosure: PHP version
* *(PHP)* Outdated version
* *(Rails)* File Content Disclosure: CVE-2019-5418
* *(Rails)* Presence of X-Runtime header
* *(WordPress)* Version detection
* *(WordPress)* WP-JSON User Enumeration
* *(WordPress)* Outdated version

### TLS/SSL Information

By default, YAWAST uses SSL Labs to gather information and issues related to TLS. This includes the full list of issues reported by SSL Labs, with some additional information and issues captured. When a scan is performed against a target that SSL Labs would not be able to scan (such as a private IP address), YAWAST will use SSLyze to perform this analysis.

By using SSL Labs and SSLyze, YAWAST is able to capture a significant number of TLS issues; the full list is too long (and updated too often) to display here.

* Certificate details
* Certificate chain
* Supported ciphers
* DNS CAA records
* ...many others

Checks for the following SSL issues are performed (the exact list depends on which integration is used):

* Expired Certificate
* Self-Signed Certificate
* MD5 Signature
* SHA1 Signature
* RC4 Cipher Suites
* CBC Cipher Suites
* Weak (< 128 bit) Cipher Suites
* SWEET32 (via `--tdessessioncount` parameter)
* POODLE
* ROBOT
* Sleeping POODLE
* Untrusted Symantec Root
* TICKETBLEED
* SSLv3 Supported
* TLS 1.0 Supported
* TLS 1.3 Early Data Supported
* TLS 1.3 Not Supported
* Zombie POODLE
* OpenSSL CVE-2014-0224
* OpenSSL CVE-2016-2107
* OpenSSL CVE-2019-1559
* OCSP Staple Missing
* LOGJAM
* Missing AEAD Support
* Insecure Renegotiation
* HEARTBLEED
* Heartbeat Extension Enabled
* GOLDENDOODLE
* Fallback SCSV Missing
* FREAK
* DROWN
* ECDH Parameter Reuse
* DH Parameter Reuse
* DH Common Primes
* Compression Enabled
* ...many others

#### SWEET32

YAWAST is unique among the tools available, in that it provides the only implementation of a test for SWEET32 that does more than check for cipher suites with a 64-bit block size. This allows YAWAST to provide the most accurate assessment of this issue available.

See [here](https://adamcaudill.com/2016/09/15/testing-sweet32-yawast/) for more information.

### DNS Information

* IP Addresses
* IP Owner/Network (via [api.iptoasn.com](https://api.iptoasn.com/))
* TXT Records
* MX Records
* NS Records
* CAA Records (with CNAME chasing)
* Common Subdomains (2,354 subdomains) - optional, via `--subdomains`
* SRV Records - optional, via `--srv`

In addition to these tests, certain basic information is also displayed, such as IPs (and the PTR record for each IP), HTTP HEAD request, and others.

### Usage

The most common usage scenario is as simple as:

`yawast scan <url1> <url2>`

Detailed [usage information](https://github.com/adamcaudill/yawast/wiki/Usage-&-Parameters) is available on the wiki.

### Sample

Sample output for a [scan](https://github.com/adamcaudill/yawast/wiki/Sample-Output) and [TLS-specific](https://github.com/adamcaudill/yawast/wiki/Scanning-TLS-(SSL)) checks are on the wiki.

### Special Thanks

* [BSI AppSec](https://www.appsecconsulting.com/) - Generously providing time to improve this tool.
* [SecLists](https://github.com/danielmiessler/SecLists) - Various lists are based on the resources collected by this project.
