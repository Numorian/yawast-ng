## 0.13.0 - In Development

* Reduced memory usage by approx. 30% + approx. 275MB.
* Added support for configuration settings in `~/.yawast-ng.json` (see Usage page in the documentation).
* Use `sitemap.xml` to establish initial spider URL list, when available.
* Reduce memory usage when not using the `--output` option.
* Improve performance of ASN data lookups.
* Bug: Fix a failure to save the output file when an existing file already exists.
* Bug: Fix an issue with saving TLS details in JSON output when using `--internalssl`.

## 0.12.1 - 2025-04-04

* Restore the Internal TLS Scanner.
* Assorted maintenance.

## 0.12.0 - 2025-04-03

YAWAST has become yawast-ng, and been substantially updated.

## 0.11.0 - 2020-01-02

* #164 - Apache Tomcat Version Detection via 406 Not Acceptable
* #181 - HSTS Preload Checking (via HSTSPreload.com API) 
* #192 - Check for Missing Cache Control Headers 
* #306 - External JavaScript Lacks SRI
* #308 - Telerik UI for ASP.NET AJAX RadAsyncUpload Enabled
* #312 - Make JSON Storage More Efficient
* #313 - Improve File Search for Misconfigured Servers
* #319 - Enumerate HTTP Methods

## 0.10.0 - 2019-12-10

* #194 - Check for Duplicate HTTP Headers
* #261 - Bump sslyze from 2.1.3 to 2.1.4
* #272 - Basic Jira Detection
* #274 - Check for .DS_Store Files
* #285 - Add support for multiple cookies
* #288 - Add detection of CVE-2019-11043 (PHP RCE)
* #291 - Bug: IP Address Check Returns HTML

## 0.9.0 - 2019-09-04

* #20 - Check for common backup files
* #207 - Specify JWT Similar To Cookie
* #235 - WordPress Plugin Local Path Disclosure
* #244 - Check for common files with phpinfo()
* #264 - Add new version command
* #237 - Bug: Connection error in check_local_ip_disclosure

## 0.8.3 - 2019-08-19

* #238 - Bug: Error with WWW Redirect Detection

## 0.8.2 - 2019-08-16

* #229 - Bug: No attribute 'is_absolute' on DNS information collection

## 0.8.1 - 2019-08-15

* #226 - Bug: TLS Redirect Failure
* #227 - Bug: Improperly Handled SSL Labs Error

## 0.8.0 - 2019-08-15

YAWAST has been completely written, and has moved from Ruby to Python.

## 0.7.2 - 2019-05-13

* #166 - Detect WWW/Non-WWW domain redirection
* #168 - SSL Labs: Add Supports CBC Field
* #170 - When checking HEAD, follow redirects
* #172 - Check for Apache Tomcat version via 404
* #173 - Check X-Powered-By for PHP Version
* #174 - SSL Labs: Add 1.3 0-RTT Support Field
* #169 - Bug: Error in connecting to SSL Labs
* #176 - Bug: NoMethodError (match?) in older versions of Ruby

## 0.7.1 - 2019-05-07

* #37 - Batch Scanning Mode
* #165 - Add check for Referrer-Policy & Feature-Policy headers
* #167 - SSL Labs: Add Zombie POODLE & Related Findings

## 0.7.0 - 2019-04-19

* #38 - JSON Output Option via `--output=` (work in progress)
* #133 - Include a Timestamp In Output
* #134 - Add options to DNS command
* #135 - Incomplete Certificate Chain Warning
* #137 - Warn on TLS 1.0
* #138 - Warn on Symantec Roots
* #139 - Add Spider Option
* #140 - Save output on cancel
* #141 - Flag --internalssl as Deprecated
* #147 - User Enumeration via Password Reset Form
* #148 - Added `--vuln_scan` option to enable new vulnerability scanner
* #151 - User Enumeration via Password Reset Form Timing Differences
* #152 - Add check for 64bit TLS Cert Serial Numbers
* #156 - Check for Rails CVE-2019-5418
* #157 - Add check for Nginx Status Page
* #158 - Add check for Tomcat RCE CVE-2019-0232
* #161 - Add WordPress WP-JSON User Enumeration
* #130 - Bug: HSTS Error leads to printing HTML
* #132 - Bug: Typo in SSL Output
* #142 - Bug: Error In Collecting DNS Information

## 0.6.0 - 2018-01-16

* #54 - Check for Python version in Server header
* #59 - SSL Labs: Display Certificate Chain
* #109 - DNS CAA Support
* #113 - Better False Positive Detection For Directory Search
* #115 - Add dns Command
* #116 - Add option '--nodns' to skip DNS checks
* #117 - Show additional information about the TLS connection
* #118 - Add check for CVE-2017-12617 - Apache Tomcat PUT RCE
* #120 - Add Docker support
* #122 - SSL Labs API v3
* #125 - Add new search paths for Struts Sample Files
* #129 - Bug: DNS Info fails if MX record points to a domain without records

## 0.5.2 - 2017-07-13

* #107 - Current version check
* #111 - Display cipher suite used when running the SWEET32 test
* #110 - Bug: SWEET32 test doesn't properly force 3DES suites

## 0.5.1 - 2017-06-26

* #106 - Bug: SWEET32: Incorrect Request Count

## 0.5.0 - 2017-04-05

* #35 - Add check for SameSite cookie attribute
* #53 - Added checks for .well-known URLs
* #75 - Use internal SSL scanner for non-standard ports
* #84 - Improve the display of ct_precert_scts
* #86 - Add check for Tomcat Manager & common passwords
* #87 - Tomcat version detection via invalid HTTP verb
* #88 - Add IP Network Info via api.iptoasn.com](https://api.iptoasn.com/)
* #90 - Add HSTS Preload check via HSTSPreload.com](https://hstspreload.com/)
* #91 - Enhanced file search
* #96 - Scan for known SRV DNS Records
* #97 - Search for Common Subdomains
* #100 - Check for missing cipher suite support
* #102 - Use SSLShake to power cipher suite enumeration
* #76 - Bug: Handle error for OpenSSL version support error
* #98 - Bug: SWEET32 Test Fails if 3DES Not Support By Latest Server Supported TLS Version
* #99 - Bug: Cloudflare SWEET32 False Positive
* #101 - Bug: SWEET32 False Negative
* #103 - Bug: Scan fails if HEAD isn't supported
* Various code and other improvements.

## 0.4.0 - 2016-11-03

* #66 - Thread directory search for better performance
* #67 - Make "Found Redirect" optional
* #69 - False positives on non-standard 404 handling
* #73 - Use `--internalssl` when host is an IP address
* #64 - Add check for secure cookie on HTTP host
* #45 - Access Control Headers Check
* #65 - Bug: Output redirection doesn't work correctly
* #70 - Bug: Handle scans of IP addresses
* #72 - Bug: internalssl & Scanning IPs Fails

## 0.3.0 - 2016-09-15

* #61 - SSL Session Count: force 3DES suites
* #23 - Add check for HTTP to HTTPS redirect
* #63 - Rename `--sslsessioncount` to `--tdessessioncount`

## 0.2.2 - 2016-09-07

* #55 - Add Protocol Intolerance information. 
* Update `ssllabs` required version to 1.24.0 to correct issue with new SSL Labs API release.

## 0.2.1 - 2016-09-03

* Initial Public Release
