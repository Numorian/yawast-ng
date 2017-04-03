## 0.5.0 - In Development

* [#35](https://github.com/adamcaudill/yawast/issues/35) - Add check for SameSite cookie attribute
* [#53](https://github.com/adamcaudill/yawast/issues/53) - Added checks for .well-known URLs
* [#75](https://github.com/adamcaudill/yawast/issues/75) - Use internal SSL scanner for non-standard ports
* [#84](https://github.com/adamcaudill/yawast/issues/84) - Improve the display of ct_precert_scts
* [#86](https://github.com/adamcaudill/yawast/issues/86) - Add check for Tomcat Manager & common passwords
* [#87](https://github.com/adamcaudill/yawast/issues/87) - Tomcat version detection via invalid HTTP verb
* [#88](https://github.com/adamcaudill/yawast/issues/88) - Add IP Network Info via [api.iptoasn.com](https://api.iptoasn.com/)
* [#90](https://github.com/adamcaudill/yawast/issues/90) - Add HSTS Preload check via [HSTSPreload.com](https://hstspreload.com/)
* [#91](https://github.com/adamcaudill/yawast/issues/91) - Enhanced file search
* [#96](https://github.com/adamcaudill/yawast/issues/96) - Scan for known SRV DNS Records
* [#97](https://github.com/adamcaudill/yawast/issues/97) - Search for Common Subdomains
* [#100](https://github.com/adamcaudill/yawast/issues/100) - Check for missing cipher suite support
* [#102](https://github.com/adamcaudill/yawast/issues/102) - Use SSLShake to power cipher suite enumeration
* [#76](https://github.com/adamcaudill/yawast/issues/76) - Bug: Handle error for OpenSSL version support error
* [#98](https://github.com/adamcaudill/yawast/issues/98) - Bug: SWEET32 Test Fails if 3DES Not Support By Latest Server Supported TLS Version
* [#99](https://github.com/adamcaudill/yawast/issues/99) - Bug: Cloudflare SWEET32 False Positive
* [#101](https://github.com/adamcaudill/yawast/issues/101) - Bug: SWEET32 False Negative
* Various code and other improvements.

## 0.4.0 - 2016-11-03

* [#66](https://github.com/adamcaudill/yawast/issues/66) - Thread directory search for better performance
* [#67](https://github.com/adamcaudill/yawast/issues/67) - Make "Found Redirect" optional
* [#69](https://github.com/adamcaudill/yawast/issues/69) - False positives on non-standard 404 handling
* [#73](https://github.com/adamcaudill/yawast/issues/73) - Use `--internalssl` when host is an IP address
* [#64](https://github.com/adamcaudill/yawast/issues/64) - Add check for secure cookie on HTTP host
* [#45](https://github.com/adamcaudill/yawast/issues/45) - Access Control Headers Check
* [#65](https://github.com/adamcaudill/yawast/issues/65) - Bug: Output redirection doesn't work correctly
* [#70](https://github.com/adamcaudill/yawast/issues/70) - Bug: Handle scans of IP addresses
* [#72](https://github.com/adamcaudill/yawast/issues/72) - Bug: internalssl & Scanning IPs Fails

## 0.3.0 - 2016-09-15

* [#61](https://github.com/adamcaudill/yawast/issues/61) - SSL Session Count: force 3DES suites
* [#23](https://github.com/adamcaudill/yawast/issues/23) - Add check for HTTP to HTTPS redirect
* [#63](https://github.com/adamcaudill/yawast/issues/63) - Rename `--sslsessioncount` to `--tdessessioncount`

## 0.2.2 - 2016-09-07

* [#55](https://github.com/adamcaudill/yawast/issues/55) - Add Protocol Intolerance information. 
* Update `ssllabs` required version to 1.24.0 to correct issue with new SSL Labs API release.

## 0.2.1 - 2016-09-03

* Initial Public Release
