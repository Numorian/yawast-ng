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

### Documentation

* [Checks Performed](https://yawast.org/checks/)
* [Installation](https://yawast.org/installation/)
* [Usage & Parameters](https://yawast.org/usage/)
* [Scanning TLS/SSL](https://yawast.org/tls/)
  * [OpenSSL & 3DES Compatibility](https://yawast.org/openssl/)
* [Sample Output](https://yawast.org/sample/)
* [FAQ](https://yawast.org/faq/)

Please see [yawast.org](https://yawast.org/) for full documentation.

### Usage

The most common usage scenario is as simple as:

`yawast scan <url1> <url2>`

Detailed [usage information](https://yawast.org/usage/) is available on the YAWAST web site.

### Sample

Sample output for a [scan](https://yawast.org/sample/) and [TLS-specific](https://yawast.org/tls/) checks are on the YAWAST web site.

### Special Thanks

* [BSI AppSec](https://www.appsecconsulting.com/) - Generously providing time to improve this tool.
* [SecLists](https://github.com/danielmiessler/SecLists) - Various lists are based on the resources collected by this project.
