## yawast-ng
[![codecov](https://codecov.io/github/Numorian/yawast-ng/branch/main/graph/badge.svg?token=LPEIB8NOE3)](https://codecov.io/github/Numorian/yawast-ng)

![YAWAST](https://github.com/Numorian/yawast-ng/raw/main/yawast_logo_v1.svg?sanitize=true)

### The YAWAST Antecedent Web Application Security Toolkit - _Next Generation_

YAWAST is an application meant to simplify initial analysis and information gathering for penetration testers and security auditors. It performs basic checks in these categories:

* TLS/SSL - Versions and cipher suites supported; common issues.
* Information Disclosure - Checks for common information leaks.
* Presence of Files or Directories - Checks for files or directories that could indicate a security issue.
* Common Vulnerabilities
* Missing Security Headers

This is meant to provide a easy way to perform initial analysis and information discovery. It's not a full testing suite, and it certainly isn't Metasploit. The idea is to provide a quick way to perform initial data collection, which can then be used to better target further tests. It is especially useful when used in conjunction with Burp Suite (via the `--proxy` parameter).

#### _Next Generation_

This project is a continuation of YAWAST, as yawast-ng, to continue the project by the original author, years after the original project was ended, taking the project in a new direction.

### Documentation

* [Checks Performed](https://numorian.github.io/yawast-ng/checks/)
* [Installation](https://numorian.github.io/yawast-ng/installation/)
* [Usage & Parameters](https://numorian.github.io/yawast-ng/usage/)
* [Scanning TLS/SSL](https://numorian.github.io/yawast-ng/tls/)
  * [OpenSSL & 3DES Compatibility](https://numorian.github.io/yawast-ng/openssl/)
* [Sample Output](https://numorian.github.io/yawast-ng/sample/)
* [FAQ](https://numorian.github.io/yawast-ng/faq/)

Please see [the project website](https://numorian.github.io/yawast-ng/) for full documentation.

### Usage

The most common usage scenario is as simple as:

`yawast scan <url1> <url2>`

Detailed [usage information](https://numorian.github.io/yawast-ng/usage/) is available on the YAWAST web site.

### Contributing

1. Fork it (https://github.com/Numorian/yawast-ng/fork)
2. Create your feature branch (`git checkout -b my-new-feature origin/develop`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

Issues that are labeled as [beginner](/issues?q=is%3Aopen+is%3Aissue+label%3Abeginner) are great starting points for new contributors. These are less complex issues that will help make you familiar with working on YAWAST.

Contributions, in the form of feature requests and pull requests are both welcome and encouraged. YAWAST will only evolve if users are willing and able to give back, and work too make YAWAST better for everyone.

Information on development standards, and guidelines for issues are available in our [CONTRIBUTING](/blob/main/CONTRIBUTING.md) document.

### Special Thanks

* [SecLists](https://github.com/danielmiessler/SecLists) - Various lists are based on the resources collected by this project.
* [FuzzDB Project](https://github.com/fuzzdb-project) - Various lists are based on the resources collected by this project.
