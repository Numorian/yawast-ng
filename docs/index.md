---
layout: default
---

YAWAST is an application meant to simplify initial analysis and information gathering for penetration testers and security auditors. It performs basic checks in these categories:

* TLS/SSL - Versions and cipher suites supported; common issues.
* Information Disclosure - Checks for common information leaks.
* Presence of Files or Directories - Checks for files or directories that could indicate a security issue.
* Common Vulnerabilities
* Missing Security Headers

This is meant to provide a easy way to perform initial analysis and information discovery. It's not a full testing suite, and it certainly isn't Metasploit. The idea is to provide a quick way to perform initial data collection, which can then be used to better target further tests. It is especially useful when used in conjunction with Burp Suite (via the `--proxy` parameter).

## Getting Started

YAWAST is packaged as a Python [package](https://pypi.org/project/yawast/), Docker container, and as a Windows EXE to make installing it as easy as possible. Details are available on the [installation page](/installation/).

#### Windows

The simplest option for Windows users is to [download](https://github.com/adamcaudill/yawast/releases) the compiled executable, as Windows requires certain dependencies to be compile.

#### macOS, Linux, etc.

The simplest options to install are:

As a Python package: `pip3 install yawast` (YAWAST requires Python 3.7)

#### Docker

`docker pull adamcaudill/yawast`

It's strongly recommended that you review the [installation](/installation/) page, to ensure you have the proper dependencies.

## Documentation

Details about YAWAST and how to use it can be found below:

* [Installation](/installation/)
* [Usage & Parameters](/usage/)
* [Scanning TLS/SSL](/tls/)
  * [OpenSSL & 3DES Compatibility](/openssl/)
* [Sample Output](/sample/)
* [FAQ](/faq/)
* [Change Log](https://github.com/adamcaudill/yawast/blob/master/CHANGELOG.md)

## Recent Blog Posts

<ul class="posts">

  {% for post in site.posts %}
    <li><span>{{ post.date | date_to_string }}</span> » <a href="{{ post.url }}" title="{{ post.title }}">{{ post.title }}</a></li>
  {% endfor %}
</ul>
