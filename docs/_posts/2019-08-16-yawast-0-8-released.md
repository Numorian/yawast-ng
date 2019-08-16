---
layout: post
title:  "YAWAST 0.8 Released"
date:   2019-08-16 12:52:00 -0400
author: 'Brandon Wilson'
---

YAWAST version 0.8 has been released; months of work has gone into this release and has required a substantial investment of time and effort. The new version of YAWAST is a complete re-write of the application – everything has been rebuilt. This version includes a number of improvements and quite a few new checks. Here is a brief overview of the changes:

* YAWAST requires Python 3.7 – The prior version of YAWAST was written in Ruby, the new version is written in Python. This opens the doors to new integrations, and we hope will encourage more community involvement.
* YAWAST now integrates SSLyze instead of using a custom internal TLS scanner.
* YAWAST now performs a full spider of the site, and checks for a variety of issues on all pages, not just the first page.
* Vulnerability checks have been expanded and are applied in a more thorough manner. This increases the number of useful findings greatly.
* Want to know what YAWAST is busy doing? Just press “d” and it will enable debug mode, printing out detailed information about what’s going on. When you’re done, just press “d” again, and the debug output will stop.
* Checks have been added for missing Cache Control headers, insecure links, external JavaScript files, vulnerable JavaScript files (via RetireJS data).
* The interface has been updated to make it easier to read and take better advantage of the features your terminal offers.
* SWEET32 test no longer relies on the local OpenSSL installation, and will work on any system. There’s no need to use an old VM or Docker just to make that check work.
* Port scanner (1,000 most common ports).
* Windows users can now download a compiled EXE, instead of needing to install Python and build various dependencies.
* ...many others

Command line parameters are still the same, most of the language is still the same – in general, this is a better YAWAST, but doesn’t break your expectations.

Installation information: https://yawast.org/installation/ (Note: If you are using the Docker image, you already have the latest version – you don’t need to do anything)

Sample output: https://yawast.org/sample/ 

List of checks performed: https://yawast.org/checks/ 

If you have any issues, please open a ticket on Github (https://github.com/adamcaudill/yawast/issues) (with all sensitive information redacted of course).

It’s recommended that YAWAST be used on all web application / web service penetration tests, to ensure that certain things are checked for, and to save you time by eliminating some manual tasks. Please make sure you upgrade to 0.8 – we will no longer be working on the older Ruby version.
