---
layout: default
title: OpenSSL & 3DES Compatibility
permalink: /openssl/
---

This page contains notes and important information about testing for SWEET32, 3DES, and OpenSSL compatibility.

### Versions 0.8 & up

YAWAST, starting with 0.8, uses an embedded copy of sslyze and leverages it for access to a compiled version of OpenSSL that supports 3DES cipher suites. This is done to make it easy to maintain, and easy for users. This eliminates the majority of issues that users have experienced.

### Versions 0.7 & below

The SWEET32 test relies on being able to send requests using a 3DES cipher suite, which when OpenSSL is compiled without 3DES support, this test fails. As most modern releases of OpenSSL have this cipher suite disabled at build time, this creates a problem for this test.

At the moment, the easiest work around for this issue is to use the [docker container](https://github.com/adamcaudill/yawast/wiki/Installation#docker) which includes a version of OpenSSL that's properly configured.
