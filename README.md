##YAWAST

Yet Another Web Application Security Tester

*Don't expect anything here to work yet - way too early.* This should be considered pre-alpha, don't expect things to work correctly or results to be comprehensive. It'll take time before this is a useful tool, it's not there yet.

####Why?

Because.

This is meant to provide a easy way to perform initial analysis and information discovery. It won't provide a full suite of testing tools, as there are better ways to do that - but it will provide basic information to help target further testing.

####Tests

The following tests are performed:

* *(Generic)* Info Disclosure: X-Powered-By header present
* *(Apache)* Info Disclosure: Module listing enabled
* *(Apache)* Info Disclosure: Server version
* *(Apache)* Info Disclosure: OpenSSL module version
* *(Apache)* Presence of /server-status
* *(Apache)* Presence of /server-info
* *(IIS)* Info Disclosure: Server version
* *(IIS)* Info Disclosure: ASP.NET version
* *(PHP)* Info Disclosure: PHP version

In addition to these test, certain basic information is also displayed, such as IPs (and the PTR record for each IP), HTTP HEAD request, and others.

####Usage

YAWAST is meant to be extremely easy to use; thus it currently has a single parameter: the URL.

`./yawast.rb <url>`

####License

Copyright (c) 2013, Adam Caudill (adam@adamcaudill.com)

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
