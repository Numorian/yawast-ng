---
layout: default
title: Usage & Parameters
permalink: /usage/
---

### Commands & Parameters

yawast-ng uses the following commands to perform different functions:

* `scan` - Performs a full scan, and includes the functionality of the `dns` and `ssl` commands.
* `dns` - Provides information on the target's DNS environment, with options to search for subdomains and SRV records.
* `ssl` - Performs a scan of the target's TLS / SSL configuration, using either SSL Labs or sslyze (bundled).

For detailed information, just enter `yawast-ng -h` to see the help information. To see information for a specific command, use `yawast-ng <command> -h` for full details. 

#### Scan Command

```
usage: yawast-ng scan [-h] [--debug] [--nocolors] [--nowrap] 
                    [--nossl] [--internalssl] [--tdessessioncount] 
                    [--dir] [--dirrecursive] [--dirlistredir] [--files] 
                    [--srv] [--subdomains] [--nodns] [--ports] [--proxy PROXY] 
                    [--cookie COOKIE] [--header HEADER] [--output OUTPUT] 
                    [--user USER] [--pass_reset_page PASS_RESET_PAGE] 
                    [--php_page PHP_PAGE]

options:
  -h, --help            show this help message and exit
  --debug               Displays debug output (very noisy)
  --nocolors            Disables the use of colors in output
  --nowrap              Disables the use of line wrapping in output
  --nossl               Disables SSL checks
  --internalssl         Disable SSL Labs integration
  --tdessessioncount    Counts the number of messages that can be sent in a single session (SWEET32)
  --dir                 Enables directory search
  --dirrecursive        Recursive directory search (only with --dir)
  --dirlistredir        Show 301 redirects (only with --dir)
  --files               Performs a search for a large list of common files
  --srv                 Scan for known SRV DNS Records
  --subdomains          Search for Common Subdomains
  --nodns               Disable DNS checks
  --ports               Scan common TCP ports
  --proxy PROXY         HTTP Proxy Server (such as Burp Suite)
  --cookie COOKIE       Session cookie
  --header HEADER       HTTP header (such as Authorization) sent with each request ('name=value')
  --output OUTPUT       Output JSON file
  --user USER           Valid username for the application (will prompt if not provided)
  --pass_reset_page PASS_RESET_PAGE
                        Password reset page URL (will prompt if not provided)
  --php_page PHP_PAGE   Relative path to PHP script (for additional tests)
```

*A note on parameters and strings:* It's important to remember that the strings that would be passed to yawast-ng may contain special characters that could be interpreted by your shell. In general, the best practice is to pass all string parameters wrapped in single-quotes to avoid this.

### Using with Zap / Burp Suite

By default, Burp Suite's proxy listens on localhost at port 8080. To use yawast-ng with Burp Suite (or any proxy for that matter), just add this to the command line:

`--proxy 'localhost:8080'`

### Authenticated Testing

For authenticated testing, yawast-ng allows you to specify a cookie to be passed via the `--cookie` parameter, or a header (i.e. `Authorization`) via the `--header` parameter.

`--cookie='SESSIONID=1234567890'`

### About the Output

You'll notice that most lines begin with a letter in a bracket; this is to tell you how to interpret the result at a glance. There are four possible values:

* `[Info]` - This indicates that the line is informational, and doesn't necessarily indicate a security issue.
* `[Warn]` - This is a Warning, which means that it could be an issue, or could expose useful information. These need to be evaluated on a case-by-case basis to determine the impact.
* `[Vuln]` - This is a Vulnerability, indicating something that is known to be an issue, and needs to be addressed.
* `[Error]` - This indicates that an error occurred; sometimes these are serious and indicate an issue with your environment, the target server, or the application. In other cases, they may just be informational to let you know that something didn't go as planned.

The indicator used may change over time based on new research or better detection techniques. In all cases, results should be carefully evaluated within the context of the application, how it's used, and what threats apply. The indicator is guidance -- a hint, if you will -- and it's up to you to determine the real impact.

### JSON Output

With the `--output` parameter, yawast-ng will create a JSON file, with information about the scan, each issue found, where the issues were found, each request and response, and reference data. These files are intended to provide comprehensive evidence of the results of the scan.

These files are rather large, so they are compressed as a zip file when they are produced; a fairly simple website can produce an output in the hundreds of thousands of lines. While these files are quite large, they are intended to provide a thorough and complete report of the scan, to allow for further process or a clear record of the evidence.

The file contains the following top-level keys:

- `_info` - General information about yawast-ng, the scan, and output.
- `data` - Information about each URL being scanned, such as DNS and TLS information.
- `issues` - A list of all issues found during the scan.
- `evidence` The evidence captured, such as the HTTP requests and response.
- `vulnerabilities` - List of the vulnerabilities being searched for.

#### The `_info` Key

This is detailed information about yawast-ng, the scan, and information useful for debugging. It contains the following keys:

- `start_time` - Time that the scan began, as a unix timestamp.
- `yawast_version` - Version of yawast-ng being used.
- `python_version` - Information about the version of Python being used.
- `openssl_version` - Version of OpenSSL being used.
- `platform` - Version of the operating system.
- `options` - Command line used to execute the scan.
- `encoding` - Operating system default encoding.
- `messages` - Messages created during the run:
  - `debug` - All debug messages created, may or may not have been displayed.
  - `normal` - Standard console output displayed during the run.
- `peak_memory` - Maximum amount of RAM used during the run.
- (additional memory & related stats)

#### The `data` Key

This includes information from the DNS and TLS checks, and may vary depending on the options selected, in an array of URLs being scanned.

#### The `issues` Key

This includes a list of each issue found, by vulnerability, with the URL the issue was found at, and a reference to the request and response, in an array of URLs being scanned.

#### The `evidence` Key

This is an array of URLs scanned, with a UUID for each request and response during the scan. These correspond to the evidence IDs in the `issues` key.

#### The `vulnerabilities` Key

This is an array of all vulnerabilities being searched for, with basic information about the vulnerability, such as the severity, and can be associated with the data in the `issues` key by name.

### Configuration File (`~/.yawast-ng.json`)

During the startup process, yawast-ng will check for a JSON file called `~/.yawast-ng.json` which contains configuration data that alters how the application runs. This will override default settings, and is intended to allow you to customize the application for your environment. 

The file is a JSON file, and should be formatted as such. The following keys are available:

- `user_agent` - The user agent string to be used for all requests to the target(s). This is useful for testing, and can be set to a specific value. If missing, yawast-ng will use the default value.
