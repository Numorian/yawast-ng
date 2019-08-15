---
layout: default
title: Usage & Parameters
permalink: /usage/
---

### Commands & Parameters

YAWAST uses the following commands to perform different functions:

* `scan` - Performs a full scan, and includes the functionality of the `dns` and `ssl` commands.
* `dns` - Provides information on the target's DNS environment, with options to search for subdomains and SRV records.
* `ssl` - Performs a scan of the target's TLS / SSL configuration, using either SSL Labs or sslyze (bundled).

For detailed information, just enter `yawast -h` to see the help information. To see information for a specific command, use `yawast <command> -h` for full details. 

#### Scan Command

```
usage: yawast scan [-h] [--debug] [--nocolors] [--nowrap] [--proxy PROXY]
                   [--cookie COOKIE] [--nossl] [--internalssl]
                   [--tdessessioncount] [--dir] [--dirrecursive]
                   [--dirlistredir] [--files] [--srv] [--subdomains] [--nodns]
                   [--output OUTPUT] [--user USER]
                   [--pass_reset_page PASS_RESET_PAGE]

optional arguments:
  -h, --help            show this help message and exit
  --debug               Displays debug output (very noisy)
  --nocolors            Disables the use of colors in output
  --nowrap              Disables the use of line wrapping in output
  --proxy PROXY         HTTP Proxy Server (such as Burp Suite)
  --cookie COOKIE       Session cookie
  --nossl               Disables SSL checks
  --internalssl         Disable SSL Labs integration
  --tdessessioncount    Counts the number of messages that can be sent in a
                        single session (SWEET32)
  --dir                 Enables directory search
  --dirrecursive        Recursive directory search (only with --dir)
  --dirlistredir        Show 301 redirects (only with --dir)
  --files               Performs a search for a large list of common files
  --srv                 Scan for known SRV DNS Records
  --subdomains          Search for Common Subdomains
  --nodns               Disable DNS checks
  --output OUTPUT       Output JSON file
  --user USER           Valid username for the application (will prompt if not
                        provided)
  --pass_reset_page PASS_RESET_PAGE
                        Password reset page URL (will prompt if not provided)
```

*A note on parameters and strings:* It's important to remember that the strings that would be passed to YAWAST may contain special characters that could be interpreted by your shell. In general, the best practice is to pass all string parameters wrapped in single-quotes to avoid this.

### Using with Zap / Burp Suite

By default, Burp Suite's proxy listens on localhost at port 8080. To use YAWAST with Burp Suite (or any proxy for that matter), just add this to the command line:

`--proxy 'localhost:8080'`

### Authenticated Testing

For authenticated testing, YAWAST allows you to specify a cookie to be passed via the `--cookie` parameter.

`--cookie='SESSIONID=1234567890'`

### About the Output

You'll notice that most lines begin with a letter in a bracket; this is to tell you how to interpret the result at a glance. There are four possible values:

* `[Info]` - This indicates that the line is informational, and doesn't necessarily indicate a security issue.
* `[Warn]` - This is a Warning, which means that it could be an issue, or could expose useful information. These need to be evaluated on a case-by-case basis to determine the impact.
* `[Vuln]` - This is a Vulnerability, indicating something that is known to be an issue, and needs to be addressed.
* `[Error]` - This indicates that an error occurred; sometimes these are serious and indicate an issue with your environment, the target server, or the application. In other cases, they may just be informational to let you know that something didn't go as planned.

The indicator used may change over time based on new research or better detection techniques. In all cases, results should be carefully evaluated within the context of the application, how it's used, and what threats apply. The indicator is guidance -- a hint, if you will -- and it's up to you to determine the real impact.
