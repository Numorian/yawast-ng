import argparse
import sys

from yawast.shared import utils
from yawast.commands import scan
from yawast.reporting import reporter


def build_parser():
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        "--debug", action="store_true", help="Displays debug output (very noisy)"
    )
    parent_parser.add_argument(
        "--nocolors", action="store_true", help="Disables the use of colors in output"
    )

    parser = argparse.ArgumentParser(prog="yawast")

    subparsers = parser.add_subparsers()
    subparsers.required = True
    subparsers.dest = "command"

    # create the parser for the "scan" command
    parser_scan = subparsers.add_parser(
        "scan", help="Scans the provided URL(s)", parents=[parent_parser]
    )
    parser_scan.add_argument("--nossl", action="store_true", help="Disables SSL checks")
    parser_scan.add_argument(
        "--nociphers",
        action="store_true",
        help="Disables check for supported ciphers (only with --internalssl)",
    )
    parser_scan.add_argument(
        "--internalssl", action="store_true", help="Disable SSL Labs integration"
    )
    parser_scan.add_argument(
        "--tdessessioncount",
        action="store_true",
        help="Counts the number of messages that can be sent in a single session (SWEET32)",
    )
    parser_scan.add_argument(
        "--dir", action="store_true", help="Enables directory search"
    )
    parser_scan.add_argument(
        "--dirrecursive",
        action="store_true",
        help="Recursive directory search (only with --dir)",
    )
    parser_scan.add_argument(
        "--dirlistredir",
        action="store_true",
        help="Show 301 redirects (only with --dir)",
    )
    parser_scan.add_argument(
        "--files",
        action="store_true",
        help="Performs a search for a large list of common files",
    )
    parser_scan.add_argument(
        "--srv", action="store_true", help="Scan for known SRV DNS Records"
    )
    parser_scan.add_argument(
        "--subdomains", action="store_true", help="Search for Common Subdomains"
    )
    parser_scan.add_argument("--nodns", action="store_true", help="Disable DNS checks")
    parser_scan.add_argument(
        "--proxy", type=str, help="HTTP Proxy Server (such as Burp Suite)"
    )
    parser_scan.add_argument("--cookie", type=str, help="Session cookie")
    parser_scan.add_argument("--output", type=str, help="Output JSON file")
    parser_scan.add_argument(
        "--user",
        type=str,
        help="Valid username for the application (will prompt if not provided)",
    )
    parser_scan.add_argument(
        "--pass_reset_page",
        type=str,
        help="Password reset page URL (will prompt if not provided)",
    )
    parser_scan.set_defaults(func=command_scan)

    return parser


def process_urls(urls):
    # now we need to make we have at least one arg that could be a URL.
    if len(urls) == 0:
        utils.exit_message("YAWAST Error: You must specify at least one URL.")

    # Next, we need to make sure we have something that looks like URLs.
    for val in enumerate(urls):
        if not str(val[1]).startswith("--"):
            if not utils.is_url(val[1]):
                utils.exit_message("YAWAST Error: Invalid URL Specified: '%s" % val[1])
        else:
            print(
                "YAWAST Error: Invalid parameter: '%s' - Ignored." % val[1],
                file=sys.stderr,
            )


def command_scan(args, urls):
    for val in enumerate(urls):
        url = utils.extract_url(val[1])

        reporter.setup(utils.get_domain(url))

        scan.start(args, url)
