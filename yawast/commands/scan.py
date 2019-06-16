import socket

from yawast.shared import network, utils, output
from yawast.scanner.cli import dns, ssl_labs, ssl_internal, ssl_sweet32, http
from urllib.parse import urlparse, urlunparse


def start(args, url):
    print(f"Scanning: {url}")

    # parse the URL, we'll need this
    parsed = urlparse(url)
    # get rid of any port number & credentials that may exist
    domain = utils.get_domain(parsed.netloc)

    # make sure it resolves
    try:
        socket.gethostbyname(domain)
    except socket.gaierror as error:
        print(f"Fatal Error: Unable to resolve {domain} ({str(error)})")

        return

    # perform some connection testing
    if parsed.scheme == "http":
        try:
            # check for TLS redirect
            tls_redirect = network.check_ssl_redirect(url)
            if tls_redirect != url:
                print(f"Server redirects to TLS: Scanning: {tls_redirect}")

                url = tls_redirect
                parsed = urlparse(url)
        except Exception:
            output.debug_exception()

            # we tried to connect to port 80, and it failed
            # this could mean a couple things, first, we need to
            #  see if it answers to 443
            parsed = parsed._replace(scheme="https")
            url = urlunparse(parsed)

            print("Server does not respond to HTTP, switching to HTTPS")
            print()
            print(f"Scanning: {url}")

            # grab the head, to see if we get anything
            try:
                network.http_head(url, timeout=5)

                print()
            except Exception as err:
                output.debug_exception()

                print(f"Fatal Error: Can not connect to {url} ({str(err)})")
                return
    else:
        # if we are scanning HTTPS, try HTTP to see what it does
        try:
            http_parsed = parsed._replace(scheme="http")
            http_url = urlunparse(http_parsed)

            network.http_head(http_url, timeout=5)

            print("Server responds to HTTP requests")
            print()
        except Exception:
            output.debug_exception()

            print("Server does not respond to HTTP requests")
            print()

    # check for www redirect
    www_redirect = network.check_www_redirect(url)
    if www_redirect is not None and www_redirect != url:
        print(f"Server performs WWW redirect: Scanning: {www_redirect}")
        url = www_redirect

    if not args.nodns:
        dns.scan(args, url, domain)

    # check to see if we are looking at an HTTPS server
    if parsed.scheme == "https" and not args.nossl:
        if args.internalssl or utils.is_ip(domain) or utils.get_port(url) != 443:
            # use internal scanner
            ssl_internal.scan(args, url, domain)
        else:
            try:
                ssl_labs.scan(args, url, domain)
            except Exception as error:
                output.debug_exception()

                output.error(f"Error running scan with SSL Labs: {str(error)}")

        if args.tdessessioncount:
            ssl_sweet32.scan(args, url, domain)

    http.scan(args, url, domain)

    # reset any stored data
    http.reset()

    return
