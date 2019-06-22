import socket
from urllib.parse import urlparse

from yawast.scanner.cli import ssl_internal, ssl_sweet32, ssl_labs
from yawast.shared import utils, network, output


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

    if parsed.scheme == "http":
        try:
            # check for TLS redirect
            tls_redirect = network.check_ssl_redirect(url)
            if tls_redirect != url:
                print(f"Server redirects to TLS: Scanning: {tls_redirect}")

                url = tls_redirect
                parsed = urlparse(url)
        except Exception as error:
            output.debug_exception()
            output.error(f"Failed to connect to {url} ({str(error)})")

            return

    www_redirect = network.check_www_redirect(url)
    if www_redirect is not None and www_redirect != url:
        print(f"Server performs WWW redirect: Scanning: {www_redirect}")
        url = www_redirect
        parsed = urlparse(url)

    # check to see if we are looking at an HTTPS server
    if parsed.scheme == "https":
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
