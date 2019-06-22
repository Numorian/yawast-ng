import socket
from urllib.parse import urlparse

from yawast.scanner.cli import dns
from yawast.shared import utils


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

    dns.scan(args, url, domain)
