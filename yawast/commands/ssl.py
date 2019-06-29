import socket

from yawast.commands import utils as cutils
from yawast.scanner.cli import ssl_internal, ssl_sweet32, ssl_labs
from yawast.scanner.session import Session
from yawast.shared import utils, output


def start(session: Session):
    print(f"Scanning: {session.url}")

    # make sure it resolves
    try:
        socket.gethostbyname(session.domain)
    except socket.gaierror as error:
        print(f"Fatal Error: Unable to resolve {session.domain} ({str(error)})")

        return

    try:
        cutils.check_redirect(session)
    except ValueError as error:
        print(f"Unable to continue: {str(error)}")

        return

    # check to see if we are looking at an HTTPS server
    if session.url_parsed.scheme == "https":
        if (
            session.args.internalssl
            or utils.is_ip(session.domain)
            or utils.get_port(session.url) != 443
        ):
            # use internal scanner
            ssl_internal.scan(session)
        else:
            try:
                ssl_labs.scan(session)
            except Exception as error:
                output.debug_exception()

                output.error(f"Error running scan with SSL Labs: {str(error)}")

        if session.args.tdessessioncount:
            ssl_sweet32.scan(session)
