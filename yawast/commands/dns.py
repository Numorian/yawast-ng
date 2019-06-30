import socket

from yawast.scanner.cli import dns
from yawast.scanner.session import Session


def start(session: Session):
    print(f"Scanning: {session.url}")

    # make sure it resolves
    try:
        socket.gethostbyname(session.domain)
    except socket.gaierror as error:
        print(f"Fatal Error: Unable to resolve {session.domain} ({str(error)})")

        return

    dns.scan(session)
