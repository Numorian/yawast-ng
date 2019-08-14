#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

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
