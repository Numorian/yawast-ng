#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

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
        output.debug_exception()
        output.error(f"Fatal Error: Unable to resolve {session.domain} ({str(error)})")

        return

    try:
        cutils.check_redirect(session)
    except Exception as error:
        output.debug_exception()
        output.error(f"Unable to continue: {str(error)}")

        return

    # check to see if we are looking at an HTTPS server
    if session.url_parsed.scheme == "https":
        if (
            session.args.internalssl
            or utils.is_ip(session.domain)
            or utils.get_port(session.url) != 443
        ):
            # use SSLyze
            try:
                ssl_internal.scan(session)
            except Exception as error:
                output.error(f"Error running scan with SSLyze: {str(error)}")
        else:
            try:
                ssl_labs.scan(session)
            except Exception as error:
                output.debug_exception()

                output.error(f"Error running scan with SSL Labs: {str(error)}")
                output.norm("Switching to internal SSL scanner...")

                try:
                    ssl_internal.scan(session)
                except Exception as error:
                    output.error(f"Error running scan with SSLyze: {str(error)}")

        if session.args.tdessessioncount:
            ssl_sweet32.scan(session)
