from yawast.scanner.session import Session
from yawast.shared import network, output


def check_redirect(session: Session):
    # perform some connection testing
    if session.url_parsed.scheme == "http":
        session.supports_http = True

        try:
            # check for TLS redirect
            tls_redirect = network.check_ssl_redirect(session.url)
            if tls_redirect != session.url:
                print(f"Server redirects to TLS: Scanning: {tls_redirect}")

                session.update_url(tls_redirect)
                session.redirects_https = True
        except Exception:
            output.debug_exception()

            # we tried to connect to port 80, and it failed
            # this could mean a couple things, first, we need to
            #  see if it answers to 443
            session.update_scheme("https")

            print("Server does not respond to HTTP, switching to HTTPS")
            print()
            print(f"Scanning: {session.url}")

            # grab the head, to see if we get anything
            try:
                network.http_head(session.url, timeout=5)

                session.supports_https = True
                session.supports_http = False

                print()
            except Exception as err:
                output.debug_exception()

                raise ValueError(
                    f"Fatal Error: Can not connect to {session.url} ({str(err)})"
                )
    else:
        session.supports_https = True

        # if we are scanning HTTPS, try HTTP to see what it does
        try:
            network.http_head(session.get_http_url(), timeout=5)
            session.supports_http = True

            print("Server responds to HTTP requests")
            print()
        except Exception:
            output.debug_exception()

            print("Server does not respond to HTTP requests")
            print()

    # check for www redirect
    www_redirect = network.check_www_redirect(session.url)
    if www_redirect is not None and www_redirect != session.url:
        print(f"Server performs WWW redirect: Scanning: {www_redirect}")
        session.update_url(www_redirect)
