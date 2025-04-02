# Inspired by: http://web.archive.org/web/20111025070757/http://pythonwise.blogspot.com/2010/02/parse-http-response.html

from io import BytesIO
from socket import socket
from http.client import HTTPResponse
from ssl import SSLSocket
from typing import Union


class FakeSocket(BytesIO):
    """
    A fake socket object that reads from a BytesIO buffer.
    """

    def makefile(self, *args, **kw):  # type: ignore
        return self


class HttpResponseParser:
    @classmethod
    def parse_from_socket(cls, sock: Union[SSLSocket, socket]) -> HTTPResponse:
        """
        Create an HTTP response from a socket.
        @param sock:
        @return:
        """
        response = sock.recv(4096)
        while b"HTTP/" not in response or b"\r\n\r\n" not in response:
            response += sock.recv(4096)

        fake_sock = FakeSocket(response)
        response = HTTPResponse(fake_sock)  # type: ignore
        response.begin()

        return response
