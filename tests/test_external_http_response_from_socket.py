from unittest import mock

import pytest

from yawast.external.http_response_from_socket import FakeSocket, HttpResponseParser


class DummySocket:
    def __init__(self, responses):
        self._responses = responses
        self._idx = 0

    def recv(self, bufsize):
        if self._idx < len(self._responses):
            r = self._responses[self._idx]
            self._idx += 1
            return r
        return b""


def test_fake_socket_makefile():
    fs = FakeSocket(b"abc")
    assert fs.makefile() is fs


def test_parse_from_socket_complete():
    # Simulate a socket that returns a complete HTTP response in one go
    http_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    sock = DummySocket([http_resp])
    resp = HttpResponseParser.parse_from_socket(sock)
    assert resp.status == 200
    assert resp.read() == b"OK"


def test_parse_from_socket_partial():
    # Simulate a socket that returns the response in two parts
    part1 = b"HTTP/1.1 200 OK\r\nContent-Length: 2"
    part2 = b"\r\n\r\nOK"
    sock = DummySocket([part1, part2])
    resp = HttpResponseParser.parse_from_socket(sock)
    assert resp.status == 200
    assert resp.read() == b"OK"
