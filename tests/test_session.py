from argparse import Namespace
from unittest import mock

import pytest

from yawast.scanner.session import Session


def test_session_init_and_update(monkeypatch):
    monkeypatch.setattr("yawast.shared.utils.get_domain", lambda netloc: netloc)
    args = Namespace()
    url = "https://example.com/path"
    s = Session(args, url)
    assert s.url == url
    assert s.url_parsed.scheme == "https"
    assert s.domain == "example.com"
    # update_scheme
    s.update_scheme("http")
    assert s.url.startswith("http://")
    # update_url
    s.update_url("https://other.com/foo")
    assert s.url == "https://other.com/foo"
    assert s.domain == "other.com"
    # get_http_url
    http_url = s.get_http_url()
    assert http_url.startswith("http://")
    assert "/foo" in http_url
