from unittest import mock

import pytest
from dns import exception, resolver

from yawast.scanner.modules.dns import basic


def _patch_debug(monkeypatch):
    dbg = mock.Mock()
    monkeypatch.setattr(basic.output, "debug_exception", dbg)
    return dbg


def test_get_ips_debug_exceptions(monkeypatch):
    dbg = _patch_debug(monkeypatch)
    for exc in [resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA]:
        monkeypatch.setattr(basic.resolver, "resolve", mock.Mock(side_effect=exc()))
        assert basic.get_ips("example.com") == []
        assert dbg.called
        dbg.reset_mock()


def test_get_text_debug_exceptions(monkeypatch):
    dbg = _patch_debug(monkeypatch)
    for exc in [resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA]:
        monkeypatch.setattr(basic.resolver, "resolve", mock.Mock(side_effect=exc()))
        assert basic.get_text("example.com") == []
        assert dbg.called
        dbg.reset_mock()


def test_get_mx_debug_exceptions(monkeypatch):
    dbg = _patch_debug(monkeypatch)
    for exc in [resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA]:
        monkeypatch.setattr(basic.resolver, "resolve", mock.Mock(side_effect=exc()))
        assert basic.get_mx("example.com") == []
        assert dbg.called
        dbg.reset_mock()


def test_get_ns_debug_exceptions(monkeypatch):
    dbg = _patch_debug(monkeypatch)
    for exc in [resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA]:
        monkeypatch.setattr(basic.resolver, "resolve", mock.Mock(side_effect=exc()))
        assert basic.get_ns("example.com") == []
        assert dbg.called
        dbg.reset_mock()


def test_get_host_debug_exceptions(monkeypatch):
    dbg = _patch_debug(monkeypatch)
    for exc in [resolver.NoNameservers, resolver.NotAbsolute, resolver.NoRootSOA]:
        monkeypatch.setattr(basic.reversename, "from_address", lambda ip: "rev")
        monkeypatch.setattr(basic.resolver, "resolve", mock.Mock(side_effect=exc()))
        assert basic.get_host("1.2.3.4") == "N/A"
        assert dbg.called
        dbg.reset_mock()
