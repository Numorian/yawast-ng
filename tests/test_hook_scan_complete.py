from unittest import mock

import pytest

import yawast.scanner.plugins.plugin_manager as plugin_manager
from yawast.scanner.session import Session


class DummyHook(plugin_manager.HookScannerBase):
    called = False

    def __init__(self):
        super().__init__()

    def scan_complete(self, session):
        DummyHook.called = True


class DummyHookError(plugin_manager.HookScannerBase):
    def scan_complete(self, session):
        raise Exception("fail")


def test_run_hook_scan_complete_calls_scan_complete(monkeypatch):
    DummyHook.called = False
    plugin_manager.plugins["hook"] = {"dummy": DummyHook}
    session = mock.Mock(spec=Session)
    plugin_manager.run_hook_scan_complete(session)
    assert DummyHook.called is True


def test_run_hook_scan_complete_handles_exception(monkeypatch):
    plugin_manager.plugins["hook"] = {"error": DummyHookError}
    session = mock.Mock(spec=Session)
    errors = []
    monkeypatch.setattr(plugin_manager.output, "error", lambda x: errors.append(x))
    plugin_manager.run_hook_scan_complete(session)
    assert any("Failed to run plugin error" in e for e in errors)
