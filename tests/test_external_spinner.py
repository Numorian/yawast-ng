import sys
import threading
import time
from unittest import mock

import pytest

from yawast.external.spinner import Spinner


def test_spinning_cursor():
    gen = Spinner.spinning_cursor()
    vals = [next(gen) for _ in range(8)]
    assert vals == ["|", "/", "-", "\\", "|", "/", "-", "\\"]


def test_spinner_start_stop(monkeypatch):
    s = Spinner(delay=0.01)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "write", lambda x: None)
    monkeypatch.setattr(sys.stdout, "flush", lambda: None)
    monkeypatch.setattr(time, "sleep", lambda x: None)
    # Patch spinner_task to exit quickly
    orig_task = s.spinner_task

    def fast_task():
        s.busy = False
        s.running = False

    s.spinner_task = fast_task
    s.start()
    s.stop()
    s.spinner_task = orig_task


def test_spinner_context_manager(monkeypatch):
    s = Spinner(delay=0.01)
    monkeypatch.setattr(s, "start", lambda: None)
    monkeypatch.setattr(s, "stop", lambda exc=None: None)
    with s as ctx:
        assert ctx is s


def test_spinner_stop_with_exception(monkeypatch):
    s = Spinner(delay=0.01)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "write", lambda x: None)
    monkeypatch.setattr(sys.stdout, "flush", lambda: None)
    monkeypatch.setattr(time, "sleep", lambda x: None)
    s.running = False
    s.busy = False
    assert s.stop(Exception("fail")) is False


def test_spinner_task_handles_exception(monkeypatch):
    s = Spinner(delay=0.01)
    s.busy = True
    s.running = True
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "flush", lambda: None)
    monkeypatch.setattr(time, "sleep", lambda x: None)
    # Should not raise
    with mock.patch.object(sys.stdout, "write", side_effect=Exception("fail")):
        s.busy = False
        s.spinner_task()
