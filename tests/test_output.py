import sys
import types
from unittest import mock

import pytest

from yawast.shared import output


def test_setup_and_toggle_debug(monkeypatch):
    monkeypatch.setattr(output, "_LogHandler", lambda: mock.Mock())
    monkeypatch.setattr(output, "init", lambda: None)
    mock_logger = mock.Mock()
    mock_logger.handlers = []
    monkeypatch.setattr(output, "get_logger", lambda: mock_logger)
    monkeypatch.setattr(
        output,
        "shutil",
        mock.Mock(get_terminal_size=lambda: types.SimpleNamespace(columns=80)),
    )
    output._init = False
    output._debug = False
    output.setup(True, False, False)
    assert output.is_debug() is True
    output.toggle_debug()
    assert output.is_debug() is False


def test_norm_info_warn_vuln_error(monkeypatch, capsys):
    monkeypatch.setattr(output, "_print", lambda x: print(x))
    output.norm("normal")
    output.info("info")
    output.warn("warn")
    output.vuln("vuln")
    output.error("error")
    out = capsys.readouterr().out
    assert "normal" in out
    assert "info" in out
    assert "warn" in out
    assert "vuln" in out
    assert "error" in out


def test_print_color(monkeypatch, capsys):
    monkeypatch.setattr(output, "_no_colors", False)
    output.print_color("\x1b[31m", "colored")
    out = capsys.readouterr().out
    assert "colored" in out
    monkeypatch.setattr(output, "_no_colors", True)
    output.print_color("\x1b[31m", "plain")
    out = capsys.readouterr().out
    assert "plain" in out


def test_debug_and_debug_exception(monkeypatch):
    output._init = True
    output._logger = mock.Mock()
    monkeypatch.setattr(
        output, "stack", lambda: [types.SimpleNamespace(function="func")] * 2
    )
    output.debug("msg")
    try:
        raise ValueError("fail")
    except Exception:
        output.debug_exception()
    assert output._logger.debug.called


def test__print_special(monkeypatch, capsys):
    monkeypatch.setattr(output, "_print", lambda x: print(x))
    output._no_colors = False
    output._print_special("\x1b[32m", "Header", "special")
    output._no_colors = True
    output._print_special("\x1b[32m", "Header", "plain")
    out = capsys.readouterr().out
    assert "special" in out
    assert "plain" in out


def test__print(monkeypatch, capsys):
    monkeypatch.setattr(output.reporter, "register_message", lambda msg, kind: None)
    monkeypatch.setattr(output.utils, "strip_ansi_str", lambda x: x)
    output._wrapper = None
    output._no_wrap = True
    output._debug = True
    output._lock = mock.Mock(__enter__=lambda s: None, __exit__=lambda s, e, v, t: None)
    output._print("[Debug] debug message")
    output._print("normal message")
    out = capsys.readouterr().out
    assert "debug message" in out
    assert "normal message" in out


def test_empty(capsys):
    output.empty()
    out = capsys.readouterr().out
    assert out.strip() == ""


class DummyRecord:
    def __init__(self, msg):
        self.msg = msg

    def getMessage(self):
        return self.msg


class DummyLogHandler(output._LogHandler):
    def emit(self, record):
        output._internal_debug(record.getMessage())


def test_log_handler_emit(monkeypatch):
    handler = DummyLogHandler()
    record = DummyRecord("logmsg")
    monkeypatch.setattr(output, "_internal_debug", lambda msg: None)
    handler.emit(record)
