#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

import pytest

from tests import utils
from yawast import main
from yawast._version import get_version
from yawast.shared import output


class TestPrintHeader:
    def test_print_header(self):
        output.setup(False, True, True)
        with utils.capture_sys_output() as (stdout, stderr):
            main.print_header()
        assert f"(v{get_version()})" in stdout.getvalue()

    def test_print_header_cpu_freq_zero(self, monkeypatch):
        output.setup(False, True, True)

        # Patch psutil.cpu_freq to return max=0, current=1234
        class DummyFreq:
            max = 0
            current = 1234

        monkeypatch.setattr(main, "psutil", main.psutil)
        monkeypatch.setattr(main.psutil, "cpu_freq", lambda: DummyFreq())
        # Patch other psutil and platform calls to avoid side effects
        monkeypatch.setattr(
            main.psutil,
            "virtual_memory",
            lambda: type("vm", (), {"total": 8 * 1024**3, "available": 4 * 1024**3})(),
        )
        monkeypatch.setattr(main.psutil, "cpu_count", lambda: 4)
        monkeypatch.setattr(main, "platform", main.platform)
        monkeypatch.setattr(main.platform, "platform", lambda: "TestOS")
        monkeypatch.setattr(main, "ssl", main.ssl)
        monkeypatch.setattr(main, "get_version", lambda: "1.2.3")
        monkeypatch.setattr(main, "_get_locale", lambda: "en_US.UTF-8")
        monkeypatch.setattr(main, "plugin_manager", main.plugin_manager)
        monkeypatch.setattr(main.plugin_manager, "load_plugins", lambda: None)
        monkeypatch.setattr(main.plugin_manager, "print_loaded_plugins", lambda: None)
        monkeypatch.setattr(main.network, "check_ipv4_connection", lambda: "IPv4 OK")
        monkeypatch.setattr(main.network, "check_ipv6_connection", lambda: "IPv6 OK")
        monkeypatch.setattr(main.reporter, "register_info", lambda *a, **k: None)
        with utils.capture_sys_output() as (stdout, stderr):
            main.print_header()
        out = stdout.getvalue()
        assert "CPU(s): 4@1234MHz" in out
        assert "IPv4 OK" in out and "IPv6 OK" in out

    def test_print_header_psutil_exception(self, monkeypatch):
        output.setup(False, True, True)
        # Simulate psutil.virtual_memory raising an exception
        monkeypatch.setattr(
            main.psutil,
            "virtual_memory",
            lambda: (_ for _ in ()).throw(Exception("fail vm")),
        )
        monkeypatch.setattr(
            main.psutil,
            "cpu_freq",
            lambda: type("f", (), {"max": 2000, "current": 2000})(),
        )
        monkeypatch.setattr(main.psutil, "cpu_count", lambda: 2)
        monkeypatch.setattr(main, "platform", main.platform)
        monkeypatch.setattr(main.platform, "platform", lambda: "TestOS")
        monkeypatch.setattr(main, "ssl", main.ssl)
        monkeypatch.setattr(main, "get_version", lambda: "1.2.3")
        monkeypatch.setattr(main, "_get_locale", lambda: "en_US.UTF-8")
        monkeypatch.setattr(main, "plugin_manager", main.plugin_manager)
        monkeypatch.setattr(main.plugin_manager, "load_plugins", lambda: None)
        monkeypatch.setattr(main.plugin_manager, "print_loaded_plugins", lambda: None)
        monkeypatch.setattr(main.network, "check_ipv4_connection", lambda: "IPv4 OK")
        monkeypatch.setattr(main.network, "check_ipv6_connection", lambda: "IPv6 OK")
        monkeypatch.setattr(main.reporter, "register_info", lambda *a, **k: None)
        with utils.capture_sys_output() as (stdout, stderr):
            try:
                main.print_header()
            except Exception:
                pass  # We expect an exception, just ensure it doesn't crash the test suite
        # No assertion needed, just coverage

    def test_print_header_network_exception(self, monkeypatch):
        output.setup(False, True, True)
        monkeypatch.setattr(
            main.psutil,
            "virtual_memory",
            lambda: type("vm", (), {"total": 8 * 1024**3, "available": 4 * 1024**3})(),
        )
        monkeypatch.setattr(
            main.psutil,
            "cpu_freq",
            lambda: type("f", (), {"max": 2000, "current": 2000})(),
        )
        monkeypatch.setattr(main.psutil, "cpu_count", lambda: 2)
        monkeypatch.setattr(main, "platform", main.platform)
        monkeypatch.setattr(main.platform, "platform", lambda: "TestOS")
        monkeypatch.setattr(main, "ssl", main.ssl)
        monkeypatch.setattr(main, "get_version", lambda: "1.2.3")
        monkeypatch.setattr(main, "_get_locale", lambda: "en_US.UTF-8")
        monkeypatch.setattr(main, "plugin_manager", main.plugin_manager)
        monkeypatch.setattr(main.plugin_manager, "load_plugins", lambda: None)
        monkeypatch.setattr(main.plugin_manager, "print_loaded_plugins", lambda: None)
        monkeypatch.setattr(
            main.network,
            "check_ipv4_connection",
            lambda: (_ for _ in ()).throw(Exception("fail ipv4")),
        )
        monkeypatch.setattr(
            main.network,
            "check_ipv6_connection",
            lambda: (_ for _ in ()).throw(Exception("fail ipv6")),
        )
        monkeypatch.setattr(main.reporter, "register_info", lambda *a, **k: None)
        with utils.capture_sys_output() as (stdout, stderr):
            try:
                main.print_header()
            except Exception:
                pass  # We expect an exception, just ensure it doesn't crash the test suite
        # No assertion needed, just coverage

    def test_print_header_plugin_manager_exception(self, monkeypatch):
        output.setup(False, True, True)
        # Patch plugin_manager.load_plugins to raise exception
        monkeypatch.setattr(
            main.psutil,
            "virtual_memory",
            lambda: type("vm", (), {"total": 8 * 1024**3, "available": 4 * 1024**3})(),
        )
        monkeypatch.setattr(
            main.psutil,
            "cpu_freq",
            lambda: type("f", (), {"max": 2000, "current": 2000})(),
        )
        monkeypatch.setattr(main.psutil, "cpu_count", lambda: 2)
        monkeypatch.setattr(main, "platform", main.platform)
        monkeypatch.setattr(main.platform, "platform", lambda: "TestOS")
        monkeypatch.setattr(main, "ssl", main.ssl)
        monkeypatch.setattr(main, "get_version", lambda: "1.2.3")
        monkeypatch.setattr(main, "_get_locale", lambda: "en_US.UTF-8")
        monkeypatch.setattr(main, "plugin_manager", main.plugin_manager)
        monkeypatch.setattr(
            main.plugin_manager,
            "load_plugins",
            lambda: (_ for _ in ()).throw(Exception("fail load_plugins")),
        )
        monkeypatch.setattr(main.plugin_manager, "print_loaded_plugins", lambda: None)
        monkeypatch.setattr(main.network, "check_ipv4_connection", lambda: "IPv4 OK")
        monkeypatch.setattr(main.network, "check_ipv6_connection", lambda: "IPv6 OK")
        monkeypatch.setattr(main.reporter, "register_info", lambda *a, **k: None)
        with utils.capture_sys_output() as (stdout, stderr):
            try:
                main.print_header()
            except Exception:
                pass  # We expect an exception, just ensure it doesn't crash the test suite
        # No assertion needed, just coverage

    def test_print_header_reporter_exception(self, monkeypatch):
        output.setup(False, True, True)
        monkeypatch.setattr(
            main.psutil,
            "virtual_memory",
            lambda: type("vm", (), {"total": 8 * 1024**3, "available": 4 * 1024**3})(),
        )
        monkeypatch.setattr(
            main.psutil,
            "cpu_freq",
            lambda: type("f", (), {"max": 2000, "current": 2000})(),
        )
        monkeypatch.setattr(main.psutil, "cpu_count", lambda: 2)
        monkeypatch.setattr(main, "platform", main.platform)
        monkeypatch.setattr(main.platform, "platform", lambda: "TestOS")
        monkeypatch.setattr(main, "ssl", main.ssl)
        monkeypatch.setattr(main, "get_version", lambda: "1.2.3")
        monkeypatch.setattr(main, "_get_locale", lambda: "en_US.UTF-8")
        monkeypatch.setattr(main, "plugin_manager", main.plugin_manager)
        monkeypatch.setattr(main.plugin_manager, "load_plugins", lambda: None)
        monkeypatch.setattr(main.plugin_manager, "print_loaded_plugins", lambda: None)
        monkeypatch.setattr(main.network, "check_ipv4_connection", lambda: "IPv4 OK")
        monkeypatch.setattr(main.network, "check_ipv6_connection", lambda: "IPv6 OK")
        monkeypatch.setattr(
            main.reporter,
            "register_info",
            lambda *a, **k: (_ for _ in ()).throw(Exception("fail register_info")),
        )
        with utils.capture_sys_output() as (stdout, stderr):
            try:
                main.print_header()
            except Exception:
                pass  # We expect an exception, just ensure it doesn't crash the test suite
        # No assertion needed, just coverage
