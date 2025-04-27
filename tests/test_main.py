import sys
import types
from unittest import mock

import pytest

import yawast.main as main_mod


def test_get_locale_success(monkeypatch):
    monkeypatch.setattr("locale.setlocale", lambda *a, **k: None)
    monkeypatch.setattr("locale.getlocale", lambda: ("en_US", "utf8"))
    monkeypatch.setattr("locale.getdefaultlocale", lambda: ("en_US", "utf8"))
    assert main_mod._get_locale() == "en_US.utf8"


def test_get_locale_fallback(monkeypatch):
    with mock.patch(
        "locale.setlocale", side_effect=[Exception("fail"), None]
    ), mock.patch(
        "locale.getlocale", side_effect=[(None, None), (None, None)]
    ), mock.patch(
        "locale.getdefaultlocale", side_effect=[Exception("fail"), ("en_US", "utf8")]
    ), mock.patch(
        "platform.system", return_value="Darwin"
    ):
        result = main_mod._get_locale()
        assert result in ("en_US.utf8", "(Unknown locale)", "None.None")


def test_get_locale_unknown(monkeypatch):
    with mock.patch("locale.setlocale", side_effect=Exception("fail")), mock.patch(
        "locale.getlocale", side_effect=Exception("fail")
    ), mock.patch("locale.getdefaultlocale", side_effect=Exception("fail")), mock.patch(
        "platform.system", return_value="Linux"
    ):
        assert main_mod._get_locale() == "(Unknown locale)"


def test_get_version_info_success(monkeypatch):
    monkeypatch.setattr(
        main_mod.network, "http_json", lambda url: ({"info": {"version": "1.2.3"}}, 200)
    )
    monkeypatch.setattr(main_mod, "get_version", lambda: "1.2.3")
    monkeypatch.setattr(main_mod.version, "parse", lambda v: v)
    result = main_mod._get_version_info()
    assert "Supported Version: 1.2.3" in result


def test_get_version_info_error(monkeypatch):
    with mock.patch.object(
        main_mod.network, "http_json", side_effect=Exception("fail")
    ):
        result = main_mod._get_version_info()
        assert "Unable to get version information" in result


def test_get_version_info_bad_code(monkeypatch):
    monkeypatch.setattr(main_mod.network, "http_json", lambda url: (None, 500))
    result = main_mod._get_version_info()
    assert "PyPi returned an error code" in result


def test_get_version_info_invalid_data(monkeypatch):
    monkeypatch.setattr(main_mod.network, "http_json", lambda url: ({}, 200))
    result = main_mod._get_version_info()
    assert "PyPi returned invalid data" in result


def test_set_basic_info(monkeypatch):
    monkeypatch.setattr(main_mod.reporter, "register_info", lambda *a, **k: None)
    monkeypatch.setattr(main_mod, "get_version", lambda: "1.2.3")
    monkeypatch.setattr(main_mod, "_get_locale", lambda: "en_US.utf8")
    monkeypatch.setattr(main_mod, "sys", sys)
    monkeypatch.setattr(main_mod, "platform", sys.modules["platform"])
    monkeypatch.setattr(main_mod, "ssl", sys.modules["ssl"])
    main_mod._set_basic_info()


def test_signal_handler_main(monkeypatch):
    with mock.patch.object(
        main_mod,
        "current_process",
        return_value=types.SimpleNamespace(name="MainProcess"),
    ):
        monkeypatch.setattr(main_mod.output, "empty", lambda: None)
        monkeypatch.setattr(main_mod.output, "norm", lambda x: None)
        monkeypatch.setattr(main_mod, "_shutdown", lambda: None)
        monkeypatch.setattr(main_mod, "active_children", lambda: None)
        with pytest.raises(SystemExit):
            main_mod.signal_handler(main_mod.signal.SIGINT, None)


def test_signal_handler_worker(monkeypatch):
    with mock.patch.object(
        main_mod, "current_process", return_value=types.SimpleNamespace(name="Worker")
    ):
        monkeypatch.setattr(main_mod, "active_children", lambda: None)
        with pytest.raises(SystemExit):
            main_mod.signal_handler(main_mod.signal.SIGINT, None)


def test_shutdown(monkeypatch):
    main_mod._has_shutdown = False
    main_mod._start_time = main_mod.datetime.now()
    main_mod._monitor = types.SimpleNamespace(peak_mem_res=123456)
    monkeypatch.setattr(main_mod.output, "debug", lambda x: None)
    monkeypatch.setattr(main_mod.output, "empty", lambda: None)
    monkeypatch.setattr(main_mod.output, "norm", lambda x: None)
    monkeypatch.setattr(main_mod.reporter, "register_info", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.reporter, "get_output_file", lambda: "")
    main_mod._shutdown()


def test_shutdown_with_output(monkeypatch):
    main_mod._has_shutdown = False
    main_mod._start_time = main_mod.datetime.now()
    main_mod._monitor = types.SimpleNamespace(peak_mem_res=0)
    monkeypatch.setattr(main_mod.output, "debug", lambda x: None)
    monkeypatch.setattr(main_mod.output, "empty", lambda: None)
    monkeypatch.setattr(main_mod.output, "norm", lambda x: None)
    monkeypatch.setattr(main_mod.reporter, "register_info", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.reporter, "get_output_file", lambda: "out.json")
    monkeypatch.setattr(main_mod.reporter, "save_output", lambda spinner: None)
    monkeypatch.setattr(
        main_mod,
        "Spinner",
        lambda: mock.MagicMock(__enter__=lambda s: s, __exit__=lambda s, e, v, t: None),
    )
    main_mod._shutdown()


def test_main_encoding_handling(monkeypatch):
    # Simulate sys.stdout.encoding not being utf-8 and reconfigure working
    class DummyStdout:
        def __init__(self):
            self.encoding = "ascii"
            self.reconfigured = False
            self.output = []

        def reconfigure(self, encoding=None):
            self.reconfigured = True
            self.encoding = encoding

        def write(self, s):
            self.output.append(s)

        def flush(self):
            pass

    class DummyArgs:
        def __init__(self):
            self.command = "version"
            self.proxy = None
            self.cookie = None
            self.header = None
            self.debug = False
            self.nocolors = False
            self.nowrap = False
            self.output = None
            self.func = lambda a, u: None

        def __contains__(self, item):
            return hasattr(self, item)

    dummy_stdout = DummyStdout()
    monkeypatch.setattr(main_mod.sys, "stdout", dummy_stdout)
    monkeypatch.setattr(main_mod.signal, "signal", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.warnings, "simplefilter", lambda *a, **k: None)
    monkeypatch.setattr(
        main_mod.command_line,
        "build_parser",
        lambda: mock.Mock(parse_known_args=lambda: (DummyArgs(), [])),
    )
    monkeypatch.setattr(main_mod.output, "setup", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.output, "debug", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.network, "init", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.config, "load_config", lambda: None)
    monkeypatch.setattr(main_mod, "print_header", lambda: None)
    monkeypatch.setattr(main_mod.reporter, "init", lambda *a, **k: None)
    monkeypatch.setattr(main_mod, "_set_basic_info", lambda: None)
    monkeypatch.setattr(main_mod.reporter, "get_output_file", lambda: "")
    monkeypatch.setattr(
        main_mod,
        "_KeyMonitor",
        lambda: mock.MagicMock(__enter__=lambda s: s, __exit__=lambda s, e, v, t: None),
    )
    monkeypatch.setattr(
        main_mod,
        "_ProcessMonitor",
        lambda: mock.MagicMock(__enter__=lambda s: s, __exit__=lambda s, e, v, t: None),
    )
    monkeypatch.setattr(main_mod, "_shutdown", lambda: None)
    main_mod.main()
    assert dummy_stdout.reconfigured


def test_main_encoding_exception(monkeypatch):
    # Simulate sys.stdout.encoding not being utf-8 and reconfigure raising exception
    class DummyStdout:
        def __init__(self):
            self.encoding = "ascii"
            self.output = []

        def reconfigure(self, encoding=None):
            raise Exception("fail reconfigure")

        def write(self, s):
            self.output.append(s)

        def flush(self):
            pass

    class DummyArgs:
        def __init__(self):
            self.command = "version"
            self.proxy = None
            self.cookie = None
            self.header = None
            self.debug = False
            self.nocolors = False
            self.nowrap = False
            self.output = None
            self.func = lambda a, u: None

        def __contains__(self, item):
            return hasattr(self, item)

    dummy_stdout = DummyStdout()
    monkeypatch.setattr(main_mod.sys, "stdout", dummy_stdout)
    monkeypatch.setattr(main_mod.signal, "signal", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.warnings, "simplefilter", lambda *a, **k: None)
    monkeypatch.setattr(
        main_mod.command_line,
        "build_parser",
        lambda: mock.Mock(parse_known_args=lambda: (DummyArgs(), [])),
    )
    monkeypatch.setattr(main_mod.output, "setup", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.output, "debug", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.network, "init", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.config, "load_config", lambda: None)
    monkeypatch.setattr(main_mod, "print_header", lambda: None)
    monkeypatch.setattr(main_mod.reporter, "init", lambda *a, **k: None)
    monkeypatch.setattr(main_mod, "_set_basic_info", lambda: None)
    monkeypatch.setattr(main_mod.reporter, "get_output_file", lambda: "")
    monkeypatch.setattr(
        main_mod,
        "_KeyMonitor",
        lambda: mock.MagicMock(__enter__=lambda s: s, __exit__=lambda s, e, v, t: None),
    )
    monkeypatch.setattr(
        main_mod,
        "_ProcessMonitor",
        lambda: mock.MagicMock(__enter__=lambda s: s, __exit__=lambda s, e, v, t: None),
    )
    monkeypatch.setattr(main_mod, "_shutdown", lambda: None)
    main_mod.main()
    # Check DummyStdout output for the error message
    assert any("Unable to set UTF-8 encoding" in s for s in dummy_stdout.output)


def test_main_keyboard_interrupt(monkeypatch):
    # Simulate KeyboardInterrupt during args.func
    class DummyStdout:
        def __init__(self):
            self.encoding = "utf-8"

        def write(self, s):
            pass

        def flush(self):
            pass

    class DummyArgs:
        def __init__(self):
            self.command = "scan"
            self.proxy = None
            self.cookie = None
            self.header = None
            self.debug = False
            self.nocolors = False
            self.nowrap = False
            self.output = None
            self.func = lambda a, u: (_ for _ in ()).throw(KeyboardInterrupt())

        def __contains__(self, item):
            return hasattr(self, item)

    dummy_stdout = DummyStdout()
    monkeypatch.setattr(main_mod.sys, "stdout", dummy_stdout)
    monkeypatch.setattr(main_mod.signal, "signal", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.warnings, "simplefilter", lambda *a, **k: None)
    monkeypatch.setattr(
        main_mod.command_line,
        "build_parser",
        lambda: mock.Mock(
            parse_known_args=lambda: (DummyArgs(), ["http://example.com"])
        ),
    )
    monkeypatch.setattr(main_mod.output, "setup", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.output, "debug", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.network, "init", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.config, "load_config", lambda: None)
    monkeypatch.setattr(main_mod, "print_header", lambda: None)
    monkeypatch.setattr(main_mod.reporter, "init", lambda *a, **k: None)
    monkeypatch.setattr(main_mod, "_set_basic_info", lambda: None)
    monkeypatch.setattr(main_mod.reporter, "get_output_file", lambda: "")
    monkeypatch.setattr(
        main_mod,
        "_KeyMonitor",
        lambda: mock.MagicMock(__enter__=lambda s: s, __exit__=lambda s, e, v, t: None),
    )
    monkeypatch.setattr(
        main_mod,
        "_ProcessMonitor",
        lambda: mock.MagicMock(__enter__=lambda s: s, __exit__=lambda s, e, v, t: None),
    )
    monkeypatch.setattr(main_mod, "_shutdown", lambda: None)
    monkeypatch.setattr(main_mod.output, "empty", lambda: None)
    monkeypatch.setattr(main_mod.output, "error", lambda *a, **k: None)
    main_mod.main()


def test_key_monitor_non_tty(monkeypatch):
    # Simulate sys.stdout.isatty() returning False
    class DummyStdout:
        def isatty(self):
            return False

    monkeypatch.setattr(main_mod.sys, "stdout", DummyStdout())
    km = main_mod._KeyMonitor()
    # Should set busy to False immediately
    km.busy = True
    km.wait_task()
    assert not km.busy


def test_key_monitor_enter_exit(monkeypatch):
    # Simulate sys.stdout.isatty() returning True, but getchar returns empty
    class DummyStdout:
        def isatty(self):
            return True

    monkeypatch.setattr(main_mod.sys, "stdout", DummyStdout())
    monkeypatch.setattr(main_mod.utils, "INPUT_LOCK", mock.MagicMock())
    monkeypatch.setattr(main_mod, "getchar", lambda: "")
    monkeypatch.setattr(main_mod.output, "debug", lambda *a, **k: None)
    km = main_mod._KeyMonitor()
    km.busy = False  # Avoid infinite loop
    # __enter__ should set busy True and start thread
    with mock.patch("threading.Thread.start", lambda s: None):
        ret = km.__enter__()
        assert ret is km and km.busy
    # __exit__ should set busy False
    assert not km.__exit__(None, None, None)


def test_process_monitor_non_tty(monkeypatch):
    # Simulate sys.stdout.isatty() returning False
    class DummyStdout:
        def isatty(self):
            return False

    monkeypatch.setattr(main_mod.sys, "stdout", DummyStdout())
    pm = main_mod._ProcessMonitor()
    pm.busy = True
    pm.monitor_task()
    assert not pm.busy


def test_process_monitor_enter_exit(monkeypatch):
    # Simulate sys.stdout.isatty() returning True
    class DummyStdout:
        def isatty(self):
            return True

    monkeypatch.setattr(main_mod.sys, "stdout", DummyStdout())
    monkeypatch.setattr(main_mod.psutil, "Process", lambda: mock.MagicMock())
    pm = main_mod._ProcessMonitor()
    pm.busy = False  # Avoid infinite loop
    with mock.patch("threading.Thread.start", lambda s: None):
        ret = pm.__enter__()
        assert ret is pm and pm.busy
    # __exit__ should set busy False
    assert not pm.__exit__(None, None, None)


def test_process_monitor_get_info(monkeypatch):
    # Test _get_info covers all branches
    proc = mock.MagicMock()
    proc.cpu_percent.return_value = 10
    proc.cpu_times.return_value = mock.MagicMock(system=1, user=2)
    proc.memory_info.return_value = mock.MagicMock(rss=123456, vms=654321)
    proc.num_threads.return_value = 5
    proc.oneshot = lambda: mock.MagicMock(
        __enter__=lambda s: None, __exit__=lambda s, e, v, t: None
    )
    proc.connections.return_value = [1, 2]
    monkeypatch.setattr(
        main_mod.psutil,
        "virtual_memory",
        lambda: mock.MagicMock(total=1000000, available=500000),
    )
    monkeypatch.setattr(
        main_mod.psutil, "cpu_freq", lambda: mock.MagicMock(current=2000, max=2000)
    )
    pm = main_mod._ProcessMonitor()
    pm.process = proc
    pm.peak_mem_res = 0
    pm.low_mem_warning = False
    monkeypatch.setattr(main_mod.output, "debug", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.output, "error", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.output, "debug_exception", lambda: None)
    info = pm._get_info()
    assert "Process Stats:" in info


def test_process_monitor_get_info_exceptions(monkeypatch):
    # Test _get_info with exceptions in connections
    proc = mock.MagicMock()
    proc.cpu_percent.return_value = 10
    proc.cpu_times.return_value = mock.MagicMock(system=1, user=2)
    proc.memory_info.return_value = mock.MagicMock(rss=123456, vms=654321)
    proc.num_threads.return_value = 5
    proc.oneshot = lambda: mock.MagicMock(
        __enter__=lambda s: None, __exit__=lambda s, e, v, t: None
    )
    proc.connections.side_effect = Exception("fail")
    monkeypatch.setattr(
        main_mod.psutil,
        "virtual_memory",
        lambda: mock.MagicMock(total=1000000, available=500000),
    )
    monkeypatch.setattr(
        main_mod.psutil, "cpu_freq", lambda: mock.MagicMock(current=2000, max=2000)
    )
    pm = main_mod._ProcessMonitor()
    pm.process = proc
    pm.peak_mem_res = 0
    pm.low_mem_warning = False
    monkeypatch.setattr(main_mod.output, "debug", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.output, "error", lambda *a, **k: None)
    monkeypatch.setattr(main_mod.output, "debug_exception", lambda: None)
    info = pm._get_info()
    assert "Process Stats:" in info
