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
