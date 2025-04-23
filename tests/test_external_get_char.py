import sys
from unittest import mock

import pytest

import yawast.external.get_char as get_char_mod


def test_getchar_windows():
    # Simulate Windows by patching msvcrt import
    with mock.patch.dict("sys.modules", {"msvcrt": mock.Mock()}):
        msvcrt = sys.modules["msvcrt"]
        msvcrt.kbhit.return_value = True
        msvcrt.getch.return_value = b"A"
        # Remove cached _func if present
        get_char_mod.getchar.__dict__.pop("_func", None)
        result = get_char_mod.getchar()
        assert result == "A"
        # Test kbhit False
        msvcrt.kbhit.return_value = False
        result = get_char_mod.getchar()
        assert result == ""


def test_getchar_posix(monkeypatch):
    # Simulate ImportError for msvcrt by removing it from sys.modules
    monkeypatch.setitem(sys.modules, "msvcrt", None)
    monkeypatch.setattr(get_char_mod, "getchar", get_char_mod.getchar)
    # Remove cached _func if present
    get_char_mod.getchar.__dict__.pop("_func", None)
    # Patch all POSIX modules and sys.stdin, and provide int values for ICANON/ECHO
    termios_mock = mock.Mock()
    termios_mock.ICANON = 2
    termios_mock.ECHO = 4
    with mock.patch.dict(
        "sys.modules",
        {
            "tty": mock.Mock(),
            "termios": termios_mock,
            "fcntl": mock.Mock(),
            "os": mock.Mock(),
        },
    ), mock.patch("termios.tcgetattr", return_value=[0, 0, 0, 0]), mock.patch(
        "termios.tcsetattr"
    ), mock.patch(
        "fcntl.fcntl", side_effect=[0, 0, 0, 0]
    ), mock.patch(
        "os.O_NONBLOCK", 0
    ), mock.patch(
        "sys.stdin"
    ) as stdin:
        stdin.fileno.return_value = 0
        stdin.read.side_effect = ["x"]
        result = get_char_mod.getchar()
        assert result == "x"


def test_getchar_posix_keyboardinterrupt(monkeypatch):
    # Remove cached _func if present
    get_char_mod.getchar.__dict__.pop("_func", None)
    termios_mock = mock.Mock()
    termios_mock.ICANON = 2
    termios_mock.ECHO = 4
    with mock.patch.dict(
        "sys.modules",
        {
            "tty": mock.Mock(),
            "termios": termios_mock,
            "fcntl": mock.Mock(),
            "os": mock.Mock(),
        },
    ), mock.patch("termios.tcgetattr", return_value=[0, 0, 0, 0]), mock.patch(
        "termios.tcsetattr"
    ), mock.patch(
        "fcntl.fcntl", side_effect=[0, 0, 0, 0]
    ), mock.patch(
        "os.O_NONBLOCK", 0
    ), mock.patch(
        "sys.stdin"
    ) as stdin:
        stdin.fileno.return_value = 0
        stdin.read.side_effect = ["\x03"]
        with pytest.raises(KeyboardInterrupt):
            get_char_mod.getchar()
