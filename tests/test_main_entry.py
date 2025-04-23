import sys
import types
from unittest import mock

import pytest


def import_main_module():
    import importlib

    return importlib.import_module("yawast.__main__")


class TestMainEntry:
    def _patch_parser_with_func(self):
        # Patch the parser to always return an argparse.Namespace with a dummy func
        import argparse

        parser_mock = mock.Mock()
        dummy_func = lambda *a, **k: None
        ns = argparse.Namespace(func=dummy_func, command="version", output=None)
        parser_mock.parse_known_args.return_value = (ns, [])
        return mock.patch("yawast.command_line.build_parser", return_value=parser_mock)

    @mock.patch("sys.version_info", (2, 7, 0))
    @mock.patch("os.popen")
    @mock.patch("os.execv")
    @mock.patch("sys.exit")
    def test_python2_redirect(self, mock_exit, mock_execv, mock_popen):
        # Simulate python3 in PATH
        mock_popen.return_value.read.return_value = "/usr/bin/python3\n"
        sys_argv = sys.argv[:]
        sys.argv = ["script.py", "arg1"]
        with self._patch_parser_with_func():
            import_main_module().main()
        mock_execv.assert_called()
        sys.argv = sys_argv

    @mock.patch("sys.version_info", (2, 7, 0))
    @mock.patch("os.popen")
    @mock.patch("os.execv")
    @mock.patch("sys.exit")
    def test_python2_no_python3(self, mock_exit, mock_execv, mock_popen):
        # Simulate python3 not in PATH
        mock_popen.return_value.read.return_value = ""
        with self._patch_parser_with_func():
            import_main_module().main()
        mock_exit.assert_called()

    @mock.patch("sys.version_info", (3, 6, 0))
    @mock.patch("sys.exit")
    def test_python_too_old(self, mock_exit):
        with self._patch_parser_with_func():
            import_main_module().main()
        mock_exit.assert_called()

    @mock.patch("sys.version_info", (3, 8, 0))
    @mock.patch("yawast.main.main")
    def test_python_valid(self, mock_main):
        import_main_module().main()
        mock_main.assert_called()
