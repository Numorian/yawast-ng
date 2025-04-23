#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

import pytest

from tests import utils
from yawast import command_line
from yawast.scanner.cli import ssl_internal
from yawast.scanner.session import Session
from yawast.shared import output


class TestSslInternal:
    def test_ssl_internal(self):
        url = "https://github.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            p = command_line.build_parser()
            ns = p.parse_args(args=["scan"])
            s = Session(ns, url)

            try:
                ssl_internal.scan(s)
            except Exception as error:
                assert error is None

            assert "Exception" not in stderr.getvalue()
            assert "Error" not in stderr.getvalue()
            assert "Error" not in stdout.getvalue()
