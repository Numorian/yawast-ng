#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

from unittest import TestCase

from tests import utils
from yawast.scanner.session import Session
from yawast import command_line
from yawast.shared import output
from yawast.scanner.cli import ssl_internal


class TestSslInternal(TestCase):
    def test_internal_ssl(self):
        url = "https://github.com/"

        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            p = command_line.build_parser()
            ns = p.parse_args(args=["scan"])
            s = Session(ns, url)

            try:
                ssl_internal.scan(s)
            except Exception as error:
                self.assertIsNone(error)

            self.assertNotIn("Exception", stderr.getvalue())
            self.assertNotIn("Error", stderr.getvalue())
            self.assertNotIn("Error", stdout.getvalue())
