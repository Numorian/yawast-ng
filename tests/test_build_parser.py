#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from unittest import TestCase

from tests import utils
from yawast import command_line


class TestBuildParser(TestCase):
    def test_build_parser(self):
        parser = command_line.build_parser()

        # make sure we got something back
        self.assertIsNotNone(parser)

        with self.assertRaises(SystemExit):
            with utils.capture_sys_output() as (stdout, stderr):
                parser.parse_known_args([""])

        self.assertIn("yawast: error", stderr.getvalue())
