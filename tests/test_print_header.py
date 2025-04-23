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
