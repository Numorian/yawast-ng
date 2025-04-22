#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

import pytest

from tests import utils
from yawast import command_line


class TestBuildParser:
    def test_build_parser(self):
        parser = command_line.build_parser()

        # make sure we got something back
        assert parser is not None

        with pytest.raises(SystemExit):
            with utils.capture_sys_output() as (stdout, stderr):
                parser.parse_known_args([""])

        assert "yawast: error" in stderr.getvalue()
