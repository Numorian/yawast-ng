#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

from unittest import TestCase

from tests import utils
from yawast.scanner.modules.ssl_labs import api
from yawast.shared import output


class TestGetInfoMessage(TestCase):
    def test_get_info_message(self):
        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            recs = api.get_info_message()

        self.assertNotIn("Exception", stderr.getvalue())
        self.assertTrue(len(recs) > 0)
