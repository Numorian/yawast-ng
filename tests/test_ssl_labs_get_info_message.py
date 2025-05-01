#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
#  See the LICENSE file for full license details.

import pytest

from tests import utils
from yawast.scanner.modules.ssl_labs import api
from yawast.shared import output


class TestSslLabsGetInfoMessage:
    def test_ssl_labs_get_info_message(self):
        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            recs = api.get_info_message()

        assert "Exception" not in stderr.getvalue()
        assert len(recs) > 0
