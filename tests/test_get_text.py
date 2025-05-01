#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
#  See the LICENSE file for full license details.

import pytest

from yawast.scanner.modules.dns import basic


class TestGetText:
    def test_get_text(self):
        recs = basic.get_text("adamcaudill.com")

        assert len(recs) > 0

        for rec in recs:
            if rec.startswith("v="):
                assert rec == "v=spf1 mx a ptr include:_spf.google.com ~all"
