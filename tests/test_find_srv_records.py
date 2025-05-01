#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
#  See the LICENSE file for full license details.

import os

import pytest

from yawast.scanner.modules.dns import srv


class TestFindSrvRecords:
    def test_find_srv_records(self):
        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/srv.txt")

        recs = srv.find_srv_records("adamcaudill.com", path)

        assert len(recs) > 0
        assert srv is not None
