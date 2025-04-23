#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

import os

import pytest

from yawast.scanner.modules.dns import subdomains


class TestFindSubdomains:
    def test_find_subdomains(self):
        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/subdomains.txt")

        recs = subdomains.find_subdomains("adamcaudill.com", path)

        assert len(recs) > 0

        assert "www.adamcaudill.com." == recs[0][1]
