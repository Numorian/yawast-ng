#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

import pytest

from yawast.scanner.modules.dns import basic


class TestGetHost:
    def test_get_host(self):
        res = basic.get_host("8.8.8.8")

        assert res == "dns.google"

    def test_get_host_na(self):
        res = basic.get_host("104.28.27.55")

        assert res == "N/A"
