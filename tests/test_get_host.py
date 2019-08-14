#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from unittest import TestCase
from yawast.scanner.plugins.dns import basic


class TestGetHost(TestCase):
    def test_get_host(self):
        res = basic.get_host("8.8.8.8")

        self.assertEqual("dns.google", res)

    def test_get_host_na(self):
        res = basic.get_host("104.28.27.55")

        self.assertEqual("N/A", res)
