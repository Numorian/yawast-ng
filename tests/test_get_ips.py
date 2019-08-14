#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from unittest import TestCase
from yawast.scanner.plugins.dns import basic


class TestGetIps(TestCase):
    def test_get_ips_ac(self):
        res = basic.get_ips("adamcaudill.com")

        self.assertEqual(4, len(res))
