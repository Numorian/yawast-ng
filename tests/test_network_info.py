#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

from unittest import TestCase

from yawast.scanner.plugins.dns import network_info


class TestNetworkInfo(TestCase):
    def test_network_info(self):
        res = network_info.network_info("104.28.27.55")

        self.assertEqual("US - CLOUDFLARENET - Cloudflare, Inc.", res)
