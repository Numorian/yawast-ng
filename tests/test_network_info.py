from unittest import TestCase
from yawast.scanner.plugins.dns import network_info


class TestNetworkInfo(TestCase):
    def test_network_info(self):
        res = network_info.network_info("104.28.27.55")

        self.assertEqual("US - CLOUDFLARENET - Cloudflare, Inc.", res)
