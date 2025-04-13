#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

from unittest import TestCase

from yawast.scanner.plugins.dns import network_info
from unittest import TestCase, mock


class TestNetworkInfo(TestCase):
    @mock.patch("yawast.scanner.plugins.dns.network_info._build_data_from_file")
    def test_network_info_known_ip4(self, mock_build_data):
        # Mock the _data to simulate known IP ranges
        network_info._data = [
            (
                1746672384,
                1746672639,
                "US",
                "CLOUDFLARENET",
            ),  # 104.28.27.55 falls in this range
        ]

        res = network_info.network_info("104.28.27.55")
        self.assertEqual("US - CLOUDFLARENET", res)

    @mock.patch("yawast.scanner.plugins.dns.network_info._build_data_from_file")
    def test_network_info_known_ip6(self, mock_build_data):
        # Mock the _data to simulate known IP ranges
        network_info._data = [
            (
                50543257686929658985975890372355686400,
                50543257686992523128595851089440407551,
                "US",
                "CLOUDFLARENET",
            ),  # 2606:4700:3031::6815:4b87 falls in this range
        ]

        res = network_info.network_info("2606:4700:3031::6815:4b87")
        self.assertEqual("US - CLOUDFLARENET", res)

    def test_network_info_known_ip4_real(self):
        res = network_info.network_info("104.28.27.55")
        self.assertEqual("US - CLOUDFLARENET", res)

    @mock.patch("yawast.scanner.plugins.dns.network_info._build_data_from_file")
    def test_network_info_unknown_ip(self, mock_build_data):
        # Mock the _data to simulate known IP ranges
        network_info._data = [
            (1746672384, 1746672639, "US", "CLOUDFLARENET"),
        ]

        res = network_info.network_info("8.8.8.8")  # IP not in the mocked range
        self.assertEqual("Unknown", res)

    @mock.patch("yawast.scanner.plugins.dns.network_info._build_data_from_file")
    def test_network_info_empty_data(self, mock_build_data):
        # Mock the _data to simulate an empty dataset
        network_info._data = []

        res = network_info.network_info("104.28.27.55")
        self.assertEqual("Unknown", res)

    @mock.patch("yawast.scanner.plugins.dns.network_info._build_data_from_file")
    def test_network_info_invalid_ip(self, mock_build_data):
        with self.assertRaises(ValueError):
            network_info.network_info("invalid_ip")

    def tearDown(self):
        # Ensure _data is cleared after each test
        network_info.purge_data()
