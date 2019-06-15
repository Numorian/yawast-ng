from unittest import TestCase
from yawast.scanner.plugins.dns import basic


class TestGetHost(TestCase):
    def test_get_host(self):
        res = basic.get_host("8.8.8.8")

        self.assertEqual("google-public-dns-a.google.com", res)

    def test_get_host_na(self):
        res = basic.get_host("104.28.27.55")

        self.assertEqual("N/A", res)
