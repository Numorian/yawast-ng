from unittest import TestCase
from yawast.scanner.plugins.dns.caa import _get_cname
from dns import resolver


class TestGetCname(TestCase):
    def test__get_cname(self):
        resv = resolver.Resolver()
        resv.nameservers = ["1.1.1.1", "8.8.8.8"]

        name = _get_cname("cntest.adamcaudill.com", resv)

        self.assertEqual("www.google.com.", name)
