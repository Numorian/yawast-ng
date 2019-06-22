from unittest import TestCase
from yawast.scanner.plugins.dns.caa import _get_caa_records
from dns import resolver


class TestGetCaaRecords(TestCase):
    def test__get_caa_records(self):
        resv = resolver.Resolver()
        resv.nameservers = ["1.1.1.1", "8.8.8.8"]

        recs = _get_caa_records("adamcaudill.com", resv)

        self.assertTrue(len(recs) > 0)

    def test__get_caa_records_none(self):
        resv = resolver.Resolver()
        resv.nameservers = ["1.1.1.1", "8.8.8.8"]

        recs = _get_caa_records("www.google.com", resv)

        self.assertTrue(len(recs) == 0)
