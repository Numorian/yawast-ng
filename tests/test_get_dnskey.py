from unittest import TestCase

from tests import utils
from yawast.scanner.plugins.dns import dnssec
from yawast.shared import output


class TestGetDnsKey(TestCase):
    def test_get_dnskey_good(self):
        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            recs = dnssec.get_dnskey("cloudflare.com")

        self.assertNotIn("Exception", stderr.getvalue())
        self.assertTrue(len(recs) > 0)

    def test_get_dnskey_none(self):
        output.setup(False, False, False)
        with utils.capture_sys_output() as (stdout, stderr):
            recs = dnssec.get_dnskey("adamcaudill.com")

        self.assertNotIn("Exception", stderr.getvalue())
        self.assertTrue(len(recs) == 0)
