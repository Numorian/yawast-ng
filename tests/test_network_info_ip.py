from unittest import TestCase

from yawast.scanner.plugins.dns.network_info import _ipv6_to_int, _is_ipv6_in_range


class TestNetworkInfoIP(TestCase):
    def test__ipv6_to_int_cf(self):
        # test a random IP
        res = _ipv6_to_int("2606:4700:4700::1111")
        self.assertEqual(50543257694033307102031451402929180945, res)

        # start of a Cloudflare range
        res = _ipv6_to_int("2606:4700:300c::")
        self.assertEqual(50543257686929658985975890372355686400, res)

        # ip in the range
        res = _ipv6_to_int("2606:4700:3031::6815:4b87")
        self.assertEqual(50543257686974389241301631653566040967, res)

        # end of a Cloudflare range
        res = _ipv6_to_int("2606:4700:303f:ffff:ffff:ffff:ffff:ffff")
        self.assertEqual(50543257686992523128595851089440407551, res)

        # check an IP in the above range
        res = _is_ipv6_in_range(
            "2606:4700:3031::6815:4b87",
            50543257686929658985975890372355686400,
            50543257686992523128595851089440407551,
        )
