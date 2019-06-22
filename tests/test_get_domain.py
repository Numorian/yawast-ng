from unittest import TestCase
from yawast.shared.utils import get_domain


class TestGetDomain(TestCase):
    def test_get_domain_clean(self):
        self.assertEqual("adamcaudill.com", get_domain("adamcaudill.com"))

    def test_get_domain_http(self):
        self.assertEqual("adamcaudill.com", get_domain("http://adamcaudill.com"))

    def test_get_domain_port(self):
        self.assertEqual("adamcaudill.com", get_domain("adamcaudill.com:80"))

    def test_get_domain_creds(self):
        self.assertEqual("adamcaudill.com", get_domain("user:pass@adamcaudill.com"))

    def test_get_domain_creds_port(self):
        self.assertEqual("adamcaudill.com", get_domain("user:pass@adamcaudill.com:80"))

    def test_get_domain_ipv4_clean(self):
        self.assertEqual("127.0.0.1", get_domain("127.0.0.1"))

    def test_get_domain_ipv4_port(self):
        self.assertEqual("127.0.0.1", get_domain("127.0.0.1:80"))

    def test_get_domain_ipv4_creds_port(self):
        self.assertEqual("127.0.0.1", get_domain("user:pass@127.0.0.1:80"))

    def test_get_domain_ipv6_clean(self):
        self.assertEqual(
            "[3ffe:2a00:100:7031::1]", get_domain("[3ffe:2a00:100:7031::1]")
        )

    def test_get_domain_ipv6_port(self):
        self.assertEqual(
            "[3ffe:2a00:100:7031::1]", get_domain("[3ffe:2a00:100:7031::1]:80")
        )
