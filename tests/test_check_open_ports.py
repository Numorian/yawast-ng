import os
from unittest import TestCase

from yawast.scanner.plugins.network import port_scan


class TestCheckOpenPorts(TestCase):
    def test_check_open_ports(self):
        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/common_ports.json")

        recs = port_scan.check_open_ports(
            "https://adamcaudill.com", "104.28.26.55", path
        )

        self.assertTrue(len(recs) > 0)
