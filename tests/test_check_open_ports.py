#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

import os
from unittest import TestCase

from tests import utils
from yawast.scanner.cli.network import _check_open_ports
from yawast.scanner.plugins.network import port_scan
from yawast.shared import output


class TestCheckOpenPorts(TestCase):
    def test_check_open_ports(self):
        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/common_ports.json")

        recs = port_scan.check_open_ports(
            "https://adamcaudill.com", "104.28.26.55", path
        )

        self.assertTrue(len(recs) > 0)

    def test_check_open_ports_invalid_ip(self):
        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/common_ports.json")

        recs = port_scan.check_open_ports(
            "https://adamcaudill.com", "256.28.26.55", path
        )

        self.assertTrue(len(recs) == 0)

    def test_check_open_ports_cli(self):
        output.setup(False, False, False)
        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/common_ports.json")

        with utils.capture_sys_output() as (stdout, stderr):
            _check_open_ports("adamcaudill.com", "https://adamcaudill.com", path)

        self.assertNotIn("Exception", stderr.getvalue())

    def test_check_open_ports_cli_bad_domain(self):
        output.setup(False, False, False)
        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/common_ports.json")

        with utils.capture_sys_output() as (stdout, stderr):
            _check_open_ports(
                "invalidaksjdhkajshd.com", "https://adamcaudill.com", path
            )

        self.assertNotIn("Exception", stderr.getvalue())
