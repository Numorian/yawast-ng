#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

import os
from unittest import mock

import pytest

from tests import utils
from yawast.scanner.cli.network import _check_open_ports
from yawast.scanner.modules.network import port_scan
from yawast.shared import output


class TestCheckOpenPorts:
    @mock.patch("yawast.scanner.modules.network.port_scan.socket.socket")
    def test_check_open_ports(self, mock_socket):
        # Simulate all ports as open
        instance = mock_socket.return_value
        instance.connect_ex.return_value = 0
        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/common_ports.json")

        recs = port_scan.check_open_ports(
            "https://adamcaudill.com", "104.21.15.2", path
        )

        assert len(recs) > 0

    @mock.patch("yawast.scanner.modules.network.port_scan.socket.socket")
    def test_check_open_ports_invalid_ip(self, mock_socket):
        # Simulate all ports as closed
        instance = mock_socket.return_value
        instance.connect_ex.return_value = 1
        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/common_ports.json")

        recs = port_scan.check_open_ports(
            "https://adamcaudill.com", "256.28.26.55", path
        )

        assert len(recs) == 0

    @mock.patch("yawast.scanner.modules.network.port_scan.socket.socket")
    def test_check_open_ports_cli(self, mock_socket):
        # Simulate all ports as open
        instance = mock_socket.return_value
        instance.connect_ex.return_value = 0
        output.setup(False, False, False)
        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/common_ports.json")

        with utils.capture_sys_output() as (stdout, stderr):
            _check_open_ports("adamcaudill.com", "https://adamcaudill.com", path)

        assert "Exception" not in stderr.getvalue()

    @mock.patch("yawast.scanner.modules.network.port_scan.socket.socket")
    def test_check_open_ports_cli_bad_domain(self, mock_socket):
        # Simulate all ports as closed
        instance = mock_socket.return_value
        instance.connect_ex.return_value = 1
        output.setup(False, False, False)
        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/common_ports.json")

        with utils.capture_sys_output() as (stdout, stderr):
            _check_open_ports(
                "invalidaksjdhkajshd.com", "https://adamcaudill.com", path
            )

        assert "Exception" not in stderr.getvalue()
