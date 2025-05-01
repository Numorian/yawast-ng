#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
#  See the LICENSE file for full license details.

import pytest

from yawast.scanner.modules.dns import basic


class TestGetIps:
    def test_get_ips(self):
        ips = basic.get_ips("adamcaudill.com")

        # make sure we have at least 2 IPs
        assert len(ips) >= 2
        assert ips is not None
