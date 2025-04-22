#  Copyright (c) 2013 - 2025 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file for full license details.

import pytest
from dns import resolver

from yawast.scanner.modules.dns.caa import _get_cname


class TestGetCname:
    def test__get_cname(self):
        resv = resolver.Resolver()
        resv.nameservers = ["1.1.1.1", "8.8.8.8"]

        name = _get_cname("cntest.adamcaudill.com", resv)

        assert name is not None
        assert "google.com" in name
