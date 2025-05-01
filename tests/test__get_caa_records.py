#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
#  See the LICENSE file for full license details.

import pytest
from dns import resolver

from yawast.scanner.modules.dns.caa import _get_caa_records


class TestGetCaaRecords:
    def test__get_caa_records(self):
        resv = resolver.Resolver()
        resv.nameservers = ["1.1.1.1", "8.8.8.8"]
        recs = _get_caa_records("adamcaudill.com", resv)
        assert len(recs) > 0

    def test__get_caa_records_none(self):
        resv = resolver.Resolver()
        resv.nameservers = ["1.1.1.1", "8.8.8.8"]
        recs = _get_caa_records("www.google.com", resv)
        assert len(recs) == 0
