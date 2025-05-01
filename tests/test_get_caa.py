#  Copyright (c) 2013 - 2025 Numorian, Inc. and Contributors.
#  This file is part of yawast-ng which is released under the MIT license.
#  See the LICENSE file for full license details.

import pytest

from yawast.scanner.modules.dns.caa import get_caa


class TestGetCaa:
    def test_get_caa(self):
        recs = get_caa("cntest.adamcaudill.com")
        assert len(recs) > 0

        # RECORD 1
        # check the domain
        assert "cntest.adamcaudill.com" == recs[0][0]

        # check the type of the CNAME
        assert "CNAME" == recs[0][1]

        # check the return of the CNAME
        assert "www.google.com." == recs[0][2]

        # RECORD 2
        # check the domain
        assert "www.google.com" == recs[1][0]

        # check the type of record
        assert "CAA" == recs[1][1]

        # check the return of the CAA
        assert [] == recs[1][2]

        # RECORD 3
        # check the domain
        assert "google.com" == recs[2][0]

        # check the type of record
        assert "CAA" == recs[2][1]

        # check the record length for the CAA data
        assert len(recs[2][2]) > 0
